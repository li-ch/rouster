//! The per-peer session runtime: framed message IO over a generic
//! stream, the real hold/keepalive timers, OPEN validation glue, and
//! the Adj-RIB-In/Out plumbing hooks. The FSM stays pure
//! ([`crate::fsm`]); this module is the async world that feeds it
//! events and performs its actions.
//!
//! Clock injection: the MRAI gate takes a `now` function (tests pass a
//! controlled one); hold/keepalive timers are tokio sleeps armed from
//! FSM actions, exercised in tests via `start_paused`.
//!
//! Collision policy (§6.8, v1): the daemon admits at most one
//! connection per configured neighbor — a second is dropped at the
//! listener. The BGP-ID tiebreak is §Deferred (stream report).

use std::collections::BTreeMap;
use std::io;
use std::net::{IpAddr, Ipv4Addr};
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use common::IpPrefix;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tracing::{info, warn};

use crate::attr::{
    AddPathCtx, AsPath, MpNextHop, MpReach, Nlri, Origin, PathAttribute, UpdateHandling,
    UpdateOutcome,
};
use crate::capability::{AddPathFamily, Capability};
use crate::error::{self, BgpError, BgpResult};
use crate::fsm::{Action, Event, Fsm, SessionConfig, State};
use crate::message::{
    BgpMessage, BgpNotification, BgpOpen, BgpRouteRefresh, BgpUpdate, DecodedFrame, BGP_HEADER_LEN,
    BGP_MARKER, BGP_MAX_MESSAGE_LEN,
};
use crate::wire::hex;

/// What the session learned, for RIB bookkeeping.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PeerInfo {
    pub address: IpAddr,
    pub remote_as: u32,
    pub bgp_id: Option<Ipv4Addr>,
}

/// Adj-RIB-In sink: everything a received UPDATE does to the RIB.
/// M4's Loc-RIB implements this; tests record calls. Withdrawals
/// carry the (prefix, path-id) pairs (RFC 7911 §5: the replacement
/// key) — classic sessions use path-id 0.
pub trait RouteSink: Send {
    fn announce(&mut self, peer: &PeerInfo, update: &BgpUpdate);
    fn withdraw(&mut self, peer: &PeerInfo, prefixes: &[Nlri]);
    /// "Deletes all routes associated with this connection" (the
    /// Established teardown rows).
    fn clear_peer(&mut self, peer: &PeerInfo);
    /// RFC 4724 §4.2 (receiving speaker, GR negotiated): the session
    /// went down — retain the peer's routes, marked stale, instead of
    /// deleting them. Default: the non-GR behavior (delete).
    fn retain_stale(&mut self, peer: &PeerInfo) {
        self.clear_peer(peer);
    }
    /// Delete the peer's routes still marked stale (restart-timer
    /// expiry, or re-establishment without the R bit). Default:
    /// nothing (nothing was retained).
    fn flush_stale(&mut self, peer: &PeerInfo) {
        let _ = peer;
    }
    /// The End-of-RIB marker for one family arrived (RFC 4724 §3):
    /// routes of that family still stale from the peer are removed.
    /// Default: nothing.
    fn eor_received(&mut self, peer: &PeerInfo, afi: u16, safi: u8) {
        let _ = (peer, afi, safi);
    }
    /// A ROUTE-REFRESH arrived (RFC 2918 §4): the session answers from
    /// [`OutRib`] itself; the hook exists for observability.
    fn refresh_requested(&mut self, peer: &PeerInfo, afi: u16, safi: u8) {
        let _ = (peer, afi, safi);
    }

    /// We are about to send ROUTE-REFRESH to the peer (RFC 2918 §3,
    /// the SIGUSR1 path): the soft inbound reset begins here — the
    /// RIB may clear the peer's Adj-RIB-In so the re-advertised set
    /// is rebuilt against the current import policy, and prefixes
    /// the new policy rejects (or the peer omits) vanish (W2-d).
    fn refresh_sent(&mut self, peer: &PeerInfo) {
        let _ = peer;
    }
}

/// A no-op sink (sessions driven purely for their wire behavior).
pub struct NullSink;
impl RouteSink for NullSink {
    fn announce(&mut self, _: &PeerInfo, _: &BgpUpdate) {}
    fn withdraw(&mut self, _: &PeerInfo, _: &[Nlri]) {}
    fn clear_peer(&mut self, _: &PeerInfo) {}
}

/// Shareable sink wrapper (the daemon hands clones to session tasks).
pub struct SharedSink<T: RouteSink>(pub Arc<Mutex<T>>);

impl<T: RouteSink> Clone for SharedSink<T> {
    fn clone(&self) -> Self {
        Self(Arc::clone(&self.0))
    }
}

impl<T: RouteSink> RouteSink for SharedSink<T> {
    fn announce(&mut self, peer: &PeerInfo, update: &BgpUpdate) {
        self.0.lock().unwrap().announce(peer, update);
    }
    fn withdraw(&mut self, peer: &PeerInfo, prefixes: &[Nlri]) {
        self.0.lock().unwrap().withdraw(peer, prefixes);
    }
    fn clear_peer(&mut self, peer: &PeerInfo) {
        self.0.lock().unwrap().clear_peer(peer);
    }
    fn retain_stale(&mut self, peer: &PeerInfo) {
        self.0.lock().unwrap().retain_stale(peer);
    }
    fn flush_stale(&mut self, peer: &PeerInfo) {
        self.0.lock().unwrap().flush_stale(peer);
    }
    fn eor_received(&mut self, peer: &PeerInfo, afi: u16, safi: u8) {
        self.0.lock().unwrap().eor_received(peer, afi, safi);
    }
    fn refresh_requested(&mut self, peer: &PeerInfo, afi: u16, safi: u8) {
        self.0.lock().unwrap().refresh_requested(peer, afi, safi);
    }
    fn refresh_sent(&mut self, peer: &PeerInfo) {
        self.0.lock().unwrap().refresh_sent(peer);
    }
}

/// Adj-RIB-Out source: what this daemon advertises once Established
/// (v1: locally-originated networks; M4 adds Loc-RIB bests).
pub trait OutRib: Send + Sync {
    /// The full advertisement set for one (AFI, SAFI) toward one
    /// peer: `next_hop` is our session address (NEXT_HOP encoding),
    /// `to_peer` the remote (reflection filtering).
    fn advertisements(
        &self,
        afi: u16,
        safi: u8,
        next_hop: IpAddr,
        to_peer: IpAddr,
        internal: bool,
    ) -> Vec<BgpUpdate>;
    /// Families to advertise into.
    fn families(&self) -> Vec<(u16, u8)> {
        vec![(1, 1), (2, 1)]
    }
}

/// A sink that records what arrived (tests + the in-process speaker).
/// Keyed by (prefix, path-id) so ADD-PATH's sibling paths stay
/// distinct (RFC 7911 §5).
#[derive(Default)]
pub struct RecordingSink {
    pub announced: BTreeMap<Nlri, BgpUpdate>,
    pub withdrawn: Vec<Nlri>,
    pub cleared: usize,
    /// RFC 4724 hooks: retain-stale calls, flush-stale calls, and the
    /// End-of-RIB (afi, safi) pairs.
    pub retained: usize,
    pub flushed: usize,
    pub eors: Vec<(u16, u8)>,
}

impl RouteSink for RecordingSink {
    fn announce(&mut self, _peer: &PeerInfo, update: &BgpUpdate) {
        for nlri in update.announced() {
            self.announced.insert(nlri, update.clone());
        }
    }
    fn withdraw(&mut self, _peer: &PeerInfo, prefixes: &[Nlri]) {
        self.withdrawn.extend_from_slice(prefixes);
    }
    fn clear_peer(&mut self, _peer: &PeerInfo) {
        self.cleared += 1;
    }
    fn retain_stale(&mut self, _peer: &PeerInfo) {
        self.retained += 1;
    }
    fn flush_stale(&mut self, _peer: &PeerInfo) {
        self.flushed += 1;
    }
    fn eor_received(&mut self, _peer: &PeerInfo, afi: u16, safi: u8) {
        self.eors.push((afi, safi));
    }
}

/// Why a session ended.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SessionEnd {
    /// We sent a NOTIFICATION (code, subcode).
    Notified(u8, u8),
    /// We received one.
    PeerNotified { code: u8, subcode: u8 },
    /// Clean TCP close / transport error.
    Transport(String),
    /// ManualStop performed (SIGTERM path): a Cease NOTIFICATION was
    /// sent before returning (§6.7).
    ManualStop,
}

/// The "large" OpenSent hold (§8.2.2.3 suggests 4 minutes).
const HOLD_LARGE: Duration = Duration::from_secs(240);
/// Disarmed timers sleep here.
const FAR: Duration = Duration::from_secs(86_400 * 365);

/// Daemon-observable session state (the §6.8 collision machinery):
/// the BGP Identifier learned from the peer's OPEN and whether the
/// session reached Established — the two facts the collision verdict
/// keys on.
#[derive(Default)]
pub struct SessionShared {
    pub peer_bgp_id: std::sync::Mutex<Option<Ipv4Addr>>,
    pub established: std::sync::atomic::AtomicBool,
    /// The peer's Graceful Restart capability (RFC 4724 §3), read by
    /// the daemon after the session ends to arm the restart-timer
    /// flush of retained stale routes.
    pub peer_gr: std::sync::Mutex<Option<crate::fsm::GracefulRestartInfo>>,
}

impl SessionShared {
    fn note_open(&self, bgp_id: Ipv4Addr) {
        *self.peer_bgp_id.lock().unwrap() = Some(bgp_id);
    }

    fn note_gr(&self, gr: Option<crate::fsm::GracefulRestartInfo>) {
        *self.peer_gr.lock().unwrap() = gr;
    }

    fn note_established(&self) {
        self.established
            .store(true, std::sync::atomic::Ordering::SeqCst);
    }

    pub fn is_established(&self) -> bool {
        self.established.load(std::sync::atomic::Ordering::SeqCst)
    }
}

/// One live BGP session over an established stream.
pub struct PeerSession<IO> {
    io: IO,
    /// F7: the session's persistent read buffer. Frames are drained
    /// from it synchronously after every select cycle; a cancelled
    /// refill can never lose mid-frame bytes (see [`read_append`]).
    read_pending: Vec<u8>,
    fsm: Fsm,
    local_as: u32,
    local_hold: u16,
    local_id: Ipv4Addr,
    peer: PeerInfo,
    /// Our address on this session (NEXT_HOP / MP_REACH source).
    local_addr: IpAddr,
    /// Capabilities we advertise in OPEN.
    advertise: Vec<Capability>,
    out_rib: Option<Arc<dyn OutRib>>,
    hold_sleep: Pin<Box<tokio::time::Sleep>>,
    keepalive_sleep: Pin<Box<tokio::time::Sleep>>,
    /// Coarse per-peer MRAI gate (default 0 = off, FRR parity;
    /// §Deferred: per-prefix queues).
    mrai: Duration,
    next_advertisement: Option<Instant>,
    now: fn() -> Instant,
    /// UPDATE error handling for this session (RFC 7606 by default;
    /// strict-RFC-4271 is the per-neighbor compatibility knob).
    update_handling: UpdateHandling,
    /// Sending-side graceful restart (RFC 4724 §3, N5 scope): the
    /// restart time to advertise in the OPEN capability. EOR markers
    /// are emitted regardless (RFC 4724 §3 recommends them generally).
    gr_advertise: Option<u16>,
    /// RFC 4724 §4.1 (restarting speaker): this session re-establishes
    /// after our own abnormal loss — the R bit rides the OPEN and the
    /// initial Adj-RIB-Out dump defers until the peer's EOR or the
    /// Selection_Deferral_Timer.
    gr_restarted: bool,
    /// The §4.1 Selection_Deferral_Timer (default 120 s; the
    /// `graceful-restart deferral` knob).
    gr_deferral: Duration,
    /// The armed deferral deadline while [`Self::gr_restarted`] holds
    /// the initial dump (FAR = disarmed).
    deferral_sleep: Pin<Box<tokio::time::Sleep>>,
    /// A restarting session's initial dump is pending (§4.1: deferred
    /// route selection — nothing advertised until the peer's EOR or
    /// the timer).
    deferred_dump: bool,
    /// RFC 4724 §4.2: the teardown retained this peer's routes as
    /// stale (suppresses the FSM's clear_peer action; the daemon arms
    /// the restart-timer flush).
    gr_retained: bool,
    /// A deliberate close (ManualStop, received NOTIFICATION): no
    /// GR retention, the teardown clears as in RFC 4271.
    gr_hard_clear: bool,
    /// The GR capability the peer negotiated (captured when the OPEN
    /// lands — the FSM clears `negotiated` during teardown rows,
    /// before the actions perform).
    gr_negotiated: Option<crate::fsm::GracefulRestartInfo>,
    /// ADD-PATH transmit (RFC 7911): our own Path Identifiers for this
    /// peer, keyed by prefix — the B-19 per-peer monotonic-counter
    /// convention. The map IS the stability guarantee: a prefix keeps
    /// the id it was first assigned across re-advertisements (refresh
    /// re-dumps, attribute churn); a fresh prefix takes the next
    /// counter value; ids are never reused after withdrawal (§2 keys
    /// the pair per neighbor; monotonicity is the convention, not an
    /// RFC MUST).
    tx_path_ids: BTreeMap<IpPrefix, u32>,
    /// The monotonic counter backing [`Self::tx_path_ids`] (starts at
    /// 1; 0 is the classic no-ADD-PATH key and is never allocated).
    tx_next_path_id: u32,
    end: Option<SessionEnd>,
    /// Daemon-side observability (None in tests).
    shared: Option<Arc<SessionShared>>,
    /// The SAVNET agent hooks (experimental-savnet, default OFF, then
    /// default None — no agent hosted, no calls made): in-process
    /// reporting of SAV-relevant session events. Route installs and
    /// withdraws report at this file's `on_message` UPDATE arm
    /// (Adj-RIB-In granularity, pre-best-path); the adjacency reports
    /// ride the Established transition and the session's teardown.
    /// Nothing on the wire depends on any of it.
    #[cfg(feature = "experimental-savnet")]
    agent: Option<Arc<dyn sav::agent::SavAgent>>,
    /// Whether the adjacency-up report already fired (the exactly-once
    /// guard for the matching down report across the teardown paths).
    #[cfg(feature = "experimental-savnet")]
    sav_adjacency_up_reported: bool,
}

impl<IO> PeerSession<IO>
where
    IO: AsyncRead + AsyncWrite + Unpin,
{
    pub fn new(
        io: IO,
        local: SessionConfig,
        peer: PeerInfo,
        local_addr: IpAddr,
        out_rib: Option<Arc<dyn OutRib>>,
        mrai: Duration,
    ) -> Self {
        let mut advertise = vec![
            Capability::Multiprotocol { afi: 1, safi: 1 },
            Capability::Multiprotocol { afi: 2, safi: 1 },
            Capability::RouteRefresh,
            Capability::FourOctetAsNumber {
                asn: local.local_as,
            },
        ];
        // RFC 7911 §4 (both directions): one capability instance, one
        // tuple per locally-enabled family — Send/Receive 1 for rx, 2
        // for tx, 3 for both. Never advertised by default (classic
        // encoding); the single-instance MUST rules the shape.
        let sr = |rx: bool, tx: bool| (rx as u8) | ((tx as u8) << 1);
        let add_path_tuples = [
            (local.add_path_rx_v4 || local.add_path_tx_v4).then_some(AddPathFamily {
                afi: 1,
                safi: 1,
                send_receive: sr(local.add_path_rx_v4, local.add_path_tx_v4),
            }),
            (local.add_path_rx_v6 || local.add_path_tx_v6).then_some(AddPathFamily {
                afi: 2,
                safi: 1,
                send_receive: sr(local.add_path_rx_v6, local.add_path_tx_v6),
            }),
        ]
        .into_iter()
        .flatten()
        .collect::<Vec<_>>();
        if !add_path_tuples.is_empty() {
            advertise.push(Capability::AddPath(add_path_tuples));
        }
        let now = tokio::time::Instant::now();
        Self {
            io,
            read_pending: Vec::new(),
            fsm: Fsm::new(local.clone()),
            local_as: local.local_as,
            local_hold: local.hold_time,
            local_id: local.local_id,
            peer,
            local_addr,
            advertise,
            out_rib,
            hold_sleep: Box::pin(tokio::time::sleep_until(now + FAR)),
            keepalive_sleep: Box::pin(tokio::time::sleep_until(now + FAR)),
            mrai,
            next_advertisement: None,
            now: Instant::now,
            update_handling: UpdateHandling::default(),
            gr_advertise: None,
            gr_restarted: false,
            gr_deferral: Duration::from_secs(crate::config::GR_DEFERRAL_DEFAULT as u64),
            deferral_sleep: Box::pin(tokio::time::sleep_until(now + FAR)),
            deferred_dump: false,
            gr_retained: false,
            gr_hard_clear: false,
            gr_negotiated: None,
            tx_path_ids: BTreeMap::new(),
            tx_next_path_id: 1,
            end: None,
            shared: None,
            #[cfg(feature = "experimental-savnet")]
            agent: None,
            #[cfg(feature = "experimental-savnet")]
            sav_adjacency_up_reported: false,
        }
    }

    /// Host a SAVNET agent (experimental-savnet; see
    /// docs/protocols/savnet.md): the session reports SAV-relevant
    /// events in-process — route installs/withdraws at the UPDATE arm,
    /// adjacency up at Established, adjacency down at teardown.
    /// Monitor-only by contract: the agent's suggestions are logged
    /// observations, never enforcement inputs.
    #[cfg(feature = "experimental-savnet")]
    pub fn with_sav_agent(mut self, agent: Arc<dyn sav::agent::SavAgent>) -> Self {
        self.agent = Some(agent);
        self
    }

    /// Report the SAVNET adjacency-down (experimental-savnet), exactly
    /// once, on the canonical teardown paths (the FSM Idle exit, the
    /// received NOTIFICATION, the transport failure). Mid-send error
    /// paths rely on the agent's documented unordered-input tolerance.
    #[cfg(feature = "experimental-savnet")]
    fn sav_adjacency_down(&mut self) {
        if self.sav_adjacency_up_reported {
            self.sav_adjacency_up_reported = false;
            if let Some(agent) = &self.agent {
                agent.on_event(sav::agent::SavAgentEvent::AdjacencyDown {
                    protocol: sav::agent::SavProtocol::Bgp,
                    peer: self.sav_peer(),
                });
            }
        }
    }

    /// The SAV-layer peer identity for this session.
    #[cfg(feature = "experimental-savnet")]
    fn sav_peer(&self) -> sav::agent::SavPeer {
        sav::agent::SavPeer {
            address: self.peer.address,
            remote_id: self.peer.remote_as,
        }
    }

    /// Publish session state for the daemon's §6.8 collision logic.
    pub fn with_shared(mut self, shared: Arc<SessionShared>) -> Self {
        self.shared = Some(shared);
        self
    }

    /// Set the UPDATE error-handling mode (RFC 7606 default;
    /// `strict-rfc4271` per neighbor for the RFC 4271 session-reset
    /// behavior).
    pub fn with_update_handling(mut self, handling: UpdateHandling) -> Self {
        self.update_handling = handling;
        self
    }

    /// Advertise the Graceful Restart capability (RFC 4724 §3, the
    /// sending side): the given Restart Time, no restart state, both
    /// unicast families with the Forwarding bit clear (v1 does not
    /// claim forwarding-state preservation for families beyond the
    /// memory-only RIB's reach — F-bit granularity is §Deferred).
    /// The Graceful Notification (N) bit rides every capability we
    /// advertise (RFC 8538 §2): bgpd implements §3.1/§3.2/§4.1, so
    /// it can both send and receive NOTIFICATIONs under the
    /// graceful-restart procedures.
    pub fn with_graceful_restart(mut self, restart_time: u16) -> Self {
        self.gr_advertise = Some(restart_time);
        self.advertise.push(Capability::GracefulRestart {
            restart_state: false,
            graceful_notification: true,
            restart_time,
            families: vec![(1, 1, false), (2, 1, false)],
        });
        self
    }

    /// RFC 4724 §4.1 (restarting speaker): this session re-establishes
    /// after OUR abnormal loss — flip the advertised Restart State
    /// bit, so the peer retains the routes we advertised before the
    /// restart for the advertised Restart Time and does not wait for
    /// our End-of-RIB before advertising. Call after
    /// [`Self::with_graceful_restart`]; rewrites the capability in
    /// place. The same call arms the §4.1 selection deferral: the
    /// initial Adj-RIB-Out dump (and its EOR markers) waits for the
    /// peer's EOR or the Selection_Deferral_Timer.
    pub fn with_restart_state(mut self) -> Self {
        self.gr_restarted = true;
        for cap in self.advertise.iter_mut() {
            if let Capability::GracefulRestart { restart_state, .. } = cap {
                *restart_state = true;
            }
        }
        self
    }

    /// Override the RFC 4724 §4.1 Selection_Deferral_Timer (the upper
    /// bound the restarting speaker's deferred initial dump waits for
    /// the peer's End-of-RIB; default 120 s, `graceful-restart
    /// deferral <1-3600>`).
    pub fn with_gr_deferral(mut self, secs: u32) -> Self {
        self.gr_deferral = Duration::from_secs(secs.max(1) as u64);
        self
    }

    /// The handling in force for the current stream position: the
    /// configured mode, with RFC 7606's `internal` refinement from
    /// the negotiated session type (the LOCAL_PREF §7 row).
    fn current_update_handling(&self) -> UpdateHandling {
        match self.update_handling {
            UpdateHandling::Rfc7606 { .. } => UpdateHandling::Rfc7606 {
                internal: self.fsm.negotiated().is_some_and(|n| n.internal),
            },
            strict => strict,
        }
    }

    /// The ADD-PATH direction inbound UPDATEs decode under: extended
    /// NLRI (RFC 7911 §3) only per the §5 negotiation — locally
    /// configured rx AND the peer offered to send (S/R 2/3) for the
    /// family. Everything else decodes classic; extended bytes under
    /// a classic gate mis-parse (the path ID's top octet reads as a
    /// prefix length — the /0 hazard), which is exactly why the gate
    /// is the negotiated fact, not a wire guess.
    fn current_add_path_ctx(&self) -> AddPathCtx {
        match self.fsm.negotiated() {
            Some(n) => AddPathCtx {
                v4: n.add_path_rx_v4,
                v6: n.add_path_rx_v6,
            },
            None => AddPathCtx::default(),
        }
    }

    /// The ADD-PATH direction outbound UPDATEs encode under (RFC 7911
    /// §5, the transmit MUST): extended NLRI only toward a peer that
    /// negotiated it — locally configured tx AND the peer offered
    /// S/R 1/3 (willing to receive) for the family.
    fn current_add_path_tx_ctx(&self) -> AddPathCtx {
        match self.fsm.negotiated() {
            Some(n) => AddPathCtx {
                v4: n.add_path_tx_v4,
                v6: n.add_path_tx_v6,
            },
            None => AddPathCtx::default(),
        }
    }

    /// Our Path Identifier for `prefix` toward this peer (RFC 7911
    /// §2): stable once assigned (the re-advertisement keeps its id),
    /// fresh prefixes take the next monotonic value, 0 is never
    /// returned (the classic key).
    fn tx_id_for(&mut self, prefix: IpPrefix) -> u32 {
        if let Some(id) = self.tx_path_ids.get(&prefix) {
            return *id;
        }
        let id = self.tx_next_path_id;
        self.tx_next_path_id = self.tx_next_path_id.saturating_add(1);
        self.tx_path_ids.insert(prefix, id);
        id
    }

    /// Stamps our path ids onto every NLRI field of an outbound UPDATE
    /// whose family negotiated ADD-PATH transmit (RFC 7911 §3): v4
    /// top-level NLRI and withdrawn, v6 MP_REACH/MP_UNREACH lists.
    /// Withdrawals look up the same map, so they carry exactly the id
    /// the announcement used — the receiver's replacement key (§5).
    /// Fields of a classic (non-negotiated) family are left untouched
    /// (id 0; the codec would refuse otherwise).
    fn assign_tx_path_ids(&mut self, update: &mut BgpUpdate) {
        let ctx = self.current_add_path_tx_ctx();
        if ctx.v4 {
            for nlri in update.nlri.iter_mut().chain(update.withdrawn.iter_mut()) {
                nlri.path_id = self.tx_id_for(nlri.prefix);
            }
        }
        if ctx.v6 {
            for attr in update.attrs.iter_mut() {
                match attr {
                    PathAttribute::MpReach(mp) => {
                        for nlri in mp.nlri.iter_mut() {
                            nlri.path_id = self.tx_id_for(nlri.prefix);
                        }
                    }
                    PathAttribute::MpUnreach(mp) => {
                        for nlri in mp.withdrawn.iter_mut() {
                            nlri.path_id = self.tx_id_for(nlri.prefix);
                        }
                    }
                    _ => {}
                }
            }
        }
    }

    /// Override the clock (tests).
    pub fn set_clock(&mut self, now: fn() -> Instant) {
        self.now = now;
    }

    pub fn state(&self) -> State {
        self.fsm.state()
    }

    /// Drives the session to termination. Assumes the TCP connection
    /// is established (the connector/listener hands over a live
    /// stream), so the FSM is jumped to OpenSent per Events 16/17.
    pub async fn run<S: RouteSink>(&mut self, sink: &mut S) -> SessionEnd {
        self.run_inner(sink, None, None).await
    }

    /// [`Self::run`] plus daemon signals: `stop` fires ManualStop
    /// (Cease in Established, §6.7 — the SIGTERM path) and `refresh`
    /// sends ROUTE-REFRESH to the peer per family (RFC 2918 — the
    /// SIGUSR1 path).
    pub async fn run_with_signals<S: RouteSink>(
        &mut self,
        sink: &mut S,
        mut stop: tokio::sync::watch::Receiver<bool>,
        mut refresh: tokio::sync::watch::Receiver<u64>,
    ) -> SessionEnd {
        self.run_inner(sink, Some(&mut stop), Some(&mut refresh))
            .await
    }

    async fn run_inner<S: RouteSink>(
        &mut self,
        sink: &mut S,
        mut stop: Option<&mut tokio::sync::watch::Receiver<bool>>,
        mut refresh: Option<&mut tokio::sync::watch::Receiver<u64>>,
    ) -> SessionEnd {
        self.fsm.fire(Event::Start { passive: false });
        let actions = self.fsm.fire(Event::TcpConnectionConfirmed);
        if let Err(e) = self.perform_all(actions, sink).await {
            return SessionEnd::Transport(e.to_string());
        }
        loop {
            if self.fsm.state() == State::Idle {
                return self
                    .end
                    .clone()
                    .unwrap_or(SessionEnd::Transport("session closed".into()));
            }
            let asn4 = self.fsm.negotiated().is_none_or(|n| n.asn4);
            let handling = self.current_update_handling();
            let add_path = self.current_add_path_ctx();
            // F7: drain every complete frame already buffered before
            // waiting again. Bytes reach `read_pending` through a
            // single bounded `read`, which consumes socket bytes only
            // when its poll returns Ready — and Ready selects this
            // branch — so no mid-frame state can be lost to a dropped
            // future. The old multi-`read_exact` reader could lose an
            // already-consumed header or body half exactly when a
            // timer branch won the select, desyncing the stream
            // ("marker is not all ones", §6.1).
            while let FrameTake::Frame(read) =
                take_frame(&mut self.read_pending, asn4, handling, add_path)
            {
                match read {
                    Ok(decoded) => {
                        if let Some(end) = self.on_message(decoded, sink).await {
                            return end;
                        }
                    }
                    Err(bgp_err) => {
                        // Route the malformed message to the right
                        // FSM error event by class (§6.1-§6.3).
                        let event = match bgp_err.notification {
                            Some((1, sub)) => Event::BgpHeaderErr(1, sub),
                            Some((2, sub)) => Event::BgpOpenMsgErr(2, sub),
                            // §6.3: the prescribed subcode rides the
                            // NOTIFICATION (previously flattened to 1).
                            other => Event::UpdateMsgErr(3, other.map(|(_, s)| s).unwrap_or(1)),
                        };
                        warn!(?bgp_err, peer = %self.peer.address, "bgpd: malformed message");
                        if let Some(end) = self.step(event, sink).await {
                            return end;
                        }
                    }
                }
            }
            tokio::select! {
                read = read_append(&mut self.io, &mut self.read_pending) => {
                    match read {
                        Ok(0) => {
                            // EOF: the peer closed the socket.
                            let actions = self.fsm.fire(Event::TcpConnectionFails);
                            let _ = self.perform_all(actions, sink).await;
                            #[cfg(feature = "experimental-savnet")]
                            self.sav_adjacency_down();
                            self.end = Some(SessionEnd::Transport("connection closed".into()));
                            return self.end.clone().unwrap();
                        }
                        Ok(_) => {}
                        Err(io_err) => {
                            let actions = self.fsm.fire(Event::TcpConnectionFails);
                            let _ = self.perform_all(actions, sink).await;
                            #[cfg(feature = "experimental-savnet")]
                            self.sav_adjacency_down();
                            self.end = Some(SessionEnd::Transport(io_err.to_string()));
                            return self.end.clone().unwrap();
                        }
                    }
                }
                _ = &mut self.hold_sleep => {
                    if let Some(end) = self.step(Event::HoldTimerExpires, sink).await {
                        return end;
                    }
                }
                _ = &mut self.keepalive_sleep => {
                    if let Some(end) = self.step(Event::KeepaliveTimerExpires, sink).await {
                        return end;
                    }
                }
                _ = &mut self.deferral_sleep => {
                    // RFC 4724 §4.1: the Selection_Deferral_Timer
                    // expired without the peer's EOR — proceed with
                    // route selection (flush the retained stale) and
                    // run the initial dump anyway.
                    if self.deferred_dump {
                        self.deferred_dump = false;
                        info!(peer = %self.peer.address,
                            "bgpd: GR selection deferral timer expired, proceeding (RFC 4724 §4.1)");
                        sink.flush_stale(&self.peer);
                        if let Err(e) = self.initial_dump().await {
                            self.end = Some(SessionEnd::Transport(e.to_string()));
                            return self.end.clone().unwrap();
                        }
                    }
                }
                changed = async {
                    match stop.as_mut() {
                        Some(stop) => stop.changed().await.is_ok() && *stop.borrow(),
                        None => std::future::pending().await,
                    }
                }, if stop.is_some() => {
                    if changed {
                        if let Some(end) = self.step(Event::ManualStop, sink).await {
                            return end;
                        }
                    }
                }
                bumped = async {
                    match refresh.as_mut() {
                        Some(refresh) => refresh.changed().await.is_ok(),
                        None => std::future::pending().await,
                    }
                }, if refresh.is_some() && self.fsm.state() == State::Established => {
                    if bumped {
                        // The soft inbound reset (RFC 2918 §3, W2-d):
                        // the RIB clears the Adj-RIB-In so the
                        // re-advertised set rebuilds against the
                        // current import policy.
                        sink.refresh_sent(&self.peer);
                        if let Err(e) = self.send_refresh_requests().await {
                            self.end = Some(SessionEnd::Transport(e.to_string()));
                            return self.end.clone().unwrap();
                        }
                    }
                }
            }
        }
    }

    /// One ROUTE-REFRESH per family both sides negotiated (v1:
    /// v4/v6 unicast when the capability was agreed).
    async fn send_refresh_requests(&mut self) -> io::Result<()> {
        let negotiated = self.fsm.negotiated();
        if !negotiated.is_some_and(|n| n.route_refresh) {
            return Ok(());
        }
        for afi in [1u16, 2u16] {
            let message = crate::message::route_refresh(afi, 1);
            self.write_message(&message).await?;
        }
        Ok(())
    }

    /// Fire one event, perform its actions; Some(end) when the session
    /// is over.
    async fn step<S: RouteSink>(&mut self, event: Event, sink: &mut S) -> Option<SessionEnd> {
        let was = self.fsm.state();
        if matches!(event, Event::ManualStop) {
            self.gr_hard_clear = true;
        }
        let actions = self.fsm.fire(event.clone());
        // Capture the peer's GR capability while the negotiation
        // record still exists (teardown rows clear it).
        if let Some(n) = self.fsm.negotiated() {
            self.gr_negotiated = n.graceful_restart;
        }
        if let Err(e) = self.perform_all(actions, sink).await {
            self.end = Some(SessionEnd::Transport(e.to_string()));
            return self.end.clone();
        }
        if self.fsm.state() == State::Established && was != State::Established {
            let n = self.fsm.negotiated();
            info!(
                peer = %self.peer.address,
                remote_as = n.map(|x| x.peer_as).unwrap_or(0),
                hold = n.map(|x| x.hold_time).unwrap_or(0),
                "bgpd: session Established"
            );
            // The SAVNET adjacency-up report (experimental-savnet):
            // in-process, monitor-only consumer; the session knows
            // addresses, not kernel interfaces, so no ifindex rides
            // tonight.
            #[cfg(feature = "experimental-savnet")]
            if let Some(agent) = &self.agent {
                self.sav_adjacency_up_reported = true;
                agent.on_event(sav::agent::SavAgentEvent::AdjacencyUp {
                    protocol: sav::agent::SavProtocol::Bgp,
                    peer: self.sav_peer(),
                    ifindex: None,
                });
            }
            if let Some(shared) = &self.shared {
                shared.note_established();
            }
            // RFC 4724 §4.2 (receiving speaker): the peer's OPEN said
            // whether it restarted. With the R bit set, stale routes
            // stay until the per-family End-of-RIB; without it, they
            // are deleted immediately — before the new exchange.
            match self.fsm.negotiated().and_then(|n| n.graceful_restart) {
                Some(gr) if gr.restart_state => {
                    info!(peer = %self.peer.address,
                        restart_time = gr.restart_time,
                        "bgpd: peer restarted (R bit), stale routes retained until EOR (RFC 4724 §4.2)");
                }
                Some(_) => {
                    info!(peer = %self.peer.address,
                        "bgpd: session re-established without restart state, flushing stale routes");
                    sink.flush_stale(&self.peer);
                }
                None => {}
            }
            if let Err(e) = self.on_established().await {
                self.end = Some(SessionEnd::Transport(e.to_string()));
                return self.end.clone();
            }
        }
        if self.fsm.state() == State::Idle {
            #[cfg(feature = "experimental-savnet")]
            self.sav_adjacency_down();
            self.end = Some(match event {
                Event::ManualStop => SessionEnd::ManualStop,
                _ => self
                    .end
                    .clone()
                    .unwrap_or(SessionEnd::Transport("session closed".into())),
            });
        }
        self.end.clone()
    }

    async fn on_message<S: RouteSink>(
        &mut self,
        decoded: DecodedFrame,
        sink: &mut S,
    ) -> Option<SessionEnd> {
        let message = decoded.message;
        match message {
            BgpMessage::Open(open) => {
                // §6.2: the peer's AS must match the configured one.
                if open.peer_as4() != self.peer.remote_as {
                    return self
                        .step(
                            Event::BgpOpenMsgErr(
                                error::error_code::OPEN_MESSAGE,
                                error::open_subcode::BAD_PEER_AS,
                            ),
                            sink,
                        )
                        .await;
                }
                self.peer.bgp_id = Some(open.bgp_id);
                if let Some(shared) = &self.shared {
                    shared.note_open(open.bgp_id);
                    shared.note_gr(open.graceful_restart());
                }
                self.step(Event::BgpOpen(open), sink).await
            }
            BgpMessage::Keepalive => self.step(Event::KeepAliveMsg, sink).await,
            BgpMessage::Update(update) => {
                // RFC 4724 §3: an UPDATE with no reachable and no
                // withdrawn NLRI is the End-of-RIB marker — the
                // stale-flush trigger for the family (v4-unicast's is
                // the bare minimum UPDATE; MP families carry an empty
                // MP_UNREACH naming theirs).
                if let Some(family) = update.end_of_rib() {
                    let (afi, safi) = family.unwrap_or((1, 1));
                    info!(peer = %self.peer.address, afi, safi,
                        "bgpd: End-of-RIB received (RFC 4724)");
                    sink.eor_received(&self.peer, afi, safi);
                    // RFC 4724 §4.1 (restarting speaker): the peer's
                    // EOR ends the selection deferral — re-selection
                    // happened above (that family's stale flushed),
                    // the initial dump follows, closed by our own EOR.
                    // (v1 coarse: the FIRST family's EOR ends it —
                    // same coarseness as the family-presence R-bit
                    // handling, disclosed.)
                    if self.deferred_dump {
                        self.deferred_dump = false;
                        self.disarm_deferral();
                        info!(peer = %self.peer.address,
                            "bgpd: EOR ended the selection deferral, advertising (RFC 4724 §4.1)");
                        if let Err(e) = self.initial_dump().await {
                            self.end = Some(SessionEnd::Transport(e.to_string()));
                            return Some(self.end.clone().unwrap());
                        }
                    }
                    return self.step(Event::UpdateMsg, sink).await;
                }
                // F3: first-AS enforcement at import, RFC 4271 §6.3 —
                // "If the UPDATE message is received from an external
                // peer, the local system MAY check whether the leftmost
                // (with respect to the position of octets in the
                // protocol message) AS in the AS_PATH attribute is
                // equal to the autonomous system number of the peer
                // that sent the message. If the check determines this
                // is not the case, the Error Subcode MUST be set to
                // Malformed AS_PATH." The §6.3 preamble prescribes the
                // wire answer for every detected error — "All errors
                // detected while processing an UPDATE message MUST be
                // indicated by sending the NOTIFICATION message with
                // the Error Code UPDATE Message Error" — so the
                // violation is UPDATE Message Error / Malformed AS_PATH
                // (3/11) and the session resets (FRR's default-on
                // `bgp enforce-first-as`, `aspath_firstas_check`).
                // iBGP is exempt by the rule's own scope ("received
                // from an external peer"): §9.2 dissemination leaves an
                // internal peer's path untouched, so it may open with
                // any AS. The check runs on the decoded path before
                // the RFC 7606 disposition arms — FRR enforces at
                // attribute-parse time, ahead of its own revised
                // handling.
                if self.peer.remote_as != self.local_as {
                    if let Some(path) = update.as_path() {
                        if path.leftmost_as() != Some(self.peer.remote_as) {
                            warn!(peer = %self.peer.address,
                                leftmost = ?path.leftmost_as(),
                                expected = self.peer.remote_as,
                                "bgpd: UPDATE rejected, first AS not the peer's (RFC 4271 §6.3)");
                            return self
                                .step(
                                    Event::UpdateMsgErr(
                                        error::error_code::UPDATE_MESSAGE,
                                        error::update_subcode::MALFORMED_AS_PATH,
                                    ),
                                    sink,
                                )
                                .await;
                        }
                    }
                }
                // RFC 7606's structured outcome (B-1): the explicit
                // third disposition. §3(d)'s missing well-known
                // mandatory attributes and §5.2's escalation fold in
                // at the decode; §6's full-UPDATE log line rides here.
                match decoded.outcome {
                    UpdateOutcome::Withdrawn { routes, causes } => {
                        // §2: "treat the UPDATE ... as though all
                        // contained routes had been withdrawn" — the
                        // announced prefixes leave the Adj-RIB-In, the
                        // explicit withdrawals still apply, and the
                        // session itself is unaffected. §6: "logging
                        // an error listing the NLRI involved and
                        // containing the entire malformed UPDATE
                        // message".
                        warn!(peer = %self.peer.address,
                            nlri = ?routes.iter().map(|n| n.to_string()).collect::<Vec<_>>(),
                            attrs = ?causes.iter().map(|(t, _)| *t).collect::<Vec<_>>(),
                            update = %hex(&decoded.frame),
                            "bgpd: malformed UPDATE treated as withdrawal (RFC 7606 §2, §6)");
                        #[cfg(feature = "experimental-savnet")]
                        if let Some(agent) = &self.agent {
                            let source = sav::agent::SavEventSource::Bgp(self.sav_peer());
                            for nlri in &routes {
                                agent.on_event(sav::agent::SavAgentEvent::RouteWithdrawn {
                                    source: source.clone(),
                                    prefix: nlri.prefix,
                                });
                            }
                        }
                        sink.withdraw(&self.peer, &routes);
                        return self.step(Event::UpdateMsg, sink).await;
                    }
                    UpdateOutcome::Discarded(causes) => {
                        warn!(peer = %self.peer.address,
                            nlri = ?update.announced().iter().map(|n| n.to_string()).collect::<Vec<_>>(),
                            attrs = ?causes,
                            update = %hex(&decoded.frame),
                            "bgpd: malformed attributes discarded, UPDATE processed (RFC 7606 §2, §6)");
                    }
                    UpdateOutcome::Clean => {}
                }
                // §9.5: discard UPDATEs whose AS_PATH carries our own
                // AS (loop); the connection itself is unaffected.
                let local_as = self.local_as;
                let loops = update.as_path().is_some_and(|p| {
                    p.segments.iter().any(|seg| match seg {
                        crate::attr::AsSegment::Set(v) | crate::attr::AsSegment::Sequence(v) => {
                            v.contains(&local_as)
                        }
                    })
                });
                if loops {
                    warn!(peer = %self.peer.address, "bgpd: UPDATE rejected, own AS in AS_PATH (§9.5)");
                    return self.step(Event::UpdateMsg, sink).await;
                }
                let withdrawn = update.withdrawn_all();
                // F5 keeps the hot path O(1): counts, never the full
                // announced-prefix string list — but a bounded
                // four-entry preview rides along (path ids included:
                // the ADD-PATH observability the interop smokes pin;
                // bench feed updates pack 64 prefixes, so the preview
                // stays tiny where the list was the problem).
                let announced = update.announced();
                let mut preview = String::new();
                for nlri in announced.iter().take(4) {
                    if !preview.is_empty() {
                        preview.push_str(", ");
                    }
                    preview.push_str(&nlri.to_string());
                }
                if announced.len() > 4 {
                    preview.push_str(", +");
                }
                info!(
                    peer = %self.peer.address,
                    announced = announced.len(),
                    withdrawn = withdrawn.len(),
                    paths = %preview,
                    "bgpd: UPDATE received"
                );
                // The SAVNET route-event reports (experimental-savnet):
                // Adj-RIB-In granularity — every announced/withdrawn
                // prefix at the same point the RIB sink learns it
                // (pre-best-path, the RFC 8704 §3.1 candidate space).
                // ADD-PATH siblings report per prefix (the SAV view
                // is prefix-shaped; path IDs are BGP-internal).
                #[cfg(feature = "experimental-savnet")]
                if let Some(agent) = &self.agent {
                    let source = sav::agent::SavEventSource::Bgp(self.sav_peer());
                    let nexthop = bgp_next_hop(&update);
                    for nlri in update.announced() {
                        agent.on_event(sav::agent::SavAgentEvent::RouteInstalled {
                            source: source.clone(),
                            prefix: nlri.prefix,
                            nexthop,
                        });
                    }
                    for nlri in &withdrawn {
                        agent.on_event(sav::agent::SavAgentEvent::RouteWithdrawn {
                            source: source.clone(),
                            prefix: nlri.prefix,
                        });
                    }
                }
                sink.announce(&self.peer, &update);
                sink.withdraw(&self.peer, &withdrawn);
                self.step(Event::UpdateMsg, sink).await
            }
            BgpMessage::Notification(n) => {
                let hard = n.is_hard_reset();
                // RFC 8538 §4: "if a BGP speaker has received the 'N'
                // bit from a peer" and receives a NOTIFICATION that is
                // not a Hard Reset, it follows the Receiving Speaker
                // rules (§4.1: "MUST retain the routes received from
                // the peer ... MUST mark them as stale routing
                // information"). A Hard Reset is the exception (§3.2:
                // "Whenever a BGP speaker receives a Hard Reset, the
                // speaker MUST terminate the BGP session following the
                // standard procedures in [RFC4271]" — the RFC 4271
                // delete). Without the N bit the RFC 4724 §4.2 rule
                // stands: a peer-chosen close is deliberate, no
                // retention.
                let n_exchanged = self
                    .gr_negotiated
                    .is_some_and(|gr| gr.graceful_notification);
                if hard || !n_exchanged {
                    self.gr_hard_clear = true;
                }
                if hard {
                    info!(
                        reason = ?n.hard_reset_reason().map(|r| (r.code, r.subcode)),
                        peer = %self.peer.address,
                        "bgpd: Hard Reset received (RFC 8538 §3.2), terminating per RFC 4271"
                    );
                }
                info!(
                    code = n.code,
                    subcode = n.subcode,
                    graceful = n_exchanged && !hard,
                    peer = %self.peer.address,
                    "bgpd: NOTIFICATION received"
                );
                let actions = self.fsm.fire(Event::NotifMsg);
                let _ = self.perform_all(actions, sink).await;
                #[cfg(feature = "experimental-savnet")]
                self.sav_adjacency_down();
                self.end = Some(SessionEnd::PeerNotified {
                    code: n.code,
                    subcode: n.subcode,
                });
                self.end.clone()
            }
            BgpMessage::RouteRefresh(rr) => self.on_route_refresh(rr, sink).await,
        }
    }

    /// RFC 2918 §4: re-advertise the Adj-RIB-Out for the requested
    /// family.
    async fn on_route_refresh<S: RouteSink>(
        &mut self,
        rr: BgpRouteRefresh,
        sink: &mut S,
    ) -> Option<SessionEnd> {
        if self.fsm.state() != State::Established {
            warn!("bgpd: ROUTE-REFRESH outside Established, ignored");
            return None;
        }
        if !self.fsm.negotiated().is_some_and(|n| n.route_refresh) {
            warn!("bgpd: ROUTE-REFRESH without capability, ignored");
            return None;
        }
        info!(peer = %self.peer.address, afi = rr.afi, safi = rr.safi,
            "bgpd: ROUTE-REFRESH received, re-advertising");
        sink.refresh_requested(&self.peer, rr.afi, rr.safi);
        let next_hop = self.local_addr;
        let to_peer = self.peer.address;
        let internal = self.fsm.negotiated().is_some_and(|n| n.internal);
        if let Some(rib) = self.out_rib.clone() {
            for mut update in rib.advertisements(rr.afi, rr.safi, next_hop, to_peer, internal) {
                if let Err(e) = self.send_update(&mut update).await {
                    self.end = Some(SessionEnd::Transport(e.to_string()));
                    return self.end.clone();
                }
            }
        }
        None
    }

    /// The Established transition: the initial advertisement of the
    /// Adj-RIB-Out. A restarting speaker (RFC 4724 §4.1) defers it —
    /// route selection waits for the peer's End-of-RIB markers or the
    /// Selection_Deferral_Timer; the deferred flushes live in the
    /// UPDATE arm (EOR) and the select loop (timer).
    async fn on_established(&mut self) -> io::Result<()> {
        if self.gr_restarted {
            self.deferred_dump = true;
            self.deferral_sleep
                .as_mut()
                .reset(tokio::time::Instant::now() + self.gr_deferral);
            info!(peer = %self.peer.address, deferral = ?self.gr_deferral,
                "bgpd: restarting speaker, initial dump deferred until EOR (RFC 4724 §4.1)");
            return Ok(());
        }
        self.initial_dump().await
    }

    /// The initial Adj-RIB-Out advertisement for every family, each
    /// dump closed by its End-of-RIB marker (RFC 4724 §3 — recommended
    /// generally, and §4.1's MUST after a restart's initial update; an
    /// empty UPDATE is a no-op for a non-GR receiver).
    async fn initial_dump(&mut self) -> io::Result<()> {
        let families = match self.out_rib.as_ref() {
            Some(rib) => rib.families(),
            // No Adj-RIB-Out source: still close the default
            // families' (empty) dumps with their markers.
            None => vec![(1, 1), (2, 1)],
        };
        let next_hop = self.local_addr;
        let to_peer = self.peer.address;
        let internal = self.fsm.negotiated().is_some_and(|n| n.internal);
        for (afi, safi) in families {
            if let Some(rib) = self.out_rib.clone() {
                for mut update in rib.advertisements(afi, safi, next_hop, to_peer, internal) {
                    self.send_update(&mut update).await?;
                }
            }
            let mut marker = BgpUpdate::end_of_rib_marker(afi, safi);
            self.send_update(&mut marker).await?;
        }
        Ok(())
    }

    async fn perform_all<S: RouteSink>(
        &mut self,
        actions: Vec<Action>,
        sink: &mut S,
    ) -> io::Result<()> {
        for action in actions {
            self.perform(action, sink).await?;
        }
        Ok(())
    }

    async fn perform<S: RouteSink>(&mut self, action: Action, sink: &mut S) -> io::Result<()> {
        let negotiated_hold = self.fsm.negotiated().map(|n| n.hold_time).unwrap_or(0);
        match action {
            Action::ConnectTcp
            | Action::StartConnectRetry
            | Action::RestartConnectRetry
            | Action::StopConnectRetry => {
                // The connector task's domain (see daemon).
            }
            Action::CloseTcp => {
                let _ = self.io.shutdown().await;
            }
            Action::SendOpen => {
                let open = BgpOpen::new(
                    self.local_as,
                    self.local_hold,
                    self.local_id,
                    self.advertise.clone(),
                );
                self.write_message(&BgpMessage::Open(open)).await?;
            }
            Action::SendKeepalive => {
                self.write_message(&BgpMessage::Keepalive).await?;
            }
            Action::Notify(code, subcode) => {
                let plain = BgpNotification {
                    code,
                    subcode,
                    data: Vec::new(),
                };
                // RFC 8538 §5.1's send-side classification (toward an
                // N-bit peer only): the permanent Cease reasons ride as
                // a Hard Reset wrapping the reason; everything else —
                // transient Cease subcodes, wire-error codes ("use of
                // Hard Reset does not appear to be indicated") — goes
                // plain. A graceful close of an N session lets the
                // peer retain our routes per §4.1.
                let n_exchanged = self
                    .gr_negotiated
                    .is_some_and(|gr| gr.graceful_notification);
                let notification = plain.wrapped_for_n_peer(n_exchanged);
                info!(
                    code, subcode, hard_reset = notification.is_hard_reset(),
                    peer = %self.peer.address,
                    "bgpd: sending NOTIFICATION"
                );
                self.end = Some(SessionEnd::Notified(
                    notification.code,
                    notification.subcode,
                ));
                self.write_message(&BgpMessage::Notification(notification))
                    .await?;
                let _ = self.io.shutdown().await;
            }
            Action::SetHoldLarge => {
                self.hold_sleep
                    .as_mut()
                    .reset(tokio::time::Instant::now() + HOLD_LARGE);
            }
            Action::ArmNegotiatedTimers => {
                let now = tokio::time::Instant::now();
                if negotiated_hold > 0 {
                    self.hold_sleep
                        .as_mut()
                        .reset(now + Duration::from_secs(negotiated_hold as u64));
                    let ka = (negotiated_hold / 3).max(1);
                    self.keepalive_sleep
                        .as_mut()
                        .reset(now + Duration::from_secs(ka as u64));
                } else {
                    self.disarm();
                }
            }
            Action::RestartHoldTimer => {
                if negotiated_hold > 0 {
                    self.hold_sleep.as_mut().reset(
                        tokio::time::Instant::now() + Duration::from_secs(negotiated_hold as u64),
                    );
                }
            }
            Action::RestartKeepalive => {
                if negotiated_hold > 0 {
                    let ka = (negotiated_hold / 3).max(1);
                    self.keepalive_sleep
                        .as_mut()
                        .reset(tokio::time::Instant::now() + Duration::from_secs(ka as u64));
                }
            }
            Action::ReleaseResources | Action::WithdrawRoutes => {
                // RFC 4724 §4.2: with the GR capability negotiated,
                // a lost session retains the peer's routes marked
                // stale (our own ManualStop and a received
                // NOTIFICATION are deliberate closes — hard clear).
                let gr = self.gr_negotiated.is_some();
                if gr && !self.gr_hard_clear {
                    self.gr_retained = true;
                    sink.retain_stale(&self.peer);
                    info!(peer = %self.peer.address,
                        "bgpd: session lost, routes retained stale (RFC 4724 §4.2)");
                } else {
                    sink.clear_peer(&self.peer);
                }
                self.disarm();
            }
        }
        Ok(())
    }

    fn disarm(&mut self) {
        let far = tokio::time::Instant::now() + FAR;
        self.hold_sleep.as_mut().reset(far);
        self.keepalive_sleep.as_mut().reset(far);
        self.disarm_deferral();
    }

    /// Disarm the §4.1 deferral timer (the EOR beat it).
    fn disarm_deferral(&mut self) {
        self.deferral_sleep
            .as_mut()
            .reset(tokio::time::Instant::now() + FAR);
    }

    async fn send_update(&mut self, update: &mut BgpUpdate) -> io::Result<()> {
        // Coarse MRAI gate: hold the whole message until the window
        // opens (§9.2.1.1; default 0 = off — FRR parity, disclosed).
        if self.mrai > Duration::ZERO {
            let now = (self.now)();
            if let Some(allowed) = self.next_advertisement {
                if now < allowed {
                    tokio::time::sleep(allowed - now).await;
                }
            }
            self.next_advertisement = Some((self.now)() + self.mrai);
        }
        // RFC 7911 §3/§5 (transmit): stamp our per-peer path ids and
        // encode the negotiated families in the extended form — only
        // toward a peer that agreed to receive it (the codec's classic
        // gate stays the backstop against mis-gating).
        self.assign_tx_path_ids(update);
        let asn4 = self.fsm.negotiated().is_none_or(|n| n.asn4);
        let add_path = self.current_add_path_tx_ctx();
        let frame = update
            .encode_frame_with(asn4, add_path)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?;
        self.io.write_all(&frame).await?;
        self.io.flush().await
    }

    async fn write_message(&mut self, message: &BgpMessage) -> io::Result<()> {
        // OPEN/KEEPALIVE/NOTIFICATION carry no AS_PATH; the 4-octet
        // width only matters for UPDATEs (send_update).
        let frame = message
            .encode(true)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?;
        self.io.write_all(&frame).await?;
        self.io.flush().await
    }
}

/// Reads one complete BGP frame: 19-octet header, then the body the
/// header's length field prescribes (bounded by the §4.1 maximum).
/// The header is checked before the body read so a bogus length never
/// drives the reader into the stream. Strict UPDATE error handling
/// (see [`read_frame_with`]).
pub async fn read_frame<IO: AsyncRead + Unpin>(
    io: &mut IO,
    asn4: bool,
) -> io::Result<BgpResult<BgpMessage>> {
    read_frame_with(
        io,
        asn4,
        UpdateHandling::StrictRfc4271,
        AddPathCtx::default(),
    )
    .await
    .map(|r| r.map(|decoded| decoded.message))
}

/// [`read_frame`] with selectable UPDATE error handling: an RFC 7606
/// mode returns salvageable UPDATEs together with the structured
/// handling outcome (and the raw frame, for §6's full-UPDATE debug
/// log) instead of an error. `add_path` carries the negotiated
/// ADD-PATH direction (RFC 7911 §3): extended NLRI decodes only where
/// both sides negotiated it.
pub async fn read_frame_with<IO: AsyncRead + Unpin>(
    io: &mut IO,
    asn4: bool,
    handling: UpdateHandling,
    add_path: AddPathCtx,
) -> io::Result<BgpResult<DecodedFrame>> {
    let mut header = [0u8; BGP_HEADER_LEN as usize];
    io.read_exact(&mut header).await?;
    if header[..16] != BGP_MARKER {
        return Ok(Err(BgpError::notify(
            error::error_code::MESSAGE_HEADER,
            error::header_subcode::CONNECTION_NOT_SYNCHRONIZED,
            "marker is not all ones (§6.1)",
        )));
    }
    let length = u16::from_be_bytes([header[16], header[17]]);
    if !(BGP_HEADER_LEN..=BGP_MAX_MESSAGE_LEN).contains(&length) {
        return Ok(Err(BgpError::notify(
            error::error_code::MESSAGE_HEADER,
            error::header_subcode::BAD_MESSAGE_LENGTH,
            format!("length {length} outside 19..=4096"),
        )));
    }
    let mut body = vec![0u8; length as usize - BGP_HEADER_LEN as usize];
    io.read_exact(&mut body).await?;
    let mut frame = header.to_vec();
    frame.extend_from_slice(&body);
    Ok(
        BgpMessage::decode_with_handling(&frame, asn4, handling, add_path).map(
            |(message, outcome)| DecodedFrame {
                message,
                outcome,
                frame,
            },
        ),
    )
}

/// What [`take_frame`] extracted from the session read buffer.
enum FrameTake {
    /// A complete frame was consumed (decoded, or failed the §6.1
    /// header checks exactly as the wire path would).
    Frame(BgpResult<DecodedFrame>),
    /// No complete frame is buffered yet — wait for more bytes.
    Incomplete,
}

/// The synchronous half of the F7 fix: extract one complete frame
/// from the session's persistent read buffer, applying the same
/// header validation [`read_frame_with`] applies on the wire. The
/// buffer is only ever cleared on a header error — §6.1 prescribes
/// the NOTIFICATION and no resynchronization.
fn take_frame(
    buf: &mut Vec<u8>,
    asn4: bool,
    handling: UpdateHandling,
    add_path: AddPathCtx,
) -> FrameTake {
    if buf.len() < BGP_HEADER_LEN as usize {
        return FrameTake::Incomplete;
    }
    if buf[..16] != BGP_MARKER {
        buf.clear();
        return FrameTake::Frame(Err(BgpError::notify(
            error::error_code::MESSAGE_HEADER,
            error::header_subcode::CONNECTION_NOT_SYNCHRONIZED,
            "marker is not all ones (§6.1)",
        )));
    }
    let length = u16::from_be_bytes([buf[16], buf[17]]);
    if !(BGP_HEADER_LEN..=BGP_MAX_MESSAGE_LEN).contains(&length) {
        buf.clear();
        return FrameTake::Frame(Err(BgpError::notify(
            error::error_code::MESSAGE_HEADER,
            error::header_subcode::BAD_MESSAGE_LENGTH,
            format!("length {length} outside 19..=4096"),
        )));
    }
    if buf.len() < length as usize {
        return FrameTake::Incomplete;
    }
    let frame: Vec<u8> = buf.drain(..length as usize).collect();
    FrameTake::Frame(
        BgpMessage::decode_with_handling(&frame, asn4, handling, add_path).map(
            |(message, outcome)| DecodedFrame {
                message,
                outcome,
                frame,
            },
        ),
    )
}

/// The cancel-safe refill half of the F7 fix: one bounded `read`
/// appending to the session's persistent buffer. A dropped pending
/// read has consumed nothing from the socket; a completed read's
/// bytes are already in `buf` whichever branch the select takes.
async fn read_append<IO: AsyncRead + Unpin>(io: &mut IO, buf: &mut Vec<u8>) -> io::Result<usize> {
    let mut chunk = [0u8; 16384];
    let n = io.read(&mut chunk).await?;
    buf.extend_from_slice(&chunk[..n]);
    Ok(n)
}

/// The v1 Adj-RIB-Out source: the `network` lines from the config,
/// each encoded as an origin UPDATE (plus, once M4's Loc-RIB lands,
/// the best paths learned from other peers — this type stays the
/// shape the session layer consumes).
pub struct ConfiguredNetworks {
    local_as: u32,
    networks: Vec<IpPrefix>,
}

impl ConfiguredNetworks {
    pub fn new(local_as: u32, networks: Vec<IpPrefix>) -> Self {
        Self { local_as, networks }
    }

    pub fn from_config(config: &crate::config::BgpdConfig) -> Self {
        Self::new(config.local_as, config.networks.clone())
    }
}

impl OutRib for ConfiguredNetworks {
    fn advertisements(
        &self,
        afi: u16,
        _safi: u8,
        next_hop: IpAddr,
        _to_peer: IpAddr,
        internal: bool,
    ) -> Vec<BgpUpdate> {
        self.networks
            .iter()
            .filter(|p| matches!((afi, p), (1, IpPrefix::V4(_)) | (2, IpPrefix::V6(_))))
            .map(|&p| originated_update(p, self.local_as, next_hop, internal))
            .collect()
    }
}

/// Builds the UPDATE that originates `prefix` from this speaker:
/// ORIGIN IGP, AS_PATH (local AS prepended only for external peers —
/// §5.1.2 forbids self-prepend to internal peers), NEXT_HOP from the
/// session address (v4: NEXT_HOP attribute; v6: MP_REACH per
/// RFC 4760).
pub fn originated_update(
    prefix: IpPrefix,
    local_as: u32,
    next_hop: IpAddr,
    internal: bool,
) -> BgpUpdate {
    let path = if internal {
        AsPath::new()
    } else {
        AsPath::sequence([local_as])
    };
    match (prefix, next_hop) {
        (IpPrefix::V4(p), IpAddr::V4(nh)) => BgpUpdate {
            withdrawn: vec![],
            attrs: vec![
                PathAttribute::Origin(Origin::Igp),
                PathAttribute::AsPath(path),
                PathAttribute::NextHop(nh),
            ],
            nlri: vec![Nlri::from(IpPrefix::V4(p))],
        },
        (IpPrefix::V6(p), IpAddr::V6(nh)) => BgpUpdate {
            withdrawn: vec![],
            attrs: vec![
                PathAttribute::Origin(Origin::Igp),
                PathAttribute::AsPath(path),
                PathAttribute::MpReach(MpReach {
                    afi: 2,
                    safi: 1,
                    next_hop: MpNextHop::V6 {
                        global: nh,
                        link_local: None,
                    },
                    nlri: vec![Nlri::from(IpPrefix::V6(p))],
                }),
            ],
            nlri: vec![],
        },
        (IpPrefix::V4(p), IpAddr::V6(_)) => BgpUpdate {
            withdrawn: vec![],
            attrs: vec![
                PathAttribute::Origin(Origin::Igp),
                PathAttribute::AsPath(path),
                // Cross-family v4 announcement on a v6 session: no
                // valid NEXT_HOP; the builder never produces this
                // shape in practice (kept total for the type system).
                PathAttribute::NextHop(Ipv4Addr::UNSPECIFIED),
            ],
            nlri: vec![Nlri::from(IpPrefix::V4(p))],
        },
        (IpPrefix::V6(p), IpAddr::V4(nh)) => BgpUpdate {
            withdrawn: vec![],
            attrs: vec![
                PathAttribute::Origin(Origin::Igp),
                PathAttribute::AsPath(path),
                PathAttribute::MpReach(MpReach {
                    afi: 2,
                    safi: 1,
                    next_hop: MpNextHop::V4(nh),
                    nlri: vec![Nlri::from(IpPrefix::V6(p))],
                }),
            ],
            nlri: vec![],
        },
    }
}

/// Builds the UPDATE that withdraws `prefixes`: v4 in the Withdrawn
/// Routes field (RFC 4271 §4.3), v6 via MP_UNREACH (RFC 4760 §4).
/// Classic withdrawals — path id 0 (the tx send path stamps the
/// ADD-PATH ids a tx peer knows, RFC 7911 §5's replacement key).
pub fn withdrawal_update(prefixes: &[IpPrefix]) -> BgpUpdate {
    let mut update = BgpUpdate::default();
    let mut v6 = Vec::new();
    for prefix in prefixes {
        match prefix {
            IpPrefix::V4(_) => update.withdrawn.push(Nlri::from(*prefix)),
            IpPrefix::V6(_) => v6.push(Nlri::from(*prefix)),
        }
    }
    if !v6.is_empty() {
        update
            .attrs
            .push(PathAttribute::MpUnreach(crate::attr::MpUnreach {
                afi: 2,
                safi: 1,
                withdrawn: v6,
            }));
    }
    update
}

/// The UPDATE's next hop for the SAVNET route-event reports
/// (experimental-savnet): the v4 NEXT_HOP attribute or the MP_REACH
/// next hop, whichever the update carries first; `None` when neither.
#[cfg(feature = "experimental-savnet")]
fn bgp_next_hop(update: &BgpUpdate) -> Option<IpAddr> {
    for attr in &update.attrs {
        match attr {
            crate::attr::PathAttribute::NextHop(v4) => return Some(IpAddr::V4(*v4)),
            crate::attr::PathAttribute::MpReach(mp) => match &mp.next_hop {
                crate::attr::MpNextHop::V4(v4) => return Some(IpAddr::V4(*v4)),
                crate::attr::MpNextHop::V6 { global, .. } => {
                    return Some(IpAddr::V6(*global));
                }
            },
            _ => {}
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::attr::AsSegment;
    use crate::message::message_type;
    use tokio::io::duplex;

    /// A minimal speaking partner: answers OPEN with OPEN, then
    /// KEEPALIVE.
    struct TestPeer {
        io: tokio::io::DuplexStream,
        asn: u32,
    }

    impl TestPeer {
        async fn handshake(&mut self, expect_as: u32) -> BgpOpen {
            let frame = read_bytes(&mut self.io).await;
            let open = match BgpMessage::decode(&frame, true).unwrap() {
                BgpMessage::Open(o) => o,
                other => panic!("expected OPEN, got {other:?}"),
            };
            assert_eq!(open.peer_as4(), expect_as);
            let mine = BgpOpen::new(self.asn, 30, "10.9.9.9".parse().unwrap(), vec![]);
            write_bytes(&mut self.io, &BgpMessage::Open(mine).encode(true).unwrap()).await;
            let frame = read_bytes(&mut self.io).await;
            assert_eq!(frame[18], message_type::KEEPALIVE);
            write_bytes(&mut self.io, &BgpMessage::Keepalive.encode(true).unwrap()).await;
            open
        }
    }

    async fn read_bytes(io: &mut tokio::io::DuplexStream) -> Vec<u8> {
        let mut header = vec![0u8; 19];
        io.read_exact(&mut header).await.unwrap();
        let len = u16::from_be_bytes([header[16], header[17]]) as usize;
        let mut body = vec![0u8; len - 19];
        io.read_exact(&mut body).await.unwrap();
        let mut frame = header;
        frame.extend_from_slice(&body);
        frame
    }

    async fn write_bytes(io: &mut tokio::io::DuplexStream, frame: &[u8]) {
        io.write_all(frame).await.unwrap();
        io.flush().await.unwrap();
    }

    fn session(
        io: tokio::io::DuplexStream,
        remote_as: u32,
        out_rib: Option<Arc<dyn OutRib>>,
    ) -> PeerSession<tokio::io::DuplexStream> {
        PeerSession::new(
            io,
            SessionConfig::new(65000, "10.0.0.1".parse().unwrap(), 90),
            PeerInfo {
                address: "192.0.2.9".parse().unwrap(),
                remote_as,
                bgp_id: None,
            },
            "192.0.2.1".parse().unwrap(),
            out_rib,
            Duration::ZERO,
        )
    }

    struct Networks(Vec<IpPrefix>);
    impl OutRib for Networks {
        fn advertisements(
            &self,
            _afi: u16,
            _safi: u8,
            nh: IpAddr,
            _to_peer: IpAddr,
            internal: bool,
        ) -> Vec<BgpUpdate> {
            self.0
                .iter()
                .map(|&p| originated_update(p, 65000, nh, internal))
                .collect()
        }
        fn families(&self) -> Vec<(u16, u8)> {
            vec![(1, 1)]
        }
    }

    /// Full exchange over an in-process duplex pair: OPEN/OPEN,
    /// KEEPALIVE/KEEPALIVE, Established, initial UPDATE carrying the
    /// network line, teardown clears the peer's routes.
    #[tokio::test]
    async fn reaches_established_and_delivers_the_network() {
        let (ours, theirs) = duplex(8192);
        let mut sess = session(
            ours,
            65001,
            Some(Arc::new(Networks(vec!["203.0.113.0/24".parse().unwrap()]))),
        );
        let sink = SharedSink(Arc::new(Mutex::new(RecordingSink::default())));
        let mut driver_sink = sink.clone();
        let driver = tokio::spawn(async move { sess.run(&mut driver_sink).await });

        let mut partner = TestPeer {
            io: theirs,
            asn: 65001,
        };
        partner.handshake(65000).await;

        let frame = read_bytes(&mut partner.io).await;
        let update = match BgpMessage::decode(&frame, true).unwrap() {
            BgpMessage::Update(u) => u,
            other => panic!("expected UPDATE, got {other:?}"),
        };
        assert_eq!(update.nlri, vec!["203.0.113.0/24".parse().unwrap()]);
        assert_eq!(update.as_path().unwrap().path_length(), 1, "eBGP prepend");
        assert_eq!(update.origin(), Some(Origin::Igp));

        // KEEPALIVE holds the session; far-side close tears it down
        // with exactly one clear_peer.
        write_bytes(
            &mut partner.io,
            &BgpMessage::Keepalive.encode(true).unwrap(),
        )
        .await;
        partner.io.shutdown().await.unwrap();
        let end = driver.await.unwrap();
        assert!(matches!(end, SessionEnd::Transport(_)));
        let sink = sink.0.lock().unwrap();
        assert_eq!(sink.cleared, 1, "teardown clears the peer's routes");
    }

    #[tokio::test]
    async fn wrong_remote_as_gets_bad_peer_as_notification() {
        let (ours, mut theirs) = duplex(8192);
        let mut sess = session(ours, 65001, None);
        let mut sink = NullSink;
        let driver = tokio::spawn(async move { sess.run(&mut sink).await });

        let frame = read_bytes(&mut theirs).await;
        assert_eq!(frame[18], message_type::OPEN);
        let impostor = BgpOpen::new(66642, 30, "10.9.9.9".parse().unwrap(), vec![]);
        write_bytes(
            &mut theirs,
            &BgpMessage::Open(impostor).encode(true).unwrap(),
        )
        .await;

        let frame = read_bytes(&mut theirs).await;
        assert_eq!(frame[18], message_type::NOTIFICATION);
        let notification = match BgpMessage::decode(&frame, true).unwrap() {
            BgpMessage::Notification(n) => n,
            other => panic!("{other:?}"),
        };
        assert_eq!(notification.code, error::error_code::OPEN_MESSAGE);
        assert_eq!(notification.subcode, error::open_subcode::BAD_PEER_AS);
        let end = driver.await.unwrap();
        assert!(matches!(end, SessionEnd::Notified(2, 2)));
    }

    // ---- F3: first-AS enforcement (RFC 4271 §6.3) ------------------

    /// A received-route UPDATE: the mandatory triple plus the given
    /// AS_PATH, announcing 203.0.113.0/24.
    fn received_update(path: AsPath) -> BgpUpdate {
        BgpUpdate {
            withdrawn: vec![],
            attrs: vec![
                PathAttribute::Origin(Origin::Igp),
                PathAttribute::AsPath(path),
                PathAttribute::NextHop("192.0.2.9".parse().unwrap()),
            ],
            nlri: vec!["203.0.113.0/24".parse().unwrap()],
        }
    }

    /// Reads frames until a NOTIFICATION arrives (KEEPALIVEs, our
    /// End-of-RIB markers, and other traffic pass), returning the raw
    /// frame for byte-level pins.
    async fn until_notification_frame(io: &mut tokio::io::DuplexStream) -> Vec<u8> {
        loop {
            let frame = read_bytes(io).await;
            if frame[18] == message_type::NOTIFICATION {
                return frame;
            }
        }
    }

    /// The exact NOTIFICATION §6.3 prescribes when the first-AS check
    /// fails: marker | length 21 | type 3 | code 3 (UPDATE Message
    /// Error) | subcode 11 (Malformed AS_PATH), no data octets —
    /// 21 octets total.
    fn malformed_as_path_notification_bytes() -> Vec<u8> {
        let mut expected = vec![0xff; 16];
        expected.extend_from_slice(&[0x00, 0x15, 0x03, 0x03, 0x0b]);
        expected
    }

    /// RFC 4271 §6.3: "If the UPDATE message is received from an
    /// external peer, the local system MAY check whether the leftmost
    /// (with respect to the position of octets in the protocol
    /// message) AS in the AS_PATH attribute is equal to the
    /// autonomous system number of the peer that sent the message.
    /// If the check determines this is not the case, the Error Subcode
    /// MUST be set to Malformed AS_PATH." An eBGP UPDATE whose path
    /// opens with 65099 (the peer speaks 65001) draws exactly that
    /// NOTIFICATION, byte for byte, and the session resets.
    #[tokio::test]
    async fn ebgp_bad_first_as_gets_malformed_as_path_notification_bytes() {
        let (ours, theirs) = duplex(8192);
        let mut sess = session(ours, 65001, None);
        let sink = SharedSink(Arc::new(Mutex::new(RecordingSink::default())));
        let mut driver_sink = sink.clone();
        let driver = tokio::spawn(async move { sess.run(&mut driver_sink).await });

        let mut partner = TestPeer {
            io: theirs,
            asn: 65001,
        };
        partner.handshake(65000).await;

        let update = received_update(AsPath::sequence([65099, 65001]));
        write_bytes(&mut partner.io, &update.encode_frame(true).unwrap()).await;

        let frame = until_notification_frame(&mut partner.io).await;
        assert_eq!(frame, malformed_as_path_notification_bytes());
        let end = driver.await.unwrap();
        assert_eq!(
            end,
            SessionEnd::Notified(
                error::error_code::UPDATE_MESSAGE,
                error::update_subcode::MALFORMED_AS_PATH,
            )
        );
        let sink = sink.0.lock().unwrap();
        assert!(
            sink.announced.is_empty(),
            "the route never reached Adj-RIB-In"
        );
        assert_eq!(sink.cleared, 1, "the teardown clears the peer's routes");
    }

    /// The well-formed twin: the path opens with the peer's own AS
    /// (65001) and the route imports normally.
    #[tokio::test]
    async fn ebgp_peer_first_as_imports_normally() {
        let (ours, theirs) = duplex(8192);
        let mut sess = session(ours, 65001, None);
        let sink = SharedSink(Arc::new(Mutex::new(RecordingSink::default())));
        let mut driver_sink = sink.clone();
        let driver = tokio::spawn(async move { sess.run(&mut driver_sink).await });

        let mut partner = TestPeer {
            io: theirs,
            asn: 65001,
        };
        partner.handshake(65000).await;

        let update = received_update(AsPath::sequence([65001, 65002]));
        write_bytes(&mut partner.io, &update.encode_frame(true).unwrap()).await;
        write_bytes(
            &mut partner.io,
            &BgpMessage::Keepalive.encode(true).unwrap(),
        )
        .await;
        partner.io.shutdown().await.unwrap();
        let end = driver.await.unwrap();
        assert!(matches!(end, SessionEnd::Transport(_)));
        let sink = sink.0.lock().unwrap();
        assert_eq!(sink.announced.len(), 1, "the route imports");
        assert!(sink.announced.contains_key(&"203.0.113.0/24".parse().unwrap()));
    }

    /// §6.3's rule is scoped to "the UPDATE message ... received from
    /// an external peer" — an internal peer's path may open with any
    /// AS (§9.2 dissemination leaves it untouched), so iBGP is exempt
    /// from the first-AS check.
    #[tokio::test]
    async fn ibgp_first_as_check_exempt() {
        let (ours, theirs) = duplex(8192);
        let mut sess = session(ours, 65000, None);
        let sink = SharedSink(Arc::new(Mutex::new(RecordingSink::default())));
        let mut driver_sink = sink.clone();
        let driver = tokio::spawn(async move { sess.run(&mut driver_sink).await });

        let mut partner = TestPeer {
            io: theirs,
            asn: 65000,
        };
        partner.handshake(65000).await;

        let update = received_update(AsPath::sequence([65099, 65001]));
        write_bytes(&mut partner.io, &update.encode_frame(true).unwrap()).await;
        write_bytes(
            &mut partner.io,
            &BgpMessage::Keepalive.encode(true).unwrap(),
        )
        .await;
        partner.io.shutdown().await.unwrap();
        driver.await.unwrap();
        let sink = sink.0.lock().unwrap();
        assert_eq!(sink.announced.len(), 1, "iBGP path of any shape imports");
    }

    /// §5.1.2 a): the empty AS_PATH is the iBGP shape — from an
    /// internal peer it imports (this test); from an external one it
    /// has no leftmost AS to equal the peer and fails the §6.3 check
    /// (the next test).
    #[tokio::test]
    async fn ibgp_empty_as_path_imports() {
        let (ours, theirs) = duplex(8192);
        let mut sess = session(ours, 65000, None);
        let sink = SharedSink(Arc::new(Mutex::new(RecordingSink::default())));
        let mut driver_sink = sink.clone();
        let driver = tokio::spawn(async move { sess.run(&mut driver_sink).await });

        let mut partner = TestPeer {
            io: theirs,
            asn: 65000,
        };
        partner.handshake(65000).await;

        let update = received_update(AsPath::default());
        write_bytes(&mut partner.io, &update.encode_frame(true).unwrap()).await;
        write_bytes(
            &mut partner.io,
            &BgpMessage::Keepalive.encode(true).unwrap(),
        )
        .await;
        partner.io.shutdown().await.unwrap();
        driver.await.unwrap();
        let sink = sink.0.lock().unwrap();
        assert_eq!(sink.announced.len(), 1);
    }

    /// The empty path over eBGP: no leftmost AS can equal the peer's,
    /// so the prescribed Malformed AS_PATH NOTIFICATION answers (FRR
    /// parity — `aspath_firstas_check` returns false for a NULL/empty
    /// path).
    #[tokio::test]
    async fn ebgp_empty_as_path_rejected() {
        let (ours, theirs) = duplex(8192);
        let mut sess = session(ours, 65001, None);
        let mut sink = NullSink;
        let driver = tokio::spawn(async move { sess.run(&mut sink).await });

        let mut partner = TestPeer {
            io: theirs,
            asn: 65001,
        };
        partner.handshake(65000).await;

        let update = received_update(AsPath::default());
        write_bytes(&mut partner.io, &update.encode_frame(true).unwrap()).await;

        let frame = until_notification_frame(&mut partner.io).await;
        assert_eq!(frame, malformed_as_path_notification_bytes());
        let end = driver.await.unwrap();
        assert_eq!(
            end,
            SessionEnd::Notified(
                error::error_code::UPDATE_MESSAGE,
                error::update_subcode::MALFORMED_AS_PATH,
            )
        );
    }

    /// A leading AS_SET has no leftmost sequence AS either — the same
    /// rejection (FRR's `aspath_firstas_check` demands a first
    /// segment of type AS_SEQUENCE).
    #[tokio::test]
    async fn ebgp_leading_as_set_rejected() {
        let (ours, theirs) = duplex(8192);
        let mut sess = session(ours, 65001, None);
        let mut sink = NullSink;
        let driver = tokio::spawn(async move { sess.run(&mut sink).await });

        let mut partner = TestPeer {
            io: theirs,
            asn: 65001,
        };
        partner.handshake(65000).await;

        let path = AsPath {
            segments: vec![AsSegment::Set(vec![65001, 65002])],
        };
        let update = received_update(path);
        write_bytes(&mut partner.io, &update.encode_frame(true).unwrap()).await;

        let frame = until_notification_frame(&mut partner.io).await;
        assert_eq!(frame, malformed_as_path_notification_bytes());
        let end = driver.await.unwrap();
        assert_eq!(
            end,
            SessionEnd::Notified(
                error::error_code::UPDATE_MESSAGE,
                error::update_subcode::MALFORMED_AS_PATH,
            )
        );
    }

    /// §6.3 keys the check on the message's AS_PATH, not on its NLRI:
    /// a withdrawal-only UPDATE carrying a bad path resets the session
    /// too (FRR enforces at attribute-parse time, before it knows what
    /// the routes were).
    #[tokio::test]
    async fn ebgp_withdrawal_with_bad_first_as_resets_session() {
        let (ours, theirs) = duplex(8192);
        let mut sess = session(ours, 65001, None);
        let mut sink = NullSink;
        let driver = tokio::spawn(async move { sess.run(&mut sink).await });

        let mut partner = TestPeer {
            io: theirs,
            asn: 65001,
        };
        partner.handshake(65000).await;

        let update = BgpUpdate {
            withdrawn: vec!["203.0.113.0/24".parse().unwrap()],
            attrs: vec![PathAttribute::AsPath(AsPath::sequence([65099]))],
            nlri: vec![],
        };
        write_bytes(&mut partner.io, &update.encode_frame(true).unwrap()).await;

        let frame = until_notification_frame(&mut partner.io).await;
        assert_eq!(frame, malformed_as_path_notification_bytes());
        let end = driver.await.unwrap();
        assert_eq!(
            end,
            SessionEnd::Notified(
                error::error_code::UPDATE_MESSAGE,
                error::update_subcode::MALFORMED_AS_PATH,
            )
        );
    }

    /// The check runs on the decoded path BEFORE the RFC 7606
    /// disposition arms — FRR enforces at attribute-parse time, ahead
    /// of its revised handling — so a bad first AS resets the session
    /// even when a second defect (a malformed ATOMIC_AGGREGATE, an
    /// attribute-discard row that would otherwise log and process)
    /// rides the same UPDATE.
    #[tokio::test]
    async fn first_as_check_precedes_rfc7606_disposition() {
        let (ours, theirs) = duplex(8192);
        let mut sess = session(ours, 65001, None);
        let sink = SharedSink(Arc::new(Mutex::new(RecordingSink::default())));
        let mut driver_sink = sink.clone();
        let driver = tokio::spawn(async move { sess.run(&mut driver_sink).await });

        let mut partner = TestPeer {
            io: theirs,
            asn: 65001,
        };
        partner.handshake(65000).await;

        // Hand-built frame: the mandatory triple with the bad path,
        // plus a length-1 ATOMIC_AGGREGATE (RFC 7606 §7 attribute
        // discard — must be length 0).
        let mut attrs = Vec::new();
        crate::attr::encode_attributes(
            &received_update(AsPath::sequence([65099])).attrs,
            &mut attrs,
            true,
            AddPathCtx::default(),
        )
        .unwrap();
        attrs.extend_from_slice(&[0x40, 0x06, 0x01, 0x00]);
        let mut body = vec![0x00, 0x00];
        body.extend_from_slice(&(attrs.len() as u16).to_be_bytes());
        body.extend_from_slice(&attrs);
        body.extend_from_slice(&[24, 203, 0, 113]); // 203.0.113.0/24
        let mut frame = vec![0xff; 16];
        frame.extend_from_slice(&((19 + body.len()) as u16).to_be_bytes());
        frame.push(message_type::UPDATE);
        frame.extend_from_slice(&body);
        write_bytes(&mut partner.io, &frame).await;

        // Sanction of the frame itself: under RFC 7606 alone it would
        // decode to attribute-discard and process — pinned by decoding
        // it directly.
        let (decoded, outcome) = BgpUpdate::decode_with_handling(
            &body,
            true,
            UpdateHandling::Rfc7606 { internal: false },
            AddPathCtx::default(),
        )
        .unwrap();
        assert_eq!(decoded.nlri.len(), 1);
        assert!(
            matches!(outcome, UpdateOutcome::Discarded(_)),
            "without the first-AS check this UPDATE would process"
        );

        let frame = until_notification_frame(&mut partner.io).await;
        assert_eq!(frame, malformed_as_path_notification_bytes());
        let end = driver.await.unwrap();
        assert_eq!(
            end,
            SessionEnd::Notified(
                error::error_code::UPDATE_MESSAGE,
                error::update_subcode::MALFORMED_AS_PATH,
            )
        );
        let sink = sink.0.lock().unwrap();
        assert!(sink.announced.is_empty());
    }

    /// A multi-segment path is judged by its FIRST segment only: the
    /// leftmost AS is 65001 (the peer) even though later segments
    /// (including an AS_SET) differ.
    #[tokio::test]
    async fn ebgp_multi_segment_path_first_segment_governs() {
        let (ours, theirs) = duplex(8192);
        let mut sess = session(ours, 65001, None);
        let sink = SharedSink(Arc::new(Mutex::new(RecordingSink::default())));
        let mut driver_sink = sink.clone();
        let driver = tokio::spawn(async move { sess.run(&mut driver_sink).await });

        let mut partner = TestPeer {
            io: theirs,
            asn: 65001,
        };
        partner.handshake(65000).await;

        let path = AsPath {
            segments: vec![
                AsSegment::Sequence(vec![65001, 64512]),
                AsSegment::Set(vec![65003, 65004]),
            ],
        };
        let update = received_update(path);
        write_bytes(&mut partner.io, &update.encode_frame(true).unwrap()).await;
        write_bytes(
            &mut partner.io,
            &BgpMessage::Keepalive.encode(true).unwrap(),
        )
        .await;
        partner.io.shutdown().await.unwrap();
        driver.await.unwrap();
        let sink = sink.0.lock().unwrap();
        assert_eq!(sink.announced.len(), 1, "leftmost AS is the peer's");
    }

    #[tokio::test(start_paused = true)]
    async fn hold_timer_expiry_sends_hold_expired_and_closes() {
        let (ours, theirs) = duplex(8192);
        let mut sess = PeerSession::new(
            ours,
            SessionConfig::new(65000, "10.0.0.1".parse().unwrap(), 3),
            PeerInfo {
                address: "192.0.2.9".parse().unwrap(),
                remote_as: 65001,
                bgp_id: None,
            },
            "192.0.2.1".parse().unwrap(),
            None,
            Duration::ZERO,
        );
        let mut sink = NullSink;
        let driver = tokio::spawn(async move { sess.run(&mut sink).await });

        let mut partner = TestPeer {
            io: theirs,
            asn: 65001,
        };
        partner.handshake(65000).await;
        // Silence: the 3 s hold expires → NOTIFICATION (4, 0). Our
        // keepalive timer (1 s) fires first — read past it.
        let frame = loop {
            let frame = read_bytes(&mut partner.io).await;
            if frame[18] == message_type::NOTIFICATION {
                break frame;
            }
        };
        let notification = match BgpMessage::decode(&frame, true).unwrap() {
            BgpMessage::Notification(n) => n,
            other => panic!("{other:?}"),
        };
        assert_eq!(notification.code, 4, "Hold Timer Expired");
        let end = driver.await.unwrap();
        assert!(matches!(end, SessionEnd::Notified(4, 0)));
    }

    /// RFC 2918 round-trip: refresh request answered by a
    /// re-advertisement, MRAI-gated (clock: paused tokio time).
    #[tokio::test(start_paused = true)]
    async fn route_refresh_re_advertises_after_mrai() {
        let (ours, theirs) = duplex(8192);
        let mut sess = PeerSession::new(
            ours,
            SessionConfig::new(65000, "10.0.0.1".parse().unwrap(), 90),
            PeerInfo {
                address: "192.0.2.9".parse().unwrap(),
                remote_as: 65001,
                bgp_id: None,
            },
            "192.0.2.1".parse().unwrap(),
            Some(Arc::new(Networks(vec!["203.0.113.0/24".parse().unwrap()]))),
            Duration::from_secs(5),
        );
        let mut sink = NullSink;
        let driver = tokio::spawn(async move { sess.run(&mut sink).await });

        let mut partner = TestPeer {
            io: theirs,
            asn: 65001,
        };
        // Handshake WITHOUT advertising route refresh: our session
        // must then ignore the refresh request. (Our own OPEN always
        // advertises it; the peer's is what gates the answer.)
        let frame = read_bytes(&mut partner.io).await;
        let _ = BgpMessage::decode(&frame, true).unwrap();
        let mine = BgpOpen::new(65001, 30, "10.9.9.9".parse().unwrap(), vec![]);
        write_bytes(
            &mut partner.io,
            &BgpMessage::Open(mine).encode(true).unwrap(),
        )
        .await;
        let frame = read_bytes(&mut partner.io).await;
        assert_eq!(frame[18], message_type::KEEPALIVE);
        write_bytes(
            &mut partner.io,
            &BgpMessage::Keepalive.encode(true).unwrap(),
        )
        .await;

        // Initial UPDATE still arrives (the family advertisement is
        // not capability-gated in v1).
        let _first = read_bytes(&mut partner.io).await;

        write_bytes(
            &mut partner.io,
            &BgpMessage::RouteRefresh(BgpRouteRefresh { afi: 1, safi: 1 })
                .encode(true)
                .unwrap(),
        )
        .await;

        partner.io.shutdown().await.unwrap();
        let end = driver.await.unwrap();
        assert!(matches!(end, SessionEnd::Transport(_)));
    }

    #[tokio::test(start_paused = true)]
    async fn keepalive_timer_drives_session_stability() {
        // Short negotiated timers (1 s keepalive / 3 s hold via the
        // peer's OPEN): the session survives on its own keepalives.
        let (ours, mut theirs) = duplex(8192);
        let mut sess = PeerSession::new(
            ours,
            SessionConfig::new(65000, "10.0.0.1".parse().unwrap(), 90),
            PeerInfo {
                address: "192.0.2.9".parse().unwrap(),
                remote_as: 65001,
                bgp_id: None,
            },
            "192.0.2.1".parse().unwrap(),
            None,
            Duration::ZERO,
        );
        let mut sink = NullSink;
        let driver = tokio::spawn(async move { sess.run(&mut sink).await });

        // OPEN exchange with hold 3.
        let frame = read_bytes(&mut theirs).await;
        let _ = BgpMessage::decode(&frame, true).unwrap();
        let mine = BgpOpen::new(65001, 3, "10.9.9.9".parse().unwrap(), vec![]);
        write_bytes(&mut theirs, &BgpMessage::Open(mine).encode(true).unwrap()).await;
        let frame = read_bytes(&mut theirs).await;
        assert_eq!(frame[18], message_type::KEEPALIVE);
        write_bytes(&mut theirs, &BgpMessage::Keepalive.encode(true).unwrap()).await;

        // Our keepalive timer (1 s) fires before the hold (3 s).
        // (End-of-RIB markers are UPDATE frames — skip past them.)
        let frame = loop {
            let frame = read_bytes(&mut theirs).await;
            if frame[18] == message_type::KEEPALIVE {
                break frame;
            }
        };
        assert_eq!(frame[18], message_type::KEEPALIVE, "keepalive sent");

        driver.abort();
        let _ = theirs.shutdown().await;
    }

    #[test]
    fn originated_update_shapes() {
        let v4 = originated_update(
            "203.0.113.0/24".parse().unwrap(),
            65000,
            "192.0.2.1".parse().unwrap(),
            false,
        );
        assert!(v4.attr(1).is_some(), "ORIGIN present");
        assert_eq!(v4.nlri.len(), 1);
        let v6 = originated_update(
            "2001:db8:1::/48".parse().unwrap(),
            65000,
            "2001:db8::1".parse().unwrap(),
            true,
        );
        assert!(v6.nlri.is_empty(), "v6 rides MP_REACH");
        assert!(v6.attr(14).is_some());
        assert!(!v4.attr(14).is_some(), "v4 needs no MP_REACH");
        // iBGP: no local-AS prepend (§5.1.2).
        assert_eq!(v6.as_path().unwrap().path_length(), 0);
    }

    #[test]
    fn withdrawal_update_splits_families() {
        let update = withdrawal_update(&[
            "203.0.113.0/24".parse().unwrap(),
            "2001:db8:1::/48".parse().unwrap(),
        ]);
        // RFC 4271 §4.3: the v4 prefix rides the Withdrawn Routes
        // field (never the NLRI field — a withdrawal is not
        // reachability).
        assert_eq!(update.withdrawn.len(), 1);
        assert!(update.nlri.is_empty());
        assert!(matches!(
            update.attrs.last(),
            Some(PathAttribute::MpUnreach(_))
        ));
    }

    // ---- RFC 7606 revised error handling at the session (N5 M1) ---

    /// A duplex helper: drive one session, hand the test side raw
    /// frame bytes, record the sink.
    struct MalformedPeer {
        io: tokio::io::DuplexStream,
        sink: SharedSink<RecordingSink>,
    }

    async fn established_session() -> (MalformedPeer, tokio::task::JoinHandle<SessionEnd>) {
        let (ours, theirs) = duplex(8192);
        let mut sess = session(ours, 65001, None);
        let sink = SharedSink(Arc::new(Mutex::new(RecordingSink::default())));
        let mut driver_sink = sink.clone();
        let driver = tokio::spawn(async move { sess.run(&mut driver_sink).await });
        let mut peer = MalformedPeer { io: theirs, sink };
        peer.handshake(65000).await;
        (peer, driver)
    }

    impl MalformedPeer {
        /// OPEN (as 65001) answered to our OPEN, then KEEPALIVE.
        async fn handshake(&mut self, _expect_as: u32) {
            let frame = read_bytes(&mut self.io).await;
            let _ = BgpMessage::decode(&frame, true).unwrap();
            let mine = BgpOpen::new(65001, 30, "10.9.9.9".parse().unwrap(), vec![]);
            write_bytes(&mut self.io, &BgpMessage::Open(mine).encode(true).unwrap()).await;
            let frame = read_bytes(&mut self.io).await;
            assert_eq!(frame[18], message_type::KEEPALIVE);
            write_bytes(&mut self.io, &BgpMessage::Keepalive.encode(true).unwrap()).await;
        }

        /// Pre-advertise a good route so the withdrawal is observable.
        async fn advertise(&mut self, prefix: &str) {
            let update = BgpMessage::Update(BgpUpdate {
                withdrawn: vec![],
                attrs: vec![
                    PathAttribute::Origin(Origin::Igp),
                    PathAttribute::AsPath(AsPath::sequence([65001])),
                    PathAttribute::NextHop("192.0.2.9".parse().unwrap()),
                ],
                nlri: vec![prefix.parse().unwrap()],
            })
            .encode(true)
            .unwrap();
            write_bytes(&mut self.io, &update).await;
        }

        async fn raw(&mut self, body: &[u8]) {
            let mut frame = vec![0xff; 16];
            put_len(&mut frame, 19 + body.len() as u16);
            frame.push(message_type::UPDATE);
            frame.extend_from_slice(body);
            write_bytes(&mut self.io, &frame).await;
        }

        /// Read until a NOTIFICATION arrives (None on EOF first).
        async fn expect_alive_after_keepalive(
            &mut self,
            driver: &tokio::task::JoinHandle<SessionEnd>,
        ) {
            write_bytes(&mut self.io, &BgpMessage::Keepalive.encode(true).unwrap()).await;
            // The session must process the KEEPALIVE after the
            // malformed UPDATE: give it a moment, then confirm the
            // driver is still running (not returned).
            for _ in 0..50 {
                if driver.is_finished() {
                    panic!("session died after a treat-as-withdraw UPDATE");
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        }
    }

    fn put_len(frame: &mut Vec<u8>, len: u16) {
        frame.push((len >> 8) as u8);
        frame.push((len & 0xff) as u8);
    }

    /// An UPDATE whose ORIGIN attribute is malformed (length 2):
    /// RFC 7606 §7 treats it as a withdrawal of the NLRI it carries —
    /// the session survives and answers the next KEEPALIVE.
    #[tokio::test]
    async fn malformed_update_treated_as_withdraw_session_survives() {
        let (mut peer, driver) = established_session().await;
        peer.advertise("203.0.113.0/24").await;
        tokio::time::sleep(Duration::from_millis(20)).await;
        {
            let sink = peer.sink.0.lock().unwrap();
            assert!(sink
                .announced
                .contains_key(&"203.0.113.0/24".parse().unwrap()));
        }
        // A re-announcement of the same prefix with a malformed
        // ORIGIN (length 2): RFC 7606 §2 treats the contained routes
        // (the NLRI below) as withdrawn.
        let body: Vec<u8> = [
            0x00, 0x00, // withdrawn len
            0x00, 0x15, // attr len: ORIGIN(5) + AS_PATH(9) + NEXT_HOP(7)
            0x40, 0x01, 0x02, 0x00, 0x00, // ORIGIN len 2 (malformed)
            0x40, 0x02, 0x06, 0x02, 0x01, 0x00, 0x00, 0xfd, 0xe9, // AS_PATH 65001 (4-octet)
            0x40, 0x03, 0x04, 192, 0, 2, 9, // NEXT_HOP
            //
            24, 203, 0, 113, // NLRI 203.0.113.0/24
        ]
        .to_vec();
        peer.raw(&body).await;
        peer.expect_alive_after_keepalive(&driver).await;
        let sink = peer.sink.0.lock().unwrap();
        assert!(
            sink.withdrawn.contains(&"203.0.113.0/24".parse().unwrap()),
            "the announced route was withdrawn (RFC 7606 §2)"
        );
        assert_eq!(sink.cleared, 0, "no teardown: the session lives");
        driver.abort();
    }

    /// The same malformed UPDATE under `strict-rfc4271`: NOTIFICATION
    /// (3, 5 Attribute Length Error) and session teardown.
    #[tokio::test]
    async fn strict_mode_still_resets_the_session() {
        let (ours, theirs) = duplex(8192);
        let mut sess = session(ours, 65001, None)
            .with_update_handling(crate::attr::UpdateHandling::StrictRfc4271);
        let sink = SharedSink(Arc::new(Mutex::new(RecordingSink::default())));
        let mut driver_sink = sink.clone();
        let driver = tokio::spawn(async move { sess.run(&mut driver_sink).await });
        let mut peer = MalformedPeer {
            io: theirs,
            sink: sink.clone(),
        };
        peer.handshake(65000).await;
        let body: Vec<u8> = [
            0x00, 0x00, 0x00, 0x0c, // attr len: ORIGIN(5) + NEXT_HOP(7)
            0x40, 0x01, 0x02, 0x00, 0x00, // ORIGIN len 2 (malformed)
            0x40, 0x03, 0x04, 192, 0, 2, 9, // NEXT_HOP
        ]
        .to_vec();
        peer.raw(&body).await;
        // (Skip past the session's End-of-RIB markers — UPDATEs.)
        let frame = loop {
            let frame = read_bytes(&mut peer.io).await;
            if frame[18] == message_type::NOTIFICATION {
                break frame;
            }
        };
        let notification = match BgpMessage::decode(&frame, true).unwrap() {
            BgpMessage::Notification(n) => n,
            other => panic!("{other:?}"),
        };
        assert_eq!(notification.code, 3);
        assert_eq!(
            notification.subcode,
            error::update_subcode::ATTRIBUTE_LENGTH_ERROR
        );
        let end = driver.await.unwrap();
        assert!(matches!(end, SessionEnd::Notified(3, _)));
    }

    // ---- RFC 7911 ADD-PATH receive (N5B) -----------------------------

    /// The receive path end to end over the duplex pair: with
    /// `addpath rx` configured our OPEN advertises S/R 1; the peer's
    /// S/R 2 turns the effective direction on (§5's MUSTs); extended
    /// NLRI — two paths of one prefix — lands keyed (prefix,
    /// path-id); a per-path withdrawal carries exactly its id.
    #[tokio::test]
    async fn add_path_session_receives_extended_updates() {
        let (ours, theirs) = duplex(8192);
        let mut config = SessionConfig::new(65000, "10.0.0.1".parse().unwrap(), 90);
        config.add_path_rx_v4 = true;
        let mut sess = PeerSession::new(
            ours,
            config,
            PeerInfo {
                address: "192.0.2.9".parse().unwrap(),
                remote_as: 65001,
                bgp_id: None,
            },
            "192.0.2.1".parse().unwrap(),
            None,
            Duration::ZERO,
        );
        let sink = SharedSink(Arc::new(Mutex::new(RecordingSink::default())));
        let mut driver_sink = sink.clone();
        let driver = tokio::spawn(async move { sess.run(&mut driver_sink).await });
        let mut peer = MalformedPeer {
            io: theirs,
            sink: sink.clone(),
        };

        // Our OPEN must carry the ADD-PATH capability, S/R 1 for v4.
        let frame = read_bytes(&mut peer.io).await;
        let our_open = match BgpMessage::decode(&frame, true).unwrap() {
            BgpMessage::Open(o) => o,
            other => panic!("{other:?}"),
        };
        assert!(
            our_open.capabilities.iter().any(|c| matches!(c,
                Capability::AddPath(tuples)
                    if tuples == &vec![AddPathFamily { afi: 1, safi: 1, send_receive: 1 }])),
            "S/R 1 advertised once rx is configured: {:?}",
            our_open.capabilities
        );

        // The peer offers to SEND (S/R 2) — the direction that lets a
        // receive-configured speaker decode extended NLRI.
        let mine = BgpOpen::new(
            65001,
            30,
            "10.9.9.9".parse().unwrap(),
            vec![Capability::AddPath(vec![AddPathFamily {
                afi: 1,
                safi: 1,
                send_receive: 2,
            }])],
        );
        write_bytes(&mut peer.io, &BgpMessage::Open(mine).encode(true).unwrap()).await;
        let frame = read_bytes(&mut peer.io).await;
        assert_eq!(frame[18], message_type::KEEPALIVE);
        write_bytes(&mut peer.io, &BgpMessage::Keepalive.encode(true).unwrap()).await;

        // Extended UPDATE: two sibling paths of one prefix.
        let ctx = crate::attr::AddPathCtx {
            v4: true,
            v6: false,
        };
        let prefix: common::IpPrefix = "203.0.113.0/24".parse().unwrap();
        let update = BgpUpdate {
            withdrawn: vec![],
            attrs: vec![
                PathAttribute::Origin(Origin::Igp),
                PathAttribute::AsPath(AsPath::sequence([65001])),
                PathAttribute::NextHop("192.0.2.9".parse().unwrap()),
            ],
            nlri: vec![Nlri { prefix, path_id: 1 }, Nlri { prefix, path_id: 2 }],
        };
        let frame = BgpMessage::Update(update).encode_with(true, ctx).unwrap();
        write_bytes(&mut peer.io, &frame).await;
        tokio::time::sleep(Duration::from_millis(20)).await;
        {
            let sink = peer.sink.0.lock().unwrap();
            assert!(
                sink.announced.contains_key(&Nlri { prefix, path_id: 1 }),
                "path 1 recorded: {:?}",
                sink.announced.keys().collect::<Vec<_>>()
            );
            assert!(
                sink.announced.contains_key(&Nlri { prefix, path_id: 2 }),
                "path 2 recorded as a sibling, not a replacement"
            );
        }

        // Per-path withdrawal: only path 1 leaves.
        let withdraw = BgpUpdate {
            withdrawn: vec![Nlri { prefix, path_id: 1 }],
            ..Default::default()
        };
        let frame = BgpMessage::Update(withdraw).encode_with(true, ctx).unwrap();
        write_bytes(&mut peer.io, &frame).await;
        tokio::time::sleep(Duration::from_millis(20)).await;
        {
            let sink = peer.sink.0.lock().unwrap();
            assert_eq!(sink.withdrawn, vec![Nlri { prefix, path_id: 1 }]);
        }
        assert!(!driver.is_finished());
        driver.abort();
    }

    /// RFC 7911 §5 (transmit) + §2: with `addpath tx` configured our
    /// OPEN advertises S/R 2; the peer's S/R 1 turns the effective
    /// direction on (§5's MUST); the initial UPDATEs leave with the
    /// extended NLRI under our own per-peer ids — distinct per prefix,
    /// monotonic (B-19) — and a ROUTE-REFRESH re-advertisement keeps
    /// exactly the same ids (the stability the re-advertisement rule
    /// wants).
    #[tokio::test]
    async fn add_path_tx_session_sends_extended_updates() {
        let (ours, theirs) = duplex(8192);
        let mut config = SessionConfig::new(65000, "10.0.0.1".parse().unwrap(), 90);
        config.add_path_tx_v4 = true;
        let mut sess = PeerSession::new(
            ours,
            config,
            PeerInfo {
                address: "192.0.2.9".parse().unwrap(),
                remote_as: 65001,
                bgp_id: None,
            },
            "192.0.2.1".parse().unwrap(),
            Some(Arc::new(Networks(vec![
                "203.0.113.0/24".parse().unwrap(),
                "198.51.100.0/24".parse().unwrap(),
            ]))),
            Duration::ZERO,
        );
        let mut sink = NullSink;
        let driver = tokio::spawn(async move { sess.run(&mut sink).await });
        let mut peer = TestPeer {
            io: theirs,
            asn: 65001,
        };

        // Our OPEN must carry ONE AddPath capability, S/R 2 for v4
        // (§4: tx willing-to-send).
        let frame = read_bytes(&mut peer.io).await;
        let our_open = match BgpMessage::decode(&frame, true).unwrap() {
            BgpMessage::Open(o) => o,
            other => panic!("{other:?}"),
        };
        assert!(
            our_open.capabilities.iter().any(|c| matches!(c,
                Capability::AddPath(tuples)
                    if tuples == &vec![AddPathFamily { afi: 1, safi: 1, send_receive: 2 }])),
            "S/R 2 advertised once tx is configured: {:?}",
            our_open.capabilities
        );

        // The peer offers to RECEIVE (S/R 1) — and route refresh, for
        // the re-advertisement leg below.
        let mine = BgpOpen::new(
            65001,
            30,
            "10.9.9.9".parse().unwrap(),
            vec![
                Capability::RouteRefresh,
                Capability::AddPath(vec![AddPathFamily {
                    afi: 1,
                    safi: 1,
                    send_receive: 1,
                }]),
            ],
        );
        write_bytes(&mut peer.io, &BgpMessage::Open(mine).encode(true).unwrap()).await;
        let frame = read_bytes(&mut peer.io).await;
        assert_eq!(frame[18], message_type::KEEPALIVE);
        write_bytes(&mut peer.io, &BgpMessage::Keepalive.encode(true).unwrap()).await;

        // The initial dump: two UPDATEs (in the Networks order), each
        // decodable ONLY under the extended gate, with ids 1 and 2.
        let ctx = crate::attr::AddPathCtx {
            v4: true,
            v6: false,
        };
        async fn read_update(
            io: &mut tokio::io::DuplexStream,
            ctx: crate::attr::AddPathCtx,
        ) -> BgpUpdate {
            let frame = read_bytes(io).await;
            match BgpMessage::decode_with_handling(
                &frame,
                true,
                crate::attr::UpdateHandling::StrictRfc4271,
                ctx,
            )
            .unwrap()
            .0
            {
                BgpMessage::Update(u) => u,
                other => panic!("expected UPDATE, got {other:?}"),
            }
        }
        let first = read_update(&mut peer.io, ctx).await;
        assert_eq!(
            first.nlri[0].prefix,
            "203.0.113.0/24".parse::<IpPrefix>().unwrap()
        );
        assert_eq!(first.nlri[0].path_id, 1, "the first prefix takes id 1");
        let second = read_update(&mut peer.io, ctx).await;
        assert_eq!(
            second.nlri[0].prefix,
            "198.51.100.0/24".parse::<IpPrefix>().unwrap()
        );
        assert_eq!(
            second.nlri[0].path_id, 2,
            "the second prefix takes the next id"
        );
        // Classic decode of the same frame fails loudly (the id's top
        // octet is not a prefix length) — the /0 hazard's mirror.
        let raw = BgpMessage::Update(first.clone())
            .encode_with(true, ctx)
            .unwrap();
        assert!(
            BgpMessage::decode(&raw, true).is_err()
                || !matches!(&BgpMessage::decode(&raw, true).unwrap(),
                    BgpMessage::Update(u) if u.nlri[0].prefix == first.nlri[0].prefix),
            "classic decode must not read the extended NLRI as the same prefix"
        );

        // Re-advertisement (RFC 2918 §4): the same prefixes keep their
        // ids — §2's own-identifier regeneration is per path, and the
        // B-19 convention keeps a path's id stable across re-sends.
        // (Read past the initial dump's End-of-RIB marker first.)
        let eor = read_update(&mut peer.io, ctx).await;
        assert!(
            eor.nlri.is_empty() && eor.withdrawn.is_empty(),
            "the v4 EOR marker closes the initial dump"
        );
        write_bytes(
            &mut peer.io,
            &BgpMessage::RouteRefresh(BgpRouteRefresh { afi: 1, safi: 1 })
                .encode(true)
                .unwrap(),
        )
        .await;
        let again_first = read_update(&mut peer.io, ctx).await;
        assert_eq!(
            again_first.nlri[0].path_id, 1,
            "id 1 survives the re-advertisement"
        );
        let again_second = read_update(&mut peer.io, ctx).await;
        assert_eq!(again_second.nlri[0].path_id, 2);
        assert!(!driver.is_finished());
        driver.abort();
    }

    /// The v6 transmit arm: MP_REACH NLRI carries the id when the v6
    /// direction negotiated (RFC 7911 §3 — every NLRI field of the
    /// family).
    #[tokio::test]
    async fn add_path_tx_assigns_v6_mp_reach_ids() {
        struct V6Networks(IpPrefix);
        impl OutRib for V6Networks {
            fn advertisements(
                &self,
                _afi: u16,
                _safi: u8,
                nh: IpAddr,
                _to_peer: IpAddr,
                internal: bool,
            ) -> Vec<BgpUpdate> {
                vec![originated_update(self.0, 65000, nh, internal)]
            }
            fn families(&self) -> Vec<(u16, u8)> {
                vec![(2, 1)]
            }
        }

        let (ours, theirs) = duplex(8192);
        let mut config = SessionConfig::new(65000, "10.0.0.1".parse().unwrap(), 90);
        config.add_path_tx_v6 = true;
        let mut sess = PeerSession::new(
            ours,
            config,
            PeerInfo {
                address: "2001:db8::9".parse().unwrap(),
                remote_as: 65001,
                bgp_id: None,
            },
            "2001:db8::1".parse().unwrap(),
            Some(Arc::new(V6Networks("2001:db8:aa::/48".parse().unwrap()))),
            Duration::ZERO,
        );
        let mut sink = NullSink;
        let driver = tokio::spawn(async move { sess.run(&mut sink).await });
        let mut peer = TestPeer {
            io: theirs,
            asn: 65001,
        };

        let frame = read_bytes(&mut peer.io).await;
        let our_open = match BgpMessage::decode(&frame, true).unwrap() {
            BgpMessage::Open(o) => o,
            other => panic!("{other:?}"),
        };
        assert!(our_open.capabilities.iter().any(|c| matches!(c,
            Capability::AddPath(tuples)
                if tuples == &vec![AddPathFamily { afi: 2, safi: 1, send_receive: 2 }])));

        let mine = BgpOpen::new(
            65001,
            30,
            "10.9.9.9".parse().unwrap(),
            vec![Capability::AddPath(vec![AddPathFamily {
                afi: 2,
                safi: 1,
                send_receive: 1,
            }])],
        );
        write_bytes(&mut peer.io, &BgpMessage::Open(mine).encode(true).unwrap()).await;
        let frame = read_bytes(&mut peer.io).await;
        assert_eq!(frame[18], message_type::KEEPALIVE);
        write_bytes(&mut peer.io, &BgpMessage::Keepalive.encode(true).unwrap()).await;

        let ctx = crate::attr::AddPathCtx {
            v4: false,
            v6: true,
        };
        let frame = read_bytes(&mut peer.io).await;
        let update = match BgpMessage::decode_with_handling(
            &frame,
            true,
            crate::attr::UpdateHandling::StrictRfc4271,
            ctx,
        )
        .unwrap()
        .0
        {
            BgpMessage::Update(u) => u,
            other => panic!("expected UPDATE, got {other:?}"),
        };
        let mp = update
            .attrs
            .iter()
            .find_map(|a| match a {
                PathAttribute::MpReach(mp) => Some(mp),
                _ => None,
            })
            .expect("v6 rides MP_REACH");
        assert_eq!(mp.nlri.len(), 1);
        assert_eq!(mp.nlri[0].path_id, 1, "the MP_REACH NLRI carries our id");
        driver.abort();
    }

    /// `addpath both` on one wire: S/R 3 exchanged both ways, the
    /// session decodes the peer's extended NLRI (the N5B receive leg)
    /// AND emits its own under our ids (§5's two directions are
    /// independent MUSTs negotiated by one capability).
    #[tokio::test]
    async fn add_path_both_directions_on_one_session() {
        let (ours, theirs) = duplex(8192);
        let mut config = SessionConfig::new(65000, "10.0.0.1".parse().unwrap(), 90);
        config.add_path_rx_v4 = true;
        config.add_path_tx_v4 = true;
        let mut sess = PeerSession::new(
            ours,
            config,
            PeerInfo {
                address: "192.0.2.9".parse().unwrap(),
                remote_as: 65001,
                bgp_id: None,
            },
            "192.0.2.1".parse().unwrap(),
            Some(Arc::new(Networks(vec!["203.0.113.0/24".parse().unwrap()]))),
            Duration::ZERO,
        );
        let sink = SharedSink(Arc::new(Mutex::new(RecordingSink::default())));
        let mut driver_sink = sink.clone();
        let driver = tokio::spawn(async move { sess.run(&mut driver_sink).await });
        let mut peer = TestPeer {
            io: theirs,
            asn: 65001,
        };

        // Our OPEN: S/R 3 for v4 (both directions, one instance).
        let frame = read_bytes(&mut peer.io).await;
        let our_open = match BgpMessage::decode(&frame, true).unwrap() {
            BgpMessage::Open(o) => o,
            other => panic!("{other:?}"),
        };
        assert!(our_open.capabilities.iter().any(|c| matches!(c,
            Capability::AddPath(tuples)
                if tuples == &vec![AddPathFamily { afi: 1, safi: 1, send_receive: 3 }])));

        // The peer answers S/R 3 too: BOTH directions negotiate.
        let mine = BgpOpen::new(
            65001,
            30,
            "10.9.9.9".parse().unwrap(),
            vec![Capability::AddPath(vec![AddPathFamily {
                afi: 1,
                safi: 1,
                send_receive: 3,
            }])],
        );
        write_bytes(&mut peer.io, &BgpMessage::Open(mine).encode(true).unwrap()).await;
        let frame = read_bytes(&mut peer.io).await;
        assert_eq!(frame[18], message_type::KEEPALIVE);
        write_bytes(&mut peer.io, &BgpMessage::Keepalive.encode(true).unwrap()).await;

        // TX leg: our initial UPDATE carries the extended form (id 1).
        let tx_ctx = crate::attr::AddPathCtx {
            v4: true,
            v6: false,
        };
        let frame = read_bytes(&mut peer.io).await;
        let sent = match BgpMessage::decode_with_handling(
            &frame,
            true,
            crate::attr::UpdateHandling::StrictRfc4271,
            tx_ctx,
        )
        .unwrap()
        .0
        {
            BgpMessage::Update(u) => u,
            other => panic!("expected UPDATE, got {other:?}"),
        };
        assert_eq!(
            sent.nlri[0].path_id, 1,
            "our id under the extended encoding"
        );

        // RX leg: the peer sends a sibling pair; both land keyed.
        let prefix: IpPrefix = "198.51.100.0/24".parse().unwrap();
        let update = BgpMessage::Update(BgpUpdate {
            withdrawn: vec![],
            attrs: vec![
                PathAttribute::Origin(Origin::Igp),
                PathAttribute::AsPath(AsPath::sequence([65001])),
                PathAttribute::NextHop("192.0.2.9".parse().unwrap()),
            ],
            nlri: vec![Nlri { prefix, path_id: 5 }, Nlri { prefix, path_id: 6 }],
        })
        .encode_with(true, tx_ctx)
        .unwrap();
        write_bytes(&mut peer.io, &update).await;
        tokio::time::sleep(Duration::from_millis(30)).await;
        {
            let sink = sink.0.lock().unwrap();
            assert!(sink.announced.contains_key(&Nlri { prefix, path_id: 5 }));
            assert!(sink.announced.contains_key(&Nlri { prefix, path_id: 6 }));
        }
        driver.abort();
    }

    /// RFC 7911 §5's replacement key on OUR side: a withdrawal of a
    /// prefix we advertised toward a tx peer carries exactly the id
    /// the announcement used — the peer removes that path, not a
    /// phantom classic key.
    #[tokio::test]
    async fn add_path_tx_withdrawals_carry_the_advertised_id() {
        let (ours, _theirs) = duplex(64);
        let mut config = SessionConfig::new(65000, "10.0.0.1".parse().unwrap(), 90);
        config.add_path_tx_v4 = true;
        let mut sess = PeerSession::new(
            ours,
            config,
            PeerInfo {
                address: "192.0.2.9".parse().unwrap(),
                remote_as: 65001,
                bgp_id: None,
            },
            "192.0.2.1".parse().unwrap(),
            None,
            Duration::ZERO,
        );
        // Simulate the negotiated tx direction (Established minus the
        // wire: the FSM record is what current_add_path_tx_ctx reads).
        sess.fsm.fire(Event::Start { passive: false });
        sess.fsm.fire(Event::TcpConnectionConfirmed);
        sess.fsm.fire(Event::BgpOpen(BgpOpen::new(
            65001,
            30,
            "10.9.9.9".parse().unwrap(),
            vec![Capability::AddPath(vec![AddPathFamily {
                afi: 1,
                safi: 1,
                send_receive: 1,
            }])],
        )));
        let prefix: IpPrefix = "203.0.113.0/24".parse().unwrap();
        let mut announce = originated_update(prefix, 65000, "192.0.2.1".parse().unwrap(), false);
        sess.assign_tx_path_ids(&mut announce);
        assert_eq!(announce.nlri[0].path_id, 1, "announced under id 1");
        let mut withdraw = withdrawal_update(&[prefix]);
        sess.assign_tx_path_ids(&mut withdraw);
        assert_eq!(
            withdraw.withdrawn[0].path_id, 1,
            "the withdrawal keys the same path (RFC 7911 §5)"
        );
    }

    /// The B-19 allocator as a unit: ids start at 1 (0 is the classic
    /// key), grow monotonically with fresh prefixes, never move once
    /// assigned, and withdrawals consult the same mapping.
    #[tokio::test]
    async fn add_path_tx_allocator_monotonic_and_stable() {
        let (ours, _theirs) = duplex(64);
        let mut config = SessionConfig::new(65000, "10.0.0.1".parse().unwrap(), 90);
        config.add_path_tx_v4 = true;
        let mut sess = PeerSession::new(
            ours,
            config,
            PeerInfo {
                address: "192.0.2.9".parse().unwrap(),
                remote_as: 65001,
                bgp_id: None,
            },
            "192.0.2.1".parse().unwrap(),
            None,
            Duration::ZERO,
        );
        let a: IpPrefix = "203.0.113.0/24".parse().unwrap();
        let b: IpPrefix = "198.51.100.0/24".parse().unwrap();
        assert_eq!(sess.tx_id_for(a), 1, "first allocation is 1, never 0");
        assert_eq!(sess.tx_id_for(b), 2, "second prefix takes the next value");
        assert_eq!(
            sess.tx_id_for(a),
            1,
            "stability: the same prefix keeps its id"
        );
        assert_eq!(sess.tx_id_for(b), 2);
        // The send path is negotiation-gated (§5): without a
        // negotiated tx direction nothing is stamped — id 0, classic
        // encoding (the wire legs live in the session tests above).
        let mut update = originated_update(a, 65000, "192.0.2.1".parse().unwrap(), false);
        sess.assign_tx_path_ids(&mut update);
        assert_eq!(update.nlri[0].path_id, 0, "unnegotiated: no ids assigned");
    }

    /// A malformed AGGREGATOR (length 3) is attribute-discard only:
    /// the route lands in the sink, no withdrawal, session alive.
    #[tokio::test]
    async fn discarded_attribute_keeps_the_route() {
        let (mut peer, driver) = established_session().await;
        let body: Vec<u8> = [
            0x00, 0x00, // withdrawn len
            0x00, 0x1a, // attr len 26: ORIGIN+AS_PATH+NEXT_HOP+AGGREGATOR
            0x40, 0x01, 0x01, 0x00, // ORIGIN IGP
            0x40, 0x02, 0x06, 0x02, 0x01, 0x00, 0x00, 0xfd, 0xe9, // AS_PATH 65001
            0x40, 0x03, 0x04, 192, 0, 2, 9, // NEXT_HOP
            0xC0, 0x07, 0x03, 0x01, 0x02, 0x03, // AGGREGATOR len 3 (malformed)
            //
            24, 203, 0, 113, // NLRI 203.0.113.0/24
        ]
        .to_vec();
        peer.raw(&body).await;
        peer.expect_alive_after_keepalive(&driver).await;
        let sink = peer.sink.0.lock().unwrap();
        assert!(
            sink.announced
                .contains_key(&"203.0.113.0/24".parse().unwrap()),
            "the route itself is kept (RFC 7606 §2 attribute discard)"
        );
        assert!(sink.withdrawn.is_empty());
        driver.abort();
    }

    /// RFC 7606 §7: an UPDATE whose NLRI lacks NEXT_HOP (missing
    /// well-known mandatory) withdraws the routes instead of
    /// resetting the session (the strict mode still notifies).
    #[tokio::test]
    async fn missing_well_known_withdraws_under_7606() {
        let (mut peer, driver) = established_session().await;
        peer.advertise("198.51.100.0/24").await;
        tokio::time::sleep(Duration::from_millis(20)).await;
        // NLRI present, ORIGIN + AS_PATH only (no NEXT_HOP).
        let body: Vec<u8> = [
            0x00, 0x00, 0x00, 0x0d, // attr len 13: ORIGIN(4)+AS_PATH(9)
            0x40, 0x01, 0x01, 0x00, //
            0x40, 0x02, 0x06, 0x02, 0x01, 0x00, 0x00, 0xfd, 0xe9, //
            24, 198, 51, 100, // NLRI 198.51.100.0/24
        ]
        .to_vec();
        peer.raw(&body).await;
        peer.expect_alive_after_keepalive(&driver).await;
        let sink = peer.sink.0.lock().unwrap();
        assert!(
            sink.withdrawn.contains(&"198.51.100.0/24".parse().unwrap()),
            "missing NEXT_HOP treats the NLRI as withdrawn (RFC 7606 §7)"
        );
        assert_eq!(sink.cleared, 0);
        driver.abort();
    }

    // ---- RFC 4724 graceful restart at the session (N5 M3) -------

    /// A speaking partner that advertises the GR capability.
    fn gr_open(
        asn: u32,
        restart_state: bool,
        graceful_notification: bool,
        restart_time: u16,
    ) -> BgpOpen {
        BgpOpen::new(
            asn,
            30,
            "10.9.9.9".parse().unwrap(),
            vec![Capability::GracefulRestart {
                restart_state,
                graceful_notification,
                restart_time,
                families: vec![(1, 1, true)],
            }],
        )
    }

    /// The receiving-side lifecycle (RFC 4724 §4.2): a session with
    /// a GR peer loses the transport — routes are RETAINED (marked
    /// stale by the RIB sink), not cleared. The peer returns with
    /// the R bit set: stale stays until the End-of-RIB marker for the
    /// family arrives.
    #[tokio::test]
    async fn gr_session_loss_retains_and_eor_flushes() {
        let sink = SharedSink(Arc::new(Mutex::new(RecordingSink::default())));
        let observed = sink.clone();

        // First life: establish, learn a route, lose the transport.
        {
            let (ours, mut theirs) = duplex(8192);
            let mut sess = session(ours, 65001, None);
            let mut driver_sink = sink.clone();
            let driver = tokio::spawn(async move { sess.run(&mut driver_sink).await });
            let frame = read_bytes(&mut theirs).await;
            let _ = BgpMessage::decode(&frame, true).unwrap();
            write_bytes(
                &mut theirs,
                &BgpMessage::Open(gr_open(65001, false, false, 30))
                    .encode(true)
                    .unwrap(),
            )
            .await;
            let frame = read_bytes(&mut theirs).await;
            assert_eq!(frame[18], message_type::KEEPALIVE);
            write_bytes(&mut theirs, &BgpMessage::Keepalive.encode(true).unwrap()).await;
            let update = BgpMessage::Update(BgpUpdate {
                withdrawn: vec![],
                attrs: vec![
                    PathAttribute::Origin(Origin::Igp),
                    PathAttribute::AsPath(AsPath::sequence([65001])),
                    PathAttribute::NextHop("192.0.2.9".parse().unwrap()),
                ],
                nlri: vec!["203.0.113.0/24".parse().unwrap()],
            });
            write_bytes(&mut theirs, &update.encode(true).unwrap()).await;
            tokio::time::sleep(Duration::from_millis(30)).await;
            theirs.shutdown().await.unwrap();
            let end = driver.await.unwrap();
            assert!(matches!(end, SessionEnd::Transport(_)));
        }
        let flushed_before;
        {
            let sink = observed.0.lock().unwrap();
            assert_eq!(sink.retained, 1, "routes retained stale (RFC 4724 §4.2)");
            assert_eq!(sink.cleared, 0, "no delete on a GR session loss");
            // (The first life's own Established ran an R-clear flush
            // over an empty stale table — a no-op.)
            flushed_before = sink.flushed;
        }

        // Second life: the peer restarts (R bit set) — stale retained
        // through re-establishment, then the v4 End-of-RIB flushes.
        {
            let (ours, mut theirs) = duplex(8192);
            let mut sess = session(ours, 65001, None);
            let mut driver_sink = sink.clone();
            let driver = tokio::spawn(async move { sess.run(&mut driver_sink).await });
            let frame = read_bytes(&mut theirs).await;
            let _ = BgpMessage::decode(&frame, true).unwrap();
            write_bytes(
                &mut theirs,
                &BgpMessage::Open(gr_open(65001, true, false, 30))
                    .encode(true)
                    .unwrap(),
            )
            .await;
            let frame = read_bytes(&mut theirs).await;
            assert_eq!(frame[18], message_type::KEEPALIVE);
            write_bytes(&mut theirs, &BgpMessage::Keepalive.encode(true).unwrap()).await;
            tokio::time::sleep(Duration::from_millis(30)).await;
            {
                let sink = observed.0.lock().unwrap();
                assert_eq!(
                    sink.flushed, flushed_before,
                    "R bit set: no new flush before EOR"
                );
            }
            // The bare minimum UPDATE = the v4-unicast End-of-RIB.
            write_bytes(
                &mut theirs,
                &BgpUpdate::default().encode_frame(true).unwrap(),
            )
            .await;
            tokio::time::sleep(Duration::from_millis(30)).await;
            {
                let sink = observed.0.lock().unwrap();
                assert_eq!(sink.eors, vec![(1, 1)], "v4 EOR observed");
            }
            theirs.shutdown().await.unwrap();
            let _ = driver.await.unwrap();
        }
    }

    /// Re-establishment WITHOUT the R bit: stale routes are flushed
    /// immediately at Established (before the new exchange).
    #[tokio::test]
    async fn gr_re_establishment_without_r_bit_flushes() {
        let sink = SharedSink(Arc::new(Mutex::new(RecordingSink::default())));
        let observed = sink.clone();
        {
            let (ours, mut theirs) = duplex(8192);
            let mut sess = session(ours, 65001, None);
            let mut driver_sink = sink.clone();
            let driver = tokio::spawn(async move { sess.run(&mut driver_sink).await });
            let frame = read_bytes(&mut theirs).await;
            let _ = BgpMessage::decode(&frame, true).unwrap();
            write_bytes(
                &mut theirs,
                &BgpMessage::Open(gr_open(65001, false, false, 30))
                    .encode(true)
                    .unwrap(),
            )
            .await;
            let _ = read_bytes(&mut theirs).await;
            write_bytes(&mut theirs, &BgpMessage::Keepalive.encode(true).unwrap()).await;
            tokio::time::sleep(Duration::from_millis(20)).await;
            theirs.shutdown().await.unwrap();
            let _ = driver.await.unwrap();
        }
        assert_eq!(observed.0.lock().unwrap().retained, 1);
        let flushed_before = observed.0.lock().unwrap().flushed;
        {
            let (ours, mut theirs) = duplex(8192);
            let mut sess = session(ours, 65001, None);
            let mut driver_sink = sink.clone();
            let driver = tokio::spawn(async move { sess.run(&mut driver_sink).await });
            let frame = read_bytes(&mut theirs).await;
            let _ = BgpMessage::decode(&frame, true).unwrap();
            write_bytes(
                &mut theirs,
                &BgpMessage::Open(gr_open(65001, false, false, 30))
                    .encode(true)
                    .unwrap(),
            )
            .await;
            let _ = read_bytes(&mut theirs).await;
            write_bytes(&mut theirs, &BgpMessage::Keepalive.encode(true).unwrap()).await;
            tokio::time::sleep(Duration::from_millis(30)).await;
            {
                let sink = observed.0.lock().unwrap();
                assert_eq!(
                    sink.flushed,
                    flushed_before + 1,
                    "no R bit: stale deleted at Established"
                );
            }
            theirs.shutdown().await.unwrap();
            let _ = driver.await.unwrap();
        }
    }

    // ---- RFC 8538 graceful notification (B-7, S8-a) ----------------

    /// The shared harness leg: establish with a peer whose OPEN
    /// carries the GR capability (N set per `n`), learn one route.
    async fn n_session_established_with_route(theirs: &mut tokio::io::DuplexStream, n: bool) {
        let frame = read_bytes(theirs).await;
        let _ = BgpMessage::decode(&frame, true).unwrap();
        write_bytes(
            theirs,
            &BgpMessage::Open(gr_open(65001, false, n, 30))
                .encode(true)
                .unwrap(),
        )
        .await;
        let _ = read_bytes(theirs).await; // our KEEPALIVE
        write_bytes(theirs, &BgpMessage::Keepalive.encode(true).unwrap()).await;
        let update = BgpMessage::Update(BgpUpdate {
            withdrawn: vec![],
            attrs: vec![
                PathAttribute::Origin(Origin::Igp),
                PathAttribute::AsPath(AsPath::sequence([65001])),
                PathAttribute::NextHop("192.0.2.9".parse().unwrap()),
            ],
            nlri: vec!["203.0.113.0/24".parse().unwrap()],
        });
        write_bytes(theirs, &update.encode(true).unwrap()).await;
        tokio::time::sleep(Duration::from_millis(30)).await;
    }

    /// RFC 8538 §4/§4.1: a NOTIFICATION received over a session whose
    /// peer advertised the N bit — and that is not a Hard Reset — is a
    /// GRACEFUL close: the Receiving Speaker rules retain the peer's
    /// routes marked stale instead of the RFC 4724 §4.2 deliberate
    /// delete. The restart-timer flush (daemon side) sweeps them if
    /// the peer never returns.
    #[tokio::test]
    async fn graceful_notification_retains_stale() {
        let sink = SharedSink(Arc::new(Mutex::new(RecordingSink::default())));
        let (ours, mut theirs) = duplex(8192);
        let mut sess = session(ours, 65001, None);
        let mut driver_sink = sink.clone();
        let driver = tokio::spawn(async move { sess.run(&mut driver_sink).await });
        n_session_established_with_route(&mut theirs, true).await;
        // A transient Cease (6/7, Collision Resolution — §5.1's
        // "Graceful Cease" row) from the N-bit peer.
        write_bytes(
            &mut theirs,
            &BgpMessage::Notification(BgpNotification::cease(
                error::cease_subcode::COLLISION_RESOLUTION_FAILURE,
            ))
            .encode(true)
            .unwrap(),
        )
        .await;
        let end = driver.await.unwrap();
        assert!(matches!(
            end,
            SessionEnd::PeerNotified {
                code: 6,
                subcode: 7
            }
        ));
        let sink = sink.0.lock().unwrap();
        assert_eq!(sink.retained, 1, "routes retained stale (RFC 8538 §4.1)");
        assert_eq!(sink.cleared, 0, "no RFC 4271 delete on a graceful close");
    }

    /// RFC 8538 §3.2: "Whenever a BGP speaker receives a Hard Reset,
    /// the speaker MUST terminate the BGP session following the
    /// standard procedures in [RFC4271]" — the routes are deleted even
    /// though the N bit was exchanged (the encapsulated reason rides
    /// along for the log).
    #[tokio::test]
    async fn hard_reset_received_hard_clears() {
        let sink = SharedSink(Arc::new(Mutex::new(RecordingSink::default())));
        let (ours, mut theirs) = duplex(8192);
        let mut sess = session(ours, 65001, None);
        let mut driver_sink = sink.clone();
        let driver = tokio::spawn(async move { sess.run(&mut driver_sink).await });
        n_session_established_with_route(&mut theirs, true).await;
        let hard = BgpNotification::hard_reset(&BgpNotification::cease(
            error::cease_subcode::ADMIN_SHUTDOWN,
        ));
        write_bytes(
            &mut theirs,
            &BgpMessage::Notification(hard).encode(true).unwrap(),
        )
        .await;
        let end = driver.await.unwrap();
        assert!(matches!(
            end,
            SessionEnd::PeerNotified {
                code: 6,
                subcode: 9
            }
        ));
        let sink = sink.0.lock().unwrap();
        assert_eq!(sink.cleared, 1, "RFC 4271 delete (Hard Reset)");
        assert_eq!(sink.retained, 0);
    }

    /// The same notification WITHOUT the N bit stays the RFC 4724
    /// §4.2 deliberate close (B-7 changes nothing for a 4724-only
    /// peer).
    #[tokio::test]
    async fn notification_without_n_bit_still_hard_clears() {
        let sink = SharedSink(Arc::new(Mutex::new(RecordingSink::default())));
        let (ours, mut theirs) = duplex(8192);
        let mut sess = session(ours, 65001, None);
        let mut driver_sink = sink.clone();
        let driver = tokio::spawn(async move { sess.run(&mut driver_sink).await });
        n_session_established_with_route(&mut theirs, false).await;
        write_bytes(
            &mut theirs,
            &BgpMessage::Notification(BgpNotification::cease(
                error::cease_subcode::COLLISION_RESOLUTION_FAILURE,
            ))
            .encode(true)
            .unwrap(),
        )
        .await;
        let _ = driver.await.unwrap();
        let sink = sink.0.lock().unwrap();
        assert_eq!(sink.cleared, 1, "no N bit: the RFC 4724 delete stands");
        assert_eq!(sink.retained, 0);
    }

    /// Send side (§5.1 + §3.1): our ManualStop's Administrative
    /// Shutdown (Cease/2 — a "Hard Reset" table row) rides toward an
    /// N-bit peer as Cease/9 wrapping the reason; toward a 4724-only
    /// peer it stays the plain Cease/2.
    #[tokio::test]
    async fn manual_stop_wraps_shutdown_only_for_n_peer() {
        for n_peer in [true, false] {
            let sink = SharedSink(Arc::new(Mutex::new(RecordingSink::default())));
            let (ours, mut theirs) = duplex(8192);
            let mut sess = session(ours, 65001, None);
            let (stop_tx, stop_rx) = tokio::sync::watch::channel(false);
            let (_refresh_tx, refresh_rx) = tokio::sync::watch::channel(0u64);
            let mut driver_sink = sink.clone();
            let driver = tokio::spawn(async move {
                sess.run_with_signals(&mut driver_sink, stop_rx, refresh_rx)
                    .await
            });
            n_session_established_with_route(&mut theirs, n_peer).await;
            stop_tx.send(true).unwrap();
            // Skip past the initial dump's EOR markers to the Cease.
            let mut notified = None;
            for _ in 0..8 {
                let frame = read_bytes(&mut theirs).await;
                if let BgpMessage::Notification(n) = BgpMessage::decode(&frame, true).unwrap() {
                    notified = Some(n);
                    break;
                }
            }
            let notified = notified.expect("expected NOTIFICATION");
            if n_peer {
                assert_eq!((notified.code, notified.subcode), (6, 9), "Hard Reset");
                let reason = notified.hard_reset_reason().unwrap();
                assert_eq!(
                    (reason.code, reason.subcode),
                    (6, error::cease_subcode::ADMIN_SHUTDOWN)
                );
            } else {
                assert_eq!(
                    (notified.code, notified.subcode),
                    (6, error::cease_subcode::ADMIN_SHUTDOWN),
                    "plain Cease toward a 4724-only peer"
                );
                assert!(!notified.is_hard_reset());
            }
            let end = driver.await.unwrap();
            assert!(matches!(end, SessionEnd::ManualStop));
            // Our own ManualStop is a deliberate close of our side —
            // the received routes are deleted, never retained.
            let sink = sink.0.lock().unwrap();
            assert_eq!(sink.cleared, 1);
            assert_eq!(sink.retained, 0);
        }
    }

    /// A session loss WITHOUT the GR capability deletes as before
    /// (clear_peer, no retention).
    #[tokio::test]
    async fn non_gr_session_loss_still_clears() {
        let (ours, theirs) = duplex(8192);
        let mut sess = session(ours, 65001, None);
        let sink = SharedSink(Arc::new(Mutex::new(RecordingSink::default())));
        let mut driver_sink = sink.clone();
        let driver = tokio::spawn(async move { sess.run(&mut driver_sink).await });
        let mut partner = TestPeer {
            io: theirs,
            asn: 65001,
        };
        partner.handshake(65000).await;
        partner.io.shutdown().await.unwrap();
        let _ = driver.await.unwrap();
        let sink = sink.0.lock().unwrap();
        assert_eq!(sink.cleared, 1, "RFC 4271 delete (no capability)");
        assert_eq!(sink.retained, 0);
    }

    /// The sending side (N5 scope): `with_graceful_restart(120)` puts
    /// the capability in our OPEN, and Established ends the initial
    /// dump with the per-family End-of-RIB markers (v4 bare + v6
    /// empty MP_UNREACH).
    #[tokio::test]
    async fn gr_sending_side_advertises_and_emits_eor() {
        let (ours, mut theirs) = duplex(8192);
        let mut sess = session(ours, 65001, None).with_graceful_restart(120);
        let mut sink = NullSink;
        let driver = tokio::spawn(async move { sess.run(&mut sink).await });

        // Our OPEN carries capability 64 with time 120, R clear, N set
        // (RFC 8538 §2 — every GR capability bgpd advertises).
        let frame = read_bytes(&mut theirs).await;
        let open = match BgpMessage::decode(&frame, true).unwrap() {
            BgpMessage::Open(o) => o,
            other => panic!("{other:?}"),
        };
        assert!(
            open.capabilities.contains(&Capability::GracefulRestart {
                restart_state: false,
                graceful_notification: true,
                restart_time: 120,
                families: vec![(1, 1, false), (2, 1, false)],
            }),
            "the GR capability rides our OPEN: {:?}",
            open.capabilities
        );
        let mine = BgpOpen::new(65001, 30, "10.9.9.9".parse().unwrap(), vec![]);
        write_bytes(&mut theirs, &BgpMessage::Open(mine).encode(true).unwrap()).await;
        let _ = read_bytes(&mut theirs).await; // our KEEPALIVE
        write_bytes(&mut theirs, &BgpMessage::Keepalive.encode(true).unwrap()).await;

        // Established (no out_rib -> no routes): the two EOR markers
        // still close their families' (empty) dumps.
        let frame = read_bytes(&mut theirs).await;
        let eor4 = match BgpMessage::decode(&frame, true).unwrap() {
            BgpMessage::Update(u) => u,
            other => panic!("expected the v4 EOR, got {other:?}"),
        };
        assert_eq!(eor4.end_of_rib(), Some(None), "bare minimum UPDATE");
        let frame = read_bytes(&mut theirs).await;
        let eor6 = match BgpMessage::decode(&frame, true).unwrap() {
            BgpMessage::Update(u) => u,
            other => panic!("expected the v6 EOR, got {other:?}"),
        };
        assert_eq!(eor6.end_of_rib(), Some(Some((2, 1))), "empty MP_UNREACH");
        driver.abort();
    }

    // ---- RFC 4724 §4.1: the restarting speaker (S7-b M3) ----------

    /// §4.1's re-establishment duties: the OPEN carries the Restart
    /// State bit, and the initial Adj-RIB-Out dump is DEFERRED —
    /// nothing is advertised until the peer's End-of-RIB arrives, then
    /// the dump runs and closes with our own EOR ("the End-of-RIB
    /// marker MUST be sent" once the initial update completes).
    #[tokio::test]
    async fn restarting_session_sets_r_bit_and_defers_until_eor() {
        let (ours, mut theirs) = duplex(8192);
        let mut sess = PeerSession::new(
            ours,
            SessionConfig::new(65000, "10.0.0.1".parse().unwrap(), 90),
            PeerInfo {
                address: "192.0.2.9".parse().unwrap(),
                remote_as: 65001,
                bgp_id: None,
            },
            "192.0.2.1".parse().unwrap(),
            Some(Arc::new(Networks(vec!["203.0.113.0/24".parse().unwrap()]))),
            Duration::ZERO,
        )
        .with_graceful_restart(120)
        .with_restart_state()
        .with_gr_deferral(1);
        let mut sink = NullSink;
        let driver = tokio::spawn(async move { sess.run(&mut sink).await });

        // Our OPEN: the GR capability with the R bit SET (§4.1) — and
        // the N bit survives the rewrite (8538 §2).
        let frame = read_bytes(&mut theirs).await;
        let open = match BgpMessage::decode(&frame, true).unwrap() {
            BgpMessage::Open(o) => o,
            other => panic!("{other:?}"),
        };
        assert!(
            open.capabilities.contains(&Capability::GracefulRestart {
                restart_state: true,
                graceful_notification: true,
                restart_time: 120,
                families: vec![(1, 1, false), (2, 1, false)],
            }),
            "the R bit rides the re-establishment OPEN: {:?}",
            open.capabilities
        );
        let mine = BgpOpen::new(65001, 30, "10.9.9.9".parse().unwrap(), vec![]);
        write_bytes(&mut theirs, &BgpMessage::Open(mine).encode(true).unwrap()).await;
        let _ = read_bytes(&mut theirs).await; // our KEEPALIVE
        write_bytes(&mut theirs, &BgpMessage::Keepalive.encode(true).unwrap()).await;

        // Established — the dump must NOT follow: §4.1 defers route
        // selection until the peer's EOR (300 ms of real silence; the
        // negotiated keepalive is 10 s, so only the deferral could
        // break the silence).
        let nothing =
            tokio::time::timeout(Duration::from_millis(300), read_bytes(&mut theirs)).await;
        assert!(
            nothing.is_err(),
            "the initial dump is deferred (RFC 4724 §4.1)"
        );

        // The peer's v4 End-of-RIB ends the deferral: the network
        // UPDATE arrives and the dump closes with our own EOR.
        write_bytes(
            &mut theirs,
            &BgpUpdate::default().encode_frame(true).unwrap(),
        )
        .await;
        let frame = read_bytes(&mut theirs).await;
        let update = match BgpMessage::decode(&frame, true).unwrap() {
            BgpMessage::Update(u) => u,
            other => panic!("expected the deferred UPDATE, got {other:?}"),
        };
        assert_eq!(update.nlri, vec!["203.0.113.0/24".parse().unwrap()]);
        let frame = read_bytes(&mut theirs).await;
        let eor = match BgpMessage::decode(&frame, true).unwrap() {
            BgpMessage::Update(u) => u,
            other => panic!("expected our EOR, got {other:?}"),
        };
        assert_eq!(
            eor.end_of_rib(),
            Some(None),
            "§4.1: EOR after the initial update"
        );
        driver.abort();
    }

    /// §4.1's Selection_Deferral_Timer: without the peer's EOR, the
    /// timer expires and the restart proceeds anyway — the retained
    /// stale is flushed (re-selection) and the dump advertises.
    /// Paused clock: idle time auto-advances the 120 s deferral
    /// (keepalives at the 10 s cadence pass by unread).
    #[tokio::test(start_paused = true)]
    async fn restarting_deferral_timer_flushes_the_dump() {
        let (ours, mut theirs) = duplex(8192);
        let mut sess = PeerSession::new(
            ours,
            SessionConfig::new(65000, "10.0.0.1".parse().unwrap(), 90),
            PeerInfo {
                address: "192.0.2.9".parse().unwrap(),
                remote_as: 65001,
                bgp_id: None,
            },
            "192.0.2.1".parse().unwrap(),
            Some(Arc::new(Networks(vec!["203.0.113.0/24".parse().unwrap()]))),
            Duration::ZERO,
        )
        .with_graceful_restart(120)
        .with_restart_state()
        .with_gr_deferral(1);
        let sink = SharedSink(Arc::new(Mutex::new(RecordingSink::default())));
        let observed = sink.clone();
        let mut driver_sink = sink.clone();
        let driver = tokio::spawn(async move { sess.run(&mut driver_sink).await });

        let frame = read_bytes(&mut theirs).await;
        let _ = BgpMessage::decode(&frame, true).unwrap();
        let mine = BgpOpen::new(65001, 30, "10.9.9.9".parse().unwrap(), vec![]);
        write_bytes(&mut theirs, &BgpMessage::Open(mine).encode(true).unwrap()).await;
        let _ = read_bytes(&mut theirs).await;
        write_bytes(&mut theirs, &BgpMessage::Keepalive.encode(true).unwrap()).await;

        // No EOR will ever arrive: idle paused time advances past the
        // keepalives (10 s cadence) to the 120 s deferral — the first
        // UPDATE frame is the timer-flushed dump.
        let frame = loop {
            let frame = read_bytes(&mut theirs).await;
            if frame[18] == message_type::UPDATE {
                break frame;
            }
        };
        let update = match BgpMessage::decode(&frame, true).unwrap() {
            BgpMessage::Update(u) => u,
            other => panic!("{other:?}"),
        };
        assert_eq!(update.nlri, vec!["203.0.113.0/24".parse().unwrap()]);
        // Re-selection ran: the stale sweep fired on the sink.
        {
            let sink = observed.0.lock().unwrap();
            assert_eq!(sink.flushed, 1, "the expired deferral flushed the stale");
        }
        driver.abort();
    }

    // --- SAVNET agent hooks (experimental-savnet only) ---

    #[cfg(feature = "experimental-savnet")]
    mod savnet_hooks {
        use super::*;
        use crate::attr::{AsPath, MpNextHop, MpReach, Origin, PathAttribute};
        use crate::message::BgpNotification;
        use std::sync::Mutex as StdMutex;
        use tokio::io::{duplex, AsyncWriteExt};

        /// An agent that records every event (the contract-test
        /// shape from the sav crate, local copy so the wiring is
        /// proven against the anchor's own call sites).
        #[derive(Default)]
        struct RecordingAgent {
            events: StdMutex<Vec<sav::agent::SavAgentEvent>>,
        }

        impl sav::agent::SavAgent for RecordingAgent {
            fn on_event(&self, event: sav::agent::SavAgentEvent) {
                self.events.lock().unwrap().push(event);
            }
            fn binding_suggestions(&self) -> Vec<sav::agent::SavBindingSuggestion> {
                Vec::new()
            }
        }

        fn sav_peer_of(address: &str, remote_as: u32) -> sav::agent::SavPeer {
            sav::agent::SavPeer {
                address: address.parse().unwrap(),
                remote_id: remote_as,
            }
        }

        /// The full sequence: Established reports adjacency up, an
        /// UPDATE reports installs and withdraws at the on_message
        /// UPDATE arm (Adj-RIB-In granularity, pre-best-path), and the
        /// session teardown (received NOTIFICATION) reports adjacency
        /// down — exactly once.
        #[tokio::test]
        async fn session_reports_the_savnet_event_sequence() {
            let agent = Arc::new(RecordingAgent::default());
            let (ours, mut theirs) = duplex(4096);
            let mut session = PeerSession::new(
                ours,
                SessionConfig::new(65000, "192.0.2.1".parse().unwrap(), 90),
                PeerInfo {
                    address: "192.0.2.9".parse().unwrap(),
                    remote_as: 65001,
                    bgp_id: None,
                },
                "192.0.2.1".parse().unwrap(),
                None,
                Duration::ZERO,
            )
            .with_shared(Arc::new(SessionShared::default()))
            .with_sav_agent(Arc::clone(&agent) as Arc<dyn sav::agent::SavAgent>);
            let sink = SharedSink(Arc::new(std::sync::Mutex::new(NullSink)));
            let driver_sink = sink.clone();
            let driver = tokio::spawn(async move { session.run(&mut { driver_sink }).await });

            // OPEN + KEEPALIVE -> Established.
            let open = BgpMessage::Open(crate::message::BgpOpen::new(
                65001,
                30,
                "10.9.9.9".parse().unwrap(),
                vec![],
            ))
            .encode(true)
            .unwrap();
            theirs.write_all(&open).await.unwrap();
            let keepalive = BgpMessage::Keepalive.encode(true).unwrap();
            theirs.write_all(&keepalive).await.unwrap();

            // Two UPDATEs (RFC 7606 §5.1: one route container each —
            // B-4's encode guard rejects the mixed frame): announce
            // 203.0.113.0/24 via 192.0.2.9, then withdraw
            // 198.51.100.0/24.
            let attrs = vec![
                PathAttribute::Origin(Origin::Igp),
                PathAttribute::AsPath(AsPath::sequence([65001])),
                PathAttribute::NextHop("192.0.2.9".parse().unwrap()),
            ];
            let announce = BgpMessage::Update(BgpUpdate {
                attrs,
                nlri: vec!["203.0.113.0/24".parse().unwrap()],
                ..Default::default()
            })
            .encode(true)
            .unwrap();
            theirs.write_all(&announce).await.unwrap();
            let withdraw = BgpMessage::Update(BgpUpdate {
                withdrawn: vec!["198.51.100.0/24".parse().unwrap()],
                ..Default::default()
            })
            .encode(true)
            .unwrap();
            theirs.write_all(&withdraw).await.unwrap();

            // Teardown by NOTIFICATION (Cease): adjacency down fires.
            let notification = BgpMessage::Notification(BgpNotification::cease(3))
                .encode(true)
                .unwrap();
            theirs.write_all(&notification).await.unwrap();

            let end = driver.await.unwrap();
            assert!(matches!(end, SessionEnd::PeerNotified { .. }));

            let events = agent.events.lock().unwrap().clone();
            let peer = sav_peer_of("192.0.2.9", 65001);
            assert_eq!(
                events,
                vec![
                    sav::agent::SavAgentEvent::AdjacencyUp {
                        protocol: sav::agent::SavProtocol::Bgp,
                        peer: peer.clone(),
                        ifindex: None,
                    },
                    sav::agent::SavAgentEvent::RouteInstalled {
                        source: sav::agent::SavEventSource::Bgp(peer.clone()),
                        prefix: "203.0.113.0/24".parse().unwrap(),
                        nexthop: Some("192.0.2.9".parse().unwrap()),
                    },
                    sav::agent::SavAgentEvent::RouteWithdrawn {
                        source: sav::agent::SavEventSource::Bgp(peer.clone()),
                        prefix: "198.51.100.0/24".parse().unwrap(),
                    },
                    sav::agent::SavAgentEvent::AdjacencyDown {
                        protocol: sav::agent::SavProtocol::Bgp,
                        peer,
                    },
                ],
                "adjacency up -> install -> withdraw -> adjacency down, exactly once each"
            );
        }

        /// The v6 arm of the next-hop extraction: an MP_REACH
        /// announcement reports the global next-hop address.
        #[tokio::test]
        async fn v6_mp_reach_updates_report_the_global_next_hop() {
            let agent = Arc::new(RecordingAgent::default());
            let (ours, mut theirs) = duplex(4096);
            let mut session = PeerSession::new(
                ours,
                SessionConfig::new(65000, "10.0.0.1".parse().unwrap(), 90),
                PeerInfo {
                    address: "2001:db8::9".parse().unwrap(),
                    remote_as: 65001,
                    bgp_id: None,
                },
                "2001:db8::1".parse().unwrap(),
                None,
                Duration::ZERO,
            )
            .with_sav_agent(Arc::clone(&agent) as Arc<dyn sav::agent::SavAgent>);
            let mut sink = NullSink;
            let driver = tokio::spawn(async move { session.run(&mut sink).await });

            let open = BgpMessage::Open(crate::message::BgpOpen::new(
                65001,
                30,
                "10.9.9.9".parse().unwrap(),
                vec![],
            ))
            .encode(true)
            .unwrap();
            theirs.write_all(&open).await.unwrap();
            theirs
                .write_all(&BgpMessage::Keepalive.encode(true).unwrap())
                .await
                .unwrap();

            let update = BgpMessage::Update(BgpUpdate {
                withdrawn: vec![],
                attrs: vec![
                    PathAttribute::Origin(Origin::Igp),
                    PathAttribute::AsPath(AsPath::sequence([65001])),
                    PathAttribute::MpReach(MpReach {
                        afi: 2,
                        safi: 1,
                        next_hop: MpNextHop::V6 {
                            global: "2001:db8::9".parse().unwrap(),
                            link_local: None,
                        },
                        nlri: vec!["2001:db8:aa::/48".parse().unwrap()],
                    }),
                ],
                nlri: vec![],
            })
            .encode(true)
            .unwrap();
            theirs.write_all(&update).await.unwrap();
            // Teardown.
            theirs
                .write_all(
                    &BgpMessage::Notification(BgpNotification::cease(3))
                        .encode(true)
                        .unwrap(),
                )
                .await
                .unwrap();
            let _ = driver.await.unwrap();

            let events = agent.events.lock().unwrap().clone();
            let install = events.iter().find_map(|event| match event {
                event @ sav::agent::SavAgentEvent::RouteInstalled { .. } => Some(event.clone()),
                _ => None,
            });
            assert_eq!(
                install,
                Some(sav::agent::SavAgentEvent::RouteInstalled {
                    source: sav::agent::SavEventSource::Bgp(sav_peer_of("2001:db8::9", 65001)),
                    prefix: "2001:db8:aa::/48".parse().unwrap(),
                    nexthop: Some("2001:db8::9".parse().unwrap()),
                })
            );
        }
    }
}
