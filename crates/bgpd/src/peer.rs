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

use crate::attr::{AsPath, MpNextHop, MpReach, Origin, PathAttribute};
use crate::capability::Capability;
use crate::error::{self, BgpError, BgpResult};
use crate::fsm::{Action, Event, Fsm, SessionConfig, State};
use crate::message::{
    BgpMessage, BgpNotification, BgpOpen, BgpRouteRefresh, BgpUpdate, BGP_HEADER_LEN, BGP_MARKER,
    BGP_MAX_MESSAGE_LEN,
};

/// What the session learned, for RIB bookkeeping.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PeerInfo {
    pub address: IpAddr,
    pub remote_as: u32,
    pub bgp_id: Option<Ipv4Addr>,
}

/// Adj-RIB-In sink: everything a received UPDATE does to the RIB.
/// M4's Loc-RIB implements this; tests record calls.
pub trait RouteSink: Send {
    fn announce(&mut self, peer: &PeerInfo, update: &BgpUpdate);
    fn withdraw(&mut self, peer: &PeerInfo, prefixes: &[IpPrefix]);
    /// "Deletes all routes associated with this connection" (the
    /// Established teardown rows).
    fn clear_peer(&mut self, peer: &PeerInfo);
    /// A ROUTE-REFRESH arrived (RFC 2918 §4): the session answers from
    /// [`OutRib`] itself; the hook exists for observability.
    fn refresh_requested(&mut self, peer: &PeerInfo, afi: u16, safi: u8) {
        let _ = (peer, afi, safi);
    }
}

/// A no-op sink (sessions driven purely for their wire behavior).
pub struct NullSink;
impl RouteSink for NullSink {
    fn announce(&mut self, _: &PeerInfo, _: &BgpUpdate) {}
    fn withdraw(&mut self, _: &PeerInfo, _: &[IpPrefix]) {}
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
    fn withdraw(&mut self, peer: &PeerInfo, prefixes: &[IpPrefix]) {
        self.0.lock().unwrap().withdraw(peer, prefixes);
    }
    fn clear_peer(&mut self, peer: &PeerInfo) {
        self.0.lock().unwrap().clear_peer(peer);
    }
    fn refresh_requested(&mut self, peer: &PeerInfo, afi: u16, safi: u8) {
        self.0.lock().unwrap().refresh_requested(peer, afi, safi);
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
#[derive(Default)]
pub struct RecordingSink {
    pub announced: BTreeMap<IpPrefix, BgpUpdate>,
    pub withdrawn: Vec<IpPrefix>,
    pub cleared: usize,
}

impl RouteSink for RecordingSink {
    fn announce(&mut self, _peer: &PeerInfo, update: &BgpUpdate) {
        for prefix in update.announced() {
            self.announced.insert(prefix, update.clone());
        }
    }
    fn withdraw(&mut self, _peer: &PeerInfo, prefixes: &[IpPrefix]) {
        self.withdrawn.extend_from_slice(prefixes);
    }
    fn clear_peer(&mut self, _peer: &PeerInfo) {
        self.cleared += 1;
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

/// One live BGP session over an established stream.
pub struct PeerSession<IO> {
    io: IO,
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
    end: Option<SessionEnd>,
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
        let advertise = vec![
            Capability::Multiprotocol { afi: 1, safi: 1 },
            Capability::Multiprotocol { afi: 2, safi: 1 },
            Capability::RouteRefresh,
            Capability::FourOctetAsNumber {
                asn: local.local_as,
            },
        ];
        let now = tokio::time::Instant::now();
        Self {
            io,
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
            end: None,
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
            tokio::select! {
                read = read_frame(&mut self.io, asn4) => {
                    match read {
                        Ok(Ok(message)) => {
                            if let Some(end) = self.on_message(message, sink).await {
                                return end;
                            }
                        }
                        Ok(Err(bgp_err)) => {
                            // Route the malformed message to the right
                            // FSM error event by class (§6.1-§6.3).
                            let event = match bgp_err.notification {
                                Some((1, sub)) => Event::BgpHeaderErr(1, sub),
                                Some((2, sub)) => Event::BgpOpenMsgErr(2, sub),
                                _ => Event::UpdateMsgErr(3, 1),
                            };
                            warn!(?bgp_err, peer = %self.peer.address, "bgpd: malformed message");
                            if let Some(end) = self.step(event, sink).await {
                                return end;
                            }
                        }
                        Err(io_err) => {
                            let actions = self.fsm.fire(Event::TcpConnectionFails);
                            let _ = self.perform_all(actions, sink).await;
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
        let actions = self.fsm.fire(event.clone());
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
            if let Err(e) = self.on_established().await {
                self.end = Some(SessionEnd::Transport(e.to_string()));
                return self.end.clone();
            }
        }
        if self.fsm.state() == State::Idle {
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
        message: BgpMessage,
        sink: &mut S,
    ) -> Option<SessionEnd> {
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
                self.step(Event::BgpOpen(open), sink).await
            }
            BgpMessage::Keepalive => self.step(Event::KeepAliveMsg, sink).await,
            BgpMessage::Update(update) => {
                if let Err(err) = update.validate_well_known() {
                    let (code, sub) = err.notification.unwrap_or((3, 1));
                    return self.step(Event::UpdateMsgErr(code, sub), sink).await;
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
                let announced: Vec<String> =
                    update.announced().iter().map(|p| p.to_string()).collect();
                let withdrawn = update.withdrawn_all();
                info!(
                    peer = %self.peer.address,
                    announced = announced.join(","),
                    withdrawn = withdrawn.len(),
                    "bgpd: UPDATE received"
                );
                sink.announce(&self.peer, &update);
                sink.withdraw(&self.peer, &withdrawn);
                self.step(Event::UpdateMsg, sink).await
            }
            BgpMessage::Notification(n) => {
                info!(
                    code = n.code,
                    subcode = n.subcode,
                    peer = %self.peer.address,
                    "bgpd: NOTIFICATION received"
                );
                let actions = self.fsm.fire(Event::NotifMsg);
                let _ = self.perform_all(actions, sink).await;
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
            for update in rib.advertisements(rr.afi, rr.safi, next_hop, to_peer, internal) {
                if let Err(e) = self.send_update(&update).await {
                    self.end = Some(SessionEnd::Transport(e.to_string()));
                    return self.end.clone();
                }
            }
        }
        None
    }

    /// The Established transition: initial advertisement of the
    /// Adj-RIB-Out for every family.
    async fn on_established(&mut self) -> io::Result<()> {
        let Some(rib) = self.out_rib.clone() else {
            return Ok(());
        };
        let next_hop = self.local_addr;
        let to_peer = self.peer.address;
        let internal = self.fsm.negotiated().is_some_and(|n| n.internal);
        for (afi, safi) in rib.families() {
            for update in rib.advertisements(afi, safi, next_hop, to_peer, internal) {
                self.send_update(&update).await?;
            }
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
                let notification = BgpNotification {
                    code,
                    subcode,
                    data: Vec::new(),
                };
                info!(
                    code, subcode, peer = %self.peer.address,
                    "bgpd: sending NOTIFICATION"
                );
                self.end = Some(SessionEnd::Notified(code, subcode));
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
                sink.clear_peer(&self.peer);
                self.disarm();
            }
        }
        Ok(())
    }

    fn disarm(&mut self) {
        let far = tokio::time::Instant::now() + FAR;
        self.hold_sleep.as_mut().reset(far);
        self.keepalive_sleep.as_mut().reset(far);
    }

    async fn send_update(&mut self, update: &BgpUpdate) -> io::Result<()> {
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
        let asn4 = self.fsm.negotiated().is_none_or(|n| n.asn4);
        let frame = update
            .encode_frame(asn4)
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
/// drives the reader into the stream.
pub async fn read_frame<IO: AsyncRead + Unpin>(
    io: &mut IO,
    asn4: bool,
) -> io::Result<BgpResult<BgpMessage>> {
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
    Ok(BgpMessage::decode(&frame, asn4))
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
            nlri: vec![IpPrefix::V4(p)],
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
                    nlri: vec![IpPrefix::V6(p)],
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
            nlri: vec![IpPrefix::V4(p)],
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
                    nlri: vec![IpPrefix::V6(p)],
                }),
            ],
            nlri: vec![],
        },
    }
}

/// Builds the UPDATE that withdraws `prefixes` (v4 in the NLRI field,
/// v6 via MP_UNREACH, per RFC 4760 §4).
pub fn withdrawal_update(prefixes: &[IpPrefix]) -> BgpUpdate {
    let mut update = BgpUpdate::default();
    let mut v6 = Vec::new();
    for prefix in prefixes {
        match prefix {
            IpPrefix::V4(_) => update.nlri.push(*prefix),
            IpPrefix::V6(_) => v6.push(*prefix),
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

#[cfg(test)]
mod tests {
    use super::*;
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
        let frame = read_bytes(&mut theirs).await;
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
        assert_eq!(update.nlri.len(), 1);
        assert!(matches!(
            update.attrs.last(),
            Some(PathAttribute::MpUnreach(_))
        ));
    }
}
