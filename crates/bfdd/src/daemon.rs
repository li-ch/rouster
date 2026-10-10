//! The bfdd daemon core — config grammar, shared listeners, session
//! set, echo reflector, and the operator status surface (A21).
//!
//! Config (`bfd.conf`-shaped, the savd line grammar): blank/`!`/`#`
//! ignored, whitespace-separated tokens, line-numbered errors.
//!
//! ```text
//! peer <ip> [multihop]          ! opens a peer stanza
//!   local-address <ip>          ! source address (default: routed)
//!   transmit-interval <ms>      ! Desired Min Tx while Up (default 300)
//!   receive-interval <ms>       ! Required Min Rx (default 300)
//!   detect-multiplier <n>       ! (default 3)
//!   echo <yes|no>               ! RFC 5880 §6.8.9 echo function
//!   echo-interval <ms>          ! Min Echo Rx we advertise (default 300)
//!   passive <yes|no>            ! §6.1 passive role
//!   demand <yes|no>             ! §6.6 demand mode
//!   version-negotiation <yes|no>! Appendix A v0 compatibility
//!   password <key-id> <secret>  ! §6.7.2 Simple Password (1..16 bytes)
//! ```
//!
//! RFC 5882 §2's "single session per data protocol path" is the
//! parser's one-peer-one-session invariant: the (peer, multihop) pair
//! is the key, and duplicates are rejected.
//!
//! SIGHUP reload is diff-based: unchanged peers keep their sessions
//! (no bounce — asserted by discriminator stability), changed peers
//! restart their session, removed peers get the graceful RFC 5882 §8
//! AdminDown hold. A timer-only change still restarts the session —
//! the soft in-place update (§6.8.2's poll sequence announcing new
//! timers) is §Deferred, disclosed.
//!
//! The daemon owns no ZAPI edge: BFD is peer-to-peer UDP (the
//! zapi-BFD registrations are a separate milestone with their own
//! capture recipe). Demultiplexing runs through one shared
//! [`Demux`] table the listeners read and reload rewrites, so a
//! reload-added peer is reachable without restarting the listeners.

use std::collections::HashMap;
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use tokio::net::UdpSocket;
use tokio::sync::{mpsc, watch};
use tracing::{info, warn};

use crate::packet::{PORT_ECHO, PORT_MULTIHOP, PORT_SINGLEHOP};
use crate::session::SessionConfig;
use crate::transport::{
    bind_control_tx, echo_disposition, spawn_session, EchoDisposition, EchoPdu, InboundPacket,
    PeerSpec, SessionCtl, SessionHandle, SessionSnapshot,
};

/// Default control timing (FRR bfdd's): 300 ms × 3.
pub const DEFAULT_INTERVAL_MS: u64 = 300;
pub const DEFAULT_MULTIPLIER: u8 = 3;

/// One parsed peer stanza.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeerLine {
    pub peer: IpAddr,
    pub multihop: bool,
    pub local_address: Option<IpAddr>,
    pub transmit_ms: u64,
    pub receive_ms: u64,
    pub multiplier: u8,
    pub echo: bool,
    pub echo_interval_ms: u64,
    pub passive: bool,
    pub demand: bool,
    pub version_negotiation: bool,
    pub password: Option<(u8, Vec<u8>)>,
}

impl PeerLine {
    /// A stanza with every knob at its documented default; the
    /// parser fills `peer` (and optionally `multihop`) from the
    /// `peer` line.
    fn template(peer: IpAddr, multihop: bool) -> Self {
        Self {
            peer,
            multihop,
            local_address: None,
            transmit_ms: DEFAULT_INTERVAL_MS,
            receive_ms: DEFAULT_INTERVAL_MS,
            multiplier: DEFAULT_MULTIPLIER,
            echo: false,
            echo_interval_ms: DEFAULT_INTERVAL_MS,
            passive: false,
            demand: false,
            version_negotiation: false,
            password: None,
        }
    }

    /// Maps onto the transport's [`PeerSpec`].
    pub fn to_spec(&self) -> PeerSpec {
        PeerSpec {
            peer: self.peer,
            local: self.local_address,
            multihop: self.multihop,
            echo: self.echo,
            session: SessionConfig {
                desired_min_tx: Duration::from_millis(self.transmit_ms),
                required_min_rx: Duration::from_millis(self.receive_ms),
                detect_mult: self.multiplier,
                min_echo_rx: if self.echo {
                    Duration::from_millis(self.echo_interval_ms)
                } else {
                    Duration::ZERO
                },
                demand_mode: self.demand,
                passive: self.passive,
                control_plane_independent: false,
                version_negotiation: self.version_negotiation,
                auth: self
                    .password
                    .as_ref()
                    .map(|(key_id, secret)| crate::session::AuthConfig {
                        key_id: *key_id,
                        password: secret.clone(),
                    }),
            },
        }
    }
}

/// The parsed configuration.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct BfddConfig {
    pub peers: Vec<PeerLine>,
}

/// Config parse errors, rousterd's shape (line-numbered).
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum BfddConfigError {
    #[error("line {line}: {reason}")]
    Line { line: usize, reason: String },
}

fn fail(line: usize, reason: impl Into<String>) -> BfddConfigError {
    BfddConfigError::Line {
        line,
        reason: reason.into(),
    }
}

fn parse_yes_no(line: usize, key: &str, val: &str) -> Result<bool, BfddConfigError> {
    match val {
        "yes" => Ok(true),
        "no" => Ok(false),
        other => Err(fail(line, format!("bad {key} `{other}` (yes|no)"))),
    }
}

/// Parses the bfdd config file (see the module docs for the grammar).
pub fn parse_bfdd_config(input: &str) -> Result<BfddConfig, BfddConfigError> {
    let mut config = BfddConfig::default();
    for (idx, raw) in input.lines().enumerate() {
        let line_no = idx + 1;
        let line = raw.trim();
        if line.is_empty() || line.starts_with('!') || line.starts_with('#') {
            continue;
        }
        let tokens: Vec<&str> = line.split_whitespace().collect();
        let peer = config.peers.last_mut();
        match (tokens.as_slice(), peer) {
            (["peer", ip], _) | (["peer", ip, "multihop"], _) => {
                let multihop = tokens.len() == 3;
                let addr: IpAddr = ip
                    .parse()
                    .map_err(|_| fail(line_no, format!("peer expects an address, got `{ip}`")))?;
                if config
                    .peers
                    .iter()
                    .any(|p| p.peer == addr && p.multihop == multihop)
                {
                    // RFC 5882 §2: one session per data protocol path.
                    return Err(fail(line_no, format!("duplicate peer `{ip}`")));
                }
                config.peers.push(PeerLine::template(addr, multihop));
            }
            (_, None) => {
                return Err(fail(
                    line_no,
                    format!("expected `peer <ip> [multihop]` before any stanza line, got `{line}`"),
                ));
            }
            (_, Some(peer)) => {
                let set_ms = |slot: &mut u64, val: &str| -> Result<(), BfddConfigError> {
                    let ms: u64 = val
                        .parse()
                        .map_err(|_| fail(line_no, format!("bad milliseconds `{val}`")))?;
                    if ms == 0 || ms > 60_000 {
                        return Err(fail(line_no, format!("interval {ms}ms outside 1..=60000")));
                    }
                    *slot = ms;
                    Ok(())
                };
                match tokens.as_slice() {
                    ["local-address", ip] => {
                        let ip: IpAddr = ip
                            .parse()
                            .map_err(|_| fail(line_no, format!("bad address `{ip}`")))?;
                        if ip.is_unspecified() {
                            return Err(fail(line_no, "local-address cannot be unspecified"));
                        }
                        if !matches!(
                            (ip, peer.peer),
                            (IpAddr::V4(_), IpAddr::V4(_)) | (IpAddr::V6(_), IpAddr::V6(_))
                        ) {
                            return Err(fail(line_no, "local-address family must match the peer"));
                        }
                        peer.local_address = Some(ip);
                    }
                    ["transmit-interval", v] => set_ms(&mut peer.transmit_ms, v)?,
                    ["receive-interval", v] => set_ms(&mut peer.receive_ms, v)?,
                    ["echo-interval", v] => set_ms(&mut peer.echo_interval_ms, v)?,
                    ["detect-multiplier", v] => {
                        let n: u8 = v
                            .parse()
                            .map_err(|_| fail(line_no, format!("bad multiplier `{v}`")))?;
                        if n == 0 {
                            return Err(fail(line_no, "detect-multiplier must be at least 1"));
                        }
                        peer.multiplier = n;
                    }
                    ["echo", v] => peer.echo = parse_yes_no(line_no, "echo", v)?,
                    ["passive", v] => peer.passive = parse_yes_no(line_no, "passive", v)?,
                    ["demand", v] => peer.demand = parse_yes_no(line_no, "demand", v)?,
                    ["version-negotiation", v] => {
                        peer.version_negotiation = parse_yes_no(line_no, "version-negotiation", v)?
                    }
                    ["password", key_id, secret] => {
                        let key_id: u8 = key_id
                            .parse()
                            .map_err(|_| fail(line_no, format!("bad key id `{key_id}`")))?;
                        if secret.is_empty() || secret.len() > 16 {
                            return Err(fail(
                                line_no,
                                format!(
                                    "password length {} outside 1..=16 (RFC 5880 §6.7.2)",
                                    secret.len()
                                ),
                            ));
                        }
                        peer.password = Some((key_id, secret.as_bytes().to_vec()));
                    }
                    _ => {
                        return Err(fail(line_no, format!("unknown peer stanza line `{line}`")));
                    }
                }
            }
        }
    }
    Ok(config)
}

/// The shared §6.8.6 steps 7–9 table: which session's feed a packet
/// from the wire belongs to — by Your Discriminator once learned, by
/// the (peer, path) key while bootstrapping. One instance per
/// daemon, shared with the listener tasks; reload rewrites it, so
/// reload-added peers are routable without listener restarts.
#[derive(Clone, Default)]
pub struct Demux {
    inner: Arc<Mutex<DemuxInner>>,
}

#[derive(Default)]
struct DemuxInner {
    by_discr: HashMap<u32, mpsc::Sender<InboundPacket>>,
    by_peer: HashMap<(IpAddr, bool), mpsc::Sender<InboundPacket>>,
}

impl Demux {
    pub fn new() -> Self {
        Self::default()
    }

    fn register(&self, key: (IpAddr, bool), discr: u32, feed: mpsc::Sender<InboundPacket>) {
        let mut inner = self.inner.lock().expect("demux lock");
        inner.by_discr.insert(discr, feed.clone());
        inner.by_peer.insert(key, feed);
    }

    fn unregister(&self, key: &(IpAddr, bool), discr: u32) {
        let mut inner = self.inner.lock().expect("demux lock");
        inner.by_discr.remove(&discr);
        inner.by_peer.remove(key);
    }

    /// Picks the destination feed for one listener packet: a nonzero
    /// Your Discriminator selects by value (step 7), a zero one
    /// selects by address pair (steps 8–9, RFC 5883 §3's rule).
    /// Returns the sender to await on (cloned out of the lock).
    fn route(
        &self,
        from: SocketAddr,
        multihop_listener: bool,
        your_discr: u32,
    ) -> Option<mpsc::Sender<InboundPacket>> {
        let inner = self.inner.lock().expect("demux lock");
        if your_discr != 0 {
            return inner.by_discr.get(&your_discr).cloned();
        }
        inner.by_peer.get(&(from.ip(), multihop_listener)).cloned()
    }
}

/// Reads Your Discriminator straight from the wire bytes (offset 8,
/// RFC 5880 §4.1); the session revalidates on its own full decode.
fn peek_your_discr(bytes: &[u8]) -> u32 {
    if bytes.len() >= 12 {
        u32::from_be_bytes(bytes[8..12].try_into().expect("len checked"))
    } else {
        0
    }
}

/// The assembled daemon: sessions, the shared listeners feeding them
/// through [`Demux`], and the echo reflector.
pub struct BfddDaemon {
    sessions: Vec<SessionHandle>,
    demux: Demux,
    /// Listener and reflector task handles, aborted when the daemon
    /// drops (a dropped daemon must release its well-known ports).
    tasks: Vec<tokio::task::JoinHandle<()>>,
    /// The shared listeners' sockets (kept alive; their tasks run
    /// until the channels close).
    listeners: Vec<Arc<UdpSocket>>,
    /// Echo sockets per family, when any peer runs echo. Bound once
    /// at spawn; a reload adding the FIRST echo peer cannot grow
    /// them (disclosed; restart to add echo).
    echo_sockets: Vec<Arc<UdpSocket>>,
    /// Snapshot subscribers for the status surface, config order.
    watches: Vec<watch::Receiver<SessionSnapshot>>,
    config: BfddConfig,
    /// Feeds the zapi edge (W1-b): every session's state TRANSITIONS
    /// land here when the daemon runs with `--zapi`. `None` in the
    /// pure-config mode (no edge task draining — a Some feed with no
    /// reader would drop reports; the field exists so spawn_peer can
    /// thread it through without a second construction path).
    status_feed: Option<mpsc::Sender<SessionSnapshot>>,
    /// Feeds the echo reflector uses to reach each session's control
    /// channel (EchoLoopback refreshes).
    echo_ctls: Vec<(u32, mpsc::Sender<SessionCtl>)>,
}

impl BfddDaemon {
    /// Builds every session and listener for the config (no zapi edge).
    pub async fn spawn(config: BfddConfig) -> io::Result<Self> {
        Self::spawn_with_status_feed(config, None).await
    }

    /// [`Self::spawn`] with a transition feed for the zapi edge
    /// (W1-b): every session — config AND dynamically added — reports
    /// state transitions onto `status_feed`.
    pub async fn spawn_with_status_feed(
        config: BfddConfig,
        status_feed: Option<mpsc::Sender<SessionSnapshot>>,
    ) -> io::Result<Self> {
        let mut daemon = Self {
            sessions: Vec::new(),
            demux: Demux::new(),
            tasks: Vec::new(),
            listeners: Vec::new(),
            echo_sockets: Vec::new(),
            watches: Vec::new(),
            config,
            status_feed,
            echo_ctls: Vec::new(),
        };

        // One shared receive socket per (family, port) the peers
        // need — FRR's topology: control packets land on 3784/4784
        // and demultiplex per §6.8.6 steps 7–9.
        let mut wanted: Vec<(bool, bool)> = Vec::new(); // (v6, multihop)
        for peer in &daemon.config.peers {
            let entry = (peer.peer.is_ipv6(), peer.multihop);
            if !wanted.contains(&entry) {
                wanted.push(entry);
            }
        }
        for (v6, multihop) in wanted {
            let port = if multihop {
                PORT_MULTIHOP
            } else {
                PORT_SINGLEHOP
            };
            let bind_addr: SocketAddr = if v6 {
                SocketAddr::new(IpAddr::from(std::net::Ipv6Addr::UNSPECIFIED), port)
            } else {
                SocketAddr::new(IpAddr::from(std::net::Ipv4Addr::UNSPECIFIED), port)
            };
            let sock = UdpSocket::bind(bind_addr).await?;
            daemon.listeners.push(Arc::new(sock));
        }

        // The echo reflector's sockets, per family, when needed.
        let need_echo_v4 = daemon
            .config
            .peers
            .iter()
            .any(|p| p.echo && p.peer.is_ipv4());
        let need_echo_v6 = daemon
            .config
            .peers
            .iter()
            .any(|p| p.echo && p.peer.is_ipv6());
        for (need, v6) in [(need_echo_v4, false), (need_echo_v6, true)] {
            if !need {
                continue;
            }
            let bind_addr: SocketAddr = if v6 {
                SocketAddr::new(IpAddr::from(std::net::Ipv6Addr::UNSPECIFIED), PORT_ECHO)
            } else {
                SocketAddr::new(IpAddr::from(std::net::Ipv4Addr::UNSPECIFIED), PORT_ECHO)
            };
            let sock = UdpSocket::bind(bind_addr).await?;
            daemon.echo_sockets.push(Arc::new(sock));
        }

        let peers = daemon.config.peers.clone();
        for line in peers {
            daemon.spawn_peer(&line).await?;
        }

        // Listener tasks: recv, peek, route through the shared demux.
        // The task holds a WEAK socket reference so daemon Drop
        // (the last strong Arc) closes the well-known port
        // synchronously — the abort alone frees it only at the next
        // poll, which would wedge a same-process restart.
        for sock in &daemon.listeners {
            let multihop_listener = sock.local_addr()?.port() == PORT_MULTIHOP;
            let sock = Arc::downgrade(sock);
            let demux = daemon.demux.clone();
            daemon.tasks.push(tokio::spawn(async move {
                let mut buf = vec![0u8; 2048];
                loop {
                    let sock = sock.upgrade().expect("strong ref held by the daemon");
                    match sock.recv_from(&mut buf).await {
                        Ok((len, from)) => {
                            let feed =
                                demux.route(from, multihop_listener, peek_your_discr(&buf[..len]));
                            match feed {
                                Some(feed) => {
                                    let _ = feed.send((from, buf[..len].to_vec())).await;
                                }
                                None => tracing::debug!(
                                    peer = %from,
                                    "bfdd: control packet for no session dropped"
                                ),
                            }
                        }
                        Err(err) => {
                            warn!(%err, "bfdd: listener read failed; stopping");
                            return;
                        }
                    }
                }
            }));
        }

        // Echo reflector tasks (§6.8.9): consume our own returns
        // (refresh the session's echo deadline), reflect the peer's
        // probes — one disposition function, the discriminator is
        // the loop guard.
        for sock in &daemon.echo_sockets {
            let sock = Arc::downgrade(sock);
            let ctls = daemon.echo_ctls.clone();
            daemon.tasks.push(tokio::spawn(async move {
                let mut buf = vec![0u8; 2048];
                loop {
                    let sock = sock.upgrade().expect("strong ref held by the daemon");
                    match sock.recv_from(&mut buf).await {
                        Ok((len, from)) => {
                            let Some(pdu) = EchoPdu::decode(&buf[..len]) else {
                                continue;
                            };
                            let ours: Vec<u32> = ctls.iter().map(|(d, _)| *d).collect();
                            match echo_disposition(&pdu, &ours) {
                                EchoDisposition::Consume => {
                                    if let Some((_, ctl)) =
                                        ctls.iter().find(|(d, _)| *d == pdu.discr)
                                    {
                                        let _ = ctl.send(SessionCtl::EchoLoopback).await;
                                    }
                                }
                                EchoDisposition::Reflect => {
                                    let _ = sock.send_to(&buf[..len], from).await;
                                }
                            }
                        }
                        Err(err) => {
                            warn!(%err, "bfdd: echo listener read failed; stopping");
                            return;
                        }
                    }
                }
            }));
        }

        info!(
            peers = daemon.sessions.len(),
            "bfdd: daemon assembled (listeners up, sessions spawned)"
        );
        Ok(daemon)
    }

    async fn spawn_peer(&mut self, line: &PeerLine) -> io::Result<()> {
        let spec = line.to_spec();
        let key = (line.peer, line.multihop);
        let (feed_tx, feed_rx) = mpsc::channel(64);
        let tx = bind_control_tx(&spec)?;
        // Echo: a dedicated socket per session (connected to the
        // peer's echo port) when the peer runs the function.
        let echo_sock = if line.echo {
            let bind_any: IpAddr = match spec.peer {
                IpAddr::V4(_) => IpAddr::from(std::net::Ipv4Addr::UNSPECIFIED),
                IpAddr::V6(_) => IpAddr::from(std::net::Ipv6Addr::UNSPECIFIED),
            };
            let std_sock =
                std::net::UdpSocket::bind(SocketAddr::new(spec.local.unwrap_or(bind_any), 0))?;
            std_sock.set_nonblocking(true)?;
            let sock = UdpSocket::from_std(std_sock)?;
            sock.connect(spec.echo_dst()).await?;
            Some(sock)
        } else {
            None
        };
        let discr = crate::transport::DiscriminatorPool::new().allocate();
        let handle = spawn_session(
            spec,
            discr,
            tx,
            feed_rx,
            echo_sock,
            self.status_feed.clone(),
        );
        self.demux.register(key, discr, feed_tx);
        self.watches.push(handle.subscribe());
        self.echo_ctls.push((discr, handle.ctl_sender().clone()));
        self.sessions.push(handle);
        Ok(())
    }

    /// The daemon's session snapshots (config order for surviving
    /// sessions).
    pub fn snapshots(&self) -> Vec<SessionSnapshot> {
        self.sessions.iter().map(|h| h.snapshot()).collect()
    }

    /// The running configuration.
    pub fn config(&self) -> &BfddConfig {
        &self.config
    }

    /// Operator status (A21): one line per session, the savd shape.
    pub fn status_text(&self, pid: u32) -> String {
        let mut out = format!(
            "bfdd {} pid {pid}\npeers {}\n",
            env!("CARGO_PKG_VERSION"),
            self.sessions.len()
        );
        for snap in self.snapshots() {
            out.push_str(&format!(
                "session peer {} state {} diag {} local-discr {} remote-discr {} detection-time {}ms tx-interval {}ms\n",
                snap.peer,
                snap.state,
                snap.diag,
                snap.local_discr,
                snap.remote_discr,
                snap.detection_time.as_millis(),
                snap.tx_interval.as_millis(),
            ));
            if let Some(t) = &snap.last_transition {
                out.push_str(&format!("  last-transition {t}\n"));
            }
        }
        out
    }

    /// SIGHUP semantics: diff the new config against the running
    /// sessions. Unchanged specs keep running (no bounce), changed
    /// specs restart, removed specs get the graceful RFC 5882 §8
    /// AdminDown hold — awaited, so the call returns with every
    /// removal fully signalled.
    pub async fn reload(&mut self, new_config: BfddConfig) -> io::Result<()> {
        let mut old = std::mem::take(&mut self.sessions);
        let mut old_demux_keys: Vec<((IpAddr, bool), u32)> = old
            .iter()
            .map(|h| ((h.spec.peer, h.spec.multihop), h.snapshot().local_discr))
            .collect();

        let mut kept = Vec::new();
        let mut kept_keys = Vec::new();
        for line in &new_config.peers {
            let key = (line.peer, line.multihop);
            if kept_keys.contains(&key) {
                return Err(io::Error::other("duplicate peer in reload config"));
            }
            let spec = line.to_spec();
            if let Some(pos) = old.iter().position(|h| h.spec == spec) {
                let handle = old.remove(pos);
                let _ = old_demux_keys.remove(pos); // stays registered
                kept_keys.push(key);
                kept.push(handle);
                continue;
            }
            // New (or changed) peer: fresh session, registered in
            // the shared demux so the listeners reach it at once
            // (spawn_peer pushed it into self.sessions).
            self.spawn_peer(line).await?;
        }

        // Whatever remains in `old` was removed: unregister, then
        // the graceful RFC 5882 §8 hold — awaited.
        let mut removed = old;
        for (i, handle) in removed.iter().enumerate() {
            let (_, discr) = old_demux_keys[i];
            self.demux
                .unregister(&(handle.spec.peer, handle.spec.multihop), discr);
        }
        for handle in removed.drain(..) {
            info!(peer = %handle.spec.peer, "bfdd: reload: peer removed; shutting down gracefully");
            handle.shutdown().await;
        }

        // Adopt: spawned sessions joined the kept set; watches and
        // echo feeds rebuild from it in config order.
        kept.extend(std::mem::take(&mut self.sessions));
        self.sessions = kept;
        self.watches = self.sessions.iter().map(|h| h.subscribe()).collect();
        self.echo_ctls = self
            .sessions
            .iter()
            .map(|h| (h.snapshot().local_discr, h.ctl_sender().clone()))
            .collect();
        self.config = new_config;
        info!(peers = self.sessions.len(), "bfdd: reload applied");
        Ok(())
    }

    /// Graceful shutdown of every session (SIGTERM/SIGINT path):
    /// each peer learns AdminDown for one Detection Time (RFC 5882
    /// §8) before the daemon exits.
    pub async fn shutdown_all(&mut self) {
        for handle in self.sessions.drain(..) {
            handle.shutdown().await;
        }
    }

    /// Creates a DYNAMIC session from a forwarded BFD_DEST_REGISTER
    /// (W1-b): the zapi edge's client command mapped onto a peer spec
    /// — timers and multihop straight off the wire, local address from
    /// the register's src when it is not the wildcard. Echo, passive
    /// and demand are off (the register carries no such fields).
    pub async fn add_dynamic_peer(
        &mut self,
        cmd: &crate::zapi::ZapiBfdSessionCmd,
    ) -> io::Result<()> {
        // An UPDATE for an existing session restarts it with the new
        // timers (the config-reload "changed peer restarts" rule).
        let key = (cmd.dst, cmd.mhop);
        if let Some(pos) = self
            .sessions
            .iter()
            .position(|h| (h.spec.peer, h.spec.multihop) == key)
        {
            self.remove_dynamic_peer(cmd.dst, cmd.mhop).await;
            let _ = pos; // position computed before removal
        }
        let local = match cmd.src {
            IpAddr::V4(v4) if !v4.is_unspecified() => Some(IpAddr::V4(v4)),
            IpAddr::V6(v6) if !v6.is_unspecified() => Some(IpAddr::V6(v6)),
            _ => None,
        };
        let line = PeerLine {
            peer: cmd.dst,
            multihop: cmd.mhop,
            local_address: local,
            transmit_ms: u64::from(cmd.min_tx_ms.max(1)),
            receive_ms: u64::from(cmd.min_rx_ms.max(1)),
            multiplier: cmd.detection_multiplier.max(1),
            echo: false,
            echo_interval_ms: DEFAULT_INTERVAL_MS,
            passive: false,
            demand: false,
            version_negotiation: false,
            password: None,
        };
        // Listeners: a first v4/v6/(mhop) peer needs its shared
        // listener bound (the wanted-list logic from spawn).
        let entry = (line.peer.is_ipv6(), line.multihop);
        let port = if line.multihop {
            PORT_MULTIHOP
        } else {
            PORT_SINGLEHOP
        };
        let already = self.listeners.iter().any(|s| {
            s.local_addr()
                .map(|a| a.port() == port && a.is_ipv6() == entry.0)
                .unwrap_or(false)
        });
        if !already {
            let bind_addr: SocketAddr = if entry.0 {
                SocketAddr::new(IpAddr::from(std::net::Ipv6Addr::UNSPECIFIED), port)
            } else {
                SocketAddr::new(IpAddr::from(std::net::Ipv4Addr::UNSPECIFIED), port)
            };
            let sock = UdpSocket::bind(bind_addr).await?;
            let sock = Arc::new(sock);
            let multihop_listener = port == PORT_MULTIHOP;
            let demux = self.demux.clone();
            let weak = Arc::downgrade(&sock);
            self.tasks.push(tokio::spawn(async move {
                let mut buf = vec![0u8; 2048];
                loop {
                    let sock = weak.upgrade().expect("strong ref held by the daemon");
                    match sock.recv_from(&mut buf).await {
                        Ok((len, from)) => {
                            let feed =
                                demux.route(from, multihop_listener, peek_your_discr(&buf[..len]));
                            match feed {
                                Some(feed) => {
                                    let _ = feed.send((from, buf[..len].to_vec())).await;
                                }
                                None => tracing::debug!(
                                    peer = %from,
                                    "bfdd: control packet for no session dropped"
                                ),
                            }
                        }
                        Err(err) => {
                            warn!(%err, "bfdd: listener read failed; stopping");
                            return;
                        }
                    }
                }
            }));
            self.listeners.push(sock);
        }
        self.spawn_peer(&line).await?;
        info!(peer = %cmd.dst, mhop = cmd.mhop, "bfdd: dynamic session created (zapi)");
        Ok(())
    }

    /// Removes a dynamic session (a forwarded DEREGISTER, W1-b): the
    /// graceful RFC 5882 §8 hold applies — the peer learns AdminDown
    /// before the session vanishes.
    pub async fn remove_dynamic_peer(&mut self, dst: IpAddr, mhop: bool) {
        if let Some(pos) = self
            .sessions
            .iter()
            .position(|h| h.spec.peer == dst && h.spec.multihop == mhop)
        {
            let handle = self.sessions.remove(pos);
            let discr = handle.snapshot().local_discr;
            self.demux.unregister(&(dst, mhop), discr);
            info!(peer = %dst, "bfdd: dynamic session removed (zapi); graceful hold");
            handle.shutdown().await;
            self.watches = self.sessions.iter().map(|h| h.subscribe()).collect();
            self.echo_ctls = self
                .sessions
                .iter()
                .map(|h| (h.snapshot().local_discr, h.ctl_sender().clone()))
                .collect();
        }
    }
}

impl Drop for BfddDaemon {
    fn drop(&mut self) {
        for task in &self.tasks {
            task.abort();
        }
        // The sessions' feeds close with the daemon's senders; their
        // tasks exit on the closed channel. (Production exits via
        // shutdown_all first; this is the library-object hygiene
        // path.)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::packet::BfdState;

    /// One daemon per host: the shared 3784/4784/3785 binds collide
    /// when tests run in parallel, so every BfddDaemon::spawn-ing
    /// test holds this lock for its duration (the production
    /// constraint made visible in tests).
    static DAEMON_TEST_LOCK: std::sync::LazyLock<tokio::sync::Mutex<()>> =
        std::sync::LazyLock::new(|| tokio::sync::Mutex::new(()));

    async fn daemon_lock() -> tokio::sync::MutexGuard<'static, ()> {
        DAEMON_TEST_LOCK.lock().await
    }

    /// `BfddDaemon::spawn` with a bounded AddrInUse retry: a prior
    /// test's per-session sockets can outlive its guard release by one
    /// runtime poll (the production constraint is real — we just give
    /// teardown a moment to finish instead of flaking ~1-in-5 under
    /// parallel load).
    async fn spawn_retrying(config: BfddConfig) -> io::Result<BfddDaemon> {
        let mut last = None;
        for _ in 0..10 {
            match BfddDaemon::spawn(config.clone()).await {
                Ok(d) => return Ok(d),
                Err(e) if e.kind() == std::io::ErrorKind::AddrInUse => {
                    last = Some(e);
                    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
                }
                Err(e) => return Err(e),
            }
        }
        Err(last.expect("retry loop ran at least once"))
    }

    /// The full grammar parses, with defaults and per-stanza values.
    #[test]
    fn config_full_grammar() {
        let text = "\
# a comment
!
peer 198.51.100.2
  transmit-interval 100
  receive-interval 150
  detect-multiplier 5
  local-address 198.51.100.1
  echo yes
  echo-interval 50
  passive no
  demand no
  version-negotiation no
  password 7 rouster!
peer 2001:db8::2 multihop
  transmit-interval 1000
";
        let config = parse_bfdd_config(text).unwrap();
        assert_eq!(config.peers.len(), 2);
        let a = &config.peers[0];
        assert_eq!(a.peer, "198.51.100.2".parse::<IpAddr>().unwrap());
        assert!((a.transmit_ms, a.receive_ms, a.multiplier) == (100, 150, 5));
        assert_eq!(a.local_address, Some("198.51.100.1".parse().unwrap()));
        assert!(a.echo && a.echo_interval_ms == 50);
        assert_eq!(a.password, Some((7, b"rouster!".to_vec())));
        let b = &config.peers[1];
        assert!(b.multihop && b.transmit_ms == 1000);
        assert!((b.receive_ms, b.multiplier) == (DEFAULT_INTERVAL_MS, DEFAULT_MULTIPLIER));
    }

    /// Defaults: FRR's 300 ms × 3, no echo, active role, no auth.
    #[test]
    fn config_defaults() {
        let config = parse_bfdd_config("peer 10.0.0.1\n").unwrap();
        let p = &config.peers[0];
        assert_eq!(
            (p.transmit_ms, p.receive_ms, p.multiplier),
            (DEFAULT_INTERVAL_MS, DEFAULT_INTERVAL_MS, DEFAULT_MULTIPLIER)
        );
        assert!(!p.echo && !p.passive && !p.demand && !p.version_negotiation);
        assert_eq!(p.password, None);
    }

    /// The rejection table, one line-numbered error per rule.
    #[test]
    fn config_rejections() {
        let cases = [
            (
                "transmit-interval 100\n",
                1,
                "expected `peer <ip> [multihop]`",
            ),
            ("peer nope\n", 1, "peer expects an address"),
            ("peer 10.0.0.1\npeer 10.0.0.1\n", 2, "duplicate peer"),
            (
                "peer 10.0.0.1\n  transmit-interval 0\n",
                2,
                "outside 1..=60000",
            ),
            (
                "peer 10.0.0.1\n  transmit-interval 61000\n",
                2,
                "outside 1..=60000",
            ),
            ("peer 10.0.0.1\n  detect-multiplier 0\n", 2, "at least 1"),
            ("peer 10.0.0.1\n  echo maybe\n", 2, "bad echo `maybe`"),
            (
                "peer 10.0.0.1\n  password 1 secretsecretsecretsecret\n",
                2,
                "outside 1..=16",
            ),
            (
                "peer 10.0.0.1\n  local-address 0.0.0.0\n",
                2,
                "cannot be unspecified",
            ),
            (
                "peer 10.0.0.1\n  local-address 2001:db8::1\n",
                2,
                "family must match",
            ),
            (
                "peer 10.0.0.1\n  nonsense yes\n",
                2,
                "unknown peer stanza line",
            ),
        ];
        for (text, want_line, needle) in cases {
            let err = parse_bfdd_config(text).unwrap_err();
            let BfddConfigError::Line { line, reason } = &err;
            assert_eq!(*line, want_line, "line for {text:?}: {err}");
            assert!(
                reason.contains(needle),
                "reason `{reason}` misses `{needle}` ({text:?})"
            );
        }
    }

    /// Same peer, different path (single-hop vs multihop) is two
    /// sessions (RFC 5882 §2 keys on the path); same path twice is a
    /// duplicate.
    #[test]
    fn config_path_keying() {
        let config = parse_bfdd_config("peer 10.0.0.1\npeer 10.0.0.1 multihop\n").unwrap();
        assert_eq!(config.peers.len(), 2);
        let err =
            parse_bfdd_config("peer 10.0.0.1 multihop\npeer 10.0.0.1 multihop\n").unwrap_err();
        assert!(err.to_string().contains("duplicate peer"));
    }

    /// PeerLine → PeerSpec mapping carries every knob.
    #[test]
    fn peer_line_to_spec() {
        let line = PeerLine {
            peer: "198.51.100.2".parse().unwrap(),
            multihop: true,
            local_address: Some("198.51.100.1".parse().unwrap()),
            transmit_ms: 100,
            receive_ms: 200,
            multiplier: 4,
            echo: true,
            echo_interval_ms: 50,
            passive: true,
            demand: true,
            version_negotiation: true,
            password: Some((2, b"pw".to_vec())),
        };
        let spec = line.to_spec();
        assert_eq!(spec.control_dst().port(), PORT_MULTIHOP);
        let s = &spec.session;
        assert_eq!(s.desired_min_tx, Duration::from_millis(100));
        assert_eq!(s.required_min_rx, Duration::from_millis(200));
        assert_eq!(s.detect_mult, 4);
        assert_eq!(s.min_echo_rx, Duration::from_millis(50));
        assert!(s.passive && s.demand_mode && s.version_negotiation);
        assert_eq!(s.auth.as_ref().unwrap().password, b"pw".to_vec());
    }

    /// Demux routing: by discriminator once learned, by (peer, path)
    /// while bootstrapping, nothing for strangers.
    #[tokio::test]
    async fn demux_routes_by_discr_then_address() {
        let demux = Demux::new();
        let (tx_a, mut rx_a) = mpsc::channel(4);
        let (tx_b, mut rx_b) = mpsc::channel(4);
        demux.register(("10.0.0.1".parse().unwrap(), false), 0x1000, tx_a);
        demux.register(("10.0.0.2".parse().unwrap(), true), 0x2000, tx_b);

        let from: SocketAddr = "10.0.0.1:49231".parse().unwrap();
        let feed = demux.route(from, false, 0x2000).unwrap();
        feed.send((from, vec![1])).await.unwrap();
        assert!(rx_b.try_recv().is_ok(), "discriminator selects B");

        let feed = demux.route(from, false, 0).unwrap();
        feed.send((from, vec![2])).await.unwrap();
        assert!(rx_a.try_recv().is_ok(), "bootstrap by address selects A");

        let stranger: SocketAddr = "192.0.2.9:49231".parse().unwrap();
        assert!(demux.route(stranger, false, 0).is_none());
        assert!(demux.route(stranger, false, 0x9999).is_none());

        demux.unregister(&("10.0.0.1".parse().unwrap(), false), 0x1000);
        assert!(demux.route(from, false, 0x1000).is_none());
        assert!(
            demux.route(from, false, 0).is_none(),
            "unregistered key drops"
        );
    }

    /// The daemon-over-real-wire test the one-listener-per-host
    /// constraint permits: a single daemon peers with itself over
    /// loopback — its own transmit socket feeds its own 3784
    /// listener, and the three-way handshake completes against the
    /// reflection (§6.8.6 through the actual shared-listener path).
    #[tokio::test]
    async fn daemon_establishes_with_itself_over_loopback() {
        let _guard = daemon_lock().await;
        let config =
            parse_bfdd_config("peer 127.0.0.1\n  transmit-interval 100\n  receive-interval 100\n")
                .unwrap();
        let mut daemon = spawn_retrying(config).await.unwrap();
        assert_eq!(daemon.snapshots().len(), 1);

        let mut watch = daemon.watches[0].clone();
        let deadline = tokio::time::Instant::now() + Duration::from_secs(20);
        loop {
            if watch.borrow().state == BfdState::Up {
                break;
            }
            tokio::select! {
                _ = watch.changed() => {}
                _ = tokio::time::sleep_until(deadline) => {
                    panic!("self-session never reached Up: {:?}", daemon.snapshots());
                }
            }
        }

        // Status surface (A21) renders the live session.
        let status = daemon.status_text(4242);
        assert!(status.contains("bfdd") && status.contains("pid 4242"));
        assert!(
            status.contains("peer 127.0.0.1 state Up"),
            "status: {status}"
        );

        daemon.shutdown_all().await;
        // The sessions list drains on shutdown; the surviving watch
        // carries the final state.
        assert_eq!(watch.borrow().state, BfdState::AdminDown);
    }

    /// Reload diffing: an unchanged peer keeps its session (same
    /// discriminator — no bounce), a changed peer restarts it.
    #[tokio::test]
    async fn reload_diffs_sessions() {
        let _guard = daemon_lock().await;
        let config =
            parse_bfdd_config("peer 127.0.0.1\n  transmit-interval 100\n  receive-interval 100\n")
                .unwrap();
        let mut daemon = spawn_retrying(config).await.unwrap();
        let discr_before = daemon.snapshots()[0].local_discr;

        // Same peer again: no bounce.
        let same =
            parse_bfdd_config("peer 127.0.0.1\n  transmit-interval 100\n  receive-interval 100\n")
                .unwrap();
        daemon.reload(same).await.unwrap();
        assert_eq!(daemon.snapshots().len(), 1);
        assert_eq!(
            daemon.snapshots()[0].local_discr,
            discr_before,
            "unchanged peer must not bounce"
        );

        // Changed timer: session restarts (discriminator changes).
        let changed = parse_bfdd_config(
            "peer 127.0.0.1\n  transmit-interval 100\n  receive-interval 100\n  detect-multiplier 5\n",
        )
        .unwrap();
        daemon.reload(changed).await.unwrap();
        assert_ne!(
            daemon.snapshots()[0].local_discr,
            discr_before,
            "changed peer restarts"
        );

        // Removed: the session list shrinks (and the removed one got
        // its graceful hold inside reload).
        let empty = BfddConfig::default();
        daemon.reload(empty).await.unwrap();
        assert!(daemon.snapshots().is_empty());
    }

    /// The echo reflector: the peer's probe comes back verbatim; a
    /// stranger's PDU with our magic but nobody's discriminator is
    /// also reflected (it is simply not ours).
    #[tokio::test]
    async fn echo_reflector_loops_the_peer_probe() {
        let _guard = daemon_lock().await;
        // One echo-enabled "peer" (itself, as above — we only need
        // the reflector socket to exist, not a session).
        let config = parse_bfdd_config(
            "peer 127.0.0.1\n  transmit-interval 100\n  receive-interval 100\n  echo yes\n  echo-interval 100\n",
        )
        .unwrap();
        let daemon = spawn_retrying(config).await.unwrap();

        let probe_sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        probe_sock.connect("127.0.0.1:3785").await.unwrap();
        let pdu = EchoPdu {
            discr: 0xfeed_face, // not ours
            seq: 1,
        };
        probe_sock.send(&pdu.encode()).await.unwrap();
        let mut buf = [0u8; 16];
        let (len, from) =
            tokio::time::timeout(Duration::from_secs(2), probe_sock.recv_from(&mut buf))
                .await
                .expect("reflection arrives")
                .unwrap();
        assert_eq!(&buf[..len], &pdu.encode()[..], "reflected verbatim");
        assert_eq!(from.port(), PORT_ECHO, "sent from the echo port");
        let _ = daemon; // dropped after the assertion set
    }
}
