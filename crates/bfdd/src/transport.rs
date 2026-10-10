//! UDP transports and the per-session async loop — RFC 5881 (single
//! hop, port 3784), RFC 5883 (multihop, port 4784), RFC 5880 §5.7/
//! §6.8.9 (echo, port 3785), and the socket topology FRR ships (the
//! interop peer): one shared receive socket per port, per-session
//! transmit sockets with RFC 5881 §4's 49152–65535 source ports and
//! §5's TTL 255.
//!
//! Deviations, both fences:
//!
//! - **Received-TTL validation is not enforced.** RFC 5881 §5 says a
//!   receiver SHOULD check TTL 255; reading the received TTL needs
//!   recvmsg ancillary data (IP_RECVTTL/IP_HOPLIMIT), which neither
//!   std nor tokio UDP sockets expose, and the no-unsafe/no-new-deps
//!   fence excludes libc/socket2. Transmit carries TTL 255 on every
//!   v4 socket (what the RFC mandates and what FRR's receive side
//!   checks); the receive-side check is §Deferred to a socket2 edge
//!   if the owner ever lifts the fence.
//! - **IPv6 transmit hop limit is the OS default, not 255.** The v6
//!   half of the same §5 rule needs IPV6_UNICAST_HOPS, which
//!   std/tokio/mio do not expose (verified: mio's set_ttl is IP_TTL
//!   only). v6 single-hop sessions against strict TTL checkers
//!   (FRR) will not establish; v6 multihop and v4 are unaffected.
//!   Same §Deferred socket2 edge covers it.
//! - **Echo loopback is UDP-level, both AFs.** RFC 5880 §5.7 makes
//!   the echo payload a local matter and §6.8.9 demultiplexes by the
//!   sender's own content; FRR-Linux reflects v4 echo in the
//!   forwarding plane via AF_PACKET (raw sockets, out of scope).
//!   Our reflector answers every UDP 3785 packet whose discriminator
//!   is not our own — the discriminator check is the loop guard: a
//!   reflected packet carries our discriminator and is consumed, so
//!   no packet can ping-pong.
//!
//! The session loop owns no sockets' lifecycle beyond its transmit
//! socket: inbound packets arrive on an mpsc feed (the daemon's
//! shared listeners demultiplex onto it; tests cross-wire real
//! sockets through [`spawn_socket_pump`]), so the loop is the same
//! code on the wire and under test.

use std::collections::HashSet;
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::time::Duration;

use tokio::net::UdpSocket;
use tokio::sync::{mpsc, oneshot, watch};
use tokio::time::{sleep_until, Instant};

use crate::packet::{
    BfdPacket, BfdState, Diagnostic, VersionPolicy, PORT_ECHO, PORT_MULTIHOP, PORT_SINGLEHOP,
    SOURCE_PORT_MAX, SOURCE_PORT_MIN,
};
use crate::session::{DiscardReason, SessionConfig, SessionSm};

/// TTL on every transmit socket: RFC 5881 §5's single-hop mandate,
/// and high enough for FRR's multihop minimum-hop threshold (which
/// RFC 5883 leaves to local policy — 255 satisfies every policy).
pub const TX_TTL: u32 = 255;

/// One inbound control/echo packet as handed to a session: where it
/// came from and its bytes.
pub type InboundPacket = (SocketAddr, Vec<u8>);

/// xorshift64* — a deterministic-enough PRNG for discriminator
/// selection, transmit jitter, and source-port choice; seeded from
/// the clock and pid so two daemons on one host differ.
#[derive(Debug, Clone)]
pub struct Rng(u64);

impl Rng {
    pub fn new_seeded() -> Self {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos() as u64)
            .unwrap_or(0x5dee_ce66_d0a2_f00d);
        Self(nanos ^ ((std::process::id() as u64) << 32) ^ 0x9e37_79b9_7f4a_7c15)
    }

    fn next_u64(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0.wrapping_mul(0x2545_f491_4f6c_dd1d)
    }

    /// A draw in [0, 1) — the transmit-jitter input (§6.8.7).
    pub fn unit(&mut self) -> f64 {
        (self.next_u64() >> 11) as f64 / (1u64 << 53) as f64
    }

    /// A source port in RFC 5881 §4's 49152–65535 range.
    pub fn source_port(&mut self) -> u16 {
        let span = u64::from(SOURCE_PORT_MAX - SOURCE_PORT_MIN + 1);
        SOURCE_PORT_MIN + (self.next_u64() % span) as u16
    }
}

impl Default for Rng {
    fn default() -> Self {
        Self::new_seeded()
    }
}

/// Local discriminator allocation — RFC 5880 §6.8.1: nonzero, unique
/// per system, and SHOULD be random (off-path confusion resistance;
/// the value's only meaning is "this is me").
#[derive(Debug, Default)]
pub struct DiscriminatorPool {
    rng: Rng,
    used: HashSet<u32>,
}

impl DiscriminatorPool {
    pub fn new() -> Self {
        Self::default()
    }

    /// Allocates a discriminator no previous allocation returned
    /// (and never zero, §6.8.1).
    pub fn allocate(&mut self) -> u32 {
        loop {
            let candidate = (self.rng.next_u64() >> 32) as u32;
            if candidate != 0 && self.used.insert(candidate) {
                return candidate;
            }
        }
    }
}

/// One configured peer: where its packets go, which encapsulation,
/// and the session parameters (the config grammar maps onto this).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeerSpec {
    pub peer: IpAddr,
    /// Local source address; `None` binds the wildcard (the kernel
    /// routes) — fine for transmit, and the receive side is the
    /// shared listener anyway.
    pub local: Option<IpAddr>,
    pub multihop: bool,
    /// Advertise the echo function and run its arms (RFC 5880
    /// §6.8.9; time-boxed M3 scope: transmission, loopback receipt,
    /// expiry accounting).
    pub echo: bool,
    pub session: SessionConfig,
}

impl PeerSpec {
    /// The control destination (RFC 5881 §4 / RFC 5883 §3).
    pub fn control_dst(&self) -> SocketAddr {
        SocketAddr::new(
            self.peer,
            if self.multihop {
                PORT_MULTIHOP
            } else {
                PORT_SINGLEHOP
            },
        )
    }

    /// The echo destination (RFC 5881 §4).
    pub fn echo_dst(&self) -> SocketAddr {
        SocketAddr::new(self.peer, PORT_ECHO)
    }

    /// §6.8.6 steps 7–9's session selection for the daemon's shared
    /// listeners: a packet from `from` belongs to this peer's session
    /// when it names our discriminator, or (the bootstrap case) when
    /// its Your Discriminator is zero and the address pair matches —
    /// the RFC 5883 §3 multihop rule, the single-hop equivalent for
    /// directly connected peers.
    pub fn matches(&self, from: SocketAddr, your_discr: u32, local_discr: u32) -> bool {
        if your_discr != 0 {
            return your_discr == local_discr;
        }
        from.ip() == self.peer
    }
}

/// Binds and connects a session transmit socket to the peer's
/// control port: RFC 5881 §4's source port range, §5's TTL 255 (set
/// before use, as the RFC advises). Connected, so the session loop
/// sends blind and the kernel carries the destination — per-session
/// sockets make FRR's `sendto`-with-explicit-destination
/// multiplexing unnecessary.
pub fn bind_control_tx(spec: &PeerSpec) -> io::Result<UdpSocket> {
    let mut rng = Rng::new_seeded();
    let any: IpAddr = match spec.peer {
        IpAddr::V4(_) => IpAddr::from(std::net::Ipv4Addr::UNSPECIFIED),
        IpAddr::V6(_) => IpAddr::from(std::net::Ipv6Addr::UNSPECIFIED),
    };
    let local = spec.local.unwrap_or(any);
    let dst = spec.control_dst();
    let mut last_err = None;
    // A handful of tries: the 16k-port range makes collisions with a
    // second session vanishingly rare, and each miss is one bind.
    for _ in 0..64 {
        match std::net::UdpSocket::bind(SocketAddr::new(local, rng.source_port())) {
            Ok(std_sock) => {
                // RFC 5881 §5: TTL 255 on transmit, set before the
                // socket carries anything. IPv4 only, disclosed:
                // std/tokio/mio expose IP_TTL alone — the v6
                // IPV6_UNICAST_HOPS option needs socket2/libc, which
                // the no-new-deps fence excludes, so v6 transmits
                // ride the OS default hop limit (§Deferred: a
                // socket2 edge if the fence is ever lifted).
                if matches!(local, IpAddr::V4(_)) {
                    std_sock.set_ttl(TX_TTL)?;
                }
                std_sock.connect(dst)?; // UDP connect: records the peer, filters inbound
                std_sock.set_nonblocking(true)?;
                return UdpSocket::from_std(std_sock);
            }
            Err(err) if err.kind() == io::ErrorKind::AddrInUse => {
                last_err = Some(err);
            }
            Err(err) => return Err(err),
        }
    }
    Err(last_err.unwrap_or_else(|| io::Error::new(io::ErrorKind::AddrInUse, "no free source port")))
}

/// The operator-visible session snapshot — the watch payload the
/// daemon's status file renders and tests await.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionSnapshot {
    pub peer: IpAddr,
    pub state: BfdState,
    pub diag: Diagnostic,
    pub local_discr: u32,
    pub remote_discr: u32,
    /// The currently computed Local Detection Time (§6.8.4).
    pub detection_time: Duration,
    /// The negotiated control transmit interval (§6.8.2).
    pub tx_interval: Duration,
    /// The last transition's RFC-named rendering, when one occurred.
    pub last_transition: Option<String>,
}

/// Commands into a running session task.
pub enum SessionCtl {
    /// Graceful stop: AdminDown held for at least one Detection Time
    /// (RFC 5882 §8), then exit; the oneshot fires when the hold
    /// completes.
    Shutdown(oneshot::Sender<()>),
    /// Our own echo packet came back (RFC 5880 §6.8.9) — refreshes
    /// the echo detection deadline.
    EchoLoopback,
}

/// A spawned session: its command channel, its observable snapshot,
/// and the task itself.
pub struct SessionHandle {
    pub spec: PeerSpec,
    ctl: mpsc::Sender<SessionCtl>,
    snapshot: watch::Receiver<SessionSnapshot>,
    join: tokio::task::JoinHandle<()>,
}

impl SessionHandle {
    /// The latest snapshot.
    pub fn snapshot(&self) -> SessionSnapshot {
        self.snapshot.borrow().clone()
    }

    /// The session's control channel (the daemon's echo reflector
    /// uses it to deliver loopback refreshes).
    pub fn ctl_sender(&self) -> &mpsc::Sender<SessionCtl> {
        &self.ctl
    }

    /// A fresh subscription to snapshot changes.
    pub fn subscribe(&self) -> watch::Receiver<SessionSnapshot> {
        self.snapshot.clone()
    }

    /// Graceful shutdown (RFC 5882 §8): AdminDown for one Detection
    /// Time, then stop. Consumes the handle.
    pub async fn shutdown(self) {
        let (done, done_rx) = oneshot::channel();
        if self.ctl.send(SessionCtl::Shutdown(done)).await.is_ok() {
            let _ = done_rx.await;
        }
        let _ = self.join.await;
    }
}

/// Spawns one session task: `tx` is its transmit socket, `inbound`
/// feeds it demultiplexed control packets, `echo_tx` (when the peer
/// runs echo) carries the echo packets to and from port 3785.
/// `report` (the zapi edge's feed, W1-b) receives a snapshot on every
/// state TRANSITION — best-effort (try_send): a full queue drops the
/// report (the next transition re-reports; zebra clients re-sync the
/// same way).
#[allow(clippy::too_many_arguments)]
pub fn spawn_session(
    spec: PeerSpec,
    local_discr: u32,
    tx: UdpSocket,
    inbound: mpsc::Receiver<InboundPacket>,
    echo_tx: Option<UdpSocket>,
    report: Option<mpsc::Sender<SessionSnapshot>>,
) -> SessionHandle {
    let label = spec.peer.to_string();
    let sm = SessionSm::new(spec.session.clone(), local_discr, label);
    let (snap_tx, snap_rx) = watch::channel(SessionSnapshot {
        peer: spec.peer,
        state: BfdState::Down,
        diag: Diagnostic::None,
        local_discr,
        remote_discr: 0,
        detection_time: sm.detection_time(),
        tx_interval: sm.negotiated_tx_interval(),
        last_transition: None,
    });
    let (ctl_tx, ctl_rx) = mpsc::channel(16);
    let join = tokio::spawn(run_session(
        spec.clone(),
        sm,
        tx,
        echo_tx,
        inbound,
        ctl_rx,
        snap_tx,
        report,
    ));
    SessionHandle {
        spec,
        ctl: ctl_tx,
        snapshot: snap_rx,
        join,
    }
}

/// Publishes a fresh snapshot (cheap; the watch coalesces) and, when
/// the update IS a transition, feeds the zapi edge's report channel.
fn publish(
    sm: &SessionSm,
    snap: &watch::Sender<SessionSnapshot>,
    note: Option<&str>,
    report: &Option<mpsc::Sender<SessionSnapshot>>,
) {
    let mut snapshot = None;
    snap.send_modify(|s| {
        s.state = sm.state();
        s.diag = sm.diag();
        s.remote_discr = sm.remote_discr();
        s.detection_time = sm.detection_time();
        s.tx_interval = sm.negotiated_tx_interval();
        if let Some(note) = note {
            s.last_transition = Some(note.to_string());
        }
        if note.is_some() {
            snapshot = Some(s.clone());
        }
    });
    if let (Some(feed), Some(snapshot)) = (report, snapshot) {
        if let Err(err) = feed.try_send(snapshot) {
            tracing::debug!(%err, "bfdd: status report dropped (queue full)");
        }
    }
}

/// The session loop: receive, periodic transmit, detection expiry,
/// echo arms, and control — every timer recomputed from the state
/// machine's pure math, per §6.8.2's "on every change" rule.
#[allow(clippy::too_many_arguments)]
async fn run_session(
    spec: PeerSpec,
    mut sm: SessionSm,
    tx: UdpSocket,
    echo_tx: Option<UdpSocket>,
    mut inbound: mpsc::Receiver<InboundPacket>,
    mut ctl: mpsc::Receiver<SessionCtl>,
    snap: watch::Sender<SessionSnapshot>,
    report: Option<mpsc::Sender<SessionSnapshot>>,
) {
    let mut rng = Rng::new_seeded();
    let policy = if spec.session.version_negotiation {
        VersionPolicy::AcceptDraft0
    } else {
        VersionPolicy::Version1Only
    };
    let first_wait = sm
        .transmit_interval(rng.unit())
        .max(Duration::from_millis(1));
    let mut next_tx = Instant::now() + first_wait;
    let mut detect_at: Option<Instant> = None;
    let mut echo_seq: u64 = 0;
    let mut echo_next_tx: Option<Instant> = None;
    let mut echo_detect_at: Option<Instant> = None;

    loop {
        // §6.8.5: a locally AdminDown session runs no detection
        // timers — nothing to detect while we are telling the peer
        // to tear down.
        if sm.state() == BfdState::AdminDown {
            detect_at = None;
        }
        let idle_tx = !sm.should_transmit_periodic();
        let detect_deadline = detect_at.unwrap_or(Instant::now() + Duration::from_secs(3600));
        let echo_tx_deadline = echo_next_tx.unwrap_or(Instant::now() + Duration::from_secs(3600));
        let echo_detect_deadline =
            echo_detect_at.unwrap_or(Instant::now() + Duration::from_secs(3600));

        tokio::select! {
            biased;

            cmd = ctl.recv() => match cmd {
                Some(SessionCtl::Shutdown(done)) => {
                    tracing::info!(peer = %spec.peer, "bfdd: session shutdown: AdminDown for one detection time (RFC 5882 §8)");
                    sm.enter_admin_down(Diagnostic::AdminDown);
                    let _ = transmit_now(&tx, &mut sm).await;
                    publish(&sm, &snap, Some("admin down (shutdown, RFC 5882 §8)"), &report);
                    let hold = sm
                        .detection_time()
                        .max(sm.negotiated_tx_interval())
                        .max(Duration::from_millis(100));
                    sleep_until(Instant::now() + hold).await;
                    let _ = transmit_now(&tx, &mut sm).await;
                    let _ = done.send(());
                    return;
                }
                Some(SessionCtl::EchoLoopback) => {
                    // §6.8.9: our echo came back — the path is alive.
                    echo_detect_at = Some(Instant::now() + sm.echo_detection_time());
                }
                None => return, // daemon gone; nothing to serve
            },

            packet = inbound.recv() => match packet {
                Some((from, bytes)) => {
                    let pkt = match BfdPacket::decode(&bytes, policy) {
                        Ok(pkt) => pkt,
                        Err(err) => {
                            tracing::debug!(peer = %from, %err, "bfdd: undecodable control packet dropped");
                            continue;
                        }
                    };
                    match sm.receive(&pkt) {
                        Ok(outcome) => {
                            // A processed packet refreshes the
                            // detection deadline (§6.8.6's final
                            // accounting).
                            detect_at = Some(Instant::now() + sm.detection_time());
                            if let Some(t) = &outcome.transition {
                                tracing::info!(peer = %spec.peer, %t, "bfdd: session transition");
                                publish(&sm, &snap, Some(&t.to_string()), &report);
                                // §6.8.7: transmit promptly on change.
                                let _ = transmit_now(&tx, &mut sm).await;
                                // §6.8.2: the interval changed with
                                // the state — the periodic deadline
                                // must not keep the pre-transition
                                // (1 s-floored) schedule, or the
                                // first Up-period gap can starve the
                                // peer's freshly-negotiated Detection
                                // Time.
                                next_tx = Instant::now() + sm.transmit_interval(rng.unit());
                            }
                            if outcome.send_final {
                                // §6.8.6 step 25: answer a Poll now.
                                let _ = transmit_now(&tx, &mut sm).await;
                                next_tx = Instant::now() + sm.transmit_interval(rng.unit());
                            }
                        }
                        Err(DiscardReason::AdminDownLocal) => {
                            // Step 21 discards after the timer
                            // updates — the packet still counts.
                            detect_at = Some(Instant::now() + sm.detection_time());
                        }
                        Err(reason) => {
                            tracing::debug!(peer = %spec.peer, %reason, "bfdd: control packet discarded");
                        }
                    }
                }
                None => return, // listeners gone
            },

            _ = sleep_until(detect_deadline), if detect_at.is_some() => {
                let t = sm.on_detection_timeout();
                if t.from != t.to {
                    tracing::info!(peer = %spec.peer, %t, "bfdd: session transition");
                    publish(&sm, &snap, Some(&t.to_string()), &report);
                }
                detect_at = None;
                let _ = transmit_now(&tx, &mut sm).await;
                next_tx = Instant::now() + sm.transmit_interval(rng.unit());
            }

            _ = sleep_until(echo_detect_deadline), if echo_detect_at.is_some() => {
                let t = sm.on_echo_timeout();
                if t.from != t.to {
                    tracing::info!(peer = %spec.peer, %t, "bfdd: session transition");
                    publish(&sm, &snap, Some(&t.to_string()), &report);
                }
                echo_detect_at = None;
                echo_next_tx = None;
                let _ = transmit_now(&tx, &mut sm).await;
                next_tx = Instant::now() + sm.transmit_interval(rng.unit());
            }

            _ = sleep_until(echo_tx_deadline), if echo_tx.is_some() && sm.echo_transmission_allowed() => {
                if let Some(sock) = &echo_tx {
                    echo_seq += 1;
                    let pdu = EchoPdu { discr: sm.local_discr(), seq: echo_seq };
                    match sock.send_to(&pdu.encode(), spec.echo_dst()).await {
                        Ok(_) => {}
                        Err(err) => tracing::debug!(peer = %spec.peer, %err, "bfdd: echo send failed"),
                    }
                    // Arm the echo detection window on the first
                    // probe; every loopback refreshes it.
                    if echo_detect_at.is_none() {
                        echo_detect_at = Some(Instant::now() + sm.echo_detection_time());
                    }
                }
                echo_next_tx = Some(Instant::now() + sm.echo_tx_interval());
            }

            _ = sleep_until(next_tx), if !idle_tx => {
                let pkt = sm.build_packet();
                if let Err(err) = tx.send(&pkt.encode()).await {
                    tracing::debug!(peer = %spec.peer, %err, "bfdd: control send failed");
                }
                next_tx = Instant::now() + sm.transmit_interval(rng.unit());
            }
        }
    }
}

/// One immediate transmission — state changes and Finals (§6.8.7).
async fn transmit_now(tx: &UdpSocket, sm: &mut SessionSm) -> io::Result<()> {
    let pkt = sm.build_packet();
    tx.send(&pkt.encode()).await.map(|_| ())
}

/// RFC 5880 §5.7: the echo payload is a local matter; ours is a
/// magic word, the sending session's discriminator (§6.8.9's
/// demultiplex key — it identifies "this is me" when the packet comes
/// home), and a sequence number.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EchoPdu {
    pub discr: u32,
    pub seq: u64,
}

impl EchoPdu {
    pub const MAGIC: u32 = 0x5255_4f45; // "ROUE"

    pub fn encode(&self) -> [u8; 16] {
        let mut buf = [0u8; 16];
        buf[0..4].copy_from_slice(&Self::MAGIC.to_be_bytes());
        buf[4..8].copy_from_slice(&self.discr.to_be_bytes());
        buf[8..16].copy_from_slice(&self.seq.to_be_bytes());
        buf
    }

    pub fn decode(bytes: &[u8]) -> Option<Self> {
        if bytes.len() < 16 || u32::from_be_bytes(bytes[0..4].try_into().ok()?) != Self::MAGIC {
            return None;
        }
        Some(Self {
            discr: u32::from_be_bytes(bytes[4..8].try_into().ok()?),
            seq: u64::from_be_bytes(bytes[8..16].try_into().ok()?),
        })
    }
}

/// What the echo reflector does with a packet arriving on 3785:
/// consume (it carries OUR discriminator — it is one of ours coming
/// home, §6.8.9) or reflect (it is the peer's probe — send it back).
/// The discriminator check is the loop guard: a reflected packet
/// carries its ORIGINAL sender's discriminator, so the originator
/// consumes what the reflector returns and no ping-pong exists.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EchoDisposition {
    Consume,
    Reflect,
}

pub fn echo_disposition(pdu: &EchoPdu, our_discrs: &[u32]) -> EchoDisposition {
    if our_discrs.contains(&pdu.discr) {
        EchoDisposition::Consume
    } else {
        EchoDisposition::Reflect
    }
}

/// Pumps a real UDP socket into a session's inbound feed — the
/// production listeners' primitive, and the test cross-wire that
/// puts the session loop on the real wire without the shared 3784
/// listener (whose bind the two-session same-host test cannot share).
pub fn spawn_socket_pump(socket: UdpSocket, feed: mpsc::Sender<InboundPacket>) {
    tokio::spawn(async move {
        let mut buf = vec![0u8; 2048];
        loop {
            match socket.recv_from(&mut buf).await {
                Ok((len, from)) => {
                    if feed.send((from, buf[..len].to_vec())).await.is_err() {
                        return;
                    }
                }
                Err(err) => {
                    tracing::debug!(%err, "bfdd: socket pump read failed; stopping");
                    return;
                }
            }
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::session::SessionConfig;

    /// §6.8.1: discriminators are nonzero and pairwise unique — a
    /// 10k-draw property loop.
    #[test]
    fn discriminator_pool_is_unique_and_nonzero() {
        let mut pool = DiscriminatorPool::new();
        let mut seen = HashSet::new();
        for _ in 0..10_000 {
            let d = pool.allocate();
            assert_ne!(d, 0);
            assert!(seen.insert(d), "discriminator {d} allocated twice");
        }
    }

    /// RFC 5881 §4/§5: the transmit socket binds inside the source
    /// port range and carries TTL 255.
    #[tokio::test]
    async fn control_tx_socket_port_and_ttl() {
        let spec = PeerSpec {
            peer: IpAddr::from(std::net::Ipv4Addr::LOCALHOST),
            local: None,
            multihop: false,
            echo: false,
            session: SessionConfig::default(),
        };
        let sock = bind_control_tx(&spec).unwrap();
        let port = sock.local_addr().unwrap().port();
        assert!(
            (SOURCE_PORT_MIN..=SOURCE_PORT_MAX).contains(&port),
            "source port {port} outside RFC 5881 §4's range"
        );
        assert_eq!(sock.ttl().unwrap(), TX_TTL);

        let v6 = PeerSpec {
            peer: IpAddr::from(std::net::Ipv6Addr::LOCALHOST),
            ..spec
        };
        let sock = bind_control_tx(&v6).unwrap();
        assert!(
            (SOURCE_PORT_MIN..=SOURCE_PORT_MAX).contains(&sock.local_addr().unwrap().port()),
            "v6 source port outside the range"
        );
        // v6 hop limit: the disclosed deviation — no settable
        // IPV6_UNICAST_HOPS under the fence; nothing to assert.
    }

    /// The destination ports: 3784 single-hop, 4784 multihop (RFC
    /// 5881 §4, RFC 5883 §3), 3785 echo.
    #[test]
    fn control_destinations() {
        let single = PeerSpec {
            peer: IpAddr::from(std::net::Ipv4Addr::LOCALHOST),
            local: None,
            multihop: false,
            echo: false,
            session: SessionConfig::default(),
        };
        let multi = PeerSpec {
            multihop: true,
            ..single.clone()
        };
        assert_eq!(single.control_dst().port(), PORT_SINGLEHOP);
        assert_eq!(multi.control_dst().port(), PORT_MULTIHOP);
        assert_eq!(single.echo_dst().port(), PORT_ECHO);
    }

    /// §6.8.6 steps 7–9 for the shared listener: a nonzero Your
    /// Discriminator selects by value, a zero one by address.
    #[test]
    fn peer_demultiplexing() {
        let spec = PeerSpec {
            peer: "198.51.100.9".parse().unwrap(),
            local: None,
            multihop: false,
            echo: false,
            session: SessionConfig::default(),
        };
        let from: SocketAddr = "198.51.100.9:49231".parse().unwrap();
        let other: SocketAddr = "198.51.100.99:49231".parse().unwrap();
        assert!(spec.matches(from, 0x1000, 0x1000));
        assert!(!spec.matches(from, 0x2000, 0x1000));
        assert!(spec.matches(from, 0, 0x1000), "bootstrap by address");
        assert!(!spec.matches(other, 0, 0x1000));
    }

    /// Echo PDU round-trip and the reflector's loop guard.
    #[test]
    fn echo_pdu_and_disposition() {
        let pdu = EchoPdu {
            discr: 0xdead_beef,
            seq: 42,
        };
        assert_eq!(EchoPdu::decode(&pdu.encode()), Some(pdu));
        assert_eq!(EchoPdu::decode(&[0u8; 15]), None);
        assert_eq!(EchoPdu::decode(&[0xff; 16]), None, "wrong magic");

        assert_eq!(
            echo_disposition(&pdu, &[0xdead_beef]),
            EchoDisposition::Consume,
            "our own packet coming home"
        );
        assert_eq!(
            echo_disposition(&pdu, &[1]),
            EchoDisposition::Reflect,
            "the peer's probe"
        );
    }

    /// The z5-family "over the real wire" test: two session loops on
    /// real UDP sockets cross-wired by pumps reach Up on both sides
    /// (§6.8.6's three-way handshake over the actual encapsulation).
    #[tokio::test]
    async fn two_sessions_reach_up_over_real_udp() {
        let (a, b) = session_pair().await;
        assert_eq!(a.snapshot().state, BfdState::Down);
        wait_for_state(&a, BfdState::Up, "A").await;
        wait_for_state(&b, BfdState::Up, "B").await;
        assert_eq!(a.snapshot().remote_discr, b.snapshot().local_discr);
        assert_eq!(b.snapshot().remote_discr, a.snapshot().local_discr);

        // A peer vanishing without AdminDown is a Detection Time
        // expiry on the other side (§6.8.8).
        a.join.abort();
        wait_for_state(&b, BfdState::Down, "B after A vanishes").await;
        assert_eq!(b.snapshot().diag, Diagnostic::TimeExpired);
        b.shutdown().await;
    }

    /// Graceful shutdown (RFC 5882 §8): the surviving peer sees
    /// AdminDown and drops with Neighbor Signaled Session Down
    /// (§6.8.6 step 22) — not a timer expiry.
    #[tokio::test]
    async fn graceful_shutdown_signals_admin_down() {
        let (a, b) = session_pair().await;
        wait_for_state(&a, BfdState::Up, "A").await;
        wait_for_state(&b, BfdState::Up, "B").await;
        a.shutdown().await;
        wait_for_state(&b, BfdState::Down, "B after A's AdminDown").await;
        assert_eq!(b.snapshot().diag, Diagnostic::NeighborSignaledSessionDown);
        b.shutdown().await;
    }

    /// Builds two cross-wired sessions on distinct loopback sockets:
    /// each side's transmit socket is connected to the other side's
    /// inbound socket, and a pump feeds arrivals to the session. The
    /// shared-3784-listener bind is the one production piece this
    /// cannot use twice on one host; the packets, timers, and loop
    /// are the real ones.
    async fn session_pair() -> (SessionHandle, SessionHandle) {
        let timers = SessionConfig {
            desired_min_tx: Duration::from_millis(100),
            required_min_rx: Duration::from_millis(100),
            detect_mult: 3,
            ..SessionConfig::default()
        };
        let mut pool = DiscriminatorPool::new();

        // Each side's inbound: a plain socket the pump feeds from.
        let rx_a = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let rx_b = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let a_addr = rx_a.local_addr().unwrap();
        let b_addr = rx_b.local_addr().unwrap();

        // Each side's transmit socket is CONNECTED to the peer's
        // inbound address — bind_control_tx's shape (RFC 5881 §4
        // source port, §5 TTL), aimed at the test's stand-in port
        // instead of 3784.
        let tx_a = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        tx_a.connect(b_addr).await.unwrap();
        let tx_b = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        tx_b.connect(a_addr).await.unwrap();

        let (feed_tx_a, feed_a) = mpsc::channel(64);
        let (feed_tx_b, feed_b) = mpsc::channel(64);
        spawn_socket_pump(rx_a, feed_tx_a);
        spawn_socket_pump(rx_b, feed_tx_b);

        let spec = |peer: IpAddr| PeerSpec {
            peer,
            local: Some(IpAddr::from(std::net::Ipv4Addr::LOCALHOST)),
            multihop: false,
            echo: false,
            session: timers.clone(),
        };
        let handle_a = spawn_session(spec(b_addr.ip()), pool.allocate(), tx_a, feed_a, None, None);
        let handle_b = spawn_session(spec(a_addr.ip()), pool.allocate(), tx_b, feed_b, None, None);
        (handle_a, handle_b)
    }

    async fn wait_for_state(h: &SessionHandle, want: BfdState, who: &str) {
        let mut rx = h.subscribe();
        let deadline = Instant::now() + Duration::from_secs(20);
        loop {
            if rx.borrow().state == want {
                return;
            }
            tokio::select! {
                _ = rx.changed() => {}
                _ = sleep_until(deadline) => {
                    panic!("{who} never reached {want}: {:?}", h.snapshot());
                }
            }
        }
    }
}
