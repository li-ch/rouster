//! The bgpd daemon: TCP 179 (or configured port) listener, per-neighbor
//! connectors with the §10 ConnectRetry cadence, the session registry
//! with §6.8 collision detection (BGP-Identifier tiebreak + Cease on
//! the loser), and graceful start/stop.
//!
//! §6.8, W2-d M5: when a second connection arrives for a neighbor
//! that already has one, the daemon reads the challenger's OPEN and
//! applies the RFC's rule — "the connection initiated by the BGP
//! speaker with the higher BGP Identifier MUST be retained" (a fully
//! Established session is never preempted). The loser gets NOTIFICATION
//! Cease with RFC 4486 subcode 7 (Collision Resolution Failure), not a
//! silent TCP close. When the peer-initiated connection wins, the
//! consumed OPEN frame is replayed to the adopted session through the
//! [`ReplayStream`] adapter, so the session layer sees an untouched
//! byte stream.
//!
//! Graceful stop, pinned to the RFC text: SIGTERM/SIGINT map to
//! Event 2 (ManualStop) on every live session — in Established that
//! sends NOTIFICATION Cease, which §6.7 sanctions for a locally-chosen
//! close ("a BGP peer MAY choose, at any given time, to close its BGP
//! connection by sending the NOTIFICATION message with the Error Code
//! Cease"). SIGUSR1 sends ROUTE-REFRESH (RFC 2918 §3) to every
//! Established peer — the on-demand refresh knob (also the
//! import-policy soft reset: re-request, re-apply).
//!
//! The ZAPI edge (NHT for peer addresses, RIB view) lives in `zedge`
//! and is wired in by the binary when the config names a socket.

use std::collections::BTreeMap;
use std::io;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::net::{TcpListener, TcpStream};
use tokio::signal::unix::{signal, SignalKind};
use tokio::sync::watch;
use tracing::{info, warn};

use crate::config::{BgpdConfig, NeighborConfig};
use crate::error::{cease_subcode, error_code};
use crate::fsm::SessionConfig;
use crate::message::{BgpMessage, BgpNotification};
use crate::peer::{OutRib, PeerInfo, PeerSession, RouteSink, SessionShared, SharedSink};

/// ConnectRetry, §10-shaped: 120 s is the RFC's suggested *initial*
/// value; v1 backs off exponentially from 1 s to that cap (disclosed
/// deviation — a freshly-started peer's listener can take a moment to
/// bind, and the flat 120 s makes cold-start races look like
/// outages). Each successful session resets the backoff.
const CONNECT_RETRY_MAX: Duration = Duration::from_secs(120);
/// How long the daemon waits for Cease messages to drain on shutdown.
const SHUTDOWN_SETTLE: Duration = Duration::from_secs(2);
/// How long the collision resolver waits for the challenger's OPEN.
const COLLISION_PROBE: Duration = Duration::from_secs(5);
/// How long an evicted incumbent gets to vacate the registry slot.
const EVICT_WAIT: Duration = Duration::from_secs(3);

/// The §6.8 verdict: does the challenger (the just-arrived,
/// peer-initiated connection) replace the incumbent?
///
/// RFC 4271 §6.8: "the connection initiated by the BGP speaker with
/// the higher BGP Identifier MUST be retained" — and an Established
/// session is never preempted. The challenger always is peer-initiated
/// (`incumbent_ours` distinguishes our connector's session from an
/// earlier accepted one; two peer-initiated connections give the
/// tiebreak nothing to decide, first-wins stands).
pub fn collision_verdict(
    our_id: Ipv4Addr,
    peer_id: Ipv4Addr,
    incumbent_ours: bool,
    incumbent_established: bool,
) -> bool {
    if incumbent_established {
        return false;
    }
    incumbent_ours && peer_id > our_id
}

/// The per-neighbor session registry entry.
#[derive(Clone)]
struct Incumbent {
    /// Registry identity: cleanup only removes its own entry (a
    /// winning challenger overwrites the slot before the evicted
    /// incumbent finishes).
    id: u64,
    /// Whether this session was initiated by us (the connector).
    ours: bool,
    shared: Arc<SessionShared>,
    evict: watch::Sender<bool>,
}

type Registry = Arc<Mutex<BTreeMap<IpAddr, Incumbent>>>;

/// What registering a session hands back: the §6.8 observability
/// handle, the eviction channel, and the registry identity (cleanup
/// only removes its own entry).
struct Registered {
    shared: Arc<SessionShared>,
    evict: watch::Receiver<bool>,
    id: u64,
}

fn register(
    registry: &Registry,
    addr: IpAddr,
    ours: bool,
    next_id: &AtomicU64,
) -> Option<Registered> {
    let mut reg = registry.lock().unwrap();
    if reg.contains_key(&addr) {
        return None;
    }
    let id = next_id.fetch_add(1, Ordering::SeqCst);
    let shared = Arc::new(SessionShared::default());
    let (evict_tx, evict_rx) = watch::channel(false);
    reg.insert(
        addr,
        Incumbent {
            id,
            ours,
            shared: Arc::clone(&shared),
            evict: evict_tx,
        },
    );
    Some(Registered {
        shared,
        evict: evict_rx,
        id,
    })
}

/// Reserve the slot for the winning challenger: overwrites whatever
/// entry exists (the evicted incumbent's cleanup is a no-op by id).
fn re_register(registry: &Registry, addr: IpAddr, next_id: &AtomicU64) -> Registered {
    let id = next_id.fetch_add(1, Ordering::SeqCst);
    let shared = Arc::new(SessionShared::default());
    let (evict_tx, evict_rx) = watch::channel(false);
    registry.lock().unwrap().insert(
        addr,
        Incumbent {
            id,
            ours: false,
            shared: Arc::clone(&shared),
            evict: evict_tx,
        },
    );
    Registered {
        shared,
        evict: evict_rx,
        id,
    }
}

fn release(registry: &Registry, addr: IpAddr, id: u64) {
    let mut reg = registry.lock().unwrap();
    if reg.get(&addr).is_some_and(|inc| inc.id == id) {
        reg.remove(&addr);
    }
}

/// A bound, not-yet-running daemon.
pub struct Daemon {
    listener: TcpListener,
    config: BgpdConfig,
}

impl Daemon {
    /// Binds the listener (v4 wildcard; v6 neighbors are v1-deferred
    /// for the listener side — connectors dial v6 fine).
    pub async fn bind(config: BgpdConfig) -> std::io::Result<Self> {
        let listener = TcpListener::bind(("0.0.0.0", config.listen_port)).await?;
        info!(port = config.listen_port, "bgpd: listening");
        Ok(Self { listener, config })
    }

    pub fn local_addr(&self) -> std::io::Result<SocketAddr> {
        self.listener.local_addr()
    }

    /// Runs until `stop` flips true: sessions get ManualStop (Cease in
    /// Established per §6.7), connectors stand down, the listener
    /// closes, and in-flight Cease messages get a bounded window to
    /// drain.
    pub async fn run<S: RouteSink + 'static>(
        self,
        sink: SharedSink<S>,
        out_rib: Arc<dyn OutRib>,
        stop: watch::Receiver<bool>,
        refresh: watch::Receiver<u64>,
        reach: Arc<dyn crate::zedge::PeerReachability>,
    ) -> std::io::Result<()> {
        let registry: Registry = Arc::new(Mutex::new(BTreeMap::new()));
        let next_id = Arc::new(AtomicU64::new(1));
        let live = Arc::new(AtomicUsize::new(0));

        // Connectors for every non-passive neighbor (Events 1/3: the
        // active side; ConnectRetry per §10).
        for neighbor in self.config.neighbors.values() {
            if neighbor.passive {
                continue;
            }
            let neighbor = neighbor.clone();
            let ctx = SessionCtx {
                sink: sink.clone(),
                out_rib: Arc::clone(&out_rib),
                registry: Arc::clone(&registry),
                next_id: Arc::clone(&next_id),
                live: Arc::clone(&live),
            };
            let mut stop = stop.clone();
            let mut refresh = refresh.clone();
            let config = self.config.clone();
            let reach = Arc::clone(&reach);
            tokio::spawn(async move {
                connector_loop(config, neighbor, ctx, &mut stop, &mut refresh, reach).await;
            });
        }

        // The accept loop: match the remote address to a configured
        // neighbor; a free slot runs the session directly, an occupied
        // one goes to the §6.8 collision resolver.
        let config = Arc::new(self.config);
        let sink_accept = sink;
        let out_rib = Arc::clone(&out_rib);
        let registry_accept = Arc::clone(&registry);
        let next_id_accept = Arc::clone(&next_id);
        let live_accept = Arc::clone(&live);
        let mut stop_accept = stop;
        let refresh_accept = refresh.clone();
        let listener = self.listener;
        loop {
            tokio::select! {
                _ = stop_accept.changed() => {
                    if *stop_accept.borrow() {
                        break;
                    }
                }
                accepted = listener.accept() => {
                    match accepted {
                        Ok((stream, peer)) => {
                            let Some(neighbor) = config.neighbors.get(&peer.ip()).cloned()
                            else {
                                warn!(%peer, "bgpd: connection from unconfigured address, rejected");
                                continue;
                            };
                            let local_addr = stream
                                .local_addr()
                                .map(|a| a.ip())
                                .unwrap_or(IpAddr::V4(Ipv4Addr::UNSPECIFIED));
                            let ctx = SessionCtx {
                                sink: sink_accept.clone(),
                                out_rib: Arc::clone(&out_rib),
                                registry: Arc::clone(&registry_accept),
                                next_id: Arc::clone(&next_id_accept),
                                live: Arc::clone(&live_accept),
                            };
                            let conn = Connection {
                                peer_addr: peer.ip(),
                                local_addr,
                                config: Arc::clone(&config),
                                neighbor,
                                ctx,
                                stop: stop_accept.clone(),
                                refresh: refresh_accept.clone(),
                            };
                            tokio::spawn(async move {
                                accept_connection(stream, conn).await;
                            });
                        }
                        Err(e) => {
                            warn!(error = %e, "bgpd: accept failed");
                        }
                    }
                }
            }
        }

        // Bounded settle: sessions flush their Cease NOTIFICATIONs.
        let deadline = tokio::time::Instant::now() + SHUTDOWN_SETTLE;
        while live.load(Ordering::SeqCst) > 0 && tokio::time::Instant::now() < deadline {
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        info!("bgpd: stopped");
        Ok(())
    }
}

/// One accepted connection: a free registry slot runs the session
/// (Events 4/5 shape); an occupied one resolves the §6.8 collision.
async fn accept_connection<S: RouteSink + 'static>(stream: TcpStream, conn: Connection<S>) {
    let live = Arc::clone(&conn.ctx.live);
    live.fetch_add(1, Ordering::SeqCst);
    let registered = register(&conn.ctx.registry, conn.peer_addr, false, &conn.ctx.next_id);
    match registered {
        Some(registered) => {
            run_session(stream, conn, registered).await;
        }
        None => {
            resolve_collision(stream, conn).await;
        }
    }
    live.fetch_sub(1, Ordering::SeqCst);
}

/// The §6.8 collision resolver: read the challenger's OPEN, apply the
/// BGP-Identifier tiebreak, Cease the loser.
async fn resolve_collision<S: RouteSink + 'static>(mut stream: TcpStream, conn: Connection<S>) {
    let peer_addr = conn.peer_addr;
    let incumbent = conn.ctx.registry.lock().unwrap().get(&peer_addr).cloned();
    let Some(incumbent) = incumbent else {
        return; // raced with teardown; nothing to collide with
    };
    // The challenger's OPEN, bounded.
    let probe =
        tokio::time::timeout(COLLISION_PROBE, crate::peer::read_frame(&mut stream, true)).await;
    let open = match probe {
        Ok(Ok(Ok(BgpMessage::Open(open)))) if open.peer_as4() == conn.neighbor.remote_as => open,
        _ => {
            warn!(peer = %peer_addr, "bgpd: collision challenger sent no usable OPEN, dropped");
            let _ = stream.shutdown().await;
            return;
        }
    };
    let our_id = conn.config.router_id.unwrap_or(Ipv4Addr::LOCALHOST);
    let keep_challenger = collision_verdict(
        our_id,
        open.bgp_id,
        incumbent.ours,
        incumbent.shared.is_established(),
    );
    if !keep_challenger {
        info!(peer = %peer_addr, challenger_id = %open.bgp_id,
            "bgpd: collision resolved for the incumbent (§6.8); Cease 6/7 to the challenger");
        if send_cease_collision(&mut stream).await.is_err() {
            // The challenger closed first; nothing to tell.
        }
        let _ = stream.shutdown().await;
        return;
    }
    // The peer-initiated connection wins: evict the incumbent, adopt
    // the challenger with its consumed OPEN frame replayed.
    info!(peer = %peer_addr, challenger_id = %open.bgp_id, our_id = %our_id,
        "bgpd: collision resolved for the challenger (peer BGP ID higher, §6.8); evicting our session");
    let registered = re_register(&conn.ctx.registry, peer_addr, &conn.ctx.next_id);
    let _ = incumbent.evict.send(true);
    // Bounded wait for the incumbent to vacate (its cleanup is id-safe
    // either way — this only paces our own re-admission logging).
    let deadline = tokio::time::Instant::now() + EVICT_WAIT;
    while tokio::time::Instant::now() < deadline {
        let vacated = conn
            .ctx
            .registry
            .lock()
            .unwrap()
            .get(&peer_addr)
            .is_none_or(|i| i.id == registered.id);
        if vacated {
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    // The consumed OPEN, re-encoded (the codec round trip is
    // gold-tested) and replayed ahead of the live read half.
    let replay = BgpMessage::Open(open).encode(true).unwrap_or_default();
    let (read_half, write_half) = stream.into_split();
    let io = ReplayStream {
        head: replay,
        pos: 0,
        read: read_half,
        write: write_half,
    };
    run_session(io, conn, registered).await;
}

/// NOTIFICATION Cease / Collision Resolution Failure (RFC 4486
/// subcode 7) — what §6.8's losing connection is told.
async fn send_cease_collision(stream: &mut TcpStream) -> io::Result<()> {
    let notification = BgpMessage::Notification(BgpNotification {
        code: error_code::CEASE,
        subcode: cease_subcode::COLLISION_RESOLUTION_FAILURE,
        data: Vec::new(),
    });
    let bytes = notification
        .encode(true)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?;
    stream.write_all(&bytes).await?;
    stream.flush().await
}

/// A split TCP stream with consumed bytes replayed ahead of the read
/// half — hands the adopted challenger to the session layer as an
/// untouched stream. No `unsafe` (Unpin projection only).
struct ReplayStream {
    head: Vec<u8>,
    pos: usize,
    read: tokio::net::tcp::OwnedReadHalf,
    write: tokio::net::tcp::OwnedWriteHalf,
}

impl AsyncRead for ReplayStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if this.pos < this.head.len() {
            let remaining = &this.head[this.pos..];
            let n = remaining.len().min(buf.capacity());
            buf.put_slice(&remaining[..n]);
            this.pos += n;
            return Poll::Ready(Ok(()));
        }
        Pin::new(&mut this.read).poll_read(cx, buf)
    }
}

impl AsyncWrite for ReplayStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.get_mut().write).poll_write(cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().write).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().write).poll_shutdown(cx)
    }
}

/// Shared session plumbing (registry + signals).
struct SessionCtx<S: RouteSink> {
    sink: SharedSink<S>,
    out_rib: Arc<dyn OutRib>,
    registry: Registry,
    next_id: Arc<AtomicU64>,
    live: Arc<AtomicUsize>,
}

impl<S: RouteSink> Clone for SessionCtx<S> {
    fn clone(&self) -> Self {
        Self {
            sink: self.sink.clone(),
            out_rib: Arc::clone(&self.out_rib),
            registry: Arc::clone(&self.registry),
            next_id: Arc::clone(&self.next_id),
            live: Arc::clone(&self.live),
        }
    }
}

/// One connection's launch state: peer/session addressing, the config
/// pair, the daemon plumbing, and the signal channels — everything a
/// session needs beyond its IO. Bundles what would otherwise be an
/// argument list mirroring the session's real state one field at a
/// time.
struct Connection<S: RouteSink> {
    peer_addr: IpAddr,
    local_addr: IpAddr,
    config: Arc<BgpdConfig>,
    neighbor: NeighborConfig,
    ctx: SessionCtx<S>,
    stop: watch::Receiver<bool>,
    refresh: watch::Receiver<u64>,
}

/// One session over any stream: per-session stop = global stop OR
/// eviction (§6.8), so the collision machinery can ManualStop exactly
/// one session.
async fn run_session<S, IO>(io: IO, conn: Connection<S>, registered: Registered)
where
    S: RouteSink,
    IO: AsyncRead + AsyncWrite + Unpin,
{
    let Connection {
        peer_addr,
        local_addr,
        config,
        neighbor,
        ctx,
        stop,
        refresh,
    } = conn;
    let Registered { shared, evict, id } = registered;

    // Per-session stop: the daemon's global stop OR this session's
    // eviction.
    let (session_stop_tx, session_stop) = watch::channel(false);
    let mut global = stop;
    let mut evict = evict;
    tokio::spawn(async move {
        tokio::select! {
            _ = global.changed() => {
                if *global.borrow() {
                    let _ = session_stop_tx.send(true);
                }
            }
            _ = evict.changed() => {
                if *evict.borrow() {
                    let _ = session_stop_tx.send(true);
                }
            }
        }
    });

    let peer = PeerInfo {
        address: peer_addr,
        remote_as: neighbor.remote_as,
        bgp_id: None,
    };
    let session_config = session_config_for(&config, &neighbor);
    // RFC 7606 §7's LOCAL_PREF row keys on the session type; the
    // session refines `internal` from the negotiated OPEN, so the
    // config side only carries the mode.
    let internal = neighbor.remote_as == config.local_as;
    let mut session = PeerSession::new(
        io,
        session_config,
        peer,
        local_addr,
        Some(ctx.out_rib),
        Duration::from_secs(neighbor.mrai),
    )
    .with_shared(shared)
    .with_update_handling(neighbor.update_handling.handling(internal));
    let mut sink = ctx.sink;
    let end = session
        .run_with_signals(&mut sink, session_stop, refresh)
        .await;
    info!(peer = %peer_addr, ?end, "bgpd: session ended");
    release(&ctx.registry, peer_addr, id);
}

/// The active side: dial the neighbor, run the session, back off
/// ConnectRetry on failure, repeat while the daemon lives.
async fn connector_loop<S: RouteSink + 'static>(
    config: BgpdConfig,
    neighbor: NeighborConfig,
    ctx: SessionCtx<S>,
    stop: &mut watch::Receiver<bool>,
    refresh: &mut watch::Receiver<u64>,
    reach: Arc<dyn crate::zedge::PeerReachability>,
) {
    let config = Arc::new(config);
    let target = SocketAddr::new(neighbor.address, config.listen_port);
    let mut backoff = Duration::from_secs(1);
    loop {
        if *stop.borrow() {
            return;
        }
        // §8's Connect precondition, the zebra-client way: wait for
        // the peer address to be usable (NHT/mirror gate; standalone
        // mode's AlwaysReachable never waits).
        while !reach.reachable(neighbor.address) {
            tokio::select! {
                _ = stop.changed() => {
                    if *stop.borrow() {
                        return;
                    }
                }
                _ = tokio::time::sleep(Duration::from_millis(500)) => {}
            }
        }
        match TcpStream::connect(target).await {
            Ok(stream) => {
                let Some(registered) =
                    register(&ctx.registry, neighbor.address, true, &ctx.next_id)
                else {
                    // A passive session beat us to it (§6.8: the
                    // peer-initiated connection is already registered;
                    // if the tiebreak favors it, the resolver evicts
                    // nothing of ours): this connector stands down.
                    return;
                };
                ctx.live.fetch_add(1, Ordering::SeqCst);
                let local_addr = stream
                    .local_addr()
                    .map(|a| a.ip())
                    .unwrap_or(IpAddr::V4(Ipv4Addr::UNSPECIFIED));
                let conn = Connection {
                    peer_addr: neighbor.address,
                    local_addr,
                    config: Arc::clone(&config),
                    neighbor: neighbor.clone(),
                    ctx: ctx.clone(),
                    stop: stop.clone(),
                    refresh: refresh.clone(),
                };
                run_session(stream, conn, registered).await;
                ctx.live.fetch_sub(1, Ordering::SeqCst);
                // A completed session is not a failed attempt:
                // re-dial immediately with the backoff reset.
                backoff = Duration::from_secs(1);
                continue;
            }
            Err(e) => {
                info!(%target, error = %e, wait = ?backoff, "bgpd: connect failed, ConnectRetry backoff");
            }
        }
        tokio::select! {
            _ = stop.changed() => {
                if *stop.borrow() {
                    return;
                }
            }
            _ = tokio::time::sleep(backoff) => {
                backoff = (backoff * 2).min(CONNECT_RETRY_MAX);
            }
        }
    }
}

/// Builds the FSM session config for a neighbor (per-neighbor timer
/// overrides beat the global hold).
fn session_config_for(config: &BgpdConfig, neighbor: &NeighborConfig) -> SessionConfig {
    let hold = neighbor.timers.map(|(_, h)| h).unwrap_or(config.hold_time);
    SessionConfig::new(
        config.local_as,
        config.router_id.unwrap_or(Ipv4Addr::LOCALHOST),
        hold,
    )
}

/// The daemon's signal wiring, returned as channels the caller passes
/// to [`Daemon::run`]: SIGTERM/SIGINT → stop; SIGUSR1 → refresh
/// counter bump. Split out so the interop test can drive the daemon
/// without OS signals.
pub struct SignalChannels {
    pub stop: watch::Receiver<bool>,
    pub refresh: watch::Receiver<u64>,
}

pub fn signal_channels() -> std::io::Result<SignalChannels> {
    let (stop_tx, stop_rx) = watch::channel(false);
    let (refresh_tx, refresh_rx) = watch::channel(0u64);
    let mut sigterm = signal(SignalKind::terminate())?;
    let mut sigint = signal(SignalKind::interrupt())?;
    let mut sigusr1 = signal(SignalKind::user_defined1())?;
    tokio::spawn(async move {
        tokio::select! {
            _ = sigterm.recv() => {}
            _ = sigint.recv() => {}
        }
        info!("bgpd: shutdown signal, sending Cease to peers (§6.7)");
        let _ = stop_tx.send(true);
    });
    tokio::spawn(async move {
        while sigusr1.recv().await.is_some() {
            refresh_tx.send_modify(|c| *c += 1);
        }
    });
    Ok(SignalChannels {
        stop: stop_rx,
        refresh: refresh_rx,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn session_config_prefers_neighbor_timers() {
        let config = BgpdConfig {
            hold_time: 90,
            ..BgpdConfig::default()
        };
        let mut neighbor = NeighborConfig {
            address: "192.0.2.9".parse().unwrap(),
            remote_as: 65001,
            passive: false,
            timers: Some((10, 30)),
            mrai: 0,
            role: None,
            update_handling: Default::default(),
        };
        assert_eq!(session_config_for(&config, &neighbor).hold_time, 30);
        neighbor.timers = None;
        assert_eq!(session_config_for(&config, &neighbor).hold_time, 90);
    }

    // ---- W2-d M5: §6.8 collision detection ------------------------

    fn id(o1: u8, o2: u8, o3: u8, o4: u8) -> Ipv4Addr {
        Ipv4Addr::new(o1, o2, o3, o4)
    }

    /// The §6.8 verdict table: "the connection initiated by the BGP
    /// speaker with the higher BGP Identifier MUST be retained"; an
    /// Established session is never preempted; the challenger is
    /// always the peer-initiated connection.
    #[test]
    fn collision_verdict_table() {
        let our = id(10, 0, 0, 1);
        let higher_peer = id(10, 0, 0, 9);
        let lower_peer = id(10, 0, 0, 0);

        // Peer's id higher and the incumbent is our connector's:
        // the peer-initiated challenger wins.
        assert!(collision_verdict(our, higher_peer, true, false));
        // Our id higher (or equal): our initiated connection stays.
        assert!(!collision_verdict(our, lower_peer, true, false));
        assert!(
            !collision_verdict(our, our, true, false),
            "no tiebreak on equal ids"
        );
        // An Established incumbent is never preempted, whatever the ids.
        assert!(!collision_verdict(our, higher_peer, true, true));
        // The incumbent is itself peer-initiated: the tiebreak has
        // nothing to choose between (both connections are the peer's);
        // first-wins.
        assert!(!collision_verdict(our, higher_peer, false, false));
    }

    /// The adopted challenger sees an untouched byte stream: the
    /// consumed OPEN frame replays ahead of the live half (real
    /// loopback pair — the adapter wraps owned TCP halves).
    #[tokio::test]
    async fn replay_stream_replays_then_streams() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let client = tokio::spawn(async move {
            let a = TcpStream::connect(addr).await.unwrap();
            a
        });
        let (b, _) = listener.accept().await.unwrap();
        let a = client.await.unwrap();
        let (read_half, write_half) = a.into_split();
        let mut replay = ReplayStream {
            head: vec![1, 2, 3],
            pos: 0,
            read: read_half,
            write: write_half,
        };
        let mut b = b;
        b.write_all(&[4, 5]).await.unwrap();
        b.flush().await.unwrap();
        let mut got = vec![0u8; 5];
        replay.read_exact(&mut got).await.unwrap();
        assert_eq!(got, vec![1, 2, 3, 4, 5], "head first, stream second");
        // Writes pass through to the peer.
        replay.write_all(&[9]).await.unwrap();
        replay.flush().await.unwrap();
        let mut one = [0u8; 1];
        b.read_exact(&mut one).await.unwrap();
        assert_eq!(one[0], 9);
    }

    /// The session publishes the OPEN-learned BGP ID and the
    /// Established transition (what the collision resolver reads).
    #[tokio::test]
    async fn session_publishes_collision_state() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let shared = Arc::new(SessionShared::default());
        let (ours, mut theirs) = tokio::io::duplex(4096);
        let mut session = PeerSession::new(
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
        )
        .with_shared(Arc::clone(&shared));
        let sink = SharedSink(Arc::new(Mutex::new(crate::peer::NullSink)));
        let mut driver_sink = sink.clone();
        let driver = tokio::spawn(async move { session.run(&mut driver_sink).await });

        // The peer's OPEN (BGP id 10.9.9.9), then the KEEPALIVE that
        // completes the handshake.
        let open = BgpMessage::Open(crate::message::BgpOpen::new(
            65001,
            30,
            "10.9.9.9".parse().unwrap(),
            vec![],
        ))
        .encode(true)
        .unwrap();
        theirs.write_all(&open).await.unwrap();
        theirs.flush().await.unwrap();
        // Consume our OPEN answer.
        let mut hdr = [0u8; 19];
        theirs.read_exact(&mut hdr).await.unwrap();
        let len = u16::from_be_bytes([hdr[16], hdr[17]]) as usize;
        let mut body = vec![0u8; len - 19];
        theirs.read_exact(&mut body).await.unwrap();
        let ka = BgpMessage::Keepalive.encode(true).unwrap();
        theirs.write_all(&ka).await.unwrap();
        theirs.flush().await.unwrap();
        let mut established = false;
        for _ in 0..100 {
            if shared.is_established() {
                established = true;
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        assert!(established, "Established observed through SessionShared");
        assert_eq!(
            *shared.peer_bgp_id.lock().unwrap(),
            Some("10.9.9.9".parse().unwrap()),
            "OPEN-learned id published"
        );
        driver.abort();
    }
}
