//! The bgpd daemon: TCP 179 (or configured port) listener, per-neighbor
//! connectors with the §10 ConnectRetry cadence, the session registry
//! (§6.8 first-wins collision policy), and graceful start/stop.
//!
//! Graceful stop, pinned to the RFC text: SIGTERM/SIGINT map to
//! Event 2 (ManualStop) on every live session — in Established that
//! sends NOTIFICATION Cease, which §6.7 sanctions for a locally-chosen
//! close ("a BGP peer MAY choose, at any given time, to close its BGP
//! connection by sending the NOTIFICATION message with the Error Code
//! Cease"). SIGUSR1 sends ROUTE-REFRESH (RFC 2918 §3) to every
//! Established peer — the on-demand knob the interop smoke uses.
//!
//! The ZAPI edge (NHT for peer addresses, RIB view) lives in `zedge`
//! and is wired in by the binary when the config names a socket.

use std::collections::HashSet;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use tokio::net::{TcpListener, TcpStream};
use tokio::signal::unix::{signal, SignalKind};
use tokio::sync::watch;
use tracing::{info, warn};

use crate::config::{BgpdConfig, NeighborConfig};
use crate::fsm::SessionConfig;
use crate::peer::{OutRib, PeerInfo, PeerSession, RouteSink, SharedSink};

/// ConnectRetry, §10-shaped: 120 s is the RFC's suggested *initial*
/// value; v1 backs off exponentially from 1 s to that cap (disclosed
/// deviation — a freshly-started peer's listener can take a moment to
/// bind, and the flat 120 s makes cold-start races look like
/// outages). Each successful session resets the backoff.
const CONNECT_RETRY_MAX: Duration = Duration::from_secs(120);
/// How long the daemon waits for Cease messages to drain on shutdown.
const SHUTDOWN_SETTLE: Duration = Duration::from_secs(2);

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
        let busy: Arc<Mutex<HashSet<IpAddr>>> = Arc::new(Mutex::new(HashSet::new()));
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
                busy: Arc::clone(&busy),
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
        // neighbor, apply the §6.8 first-wins admission, spawn the
        // session.
        let config = self.config;
        let sink_accept = sink;
        let out_rib = Arc::clone(&out_rib);
        let busy_accept = Arc::clone(&busy);
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
                            if !admit(&busy_accept, peer.ip()) {
                                warn!(%peer, "bgpd: second connection for peer dropped (§6.8 first-wins)");
                                continue;
                            }
                            let config = config.clone();
                            let ctx = SessionCtx {
                                sink: sink_accept.clone(),
                                out_rib: Arc::clone(&out_rib),
                                busy: Arc::clone(&busy_accept),
                                live: Arc::clone(&live_accept),
                            };
                            let stop = stop_accept.clone();
                            let refresh = refresh_accept.clone();
                            live_accept.fetch_add(1, Ordering::SeqCst);
                            tokio::spawn(async move {
                                run_accepted_session(
                                    stream, peer.ip(), &config, &neighbor, ctx, stop, refresh,
                                )
                                .await;
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

/// One accepted session: the passive side (Events 4/5 shape) driven to
/// termination.
/// Shared session plumbing (registry + signals).
struct SessionCtx<S: RouteSink> {
    sink: SharedSink<S>,
    out_rib: Arc<dyn OutRib>,
    busy: Arc<Mutex<HashSet<IpAddr>>>,
    live: Arc<AtomicUsize>,
}

impl<S: RouteSink> Clone for SessionCtx<S> {
    fn clone(&self) -> Self {
        Self {
            sink: self.sink.clone(),
            out_rib: Arc::clone(&self.out_rib),
            busy: Arc::clone(&self.busy),
            live: Arc::clone(&self.live),
        }
    }
}

async fn run_accepted_session<S: RouteSink>(
    stream: TcpStream,
    peer_addr: IpAddr,
    config: &BgpdConfig,
    neighbor: &NeighborConfig,
    ctx: SessionCtx<S>,
    stop: watch::Receiver<bool>,
    refresh: watch::Receiver<u64>,
) {
    let peer = PeerInfo {
        address: peer_addr,
        remote_as: neighbor.remote_as,
        bgp_id: None,
    };
    let local_addr = stream
        .local_addr()
        .map(|a| a.ip())
        .unwrap_or(IpAddr::V4(Ipv4Addr::UNSPECIFIED));
    let session_config = session_config_for(config, neighbor);
    let mut session = PeerSession::new(
        stream,
        session_config,
        peer,
        local_addr,
        Some(ctx.out_rib),
        Duration::from_secs(neighbor.mrai),
    );
    let mut sink = ctx.sink;
    let end = session.run_with_signals(&mut sink, stop, refresh).await;
    info!(peer = %peer_addr, ?end, "bgpd: session ended");
    ctx.busy.lock().unwrap().remove(&peer_addr);
    ctx.live.fetch_sub(1, Ordering::SeqCst);
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
                if !admit(&ctx.busy, neighbor.address) {
                    // A passive session beat us to it (§6.8
                    // first-wins): this connector stands down.
                    return;
                }
                ctx.live.fetch_add(1, Ordering::SeqCst);
                let peer = PeerInfo {
                    address: neighbor.address,
                    remote_as: neighbor.remote_as,
                    bgp_id: None,
                };
                let local_addr = stream
                    .local_addr()
                    .map(|a| a.ip())
                    .unwrap_or(IpAddr::V4(Ipv4Addr::UNSPECIFIED));
                let session_config = session_config_for(&config, &neighbor);
                let mut session = PeerSession::new(
                    stream,
                    session_config,
                    peer,
                    local_addr,
                    Some(Arc::clone(&ctx.out_rib)),
                    Duration::from_secs(neighbor.mrai),
                );
                let mut sink = ctx.sink.clone();
                let end = session
                    .run_with_signals(&mut sink, stop.clone(), refresh.clone())
                    .await;
                info!(peer = %neighbor.address, ?end, "bgpd: session ended");
                ctx.busy.lock().unwrap().remove(&neighbor.address);
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

fn admit(busy: &Arc<Mutex<HashSet<IpAddr>>>, peer: IpAddr) -> bool {
    busy.lock().unwrap().insert(peer)
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
        };
        assert_eq!(session_config_for(&config, &neighbor).hold_time, 30);
        neighbor.timers = None;
        assert_eq!(session_config_for(&config, &neighbor).hold_time, 90);
    }
}
