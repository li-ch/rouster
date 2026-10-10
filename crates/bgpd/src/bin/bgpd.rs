//! bgpd — the Rouster BGP daemon (Phase 2, stream P2-b).
//!
//! Thin shell in the savd shape: config load, the Loc-RIB + policy
//! seams, the ZAPI edge (NHT for peer addresses, best-path export to
//! the zebra) when the config names a socket, then daemon run with
//! signal wiring (SIGTERM/SIGINT → ManualStop → Cease per §6.7;
//! SIGUSR1 → ROUTE-REFRESH per RFC 2918).
//!
//! Usage: `bgpd --config <PATH>`.

use std::sync::{Arc, Mutex};
use std::time::Duration;

use bgpd::peer::{ConfiguredNetworks, SharedSink};
use bgpd::rib::{AcceptAll, LocRib, LocRibOut, RibSink};
use bgpd::zedge::{self, AlwaysReachable, MirrorReachability, PeerReachability, ZedgeCommand};
use bgpd::{daemon, rib};
use tracing::{error, info, warn};

fn main() {
    let mut config_path = None;
    let mut it = std::env::args().skip(1);
    while let Some(arg) = it.next() {
        match arg.as_str() {
            "--config" | "-f" => {
                config_path = Some(
                    it.next()
                        .map(std::path::PathBuf::from)
                        .expect("--config requires a path"),
                );
            }
            "--help" | "-h" => {
                println!("usage: bgpd --config <PATH>");
                std::process::exit(0);
            }
            other => {
                eprintln!("unknown argument `{other}`");
                std::process::exit(2);
            }
        }
    }
    let config_path = config_path.expect("missing --config <PATH>");

    // savd-parity init: plain fmt, RUST_LOG-style filtering is not
    // wired (rousterd's logging module owns that shape).
    let _ = tracing_subscriber::fmt().try_init();

    let text = match std::fs::read_to_string(&config_path) {
        Ok(text) => text,
        Err(e) => {
            eprintln!("bgpd: cannot read {}: {e}", config_path.display());
            std::process::exit(1);
        }
    };
    let config = match bgpd::config::parse_config(&text) {
        Ok(config) => config,
        Err(e) => {
            eprintln!("bgpd: {e}");
            std::process::exit(1);
        }
    };
    info!(local_as = config.local_as, "bgpd: starting");

    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("tokio runtime");
    runtime.block_on(async move {
        // RIB: Loc-RIB behind the shared sink; best-path changes flow
        // to the export drainer (ZAPI) and the Adj-RIB-Out.
        let loc_rib = Arc::new(Mutex::new(LocRib::new(config.local_as)));
        let sink = SharedSink(Arc::new(Mutex::new(RibSink::new(Arc::clone(&loc_rib)))));
        let out_rib = Arc::new(LocRibOut::new(
            Arc::clone(&loc_rib),
            ConfiguredNetworks::from_config(&config),
            Arc::new(AcceptAll),
        ));

        // ZAPI edge: NHT for peers + best-path export (optional —
        // standalone mode runs without a zebra).
        let reach: Arc<dyn PeerReachability> = match config.zapi_socket.clone() {
            Some(socket) => {
                let peers = config.neighbors.keys().copied().collect();
                match zedge::spawn(socket, peers).await {
                    Ok((mirror, tx)) => {
                        // Export drainer: RibSink changes → ZAPI.
                        let drain_sink = sink.clone();
                        tokio::spawn(async move {
                            loop {
                                let changes = {
                                    let mut sink = drain_sink.0.lock().unwrap();
                                    sink.take_changes()
                                };
                                for change in changes {
                                    let command =
                                        match change.best.as_ref().and_then(rib::route_entry) {
                                            Some(entry) => ZedgeCommand::RouteAdd(entry),
                                            None => ZedgeCommand::RouteDel(
                                                rib::route_delete_entry(change.prefix),
                                            ),
                                        };
                                    let _ = tx.send(command);
                                }
                                tokio::time::sleep(Duration::from_millis(250)).await;
                            }
                        });
                        Arc::new(MirrorReachability(mirror))
                    }
                    Err(e) => {
                        warn!(error = %e, "bgpd: running standalone (no zapi edge)");
                        Arc::new(AlwaysReachable)
                    }
                }
            }
            None => Arc::new(AlwaysReachable),
        };

        let channels = match daemon::signal_channels() {
            Ok(channels) => channels,
            Err(e) => {
                error!("bgpd: signal setup failed: {e}");
                std::process::exit(1);
            }
        };
        let daemon = match daemon::Daemon::bind(config).await {
            Ok(daemon) => daemon,
            Err(e) => {
                error!("bgpd: bind failed: {e}");
                std::process::exit(1);
            }
        };
        if let Err(e) = daemon
            .run(
                sink,
                out_rib,
                channels.stop,
                channels.refresh,
                Arc::clone(&reach) as Arc<dyn PeerReachability>,
            )
            .await
        {
            error!("bgpd: run failed: {e}");
            std::process::exit(1);
        }
    });
}
