//! bgpd — the Rouster BGP daemon (Phase 2, stream P2-b).
//!
//! Thin shell in the savd shape: config load, the Loc-RIB + policy
//! seams, the ZAPI edge (NHT for peer addresses, best-path export to
//! the zebra) when the config names a socket, then daemon run with
//! signal wiring (SIGTERM/SIGINT → ManualStop → Cease per §6.7;
//! SIGUSR1 → ROUTE-REFRESH per RFC 2918).
//!
//! Usage: `bgpd --config <PATH>`, or `bgpd --validate-config <PATH>`
//! to parse a candidate config and exit 0/1 (the configd pre-apply
//! gate's daemon half, S8-c).

use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use bgpd::peer::{ConfiguredNetworks, SharedSink};
use bgpd::rib::{LocRib, LocRibOut, RibSink};
use bgpd::zedge::{self, AlwaysReachable, NhtReachability, PeerReachability};
use bgpd::{daemon, rib};
use tracing::{error, info, warn};

fn main() {
    let mut config_path = None;
    let mut validate_path = None;
    let mut it = std::env::args().skip(1);
    while let Some(arg) = it.next() {
        match arg.as_str() {
            "--config" | "-f" => {
                config_path = Some(
                    it.next()
                        .map(PathBuf::from)
                        .expect("--config requires a path"),
                );
            }
            "--validate-config" => {
                validate_path = Some(
                    it.next()
                        .map(PathBuf::from)
                        .expect("--validate-config requires a path"),
                );
            }
            "--help" | "-h" => {
                println!("usage: bgpd --config <PATH>");
                println!("       bgpd --validate-config <PATH>");
                std::process::exit(0);
            }
            other => {
                eprintln!("unknown argument `{other}`");
                std::process::exit(2);
            }
        }
    }
    // The validate arm is config-only: it exits before the runtime,
    // sockets, or sessions, so it runs on any host.
    if let Some(path) = validate_path {
        std::process::exit(validate_config(&path));
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
        // W2-d: policy + validation wiring. Named filters compile (or
        // the daemon refuses to start — a bad policy is a config
        // error, not a warning); the RPKI tables load or the RTR
        // client spawns; the Loc-RIB and Adj-RIB-Out run through the
        // pipelines. Unconfigured everything = the v1 accept-all
        // behavior.
        let named = match bgpd::policy_engine::compile_named_policy(&config) {
            Ok(named) => named,
            Err(e) => {
                error!("bgpd: {e}");
                std::process::exit(1);
            }
        };
        let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
        let tables = match bgpd::rov::tables_from_config(&config.rpki, shutdown_rx) {
            Ok(tables) => tables,
            Err(e) => {
                error!("bgpd: {e}");
                std::process::exit(1);
            }
        };
        let validation = Arc::new(bgpd::rov::ValidationGate {
            tables,
            reject_invalid: config.rpki.reject_invalid,
            aspa: config.aspa,
            roles: config
                .neighbors
                .iter()
                .filter_map(|(addr, n)| n.role.map(|r| (*addr, r)))
                .collect(),
        });
        let import: Arc<dyn bgpd::rib::ImportPolicy> = Arc::new(
            bgpd::policy_engine::ImportPipeline::new(Arc::clone(&validation), named.import),
        );
        let export: Arc<dyn bgpd::rib::ExportPolicy> =
            Arc::new(bgpd::policy_engine::ExportPipeline::new(
                Arc::clone(&validation),
                named.export,
                config.local_as,
            ));

        // RIB: Loc-RIB behind the shared sink; best-path changes flow
        // to the export drainer (ZAPI) and the Adj-RIB-Out. Route
        // server mode (N5): the RS-client set rides the Loc-RIB —
        // their routes reflect transparently between clients and
        // never reach the kernel.
        let loc_rib = Arc::new(Mutex::new(LocRib::with_policy(config.local_as, import)));
        {
            let mut rib = loc_rib.lock().unwrap();
            rib.set_route_server_clients(
                config
                    .neighbors
                    .values()
                    .filter(|n| n.route_server)
                    .map(|n| n.address),
            );
            // RFC 4456 (S7-b): the route-reflector client set —
            // §9.2's iBGP redistribution prohibition lifts toward and
            // from these peers.
            rib.set_route_reflector_clients(
                config
                    .neighbors
                    .values()
                    .filter(|n| n.rr_client)
                    .map(|n| n.address),
            );
        }
        let sink = SharedSink(Arc::new(Mutex::new(RibSink::new(Arc::clone(&loc_rib)))));
        // PERF-M1 M1: the memory census (feature `mem-census`,
        // runtime-gated by BGPD_MEM_CENSUS=1 so one binary serves both
        // the clean receipt runs and the census runs). Inert otherwise:
        // zero code without the feature, one env check with it.
        #[cfg(feature = "mem-census")]
        if std::env::var_os("BGPD_MEM_CENSUS").is_some() {
            bgpd::census::spawn(Arc::clone(&loc_rib));
        }
        // The BAR-SAV feed writer (S9-a M3, `barsav feed <path>`): a
        // read-only Adj-RIB-In snapshot publisher. It never touches
        // the decision path — it locks the Loc-RIB just long enough
        // to render `LocRib::barsav_feed_text`, and swaps the file
        // atomically (tmp + rename) only when the snapshot changed,
        // so savd's poll never reads a half-written line. Determinism
        // of the render makes change detection a plain compare.
        if let Some(feed_path) = config.barsav_feed.clone() {
            let feed_rib = Arc::clone(&loc_rib);
            tokio::spawn(async move {
                let mut last = String::new();
                loop {
                    let text = {
                        let rib = feed_rib.lock().unwrap();
                        rib.barsav_feed_text()
                    };
                    if text != last {
                        let tmp = feed_path.with_extension("tmp");
                        if let Err(e) = std::fs::write(&tmp, &text) {
                            warn!(error = %e, path = %feed_path.display(),
                                "bgpd: cannot write barsav feed snapshot");
                        } else if let Err(e) = std::fs::rename(&tmp, &feed_path) {
                            warn!(error = %e, path = %feed_path.display(),
                                "bgpd: cannot publish barsav feed snapshot");
                        } else {
                            let lines = text.lines().count() - 2; // header
                            info!(path = %feed_path.display(), paths = lines,
                                "bgpd: barsav feed snapshot published");
                            last = text;
                        }
                    }
                    tokio::time::sleep(Duration::from_millis(500)).await;
                }
            });
        }
        let out_rib = Arc::new(LocRibOut::new(
            Arc::clone(&loc_rib),
            ConfiguredNetworks::from_config(&config),
            export,
        ));

        // ZAPI edge: NHT for peers + best-path export (optional —
        // standalone mode runs without a zebra).
        let reach: Arc<dyn PeerReachability> = match config.zapi_socket.clone() {
            Some(socket) => {
                let peers = config.neighbors.keys().copied().collect();
                match zedge::spawn(socket, peers).await {
                    Ok((nht, tx)) => {
                        // Export drainer: RibSink changes → ZAPI
                        // (route-server bests never install — the RS
                        // RIB stays out of the kernel).
                        let drain_sink = sink.clone();
                        tokio::spawn(async move {
                            loop {
                                let changes = {
                                    let mut sink = drain_sink.0.lock().unwrap();
                                    sink.take_changes()
                                };
                                for change in changes {
                                    for command in rib::zebra_commands(&change) {
                                        let _ = tx.send(command);
                                    }
                                }
                                tokio::time::sleep(Duration::from_millis(250)).await;
                            }
                        });
                        Arc::new(NhtReachability(nht))
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
        // Daemon stop also stands down the RTR client (the tables
        // handle outlives it safely either way).
        {
            let mut stop = channels.stop.clone();
            let shutdown_tx = shutdown_tx;
            tokio::spawn(async move {
                while stop.changed().await.is_ok() {
                    if *stop.borrow() {
                        let _ = shutdown_tx.send(true);
                        return;
                    }
                }
            });
        }
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

/// `--validate-config` (the S8-a rider; configd's pre-apply gate's
/// daemon half): parse the candidate file with the daemon's own
/// parser and run every synchronous startup refusal — the named
/// policy compile (a bad route-map is a config error, not a warning)
/// and the RPKI static legs (the cache address syntax, the vrp-file
/// content). Exit 0 with a one-line OK on stderr, or exit 1 with the
/// line-numbered error verbatim (configd surfaces it as the apply's
/// refusal reason). What it deliberately does NOT do: dial the RTR
/// cache, open the ZAPI socket, or bind :179 — those are runtime
/// concerns, not config validity.
fn validate_config(path: &Path) -> i32 {
    let text = match std::fs::read_to_string(path) {
        Ok(text) => text,
        Err(e) => {
            eprintln!("bgpd: cannot read {}: {e}", path.display());
            return 1;
        }
    };
    let config = match bgpd::config::parse_config(&text) {
        Ok(config) => config,
        Err(e) => {
            eprintln!("bgpd: {}: {e}", path.display());
            return 1;
        }
    };
    if let Err(e) = bgpd::policy_engine::compile_named_policy(&config) {
        eprintln!("bgpd: {}: {e}", path.display());
        return 1;
    }
    if let Some((host, _port)) = &config.rpki.cache {
        if host.parse::<std::net::IpAddr>().is_err() {
            eprintln!(
                "bgpd: {}: rpki cache `{host}` is not an address",
                path.display()
            );
            return 1;
        }
    }
    if let Some(vrp) = &config.rpki.vrp_file {
        let text = match std::fs::read_to_string(vrp) {
            Ok(text) => text,
            Err(e) => {
                eprintln!(
                    "bgpd: {}: cannot read vrp-file {}: {e}",
                    path.display(),
                    vrp.display()
                );
                return 1;
            }
        };
        if let Err(e) = bgpd::rov::parse_vrp_file(&text) {
            eprintln!("bgpd: {}: vrp-file {}: {e}", path.display(), vrp.display());
            return 1;
        }
    }
    eprintln!(
        "bgpd: {}: OK (local AS {}, {} neighbors, {} networks)",
        path.display(),
        config.local_as,
        config.neighbors.len(),
        config.networks.len()
    );
    0
}
