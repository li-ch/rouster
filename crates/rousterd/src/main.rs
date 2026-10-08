//! rousterd — the Rouster main daemon.
//!
//! Single-binary default (docs/architecture.md): protocol tasks, the RIB, the
//! dataplane backend, and the edge adapters (ZAPI server, vtysh shim, northbound)
//! all run as Tokio tasks in one process. Optional per-protocol binaries come
//! later for operators who want FRR-style process isolation.
//!
//! Phase 0 scope: load static routes from a config file, program them into
//! the kernel via the dataplane trait, mirror the kernel FIB, and keep the
//! dataplane reconciled (externally deleted routes are reinstalled; SIGHUP
//! reloads the config and withdraws vanished routes). `--once` installs and
//! exits (used by the netns/container smoke tests).

mod config;

use std::path::{Path, PathBuf};
use std::time::Duration;

use common::RouteEntry;
use netlink_dp::NetlinkDataplane;
use rib::Rib;
use tokio::signal::unix::{signal, SignalKind};
use tracing::{error, info};

/// Safety net for missed dataplane events: reconcile is diff-based, so an
/// extra pass with no drift programs nothing.
const RECONCILE_INTERVAL: Duration = Duration::from_secs(10);

struct Args {
    config: PathBuf,
    once: bool,
}

fn parse_args() -> Result<Args, String> {
    let mut config = None;
    let mut once = false;
    let mut it = std::env::args().skip(1);
    while let Some(arg) = it.next() {
        match arg.as_str() {
            "--config" | "-f" => {
                config = Some(PathBuf::from(it.next().ok_or("--config requires a path")?));
            }
            "--once" => once = true,
            "--help" | "-h" => {
                println!("usage: rousterd --config <PATH> [--once]");
                std::process::exit(0);
            }
            other => return Err(format!("unknown argument `{other}`")),
        }
    }
    Ok(Args {
        config: config.ok_or("missing --config <PATH>")?,
        once,
    })
}

/// Re-reads and re-parses the config file. Errors keep the running config
/// (soft reconfiguration semantics).
fn reload_config(path: &Path) -> Result<Vec<RouteEntry>, String> {
    let text = std::fs::read_to_string(path).map_err(|e| e.to_string())?;
    config::parse_static_routes(&text).map_err(|e| e.to_string())
}

#[tokio::main]
async fn main() -> std::io::Result<()> {
    tracing_subscriber::fmt::init();
    info!(version = env!("CARGO_PKG_VERSION"), "rousterd starting");

    let args = parse_args().map_err(|e| {
        error!("{e}");
        std::io::Error::new(std::io::ErrorKind::InvalidInput, e)
    })?;

    // Dataplane (Linux only; stub errors out on other platforms).
    let (dp, conn) = NetlinkDataplane::new()?;
    tokio::spawn(conn);

    // Static routes → RIB → kernel.
    let text = std::fs::read_to_string(&args.config)?;
    let routes = config::parse_static_routes(&text).map_err(|e| {
        error!(%e, "config parse failed");
        std::io::Error::new(std::io::ErrorKind::InvalidData, e.to_string())
    })?;
    info!(count = routes.len(), path = %args.config.display(), "loaded static routes");

    let mut rib = Rib::new();
    for route in routes {
        rib.add_route(route);
    }
    rib.reconcile(&dp).await;

    // Initial mirror of kernel interface and route state; afterwards track
    // link/address/route changes as they arrive.
    let mut dp = dp;
    for ev in dp
        .dump_state()
        .await
        .map_err(|e| std::io::Error::other(e.to_string()))?
    {
        rib.apply_event(&ev);
    }
    info!(
        interfaces = rib.interfaces().len(),
        "initial interface state mirrored"
    );
    info!(
        kernel_routes = rib.kernel_route_count(),
        "initial kernel route mirror"
    );
    // Mirrored connected prefixes may resolve gateway nexthops that the
    // first pass above had to skip (unresolved gateways are not
    // programmed); re-run the diff before serving or exiting.
    rib.reconcile(&dp).await;

    let kernel_routes = dp
        .dump_route_count()
        .await
        .map_err(|e| std::io::Error::other(e.to_string()))?;
    info!(kernel_routes, "kernel route mirror check");

    if args.once {
        info!("--once: routes installed, exiting");
        return Ok(());
    }

    let mut hangup = signal(SignalKind::hangup())?;
    let mut reconcile_tick = tokio::time::interval(RECONCILE_INTERVAL);

    // TODO(phase-1): spawn zapi::server::serve().
    loop {
        tokio::select! {
            ev = dp.next_event() => {
                match ev {
                    Some(ev) => {
                        rib.apply_event(&ev);
                        info!(%ev, interfaces = rib.interfaces().len(), "dataplane event");
                        // Route events invalidate programmed-set belief
                        // (external deletions); reconcile reinstalls.
                        rib.reconcile(&dp).await;
                    }
                    // Netlink connection closed; nothing left to do.
                    None => break,
                }
            }
            _ = hangup.recv() => {
                info!("SIGHUP: reloading config");
                match reload_config(&args.config) {
                    Ok(routes) => {
                        rib.reload_static(&routes);
                        info!(count = routes.len(), "config reloaded");
                    }
                    Err(e) => error!(%e, "config reload failed; keeping running config"),
                }
                rib.reconcile(&dp).await;
            }
            _ = reconcile_tick.tick() => {
                rib.reconcile(&dp).await;
            }
            _ = tokio::signal::ctrl_c() => break,
        }
    }
    info!("shutdown");
    Ok(())
}
