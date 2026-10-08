//! rousterd — the Rouster main daemon.
//!
//! Single-binary default (docs/architecture.md): protocol tasks, the RIB, the
//! dataplane backend, and the edge adapters (ZAPI server, vtysh shim, northbound)
//! all run as Tokio tasks in one process. Optional per-protocol binaries come
//! later for operators who want FRR-style process isolation.
//!
//! Phase 0 scope: load static routes from a config file and program them into
//! the kernel via the dataplane trait. `--once` installs and exits (used by
//! the netns/container smoke tests).

mod config;

use std::path::PathBuf;

use netlink_dp::NetlinkDataplane;
use rib::Rib;
use tracing::{error, info};

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
    rib.sync_dataplane(&dp)
        .await
        .map_err(|e| std::io::Error::other(e.to_string()))?;

    let kernel_routes = dp
        .dump_route_count()
        .await
        .map_err(|e| std::io::Error::other(e.to_string()))?;
    info!(kernel_routes, "kernel route mirror check");

    if args.once {
        info!("--once: routes installed, exiting");
        return Ok(());
    }

    // Resident mode: initial mirror of kernel interface state, then track
    // link/address changes as they arrive.
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

    // TODO(phase-1): spawn zapi::server::serve().
    loop {
        tokio::select! {
            ev = dp.next_event() => {
                match ev {
                    Some(ev) => {
                        rib.apply_event(&ev);
                        info!(%ev, interfaces = rib.interfaces().len(), "dataplane event");
                    }
                    // Netlink connection closed; nothing left to do.
                    None => break,
                }
            }
            _ = tokio::signal::ctrl_c() => break,
        }
    }
    info!("shutdown");
    Ok(())
}
