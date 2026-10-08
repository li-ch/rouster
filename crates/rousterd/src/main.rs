//! rousterd — the Rouster main daemon.
//!
//! Single-binary default (docs/architecture.md): protocol tasks, the RIB, the
//! dataplane backend, and the edge adapters (ZAPI server, vtysh shim, northbound)
//! all run as Tokio tasks in one process. Optional per-protocol binaries come
//! later for operators who want FRR-style process isolation.

use tracing::info;

#[tokio::main]
async fn main() -> std::io::Result<()> {
    tracing_subscriber::fmt::init();
    info!(version = env!("CARGO_PKG_VERSION"), "rousterd starting");

    // TODO(phase-0):
    // 1. open netlink dataplane (netlink_dp::NetlinkDataplane::new),
    //    spawn connection driver;
    // 2. initial sync: dump kernel links/addresses/routes into rib::Rib;
    // 3. load static routes from config, rib.sync_dataplane();
    // 4. spawn zapi::server::serve() (Phase 1) and event-loop tasks.

    info!("rousterd skeleton up — nothing to do yet, exiting");
    Ok(())
}
