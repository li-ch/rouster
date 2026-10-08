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
//!
//! Phase 1 (partial): with a `zapi socket <PATH>` config line the ZAPI edge
//! server accepts FRR daemon connections; their ROUTE_ADD/DELETE and NHT
//! requests arrive as [`zapi::RibCommand`]s on a queue this main loop drains
//! into the RIB, reconciling after each batch. Default off.

mod config;

use std::collections::{BTreeSet, HashMap};
use std::path::{Path, PathBuf};
use std::time::Duration;

use common::IpPrefix;
use netlink_dp::NetlinkDataplane;
use rib::Rib;
use tokio::signal::unix::{signal, SignalKind};
use tokio::sync::mpsc;
use tracing::{debug, error, info, warn};
use zapi::{InterfaceMirror, RibCommand};

/// Safety net for missed dataplane events: reconcile is diff-based, so an
/// extra pass with no drift programs nothing.
const RECONCILE_INTERVAL: Duration = Duration::from_secs(10);

/// Capacity of the ZAPI-session → RIB command queue. Bounded so a daemon
/// burst applies backpressure to its session task instead of unbounded
/// queue growth.
const ZAPI_COMMAND_QUEUE: usize = 256;

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
fn reload_config(path: &Path) -> Result<config::Config, String> {
    let text = std::fs::read_to_string(path).map_err(|e| e.to_string())?;
    config::parse_config(&text).map_err(|e| e.to_string())
}

/// Spawns the ZAPI edge server task (the exact code path `main` uses when
/// the config carries a `zapi socket` line). Split out so the wiring is
/// unit-testable.
fn spawn_zapi_server(
    socket: PathBuf,
    commands: mpsc::Sender<RibCommand>,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        if let Err(err) = zapi::serve(&socket, commands).await {
            error!(%err, "zapi: server exited");
        }
    })
}

/// Applies one ZAPI session command to the RIB and the driver-side
/// registries. Returns whether the protocol tables changed (the caller
/// reconciles on change).
fn apply_rib_command(
    rib: &mut Rib,
    nht_registrations: &mut HashMap<u64, BTreeSet<IpPrefix>>,
    redistributes: &mut HashMap<u64, BTreeSet<(u8, u8, u16)>>,
    command: RibCommand,
) -> bool {
    match command {
        RibCommand::AddRoute(entry) => {
            info!(prefix = %entry.prefix, protocol = ?entry.protocol, "zapi: route add");
            rib.add_route(entry);
            true
        }
        RibCommand::DeleteRoute {
            table,
            prefix,
            protocol,
        } => {
            let removed = rib.table_mut(table).remove(&prefix, protocol);
            if removed {
                info!(prefix = %prefix, ?protocol, "zapi: route delete");
            } else {
                debug!(prefix = %prefix, ?protocol, "zapi: route delete for absent route");
            }
            removed
        }
        // Answer immediately from the RIB's current resolution; the
        // registration itself is Z3B's input (event-driven re-evaluation).
        RibCommand::RegisterNexthop {
            owner,
            prefix,
            reply,
        } => {
            nht_registrations.entry(owner).or_default().insert(prefix);
            let resolution = rib.lookup_nexthop(prefix_addr(&prefix));
            let _ = reply.send(resolution);
            false
        }
        RibCommand::UnregisterNexthop { owner, prefix } => {
            if let Some(set) = nht_registrations.get_mut(&owner) {
                set.remove(&prefix);
                if set.is_empty() {
                    nht_registrations.remove(&owner);
                }
            }
            false
        }
        // Tonight: store only (REDISTRIBUTE_ROUTE_ADD push is Z3B).
        RibCommand::RegisterRedistribute {
            owner,
            afi,
            route_type,
            instance,
        } => {
            redistributes
                .entry(owner)
                .or_default()
                .insert((afi, route_type, instance));
            debug!(owner, afi, route_type, instance, "zapi: redistribute add");
            false
        }
        RibCommand::UnregisterRedistribute {
            owner,
            afi,
            route_type,
            instance,
        } => {
            if let Some(set) = redistributes.get_mut(&owner) {
                set.remove(&(afi, route_type, instance));
                if set.is_empty() {
                    redistributes.remove(&owner);
                }
            }
            false
        }
        RibCommand::RequestInterfaces { reply } => {
            let mirror: Vec<InterfaceMirror> = rib
                .interfaces()
                .iter()
                .map(|(&ifindex, iface)| InterfaceMirror {
                    ifindex,
                    name: iface.name.clone(),
                    is_up: iface.is_up,
                    addresses: iface.addresses.clone(),
                })
                .collect();
            let _ = reply.send(mirror);
            false
        }
    }
}

fn prefix_addr(prefix: &IpPrefix) -> std::net::IpAddr {
    match prefix {
        IpPrefix::V4(p) => std::net::IpAddr::V4(p.addr()),
        IpPrefix::V6(p) => std::net::IpAddr::V6(p.addr()),
    }
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
    let config = config::parse_config(&text).map_err(|e| {
        error!(%e, "config parse failed");
        std::io::Error::new(std::io::ErrorKind::InvalidData, e)
    })?;
    let routes = &config.static_routes;
    info!(count = routes.len(), path = %args.config.display(), "loaded static routes");

    let mut rib = Rib::new();
    for route in routes {
        rib.add_route(route.clone());
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

    // ZAPI edge server: default OFF (no `zapi socket` line → no server, so
    // the `--once` CI behavior is unchanged). Main keeps its sender clone
    // alive so the receive arm below never sees a closed channel.
    let (zapi_tx, mut zapi_rx) = mpsc::channel::<RibCommand>(ZAPI_COMMAND_QUEUE);
    if let Some(socket) = config.zapi_socket.clone() {
        if let Some(parent) = socket.parent() {
            std::fs::create_dir_all(parent)?;
        }
        info!(path = %socket.display(), "zapi: starting server");
        spawn_zapi_server(socket, zapi_tx.clone());
    }
    // Driver-side registries fed by RibCommands (Z3B consumes them).
    let mut nht_registrations: HashMap<u64, BTreeSet<IpPrefix>> = HashMap::new();
    let mut redistributes: HashMap<u64, BTreeSet<(u8, u8, u16)>> = HashMap::new();

    let mut hangup = signal(SignalKind::hangup())?;
    let mut reconcile_tick = tokio::time::interval(RECONCILE_INTERVAL);

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
                    Ok(new_config) => {
                        if new_config.zapi_socket != config.zapi_socket {
                            warn!("zapi socket change requires a restart; keeping running socket");
                        }
                        rib.reload_static(&new_config.static_routes);
                        info!(count = new_config.static_routes.len(), "config reloaded");
                    }
                    Err(e) => error!(%e, "config reload failed; keeping running config"),
                }
                rib.reconcile(&dp).await;
            }
            _ = reconcile_tick.tick() => {
                rib.reconcile(&dp).await;
            }
            Some(command) = zapi_rx.recv() => {
                let mut changed = apply_rib_command(
                    &mut rib,
                    &mut nht_registrations,
                    &mut redistributes,
                    command,
                );
                // Drain whatever else arrived with it (a daemon often
                // bursts), then reconcile once for the whole batch.
                while let Ok(command) = zapi_rx.try_recv() {
                    changed |= apply_rib_command(
                        &mut rib,
                        &mut nht_registrations,
                        &mut redistributes,
                        command,
                    );
                }
                if changed {
                    rib.reconcile(&dp).await;
                }
            }
            _ = tokio::signal::ctrl_c() => break,
        }
    }
    info!("shutdown");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::UnixStream;
    use zapi::{ZapiCommand, ZapiHello, ZapiMessage, ZAPI_HEADER_LEN};

    /// WIRED: a config carrying a `zapi socket` line, run through the same
    /// spawn path `main` uses, accepts a client and answers its HELLO.
    #[tokio::test]
    async fn zapi_socket_config_spawns_accepting_server() {
        let socket = std::env::temp_dir().join(format!(
            "rousterd-wired-{}-{}.sock",
            std::process::id(),
            line!()
        ));
        let _ = std::fs::remove_file(&socket);
        let text = format!(
            "ip route 203.0.113.0/24 blackhole\nzapi socket {}\n",
            socket.display()
        );
        let config = config::parse_config(&text).expect("config parses");
        assert_eq!(config.zapi_socket, Some(socket.clone()));

        let (tx, mut rx) = mpsc::channel::<RibCommand>(16);
        let server = match config.zapi_socket.clone() {
            Some(socket) => spawn_zapi_server(socket, tx),
            None => panic!("expected a socket path"),
        };

        // The listener accepts and the session speaks ZAPI. serve() binds
        // when its task first polls; connect yields to let that happen, so
        // a retry loop (no timers) is enough.
        let mut client = loop {
            match UnixStream::connect(&socket).await {
                Ok(client) => break client,
                Err(_) => tokio::task::yield_now().await,
            }
        };
        client
            .write_all(
                &ZapiMessage::Hello(ZapiHello {
                    redist_default: 10,
                    instance: 0,
                    session_id: 0,
                    synchronous: 0,
                })
                .encode_frame(0)
                .unwrap(),
            )
            .await
            .unwrap();
        let mut header_buf = [0u8; ZAPI_HEADER_LEN];
        client.read_exact(&mut header_buf).await.unwrap();
        let header = zapi::ZapiHeader::decode(&header_buf).unwrap();
        assert_eq!(
            ZapiCommand::from_u16(header.command),
            ZapiCommand::Hello,
            "HELLO echoed back through the spawned server"
        );

        server.abort();
        let _ = std::fs::remove_file(&socket);
        rx.close();
    }
}
