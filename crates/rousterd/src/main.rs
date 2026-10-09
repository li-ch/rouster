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
//!
//! Static-route provenance (Z4): the canonical path is the separate
//! `staticd` binary (config → ZAPI client of this daemon — the FRR shape).
//! rousterd's direct config load is LEGACY: `--once` (CI smoke) and resident
//! mode without a `zapi socket` line keep it for now.

use std::path::PathBuf;
use std::time::Duration;

use netlink_dp::NetlinkDataplane;
use rousterd::config::Config;
use rousterd::driver::RibDriver;
use tokio::signal::unix::{signal, SignalKind};
use tokio::sync::mpsc;
use tracing::{error, info, warn};
use zapi::RibCommand;

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
fn reload_config(path: &std::path::Path) -> Result<Config, String> {
    let text = std::fs::read_to_string(path).map_err(|e| e.to_string())?;
    rousterd::config::parse_config(&text).map_err(|e| e.to_string())
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

#[tokio::main]
async fn main() -> std::io::Result<()> {
    // ANSI color only on a TTY: redirected log files stay plain bytes
    // (smoke greps, quarantine captures).
    rousterd::logging::init();
    info!(version = env!("CARGO_PKG_VERSION"), "rousterd starting");

    let args = parse_args().map_err(|e| {
        error!("{e}");
        std::io::Error::new(std::io::ErrorKind::InvalidInput, e)
    })?;

    // Dataplane (Linux only; stub errors out on other platforms).
    let (dp, conn) = NetlinkDataplane::new()?;
    tokio::spawn(conn);

    // Static routes → RIB → kernel. Legacy path (see module docs): the
    // canonical static-route source is the staticd binary speaking ZAPI.
    let text = std::fs::read_to_string(&args.config)?;
    let config = rousterd::config::parse_config(&text).map_err(|e| {
        error!(%e, "config parse failed");
        std::io::Error::new(std::io::ErrorKind::InvalidData, e)
    })?;
    let routes = &config.static_routes;
    info!(count = routes.len(), path = %args.config.display(), "loaded static routes");

    let mut driver = RibDriver::new();
    for route in routes {
        driver.rib.add_route(route.clone());
    }
    driver.rib.reconcile(&dp).await;

    // Initial mirror of kernel interface and route state; afterwards track
    // link/address/route changes as they arrive. Routed through the driver
    // so link/address events also re-evaluate registered ZAPI nexthops
    // (Z3B); no sessions exist yet at this point, so nothing is pushed.
    let mut dp = dp;
    for ev in dp
        .dump_state()
        .await
        .map_err(|e| std::io::Error::other(e.to_string()))?
    {
        driver.apply_event(&ev);
    }
    info!(
        interfaces = driver.rib.interfaces().len(),
        "initial interface state mirrored"
    );
    info!(
        kernel_routes = driver.rib.kernel_route_count(),
        "initial kernel route mirror"
    );
    // Mirrored connected prefixes may resolve gateway nexthops that the
    // first pass above had to skip (unresolved gateways are not
    // programmed); re-run the diff before serving or exiting.
    driver.rib.reconcile(&dp).await;

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

    let mut hangup = signal(SignalKind::hangup())?;
    let mut reconcile_tick = tokio::time::interval(RECONCILE_INTERVAL);

    loop {
        tokio::select! {
            ev = dp.next_event() => {
                match ev {
                    Some(ev) => {
                        // Through the driver: link/address events re-evaluate
                        // registered ZAPI nexthops and push NEXTHOP_UPDATE
                        // on resolution flips (Z3B).
                        driver.apply_event(&ev);
                        info!(%ev, interfaces = driver.rib.interfaces().len(), "dataplane event");
                        // Route events invalidate programmed-set belief
                        // (external deletions); reconcile reinstalls.
                        driver.rib.reconcile(&dp).await;
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
                        driver.rib.reload_static(&new_config.static_routes);
                        info!(count = new_config.static_routes.len(), "config reloaded");
                    }
                    Err(e) => error!(%e, "config reload failed; keeping running config"),
                }
                driver.rib.reconcile(&dp).await;
            }
            _ = reconcile_tick.tick() => {
                driver.rib.reconcile(&dp).await;
            }
            Some(command) = zapi_rx.recv() => {
                // Apply the batch that arrived with this command, then
                // reconcile once for the whole batch (inside drive()).
                let _ = driver.apply(command);
                let _ = driver.drain(&mut zapi_rx, &dp).await;
            }
            _ = tokio::signal::ctrl_c() => break,
        }
    }
    info!("shutdown");
    Ok(())
}

#[cfg(test)]
mod tests {
    use rousterd::config;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::UnixStream;
    use zapi::{ZapiCommand, ZapiHello, ZapiMessage, ZAPI_HEADER_LEN};

    use super::*;

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
        let parsed = config::parse_config(&text).expect("config parses");
        assert_eq!(parsed.zapi_socket, Some(socket.clone()));

        let (tx, mut rx) = mpsc::channel::<RibCommand>(16);
        let server = match parsed.zapi_socket.clone() {
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
