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
//!
//! `--validate-config <PATH>` (S8-c): parse a candidate config file and
//! exit 0 (one-line OK on stderr) or 1 (the parser's line-numbered error
//! verbatim) — the daemon half of configd's pre-apply semantic-validation
//! gate (docs/protocols/config.md §Deferred-1, landed).

use std::path::PathBuf;
use std::time::Duration;

use common::DataplaneEvent;
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

/// The status file's own refresh cadence (PERF-P3 M2a), decoupled from
/// the reconcile tick above. The E1 receipt's wall decomposition named
/// the 10 s publish grid as the dominant share of the externally
/// observed table-completion time: every install was ACK-verified at
/// +9.3 s while the observer learned of it at the next grid point
/// (~+17.5 s) — and an operator polling `rousterctl` mid-convergence
/// saw the same 10 s-stale file (P0-b's escalated "faster refresh"
/// option, landed). FRR's native surface (vtysh) answers live, so the
/// comparison's observation lag now matches: ours ≤1 s refresh + the
/// poller's own 1 s, FRR's ≤1 s poll. The publish itself is
/// O(interfaces + neighbours + tables) — the per-table route counts
/// went incremental with it (`rib::Table::counts`).
const STATUS_REFRESH_INTERVAL: Duration = Duration::from_secs(1);

/// Capacity of the ZAPI-session → RIB command queue. Bounded so a daemon
/// burst applies backpressure to its session task instead of unbounded
/// queue growth.
const ZAPI_COMMAND_QUEUE: usize = 256;

enum Args {
    Run {
        config: PathBuf,
        once: bool,
    },
    /// `--validate-config <PATH>` (S8-c): parse a candidate config
    /// file and exit 0/1 — the configd pre-apply gate's daemon half.
    Validate {
        path: PathBuf,
    },
}

fn parse_args() -> Result<Args, String> {
    let mut config = None;
    let mut once = false;
    let mut validate = None;
    let mut it = std::env::args().skip(1);
    while let Some(arg) = it.next() {
        match arg.as_str() {
            "--config" | "-f" => {
                config = Some(PathBuf::from(it.next().ok_or("--config requires a path")?));
            }
            "--once" => once = true,
            "--validate-config" => {
                validate = Some(PathBuf::from(
                    it.next().ok_or("--validate-config requires a path")?,
                ));
            }
            "--help" | "-h" => {
                println!("usage: rousterd --config <PATH> [--once]");
                println!("       rousterd --validate-config <PATH>");
                std::process::exit(0);
            }
            other => return Err(format!("unknown argument `{other}`")),
        }
    }
    if let Some(path) = validate {
        return Ok(Args::Validate { path });
    }
    Ok(Args::Run {
        config: config.ok_or("missing --config <PATH>")?,
        once,
    })
}

/// The `--validate-config` arm: parse the candidate file with the
/// daemon's own parser and report. Exit 0 with a one-line OK on
/// stderr, or exit 1 with the parser's line-numbered error verbatim
/// (configd surfaces it as the apply's refusal reason). Runs before
/// any dataplane construction, so it works on any host.
fn validate_config(path: &std::path::Path) -> i32 {
    match std::fs::read_to_string(path) {
        Ok(text) => match rousterd::config::parse_config(&text) {
            Ok(config) => {
                eprintln!(
                    "rousterd: {}: OK ({} static routes, zapi socket {})",
                    path.display(),
                    config.static_routes.len(),
                    if config.zapi_socket.is_some() {
                        "on"
                    } else {
                        "off"
                    }
                );
                0
            }
            Err(err) => {
                eprintln!("rousterd: {}: {err}", path.display());
                1
            }
        },
        Err(err) => {
            eprintln!("rousterd: cannot read {}: {err}", path.display());
            1
        }
    }
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

/// Interface name for the neighbour log lines: the mirrored name when
/// known, else the bare ifindex (kernel notification order is not
/// guaranteed to put RTM_NEWLINK before RTM_NEWNEIGH).
fn ifname_of(driver: &RibDriver, ifindex: u32) -> String {
    driver
        .rib
        .interfaces()
        .get(&ifindex)
        .map(|iface| iface.name.clone())
        .unwrap_or_else(|| format!("ifindex {ifindex}"))
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

    // The validate arm is config-only: it must never need netlink, so
    // it exits before the dataplane construction below (host-runnable
    // anywhere — the configd pre-apply gate depends on that).
    if let Args::Validate { path } = &args {
        std::process::exit(validate_config(path));
    }
    let Args::Run {
        config: args_config,
        once: args_once,
    } = &args
    else {
        unreachable!("the validate arm exited above");
    };

    // Dataplane (Linux only; stub errors out on other platforms).
    let (dp, conn) = NetlinkDataplane::new()?;
    tokio::spawn(conn);

    // Static routes → RIB → kernel. Legacy path (see module docs): the
    // canonical static-route source is the staticd binary speaking ZAPI.
    let text = std::fs::read_to_string(args_config)?;
    let config = rousterd::config::parse_config(&text).map_err(|e| {
        error!(%e, "config parse failed");
        std::io::Error::new(std::io::ErrorKind::InvalidData, e)
    })?;
    let routes = &config.static_routes;
    info!(count = routes.len(), path = %args_config.display(), "loaded static routes");

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
    info!(
        neighbours = driver.rib.neighbours().len(),
        "initial neighbour mirror"
    );
    // The CONNECT protocol table derived from the mirrored addresses
    // (main table only counted here — an enslaved member's connected
    // routes live in its VRF's table, W4 placement).
    info!(
        connected = driver.rib.connected_keys().count(),
        "initial connected routes"
    );
    // VRF devices seen in the link dump (W4): each logs its bound table,
    // how many kernel-origin routes the mirror holds in that table, and
    // how many mirrored links it enslaves. Live VRF changes ride the
    // generic dataplane-event line (the LinkNew Display carries the vrf
    // table and master ifindex).
    for (&ifindex, iface) in driver.rib.interfaces() {
        let Some(table) = iface.vrf_table else {
            continue;
        };
        let enslaved = driver
            .rib
            .interfaces()
            .values()
            .filter(|member| member.master_ifindex == Some(ifindex))
            .count();
        let routes = driver
            .rib
            .kernel_table(table)
            .map(|t| t.iter().count())
            .unwrap_or(0);
        info!(vrf = %iface.name, ifindex, table, enslaved, routes, "vrf mirror");
    }
    // Mirrored connected prefixes may resolve gateway nexthops that the
    // first pass above had to skip (unresolved gateways are not
    // programmed); re-run the diff before serving or exiting.
    driver.rib.reconcile(&dp).await;

    let kernel_routes = dp
        .dump_route_count()
        .await
        .map_err(|e| std::io::Error::other(e.to_string()))?;
    info!(kernel_routes, "kernel route mirror check");

    if *args_once {
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
    // F8 hygiene: default Burst behavior fires every tick missed
    // during a long await immediately back-to-back — under a mass
    // import that stacks extra full-table reconciles behind each
    // batch. Delay collapses missed ticks into one, a full interval
    // apart.
    reconcile_tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    // PERF-P3 M2a: the status file refreshes on its own 1 s cadence
    // (same Delay hygiene — a publish skipped behind a long install
    // batch collapses into the next tick, never bursts).
    let mut status_tick = tokio::time::interval(STATUS_REFRESH_INTERVAL);
    status_tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

    loop {
        tokio::select! {
            ev = dp.next_event() => {
                match ev {
                    Some(ev) => {
                        // Through the driver: link/address events re-evaluate
                        // registered ZAPI nexthops and push NEXTHOP_UPDATE
                        // on resolution flips (Z3B).
                        driver.apply_event(&ev);
                        // Neighbours get dedicated up/down lines (ip +
                        // ifname, resolved from the interface mirror);
                        // everything else keeps the generic event line.
                        match &ev {
                            DataplaneEvent::NeighbourNew { entry } => {
                                let ifname = ifname_of(&driver, entry.link_ifindex);
                                if entry.is_up() {
                                    info!(neighbour = %entry, ifname = %ifname, "neighbour up");
                                } else {
                                    info!(
                                        neighbour = %entry,
                                        ifname = %ifname,
                                        "neighbour state change"
                                    );
                                }
                            }
                            DataplaneEvent::NeighbourDel { ip, link_ifindex } => {
                                let ifname = ifname_of(&driver, *link_ifindex);
                                info!(neighbour = %ip, ifname = %ifname, "neighbour down");
                            }
                            other => info!(
                                %other,
                                interfaces = driver.rib.interfaces().len(),
                                "dataplane event"
                            ),
                        }
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
                match reload_config(args_config) {
                    Ok(new_config) => {
                        if new_config.zapi_socket != config.zapi_socket {
                            warn!("zapi socket change requires a restart; keeping running socket");
                        }
                        // Through the driver (M2): reload-caused best
                        // changes fan redistribute pushes to registered
                        // ZAPI sessions, same as route commands.
                        driver.reload_static(&new_config.static_routes);
                        info!(count = new_config.static_routes.len(), "config reloaded");
                    }
                    Err(e) => error!(%e, "config reload failed; keeping running config"),
                }
                driver.rib.reconcile(&dp).await;
            }
            _ = reconcile_tick.tick() => {
                driver.rib.reconcile(&dp).await;
                // NHT re-evaluation rides the tick: route events (a
                // protocol daemon installing the covering route after a
                // client registered) must flip tracked nexthops, as
                // zebra does — the mixed-IGP cell measured a
                // registration stuck unresolved otherwise (bgpd's
                // register raced the OSPF route's arrival; only
                // link/address events re-armed before).
                driver.tick_nht();
            }
            _ = status_tick.tick() => {
                rousterd::status::publish(&driver.rib);
                // E7 queue observability: the install window's
                // occupancy alongside the status snapshot. Best-effort
                // (a failed write logs nothing extra — the status file
                // remains the primary surface).
                let (cur, peak) = netlink_dp::nl_queue_stats();
                let _ = std::fs::write(
                    "/run/rouster/rousterd.queues",
                    format!("netlink_inflight {cur}\nnetlink_inflight_peak {peak}\n"),
                );
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
