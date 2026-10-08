//! staticd — the Rouster static-route daemon (Z4).
//!
//! FRR shape: a separate small binary that parses the route config and
//! speaks ZAPI to rousterd's edge server. After the initial load it stays
//! resident: SIGHUP re-parses the config and diffs it onto the server
//! (ROUTE_DELETE vanished prefixes, ROUTE_ADD new ones, NHT follows the
//! gateways); zebra pushes are logged; a lost session is re-established by
//! replaying the whole config (the reconnect behavior captured in the
//! staticd fixture).
//!
//! This is the CANONICAL static-route path; rousterd's direct config load
//! is legacy (`--once` CI mode / resident mode without a `zapi socket`).
//!
//! Usage: `staticd --config <PATH> --zapi-socket <PATH> [--once]`

use std::io;
use std::path::{Path, PathBuf};
use std::time::Duration;

use rousterd::staticd::StaticDaemon;
use tokio::signal::unix::{signal, SignalKind};
use tokio::time::sleep;
use tracing::{error, info, warn};

/// Pause between reconnect attempts when rousterd is not up (yet).
const RECONNECT_PAUSE: Duration = Duration::from_secs(1);

struct Args {
    config: PathBuf,
    zapi_socket: PathBuf,
    once: bool,
}

fn parse_args() -> Result<Args, String> {
    let mut config = None;
    let mut zapi_socket = None;
    let mut once = false;
    let mut it = std::env::args().skip(1);
    while let Some(arg) = it.next() {
        match arg.as_str() {
            "--config" | "-f" => {
                config = Some(PathBuf::from(it.next().ok_or("--config requires a path")?));
            }
            "--zapi-socket" | "-z" => {
                zapi_socket = Some(PathBuf::from(
                    it.next().ok_or("--zapi-socket requires a path")?,
                ));
            }
            "--once" => once = true,
            "--help" | "-h" => {
                println!("usage: staticd --config <PATH> --zapi-socket <PATH> [--once]");
                std::process::exit(0);
            }
            other => return Err(format!("unknown argument `{other}`")),
        }
    }
    Ok(Args {
        config: config.ok_or("missing --config <PATH>")?,
        zapi_socket: zapi_socket.ok_or("missing --zapi-socket <PATH>")?,
        once,
    })
}

/// Reads and parses the config file (the shared rousterd parser — one
/// grammar, no fork). A `zapi socket` line inside a staticd config is
/// meaningless here and warned about once.
fn load_routes(path: &Path) -> Result<Vec<common::RouteEntry>, String> {
    let text = std::fs::read_to_string(path).map_err(|e| e.to_string())?;
    let config = rousterd::config::parse_config(&text).map_err(|e| e.to_string())?;
    if config.zapi_socket.is_some() {
        warn!(
            "staticd config carries a `zapi socket` line; ignoring (that is rousterd's directive)"
        );
    }
    Ok(config.static_routes)
}

/// Connects to the ZAPI socket, tolerating a rousterd that is still
/// starting: yield-retries first (an in-process server binds within them),
/// then sleeps between attempts.
async fn connect(socket: &Path) -> io::Result<StaticDaemon<tokio::net::UnixStream>> {
    let mut last = None;
    for attempt in 0..100u32 {
        match StaticDaemon::connect(socket).await {
            Ok(daemon) => return Ok(daemon),
            Err(err) if attempt < 5 => {
                last = Some(err);
                tokio::task::yield_now().await;
            }
            Err(err) => {
                warn!(%err, "staticd: rousterd not reachable yet");
                last = Some(err);
                sleep(RECONNECT_PAUSE).await;
            }
        }
    }
    error!("staticd: giving up connecting to rousterd");
    Err(last.expect("100 attempts always set the error"))
}

#[tokio::main]
async fn main() -> std::io::Result<()> {
    tracing_subscriber::fmt::init();
    info!(version = env!("CARGO_PKG_VERSION"), "staticd starting");

    let args = parse_args().map_err(|e| {
        error!("{e}");
        io::Error::new(io::ErrorKind::InvalidInput, e)
    })?;

    // Startup config errors are fatal (same as rousterd's startup parse).
    let mut routes = load_routes(&args.config).map_err(|e| {
        error!(%e, "staticd: config parse failed");
        io::Error::new(io::ErrorKind::InvalidData, e)
    })?;

    let mut hangup = signal(SignalKind::hangup())?;

    'session: loop {
        let mut daemon = connect(&args.zapi_socket).await?;
        if let Err(err) = daemon.initial_load(&routes).await {
            error!(%err, "staticd: initial load failed; retrying");
            sleep(RECONNECT_PAUSE).await;
            continue 'session;
        }

        if args.once {
            info!("staticd: --once: config installed, exiting");
            return Ok(());
        }

        // Resident: SIGHUP reloads, zebra pushes are logged, a lost
        // session tears down into a full reconnect (re-HELLO + replay —
        // what the captured FRR staticd does after a zebra restart).
        loop {
            tokio::select! {
                _ = hangup.recv() => {
                    info!("staticd: SIGHUP: reloading config");
                    match load_routes(&args.config) {
                        Ok(new_routes) => {
                            if let Err(err) = daemon.reload(&new_routes).await {
                                warn!(%err, "staticd: reload failed");
                            } else {
                                // Keep the converged set: a later reconnect
                                // replays the LATEST config, not the startup
                                // one (soft reconfiguration semantics).
                                routes = new_routes;
                            }
                        }
                        Err(e) => error!(%e, "staticd: reload parse failed; keeping running config"),
                    }
                }
                read = daemon.read_message() => {
                    if let Err(err) = read {
                        warn!(%err, "staticd: session lost; reconnecting");
                        sleep(RECONNECT_PAUSE).await;
                        continue 'session;
                    }
                }
                _ = tokio::signal::ctrl_c() => {
                    info!("staticd: shutdown");
                    return Ok(());
                }
            }
        }
    }
}
