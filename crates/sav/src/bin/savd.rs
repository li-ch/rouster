//! savd — the Rouster SAV daemon (W8).
//!
//! Holds the SAV Information Base, keeps a RIB view over the ZAPI client
//! edge (redistribution pushes — see `sav::savd`'s docs for the coupling
//! choice), and programs enforcement through the Dataplane trait
//! **monitor-only by default**. SIGHUP re-parses the config (the drop
//! friction line is re-checked — a rejected reload keeps the running
//! config) and regenerates; the poll cadence re-evaluates whatever the
//! RIB pushes changed; SIGTERM/SIGINT clear everything installed and
//! exit, leaving the kernel clean.
//!
//! Usage: `savd --config <PATH> --zapi-socket <PATH>`
//!
//! The daemon logic lives in `sav::savd` (this binary is the thin shell,
//! the staticd shape).

use std::io;
use std::path::{Path, PathBuf};
use std::time::Duration;

use netlink_dp::NetlinkDataplane;
use sav::savd::{parse_savd_config, SavDaemon};
use tokio::signal::unix::{signal, SignalKind};
use tokio::time::sleep;
use tracing::{error, info, warn};

/// Pause between reconnect attempts when rousterd is not up (yet).
const RECONNECT_PAUSE: Duration = Duration::from_secs(1);

struct Args {
    config: PathBuf,
    zapi_socket: PathBuf,
}

fn parse_args() -> Result<Args, String> {
    let mut config = None;
    let mut zapi_socket = None;
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
            "--help" | "-h" => {
                println!("usage: savd --config <PATH> --zapi-socket <PATH>");
                std::process::exit(0);
            }
            other => return Err(format!("unknown argument `{other}`")),
        }
    }
    Ok(Args {
        config: config.ok_or("missing --config <PATH>")?,
        zapi_socket: zapi_socket.ok_or("missing --zapi-socket <PATH>")?,
    })
}

/// Reads, parses, and validates the config. The drop-mode friction gate
/// makes this fallible by design: `action drop` without
/// `i-understand-drop-mode yes` is a refusal, both at startup and on
/// reload.
fn load_config(path: &Path) -> Result<sav::savd::SavdConfig, String> {
    let text = std::fs::read_to_string(path).map_err(|e| e.to_string())?;
    parse_savd_config(&text).map_err(|e| e.to_string())
}

/// Connects to the ZAPI socket, tolerating a rousterd that is still
/// starting (staticd's yield-then-sleep retry).
async fn connect(socket: &Path) -> io::Result<SavDaemon<tokio::net::UnixStream>> {
    let mut last = None;
    for attempt in 0..100u32 {
        match zapi::ZapiClient::connect(socket).await {
            Ok(client) => return Ok(SavDaemon::new(client)),
            Err(err) if attempt < 5 => {
                last = Some(err);
                tokio::task::yield_now().await;
            }
            Err(err) => {
                warn!(%err, "savd: rousterd not reachable yet");
                last = Some(err);
                sleep(RECONNECT_PAUSE).await;
            }
        }
    }
    error!("savd: giving up connecting to rousterd");
    Err(last.expect("100 attempts always set the error"))
}

#[tokio::main]
async fn main() -> io::Result<()> {
    // Plain log files (the smoke greps them; no ANSI, stderr).
    let _ = tracing_subscriber::fmt()
        .with_ansi(false)
        .with_writer(std::io::stderr)
        .try_init();
    info!(version = env!("CARGO_PKG_VERSION"), "savd starting");

    let args = parse_args().map_err(|e| {
        error!("{e}");
        io::Error::new(io::ErrorKind::InvalidInput, e)
    })?;

    let mut config = load_config(&args.config).map_err(|e| {
        error!("savd: {e}");
        io::Error::new(io::ErrorKind::PermissionDenied, e)
    })?;
    info!(%config, "savd: config loaded");

    // Dataplane: enforcement installs/clears AND the live interface
    // mirror (names for the config's interface lines).
    let (mut dp, conn) = NetlinkDataplane::new()?;
    tokio::spawn(conn);

    let mut hangup = signal(SignalKind::hangup())?;
    let mut terminate = signal(SignalKind::terminate())?;

    'session: loop {
        let mut daemon = connect(&args.zapi_socket).await?;
        daemon.set_config(config.clone());

        // Seed the interface mirror from the kernel dump BEFORE the
        // first evaluation (configured names resolve against it).
        for ev in dp
            .dump_state()
            .await
            .map_err(|e| io::Error::other(e.to_string()))?
        {
            daemon.apply_event(&ev);
        }

        if let Err(err) = daemon.initial_sync().await {
            error!(%err, "savd: initial sync failed; retrying");
            sleep(RECONNECT_PAUSE).await;
            continue 'session;
        }
        // WIRED: first evaluation installs (monitor by default) and
        // logs the rule set.
        if let Err(err) = daemon.evaluate(&dp).await {
            error!(%err, "savd: first evaluation failed; retrying");
            sleep(RECONNECT_PAUSE).await;
            continue 'session;
        }

        let mut poll = tokio::time::interval_at(
            tokio::time::Instant::now() + config.poll_interval(),
            config.poll_interval(),
        );

        loop {
            tokio::select! {
                _ = hangup.recv() => {
                    info!("savd: SIGHUP: reloading config");
                    match load_config(&args.config) {
                        Ok(new_config) => {
                            daemon.set_config(new_config.clone());
                            // Refresh the interface mirror too: a new
                            // config may name interfaces that appeared
                            // since startup.
                            for ev in dp
                                .dump_state()
                                .await
                                .map_err(|e| io::Error::other(e.to_string()))?
                            {
                                daemon.apply_event(&ev);
                            }
                            if let Err(err) = daemon.evaluate(&dp).await {
                                warn!(%err, "savd: reload evaluation failed");
                            } else {
                                config = new_config;
                                let interval = config.poll_interval();
                                poll = tokio::time::interval_at(
                                    tokio::time::Instant::now() + interval,
                                    interval,
                                );
                            }
                        }
                        Err(e) => error!(%e, "savd: reload refused; keeping running config"),
                    }
                }
                _ = poll.tick() => {
                    if let Err(err) = daemon.evaluate(&dp).await {
                        warn!(%err, "savd: poll evaluation failed");
                    }
                }
                ev = dp.next_event() => {
                    match ev {
                        Some(ev) => daemon.apply_event(&ev),
                        None => {
                            warn!("savd: netlink connection closed");
                            break;
                        }
                    }
                }
                read = daemon.read_message() => {
                    if let Err(err) = read {
                        warn!(%err, "savd: session lost; reconnecting");
                        sleep(RECONNECT_PAUSE).await;
                        continue 'session;
                    }
                }
                _ = tokio::signal::ctrl_c() => {
                    info!("savd: SIGINT: clearing installed rules and exiting");
                    if let Err(err) = daemon.clear(&dp).await {
                        error!(%err, "savd: clear failed; state file allows a later restore");
                    }
                    return Ok(());
                }
                _ = terminate.recv() => {
                    info!("savd: SIGTERM: clearing installed rules and exiting");
                    if let Err(err) = daemon.clear(&dp).await {
                        error!(%err, "savd: clear failed; state file allows a later restore");
                    }
                    return Ok(());
                }
            }
        }
        // Netlink closed: drop the session and reconnect from scratch.
        sleep(RECONNECT_PAUSE).await;
    }
}
