//! savd — the Rouster SAV daemon (W8).
//!
//! Holds the SAV Information Base, keeps a RIB view over the ZAPI client
//! edge (redistribution pushes — see `sav::savd`'s docs for the coupling
//! choice), and programs enforcement through the Dataplane trait
//! **monitor-only by default**. Re-evaluation is event-driven: every
//! redistribute push and interface event marks the view dirty and the
//! select loop converges immediately (the poll cadence stays as the
//! safety net); allowlist deletions ride the RFC 8704 §3.6.2
//! hysteresis window, flushed by a timer on the earliest deadline.
//! SIGHUP re-parses the config (the drop friction line is re-checked —
//! a rejected reload keeps the running config) and regenerates;
//! SIGTERM/SIGINT clear everything installed and exit, leaving the
//! kernel clean.
//!
//! Usage: `savd --config <PATH> --zapi-socket <PATH> [--pidfile <PATH>]
//! [--status-file <PATH>]`, or `savd --show` to print the daemon's
//! published status.
//!
//! Operator surface (A21), run-dir files only — no IPC, no wire
//! changes: a pidfile (`/run/rouster/savd.pid` by default) written at
//! start and removed on every clean exit (only SIGKILL leaves it
//! behind, and the pid it names is then dead), and a status file
//! (`/run/rouster/savd.status`) refreshed after every evaluate with the
//! installed rule set and monitor counts — `savd --show` prints it
//! instead of a log grep. On the SIGTERM/SIGINT clear the status file
//! goes too; after a SIGKILL it survives as the last-known-installed
//! record.
//!
//! The daemon logic lives in `sav::savd` (this binary is the thin shell,
//! the staticd shape).

use std::io;
use std::path::{Path, PathBuf};
use std::time::Duration;

use netlink_dp::sav_nft::SavBackend as DpBackend;
use netlink_dp::NetlinkDataplane;
use sav::savd::{parse_savd_config, SavDaemon, SavdBackend};
use tokio::signal::unix::{signal, SignalKind};
use tokio::time::sleep;
use tracing::{error, info, warn};

/// Pause between reconnect attempts when rousterd is not up (yet).
const RECONNECT_PAUSE: Duration = Duration::from_secs(1);

/// Default pidfile (A21): the run dir the workspace sanctions for
/// daemon state — the same dir as the netlink backend's sav-applied
/// file.
const DEFAULT_PIDFILE: &str = "/run/rouster/savd.pid";

/// Default status file (A21): what `savd --show` prints, refreshed by
/// the daemon after every evaluate.
const DEFAULT_STATUS_FILE: &str = "/run/rouster/savd.status";

/// What the operator asked savd to do: run the daemon, or print its
/// published status (`--show` needs no config or ZAPI socket — it only
/// reads the status file).
enum Command {
    Run {
        config: PathBuf,
        zapi_socket: PathBuf,
        pidfile: PathBuf,
        status_file: PathBuf,
    },
    Show {
        status_file: PathBuf,
    },
}

fn parse_args() -> Result<Command, String> {
    let mut config = None;
    let mut zapi_socket = None;
    let mut pidfile = None;
    let mut status_file = None;
    let mut show = false;
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
            "--pidfile" | "-p" => {
                pidfile = Some(PathBuf::from(it.next().ok_or("--pidfile requires a path")?));
            }
            "--status-file" => {
                status_file = Some(PathBuf::from(
                    it.next().ok_or("--status-file requires a path")?,
                ));
            }
            "--show" => show = true,
            "--help" | "-h" => {
                println!(
                    "usage: savd --config <PATH> --zapi-socket <PATH> \
                     [--pidfile <PATH>] [--status-file <PATH>]"
                );
                println!("       savd --show [--status-file <PATH>]");
                std::process::exit(0);
            }
            other => return Err(format!("unknown argument `{other}`")),
        }
    }
    let status_file = status_file.unwrap_or_else(|| PathBuf::from(DEFAULT_STATUS_FILE));
    if show {
        return Ok(Command::Show { status_file });
    }
    Ok(Command::Run {
        config: config.ok_or("missing --config <PATH>")?,
        zapi_socket: zapi_socket.ok_or("missing --zapi-socket <PATH>")?,
        pidfile: pidfile.unwrap_or_else(|| PathBuf::from(DEFAULT_PIDFILE)),
        status_file,
    })
}

/// The daemon's pidfile (A21): written at start, removed on exit. The
/// guard's Drop covers every return path from `run` — the SIGTERM and
/// SIGINT clean exits included — so only SIGKILL leaves the file
/// behind, and the pid it names is then dead (a stale-but-dead pid is
/// the conventional detectable state).
struct Pidfile {
    path: PathBuf,
}

impl Pidfile {
    /// Writes the live pid to `path`, creating the parent dir
    /// (`/run/rouster` may not exist yet; the netlink backend creates
    /// it for the sav-applied file the same way). A leftover from a
    /// SIGKILLed predecessor is simply overwritten.
    fn create(path: &Path) -> io::Result<Self> {
        if let Some(dir) = path.parent() {
            std::fs::create_dir_all(dir)?;
        }
        std::fs::write(path, format!("{}\n", std::process::id()))?;
        Ok(Self {
            path: path.to_path_buf(),
        })
    }
}

impl Drop for Pidfile {
    fn drop(&mut self) {
        if let Err(err) = std::fs::remove_file(&self.path) {
            warn!(%err, path = %self.path.display(), "savd: pidfile removal failed");
        }
    }
}

/// Publishes the daemon's status snapshot to the status file (A21):
/// operators — and `savd --show` — read the file instead of grepping
/// logs. Diagnostics only: a failed write warns and never fails the
/// evaluate that produced the state.
fn publish_status(path: &Path, pid: u32, daemon: &SavDaemon<tokio::net::UnixStream>) {
    if let Err(err) = std::fs::write(path, daemon.status_text(pid)) {
        warn!(%err, path = %path.display(), "savd: status file write failed");
    }
}

/// Removes the status file on the clean-exit paths (A21): after the
/// clear the file's content would be a lie. Best-effort, quiet on
/// NotFound (the daemon may exit before its first evaluate published
/// anything).
fn remove_status(path: &Path) {
    if let Err(err) = std::fs::remove_file(path) {
        if err.kind() != io::ErrorKind::NotFound {
            warn!(%err, path = %path.display(), "savd: status file removal failed");
        }
    }
}

/// `savd --show` (A21): the daemon's published status — the installed
/// rule set and monitor counts straight from the status file (no IPC;
/// the daemon refreshes it after every evaluate).
fn show(path: &Path) -> io::Result<String> {
    std::fs::read_to_string(path)
}

/// Evaluate + status refresh (A21): every convergence point in the
/// select loop lands here, so the status file always reflects the last
/// evaluated state.
async fn evaluate(
    daemon: &mut SavDaemon<tokio::net::UnixStream>,
    dp: &NetlinkDataplane,
    status_file: &Path,
    pid: u32,
) -> io::Result<()> {
    daemon.evaluate(dp).await?;
    publish_status(status_file, pid, daemon);
    Ok(())
}

/// Reads, parses, and validates the config. The drop-mode friction gate
/// makes this fallible by design: `action drop` without
/// `i-understand-drop-mode yes` is a refusal, both at startup and on
/// reload.
fn load_config(path: &Path) -> Result<sav::savd::SavdConfig, String> {
    let text = std::fs::read_to_string(path).map_err(|e| e.to_string())?;
    parse_savd_config(&text).map_err(|e| e.to_string())
}

/// The config's backend knob → the dataplane's backend enum (two
/// crates, two enums — the orphan-rule pattern; the mapping is total
/// and one-to-one).
fn dp_backend(backend: SavdBackend) -> DpBackend {
    match backend {
        SavdBackend::RpFilter => DpBackend::RpFilter,
        SavdBackend::Nft => DpBackend::Nft,
    }
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

    let command = parse_args().map_err(|e| {
        error!("{e}");
        io::Error::new(io::ErrorKind::InvalidInput, e)
    })?;
    match command {
        Command::Show { status_file } => match show(&status_file) {
            Ok(text) => {
                print!("{text}");
                Ok(())
            }
            Err(err) => {
                error!(
                    %err,
                    path = %status_file.display(),
                    "savd: no status to show (not running, or not yet evaluated)"
                );
                Err(err)
            }
        },
        Command::Run {
            config,
            zapi_socket,
            pidfile,
            status_file,
        } => run(&config, &zapi_socket, &pidfile, &status_file).await,
    }
}

/// The daemon body (A21: split out of main so `--show` short-circuits
/// before any daemon setup).
async fn run(
    config_path: &Path,
    zapi_socket: &Path,
    pidfile_path: &Path,
    status_file: &Path,
) -> io::Result<()> {
    let pid = std::process::id();

    let mut config = load_config(config_path).map_err(|e| {
        error!("savd: {e}");
        io::Error::new(io::ErrorKind::PermissionDenied, e)
    })?;
    info!(%config, "savd: config loaded");

    // PIDFILE (A21): written once the config accepted us; from here on
    // the guard removes it on every exit (SIGTERM/SIGINT included).
    let _pidfile = Pidfile::create(pidfile_path)?;
    info!(path = %pidfile_path.display(), "savd: pidfile written");

    // Dataplane: enforcement installs/clears AND the live interface
    // mirror (names for the config's interface lines). The config's
    // `backend` knob selects the SAV enforcement surface (default
    // rp_filter; `nft` routes the SAV trait ops to the nftables
    // ruleset backend, kernel monitor counters included).
    let (dp, conn) = NetlinkDataplane::new()?;
    let mut dp = dp.with_sav_backend(dp_backend(config.backend));
    tokio::spawn(conn);

    let mut hangup = signal(SignalKind::hangup())?;
    let mut terminate = signal(SignalKind::terminate())?;

    'session: loop {
        let mut daemon = connect(zapi_socket).await?;
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
        if let Err(err) = evaluate(&mut daemon, &dp, status_file, pid).await {
            error!(%err, "savd: first evaluation failed; retrying");
            sleep(RECONNECT_PAUSE).await;
            continue 'session;
        }

        let mut poll = tokio::time::interval_at(
            tokio::time::Instant::now() + config.poll_interval(),
            config.poll_interval(),
        );

        loop {
            // Deferred-deletion timer (RFC 8704 §3.6.2): re-created each
            // iteration from the current earliest deadline (the value is
            // copied out — select! futures must not hold a daemon
            // borrow next to read_message's). sleep_until is
            // cancel-safe and select! drops the losing futures, so a
            // fresh deferral simply moves the deadline on the next
            // iteration; the arm is inert while nothing is deferred.
            let flush_deadline = daemon.deletion_deadline();
            tokio::select! {
                _ = hangup.recv() => {
                    info!("savd: SIGHUP: reloading config");
                    match load_config(config_path) {
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
                            if let Err(err) =
                                evaluate(&mut daemon, &dp, status_file, pid).await
                            {
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
                    if let Err(err) = evaluate(&mut daemon, &dp, status_file, pid).await {
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
                _ = async move {
                    match flush_deadline {
                        Some(deadline) => tokio::time::sleep_until(deadline).await,
                        None => std::future::pending::<()>().await,
                    }
                } => {
                    // The hysteresis window elapsed: evaluate applies
                    // the expired deferred deletions.
                    if let Err(err) = evaluate(&mut daemon, &dp, status_file, pid).await {
                        warn!(%err, "savd: deferred-deletion flush evaluation failed");
                    }
                }
                _ = tokio::signal::ctrl_c() => {
                    info!("savd: SIGINT: clearing installed rules and exiting");
                    if let Err(err) = daemon.clear(&dp).await {
                        error!(%err, "savd: clear failed; state file allows a later restore");
                    }
                    remove_status(status_file);
                    return Ok(());
                }
                _ = terminate.recv() => {
                    info!("savd: SIGTERM: clearing installed rules and exiting");
                    if let Err(err) = daemon.clear(&dp).await {
                        error!(%err, "savd: clear failed; state file allows a later restore");
                    }
                    remove_status(status_file);
                    return Ok(());
                }
            }
            // Event-driven re-evaluation (W8 §Deferred 1): every mirror
            // change (redistribute push, interface/address event) marked
            // the view dirty — converge now instead of waiting for the
            // poll tick, which stays as the safety-net cadence.
            if daemon.take_dirty() {
                if let Err(err) = evaluate(&mut daemon, &dp, status_file, pid).await {
                    warn!(%err, "savd: event-driven evaluation failed");
                }
            }
        }
        // Netlink closed: drop the session and reconnect from scratch.
        sleep(RECONNECT_PAUSE).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The backend knob's two enums map one-to-one (the binary is the
    /// only translation point; total by construction).
    #[test]
    fn backend_knob_maps_one_to_one() {
        assert_eq!(dp_backend(SavdBackend::RpFilter), DpBackend::RpFilter);
        assert_eq!(dp_backend(SavdBackend::Nft), DpBackend::Nft);
    }

    /// A unique-per-run scratch dir (the nested path exercises
    /// Pidfile's parent-dir creation).
    fn scratch(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("savd-a21-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        dir
    }

    /// PIDFILE: written at start (the live pid, newline-terminated) and
    /// removed on clean exit — the guard's drop, which is `run`'s every
    /// return path, the SIGTERM/SIGINT arms included.
    #[test]
    fn pidfile_written_at_start_and_removed_on_clean_exit() {
        let dir = scratch("pid");
        let path = dir.join("savd.pid");
        let guard = Pidfile::create(&path).unwrap();
        assert_eq!(
            std::fs::read_to_string(&path).unwrap(),
            format!("{}\n", std::process::id()),
            "start writes the live pid (parent dir created)"
        );
        drop(guard); // the clean-exit path
        assert!(!path.exists(), "clean exit removes the pidfile");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// PIDFILE: a leftover from a SIGKILLed predecessor is overwritten
    /// by the next start (a stale file never refuses to start).
    #[test]
    fn pidfile_overwrites_a_stale_predecessor() {
        let dir = scratch("stale");
        let path = dir.join("savd.pid");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(&path, "99999\n").unwrap();
        let guard = Pidfile::create(&path).unwrap();
        assert_eq!(
            std::fs::read_to_string(&path).unwrap(),
            format!("{}\n", std::process::id()),
            "the live pid replaces the dead one"
        );
        drop(guard);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// STATUS: `--show` returns exactly what the daemon published; a
    /// missing file is the not-running answer (an error, not a panic);
    /// the clean-exit path removes the file and stays quiet when there
    /// was nothing to remove.
    #[test]
    fn show_prints_the_published_status_and_errors_when_absent() {
        let dir = scratch("show");
        let path = dir.join("savd.status");
        assert!(
            show(&path).is_err(),
            "no daemon, no status file: an error, not a panic"
        );
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(&path, "savd 0.0.0 pid 42\n").unwrap();
        assert_eq!(show(&path).unwrap(), "savd 0.0.0 pid 42\n");
        remove_status(&path);
        assert!(!path.exists(), "the clean-exit path removes it");
        remove_status(&path); // quiet on NotFound (never published)
        let _ = std::fs::remove_dir_all(&dir);
    }
}
