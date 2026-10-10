//! bfdd — the Rouster BFD daemon binary (Phase 2 stream P2-a).
//!
//! The thin shell over `bfdd::daemon` (the savd shape): the daemon
//! logic and session loops live in the library where tests drive the
//! production code; this binary owns arguments, signals, the run-dir
//! files, and the logging surface.
//!
//! Usage: `bfdd --config <PATH> [--pidfile <PATH>] [--status-file
//! <PATH>]`, or `bfdd --show` to print the published status.
//!
//! Operator surface (A21), run-dir files only — no IPC: a pidfile
//! (`/run/rouster/bfdd.pid`) written at start and removed on clean
//! exit, and a status file (`/run/rouster/bfdd.status`) refreshed on
//! every session change — one `session` line per peer with state,
//! diagnostic, discriminators, and timings. SIGHUP re-parses the
//! config and applies the session diff (unchanged peers never
//! bounce; a rejected reload keeps the running config). SIGTERM and
//! SIGINT hold AdminDown for one Detection Time per peer (RFC 5882
//! §8) so the peers learn of the shutdown, then exit 0.

use std::io;
use std::path::{Path, PathBuf};
use std::time::Duration;

use bfdd::daemon::{parse_bfdd_config, BfddConfig, BfddDaemon};
use tokio::signal::unix::{signal, SignalKind};
use tracing::{error, info, warn};

/// Default pidfile (A21).
const DEFAULT_PIDFILE: &str = "/run/rouster/bfdd.pid";

/// Default status file (A21): what `bfdd --show` prints, refreshed
/// by the daemon on every session change.
const DEFAULT_STATUS_FILE: &str = "/run/rouster/bfdd.status";

/// How often the status file refreshes even without changes (the
/// safety-net cadence; detection times move with learned remote
/// values even when no transition fires).
const STATUS_REFRESH: Duration = Duration::from_secs(1);

/// What the operator asked bfdd to do.
enum Command {
    Run {
        config: PathBuf,
        pidfile: PathBuf,
        status_file: PathBuf,
    },
    Show {
        status_file: PathBuf,
    },
}

fn parse_args() -> Result<Command, String> {
    let mut config = None;
    let mut pidfile = None;
    let mut status_file = None;
    let mut show = false;
    let mut it = std::env::args().skip(1);
    while let Some(arg) = it.next() {
        match arg.as_str() {
            "--config" | "-f" => {
                config = Some(PathBuf::from(it.next().ok_or("--config requires a path")?));
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
                println!("usage: bfdd --config <PATH> [--pidfile <PATH>] [--status-file <PATH>]");
                println!("       bfdd --show [--status-file <PATH>]");
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
        pidfile: pidfile.unwrap_or_else(|| PathBuf::from(DEFAULT_PIDFILE)),
        status_file,
    })
}

/// The daemon's pidfile (A21): written at start, removed on every
/// clean-exit return path (only SIGKILL leaves it behind, naming a
/// dead pid).
struct Pidfile {
    path: PathBuf,
}

impl Pidfile {
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
            warn!(%err, path = %self.path.display(), "bfdd: pidfile removal failed");
        }
    }
}

/// Publishes the status snapshot (A21); diagnostics only — a failed
/// write never fails the session that produced the state.
fn publish_status(path: &Path, pid: u32, daemon: &BfddDaemon) {
    if let Err(err) = std::fs::write(path, daemon.status_text(pid)) {
        warn!(%err, path = %path.display(), "bfdd: status file write failed");
    }
}

/// Removes the status file on the clean-exit paths; quiet on
/// NotFound (the daemon may exit before its first publish).
fn remove_status(path: &Path) {
    if let Err(err) = std::fs::remove_file(path) {
        if err.kind() != io::ErrorKind::NotFound {
            warn!(%err, path = %path.display(), "bfdd: status file removal failed");
        }
    }
}

fn load_config(path: &Path) -> Result<BfddConfig, String> {
    let text = std::fs::read_to_string(path).map_err(|e| e.to_string())?;
    parse_bfdd_config(&text).map_err(|e| e.to_string())
}

#[tokio::main]
async fn main() -> io::Result<()> {
    // Plain log files (the smoke greps them; no ANSI, stderr).
    let _ = tracing_subscriber::fmt()
        .with_ansi(false)
        .with_writer(std::io::stderr)
        .try_init();
    info!(version = env!("CARGO_PKG_VERSION"), "bfdd starting");

    let command = parse_args().map_err(|e| {
        error!("{e}");
        io::Error::new(io::ErrorKind::InvalidInput, e)
    })?;
    match command {
        Command::Show { status_file } => match std::fs::read_to_string(&status_file) {
            Ok(text) => {
                print!("{text}");
                Ok(())
            }
            Err(err) => {
                error!(
                    %err,
                    path = %status_file.display(),
                    "bfdd: no status to show (not running, or no session yet)"
                );
                Err(err)
            }
        },
        Command::Run {
            config,
            pidfile,
            status_file,
        } => run(&config, &pidfile, &status_file).await,
    }
}

async fn run(config_path: &Path, pidfile_path: &Path, status_file: &Path) -> io::Result<()> {
    let pid = std::process::id();

    let mut daemon = BfddDaemon::spawn(load_config(config_path).map_err(|e| {
        error!("bfdd: {e}");
        io::Error::new(io::ErrorKind::PermissionDenied, e)
    })?)
    .await?;
    info!(
        config = %config_path.display(),
        peers = daemon.config().peers.len(),
        "bfdd: config loaded"
    );

    let _pidfile = Pidfile::create(pidfile_path)?;
    info!(path = %pidfile_path.display(), "bfdd: pidfile written");
    publish_status(status_file, pid, &daemon);

    let mut hangup = signal(SignalKind::hangup())?;
    let mut terminate = signal(SignalKind::terminate())?;
    let mut refresh = tokio::time::interval(STATUS_REFRESH);
    refresh.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

    loop {
        tokio::select! {
            _ = hangup.recv() => {
                info!("bfdd: SIGHUP: reloading config");
                match load_config(config_path) {
                    Ok(new_config) => {
                        if let Err(err) = daemon.reload(new_config).await {
                            error!(%err, "bfdd: reload failed; keeping running sessions");
                        }
                    }
                    Err(e) => error!(%e, "bfdd: reload refused; keeping running config"),
                }
                publish_status(status_file, pid, &daemon);
            }
            _ = refresh.tick() => publish_status(status_file, pid, &daemon),
            _ = tokio::signal::ctrl_c() => {
                info!("bfdd: SIGINT: AdminDown hold (RFC 5882 §8) and exit");
                daemon.shutdown_all().await;
                remove_status(status_file);
                return Ok(());
            }
            _ = terminate.recv() => {
                info!("bfdd: SIGTERM: AdminDown hold (RFC 5882 §8) and exit");
                daemon.shutdown_all().await;
                remove_status(status_file);
                return Ok(());
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A unique-per-run scratch dir (the nested path exercises
    /// Pidfile's parent-dir creation).
    fn scratch(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("bfdd-a21-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        dir
    }

    /// PIDFILE: written at start (the live pid, newline-terminated)
    /// and removed on clean exit.
    #[test]
    fn pidfile_written_at_start_and_removed_on_clean_exit() {
        let dir = scratch("pid");
        let path = dir.join("bfdd.pid");
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

    /// PIDFILE: a stale predecessor is overwritten, never refusing
    /// to start.
    #[test]
    fn pidfile_overwrites_a_stale_predecessor() {
        let dir = scratch("stale");
        let path = dir.join("bfdd.pid");
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

    /// STATUS: the clean-exit removal is quiet when there was
    /// nothing to remove.
    #[test]
    fn status_removal_is_quiet_when_absent() {
        let dir = scratch("status");
        let path = dir.join("bfdd.status");
        assert!(!path.exists());
        remove_status(&path); // must not panic
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(&path, "bfdd 0.0.0 pid 42\n").unwrap();
        remove_status(&path);
        assert!(!path.exists());
        let _ = std::fs::remove_dir_all(&dir);
    }
}
