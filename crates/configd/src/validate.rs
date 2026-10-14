//! Deep validation (S8-c M2): run each section's rendered bytes
//! through the owning daemon's own `--validate-config` arm BEFORE any
//! file is written or any signal sent — closing S7-c's
//! "structurally fine, semantically refused" gap at the only place
//! that can close it: the daemon's own parser.
//!
//! The contract, per daemon (the flag landed S8-c in rousterd, savd,
//! and bfdd; bgpd/ospfd ride their own streams this round):
//!
//! - **exit 0** — the rendered file parses (and passes the daemon's
//!   own validation gates — savd's drop-friction line included).
//! - **exit 1** — refusal; stderr carries the parser's line-numbered
//!   error verbatim, which configd surfaces as its refusal reason.
//! - **binary absent** (not found in the search dirs) or **binary
//!   predates the flag** (its `--help` does not mention
//!   `--validate-config`) — **skip with warning**, never fail: an
//!   operator running configd without the daemon binaries installed
//!   must still be able to stage files. Structural validation (the
//!   canonical grammar) has already run at this point either way.
//!
//! Binary discovery order: an explicit dir (the `--daemon-bin-dir`
//! flag, or `ROUSTER_DAEMON_BIN_DIR`), the configd executable's own
//! directory (the cargo target layout — and every deployment image —
//! puts the suite's binaries side by side), then `PATH`. First
//! executable hit wins.
//!
//! Every child run is bounded ([`RUN_TIMEOUT`]) — a wedged binary
//! must not wedge an apply — and the rendered bytes go through a temp
//! file (the daemon arms read a real path), removed on every exit
//! path.

use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use tracing::warn;

use crate::tree::{Canonical, Daemon};

/// How long any single validator child may run.
const RUN_TIMEOUT: Duration = Duration::from_secs(5);

/// The env var that pins the daemon-binary search dir (the flag's
/// fallback for library callers).
pub const BIN_DIR_ENV: &str = "ROUSTER_DAEMON_BIN_DIR";

/// One daemon's deep-validation result.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Validation {
    /// The daemon's own parser accepted the rendered bytes.
    Validated,
    /// No basis to validate; the canonical grammar's structural pass
    /// is all this section got. Never a failure.
    Skipped(SkipReason),
    /// The daemon's own parser refused the rendered bytes — the
    /// pre-apply gate's refusal (`detail` is the daemon's stderr,
    /// verbatim).
    Refused { detail: String },
}

/// Why a daemon's validation was skipped.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SkipReason {
    /// No daemon binary found in any search dir.
    NoBinary,
    /// The binary exists but its `--help` does not mention
    /// `--validate-config` (an older build; bgpd/ospfd until their
    /// streams land the flag).
    NoFlag,
    /// The child could not be run or timed out.
    SpawnFailed(String),
}

impl Validation {
    /// The one-line rendering for CLI/status output.
    pub fn word(&self) -> String {
        match self {
            Validation::Validated => "validated".to_string(),
            Validation::Skipped(SkipReason::NoBinary) => "skipped-no-binary".to_string(),
            Validation::Skipped(SkipReason::NoFlag) => "skipped-no-flag".to_string(),
            Validation::Skipped(SkipReason::SpawnFailed(_)) => "skipped-spawn-failed".to_string(),
            Validation::Refused { .. } => "refused".to_string(),
        }
    }
}

/// The search dirs for daemon binaries, in order: the explicit
/// override (flag or [`BIN_DIR_ENV`]), configd's own exe dir, then
/// the `PATH` entries.
pub fn search_dirs(explicit: Option<&Path>) -> Vec<PathBuf> {
    let mut dirs: Vec<PathBuf> = Vec::new();
    let mut push = |dir: PathBuf| {
        if !dirs.contains(&dir) {
            dirs.push(dir);
        }
    };
    match explicit {
        Some(dir) => push(dir.to_path_buf()),
        None => {
            if let Ok(from_env) = std::env::var(BIN_DIR_ENV) {
                for dir in from_env.split(':').filter(|d| !d.is_empty()) {
                    push(PathBuf::from(dir));
                }
            }
        }
    }
    if let Ok(exe) = std::env::current_exe() {
        if let Some(dir) = exe.parent() {
            push(dir.to_path_buf());
        }
    }
    if let Ok(path) = std::env::var("PATH") {
        for dir in path.split(':').filter(|d| !d.is_empty()) {
            push(PathBuf::from(dir));
        }
    }
    dirs
}

/// Is `path` an executable regular file (the unix bit; the suite's
/// targets are all unix)?
fn is_executable(path: &Path) -> bool {
    let Ok(meta) = std::fs::metadata(path) else {
        return false;
    };
    meta.is_file() && (meta.permissions().mode() & 0o111 != 0)
}

/// Finds the daemon's binary in the search dirs.
pub fn resolve_daemon_bin(daemon: Daemon, dirs: &[PathBuf]) -> Option<PathBuf> {
    dirs.iter()
        .map(|dir| dir.join(daemon_binary_name(daemon)))
        .find(|path| is_executable(path))
}

/// The binary name for a daemon (`rousterd`, `savd`, … — the suite's
/// process names).
fn daemon_binary_name(daemon: Daemon) -> &'static str {
    daemon.name()
}

/// Runs a command with a hard timeout; kills the child if it
/// overruns. Returns the (exit code, combined stderr) or the failure
/// note.
fn run_bounded(mut command: Command) -> Result<(Option<i32>, String), String> {
    command.stdin(Stdio::null());
    command.stdout(Stdio::piped());
    command.stderr(Stdio::piped());
    let mut child = command.spawn().map_err(|e| e.to_string())?;
    let deadline = Instant::now() + RUN_TIMEOUT;
    loop {
        match child.try_wait() {
            Ok(Some(status)) => {
                // Both pipes: the riders print help to stdout and
                // their verdicts to stderr — callers want either.
                let mut text = String::new();
                if let Some(pipe) = child.stdout.take() {
                    drain(pipe, &mut text);
                }
                if let Some(pipe) = child.stderr.take() {
                    drain(pipe, &mut text);
                }
                return Ok((status.code(), text));
            }
            Ok(None) => {
                if Instant::now() >= deadline {
                    let _ = child.kill();
                    let _ = child.wait();
                    return Err("timed out".to_string());
                }
                std::thread::sleep(Duration::from_millis(20));
            }
            Err(err) => return Err(err.to_string()),
        }
    }
}

/// Does this binary know `--validate-config`? Its `--help` says so —
/// the probe that keeps an older (or not-yet-flagged: bgpd/ospfd)
/// binary a skip, not a failure.
fn supports_flag(bin: &Path) -> bool {
    let mut command = Command::new(bin);
    command.arg("--help");
    match run_bounded(command) {
        Ok((_, output)) => output.contains("--validate-config"),
        Err(_) => false,
    }
}

/// Reads one captured child pipe into `out` (read errors are dropped:
/// diagnostics only).
fn drain(mut pipe: impl std::io::Read, out: &mut String) {
    let _ = pipe.read_to_string(out);
}

/// A counter for unique temp-file names (process-unique).
static TEMP_SEQ: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

/// Deep-validates one daemon's rendered bytes. Never panics, never
/// blocks past [`RUN_TIMEOUT`].
pub fn validate_rendered(daemon: Daemon, rendered: &str, dirs: &[PathBuf]) -> Validation {
    let Some(bin) = resolve_daemon_bin(daemon, dirs) else {
        return Validation::Skipped(SkipReason::NoBinary);
    };
    if !supports_flag(&bin) {
        return Validation::Skipped(SkipReason::NoFlag);
    }
    let seq = TEMP_SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let temp = std::env::temp_dir().join(format!(
        "configd-validate-{}-{seq}-{}.conf",
        std::process::id(),
        daemon.name()
    ));
    let (code, stderr) = match std::fs::write(&temp, rendered) {
        Ok(()) => {
            let mut command = Command::new(&bin);
            command.arg("--validate-config").arg(&temp);
            match run_bounded(command) {
                Ok(pair) => pair,
                Err(note) => {
                    let _ = std::fs::remove_file(&temp);
                    return Validation::Skipped(SkipReason::SpawnFailed(note));
                }
            }
        }
        Err(err) => {
            return Validation::Skipped(SkipReason::SpawnFailed(format!(
                "cannot stage {}: {err}",
                temp.display()
            )))
        }
    };
    let _ = std::fs::remove_file(&temp);
    match code {
        Some(0) => Validation::Validated,
        Some(1) => Validation::Refused {
            detail: stderr.trim().to_string(),
        },
        other => Validation::Skipped(SkipReason::SpawnFailed(format!(
            "exit {other:?}: {}",
            stderr.trim()
        ))),
    }
}

/// Deep-validates every section of a parsed canonical tree, in apply
/// order. bgpd/ospfd are included whenever their binaries gain the
/// flag (the probe); absent binaries are disclosed skips.
pub fn validate_canonical(tree: &Canonical, dirs: &[PathBuf]) -> Vec<(Daemon, Validation)> {
    let rendered = crate::render::render_all(tree);
    let mut out = Vec::new();
    for daemon in Daemon::all() {
        if let Some(bytes) = rendered.get(&daemon) {
            out.push((daemon, validate_rendered(daemon, bytes, dirs)));
        }
    }
    out
}

/// The refusal summary for an error message: one line per refusing
/// daemon, its stderr verbatim. `None` when nothing refused.
pub fn refusal_summary(results: &[(Daemon, Validation)]) -> Option<String> {
    let refusals: Vec<&(Daemon, Validation)> = results
        .iter()
        .filter(|(_, v)| matches!(v, Validation::Refused { .. }))
        .collect();
    if refusals.is_empty() {
        return None;
    }
    let mut out = String::new();
    for (daemon, verdict) in refusals {
        if let Validation::Refused { detail } = verdict {
            if !out.is_empty() {
                out.push_str("; ");
            }
            out.push_str(&format!("{}: {detail}", daemon.name()));
        }
    }
    Some(out)
}

/// Logs (warns) the skips in a result set — the disclosure half of
/// the probe-skip contract.
pub fn warn_skips(results: &[(Daemon, Validation)]) {
    for (daemon, verdict) in results {
        if let Validation::Skipped(why) = verdict {
            let why = match why {
                SkipReason::NoBinary => "no binary found".to_string(),
                SkipReason::NoFlag => "binary predates --validate-config".to_string(),
                SkipReason::SpawnFailed(note) => format!("validator failed: {note}"),
            };
            warn!(daemon = daemon.name(), %why, "configd: semantic validation skipped");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tree::parse;

    /// A stand-in daemon binary: a shell script whose exit code keys
    /// off a marker word in the rendered bytes ("REFUSE-ME") — the
    /// daemon-side `--validate-config` contract in six lines.
    fn standin_daemon(dir: &Path, name: &str) -> PathBuf {
        let path = dir.join(name);
        std::fs::write(
            &path,
            "#!/bin/sh\n\
             case \"$1\" in\n\
             --help) echo 'usage: standin --config <PATH> [--validate-config <PATH>]'; exit 0;;\n\
             --validate-config) shift; if grep -q REFUSE-ME \"$1\"; then \
             echo \"$0: $1: line 1: standin refusal\" >&2; exit 1; fi; \
             echo \"$0: $1: OK\" >&2; exit 0;;\n\
             esac\n\
             exit 2\n",
        )
        .unwrap();
        make_executable(&path);
        path
    }

    fn make_executable(path: &Path) {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = std::fs::metadata(path).unwrap().permissions();
        perms.set_mode(0o755);
        std::fs::set_permissions(path, perms).unwrap();
    }

    fn scratch(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "configd-validate-{tag}-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    /// Counts the validator temp files in the shared tmpdir (other
    /// test processes create theirs concurrently, so only the DELTA
    /// around this test's own call is meaningful).
    fn temp_leftovers() -> usize {
        std::fs::read_dir(std::env::temp_dir())
            .unwrap()
            .filter_map(|e| e.ok())
            .filter(|e| {
                e.file_name()
                    .to_string_lossy()
                    .starts_with("configd-validate-")
            })
            .count()
    }

    #[test]
    fn validated_when_the_daemon_accepts() {
        let dir = scratch("ok");
        standin_daemon(&dir, "savd");
        let before = temp_leftovers();
        let verdict = validate_rendered(Daemon::Savd, "mode strict\n", std::slice::from_ref(&dir));
        assert_eq!(verdict, Validation::Validated);
        assert!(
            temp_leftovers() <= before,
            "this call's validator temp file was cleaned up"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn refused_carries_the_daemon_stderr_verbatim() {
        let dir = scratch("refuse");
        standin_daemon(&dir, "bfdd");
        let verdict =
            validate_rendered(Daemon::Bfdd, "peer REFUSE-ME\n", std::slice::from_ref(&dir));
        match verdict {
            Validation::Refused { detail } => {
                assert!(detail.contains("line 1:"), "{detail}");
                assert!(detail.contains("standin refusal"), "{detail}");
            }
            other => panic!("expected refusal, got {other:?}"),
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn absent_binary_and_flagless_binary_are_skips_not_failures() {
        let dir = scratch("skips");
        // No binaries at all.
        assert_eq!(
            validate_rendered(Daemon::Savd, "mode strict\n", std::slice::from_ref(&dir)),
            Validation::Skipped(SkipReason::NoBinary)
        );
        // A binary that predates the flag (help says nothing about it).
        let old = dir.join("rousterd");
        std::fs::write(
            &old,
            "#!/bin/sh\necho 'usage: old rousterd --config <PATH>'\nexit 0\n",
        )
        .unwrap();
        make_executable(&old);
        assert_eq!(
            validate_rendered(
                Daemon::Rousterd,
                "ip route 1.2.3.0/24 blackhole\n",
                std::slice::from_ref(&dir)
            ),
            Validation::Skipped(SkipReason::NoFlag)
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn refusal_summary_names_each_refusing_daemon() {
        let results = vec![
            (Daemon::Rousterd, Validation::Validated),
            (
                Daemon::Savd,
                Validation::Refused {
                    detail: "savd: line 2: bad mode `nosuch`".to_string(),
                },
            ),
            (Daemon::Bfdd, Validation::Skipped(SkipReason::NoBinary)),
        ];
        assert_eq!(
            refusal_summary(&results).as_deref(),
            Some("savd: savd: line 2: bad mode `nosuch`")
        );
        assert_eq!(
            refusal_summary(&[(Daemon::Savd, Validation::Validated)]),
            None
        );
    }

    #[test]
    fn validate_canonical_walks_sections_in_apply_order() {
        let dir = scratch("canonical");
        standin_daemon(&dir, "savd");
        standin_daemon(&dir, "bgpd");
        let tree =
            parse("daemon savd {\nmode strict\n}\ndaemon bgpd {\nrouter bgp 65000\n}\n").unwrap();
        let results = validate_canonical(&tree, std::slice::from_ref(&dir));
        assert_eq!(
            results,
            vec![
                (Daemon::Savd, Validation::Validated),
                (Daemon::Bgpd, Validation::Validated)
            ]
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_wedged_validator_times_out_as_a_skip() {
        let dir = scratch("wedge");
        // Probes --help honestly (so the flag check passes fast), then
        // wedges on the validate arm — the bound must kill it.
        let wedged = dir.join("savd");
        std::fs::write(
            &wedged,
            "#!/bin/sh\n[ \"$1\" = --help ] && { echo 'usage: --validate-config <PATH>'; exit 0; }\nsleep 60\n",
        )
        .unwrap();
        make_executable(&wedged);
        let started = Instant::now();
        let verdict = validate_rendered(Daemon::Savd, "mode strict\n", std::slice::from_ref(&dir));
        let timed_out = matches!(
            &verdict,
            Validation::Skipped(SkipReason::SpawnFailed(note)) if note.contains("timed out")
        );
        assert!(timed_out, "{verdict:?}");
        assert!(
            started.elapsed() < RUN_TIMEOUT + Duration::from_secs(5),
            "the bound held: {:?}",
            started.elapsed()
        );
        let _ = std::fs::remove_dir_all(&dir);
    }
}
