//! Transactional apply (Phase 4, M2): render → atomic write → SIGHUP
//! in dependency order → generation record. Rollback v1 re-applies
//! the previous generation.
//!
//! The pipeline, per apply:
//!
//! ```text
//! canonical file ──parse──> section tree ──render──> per-daemon bytes
//!        │                                          │
//!        │                                     atomic write (temp+rename)
//!        │                                          │  registry order:
//!        │                                          │  rousterd, savd, bfdd,
//!        │                                          │  ospfd, bgpd
//!        │                                          v
//!        │                              SIGHUP per ARMED daemon present
//!        │                              (rousterd pid = rousterd.status
//!        │                               header; savd/bfdd pidfiles;
//!        │                               ospfd/bgpd: no arm, never signaled)
//!        │                                          │
//!        └────────── hash ────────────> generation dir + current/previous
//!                                           │
//!                                           v
//!                                <run-dir>/configd.status
//! ```
//!
//! **What is and is not transactional, honestly**: each file
//! replacement is atomic (a daemon never re-parses a half-written
//! file); the generation record is written only after every render
//! succeeded, so a failed apply never advances `current`; and
//! rollback is explicit (`configd rollback` re-applies the previous
//! generation through this same pipeline). What v1 does NOT have is
//! cross-file atomicity or automatic rollback on a daemon's rejected
//! reload — a daemon that dislikes its new file keeps its running
//! config (every landed SIGHUP arm behaves this way: parse failure →
//! warning, running config retained) until the operator rolls back.
//! Automatic rollback needs daemon status-file semantics beyond
//! v1's scope (§Deferred, docs/protocols/config.md).
//!
//! Failure handling: a write error stops the pipeline at that daemon
//! (earlier files are already replaced — disclosed above), no
//! generation is recorded, and the error names the file. A daemon
//! with a dead/missing pid is NOT a failure: the file is in place
//! and the next start of that daemon reads it; the per-daemon
//! outcome records `not-running` and the apply still succeeds.
//!
//! The generation store lives under `<run-dir>/configd/`:
//!
//! ```text
//! <run-dir>/configd/generations/<seq>-<hash>/rouster.conf   the canonical
//!                                                           bytes as applied
//! <run-dir>/configd/current        one line: this generation's dir name
//! <run-dir>/configd/previous       one line: the prior generation's dir name
//! ```
//!
//! Rollback reads `previous`, re-applies its bytes as a NEW
//! generation (so the audit trail never rewrites history), and the
//! two rollbacks-in-a-row case toggles — standard FRR-style behavior.
//! History is pruned to the newest [`KEEP_GENERATIONS`] dirs.

use std::fs;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use tracing::info;

use crate::atomic::write_atomic;
use crate::render::render_daemon;
use crate::signal::{self, PidSource};
use crate::status;
use crate::tree::{self, Daemon};

/// How many generation dirs to retain (current + previous + history
/// headroom); older ones are pruned after each apply.
pub const KEEP_GENERATIONS: usize = 8;

/// The per-daemon actuation registry: file, pid source, signal arm,
/// in apply order. rousterd (the RIB/zebra) first, protocols after.
pub struct DaemonSpec {
    pub daemon: Daemon,
    pub pid_source: PidSource,
    /// Whether configd may SIGHUP this daemon (false for ospfd/bgpd:
    /// no SIGHUP arm — the default disposition would terminate them).
    pub signal_arm: bool,
}

/// Builds the registry for a given run-dir (pid sources point into
/// it).
pub fn registry(run_dir: &Path) -> Vec<DaemonSpec> {
    vec![
        DaemonSpec {
            daemon: Daemon::Rousterd,
            pid_source: PidSource::StatusHeader(run_dir.join("rousterd.status")),
            signal_arm: true,
        },
        DaemonSpec {
            daemon: Daemon::Savd,
            pid_source: PidSource::Pidfile(run_dir.join("savd.pid")),
            signal_arm: true,
        },
        DaemonSpec {
            daemon: Daemon::Bfdd,
            pid_source: PidSource::Pidfile(run_dir.join("bfdd.pid")),
            signal_arm: true,
        },
        DaemonSpec {
            daemon: Daemon::Ospfd,
            pid_source: PidSource::None,
            signal_arm: false,
        },
        DaemonSpec {
            daemon: Daemon::Bgpd,
            pid_source: PidSource::None,
            signal_arm: false,
        },
    ]
}

/// Where an applied config came from (the status line renders it).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RollbackSource {
    /// The operator's file path.
    File(PathBuf),
    /// A rollback re-applying generation `<seq>`.
    Rollback { from: u64 },
}

impl RollbackSource {
    /// The status-file rendering of this source (the `source` line's
    /// word).
    pub fn render_status_word(&self) -> String {
        match self {
            RollbackSource::File(path) => path.display().to_string(),
            RollbackSource::Rollback { from } => format!("rollback of generation {from}"),
        }
    }
}

/// Options for one apply.
#[derive(Debug, Clone)]
pub struct ApplyOptions {
    /// The run-dir (default `/run/rouster`): pid sources live here,
    /// the generation store is `<run-dir>/configd/`, the status file
    /// is `<run-dir>/configd.status`.
    pub run_dir: PathBuf,
    /// The directory the daemon config files render into (default
    /// `/etc`; `<etc-dir>/<daemon>.conf`).
    pub etc_dir: PathBuf,
}

impl Default for ApplyOptions {
    fn default() -> Self {
        Self {
            run_dir: PathBuf::from("/run/rouster"),
            etc_dir: PathBuf::from("/etc"),
        }
    }
}

/// One daemon's actuation outcome, in the status file's vocabulary.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DaemonOutcome {
    /// File written, SIGHUP delivered to the live pid.
    Signaled { pid: u32 },
    /// File written, but no live daemon to signal (absent or dead pid
    /// source) — the next start reads the new file. Not a failure.
    NotRunning,
    /// File written; this daemon has no SIGHUP arm yet (ospfd, bgpd)
    /// — reload deferred to its next start.
    NoSignalArm,
    /// File written, but the SIGHUP itself failed (permissions, race
    /// with a dying pid); the note carries the shell's complaint.
    SignalFailed { note: String },
}

impl DaemonOutcome {
    /// The status-file word for this outcome.
    pub fn word(&self) -> &'static str {
        match self {
            DaemonOutcome::Signaled { .. } => "signaled",
            DaemonOutcome::NotRunning => "not-running",
            DaemonOutcome::NoSignalArm => "no-signal-arm",
            DaemonOutcome::SignalFailed { .. } => "signal-failed",
        }
    }
}

/// The apply report (feeds the status file and the CLI output).
#[derive(Debug, Clone)]
pub struct ApplyReport {
    /// The generation this apply recorded.
    pub generation: u64,
    /// The canonical file's content hash (FNV-1a 64, 16 hex chars — a
    /// change fingerprint, not a cryptographic checksum).
    pub hash: String,
    /// Unix seconds at apply time.
    pub applied_unix: u64,
    /// Where the canonical bytes came from.
    pub source: RollbackSource,
    /// The configd-recorded router-id, if the canonical file had one.
    pub router_id: Option<std::net::Ipv4Addr>,
    /// Per-daemon outcomes, in apply order, only for daemons with a
    /// section in the applied file.
    pub outcomes: Vec<(Daemon, DaemonOutcome)>,
    /// The pre-apply gate's verdicts (S8-c): what each section's deep
    /// validation did — `validated`, or the disclosed skip (an absent
    /// or flagless binary). A refusal never reaches a report (it
    /// fails the apply).
    pub validations: Vec<(Daemon, crate::validate::Validation)>,
    /// Each daemon file's rendered path + byte length (render proof).
    pub rendered: Vec<(Daemon, PathBuf, usize)>,
}

/// Apply errors: nothing was recorded on any of these paths (the
/// generation store only advances on a fully rendered + written
/// apply).
#[derive(Debug, thiserror::Error)]
pub enum ApplyError {
    #[error("cannot read {path}: {err}")]
    Read { path: PathBuf, err: std::io::Error },
    #[error("canonical file rejected: {0}")]
    Parse(#[from] tree::ParseError),
    /// A daemon's own parser refused its rendered section (S8-c's
    /// pre-apply gate): nothing was written, nothing was signaled.
    #[error("semantic validation refused the apply: {refusal}")]
    Validation { refusal: String },
    #[error("cannot write {path}: {err}")]
    Write { path: PathBuf, err: std::io::Error },
    #[error("generation store at {path}: {err}")]
    Store { path: PathBuf, err: std::io::Error },
    #[error("no previous generation to roll back to ({path} missing or empty)")]
    NoPrevious { path: PathBuf },
}

/// FNV-1a 64 over the canonical bytes — the config hash. A change
/// fingerprint for the status file (collision-resistant enough for
/// "did the config change", not a security property; disclosed).
pub fn config_hash(bytes: &[u8]) -> String {
    let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
    for &byte in bytes {
        hash ^= u64::from(byte);
        hash = hash.wrapping_mul(0x100_0000_01b3);
    }
    format!("{hash:016x}")
}

/// Applies a canonical file (already read to bytes) through the full
/// pipeline. `source` records provenance for the status file.
pub fn apply(
    bytes: &[u8],
    source: RollbackSource,
    opts: &ApplyOptions,
) -> Result<ApplyReport, ApplyError> {
    // 1. Parse (structural validation refuses a bad file outright).
    let text = std::str::from_utf8(bytes).map_err(|_| tree::ParseError::Line {
        line: 0,
        reason: "canonical file is not valid UTF-8".to_string(),
    })?;
    let parsed = tree::parse(text)?;

    // 1.5 (S8-c M2) Deep validation, the pre-apply gate: each
    // section's rendered bytes through the owning daemon's own
    // `--validate-config` arm, BEFORE any file is touched. Absent or
    // flagless binaries are disclosed skips, never failures; a
    // refusal is — the whole point — an apply error naming the
    // daemon's line-numbered complaint.
    let validation_dirs = crate::validate::search_dirs(None);
    let validation = crate::validate::validate_canonical(&parsed, &validation_dirs);
    crate::validate::warn_skips(&validation);
    if let Some(refusal) = crate::validate::refusal_summary(&validation) {
        return Err(ApplyError::Validation { refusal });
    }

    // 2. Render every section (registry order).
    let mut rendered: Vec<(Daemon, PathBuf, String)> = Vec::new();
    for daemon in Daemon::all() {
        if let Some(section) = parsed.section(daemon) {
            let out = render_daemon(section);
            let path = opts.etc_dir.join(daemon.file_name());
            rendered.push((daemon, path, out));
        }
    }

    // 3. Atomic-write each file. A write error stops here: no
    // generation is recorded (disclosed: earlier files are replaced).
    for (daemon, path, out) in &rendered {
        write_atomic(path, out).map_err(|err| ApplyError::Write {
            path: path.clone(),
            err,
        })?;
        info!(daemon = daemon.name(), path = %path.display(), bytes = out.len(), "rendered");
    }

    // 4. Signal every ARMED daemon with a section, in order.
    let registry = registry(&opts.run_dir);
    let mut outcomes = Vec::new();
    for spec in &registry {
        if !rendered.iter().any(|(d, _, _)| *d == spec.daemon) {
            continue;
        }
        if !spec.signal_arm {
            outcomes.push((spec.daemon, DaemonOutcome::NoSignalArm));
            continue;
        }
        match signal::resolve_pid(&spec.pid_source) {
            Some(pid) if signal::liveness(pid) == signal::Liveness::Alive => {
                match signal::send_sighup(pid) {
                    Ok(()) => outcomes.push((spec.daemon, DaemonOutcome::Signaled { pid })),
                    Err(note) => outcomes.push((spec.daemon, DaemonOutcome::SignalFailed { note })),
                }
            }
            _ => outcomes.push((spec.daemon, DaemonOutcome::NotRunning)),
        }
    }

    // 5. Record the generation (current + previous), prune history.
    let hash = config_hash(bytes);
    let generation = record_generation(bytes, &hash, opts)?;

    // 6. Publish the status file.
    let report = ApplyReport {
        generation,
        hash,
        applied_unix: SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0),
        source,
        router_id: parsed.router_id.map(|(_, addr)| addr),
        outcomes,
        validations: validation,
        rendered: rendered
            .into_iter()
            .map(|(d, p, out)| (d, p, out.len()))
            .collect(),
    };
    let status_path = opts.run_dir.join("configd.status");
    let text = status::render_status(&report, opts);
    write_atomic(&status_path, &text).map_err(|err| ApplyError::Store {
        path: status_path,
        err,
    })?;

    Ok(report)
}

/// Applies an operator file from disk.
pub fn apply_file(path: &Path, opts: &ApplyOptions) -> Result<ApplyReport, ApplyError> {
    let bytes = fs::read(path).map_err(|err| ApplyError::Read {
        path: path.to_path_buf(),
        err,
    })?;
    apply(&bytes, RollbackSource::File(path.to_path_buf()), opts)
}

/// Rolls back: re-applies the previous generation's canonical bytes
/// as a new generation.
pub fn rollback(opts: &ApplyOptions) -> Result<ApplyReport, ApplyError> {
    let store = opts.run_dir.join("configd");
    let previous_pointer = store.join("previous");
    let name = match fs::read_to_string(&previous_pointer) {
        Ok(text) => text.trim().to_string(),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
            return Err(ApplyError::NoPrevious {
                path: previous_pointer,
            });
        }
        Err(err) => {
            return Err(ApplyError::Store {
                path: previous_pointer,
                err,
            });
        }
    };
    if name.is_empty() {
        return Err(ApplyError::NoPrevious {
            path: previous_pointer,
        });
    }
    let gen_path = store.join("generations").join(&name).join("rouster.conf");
    let bytes = fs::read(&gen_path).map_err(|err| ApplyError::Store {
        path: gen_path,
        err,
    })?;
    let from = name
        .split('-')
        .next()
        .and_then(|seq| seq.parse().ok())
        .unwrap_or(0);
    apply(&bytes, RollbackSource::Rollback { from }, opts)
}

/// Writes the new generation dir, swaps the pointers, prunes history.
/// Returns the generation sequence number.
fn record_generation(bytes: &[u8], hash: &str, opts: &ApplyOptions) -> Result<u64, ApplyError> {
    let store = opts.run_dir.join("configd");
    let generations = store.join("generations");
    fs::create_dir_all(&generations).map_err(|err| ApplyError::Store {
        path: generations.clone(),
        err,
    })?;

    // Next sequence: one past the highest existing.
    let mut highest = 0;
    for entry in fs::read_dir(&generations).map_err(|err| ApplyError::Store {
        path: generations.clone(),
        err,
    })? {
        let entry = entry.map_err(|err| ApplyError::Store {
            path: generations.clone(),
            err,
        })?;
        if let Some(seq) =
            parse_generation_seq(&entry.file_name().into_string().unwrap_or_default())
        {
            highest = highest.max(seq);
        }
    }
    let seq = highest + 1;
    let name = format!("{seq:06}-{hash}");
    let dir = generations.join(&name);
    fs::create_dir_all(&dir).map_err(|err| ApplyError::Store {
        path: dir.clone(),
        err,
    })?;
    write_atomic(&dir.join("rouster.conf"), &String::from_utf8_lossy(bytes))
        .map_err(|err| ApplyError::Store { path: dir, err })?;

    // Swap pointers: previous <- old current, current <- new.
    let current = store.join("current");
    let old_current = fs::read_to_string(&current)
        .ok()
        .map(|text| text.trim().to_string())
        .filter(|text| !text.is_empty());
    if let Some(old) = &old_current {
        write_atomic(&store.join("previous"), &format!("{old}\n")).map_err(|err| {
            ApplyError::Store {
                path: store.join("previous"),
                err,
            }
        })?;
    }
    write_atomic(&current, &format!("{name}\n"))
        .map_err(|err| ApplyError::Store { path: current, err })?;

    prune_history(&generations)?;
    Ok(seq)
}

/// Parses `<seq>-<hash>` dir names to their sequence number (the
/// dash is required — a bare `000041` is not a generation dir).
fn parse_generation_seq(name: &str) -> Option<u64> {
    let (seq, _) = name.split_once('-')?;
    if seq.len() != 6 || !seq.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    seq.parse().ok()
}

/// Keeps only the newest [`KEEP_GENERATIONS`] generation dirs.
fn prune_history(generations: &Path) -> Result<(), ApplyError> {
    let mut seqs: Vec<(u64, String)> = Vec::new();
    for entry in fs::read_dir(generations).map_err(|err| ApplyError::Store {
        path: generations.to_path_buf(),
        err,
    })? {
        let entry = entry.map_err(|err| ApplyError::Store {
            path: generations.to_path_buf(),
            err,
        })?;
        let name = entry.file_name().into_string().unwrap_or_default();
        if let Some(seq) = parse_generation_seq(&name) {
            seqs.push((seq, name));
        }
    }
    seqs.sort();
    let excess = seqs.len().saturating_sub(KEEP_GENERATIONS);
    for (_, name) in seqs.into_iter().take(excess) {
        let dir = generations.join(&name);
        if let Err(err) = fs::remove_dir_all(&dir) {
            if err.kind() != std::io::ErrorKind::NotFound {
                return Err(ApplyError::Store { path: dir, err });
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A temp fixture: fresh dirs per test, removed on drop.
    struct Temp {
        root: PathBuf,
    }

    impl Temp {
        fn new(tag: &str) -> Self {
            let root = std::env::temp_dir().join(format!(
                "configd-apply-{tag}-{}-{:?}",
                std::process::id(),
                std::thread::current().id()
            ));
            let _ = fs::remove_dir_all(&root);
            fs::create_dir_all(&root).unwrap();
            Self { root }
        }

        fn opts(&self) -> ApplyOptions {
            ApplyOptions {
                run_dir: self.root.join("run"),
                etc_dir: self.root.join("etc"),
            }
        }
    }

    impl Drop for Temp {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.root);
        }
    }

    const CANONICAL: &str = "router-id 198.51.100.1\n\
                             daemon rousterd {\n\
                             zapi socket /run/rouster/zserv.api\n\
                             }\n\
                             daemon savd {\n\
                             mode strict\n\
                             poll 2\n\
                             }\n\
                             daemon bfdd {\n\
                             peer 192.0.2.9\n\
                             }\n";

    #[test]
    fn hash_is_fnv1a_with_known_vector() {
        // FNV-1a 64 of "a" — the reference vector.
        assert_eq!(config_hash(b"a"), "af63dc4c8601ec8c");
        assert_eq!(config_hash(b""), "cbf29ce484222325");
        // Change fingerprint: one byte differs, hashes differ.
        assert_ne!(config_hash(b"daemon x"), config_hash(b"daemon y"));
    }

    #[test]
    fn apply_renders_files_and_records_generation() {
        let temp = Temp::new("first");
        let opts = temp.opts();
        let report = apply(
            CANONICAL.as_bytes(),
            RollbackSource::File(PathBuf::from("/root/rouster.conf")),
            &opts,
        )
        .unwrap();

        // Files rendered with exact bytes.
        assert_eq!(
            fs::read_to_string(opts.etc_dir.join("rouster.conf")).unwrap(),
            "zapi socket /run/rouster/zserv.api\n"
        );
        assert_eq!(
            fs::read_to_string(opts.etc_dir.join("savd.conf")).unwrap(),
            "mode strict\npoll 2\n"
        );
        assert_eq!(
            fs::read_to_string(opts.etc_dir.join("bfdd.conf")).unwrap(),
            "peer 192.0.2.9\n"
        );

        // Generation 1 recorded; no previous yet.
        assert_eq!(report.generation, 1);
        let store = opts.run_dir.join("configd");
        assert_eq!(
            fs::read_to_string(store.join("current")).unwrap().trim(),
            format!("000001-{}", report.hash)
        );
        assert!(!store.join("previous").exists());
        assert_eq!(
            fs::read_to_string(
                store
                    .join("generations")
                    .join(format!("000001-{}", report.hash))
                    .join("rouster.conf")
            )
            .unwrap(),
            CANONICAL
        );

        // No daemons running: every armed daemon is not-running.
        for (daemon, outcome) in &report.outcomes {
            match daemon {
                Daemon::Rousterd | Daemon::Savd | Daemon::Bfdd => {
                    assert_eq!(outcome.word(), "not-running", "{daemon:?}");
                }
                _ => unreachable!("no ospfd/bgpd section"),
            }
        }
    }

    #[test]
    fn second_apply_advances_and_keeps_previous() {
        let temp = Temp::new("second");
        let opts = temp.opts();
        let first = apply(
            CANONICAL.as_bytes(),
            RollbackSource::File(PathBuf::from("/x")),
            &opts,
        )
        .unwrap();
        let changed = CANONICAL.replace("poll 2", "poll 3");
        let second = apply(
            changed.as_bytes(),
            RollbackSource::File(PathBuf::from("/x")),
            &opts,
        )
        .unwrap();

        assert_eq!(second.generation, 2);
        let store = opts.run_dir.join("configd");
        assert_eq!(
            fs::read_to_string(store.join("current")).unwrap().trim(),
            format!("000002-{}", second.hash)
        );
        assert_eq!(
            fs::read_to_string(store.join("previous")).unwrap().trim(),
            format!("000001-{}", first.hash)
        );
        // The rendered file follows the new generation.
        assert!(fs::read_to_string(opts.etc_dir.join("savd.conf"))
            .unwrap()
            .contains("poll 3"));
    }

    #[test]
    fn apply_order_is_rousterd_first_protocols_after() {
        // The registry's order is the pipeline's order — pinned here
        // so the dependency rule cannot silently drift.
        let opts = ApplyOptions::default();
        let names: Vec<_> = registry(&opts.run_dir)
            .into_iter()
            .map(|spec| spec.daemon.name())
            .collect();
        assert_eq!(names, ["rousterd", "savd", "bfdd", "ospfd", "bgpd"]);
    }

    #[test]
    fn bad_canonical_refused_nothing_written() {
        let temp = Temp::new("refused");
        let opts = temp.opts();
        let err = apply(
            b"daemon nosuch {\n}\n",
            RollbackSource::File(PathBuf::from("/x")),
            &opts,
        )
        .unwrap_err();
        assert!(err.to_string().contains("unknown daemon `nosuch`"));
        assert!(!opts.etc_dir.join("rouster.conf").exists());
        assert!(!opts.run_dir.join("configd").exists());
        assert!(!opts.run_dir.join("configd.status").exists());
    }

    #[test]
    fn rollback_reapplies_previous_generation_content() {
        let temp = Temp::new("rollback");
        let opts = temp.opts();
        apply(
            CANONICAL.as_bytes(),
            RollbackSource::File(PathBuf::from("/x")),
            &opts,
        )
        .unwrap();
        let changed = CANONICAL.replace("poll 2", "poll 3");
        apply(
            changed.as_bytes(),
            RollbackSource::File(PathBuf::from("/x")),
            &opts,
        )
        .unwrap();
        assert!(fs::read_to_string(opts.etc_dir.join("savd.conf"))
            .unwrap()
            .contains("poll 3"));

        let report = rollback(&opts).unwrap();
        // Generation 3 (history is never rewritten), content of gen 1.
        assert_eq!(report.generation, 3);
        assert_eq!(report.source, RollbackSource::Rollback { from: 1 });
        assert!(fs::read_to_string(opts.etc_dir.join("savd.conf"))
            .unwrap()
            .contains("poll 2"));
        // Current/previous swapped forward: current=gen3, previous=gen2.
        let store = opts.run_dir.join("configd");
        assert_eq!(
            fs::read_to_string(store.join("current")).unwrap().trim(),
            format!("000003-{}", report.hash)
        );
        assert!(fs::read_to_string(store.join("previous"))
            .unwrap()
            .trim()
            .starts_with("000002-"));
    }

    #[test]
    fn rollback_twice_toggles() {
        let temp = Temp::new("toggle");
        let opts = temp.opts();
        apply(
            CANONICAL.as_bytes(),
            RollbackSource::File(PathBuf::from("/x")),
            &opts,
        )
        .unwrap();
        let changed = CANONICAL.replace("poll 2", "poll 3");
        apply(
            changed.as_bytes(),
            RollbackSource::File(PathBuf::from("/x")),
            &opts,
        )
        .unwrap();
        rollback(&opts).unwrap(); // -> poll 2 (gen 3)
        let report = rollback(&opts).unwrap(); // -> poll 3 (gen 4, from gen 2)
        assert_eq!(report.source, RollbackSource::Rollback { from: 2 });
        assert!(fs::read_to_string(opts.etc_dir.join("savd.conf"))
            .unwrap()
            .contains("poll 3"));
    }

    #[test]
    fn rollback_without_previous_is_an_error() {
        let temp = Temp::new("noprev");
        let opts = temp.opts();
        let err = rollback(&opts).unwrap_err();
        assert!(matches!(err, ApplyError::NoPrevious { .. }));
        // Also after exactly one apply (no previous pointer yet).
        apply(
            CANONICAL.as_bytes(),
            RollbackSource::File(PathBuf::from("/x")),
            &opts,
        )
        .unwrap();
        assert!(matches!(
            rollback(&opts).unwrap_err(),
            ApplyError::NoPrevious { .. }
        ));
    }

    #[test]
    fn history_is_pruned_to_bound() {
        let temp = Temp::new("prune");
        let opts = temp.opts();
        for i in 0..(KEEP_GENERATIONS as u64 + 3) {
            let text = CANONICAL.replace("poll 2", &format!("poll {i}"));
            apply(
                text.as_bytes(),
                RollbackSource::File(PathBuf::from("/x")),
                &opts,
            )
            .unwrap();
        }
        let generations = opts.run_dir.join("configd").join("generations");
        let count = fs::read_dir(&generations).unwrap().count();
        assert_eq!(count, KEEP_GENERATIONS);
        // The newest survived (current names it).
        let current = fs::read_to_string(opts.run_dir.join("configd").join("current"))
            .unwrap()
            .trim()
            .to_string();
        assert!(generations.join(&current).exists());
    }

    #[test]
    fn generation_seq_parses_only_six_digit_names() {
        assert_eq!(parse_generation_seq("000042-abcdef0123456789"), Some(42));
        assert_eq!(parse_generation_seq("42-abcdef0123456789"), None);
        assert_eq!(parse_generation_seq("notagen"), None);
        assert_eq!(parse_generation_seq("000041"), None);
    }
}
