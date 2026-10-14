//! configd — the Rouster config-manager CLI (Phase 4, M3; the S8-c
//! validate verb and the pre-apply gate).
//!
//! Thin shell over the `configd` library, the rousterctl shape (no
//! daemon, no IPC — the verbs act on files and signals directly):
//!
//! ```text
//! configd validate <FILE> [--daemon-bin-dir <PATH>]
//! configd apply <FILE> [--run-dir <PATH>] [--etc-dir <PATH>] [--daemon-bin-dir <PATH>]
//! configd rollback [--run-dir <PATH>] [--etc-dir <PATH>]
//! configd status [--run-dir <PATH>]
//! configd render <FILE> [--dry-run] [--etc-dir <PATH>]
//! ```
//!
//! Defaults: `--run-dir /run/rouster`, `--etc-dir /etc`.
//!
//! Exit codes: **0** ok · **1** execution error (unreadable file,
//! rejected canonical, a daemon's semantic refusal, write failure) ·
//! **2** usage · **3** nothing to act on (`status` with no status
//! file published, `rollback` with no previous generation).
//!
//! `configd validate` (S8-c) renders each section in memory and runs
//! the owning daemon's own `--validate-config` on the rendered bytes
//! — nothing is written, nothing is signaled. `apply` runs the same
//! gate FIRST and refuses on any failure (the S7-c §Deferred-1 ask);
//! absent or flagless daemon binaries are disclosed skips, never
//! failures. `render --dry-run` prints each daemon's rendered output
//! with its destination path and touches nothing — the
//! vtyd-integration entry point (W1-c's parse-only config mode
//! previews through it later).

use std::path::PathBuf;
use std::process::ExitCode;

use configd::apply::{apply_file, rollback, ApplyOptions};
use configd::tree::{self, Daemon};
use configd::validate::{self, SkipReason, Validation};
use configd::{render_daemon, ParseError};

const EXIT_OK: u8 = 0;
const EXIT_EXEC: u8 = 1;
const EXIT_USAGE: u8 = 2;
const EXIT_NOTHING: u8 = 3;

enum Command {
    Validate { file: PathBuf },
    Apply { file: PathBuf },
    Rollback,
    Status,
    Render { file: PathBuf, dry_run: bool },
}

struct Cli {
    command: Command,
    run_dir: PathBuf,
    etc_dir: PathBuf,
    daemon_bin_dir: Option<PathBuf>,
}

fn usage() -> String {
    "usage: configd validate <FILE> [--daemon-bin-dir <PATH>]\n\
     \x20      configd apply <FILE> [--run-dir <PATH>] [--etc-dir <PATH>] [--daemon-bin-dir <PATH>]\n\
     \x20      configd rollback [--run-dir <PATH>] [--etc-dir <PATH>]\n\
     \x20      configd status [--run-dir <PATH>]\n\
     \x20      configd render <FILE> [--dry-run] [--etc-dir <PATH>]\n\
     \n\
     defaults: --run-dir /run/rouster, --etc-dir /etc\n\
     daemon binary search: --daemon-bin-dir, $ROUSTER_DAEMON_BIN_DIR,\n\
     \x20                     configd's own dir, then PATH\n\
     exit codes: 0 ok, 1 execution error, 2 usage, 3 nothing to act on"
        .to_string()
}

fn parse_args(argv: &[String]) -> Result<Cli, String> {
    let mut run_dir = None;
    let mut etc_dir = None;
    let mut daemon_bin_dir = None;
    let mut verb = None;
    let mut positional: Vec<String> = Vec::new();
    let mut dry_run = false;
    let mut it = argv.iter();
    while let Some(arg) = it.next() {
        match arg.as_str() {
            "--run-dir" => {
                run_dir = Some(PathBuf::from(it.next().ok_or("--run-dir requires a path")?));
            }
            "--etc-dir" => {
                etc_dir = Some(PathBuf::from(it.next().ok_or("--etc-dir requires a path")?));
            }
            "--daemon-bin-dir" => {
                daemon_bin_dir = Some(PathBuf::from(
                    it.next().ok_or("--daemon-bin-dir requires a path")?,
                ));
            }
            "--dry-run" => dry_run = true,
            "-h" | "--help" => {
                print!("{}", usage());
                std::process::exit(i32::from(EXIT_OK));
            }
            "-V" | "--version" => {
                println!("configd {}", env!("CARGO_PKG_VERSION"));
                std::process::exit(i32::from(EXIT_OK));
            }
            other if other.starts_with('-') => {
                return Err(format!("unknown flag `{other}`"));
            }
            other => {
                if verb.is_none() {
                    verb = Some(other.to_string());
                } else {
                    positional.push(other.to_string());
                }
            }
        }
    }

    let command = match verb.as_deref() {
        Some("validate") => Command::Validate {
            file: PathBuf::from(&positional.first().ok_or("validate requires <FILE>")?),
        },
        Some("apply") => Command::Apply {
            file: PathBuf::from(&positional.first().ok_or("apply requires <FILE>")?),
        },
        Some("rollback") if positional.is_empty() => Command::Rollback,
        Some("status") if positional.is_empty() => Command::Status,
        Some("render") => Command::Render {
            file: PathBuf::from(&positional.first().ok_or("render requires <FILE>")?),
            dry_run,
        },
        Some(other) => return Err(format!("unknown command `{other}`")),
        None => return Err("missing command".to_string()),
    };

    if dry_run && !matches!(command, Command::Render { .. }) {
        return Err("--dry-run is a render flag only".to_string());
    }

    Ok(Cli {
        command,
        run_dir: run_dir.unwrap_or_else(|| PathBuf::from("/run/rouster")),
        etc_dir: etc_dir.unwrap_or_else(|| PathBuf::from("/etc")),
        daemon_bin_dir,
    })
}

fn main() -> ExitCode {
    let argv: Vec<String> = std::env::args().skip(1).collect();
    let cli = match parse_args(&argv) {
        Ok(cli) => cli,
        Err(message) => {
            eprintln!("configd: {message}");
            eprintln!();
            eprint!("{}", usage());
            return ExitCode::from(EXIT_USAGE);
        }
    };
    let opts = ApplyOptions {
        run_dir: cli.run_dir.clone(),
        etc_dir: cli.etc_dir.clone(),
    };
    // The explicit bin-dir rides the env var the library's search
    // reads (apply_file's signature is the e2e-pinned surface; the
    // CLI is single-threaded here, before any library call).
    if let Some(dir) = &cli.daemon_bin_dir {
        std::env::set_var(validate::BIN_DIR_ENV, dir);
    }

    match cli.command {
        Command::Validate { file } => {
            match validate_command(&file, cli.daemon_bin_dir.as_deref()) {
                Ok(()) => ExitCode::from(EXIT_OK),
                Err(err) => {
                    eprintln!("configd: {err}");
                    ExitCode::from(EXIT_EXEC)
                }
            }
        }
        Command::Apply { file } => match apply_file(&file, &opts) {
            Ok(report) => {
                print_report(&report);
                ExitCode::from(EXIT_OK)
            }
            Err(err) => {
                eprintln!("configd: {err}");
                ExitCode::from(EXIT_EXEC)
            }
        },
        Command::Rollback => match rollback(&opts) {
            Ok(report) => {
                print_report(&report);
                ExitCode::from(EXIT_OK)
            }
            Err(err) => {
                eprintln!("configd: {err}");
                match err {
                    configd::ApplyError::NoPrevious { .. } => ExitCode::from(EXIT_NOTHING),
                    _ => ExitCode::from(EXIT_EXEC),
                }
            }
        },
        Command::Status => {
            let path = cli.run_dir.join("configd.status");
            match std::fs::read_to_string(&path) {
                Ok(text) => {
                    print!("{text}");
                    ExitCode::from(EXIT_OK)
                }
                Err(_) => {
                    eprintln!(
                        "configd: no status published ({}) — nothing applied yet",
                        path.display()
                    );
                    ExitCode::from(EXIT_NOTHING)
                }
            }
        }
        Command::Render { file, dry_run } => match render_command(&file, &opts, dry_run) {
            Ok(()) => ExitCode::from(EXIT_OK),
            Err(err) => {
                eprintln!("configd: {err}");
                ExitCode::from(EXIT_EXEC)
            }
        },
    }
}

/// The apply/rollback stdout report: one line per daemon, the
/// generation, and the recorded-not-pushed router-id disclosure.
fn print_report(report: &configd::ApplyReport) {
    for (daemon, verdict) in &report.validations {
        if let Validation::Skipped(why) = verdict {
            let why = match why {
                SkipReason::NoBinary => "no binary found".to_string(),
                SkipReason::NoFlag => "binary predates --validate-config".to_string(),
                SkipReason::SpawnFailed(note) => format!("validator failed: {note}"),
            };
            eprintln!(
                "configd: warning: {}: semantic validation skipped ({why}); \
                 structural validation only",
                daemon.name()
            );
        }
    }
    for (daemon, path, bytes) in &report.rendered {
        let outcome = report
            .outcomes
            .iter()
            .find(|(d, _)| d == daemon)
            .map(|(_, o)| o);
        let mut line = format!(
            "configd: {} -> {} ({} bytes)",
            daemon.name(),
            path.display(),
            bytes
        );
        match outcome {
            Some(configd::DaemonOutcome::Signaled { pid }) => {
                line.push_str(&format!(", SIGHUP {pid}"));
            }
            Some(configd::DaemonOutcome::NotRunning) => {
                line.push_str(", not running (file in place for next start)");
            }
            Some(configd::DaemonOutcome::NoSignalArm) => {
                line.push_str(", no SIGHUP arm (picked up at next start)");
            }
            Some(configd::DaemonOutcome::SignalFailed { note }) => {
                line.push_str(&format!(", SIGHUP FAILED: {note}"));
            }
            None => {}
        }
        println!("{line}");
    }
    if let Some(addr) = report.router_id {
        println!(
            "configd: router-id {addr} recorded (no daemon consumes it in v1; \
             see docs/protocols/config.md)"
        );
    }
    println!(
        "configd: generation {} recorded (hash {})",
        report.generation, report.hash
    );
}

/// `configd validate` (S8-c): parse the canonical file, render each
/// section in memory, and run the owning daemon's own
/// `--validate-config` on the rendered bytes. Nothing is written,
/// nothing is signaled. Exit 0 when every present section validated
/// (skips are honest, not failures); exit 1 on any refusal or on an
/// unreadable/structurally-rejected file.
fn validate_command(
    file: &std::path::Path,
    bin_dir: Option<&std::path::Path>,
) -> Result<(), String> {
    let bytes = std::fs::read(file).map_err(|e| format!("cannot read {}: {e}", file.display()))?;
    let text = std::str::from_utf8(&bytes)
        .map_err(|_| format!("{} is not valid UTF-8", file.display()))?;
    let parsed = tree::parse(text).map_err(|err| format!("canonical file rejected: {err}"))?;
    let dirs = validate::search_dirs(bin_dir);
    let results = validate::validate_canonical(&parsed, &dirs);
    for (daemon, verdict) in &results {
        match verdict {
            Validation::Validated => println!("configd: {}: semantic validation OK", daemon.name()),
            Validation::Skipped(why) => {
                let why = match why {
                    SkipReason::NoBinary => "no binary found".to_string(),
                    SkipReason::NoFlag => "binary predates --validate-config".to_string(),
                    SkipReason::SpawnFailed(note) => format!("validator failed: {note}"),
                };
                println!(
                    "configd: warning: {}: semantic validation skipped ({why}); \
                     structural validation only",
                    daemon.name()
                );
            }
            Validation::Refused { detail } => {
                println!(
                    "configd: {}: REFUSED by the daemon's own parser:",
                    daemon.name()
                );
                for line in detail.lines() {
                    println!("  {line}");
                }
            }
        }
    }
    match validate::refusal_summary(&results) {
        Some(refusal) => Err(format!("semantic validation refused: {refusal}")),
        None => Ok(()),
    }
}

/// `configd render`: parse + render, print (dry-run) or write (no
/// signals, no generation — a staging verb).
fn render_command(
    file: &std::path::Path,
    opts: &ApplyOptions,
    dry_run: bool,
) -> Result<(), String> {
    let bytes = std::fs::read(file).map_err(|e| format!("cannot read {}: {e}", file.display()))?;
    let text = std::str::from_utf8(&bytes)
        .map_err(|_| format!("{} is not valid UTF-8", file.display()))?;
    let parsed = tree::parse(text).map_err(|err| render_parse_error(&err))?;
    for daemon in Daemon::all() {
        if let Some(section) = parsed.section(daemon) {
            let out = render_daemon(section);
            let dest = opts.etc_dir.join(daemon.file_name());
            if dry_run {
                println!(
                    "# {} -> {} ({} bytes)",
                    daemon.name(),
                    dest.display(),
                    out.len()
                );
                print!("{out}");
                if !out.is_empty() && !out.ends_with('\n') {
                    println!();
                }
            } else {
                configd::atomic::write_atomic(&dest, &out)
                    .map_err(|e| format!("cannot write {}: {e}", dest.display()))?;
                println!(
                    "configd: {} -> {} ({} bytes, staged)",
                    daemon.name(),
                    dest.display(),
                    out.len()
                );
            }
        }
    }
    Ok(())
}

/// The parse error with the file's name attached.
fn render_parse_error(err: &ParseError) -> String {
    format!("canonical file rejected: {err}")
}
