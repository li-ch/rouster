//! Command-line parsing — hand-rolled and std-only.
//!
//! v1's grammar is two subcommands and three global flags; a parser
//! dependency would outweigh the problem. If the grammar ever grows
//! past what stays readable here, pulling one in is an owner decision
//! to record, not a patch detail.

use std::path::PathBuf;

/// The run dir every v1 surface reads (the workspace's naming rule).
pub const DEFAULT_RUN_DIR: &str = "/run/rouster";

/// What the operator asked for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Command {
    /// `show sav [--json]`.
    ShowSav { json: bool },
    /// `status`.
    Status,
    /// `--help` / `-h`.
    Help,
    /// `--version` / `-V`.
    Version,
}

/// A parsed invocation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Cli {
    /// Run dir to inspect (default `/run/rouster`).
    pub run_dir: PathBuf,
    /// The subcommand (or help/version).
    pub command: Command,
}

/// Parse failure — always a usage error (exit 2 in [`crate::run`]).
pub type UsageError = String;

/// Parses `argv` (no program name) into a [`Cli`].
///
/// Grammar: `rousterctl [--run-dir <PATH>] <SUBCOMMAND> [FLAGS]`
/// with subcommands `show sav [--json]` and `status`. `--json` is a
/// `show sav` flag — before the subcommand or on `status` it is a
/// usage error, so the flag's meaning never depends on position.
pub fn parse(argv: &[String]) -> Result<Cli, UsageError> {
    let mut run_dir = PathBuf::from(DEFAULT_RUN_DIR);
    let mut json = false;
    let mut command: Option<Command> = None;

    let mut index = 0;
    while index < argv.len() {
        let arg = argv[index].as_str();
        match arg {
            "--help" | "-h" => {
                return Ok(Cli {
                    run_dir,
                    command: Command::Help,
                })
            }
            "--version" | "-V" => {
                return Ok(Cli {
                    run_dir,
                    command: Command::Version,
                })
            }
            "--run-dir" => {
                index += 1;
                let value = argv
                    .get(index)
                    .ok_or_else(|| "--run-dir requires a path".to_string())?;
                run_dir = PathBuf::from(value);
            }
            "--json" => {
                if matches!(command, Some(Command::ShowSav { .. })) {
                    json = true;
                } else {
                    return Err("`--json` belongs to `show sav`".to_string());
                }
            }
            "show" if command.is_none() => {
                let target = argv
                    .get(index + 1)
                    .ok_or_else(|| "`show` needs a target — v1 has only `show sav`".to_string())?;
                if target != "sav" {
                    return Err(format!(
                        "unknown show target `{target}` — v1 has only `show sav`"
                    ));
                }
                command = Some(Command::ShowSav { json: false });
                index += 1;
            }
            "status" if command.is_none() => command = Some(Command::Status),
            other => {
                if other.starts_with('-') {
                    return Err(format!("unknown flag `{other}`"));
                }
                if command.is_some() {
                    return Err(format!("unexpected argument `{other}`"));
                }
                return Err(format!("unknown subcommand `{other}`"));
            }
        }
        index += 1;
    }

    let command =
        command.ok_or_else(|| "missing subcommand — try `show sav` or `status`".to_string())?;
    let command = match command {
        Command::ShowSav { .. } => Command::ShowSav { json },
        other => other,
    };
    Ok(Cli { run_dir, command })
}

/// The `--help` text: every subcommand, every flag, the exit codes.
pub fn help_text() -> String {
    format!(
        "rousterctl {version} — Rouster operator CLI (v1: read-only run-dir surfaces)

USAGE:
    rousterctl [--run-dir <PATH>] <SUBCOMMAND> [FLAGS]

SUBCOMMANDS:
    show sav [--json]   savd's published status (installed rule set, config,
                        monitor counters) from <run-dir>/savd.status, plus a
                        pid liveness assessment
    status              run-dir inventory: savd running vs stale, rousterd
                        zapi sockets if present

FLAGS:
    --run-dir <PATH>    run dir to inspect (default {default_run_dir})
    --json              show sav only: emit one machine-readable object
    --help, -h          this help
    --version, -V       print the version

EXIT CODES:
    0 ok, 2 usage, 3 not found (no status published),
    4 not running (stale files naming a dead pid)

v1 surfaces are read-only; rousterctl never writes the run dir.
",
        version = crate::VERSION,
        default_run_dir = DEFAULT_RUN_DIR,
    )
}
