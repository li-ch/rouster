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
    /// `show interface [NAME] [--json]` (rousterd's dump).
    ShowInterface { name: Option<String>, json: bool },
    /// `show neighbour [PREFIX] [--json]` (rousterd's dump).
    ShowNeighbour { prefix: Option<String>, json: bool },
    /// `show vrf [--json]` (rousterd's dump).
    ShowVrf { json: bool },
    /// `show rib summary [--json]` (rousterd's dump).
    ShowRibSummary { json: bool },
    /// `status`.
    Status,
    /// `--help` / `-h`.
    Help,
    /// `--version` / `-V`.
    Version,
}

/// Is this command a `show` (the only place `--json` may sit)?
fn is_show(command: &Option<Command>) -> bool {
    matches!(
        command,
        Some(Command::ShowSav { .. })
            | Some(Command::ShowInterface { .. })
            | Some(Command::ShowNeighbour { .. })
            | Some(Command::ShowVrf { .. })
            | Some(Command::ShowRibSummary { .. })
    )
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
/// with subcommands `show sav`, `show interface [NAME]`, `show
/// neighbour [PREFIX]`, `show vrf`, `show rib summary`, and `status`.
/// `--json` is a show-command flag — before the subcommand or on
/// `status` it is a usage error, so the flag's meaning never depends
/// on position.
pub fn parse(argv: &[String]) -> Result<Cli, UsageError> {
    let mut run_dir = PathBuf::from(DEFAULT_RUN_DIR);
    let mut json = false;
    let mut command: Option<Command> = None;
    let mut positional: Option<String> = None;

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
                if is_show(&command) {
                    json = true;
                } else {
                    return Err("`--json` belongs to a `show` subcommand".to_string());
                }
            }
            "show" if command.is_none() => {
                let target = argv.get(index + 1).ok_or_else(|| {
                    "`show` needs a target — v2 has `show sav`, `show interface`, `show neighbour`, `show vrf`, `show rib summary`".to_string()
                })?;
                match target.as_str() {
                    "sav" => command = Some(Command::ShowSav { json: false }),
                    "interface" => command = Some(Command::ShowInterface { name: None, json: false }),
                    "neighbour" => command = Some(Command::ShowNeighbour { prefix: None, json: false }),
                    "vrf" => command = Some(Command::ShowVrf { json: false }),
                    "rib" => {
                        let word = argv.get(index + 2).ok_or_else(|| {
                            "`show rib` needs `summary` in v2".to_string()
                        })?;
                        if word != "summary" {
                            return Err(format!(
                                "unknown show rib form `{word}` — v2 has only `show rib summary`"
                            ));
                        }
                        command = Some(Command::ShowRibSummary { json: false });
                        index += 1;
                    }
                    other => {
                        return Err(format!(
                            "unknown show target `{other}` — v2 has `show sav`, `show interface`, \
                             `show neighbour`, `show vrf`, `show rib summary`"
                        ))
                    }
                }
                index += 1;
            }
            "status" if command.is_none() => command = Some(Command::Status),
            other => {
                if other.starts_with('-') {
                    return Err(format!("unknown flag `{other}`"));
                }
                // The optional positional of `show interface [NAME]`
                // / `show neighbour [PREFIX]` (one only; a second is
                // an error).
                match (&mut command, positional.is_some()) {
                    (Some(Command::ShowInterface { name, .. }), false) => {
                        *name = Some(other.to_string());
                        positional = Some(other.to_string());
                    }
                    (Some(Command::ShowNeighbour { prefix, .. }), false) => {
                        *prefix = Some(other.to_string());
                        positional = Some(other.to_string());
                    }
                    (Some(_), _) => {
                        return Err(format!("unexpected argument `{other}`"));
                    }
                    _ => return Err(format!("unknown subcommand `{other}`")),
                }
            }
        }
        index += 1;
    }

    let command =
        command.ok_or_else(|| "missing subcommand — try `show sav` or `status`".to_string())?;
    let command = match command {
        Command::ShowSav { .. } => Command::ShowSav { json },
        Command::ShowInterface { name, .. } => Command::ShowInterface { name, json },
        Command::ShowNeighbour { prefix, .. } => Command::ShowNeighbour { prefix, json },
        Command::ShowVrf { .. } => Command::ShowVrf { json },
        Command::ShowRibSummary { .. } => Command::ShowRibSummary { json },
        other => other,
    };
    Ok(Cli { run_dir, command })
}

/// The `--help` text: every subcommand, every flag, the exit codes.
pub fn help_text() -> String {
    format!(
        "rousterctl {version} — Rouster operator CLI (v2: read-only run-dir surfaces)

USAGE:
    rousterctl [--run-dir <PATH>] <SUBCOMMAND> [FLAGS]

SUBCOMMANDS:
    show sav [--json]           savd's published status (installed rule set, config,
                                monitor counters) from <run-dir>/savd.status, plus a
                                pid liveness assessment
    show interface [NAME]       the interface table rousterd mirrors (name, ifindex,
                                flags, addresses, VRF membership) from
                                <run-dir>/rousterd.status
    show neighbour [PREFIX]     the ARP/NDP mirror; PREFIX filters (bare address or
                                CIDR, either family) from <run-dir>/rousterd.status
    show vrf                    VRF devices: bound table, member interfaces, counts
                                from <run-dir>/rousterd.status
    show rib summary            per-table route/prefix/connected/kernel counts with
                                VRF associations from <run-dir>/rousterd.status
    status                      run-dir inventory: savd and rousterd running vs stale

FLAGS:
    --run-dir <PATH>    run dir to inspect (default {default_run_dir})
    --json              show commands only: emit one machine-readable object
    --help, -h          this help
    --version, -V       print the version

EXIT CODES:
    0 ok, 2 usage, 3 not found (no status published, or a filter that
    names nothing), 4 not running (stale files naming a dead pid)

Surfaces are read-only; rousterctl never writes the run dir.
",
        version = crate::VERSION,
        default_run_dir = DEFAULT_RUN_DIR,
    )
}
