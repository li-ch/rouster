//! Wiring: run-dir files → operator answers → exit codes.
//!
//! Exit codes (the v2 contract, see docs/operator-surfaces.md):
//! `0` ok · `2` usage · `3` not found (no status published, or a
//! filter that names nothing) · `4` not running (stale files naming
//! a dead pid).

use std::path::{Path, PathBuf};

use crate::args::{self, Cli, Command};
use crate::liveness::{pid_state, PidState};
use crate::rousterd::RousterdStatus;
use crate::status::SavStatus;

/// Everything went fine.
pub const EXIT_OK: u8 = 0;
/// Bad command line.
pub const EXIT_USAGE: u8 = 2;
/// A needed run-dir file does not exist.
pub const EXIT_NOT_FOUND: u8 = 3;
/// Run-dir files name a daemon that is no longer running.
pub const EXIT_NOT_RUNNING: u8 = 4;

/// Runs one invocation and returns its exit code. Output goes to
/// stdout (answers) and stderr (complaints), like an operator tool.
pub fn dispatch(cli: &Cli) -> u8 {
    match &cli.command {
        Command::Help => {
            print!("{}", args::help_text());
            EXIT_OK
        }
        Command::Version => {
            println!("{}", crate::VERSION);
            EXIT_OK
        }
        Command::ShowSav { json } => show_sav(&cli.run_dir, *json),
        Command::ShowInterface { name, json } => {
            show_rousterd(&cli.run_dir, *json, &RdView::Interface(name.clone()))
        }
        Command::ShowNeighbour { prefix, json } => {
            if let Some(prefix) = prefix {
                if !crate::rousterd::valid_filter(prefix) {
                    eprintln!(
                        "rousterctl: bad prefix filter `{prefix}` — want A.B.C.D[/M] or X:X::X:X[/M]"
                    );
                    return EXIT_USAGE;
                }
            }
            show_rousterd(&cli.run_dir, *json, &RdView::Neighbour(prefix.clone()))
        }
        Command::ShowVrf { json } => show_rousterd(&cli.run_dir, *json, &RdView::Vrf),
        Command::ShowRibSummary { json } => show_rousterd(&cli.run_dir, *json, &RdView::RibSummary),
        Command::Status => status(&cli.run_dir),
    }
}

/// Which rousterd-dump view a `show` command asked for.
enum RdView {
    Interface(Option<String>),
    Neighbour(Option<String>),
    Vrf,
    RibSummary,
}

impl RdView {
    /// Did the view's filter name nothing? (Exit 3: the asked-for
    /// thing is not in the published state.) An unfiltered view is
    /// never a miss — an empty table is a fine answer.
    fn is_miss(&self, parsed: &RousterdStatus) -> bool {
        match self {
            RdView::Interface(name) => name
                .as_deref()
                .is_some_and(|name| parsed.interfaces_matching(Some(name)).is_empty()),
            RdView::Neighbour(prefix) => prefix
                .as_deref()
                .is_some_and(|prefix| parsed.neighbours_matching(Some(prefix)).is_empty()),
            _ => false,
        }
    }

    fn render_terminal(&self, parsed: &RousterdStatus) -> String {
        match self {
            RdView::Interface(name) => parsed.render_interfaces(name.as_deref()),
            RdView::Neighbour(prefix) => parsed.render_neighbours(prefix.as_deref()),
            RdView::Vrf => parsed.render_vrfs(),
            RdView::RibSummary => parsed.render_rib_summary(),
        }
    }

    fn render_json(&self, parsed: &RousterdStatus, state: PidState) -> String {
        match self {
            RdView::Interface(name) => parsed.render_interfaces_json(state, name.as_deref()),
            RdView::Neighbour(prefix) => parsed.render_neighbours_json(state, prefix.as_deref()),
            RdView::Vrf => parsed.render_vrfs_json(state),
            RdView::RibSummary => parsed.render_rib_summary_json(state),
        }
    }
}

/// The shared rousterd-dump leg: read the file (3 when missing),
/// assess liveness from the pid the header records (rousterd has no
/// pidfile — the header is its live word), render terminal or JSON,
/// exit 3 on a filter that names nothing, and 4 on a dead pid (the
/// file is the last-known record).
fn show_rousterd(run_dir: &Path, json: bool, view: &RdView) -> u8 {
    let status_path = run_dir.join("rousterd.status");
    let text = match std::fs::read_to_string(&status_path) {
        Ok(text) => text,
        Err(err) => {
            eprintln!(
                "rousterctl: no rousterd status published at {} ({err})",
                status_path.display()
            );
            return EXIT_NOT_FOUND;
        }
    };
    let parsed = RousterdStatus::parse(&text);
    let state = parsed.pid.map(pid_state).unwrap_or(PidState::Unknown);
    if json {
        println!("{}", view.render_json(&parsed, state));
    } else {
        print!(
            "{}{}",
            join_lines(&parsed.header_lines(state)),
            view.render_terminal(&parsed)
        );
        if parsed.unknown_lines > 0 {
            print!("{}", parsed.unknown_disclosure());
        }
    }
    if state == PidState::Dead {
        let pid = parsed
            .pid
            .map(|p| p.to_string())
            .unwrap_or_else(|| "?".into());
        eprintln!(
            "rousterctl: rousterd pid {pid} is not running — \
             this is the last-known record (stale run-dir files)"
        );
        return EXIT_NOT_RUNNING;
    }
    if view.is_miss(&parsed) {
        return EXIT_NOT_FOUND;
    }
    EXIT_OK
}

/// Join rendered header lines (each already newline-free) into the
/// terminal block.
fn join_lines(lines: &[String]) -> String {
    let mut out = String::new();
    for line in lines {
        out.push_str(line);
        out.push('\n');
    }
    out
}

/// `show sav`: render the published status; assess liveness from the
/// pidfile first (the daemon's live word), falling back to the pid
/// the status file itself records. A dead pid still renders — the
/// file is the last-known record — but exits 4 so scripts can tell.
fn show_sav(run_dir: &Path, json: bool) -> u8 {
    let status_path = run_dir.join("savd.status");
    let text = match std::fs::read_to_string(&status_path) {
        Ok(text) => text,
        Err(err) => {
            eprintln!(
                "rousterctl: no savd status published at {} ({err})",
                status_path.display()
            );
            return EXIT_NOT_FOUND;
        }
    };
    let parsed = SavStatus::parse(&text);
    let pid = read_pidfile(run_dir).or(parsed.pid);
    let state = match pid {
        Some(pid) => pid_state(pid),
        None => PidState::Unknown,
    };
    if json {
        println!("{}", parsed.render_json(state));
    } else {
        print!("{}", parsed.render_terminal(state));
    }
    if state == PidState::Dead {
        let pid = pid.map(|p| p.to_string()).unwrap_or_else(|| "?".into());
        eprintln!(
            "rousterctl: savd pid {pid} is not running — \
             this is the last-known record (stale run-dir files)"
        );
        return EXIT_NOT_RUNNING;
    }
    EXIT_OK
}

/// `status`: inventory the run dir — what is running vs stale. Stale
/// savd files (a dead pid) exit 4; nothing running at all is a fine
/// answer and exits 0.
fn status(run_dir: &Path) -> u8 {
    println!("run-dir {}", run_dir.display());
    if !run_dir.is_dir() {
        println!("  (absent)");
    }
    let mut exit = EXIT_OK;

    let pid = read_pidfile(run_dir);
    let has_status = run_dir.join("savd.status").is_file();
    match pid {
        Some(pid) => match pid_state(pid) {
            PidState::Running => {
                if has_status {
                    let rules = std::fs::read_to_string(run_dir.join("savd.status"))
                        .ok()
                        .map(|text| {
                            let parsed = SavStatus::parse(&text);
                            parsed.installed_claim.unwrap_or(parsed.rules.len() as u64)
                        })
                        .unwrap_or(0);
                    println!("savd     pid {pid} running, status published ({rules} rules)");
                } else {
                    println!(
                        "savd     pid {pid} running, no status published yet \
                         (never evaluated)"
                    );
                }
            }
            PidState::Dead => {
                println!(
                    "savd     pid {pid} DEAD — stale run-dir files \
                     (pidfile/status are the last-known record)"
                );
                exit = EXIT_NOT_RUNNING;
            }
            PidState::Unknown => {
                println!("savd     pid {pid} present, liveness unknown (probe failed)");
            }
        },
        None => {
            if has_status {
                exit = status_without_pidfile(run_dir);
            } else {
                println!("savd     not running (no pidfile, no status file)");
            }
        }
    }

    // The rousterd leg: assessable since the status dump's header
    // pid (no pidfile contract yet — the header is the live word).
    // Without a dump, the v1 fallback stands: list socket candidates
    // and disclose that liveness is not knowable.
    let dump = run_dir.join("rousterd.status");
    if dump.is_file() {
        let parsed = std::fs::read_to_string(&dump)
            .ok()
            .map(|text| RousterdStatus::parse(&text));
        match parsed.as_ref().and_then(|parsed| parsed.pid) {
            Some(pid) => match pid_state(pid) {
                PidState::Running => {
                    let parsed = parsed.as_ref().expect("pid came from this parse");
                    println!(
                        "rousterd  pid {pid} running, dump published \
                         ({} interfaces, {} neighbours, {} table{})",
                        parsed.interfaces.len(),
                        parsed.neighbours.len(),
                        parsed.tables.len(),
                        if parsed.tables.len() == 1 { "" } else { "s" },
                    );
                }
                PidState::Dead => {
                    println!(
                        "rousterd  pid {pid} DEAD — stale dump \
                         (the last-known record)"
                    );
                    exit = exit.max(EXIT_NOT_RUNNING);
                }
                PidState::Unknown => {
                    println!("rousterd  pid {pid} present, liveness unknown (probe failed)");
                }
            },
            None => {
                println!("rousterd  dump present, no pid recorded");
            }
        }
    } else {
        let sockets = socket_candidates(run_dir);
        if sockets.is_empty() {
            println!(
                "rousterd  no dump and no zapi socket in the run dir \
                 (not running, or an older rousterd without the status writer)"
            );
        } else {
            for socket in sockets {
                println!(
                    "rousterd  zapi socket {} present \
                     (no status dump — older rousterd, liveness not knowable)",
                    socket.display()
                );
            }
        }
    }
    exit
}

/// The no-pidfile branch of the savd inventory: assess via the pid
/// the status file itself records.
fn status_without_pidfile(run_dir: &Path) -> u8 {
    let recorded = std::fs::read_to_string(run_dir.join("savd.status"))
        .ok()
        .and_then(|text| SavStatus::parse(&text).pid);
    match recorded {
        Some(pid) => match pid_state(pid) {
            PidState::Dead => {
                println!(
                    "savd     status file says pid {pid}, which is DEAD — \
                     stale (pidfile missing)"
                );
                EXIT_NOT_RUNNING
            }
            PidState::Running => {
                println!("savd     status file says pid {pid} (running; pidfile missing)");
                EXIT_OK
            }
            PidState::Unknown => {
                println!("savd     status file says pid {pid} (liveness unknown)");
                EXIT_OK
            }
        },
        None => {
            println!("savd     status file present, no pid recorded");
            EXIT_OK
        }
    }
}

/// The pid the pidfile names (first line), if it is a number.
fn read_pidfile(run_dir: &Path) -> Option<u32> {
    let text = std::fs::read_to_string(run_dir.join("savd.pid")).ok()?;
    text.lines().next()?.trim().parse().ok()
}

/// Socket files in the run dir (rousterd zapi candidates). There is
/// no canonical socket name yet — anything that IS a socket, or is
/// named like one, is listed.
fn socket_candidates(run_dir: &Path) -> Vec<PathBuf> {
    let mut found = Vec::new();
    let Ok(entries) = std::fs::read_dir(run_dir) else {
        return found;
    };
    for entry in entries.flatten() {
        let name = entry.file_name();
        let name = name.to_string_lossy();
        let is_socket = entry
            .file_type()
            .map(|file_type| file_type_is_socket(&file_type))
            .unwrap_or(false);
        if is_socket || name.ends_with(".sock") {
            found.push(entry.path());
        }
    }
    found.sort();
    found
}

/// `FileType::is_socket` where it exists (every platform v1 targets).
fn file_type_is_socket(file_type: &std::fs::FileType) -> bool {
    #[cfg(unix)]
    {
        use std::os::unix::fs::FileTypeExt;
        file_type.is_socket()
    }
    #[cfg(not(unix))]
    {
        let _ = file_type;
        false
    }
}
