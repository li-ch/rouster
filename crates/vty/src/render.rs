//! The `show` command renderers — Cisco-flavored output over the
//! run-dir contract, with honest missing/stale reporting (`%`
//! complaint lines, the vty convention for errors and cautions).
//!
//! Sources: `savd.status`/`savd.pid` and `bfdd.status`/`bfdd.pid`
//! under the run dir — file reads only, the contract
//! `docs/operator-surfaces.md` pins. A missing file is an honest
//! one-line complaint, never a fabricated answer; a dead pid still
//! renders the file (it is the last-known record) with a stale
//! footer, mirroring rousterctl's exit-4 semantics in text form.

use std::path::Path;

use crate::bfdparse::BfdStatus;
use crate::liveness::{pid_state, read_pidfile, PidState};
use crate::savparse::SavStatus;
use crate::session::Session;

/// `show version`: who we are, where we listen, what we read.
pub fn show_version(session: &Session) -> Vec<String> {
    let uptime = session.info.started.elapsed().as_secs();
    vec![
        format!(
            "Rouster vtyd {} — vtysh-compatible VTY server",
            crate::VERSION
        ),
        format!("Hostname: {}", session.hostname),
        format!(
            "VTY: {}:{} (plain TCP line protocol, v1 disclosure)",
            session.info.bind, session.info.port
        ),
        format!("Run dir: {}", session.info.run_dir.display()),
        format!("Uptime: {uptime}s  pid {}", session.info.pid),
        "`?` for help, `list` for commands, `exit` to close".into(),
    ]
}

/// `show sav [rules]`: re-render `savd.status` with a liveness
/// assessment (pidfile first — the daemon's live word — then the
/// pid the status file itself records).
pub fn show_sav(run_dir: &Path, rules_only: bool) -> Vec<String> {
    let path = run_dir.join("savd.status");
    let Ok(text) = std::fs::read_to_string(&path) else {
        return vec![format!("% No savd status published at {}", path.display())];
    };
    let parsed = SavStatus::parse(&text);
    let pid = read_pidfile(&run_dir.join("savd.pid")).or(parsed.pid);
    let state = pid.map(pid_state).unwrap_or(PidState::Unknown);
    let mut out = Vec::new();
    if !rules_only {
        let pid_text = pid.map(|p| p.to_string()).unwrap_or_else(|| "?".into());
        out.push(format!(
            "savd {}  pid {pid_text}  {}",
            parsed.version.as_deref().unwrap_or("?"),
            state.assessment()
        ));
        out.push(render_sav_config(&parsed));
        match (parsed.installed_claim, parsed.evaluated) {
            (Some(count), Some(false)) => {
                out.push(format!("installed {count} rules (never evaluated)"))
            }
            (Some(count), _) => out.push(format!("installed {count} rules")),
            (None, _) => out.push("installed ? rules".into()),
        }
    }
    if !parsed.rules.is_empty() {
        if !rules_only {
            out.push(String::new());
        }
        out.extend(render_sav_table(&parsed.rules));
    } else if rules_only {
        out.push("(no rules installed)".into());
    }
    if !rules_only {
        out.push(String::new());
        out.push(render_sav_monitor(&parsed));
        if parsed.unknown_lines > 0 {
            out.push(format!(
                "({} unrecognized line{} — the daemon's format is newer than this vty)",
                parsed.unknown_lines,
                if parsed.unknown_lines == 1 { "" } else { "s" },
            ));
        }
    }
    if state == PidState::Dead {
        let pid_text = pid.map(|p| p.to_string()).unwrap_or_else(|| "?".into());
        out.push(format!(
            "% savd pid {pid_text} is not running — this is the last-known record (stale run-dir files)"
        ));
    }
    out
}

/// The `config` line, re-rendered from what was recognized.
fn render_sav_config(parsed: &SavStatus) -> String {
    let mut out = String::from("config");
    if let Some(mode) = &parsed.config.mode {
        out.push_str(&format!("  mode {mode}"));
    }
    if let Some(action) = &parsed.config.action {
        out.push_str(&format!("  action {action}"));
    }
    if let Some(secs) = parsed.config.poll_secs {
        out.push_str(&format!("  poll {secs}s"));
    }
    if let Some(interfaces) = parsed.config.interfaces {
        out.push_str(&format!("  interfaces {interfaces}"));
    }
    if let Some(bindings) = parsed.config.bindings {
        out.push_str(&format!("  bindings {bindings}"));
    }
    out
}

/// The `monitor` line, re-rendered from what was recognized.
fn render_sav_monitor(parsed: &SavStatus) -> String {
    let mut out = String::from("monitor");
    if let Some(source) = &parsed.monitor.source {
        out.push_str(&format!("  source {source}"));
    }
    if let Some(invalid) = parsed.monitor.invalid {
        out.push_str(&format!("  invalid={invalid}"));
    }
    if let Some(valid) = parsed.monitor.valid {
        out.push_str(&format!("  valid={valid}"));
    }
    if let Some(unknown) = parsed.monitor.unknown {
        out.push_str(&format!("  unknown={unknown}"));
    }
    out
}

/// The aligned rule table (two-space gutters; `-` marks a cell the
/// op shape does not carry).
fn render_sav_table(rules: &[crate::savparse::SavRule]) -> Vec<String> {
    let headers = ["IDX", "POLARITY", "TARGET", "MEMBERS", "URPF", "ACTION"];
    let rows: Vec<[String; 6]> = rules
        .iter()
        .enumerate()
        .map(|(index, rule)| {
            let cells = rule.cells();
            [
                (index + 1).to_string(),
                dash(&cells[0]),
                dash(&cells[1]),
                dash(&cells[2]),
                dash(&cells[3]),
                dash(&cells[4]),
            ]
        })
        .collect();
    align_table(&headers, &rows)
}

/// `-` for the empty cells a rule shape does not carry.
fn dash(cell: &str) -> String {
    if cell.is_empty() {
        "-".into()
    } else {
        cell.to_string()
    }
}

/// `show bfd [summary]`: re-render `bfdd.status` with a liveness
/// assessment.
pub fn show_bfd(run_dir: &Path, summary_only: bool) -> Vec<String> {
    let path = run_dir.join("bfdd.status");
    let Ok(text) = std::fs::read_to_string(&path) else {
        return vec![format!("% No bfdd status published at {}", path.display())];
    };
    let parsed = BfdStatus::parse(&text);
    let pid = read_pidfile(&run_dir.join("bfdd.pid")).or(parsed.pid);
    let state = pid.map(pid_state).unwrap_or(PidState::Unknown);
    let pid_text = pid.map(|p| p.to_string()).unwrap_or_else(|| "?".into());
    let mut out = Vec::new();
    if summary_only {
        out.push(format!(
            "bfdd {}  pid {pid_text}  {}",
            parsed.version.as_deref().unwrap_or("?"),
            state.assessment()
        ));
        match (parsed.peers_claim, parsed.sessions.len()) {
            (Some(claim), listed) if claim as usize != listed => {
                out.push(format!("peers {claim} ({listed} listed)"));
            }
            (Some(claim), _) => out.push(format!("peers {claim}")),
            (None, listed) => out.push(format!("peers {listed} (listed)")),
        }
        let mut counts: Vec<(String, usize)> = Vec::new();
        for session in &parsed.sessions {
            let state = session.state.clone().unwrap_or_else(|| "?".into());
            match counts.iter_mut().find(|(name, _)| *name == state) {
                Some((_, count)) => *count += 1,
                None => counts.push((state, 1)),
            }
        }
        counts.sort();
        if counts.is_empty() {
            out.push("states (none)".into());
        } else {
            let rendered: Vec<String> = counts
                .iter()
                .map(|(state, count)| format!("{state} {count}"))
                .collect();
            out.push(format!("states {}", rendered.join("  ")));
        }
    } else {
        out.push(format!(
            "bfdd {}  pid {pid_text}  {}",
            parsed.version.as_deref().unwrap_or("?"),
            state.assessment()
        ));
        out.push(format!(
            "peers {}",
            parsed.peers_claim.unwrap_or(parsed.sessions.len() as u64)
        ));
        if !parsed.sessions.is_empty() {
            out.push(String::new());
        }
        for session in &parsed.sessions {
            out.push(format!(
                "session peer {} state {} diag {} local-discr {} remote-discr {} detection-time {}ms tx-interval {}ms",
                session.peer.as_deref().unwrap_or("?"),
                session.state.as_deref().unwrap_or("?"),
                session.diag.map(|d| d.to_string()).unwrap_or_else(|| "?".into()),
                session.local_discr.map(|d| d.to_string()).unwrap_or_else(|| "?".into()),
                session.remote_discr.map(|d| d.to_string()).unwrap_or_else(|| "?".into()),
                session.detection_time_ms.map(|d| d.to_string()).unwrap_or_else(|| "?".into()),
                session.tx_interval_ms.map(|d| d.to_string()).unwrap_or_else(|| "?".into()),
            ));
            if let Some(transition) = &session.last_transition {
                out.push(format!("  last-transition {transition}"));
            }
        }
        if parsed.unknown_lines > 0 {
            out.push(format!(
                "({} unrecognized line{} — the daemon's format is newer than this vty)",
                parsed.unknown_lines,
                if parsed.unknown_lines == 1 { "" } else { "s" },
            ));
        }
    }
    if state == PidState::Dead {
        out.push(format!(
            "% bfdd pid {pid_text} is not running — this is the last-known record (stale run-dir files)"
        ));
    }
    out
}

/// Column-aligned table rendering (two-space gutters).
fn align_table(headers: &[&str], rows: &[[String; 6]]) -> Vec<String> {
    let widths: Vec<usize> = (0..headers.len())
        .map(|column| {
            rows.iter()
                .map(|row| row[column].len())
                .chain([headers[column].len()])
                .max()
                .unwrap_or(0)
        })
        .collect();
    let mut out = Vec::new();
    let header_cells: Vec<String> = headers
        .iter()
        .enumerate()
        .map(|(column, header)| format!("{header:<width$}", width = widths[column]))
        .collect();
    out.push(header_cells.join("  "));
    for row in rows {
        let cells: Vec<String> = row
            .iter()
            .enumerate()
            .map(|(column, cell)| format!("{cell:<width$}", width = widths[column]))
            .collect();
        out.push(cells.join("  "));
    }
    out
}
