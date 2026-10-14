//! The configd status file (Phase 4, M3): `<run-dir>/configd.status`,
//! the house line-based format — keyword-led lines, one fact per
//! line, tolerant to read (unknown lines dropped, known keywords
//! picked wherever they sit), never guessing.
//!
//! ```text
//! configd 0.0.0
//! generation 2 1a2b3c4d5e6f7088
//! applied 1790000123
//! source /root/rouster.conf
//! router-id 198.51.100.1          (or: router-id none)
//! daemons 3
//! daemon rousterd file /etc/rouster.conf bytes 38 pid 4242 result signaled ack no-ack-surface
//! daemon savd file /etc/savd.conf bytes 18 pid 4243 result signaled ack confirmed
//! daemon bfdd file /etc/bfdd.conf bytes 15 result not-running
//! ```
//!
//! `applied` is Unix seconds (no date math without a dependency; the
//! fence holds). The hash is the FNV-1a change fingerprint of the
//! canonical bytes. `result` is the **actuation record** — what
//! configd did — NOT the daemon's acceptance; `ack` (S8-c M3) is the
//! acceptance half: the post-signal verification verdict for each
//! SIGNALED daemon (`confirmed` / `failed` / `unverified` /
//! `no-status`, or `no-ack-surface` for a signaled daemon that
//! publishes nothing config-shaped today — rousterd). A `failed` ack
//! never appears in a published status file: it triggers the
//! auto-rollback, and the published file describes the revert.
//!
//! `configd status` prints this file verbatim (the `savd --show`
//! shape); [`parse_status`] is the tolerant reader for tooling and
//! tests.

use std::path::Path;

use crate::apply::{ApplyOptions, ApplyReport, DaemonOutcome};

/// Renders the status file text for an apply report.
pub fn render_status(report: &ApplyReport, opts: &ApplyOptions) -> String {
    let mut out = String::new();
    out.push_str(&format!("configd {}\n", env!("CARGO_PKG_VERSION")));
    out.push_str(&format!(
        "generation {} {}\n",
        report.generation, report.hash
    ));
    out.push_str(&format!("applied {}\n", report.applied_unix));
    out.push_str(&format!("source {}\n", report.source.render_status_word()));
    match report.router_id {
        Some(addr) => out.push_str(&format!("router-id {addr}\n")),
        None => out.push_str("router-id none\n"),
    }
    out.push_str(&format!(
        "run-dir {}\netc-dir {}\n",
        opts.run_dir.display(),
        opts.etc_dir.display()
    ));
    out.push_str(&format!("daemons {}\n", report.outcomes.len()));
    for (daemon, path, bytes) in &report.rendered {
        let outcome = report
            .outcomes
            .iter()
            .find(|(d, _)| d == daemon)
            .map(|(_, o)| o);
        let mut line = format!(
            "daemon {} file {} bytes {}",
            daemon.name(),
            path.display(),
            bytes
        );
        match outcome {
            Some(DaemonOutcome::Signaled { pid }) => {
                line.push_str(&format!(" pid {pid}"));
            }
            Some(DaemonOutcome::SignalFailed { note }) => {
                line.push_str(&format!(" note {note}"));
            }
            _ => {}
        }
        if let Some(outcome) = outcome {
            line.push_str(&format!(" result {}", outcome.word()));
        }
        // S8-c M3: the post-signal verification verdict, when the
        // daemon was signaled and this reader's writer recorded one
        // (older status files simply lack the word).
        if let Some((_, ack)) = report.acks.iter().find(|(d, _)| d == daemon) {
            line.push_str(&format!(" ack {}", ack.word()));
        }
        out.push_str(line.trim_end());
        out.push('\n');
    }
    out
}

/// The tolerant reader's shape: the facts tooling needs, unpicked
/// from wherever they sit on their lines.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct ConfigdStatus {
    pub generation: Option<u64>,
    pub hash: Option<String>,
    pub applied_unix: Option<u64>,
    pub source: Option<String>,
    pub router_id: Option<String>,
    /// One entry per `daemon` line: (name, result word).
    pub daemons: Vec<(String, String)>,
    /// Post-signal verification verdicts (S8-c M3), when present:
    /// (name, ack word). Older status files have none.
    pub acks: Vec<(String, String)>,
    /// How many lines matched nothing this reader knows.
    pub unknown_lines: usize,
}

/// Parses a configd.status (never fails; missing facts stay `None`).
pub fn parse_status(text: &str) -> ConfigdStatus {
    let mut status = ConfigdStatus::default();
    for raw in text.lines() {
        let line = raw.trim();
        if line.is_empty() {
            continue;
        }
        let tokens: Vec<&str> = line.split_whitespace().collect();
        match tokens.as_slice() {
            ["generation", seq, hash, ..] => {
                status.generation = seq.parse().ok();
                status.hash = Some((*hash).to_string());
            }
            ["applied", secs] => {
                status.applied_unix = secs.strip_suffix('s').unwrap_or(secs).parse().ok();
            }
            ["source", rest @ ..] if !rest.is_empty() => {
                status.source = Some(rest.join(" "));
            }
            ["router-id", addr] => {
                status.router_id = Some((*addr).to_string());
            }
            ["daemons", _count] => {}
            ["daemon", name, rest @ ..] => {
                // The result word sits at the line end (`result <word>`);
                // the S8-c ack word may follow it (`ack <word>`).
                if let Some(pos) = rest.iter().position(|t| *t == "result") {
                    if let Some(word) = rest.get(pos + 1) {
                        status
                            .daemons
                            .push(((*name).to_string(), (*word).to_string()));
                        if let Some(ack) = rest
                            .iter()
                            .position(|t| *t == "ack")
                            .and_then(|p| rest.get(p + 1))
                        {
                            status.acks.push(((*name).to_string(), (*ack).to_string()));
                        }
                        continue;
                    }
                }
                status
                    .daemons
                    .push(((*name).to_string(), String::from("unknown")));
            }
            ["configd", ..] | ["run-dir", ..] | ["etc-dir", ..] => {}
            _ => status.unknown_lines += 1,
        }
    }
    status
}

/// Reads and parses the status file at `run-dir/configd.status`.
pub fn read(run_dir: &Path) -> Option<ConfigdStatus> {
    let text = std::fs::read_to_string(run_dir.join("configd.status")).ok()?;
    Some(parse_status(&text))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::apply::{DaemonOutcome, RollbackSource};
    use crate::tree::Daemon;
    use std::net::Ipv4Addr;
    use std::path::PathBuf;

    fn sample_report() -> (ApplyReport, ApplyOptions) {
        let report = ApplyReport {
            generation: 2,
            hash: "1a2b3c4d5e6f7088".to_string(),
            applied_unix: 1_790_000_123,
            source: RollbackSource::File(PathBuf::from("/root/rouster.conf")),
            router_id: Some("198.51.100.1".parse::<Ipv4Addr>().unwrap()),
            outcomes: vec![
                (Daemon::Rousterd, DaemonOutcome::Signaled { pid: 4242 }),
                (Daemon::Savd, DaemonOutcome::Signaled { pid: 4243 }),
                (Daemon::Bfdd, DaemonOutcome::NotRunning),
            ],
            acks: vec![
                (Daemon::Rousterd, crate::verify::Ack::NoSurface),
                (Daemon::Savd, crate::verify::Ack::Confirmed),
            ],
            validations: vec![
                (Daemon::Rousterd, crate::validate::Validation::Validated),
                (Daemon::Savd, crate::validate::Validation::Validated),
                (
                    Daemon::Bfdd,
                    crate::validate::Validation::Skipped(crate::validate::SkipReason::NoBinary),
                ),
            ],
            rendered: vec![
                (Daemon::Rousterd, PathBuf::from("/etc/rouster.conf"), 38),
                (Daemon::Savd, PathBuf::from("/etc/savd.conf"), 18),
                (Daemon::Bfdd, PathBuf::from("/etc/bfdd.conf"), 15),
            ],
        };
        let opts = ApplyOptions {
            run_dir: PathBuf::from("/run/rouster"),
            etc_dir: PathBuf::from("/etc"),
        };
        (report, opts)
    }

    #[test]
    fn renders_the_house_line_format() {
        let (report, opts) = sample_report();
        let text = render_status(&report, &opts);
        assert_eq!(
            text,
            "configd 0.0.0\n\
             generation 2 1a2b3c4d5e6f7088\n\
             applied 1790000123\n\
             source /root/rouster.conf\n\
             router-id 198.51.100.1\n\
             run-dir /run/rouster\n\
             etc-dir /etc\n\
             daemons 3\n\
             daemon rousterd file /etc/rouster.conf bytes 38 pid 4242 result signaled ack no-ack-surface\n\
             daemon savd file /etc/savd.conf bytes 18 pid 4243 result signaled ack confirmed\n\
             daemon bfdd file /etc/bfdd.conf bytes 15 result not-running\n"
        );
    }

    #[test]
    fn router_id_none_renders() {
        let (mut report, opts) = sample_report();
        report.router_id = None;
        assert!(render_status(&report, &opts).contains("router-id none\n"));
    }

    #[test]
    fn round_trip_parse_picks_the_facts() {
        let (report, opts) = sample_report();
        let parsed = parse_status(&render_status(&report, &opts));
        assert_eq!(parsed.generation, Some(2));
        assert_eq!(parsed.hash.as_deref(), Some("1a2b3c4d5e6f7088"));
        assert_eq!(parsed.applied_unix, Some(1_790_000_123));
        assert_eq!(parsed.source.as_deref(), Some("/root/rouster.conf"));
        assert_eq!(parsed.router_id.as_deref(), Some("198.51.100.1"));
        assert_eq!(
            parsed.daemons,
            vec![
                ("rousterd".to_string(), "signaled".to_string()),
                ("savd".to_string(), "signaled".to_string()),
                ("bfdd".to_string(), "not-running".to_string()),
            ]
        );
        assert_eq!(
            parsed.acks,
            vec![
                ("rousterd".to_string(), "no-ack-surface".to_string()),
                ("savd".to_string(), "confirmed".to_string()),
            ]
        );
        assert_eq!(parsed.unknown_lines, 0);
    }

    #[test]
    fn parse_is_tolerant_to_growth_and_garbage() {
        // Added fields ride along; unknown lines are counted, not
        // fatal; malformed numbers leave fields unset.
        let text = "configd 9.9.9 extra\n\
                    generation 7 deadbeef12345678 new-field x\n\
                    applied notanumber\n\
                    source rollback of generation 6\n\
                    brand new line shape\n\
                    another one\n\
                    daemon ospfd file /etc/ospfd.conf bytes 4 result no-signal-arm\n";
        let parsed = parse_status(text);
        assert_eq!(parsed.generation, Some(7));
        assert_eq!(parsed.hash.as_deref(), Some("deadbeef12345678"));
        assert_eq!(parsed.applied_unix, None);
        assert_eq!(parsed.source.as_deref(), Some("rollback of generation 6"));
        assert_eq!(parsed.unknown_lines, 2);
        assert_eq!(
            parsed.daemons.last(),
            Some(&("ospfd".to_string(), "no-signal-arm".to_string()))
        );
    }

    #[test]
    fn daemon_line_without_result_word_is_unknown_not_fatal() {
        let parsed = parse_status("daemon savd file /etc/savd.conf bytes 5\n");
        assert_eq!(
            parsed.daemons,
            vec![("savd".to_string(), "unknown".to_string())]
        );
    }

    #[test]
    fn read_from_disk_round_trip() {
        let dir = std::env::temp_dir().join(format!("configd-status-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("configd.status"), "generation 3 abc\n").unwrap();
        let parsed = read(&dir).unwrap();
        assert_eq!(parsed.generation, Some(3));
        assert!(read(Path::new("/nonexistent-configd-dir")).is_none());
        let _ = std::fs::remove_dir_all(&dir);
    }
}
