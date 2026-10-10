//! Tolerant parsing of `bfdd.status` — the S3 conventions applied
//! to the second run-dir publisher (`docs/protocols/bfd.md`
//! "Operator surface (A21)"): one `session` line per peer with
//! state, diagnostic, discriminators, and timings, an indented
//! `last-transition` child line, header `bfdd <version> pid <pid>`
//! and `peers <n>`.
//!
//! ```text
//! bfdd 0.0.0 pid 4711
//! peers 2
//! session peer 192.0.2.2 state Up diag 0 local-discr 1 remote-discr 7 detection-time 900ms tx-interval 300ms
//!   last-transition Up -> Down (Neighbor Signaled Session Down (3), ...)
//! ```
//!
//! Tolerance contract (the daemon's format may grow): unknown
//! top-level lines are counted and dropped; session keywords are
//! picked out wherever they sit, so added fields ride along; a
//! `session` line whose shape is too broken to carry even the peer
//! is counted unknown; indented lines attach to the session above
//! them (bfdd writes `last-transition` children that way). Parsing
//! never fails.

/// One `session` line, keyword-scanned.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct BfdSession {
    /// The peer address (v4 or v6, verbatim).
    pub peer: Option<String>,
    /// The session state (`Up`, `Down`, `Init`, `AdminDown`, ...).
    pub state: Option<String>,
    /// The diagnostic code.
    pub diag: Option<u32>,
    /// Our discriminator.
    pub local_discr: Option<u32>,
    /// The learned remote discriminator.
    pub remote_discr: Option<u32>,
    /// The negotiated detection time.
    pub detection_time_ms: Option<u64>,
    /// The negotiated transmit interval.
    pub tx_interval_ms: Option<u64>,
    /// The indented `last-transition` child line, verbatim.
    pub last_transition: Option<String>,
}

/// A parsed `bfdd.status`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct BfdStatus {
    /// The daemon's version string.
    pub version: Option<String>,
    /// The pid the daemon recorded.
    pub pid: Option<u32>,
    /// The peer count the file claimed.
    pub peers_claim: Option<u64>,
    /// The session lines, in file order.
    pub sessions: Vec<BfdSession>,
    /// How many lines matched nothing this version knows.
    pub unknown_lines: usize,
}

impl BfdStatus {
    /// Parses a status file's content. Never fails.
    pub fn parse(text: &str) -> BfdStatus {
        let mut parsed = BfdStatus::default();
        for line in text.lines() {
            let line = line.trim_end_matches('\r').trim_end();
            if line.is_empty() {
                continue;
            }
            // Indented lines are children of the session above.
            if line.starts_with(' ') || line.starts_with('\t') {
                let body = line.trim();
                if let Some(field) = body.strip_prefix("last-transition ") {
                    if let Some(session) = parsed.sessions.last_mut() {
                        session.last_transition = Some(field.to_string());
                        continue;
                    }
                }
                // An indented line with no session above (or an
                // unknown child) counts unknown.
                parsed.unknown_lines += 1;
                continue;
            }
            let tokens: Vec<&str> = line.split_whitespace().collect();
            match tokens.first().copied() {
                Some("bfdd") => parse_header(&mut parsed, &tokens),
                Some("peers") => parsed.peers_claim = tokens.get(1).and_then(|t| t.parse().ok()),
                Some("session") => {
                    let mut session = BfdSession::default();
                    parse_session_body(&mut session, &tokens[1..]);
                    if session.peer.is_some() || session.state.is_some() {
                        parsed.sessions.push(session);
                    } else {
                        parsed.unknown_lines += 1;
                    }
                }
                _ => parsed.unknown_lines += 1,
            }
        }
        parsed
    }
}

/// Header line: `bfdd <version> pid <pid>`, keyword-picked.
fn parse_header(parsed: &mut BfdStatus, tokens: &[&str]) {
    if let Some(version) = tokens.get(1) {
        if *version != "pid" {
            parsed.version = Some(version.to_string());
        }
    }
    if let Some(position) = tokens.iter().position(|token| *token == "pid") {
        if let Some(value) = tokens.get(position + 1) {
            parsed.pid = value.parse().ok();
        }
    }
}

/// Session body (after `session`): keyword/value pairs scanned
/// wherever they sit.
fn parse_session_body(session: &mut BfdSession, tokens: &[&str]) {
    for (index, token) in tokens.iter().enumerate() {
        let Some(value) = tokens.get(index + 1) else {
            break;
        };
        match *token {
            "peer" => session.peer = Some(value.to_string()),
            "state" => session.state = Some(value.to_string()),
            "diag" => session.diag = value.parse().ok(),
            "local-discr" => session.local_discr = value.parse().ok(),
            "remote-discr" => session.remote_discr = value.parse().ok(),
            "detection-time" => {
                session.detection_time_ms = value.strip_suffix("ms").unwrap_or(value).parse().ok()
            }
            "tx-interval" => {
                session.tx_interval_ms = value.strip_suffix("ms").unwrap_or(value).parse().ok()
            }
            _ => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const TODAY: &str = "\
bfdd 0.0.0 pid 4711
peers 2
session peer 192.0.2.2 state Up diag 0 local-discr 1 remote-discr 7 detection-time 900ms tx-interval 300ms
session peer 2001:db8::2 state Down diag 1 local-discr 2 remote-discr 0 detection-time 900ms tx-interval 300ms
  last-transition Up -> Down (Control Detection Time Expired (1), timeout while Up)
";

    #[test]
    fn parses_todays_full_shape() {
        let parsed = BfdStatus::parse(TODAY);
        assert_eq!(parsed.version.as_deref(), Some("0.0.0"));
        assert_eq!(parsed.pid, Some(4711));
        assert_eq!(parsed.peers_claim, Some(2));
        assert_eq!(parsed.sessions.len(), 2);
        let first = &parsed.sessions[0];
        assert_eq!(first.peer.as_deref(), Some("192.0.2.2"));
        assert_eq!(first.state.as_deref(), Some("Up"));
        assert_eq!(first.remote_discr, Some(7));
        assert_eq!(first.detection_time_ms, Some(900));
        assert_eq!(first.tx_interval_ms, Some(300));
        assert_eq!(parsed.unknown_lines, 0);
    }

    #[test]
    fn last_transition_attaches_to_the_session_above() {
        let parsed = BfdStatus::parse(TODAY);
        assert_eq!(parsed.sessions[0].last_transition, None);
        assert_eq!(
            parsed.sessions[1].last_transition.as_deref(),
            Some("Up -> Down (Control Detection Time Expired (1), timeout while Up)")
        );
    }

    #[test]
    fn future_fields_ride_and_unknown_lines_count() {
        let text = "\
bfdd 2.0.0 pid 51234 uptime 3600s
peers 1 echo-mode
session peer 192.0.2.2 state Up diag 0 local-discr 1 remote-discr 7 detection-time 900ms tx-interval 300ms echo-interval 300ms
agent something 1
";
        let parsed = BfdStatus::parse(text);
        assert_eq!(parsed.version.as_deref(), Some("2.0.0"));
        assert_eq!(parsed.pid, Some(51234));
        // `peers 1 echo-mode`: the count is picked, the extra field
        // ignored.
        assert_eq!(parsed.peers_claim, Some(1));
        assert_eq!(parsed.sessions.len(), 1);
        assert_eq!(parsed.unknown_lines, 1);
    }

    #[test]
    fn malformed_numbers_leave_fields_unset() {
        let parsed = BfdStatus::parse("bfdd x pid nope\nsession peer 1.2.3.4 state Up diag X\n");
        assert_eq!(parsed.version.as_deref(), Some("x"));
        assert_eq!(parsed.pid, None);
        assert_eq!(parsed.sessions[0].diag, None);
        assert_eq!(parsed.sessions[0].peer.as_deref(), Some("1.2.3.4"));
    }

    #[test]
    fn a_session_line_without_even_a_peer_counts_unknown() {
        let parsed = BfdStatus::parse("bfdd 0.0.0 pid 1\nsession nonsense entirely\n");
        assert!(parsed.sessions.is_empty());
        assert_eq!(parsed.unknown_lines, 1);
    }

    #[test]
    fn empty_and_never_started_files_parse_quietly() {
        let parsed = BfdStatus::parse("");
        assert_eq!(parsed, BfdStatus::default());
        let parsed = BfdStatus::parse("bfdd 0.0.0 pid 5\npeers 0\n");
        assert_eq!(parsed.peers_claim, Some(0));
        assert!(parsed.sessions.is_empty());
    }
}
