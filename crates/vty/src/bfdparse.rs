//! `bfdd.status` parsing — re-exported from the ONE run-dir reader
//! (`common::rundir`, the N8 consolidation). Format per
//! `docs/protocols/bfd.md` "Operator surface (A21)": one `session`
//! line per peer with state, diagnostic, discriminators, and
//! timings, an indented `last-transition` child line, header
//! `bfdd <version> pid <pid>` and `peers <n>`.
//!
//! ```text
//! bfdd 0.0.0 pid 4711
//! peers 2
//! session peer 192.0.2.2 state Up diag 0 local-discr 1 remote-discr 7 detection-time 900ms tx-interval 300ms
//!   last-transition Up -> Down (Neighbor Signaled Session Down (3), ...)
//! ```
//!
//! Tolerance contract (the daemon's format may grow; the S3 rules,
//! owned by the shared reader): unknown top-level lines are counted
//! and dropped; session keywords are picked out wherever they sit, so
//! added fields ride along; a `session` line whose shape is too
//! broken to carry even the peer is counted unknown; indented lines
//! attach to the session above them. Parsing never fails.

pub use common::rundir::{parse_bfdd, BfdSession, BfdStatus};

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
