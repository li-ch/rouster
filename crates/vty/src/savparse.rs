//! `savd.status` parsing — re-exported from the ONE run-dir reader
//! (`common::rundir`, the N8 consolidation; the format contract is
//! docs/operator-surfaces.md §2.1):
//!
//! ```text
//! savd 0.0.0 pid 4242
//! config mode strict-uRPF action monitor poll 5s interfaces 2 bindings 0
//! installed 2 rules
//! rule allow if#2 [198.51.100.0/24] strict monitor
//! monitor source simulation invalid=0 valid=0 unknown=0
//! ```
//!
//! Tolerance contract (the S3 rules, owned by the shared reader):
//! unknown *lines* are counted and dropped; known *keywords* are
//! picked out wherever they sit on their line, so added fields ride
//! along harmlessly; a `rule` line matching no known shape is kept
//! verbatim so no operator data is lost; a malformed number leaves
//! its field unset. Parsing never fails.

pub use common::rundir::{parse_savd, SavConfig, SavMonitor, SavRule, SavStatus};

#[cfg(test)]
mod tests {
    use super::*;

    const TODAY: &str = "\
savd 0.0.0 pid 4242
config mode strict-uRPF action monitor poll 5s interfaces 2 bindings 0
installed 4 rules
rule allow if#2 [198.51.100.0/24] strict monitor
rule block if#7 [192.0.2.0/26] drop
rule allow 2001:db8:1::/48 if [2, 3] monitor
rule block 192.0.2.128/25 if [7, 9] monitor
monitor source simulation invalid=1 valid=2 unknown=3
";

    #[test]
    fn parses_todays_full_shape() {
        let parsed = SavStatus::parse(TODAY);
        assert_eq!(parsed.version.as_deref(), Some("0.0.0"));
        assert_eq!(parsed.pid, Some(4242));
        assert_eq!(parsed.config.mode.as_deref(), Some("strict-uRPF"));
        assert_eq!(parsed.config.poll_secs, Some(5));
        assert_eq!(parsed.installed_claim, Some(4));
        assert_eq!(parsed.rules.len(), 4);
        assert_eq!(parsed.monitor.valid, Some(2));
        assert_eq!(parsed.unknown_lines, 0);
    }

    #[test]
    fn rule_shapes_split_by_scale() {
        let parsed = SavStatus::parse(TODAY);
        assert!(matches!(
            &parsed.rules[0],
            SavRule::Iface { urpf: Some(hint), .. } if hint == "strict"
        ));
        assert!(matches!(
            &parsed.rules[1],
            SavRule::Iface { urpf: None, .. }
        ));
        assert!(
            matches!(&parsed.rules[2], SavRule::Prefix { ifindexes, .. } if ifindexes == &vec![2, 3])
        );
        assert!(matches!(&parsed.rules[3], SavRule::Prefix { .. }));
    }

    #[test]
    fn unknown_rule_shapes_are_kept_verbatim() {
        let parsed = SavStatus::parse("savd 0.0.0 pid 1\nrule frob if#2 [x] magic\n");
        assert_eq!(parsed.rules.len(), 1);
        assert!(matches!(&parsed.rules[0], SavRule::Raw(text) if text.contains("frob")));
    }

    #[test]
    fn future_fields_and_lines_ride_along() {
        let text = "\
savd 2.0.0 pid 51234 uptime 3600s
config mode EFP-uRPF action monitor poll 5s interfaces 2 bindings 1 ttl-window 90s
installed 1 rules
rule allow if#2 [198.51.100.0/24] strict monitor expires-in 120s
agent session 3 peers 1
monitor source dataplane invalid=1 valid=2 unknown=3 window 60s
";
        let parsed = SavStatus::parse(text);
        assert_eq!(parsed.version.as_deref(), Some("2.0.0"));
        assert_eq!(parsed.pid, Some(51234));
        assert_eq!(parsed.config.bindings, Some(1));
        // The extra `expires-in` tail makes the rule unknown-shape —
        // kept verbatim, not lost.
        assert!(matches!(&parsed.rules[0], SavRule::Raw(_)));
        // The whole unknown `agent` line is counted, not fatal.
        assert_eq!(parsed.unknown_lines, 1);
        assert_eq!(parsed.monitor.source.as_deref(), Some("dataplane"));
    }

    #[test]
    fn malformed_numbers_leave_their_field_unset() {
        let parsed = SavStatus::parse("savd x pid notanumber\ninstalled NaN rules\n");
        assert_eq!(parsed.version.as_deref(), Some("x"));
        assert_eq!(parsed.pid, None);
        assert_eq!(parsed.installed_claim, None);
        assert_eq!(parsed.evaluated, None);
    }

    #[test]
    fn never_evaluated_marker_is_recognized() {
        let parsed = SavStatus::parse("savd 0.0.0 pid 9\ninstalled 0 rules (never evaluated)\n");
        assert_eq!(parsed.installed_claim, Some(0));
        assert_eq!(parsed.evaluated, Some(false));
    }
}
