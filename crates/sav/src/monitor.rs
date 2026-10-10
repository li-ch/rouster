//! Route-lookup monitor simulation — the pre-registered fallback when
//! the enforcement backend exposes no per-rule kernel counters (the
//! W7 rp_filter sysctl backend: strict/loose rp_filter drops, it does
//! not count).
//!
//! Monitor mode must still count would-be drops before any operator
//! opts into dropping (the workspace rule "enforcement defaults to
//! log/monitor before drop"). This type is that counting surface:
//! [`SpoofMonitor::observe`] runs one (source, arrival-interface)
//! observation through [`crate::table::evaluate`] — the reference
//! semantics of the compiled ops, i.e. a route-lookup simulation — and
//! increments the matching verdict bucket of [`common::SavMonitorCounts`].
//! It has no drop path at all; the daemon (W8) wires it to whatever
//! traffic-observation surface exists and asks the dataplane's
//! [`common::Dataplane::sav_monitor_counts`] first, falling back here
//! when that answers `Unsupported`.
//!
//! Disclosure (pre-registered): the simulation judges the compiled
//! rule set, not live packets — it is exactly as accurate as the SIB
//! snapshot the rules were generated from, and it cannot see traffic
//! no one feeds it. What it proves is the verdict pipeline and the
//! counter wiring; per-packet kernel counting needs a counter-bearing
//! backend (nftables counters) or eBPF.

use std::net::IpAddr;

use common::SavMonitorCounts;

use crate::table::{evaluate, SavOp, Verdict};

/// Counts verdicts of observations against a compiled op list.
#[derive(Debug, Clone, Default)]
pub struct SpoofMonitor {
    ops: Vec<SavOp>,
    counts: SavMonitorCounts,
}

impl SpoofMonitor {
    /// A monitor over the compiled ops being enforced.
    pub fn new(ops: &[SavOp]) -> Self {
        Self {
            ops: ops.to_vec(),
            counts: SavMonitorCounts::default(),
        }
    }

    /// Observe one (source, arrival-interface) pair: run it through the
    /// reference evaluation and increment the verdict's bucket.
    /// Invalid is the spoof counter — the number a monitor action
    /// would log and a drop action would have dropped; unknown never
    /// counts toward spoof (unknown ≠ invalid).
    pub fn observe(&mut self, source: IpAddr, ingress: u32) -> Verdict {
        let verdict = evaluate(&self.ops, source, ingress).verdict;
        match verdict {
            Verdict::Invalid => self.counts.invalid += 1,
            Verdict::Valid => self.counts.valid += 1,
            Verdict::Unknown => self.counts.unknown += 1,
        }
        verdict
    }

    /// The counters so far.
    pub fn counts(&self) -> SavMonitorCounts {
        self.counts
    }

    /// Replace the op list being judged, keeping the accumulated counters
    /// (the daemon's reload path: rules regenerate, the spoof counter must
    /// not reset). Unchanged counters also make before/after comparable
    /// across an evaluate that produced the same ops.
    pub fn set_ops(&mut self, ops: &[SavOp]) {
        self.ops = ops.to_vec();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    /// Strict uRPF ops: the spoofed arrival (source of the /24 arriving
    /// on the wrong interface) increments the spoof counter; the
    /// legitimate arrival counts valid; an interface with no mode
    /// counts unknown and is never a spoof.
    #[test]
    fn spoof_increments_valid_passes_unknown_never_spoofs() {
        let ops = vec![
            SavOp::IbaPermit {
                ifindex: 2,
                prefixes: vec!["198.51.100.0/24".parse().unwrap()],
                action: crate::mode::SavAction::Monitor,
                origin: None,
            },
            SavOp::IbaPermit {
                ifindex: 3,
                prefixes: vec![],
                action: crate::mode::SavAction::Monitor,
                origin: None,
            },
        ];
        let mut monitor = SpoofMonitor::new(&ops);
        // Legit: the /24's egress interface.
        assert_eq!(monitor.observe(ip("198.51.100.9"), 2), Verdict::Valid);
        // Spoof: same source on the empty-allowlist interface.
        assert_eq!(monitor.observe(ip("198.51.100.9"), 3), Verdict::Invalid);
        assert_eq!(monitor.observe(ip("198.51.100.9"), 3), Verdict::Invalid);
        // Unjudged: no mode on interface 9.
        assert_eq!(monitor.observe(ip("198.51.100.9"), 9), Verdict::Unknown);
        assert_eq!(
            monitor.counts(),
            SavMonitorCounts {
                invalid: 2,
                valid: 1,
                unknown: 1,
            },
            "spoof counter counts exactly the invalid verdicts"
        );
    }

    /// Monitor mode drops nothing by construction: the type has no
    /// drop path — observing a spoofed pair changes counters only.
    /// (Asserted behaviorally: repeated spoof observations accumulate;
    /// nothing else in the API can act on traffic.)
    #[test]
    fn monitor_only_counts_it_cannot_drop() {
        let ops = vec![SavOp::IbaPermit {
            ifindex: 2,
            prefixes: vec![],
            action: crate::mode::SavAction::Monitor,
            origin: None,
        }];
        let mut monitor = SpoofMonitor::new(&ops);
        for _ in 0..5 {
            assert_eq!(monitor.observe(ip("203.0.113.5"), 2), Verdict::Invalid);
        }
        assert_eq!(monitor.counts().invalid, 5);
        assert_eq!(monitor.counts().valid, 0);
    }

    /// An empty op list leaves everything unknown — no rules, no
    /// spoofs, no drops (fail-open on unjudged traffic).
    #[test]
    fn no_ops_means_all_unknown() {
        let mut monitor = SpoofMonitor::new(&[]);
        assert_eq!(monitor.observe(ip("10.0.0.1"), 2), Verdict::Unknown);
        assert_eq!(
            monitor.counts(),
            SavMonitorCounts {
                invalid: 0,
                valid: 0,
                unknown: 1,
            }
        );
    }

    /// Regenerating the op list (the daemon's poll/reload path) keeps the
    /// accumulated counters: observations before the swap stay counted,
    /// new ones accumulate on top.
    #[test]
    fn set_ops_keeps_counters_across_regeneration() {
        let ops = vec![SavOp::IbaPermit {
            ifindex: 2,
            prefixes: vec!["198.51.100.0/24".parse().unwrap()],
            action: crate::mode::SavAction::Monitor,
            origin: None,
        }];
        let mut monitor = SpoofMonitor::new(&ops);
        assert_eq!(monitor.observe(ip("198.51.100.9"), 2), Verdict::Valid);
        assert_eq!(monitor.observe(ip("203.0.113.5"), 2), Verdict::Invalid);

        // Regenerate to an empty op list: counters preserved, new
        // verdicts judged by the NEW ops (no mode on the interface
        // anymore → unknown, not invalid — fail-open).
        monitor.set_ops(&[]);
        assert_eq!(monitor.counts().invalid, 1);
        assert_eq!(monitor.counts().valid, 1);
        assert_eq!(monitor.observe(ip("198.51.100.9"), 2), Verdict::Unknown);
        assert_eq!(
            monitor.counts().invalid,
            1,
            "unchanged: unknown is not spoof"
        );
        assert_eq!(monitor.counts().unknown, 1);
    }
}
