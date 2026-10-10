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
//! increments the matching verdict bucket of [`common::SavMonitorCounts`],
//! in the aggregate and per deciding op ([`SpoofMonitor::per_op`], the
//! GSC §4 "count" policy's per-rule counters — which op spoke comes
//! from the evaluation's [`crate::table::Decision`] provenance).
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

use std::collections::BTreeMap;
use std::net::IpAddr;

use common::SavMonitorCounts;

use crate::table::{evaluate, SavOp, Verdict};

/// Counts verdicts of observations against a compiled op list — in the
/// aggregate ([`SpoofMonitor::counts`]) and per deciding op
/// ([`SpoofMonitor::per_op`], GSC §4's "count" monitor policy: "per-rule
/// counters", sourced from the [`crate::table::Decision`] provenance).
#[derive(Debug, Clone, Default)]
pub struct SpoofMonitor {
    ops: Vec<SavOp>,
    tallies: Vec<SavMonitorCounts>,
    counts: SavMonitorCounts,
}

impl SpoofMonitor {
    /// A monitor over the compiled ops being enforced.
    pub fn new(ops: &[SavOp]) -> Self {
        Self {
            ops: ops.to_vec(),
            tallies: vec![SavMonitorCounts::default(); ops.len()],
            counts: SavMonitorCounts::default(),
        }
    }

    /// Observe one (source, arrival-interface) pair: run it through the
    /// reference evaluation and increment the verdict's bucket — both
    /// the aggregate and the deciding op's row (a `Unknown` verdict
    /// names no op, so it never lands in a per-op row).
    /// Invalid is the spoof counter — the number a monitor action
    /// would log and a drop action would have dropped; unknown never
    /// counts toward spoof (unknown ≠ invalid).
    pub fn observe(&mut self, source: IpAddr, ingress: u32) -> Verdict {
        // The decision's op borrows self.ops; resolve it to an index
        // inside the block so the tallies borrow can begin.
        let (verdict, decided) = {
            let decision = evaluate(&self.ops, source, ingress);
            let decided = decision
                .op
                .and_then(|op| self.ops.iter().position(|o| std::ptr::eq(o, op)));
            (decision.verdict, decided)
        };
        let tally = decided.map(|index| &mut self.tallies[index]);
        match verdict {
            Verdict::Invalid => {
                self.counts.invalid += 1;
                if let Some(tally) = tally {
                    tally.invalid += 1;
                }
            }
            Verdict::Valid => {
                self.counts.valid += 1;
                if let Some(tally) = tally {
                    tally.valid += 1;
                }
            }
            Verdict::Unknown => {
                self.counts.unknown += 1;
                if let Some(tally) = tally {
                    tally.unknown += 1;
                }
            }
        }
        verdict
    }

    /// The counters so far.
    pub fn counts(&self) -> SavMonitorCounts {
        self.counts
    }

    /// The per-op verdict tallies so far (GSC §4 count), aligned with
    /// the op list: one row per op, `zero` for ops no observation has
    /// decided. Simulation-sourced — no landed backend reports
    /// per-rule counters (the dataplane's aggregate
    /// [`common::SavMonitorCounts`] is the backend view).
    pub fn per_op(&self) -> impl Iterator<Item = (&SavOp, &SavMonitorCounts)> {
        self.ops.iter().zip(self.tallies.iter())
    }

    /// Replace the op list being judged, keeping the accumulated
    /// counters (the daemon's reload path: rules regenerate, the spoof
    /// counter must not reset). Unchanged counters also make before/
    /// after comparable across an evaluate that produced the same ops.
    ///
    /// Per-op tallies re-key by op *value*: a rule that persists
    /// byte-identically keeps its tally, a changed rule is a new rule
    /// (zero), and a vanished rule's tally leaves with it.
    pub fn set_ops(&mut self, ops: &[SavOp]) {
        let mut carried: BTreeMap<SavOp, SavMonitorCounts> =
            self.ops.drain(..).zip(self.tallies.drain(..)).collect();
        self.ops = ops.to_vec();
        self.tallies = self
            .ops
            .iter()
            .map(|op| carried.remove(op).unwrap_or_default())
            .collect();
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

    /// GSC §4 "count" is per-rule: each observation's verdict tallies
    /// against the op that DECIDED it (the Decision provenance), not
    /// merely the op of the arrival interface — here a router-scale
    /// PBA op decides traffic that arrived on an interface with no
    /// interface-scale op at all. Unjudged (Unknown) observations name
    /// no op and land in no per-op row, while the aggregate still
    /// counts them.
    #[test]
    fn per_op_tallies_attribute_each_verdict_to_its_deciding_op() {
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
            SavOp::PbaPermit {
                prefix: "203.0.113.0/24".parse().unwrap(),
                ifindexes: vec![4],
                action: crate::mode::SavAction::Monitor,
                origin: None,
            },
        ];
        let mut monitor = SpoofMonitor::new(&ops);
        assert_eq!(monitor.observe(ip("198.51.100.9"), 2), Verdict::Valid); // ops[0]
        assert_eq!(monitor.observe(ip("198.51.100.9"), 3), Verdict::Invalid); // ops[1]
        assert_eq!(monitor.observe(ip("198.51.100.9"), 3), Verdict::Invalid); // ops[1]
                                                                              // Router scale: arrival on ifindex 9 has no interface op; the
                                                                              // PBA op (not in the allowlist) decides Invalid.
        assert_eq!(monitor.observe(ip("203.0.113.5"), 9), Verdict::Invalid); // ops[2]
                                                                             // Unjudged: source nothing covers, still on ifindex 9.
        assert_eq!(monitor.observe(ip("192.0.2.1"), 9), Verdict::Unknown);
        let tallies: Vec<(&SavOp, SavMonitorCounts)> =
            monitor.per_op().map(|(op, counts)| (op, *counts)).collect();
        assert_eq!(
            tallies[0].1,
            SavMonitorCounts {
                invalid: 0,
                valid: 1,
                unknown: 0
            },
            "the arrival interface's own op"
        );
        assert_eq!(
            tallies[1].1,
            SavMonitorCounts {
                invalid: 2,
                valid: 0,
                unknown: 0
            },
            "the spoofed arrivals attribute to the deny-all op"
        );
        assert_eq!(
            tallies[2].1,
            SavMonitorCounts {
                invalid: 1,
                valid: 0,
                unknown: 0
            },
            "the router-scale decision attributes to the PBA op"
        );
        // The aggregate keeps the unjudged observation too.
        assert_eq!(
            monitor.counts(),
            SavMonitorCounts {
                invalid: 3,
                valid: 1,
                unknown: 1
            }
        );
    }

    /// Regeneration re-keys per-op tallies by op VALUE: a persistent
    /// (byte-identical) rule keeps its tally wherever it sits in the
    /// new list, a changed rule is a new rule (zero), and a vanished
    /// rule's tally leaves with it — the aggregate never resets.
    #[test]
    fn set_ops_rekeys_per_op_tallies_by_op_value() {
        let allow = |prefixes: &[&str]| SavOp::IbaPermit {
            ifindex: 2,
            prefixes: prefixes.iter().map(|p| p.parse().unwrap()).collect(),
            action: crate::mode::SavAction::Monitor,
            origin: None,
        };
        let mut monitor = SpoofMonitor::new(&[allow(&["198.51.100.0/24"])]);
        assert_eq!(monitor.observe(ip("198.51.100.9"), 2), Verdict::Valid);
        assert_eq!(monitor.observe(ip("203.0.113.5"), 2), Verdict::Invalid);

        // Persistent op moves position (a new op sorts before it):
        // the tally follows the value, the new op starts at zero.
        let grown = [allow(&[]), allow(&["198.51.100.0/24"])];
        monitor.set_ops(&grown);
        let tallies: Vec<SavMonitorCounts> = monitor.per_op().map(|(_, counts)| *counts).collect();
        assert_eq!(
            tallies,
            vec![
                SavMonitorCounts::default(),
                SavMonitorCounts {
                    invalid: 1,
                    valid: 1,
                    unknown: 0
                },
            ],
            "the byte-identical op kept its tally at its new index"
        );

        // A changed rule (allowlist edited) is a new rule: zero.
        let edited = [allow(&["198.51.100.0/25"])];
        monitor.set_ops(&edited);
        assert_eq!(
            monitor.per_op().next().unwrap().1,
            &SavMonitorCounts::default(),
            "a changed rule starts from zero"
        );
        // The aggregate survives every regeneration.
        assert_eq!(monitor.counts().invalid, 1);
        assert_eq!(monitor.counts().valid, 1);
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
