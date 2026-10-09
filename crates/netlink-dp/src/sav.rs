//! SAV program → rp_filter sysctl translation (pure; no I/O).
//!
//! Backend choice (pre-registered order, first that probes working in
//! the cached images): nftables `fib saddr . iif` rules are the
//! preferred surface, but every cached image ships without `nft`
//! (probe evidence: away/2026-10-09/quarantine/B8-enforcement-surface.md
//! plus the W7 re-probe) — so enforcement lands on the fallback,
//! Linux's kernel uRPF via the per-interface `rp_filter` sysctl
//! (`fib_validate_source`; strict = 1, RFC 3704 §2.2; loose = 2,
//! RFC 3704 §2.5).
//!
//! What that surface can and cannot express — every "cannot" is a
//! disclosed approximation, not a silent no-op:
//!
//! * Interface **allowlists** (IBA) with the Drop action map to the
//!   allowlist's generator semantics: strict → 1, loose/FP/EFP → 2.
//!   The kernel then enforces *the FIB's own* uRPF, not the compiled
//!   prefix list — outcome-equivalent while the SIB was ingested from
//!   this kernel's RIB mirror (the W5 path), approximate for
//!   operator-configured bindings (no FIB counterpart exists). This
//!   module therefore drops the prefix content on the floor and keeps
//!   only the mode; the disclosures record that.
//! * Allowlists with the **Monitor** action install *nothing*:
//!   rp_filter has no count-only mode (a 1 or a 2 drops), so monitor
//!   stays at 0 and counting runs in the `sav` layer
//!   (`sav::monitor`, the pre-registered route-lookup simulation).
//!   The interfaces are listed in [`SysctlPlan::monitored`] so the
//!   backend can log exactly what is being watched-but-not-dropped.
//! * **Blocklists** (IBB) and **router-scale** interface sets
//!   (PBA/PBB) cannot be expressed by a FIB-wide per-interface
//!   knob; they are rejected with reasons and left for the nftables
//!   backend (W7B) to enforce for real.
//! * **IPv6** has no rp_filter sysctl at all; v6 prefixes are
//!   stripped (a mixed-family allowlist keeps its v4 half — losing v4
//!   coverage over one v6 prefix would be worse), and a v6-only
//!   allowlist is rejected.
//! * The plan is order/duplicate-invariant (BTreeMap, most-restrictive
//!   value wins on a conflict) — same program, same plan, always.

use std::collections::BTreeMap;

use common::{IpPrefix, SavProgram, SavProgramOp, SavUrpf};

/// Strict rp_filter value (RFC 3704 §2.2 egress-membership check).
pub const RP_FILTER_STRICT: u8 = 1;
/// Loose rp_filter value (RFC 3704 §2.5 route-existence check).
pub const RP_FILTER_LOOSE: u8 = 2;
/// rp_filter disabled (monitor mode leaves the kernel here).
pub const RP_FILTER_OFF: u8 = 0;

/// What a [`SavProgram`] translates into on the sysctl surface.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SysctlPlan {
    /// Per-interface rp_filter values to write (Drop-action allowlists
    /// only). The backend resolves ifindex → interface name.
    pub rp_filter: BTreeMap<u32, u8>,
    /// Interfaces under a Monitor-action allowlist: nothing is written
    /// for them (monitor drops nothing by construction); counting is
    /// the sav layer's job.
    pub monitored: Vec<u32>,
    /// Ops this surface cannot express, each with its reason — logged
    /// as warnings by the backend, never silently swallowed.
    pub rejected: Vec<(SavProgramOp, &'static str)>,
}

impl SysctlPlan {
    /// Translate a program. Pure and deterministic (see module docs for
    /// the mapping rules and their disclosures).
    pub fn from_program(program: &SavProgram) -> Self {
        let mut plan = SysctlPlan::default();
        for op in program.ops() {
            match op {
                SavProgramOp::IfaceAllow {
                    ifindex,
                    prefixes,
                    urpf,
                    action,
                } => {
                    // An empty list is GSC §2.1's deny-all (strict): it
                    // proceeds like any strict ask. A non-empty list
                    // with no v4 member is v6-only and cannot be
                    // enforced here; a mixed list keeps its v4 half.
                    let has_v6 = prefixes.iter().any(|p| matches!(p, IpPrefix::V6(_)));
                    let has_v4 = prefixes.iter().any(|p| matches!(p, IpPrefix::V4(_)));
                    if has_v6 && !has_v4 {
                        plan.rejected.push((
                            op.clone(),
                            "ipv6-only allowlist: rp_filter is IPv4-only (v6 enforcement needs a rule engine)",
                        ));
                        continue;
                    }
                    match action {
                        common::SavEnforce::Monitor => {
                            // Monitor drops nothing: leave the kernel at
                            // rp_filter=0 and count in the sav layer.
                            plan.monitored.push(*ifindex);
                        }
                        common::SavEnforce::Drop => {
                            let value = match *urpf {
                                SavUrpf::Strict => RP_FILTER_STRICT,
                                SavUrpf::Loose => RP_FILTER_LOOSE,
                            };
                            // Most restrictive wins on a conflict: 1
                            // (strict) is a subset of 2 (loose), so a
                            // strict ask never loosens a previous one.
                            let entry = plan.rp_filter.entry(*ifindex).or_insert(value);
                            if *entry > value {
                                *entry = value;
                            }
                        }
                    }
                }
                SavProgramOp::IfaceBlock { .. } => plan.rejected.push((
                    op.clone(),
                    "interface prefix blocklist (IBB): rp_filter cannot express blocklists",
                )),
                SavProgramOp::PrefixAllow { .. } => plan.rejected.push((
                    op.clone(),
                    "router-scale interface set (PBA): rp_filter is FIB-wide per interface",
                )),
                SavProgramOp::PrefixBlock { .. } => plan.rejected.push((
                    op.clone(),
                    "router-scale interface set (PBB): rp_filter is FIB-wide per interface",
                )),
            }
        }
        plan.monitored.sort();
        plan.monitored.dedup();
        plan
    }

    /// True when the plan would touch nothing (empty program or
    /// monitor-only).
    pub fn is_noop(&self) -> bool {
        self.rp_filter.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use common::{SavEnforce, SavProgramOp};

    fn p(s: &str) -> IpPrefix {
        s.parse().unwrap()
    }

    fn allow(ifindex: u32, prefixes: &[&str], urpf: SavUrpf, action: SavEnforce) -> SavProgramOp {
        SavProgramOp::IfaceAllow {
            ifindex,
            prefixes: prefixes.iter().map(|s| p(s)).collect(),
            urpf,
            action,
        }
    }

    /// The core mapping: strict+drop → 1, loose+drop → 2, monitor → no
    /// write but a monitored entry.
    #[test]
    fn drop_maps_by_urpf_semantics_monitor_writes_nothing() {
        let plan = SysctlPlan::from_program(&SavProgram::from_ops([
            allow(2, &["198.51.100.0/24"], SavUrpf::Strict, SavEnforce::Drop),
            allow(3, &["198.51.100.0/24"], SavUrpf::Loose, SavEnforce::Drop),
            allow(
                4,
                &["198.51.100.0/24"],
                SavUrpf::Strict,
                SavEnforce::Monitor,
            ),
        ]));
        assert_eq!(plan.rp_filter.get(&2), Some(&RP_FILTER_STRICT));
        assert_eq!(plan.rp_filter.get(&3), Some(&RP_FILTER_LOOSE));
        assert!(!plan.rp_filter.contains_key(&4));
        assert_eq!(plan.monitored, vec![4]);
        assert!(plan.rejected.is_empty());
        assert!(!plan.is_noop());
    }

    /// Empty allowlist + drop is still a deny-all (GSC §2.1): strict
    /// with no prefixes maps to rp_filter=1 like any strict ask — the
    /// kernel's FIB check is the enforcement, the list was empty.
    #[test]
    fn empty_allowlist_drop_is_strict_denial() {
        let plan = SysctlPlan::from_program(&SavProgram::from_ops([allow(
            5,
            &[],
            SavUrpf::Strict,
            SavEnforce::Drop,
        )]));
        assert_eq!(plan.rp_filter.get(&5), Some(&RP_FILTER_STRICT));
    }

    /// Conflicting values on one interface resolve most-restrictively
    /// and order-independently: strict(1) never loosens a loose(2).
    #[test]
    fn conflicts_resolve_most_restrictively_and_order_independently() {
        let a = SavProgram::from_ops([
            allow(2, &["10.0.0.0/8"], SavUrpf::Loose, SavEnforce::Drop),
            allow(2, &["192.0.2.0/24"], SavUrpf::Strict, SavEnforce::Drop),
        ]);
        let b = SavProgram::from_ops([
            allow(2, &["192.0.2.0/24"], SavUrpf::Strict, SavEnforce::Drop),
            allow(2, &["10.0.0.0/8"], SavUrpf::Loose, SavEnforce::Drop),
        ]);
        let (pa, pb) = (SysctlPlan::from_program(&a), SysctlPlan::from_program(&b));
        assert_eq!(pa, pb, "plan is order-invariant");
        assert_eq!(pa.rp_filter.get(&2), Some(&RP_FILTER_STRICT));
    }

    /// v6 prefixes: a mixed allowlist keeps its v4 half; a v6-only
    /// allowlist is rejected with the IPv4-only reason.
    #[test]
    fn ipv6_prefixes_are_stripped_or_rejected() {
        let plan = SysctlPlan::from_program(&SavProgram::from_ops([allow(
            2,
            &["198.51.100.0/24", "2001:db8::/48"],
            SavUrpf::Strict,
            SavEnforce::Drop,
        )]));
        assert_eq!(plan.rp_filter.get(&2), Some(&RP_FILTER_STRICT));
        assert!(plan.rejected.is_empty(), "v4 half enforced, no rejection");

        let v6only = SysctlPlan::from_program(&SavProgram::from_ops([allow(
            3,
            &["2001:db8::/48"],
            SavUrpf::Strict,
            SavEnforce::Drop,
        )]));
        assert!(v6only.rp_filter.is_empty());
        assert_eq!(v6only.rejected.len(), 1);
        assert!(v6only.rejected[0].1.contains("IPv4-only"));
    }

    /// IBB/PBA/PBB are beyond the sysctl surface: rejected with
    /// reasons, never silently enforced-or-ignored.
    #[test]
    fn unsupported_rule_kinds_are_rejected_with_reasons() {
        let plan = SysctlPlan::from_program(&SavProgram::from_ops([
            SavProgramOp::IfaceBlock {
                ifindex: 2,
                prefixes: vec![p("192.0.2.0/24")],
                action: SavEnforce::Drop,
            },
            SavProgramOp::PrefixAllow {
                prefix: p("203.0.113.0/24"),
                ifindexes: vec![2, 3],
                action: SavEnforce::Drop,
            },
            SavProgramOp::PrefixBlock {
                prefix: p("203.0.113.0/24"),
                ifindexes: vec![4],
                action: SavEnforce::Monitor,
            },
        ]));
        assert!(plan.rp_filter.is_empty());
        assert!(plan.monitored.is_empty());
        assert!(plan.is_noop());
        assert_eq!(plan.rejected.len(), 3);
        assert!(plan.rejected[0].1.contains("IBB"));
        assert!(plan.rejected[1].1.contains("PBA"));
        assert!(plan.rejected[2].1.contains("PBB"));
    }

    /// Monitor-only programs are a logged no-op on the kernel: the
    /// plan records the watched interfaces and touches nothing.
    #[test]
    fn monitor_only_program_is_a_logged_noop() {
        let plan = SysctlPlan::from_program(&SavProgram::from_ops([
            allow(
                2,
                &["198.51.100.0/24"],
                SavUrpf::Strict,
                SavEnforce::Monitor,
            ),
            allow(3, &["192.0.2.0/24"], SavUrpf::Loose, SavEnforce::Monitor),
            allow(2, &["10.0.0.0/8"], SavUrpf::Loose, SavEnforce::Monitor),
        ]));
        assert!(plan.is_noop());
        assert_eq!(plan.monitored, vec![2, 3], "deduplicated, sorted");
    }
}
