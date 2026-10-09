//! The SAV Table Manager's compile step (architecture.md §2's "table
//! manager" box; docs/implementation-plan.md §Phase 1.5): typed rules
//! ([`crate::gen::RuleSet`]) in, dataplane ops ([`SavOp`]) out.
//!
//! [`SavOp`] is the shape W7's dataplane backend consumes —
//! set-membership checks (a source against an interface's prefix set, or
//! an arrival interface against a prefix's interface set) each carrying
//! their [`SavAction`] as data. This module is pure: no I/O, no kernel
//! programming; enforcing the ops is W7's job through the dataplane
//! trait.
//!
//! [`evaluate`] is the *reference semantics* of the compiled ops — the
//! GSC §3 four-step pipeline as a pure function. It is what the tests
//! assert against and what W8's monitor path can log from; W7's real
//! enforcement must stay outcome-equivalent to it (GSC §1: "the SAV
//! outcomes SHOULD be equivalent to the described SAV capabilities").

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::net::IpAddr;

use common::IpPrefix;
use tracing::warn;

use crate::gen::{RuleSet, SavRule};
use crate::mode::{SavAction, SavConfig, ValidationMode};
use crate::{prefix_contains, prefix_len};

/// One compiled enforcement operation. Interface-scale ops are
/// per-interface prefix-set memberships; router-scale ops are
/// per-prefix interface-set memberships — both directions of GSC §3
/// Figure 1's "SAV rule" definition ("mapping the incoming interfaces
/// with specific source addresses/prefixes").
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SavOp {
    /// IBA-SAV on one interface (GSC §2.1): a packet arriving on
    /// `ifindex` is valid iff its source is inside some prefix of
    /// `prefixes`; an empty set denies everything ("invalid if not
    /// matched").
    IbaPermit {
        /// The interface the allowlist gates.
        ifindex: u32,
        /// The allowlist, sorted and deduplicated.
        prefixes: Vec<IpPrefix>,
        /// What enforcement does with invalid verdicts here.
        action: SavAction,
    },
    /// IBB-SAV on one interface (GSC §2.2): a packet arriving on
    /// `ifindex` with a source inside some prefix of `prefixes` is
    /// invalid; unlisted sources fall through to router-scale modes.
    IbbBlock {
        ifindex: u32,
        prefixes: Vec<IpPrefix>,
        action: SavAction,
    },
    /// PBA-SAV for one protected prefix (GSC §2.3): sources inside
    /// `prefix` are valid iff they arrive on one of `ifindexes`;
    /// "invalid if not matched".
    PbaPermit {
        prefix: IpPrefix,
        ifindexes: Vec<u32>,
        action: SavAction,
    },
    /// PBB-SAV for one protected prefix (GSC §2.4): sources inside
    /// `prefix` are invalid iff they arrive on one of `ifindexes`.
    PbbBlock {
        prefix: IpPrefix,
        ifindexes: Vec<u32>,
        action: SavAction,
    },
}

impl SavOp {
    /// The action this op's invalid verdicts map to.
    pub fn action(&self) -> SavAction {
        match *self {
            SavOp::IbaPermit { action, .. }
            | SavOp::IbbBlock { action, .. }
            | SavOp::PbaPermit { action, .. }
            | SavOp::PbbBlock { action, .. } => action,
        }
    }

    /// The validation mode this op enforces.
    pub fn mode(&self) -> ValidationMode {
        match *self {
            SavOp::IbaPermit { .. } => ValidationMode::Iba,
            SavOp::IbbBlock { .. } => ValidationMode::Ibb,
            SavOp::PbaPermit { .. } => ValidationMode::Pba,
            SavOp::PbbBlock { .. } => ValidationMode::Pbb,
        }
    }
}

impl fmt::Display for SavOp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SavOp::IbaPermit {
                ifindex,
                prefixes,
                action,
            } => {
                let p: Vec<String> = prefixes.iter().map(|p| p.to_string()).collect();
                write!(f, "iba permit #{ifindex} [{}] {action}", p.join(", "))
            }
            SavOp::IbbBlock {
                ifindex,
                prefixes,
                action,
            } => {
                let p: Vec<String> = prefixes.iter().map(|p| p.to_string()).collect();
                write!(f, "ibb block #{ifindex} [{}] {action}", p.join(", "))
            }
            SavOp::PbaPermit {
                prefix,
                ifindexes,
                action,
            } => write!(f, "pba permit {prefix} {ifindexes:?} {action}"),
            SavOp::PbbBlock {
                prefix,
                ifindexes,
                action,
            } => write!(f, "pbb block {prefix} {ifindexes:?} {action}"),
        }
    }
}

/// The result of validating one (source, arrival-interface) against a
/// compiled op list. `Unknown` is a first-class answer — the workspace
/// SAVNET rule "unknown ≠ invalid": traffic on an interface with no
/// mode enabled, or a source no router-scale rule protects, is
/// *unjudged*, and unjudged traffic is monitored, never dropped.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Verdict {
    /// Conforms to the applicable mode's rule.
    Valid,
    /// Violates the applicable mode's rule (what the op's action is
    /// applied to — Monitor by default, Drop only where configured).
    Invalid,
    /// No applicable mode: nothing judged. Never a drop.
    Unknown,
}

impl fmt::Display for Verdict {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Verdict::Valid => "valid",
            Verdict::Invalid => "invalid",
            Verdict::Unknown => "unknown",
        })
    }
}

/// Compile a rule set + enforcement config into the deterministic
/// [`SavOp`] list — the SAV Table Manager's whole local job.
///
/// GSC §3's coexistence rules, enforced here:
/// - IBA and IBB cannot both act on one interface. The config already
///   makes that unrepresentable per interface; IBB *rules* naming an
///   IBA-configured interface are dropped with a warning (GSC §3's
///   "IBB-SAV should be ignored" option; the merge-by-subtraction
///   variant is a deliberate later choice, see §Deferred in the stage
///   report).
/// - PBA and PBB cannot both act for one prefix: when both rule kinds
///   name the same prefix, the PBB rules are dropped with a warning
///   (GSC §3's "PBB-SAV should be ignored" option).
/// - An interface enabled for IBA with no matching rules still gets an
///   (empty) [`SavOp::IbaPermit`] — an allowlist that lists nothing
///   denies everything (GSC §2.1 "otherwise invalid").
///
/// Ordering is fixed: IbaPermit (ifindex ascending), IbbBlock
/// (ifindex ascending), PbaPermit (prefix ascending), PbbBlock (prefix
/// ascending) — same rules + config ⇒ byte-identical op list. Router
/// rules listing the query-only [`crate::InterfaceRef::Any`] marker
/// contribute nothing (it is never an enforcement constraint). No I/O.
pub fn compile(rules: &RuleSet, cfg: &SavConfig) -> Vec<SavOp> {
    // Interface-scale: collect each IBA/IBB-configured interface's
    // prefix set from the rules naming it.
    let mut iba: BTreeMap<u32, Vec<IpPrefix>> = BTreeMap::new();
    let mut ibb: BTreeMap<u32, Vec<IpPrefix>> = BTreeMap::new();
    for rule in rules.rules() {
        match *rule {
            SavRule::Iba {
                prefix,
                ref interfaces,
            } => {
                for ifindex in ifindexes_of(interfaces) {
                    iba.entry(ifindex).or_default().push(prefix);
                }
            }
            SavRule::Ibb {
                prefix,
                ref interfaces,
            } => {
                for ifindex in ifindexes_of(interfaces) {
                    // GSC §3: where IBA is configured, IBB is ignored.
                    if cfg.mode_on(ifindex) == Some(ValidationMode::Iba) {
                        warn!(
                            ifindex,
                            %prefix,
                            "ibb rule ignored on iba-enabled interface (GSC §3 exclusivity)"
                        );
                        continue;
                    }
                    ibb.entry(ifindex).or_default().push(prefix);
                }
            }
            // Router-scale: union per prefix; exclusivity below.
            SavRule::Pba { .. } | SavRule::Pbb { .. } => {}
        }
    }

    let mut ops = Vec::new();
    // Seed every configured interface so an allowlist/blocklist with no
    // matching rules still enforces its polarity (GSC §2.1: an IBA list
    // that records nothing denies everything).
    for ifindex in cfg.enabled_interfaces(ValidationMode::Iba) {
        iba.entry(ifindex).or_default();
    }
    for ifindex in cfg.enabled_interfaces(ValidationMode::Ibb) {
        ibb.entry(ifindex).or_default();
    }
    for (&ifindex, prefixes) in &iba {
        // Only IBA-configured interfaces enforce their allowlist — a
        // rule naming an unconfigured interface is inert data.
        if cfg.mode_on(ifindex) != Some(ValidationMode::Iba) {
            continue;
        }
        ops.push(SavOp::IbaPermit {
            ifindex,
            prefixes: sorted_prefixes(prefixes.clone()),
            action: cfg.action_on(ifindex),
        });
    }
    for (&ifindex, prefixes) in &ibb {
        if cfg.mode_on(ifindex) != Some(ValidationMode::Ibb) {
            continue;
        }
        ops.push(SavOp::IbbBlock {
            ifindex,
            prefixes: sorted_prefixes(prefixes.clone()),
            action: cfg.action_on(ifindex),
        });
    }

    // Router-scale: group interface sets per (mode, prefix).
    let mut pba: BTreeMap<IpPrefix, Vec<u32>> = BTreeMap::new();
    let mut pbb: BTreeMap<IpPrefix, Vec<u32>> = BTreeMap::new();
    let pba_prefixes: BTreeSet<IpPrefix> = rules
        .rules()
        .iter()
        .filter(|r| matches!(r, SavRule::Pba { .. }))
        .map(|r| r.prefix())
        .collect();
    for rule in rules.rules() {
        match *rule {
            SavRule::Pba {
                prefix,
                ref interfaces,
            } => {
                pba.entry(prefix)
                    .or_default()
                    .extend(ifindexes_of(interfaces));
            }
            SavRule::Pbb {
                prefix,
                ref interfaces,
            } => {
                // GSC §3: where PBA protects the prefix, PBB is ignored.
                if pba_prefixes.contains(&prefix) {
                    warn!(
                        %prefix,
                        "pbb rule ignored: prefix also protected by pba (GSC §3 exclusivity)"
                    );
                    continue;
                }
                pbb.entry(prefix)
                    .or_default()
                    .extend(ifindexes_of(interfaces));
            }
            _ => {}
        }
    }
    for (prefix, mut ifindexes) in pba {
        ifindexes.sort();
        ifindexes.dedup();
        ops.push(SavOp::PbaPermit {
            prefix,
            ifindexes,
            action: cfg.router_action(),
        });
    }
    for (prefix, mut ifindexes) in pbb {
        ifindexes.sort();
        ifindexes.dedup();
        ops.push(SavOp::PbbBlock {
            prefix,
            ifindexes,
            action: cfg.router_action(),
        });
    }
    ops
}

/// The ifindexes named by a rule's interface list (concrete refs only;
/// the `Any` marker yields nothing).
fn ifindexes_of(interfaces: &[crate::InterfaceRef]) -> impl Iterator<Item = u32> + '_ {
    interfaces.iter().filter_map(|i| i.ifindex())
}

fn sorted_prefixes(mut prefixes: Vec<IpPrefix>) -> Vec<IpPrefix> {
    prefixes.sort();
    prefixes.dedup();
    prefixes
}

/// Reference semantics of a compiled op list: the GSC §3 four-step
/// pipeline over one (source, arrival interface) pair.
///
/// 1. Record the packet's source and incoming interface; state starts
///    "valid".
/// 2. *IBA*: the arrival interface's [`SavOp::IbaPermit`] is decisive —
///    source matched ⇒ [`Verdict::Valid`], else [`Verdict::Invalid`].
///    GSC §3: "If an interface has IBA-SAV enabled, traffic on that
///    interface does not need to go through any other modes" — IBA
///    short-circuits everything below.
/// 3. *IBB*: a matched blocklist prefix ⇒ [`Verdict::Invalid`]; a
///    non-match is "valid" only provisionally — GSC §3: "the traffic
///    must also be checked against PBA-SAV or PBB-SAV if those modes
///    are applicable", so evaluation falls through.
/// 4. *PBA/PBB*: the longest covering protected prefix's op decides
///    (PBA: arrival ∈ interface set ? Valid : Invalid; PBB: arrival ∈
///    interface set ? Invalid : Valid). No covering protected prefix ⇒
///    [`Verdict::Unknown`] — no mode judged this packet.
///
/// Longest-covering-prefix selection is deterministic: at most one
/// prefix per (family, length) can contain a given address, and
/// compile de-duplicates per prefix.
pub fn evaluate(ops: &[SavOp], source: IpAddr, ingress: u32) -> Verdict {
    // Step 2 — IBA is decisive for its interface.
    if let Some(SavOp::IbaPermit { prefixes, .. }) = ops
        .iter()
        .find(|op| matches!(op, SavOp::IbaPermit { ifindex, .. } if *ifindex == ingress))
    {
        return if prefixes.iter().any(|p| prefix_contains(*p, source)) {
            Verdict::Valid
        } else {
            Verdict::Invalid
        };
    }
    // Step 3 — IBB match is invalid; a non-match falls through.
    if let Some(SavOp::IbbBlock { prefixes, .. }) = ops
        .iter()
        .find(|op| matches!(op, SavOp::IbbBlock { ifindex, .. } if *ifindex == ingress))
    {
        if prefixes.iter().any(|p| prefix_contains(*p, source)) {
            return Verdict::Invalid;
        }
    }
    // Step 4 — the longest covering router-scale op decides.
    let covering = ops
        .iter()
        .filter(|op| match op {
            SavOp::PbaPermit { prefix, .. } | SavOp::PbbBlock { prefix, .. } => {
                prefix_contains(*prefix, source)
            }
            _ => false,
        })
        .max_by_key(|op| prefix_len(op_prefix(op)));
    match covering {
        Some(SavOp::PbaPermit { ifindexes, .. }) => {
            if ifindexes.contains(&ingress) {
                Verdict::Valid
            } else {
                Verdict::Invalid
            }
        }
        Some(SavOp::PbbBlock { ifindexes, .. }) => {
            if ifindexes.contains(&ingress) {
                Verdict::Invalid
            } else {
                Verdict::Valid
            }
        }
        _ => Verdict::Unknown,
    }
}

fn op_prefix(op: &SavOp) -> IpPrefix {
    match *op {
        SavOp::PbaPermit { prefix, .. } | SavOp::PbbBlock { prefix, .. } => prefix,
        _ => unreachable!("router-scale ops only"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::gen::{generate_urpf, UrpfMode};
    use crate::mode::{SavAction, ValidationMode};
    use crate::{Binding, BindingOrigin, InterfaceRef, Sib};
    use common::{Nexthop, NexthopGroup, RouteEntry, RouteProtocol};

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    fn if_ref(ifindex: u32) -> InterfaceRef {
        InterfaceRef::If {
            ifindex,
            name: None,
        }
    }

    fn static_if_route(prefix: &str, ifindex: u32) -> RouteEntry {
        RouteEntry::new(
            prefix.parse().unwrap(),
            RouteProtocol::Static,
            NexthopGroup::single(Nexthop::IfIndex(ifindex)),
            0,
        )
    }

    fn cfg_iba_2_3() -> SavConfig {
        let mut cfg = SavConfig::new();
        cfg.enable_interface(2, ValidationMode::Iba, SavAction::Monitor);
        cfg.enable_interface(3, ValidationMode::Iba, SavAction::Monitor);
        cfg
    }

    fn pba(prefix: &str, ifindexes: &[u32]) -> SavRule {
        SavRule::Pba {
            prefix: prefix.parse().unwrap(),
            interfaces: ifindexes.iter().map(|&ix| if_ref(ix)).collect(),
        }
    }

    fn pbb(prefix: &str, ifindexes: &[u32]) -> SavRule {
        SavRule::Pbb {
            prefix: prefix.parse().unwrap(),
            interfaces: ifindexes.iter().map(|&ix| if_ref(ix)).collect(),
        }
    }

    fn ibb(prefix: &str, ifindexes: &[u32]) -> SavRule {
        SavRule::Ibb {
            prefix: prefix.parse().unwrap(),
            interfaces: ifindexes.iter().map(|&ix| if_ref(ix)).collect(),
        }
    }

    // The end-to-end worked example: generate from (Sib, Rib), compile,
    // evaluate. Topology (RFC 3704 §2.2/§2.3/§2.5 and RFC 8704 §2.4
    // semantics; RFC 5737/3849 documentation ranges): 198.51.100.0/24
    // best route via ifindex 2 with a BGP alternate via 3; a v4 default
    // via 2. IBA enabled on 2 and 3, monitor action.
    fn worked_example() -> (Sib, rib::Rib, SavConfig) {
        let mut rib = rib::Rib::new();
        rib.add_route(static_if_route("198.51.100.0/24", 2));
        let mut alternate = static_if_route("198.51.100.0/24", 3);
        alternate.protocol = RouteProtocol::Bgp;
        rib.add_route(alternate);
        rib.add_route(static_if_route("0.0.0.0/0", 2));
        (Sib::from_rib(&rib), rib, cfg_iba_2_3())
    }

    /// RFC 3704 §2.2: strict uRPF under asymmetric routing — the
    /// source's best-route egress (ifindex 2) does not contain the
    /// arrival interface 3 ⇒ invalid; RFC 3704 §2.5 loose passes it
    /// (explicit route exists); RFC 3704 §2.3 FP passes on both member
    /// interfaces (best 2 + alternate 3); RFC 8704 §2.4 EFP additionally
    /// passes the default-only source 203.0.113.5 that loose fails.
    /// Table-driven over (mode, source, ingress) → verdict.
    #[test]
    fn urpf_worked_examples_table() {
        let (sib, rib, cfg) = worked_example();
        let cases = [
            // (generator, source, ingress, expected verdict, citation)
            // Asymmetric arrival: strict blocks, loose/FP pass (RFC 3704 §2.2 vs §2.3/§2.5).
            (
                UrpfMode::Strict,
                "198.51.100.9",
                2,
                Verdict::Valid,
                "RFC 3704 §2.2: received on the forwarding interface",
            ),
            (
                UrpfMode::Strict,
                "198.51.100.9",
                3,
                Verdict::Invalid,
                "RFC 3704 §2.2: asymmetric (hot-potato) arrival breaks strict",
            ),
            (
                UrpfMode::Loose,
                "198.51.100.9",
                3,
                Verdict::Valid,
                "RFC 3704 §2.5: existence of an explicit route suffices",
            ),
            (
                UrpfMode::Fp,
                "198.51.100.9",
                3,
                Verdict::Valid,
                "RFC 3704 §2.3: alternate paths are valid for consideration",
            ),
            (
                UrpfMode::Fp,
                "198.51.100.9",
                2,
                Verdict::Valid,
                "RFC 3704 §2.3: best path member",
            ),
            // Default-only source: only EFP allows it (RFC 8704 §2.4:
            // the FIB's default encompasses the source address).
            (
                UrpfMode::Efp,
                "203.0.113.5",
                3,
                Verdict::Valid,
                "RFC 8704 §2.4: default route encompasses the source",
            ),
            (
                UrpfMode::Loose,
                "203.0.113.5",
                3,
                Verdict::Invalid,
                "RFC 3704 §2.5: default routes are excluded from the lookup",
            ),
            (
                UrpfMode::Strict,
                "203.0.113.5",
                2,
                Verdict::Invalid,
                "no concrete cover; the /0 is not an enforcement constraint (W5)",
            ),
        ];
        for (mode, source, ingress, expected, why) in cases {
            let rules = generate_urpf(mode, &sib, &rib, &cfg);
            let ops = compile(&rules, &cfg);
            let got = evaluate(&ops, ip(source), ingress);
            assert_eq!(
                got, expected,
                "{mode} src {source} ingress {ingress}: {why}"
            );
        }
    }

    /// No mode anywhere: unknown ≠ invalid — nothing is judged, and
    /// nothing would ever be dropped (the Verdict the monitor path
    /// logs).
    #[test]
    fn unjudged_traffic_is_unknown_not_invalid() {
        let (sib, rib, cfg) = worked_example();
        let rules = generate_urpf(UrpfMode::Strict, &sib, &rib, &cfg);
        let ops = compile(&rules, &cfg);
        // Interface 9 has no mode enabled: no opinion.
        assert_eq!(evaluate(&ops, ip("198.51.100.9"), 9), Verdict::Unknown);

        // With no ops at all everything is unknown.
        assert_eq!(evaluate(&[], ip("198.51.100.9"), 2), Verdict::Unknown);
        let empty = compile(&RuleSet::default(), &SavConfig::new());
        assert!(empty.is_empty());
    }

    /// GSC §2.1: "Only the source prefixes recorded in the list will be
    /// considered valid, otherwise invalid" — an IBA-enabled interface
    /// with an empty allowlist denies everything (and the op's action
    /// says what happens next: monitor by default).
    #[test]
    fn iba_with_empty_allowlist_denies_all() {
        let cfg = cfg_iba_2_3();
        let sib = Sib::new(); // no bindings at all
        let rib = rib::Rib::new();
        let rules = generate_urpf(UrpfMode::Strict, &sib, &rib, &cfg);
        let ops = compile(&rules, &cfg);
        assert_eq!(
            ops,
            vec![
                SavOp::IbaPermit {
                    ifindex: 2,
                    prefixes: vec![],
                    action: SavAction::Monitor,
                },
                SavOp::IbaPermit {
                    ifindex: 3,
                    prefixes: vec![],
                    action: SavAction::Monitor,
                },
            ],
            "both IBA-enabled interfaces keep an (empty) allowlist op"
        );
        assert_eq!(evaluate(&ops, ip("198.51.100.9"), 2), Verdict::Invalid);
    }

    /// GSC §2.2: an IBB-listed source is invalid on the listed
    /// interface only; unlisted sources fall through (here: to
    /// Unknown — no router-scale rules).
    #[test]
    fn ibb_blocks_only_the_listed_prefix() {
        let mut cfg = SavConfig::new();
        cfg.enable_interface(3, ValidationMode::Ibb, SavAction::Monitor);
        let rules = RuleSet::from_rules([ibb("192.0.2.0/24", &[3])]);
        let ops = compile(&rules, &cfg);
        assert_eq!(
            ops,
            vec![SavOp::IbbBlock {
                ifindex: 3,
                prefixes: vec!["192.0.2.0/24".parse().unwrap()],
                action: SavAction::Monitor,
            }]
        );
        assert_eq!(evaluate(&ops, ip("192.0.2.7"), 3), Verdict::Invalid);
        assert_eq!(
            evaluate(&ops, ip("198.51.100.9"), 3),
            Verdict::Unknown,
            "unlisted source falls through with no router rules"
        );
        assert_eq!(
            evaluate(&ops, ip("192.0.2.7"), 2),
            Verdict::Unknown,
            "other interfaces are not IBB's business"
        );
    }

    /// GSC §2.3: PBA — "A packet is considered valid only if its
    /// incoming interface is in the interface allowlist for that source
    /// prefix"; an unprotected prefix is not judged at all.
    #[test]
    fn pba_judges_only_its_protected_prefix() {
        let cfg = SavConfig::new();
        let rules = RuleSet::from_rules([pba("198.51.100.0/24", &[2, 3])]);
        let ops = compile(&rules, &cfg);
        assert_eq!(
            ops,
            vec![SavOp::PbaPermit {
                prefix: "198.51.100.0/24".parse().unwrap(),
                ifindexes: vec![2, 3],
                action: SavAction::Monitor,
            }]
        );
        assert_eq!(evaluate(&ops, ip("198.51.100.9"), 2), Verdict::Valid);
        assert_eq!(evaluate(&ops, ip("198.51.100.9"), 3), Verdict::Valid);
        assert_eq!(evaluate(&ops, ip("198.51.100.9"), 4), Verdict::Invalid);
        assert_eq!(
            evaluate(&ops, ip("203.0.113.5"), 4),
            Verdict::Unknown,
            "source outside the protected prefix: no judgment"
        );
    }

    /// GSC §2.4: PBB — invalid only "when its incoming interface is in
    /// the interface blocklist" for the prefix.
    #[test]
    fn pbb_blocks_only_the_listed_direction() {
        let cfg = SavConfig::new();
        let rules = RuleSet::from_rules([pbb("198.51.100.0/24", &[4])]);
        let ops = compile(&rules, &cfg);
        assert_eq!(evaluate(&ops, ip("198.51.100.9"), 4), Verdict::Invalid);
        assert_eq!(evaluate(&ops, ip("198.51.100.9"), 2), Verdict::Valid);
        assert_eq!(evaluate(&ops, ip("203.0.113.5"), 4), Verdict::Unknown);
    }

    /// GSC §3: "If an interface has IBA-SAV enabled, traffic on that
    /// interface does not need to go through any other modes" — an IBA
    /// decision (even Invalid) short-circuits router-scale modes.
    #[test]
    fn iba_short_circuits_router_scale_modes() {
        let mut cfg = cfg_iba_2_3();
        cfg.set_router_action(SavAction::Drop);
        // A PBA rule would call 198.51.100.9 on ingress 3 Valid; the
        // IBA allowlist (strict, egress 2) says Invalid — IBA wins.
        let (sib, rib, cfg2) = {
            let mut rib = rib::Rib::new();
            rib.add_route(static_if_route("198.51.100.0/24", 2));
            (Sib::from_rib(&rib), rib, cfg)
        };
        let strict = generate_urpf(UrpfMode::Strict, &sib, &rib, &cfg2);
        let mut rules = strict.rules().to_vec();
        rules.push(pba("198.51.100.0/24", &[3]));
        let all = RuleSet::from_rules(rules);
        let ops = compile(&all, &cfg2);
        assert_eq!(evaluate(&ops, ip("198.51.100.9"), 3), Verdict::Invalid);
        // Without any interface mode enabled, PBA judges the same
        // packet Valid (only IBA short-circuits it, not the other way
        // round).
        let only_pba = RuleSet::from_rules([pba("198.51.100.0/24", &[3])]);
        let ops2 = compile(&only_pba, &SavConfig::new());
        assert_eq!(evaluate(&ops2, ip("198.51.100.9"), 3), Verdict::Valid);
    }

    /// GSC §3: "IBA-SAV and IBB-SAV ... must not be enabled on same
    /// interface at same time. If they are ..., IBB-SAV should be
    /// ignored" — IBB rules naming an IBA-configured interface compile
    /// to nothing there.
    #[test]
    fn ibb_rules_are_ignored_on_iba_interfaces() {
        let cfg = cfg_iba_2_3();
        let rules = RuleSet::from_rules([
            ibb("192.0.2.0/24", &[2]), // IBA-configured: ignored
            ibb("192.0.2.0/24", &[5]), // unconfigured: also inert
        ]);
        let ops = compile(&rules, &cfg);
        // Both IBA interfaces still get their (empty) allowlists; no
        // IbbBlock op exists.
        assert!(ops.iter().all(|op| !matches!(op, SavOp::IbbBlock { .. })));
        assert_eq!(ops.len(), 2);
        assert_eq!(evaluate(&ops, ip("192.0.2.7"), 2), Verdict::Invalid);
    }

    /// GSC §3: "PBA-SAV and PBB-SAV ... are also mutually exclusive" —
    /// same prefix in both kinds ⇒ PBB dropped, PBA decides.
    #[test]
    fn pbb_is_ignored_where_pba_protects_the_prefix() {
        let cfg = SavConfig::new();
        let rules =
            RuleSet::from_rules([pba("198.51.100.0/24", &[2]), pbb("198.51.100.0/24", &[2])]);
        let ops = compile(&rules, &cfg);
        assert_eq!(ops.len(), 1);
        assert!(matches!(ops[0], SavOp::PbaPermit { .. }));
        assert_eq!(evaluate(&ops, ip("198.51.100.9"), 2), Verdict::Valid);
    }

    /// GSC §3 step 3: "When the IBB-SAV validation result is 'valid',
    /// the traffic must also be checked against PBA-SAV or PBB-SAV" —
    /// an IBB non-match falls through to the router-scale verdict.
    #[test]
    fn ibb_valid_falls_through_to_router_scale() {
        let mut cfg = SavConfig::new();
        cfg.enable_interface(3, ValidationMode::Ibb, SavAction::Monitor);
        let rules = RuleSet::from_rules([
            ibb("192.0.2.0/24", &[3]),
            pba("198.51.100.0/24", &[2]), // arrival 3 not in allowlist
        ]);
        let ops = compile(&rules, &cfg);
        assert_eq!(
            evaluate(&ops, ip("198.51.100.9"), 3),
            Verdict::Invalid,
            "IBB says valid, PBA rejects ingress 3"
        );
        assert_eq!(
            evaluate(&ops, ip("203.0.113.5"), 3),
            Verdict::Unknown,
            "IBB valid + no covering router rule = unknown"
        );
    }

    /// Actions ride the ops as data: interface ops carry the per-
    /// interface action, router ops the router-wide one — and Monitor
    /// is the default everywhere (workspace rule: log before drop).
    #[test]
    fn ops_carry_configured_actions_with_monitor_default() {
        let mut cfg = SavConfig::new();
        cfg.enable_interface(2, ValidationMode::Iba, SavAction::Drop);
        cfg.enable_interface(3, ValidationMode::Iba, SavAction::Monitor);
        let rules = RuleSet::from_rules([pba("10.0.0.0/8", &[2])]);
        let ops = compile(&rules, &cfg);
        assert_eq!(ops[0].action(), SavAction::Drop, "per-interface action");
        let iba_ops: Vec<&SavOp> = ops
            .iter()
            .filter(|op| matches!(op, SavOp::IbaPermit { ifindex: 2, .. }))
            .collect();
        assert_eq!(iba_ops.len(), 1);
        assert_eq!(iba_ops[0].action(), SavAction::Drop);
        let pba_ops: Vec<&SavOp> = ops
            .iter()
            .filter(|op| matches!(op, SavOp::PbaPermit { .. }))
            .collect();
        assert_eq!(pba_ops[0].action(), SavAction::Monitor, "router default");
        let mut cfg_drop_router = cfg.clone();
        cfg_drop_router.set_router_action(SavAction::Drop);
        assert_eq!(
            compile(&rules, &cfg_drop_router)
                .iter()
                .find(|op| matches!(op, SavOp::PbaPermit { .. }))
                .unwrap()
                .action(),
            SavAction::Drop
        );
    }

    /// Compile is deterministic and rule-input-order independent (same
    /// readout as generation, one layer down); overlapping allowlist
    /// prefixes are OR-membership (any contains ⇒ matched).
    #[test]
    fn compile_is_deterministic_and_membership_is_or() {
        let (sib, rib, cfg) = worked_example();
        let strict = generate_urpf(UrpfMode::Strict, &sib, &rib, &cfg);
        let first = compile(&strict, &cfg);
        let second = compile(&strict, &cfg);
        assert_eq!(format!("{first:?}"), format!("{second:?}"));

        // Overlapping prefixes both land on the interface's list; a
        // source covered by either passes.
        let mut cfg2 = SavConfig::new();
        cfg2.enable_interface(2, ValidationMode::Iba, SavAction::Monitor);
        let overlapping = RuleSet::from_rules([
            crate::gen::SavRule::Iba {
                prefix: "10.0.0.0/8".parse().unwrap(),
                interfaces: vec![if_ref(2)],
            },
            crate::gen::SavRule::Iba {
                prefix: "10.1.0.0/16".parse().unwrap(),
                interfaces: vec![if_ref(2)],
            },
        ]);
        let ops = compile(&overlapping, &cfg2);
        let SavOp::IbaPermit { prefixes, .. } = &ops[0] else {
            panic!("expected iba op");
        };
        assert_eq!(prefixes.len(), 2, "both prefixes on the list");
        assert_eq!(evaluate(&ops, ip("10.1.2.3"), 2), Verdict::Valid);
        assert_eq!(evaluate(&ops, ip("10.9.9.9"), 2), Verdict::Valid);
        assert_eq!(evaluate(&ops, ip("192.0.2.1"), 2), Verdict::Invalid);
    }

    /// Router-scale longest-covering-prefix wins when protected
    /// prefixes nest (the PBA /16 shields the source the /24 does not
    /// know about — deterministic choice).
    #[test]
    fn router_scale_longest_covering_prefix_decides() {
        let cfg = SavConfig::new();
        let rules = RuleSet::from_rules([pba("10.0.0.0/8", &[2]), pbb("10.1.0.0/16", &[3])]);
        let ops = compile(&rules, &cfg);
        // 10.1.2.3: the /16 PBB wins over the /8 PBA.
        assert_eq!(evaluate(&ops, ip("10.1.2.3"), 3), Verdict::Invalid);
        assert_eq!(evaluate(&ops, ip("10.1.2.3"), 2), Verdict::Valid);
        // 10.9.9.9: only the /8 covers it.
        assert_eq!(evaluate(&ops, ip("10.9.9.9"), 4), Verdict::Invalid);
    }

    /// Hand-built bindings through the whole pipe (config origin):
    /// strict honors the operator override end to end.
    #[test]
    fn config_binding_flows_through_compile() {
        let cfg = cfg_iba_2_3();
        let mut sib = Sib::new();
        sib.update(Binding {
            prefix: "192.0.2.0/24".parse().unwrap(),
            interfaces: vec![if_ref(3)],
            origin: BindingOrigin::Config,
        })
        .unwrap();
        let rib = rib::Rib::new();
        let rules = generate_urpf(UrpfMode::Strict, &sib, &rib, &cfg);
        let ops = compile(&rules, &cfg);
        assert_eq!(evaluate(&ops, ip("192.0.2.7"), 3), Verdict::Valid);
        assert_eq!(evaluate(&ops, ip("192.0.2.7"), 2), Verdict::Invalid);
    }
}
