//! Rule generation: the uRPF-family equivalence generators
//! (docs/implementation-plan.md §Phase 1.5 "Local rule generation without
//! new wire protocols: strict/loose/FP-uRPF/EFP-uRPF (RFC 3704/8704)
//! equivalence from RIB data").
//!
//! Every generator reads a ([`Sib`], [`Rib`]) snapshot plus the
//! [`SavConfig`] enablement and emits a [`RuleSet`] — pure data, a
//! sorted, deduplicated `Vec` of typed [`SavRule`]s. No I/O, no
//! dataplane programming ([`crate::table::compile`] produces the op
//! list W7's backend consumes).
//!
//! All four generators compile into IBA-SAV-shaped rules (GSC §2.1:
//! "FIB-based strict uRPF belongs to this mode"; loose uRPF is its
//! "extreme example"). The mapping from the SIB's query semantics to
//! rule semantics:
//!
//! | Generator | SIB answer shape used | Rules emitted |
//! |-----------|-----------------------|---------------|
//! | [`Strict`] | concrete egress set of the longest binding | prefix valid on that set (∩ enabled) |
//! | [`Loose`]  | *existence* of a concrete binding | prefix valid on every enabled interface |
//! | [`Fp`]     | strict's set ∪ alternate candidates' egress (from the RIB) | prefix valid on the union (∩ enabled) |
//! | [`Efp`]    | loose, plus the /0 fallback marker's family | one 0/0 (or ::/0) allow-everything rule per default-routed family |
//!
//! Default-route sources (the SIB's [`InterfaceRef::Any`] answer) are
//! deliberately **not** an enforcement constraint of strict/loose/FP —
//! W5 pinned that the stored /0 binding's concrete egress is debug
//! state only. [`Efp`] is the mode that speaks for them.

use std::fmt;

use common::{IpPrefix, RouteProtocol};
use rib::Rib;

use crate::mode::{SavConfig, ValidationMode};
use crate::{prefix_len, rib_egress, BindingOrigin, InterfaceRef, Sib, MAIN_TABLE};

/// Which uRPF-equivalent generator to run.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum UrpfMode {
    /// Strict uRPF (RFC 3704 §2.2; RFC 8704 §2.2): "the source address
    /// is looked up in the FIB — and if the packet is received on the
    /// interface which would be used to forward the traffic to the
    /// source of the packet, it passes the check". Equivalent here: the
    /// source's SIB egress set (best route, ECMP members included) must
    /// contain the arrival interface. Breaks under asymmetric routing
    /// (RFC 3704 §2.2 "hot potato"); a default-routed source gets no
    /// rule anywhere (strict is inapplicable there per RFC 3704 §2.2's
    /// failure modes — see [`UrpfMode::Efp`]).
    Strict,
    /// Loose uRPF equivalent, scoped per the plan as an explicit-route
    /// presence check (RFC 3704 §2.5 semantics: "in the lookup, default
    /// routes are excluded"): the source is merely *routable* — some
    /// concrete binding covers it, any egress. Directionality is
    /// sacrificed (RFC 3704 §2.4), so every concrete prefix is allowed
    /// on every IBA-enabled interface. Default-only sources do **not**
    /// pass (that addition is [`UrpfMode::Efp`]).
    Loose,
    /// Feasible-path uRPF (RFC 3704 §2.3): strict "but instead of just
    /// inserting one best route there, the alternative paths (if any)
    /// have been added as well". Approximation (disclosed): RFC 3704
    /// populates the feasible set "using routing-protocol specific
    /// methods" (e.g. all feasible BGP paths); until a protocol RIB
    /// exposes feasibility, the RIB's full per-prefix candidate list
    /// (every protocol's route — [`rib::Table`] keeps them all) is the
    /// local equivalent: the union of every candidate's resolved
    /// egress, with the best route's ECMP members arriving through the
    /// SIB binding.
    Fp,
    /// Enhanced feasible-path uRPF, scoped per the plan as loose +
    /// "additionally allow sources of prefixes with a default route
    /// only" (RFC 8704): a source covered solely by the default route
    /// passes. With a default route present every source is routable,
    /// so the family compiles to a single 0/0 (or ::/0) allow rule —
    /// GSC §2.1's "extreme example" over-broad allowlist, exactly. RFC
    /// 8704's full EFP-uRPF (origin-AS-grouped RPF lists from
    /// Adj-RIBs-In, §3.1.1/§3.4) needs BGP and is later work; tonight
    /// is the RFC 8704 §2.4-grade loose core of it.
    Efp,
}

impl fmt::Display for UrpfMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let name = match self {
            UrpfMode::Strict => "strict-uRPF",
            UrpfMode::Loose => "loose-uRPF",
            UrpfMode::Fp => "FP-uRPF",
            UrpfMode::Efp => "EFP-uRPF",
        };
        f.write_str(name)
    }
}

/// Where a rule came from (B5 observation 5): rule sources are plural
/// by design — operator statics, the FIB, BGP, a SAVNET agent — and
/// this field records which one spoke, for W7/W8 logging. Purely
/// informational provenance: never an enforcement input, and
/// deliberately optional ([`Option`]) so builders that have no source
/// to name (tests, future rule builders) carry none.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum RuleOrigin {
    /// Statically configured: an operator's binding or rule
    /// (`sav.conf`-shaped config).
    Static,
    /// FIB-derived: the uRPF-equivalence generators reading a
    /// RIB-learned best route that is not BGP.
    Fib,
    /// A BGP-learned best route's binding.
    Bgp,
    /// A SAVNET agent's rule (the draft-dependent signaling behind
    /// `experimental-savnet`; nothing sets it tonight).
    SavnetAgent,
}

impl fmt::Display for RuleOrigin {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let name = match self {
            RuleOrigin::Static => "static",
            RuleOrigin::Fib => "fib",
            RuleOrigin::Bgp => "bgp",
            RuleOrigin::SavnetAgent => "savnet-agent",
        };
        f.write_str(name)
    }
}

/// One typed SAV rule: a source prefix mapped to the interfaces the
/// rule speaks for, tagged with its validation mode. Pure data; rule
/// sets are ordered deterministically (see [`RuleSet`]).
///
/// Every rule optionally carries its [`RuleOrigin`] provenance (B5
/// observation 5) — informational only, never an enforcement input.
///
/// Semantics per variant (GSC §2.1–§2.4):
/// - [`Iba`](SavRule::Iba): sources in `prefix` are valid on
///   `interfaces`, invalid on other IBA-enabled interfaces.
/// - [`Ibb`](SavRule::Ibb): sources in `prefix` are invalid on
///   `interfaces`; IBB-valid sources still fall through to
///   router-scale modes (GSC §3).
/// - [`Pba`](SavRule::Pba): `prefix` is a *protected* prefix — its
///   sources are valid only on `interfaces` (router scale).
/// - [`Pbb`](SavRule::Pbb): `prefix`'s sources are invalid on
///   `interfaces` (router scale).
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum SavRule {
    /// Interface-based prefix allowlist entry (GSC §2.1).
    Iba {
        /// Sources inside this prefix pass on `interfaces`.
        prefix: IpPrefix,
        /// The interfaces the rule covers (concrete refs; the SIB's
        /// `Any` marker never appears in generated rules).
        interfaces: Vec<InterfaceRef>,
        /// Which source produced this rule (B5 observation 5);
        /// `None` when the builder did not say.
        origin: Option<RuleOrigin>,
    },
    /// Interface-based prefix blocklist entry (GSC §2.2).
    Ibb {
        /// Sources inside this prefix fail on `interfaces`.
        prefix: IpPrefix,
        interfaces: Vec<InterfaceRef>,
        origin: Option<RuleOrigin>,
    },
    /// Prefix-based interface allowlist entry (GSC §2.3).
    Pba {
        /// The protected source prefix.
        prefix: IpPrefix,
        /// The only interfaces its sources may arrive on.
        interfaces: Vec<InterfaceRef>,
        origin: Option<RuleOrigin>,
    },
    /// Prefix-based interface blocklist entry (GSC §2.4).
    Pbb {
        /// The protected source prefix.
        prefix: IpPrefix,
        /// The interfaces its sources may never arrive on.
        interfaces: Vec<InterfaceRef>,
        origin: Option<RuleOrigin>,
    },
}

impl SavRule {
    /// The rule's source prefix.
    pub fn prefix(&self) -> IpPrefix {
        match *self {
            SavRule::Iba { prefix, .. }
            | SavRule::Ibb { prefix, .. }
            | SavRule::Pba { prefix, .. }
            | SavRule::Pbb { prefix, .. } => prefix,
        }
    }

    /// The rule's interface list.
    pub fn interfaces(&self) -> &[InterfaceRef] {
        match self {
            SavRule::Iba { interfaces, .. }
            | SavRule::Ibb { interfaces, .. }
            | SavRule::Pba { interfaces, .. }
            | SavRule::Pbb { interfaces, .. } => interfaces,
        }
    }

    /// The validation mode this rule belongs to.
    pub fn mode(&self) -> ValidationMode {
        match *self {
            SavRule::Iba { .. } => ValidationMode::Iba,
            SavRule::Ibb { .. } => ValidationMode::Ibb,
            SavRule::Pba { .. } => ValidationMode::Pba,
            SavRule::Pbb { .. } => ValidationMode::Pbb,
        }
    }

    /// The rule's provenance, when its builder said one (B5
    /// observation 5) — informational only.
    pub fn origin(&self) -> Option<RuleOrigin> {
        match *self {
            SavRule::Iba { origin, .. }
            | SavRule::Ibb { origin, .. }
            | SavRule::Pba { origin, .. }
            | SavRule::Pbb { origin, .. } => origin,
        }
    }
}

impl fmt::Display for SavRule {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        use crate::mode::ModePolarity;
        let ifaces: Vec<String> = self.interfaces().iter().map(|i| i.to_string()).collect();
        write!(
            f,
            "{} {} {} [{}]",
            self.mode(),
            match self.mode().polarity() {
                ModePolarity::Allow => "permit",
                ModePolarity::Block => "block",
            },
            self.prefix(),
            ifaces.join(", ")
        )?;
        match self.origin() {
            Some(origin) => write!(f, " (from {origin})"),
            None => Ok(()),
        }
    }
}

/// A deterministic rule set: sorted (variant order Iba < Ibb < Pba <
/// Pbb — the derive — then prefix, then interface list) and
/// deduplicated. The same (Sib, Rib, SavConfig) input always yields a
/// byte-identical set.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RuleSet {
    rules: Vec<SavRule>,
}

impl RuleSet {
    /// Build from rules, normalizing to the canonical sorted+deduped
    /// order (idempotent: re-normalizing a RuleSet is a no-op).
    pub fn from_rules(rules: impl IntoIterator<Item = SavRule>) -> Self {
        let mut rules: Vec<SavRule> = rules.into_iter().collect();
        rules.sort();
        rules.dedup();
        Self { rules }
    }

    /// The canonical-order rules.
    pub fn rules(&self) -> &[SavRule] {
        &self.rules
    }

    /// True when no rule was generated.
    pub fn is_empty(&self) -> bool {
        self.rules.is_empty()
    }

    /// Number of rules.
    pub fn len(&self) -> usize {
        self.rules.len()
    }
}

/// Generate the IBA-SAV rule set equivalent to `mode`'s uRPF flavor,
/// from the current (Sib, Rib) view and enforcement config.
///
/// Only interfaces enabled for [`ValidationMode::Iba`] receive rules —
/// the generators never touch IBB/PBA/PBB surfaces. Deterministic:
/// rule order comes from [`RuleSet`]'s canonical sort, interface lists
/// are built in ifindex order, and inputs are only read.
pub fn generate_urpf(mode: UrpfMode, sib: &Sib, rib: &Rib, cfg: &SavConfig) -> RuleSet {
    let enabled = iba_enabled_refs(cfg, rib);
    // One binding per prefix (Config shadows Rib — the same precedence
    // interfaces_for applies), so the rule set never speaks twice for
    // one prefix.
    let bindings = sib.effective_bindings();
    match mode {
        // Strict: the best route's egress set (SIB binding, ECMP
        // members included) is the allow set (RFC 3704 §2.2).
        UrpfMode::Strict => RuleSet::from_rules(
            bindings
                .filter(|b| prefix_len(b.prefix) > 0)
                .filter_map(|b| {
                    let origin = rule_origin(rib, &b.origin, b.prefix);
                    restrict(&b.interfaces, &enabled).map(|interfaces| SavRule::Iba {
                        prefix: b.prefix,
                        interfaces,
                        origin,
                    })
                }),
        ),
        // Loose: any concrete binding makes the source routable on
        // every enabled interface (directionality sacrificed, RFC 3704
        // §2.4/§2.5); the /0 binding itself is not a constraint.
        UrpfMode::Loose => {
            RuleSet::from_rules(bindings.filter(|b| prefix_len(b.prefix) > 0).map(|b| {
                SavRule::Iba {
                    prefix: b.prefix,
                    interfaces: enabled.clone(),
                    origin: rule_origin(rib, &b.origin, b.prefix),
                }
            }))
        }
        // FP: strict's set unioned with every RIB candidate's egress
        // (the best route's own egress is already the SIB binding).
        UrpfMode::Fp => RuleSet::from_rules(
            bindings
                .filter(|b| prefix_len(b.prefix) > 0)
                .filter_map(|b| {
                    let mut feasible = b.interfaces.clone();
                    if b.origin == BindingOrigin::Rib {
                        feasible.extend(alternate_egress(rib, b.prefix));
                    }
                    let origin = rule_origin(rib, &b.origin, b.prefix);
                    restrict(&feasible, &enabled).map(|interfaces| SavRule::Iba {
                        prefix: b.prefix,
                        interfaces,
                        origin,
                    })
                }),
        ),
        // EFP: per family, a present default route makes every source
        // routable (one 0/0-or-::/0 rule subsumes the concrete list);
        // without one, the family degenerates to loose.
        UrpfMode::Efp => RuleSet::from_rules(bindings.filter_map(|b| {
            if prefix_len(b.prefix) == 0 {
                Some(SavRule::Iba {
                    prefix: b.prefix,
                    interfaces: enabled.clone(),
                    origin: rule_origin(rib, &b.origin, b.prefix),
                })
            } else if sib_has_default(sib, family_of(b.prefix)) {
                None
            } else {
                Some(SavRule::Iba {
                    prefix: b.prefix,
                    interfaces: enabled.clone(),
                    origin: rule_origin(rib, &b.origin, b.prefix),
                })
            }
        })),
    }
}

/// The provenance a generated rule carries for one binding (B5
/// observation 5): operator config is [`RuleOrigin::Static`];
/// RIB-derived rules are [`RuleOrigin::Fib`], except that a
/// BGP-learned best route is called out as [`RuleOrigin::Bgp`] — the
/// binding does not remember the protocol, so the best route is
/// re-read here. [`RuleOrigin::SavnetAgent`] arrives with the agent.
fn rule_origin(rib: &Rib, binding: &BindingOrigin, prefix: IpPrefix) -> Option<RuleOrigin> {
    match binding {
        BindingOrigin::Config => Some(RuleOrigin::Static),
        BindingOrigin::Rib => {
            let bgp = rib
                .table(MAIN_TABLE)
                .and_then(|table| table.best(&prefix))
                .is_some_and(|best| best.protocol == RouteProtocol::Bgp);
            Some(if bgp {
                RuleOrigin::Bgp
            } else {
                RuleOrigin::Fib
            })
        }
    }
}

/// The IBA-enabled interfaces as concrete refs (ifindex order; names
/// from the RIB's interface mirror, empty placeholder names kept as
/// `None` — same rule as the SIB's ingestion).
fn iba_enabled_refs(cfg: &SavConfig, rib: &Rib) -> Vec<InterfaceRef> {
    cfg.enabled_interfaces(ValidationMode::Iba)
        .into_iter()
        .map(|ifindex| InterfaceRef::If {
            ifindex,
            name: rib
                .interfaces()
                .get(&ifindex)
                .and_then(|iface| (!iface.name.is_empty()).then(|| iface.name.clone())),
        })
        .collect()
}

/// Keep only enabled interfaces (sorted, deduped); `None` when nothing
/// survives — the prefix then appears in no interface's allowlist,
/// which *is* its strict/FP semantics on the enabled set (invalid
/// everywhere enabled), so no empty-interface rule is emitted.
fn restrict(interfaces: &[InterfaceRef], enabled: &[InterfaceRef]) -> Option<Vec<InterfaceRef>> {
    let mut kept: Vec<InterfaceRef> = interfaces
        .iter()
        .filter(|i| enabled.iter().any(|e| same_ifindex(e, i)))
        .cloned()
        .collect();
    if kept.is_empty() {
        None
    } else {
        kept.sort();
        kept.dedup();
        Some(kept)
    }
}

/// Interface identity is the ifindex; names are cosmetic mirror state
/// (two refs with the same ifindex are the same interface).
fn same_ifindex(a: &InterfaceRef, b: &InterfaceRef) -> bool {
    match (a.ifindex(), b.ifindex()) {
        (Some(x), Some(y)) => x == y,
        _ => false,
    }
}

/// Whether the SIB holds a /0 binding of this family (either origin).
fn sib_has_default(sib: &Sib, family: Family) -> bool {
    sib.bindings()
        .any(|b| prefix_len(b.prefix) == 0 && family_of(b.prefix) == family)
}

/// The resolved egress interfaces of every RIB candidate for `prefix`
/// (all protocols' routes, not just the best — RFC 3704 §2.3's
/// alternates). Best-unresolvable prefixes never reach here: the SIB
/// skipped them, so no binding exists to expand.
fn alternate_egress(rib: &Rib, prefix: IpPrefix) -> Vec<InterfaceRef> {
    let mut out = Vec::new();
    if let Some(table) = rib.table(MAIN_TABLE) {
        for (p, candidates) in table.iter() {
            if *p != prefix {
                continue;
            }
            for entry in candidates {
                out.extend(rib_egress(rib, &entry.nexthops));
            }
        }
    }
    out.sort();
    out.dedup();
    out
}

/// Address family of a prefix (for the per-family default lookup).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Family {
    V4,
    V6,
}

fn family_of(prefix: IpPrefix) -> Family {
    match prefix {
        IpPrefix::V4(_) => Family::V4,
        IpPrefix::V6(_) => Family::V6,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mode::{SavAction, ValidationMode};
    use crate::{Binding, BindingOrigin};
    use common::{Nexthop, NexthopGroup, RouteEntry, RouteProtocol};

    fn ip(s: &str) -> std::net::IpAddr {
        s.parse().unwrap()
    }

    fn if_ref(ifindex: u32) -> InterfaceRef {
        InterfaceRef::If {
            ifindex,
            name: None,
        }
    }

    fn rib_binding(prefix: &str, ifindexes: &[u32]) -> Binding {
        Binding {
            prefix: prefix.parse().unwrap(),
            interfaces: ifindexes.iter().map(|&ix| if_ref(ix)).collect(),
            origin: BindingOrigin::Rib,
            expires_at: None,
        }
    }

    fn config_binding(prefix: &str, ifindexes: &[u32]) -> Binding {
        Binding {
            prefix: prefix.parse().unwrap(),
            interfaces: ifindexes.iter().map(|&ix| if_ref(ix)).collect(),
            origin: BindingOrigin::Config,
            expires_at: None,
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

    /// IBA on ifaces 2 and 3, monitor action — the standard fixture.
    fn cfg_iba_2_3() -> SavConfig {
        let mut cfg = SavConfig::new();
        cfg.enable_interface(2, ValidationMode::Iba, SavAction::Monitor);
        cfg.enable_interface(3, ValidationMode::Iba, SavAction::Monitor);
        cfg
    }

    /// The expected shape of a generated rule: rib-derived provenance
    /// (`Fib`) — the generators' common case in the fixtures below.
    fn iba(prefix: &str, ifindexes: &[u32]) -> SavRule {
        iba_of(prefix, ifindexes, Some(RuleOrigin::Fib))
    }

    /// …with operator-config provenance (a Config binding's rule).
    fn iba_static(prefix: &str, ifindexes: &[u32]) -> SavRule {
        iba_of(prefix, ifindexes, Some(RuleOrigin::Static))
    }

    fn iba_of(prefix: &str, ifindexes: &[u32], origin: Option<RuleOrigin>) -> SavRule {
        SavRule::Iba {
            prefix: prefix.parse().unwrap(),
            interfaces: ifindexes.iter().map(|&ix| if_ref(ix)).collect(),
            origin,
        }
    }

    /// The asymmetric-routing topology: 198.51.100.0/24's best route
    /// egresses via ifindex 2 only.
    fn asymmetric_sib_rib() -> (Sib, Rib) {
        let mut rib = Rib::new();
        rib.add_route(static_if_route("198.51.100.0/24", 2));
        let sib = Sib::from_rib(&rib);
        (sib, rib)
    }

    /// …plus a never-best BGP alternate via ifindex 3 (admin distance
    /// 20 vs static's 1) — exactly RFC 3704 §2.3's "alternative paths".
    fn asymmetric_sib_rib_with_alternate() -> (Sib, Rib) {
        let mut rib = Rib::new();
        rib.add_route(static_if_route("198.51.100.0/24", 2));
        let mut alternate = static_if_route("198.51.100.0/24", 3);
        alternate.protocol = RouteProtocol::Bgp;
        rib.add_route(alternate);
        let sib = Sib::from_rib(&rib);
        (sib, rib)
    }

    /// RFC 3704 §2.2 (strict): asymmetric routing — "the test is only
    /// applicable in places where routing is symmetrical"; §2.4/§2.5
    /// (loose): "it checks only for the existence of a route, not where
    /// the route points to". Table-driven: the same source arriving on
    /// the wrong-side interface is blocked by strict and passed by
    /// loose.
    #[test]
    fn strict_blocks_asymmetric_arrival_while_loose_passes() {
        let (sib, rib) = asymmetric_sib_rib();
        let cfg = cfg_iba_2_3();
        let strict = generate_urpf(UrpfMode::Strict, &sib, &rib, &cfg);
        assert_eq!(strict.rules(), &[iba("198.51.100.0/24", &[2])]);

        let loose = generate_urpf(UrpfMode::Loose, &sib, &rib, &cfg);
        assert_eq!(loose.rules(), &[iba("198.51.100.0/24", &[2, 3])]);
    }

    /// RFC 3704 §2.3 (FP-uRPF): "instead of just inserting one best
    /// route there, the alternative paths (if any) have been added as
    /// well, and are valid for consideration". The /24 has best via
    /// ifindex 2 and a BGP alternate via ifindex 3: FP's rule covers
    /// both member interfaces; strict stays best-only. ECMP inside the
    /// best route is covered the same way (the SIB binding carries all
    /// group members).
    #[test]
    fn fp_passes_on_all_feasible_member_interfaces() {
        let (sib, rib) = asymmetric_sib_rib_with_alternate();
        let cfg = cfg_iba_2_3();

        let fp = generate_urpf(UrpfMode::Fp, &sib, &rib, &cfg);
        assert_eq!(fp.rules(), &[iba("198.51.100.0/24", &[2, 3])]);

        let strict = generate_urpf(UrpfMode::Strict, &sib, &rib, &cfg);
        assert_eq!(
            strict.rules(),
            &[iba("198.51.100.0/24", &[2])],
            "strict remains best-route-only"
        );

        // ECMP in the best route itself: both members are feasible for
        // strict already (RFC 8704 §2.2's forwarding-information set).
        let mut rib_ecmp = Rib::new();
        let mut group = NexthopGroup::new();
        group.add(Nexthop::IfIndex(2), 1);
        group.add(Nexthop::IfIndex(3), 1);
        rib_ecmp.add_route(RouteEntry::new(
            "203.0.113.0/24".parse().unwrap(),
            RouteProtocol::Static,
            group,
            0,
        ));
        let sib_ecmp = Sib::from_rib(&rib_ecmp);
        assert_eq!(
            generate_urpf(UrpfMode::Strict, &sib_ecmp, &rib_ecmp, &cfg).rules(),
            &[iba("203.0.113.0/24", &[2, 3])]
        );
    }

    /// RFC 8704 §2.4 (the loose core EFP builds on): an ingress packet
    /// "is accepted only if the FIB has one or more prefixes that
    /// encompass the source address" — a default route encompasses
    /// every source of its family. Plan-scoped loose (explicit-route
    /// presence, RFC 3704 §2.5) still fails default-only sources; EFP
    /// is the mode that allows them.
    #[test]
    fn efp_passes_default_only_sources_that_loose_still_fails() {
        let mut rib = Rib::new();
        rib.add_route(static_if_route("198.51.100.0/24", 2));
        rib.add_route(static_if_route("0.0.0.0/0", 2));
        let sib = Sib::from_rib(&rib);
        let cfg = cfg_iba_2_3();

        // The default-only source 203.0.113.5: only the /0 covers it.
        let efp = generate_urpf(UrpfMode::Efp, &sib, &rib, &cfg);
        assert_eq!(efp.rules(), &[iba("0.0.0.0/0", &[2, 3])]);

        let loose = generate_urpf(UrpfMode::Loose, &sib, &rib, &cfg);
        assert_eq!(
            loose.rules(),
            &[iba("198.51.100.0/24", &[2, 3])],
            "loose emits concrete prefixes only (default excluded, RFC 3704 §2.5)"
        );

        // Without a default in the family, EFP degenerates to loose.
        let mut rib_nodefault = Rib::new();
        rib_nodefault.add_route(static_if_route("198.51.100.0/24", 2));
        let sib_nodefault = Sib::from_rib(&rib_nodefault);
        assert_eq!(
            generate_urpf(UrpfMode::Efp, &sib_nodefault, &rib_nodefault, &cfg).rules(),
            &[iba("198.51.100.0/24", &[2, 3])]
        );
    }

    /// The stored /0 binding is debug state, never an enforcement
    /// constraint (W5): strict, loose and FP emit no rule from it —
    /// only EFP consults its presence.
    #[test]
    fn strict_loose_and_fp_skip_the_default_binding() {
        let mut rib = Rib::new();
        rib.add_route(static_if_route("0.0.0.0/0", 2));
        let sib = Sib::from_rib(&rib);
        let cfg = cfg_iba_2_3();
        for mode in [UrpfMode::Strict, UrpfMode::Loose, UrpfMode::Fp] {
            assert!(
                generate_urpf(mode, &sib, &rib, &cfg).is_empty(),
                "{mode} must not turn the default route into a rule"
            );
        }
    }

    /// Config-origin bindings flow through every generator; FP unions
    /// RIB alternates into Rib-origin bindings only (the operator spoke
    /// for Config ones).
    #[test]
    fn config_bindings_drive_generation_without_fp_expansion() {
        let (sib, rib) = asymmetric_sib_rib_with_alternate();
        let mut sib = sib;
        sib.update(config_binding("198.51.100.0/24", &[3])).unwrap();
        let cfg = cfg_iba_2_3();

        assert_eq!(
            generate_urpf(UrpfMode::Strict, &sib, &rib, &cfg).rules(),
            &[iba_static("198.51.100.0/24", &[3])],
            "the config binding replaced the rib one in the SIB"
        );
        assert_eq!(
            generate_urpf(UrpfMode::Fp, &sib, &rib, &cfg).rules(),
            &[iba_static("198.51.100.0/24", &[3])],
            "no alternate union into an operator-pinned binding"
        );

        // Both origins present on distinct prefixes: loose covers both.
        let mut sib2 = Sib::new();
        sib2.update(rib_binding("10.0.0.0/8", &[2])).unwrap();
        sib2.update(config_binding("192.0.2.0/24", &[3])).unwrap();
        let rib_empty = Rib::new();
        assert_eq!(
            generate_urpf(UrpfMode::Loose, &sib2, &rib_empty, &cfg).rules(),
            &[
                iba("10.0.0.0/8", &[2, 3]),
                iba_static("192.0.2.0/24", &[2, 3])
            ]
        );
    }

    /// Rules only ever reference IBA-enabled interfaces; a binding whose
    /// egress misses the enabled set emits no rule (its sources are
    /// simply in no allowlist — invalid everywhere enabled, which *is*
    /// the strict semantics there). With nothing enabled, nothing is
    /// generated at all.
    #[test]
    fn rules_are_restricted_to_enabled_interfaces() {
        let mut sib = Sib::new();
        sib.update(rib_binding("10.1.0.0/16", &[7])).unwrap();
        sib.update(rib_binding("10.2.0.0/16", &[2, 7])).unwrap();
        let rib = Rib::new();
        let cfg = cfg_iba_2_3();
        let strict = generate_urpf(UrpfMode::Strict, &sib, &rib, &cfg);
        assert_eq!(strict.rules(), &[iba("10.2.0.0/16", &[2])]);

        let mut sib2 = Sib::new();
        sib2.update(rib_binding("10.0.0.0/8", &[2])).unwrap();
        let cfg_none = SavConfig::new();
        assert!(
            generate_urpf(UrpfMode::Strict, &sib2, &rib, &cfg_none).is_empty(),
            "no IBA-enabled interface, no rules"
        );
    }

    /// Per-family defaults: a v6 default opens only the v6 family's EFP
    /// rule; v4 stays concrete-only.
    #[test]
    fn efp_default_handling_is_per_family() {
        let mut rib = Rib::new();
        rib.add_route(static_if_route("198.51.100.0/24", 2));
        rib.add_route(static_if_route("2001:db8:1::/48", 3));
        rib.add_route(static_if_route("::/0", 3));
        let sib = Sib::from_rib(&rib);
        let cfg = cfg_iba_2_3();
        let efp = generate_urpf(UrpfMode::Efp, &sib, &rib, &cfg);
        assert_eq!(
            efp.rules(),
            &[iba("198.51.100.0/24", &[2, 3]), iba("::/0", &[2, 3]),],
            "v4 keeps concrete prefixes (no v4 default); v6 collapses to ::/0"
        );
    }

    /// DETERMINISM readout core: same (Sib, Rib, SavConfig) input ⇒
    /// byte-identical rule set, and RuleSet normalization is a stable
    /// sort+dedup regardless of input order.
    #[test]
    fn generation_is_byte_identical_across_runs() {
        let (sib, rib) = asymmetric_sib_rib_with_alternate();
        let mut sib = sib;
        sib.update(rib_binding("10.0.0.0/8", &[2, 3])).unwrap();
        sib.update(config_binding("192.0.2.0/24", &[3])).unwrap();
        let cfg = cfg_iba_2_3();
        for mode in [
            UrpfMode::Strict,
            UrpfMode::Loose,
            UrpfMode::Fp,
            UrpfMode::Efp,
        ] {
            let first = generate_urpf(mode, &sib, &rib, &cfg);
            let second = generate_urpf(mode, &sib, &rib, &cfg);
            assert_eq!(format!("{first:?}"), format!("{second:?}"), "{mode}");
        }
        // Normalization: order and duplicates in hand-built input do
        // not leak through.
        let a = RuleSet::from_rules([
            iba("10.0.0.0/8", &[2]),
            iba("10.0.0.0/8", &[2]),
            iba("192.0.2.0/24", &[3]),
        ]);
        let b = RuleSet::from_rules([iba("192.0.2.0/24", &[3]), iba("10.0.0.0/8", &[2])]);
        assert_eq!(a, b);
        assert_eq!(a.len(), 2);
    }

    /// Generated interface lists are normalized ifindex order regardless
    /// of binding insertion order (determinism at the rule-field level).
    #[test]
    fn generated_interface_lists_are_sorted() {
        let mut sib = Sib::new();
        sib.update(rib_binding("10.9.0.0/16", &[7, 2])).unwrap();
        let rib = Rib::new();
        let mut cfg = cfg_iba_2_3();
        cfg.enable_interface(7, ValidationMode::Iba, SavAction::Monitor);
        let strict = generate_urpf(UrpfMode::Strict, &sib, &rib, &cfg);
        assert_eq!(strict.rules(), &[iba("10.9.0.0/16", &[2, 7])]);
    }

    /// B5 observation 5: rule sources are plural by design, so every
    /// generated rule records which one spoke — RIB-derived rules are
    /// Fib (a BGP-learned best route is called out as Bgp), an
    /// operator-configured binding is Static, and a hand-built rule
    /// that said nothing stays None.
    #[test]
    fn generated_rules_record_their_source() {
        let cfg = cfg_iba_2_3();

        // Rib-derived, static best route: Fib.
        let (sib, rib) = asymmetric_sib_rib();
        let strict = generate_urpf(UrpfMode::Strict, &sib, &rib, &cfg);
        assert_eq!(strict.rules()[0].origin(), Some(RuleOrigin::Fib));

        // A BGP-learned best route (the binding is Rib-origin; the
        // protocol is re-read from the best route): Bgp.
        let mut rib_bgp = Rib::new();
        let mut r = static_if_route("198.51.100.0/24", 2);
        r.protocol = RouteProtocol::Bgp;
        rib_bgp.add_route(r);
        let sib_bgp = Sib::from_rib(&rib_bgp);
        assert_eq!(
            generate_urpf(UrpfMode::Strict, &sib_bgp, &rib_bgp, &cfg).rules()[0].origin(),
            Some(RuleOrigin::Bgp)
        );

        // Operator-configured binding: Static.
        let mut sib_cfg = Sib::new();
        sib_cfg
            .update(config_binding("192.0.2.0/24", &[2]))
            .unwrap();
        assert_eq!(
            generate_urpf(UrpfMode::Strict, &sib_cfg, &Rib::new(), &cfg).rules()[0].origin(),
            Some(RuleOrigin::Static)
        );

        // A builder that said nothing: absent stays None.
        let hand = iba_of("10.0.0.0/8", &[2], None);
        assert_eq!(hand.origin(), None);
    }

    /// The `ip` helper keeps worked-example sources honest (parse
    /// sanity for the addresses the RFC examples cite).
    #[test]
    fn worked_example_sources_parse() {
        assert_eq!(
            ip("198.51.100.9").to_string(),
            "198.51.100.9",
            "RFC 5737 doc range used by the asymmetric example"
        );
        assert_eq!(ip("203.0.113.5").to_string(), "203.0.113.5");
    }
}
