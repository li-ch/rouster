//! The SAV Information Base (SIB): the typed store of source-prefix ↔
//! interface bindings.
//!
//! Architecture position (docs/architecture.md §2 and §3): SAV is a
//! first-class core subsystem — "SAV: SIB · validation-mode rules · table
//! manager" — living in the core and *enforcing via the dataplane trait*.
//! This crate is the first of those three boxes. The SIB only stores
//! bindings and answers queries; it never decides and never drops — the
//! SAVNET rules bind downstream: enforcement defaults to log/monitor
//! before drop, and **unknown ≠ invalid** (an "empty" or "any interface"
//! answer is *no conclusion*, never a spoof verdict).
//!
//! Bindings derive from the RIB tonight ([`Sib::from_rib`]: the merged
//! best of the main table's protocol candidates and its CONNECT set —
//! the C2-ratified fold-in onto the S1 explicit rib surfaces, 2026-10-11
//! — with egress interfaces resolved through the recursive resolver)
//! and from operator config (the `binding` lines [`savd`] parses, fed
//! through [`Sib::replace_origin`] as the Config origin). Everything
//! here is in-process, synchronous, and side-effect-free on the
//! dataplane: no IPC, no wire formats. The one draft-dependent surface
//! — the SAVNET agent interface — lives behind the crate's
//! `experimental-savnet` feature (default OFF; see [`agent`] when
//! compiled in).
//!
//! Bindings may carry an optional expiry ([`Binding::expires_at`], aged
//! out by [`Sib::sweep`]) so stale *dynamically-learned* state cannot
//! live forever — the ageing hook the SAVNET agent (a future dynamic
//! origin) will refresh on confirmation. Honest disclosure: **no landed
//! origin sets a finite TTL yet**. Rib-derived bindings are wholesale
//! re-derived on every re-ingest (effectively fresh, so no deadline is
//! stamped), and Config bindings are operator-pinned: the SIB rejects
//! an expiry on them at insertion ([`SavError::PinnedExpiry`]) — pinned
//! means pinned. The mechanism is landed and wired ([`savd`]'s evaluate
//! sweeps once per cycle), waiting for an origin that learns.
//!
//! Slice 2 completed the rule layer between the SIB and enforcement:
//! [`mode`] (the IBA/IBB/PBA/PBB validation-mode taxonomy and
//! per-interface enablement), [`gen`] (strict/loose/FP/EFP-uRPF
//! equivalence rule generation from a (Sib, Rib) view), and [`table`]
//! (the SAV Table Manager compile step: rules → `SavOp`s with their
//! Monitor/Drop action as data, plus the reference evaluation
//! semantics). Slice 3 bridged enforcement: [`program`] converts
//! compiled ops into the backend-neutral [`common::SavProgram`] the
//! `Dataplane` trait installs, and [`monitor`] is the route-lookup
//! counting surface monitor mode falls back to when the backend
//! exposes no kernel counters. Slice 4 (W8) wired the daemon:
//! [`savd`] holds the SIB, keeps a RIB view over the ZAPI client edge,
//! regenerates + installs rules on the poll cadence (SIGHUP = full
//! reload), and refuses to start in drop mode without the explicit
//! `i-understand-drop-mode yes` friction line.

pub mod gen;
pub mod mode;
pub mod monitor;
pub mod program;
pub mod savd;
pub mod table;

#[cfg(feature = "experimental-savnet")]
pub mod agent;

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::net::IpAddr;
use std::time::Instant;

use common::{IpPrefix, Nexthop, NexthopGroup, TableId};
use rib::Rib;
use tracing::{debug, info};

/// The table the SIB ingests: `RT_TABLE_MAIN` (254), the FIB of the
/// default namespace. VRF tables are deliberately not read — a binding
/// derived inside a VRF would be wrong for the default namespace
/// (VRF-scoped SAV is Phase-1+ work; the W4 `Rib::vrf_of_table`
/// association is the surface it will build on).
pub(crate) const MAIN_TABLE: TableId = 254;

/// Errors from storing bindings. The SIB's stored invariants: a binding
/// always names at least one *concrete* egress interface, the
/// query-only [`InterfaceRef::Any`] marker is never stored, and an
/// operator-pinned (Config-origin) binding never carries an expiry.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum SavError {
    #[error("binding for {prefix} names no interfaces")]
    EmptyBinding { prefix: IpPrefix },
    #[error("binding for {prefix} carries the query-only any-interface marker")]
    MarkerInBinding { prefix: IpPrefix },
    #[error("binding for {prefix} is operator-pinned (config origin) and cannot carry an expiry")]
    PinnedExpiry { prefix: IpPrefix },
}

/// Where a SIB binding came from. Precedence is documented on
/// [`Sib::interfaces_for`]: longest prefix first; at the same prefix,
/// Config overrides Rib (operator override).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum BindingOrigin {
    /// Derived from the RIB: best main-table routes whose egress
    /// interfaces resolve. Recomputed wholesale by [`Sib::ingest_rib`].
    /// This is the dynamically-learned slot: these bindings (and only
    /// these) may carry an [`Binding::expires_at`] to age out stale
    /// learning — today's derivation stamps none (the wholesale
    /// re-ingest already refreshes them), leaving the TTL for the
    /// SAVNET agent's future dynamic feed.
    Rib,
    /// Statically configured (`sav.conf`-shaped
    /// `binding <prefix> interface <name>...` lines, fed wholesale by
    /// savd — see [`crate::savd::SavdConfig::bindings`]).
    /// Operator-pinned: a Config binding can never expire (insertion
    /// rejects an expiry with [`SavError::PinnedExpiry`]).
    Config,
}

impl fmt::Display for BindingOrigin {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            BindingOrigin::Rib => write!(f, "rib"),
            BindingOrigin::Config => write!(f, "config"),
        }
    }
}

/// One element of a SIB query answer. `If` variants are the only things
/// ever stored in a [`Binding`]; `Any` is synthesized by
/// [`Sib::interfaces_for`] for the default-route fallback and is rejected
/// at insertion time ([`SavError::MarkerInBinding`]).
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum InterfaceRef {
    /// A concrete egress interface: kernel ifindex plus the mirrored
    /// interface name when the RIB has observed the link.
    If {
        ifindex: u32,
        /// `None` when the ifindex has no mirrored link state (a route
        /// pointing at an interface no dataplane event has shown us).
        name: Option<String>,
    },
    /// The default-route fallback marker: the longest matching binding is
    /// the default route, so the SIB cannot constrain the ingress
    /// interface — "any interface". This is a *marker*, not a wildcard
    /// binding: the SIB never stores "all interfaces"; the stored default
    /// binding keeps its concrete egress for debug/snapshot while the
    /// query path answers the marker. Downstream this means *no
    /// conclusion* (unknown ≠ invalid): log/monitor, do not drop.
    Any,
}

impl InterfaceRef {
    /// The kernel ifindex of a concrete interface ref; `None` for the
    /// `Any` marker.
    pub fn ifindex(&self) -> Option<u32> {
        match self {
            InterfaceRef::If { ifindex, .. } => Some(*ifindex),
            InterfaceRef::Any => None,
        }
    }

    /// True for the query-only default-route marker.
    pub fn is_any(&self) -> bool {
        matches!(self, InterfaceRef::Any)
    }
}

impl fmt::Display for InterfaceRef {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            InterfaceRef::If { ifindex, name } => match name {
                Some(name) => write!(f, "{name}#{ifindex}"),
                None => write!(f, "ifindex-{ifindex}"),
            },
            InterfaceRef::Any => write!(f, "any-interface"),
        }
    }
}

/// One source-prefix ↔ interface(s) binding.
///
/// Stored per `(prefix, origin)` key with replace semantics: updating a
/// binding for the same key replaces it (never merges); re-ingesting the
/// RIB replaces the whole Rib slot and leaves the Config slot alone.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Binding {
    /// Sources inside this prefix may legitimately arrive on
    /// `interfaces` (subject to the query's longest-match + precedence
    /// rules).
    pub prefix: IpPrefix,
    /// Concrete egress interfaces, normalized at insertion (sorted, no
    /// duplicates). The `Any` marker is never storable.
    pub interfaces: Vec<InterfaceRef>,
    /// Where this binding came from (precedence rules on
    /// [`Sib::interfaces_for`]).
    pub origin: BindingOrigin,
    /// Optional expiry for dynamically-learned bindings (the TTL hook
    /// SAVNET wants): [`Sib::sweep`] removes the binding once `now`
    /// reaches this deadline. `None` (the only value any landed origin
    /// stamps tonight) means the binding never ages out. Rejected on
    /// Config-origin bindings — operator-pinned bindings cannot expire
    /// ([`SavError::PinnedExpiry`]).
    ///
    /// Monotonic clock (`std::time::Instant`), not wall time: expiry is
    /// an in-process ageing decision that must be immune to wall-clock
    /// steps. Queries do NOT check expiry — ageing happens only at
    /// [`Sib::sweep`], so a stale binding answers queries at most until
    /// the caller's next sweep (one code path, bounded staleness).
    pub expires_at: Option<Instant>,
}

impl fmt::Display for Binding {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let ifaces: Vec<String> = self.interfaces.iter().map(|i| i.to_string()).collect();
        write!(
            f,
            "{} -> [{}] (from {})",
            self.prefix,
            ifaces.join(", "),
            self.origin
        )
    }
}

/// The SAV Information Base: the typed store of source-prefix ↔
/// interface bindings (architecture.md §2's "SIB" box of the SAV
/// subsystem).
///
/// Query semantics follow the SAVNET rules: any answer that is not a set
/// of concrete interfaces is *no conclusion* — unknown ≠ invalid, and
/// enforcement (a later slice, via the dataplane trait) logs/monitors
/// instead of dropping.
#[derive(Debug, Clone, Default)]
pub struct Sib {
    /// Keyed by (prefix, origin): one binding per key, replace on update;
    /// BTreeMap so snapshot iteration is deterministic (sorted by prefix,
    /// then origin).
    bindings: BTreeMap<(IpPrefix, BindingOrigin), Binding>,
}

impl Sib {
    /// An empty SIB.
    pub fn new() -> Self {
        Self::default()
    }

    /// Builder: a fresh SIB with the RIB-origin bindings derived from
    /// `rib` (see [`Sib::ingest_rib`] for the derivation rules). Plain
    /// synchronous function — the daemon calls it on a timer/event; no
    /// IPC, no wire formats.
    pub fn from_rib(rib: &Rib) -> Self {
        let mut sib = Self::new();
        sib.ingest_rib(rib);
        sib
    }

    /// Replace the RIB-origin bindings from `rib`'s current view of the
    /// main table, leaving Config-origin bindings alone (replace
    /// semantics are per origin). Wholesale by design tonight; the daemon
    /// (W8) re-ingests on a timer/event — incremental diffing on rib
    /// events is §Deferred.
    ///
    /// Derivation per prefix over the merged view (the C2-ratified
    /// fold-in onto the S1 explicit rib surfaces, 2026-10-11):
    ///
    /// - The key set is the union of the main table's per-protocol
    ///   candidates and its CONNECT set ([`Rib::connected_table`] —
    ///   every address on every UP interface as its network prefix).
    ///   Per prefix the binding follows [`Rib::best_with_connected`]:
    ///   a connected candidate masks a protocol best at distance 0
    ///   (zebra semantics — nothing outranks a connected prefix), so a
    ///   configured address on an interface *is* the SAV truth for its
    ///   network: sources there legitimately arrive on that interface.
    /// - Egress interfaces are resolved through the recursive resolver
    ///   ([`Rib::resolve_nexthop_recursive`]): `IfIndex` and
    ///   explicit-ifindex hops map to their ifindex, gateway hops walk
    ///   on-link first then the covering-route chain (the S1-disclosed
    ///   deviations — no fall-through, the /0 default never answers —
    ///   carry over unchanged; the kernel mirror participates in the
    ///   *walk* as a resolution source but never as a binding source).
    ///
    /// A merged best with no resolvable egress (an unresolved gateway
    /// chain, or a blackhole) yields **no binding**: the SIB never
    /// asserts an empty interface set (unknown ≠ invalid), so the query
    /// falls through to less specific bindings. Kernel-mirror routes
    /// are observed state and are never ingested as bindings — the same
    /// rule the RIB applies to best-path selection.
    ///
    /// Equivalence: when the two new surfaces are empty (no CONNECT
    /// candidates, and no walk candidate covers any gateway — e.g. a
    /// bare `Rib::new()` fed `IfIndex`-hop routes), the derivation is
    /// byte-identical to the pre-fold-in one (property-pinned).
    pub fn ingest_rib(&mut self, rib: &Rib) -> &mut Self {
        let mut made = Vec::new();
        let mut skipped = 0usize;
        // The merged key set: protocol candidates ∪ CONNECT candidates
        // of the main table (BTreeSet for deterministic prefix order).
        let mut prefixes: BTreeSet<IpPrefix> = BTreeSet::new();
        if let Some(table) = rib.table(MAIN_TABLE) {
            prefixes.extend(table.iter().map(|(prefix, _)| *prefix));
        }
        if let Some(table) = rib.connected_table(MAIN_TABLE) {
            prefixes.extend(table.iter().map(|(prefix, _)| *prefix));
        }
        for prefix in prefixes {
            let Some(best) = rib.best_with_connected(MAIN_TABLE, &prefix) else {
                continue;
            };
            let interfaces = rib_egress(rib, &best.nexthops);
            if interfaces.is_empty() {
                skipped += 1;
                debug!(
                    prefix = %best.prefix,
                    protocol = ?best.protocol,
                    "no resolved egress interface; no SIB binding (unknown != invalid)"
                );
                continue;
            }
            made.push(Binding {
                prefix,
                interfaces,
                origin: BindingOrigin::Rib,
                // No TTL on rib-derived bindings: the wholesale
                // re-ingest that rebuilds this slot on every
                // evaluate already refreshes it, so a deadline here
                // would only misexpire bindings whose route is still
                // present. The field waits for a dynamic origin.
                expires_at: None,
            });
        }
        info!(
            bindings = made.len(),
            skipped, "sib ingested rib best routes (main table, merged with connected)"
        );
        self.replace_slot(BindingOrigin::Rib, made);
        self
    }

    /// Insert-or-replace one binding under its `(prefix, origin)` key
    /// (replace, never merge). Validates the stored invariants first:
    /// at least one interface, all concrete (no `Any` marker).
    pub fn update(&mut self, binding: Binding) -> Result<(), SavError> {
        let mut binding = binding;
        validate(&binding)?;
        normalize(&mut binding.interfaces);
        self.bindings
            .insert((binding.prefix, binding.origin), binding);
        Ok(())
    }

    /// Replace every binding of one origin with `bindings` atomically:
    /// the whole batch is validated before anything is committed, so a
    /// rejected batch leaves the slot untouched.
    pub fn replace_origin(
        &mut self,
        origin: BindingOrigin,
        bindings: impl IntoIterator<Item = Binding>,
    ) -> Result<(), SavError> {
        let mut made = Vec::new();
        for binding in bindings {
            let mut binding = binding;
            validate(&binding)?;
            normalize(&mut binding.interfaces);
            made.push(binding);
        }
        self.replace_slot(origin, made);
        Ok(())
    }

    /// Withdraw one binding by `(prefix, origin)`. Returns whether a
    /// binding was there. The other origin's binding for the same prefix,
    /// if any, is untouched.
    pub fn remove(&mut self, prefix: &IpPrefix, origin: BindingOrigin) -> bool {
        self.bindings.remove(&(*prefix, origin)).is_some()
    }

    /// Age out expired bindings (the TTL pass): every binding whose
    /// [`Binding::expires_at`] deadline has passed (`deadline <= now`)
    /// is removed; the swept `(prefix, origin)` keys are returned in
    /// deterministic map order (sorted by prefix, then origin).
    /// Bindings with no expiry never age out, and Config-origin
    /// bindings can never carry one (insertion rejects it — pinned
    /// bindings must not expire), so a sweep only ever retires stale
    /// *dynamic* learning.
    ///
    /// Removal follows [`Sib::remove`] semantics — covering fallback
    /// per the query model: a swept prefix's queries fall through to
    /// the covering binding, the other origin's same-prefix slot, the
    /// default-route [`InterfaceRef::Any`] marker, or nothing (unknown
    /// ≠ invalid — an expired binding leaves *no conclusion* behind,
    /// never a stale verdict). Re-learning a swept key through
    /// [`Sib::update`] / [`Sib::replace_origin`] simply re-stores it
    /// with a fresh deadline. The sweep is idempotent: keys it returns
    /// once are gone, so an immediate repeat reports nothing.
    ///
    /// This is the SIB-level half of the design only; *when* to sweep
    /// is the owner's call ([`savd`] runs one bounded sweep per
    /// evaluate cycle, on an injected clock).
    pub fn sweep(&mut self, now: Instant) -> Vec<(IpPrefix, BindingOrigin)> {
        let expired: Vec<(IpPrefix, BindingOrigin)> = self
            .bindings
            .iter()
            .filter(|(_, b)| matches!(b.expires_at, Some(deadline) if deadline <= now))
            .map(|(key, _)| *key)
            .collect();
        for key in &expired {
            self.bindings.remove(key);
        }
        expired
    }

    /// Point lookup: the stored binding for one `(prefix, origin)` key.
    pub fn binding(&self, prefix: &IpPrefix, origin: BindingOrigin) -> Option<&Binding> {
        self.bindings.get(&(*prefix, origin))
    }

    /// Full snapshot iteration for tests/debug, deterministic order
    /// (sorted by prefix, then origin).
    pub fn bindings(&self) -> impl Iterator<Item = &Binding> {
        self.bindings.values()
    }

    /// The effective bindings, one per prefix, applying the documented
    /// precedence at the prefix level: a [`BindingOrigin::Config`]
    /// binding shadows the [`BindingOrigin::Rib`] binding of the same
    /// prefix (the prefix-level form of [`Sib::interfaces_for`]'s rule
    /// 2). This is the iteration the rule generators use — a rule set
    /// must see exactly one binding per prefix. Deterministic (prefix
    /// order).
    pub fn effective_bindings(&self) -> impl Iterator<Item = &Binding> {
        self.bindings.values().filter(|b| {
            b.origin == BindingOrigin::Config
                || !self
                    .bindings
                    .contains_key(&(b.prefix, BindingOrigin::Config))
        })
    }

    /// The ingress interfaces on which a packet with this `source`
    /// address could legitimately arrive, per the bindings:
    /// **longest-prefix match**, so a more specific binding always
    /// answers before a covering one.
    ///
    /// Precedence when several bindings match:
    /// 1. Longest matching prefix wins, across origins (a RIB-derived
    ///    /24 beats an operator-configured /8 — specificity is
    ///    information).
    /// 2. At the *same* prefix, [`BindingOrigin::Config`] overrides
    ///    [`BindingOrigin::Rib`] (operator override).
    ///
    /// Answers and what each means downstream:
    /// - concrete interfaces — the egress set of the winning binding;
    /// - [`InterfaceRef::Any`] alone — the longest match is the **default
    ///   route**: the SIB cannot constrain the interface, so the answer
    ///   is the "any interface" *marker*, never a wildcard binding over
    ///   all interfaces (the stored default binding keeps its concrete
    ///   egress in the snapshot as debug state, not as an enforcement
    ///   constraint);
    /// - empty — nothing matched at all (no binding and no default route).
    ///
    /// Both non-concrete answers are *no conclusion* (unknown ≠ invalid):
    /// enforcement layers log/monitor, they do not drop.
    ///
    /// Longest-match is a linear scan tonight (the same scale as the
    /// RIB's gateway resolution); a trie is warranted once SIBs grow —
    /// §Deferred.
    pub fn interfaces_for(&self, source: IpAddr) -> Vec<InterfaceRef> {
        let rib = self.longest_in(BindingOrigin::Rib, source);
        let config = self.longest_in(BindingOrigin::Config, source);
        let winner = match (config, rib) {
            // Equal lengths here mean the same prefix (two distinct
            // prefixes of one family and length cannot both contain the
            // same address), so Config's documented override applies.
            (Some(config), Some(rib)) => {
                if prefix_len(config.prefix) >= prefix_len(rib.prefix) {
                    config
                } else {
                    rib
                }
            }
            (Some(config), None) => config,
            (None, Some(rib)) => rib,
            (None, None) => return Vec::new(),
        };
        if prefix_len(winner.prefix) == 0 {
            vec![InterfaceRef::Any]
        } else {
            winner.interfaces.clone()
        }
    }

    /// Longest binding of one origin whose prefix contains `source`
    /// (family-checked). At most one prefix per length can match, so
    /// `max_by_key` is deterministic.
    fn longest_in(&self, origin: BindingOrigin, source: IpAddr) -> Option<&Binding> {
        self.bindings
            .values()
            .filter(|b| b.origin == origin && prefix_contains(b.prefix, source))
            .max_by_key(|b| prefix_len(b.prefix))
    }

    /// Unvalidated-slot replace for bindings generated in-crate (they
    /// satisfy the invariants by construction).
    fn replace_slot(&mut self, origin: BindingOrigin, made: Vec<Binding>) {
        self.bindings.retain(|(_, o), _| *o != origin);
        self.bindings
            .extend(made.into_iter().map(|b| ((b.prefix, b.origin), b)));
    }
}

/// Reject bindings that would break the stored invariants: no interfaces,
/// the query-only marker present, or an expiry on an operator-pinned
/// (Config-origin) binding — pinned bindings must not age out.
fn validate(binding: &Binding) -> Result<(), SavError> {
    if binding.interfaces.is_empty() {
        return Err(SavError::EmptyBinding {
            prefix: binding.prefix,
        });
    }
    if binding.interfaces.iter().any(InterfaceRef::is_any) {
        return Err(SavError::MarkerInBinding {
            prefix: binding.prefix,
        });
    }
    if binding.origin == BindingOrigin::Config && binding.expires_at.is_some() {
        return Err(SavError::PinnedExpiry {
            prefix: binding.prefix,
        });
    }
    Ok(())
}

/// Sort and dedupe a binding's interface list so stored (and therefore
/// queried) order is deterministic.
fn normalize(interfaces: &mut Vec<InterfaceRef>) {
    interfaces.sort();
    interfaces.dedup();
}

/// The egress interfaces of a merged-best nexthop group, resolved
/// through the recursive resolver (the C2-ratified fold-in):
/// `IfIndex` and explicit-if hops carry their ifindex directly, bare
/// gateway hops walk on-link first then the covering-route chain
/// ([`Rib::resolve_nexthop_recursive`] — the S1 deviations apply: no
/// fall-through on an unusable candidate, the /0 default never
/// answers), blackholes contribute nothing. Empty result = no binding
/// (see [`Sib::ingest_rib`]). Both call sites (the SIB ingest and the
/// FP-mode alternate expansion in [`gen`]) ride the same resolver, so
/// a gateway resolves identically for a binding and for an alternate
/// feasible path.
pub(crate) fn rib_egress(rib: &Rib, group: &NexthopGroup) -> Vec<InterfaceRef> {
    let mut out: Vec<InterfaceRef> = Vec::new();
    for &(hop, _weight) in group.hops() {
        let ifindex = match hop {
            Nexthop::IfIndex(ifindex) => Some(ifindex),
            Nexthop::Ipv4If(_, ifindex) | Nexthop::Ipv6If(_, ifindex) => Some(ifindex),
            Nexthop::Ipv4(gateway) => rib
                .resolve_nexthop_recursive(IpAddr::V4(gateway))
                .and_then(nexthop_ifindex),
            Nexthop::Ipv6(gateway) => rib
                .resolve_nexthop_recursive(IpAddr::V6(gateway))
                .and_then(nexthop_ifindex),
            Nexthop::Blackhole => None,
        };
        if let Some(ifindex) = ifindex {
            let name = rib
                .interfaces()
                .get(&ifindex)
                // Placeholder mirror entries (address-before-link kernel
                // notification order) carry an empty name; keep it None.
                .and_then(|iface| (!iface.name.is_empty()).then(|| iface.name.clone()));
            let reference = InterfaceRef::If { ifindex, name };
            if !out.contains(&reference) {
                out.push(reference);
            }
        }
    }
    out.sort();
    out
}

/// The ifindex of a *resolved* nexthop (`Ipv4If`/`Ipv6If`); gateway forms
/// never reach here unresolved.
fn nexthop_ifindex(hop: Nexthop) -> Option<u32> {
    match hop {
        Nexthop::Ipv4If(_, ifindex) | Nexthop::Ipv6If(_, ifindex) => Some(ifindex),
        _ => None,
    }
}

/// Family-checked prefix membership.
pub(crate) fn prefix_contains(prefix: IpPrefix, addr: IpAddr) -> bool {
    match (prefix, addr) {
        (IpPrefix::V4(prefix), IpAddr::V4(addr)) => prefix.contains(addr),
        (IpPrefix::V6(prefix), IpAddr::V6(addr)) => prefix.contains(addr),
        _ => false,
    }
}

pub(crate) fn prefix_len(prefix: IpPrefix) -> u8 {
    match prefix {
        IpPrefix::V4(prefix) => prefix.prefix_len(),
        IpPrefix::V6(prefix) => prefix.prefix_len(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use common::{Nexthop, NexthopGroup, RouteEntry, RouteProtocol};
    use std::time::Duration;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    fn if_ref(ifindex: u32, name: Option<&str>) -> InterfaceRef {
        InterfaceRef::If {
            ifindex,
            name: name.map(String::from),
        }
    }

    fn binding_of(prefix: &str, ifindexes: &[u32], origin: BindingOrigin) -> Binding {
        Binding {
            prefix: prefix.parse().unwrap(),
            interfaces: ifindexes.iter().map(|&ix| if_ref(ix, None)).collect(),
            origin,
            expires_at: None,
        }
    }

    fn rib_binding(prefix: &str, ifindexes: &[u32]) -> Binding {
        binding_of(prefix, ifindexes, BindingOrigin::Rib)
    }

    fn config_binding(prefix: &str, ifindexes: &[u32]) -> Binding {
        binding_of(prefix, ifindexes, BindingOrigin::Config)
    }

    fn static_if_route(prefix: &str, ifindex: u32) -> RouteEntry {
        RouteEntry::new(
            prefix.parse().unwrap(),
            RouteProtocol::Static,
            NexthopGroup::single(Nexthop::IfIndex(ifindex)),
            0,
        )
    }

    #[test]
    fn longest_prefix_match_wins() {
        let mut sib = Sib::new();
        sib.update(rib_binding("10.0.0.0/16", &[2])).unwrap();
        sib.update(rib_binding("10.0.5.0/24", &[3])).unwrap();
        assert_eq!(sib.interfaces_for(ip("10.0.5.9")), vec![if_ref(3, None)]);
        assert_eq!(sib.interfaces_for(ip("10.0.9.9")), vec![if_ref(2, None)]);
    }

    #[test]
    fn v6_longest_prefix_match() {
        let mut sib = Sib::new();
        sib.update(rib_binding("2001:db8:5::/48", &[2])).unwrap();
        sib.update(rib_binding("2001:db8:5:aa::/64", &[4])).unwrap();
        assert_eq!(
            sib.interfaces_for(ip("2001:db8:5:aa::1")),
            vec![if_ref(4, None)]
        );
        assert_eq!(
            sib.interfaces_for(ip("2001:db8:5:bb::1")),
            vec![if_ref(2, None)]
        );
    }

    #[test]
    fn address_families_are_kept_separate() {
        let mut sib = Sib::new();
        sib.update(rib_binding("192.0.2.0/24", &[2])).unwrap();
        sib.update(rib_binding("2001:db8:5::/64", &[4])).unwrap();
        assert_eq!(sib.interfaces_for(ip("192.0.2.7")), vec![if_ref(2, None)]);
        assert_eq!(
            sib.interfaces_for(ip("2001:db8:5::9")),
            vec![if_ref(4, None)]
        );
        // No default route here, so an unmatched source of either family
        // has no conclusion at all — never the other family's binding.
        assert!(sib.interfaces_for(ip("198.51.100.7")).is_empty());
        assert!(sib.interfaces_for(ip("2001:db8:6::9")).is_empty());
    }

    #[test]
    fn empty_sib_answers_empty_not_any() {
        let sib = Sib::new();
        assert!(sib.interfaces_for(ip("10.0.0.1")).is_empty());
        assert!(sib.interfaces_for(ip("2001:db8::1")).is_empty());
    }

    #[test]
    fn same_prefix_config_overrides_rib() {
        let mut sib = Sib::new();
        sib.update(rib_binding("192.0.2.0/24", &[2])).unwrap();
        sib.update(config_binding("192.0.2.0/24", &[5])).unwrap();
        assert_eq!(sib.interfaces_for(ip("192.0.2.7")), vec![if_ref(5, None)]);
    }

    #[test]
    fn more_specific_beats_origin_precedence() {
        let mut sib = Sib::new();
        sib.update(config_binding("10.0.0.0/8", &[5])).unwrap();
        sib.update(rib_binding("10.1.0.0/16", &[2])).unwrap();
        assert_eq!(
            sib.interfaces_for(ip("10.1.2.3")),
            vec![if_ref(2, None)],
            "longer prefix wins even across origins"
        );
        assert_eq!(
            sib.interfaces_for(ip("10.2.0.1")),
            vec![if_ref(5, None)],
            "the config /8 still answers outside the rib /16"
        );
    }

    #[test]
    fn update_replaces_within_its_origin_only() {
        let mut sib = Sib::new();
        sib.update(rib_binding("192.0.2.0/24", &[2])).unwrap();
        sib.update(config_binding("192.0.2.0/24", &[5])).unwrap();
        sib.update(rib_binding("192.0.2.0/24", &[3, 4])).unwrap();
        assert_eq!(
            sib.binding(&"192.0.2.0/24".parse().unwrap(), BindingOrigin::Rib)
                .unwrap()
                .interfaces,
            vec![if_ref(3, None), if_ref(4, None)],
            "the same (prefix, origin) key replaces, never merges"
        );
        assert_eq!(
            sib.interfaces_for(ip("192.0.2.7")),
            vec![if_ref(5, None)],
            "the config slot is untouched by a rib update"
        );
    }

    #[test]
    fn ingest_rib_replaces_rib_slot_and_preserves_config() {
        let mut rib = Rib::new();
        rib.add_route(static_if_route("10.0.0.0/16", 2));
        let mut sib = Sib::from_rib(&rib);
        sib.update(config_binding("10.0.0.0/16", &[5])).unwrap();
        assert_eq!(sib.interfaces_for(ip("10.0.0.1")), vec![if_ref(5, None)]);

        // A later rib snapshot: the prefix is withdrawn, a new one added.
        let mut rib2 = Rib::new();
        rib2.add_route(static_if_route("10.9.0.0/16", 3));
        sib.ingest_rib(&rib2);
        assert!(
            sib.binding(&"10.0.0.0/16".parse().unwrap(), BindingOrigin::Rib)
                .is_none(),
            "the withdrawn prefix is gone from the rib slot"
        );
        assert_eq!(sib.interfaces_for(ip("10.9.0.1")), vec![if_ref(3, None)]);
        assert_eq!(
            sib.interfaces_for(ip("10.0.0.1")),
            vec![if_ref(5, None)],
            "the config binding survived the rib re-ingest"
        );
    }

    #[test]
    fn default_route_answers_the_any_marker() {
        let mut sib = Sib::new();
        sib.update(rib_binding("0.0.0.0/0", &[2])).unwrap();
        sib.update(rib_binding("::/0", &[4])).unwrap();
        assert_eq!(
            sib.interfaces_for(ip("172.16.1.1")),
            vec![InterfaceRef::Any]
        );
        assert_eq!(
            sib.interfaces_for(ip("2001:db8:99::1")),
            vec![InterfaceRef::Any]
        );
        // The stored default binding keeps its concrete egress (visible
        // in the snapshot); the marker is synthesized at query time — the
        // SIB never stores an "all interfaces" wildcard.
        assert_eq!(
            sib.binding(&"0.0.0.0/0".parse().unwrap(), BindingOrigin::Rib)
                .unwrap()
                .interfaces,
            vec![if_ref(2, None)]
        );
    }

    #[test]
    fn specific_binding_beats_the_default_fallback() {
        let mut sib = Sib::new();
        sib.update(rib_binding("0.0.0.0/0", &[2])).unwrap();
        sib.update(rib_binding("10.0.0.0/8", &[3])).unwrap();
        assert_eq!(sib.interfaces_for(ip("10.5.5.5")), vec![if_ref(3, None)]);
        assert_eq!(
            sib.interfaces_for(ip("172.16.1.1")),
            vec![InterfaceRef::Any]
        );
    }

    #[test]
    fn multi_interface_binding_returns_every_egress_sorted() {
        let mut sib = Sib::new();
        sib.update(rib_binding("10.9.0.0/16", &[7, 2])).unwrap();
        assert_eq!(
            sib.interfaces_for(ip("10.9.1.1")),
            vec![if_ref(2, None), if_ref(7, None)],
            "ECMP egress set, insertion-normalized to ifindex order"
        );
    }

    #[test]
    fn update_rejects_empty_and_marker_bindings() {
        let mut sib = Sib::new();
        let empty = Binding {
            prefix: "10.0.0.0/8".parse().unwrap(),
            interfaces: vec![],
            origin: BindingOrigin::Rib,
            expires_at: None,
        };
        assert_eq!(
            sib.update(empty.clone()),
            Err(SavError::EmptyBinding {
                prefix: empty.prefix
            })
        );
        let marker = Binding {
            prefix: "10.0.0.0/8".parse().unwrap(),
            interfaces: vec![InterfaceRef::Any],
            origin: BindingOrigin::Rib,
            expires_at: None,
        };
        assert_eq!(
            sib.update(marker.clone()),
            Err(SavError::MarkerInBinding {
                prefix: marker.prefix
            })
        );
        assert_eq!(sib.bindings().count(), 0);

        // replace_origin validates the whole batch before committing.
        let batch = vec![rib_binding("192.0.2.0/24", &[2]), marker];
        assert!(sib.replace_origin(BindingOrigin::Rib, batch).is_err());
        assert_eq!(
            sib.bindings().count(),
            0,
            "a rejected batch leaves the slot untouched"
        );
    }

    #[test]
    fn remove_drops_exactly_one_origin_slot() {
        let mut sib = Sib::new();
        let p: IpPrefix = "10.0.5.0/24".parse().unwrap();
        sib.update(rib_binding("10.0.0.0/16", &[2])).unwrap();
        sib.update(rib_binding("10.0.5.0/24", &[3])).unwrap();
        sib.update(config_binding("10.0.5.0/24", &[5])).unwrap();
        assert!(sib.remove(&p, BindingOrigin::Rib));
        assert!(!sib.remove(&p, BindingOrigin::Rib));
        assert_eq!(
            sib.interfaces_for(ip("10.0.5.9")),
            vec![if_ref(5, None)],
            "the config slot still answers"
        );
        assert!(sib.remove(&p, BindingOrigin::Config));
        assert_eq!(
            sib.interfaces_for(ip("10.0.5.9")),
            vec![if_ref(2, None)],
            "falls back to the covering /16"
        );
    }

    /// TTL sweep (W5 §Deferred 3): a binding whose deadline has passed
    /// is swept and its queries fall back per the model — the covering
    /// binding, or the other origin's same-prefix slot — while
    /// unexpired and un-TTL'd bindings stay. The boundary is inclusive
    /// (`deadline == now` is expired), the sweep is idempotent, and a
    /// re-learned key returns with its fresh deadline.
    #[test]
    fn sweep_removes_expired_bindings_and_queries_fall_back() {
        let now = Instant::now();
        let mut sib = Sib::new();
        sib.update(rib_binding("10.0.0.0/16", &[2])).unwrap();
        // Expired exactly at the boundary (deadline == now).
        let mut expired = rib_binding("10.0.5.0/24", &[3]);
        expired.expires_at = Some(now);
        sib.update(expired).unwrap();
        // Not yet expired: strictly future deadline survives the sweep.
        let mut fresh = rib_binding("10.9.0.0/24", &[4]);
        fresh.expires_at = Some(now + Duration::from_secs(30));
        sib.update(fresh).unwrap();
        // The same-prefix other-origin fallback: the rib slot expires,
        // the pinned config slot underneath answers.
        let mut expired2 = rib_binding("203.0.113.0/24", &[7]);
        expired2.expires_at = Some(now);
        sib.update(expired2).unwrap();
        sib.update(config_binding("203.0.113.0/24", &[5])).unwrap();

        let swept = sib.sweep(now);
        assert_eq!(
            swept,
            vec![
                ("10.0.5.0/24".parse().unwrap(), BindingOrigin::Rib),
                ("203.0.113.0/24".parse().unwrap(), BindingOrigin::Rib),
            ],
            "exactly the expired keys, deterministic (prefix, origin) order"
        );
        assert_eq!(
            sib.interfaces_for(ip("10.0.5.9")),
            vec![if_ref(2, None)],
            "the swept /24 falls back to the covering /16"
        );
        assert_eq!(
            sib.interfaces_for(ip("203.0.113.9")),
            vec![if_ref(5, None)],
            "the swept rib slot falls back to the pinned config slot"
        );
        assert_eq!(
            sib.interfaces_for(ip("10.9.0.1")),
            vec![if_ref(4, None)],
            "the unexpired TTL binding survives"
        );
        assert_eq!(sib.bindings().count(), 3);

        // Idempotent: the swept keys are gone, a repeat reports nothing.
        assert!(sib.sweep(now).is_empty());
        assert_eq!(sib.bindings().count(), 3);

        // Re-learning a swept key re-stores it with a fresh deadline.
        let mut relearned = rib_binding("10.0.5.0/24", &[3]);
        relearned.expires_at = Some(now + Duration::from_secs(60));
        sib.update(relearned).unwrap();
        assert!(sib.sweep(now).is_empty(), "the fresh deadline holds");
        assert_eq!(
            sib.interfaces_for(ip("10.0.5.9")),
            vec![if_ref(3, None)],
            "the re-learned binding answers again"
        );
    }

    /// Pinned bindings never expire: an expiry on a Config-origin
    /// binding is rejected at insertion — single-key and batch — so
    /// the sweep can never retire operator state. The same deadline on
    /// a Rib binding is fine (dynamic origins age out).
    #[test]
    fn pinned_config_bindings_cannot_carry_an_expiry() {
        let mut sib = Sib::new();
        let mut pinned = config_binding("192.0.2.0/24", &[5]);
        pinned.expires_at = Some(Instant::now() + Duration::from_secs(3600));
        assert_eq!(
            sib.update(pinned.clone()),
            Err(SavError::PinnedExpiry {
                prefix: pinned.prefix
            }),
            "pinned means pinned — the future deadline does not help"
        );
        // The batch form rejects it too, before committing anything.
        let mut rib_ttl = rib_binding("10.0.0.0/8", &[2]);
        rib_ttl.expires_at = Some(Instant::now());
        assert!(
            sib.replace_origin(BindingOrigin::Config, vec![pinned, rib_ttl.clone()])
                .is_err(),
            "a pinned expiry rejects the whole batch"
        );
        assert_eq!(
            sib.bindings().count(),
            0,
            "the rejected batch left the slot untouched"
        );
        // The same TTL on a rib binding is accepted (dynamic slot).
        sib.update(rib_ttl).unwrap();
        assert_eq!(sib.bindings().count(), 1);
    }

    #[test]
    fn snapshot_iteration_covers_all_bindings_sorted() {
        let mut sib = Sib::new();
        sib.update(rib_binding("10.0.0.0/8", &[2])).unwrap();
        sib.update(rib_binding("10.0.5.0/24", &[3])).unwrap();
        sib.update(config_binding("192.0.2.0/24", &[5])).unwrap();
        let keys: Vec<(IpPrefix, BindingOrigin)> =
            sib.bindings().map(|b| (b.prefix, b.origin)).collect();
        assert_eq!(keys.len(), 3);
        assert!(keys.contains(&("10.0.0.0/8".parse().unwrap(), BindingOrigin::Rib)));
        assert!(keys.contains(&("10.0.5.0/24".parse().unwrap(), BindingOrigin::Rib)));
        assert!(keys.contains(&("192.0.2.0/24".parse().unwrap(), BindingOrigin::Config)));
        assert!(
            keys.windows(2).all(|w| w[0] < w[1]),
            "deterministic (prefix, origin) order"
        );
    }

    // --- C2 fold-in: connected prefixes + the recursive walk ---

    fn link_event(ifindex: u32, name: &str, is_up: bool) -> common::DataplaneEvent {
        common::DataplaneEvent::LinkNew {
            ifindex,
            name: name.into(),
            is_up,
            flags: if is_up {
                common::LinkFlags::up_broadcast()
            } else {
                common::LinkFlags::default()
            },
            vrf_table: None,
            master_ifindex: None,
        }
    }

    fn address_event(ifindex: u32, prefix: &str, add: bool) -> common::DataplaneEvent {
        let prefix = prefix.parse().unwrap();
        if add {
            common::DataplaneEvent::AddressNew { ifindex, prefix }
        } else {
            common::DataplaneEvent::AddressDel { ifindex, prefix }
        }
    }

    /// The C2 fold-in's first half: a connected prefix (an address on
    /// an UP interface) becomes a Rib-origin binding on exactly that
    /// interface, masks a protocol best for the same prefix (zebra
    /// distance-0 semantics — `best_with_connected`), and withdraws
    /// with the address.
    #[test]
    fn connected_prefixes_fold_into_the_sib_and_mask_protocol_bests() {
        let mut rib = Rib::new();
        rib.apply_event(&link_event(2, "eth0", true));
        rib.apply_event(&address_event(2, "192.0.2.1/24", true));
        // A protocol candidate for the SAME prefix: connected masks it
        // (a blackhole here would otherwise be a binding-free prefix —
        // the connected candidate must win the merged best instead).
        rib.add_route(RouteEntry::new(
            "192.0.2.0/24".parse().unwrap(),
            RouteProtocol::Static,
            NexthopGroup::single(Nexthop::Blackhole),
            0,
        ));
        let sib = Sib::from_rib(&rib);
        assert_eq!(
            sib.binding(&"192.0.2.0/24".parse().unwrap(), BindingOrigin::Rib)
                .unwrap()
                .interfaces,
            vec![if_ref(2, Some("eth0"))],
            "the connected candidate (not the static blackhole) derives the binding"
        );
        assert_eq!(
            sib.interfaces_for(ip("192.0.2.55")),
            vec![if_ref(2, Some("eth0"))]
        );

        // The address leaving withdraws the connected binding; the
        // blackhole becomes the merged best and yields none.
        rib.apply_event(&address_event(2, "192.0.2.1/24", false));
        let sib = Sib::from_rib(&rib);
        assert!(
            sib.binding(&"192.0.2.0/24".parse().unwrap(), BindingOrigin::Rib)
                .is_none(),
            "no address, no connected candidate; the blackhole best yields no binding"
        );
    }

    /// The fold-in's second half: a gateway no on-link prefix covers
    /// resolves through the recursive walk (the covering route's own
    /// hop), while a cyclic chain still yields no binding (unknown ≠
    /// invalid).
    #[test]
    fn recursive_walk_resolves_off_link_gateways_into_bindings() {
        let mut rib = Rib::new();
        rib.apply_event(&link_event(2, "eth0", true));
        rib.apply_event(&address_event(2, "10.1.1.1/24", true));
        // 203.0.113.0/24 via 100.64.0.1 (off-link), covered by
        // 100.64.0.0/10 via the on-link 10.1.1.9: two chained hops.
        let gw = |p: &str, g: &str| {
            RouteEntry::new(
                p.parse().unwrap(),
                RouteProtocol::Static,
                NexthopGroup::single(Nexthop::Ipv4(g.parse().unwrap())),
                0,
            )
        };
        rib.add_route(gw("203.0.113.0/24", "100.64.0.1"));
        rib.add_route(gw("100.64.0.0/10", "10.1.1.9"));
        let sib = Sib::from_rib(&rib);
        assert_eq!(
            sib.interfaces_for(ip("203.0.113.7")),
            vec![if_ref(2, Some("eth0"))],
            "the off-link gateway resolved through the walk to eth0"
        );

        // A two-gateway cycle terminates unresolved: no binding, the
        // query falls through to whatever else covers (nothing here).
        let mut rib2 = Rib::new();
        rib2.apply_event(&link_event(2, "eth0", true));
        rib2.apply_event(&address_event(2, "10.1.1.1/24", true));
        rib2.add_route(gw("10.2.0.0/16", "10.3.0.1"));
        rib2.add_route(gw("10.3.0.0/16", "10.2.0.1"));
        let sib2 = Sib::from_rib(&rib2);
        assert!(
            sib2.binding(&"10.2.0.0/16".parse().unwrap(), BindingOrigin::Rib)
                .is_none(),
            "a cyclic chain yields no binding (unknown != invalid)"
        );
    }

    /// The byte-identical-when-empty bar: with no CONNECT candidates
    /// and no walk-reachable gateway (a bare rib whose gateway hops
    /// nothing covers), the fold-in derivation equals the legacy one
    /// (protocol best + direct ifindex extraction) exactly.
    #[test]
    fn empty_new_surfaces_derive_the_legacy_bindings_byte_identically() {
        let mut rib = Rib::new();
        rib.add_route(static_if_route("10.0.0.0/16", 2));
        rib.add_route(static_if_route("2001:db8:5::/64", 4));
        // Gateway routes whose gateways are covered by nothing (no
        // interface mirror, no covering candidate): still no binding.
        let gw = |p: &str, g: &str| {
            RouteEntry::new(
                p.parse().unwrap(),
                RouteProtocol::Static,
                NexthopGroup::single(Nexthop::Ipv4(g.parse().unwrap())),
                0,
            )
        };
        rib.add_route(gw("198.51.100.0/24", "203.0.113.9"));
        let sib = Sib::from_rib(&rib);
        // The legacy derivation, inline: protocol bests with ifindex
        // hops only — exactly what the pre-fold-in ingest produced.
        let legacy: Vec<Binding> = vec![
            rib_binding("10.0.0.0/16", &[2]),
            rib_binding("2001:db8:5::/64", &[4]),
        ];
        assert_eq!(
            sib.bindings().cloned().collect::<Vec<_>>(),
            legacy,
            "empty connected + unreachable walk: byte-identical derivation"
        );
    }
}
