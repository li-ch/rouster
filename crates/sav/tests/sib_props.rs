//! W5B property tests: the SIB ingest→query invariants.
//!
//! The three pre-registered properties (W5's continuation ladder) plus
//! four cheap ones that fall out of the same reference model:
//!
//! 1. **idempotence** — ingesting the same RIB twice changes nothing
//!    (snapshot and every query answer);
//! 2. **origin-replace** — `ingest_rib` wholesale-replaces the Rib slot
//!    with exactly the model derivation while the Config slot survives
//!    untouched, and queries follow the model over the union;
//! 3. **longest-prefix totality** — `interfaces_for` never panics and
//!    always answers one of the three well-formed shapes (empty / the
//!    exclusive `Any` marker / the winning binding's interface set),
//!    exactly matching the documented longest-match + Config-override
//!    semantics recomputed by a test-side reference model;
//! 4. **key replace, never merge** — updating the same (prefix, origin)
//!    key leaves exactly the replacement's normalized interface set;
//! 5. **snapshot round-trip** — iteration is deterministically sorted and
//!    rebuilding a SIB from a snapshot reproduces both storage and every
//!    query answer;
//! 6. **batch atomicity** — `replace_origin` commits a valid batch
//!    wholesale (the origin slot equals exactly the replayed batch, the
//!    other origin's slot survives, queries follow the model over the
//!    union), while a batch carrying an empty or marker binding anywhere
//!    in it is rejected with the matching error and commits nothing.
//! 7. **remove + covering fallback** — withdrawing a (prefix, origin)
//!    key drops exactly that slot (`remove` reports true once, false on
//!    a repeat or on a key never stored, and never touches the other
//!    origin's same-prefix slot), and every query inside a withdrawn
//!    prefix falls back to what the remaining bindings cover per the
//!    model: the covering binding, the other origin's same-prefix slot,
//!    the default-route `Any` marker, or empty when nothing is left.
//! 8. **sweep + covering fallback** (A22) — the TTL pass retires
//!    exactly the keys whose deadline has passed (deadline ≤ the sweep
//!    instant; config keys never carry one — pinned bindings cannot
//!    expire), reports them in map order, and every query over the
//!    survivors follows the model — a swept prefix's inside-probe is
//!    answered by the covering binding, the other origin's same-prefix
//!    slot, the default-route `Any` marker, or nothing; a repeat sweep
//!    retires nothing (idempotence).
//!
//! C2 fold-in extensions (2026-10-11; the SIB now consumes the S1
//! explicit rib surfaces — the CONNECT table and the recursive
//! resolver). The reference model gained both sources and every
//! property above re-pinned against it; three new properties pin the
//! fold-in itself:
//!
//! 9. **connected fold-in** — over a RIB with an interface mirror
//!    (link/address events) plus protocol routes, the derivation equals
//!    the model's merged view: connected candidates (network form of
//!    every UP-interface address, lowest ifindex winning same-prefix
//!    ties) mask protocol bests and become bindings on their interface;
//!    queries follow the model over the union.
//! 10. **recursive walk** — over bare RIBs whose bare-gateway hops are
//!     deliberately drawn INSIDE other routes' prefixes, the derivation
//!     equals the model's walk (on-link first — empty on a bare Rib —
//!     then one best covering candidate, /0 excluded, cycles via the
//!     visited set, blackhole/held terminating without fall-through).
//! 11. **empty-surface equivalence** — with no CONNECT candidates and
//!     no ifindex-free hops left to resolve (only IfIndex/explicit-if/
//!     blackhole hops over a bare Rib), the fold-in derivation is
//!     byte-identical to the legacy one (the pre-fold-in model):
//!     the new surfaces change nothing when they carry nothing.
//!
//! Determinism (frozen bar "seeds fixed"): every runner is constructed
//! with an explicit [`proptest::test_runner::RngSeed::Fixed`], so plain
//! `cargo test` replays identical case sequences every run. The
//! `PROPTEST_RNG_SEED` environment variable still overrides the in-code
//! seeds (proptest contextualizes env vars over the config) when a human
//! wants to explore; the gate does not set it.
//!
//! Generation notes: prefixes are always canonical (network-masked, the
//! form real route ingestion carries), so the documented tie-break
//! invariant holds — two distinct prefixes of one family and length
//! cannot both contain the same address. Routes use `IfIndex`/explicit-if
//! hops (always resolvable), bare gateway hops (unresolvable against a
//! bare `Rib::new()` with no interface mirror ON-LINK, but resolvable
//! through the walk when another route covers them — the model computes
//! exactly which) and blackholes, so the "no resolvable egress ⇒ no
//! binding" rule (unknown ≠ invalid) is exercised per hop. Interface
//! names are cosmetic to the SIB and mixed `None`/`Some` on purpose.

use std::collections::BTreeMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::time::{Duration, Instant};

use common::{IpPrefix, Ipv4Prefix, Ipv6Prefix, Nexthop, NexthopGroup, RouteEntry, RouteProtocol};
use proptest::prelude::*;
use proptest::test_runner::RngSeed;
use rib::Rib;
use sav::{Binding, BindingOrigin, InterfaceRef, SavError, Sib};

/// One fixed seed per property (distinct streams). Named constants keep
/// the "seeds fixed" bar greppable and give each property an independent
/// deterministic case sequence.
const SEED_IDEMPOTENCE: u64 = 0x5735_4201;
const SEED_ORIGIN_REPLACE: u64 = 0x5735_4202;
const SEED_LONGEST_PREFIX: u64 = 0x5735_4203;
const SEED_KEY_REPLACE: u64 = 0x5735_4204;
const SEED_ROUND_TRIP: u64 = 0x5735_4205;
const SEED_BATCH_ATOMICITY: u64 = 0x5735_4206;
const SEED_REMOVE_FALLBACK: u64 = 0x5735_4207;
const SEED_SWEEP_FALLBACK: u64 = 0x5735_4208;
// C2 fold-in properties (2026-10-11): distinct streams, same scheme.
const SEED_CONNECTED_FOLD_IN: u64 = 0x5735_4209;
const SEED_RECURSIVE_WALK: u64 = 0x5735_420a;
const SEED_EMPTY_SURFACE_EQUIV: u64 = 0x5735_420b;

fn seeded(seed: u64) -> ProptestConfig {
    ProptestConfig {
        rng_seed: RngSeed::Fixed(seed),
        ..ProptestConfig::default()
    }
}

// ---------------------------------------------------------------------------
// Strategies
// ---------------------------------------------------------------------------

/// Canonical (network-masked) v4 prefix.
fn v4_strategy() -> impl Strategy<Value = Ipv4Prefix> {
    (any::<[u8; 4]>(), 0u8..=32).prop_map(|(octets, len)| {
        let bits = u32::from(Ipv4Addr::from(octets));
        let masked = if len == 0 {
            0
        } else {
            bits & (u32::MAX << (32 - u32::from(len)))
        };
        Ipv4Prefix::new(Ipv4Addr::from(masked), len).unwrap()
    })
}

/// Canonical (network-masked) v6 prefix.
fn v6_strategy() -> impl Strategy<Value = Ipv6Prefix> {
    (any::<[u16; 8]>(), 0u8..=128).prop_map(|(words, len)| {
        let bits = u128::from(Ipv6Addr::from(words));
        let masked = if len == 0 {
            0
        } else {
            bits & (u128::MAX << (128 - u32::from(len)))
        };
        Ipv6Prefix::new(Ipv6Addr::from(masked), len).unwrap()
    })
}

fn prefix_strategy() -> impl Strategy<Value = IpPrefix> {
    prop_oneof![
        v4_strategy().prop_map(IpPrefix::V4),
        v6_strategy().prop_map(IpPrefix::V6),
    ]
}

fn ifindex_strategy() -> impl Strategy<Value = u32> {
    1u32..=16
}

/// Concrete interface refs only — the `Any` marker is query-only and a
/// storage invariant violation, so no valid binding ever carries it; the
/// batch-atomicity property injects it explicitly as a poison instead.
fn ifref_strategy() -> impl Strategy<Value = InterfaceRef> {
    (
        ifindex_strategy(),
        proptest::option::of(any::<u8>().prop_map(|n| format!("eth{n}"))),
    )
        .prop_map(|(ifindex, name)| InterfaceRef::If { ifindex, name })
}

/// A storage-valid binding of either origin: non-empty, concrete,
/// (deliberately) unnormalized interface list.
fn binding_strategy() -> impl Strategy<Value = Binding> {
    (
        prefix_strategy(),
        proptest::collection::vec(ifref_strategy(), 1..=4),
        any::<bool>(),
    )
        .prop_map(|(prefix, interfaces, config)| Binding {
            prefix,
            interfaces,
            origin: if config {
                BindingOrigin::Config
            } else {
                BindingOrigin::Rib
            },
            // No expiry here: the sweep property stamps deadlines
            // selectively on rib bindings (config is pinned and would
            // reject one).
            expires_at: None,
        })
}

fn config_binding_strategy() -> impl Strategy<Value = Binding> {
    binding_strategy().prop_map(|mut b| {
        b.origin = BindingOrigin::Config;
        b
    })
}

/// Route hops: ifindex-carrying forms (always resolvable), bare gateways
/// (resolvable on a bare Rib only through the covering-route walk —
/// another generated route may or may not cover them, exactly what the
/// model computes), and blackholes — the full hop taxonomy `rib_egress`
/// branches on.
fn hop_strategy() -> impl Strategy<Value = Nexthop> {
    prop_oneof![
        ifindex_strategy().prop_map(Nexthop::IfIndex),
        (any::<Ipv4Addr>(), ifindex_strategy()).prop_map(|(a, ix)| Nexthop::Ipv4If(a, ix)),
        (any::<Ipv6Addr>(), ifindex_strategy()).prop_map(|(a, ix)| Nexthop::Ipv6If(a, ix)),
        Just(Nexthop::Blackhole),
        any::<Ipv4Addr>().prop_map(Nexthop::Ipv4),
        any::<Ipv6Addr>().prop_map(Nexthop::Ipv6),
    ]
}

/// A protocol-route candidate for the main table (kernel/connected
/// origins arrive via the mirror, not the protocol tables, so they are
/// out of the SIB's feed by construction).
fn route_strategy() -> impl Strategy<Value = RouteEntry> {
    use RouteProtocol::{Bgp, IsIs, Ospf, Rip, Static};
    (
        prefix_strategy(),
        prop_oneof![Just(Static), Just(Ospf), Just(Bgp), Just(Rip), Just(IsIs)],
        any::<u32>(),
        proptest::collection::vec(hop_strategy(), 1..=3),
    )
        .prop_map(|(prefix, protocol, metric, hops)| {
            let mut group = NexthopGroup::new();
            for hop in hops {
                group.add(hop, 1);
            }
            RouteEntry::new(prefix, protocol, group, metric)
        })
}

fn routes_strategy() -> impl Strategy<Value = Vec<RouteEntry>> {
    proptest::collection::vec(route_strategy(), 0..=12)
}

fn probes_strategy() -> impl Strategy<Value = Vec<IpAddr>> {
    proptest::collection::vec(any::<IpAddr>(), 0..=8)
}

fn entropy_strategy() -> impl Strategy<Value = Vec<[u8; 16]>> {
    proptest::collection::vec(any::<[u8; 16]>(), 0..=14)
}

// ---------------------------------------------------------------------------
// Reference model (test-side recomputation of the documented semantics)
// ---------------------------------------------------------------------------

/// What the SIB stores, as the tests replay it: last update wins per
/// (prefix, origin) key, interface lists insertion-normalized. `Sib` is
/// not `Clone`, and strategies need `Clone + Debug` values, so the Rib
/// itself is always rebuilt from the route list inside the test body.
type Stored = BTreeMap<(IpPrefix, BindingOrigin), Binding>;

fn normalize(interfaces: &mut Vec<InterfaceRef>) {
    interfaces.sort();
    interfaces.dedup();
}

fn replay(updates: &[Binding]) -> Stored {
    let mut stored = Stored::new();
    for update in updates {
        let mut binding = update.clone();
        normalize(&mut binding.interfaces);
        stored.insert((binding.prefix, binding.origin), binding);
    }
    stored
}

fn build_rib(routes: &[RouteEntry]) -> Rib {
    let mut rib = Rib::new();
    for route in routes {
        rib.add_route(route.clone());
    }
    rib
}

/// One interface-mirror spec for the connected-fold-in property: the
/// link state (ifindex, name, admin up) and the raw address prefixes
/// (host bits preserved — `sync_connected` network-masks them for the
/// CONNECT table, on-link resolution matches through them raw).
#[derive(Clone, Debug)]
struct IfaceSpec {
    ifindex: u32,
    name: String,
    is_up: bool,
    addresses: Vec<IpPrefix>,
}

/// Raw (not network-masked) address prefixes — host bits land wherever
/// the entropy puts them, exercising `network_prefix` on the connected
/// path and raw-`contains` matching on the on-link path.
fn host_prefix_strategy() -> impl Strategy<Value = IpPrefix> {
    prop_oneof![
        (any::<[u8; 4]>(), 8u8..=32).prop_map(|(octets, len)| {
            IpPrefix::V4(Ipv4Prefix::new(Ipv4Addr::from(octets), len).unwrap())
        }),
        (any::<[u16; 8]>(), 16u8..=72).prop_map(|(words, len)| {
            IpPrefix::V6(Ipv6Prefix::new(Ipv6Addr::from(words), len).unwrap())
        }),
    ]
}

fn iface_spec_strategy() -> impl Strategy<Value = IfaceSpec> {
    (
        ifindex_strategy(),
        any::<u8>().prop_map(|n| format!("eth{n}")),
        any::<bool>(),
        proptest::collection::vec(host_prefix_strategy(), 0..=3),
    )
        .prop_map(|(ifindex, name, is_up, addresses)| IfaceSpec {
            ifindex,
            name,
            is_up,
            addresses,
        })
}

fn iface_specs_strategy() -> impl Strategy<Value = Vec<IfaceSpec>> {
    proptest::collection::vec(iface_spec_strategy(), 0..=6)
}

/// A Rib with an interface mirror: link/address events exactly as the
/// daemon's dataplane feed drives them (duplicate ifindexes replace
/// link state, addresses accumulate per ifindex — the model replays
/// the same rules).
fn build_mirror_rib(specs: &[IfaceSpec]) -> Rib {
    let mut rib = Rib::new();
    for spec in specs {
        rib.apply_event(&common::DataplaneEvent::LinkNew {
            ifindex: spec.ifindex,
            name: spec.name.clone(),
            is_up: spec.is_up,
            flags: if spec.is_up {
                common::LinkFlags::up_broadcast()
            } else {
                common::LinkFlags::default()
            },
            vrf_table: None,
            master_ifindex: None,
            hw_addr: None,
        });
        for &prefix in &spec.addresses {
            rib.apply_event(&common::DataplaneEvent::AddressNew {
                ifindex: spec.ifindex,
                prefix,
            });
        }
    }
    rib
}

/// The interface mirror as the events build it (the model's replay of
/// `Rib::apply_event`): last link state wins per ifindex, addresses
/// accumulate without duplicates, keyed by ascending ifindex — the
/// iteration order `resolve_on_link` sees.
fn mirror_of(specs: &[IfaceSpec]) -> BTreeMap<u32, (String, bool, Vec<IpPrefix>)> {
    let mut mirror: BTreeMap<u32, (String, bool, Vec<IpPrefix>)> = BTreeMap::new();
    for spec in specs {
        let entry = mirror.entry(spec.ifindex).or_default();
        entry.0 = spec.name.clone();
        entry.1 = spec.is_up;
        for &prefix in &spec.addresses {
            if !entry.2.contains(&prefix) {
                entry.2.push(prefix);
            }
        }
    }
    mirror
}

/// The network form of an address prefix (`sync_connected`'s connected
/// route announces the NETWORK form) — the rib crate's `network_prefix`
/// replayed.
fn network_prefix_of(prefix: IpPrefix) -> IpPrefix {
    match prefix {
        IpPrefix::V4(p) => {
            let len = p.prefix_len();
            let bits = u32::from(p.addr());
            let mask = if len == 0 {
                0
            } else {
                !0u32 << (32 - u32::from(len))
            };
            IpPrefix::V4(Ipv4Prefix::new(Ipv4Addr::from(bits & mask), len).expect("len preserved"))
        }
        IpPrefix::V6(p) => {
            let len = p.prefix_len();
            let bits = u128::from(p.addr());
            let mask = if len == 0 {
                0
            } else {
                !0u128 << (128 - u32::from(len))
            };
            IpPrefix::V6(Ipv6Prefix::new(Ipv6Addr::from(bits & mask), len).expect("len preserved"))
        }
    }
}

/// The model's walk (the C2 fold-in reference): on-link first (the
/// longest address prefix on an UP interface containing the gateway,
/// lowest ifindex winning length ties), then ONE best covering
/// candidate across the protocol bests and the CONNECT set — the /0
/// default never answers, cycles die on the visited set, blackholes
/// and empty-hop candidates terminate unresolved with NO fall-through.
fn model_resolve(
    gw: IpAddr,
    candidates: &BTreeMap<IpPrefix, Vec<&RouteEntry>>,
    connected: &BTreeMap<IpPrefix, u32>,
    mirror: &BTreeMap<u32, (String, bool, Vec<IpPrefix>)>,
    visited: &mut std::collections::BTreeSet<IpAddr>,
) -> Option<u32> {
    // On-link arm (resolve_on_link): ascending ifindex, strict `>` —
    // the first interface at the max length wins ties.
    let mut best: Option<(u8, u32)> = None;
    for (&ifindex, (_, is_up, addresses)) in mirror {
        if !*is_up {
            continue;
        }
        for &prefix in addresses {
            let len = match (prefix, gw) {
                (IpPrefix::V4(p), IpAddr::V4(a)) if p.contains(a) => p.prefix_len(),
                (IpPrefix::V6(p), IpAddr::V6(a)) if p.contains(a) => p.prefix_len(),
                _ => continue,
            };
            if best.is_none_or(|(best_len, _)| len > best_len) {
                best = Some((len, ifindex));
            }
        }
    }
    if let Some((_, ifindex)) = best {
        return Some(ifindex);
    }
    if !visited.insert(gw) {
        return None; // cycle guard
    }
    // The covering candidate: longest non-default containing prefix
    // (distinct canonical prefixes ⇒ one per length ⇒ deterministic);
    // at the same prefix the CONNECT candidate (distance 0) masks any
    // protocol best — exactly `covering_route`'s (len, dist, metric)
    // maximum over the two sources.
    let covering = candidates
        .keys()
        .chain(connected.keys())
        .copied()
        .filter(|p| contains(*p, gw) && prefix_len(*p) > 0)
        .max_by_key(|p| prefix_len(*p))?;
    let (hop, _weight) = match connected.get(&covering) {
        Some(&ifindex) => (Nexthop::IfIndex(ifindex), 1u8),
        None => candidates[&covering]
            .iter()
            .min_by_key(|e| (e.protocol.admin_distance(), e.metric))
            .expect("candidate list is non-empty")
            .nexthops
            .hops()
            .first()
            .copied()?,
    };
    match hop {
        // A device/ifindex-carrying hop adopts its ifindex for the
        // gateway; a blackhole or an unusable candidate terminates
        // unresolved — no fall-through to shorter prefixes.
        Nexthop::IfIndex(ifindex) => Some(ifindex),
        Nexthop::Ipv4If(_, ifindex) | Nexthop::Ipv6If(_, ifindex) => Some(ifindex),
        Nexthop::Blackhole => None,
        Nexthop::Ipv4(next) => {
            model_resolve(IpAddr::V4(next), candidates, connected, mirror, visited)
        }
        Nexthop::Ipv6(next) => {
            model_resolve(IpAddr::V6(next), candidates, connected, mirror, visited)
        }
    }
}

/// The model egress of one hop list: ifindex-carrying hops contribute
/// their (mirror-named) interface, bare gateways go through
/// [`model_resolve`], blackholes contribute nothing.
fn model_egress(
    hops: &[(Nexthop, u8)],
    candidates: &BTreeMap<IpPrefix, Vec<&RouteEntry>>,
    connected: &BTreeMap<IpPrefix, u32>,
    mirror: &BTreeMap<u32, (String, bool, Vec<IpPrefix>)>,
) -> Vec<InterfaceRef> {
    let name_of = |ifindex: u32| mirror.get(&ifindex).map(|(name, _, _)| name.clone());
    let mut interfaces: Vec<InterfaceRef> = Vec::new();
    for &(hop, _weight) in hops {
        let ifindex = match hop {
            Nexthop::IfIndex(ifindex) => Some(ifindex),
            Nexthop::Ipv4If(_, ifindex) | Nexthop::Ipv6If(_, ifindex) => Some(ifindex),
            Nexthop::Blackhole => None,
            Nexthop::Ipv4(gw) => model_resolve(
                IpAddr::V4(gw),
                candidates,
                connected,
                mirror,
                &mut std::collections::BTreeSet::new(),
            ),
            Nexthop::Ipv6(gw) => model_resolve(
                IpAddr::V6(gw),
                candidates,
                connected,
                mirror,
                &mut std::collections::BTreeSet::new(),
            ),
        };
        if let Some(ifindex) = ifindex {
            let reference = InterfaceRef::If {
                ifindex,
                name: name_of(ifindex),
            };
            if !interfaces.contains(&reference) {
                interfaces.push(reference);
            }
        }
    }
    interfaces.sort();
    interfaces
}

/// The bindings `Sib::from_rib` must derive from `routes` over a bare
/// Rib (no interface mirror): replay the main table's per-protocol
/// candidate replacement, pick each prefix's best route exactly like
/// `Table::best`, then resolve egress through the walk-aware model
/// (which on a bare Rib reduces to the covering-route walk — bare
/// gateways resolve only when another route covers them).
fn derive_expected(routes: &[RouteEntry]) -> Vec<Binding> {
    derive_expected_with_mirror(routes, &[])
}

/// The full fold-in derivation (C2): protocol candidates over an
/// interface mirror. The CONNECT set (network form of every
/// UP-interface address, lowest ifindex winning same-network ties,
/// main table — no VRFs generated) participates twice: its candidates
/// MASK protocol bests at distance 0 (the merged
/// `best_with_connected` view), and they are covering candidates for
/// the recursive walk.
fn derive_expected_with_mirror(routes: &[RouteEntry], specs: &[IfaceSpec]) -> Vec<Binding> {
    let mut candidates: BTreeMap<IpPrefix, Vec<&RouteEntry>> = BTreeMap::new();
    for route in routes {
        let list = candidates.entry(route.prefix).or_default();
        list.retain(|e| e.protocol != route.protocol);
        list.push(route);
    }
    let mirror = mirror_of(specs);
    let mut connected: BTreeMap<IpPrefix, u32> = BTreeMap::new();
    for (&ifindex, (_, is_up, addresses)) in &mirror {
        if !*is_up {
            continue;
        }
        for &addr in addresses {
            let net = network_prefix_of(addr);
            connected
                .entry(net)
                .and_modify(|ix| *ix = (*ix).min(ifindex))
                .or_insert(ifindex);
        }
    }
    let mut keys: std::collections::BTreeSet<IpPrefix> = candidates.keys().copied().collect();
    keys.extend(connected.keys().copied());
    let mut expected = Vec::new();
    for prefix in keys {
        // The merged best: a connected candidate masks the protocol
        // best; otherwise `Table::best` over the prefix's candidates.
        let hops: Vec<(Nexthop, u8)> = match connected.get(&prefix) {
            Some(&ifindex) => vec![(Nexthop::IfIndex(ifindex), 1u8)],
            None => candidates[&prefix]
                .iter()
                .min_by_key(|e| (e.protocol.admin_distance(), e.metric))
                .expect("candidate list is non-empty")
                .nexthops
                .hops()
                .to_vec(),
        };
        let interfaces = model_egress(&hops, &candidates, &connected, &mirror);
        if !interfaces.is_empty() {
            expected.push(Binding {
                prefix,
                interfaces,
                origin: BindingOrigin::Rib,
                expires_at: None,
            });
        }
    }
    expected
}

/// The PRE-fold-in derivation (the W5B legacy model), kept verbatim for
/// the empty-surface equivalence property: protocol bests over a bare
/// Rib, ifindex-carrying hops contributing directly, bare gateways
/// NEVER resolving (the old on-link-only resolver against an empty
/// mirror), blackholes contributing nothing.
fn legacy_derive(routes: &[RouteEntry]) -> Vec<Binding> {
    let mut candidates: BTreeMap<IpPrefix, Vec<&RouteEntry>> = BTreeMap::new();
    for route in routes {
        let list = candidates.entry(route.prefix).or_default();
        list.retain(|e| e.protocol != route.protocol);
        list.push(route);
    }
    let mut expected = Vec::new();
    for (prefix, list) in candidates {
        let best = list
            .iter()
            .min_by_key(|e| (e.protocol.admin_distance(), e.metric))
            .unwrap();
        let mut interfaces: Vec<InterfaceRef> = Vec::new();
        for &(hop, _weight) in best.nexthops.hops() {
            if let Some(ifindex) = hop_ifindex(hop) {
                let reference = InterfaceRef::If {
                    ifindex,
                    name: None, // bare Rib: no interface mirror
                };
                if !interfaces.contains(&reference) {
                    interfaces.push(reference);
                }
            }
        }
        interfaces.sort();
        if !interfaces.is_empty() {
            expected.push(Binding {
                prefix,
                interfaces,
                origin: BindingOrigin::Rib,
                expires_at: None,
            });
        }
    }
    expected
}

fn hop_ifindex(hop: Nexthop) -> Option<u32> {
    match hop {
        Nexthop::IfIndex(ifindex) | Nexthop::Ipv4If(_, ifindex) | Nexthop::Ipv6If(_, ifindex) => {
            Some(ifindex)
        }
        Nexthop::Ipv4(_) | Nexthop::Ipv6(_) | Nexthop::Blackhole => None,
    }
}

/// Family-checked prefix membership (the query's candidate filter).
fn contains(prefix: IpPrefix, addr: IpAddr) -> bool {
    match (prefix, addr) {
        (IpPrefix::V4(p), IpAddr::V4(a)) => p.contains(a),
        (IpPrefix::V6(p), IpAddr::V6(a)) => p.contains(a),
        _ => false,
    }
}

fn prefix_len(prefix: IpPrefix) -> u8 {
    match prefix {
        IpPrefix::V4(p) => p.prefix_len(),
        IpPrefix::V6(p) => p.prefix_len(),
    }
}

/// A random address *inside* `prefix` (host bits from `entropy`) —
/// guarantees candidate coverage even when the random probes miss every
/// stored prefix.
fn addr_inside(prefix: IpPrefix, entropy: [u8; 16]) -> IpAddr {
    match prefix {
        IpPrefix::V4(p) => {
            let len = u32::from(p.prefix_len());
            let network = u32::from(p.addr());
            let host = u32::from_be_bytes([entropy[0], entropy[1], entropy[2], entropy[3]]);
            let addr = match len {
                0 => host,
                32 => network,
                len => (network & (u32::MAX << (32 - len))) | (host & (u32::MAX >> len)),
            };
            IpAddr::V4(Ipv4Addr::from(addr))
        }
        IpPrefix::V6(p) => {
            let len = u32::from(p.prefix_len());
            let network = u128::from(p.addr());
            let host = u128::from_be_bytes(entropy);
            let addr = match len {
                0 => host,
                128 => network,
                len => (network & (u128::MAX << (128 - len))) | (host & (u128::MAX >> len)),
            };
            IpAddr::V6(Ipv6Addr::from(addr))
        }
    }
}

/// The reference model of `Sib::interfaces_for`, recomputed from the
/// stored bindings per the rules documented on that method: longest
/// matching prefix across origins; at equal length — necessarily the
/// same prefix — Config overrides Rib; a winning default route answers
/// the exclusive `Any` marker; no candidate answers empty (unknown ≠
/// invalid).
fn model_interfaces_for(stored: &Stored, source: IpAddr) -> Vec<InterfaceRef> {
    let mut winner: Option<&Binding> = None;
    for binding in stored.values() {
        if !contains(binding.prefix, source) {
            continue;
        }
        // `>=`: BTreeMap order visits an identical prefix's Rib slot
        // before its Config slot, so Config replaces on the tie — the
        // documented operator override.
        if winner.is_none_or(|w| {
            (prefix_len(binding.prefix), binding.origin) >= (prefix_len(w.prefix), w.origin)
        }) {
            winner = Some(binding);
        }
    }
    match winner {
        None => Vec::new(),
        Some(w) if prefix_len(w.prefix) == 0 => vec![InterfaceRef::Any],
        Some(w) => w.interfaces.clone(),
    }
}

fn snapshot(sib: &Sib) -> Vec<Binding> {
    sib.bindings().cloned().collect()
}

fn origin_slot(sib: &Sib, origin: BindingOrigin) -> Vec<Binding> {
    sib.bindings()
        .filter(|b| b.origin == origin)
        .cloned()
        .collect()
}

// ---------------------------------------------------------------------------
// Property 1 — ingest idempotence
// ---------------------------------------------------------------------------

proptest! {
    #![proptest_config(seeded(SEED_IDEMPOTENCE))]
    #[test]
    fn ingest_is_idempotent(routes in routes_strategy(), probes in probes_strategy()) {
        let rib = build_rib(&routes);
        let once = Sib::from_rib(&rib);
        let mut twice = Sib::from_rib(&rib);
        twice.ingest_rib(&rib);

        prop_assert_eq!(
            snapshot(&twice),
            snapshot(&once),
            "re-ingesting the same rib changes no binding"
        );
        prop_assert_eq!(
            snapshot(&once),
            derive_expected(&routes),
            "the derivation matches the reference model"
        );
        for &probe in &probes {
            prop_assert_eq!(
                twice.interfaces_for(probe),
                once.interfaces_for(probe),
                "re-ingesting the same rib changes no query answer"
            );
        }
    }
}

// ---------------------------------------------------------------------------
// Property 2 — origin-replace: the Rib slot is wholesale-replaced, the
// Config slot survives, queries follow the model over the union
// ---------------------------------------------------------------------------

proptest! {
    #![proptest_config(seeded(SEED_ORIGIN_REPLACE))]
    #[test]
    fn ingest_replaces_the_rib_slot_and_preserves_config(
        config_updates in proptest::collection::vec(config_binding_strategy(), 0..=6),
        stale in routes_strategy(),
        fresh in routes_strategy(),
        probes in probes_strategy(),
    ) {
        let mut sib = Sib::from_rib(&build_rib(&stale));
        for binding in &config_updates {
            sib.update(binding.clone()).unwrap();
        }
        let fresh_rib = build_rib(&fresh);
        sib.ingest_rib(&fresh_rib);

        // The Rib slot is exactly the fresh derivation: nothing of the
        // stale rib survives except where re-derived.
        prop_assert_eq!(origin_slot(&sib, BindingOrigin::Rib), derive_expected(&fresh));

        // The Config slot is exactly the replayed updates.
        let want_config = replay(&config_updates);
        prop_assert_eq!(
            origin_slot(&sib, BindingOrigin::Config),
            want_config.values().cloned().collect::<Vec<_>>()
        );

        // Queries follow the model over config ∪ fresh rib bindings.
        let mut combined = want_config;
        for binding in derive_expected(&fresh) {
            combined.insert((binding.prefix, binding.origin), binding);
        }
        for &probe in &probes {
            prop_assert_eq!(sib.interfaces_for(probe), model_interfaces_for(&combined, probe));
        }
    }
}

// ---------------------------------------------------------------------------
// Property 3 — longest-prefix totality: every query answers one of the
// three well-formed shapes, exactly as the reference model computes
// ---------------------------------------------------------------------------

proptest! {
    #![proptest_config(seeded(SEED_LONGEST_PREFIX))]
    #[test]
    fn longest_prefix_query_is_total_and_model_correct(
        updates in proptest::collection::vec(binding_strategy(), 0..=14),
        probes in probes_strategy(),
        entropy in entropy_strategy(),
    ) {
        let mut sib = Sib::new();
        for binding in &updates {
            sib.update(binding.clone()).unwrap();
        }
        let stored = replay(&updates);

        // Storage itself matches the replay: last-update-wins per key,
        // interface lists normalized.
        prop_assert_eq!(snapshot(&sib), stored.values().cloned().collect::<Vec<_>>());

        let mut all_probes = probes;
        for (binding, entropy) in updates.iter().zip(entropy.iter()) {
            all_probes.push(addr_inside(binding.prefix, *entropy));
        }
        for probe in all_probes {
            let got = sib.interfaces_for(probe);
            // Correctness: the exact documented semantics.
            prop_assert_eq!(&got, &model_interfaces_for(&stored, probe), "for probe {}", probe);
            // Totality shape 1: empty exactly when nothing covers the
            // source (never a wrong "no conclusion").
            let covered = stored.values().any(|b| contains(b.prefix, probe));
            prop_assert_eq!(got.is_empty(), !covered, "for probe {}", probe);
            // Totality shape 2: the marker is exclusive — never mixed
            // with concrete refs.
            let markers = got.iter().filter(|r| r.is_any()).count();
            prop_assert!(
                markers == 0 || (markers == 1 && got.len() == 1),
                "the any-interface marker never mixes with concrete refs, got {:?}",
                got
            );
        }
    }
}

// ---------------------------------------------------------------------------
// Property 4 — key replace, never merge (the single-key form of the
// origin-replace semantics)
// ---------------------------------------------------------------------------

proptest! {
    #![proptest_config(seeded(SEED_KEY_REPLACE))]
    #[test]
    fn update_replaces_a_key_never_merges(
        prefix in prefix_strategy(),
        is_config in any::<bool>(),
        first in proptest::collection::vec(ifref_strategy(), 1..=4),
        second in proptest::collection::vec(ifref_strategy(), 1..=4),
        entropy in any::<[u8; 16]>(),
    ) {
        let origin = if is_config { BindingOrigin::Config } else { BindingOrigin::Rib };
        let mut sib = Sib::new();
        sib.update(Binding { prefix, interfaces: first, origin, expires_at: None }).unwrap();
        sib.update(Binding { prefix, interfaces: second.clone(), origin, expires_at: None })
            .unwrap();

        let mut want = second;
        normalize(&mut want);
        prop_assert_eq!(sib.bindings().count(), 1, "one binding per (prefix, origin) key");
        prop_assert_eq!(
            &sib.binding(&prefix, origin).unwrap().interfaces,
            &want,
            "the replacement's set, sorted and deduped — never a merge with the first"
        );

        // The query answers exactly the replacement's set — or the
        // default-route marker when the key is a default.
        let expected = if prefix_len(prefix) == 0 {
            vec![InterfaceRef::Any]
        } else {
            want
        };
        prop_assert_eq!(sib.interfaces_for(addr_inside(prefix, entropy)), expected);
    }
}

// ---------------------------------------------------------------------------
// Property 5 — snapshot round-trip: sorted iteration, faithful rebuild
// ---------------------------------------------------------------------------

proptest! {
    #![proptest_config(seeded(SEED_ROUND_TRIP))]
    #[test]
    fn snapshot_round_trips_into_an_equivalent_sib(
        updates in proptest::collection::vec(binding_strategy(), 0..=14),
        probes in probes_strategy(),
        entropy in entropy_strategy(),
    ) {
        let mut sib = Sib::new();
        for binding in &updates {
            sib.update(binding.clone()).unwrap();
        }
        let snap = snapshot(&sib);

        // Deterministic (prefix, origin) iteration order.
        prop_assert!(
            snap.windows(2)
                .all(|w| (w[0].prefix, w[0].origin) < (w[1].prefix, w[1].origin)),
            "snapshot iteration is sorted by (prefix, origin)"
        );

        let mut rebuilt = Sib::new();
        for binding in &snap {
            rebuilt.update(binding.clone()).unwrap();
        }
        prop_assert_eq!(snapshot(&rebuilt), snap);

        let mut all_probes = probes;
        for (binding, entropy) in updates.iter().zip(entropy.iter()) {
            all_probes.push(addr_inside(binding.prefix, *entropy));
        }
        for probe in all_probes {
            prop_assert_eq!(
                rebuilt.interfaces_for(probe),
                sib.interfaces_for(probe),
                "for probe {}",
                probe
            );
        }
    }
}

// ---------------------------------------------------------------------------
// Property 6 — replace_origin batch atomicity: a batch commits wholesale
// or not at all (the property form of the W5 unit test)
// ---------------------------------------------------------------------------

proptest! {
    #![proptest_config(seeded(SEED_BATCH_ATOMICITY))]
    #[test]
    fn replace_origin_commits_a_batch_wholesale_or_not_at_all(
        initial in proptest::collection::vec(binding_strategy(), 0..=10),
        batch in proptest::collection::vec(binding_strategy(), 0..=8),
        is_config in any::<bool>(),
        poison_prefix in prefix_strategy(),
        probes in probes_strategy(),
        entropy in entropy_strategy(),
    ) {
        let (origin, other) = if is_config {
            (BindingOrigin::Config, BindingOrigin::Rib)
        } else {
            (BindingOrigin::Rib, BindingOrigin::Config)
        };
        let mut sib = Sib::new();
        for binding in &initial {
            sib.update(binding.clone()).unwrap();
        }
        // Origin-coherent batches are the caller contract (`ingest_rib`
        // feeds derived Rib bindings; savd feeds the parsed `binding`
        // lines as Config — see crates/sav/src/savd.rs), so the batch is
        // coerced to the target origin before every call below.
        let batch: Vec<Binding> = batch
            .into_iter()
            .map(|mut b| {
                b.origin = origin;
                b
            })
            .collect();

        // A valid batch: accepted, the origin slot wholesale-replaced
        // with exactly the replayed batch — nothing of the old slot
        // survives, nothing merges — and the other origin untouched.
        let other_before = origin_slot(&sib, other);
        let want = replay(&batch);
        prop_assert!(sib.replace_origin(origin, batch.clone()).is_ok());
        prop_assert_eq!(
            origin_slot(&sib, origin),
            want.values().cloned().collect::<Vec<_>>(),
            "the slot equals exactly the batch, replayed per key"
        );
        prop_assert_eq!(
            origin_slot(&sib, other),
            other_before.clone(),
            "the other origin's slot survives the replace"
        );

        // Queries see the replaced slot: the model over the union of the
        // two slots (random probes plus one address inside every batch
        // prefix, so the new bindings are actually hit).
        let mut stored = Stored::new();
        for binding in other_before.iter().chain(want.values()) {
            stored.insert((binding.prefix, binding.origin), binding.clone());
        }
        let mut all_probes = probes;
        for (binding, entropy) in batch.iter().zip(entropy.iter()) {
            all_probes.push(addr_inside(binding.prefix, *entropy));
        }
        for probe in all_probes {
            prop_assert_eq!(sib.interfaces_for(probe), model_interfaces_for(&stored, probe));
        }

        // An invalid batch — an empty or marker binding, injected at
        // *every* position — is rejected with the matching error and
        // commits nothing: the whole SIB is exactly what it was. The
        // poison's prefix is generated (rejection is per-binding and
        // key-independent); the same-prefix shape is pinned by the W5
        // unit test.
        let poisons = [
            Binding {
                prefix: poison_prefix,
                interfaces: vec![],
                origin,
                expires_at: None,
            },
            Binding {
                prefix: poison_prefix,
                interfaces: vec![InterfaceRef::Any],
                origin,
                expires_at: None,
            },
        ];
        let before = snapshot(&sib);
        for pos in 0..=batch.len() {
            for poison in &poisons {
                let mut poisoned = batch.clone();
                poisoned.insert(pos, poison.clone());
                let expected = if poison.interfaces.is_empty() {
                    SavError::EmptyBinding {
                        prefix: poison.prefix,
                    }
                } else {
                    SavError::MarkerInBinding {
                        prefix: poison.prefix,
                    }
                };
                prop_assert_eq!(
                    sib.replace_origin(origin, poisoned),
                    Err(expected),
                    "the poison rejects the batch wherever it sits"
                );
                prop_assert_eq!(
                    snapshot(&sib),
                    before.clone(),
                    "a rejected batch leaves the SIB untouched"
                );
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Property 7 — remove + covering fallback: withdrawing a key drops exactly
// its slot and queries fall back to what the remaining bindings cover
// ---------------------------------------------------------------------------

proptest! {
    #![proptest_config(seeded(SEED_REMOVE_FALLBACK))]
    #[test]
    fn remove_drops_one_slot_and_queries_fall_back_to_the_covering_binding(
        updates in proptest::collection::vec(binding_strategy(), 0..=14),
        coins in proptest::collection::vec(any::<bool>(), 0..=14),
        absent in proptest::collection::vec(prefix_strategy(), 0..=4),
        probes in probes_strategy(),
        entropy in entropy_strategy(),
    ) {
        let mut sib = Sib::new();
        for binding in &updates {
            sib.update(binding.clone()).unwrap();
        }
        let mut stored = replay(&updates);

        // Withdraw a subset of the stored keys: one coin per key, with
        // the first key forced out so every non-empty case exercises at
        // least one withdrawal (the coins alone could keep everything).
        let keys: Vec<(IpPrefix, BindingOrigin)> = stored.keys().cloned().collect();
        for (index, &(prefix, origin)) in keys.iter().enumerate() {
            if !(index == 0 || coins.get(index).copied().unwrap_or(false)) {
                continue;
            }
            prop_assert!(
                sib.remove(&prefix, origin),
                "removing the stored key ({}, {}) reports true",
                prefix,
                origin
            );
            prop_assert!(
                !sib.remove(&prefix, origin),
                "a repeat remove of the now-absent key reports false"
            );
            stored.remove(&(prefix, origin));
        }
        prop_assert_eq!(
            snapshot(&sib),
            stored.values().cloned().collect::<Vec<_>>(),
            "storage is exactly the replay minus the withdrawn keys — the \
             other origin's same-prefix slot, when kept, is still there"
        );

        // Keys never stored (or coincidentally still present — generated
        // prefixes may collide) report model membership exactly; a miss
        // must not mutate anything, which the snapshot check below pins.
        for prefix in &absent {
            for origin in [BindingOrigin::Rib, BindingOrigin::Config] {
                let was_there = stored.contains_key(&(*prefix, origin));
                prop_assert_eq!(
                    sib.remove(prefix, origin),
                    was_there,
                    "remove returns whether the key is stored, nothing else"
                );
                stored.remove(&(*prefix, origin));
            }
        }
        prop_assert_eq!(snapshot(&sib), stored.values().cloned().collect::<Vec<_>>());

        // Queries fall back per the model over what remains: random
        // probes, one address inside every original prefix — surviving
        // or withdrawn — so the covering fallback is actually hit: a
        // withdrawn prefix's inside-probe must be answered by the
        // covering binding, the other origin's same-prefix slot, the
        // default-route `Any` marker, or nothing at all.
        let mut all_probes = probes;
        for ((prefix, _origin), entropy) in keys.iter().zip(entropy.iter()) {
            all_probes.push(addr_inside(*prefix, *entropy));
        }
        for probe in all_probes {
            prop_assert_eq!(
                sib.interfaces_for(probe),
                model_interfaces_for(&stored, probe),
                "for probe {}",
                probe
            );
        }
    }
}

// ---------------------------------------------------------------------------
// Property 8 — sweep + covering fallback (A22): the TTL pass retires
// exactly the expired keys and queries fall back to what the survivors
// cover
// ---------------------------------------------------------------------------

proptest! {
    #![proptest_config(seeded(SEED_SWEEP_FALLBACK))]
    #[test]
    fn sweep_retires_exactly_expired_keys_and_queries_fall_back(
        updates in proptest::collection::vec(binding_strategy(), 0..=14),
        coins in proptest::collection::vec(any::<bool>(), 0..=14),
        offsets in proptest::collection::vec(0u64..=2000, 0..=14),
        probes in probes_strategy(),
        entropy in entropy_strategy(),
    ) {
        // Deterministic t0-relative time: every deadline and the sweep
        // instant derive from one base by arithmetic, never from a
        // later wall-clock read, so pass/fail never depends on machine
        // speed. Deadlines straddle the sweep instant (0..=2000 ms
        // against a sweep at 1000 ms).
        let t0 = Instant::now();
        let sweep_at = t0 + Duration::from_millis(1000);
        // Stamp expiries on the rib bindings a coin at a time; the
        // first rib binding is forced to an already-expired deadline so
        // every non-empty case exercises at least one sweep hit. Config
        // bindings stay un-TTL'd — pinned bindings reject an expiry at
        // insertion (the unit tests pin that rejection).
        let first_rib = updates.iter().position(|b| b.origin == BindingOrigin::Rib);
        let updates: Vec<Binding> = updates
            .into_iter()
            .enumerate()
            .map(|(i, mut b)| {
                if b.origin == BindingOrigin::Rib
                    && (Some(i) == first_rib || coins.get(i).copied().unwrap_or(false))
                {
                    let millis = if Some(i) == first_rib {
                        0
                    } else {
                        offsets.get(i).copied().unwrap_or(0)
                    };
                    b.expires_at = Some(t0 + Duration::from_millis(millis));
                }
                b
            })
            .collect();
        let mut sib = Sib::new();
        for binding in &updates {
            sib.update(binding.clone()).unwrap();
        }
        let stored = replay(&updates);

        // Model: the survivors are everything except the expired keys
        // (deadline ≤ the sweep instant, inclusive boundary).
        let expired: Vec<(IpPrefix, BindingOrigin)> = stored
            .iter()
            .filter(|(_, b)| matches!(b.expires_at, Some(deadline) if deadline <= sweep_at))
            .map(|(key, _)| *key)
            .collect();
        prop_assert!(
            !expired.is_empty() || first_rib.is_none(),
            "the forced first-rib deadline guarantees a hit whenever a rib binding exists"
        );
        let mut survivors = stored.clone();
        for key in &expired {
            survivors.remove(key);
        }

        let swept = sib.sweep(sweep_at);
        prop_assert_eq!(&swept, &expired, "exactly the expired keys, in map order");
        prop_assert!(
            swept.iter().all(|(_, origin)| *origin != BindingOrigin::Config),
            "operator-pinned bindings are never swept"
        );
        prop_assert_eq!(
            snapshot(&sib),
            survivors.values().cloned().collect::<Vec<_>>(),
            "storage is exactly the replay minus the expired keys"
        );

        // Queries fall back per the model over the survivors: random
        // probes plus one address inside every original prefix —
        // surviving or swept — so a swept key's inside-probe actually
        // hits the covering fallback.
        let mut all_probes = probes;
        for ((prefix, _origin), entropy) in stored.keys().zip(entropy.iter()) {
            all_probes.push(addr_inside(*prefix, *entropy));
        }
        for probe in all_probes {
            prop_assert_eq!(
                sib.interfaces_for(probe),
                model_interfaces_for(&survivors, probe),
                "for probe {}",
                probe
            );
        }

        // Idempotent: the swept keys are gone, a repeat retires nothing.
        prop_assert!(sib.sweep(sweep_at).is_empty());
    }
}

// ---------------------------------------------------------------------------
// Property 9 — the connected fold-in (C2): over an interface mirror, the
// derivation equals the model's merged (CONNECT-masking) view
// ---------------------------------------------------------------------------

proptest! {
    #![proptest_config(seeded(SEED_CONNECTED_FOLD_IN))]
    #[test]
    fn connected_fold_in_matches_the_merged_model(
        specs in iface_specs_strategy(),
        routes in routes_strategy(),
        probes in probes_strategy(),
    ) {
        let mut rib = build_mirror_rib(&specs);
        for route in &routes {
            rib.add_route(route.clone());
        }
        let sib = Sib::from_rib(&rib);

        // The derivation equals the model's merged view: connected
        // candidates (network form, lowest ifindex ties) become
        // bindings on their interface and mask protocol bests; every
        // egress (connected IfIndex hops, protocol hops, walk-resolved
        // gateways) resolves identically.
        prop_assert_eq!(
            snapshot(&sib),
            derive_expected_with_mirror(&routes, &specs),
            "the fold-in derivation equals the merged model"
        );

        // Queries follow the model over the union of the two origins
        // (the Rib slot just derived): random probes plus an address
        // inside every derived prefix and every mirror address network.
        let stored: Stored = sib
            .bindings()
            .map(|b| ((b.prefix, b.origin), b.clone()))
            .collect();
        let mut all_probes = probes;
        for binding in sib.bindings() {
            // deterministic inside-probe: first 16 bytes of the network.
            let mut entropy_bytes = [0u8; 16];
            let probe_addr = match binding.prefix {
                IpPrefix::V4(p) => {
                    entropy_bytes[..4].copy_from_slice(&p.addr().octets());
                    addr_inside(binding.prefix, entropy_bytes)
                }
                IpPrefix::V6(p) => {
                    entropy_bytes.copy_from_slice(&p.addr().octets()[..16]);
                    addr_inside(binding.prefix, entropy_bytes)
                }
            };
            all_probes.push(probe_addr);
        }
        for probe in all_probes {
            prop_assert_eq!(
                sib.interfaces_for(probe),
                model_interfaces_for(&stored, probe),
                "for probe {}",
                probe
            );
        }
    }
}

// ---------------------------------------------------------------------------
// Property 10 — the recursive walk (C2): bare-gateway hops deliberately
// drawn inside other routes' prefixes resolve exactly as the model's
// walk computes (chains, cycles, blackhole/held termination)
// ---------------------------------------------------------------------------

proptest! {
    #![proptest_config(seeded(SEED_RECURSIVE_WALK))]
    #[test]
    fn recursive_walk_derivation_matches_the_model(
        pool in proptest::collection::vec(prefix_strategy(), 1..=8),
        hops in proptest::collection::vec(
            proptest::option::of(ifindex_strategy()), 0..=12),
        coins in proptest::collection::vec(any::<bool>(), 0..=48),
        entropy in entropy_strategy(),
    ) {
        // One route per generated hop slot: the prefix comes from the
        // pool (round-robin — same-prefix routes replay the per-protocol
        // replacement the model expects), and the hop is an ifindex
        // route, a blackhole, or — the walk-heavy arm — a bare gateway
        // drawn INSIDE another pool prefix of the same family, so the
        // covering-route chain (and its cycles) is actually exercised.
        let mut routes: Vec<RouteEntry> = Vec::new();
        for (i, ifindex) in hops.iter().enumerate() {
            let prefix = pool[i % pool.len()];
            let protocols = [RouteProtocol::Static, RouteProtocol::Ospf, RouteProtocol::Bgp];
            let protocol = protocols[i % protocols.len()];
            let coin = coins.get(i).copied().unwrap_or(false);
            let hop = match (ifindex, coin) {
                (Some(ifindex), _) => Nexthop::IfIndex(*ifindex),
                (None, true) => Nexthop::Blackhole,
                (None, false) => {
                    // A bare gateway inside a same-family pool prefix
                    // (self included: the self-covering cycle shape).
                    let target = pool[(i + 1) % pool.len()];
                    match (target, entropy.get(i).copied().unwrap_or([0u8; 16])) {
                        (IpPrefix::V4(_), e) => match addr_inside(target, e) {
                            IpAddr::V4(a) => Nexthop::Ipv4(a),
                            IpAddr::V6(_) => unreachable!("family preserved"),
                        },
                        (IpPrefix::V6(_), e) => match addr_inside(target, e) {
                            IpAddr::V6(a) => Nexthop::Ipv6(a),
                            IpAddr::V4(_) => unreachable!("family preserved"),
                        },
                    }
                }
            };
            routes.push(RouteEntry::new(
                prefix,
                protocol,
                NexthopGroup::single(hop),
                0,
            ));
        }
        let rib = build_rib(&routes);
        let sib = Sib::from_rib(&rib);
        prop_assert_eq!(
            snapshot(&sib),
            derive_expected(&routes),
            "walk-resolved derivation equals the model over the same candidate set"
        );
    }
}

// ---------------------------------------------------------------------------
// Property 11 — empty-surface equivalence (C2): with no CONNECT
// candidates and no ifindex-free hop left to resolve, the fold-in
// derivation is byte-identical to the legacy (pre-fold-in) one
// ---------------------------------------------------------------------------

proptest! {
    #![proptest_config(seeded(SEED_EMPTY_SURFACE_EQUIV))]
    #[test]
    fn empty_new_surfaces_derive_the_legacy_bindings_byte_identically(
        pool in proptest::collection::vec(prefix_strategy(), 0..=8),
        ifindexes in proptest::collection::vec(
            proptest::option::of(ifindex_strategy()), 0..=12),
        coins in proptest::collection::vec(any::<bool>(), 0..=12),
    ) {
        // Only ifindex-carrying and blackhole hops over a bare Rib: no
        // interface mirror (so no CONNECT set), no bare gateways (so
        // the walk is never consulted) — both new surfaces empty.
        let mut routes: Vec<RouteEntry> = Vec::new();
        for (i, ifindex) in ifindexes.iter().enumerate() {
            let prefix = pool.get(i).copied().unwrap_or_else(|| {
                "203.0.113.0/24".parse::<IpPrefix>().unwrap()
            });
            let hop = match ifindex {
                Some(ix) => Nexthop::IfIndex(*ix),
                None if coins.get(i).copied().unwrap_or(false) => Nexthop::Blackhole,
                None => Nexthop::Ipv4If("198.51.100.1".parse().unwrap(), 7),
            };
            routes.push(RouteEntry::new(
                prefix,
                RouteProtocol::Static,
                NexthopGroup::single(hop),
                0,
            ));
        }
        let rib = build_rib(&routes);
        let sib = Sib::from_rib(&rib);
        prop_assert_eq!(
            snapshot(&sib),
            legacy_derive(&routes),
            "empty connected surface + no gateway to walk: the derivation is \
             byte-identical to the pre-fold-in model"
        );
    }
}
