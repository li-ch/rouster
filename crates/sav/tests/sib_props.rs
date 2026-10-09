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
//! bare `Rib::new()` with no interface mirror) and blackholes, so the
//! "no resolvable egress ⇒ no binding" rule (unknown ≠ invalid) is
//! exercised per hop. Interface names are cosmetic to the SIB and mixed
//! `None`/`Some` on purpose.

use std::collections::BTreeMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

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
        })
}

fn config_binding_strategy() -> impl Strategy<Value = Binding> {
    binding_strategy().prop_map(|mut b| {
        b.origin = BindingOrigin::Config;
        b
    })
}

/// Route hops: ifindex-carrying forms (always resolvable), bare gateways
/// (never resolvable against a bare Rib), and blackholes — the full hop
/// taxonomy `rib_egress` branches on.
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

/// The bindings `Sib::from_rib` must derive from `routes`: replay the
/// main table's per-protocol candidate replacement, pick each prefix's
/// best route exactly like `Table::best` (`min (admin distance, metric)`,
/// first candidate wins ties), then resolve egress against a bare Rib —
/// ifindex-carrying hops contribute, bare gateways stay unresolved,
/// blackholes contribute nothing; an empty result yields no binding.
fn derive_expected(routes: &[RouteEntry]) -> Vec<Binding> {
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
        sib.update(Binding { prefix, interfaces: first, origin }).unwrap();
        sib.update(Binding { prefix, interfaces: second.clone(), origin }).unwrap();

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
            },
            Binding {
                prefix: poison_prefix,
                interfaces: vec![InterfaceRef::Any],
                origin,
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
