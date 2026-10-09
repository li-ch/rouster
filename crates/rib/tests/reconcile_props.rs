//! M3 property tests: the reconcile diff's add/withdraw/keep partition.
//!
//! [`Rib::reconcile`] diffs the desired state (each (table, prefix)'s best
//! route in resolved programming form) against what the RIB last
//! programmed, installing what is missing or changed, withdrawing what is
//! stale, and leaving the rest untouched. These properties pin the diff's
//! partition invariants over the public surface (`add_route`, `table_mut`,
//! `reload_static`, `reconcile`):
//!
//! 1. **partition totality** — every key the RIB had programmed (every
//!    old-best key) receives exactly one disposition in the next pass: one
//!    replace (add), one delete (withdraw), or no call at all (keep). No
//!    key is both installed and withdrawn, no kept key silently loses its
//!    programmed form, and no withdraw ever targets a key the RIB had not
//!    programmed.
//! 2. **keep ⇔ best unchanged** — for every old-best key the pass is
//!    silent exactly when the key's new desired form is byte-identical to
//!    the programmed form; a changed best is re-installed with exactly the
//!    new form, a vanished best is withdrawn exactly once with the old
//!    one.
//! 3. **stable fixpoint** — after the mutation pass the mock dataplane
//!    holds exactly the model's desired state (no stale route left, none
//!    missing), and a further pass with no mutation issues no dataplane
//!    call at all (soft-reconfiguration spirit: nothing bounces).
//!
//! Determinism (frozen bar "seeds fixed"): every runner is constructed
//! with an explicit [`proptest::test_runner::RngSeed::Fixed`], so plain
//! `cargo test` replays identical case sequences every run (W5B
//! convention, `crates/sav/tests/sib_props.rs`). The `PROPTEST_*`
//! environment variables still override the in-code seeds (proptest
//! contextualizes env vars over the config) when a human wants to
//! explore; the gate does not set them.
//!
//! Generation notes: prefixes are canonical (network-masked, the form real
//! route ingestion carries); routes mix protocols (static + IGP/EGP) and
//! tables, and hops span the full taxonomy — ifindex-carrying and
//! blackhole hops (always eligible), bare gateway hops (never resolvable
//! against a bare `Rib::new()` with no interface mirror, so a best route
//! may end up held in the RIB rather than desired). The test-side
//! reference model replays the table semantics exactly (`Table::add`
//! same-protocol retain+push, `Table::best` min by (admin distance,
//! metric) first-wins, `reload_static`'s vanished-static withdrawal) and
//! recomputes the desired set the way `reconcile` documents it. The
//! strategy/model helpers intentionally mirror `sib_props.rs` (keeping
//! this micro single-file; lifting them into shared test support stays a
//! recorded follow-up).

use std::collections::{BTreeMap, BTreeSet};
use std::future::Future;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::sync::Mutex;

use common::{
    Dataplane, DataplaneError, IpPrefix, Ipv4Prefix, Ipv6Prefix, Nexthop, NexthopGroup, RouteEntry,
    RouteProtocol, TableId,
};
use proptest::prelude::*;
use proptest::test_runner::RngSeed;
use rib::Rib;

/// One fixed seed per property (distinct streams), W5B convention. The
/// prefix spells M3 in ASCII (0x4D 0x33).
const SEED_PARTITION: u64 = 0x4D33_0101;
const SEED_KEEP_IFF_UNCHANGED: u64 = 0x4D33_0102;
const SEED_FIXPOINT: u64 = 0x4D33_0103;

fn seeded(seed: u64) -> ProptestConfig {
    ProptestConfig {
        rng_seed: RngSeed::Fixed(seed),
        ..ProptestConfig::default()
    }
}

/// (table, prefix) — the key space of the reconcile diff.
type Key = (TableId, IpPrefix);

// ---------------------------------------------------------------------------
// Strategies (canonical prefixes, mirroring sib_props.rs)
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

fn table_strategy() -> impl Strategy<Value = TableId> {
    prop_oneof![Just(254u32), Just(255u32), Just(5001u32)]
}

/// Protocol-table origins only: kernel/connected arrive via the mirror
/// and never enter the protocol tables, so they are out of the diff's
/// input by construction. Static is overweighted so the reload swap
/// carries weight.
fn protocol_strategy() -> impl Strategy<Value = RouteProtocol> {
    use RouteProtocol::{Bgp, IsIs, Ospf, Rip, Static};
    prop_oneof![
        3 => Just(Static),
        3 => Just(Ospf),
        1 => Just(Bgp),
        1 => Just(Rip),
        1 => Just(IsIs),
    ]
}

/// Route hops: ifindex-carrying forms and blackholes (always eligible for
/// programming), bare gateways (never resolvable against a bare Rib —
/// they make a best route held rather than desired).
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

fn route_strategy() -> impl Strategy<Value = RouteEntry> {
    (
        prefix_strategy(),
        protocol_strategy(),
        table_strategy(),
        any::<u32>(),
        proptest::collection::vec((hop_strategy(), 1u8..=4), 1..=3),
    )
        .prop_map(|(prefix, protocol, table, metric, hops)| {
            let mut nexthops = NexthopGroup::new();
            for (hop, weight) in hops {
                nexthops.add(hop, weight);
            }
            let mut entry = RouteEntry::new(prefix, protocol, nexthops, metric);
            entry.table = table;
            entry
        })
}

/// The scenario every property replays: an initial route set (with some
/// non-static candidates withdrawn before the baseline pass), then
/// between the passes protocol churn followed by a `reload_static` swap —
/// the M2 soft-reconfiguration machinery. `drop_mask` bit i (mod 32)
/// withdraws initial route i's protocol candidate; static routes are
/// skipped there because their lifecycle belongs to the reload.
#[derive(Clone, Debug)]
struct Scenario {
    initial: Vec<RouteEntry>,
    churn: Vec<RouteEntry>,
    reload: Vec<RouteEntry>,
    drop_mask: u32,
}

fn scenario_strategy() -> impl Strategy<Value = Scenario> {
    (
        proptest::collection::vec(route_strategy(), 0..=14),
        proptest::collection::vec(route_strategy(), 0..=10),
        proptest::collection::vec(route_strategy(), 0..=14),
        any::<u32>(),
    )
        .prop_map(|(initial, churn, reload, drop_mask)| Scenario {
            initial,
            churn,
            reload,
            drop_mask,
        })
}

// ---------------------------------------------------------------------------
// Reference model (test-side recomputation of the documented semantics)
// ---------------------------------------------------------------------------

/// Candidate lists per key, replayed exactly as the tables store them:
/// per-protocol replace (retain+push, insertion order preserved), so
/// `min_by_key` first-wins ties break identically to `Table::best`.
type Model = BTreeMap<Key, Vec<RouteEntry>>;

fn model_add(model: &mut Model, entry: &RouteEntry) {
    let candidates = model.entry(key_of(entry)).or_default();
    candidates.retain(|e| e.protocol != entry.protocol);
    candidates.push(entry.clone());
}

fn model_withdraw(model: &mut Model, key: Key, protocol: RouteProtocol) {
    if let Some(candidates) = model.get_mut(&key) {
        candidates.retain(|e| e.protocol != protocol);
        if candidates.is_empty() {
            model.remove(&key);
        }
    }
}

/// `Rib::reload_static` replayed: static candidates at keys absent from
/// the fresh config are withdrawn (whatever else lives at those keys
/// survives), then every fresh route replaces its key's same-protocol
/// candidate.
fn model_reload_static(model: &mut Model, routes: &[RouteEntry]) {
    let fresh: BTreeSet<Key> = routes.iter().map(key_of).collect();
    let vanished: Vec<Key> = model
        .iter()
        .filter(|(_, candidates)| {
            candidates
                .iter()
                .any(|e| e.protocol == RouteProtocol::Static)
        })
        .filter(|(key, _)| !fresh.contains(*key))
        .map(|(key, _)| *key)
        .collect();
    for key in vanished {
        model_withdraw(model, key, RouteProtocol::Static);
    }
    for route in routes {
        model_add(model, route);
    }
}

/// A hop is eligible for programming exactly when it carries an ifindex
/// or is a blackhole; bare gateways never resolve against a bare Rib.
fn hop_eligible(hop: Nexthop) -> bool {
    matches!(
        hop,
        Nexthop::IfIndex(_) | Nexthop::Ipv4If(..) | Nexthop::Ipv6If(..) | Nexthop::Blackhole
    )
}

/// The desired set the way `reconcile` computes it: per key the best
/// candidate (min by (admin distance, metric), first-wins), rewritten to
/// resolved programming form; an empty eligible subset holds the route in
/// the RIB instead of desiring it.
fn model_desired(model: &Model) -> BTreeMap<Key, RouteEntry> {
    let mut desired = BTreeMap::new();
    for (key, candidates) in model {
        let best = candidates
            .iter()
            .min_by_key(|e| (e.protocol.admin_distance(), e.metric))
            .unwrap();
        let mut resolved = NexthopGroup::new();
        for &(hop, weight) in best.nexthops.hops() {
            if hop_eligible(hop) {
                resolved.add(hop, weight);
            }
        }
        if resolved.is_empty() {
            continue;
        }
        let mut form = best.clone();
        form.nexthops = resolved;
        desired.insert(*key, form);
    }
    desired
}

// ---------------------------------------------------------------------------
// Recording dataplane mock (rib's MockDp recipe, plus a kernel-belief
// mirror so "still programmed" is checkable from outside)
// ---------------------------------------------------------------------------

#[derive(Clone, Debug)]
enum DpOp {
    Replace(RouteEntry),
    Delete(RouteEntry),
}

fn key_of(entry: &RouteEntry) -> Key {
    (entry.table, entry.prefix)
}

#[derive(Default)]
struct RecordingDp {
    ops: Mutex<Vec<DpOp>>,
    /// What the mock kernel holds, keyed like the RIB's programmed set —
    /// updated on every successful op.
    kernel: Mutex<BTreeMap<Key, RouteEntry>>,
}

impl RecordingDp {
    fn op_count(&self) -> usize {
        self.ops.lock().unwrap().len()
    }

    fn ops_since(&self, start: usize) -> Vec<DpOp> {
        self.ops.lock().unwrap()[start..].to_vec()
    }

    fn kernel(&self) -> BTreeMap<Key, RouteEntry> {
        self.kernel.lock().unwrap().clone()
    }
}

impl Dataplane for RecordingDp {
    fn route_replace(
        &self,
        entry: &RouteEntry,
    ) -> impl Future<Output = Result<(), DataplaneError>> + Send {
        self.kernel
            .lock()
            .unwrap()
            .insert(key_of(entry), entry.clone());
        self.ops.lock().unwrap().push(DpOp::Replace(entry.clone()));
        std::future::ready(Ok(()))
    }

    fn route_delete(
        &self,
        entry: &RouteEntry,
    ) -> impl Future<Output = Result<(), DataplaneError>> + Send {
        self.kernel.lock().unwrap().remove(&key_of(entry));
        self.ops.lock().unwrap().push(DpOp::Delete(entry.clone()));
        std::future::ready(Ok(()))
    }
}

/// Minimal executor (nothing in the mock ever returns `Pending` for
/// long): a polling spin on a no-op waker.
fn block_on<F: Future>(fut: F) -> F::Output {
    use std::pin::pin;
    use std::task::{Context, Poll, Waker};

    let waker = Waker::noop();
    let mut cx = Context::from_waker(waker);
    let mut fut = pin!(fut);
    loop {
        match fut.as_mut().poll(&mut cx) {
            Poll::Ready(out) => return out,
            Poll::Pending => std::thread::yield_now(),
        }
    }
}

fn replaces<'a>(ops: &'a [DpOp], key: &Key) -> Vec<&'a RouteEntry> {
    ops.iter()
        .filter_map(|op| match op {
            DpOp::Replace(entry) if key_of(entry) == *key => Some(entry),
            _ => None,
        })
        .collect()
}

fn deletes<'a>(ops: &'a [DpOp], key: &Key) -> Vec<&'a RouteEntry> {
    ops.iter()
        .filter_map(|op| match op {
            DpOp::Delete(entry) if key_of(entry) == *key => Some(entry),
            _ => None,
        })
        .collect()
}

// ---------------------------------------------------------------------------
// Scenario harness
// ---------------------------------------------------------------------------

/// Everything a property needs to judge one mutation pass.
struct ReconcileRun {
    rib: Rib,
    dp: RecordingDp,
    /// What pass 0 programmed — the old-best keys the diff partitions.
    old: BTreeMap<Key, RouteEntry>,
    /// Model's desired set before the mutations (pass-0 validity).
    desired_before: BTreeMap<Key, RouteEntry>,
    /// Model's desired set after the mutations.
    desired_after: BTreeMap<Key, RouteEntry>,
    /// Dataplane ops the mutation pass issued.
    ops: Vec<DpOp>,
}

impl ReconcileRun {
    /// One more reconcile pass; returns its ops.
    fn pass(&mut self) -> Vec<DpOp> {
        let start = self.dp.op_count();
        block_on(self.rib.reconcile(&self.dp));
        self.dp.ops_since(start)
    }
}

/// Replays the scenario: load initial routes, withdraw the masked
/// protocol candidates, reconcile a baseline (pass 0), mutate (churn then
/// the static reload), reconcile again (pass 1, the diff under test).
fn run_scenario(scenario: &Scenario) -> ReconcileRun {
    let mut rib = Rib::new();
    let mut model = Model::new();
    for entry in &scenario.initial {
        rib.add_route(entry.clone());
        model_add(&mut model, entry);
    }
    for (i, entry) in scenario.initial.iter().enumerate() {
        if (scenario.drop_mask >> (i % 32)) & 1 == 1 && entry.protocol != RouteProtocol::Static {
            rib.table_mut(entry.table)
                .remove(&entry.prefix, entry.protocol);
            model_withdraw(&mut model, (entry.table, entry.prefix), entry.protocol);
        }
    }

    let dp = RecordingDp::default();
    let desired_before = model_desired(&model);

    // Pass 0: establish the programmed baseline the diff partitions.
    let mut run = ReconcileRun {
        rib,
        dp,
        old: BTreeMap::new(),
        desired_before,
        desired_after: BTreeMap::new(),
        ops: Vec::new(),
    };
    run.pass();
    run.old = run.dp.kernel();

    // Mutations between the passes: protocol churn, then the reload swap.
    for entry in &scenario.churn {
        run.rib.add_route(entry.clone());
        model_add(&mut model, entry);
    }
    run.rib.reload_static(&scenario.reload);
    model_reload_static(&mut model, &scenario.reload);

    // Pass 1: the diff under test.
    run.ops = run.pass();
    run.desired_after = model_desired(&model);
    run
}

// ---------------------------------------------------------------------------
// Property 1 — partition totality: every old-best key gets exactly one
// disposition, and every op belongs to a partition cell
// ---------------------------------------------------------------------------

proptest! {
    #![proptest_config(seeded(SEED_PARTITION))]
    #[test]
    fn old_best_keys_partition_into_add_withdraw_keep(scenario in scenario_strategy()) {
        let run = run_scenario(&scenario);
        // The baseline is honest: pass 0 programmed exactly the model's
        // desired set, so `old` is the old-best key set.
        prop_assert_eq!(&run.old, &run.desired_before);

        for (key, old_form) in &run.old {
            let replaces = replaces(&run.ops, key);
            let deletes = deletes(&run.ops, key);
            prop_assert!(
                replaces.len() + deletes.len() <= 1,
                "key {:?}: {} replaces + {} deletes — one disposition per old key",
                key,
                replaces.len(),
                deletes.len()
            );
            if replaces.is_empty() && deletes.is_empty() {
                // The keep disposition: still programmed, byte-identical.
                let kernel = run.dp.kernel();
                prop_assert_eq!(
                    kernel.get(key),
                    Some(old_form),
                    "kept key {:?} must stay programmed unchanged",
                    key
                );
            }
        }

        // Every op belongs to exactly one cell: deletes only ever target
        // old keys; a replace is a changed old key or a brand-new one.
        for op in &run.ops {
            match op {
                DpOp::Replace(entry) => {
                    let key = key_of(entry);
                    if let Some(old_form) = run.old.get(&key) {
                        prop_assert_ne!(
                            entry, old_form,
                            "replaced old key {:?} must have a changed form", key
                        );
                    } else {
                        prop_assert!(
                            run.desired_after.contains_key(&key),
                            "install for key {:?} that the model does not desire",
                            key
                        );
                    }
                }
                DpOp::Delete(entry) => {
                    prop_assert!(
                        run.old.contains_key(&key_of(entry)),
                        "withdraw for key {:?} that was never programmed",
                        key_of(entry)
                    );
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Property 2 — keep ⇔ best unchanged (the silence rule of the diff)
// ---------------------------------------------------------------------------

proptest! {
    #![proptest_config(seeded(SEED_KEEP_IFF_UNCHANGED))]
    #[test]
    fn keep_holds_exactly_when_best_is_unchanged(scenario in scenario_strategy()) {
        let run = run_scenario(&scenario);
        prop_assert_eq!(&run.old, &run.desired_before);

        for (key, old_form) in &run.old {
            let replaces = replaces(&run.ops, key);
            let deletes = deletes(&run.ops, key);
            let kept = replaces.is_empty() && deletes.is_empty();
            let desired = run.desired_after.get(key);

            // Forward: silence means the new best is byte-identical.
            if kept {
                prop_assert_eq!(desired, Some(old_form), "kept key {:?}", key);
            }
            // Backward: a byte-identical best means silence.
            if desired == Some(old_form) {
                prop_assert!(kept, "unchanged best for key {:?} was re-sent", key);
            }
            if let Some(new_form) = desired {
                // Changed best: exactly one replace carrying the new form.
                if new_form != old_form {
                    prop_assert_eq!(
                        replaces.len(),
                        1,
                        "changed best for key {:?} was not re-installed",
                        key
                    );
                    prop_assert_eq!(replaces[0], new_form);
                }
            } else {
                // Vanished best: exactly one withdraw carrying the old form.
                prop_assert_eq!(
                    deletes.len(),
                    1,
                    "vanished best for key {:?} was not withdrawn",
                    key
                );
                prop_assert_eq!(deletes[0], old_form);
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Property 3 — stable fixpoint: the pass reaches exactly the desired
// state and a no-mutation pass issues nothing
// ---------------------------------------------------------------------------

proptest! {
    #![proptest_config(seeded(SEED_FIXPOINT))]
    #[test]
    fn reconcile_reaches_a_stable_fixpoint(scenario in scenario_strategy()) {
        let mut run = run_scenario(&scenario);
        prop_assert_eq!(&run.old, &run.desired_before);

        // The mutation pass brought the dataplane to exactly the model's
        // desired state: no stale route left behind, no desired route missing.
        prop_assert_eq!(&run.dp.kernel(), &run.desired_after);

        // A pass over an already-converged state issues no calls at all —
        // unchanged bests never bounce (soft reconfiguration).
        let ops = run.pass();
        prop_assert!(ops.is_empty(), "no-mutation pass issued {:?}", ops);
        prop_assert_eq!(&run.dp.kernel(), &run.desired_after);
    }
}
