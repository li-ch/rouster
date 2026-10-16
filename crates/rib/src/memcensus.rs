//! The PERF-P3 memory census (rides the `cpu-census` feature gate —
//! the fence forbids manifest edits, so the existing feature is
//! reused; runtime-armed separately by `ROUSTERD_MEM_CENSUS=1`): a
//! deep walk over the RIB's storage that names the per-structure
//! memory consumers at table-size milestones, so the zebra-side
//! optimization order is evidence, not fashion.
//!
//! Method notes (the receipts depend on these):
//! - **Counts and duplication** are measured exactly: per-table
//!   prefix/candidate counts, the programmed-belief size, the NHT
//!   table, and the nexthop-group duplication factor (distinct group
//!   contents among stored candidates vs. among programmed beliefs,
//!   hashed by value — the FRR nexthop-object-sharing question).
//! - **Inline sizes** are `size_of` facts. The BTreeMap node share is
//!   a MODEL, disclosed: std nodes hold up to 11 slots, so a full node
//!   for (K, V) costs roughly `(11 * (size_of::<K>() +
//!   size_of::<V>()) + 48) / 11` per entry, and random-order inserts
//!   leave nodes partly empty — the model's full-fill number is a
//!   floor, the RSS delta is the truth.
//! - **RSS/HWM** come from `/proc/self/status` (Linux container;
//!   absent on other hosts → dropped fields). The walk's own
//!   transients are disclosed by sampling RSS before and after and
//!   reporting the walk's wall cost.
//! - The first observation captures the baseline RSS used by the
//!   derived `b_per_prefix` (empty→now); milestones fire inside the
//!   ingest path (their cost shows in the census run only, never in
//!   clean receipts — the module compiles away without the feature,
//!   and stays inert without the env var).

use std::collections::HashSet;
use std::hash::{Hash, Hasher};
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant};

use common::{Nexthop, NexthopGroup, RouteEntry};
use tracing::info;

use crate::Rib;

/// Route-add counts that trigger a census dump during ingest (each
/// fires once, monotonic).
const MILESTONES: [usize; 3] = [10_000, 100_000, 1_000_000];

/// Quiet window after the last route add before the plateau dump (the
/// post-EOR settled state).
const PLATEAU_QUIET: Duration = Duration::from_secs(5);

fn armed() -> bool {
    static ARMED: OnceLock<bool> = OnceLock::new();
    *ARMED.get_or_init(|| std::env::var("ROUSTERD_MEM_CENSUS").ok().as_deref() == Some("1"))
}

fn adds() -> &'static AtomicUsize {
    static ADDS: AtomicUsize = AtomicUsize::new(0);
    &ADDS
}

fn milestone_next() -> &'static AtomicUsize {
    static NEXT: AtomicUsize = AtomicUsize::new(0);
    &NEXT
}

fn plateau_done() -> &'static AtomicBool {
    static DONE: AtomicBool = AtomicBool::new(false);
    &DONE
}

fn last_add() -> &'static Mutex<Option<Instant>> {
    static LAST: Mutex<Option<Instant>> = Mutex::new(None);
    &LAST
}

fn rss_base_kb() -> &'static AtomicU64 {
    static BASE: AtomicU64 = AtomicU64::new(0);
    &BASE
}

/// `(VmRSS kB, VmHWM kB)` from procfs; `None` off Linux.
fn rss_pair() -> Option<(u64, u64)> {
    let status = std::fs::read_to_string("/proc/self/status").ok()?;
    let mut rss = None;
    let mut hwm = None;
    for line in status.lines() {
        if let Some(rest) = line.strip_prefix("VmRSS:") {
            rss = rest.split_whitespace().next()?.parse().ok();
        } else if let Some(rest) = line.strip_prefix("VmHWM:") {
            hwm = rest.split_whitespace().next()?.parse().ok();
        }
    }
    Some((rss?, hwm?))
}

fn group_hash(hops: &[(Nexthop, u8)]) -> u64 {
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    hops.hash(&mut hasher);
    hasher.finish()
}

/// Called from [`Rib::add_route`]: counts the add and fires any
/// milestone dump due.
pub(crate) fn note_add(rib: &Rib) {
    if !armed() {
        return;
    }
    adds().fetch_add(1, Ordering::Relaxed);
    *last_add().lock().unwrap() = Some(Instant::now());
    let next = milestone_next().load(Ordering::Relaxed);
    if next < MILESTONES.len() && adds().load(Ordering::Relaxed) >= MILESTONES[next] {
        milestone_next().store(next + 1, Ordering::Relaxed);
        dump(rib, MILESTONES[next]);
    }
}

/// Called from the daemon's status cadence: the settled-state dump
/// once ingest has been quiet past [`PLATEAU_QUIET`].
pub fn plateau_maybe(rib: &Rib) {
    if !armed() || plateau_done().load(Ordering::Relaxed) {
        return;
    }
    let quiet = last_add()
        .lock()
        .unwrap()
        .is_some_and(|t| t.elapsed() >= PLATEAU_QUIET);
    if quiet {
        plateau_done().store(true, Ordering::Relaxed);
        dump(rib, 0);
    }
}

/// One census dump: measured counts + duplication + RSS + the inline
/// size facts. One `info!` line per trigger, `memcensus`-prefixed.
fn dump(rib: &Rib, milestone: usize) {
    let t0 = Instant::now();
    let rss_before = rss_pair();
    let mut prefixes = 0usize;
    let mut candidates = 0usize;
    let mut single_hop = 0usize;
    let mut multi_hop = 0usize;
    let mut distinct_in_tables: HashSet<u64> = HashSet::new();
    for table in rib.tables.values() {
        for (_, cands) in table.iter() {
            prefixes += 1;
            candidates += cands.len();
            for entry in cands {
                distinct_in_tables.insert(group_hash(entry.nexthops.hops()));
                if entry.nexthops.hops().len() == 1 {
                    single_hop += 1;
                } else {
                    multi_hop += 1;
                }
            }
        }
    }
    let mut distinct_in_programmed: HashSet<u64> = HashSet::new();
    for belief in rib.programmed.values() {
        distinct_in_programmed.insert(group_hash(belief.hops.hops()));
    }
    let kernel_mirror_prefixes: usize = rib.kernel_mirror.values().map(|t| t.iter().count()).sum();
    let walk = t0.elapsed();
    let (rss_kb, hwm_kb) = rss_pair().unzip();
    let base = rss_base_kb().load(Ordering::Relaxed);
    if base == 0 {
        if let Some(rss) = rss_kb {
            rss_base_kb().store(rss, Ordering::Relaxed);
        }
    }
    let b_per_prefix = match (rss_kb, prefixes) {
        (Some(rss), n) if n > 0 && base > 0 => Some((rss.saturating_sub(base)) * 1024 / n as u64),
        _ => None,
    };
    // The node model (disclosed): full-fill BTreeMap share per entry.
    let node_share = |k: usize, v: usize| (11 * (k + v) + 48) / 11;
    info!(
        milestone,
        prefixes,
        candidates,
        single_hop,
        multi_hop,
        distinct_nhg_in_tables = distinct_in_tables.len(),
        distinct_nhg_in_programmed = distinct_in_programmed.len(),
        programmed = rib.programmed.len(),
        kernel_mirror_prefixes,
        nht_tracked = rib.nht.len(),
        neighbours = rib.neighbours.len(),
        interfaces = rib.interfaces().len(),
        rss_kb = rss_kb.unwrap_or(0),
        hwm_kb = hwm_kb.unwrap_or(0),
        census_self_delta_kb = rss_before
            .map(|(before, _)| before)
            .zip(rss_kb)
            .map(|(before, after)| after.saturating_sub(before))
            .unwrap_or(0),
        b_per_prefix = b_per_prefix.unwrap_or(0),
        size_route_entry = std::mem::size_of::<RouteEntry>(),
        size_nexthopgroup = std::mem::size_of::<NexthopGroup>(),
        model_tables_node_full_fill_b = node_share(
            std::mem::size_of::<common::IpPrefix>(),
            std::mem::size_of::<Vec<RouteEntry>>()
        ),
        model_programmed_node_full_fill_b = node_share(
            std::mem::size_of::<(common::TableId, common::IpPrefix)>(),
            std::mem::size_of::<RouteEntry>()
        ),
        walk_ms = walk.as_millis() as u64,
        "memcensus"
    );
}
