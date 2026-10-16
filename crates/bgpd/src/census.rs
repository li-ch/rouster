//! The PERF-M1 memory census (feature `mem-census`, env-gated at
//! runtime by `BGPD_MEM_CENSUS=1`): a deep-size walk over the Loc-RIB
//! that names the per-structure memory consumers at table-size
//! milestones, so the optimization order is evidence, not fashion.
//!
//! Method notes (the receipts depend on these):
//! - **Deep size** counts what a structure owns on the heap: the
//!   `Vec<PathAttribute>` buffer (`capacity * size_of::<PathAttribute>()`),
//!   plus every per-variant buffer (AS_PATH segment and ASN vectors,
//!   COMMUNITIES, unknown-attribute values). Inline sizes (`size_of`)
//!   are reported separately — they are the keyed-map share (each
//!   BTreeMap slot stores key + value inline; the node header
//!   amortizes to ~3 B/entry at capacity 11).
//! - **Duplication factor** re-encodes each stored attribute list to
//!   its wire form (`encode_attributes`, deterministic for equal
//!   lists) and counts distinct byte strings — the FRR `bgp_attr`
//!   intern-table question: how many of the stored tuples are
//!   duplicates of another? Reported for the full tuple, for the
//!   AS_PATH alone, and for the tuple minus AS_PATH (the tuple the
//!   Adj-RIB-In duplicates into the Loc-RIB best table on every
//!   election — the `best` clone share).
//! - **RSS** comes from `/proc/self/status` (the SUT runs in a Linux
//!   container; absent on other hosts → `None`). The census walk's
//!   own transients (the duplication `HashSet`) are disclosed by
//!   sampling RSS before and after the walk.
//! - The walk locks the RIB briefly; it changes nothing (read-only
//!   `&LocRib`), matching the barsav feed writer's locking shape.

use std::collections::HashSet;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use tracing::info;

use crate::attr::{encode_attributes, AddPathCtx, AsSegment, PathAttribute};
use crate::rib::LocRib;

/// Table-size milestones that trigger a full census dump (monotonic
/// during ingest; each fires once). Scaled to bracket both the 100k
/// receipt slice and the full 1.126M table.
const MILESTONES: [usize; 8] = [
    1_000, 3_000, 10_000, 30_000, 100_000, 300_000, 1_000_000, 3_000_000,
];

/// Ticks (1 s) the route count must hold still after a change before
/// the plateau dump fires (the "final" table state, post-EOR).
const PLATEAU_TICKS: u32 = 5;

/// One census snapshot: every number the campaign's target list is
/// built from. All byte counts are `usize`.
#[derive(Debug, Default)]
pub struct Census {
    // --- counts -----------------------------------------------------
    pub routes_adj: usize,
    pub routes_best: usize,
    pub peers: usize,
    // --- deep (heap-owned) bytes ------------------------------------
    /// Sum of every Adj-RIB-In route's attribute-list storage: the
    /// Vec buffer + all per-variant buffers.
    pub attrs_deep_adj: usize,
    /// The same sum over the best table (the election's deep copy).
    pub attrs_deep_best: usize,
    /// AS_PATH share of `attrs_deep_adj`: segment vectors + ASN vectors.
    pub aspath_deep_adj: usize,
    /// COMMUNITIES share of `attrs_deep_adj`.
    pub communities_deep_adj: usize,
    /// Unknown-attribute (e.g. LARGE_COMMUNITY passthrough) value
    /// buffers — share of `attrs_deep_adj`.
    pub unknown_deep_adj: usize,
    /// The attribute-list Vec buffers alone (capacity × element size).
    pub attr_vec_buffers_adj: usize,
    // --- duplication (the FRR bgp_attr question) --------------------
    /// Distinct full attribute tuples among Adj-RIB-In routes.
    pub distinct_attr_tuples: usize,
    /// Distinct AS_PATH encodings among them.
    pub distinct_aspaths: usize,
    /// Distinct tuples with the AS_PATH removed.
    pub distinct_tuples_minus_aspath: usize,
    /// The interner's live tuple count (post-M2; 0 pre-interning).
    pub interned_tuples: usize,
    // --- shapes ------------------------------------------------------
    /// Routes whose AS_PATH is a single AS_SEQUENCE segment.
    pub aspath_single_sequence: usize,
    /// Total ASN octets stored across all paths (4/ASN).
    pub total_asns: usize,
    /// Number of distinct heap allocations the attr model makes per
    /// Adj-RIB-In route, on average (×100 = centi-allocs).
    pub attr_allocs_centi: usize,
    // --- process -----------------------------------------------------
    pub vm_rss_kb: Option<usize>,
    pub vm_hwm_kb: Option<usize>,
    pub vm_rss_kb_after_walk: Option<usize>,
}

impl Census {
    /// The one-line ledger form (the log the receipts parse).
    pub fn log_line(&self) -> String {
        format!(
            "MEM-CENSUS routes_adj={} routes_best={} peers={} \
             attrs_deep_adj={} attrs_deep_best={} \
             aspath_deep_adj={} communities_deep_adj={} unknown_deep_adj={} \
             attr_vec_buffers_adj={} distinct_attr_tuples={} \
             distinct_aspaths={} distinct_tuples_minus_aspath={} \
             interned_tuples={} aspath_single_sequence={} total_asns={} \
             attr_allocs_centi={} vm_rss_kb={} vm_hwm_kb={} vm_rss_after={}",
            self.routes_adj,
            self.routes_best,
            self.peers,
            self.attrs_deep_adj,
            self.attrs_deep_best,
            self.aspath_deep_adj,
            self.communities_deep_adj,
            self.unknown_deep_adj,
            self.attr_vec_buffers_adj,
            self.distinct_attr_tuples,
            self.distinct_aspaths,
            self.distinct_tuples_minus_aspath,
            self.interned_tuples,
            self.aspath_single_sequence,
            self.total_asns,
            self.attr_allocs_centi,
            self.vm_rss_kb.map(|v| v.to_string()).unwrap_or("-".into()),
            self.vm_hwm_kb.map(|v| v.to_string()).unwrap_or("-".into()),
            self.vm_rss_kb_after_walk
                .map(|v| v.to_string())
                .unwrap_or("-".into()),
        )
    }

    /// The constant table (inline sizes; the keyed-map share inputs).
    pub fn constants_line() -> String {
        format!(
            "MEM-CENSUS-CONSTS size_route={} size_nlri={} size_prefix={} \
             size_path_attribute={} size_as_segment={} size_peer_info={} \
             size_best_change={}",
            std::mem::size_of::<crate::rib::Route>(),
            std::mem::size_of::<crate::attr::Nlri>(),
            std::mem::size_of::<common::IpPrefix>(),
            std::mem::size_of::<PathAttribute>(),
            std::mem::size_of::<AsSegment>(),
            std::mem::size_of::<crate::peer::PeerInfo>(),
            std::mem::size_of::<crate::rib::BestChange>(),
        )
    }
}

fn proc_status_kb(field: &str) -> Option<usize> {
    let text = std::fs::read_to_string("/proc/self/status").ok()?;
    for line in text.lines() {
        if let Some(rest) = line.strip_prefix(field) {
            let mut it = rest.split_whitespace();
            let kb = it.next()?.parse().ok()?;
            return Some(kb);
        }
    }
    None
}

/// The walk itself: read-only over the RIB. Post-M2 the attribute
/// tuples are interned and shared (`Arc`), so "deep size" is summed
/// once per DISTINCT tuple (pointer identity), not per route — the
/// per-route sum would over-count the shared instances.
pub fn walk(rib: &LocRib) -> Census {
    let mut c = Census {
        vm_rss_kb: proc_status_kb("VmRSS:"),
        vm_hwm_kb: proc_status_kb("VmHWM:"),
        ..Default::default()
    };
    let mut attr_allocs: usize = 0;
    let mut tuples: HashSet<Vec<u8>> = HashSet::new();
    let mut aspaths: HashSet<Vec<u8>> = HashSet::new();
    let mut minus_aspath: HashSet<Vec<u8>> = HashSet::new();
    let mut seen_arc: HashSet<usize> = HashSet::new();

    let size_pa = std::mem::size_of::<PathAttribute>();
    let encode = |attrs: &[PathAttribute], strip_aspath: bool| -> Vec<u8> {
        let filtered: Vec<PathAttribute> = if strip_aspath {
            attrs
                .iter()
                .filter(|a| a.attr_type() != crate::attr::attr_type::AS_PATH)
                .cloned()
                .collect()
        } else {
            attrs.to_vec()
        };
        let mut out = Vec::new();
        // asn4=true: the feed's negotiated encoding; distinctness does
        // not depend on the width (the mapping is injective).
        let _ = encode_attributes(&filtered, &mut out, true, AddPathCtx::default());
        out
    };

    for route in rib.census_adj_routes() {
        c.routes_adj += 1;
        if seen_arc.insert(Arc::as_ptr(&route.attrs) as usize) {
            // First sighting of this interned tuple: count its storage.
            c.attrs_deep_adj += route.attrs.capacity() * size_pa;
            c.attr_vec_buffers_adj += route.attrs.capacity() * size_pa;
            attr_allocs += 1;
            for attr in route.attrs.iter() {
                match attr {
                    PathAttribute::AsPath(p) => {
                        c.aspath_deep_adj +=
                            p.segments.capacity() * std::mem::size_of::<AsSegment>();
                        attr_allocs += 1;
                        if p.segments.len() == 1 && matches!(p.segments[0], AsSegment::Sequence(_))
                        {
                            c.aspath_single_sequence += 1;
                        }
                        for seg in &p.segments {
                            let asns = match seg {
                                AsSegment::Set(v) | AsSegment::Sequence(v) => v,
                            };
                            c.aspath_deep_adj += asns.capacity() * 4;
                            c.total_asns += asns.len();
                            attr_allocs += 1;
                        }
                    }
                    PathAttribute::Communities(v) => {
                        c.communities_deep_adj += v.capacity() * 4;
                        attr_allocs += 1;
                    }
                    PathAttribute::Unknown { value, .. } => {
                        c.unknown_deep_adj += value.capacity();
                        attr_allocs += 1;
                    }
                    _ => {}
                }
            }
        }
        tuples.insert(encode(&route.attrs, false));
        if let Some(PathAttribute::AsPath(p)) = route
            .attrs
            .iter()
            .find(|a| a.attr_type() == crate::attr::attr_type::AS_PATH)
        {
            let mut bytes = Vec::new();
            p.encode(&mut bytes, true);
            aspaths.insert(bytes);
        }
        minus_aspath.insert(encode(&route.attrs, true));
    }
    for route in rib.best_routes() {
        c.routes_best += 1;
        if seen_arc.insert(Arc::as_ptr(&route.attrs) as usize) {
            // A best-table tuple the Adj-RIB-In does not also hold
            // (a policy fork): its storage counts here.
            c.attrs_deep_best += route.attrs.capacity() * size_pa;
            for attr in route.attrs.iter() {
                match attr {
                    PathAttribute::AsPath(p) => {
                        c.attrs_deep_best +=
                            p.segments.capacity() * std::mem::size_of::<AsSegment>();
                        for seg in &p.segments {
                            let asns = match seg {
                                AsSegment::Set(v) | AsSegment::Sequence(v) => v,
                            };
                            c.attrs_deep_best += asns.capacity() * 4;
                        }
                    }
                    PathAttribute::Communities(v) => c.attrs_deep_best += v.capacity() * 4,
                    PathAttribute::Unknown { value, .. } => c.attrs_deep_best += value.capacity(),
                    _ => {}
                }
            }
        }
    }
    c.peers = rib.census_peer_count();
    c.distinct_attr_tuples = tuples.len();
    c.distinct_aspaths = aspaths.len();
    c.distinct_tuples_minus_aspath = minus_aspath.len();
    c.interned_tuples = rib.attrs.len();
    c.attr_allocs_centi = if c.routes_adj > 0 {
        attr_allocs * 100 / c.routes_adj
    } else {
        0
    };
    c.vm_rss_kb_after_walk = proc_status_kb("VmRSS:");
    c
}

/// The runtime-gated sampler: dumps the constant table once, then a
/// full census at each milestone crossing and at the post-EOR plateau.
pub fn spawn(rib: std::sync::Arc<Mutex<LocRib>>) {
    info!("{}", Census::constants_line());
    tokio::spawn(async move {
        let mut next_milestone = 0usize; // index into MILESTONES
        let mut last_count = usize::MAX;
        let mut stable_ticks: u32 = 0;
        let mut plateau_dumped_at = usize::MAX;
        loop {
            let count = { rib.lock().unwrap().route_count() };
            if next_milestone < MILESTONES.len() && count >= MILESTONES[next_milestone] {
                let census = { walk(&rib.lock().unwrap()) };
                info!(routes = count, "{}", census.log_line());
                next_milestone += 1;
                last_count = count;
                continue;
            }
            if count == last_count {
                stable_ticks += 1;
            } else {
                stable_ticks = 0;
                last_count = count;
            }
            if stable_ticks == PLATEAU_TICKS && count > 0 && plateau_dumped_at != count {
                let census = { walk(&rib.lock().unwrap()) };
                info!(routes = count, "{}", census.log_line());
                plateau_dumped_at = count;
            }
            tokio::time::sleep(Duration::from_secs(1)).await;
        }
    });
}
