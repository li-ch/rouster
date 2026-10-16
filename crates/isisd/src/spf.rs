//! The per-level SPF: the Dijkstra over IS-reachability TLVs (ISO
//! 10589 §7.2.2's Decision Process / Annex C.2's algorithm via RFC
//! 1142; RFC 1195 §3.10 for the IP route derivation), pure and
//! property-tested against a brute-force Bellman-Ford oracle — the
//! ospfd `spf.rs` recipe.
//!
//! Metric selection — **wide preferred, narrow fallback** (RFC 5305's
//! metric-style transition, as FRR 10.2.2 reads it): an LSP carrying
//! TLV 22 is read wide (TLV 2 ignored); only a TLV-2-only LSP is read
//! narrow. A router in transition advertises both; peers on wide
//! read the wide. Same per-LSP rule for prefixes: TLV 135 first,
//! else 128/130.
//!
//! Exclusions, each spec-pinned:
//!
//! - **Purged LSPs** (zero remaining lifetime) are not used by the
//!   decision process — ISO §7.3.16.4's tombstone is header-only, so
//!   there is nothing to use.
//! - **Overloaded LSPs** (LSPDBOL): ISO §9.8 — "An LSP with this bit
//!   set will not be used by any decision process to calculate
//!   routes **to another IS through** the originating system": its
//!   prefixes stay reachable, transit through it does not.
//! - **Max-metric links/prefixes** (RFC 5305 §3/§4): a link at
//!   2^24-1 "MUST NOT be considered during the normal SPF
//!   computation"; a prefix ≥ MAX_PATH_METRIC likewise.
//! - **Attached bit** (ISO §9.8's ATT bits; RFC 1195 §3.10.1): an
//!   L1 computation collects the reachable attached L2 ISs and
//!   reports them as the candidates for the default route ("Amongst
//!   routes in the area … to attached level 2 routers, the shortest
//!   routes are preferred" — equal cost may load-split).
//!
//! The graph: vertices are system IDs; a router LSP's TLV 22/2
//! entries are edges — a non-pseudonode entry is a direct edge at
//! its metric, a pseudonode entry is an edge to the LAN vertex,
//! whose own LSP then fans out to every attached router at metric 0
//! (the ISO broadcast model; p2p circuits never produce one).

use std::collections::{BTreeMap, BinaryHeap, HashMap, HashSet};
use std::net::Ipv4Addr;

use crate::lspdb::Lspdb;
use crate::pdu::{Lsp, LspBits};
use crate::system::{Level, NeighborId, SystemId};
use crate::tlv::{NarrowIpReach, OldIsNeighbor, Tlv, WideIpReach};

/// One forwarding next hop for a destination.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NextHop {
    /// The first-hop neighbour (a direct circuit peer, pseudonode 0).
    pub neighbor: SystemId,
    /// The neighbour's IP on that circuit (TLV 132 of its LSP —
    /// RFC 1195 §5.2.1's interface address list; the first usable
    /// one).
    pub address: Option<Ipv4Addr>,
}

/// One computed IP route.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Route {
    pub prefix: (Ipv4Addr, u8),
    /// End-to-end metric: SPF distance to the origin + the prefix
    /// metric (RFC 1195 §3.10.2's distance composition).
    pub metric: u64,
    pub next_hops: Vec<NextHop>,
    /// True when derived from TLV 130 (external reachability).
    pub external: bool,
    /// RFC 5302's up/down bit as read from the advertisement: true
    /// means the prefix was leaked **down** (L2→L1) by the advertising
    /// border. Pure observability for path computation — every
    /// prefix is routed — but the L1→L2 re-advertisement guard at the
    /// border (RFC 5302 §2: "Prefixes with the up/down bit set that
    /// are learned via L1 routing MUST NOT be advertised by L1L2
    /// routers back into L2") reads it.
    pub up_down: bool,
}

/// The SPF result for one level.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SpfResult {
    /// SPF distance to every reachable IS vertex — routers
    /// (`pseudonode == 0`) and LAN pseudonodes alike (ISO §7.2.3's
    /// broadcast graph).
    pub distances: BTreeMap<NeighborId, u64>,
    /// Next hops per destination IS (first hops on the shortest
    /// paths — the ECMP set deduplicated by neighbour). Router
    /// vertices only: a LAN forwards nothing by itself.
    pub next_hops: BTreeMap<NeighborId, Vec<NextHop>>,
    /// The IP routes derived from reachable LSPs' prefix TLVs.
    pub routes: Vec<Route>,
    /// L1 only: the reachable attached L2 ISs (RFC 1195 §3.10.1's
    /// default-route candidates — nearest first, the daemon
    /// originates 0.0.0.0/0 toward them).
    pub attached: Vec<(SystemId, u64, Vec<NextHop>)>,
}

/// One graph edge.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Edge {
    to: NeighborId,
    metric: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct HeapNode {
    cost: u64,
    id: NeighborId,
}

impl Ord for HeapNode {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        // Min-heap: reverse the natural max-heap order.
        other
            .cost
            .cmp(&self.cost)
            .then_with(|| other.id.cmp(&self.id))
    }
}

impl PartialOrd for HeapNode {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

/// The metric an adjacency entry contributes, or `None` when the
/// entry is excluded (RFC 5305 §3's max link metric).
fn link_metric(metric: u32) -> Option<u64> {
    if metric >= crate::MAX_LINK_METRIC {
        None
    } else {
        Some(metric as u64)
    }
}

/// Collect the usable edges of one LSP (wide preferred, narrow
/// fallback; overload kills transit; purged LSPs carry nothing).
/// Adjacency entries that name a pseudonode become edges to the LAN
/// vertex (ISO §7.2.3's broadcast model) — the pseudonode LSP's own
/// entries then fan out to the member routers at their advertised
/// (zero, §7.2.3) metric.
fn edges_of(lsp: &Lsp) -> Vec<Edge> {
    if lsp.is_purge() {
        return vec![];
    }
    let wide: Vec<&Vec<crate::tlv::ExtIsNeighbor>> = lsp
        .tlvs
        .iter()
        .filter_map(|t| match t {
            Tlv::ExtIsReachability(e) => Some(e),
            _ => None,
        })
        .collect();
    let mut edges = Vec::new();
    if !wide.is_empty() {
        for t in wide {
            for n in t {
                if let Some(m) = link_metric(n.metric) {
                    edges.push(Edge {
                        to: n.id,
                        metric: m,
                    });
                }
            }
        }
        return edges;
    }
    for t in &lsp.tlvs {
        if let Tlv::IsReachability(list) = t {
            for OldIsNeighbor {
                id, default_metric, ..
            } in list
            {
                edges.push(Edge {
                    to: *id,
                    metric: default_metric.metric() as u64,
                });
            }
        }
    }
    edges
}

/// Run the SPF for `level` over `db` rooted at `self_id` at clock
/// `now`. `Level::Level1` collects the attached-bit candidates.
pub fn run(self_id: SystemId, level: Level, db: &Lspdb, now: u64) -> SpfResult {
    // The vertex set and adjacency: every LSP is one vertex keyed by
    // its (system, pseudonode) id — router LSPs at pseudonode 0, a
    // DIS's pseudonode LSPs as LAN vertices (fragment space is
    // v1-flat — fragment 0 of each).
    let root = NeighborId::new(self_id, 0);
    let mut adjacency: HashMap<NeighborId, Vec<Edge>> = HashMap::new();
    let mut bits_by_system: HashMap<NeighborId, LspBits> = HashMap::new();
    let mut addresses: HashMap<NeighborId, Vec<Ipv4Addr>> = HashMap::new();
    let mut stored: HashMap<NeighborId, &Lsp> = HashMap::new();

    for record in db.stored_lsps() {
        let lsp = &record.lsp;
        if lsp.is_purge() || record.remaining_lifetime(now) == 0 {
            continue;
        }
        let vertex = NeighborId::new(lsp.id.system, lsp.id.pseudonode);
        adjacency.entry(vertex).or_default().extend(edges_of(lsp));
        if lsp.id.pseudonode == 0 {
            // Router-only TLVs: the type block (§7.2.5 reads it from
            // fragment 0 — v1's flat fragment space) and TLV 132.
            bits_by_system.insert(vertex, lsp.bits);
            let addrs: Vec<Ipv4Addr> = lsp
                .tlvs
                .iter()
                .filter_map(|t| match t {
                    Tlv::IpInterfaceAddress(a) => Some(a.clone()),
                    _ => None,
                })
                .flatten()
                .collect();
            if !addrs.is_empty() {
                addresses.insert(vertex, addrs);
            }
            stored.insert(vertex, lsp);
        }
    }

    // Dijkstra from the root router vertex.
    let mut dist: HashMap<NeighborId, u64> = HashMap::new();
    let mut parents: HashMap<NeighborId, HashSet<NeighborId>> = HashMap::new();
    let mut heap = BinaryHeap::new();
    dist.insert(root, 0);
    heap.push(HeapNode { cost: 0, id: root });
    while let Some(HeapNode { cost, id }) = heap.pop() {
        if cost > dist.get(&id).copied().unwrap_or(u64::MAX) {
            continue;
        }
        // Overloaded ROUTERS do not forward through themselves (ISO
        // §9.8: no routes "to another IS through the originating
        // system") — their own LSP contributes no transit edges.
        // LAN vertices carry no type block and always fan out.
        let overloaded = bits_by_system.get(&id).map(|b| b.overload).unwrap_or(false);
        if overloaded && id != root {
            continue;
        }
        let Some(edges) = adjacency.get(&id) else {
            continue;
        };
        for edge in edges {
            // NOTE: overload excludes transit (handled at the pop
            // above), not reachability — an overloaded IS's own
            // prefixes stay routable (ISO §9.8: no routes "to
            // another IS THROUGH the originating system").
            let next = cost + edge.metric;
            let current = dist.get(&edge.to).copied().unwrap_or(u64::MAX);
            if next < current {
                dist.insert(edge.to, next);
                parents.insert(edge.to, HashSet::from([id]));
                heap.push(HeapNode {
                    cost: next,
                    id: edge.to,
                });
            } else if next == current {
                parents.entry(edge.to).or_default().insert(id);
            }
        }
    }

    // Next hops: walk the DAG back to the first hop; the parent of
    // root's direct neighbours is root, so such a neighbour's own
    // entry is the first hop. A LAN vertex on the path resolves
    // THROUGH to the member router it leads to (the frame goes
    // straight to that member's MAC — the pseudonode forwards
    // nothing).
    let mut next_hops: BTreeMap<NeighborId, Vec<NextHop>> = BTreeMap::new();
    let mut resolved: HashMap<NeighborId, Vec<SystemId>> = HashMap::new();
    for &dest in dist.keys() {
        if dest == root || dest.is_pseudonode() {
            continue;
        }
        let hops = first_hops(dest, &parents, root, &mut resolved, &mut HashSet::new());
        let hops: Vec<NextHop> = hops
            .into_iter()
            .map(|system| NextHop {
                neighbor: system,
                address: addresses
                    .get(&NeighborId::new(system, 0))
                    .and_then(|a| a.first().copied()),
            })
            .collect();
        next_hops.insert(dest, hops);
    }

    let mut result = SpfResult {
        distances: dist.iter().map(|(&k, &v)| (k, v)).collect(),
        next_hops,
        routes: Vec::new(),
        attached: Vec::new(),
    };

    // Prefixes: wide preferred (135), else narrow (128/130), from
    // reachable router vertices.
    for (&vertex, &cost) in result.distances.iter() {
        if vertex == root || vertex.is_pseudonode() {
            continue;
        }
        let Some(lsp) = stored.get(&vertex) else {
            continue;
        };
        let hops = result.next_hops.get(&vertex).cloned().unwrap_or_default();
        if hops.is_empty() {
            continue; // reachable only via a LAN we cannot resolve
        }
        let wide: Vec<&Vec<WideIpReach>> = lsp
            .tlvs
            .iter()
            .filter_map(|t| match t {
                Tlv::ExtIpReachability(p) => Some(p),
                _ => None,
            })
            .collect();
        if !wide.is_empty() {
            for list in wide {
                for p in list {
                    if p.metric as u64 >= crate::MAX_PATH_METRIC as u64 {
                        continue;
                    }
                    result.routes.push(Route {
                        prefix: p.prefix,
                        metric: cost + p.metric as u64,
                        next_hops: hops.clone(),
                        external: false,
                        up_down: p.up_down,
                    });
                }
            }
        } else {
            for t in &lsp.tlvs {
                let (list, external): (&Vec<NarrowIpReach>, bool) = match t {
                    Tlv::IpInternalReachability(list) => (list, false),
                    Tlv::IpExternalReachability(list) => (list, true),
                    _ => continue,
                };
                for p in list {
                    let (addr, plen) = p.prefix();
                    result.routes.push(Route {
                        prefix: (addr, plen),
                        metric: cost + p.default_metric.metric() as u64,
                        next_hops: hops.clone(),
                        external,
                        // RFC 5302 §2 redefined the default-metric
                        // octet's bit 7 on TLVs 128/130 as the
                        // up/down bit (the DP-10589 I/E-style flag).
                        up_down: p.default_metric.up_down,
                    });
                }
            }
        }
    }

    // The attached-bit candidates (L1 only): reachable routers whose
    // LSP carries an ATT bit and can forward (they are L2 ISs —
    // IS type 3 on the wire).
    if level == Level::Level1 {
        let mut attached: Vec<(SystemId, u64, Vec<NextHop>)> = result
            .distances
            .iter()
            .filter(|(&vertex, _)| vertex != root && !vertex.is_pseudonode())
            .filter_map(|(&vertex, &cost)| {
                let bits = bits_by_system.get(&vertex)?;
                let hops = result.next_hops.get(&vertex)?.clone();
                if hops.is_empty() {
                    return None;
                }
                if bits.is_attached() && bits.is_type.has_level2() {
                    Some((vertex.system, cost, hops))
                } else {
                    None
                }
            })
            .collect();
        attached.sort_by_key(|(_, cost, _)| *cost);
        result.attached = attached;
    }

    result
}

/// First hops for `dest` by walking the parent DAG down to root's
/// direct neighbours. A LAN vertex whose parents include root means
/// both stations sit on that LAN — the member the path continues to
/// is itself the first hop (frames cross the LAN straight to its
/// MAC; the pseudonode only models the broadcast segment).
fn first_hops(
    dest: NeighborId,
    parents: &HashMap<NeighborId, HashSet<NeighborId>>,
    root: NeighborId,
    memo: &mut HashMap<NeighborId, Vec<SystemId>>,
    seen: &mut HashSet<NeighborId>,
) -> Vec<SystemId> {
    if let Some(cached) = memo.get(&dest) {
        return cached.clone();
    }
    if dest == root {
        return vec![];
    }
    if !seen.insert(dest) {
        return vec![]; // cycle guard (cannot happen on a DAG, belt and braces)
    }
    let Some(ps) = parents.get(&dest) else {
        seen.remove(&dest);
        return vec![];
    };
    let mut hops: Vec<SystemId> = Vec::new();
    for &p in ps {
        if p == root {
            // A direct router-to-router edge: dest itself forwards.
            hops.push(dest.system);
        } else if parents.get(&p).is_some_and(|gp| gp.contains(&root)) {
            // p is one hop from root. A LAN vertex there means dest
            // is a member of a LAN we are on — dest forwards.
            // Otherwise p is a direct neighbour and the first hop.
            if p.is_pseudonode() {
                hops.push(dest.system);
            } else {
                hops.push(p.system);
            }
        } else {
            hops.extend(first_hops(p, parents, root, memo, seen));
        }
    }
    hops.sort();
    hops.dedup();
    seen.remove(&dest);
    memo.insert(dest, hops.clone());
    hops
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pdu::{lsp as lsp_pdu, LspBits, Pdu, PduBody};
    use crate::system::{LspId, NeighborId, SystemId};
    use crate::tlv::{ExtIsNeighbor, WideIpReach, NLPID_IPV4};

    const R1: SystemId = SystemId::from_bytes([0, 0, 0, 0, 0, 1]);
    const R2: SystemId = SystemId::from_bytes([0, 0, 0, 0, 0, 2]);
    const R3: SystemId = SystemId::from_bytes([0, 0, 0, 0, 0, 3]);
    const R4: SystemId = SystemId::from_bytes([0, 0, 0, 0, 0, 4]);

    /// The router vertex of a system id.
    fn v(id: SystemId) -> NeighborId {
        NeighborId::new(id, 0)
    }

    fn neighbor(id: SystemId, metric: u32) -> ExtIsNeighbor {
        ExtIsNeighbor {
            id: NeighborId::new(id, 0),
            metric,
            sub_tlvs: vec![],
        }
    }

    /// Build a router LSP and install it: TLV 22 adjacencies + TLV
    /// 135 prefixes + TLV 132 addresses.
    fn add_router(
        db: &mut Lspdb,
        id: SystemId,
        neighbors: Vec<ExtIsNeighbor>,
        prefixes: Vec<WideIpReach>,
        address: Option<Ipv4Addr>,
        bits: LspBits,
    ) {
        let mut tlvs = vec![
            Tlv::ProtocolsSupported(vec![NLPID_IPV4]),
            Tlv::ExtIsReachability(neighbors),
            Tlv::ExtIpReachability(prefixes),
        ];
        if let Some(a) = address {
            tlvs.push(Tlv::IpInterfaceAddress(vec![a]));
        }
        let pdu = lsp_pdu(false, LspId::zero(id), 1, 1200, bits, tlvs);
        let bytes = pdu.encode();
        let decoded = Pdu::decode(&bytes).expect("encodes");
        let PduBody::Lsp(l) = decoded.body else {
            unreachable!()
        };
        let mut l = l;
        // Keep the wire checksum so the DB's confusion logic sees
        // self-consistent instances.
        let _ = &mut l;
        db.install(l, 0);
    }

    fn wide(metric: u32, addr: [u8; 4], plen: u8) -> WideIpReach {
        WideIpReach {
            metric,
            up_down: false,
            prefix: (Ipv4Addr::from(addr), plen),
            sub_tlvs: vec![],
        }
    }

    #[test]
    fn two_router_line() {
        let mut db = Lspdb::new();
        add_router(
            &mut db,
            R1,
            vec![neighbor(R2, 10)],
            vec![wide(10, [10, 1, 0, 0], 24)],
            Some(Ipv4Addr::new(10, 0, 0, 1)),
            LspBits::default(),
        );
        add_router(
            &mut db,
            R2,
            vec![neighbor(R1, 10)],
            vec![wide(5, [192, 168, 0, 0], 24)],
            Some(Ipv4Addr::new(10, 0, 0, 2)),
            LspBits::default(),
        );
        let result = run(R1, Level::Level1, &db, 0);
        assert_eq!(result.distances.get(&v(R2)), Some(&10));
        let hops = result.next_hops.get(&v(R2)).unwrap();
        assert_eq!(hops.len(), 1);
        assert_eq!(hops[0].neighbor, R2);
        assert_eq!(hops[0].address, Some(Ipv4Addr::new(10, 0, 0, 2)));
        // R2's prefix: distance 10 + prefix metric 5.
        assert!(result
            .routes
            .iter()
            .any(|r| r.prefix == (Ipv4Addr::new(192, 168, 0, 0), 24) && r.metric == 15));
    }

    /// RFC 5305 §3: a link at 2^24-1 is excluded from normal SPF.
    #[test]
    fn max_metric_link_excluded() {
        let mut db = Lspdb::new();
        add_router(
            &mut db,
            R1,
            vec![neighbor(R2, crate::MAX_LINK_METRIC), neighbor(R3, 50)],
            vec![],
            None,
            LspBits::default(),
        );
        add_router(&mut db, R2, vec![], vec![], None, LspBits::default());
        add_router(&mut db, R3, vec![], vec![], None, LspBits::default());
        let result = run(R1, Level::Level2, &db, 0);
        assert_eq!(result.distances.get(&v(R2)), None);
        assert_eq!(result.distances.get(&v(R3)), Some(&50));
    }

    /// ISO §9.8: an overloaded IS does not forward transit traffic,
    /// but its own prefixes remain reachable.
    #[test]
    fn overload_blocks_transit_not_termination() {
        let mut db = Lspdb::new();
        add_router(
            &mut db,
            R1,
            vec![neighbor(R2, 10)],
            vec![],
            None,
            LspBits::default(),
        );
        add_router(
            &mut db,
            R2,
            vec![neighbor(R3, 10)],
            vec![wide(0, [172, 16, 0, 0], 16)],
            None,
            LspBits {
                overload: true,
                ..LspBits::default()
            },
        );
        add_router(&mut db, R3, vec![], vec![], None, LspBits::default());
        let result = run(R1, Level::Level1, &db, 0);
        assert_eq!(
            result.distances.get(&v(R2)),
            Some(&10),
            "R2 itself reachable"
        );
        assert_eq!(
            result.distances.get(&v(R3)),
            None,
            "no transit through overload"
        );
        assert!(
            result
                .routes
                .iter()
                .any(|r| r.prefix == (Ipv4Addr::new(172, 16, 0, 0), 16)),
            "R2's own prefixes stay reachable"
        );
    }

    /// RFC 1195 §3.10.1: the L1 default route goes to the nearest
    /// attached L2 IS; equal-cost candidates all appear.
    #[test]
    fn attached_bit_default_candidates() {
        let mut db = Lspdb::new();
        let attached_bits = LspBits {
            attached: [true, false, false, false],
            is_type: Level::Level2,
            ..LspBits::default()
        };
        add_router(
            &mut db,
            R1,
            vec![neighbor(R2, 10), neighbor(R3, 20)],
            vec![],
            None,
            LspBits::default(),
        );
        add_router(
            &mut db,
            R2,
            vec![neighbor(R1, 10)],
            vec![],
            None,
            attached_bits,
        );
        add_router(
            &mut db,
            R3,
            vec![neighbor(R1, 20)],
            vec![],
            None,
            attached_bits,
        );
        // R4: L2 but NOT attached — not a candidate.
        add_router(
            &mut db,
            R4,
            vec![neighbor(R1, 5)],
            vec![],
            None,
            LspBits {
                is_type: Level::Level2,
                ..LspBits::default()
            },
        );
        let result = run(R1, Level::Level1, &db, 0);
        assert_eq!(result.attached.len(), 2);
        assert_eq!(result.attached[0].0, R2, "nearest first");
        assert_eq!(result.attached[0].1, 10);
        assert_eq!(result.attached[1].0, R3);
        // At L2 the attached list is not collected.
        let result = run(R1, Level::Level2, &db, 0);
        assert!(result.attached.is_empty());
    }

    /// ECMP: two equal-cost paths both appear as next hops.
    #[test]
    fn equal_cost_multi_path() {
        let mut db = Lspdb::new();
        add_router(
            &mut db,
            R1,
            vec![neighbor(R2, 10), neighbor(R3, 10)],
            vec![],
            None,
            LspBits::default(),
        );
        add_router(
            &mut db,
            R2,
            vec![neighbor(R4, 10)],
            vec![],
            None,
            LspBits::default(),
        );
        add_router(
            &mut db,
            R3,
            vec![neighbor(R4, 10)],
            vec![],
            None,
            LspBits::default(),
        );
        add_router(
            &mut db,
            R4,
            vec![],
            vec![wide(0, [10, 9, 0, 0], 16)],
            None,
            LspBits::default(),
        );
        let result = run(R1, Level::Level1, &db, 0);
        assert_eq!(result.distances.get(&v(R4)), Some(&20));
        let hops = result.next_hops.get(&v(R4)).unwrap();
        let mut neighbors: Vec<SystemId> = hops.iter().map(|h| h.neighbor).collect();
        neighbors.sort();
        assert_eq!(neighbors, vec![R2, R3]);
    }

    /// Narrow fallback: a TLV-2-only LSP is read narrow; when TLV 22
    /// exists, TLV 2 is ignored (the wide preference).
    #[test]
    fn narrow_fallback_and_wide_preference() {
        let mut db = Lspdb::new();
        // R2 advertises BOTH TLV 2 (metric 1) and TLV 22 (metric 40):
        // wide wins.
        let pdu = lsp_pdu(
            false,
            LspId::zero(R2),
            1,
            1200,
            LspBits::default(),
            vec![
                Tlv::ProtocolsSupported(vec![NLPID_IPV4]),
                Tlv::IsReachability(vec![crate::tlv::OldIsNeighbor {
                    id: NeighborId::new(R1, 0),
                    default_metric: crate::tlv::NarrowMetric {
                        flag: false,
                        up_down: false,
                        value: 1,
                    },
                    delay_metric: crate::tlv::NarrowMetric {
                        flag: true,
                        up_down: false,
                        value: 0,
                    },
                    expense_metric: crate::tlv::NarrowMetric {
                        flag: true,
                        up_down: false,
                        value: 0,
                    },
                    error_metric: crate::tlv::NarrowMetric {
                        flag: true,
                        up_down: false,
                        value: 0,
                    },
                }]),
                Tlv::ExtIsReachability(vec![neighbor(R1, 40)]),
            ],
        );
        let decoded = Pdu::decode(&pdu.encode()).unwrap();
        let PduBody::Lsp(l) = decoded.body else {
            unreachable!()
        };
        db.install(l, 0);
        add_router(
            &mut db,
            R1,
            vec![neighbor(R2, 40)],
            vec![],
            None,
            LspBits::default(),
        );
        let result = run(R1, Level::Level2, &db, 0);
        assert_eq!(
            result.distances.get(&v(R2)),
            Some(&40),
            "wide metric preferred over narrow 1"
        );

        // A TLV-2-only neighbour set: read narrow.
        let mut db2 = Lspdb::new();
        let pdu = lsp_pdu(
            false,
            LspId::zero(R2),
            1,
            1200,
            LspBits::default(),
            vec![Tlv::IsReachability(vec![crate::tlv::OldIsNeighbor {
                id: NeighborId::new(R1, 0),
                default_metric: crate::tlv::NarrowMetric {
                    flag: false,
                    up_down: false,
                    value: 7,
                },
                delay_metric: crate::tlv::NarrowMetric {
                    flag: true,
                    up_down: false,
                    value: 0,
                },
                expense_metric: crate::tlv::NarrowMetric {
                    flag: true,
                    up_down: false,
                    value: 0,
                },
                error_metric: crate::tlv::NarrowMetric {
                    flag: true,
                    up_down: false,
                    value: 0,
                },
            }])],
        );
        let decoded = Pdu::decode(&pdu.encode()).unwrap();
        let PduBody::Lsp(l) = decoded.body else {
            unreachable!()
        };
        db2.install(l, 0);
        add_router(&mut db2, R1, vec![], vec![], None, LspBits::default());
        // Rooted at R2 (its LSP carries the narrow adjacency; the
        // symmetric R1 side of a narrow link is the same shape).
        let result = run(R2, Level::Level2, &db2, 0);
        assert_eq!(result.distances.get(&v(R1)), Some(&7), "narrow fallback");
    }

    /// Purged LSPs contribute nothing (§7.3.16.4's tombstone).
    #[test]
    fn purged_lsp_excluded() {
        let mut db = Lspdb::new();
        add_router(&mut db, R1, vec![], vec![], None, LspBits::default());
        add_router(
            &mut db,
            R2,
            vec![neighbor(R1, 3)],
            vec![],
            None,
            LspBits::default(),
        );
        // Age R2's LSP into a purge.
        let purges = db.tick(1200, false);
        assert_eq!(purges.len(), 2); // both LSPs age out
        let result = run(R1, Level::Level1, &db, 1200);
        assert!(!result.distances.contains_key(&v(R2)));
    }

    /// RFC 5302's up/down bit rides the computed `Route` from both
    /// advertisement families — wide (TLV 135's control octet) and
    /// narrow (the default-metric octet's bit 7 on TLV 128/130) — so
    /// the border's re-advertisement guard can read it.
    #[test]
    fn updown_bit_propagates_to_routes() {
        // Wide: control octet 0x80|24.
        let mut db = Lspdb::new();
        add_router(
            &mut db,
            R2,
            vec![neighbor(R1, 10)],
            vec![WideIpReach {
                metric: 7,
                up_down: true,
                prefix: (Ipv4Addr::new(10, 40, 0, 0), 24),
                sub_tlvs: vec![],
            }],
            Some(Ipv4Addr::new(10, 0, 0, 2)),
            LspBits::default(),
        );
        add_router(
            &mut db,
            R1,
            vec![neighbor(R2, 10)],
            vec![],
            None,
            LspBits::default(),
        );
        let result = run(R1, Level::Level2, &db, 0);
        let route = result
            .routes
            .iter()
            .find(|r| r.prefix == (Ipv4Addr::new(10, 40, 0, 0), 24))
            .unwrap();
        assert!(route.up_down);

        // Narrow: the default-metric octet carries the bit (RFC 5302
        // §2 redefined it on TLVs 128/130).
        let mut db = Lspdb::new();
        let narrow = lsp_pdu(
            false,
            LspId::zero(R2),
            1,
            1200,
            LspBits::default(),
            vec![
                Tlv::ProtocolsSupported(vec![NLPID_IPV4]),
                Tlv::IsReachability(vec![crate::tlv::OldIsNeighbor {
                    id: NeighborId::new(R1, 0),
                    default_metric: crate::tlv::NarrowMetric {
                        flag: false,
                        up_down: false,
                        value: 10,
                    },
                    delay_metric: crate::tlv::NarrowMetric {
                        flag: true,
                        up_down: false,
                        value: 0,
                    },
                    expense_metric: crate::tlv::NarrowMetric {
                        flag: true,
                        up_down: false,
                        value: 0,
                    },
                    error_metric: crate::tlv::NarrowMetric {
                        flag: true,
                        up_down: false,
                        value: 0,
                    },
                }]),
                Tlv::IpInternalReachability(vec![crate::tlv::NarrowIpReach {
                    default_metric: crate::tlv::NarrowMetric {
                        flag: false,
                        up_down: true,
                        value: 7,
                    },
                    delay_metric: crate::tlv::NarrowMetric {
                        flag: true,
                        up_down: false,
                        value: 0,
                    },
                    expense_metric: crate::tlv::NarrowMetric {
                        flag: true,
                        up_down: false,
                        value: 0,
                    },
                    error_metric: crate::tlv::NarrowMetric {
                        flag: true,
                        up_down: false,
                        value: 0,
                    },
                    address: Ipv4Addr::new(10, 50, 0, 0),
                    mask: Ipv4Addr::new(255, 255, 255, 0),
                    external: false,
                }]),
            ],
        );
        let decoded = Pdu::decode(&narrow.encode()).unwrap();
        let PduBody::Lsp(l) = decoded.body else {
            unreachable!()
        };
        db.install(l, 0);
        add_router(
            &mut db,
            R1,
            vec![neighbor(R2, 10)],
            vec![],
            None,
            LspBits::default(),
        );
        let result = run(R1, Level::Level2, &db, 0);
        let route = result
            .routes
            .iter()
            .find(|r| r.prefix == (Ipv4Addr::new(10, 50, 0, 0), 24))
            .unwrap();
        assert!(route.up_down, "the narrow bit reaches the route");
    }

    /// The broadcast model (ISO §7.2.3): three routers on one LAN —
    /// each router LSP carries a pseudonode adjacency entry at its
    /// circuit metric; the DIS's pseudonode LSP fans out to every
    /// member (itself included, §7.3.8's "own systemID with an
    /// appended zero octet") at metric zero. Distances cross the LAN
    /// as m1 + 0 + m2; next hops resolve THROUGH the LAN vertex to
    /// the member itself; the LAN vertex is reachable but forwards
    /// nothing.
    #[test]
    fn lan_fanout_three_routers() {
        let dis = R1; // R1 is the DIS: pseudonode 1
        let lan = NeighborId::new(dis, 1);
        let mut db = Lspdb::new();
        // Router LSPs: each attaches to the LAN at metric 10.
        for (sys, addr) in [
            (R1, Ipv4Addr::new(10, 0, 0, 1)),
            (R2, Ipv4Addr::new(10, 0, 0, 2)),
            (R3, Ipv4Addr::new(10, 0, 0, 3)),
        ] {
            add_router(
                &mut db,
                sys,
                vec![ExtIsNeighbor {
                    id: lan,
                    metric: 10,
                    sub_tlvs: vec![],
                }],
                if sys == R3 {
                    vec![wide(5, [192, 168, 30, 0], 24)]
                } else {
                    vec![]
                },
                Some(addr),
                LspBits::default(),
            );
        }
        // The pseudonode LSP: links to every member at metric 0.
        let members = [R1, R2, R3].map(|m| ExtIsNeighbor {
            id: NeighborId::new(m, 0),
            metric: 0,
            sub_tlvs: vec![],
        });
        let pdu = lsp_pdu(
            false,
            LspId::new(dis, 1, 0),
            1,
            1200,
            LspBits::default(),
            vec![
                Tlv::ProtocolsSupported(vec![NLPID_IPV4]),
                Tlv::ExtIsReachability(members.to_vec()),
            ],
        );
        let decoded = Pdu::decode(&pdu.encode()).unwrap();
        let PduBody::Lsp(l) = decoded.body else {
            unreachable!()
        };
        db.install(l, 0);

        let result = run(R2, Level::Level2, &db, 0);
        // The LAN vertex is reachable at our circuit metric; each
        // member pays only ITS OWN attachment metric (the pseudonode
        // edges are zero — the per-endpoint LAN costing).
        assert_eq!(result.distances.get(&lan), Some(&10));
        assert_eq!(result.distances.get(&v(R1)), Some(&10));
        assert_eq!(result.distances.get(&v(R3)), Some(&10));
        // Next hops resolve through the LAN to the member itself (the
        // frame crosses the segment straight to its MAC).
        let hops = result.next_hops.get(&v(R3)).unwrap();
        assert_eq!(hops.len(), 1);
        assert_eq!(hops[0].neighbor, R3);
        assert_eq!(hops[0].address, Some(Ipv4Addr::new(10, 0, 0, 3)));
        // The LAN vertex itself has no forwarding entry.
        assert!(!result.next_hops.contains_key(&lan));
        // R3's prefix rides the LAN: 10 (to the LAN) + 0 + 10 (to
        // R3) + 5 (the prefix) = 25.
        let route = result
            .routes
            .iter()
            .find(|r| r.prefix == (Ipv4Addr::new(192, 168, 30, 0), 24))
            .unwrap();
        assert_eq!(route.metric, 15);
        assert_eq!(route.next_hops[0].neighbor, R3);
    }

    // ---- the brute-force oracle (the ospfd recipe) ----------------

    /// Bellman-Ford over the same edge extraction: |V|·|E| relaxations.
    /// Vertices are the full (system, pseudonode) ids — LAN vertices
    /// included, exactly like the Dijkstra under test.
    fn oracle_distances(db: &Lspdb, root: SystemId, now: u64) -> BTreeMap<NeighborId, u64> {
        let mut edges: Vec<(NeighborId, NeighborId, u64)> = Vec::new();
        let mut live: HashSet<NeighborId> = HashSet::new();
        let mut overloaded: HashSet<NeighborId> = HashSet::new();
        for record in db.stored_lsps() {
            let lsp = &record.lsp;
            if lsp.is_purge() || record.remaining_lifetime(now) == 0 {
                continue;
            }
            let vertex = NeighborId::new(lsp.id.system, lsp.id.pseudonode);
            live.insert(vertex);
            if lsp.id.pseudonode == 0 && lsp.bits.overload {
                overloaded.insert(vertex);
            }
            for e in edges_of(lsp) {
                edges.push((vertex, e.to, e.metric));
            }
        }
        let root = NeighborId::new(root, 0);
        let mut dist: BTreeMap<NeighborId, u64> = BTreeMap::new();
        dist.insert(root, 0);
        for _ in 0..=edges.len() + 1 {
            let mut changed = false;
            for &(from, to, m) in &edges {
                // Overload blocks transit (edges OUT of the
                // overloaded ROUTER), not reachability of it.
                if overloaded.contains(&from) && from != root {
                    continue;
                }
                if let Some(&d) = dist.get(&from) {
                    let nd = d + m;
                    let better = dist.get(&to).is_none_or(|&c| nd < c);
                    if better {
                        dist.insert(to, nd);
                        changed = true;
                    }
                }
            }
            if !changed {
                break;
            }
        }
        dist.retain(|k, _| live.contains(k) || k == &root);
        dist
    }

    fn random_spf_case(seed: u64) -> (Lspdb, SystemId) {
        // xorshift64*: deterministic topologies from the seed.
        let mut s = seed.wrapping_mul(2685821657736338717);
        let mut next = move || {
            s ^= s >> 12;
            s ^= s << 25;
            s ^= s >> 27;
            s.wrapping_mul(2685821657736338717)
        };
        let systems = [R1, R2, R3, R4];
        let mut db = Lspdb::new();
        // One optional broadcast segment (ISO 10589 §7.2.3): a LAN
        // vertex (the DIS's pseudonode) that a subset of routers
        // attach to, with its pseudonode LSP fanning out at metric 0.
        let lan_on = next() % 2 == 0;
        let lan = NeighborId::new(R4, 1);
        let mut lan_members: Vec<SystemId> = Vec::new();
        if lan_on {
            for &sys in &systems[..3] {
                if next() % 2 == 0 {
                    lan_members.push(sys);
                }
            }
        }
        for &sys in &systems {
            let n = (next() % 3) as usize;
            let mut neighbors = Vec::new();
            for _ in 0..n {
                let target = systems[(next() % systems.len() as u64) as usize];
                neighbors.push(neighbor(target, (next() % 30) as u32));
            }
            let lan_active = !lan_members.is_empty();
            if lan_active && (lan_members.contains(&sys) || sys == R4) {
                neighbors.push(ExtIsNeighbor {
                    id: lan,
                    metric: (next() % 20) as u32,
                    sub_tlvs: vec![],
                });
            }
            let p = (next() % 2) as usize;
            let prefixes = (0..p)
                .map(|_| wide((next() % 20) as u32, [10, 0, (next() % 256) as u8, 0], 24))
                .collect();
            let bits = if next() % 4 == 0 {
                LspBits {
                    overload: true,
                    ..LspBits::default()
                }
            } else {
                LspBits::default()
            };
            add_router(&mut db, sys, neighbors, prefixes, None, bits);
        }
        if !lan_members.is_empty() {
            // The DIS's pseudonode LSP: a link to every member (the
            // DIS itself included, §7.3.8's "own systemID with an
            // appended zero octet") at metric zero (§7.2.3).
            let members: Vec<ExtIsNeighbor> = lan_members
                .iter()
                .chain(std::iter::once(&R4))
                .map(|&m| ExtIsNeighbor {
                    id: NeighborId::new(m, 0),
                    metric: 0,
                    sub_tlvs: vec![],
                })
                .collect();
            let pdu = lsp_pdu(
                false,
                LspId::new(R4, 1, 0),
                1,
                1200,
                LspBits::default(),
                vec![
                    Tlv::ProtocolsSupported(vec![NLPID_IPV4]),
                    Tlv::ExtIsReachability(members),
                ],
            );
            let decoded = Pdu::decode(&pdu.encode()).expect("encodes");
            let PduBody::Lsp(l) = decoded.body else {
                unreachable!()
            };
            db.install(l, 0);
        }
        let root = systems[(next() % systems.len() as u64) as usize];
        (db, root)
    }

    /// Property: Dijkstra matches the Bellman-Ford oracle on random
    /// 4-router topologies, with and without a broadcast segment (the
    /// ospfd `property_distances_match_bellman_ford_oracle` shape,
    /// extended over LAN vertices).
    #[test]
    fn property_distances_match_bellman_ford_oracle() {
        for seed in 0..300u64 {
            let (db, root) = random_spf_case(seed);
            let ours = run(root, Level::Level1, &db, 0);
            let oracle = oracle_distances(&db, root, 0);
            for (node, want) in oracle.iter() {
                assert_eq!(
                    ours.distances.get(node),
                    Some(want),
                    "seed {seed}: distance to {node}"
                );
            }
            for (node, got) in ours.distances.iter() {
                if *node != NeighborId::new(root, 0) {
                    assert_eq!(
                        oracle.get(node),
                        Some(got),
                        "seed {seed}: extra reachability {node}"
                    );
                }
            }
        }
    }

    /// Property: next-hop sets only contain stations the root frames
    /// can actually reach directly — direct p2p neighbours, or
    /// members of a LAN the root sits on — and every routed prefix
    /// sits on a reachable node with metric ≥ the SPF distance (the
    /// route composition).
    #[test]
    fn property_next_hops_and_route_composition() {
        for seed in 0..300u64 {
            let (db, root) = random_spf_case(seed);
            let result = run(root, Level::Level2, &db, 0);
            // The root's own LSP: p2p edge targets are direct
            // neighbours; a LAN edge makes that LAN's members direct
            // (the pseudonode LSP lists them).
            let mut direct: HashSet<SystemId> = HashSet::new();
            let mut root_lans: HashSet<NeighborId> = HashSet::new();
            if let Some(l) = db.lsps().find(|l| l.id.system == root) {
                for e in edges_of(l) {
                    if e.to.is_pseudonode() {
                        root_lans.insert(e.to);
                    } else {
                        direct.insert(e.to.system);
                    }
                }
            }
            for l in db.lsps() {
                if root_lans.contains(&NeighborId::new(l.id.system, l.id.pseudonode)) {
                    for e in edges_of(l) {
                        if !e.to.is_pseudonode() {
                            direct.insert(e.to.system);
                        }
                    }
                }
            }
            direct.remove(&root);
            for (dest, hops) in result.next_hops.iter() {
                for hop in hops {
                    assert!(
                        direct.contains(&hop.neighbor),
                        "seed {seed}: next hop {} for {} is not a direct neighbour",
                        hop.neighbor,
                        dest
                    );
                }
            }
            for route in &result.routes {
                // When exactly one router advertises the prefix, the
                // route metric must be at least the SPF distance to
                // it (the composition cost). (With several
                // advertisers the route may belong to any of them —
                // attribution is ambiguous, so the property only
                // pins the unique case.)
                let origins: Vec<NeighborId> = db
                    .lsps()
                    .filter(|l| {
                        l.tlvs.iter().any(|t| match t {
                            Tlv::ExtIpReachability(ps) => {
                                ps.iter().any(|p| p.prefix == route.prefix)
                            }
                            _ => false,
                        })
                    })
                    .map(|l| NeighborId::new(l.id.system, l.id.pseudonode))
                    .collect();
                if let [origin] = origins.as_slice() {
                    if let Some(&d) = result.distances.get(origin) {
                        assert!(
                            route.metric >= d,
                            "seed {seed}: route metric below the SPF distance"
                        );
                    }
                }
            }
        }
    }

    /// The interop topology shape: our two-router smoke, end to end
    /// through the DB + SPF stack.
    #[test]
    fn interop_shape_two_routers() {
        let mut db = Lspdb::new();
        add_router(
            &mut db,
            R1,
            vec![neighbor(R2, 10)],
            vec![wide(10, [203, 0, 113, 0], 24)],
            Some(Ipv4Addr::new(172, 16, 0, 1)),
            LspBits::default(),
        );
        add_router(
            &mut db,
            R2,
            vec![neighbor(R1, 10)],
            vec![wide(10, [198, 51, 100, 0], 24)],
            Some(Ipv4Addr::new(172, 16, 0, 2)),
            LspBits::default(),
        );
        let result = run(R2, Level::Level1, &db, 0);
        // R2 learns 203.0.113.0/24 via R1 at 10 + 10.
        let route = result
            .routes
            .iter()
            .find(|r| r.prefix == (Ipv4Addr::new(203, 0, 113, 0), 24))
            .unwrap();
        assert_eq!(route.metric, 20);
        assert_eq!(
            route.next_hops[0].address,
            Some(Ipv4Addr::new(172, 16, 0, 1))
        );
    }
}
