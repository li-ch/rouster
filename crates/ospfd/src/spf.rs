//! The intra-area SPF (RFC 2328 §16.1) and its scheduling wrapper.
//!
//! The §16.1 two-stage method, followed to the letter:
//!
//! - **Stage one** builds the shortest-path tree over *transit*
//!   vertices only (routers and transit networks), with the modified
//!   Dijkstra the RFC prescribes: links must be bidirectional (step
//!   2b's "has a link back to vertex V" check — a missing, MaxAge or
//!   one-way LSA drops the edge), equal-cost candidates *accumulate*
//!   next hops (step 2d), and when several candidates are equally
//!   close, **network vertices are chosen before router vertices**
//!   (step 3 — required to find all equal-cost paths). A router-LSA
//!   V-bit sets the area's `TransitCapability` (step 2).
//! - **Stage two** walks every reachable router's stub links
//!   (§16.1's second stage): distance = distance-to-router + stub
//!   cost, with equal-cost next-hop accumulation and the
//!   larger-Link-State-ID origin tiebreak.
//! - **Next hops** follow §16.1.1: destinations behind at least one
//!   intervening router inherit the parent's hops; a destination
//!   whose parent is the root gets the root's own outgoing interface
//!   (the p2p/transit link's Link Data); a router whose parent is a
//!   network the root sits on takes its next-hop *address* from the
//!   destination router-LSA's Link Data on the links pointing back
//!   at that network.
//!
//! Incremental SPF (§16.5/§16.6) is §Deferred — v1 always recomputes
//! from scratch, which §16.1's closing note explicitly permits ("The
//! specification does not require that the above two stage method be
//! used... However... an identical tree must be produced").
//!
//! The scheduling wrapper ([`SpfScheduler`]) is pure and
//! clock-injected: it coalesces change notifications and applies an
//! FRR-parity throttle (`timers throttle spf 0ms/50ms/5000ms`, the
//! RFC is silent on values) so a flap storm cannot re-run Dijkstra
//! back-to-back. The RFC's own words for why: §16 step (1) rebuilds
//! from scratch, so the wrapper is where the cost of that lands.

use std::collections::HashMap;
use std::net::Ipv4Addr;

use crate::lsa::{LinkStateId, LinkType, LsaBody, LsaKey, LsaType, RouterId, RouterLsa};
use crate::lsdb::Lsdb;

/// A graph vertex: a router or a transit network (the DR's address).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Vertex {
    Router(RouterId),
    Network(u32),
}

impl Vertex {
    /// Step 3's tiebreak: network vertices sort before router
    /// vertices at equal distance.
    fn kind_rank(&self) -> u8 {
        match self {
            Self::Network(_) => 0,
            Self::Router(_) => 1,
        }
    }
}

/// One next hop (§16.1.1): an outgoing root interface address plus,
/// when the destination is behind another router, that router's
/// address on the path.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct NextHop {
    /// The calculating router's own interface address toward the
    /// parent vertex (the root's Link Data on its p2p/transit link).
    pub interface: Ipv4Addr,
    /// The next-hop router's address, when one intervenes (None for
    /// directly connected destinations and p2p neighbors).
    pub router: Option<Ipv4Addr>,
}

/// A computed route (the §11 entry shape, intra-area subset).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Route {
    pub destination: Destination,
    /// Link state cost of the path.
    pub cost: u32,
    /// Equal-cost multipath set (§16.1 step 2d / §16.8).
    pub next_hops: Vec<NextHop>,
    /// The LSA the route was derived from (§11's Link State Origin).
    pub origin: LsaKey,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Destination {
    /// An IP prefix (transit network, stub network).
    Network { addr: Ipv4Addr, mask: Ipv4Addr },
    /// A router destination (ABR/ASBR paths, §16.1 step 4).
    Router(RouterId),
}

impl Destination {
    pub fn prefix_str(&self) -> String {
        match self {
            Self::Network { addr, mask } => format!("{}/{}", addr, mask_prefix(*mask)),
            Self::Router(r) => r.to_string(),
        }
    }
}

fn mask_prefix(mask: Ipv4Addr) -> u8 {
    u32::from(mask).count_ones() as u8
}

/// One router-LSA's capability bits (§A.4.2 + RFC 3101 Appendix B's
/// Nt) — the ABR/ASBR classification §12.4.3/§16.4 and the NSSA
/// translator election §3.1 read.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct RouterFlags {
    pub b: bool,
    pub e: bool,
    /// The NSSA translator bit (RFC 3101 §3.1 — meaningful in the
    /// NSSA's own copy of the router-LSA).
    pub nt: bool,
}

/// The result of one area calculation.
#[derive(Debug, Clone, Default)]
pub struct SpfResult {
    /// §16.1 step 2: TRUE when any router-LSA on the tree has the
    /// V-bit set (a virtual link uses this area as transit).
    pub transit_capability: bool,
    /// Every seen router-LSA's B/E/Nt flags — present whether or not
    /// the router ended up on the tree.
    pub router_flags: HashMap<RouterId, RouterFlags>,
    /// Distance to every reachable transit vertex.
    pub distances: HashMap<Vertex, u32>,
    /// The intra-area routes, deterministically ordered.
    pub routes: Vec<Route>,
}

/// A finalized tree vertex plus its §16.1.1 next-hop state.
///
/// §16.1.1 is a *per-path* rule, so a vertex carries two hop sets:
/// - `route_hops`: the vertex's own next hops (what its routing table
///   entry uses);
/// - `hops`: what children inherit ("the destination simply inherits
///   the set of next hops from the parent"). For routers these are
///   the same. For a network the root itself sits on, `route_hops`
///   is the root's interface (no next-hop router — the network is
///   the destination) while `hops` starts empty: an intervening
///   router exists on no path yet, and the root's attach hop alone is
///   not a valid inherited next hop for a router beyond. Equal-cost
///   merges of through-router paths append to `hops`.
#[derive(Debug, Clone)]
struct TreeEntry {
    distance: u32,
    route_hops: Vec<NextHop>,
    hops: Vec<NextHop>,
    /// The root's own interface address when the root is directly
    /// attached to this network (§16.1.1's "network that directly
    /// connects the calculating router" case).
    root_if: Option<Ipv4Addr>,
}

/// A pending candidate (the §16.1 candidate list entry).
#[derive(Debug, Clone)]
struct Cand {
    distance: u32,
    /// The vertex's own §16.1.1 next hops so far.
    route_hops: Vec<NextHop>,
    /// What children of this vertex would inherit.
    hops: Vec<NextHop>,
    /// Root's interface, when the root is directly attached (networks).
    root_if: Option<Ipv4Addr>,
    /// Insertion sequence — the FIFO tiebreak among equal candidates.
    seq: u64,
}

/// Run the §16.1 calculation for one area, rooted at `root`.
pub fn calculate(root: RouterId, lsdb: &Lsdb) -> SpfResult {
    // Index the transit LSAs: router-LSAs by RouterId, network-LSAs
    // by their Link State ID (the DR address). §16's opening: MaxAge
    // LSAs are treated as absent.
    let mut router_lsas: HashMap<RouterId, &RouterLsa> = HashMap::new();
    let mut network_lsas: HashMap<u32, (Ipv4Addr, Vec<RouterId>)> = HashMap::new();
    let mut router_flags: HashMap<RouterId, RouterFlags> = HashMap::new();
    for entry in lsdb.all() {
        if entry.lsa.header.is_max_age() {
            continue;
        }
        match &entry.lsa.body {
            LsaBody::Router(r) => {
                router_flags.insert(
                    entry.lsa.header.adv_router,
                    RouterFlags {
                        b: r.b_bit,
                        e: r.e_bit,
                        nt: r.nt_bit,
                    },
                );
                router_lsas.insert(entry.lsa.header.adv_router, r);
            }
            LsaBody::Network(n) => {
                network_lsas.insert(
                    entry.lsa.header.link_state_id.0,
                    (n.mask, n.attached.clone()),
                );
            }
            _ => {}
        }
    }

    let mut result = SpfResult {
        router_flags,
        ..SpfResult::default()
    };
    let mut tree: HashMap<Vertex, TreeEntry> = HashMap::new();
    // The root's own LSA may be absent (a router with no links yet);
    // the tree still starts at the root with distance 0.
    tree.insert(
        Vertex::Router(root),
        TreeEntry {
            distance: 0,
            route_hops: vec![],
            hops: vec![],
            root_if: None,
        },
    );

    // Candidate list: vertex -> (distance, route_hops, inheritable
    // hops, root_if, insertion sequence). Pop order is (distance,
    // network-before-router, insertion) — FRR's non-unique skiplist
    // pops equal keys FIFO, and that insertion order is what lets
    // late relaxations merge equal-cost hops into still-pending
    // candidates.
    let mut candidates: HashMap<Vertex, Cand> = HashMap::new();
    let mut insert_seq: u64 = 0;

    // Step 2 lifted into a closure so the root's own links get
    // examined before the first candidate exists (§16.1 step 1
    // initializes the tree to "only the root"; step 2 applies to the
    // vertex "just added", root included).
    let expand = |v: Vertex,
                  tree: &mut HashMap<Vertex, TreeEntry>,
                  result: &mut SpfResult,
                  candidates: &mut HashMap<Vertex, Cand>,
                  insert_seq: &mut u64| {
        match v {
            Vertex::Router(rid) => {
                let Some(lsa) = router_lsas.get(&rid) else {
                    return;
                };
                if lsa.v_bit {
                    result.transit_capability = true;
                }
                for link in &lsa.links {
                    let w = match link.link_type {
                        // (a) stub networks wait for stage two.
                        LinkType::Stub => continue,
                        // Type 1/4: the link ID is the neighboring
                        // router's ID.
                        LinkType::PointToPoint | LinkType::Virtual => {
                            Vertex::Router(RouterId(link.link_id.0))
                        }
                        // Type 2: the link ID is the DR's address.
                        LinkType::Transit => Vertex::Network(link.link_id.0),
                    };
                    relax(
                        &v,
                        &w,
                        link.metric as u32,
                        &link.link_data,
                        root,
                        &router_lsas,
                        &network_lsas,
                        tree,
                        candidates,
                        insert_seq,
                    );
                }
            }
            Vertex::Network(net) => {
                let Some((_, attached)) = network_lsas.get(&net) else {
                    return;
                };
                // §A.4.3: the distance from the network to all
                // attached routers is zero — the router→network link
                // metrics carry the cost.
                for rid in attached {
                    relax(
                        &v,
                        &Vertex::Router(*rid),
                        0,
                        &0,
                        root,
                        &router_lsas,
                        &network_lsas,
                        tree,
                        candidates,
                        insert_seq,
                    );
                }
            }
        }
    };

    // Step 1-2 for the root itself.
    result.distances.insert(Vertex::Router(root), 0);
    expand(
        Vertex::Router(root),
        &mut tree,
        &mut result,
        &mut candidates,
        &mut insert_seq,
    );

    loop {
        // Step 3: the closest candidate; networks before routers at
        // equal distance (the equal-cost-path requirement).
        let pick = candidates
            .iter()
            .filter(|(v, _)| !tree.contains_key(v))
            .min_by_key(|(v, c)| (c.distance, v.kind_rank(), c.seq))
            .map(|(v, c)| (*v, c.clone()));
        let (v, cand) = match pick {
            None => break,
            Some(x) => x,
        };
        tree.insert(
            v,
            TreeEntry {
                distance: cand.distance,
                route_hops: cand.route_hops.clone(),
                hops: cand.hops.clone(),
                root_if: cand.root_if,
            },
        );
        result.distances.insert(v, cand.distance);
        candidates.remove(&v);

        // Step 2: examine the LSA of the vertex just added.
        expand(v, &mut tree, &mut result, &mut candidates, &mut insert_seq);
    }

    // Step 4: routing table entries for the transit vertices, in tree
    // order (already deterministic via the pick order); we emit at the
    // end from `tree` sorted for stable output.
    let mut order: Vec<(&Vertex, &TreeEntry)> = tree.iter().collect();
    order.sort_by_key(|(v, e)| (e.distance, v.kind_rank(), vertex_id(**v)));
    for (v, entry) in order {
        match v {
            Vertex::Router(rid) => {
                if *rid == root {
                    continue;
                }
                // §16.1 step 4: router destinations (ABR/ASBR paths).
                result.routes.push(Route {
                    destination: Destination::Router(*rid),
                    cost: entry.distance,
                    next_hops: dedup_hops(entry.route_hops.clone()),
                    origin: LsaKey {
                        ls_type: LsaType::ROUTER,
                        link_state_id: LinkStateId(rid.0),
                        adv_router: *rid,
                    },
                });
            }
            Vertex::Network(net) => {
                let Some((mask, _)) = network_lsas.get(net) else {
                    continue;
                };
                let addr = Ipv4Addr::from(*net);
                // The entry's Destination ID masks the Vertex ID with
                // the network-LSA's mask.
                let masked = Ipv4Addr::from(u32::from(addr) & u32::from(*mask));
                result.routes.push(Route {
                    destination: Destination::Network {
                        addr: masked,
                        mask: *mask,
                    },
                    cost: entry.distance,
                    next_hops: dedup_hops(entry.route_hops.clone()),
                    origin: LsaKey {
                        ls_type: LsaType::NETWORK,
                        link_state_id: LinkStateId(*net),
                        adv_router: RouterId(*net),
                    },
                });
            }
        }
    }

    // Stage two: the stub networks, per reachable router vertex.
    // Deterministic router order (smallest ID first) keeps the
    // equal-cost accumulation order stable.
    let mut routers: Vec<(RouterId, u32, Vec<NextHop>)> = tree
        .iter()
        .filter_map(|(v, e)| match v {
            Vertex::Router(r) if *r != root => Some((*r, e.distance, e.hops.clone())),
            _ => None,
        })
        .collect();
    routers.sort_by_key(|(r, _, _)| r.0);

    // Best-known stub route bookkeeping: prefix -> (cost, hops,
    // origin LS ID).
    let mut stub_best: HashMap<(u32, u32), (u32, Vec<NextHop>, u32)> = HashMap::new();
    for (rid, router_dist, router_hops) in routers {
        let Some(lsa) = router_lsas.get(&rid) else {
            continue;
        };
        for link in &lsa.links {
            if link.link_type != LinkType::Stub {
                continue;
            }
            // (1) D = distance(root→router) + stub metric.
            let d = router_dist + link.metric as u32;
            let prefix = (link.link_id.0, link.link_data);
            match stub_best.get_mut(&prefix) {
                Some(best) if best.0 < d => continue, // larger: skip
                Some(best) if best.0 == d => {
                    // (2) equal: add the hop set; the origin becomes
                    // the larger Link State ID.
                    best.1.extend(router_hops.iter().copied());
                    if best.2 < rid.0 {
                        best.2 = rid.0;
                    }
                }
                Some(best) => {
                    // smaller: overwrite.
                    *best = (d, router_hops.clone(), rid.0);
                }
                None => {
                    stub_best.insert(prefix, (d, router_hops.clone(), rid.0));
                }
            }
        }
        // The root's own stub links use §16.1.1's first case: the
        // outgoing interface is the root's own (correlated below).
    }
    // The root's stub networks: distance = stub metric, next hop =
    // the root interface (Link Data of a root p2p link on the same
    // subnet; the stub record itself carries the mask, not an
    // address — documented correlation, §16.1.1 first case).
    if let Some(root_lsa) = router_lsas.get(&root) {
        let root_ifaddrs: Vec<u32> = root_lsa
            .links
            .iter()
            .filter(|l| matches!(l.link_type, LinkType::PointToPoint | LinkType::Transit))
            .map(|l| l.link_data)
            .collect();
        for link in &root_lsa.links {
            if link.link_type != LinkType::Stub {
                continue;
            }
            let d = link.metric as u32;
            let prefix = (link.link_id.0, link.link_data);
            match stub_best.get_mut(&prefix) {
                Some(best) if best.0 < d => continue,
                Some(best) if best.0 == d => {}
                Some(best) => *best = (d, vec![], root.0),
                None => {
                    stub_best.insert(prefix, (d, vec![], root.0));
                }
            }
            // Correlate: a root transit/p2p interface inside the stub
            // prefix identifies the outgoing interface.
            let ifaddr = root_ifaddrs
                .iter()
                .find(|a| **a & link.link_data == link.link_id.0);
            if let Some(&a) = ifaddr {
                if let Some(best) = stub_best.get_mut(&prefix) {
                    best.1 = vec![NextHop {
                        interface: Ipv4Addr::from(a),
                        router: None,
                    }];
                }
            }
        }
    }
    for ((net, mask), (cost, hops, origin)) in stub_best {
        result.routes.push(Route {
            destination: Destination::Network {
                addr: Ipv4Addr::from(net),
                mask: Ipv4Addr::from(mask),
            },
            cost,
            next_hops: dedup_hops(hops),
            origin: LsaKey {
                ls_type: LsaType::ROUTER,
                link_state_id: LinkStateId(origin),
                adv_router: RouterId(origin),
            },
        });
    }

    // Stable final order: routers first (by ID), then networks by
    // prefix — goldens depend on it.
    result
        .routes
        .sort_by(|a, b| match (&a.destination, &b.destination) {
            (Destination::Router(x), Destination::Router(y)) => x.0.cmp(&y.0),
            (Destination::Router(_), Destination::Network { .. }) => std::cmp::Ordering::Less,
            (Destination::Network { .. }, Destination::Router(_)) => std::cmp::Ordering::Greater,
            (
                Destination::Network { addr: x, mask: mx },
                Destination::Network { addr: y, mask: my },
            ) => (u32::from(*x), u32::from(*mx)).cmp(&(u32::from(*y), u32::from(*my))),
        });
    result
}

fn vertex_id(v: Vertex) -> u32 {
    match v {
        Vertex::Router(r) => r.0,
        Vertex::Network(n) => n,
    }
}

/// §16.1 step 2b/2c/2d for one (V → W) edge, computing the §16.1.1
/// hop sets for the (V, W) link.
#[allow(clippy::too_many_arguments)]
fn relax(
    v: &Vertex,
    w: &Vertex,
    cost: u32,
    link_data: &u32,
    root: RouterId,
    router_lsas: &HashMap<RouterId, &RouterLsa>,
    network_lsas: &HashMap<u32, (Ipv4Addr, Vec<RouterId>)>,
    tree: &HashMap<Vertex, TreeEntry>,
    candidates: &mut HashMap<Vertex, Cand>,
    insert_seq: &mut u64,
) {
    // (b) W's LSA must exist and have a link back to V.
    let backlink = match (*v, *w) {
        (Vertex::Router(a), Vertex::Router(b)) => router_lsas.get(&b).is_some_and(|lsa| {
            lsa.links.iter().any(|l| {
                matches!(l.link_type, LinkType::PointToPoint | LinkType::Virtual)
                    && l.link_id.0 == a.0
            })
        }),
        (Vertex::Router(a), Vertex::Network(_)) => network_lsas
            .get(&vertex_id(*w))
            .is_some_and(|(_, att)| att.contains(&a)),
        (Vertex::Network(_), Vertex::Router(b)) => router_lsas.get(&b).is_some_and(|lsa| {
            lsa.links
                .iter()
                .any(|l| l.link_type == LinkType::Transit && l.link_id.0 == vertex_id(*v))
        }),
        (Vertex::Network(_), Vertex::Network(_)) => false,
    };
    if !backlink {
        return;
    }
    // (c) already on the tree: skip (FRR-pinned §16.1 step (c)).
    if tree.contains_key(w) {
        return;
    }
    let v_entry = &tree[v];
    let d = v_entry.distance + cost;

    // §16.1.1 next-hop computation for the (V, W) link.
    let (route_hops, hops, root_if): (Vec<NextHop>, Vec<NextHop>, Option<Ipv4Addr>) = match v {
        // Parent is the root.
        Vertex::Router(r) if *r == root => {
            let h = vec![NextHop {
                interface: Ipv4Addr::from(*link_data),
                router: None,
            }];
            // A p2p neighbor destination needs no next-hop address;
            // children inherit the same hop (§16.1.1 case one).
            match w {
                Vertex::Router(_) => (h.clone(), h, None),
                // The network is the destination; children derive
                // their own hops per case two.
                Vertex::Network(_) => (h, vec![], Some(Ipv4Addr::from(*link_data))),
            }
        }
        // Parent is a router other than the root: W inherits (there
        // is at least one intervening router on every such path).
        Vertex::Router(_) => (v_entry.hops.clone(), v_entry.hops.clone(), None),
        // Parent is a network.
        Vertex::Network(net) => {
            let mut route = Vec::new();
            if let Some(rif) = v_entry.root_if {
                // §16.1.1 case two: the network directly connects the
                // root to the destination router — each of W's links
                // pointing back at the network yields a next-hop
                // address (W's Link Data on it), out the root's own
                // interface on that network.
                if let Some(lsa) = router_lsas.get(&RouterId(vertex_id(*w))) {
                    for l in &lsa.links {
                        if l.link_type == LinkType::Transit && l.link_id.0 == *net {
                            route.push(NextHop {
                                interface: rif,
                                router: Some(Ipv4Addr::from(l.link_data)),
                            });
                        }
                    }
                }
            }
            // Paths through other routers onto this network: inherit
            // the network's accumulated hop set (§16.1.1 case one).
            let mut inherit = v_entry.hops.clone();
            route.append(&mut inherit);
            (route.clone(), route, None)
        }
    };

    match candidates.get_mut(w) {
        // Greater than the candidate distance: examine the next link.
        Some(c) if c.distance < d => {}
        // Equal: add this link's hops to the candidate's sets
        // (§16.1 step 2d's second bullet).
        Some(c) if c.distance == d => {
            c.route_hops.extend(route_hops);
            c.hops.extend(hops);
        }
        // Less: reset the candidate, keeping its queue slot.
        Some(c) => {
            c.distance = d;
            c.route_hops = route_hops;
            c.hops = hops;
            c.root_if = root_if;
        }
        // New candidate.
        None => {
            *insert_seq += 1;
            candidates.insert(
                *w,
                Cand {
                    distance: d,
                    route_hops,
                    hops,
                    root_if,
                    seq: *insert_seq,
                },
            );
        }
    }
}

fn dedup_hops(mut hops: Vec<NextHop>) -> Vec<NextHop> {
    hops.sort();
    hops.dedup();
    hops
}

/// The pure SPF throttle/scheduler (clock-injected). FRR-parity
/// defaults: initial delay 0, increment 50 ms, maximum 5 s
/// (`timers throttle spf`); RFC 2328 is silent on scheduling values.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SpfScheduler {
    /// First scheduling delay after an idle period.
    pub initial_delay_ms: u64,
    /// Multiplier-style increment between back-to-back runs.
    pub increment_ms: u64,
    /// Ceiling of the backoff.
    pub max_delay_ms: u64,
    last_run: Option<u64>,
    next_due: Option<u64>,
    current_delay_ms: u64,
}

impl Default for SpfScheduler {
    fn default() -> Self {
        Self {
            initial_delay_ms: 0,
            increment_ms: 50,
            max_delay_ms: 5000,
            last_run: None,
            next_due: None,
            current_delay_ms: 0,
        }
    }
}

impl SpfScheduler {
    pub fn new(initial_ms: u64, increment_ms: u64, max_ms: u64) -> Self {
        Self {
            initial_delay_ms: initial_ms,
            increment_ms,
            max_delay_ms: max_ms,
            ..Self::default()
        }
    }

    /// A topology change arrived at `now` (ms). Returns the (possibly
    /// unchanged) due time. Repeated changes inside a backoff window
    /// push the run out along the increment schedule, capped at the
    /// maximum — never earlier than an already-set due time. A change
    /// arriving after a quiet period of at least the max delay starts
    /// a fresh cycle at the initial delay.
    pub fn on_change(&mut self, now_ms: u64) -> Option<u64> {
        let idle = self
            .last_run
            .is_some_and(|t| now_ms.saturating_sub(t) >= self.max_delay_ms);
        let delay = if self.last_run.is_none() || idle {
            self.current_delay_ms = 0;
            self.initial_delay_ms
        } else {
            self.current_delay_ms
                .saturating_add(self.increment_ms)
                .min(self.max_delay_ms)
                .max(self.initial_delay_ms)
        };
        self.current_delay_ms = delay;
        let proposed = now_ms.saturating_add(delay);
        self.next_due = Some(match self.next_due {
            Some(due) => due.max(proposed),
            None => proposed,
        });
        self.next_due
    }

    /// When a run is currently scheduled.
    pub fn due_at(&self) -> Option<u64> {
        self.next_due
    }

    /// Whether a run is due at `now`.
    pub fn is_due(&self, now_ms: u64) -> bool {
        self.next_due.is_some_and(|d| now_ms >= d)
    }

    /// Record the run: clears the schedule and starts the next
    /// backoff step.
    pub fn mark_run(&mut self, now_ms: u64) {
        self.last_run = Some(now_ms);
        self.next_due = None;
    }

    /// Idle reset (all change sources quiescent): the next burst
    /// starts over at the initial delay.
    pub fn reset_backoff(&mut self) {
        self.current_delay_ms = 0;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::lsa::{LinkStateId, Lsa, LsaHeader, NetworkLsa, Options, RouterLink};
    use crate::lsdb::{InstallOutcome, Lsdb};
    use std::net::Ipv4Addr;

    fn ip(s: &str) -> Ipv4Addr {
        s.parse().unwrap()
    }

    /// Build and install a router-LSA for `rid` with the given links.
    fn router(rid: &str, links: Vec<RouterLink>, v_bit: bool) -> Lsa {
        Lsa {
            header: LsaHeader {
                ls_age: 1,
                options: Options(0x02),
                ls_type: LsaType::ROUTER,
                link_state_id: LinkStateId(u32::from(ip(rid))),
                adv_router: RouterId(u32::from(ip(rid))),
                seq: 0x8000_0001,
                checksum: 0x1234,
                length: 0,
            },
            body: LsaBody::Router(RouterLsa {
                v_bit,
                e_bit: false,
                b_bit: false,
                nt_bit: false,
                links,
            }),
        }
    }

    fn network(dr: &str, mask: &str, attached: &[&str]) -> Lsa {
        Lsa {
            header: LsaHeader {
                ls_age: 1,
                options: Options(0x02),
                ls_type: LsaType::NETWORK,
                link_state_id: LinkStateId(u32::from(ip(dr))),
                adv_router: RouterId(u32::from(ip(dr))),
                seq: 0x8000_0001,
                checksum: 0x1234,
                length: 0,
            },
            body: LsaBody::Network(NetworkLsa {
                mask: ip(mask),
                attached: attached
                    .iter()
                    .map(|r| RouterId(u32::from(ip(r))))
                    .collect(),
            }),
        }
    }

    /// A type-2 link to a transit network (Link Data = ifaddr).
    fn to_net(dr: &str, ifaddr: &str, metric: u16) -> RouterLink {
        RouterLink {
            link_id: LinkStateId(u32::from(ip(dr))),
            link_data: u32::from(ip(ifaddr)),
            link_type: LinkType::Transit,
            metric,
            tos: vec![],
        }
    }

    /// A type-1 link to a neighboring router.
    fn to_rtr(peer: &str, ifaddr: &str, metric: u16) -> RouterLink {
        RouterLink {
            link_id: LinkStateId(u32::from(ip(peer))),
            link_data: u32::from(ip(ifaddr)),
            link_type: LinkType::PointToPoint,
            metric,
            tos: vec![],
        }
    }

    /// A type-3 stub link (Link Data = mask).
    fn stub(subnet: &str, mask: &str, metric: u16) -> RouterLink {
        RouterLink {
            link_id: LinkStateId(u32::from(ip(subnet))),
            link_data: u32::from(ip(mask)),
            link_type: LinkType::Stub,
            metric,
            tos: vec![],
        }
    }

    fn install_all(db: &mut Lsdb, lsas: Vec<Lsa>) {
        for l in lsas {
            assert_eq!(
                db.install(l, true, 0),
                InstallOutcome::Installed { changed: true }
            );
        }
    }

    fn route_for<'a>(res: &'a SpfResult, dest: &Destination) -> &'a Route {
        res.routes
            .iter()
            .find(|r| &r.destination == dest)
            .unwrap_or_else(|| panic!("no route for {:?}", dest.prefix_str()))
    }

    fn nh(iface: &str, rtr: Option<&str>) -> NextHop {
        NextHop {
            interface: ip(iface),
            router: rtr.map(ip),
        }
    }

    // ---- golden shapes -------------------------------------------

    #[test]
    fn router_flags_report_the_b_and_e_bits() {
        // §A.4.2: the router-LSA flags surface for every seen router
        // (the §12.4.3/§16.4 ABR/ASBR classification input).
        let own = RouterId(u32::from(ip("1.1.1.1")));
        let mut lsdb = Lsdb::new();
        // Two p2p neighbors back-linking to us.
        let links = vec![RouterLink {
            link_id: LinkStateId(u32::from(ip("1.1.1.1"))),
            link_data: u32::from(ip("10.0.0.2")),
            link_type: LinkType::PointToPoint,
            metric: 5,
            tos: vec![],
        }];
        let mut abr = router("2.2.2.2", links.clone(), false);
        if let LsaBody::Router(r) = &mut abr.body {
            r.b_bit = true;
        }
        let mut asbr = router("3.3.3.3", links, false);
        if let LsaBody::Router(r) = &mut asbr.body {
            r.e_bit = true;
        }
        let _ = lsdb.install(abr.with_computed_header(), true, 0);
        let _ = lsdb.install(asbr.with_computed_header(), true, 0);
        // Our own LSA with links back to both (bidirectionality).
        let own_links = vec![
            RouterLink {
                link_id: LinkStateId(u32::from(ip("2.2.2.2"))),
                link_data: u32::from(ip("10.0.0.1")),
                link_type: LinkType::PointToPoint,
                metric: 5,
                tos: vec![],
            },
            RouterLink {
                link_id: LinkStateId(u32::from(ip("3.3.3.3"))),
                link_data: u32::from(ip("10.0.0.1")),
                link_type: LinkType::PointToPoint,
                metric: 5,
                tos: vec![],
            },
        ];
        let own_lsa = router("1.1.1.1", own_links, false);
        let _ = lsdb.install(own_lsa.with_computed_header(), true, 0);
        let result = calculate(own, &lsdb);
        assert_eq!(
            result.router_flags.get(&RouterId(u32::from(ip("2.2.2.2")))),
            Some(&RouterFlags {
                b: true,
                e: false,
                nt: false
            }),
            "the ABR's B-bit"
        );
        assert_eq!(
            result.router_flags.get(&RouterId(u32::from(ip("3.3.3.3")))),
            Some(&RouterFlags {
                b: false,
                e: true,
                nt: false
            }),
            "the ASBR's E-bit"
        );
    }

    #[test]
    fn two_routers_point_to_point() {
        // The classic two-node shape: RT1 --10-- RT2 over a /30,
        // each side advertising the p2p link plus a stub for the /30.
        let mut db = Lsdb::new();
        install_all(
            &mut db,
            vec![
                router(
                    "1.1.1.1",
                    vec![
                        to_rtr("2.2.2.2", "10.0.0.1", 10),
                        stub("10.0.0.0", "255.255.255.252", 10),
                    ],
                    false,
                ),
                router(
                    "2.2.2.2",
                    vec![
                        to_rtr("1.1.1.1", "10.0.0.2", 10),
                        stub("10.0.0.0", "255.255.255.252", 10),
                    ],
                    false,
                ),
            ],
        );
        let res = calculate(RouterId(u32::from(ip("1.1.1.1"))), &db);
        assert!(!res.transit_capability);
        // Router destination 2.2.2.2 at cost 10, no next-hop address
        // (§16.1.1: p2p neighbor needs none).
        let r = route_for(
            &res,
            &Destination::Router(RouterId(u32::from(ip("2.2.2.2")))),
        );
        assert_eq!(r.cost, 10);
        assert_eq!(r.next_hops, vec![nh("10.0.0.1", None)]);
        // The /30 stub, reachable both ways at cost 10: equal-cost
        // accumulation — but the next hops dedup to one interface.
        let r = route_for(
            &res,
            &Destination::Network {
                addr: ip("10.0.0.0"),
                mask: ip("255.255.255.252"),
            },
        );
        assert_eq!(r.cost, 10);
        assert_eq!(r.next_hops, vec![nh("10.0.0.1", None)]);
    }

    #[test]
    fn three_routers_on_a_broadcast_network() {
        // The classic pseudo-node shape: DR 10.1.1.1 (=RT1) with RT2,
        // RT3 attached; costs 1, 5 from RT1; RT2--RT3 via the net.
        let mut db = Lsdb::new();
        install_all(
            &mut db,
            vec![
                router(
                    "1.1.1.1",
                    vec![
                        to_net("10.1.1.1", "10.1.1.1", 1),
                        stub("192.168.1.0", "255.255.255.0", 1),
                    ],
                    false,
                ),
                router(
                    "2.2.2.2",
                    vec![
                        to_net("10.1.1.1", "10.1.1.2", 5),
                        stub("192.168.2.0", "255.255.255.0", 1),
                    ],
                    false,
                ),
                router("3.3.3.3", vec![to_net("10.1.1.1", "10.1.1.3", 2)], false),
                network(
                    "10.1.1.1",
                    "255.255.255.0",
                    &["1.1.1.1", "2.2.2.2", "3.3.3.3"],
                ),
            ],
        );
        let res = calculate(RouterId(u32::from(ip("1.1.1.1"))), &db);
        // Transit network at cost 1 with no next-hop router (root is
        // the DR sitting on it).
        let net_route = route_for(
            &res,
            &Destination::Network {
                addr: ip("10.1.1.0"),
                mask: ip("255.255.255.0"),
            },
        );
        assert_eq!(net_route.cost, 1);
        assert_eq!(net_route.next_hops, vec![nh("10.1.1.1", None)]);
        // RT2 and RT3: §A.4.3 — the network→router edge costs zero,
        // so each attached router is at exactly the root's net cost
        // (each router pays its OWN outgoing metric only; RT2's 5 and
        // RT3's 2 count for traffic leaving THEM). Next hops are the
        // routers' own addresses on the net (§16.1.1's network case).
        let r2 = route_for(
            &res,
            &Destination::Router(RouterId(u32::from(ip("2.2.2.2")))),
        );
        assert_eq!(r2.cost, 1);
        assert_eq!(r2.next_hops, vec![nh("10.1.1.1", Some("10.1.1.2"))]);
        let r3 = route_for(
            &res,
            &Destination::Router(RouterId(u32::from(ip("3.3.3.3")))),
        );
        assert_eq!(r3.cost, 1);
        assert_eq!(r3.next_hops, vec![nh("10.1.1.1", Some("10.1.1.3"))]);
        // RT3's stub at 3+1 via RT3.
        // (not advertised in this shape)
        // RT2's stub network at 1+1 via RT2's next hop.
        let s2 = route_for(
            &res,
            &Destination::Network {
                addr: ip("192.168.2.0"),
                mask: ip("255.255.255.0"),
            },
        );
        assert_eq!(s2.cost, 2);
        assert_eq!(s2.next_hops, vec![nh("10.1.1.1", Some("10.1.1.2"))]);
    }

    #[test]
    fn equal_cost_paths_accumulate() {
        // Square: RT1 -1- RT2 -1- RT4 and RT1 -1- RT3 -1- RT4:
        // RT4 at cost 2 through BOTH next hops (§16.1 step 2d,
        // §16.8 equal-cost multipath).
        let mut db = Lsdb::new();
        install_all(
            &mut db,
            vec![
                router(
                    "1.1.1.1",
                    vec![
                        to_rtr("2.2.2.2", "10.0.0.1", 1),
                        to_rtr("3.3.3.3", "10.0.1.1", 1),
                    ],
                    false,
                ),
                router(
                    "2.2.2.2",
                    vec![
                        to_rtr("1.1.1.1", "10.0.0.2", 1),
                        to_rtr("4.4.4.4", "10.0.2.1", 1),
                    ],
                    false,
                ),
                router(
                    "3.3.3.3",
                    vec![
                        to_rtr("1.1.1.1", "10.0.1.2", 1),
                        to_rtr("4.4.4.4", "10.0.3.1", 1),
                    ],
                    false,
                ),
                router(
                    "4.4.4.4",
                    vec![
                        to_rtr("2.2.2.2", "10.0.2.2", 1),
                        to_rtr("3.3.3.3", "10.0.3.2", 1),
                    ],
                    false,
                ),
            ],
        );
        let res = calculate(RouterId(u32::from(ip("1.1.1.1"))), &db);
        let r4 = route_for(
            &res,
            &Destination::Router(RouterId(u32::from(ip("4.4.4.4")))),
        );
        assert_eq!(r4.cost, 2);
        let mut hops = r4.next_hops.clone();
        hops.sort();
        assert_eq!(hops, vec![nh("10.0.0.1", None), nh("10.0.1.1", None)]);
    }

    #[test]
    fn network_before_router_tiebreak_finds_ecmp() {
        // The §16.1 step 3 note: at equal distance network vertices
        // are chosen first — otherwise some equal-cost paths are
        // missed. Shape: root reaches net N and router RX both at
        // cost 1; RX also sits on N; router RY beyond both at +0.
        let mut db = Lsdb::new();
        install_all(
            &mut db,
            vec![
                router(
                    "1.1.1.1",
                    vec![
                        to_net("10.1.1.1", "10.1.1.1", 1),
                        to_rtr("9.9.9.9", "10.0.0.1", 1),
                    ],
                    false,
                ),
                router(
                    "9.9.9.9",
                    vec![
                        to_rtr("1.1.1.1", "10.0.0.2", 1),
                        to_rtr("5.5.5.5", "10.9.9.1", 0),
                    ],
                    false,
                ),
                // 5.5.5.5 is on the network too (cost 0 from it).
                router(
                    "5.5.5.5",
                    vec![
                        to_net("10.1.1.1", "10.1.1.5", 1),
                        to_rtr("9.9.9.9", "10.9.9.2", 0),
                    ],
                    false,
                ),
                network("10.1.1.1", "255.255.255.0", &["1.1.1.1", "5.5.5.5"]),
            ],
        );
        let res = calculate(RouterId(u32::from(ip("1.1.1.1"))), &db);
        // 5.5.5.5 is reachable at cost 1 two ways: directly via the
        // network (1+0) and via 9.9.9.9 (1+0).
        let r5 = route_for(
            &res,
            &Destination::Router(RouterId(u32::from(ip("5.5.5.5")))),
        );
        assert_eq!(r5.cost, 1);
        let mut hops = r5.next_hops.clone();
        hops.sort();
        assert_eq!(
            hops,
            vec![nh("10.0.0.1", None), nh("10.1.1.1", Some("10.1.1.5"))]
        );
    }

    #[test]
    fn one_way_link_is_dropped() {
        // §16.1 step 2b: RT2 claims a link to RT1 but RT1's LSA has
        // no link back — the edge must not enter the tree.
        let mut db = Lsdb::new();
        install_all(
            &mut db,
            vec![
                router("1.1.1.1", vec![], false),
                router("2.2.2.2", vec![to_rtr("1.1.1.1", "10.0.0.2", 5)], false),
            ],
        );
        let res = calculate(RouterId(u32::from(ip("1.1.1.1"))), &db);
        assert!(res.routes.is_empty());
    }

    #[test]
    fn max_age_lsa_is_absent() {
        // §16's opening: a MaxAge LSA is treated as a failed lookup.
        let mut db = Lsdb::new();
        let mut r2 = router("2.2.2.2", vec![to_rtr("1.1.1.1", "10.0.0.2", 5)], false);
        r2.header.ls_age = crate::MAX_AGE;
        install_all(
            &mut db,
            vec![
                router("1.1.1.1", vec![to_rtr("2.2.2.2", "10.0.0.1", 5)], false),
                r2,
            ],
        );
        let res = calculate(RouterId(u32::from(ip("1.1.1.1"))), &db);
        assert!(res.routes.is_empty());
    }

    #[test]
    fn v_bit_sets_transit_capability() {
        let mut db = Lsdb::new();
        install_all(
            &mut db,
            vec![
                router("1.1.1.1", vec![to_rtr("2.2.2.2", "10.0.0.1", 1)], false),
                router("2.2.2.2", vec![to_rtr("1.1.1.1", "10.0.0.2", 1)], true),
            ],
        );
        let res = calculate(RouterId(u32::from(ip("1.1.1.1"))), &db);
        assert!(res.transit_capability, "V-bit on a tree router-LSA");
    }

    #[test]
    fn origin_tiebreak_prefers_larger_ls_id() {
        // Stage 2 (§16.1): equal-cost stub reachable from two
        // routers — the origin (Link State Origin) becomes the
        // router-LSA with the LARGER Link State ID.
        let mut db = Lsdb::new();
        install_all(
            &mut db,
            vec![
                router(
                    "1.1.1.1",
                    vec![
                        to_rtr("2.2.2.2", "10.0.0.1", 1),
                        to_rtr("3.3.3.3", "10.0.1.1", 1),
                    ],
                    false,
                ),
                router(
                    "2.2.2.2",
                    vec![
                        to_rtr("1.1.1.1", "10.0.0.2", 1),
                        stub("172.16.9.0", "255.255.255.0", 1),
                    ],
                    false,
                ),
                router(
                    "3.3.3.3",
                    vec![
                        to_rtr("1.1.1.1", "10.0.1.2", 1),
                        stub("172.16.9.0", "255.255.255.0", 1),
                    ],
                    false,
                ),
            ],
        );
        let res = calculate(RouterId(u32::from(ip("1.1.1.1"))), &db);
        let r = route_for(
            &res,
            &Destination::Network {
                addr: ip("172.16.9.0"),
                mask: ip("255.255.255.0"),
            },
        );
        assert_eq!(r.cost, 2);
        assert_eq!(r.origin.adv_router, RouterId(u32::from(ip("3.3.3.3"))));
        // Equal-cost next hops through BOTH routers.
        let mut hops = r.next_hops.clone();
        hops.sort();
        assert_eq!(hops, vec![nh("10.0.0.1", None), nh("10.0.1.1", None)]);
    }

    #[test]
    fn stub_cheaper_path_overwrites() {
        let mut db = Lsdb::new();
        install_all(
            &mut db,
            vec![
                router(
                    "1.1.1.1",
                    vec![
                        to_rtr("2.2.2.2", "10.0.0.1", 1),
                        to_rtr("3.3.3.3", "10.0.1.1", 1),
                    ],
                    false,
                ),
                router(
                    "2.2.2.2",
                    vec![
                        to_rtr("1.1.1.1", "10.0.0.2", 1),
                        stub("172.16.9.0", "255.255.255.0", 1),
                    ],
                    false,
                ),
                router(
                    "3.3.3.3",
                    vec![
                        to_rtr("1.1.1.1", "10.0.1.2", 1),
                        stub("172.16.9.0", "255.255.255.0", 9),
                    ],
                    false,
                ),
            ],
        );
        let res = calculate(RouterId(u32::from(ip("1.1.1.1"))), &db);
        let r = route_for(
            &res,
            &Destination::Network {
                addr: ip("172.16.9.0"),
                mask: ip("255.255.255.0"),
            },
        );
        assert_eq!(r.cost, 2);
        assert_eq!(r.origin.adv_router, RouterId(u32::from(ip("2.2.2.2"))));
        assert_eq!(r.next_hops, vec![nh("10.0.0.1", None)]);
    }

    #[test]
    fn inherited_hops_behind_an_intervening_router() {
        // §16.1.1 first rule: with at least one intervening router,
        // the destination inherits the parent's hops — here RT3's
        // stub behind RT2 keeps RT2's next hop.
        let mut db = Lsdb::new();
        install_all(
            &mut db,
            vec![
                router("1.1.1.1", vec![to_net("10.1.1.1", "10.1.1.1", 1)], false),
                router(
                    "2.2.2.2",
                    vec![
                        to_net("10.1.1.1", "10.1.1.2", 1),
                        to_rtr("3.3.3.3", "10.2.2.1", 4),
                    ],
                    false,
                ),
                router(
                    "3.3.3.3",
                    vec![
                        to_rtr("2.2.2.2", "10.2.2.2", 4),
                        stub("192.168.3.0", "255.255.255.0", 1),
                    ],
                    false,
                ),
                network("10.1.1.1", "255.255.255.0", &["1.1.1.1", "2.2.2.2"]),
            ],
        );
        let res = calculate(RouterId(u32::from(ip("1.1.1.1"))), &db);
        // RT3: 1 (to net) + 4 = 5, inheriting RT2's hop set.
        let r3 = route_for(
            &res,
            &Destination::Router(RouterId(u32::from(ip("3.3.3.3")))),
        );
        assert_eq!(r3.cost, 5);
        assert_eq!(r3.next_hops, vec![nh("10.1.1.1", Some("10.1.1.2"))]);
        // RT3's stub: 5 + 1, same hops.
        let s3 = route_for(
            &res,
            &Destination::Network {
                addr: ip("192.168.3.0"),
                mask: ip("255.255.255.0"),
            },
        );
        assert_eq!(s3.cost, 6);
        assert_eq!(s3.next_hops, vec![nh("10.1.1.1", Some("10.1.1.2"))]);
    }

    // ---- the brute-force oracle ----------------------------------

    struct XorShift(u64);
    impl XorShift {
        fn next(&mut self) -> u64 {
            self.0 ^= self.0 << 13;
            self.0 ^= self.0 >> 7;
            self.0 ^= self.0 << 17;
            self.0
        }
    }

    /// Random small graph: N routers, some p2p links, one broadcast
    /// network, stub links on each router. Returns (lsas, root).
    fn random_topology(rng: &mut XorShift, n_routers: usize) -> (Vec<Lsa>, RouterId) {
        let addr = |i: usize| Ipv4Addr::new(10, 0, i as u8, 1);
        let ifaddr = |i: usize, j: usize| Ipv4Addr::new(172, 16, i as u8, j as u8);
        let ids: Vec<RouterId> = (0..n_routers)
            .map(|i| RouterId(u32::from(addr(i))))
            .collect();
        let mut lsas = Vec::new();
        // p2p links: symmetric or one-way (both shapes legal input).
        let mut links: Vec<Vec<RouterLink>> = vec![vec![]; n_routers];
        for i in 0..n_routers {
            for j in (i + 1)..n_routers {
                let roll = rng.next() % 10;
                if roll < 4 {
                    let cost = (1 + rng.next() % 9) as u16;
                    links[i].push(RouterLink {
                        link_id: LinkStateId(ids[j].0),
                        link_data: u32::from(ifaddr(i, 2)),
                        link_type: LinkType::PointToPoint,
                        metric: cost,
                        tos: vec![],
                    });
                    if roll < 3 {
                        links[j].push(RouterLink {
                            link_id: LinkStateId(ids[i].0),
                            link_data: u32::from(ifaddr(j, 2)),
                            link_type: LinkType::PointToPoint,
                            metric: cost,
                            tos: vec![],
                        });
                    }
                }
            }
        }
        // One broadcast network with a random attached subset.
        let dr = Ipv4Addr::new(192, 168, 0, 1);
        let mut attached: Vec<RouterId> = Vec::new();
        for (i, id) in ids.iter().enumerate() {
            if rng.next() % 2 == 1 {
                attached.push(*id);
                links[i].push(RouterLink {
                    link_id: LinkStateId(u32::from(dr)),
                    link_data: u32::from(Ipv4Addr::new(192, 168, 0, 2 + i as u8)),
                    link_type: LinkType::Transit,
                    metric: (1 + rng.next() % 9) as u16,
                    tos: vec![],
                });
            }
        }
        // Stubs per router.
        for (i, link_set) in links.iter_mut().enumerate() {
            let n_stub = rng.next() % 3;
            for s in 0..n_stub {
                link_set.push(RouterLink {
                    link_id: LinkStateId(u32::from(Ipv4Addr::new(
                        172,
                        17,
                        i as u8,
                        (s * 16) as u8,
                    ))),
                    link_data: u32::from(Ipv4Addr::new(255, 255, 255, 240)),
                    link_type: LinkType::Stub,
                    metric: (1 + rng.next() % 5) as u16,
                    tos: vec![],
                });
            }
        }
        for (i, id) in ids.iter().enumerate() {
            lsas.push(router(&id.to_string(), links[i].clone(), false));
        }
        if attached.len() >= 2 {
            let names: Vec<&str> = attached
                .iter()
                .map(|r| Box::leak(r.to_string().into_boxed_str()) as &str)
                .collect();
            lsas.push(network(&dr.to_string(), "255.255.255.0", &names));
        }
        (lsas, ids[(rng.next() as usize) % n_routers])
    }

    /// Oracle: Bellman-Ford distances over the transit-only graph
    /// with the same bidirectionality rule.
    fn oracle_distances(lsas: &[Lsa], root: RouterId) -> HashMap<Vertex, u32> {
        let mut router_links: HashMap<RouterId, &Vec<RouterLink>> = HashMap::new();
        let mut net_attached: HashMap<u32, Vec<RouterId>> = HashMap::new();
        for l in lsas {
            match &l.body {
                LsaBody::Router(r) => {
                    router_links.insert(l.header.adv_router, &r.links);
                }
                LsaBody::Network(n) => {
                    net_attached.insert(l.header.link_state_id.0, n.attached.clone());
                }
                _ => {}
            }
        }
        let mut dist: HashMap<Vertex, u32> = HashMap::new();
        dist.insert(Vertex::Router(root), 0);
        loop {
            let mut changed = false;
            for (rid, links) in &router_links {
                let Some(&dr) = dist.get(&Vertex::Router(*rid)) else {
                    continue;
                };
                for l in links.iter() {
                    let (w, cost) = match l.link_type {
                        LinkType::Stub => continue,
                        LinkType::PointToPoint | LinkType::Virtual => {
                            let peer = RouterId(l.link_id.0);
                            let ok = router_links.get(&peer).is_some_and(|pl| {
                                pl.iter().any(|p| {
                                    matches!(
                                        p.link_type,
                                        LinkType::PointToPoint | LinkType::Virtual
                                    ) && p.link_id.0 == rid.0
                                })
                            });
                            if !ok {
                                continue;
                            }
                            (Vertex::Router(peer), l.metric as u32)
                        }
                        LinkType::Transit => {
                            let net = l.link_id.0;
                            let Some(att) = net_attached.get(&net) else {
                                continue;
                            };
                            if !att.contains(rid) {
                                continue;
                            }
                            (Vertex::Network(net), l.metric as u32)
                        }
                    };
                    let nd = dr + cost;
                    if nd < *dist.get(&w).unwrap_or(&u32::MAX) {
                        dist.insert(w, nd);
                        changed = true;
                    }
                }
            }
            for (net, att) in &net_attached {
                let Some(&dn) = dist.get(&Vertex::Network(*net)) else {
                    continue;
                };
                for rid in att {
                    let nd = dn; // network -> router cost is zero
                    if nd < *dist.get(&Vertex::Router(*rid)).unwrap_or(&u32::MAX) {
                        dist.insert(Vertex::Router(*rid), nd);
                        changed = true;
                    }
                }
            }
            if !changed {
                break;
            }
        }
        dist
    }

    #[test]
    fn property_distances_match_bellman_ford_oracle() {
        let mut rng = XorShift(0x0050_0466_0170_0310);
        for _ in 0..300 {
            let (lsas, root) = random_topology(&mut rng, 5);
            let mut db = Lsdb::new();
            for l in &lsas {
                db.install(l.clone(), true, 0);
            }
            let res = calculate(root, &db);
            let oracle = oracle_distances(&lsas, root);
            // Every oracle distance matches the SPF result.
            for (v, d) in &oracle {
                assert_eq!(
                    res.distances.get(v),
                    Some(d),
                    "vertex {v:?} root {root} dist mismatch"
                );
            }
            // And SPF found nothing the oracle missed.
            for (v, d) in &res.distances {
                assert_eq!(oracle.get(v), Some(d), "vertex {v:?} not in oracle");
            }
        }
    }

    #[test]
    fn property_next_hops_are_min_cost_first_edges() {
        // For router destinations: every advertised next hop must be
        // the first edge of SOME minimum-cost path, and the set must
        // cover every distinct first edge of the minimum-cost paths.
        // Enumerate simple paths exhaustively on 4-router graphs.
        let mut rng = XorShift(0x7ea1_0002_dead_0003);
        for iter in 0..200 {
            let (lsas, root) = random_topology(&mut rng, 4);
            let mut db = Lsdb::new();
            for l in &lsas {
                db.install(l.clone(), true, 0);
            }
            let res = calculate(root, &db);
            if let Err(msg) = try_check_first_edges(&lsas, root, &res) {
                panic!("iter {iter} root {root}: {msg}\n{:#?}", lsas);
            }
        }
    }

    /// Exhaustive simple-path enumeration for the first-edge check.
    fn try_check_first_edges(lsas: &[Lsa], root: RouterId, res: &SpfResult) -> Result<(), String> {
        let mut router_links: HashMap<RouterId, &Vec<RouterLink>> = HashMap::new();
        let mut net_attached: HashMap<u32, Vec<RouterId>> = HashMap::new();
        for l in lsas {
            match &l.body {
                LsaBody::Router(r) => {
                    router_links.insert(l.header.adv_router, &r.links);
                }
                LsaBody::Network(n) => {
                    net_attached.insert(l.header.link_state_id.0, n.attached.clone());
                }
                _ => {}
            }
        }
        // Enumerate simple transit paths (alternating router/net
        // vertices) from root, tracking the root interface used.
        #[derive(Clone)]
        struct Walk<'a> {
            v: Vertex,
            cost: u32,
            first_if: Option<Ipv4Addr>,
            visited: Vec<Vertex>,
            links: std::marker::PhantomData<&'a ()>,
        }
        let _ = std::marker::PhantomData::<()>;
        let mut best: HashMap<Vertex, (u32, Vec<Ipv4Addr>)> = HashMap::new();
        let start = Walk {
            v: Vertex::Router(root),
            cost: 0,
            first_if: None,
            visited: vec![Vertex::Router(root)],
            links: std::marker::PhantomData,
        };
        let mut queue = vec![start];
        while let Some(w) = queue.pop() {
            let entry = best.entry(w.v).or_insert((u32::MAX, vec![]));
            if w.cost < entry.0 {
                *entry = (w.cost, vec![]);
            }
            if w.cost == entry.0 {
                if let Some(f) = w.first_if {
                    if !entry.1.contains(&f) {
                        entry.1.push(f);
                    }
                }
            }
            if w.visited.len() > 10 {
                continue;
            }
            match w.v {
                Vertex::Router(r) => {
                    let Some(links) = router_links.get(&r) else {
                        continue;
                    };
                    for l in links.iter() {
                        let (nv, cost) = match l.link_type {
                            LinkType::Stub => continue,
                            LinkType::PointToPoint | LinkType::Virtual => {
                                let peer = RouterId(l.link_id.0);
                                let ok = router_links.get(&peer).is_some_and(|pl| {
                                    pl.iter().any(|p| {
                                        matches!(
                                            p.link_type,
                                            LinkType::PointToPoint | LinkType::Virtual
                                        ) && p.link_id.0 == r.0
                                    })
                                });
                                if !ok {
                                    continue;
                                }
                                (Vertex::Router(peer), l.metric as u32)
                            }
                            LinkType::Transit => {
                                let net = l.link_id.0;
                                let Some(att) = net_attached.get(&net) else {
                                    continue;
                                };
                                if !att.contains(&r) {
                                    continue;
                                }
                                (Vertex::Network(net), l.metric as u32)
                            }
                        };
                        if w.visited.contains(&nv) {
                            continue;
                        }
                        let first_if = w.first_if.or(Some(Ipv4Addr::from(l.link_data)));
                        let mut visited = w.visited.clone();
                        visited.push(nv);
                        queue.push(Walk {
                            v: nv,
                            cost: w.cost + cost,
                            first_if,
                            visited,
                            links: std::marker::PhantomData,
                        });
                    }
                }
                Vertex::Network(net) => {
                    let Some(att) = net_attached.get(&net) else {
                        continue;
                    };
                    for rid in att {
                        let nv = Vertex::Router(*rid);
                        if w.visited.contains(&nv) {
                            continue;
                        }
                        let mut visited = w.visited.clone();
                        visited.push(nv);
                        queue.push(Walk {
                            v: nv,
                            cost: w.cost, // network -> router is zero
                            first_if: w.first_if,
                            visited,
                            links: std::marker::PhantomData,
                        });
                    }
                }
            }
        }
        // Compare router-destination routes against the enumeration.
        for route in &res.routes {
            if let Destination::Router(rid) = route.destination {
                let Some((cost, firsts)) = best.get(&Vertex::Router(rid)) else {
                    return Err(format!("route to {rid} but no enumerated path"));
                };
                if route.cost != *cost {
                    return Err(format!("cost to {rid}: {} vs {}", route.cost, cost));
                }
                let got: std::collections::HashSet<Ipv4Addr> =
                    route.next_hops.iter().map(|h| h.interface).collect();
                let want: std::collections::HashSet<Ipv4Addr> = firsts.iter().copied().collect();
                if got != want {
                    return Err(format!(
                        "first-edge set to {rid}: got {:?} want {:?}",
                        got, want
                    ));
                }
            }
        }
        Ok(())
    }

    // ---- scheduler ------------------------------------------------

    #[test]
    fn scheduler_throttles_and_backs_off() {
        let mut s = SpfScheduler::default(); // 0 / 50 / 5000 ms
                                             // First change from idle: runs at now (initial delay 0).
        assert_eq!(s.on_change(1000), Some(1000));
        assert!(s.is_due(1000));
        s.mark_run(1000);
        assert_eq!(s.due_at(), None);
        // A burst: each change grows the delay along the increment
        // schedule (50 -> 100 -> ...) and never pulls a set due time
        // earlier.
        s.on_change(1010);
        assert_eq!(s.due_at(), Some(1010 + 50));
        s.on_change(1020);
        assert_eq!(s.due_at(), Some(1020 + 100), "delay grows with the burst");
        // A change before the due time never reschedules earlier.
        s.on_change(1030);
        assert!(s.due_at().unwrap() >= 1120);
        let run_at = s.due_at().unwrap();
        s.mark_run(run_at);
        // The burst raised the current delay to 150; the next change
        // grows it once more (150+50 = 200).
        assert_eq!(s.on_change(run_at + 1), Some(run_at + 1 + 200));
        // Capped at the maximum.
        let mut s2 = SpfScheduler::default();
        s2.mark_run(0);
        let mut now = 0u64;
        for _ in 0..200 {
            s2.mark_run(now);
            let due = s2.on_change(now).unwrap();
            now = due;
        }
        assert!(s2.current_delay_ms <= 5000);
        // A change after a quiet period of at least the max delay
        // starts fresh at the initial delay (0).
        assert_eq!(s2.on_change(now + 10_000), Some(now + 10_000));
    }
}
