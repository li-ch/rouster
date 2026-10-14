//! The OSPFv3 intra-area SPF (RFC 5340 §4.8.1/§4.8.2 over RFC 2328
//! §16.1/§16.1.1).
//!
//! §4.8.1: "The graph used by the shortest-path tree calculation is
//! identical for both IPv4 and IPv6. ... A router is identified by its
//! OSPF Router ID, while a transit link is identified by its
//! Designated Router's Interface ID and OSPF Router ID." The Dijkstra
//! is RFC 2328 §16.1's, with the exceptions this module implements:
//!
//! - **Transit vertices key on (DR Interface ID, DR Router ID)** —
//!   the network-LSA's (Link State ID, Advertising Router) pair
//!   (§4.4.1: "For network-LSAs, the Link State ID is set to the
//!   Designated Router's Interface ID on the link").
//! - **The multiple-router-LSA concatenation** (§4.8.1 step 2 / A.4.3):
//!   "All router-LSAs with the Advertising Router set to V's OSPF
//!   Router ID MUST be processed as an aggregate, treating them as
//!   fragments of a single large router-LSA. The Options field and
//!   the router type bits (bits Nt, V, E, and B) should always be
//!   taken from the router-LSA with the smallest Link State ID."
//!   [`RouterAgg`] is that aggregate — no helper here assumes one
//!   router-LSA per (router, area) (the §Deferred trap).
//! - **The V6/R-bit gate** (§4.8.1 step 2b): a router W whose
//!   router-LSA options lack the V6 or R bit is skipped as a transit
//!   ("the transit link W is ignored and V's next link is examined").
//!   (§3.1's note: "The V6-bit and R-bit are only examined in
//!   Router-LSAs during the SPF calculation".)
//! - **Stage two walks the intra-area-prefix-LSAs** instead of stub
//!   links: "The cost of any advertised prefix is the sum of the
//!   prefix's advertised metric plus the cost to the transit vertex
//!   (either router or transit network) identified by
//!   intra-area-prefix-LSA's Referenced LS Type, Referenced Link State
//!   ID, and Referenced Advertising Router fields"; NU-bit prefixes
//!   are excluded ("A prefix advertisement whose NU-bit is set SHOULD
//!   NOT be included in the routing calculation").
//!
//! §4.8.2 next hops: "When calculating the next-hop IPv6 address for
//! a router (call it Router X) that shares a link with the
//! calculating router, the calculating router assigns the next-hop
//! IPv6 address to be the link-local interface address contained in
//! Router X's link-LSA (see Appendix A.4.9) for the link." The
//! address source is the attached link's link-local-scope database
//! ([`SpfLinkV3`]) — never the router-LSAs ("link-local addresses
//! appear in OSPF link-LSAs and nowhere else", §2.5). The RFC's
//! fallback — "For other link types, the next-hop address may be
//! determined via the IPv6 source address in the neighbor's Hello
//! packet" — is why the hop also carries the adjacent Router ID
//! ([`NextHopV3::via`]): the daemon substitutes the adjacency's
//! Hello source when the link-LSA is not there yet. And "In the case
//! where the intra-area-prefix-LSA's referenced LSA is a directly
//! connected network-LSA, the prefixes are also considered to be
//! directly connected. In this case, the next hop is solely the
//! outgoing link and no IPv6 next-hop address is selected" — the
//! `address: None, via: None` hop.
//!
//! What is deliberately the same as the v2 engine (`spf.rs`): the
//! candidate pop order (distance, network-before-router, insertion
//! FIFO), the two per-vertex hop sets (own route hops vs the hops
//! children inherit), equal-cost accumulation, on-tree vertices never
//! re-relaxed, network→router edges costing zero, MaxAge LSAs
//! treated as absent, and the bidirectionality rule (§16.1 step 2b
//! over the v3 link tuples). §4.8.1: "The Dijkstra calculation for
//! IPv6 is identical to that specified for IPv4, with the following
//! exceptions."
//!
//! Deferred (§4.8.1 step 4's tail): the v3 virtual-neighbor address
//! resolution from LA-bit prefixes — rides with virtual links v3.

use std::collections::HashMap;
use std::net::Ipv6Addr;

use common::Ipv6Prefix;

use crate::lsa::{LsaKey, LsaType, RouterId};
use crate::lsa_v3::{LsaBodyV3, LsaV3, Options24, Prefix, RouterLinkV3};
use crate::lsdb::Lsdb;

/// The v3 router type bits, taken from the lowest-LS-ID fragment
/// (§4.8.1 step 2).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct RouterFlagsV3 {
    pub nt: bool,
    pub v: bool,
    pub e: bool,
    pub b: bool,
}

/// One §4.8.2 next hop.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct NextHopV3 {
    /// The calculating router's own Interface ID on the outgoing link
    /// (v3's replacement for the v2 Link-Data interface address,
    /// §2.2/A.4.3).
    pub interface_id: u32,
    /// The adjacent router's link-local address — Router X's link-LSA
    /// value (§4.8.2); `None` when the hop is directly connected (no
    /// next-hop address) or when no link-LSA exists yet (the daemon
    /// falls back to the Hello source via `via`).
    pub address: Option<Ipv6Addr>,
    /// The adjacent router the hop forwards through — the §4.8.2
    /// Hello-source fallback's lookup key; `None` only for the
    /// directly-connected form.
    pub via: Option<RouterId>,
}

/// A graph vertex: a router or a transit link (§4.8.1's vertex IDs).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum VertexV3 {
    Router(RouterId),
    /// (DR Interface ID, DR Router ID) — the transit link's identity.
    Network {
        dr_interface_id: u32,
        dr_router_id: RouterId,
    },
}

impl VertexV3 {
    /// §16.1 step 3's tiebreak: transit links chosen before routers
    /// at equal distance.
    fn kind_rank(&self) -> u8 {
        match self {
            Self::Network { .. } => 0,
            Self::Router(_) => 1,
        }
    }
}

/// One attached link of the calculating router: its own Interface ID
/// plus the link's link-local-scope database (§3.2 — the link's
/// link-LSAs, the §4.8.2 next-hop source).
pub struct SpfLinkV3<'a> {
    /// OUR Interface ID on this link (the InterfaceV3 ifindex).
    pub interface_id: u32,
    pub lsdb: &'a Lsdb<LsaV3>,
}

/// A router destination (§4.8.1 step 4: per-area routing table
/// entries exist for each of the area's routers).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RouterRouteV3 {
    pub router: RouterId,
    pub cost: u32,
    pub next_hops: Vec<NextHopV3>,
    pub flags: RouterFlagsV3,
}

/// A prefix route from the stage-two intra-area-prefix walk.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PrefixRouteV3 {
    pub prefix: Ipv6Prefix,
    pub cost: u32,
    pub next_hops: Vec<NextHopV3>,
    /// The IAPR-LSA the route was derived from (§11's Link State
    /// Origin).
    pub origin: LsaKey,
}

/// The result of one area's calculation.
#[derive(Debug, Clone, Default)]
pub struct SpfResultV3 {
    /// Any on-tree router-LSA's V-bit (a virtual link transits the
    /// area — the §16.1 step 2 input).
    pub transit_capability: bool,
    /// Every seen router's flags (from the lowest-LS-ID fragment) —
    /// present whether or not the router reached the tree.
    pub router_flags: HashMap<RouterId, RouterFlagsV3>,
    /// Distance to every reachable transit vertex.
    pub distances: HashMap<VertexV3, u32>,
    /// Router destinations, deterministically ordered.
    pub routers: Vec<RouterRouteV3>,
    /// Prefix routes, deterministically ordered (by prefix string).
    pub routes: Vec<PrefixRouteV3>,
}

/// §4.8.1 step 2's aggregate: one router's complete set of
/// router-LSA fragments — the concatenated links plus the Options and
/// Nt/V/E/B bits taken from the smallest Link State ID instance.
struct RouterAgg<'a> {
    options: Options24,
    flags: RouterFlagsV3,
    links: Vec<&'a RouterLinkV3>,
}

/// A finalized tree vertex plus its next-hop state (the v2 engine's
/// two-hop-set discipline; see `spf.rs`'s `TreeEntry` for the
/// load-bearing explanation of route_hops vs hops).
#[derive(Debug, Clone)]
struct TreeEntryV3 {
    distance: u32,
    route_hops: Vec<NextHopV3>,
    hops: Vec<NextHopV3>,
    /// Our own Interface ID when the root is directly attached to
    /// this transit link (the §4.8.2 case-two input).
    root_if: Option<u32>,
}

#[derive(Debug, Clone)]
struct CandV3 {
    distance: u32,
    route_hops: Vec<NextHopV3>,
    hops: Vec<NextHopV3>,
    root_if: Option<u32>,
    seq: u64,
}

/// The §4.8.1 calculation for one area, rooted at `root`. `links` are
/// the root's attached links with their link-local-scope stores (the
/// §4.8.2 next-hop source).
pub fn calculate_v3(root: RouterId, area: &Lsdb<LsaV3>, links: &[SpfLinkV3<'_>]) -> SpfResultV3 {
    // ---- the aggregate index (the A.4.3 concatenation) ----------
    // Fragments collected per router, then reduced: links from ALL
    // fragments, Options/flags from the smallest Link State ID.
    let mut fragments: HashMap<RouterId, Vec<(u32, &crate::lsa_v3::RouterLsaV3)>> = HashMap::new();
    let mut networks: HashMap<(u32, RouterId), Vec<RouterId>> = HashMap::new();
    let mut prefixes: Vec<&LsaV3> = Vec::new();
    for entry in area.all() {
        if entry.lsa.header.is_max_age() {
            continue; // §16's opening: a MaxAge LSA is a failed lookup
        }
        match &entry.lsa.body {
            LsaBodyV3::Router(r) => {
                fragments
                    .entry(entry.lsa.header.adv_router)
                    .or_default()
                    .push((entry.lsa.header.link_state_id.0, r));
            }
            LsaBodyV3::Network(n) => {
                // The transit link's identity: (LS ID = the DR's
                // Interface ID, Advertising Router = the DR).
                networks.insert(
                    (
                        entry.lsa.header.link_state_id.0,
                        entry.lsa.header.adv_router,
                    ),
                    n.attached.clone(),
                );
            }
            LsaBodyV3::IntraAreaPrefix(_) => prefixes.push(&entry.lsa),
            _ => {}
        }
    }
    let mut router_aggs: HashMap<RouterId, RouterAgg> = HashMap::new();
    for (rid, mut frags) in fragments {
        // "The Options field and the router type bits (bits Nt, V, E,
        // and B) should always be taken from the router-LSA with the
        // smallest Link State ID" (§4.8.1 step 2).
        frags.sort_by_key(|(lsid, _)| *lsid);
        let (_, first) = frags[0];
        let mut links = Vec::new();
        for (_, frag) in &frags {
            links.extend(frag.links.iter());
        }
        router_aggs.insert(
            rid,
            RouterAgg {
                options: first.options,
                flags: RouterFlagsV3 {
                    nt: first.nt_bit,
                    v: first.v_bit,
                    e: first.e_bit,
                    b: first.b_bit,
                },
                links,
            },
        );
    }

    // §4.8.2's address source: (our Interface ID, adjacent router) ->
    // that router's link-local in the link's link-local-scope store.
    let mut link_locals: HashMap<(u32, RouterId), Ipv6Addr> = HashMap::new();
    for link in links {
        for entry in link.lsdb.all() {
            if let LsaBodyV3::Link(body) = &entry.lsa.body {
                link_locals.insert(
                    (link.interface_id, entry.lsa.header.adv_router),
                    body.link_local_address,
                );
            }
        }
    }

    let mut result = SpfResultV3 {
        router_flags: router_aggs
            .iter()
            .map(|(rid, agg)| (*rid, agg.flags))
            .collect(),
        ..SpfResultV3::default()
    };

    let mut tree: HashMap<VertexV3, TreeEntryV3> = HashMap::new();
    tree.insert(
        VertexV3::Router(root),
        TreeEntryV3 {
            distance: 0,
            route_hops: vec![],
            hops: vec![],
            root_if: None,
        },
    );
    let mut candidates: HashMap<VertexV3, CandV3> = HashMap::new();
    let mut insert_seq: u64 = 0;

    // Step 2 lifted into a closure (the root expands before any
    // candidate exists — the v2 engine's shape).
    let expand = |v: VertexV3,
                  tree: &mut HashMap<VertexV3, TreeEntryV3>,
                  result: &mut SpfResultV3,
                  candidates: &mut HashMap<VertexV3, CandV3>,
                  insert_seq: &mut u64| {
        match v {
            VertexV3::Router(rid) => {
                let Some(agg) = router_aggs.get(&rid) else {
                    return;
                };
                if agg.flags.v {
                    result.transit_capability = true;
                }
                for link in &agg.links {
                    match link.link_type {
                        crate::lsa_v3::LinkTypeV3::PointToPoint
                        | crate::lsa_v3::LinkTypeV3::Virtual => {
                            relax_edge(
                                v,
                                VertexV3::Router(link.neighbor_router_id),
                                u32::from(link.metric),
                                Some(link.interface_id),
                                root,
                                &router_aggs,
                                &networks,
                                &link_locals,
                                tree,
                                candidates,
                                insert_seq,
                            );
                        }
                        crate::lsa_v3::LinkTypeV3::Transit => {
                            // The described neighbor is the link's DR —
                            // the transit vertex key.
                            relax_edge(
                                v,
                                VertexV3::Network {
                                    dr_interface_id: link.neighbor_interface_id,
                                    dr_router_id: link.neighbor_router_id,
                                },
                                u32::from(link.metric),
                                Some(link.interface_id),
                                root,
                                &router_aggs,
                                &networks,
                                &link_locals,
                                tree,
                                candidates,
                                insert_seq,
                            );
                        }
                    }
                }
            }
            VertexV3::Network { .. } => {
                let Some(attached) = networks.get(&(dr_iface(v), dr_router(v))) else {
                    return;
                };
                // §A.4.3 lineage: transit link -> attached router
                // costs zero.
                for rid in attached {
                    relax_edge(
                        v,
                        VertexV3::Router(*rid),
                        0,
                        None,
                        root,
                        &router_aggs,
                        &networks,
                        &link_locals,
                        tree,
                        candidates,
                        insert_seq,
                    );
                }
            }
        }
    };

    result.distances.insert(VertexV3::Router(root), 0);
    expand(
        VertexV3::Router(root),
        &mut tree,
        &mut result,
        &mut candidates,
        &mut insert_seq,
    );

    loop {
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
            TreeEntryV3 {
                distance: cand.distance,
                route_hops: cand.route_hops.clone(),
                hops: cand.hops.clone(),
                root_if: cand.root_if,
            },
        );
        result.distances.insert(v, cand.distance);
        candidates.remove(&v);
        expand(v, &mut tree, &mut result, &mut candidates, &mut insert_seq);
    }

    // Step 4: the router destinations, in tree order.
    let mut order: Vec<(&VertexV3, &TreeEntryV3)> = tree.iter().collect();
    order.sort_by_key(|(v, e)| (e.distance, v.kind_rank(), vertex_id(**v)));
    for (v, entry) in order {
        if let VertexV3::Router(rid) = v {
            if *rid == root {
                continue;
            }
            result.routers.push(RouterRouteV3 {
                router: *rid,
                cost: entry.distance,
                next_hops: dedup_hops(entry.route_hops.clone()),
                flags: result.router_flags.get(rid).copied().unwrap_or_default(),
            });
        }
    }

    // Stage two: the intra-area-prefix-LSAs (§4.8.1's second stage).
    // Deterministic LSA order keeps the equal-cost merge stable.
    let mut iapr: Vec<&LsaV3> = prefixes;
    iapr.sort_by_key(|lsa| lsa.key());
    let mut prefix_best: HashMap<(u128, u8), (u32, Vec<NextHopV3>, LsaKey)> = HashMap::new();
    for lsa in iapr {
        let LsaBodyV3::IntraAreaPrefix(body) = &lsa.body else {
            continue;
        };
        // The referenced transit vertex (A.4.10's triple).
        let vertex = match body.referenced_ls_type {
            LsaType::V3_ROUTER => VertexV3::Router(body.referenced_adv_router),
            LsaType::V3_NETWORK => VertexV3::Network {
                dr_interface_id: body.referenced_link_state_id.0,
                dr_router_id: body.referenced_adv_router,
            },
            _ => continue,
        };
        let Some(entry) = tree.get(&vertex) else {
            continue; // the referenced vertex is not on the tree
        };
        for pm in &body.prefixes {
            // "A prefix advertisement whose NU-bit is set SHOULD NOT
            // be included in the routing calculation."
            if pm.prefix.options.nu_bit() {
                continue;
            }
            let Some(prefix) = ipv6_prefix_of(&pm.prefix) else {
                continue;
            };
            let d = entry.distance.saturating_add(u32::from(pm.metric));
            let key = (u128::from(prefix.addr()), prefix.prefix_len());
            match prefix_best.get_mut(&key) {
                Some(best) if best.0 < d => continue,
                Some(best) if best.0 == d => {
                    best.1.extend(entry.route_hops.iter().copied());
                }
                Some(best) => {
                    *best = (d, entry.route_hops.clone(), lsa.key());
                }
                None => {
                    prefix_best.insert(key, (d, entry.route_hops.clone(), lsa.key()));
                }
            }
        }
    }
    for ((addr, len), (cost, hops, origin)) in prefix_best {
        if let Ok(prefix) = Ipv6Prefix::new(Ipv6Addr::from(addr), len) {
            result.routes.push(PrefixRouteV3 {
                prefix,
                cost,
                next_hops: dedup_hops(hops),
                origin,
            });
        }
    }
    result.routes.sort_by_key(|r| r.prefix.to_string());
    result
}

fn dr_iface(v: VertexV3) -> u32 {
    match v {
        VertexV3::Network {
            dr_interface_id, ..
        } => dr_interface_id,
        VertexV3::Router(_) => 0,
    }
}

fn dr_router(v: VertexV3) -> RouterId {
    match v {
        VertexV3::Network { dr_router_id, .. } => dr_router_id,
        VertexV3::Router(r) => r,
    }
}

fn vertex_id(v: VertexV3) -> u64 {
    match v {
        VertexV3::Router(r) => u64::from(r.0),
        VertexV3::Network {
            dr_interface_id,
            dr_router_id,
        } => (u64::from(dr_router_id.0) << 32) | u64::from(dr_interface_id),
    }
}

/// §16.1 step 2b/2c/2d for one (V → W) edge. `link_interface` is OUR
/// Interface ID on the link when V is a router (the link record's
/// Interface ID field); None for network→router edges (the outgoing
/// interface is the one the root reached the network through — the
/// §4.8.2 case-two machinery).
#[allow(clippy::too_many_arguments)]
fn relax_edge(
    v: VertexV3,
    w: VertexV3,
    cost: u32,
    link_interface: Option<u32>,
    root: RouterId,
    router_aggs: &HashMap<RouterId, RouterAgg>,
    networks: &HashMap<(u32, RouterId), Vec<RouterId>>,
    link_locals: &HashMap<(u32, RouterId), Ipv6Addr>,
    tree: &HashMap<VertexV3, TreeEntryV3>,
    candidates: &mut HashMap<VertexV3, CandV3>,
    insert_seq: &mut u64,
) {
    // (b) W's LSA must exist and have a link back to V; for a router
    // W the V6/R gate applies first (§4.8.1 step 2b: "if W is a
    // router and the router-LSA V6-bit or R-bit is not set in the LSA
    // options, the transit link W is ignored").
    match w {
        VertexV3::Router(wid) => {
            let Some(agg) = router_aggs.get(&wid) else {
                return;
            };
            if !agg.options.v6_bit() || !agg.options.r_bit() {
                return; // §4.8.1 step 2b
            }
            let back = match v {
                VertexV3::Router(vid) => agg.links.iter().any(|l| {
                    matches!(
                        l.link_type,
                        crate::lsa_v3::LinkTypeV3::PointToPoint
                            | crate::lsa_v3::LinkTypeV3::Virtual
                    ) && l.neighbor_router_id == vid
                }),
                VertexV3::Network {
                    dr_interface_id,
                    dr_router_id,
                } => agg.links.iter().any(|l| {
                    matches!(l.link_type, crate::lsa_v3::LinkTypeV3::Transit)
                        && l.neighbor_interface_id == dr_interface_id
                        && l.neighbor_router_id == dr_router_id
                }),
            };
            if !back {
                return;
            }
        }
        VertexV3::Network {
            dr_interface_id,
            dr_router_id,
        } => {
            // The network-LSA (keyed by the DR pair) must list V as
            // attached.
            let Some(attached) = networks.get(&(dr_interface_id, dr_router_id)) else {
                return;
            };
            let attached = match v {
                VertexV3::Router(vid) => attached.contains(&vid),
                VertexV3::Network { .. } => false,
            };
            if !attached {
                return;
            }
        }
    }
    // (c) On the tree already: skip.
    if tree.contains_key(&w) {
        return;
    }
    let v_entry = &tree[&v];
    let d = v_entry.distance.saturating_add(cost);

    // §4.8.2: Router X's link-local on the link — its link-LSA in the
    // outgoing link's store. `via` stays for the Hello-source
    // fallback when the store has none.
    let hop_to = |own_if: u32, x: RouterId| NextHopV3 {
        interface_id: own_if,
        address: link_locals.get(&(own_if, x)).copied(),
        via: Some(x),
    };

    // The §4.8.2 next-hop sets for the (V, W) edge.
    let (route_hops, hops, root_if): (Vec<NextHopV3>, Vec<NextHopV3>, Option<u32>) = match v {
        VertexV3::Router(r) if r == root => {
            let Some(own_if) = link_interface else {
                return; // a root edge without an Interface ID is malformed
            };
            match w {
                VertexV3::Router(wid) => {
                    // §4.8.2: Router X shares a link with the root —
                    // the hop's address is X's link-local from X's
                    // link-LSA on THIS link. Children inherit the same
                    // hop (§16.1.1 case one, v2 shape).
                    let h = hop_to(own_if, wid);
                    (vec![h], vec![h], None)
                }
                VertexV3::Network { .. } => {
                    // The transit link is the destination (root
                    // attached); children derive their own hops.
                    let h = NextHopV3 {
                        interface_id: own_if,
                        address: None,
                        via: None,
                    };
                    (vec![h], vec![], Some(own_if))
                }
            }
        }
        VertexV3::Router(_) => (v_entry.hops.clone(), v_entry.hops.clone(), None),
        VertexV3::Network { .. } => {
            let mut route = Vec::new();
            if let Some(rif) = v_entry.root_if {
                // §4.8.2 case two: the root is attached to this
                // transit link — W's hop is W's own link-local on it.
                if let VertexV3::Router(wid) = w {
                    route.push(hop_to(rif, wid));
                }
            }
            // Paths through other routers onto this link inherit its
            // accumulated hop set (§16.1.1 case one, v2 shape).
            let mut inherit = v_entry.hops.clone();
            route.append(&mut inherit);
            (route.clone(), route, None)
        }
    };

    match candidates.get_mut(&w) {
        Some(c) if c.distance < d => {}
        Some(c) if c.distance == d => {
            c.route_hops.extend(route_hops);
            c.hops.extend(hops);
        }
        Some(c) => {
            c.distance = d;
            c.route_hops = route_hops;
            c.hops = hops;
            c.root_if = root_if;
        }
        None => {
            *insert_seq += 1;
            candidates.insert(
                w,
                CandV3 {
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

fn dedup_hops(mut hops: Vec<NextHopV3>) -> Vec<NextHopV3> {
    hops.sort();
    hops.dedup();
    hops
}

/// The A.4.1 prefix triple back to a route prefix (the daemon_v3
/// shape, shared for the test surface).
pub(crate) fn ipv6_prefix_of(prefix: &Prefix) -> Option<Ipv6Prefix> {
    let mut bytes = [0u8; 16];
    let take = Prefix::words(prefix.len).min(16);
    if prefix.addr.len() != take {
        return None;
    }
    bytes[..take].copy_from_slice(&prefix.addr);
    Ipv6Prefix::new(Ipv6Addr::from(bytes), prefix.len).ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::lsa::LinkStateId;
    use crate::lsa_v3::{
        IntraAreaPrefixLsaV3, LinkLsaV3, LinkTypeV3, LsaHeaderV3, NetworkLsaV3, PrefixMetric,
        PrefixOptions, RouterLsaV3,
    };
    use crate::lsdb::Lsdb;

    fn opts_v6() -> Options24 {
        Options24(Options24::V6 | Options24::E | Options24::R)
    }

    fn ll(seed: u8) -> Ipv6Addr {
        format!("fe80::{seed:x}").parse().unwrap()
    }

    /// A v3 router-LSA fragment: links + explicit LS ID + flags.
    fn router_lsa(rid: u32, lsid: u32, links: Vec<RouterLinkV3>) -> LsaV3 {
        LsaV3 {
            header: LsaHeaderV3 {
                ls_age: 1,
                ls_type: LsaType::V3_ROUTER,
                link_state_id: LinkStateId(lsid),
                adv_router: RouterId(rid),
                seq: 0x8000_0001,
                checksum: 0x1234,
                length: 0,
            },
            body: LsaBodyV3::Router(RouterLsaV3 {
                nt_bit: false,
                v_bit: false,
                e_bit: false,
                b_bit: false,
                options: opts_v6(),
                links,
            }),
        }
    }

    fn net_lsa(dr_iface: u32, dr_rid: u32, attached: &[u32]) -> LsaV3 {
        LsaV3 {
            header: LsaHeaderV3 {
                ls_age: 1,
                ls_type: LsaType::V3_NETWORK,
                link_state_id: LinkStateId(dr_iface),
                adv_router: RouterId(dr_rid),
                seq: 0x8000_0001,
                checksum: 0x1234,
                length: 0,
            },
            body: LsaBodyV3::Network(NetworkLsaV3 {
                options: opts_v6(),
                attached: attached.iter().map(|r| RouterId(*r)).collect(),
            }),
        }
    }

    /// A link-LSA: the router's link-local on a link (LS ID = its
    /// Interface ID there).
    fn link_lsa(rid: u32, iface: u32, link_local: Ipv6Addr) -> LsaV3 {
        LsaV3 {
            header: LsaHeaderV3 {
                ls_age: 1,
                ls_type: LsaType::V3_LINK,
                link_state_id: LinkStateId(iface),
                adv_router: RouterId(rid),
                seq: 0x8000_0001,
                checksum: 0x1234,
                length: 0,
            },
            body: LsaBodyV3::Link(LinkLsaV3 {
                router_priority: 1,
                options: opts_v6(),
                link_local_address: link_local,
                prefixes: vec![],
            }),
        }
    }

    fn p2p(own_iface: u32, nbr_iface: u32, nbr: u32, metric: u16) -> RouterLinkV3 {
        RouterLinkV3 {
            link_type: LinkTypeV3::PointToPoint,
            metric,
            interface_id: own_iface,
            neighbor_interface_id: nbr_iface,
            neighbor_router_id: RouterId(nbr),
        }
    }

    fn transit(own_iface: u32, dr_iface: u32, dr_rid: u32, metric: u16) -> RouterLinkV3 {
        RouterLinkV3 {
            link_type: LinkTypeV3::Transit,
            metric,
            interface_id: own_iface,
            neighbor_interface_id: dr_iface,
            neighbor_router_id: RouterId(dr_rid),
        }
    }

    /// (len, address-bytes, metric) -> one IAPR for a referenced
    /// (type, LS ID, adv router) triple.
    fn iapr_lsa(
        rid: u32,
        lsid: u32,
        refs: (LsaType, u32, u32),
        prefixes: Vec<(u8, [u8; 16], u16)>,
    ) -> LsaV3 {
        LsaV3 {
            header: LsaHeaderV3 {
                ls_age: 1,
                ls_type: LsaType::V3_INTRA_AREA_PREFIX,
                link_state_id: LinkStateId(lsid),
                adv_router: RouterId(rid),
                seq: 0x8000_0001,
                checksum: 0x1234,
                length: 0,
            },
            body: LsaBodyV3::IntraAreaPrefix(IntraAreaPrefixLsaV3 {
                prefixes: prefixes
                    .into_iter()
                    .map(|(len, addr, metric)| PrefixMetric {
                        metric,
                        prefix: crate::lsa_v3::Prefix {
                            len,
                            options: PrefixOptions(0),
                            addr: addr[..Prefix::words(len)].to_vec(),
                        },
                    })
                    .collect(),
                referenced_ls_type: refs.0,
                referenced_link_state_id: LinkStateId(refs.1),
                referenced_adv_router: RouterId(refs.2),
            }),
        }
    }

    fn db8(subnet: u8) -> [u8; 16] {
        let mut b = [0u8; 16];
        b[..6].copy_from_slice(&[0x20, 0x01, 0x0d, 0xb8, 0x00, subnet]);
        b
    }

    /// The full test harness: an area LSDB plus the root's attached
    /// link stores.
    struct Rig {
        area: Lsdb<LsaV3>,
        links: Vec<(u32, Lsdb<LsaV3>)>,
    }

    impl Rig {
        fn new() -> Self {
            Self {
                area: Lsdb::new(),
                links: Vec::new(),
            }
        }

        fn install(&mut self, lsa: LsaV3) {
            self.area.install(lsa, true, 0);
        }

        /// Attach a root interface with its link-scope store.
        fn attach(&mut self, interface_id: u32, link_lsas: Vec<LsaV3>) {
            let mut store = Lsdb::new();
            for lsa in link_lsas {
                store.install(lsa, true, 0);
            }
            self.links.push((interface_id, store));
        }

        fn run(&self, root: u32) -> SpfResultV3 {
            let links: Vec<SpfLinkV3> = self
                .links
                .iter()
                .map(|(id, db)| SpfLinkV3 {
                    interface_id: *id,
                    lsdb: db,
                })
                .collect();
            calculate_v3(RouterId(root), &self.area, &links)
        }
    }

    #[test]
    fn two_routers_p2p_with_link_lsa_next_hops() {
        // The v3 two-node shape: R1 -- R2 over p2p; R2's prefix rides
        // its IAPR. The next hop must come from R2's link-LSA (4.8.2).
        let mut rig = Rig::new();
        rig.install(router_lsa(1, 0, vec![p2p(11, 22, 2, 10)]));
        rig.install(router_lsa(2, 0, vec![p2p(22, 11, 1, 10)]));
        rig.attach(11, vec![link_lsa(2, 22, ll(0x22))]);
        // R2's IAPR: 2001:db8:2::/64 off its router-LSA.
        rig.install(iapr_lsa(
            2,
            0,
            (LsaType::V3_ROUTER, 0, 2),
            vec![(64, db8(2), 0)],
        ));
        let res = rig.run(1);
        assert_eq!(res.routers.len(), 1, "one router destination");
        assert_eq!(res.routers[0].router, RouterId(2));
        assert_eq!(res.routers[0].cost, 10);
        // The hop: our interface 11, R2's link-local, via R2.
        assert_eq!(
            res.routers[0].next_hops,
            vec![NextHopV3 {
                interface_id: 11,
                address: Some(ll(0x22)),
                via: Some(RouterId(2)),
            }],
            "4.8.2: the next hop is the link-local in R2's link-LSA"
        );
        // The prefix route: 10 + 0 metric.
        assert_eq!(res.routes.len(), 1);
        assert_eq!(res.routes[0].prefix.to_string(), "2001:db8:2::/64");
        assert_eq!(res.routes[0].cost, 10);
        assert_eq!(res.routes[0].next_hops, res.routers[0].next_hops);
    }

    #[test]
    fn missing_link_lsa_leaves_the_hop_addressless_with_via() {
        // No link-LSA from R2: the hop keeps `via` so the daemon can
        // fall back to the Hello source (4.8.2's second sentence).
        let mut rig = Rig::new();
        rig.install(router_lsa(1, 0, vec![p2p(11, 22, 2, 10)]));
        rig.install(router_lsa(2, 0, vec![p2p(22, 11, 1, 10)]));
        rig.attach(11, vec![]);
        let res = rig.run(1);
        assert_eq!(
            res.routers[0].next_hops,
            vec![NextHopV3 {
                interface_id: 11,
                address: None,
                via: Some(RouterId(2)),
            }]
        );
    }

    #[test]
    fn multi_hop_path_inherits_the_first_hop() {
        // R1 - R2 - R3: R3's next hop is R2's link-local (inherited).
        let mut rig = Rig::new();
        rig.install(router_lsa(1, 0, vec![p2p(11, 22, 2, 1)]));
        rig.install(router_lsa(2, 0, vec![p2p(22, 11, 1, 1), p2p(23, 33, 3, 4)]));
        rig.install(router_lsa(3, 0, vec![p2p(33, 23, 2, 4)]));
        rig.attach(11, vec![link_lsa(2, 22, ll(0x22))]);
        let res = rig.run(1);
        let r3 = res
            .routers
            .iter()
            .find(|r| r.router == RouterId(3))
            .unwrap();
        assert_eq!(r3.cost, 5);
        assert_eq!(
            r3.next_hops,
            vec![NextHopV3 {
                interface_id: 11,
                address: Some(ll(0x22)),
                via: Some(RouterId(2)),
            }],
            "16.1.1: destinations behind an intervening router inherit"
        );
    }

    #[test]
    fn fragments_concatenate_and_flags_take_the_lowest_lsid() {
        // A.4.3/4.8.1 step 2: R2 originates TWO fragments — its links
        // concatenate, and the V/E/B/Nt bits + Options come ONLY from
        // the fragment with the smallest Link State ID. Setting V on
        // the HIGHER fragment must be ignored.
        let mut rig = Rig::new();
        rig.install(router_lsa(1, 0, vec![p2p(11, 22, 2, 1), p2p(12, 33, 3, 1)]));
        // Fragment 0: the link to R1, flags all clear (the winner).
        let frag0 = router_lsa(2, 0, vec![p2p(22, 11, 1, 1)]);
        // Fragment 1: the link to R3, V-bit set (IGNORED for flags,
        // its LINK still counts).
        let mut frag1 = router_lsa(2, 1, vec![p2p(23, 33, 3, 4)]);
        if let LsaBodyV3::Router(r) = &mut frag1.body {
            r.v_bit = true;
        }
        rig.install(frag0);
        rig.install(frag1);
        rig.install(router_lsa(3, 0, vec![p2p(33, 23, 2, 4)]));
        rig.attach(11, vec![link_lsa(2, 22, ll(0x22))]);
        rig.attach(12, vec![link_lsa(3, 33, ll(0x33))]);
        let res = rig.run(1);
        // R3 reachable THROUGH R2's second fragment's link: 1 + 4.
        let r3 = res
            .routers
            .iter()
            .find(|r| r.router == RouterId(3))
            .expect("R3 reachable through the concatenated fragment link");
        assert_eq!(r3.cost, 5);
        assert_eq!(r3.next_hops[0].interface_id, 11, "through R2's first link");
        // The flags come from fragment 0: no V-bit -> no transit
        // capability, even though fragment 1 sets it.
        assert!(
            !res.transit_capability,
            "the V-bit on the higher-LS-ID fragment is ignored (4.8.1 step 2)"
        );
        assert!(!res.router_flags.get(&RouterId(2)).unwrap().v);
        // And the symmetric shape: V on the LOWEST fragment counts.
        let mut rig2 = Rig::new();
        rig2.install(router_lsa(1, 0, vec![p2p(11, 22, 2, 1)]));
        let mut frag = router_lsa(2, 0, vec![p2p(22, 11, 1, 1)]);
        if let LsaBodyV3::Router(r) = &mut frag.body {
            r.v_bit = true;
        }
        rig2.install(frag);
        rig2.attach(11, vec![link_lsa(2, 22, ll(0x22))]);
        assert!(rig2.run(1).transit_capability);
    }

    #[test]
    fn missing_v6_or_r_bit_router_is_skipped() {
        // 4.8.1 step 2b: R2's options lack the R-bit -> the edge into
        // R2 is ignored entirely.
        let mut rig = Rig::new();
        rig.install(router_lsa(1, 0, vec![p2p(11, 22, 2, 1), p2p(12, 33, 3, 1)]));
        let mut r2 = router_lsa(2, 0, vec![p2p(22, 11, 1, 1)]);
        if let LsaBodyV3::Router(r) = &mut r2.body {
            r.options = Options24(Options24::V6 | Options24::E); // no R
        }
        rig.install(r2);
        rig.install(router_lsa(3, 0, vec![p2p(33, 12, 1, 1)]));
        rig.attach(11, vec![]);
        rig.attach(12, vec![]);
        let res = rig.run(1);
        assert!(
            res.routers.iter().all(|r| r.router != RouterId(2)),
            "the no-R-bit router is not a transit (4.8.1 step 2b)"
        );
        assert!(res.routers.iter().any(|r| r.router == RouterId(3)));
    }

    #[test]
    fn transit_networks_key_on_dr_interface_id_and_router_id() {
        // Two broadcast links whose DRs share Interface ID 5 but are
        // different routers: DISTINCT vertices (4.8.1's vertex ID).
        // R1 sits on both; R2 beyond net A, R3 beyond net B.
        let mut rig = Rig::new();
        rig.install(router_lsa(
            1,
            0,
            vec![
                transit(11, 5, 0x64, 1), // net A: DR iface 5, DR = 100
                transit(12, 5, 0x65, 2), // net B: DR iface 5, DR = 101
            ],
        ));
        rig.install(router_lsa(2, 0, vec![transit(21, 5, 0x64, 3)])); // on A
        rig.install(router_lsa(3, 0, vec![transit(31, 5, 0x65, 4)])); // on B
        rig.install(net_lsa(5, 0x64, &[1, 2]));
        rig.install(net_lsa(5, 0x65, &[1, 3]));
        rig.attach(11, vec![link_lsa(2, 21, ll(0x21))]);
        rig.attach(12, vec![link_lsa(3, 31, ll(0x31))]);
        let res = rig.run(1);
        let r2 = res
            .routers
            .iter()
            .find(|r| r.router == RouterId(2))
            .unwrap();
        let r3 = res
            .routers
            .iter()
            .find(|r| r.router == RouterId(3))
            .unwrap();
        assert_eq!(r2.cost, 1, "net A -> R2 at the root's link cost + 0");
        assert_eq!(r2.next_hops[0].interface_id, 11, "out interface 11 (net A)");
        assert_eq!(
            r2.next_hops[0].address,
            Some(ll(0x21)),
            "R2's link-local on A"
        );
        assert_eq!(r3.cost, 2, "net B -> R3 at the root's link cost + 0");
        assert_eq!(r3.next_hops[0].interface_id, 12, "out interface 12 (net B)");
        assert_eq!(
            r3.next_hops[0].address,
            Some(ll(0x31)),
            "R3's link-local on B — the DR-pair keying kept the links apart"
        );
    }

    #[test]
    fn directly_connected_iapr_prefix_has_no_next_hop_address() {
        // 4.8.2: an IAPR referencing a network-LSA the root sits on —
        // "the next hop is solely the outgoing link and no IPv6
        // next-hop address is selected."
        let mut rig = Rig::new();
        rig.install(router_lsa(1, 0, vec![transit(11, 5, 0x64, 1)]));
        rig.install(router_lsa(2, 0, vec![transit(21, 5, 0x64, 1)]));
        rig.install(net_lsa(5, 0x64, &[1, 2]));
        // R2 (the DR) originates the network's IAPR.
        rig.install(iapr_lsa(
            2,
            0,
            (LsaType::V3_NETWORK, 5, 0x64),
            vec![(64, db8(0xa), 0)],
        ));
        rig.attach(11, vec![link_lsa(2, 21, ll(0x21))]);
        let res = rig.run(1);
        assert_eq!(res.routes.len(), 1);
        assert_eq!(res.routes[0].cost, 1);
        assert_eq!(
            res.routes[0].next_hops,
            vec![NextHopV3 {
                interface_id: 11,
                address: None,
                via: None,
            }],
            "directly connected: no next-hop address (4.8.2)"
        );
    }

    #[test]
    fn nu_bit_prefixes_are_excluded() {
        let mut rig = Rig::new();
        rig.install(router_lsa(1, 0, vec![p2p(11, 22, 2, 1)]));
        rig.install(router_lsa(2, 0, vec![p2p(22, 11, 1, 1)]));
        rig.attach(11, vec![link_lsa(2, 22, ll(0x22))]);
        let mut lsa = iapr_lsa(2, 0, (LsaType::V3_ROUTER, 0, 2), vec![(64, db8(2), 1)]);
        if let LsaBodyV3::IntraAreaPrefix(body) = &mut lsa.body {
            body.prefixes[0].prefix.options = PrefixOptions(PrefixOptions::NU);
        }
        rig.install(lsa);
        let res = rig.run(1);
        assert!(res.routes.is_empty(), "NU-bit prefix excluded (4.8.1)");
    }

    #[test]
    fn equal_cost_prefixes_merge_hops() {
        // Two IAPRs advertising the same prefix at the same cost off
        // two routers: the hops merge (16.1 step 2d lineage).
        let mut rig = Rig::new();
        rig.install(router_lsa(1, 0, vec![p2p(11, 22, 2, 1), p2p(12, 33, 3, 1)]));
        rig.install(router_lsa(2, 0, vec![p2p(22, 11, 1, 1)]));
        rig.install(router_lsa(3, 0, vec![p2p(33, 12, 1, 1)]));
        rig.attach(11, vec![link_lsa(2, 22, ll(0x22))]);
        rig.attach(12, vec![link_lsa(3, 33, ll(0x33))]);
        rig.install(iapr_lsa(
            2,
            0,
            (LsaType::V3_ROUTER, 0, 2),
            vec![(64, db8(7), 1)],
        ));
        rig.install(iapr_lsa(
            3,
            0,
            (LsaType::V3_ROUTER, 0, 3),
            vec![(64, db8(7), 1)],
        ));
        let res = rig.run(1);
        assert_eq!(res.routes.len(), 1, "one merged route");
        assert_eq!(res.routes[0].cost, 2);
        let mut hops = res.routes[0].next_hops.clone();
        hops.sort();
        assert_eq!(hops.len(), 2);
        assert_eq!(hops[0].interface_id, 11);
        assert_eq!(hops[0].address, Some(ll(0x22)));
        assert_eq!(hops[1].interface_id, 12);
        assert_eq!(hops[1].address, Some(ll(0x33)));
    }

    #[test]
    fn one_way_and_maxage_edges_are_dropped() {
        // §16.1 step 2b: R2 claims a link to R1 but R1 has none back.
        let mut rig = Rig::new();
        rig.install(router_lsa(1, 0, vec![]));
        rig.install(router_lsa(2, 0, vec![p2p(22, 11, 1, 5)]));
        rig.attach(11, vec![]);
        assert!(rig.run(1).routers.is_empty());
        // MaxAge: treated as absent.
        let mut rig2 = Rig::new();
        rig2.install(router_lsa(1, 0, vec![p2p(11, 22, 2, 5)]));
        let mut aged = router_lsa(2, 0, vec![p2p(22, 11, 1, 5)]);
        aged.header.ls_age = crate::MAX_AGE;
        rig2.install(aged);
        rig2.attach(11, vec![]);
        assert!(rig2.run(1).routers.is_empty());
    }

    // ---- the brute-force oracle (the spf.rs discipline) ----------

    struct XorShift(u64);
    impl XorShift {
        fn next(&mut self) -> u64 {
            self.0 ^= self.0 << 13;
            self.0 ^= self.0 >> 7;
            self.0 ^= self.0 << 17;
            self.0
        }
    }

    /// One random router's model: its links (the harness splits them
    /// into fragments randomly) and options.
    struct ModelRouter {
        links: Vec<RouterLinkV3>,
        options: Options24,
    }

    /// A generated topology: (model, root index, area LSAs, the
    /// root's (Interface ID, link-LSAs) attachments).
    type RandomTopo = (Vec<ModelRouter>, usize, Vec<LsaV3>, Vec<(u32, Vec<LsaV3>)>);

    /// Random small v3 topology: N routers, symmetric-or-one-way p2p
    /// links, one broadcast network (DR pair (5, 0x64)) with a random
    /// attached subset, random fragment splits.
    fn random_topology(rng: &mut XorShift, n: usize) -> RandomTopo {
        let ifaces: Vec<u32> = (1..=n as u32).map(|i| i * 10).collect();
        let mut model: Vec<ModelRouter> = (0..n)
            .map(|_| ModelRouter {
                links: vec![],
                options: opts_v6(),
            })
            .collect();
        for i in 0..n {
            for j in (i + 1)..n {
                let roll = rng.next() % 10;
                if roll < 4 {
                    let cost = (1 + rng.next() % 9) as u16;
                    model[i]
                        .links
                        .push(p2p(ifaces[i], ifaces[j], (j + 1) as u32, cost));
                    if roll < 3 {
                        model[j]
                            .links
                            .push(p2p(ifaces[j], ifaces[i], (i + 1) as u32, cost));
                    }
                }
            }
        }
        let dr_iface = 5u32;
        let dr_rid = 0x64u32;
        let mut attached: Vec<usize> = Vec::new();
        for i in 0..n {
            if rng.next() % 2 == 1 {
                attached.push(i);
                model[i].links.push(transit(
                    ifaces[i] + 1,
                    dr_iface,
                    dr_rid,
                    (1 + rng.next() % 9) as u16,
                ));
            }
        }
        // Randomly degrade one router's options (the V6/R gate input).
        if n > 1 {
            let i = (rng.next() as usize) % n;
            model[i].options = Options24(Options24::E); // neither V6 nor R
        }
        // Emit the LSAs, splitting links into fragments of 1-2 links
        // (the A.4.3 concatenation input).
        let mut lsas = Vec::new();
        for (i, m) in model.iter().enumerate() {
            let mut chunk = Vec::new();
            let mut lsid = 0u32;
            for link in &m.links {
                chunk.push(link.clone());
                if chunk.len() as u64 == 1 + rng.next() % 2 {
                    let mut lsa = router_lsa((i + 1) as u32, lsid, std::mem::take(&mut chunk));
                    if let LsaBodyV3::Router(r) = &mut lsa.body {
                        r.options = m.options;
                    }
                    lsas.push(lsa);
                    lsid += 1;
                }
            }
            if !chunk.is_empty() || lsid == 0 {
                let mut lsa = router_lsa((i + 1) as u32, lsid, chunk);
                if let LsaBodyV3::Router(r) = &mut lsa.body {
                    r.options = m.options;
                }
                lsas.push(lsa);
            }
        }
        if attached.len() >= 2 {
            lsas.push(net_lsa(
                dr_iface,
                dr_rid,
                &attached.iter().map(|i| (i + 1) as u32).collect::<Vec<_>>(),
            ));
        }
        // The root's attached links (root = router 1, index 0): every
        // DISTINCT own-Interface-ID of the root's links, with the
        // attached routers' link-LSAs in the store.
        let root = 0usize;
        let mut links: Vec<(u32, Vec<LsaV3>)> = Vec::new();
        let mut seen = std::collections::BTreeSet::new();
        for link in &model[root].links {
            let own = link.interface_id;
            if !seen.insert(own) {
                continue;
            }
            let store: Vec<LsaV3> = match link.link_type {
                LinkTypeV3::PointToPoint | LinkTypeV3::Virtual => {
                    vec![link_lsa(
                        link.neighbor_router_id.0,
                        link.neighbor_interface_id,
                        ll(0x80),
                    )]
                }
                LinkTypeV3::Transit => attached
                    .iter()
                    .filter(|i| **i != root)
                    .map(|i| link_lsa((i + 1) as u32, ifaces[*i] + 1, ll(0x80 + *i as u8)))
                    .collect(),
            };
            links.push((own, store));
        }
        (model, root, lsas, links)
    }

    /// Bellman-Ford distances over the same graph the SPF sees: the
    /// concatenated links, the V6/R gate, the DR-pair network key,
    /// and the bidirectionality rules.
    fn oracle_distances(
        model: &[ModelRouter],
        root: usize,
        attached: &[usize],
    ) -> HashMap<VertexV3, u32> {
        let rid_of = |i: usize| RouterId((i + 1) as u32);
        // A network-LSA exists only with >= 2 attached routers (the
        // harness's emission rule) — without one there is no transit
        // vertex on the wire (the p2p edges are unaffected).
        let have_net = attached.len() >= 2;
        let net_key = (5u32, RouterId(0x64));
        let net_attached: Vec<RouterId> = attached.iter().map(|i| rid_of(*i)).collect();
        let mut dist: HashMap<VertexV3, u32> = HashMap::new();
        dist.insert(VertexV3::Router(rid_of(root)), 0);
        let v6r = |m: &ModelRouter| m.options.v6_bit() && m.options.r_bit();
        loop {
            let mut changed = false;
            for i in 0..model.len() {
                let Some(d) = dist.get(&VertexV3::Router(rid_of(i))).copied() else {
                    continue;
                };
                for l in &model[i].links {
                    match l.link_type {
                        LinkTypeV3::PointToPoint | LinkTypeV3::Virtual => {
                            let j = (l.neighbor_router_id.0 - 1) as usize;
                            if j >= model.len() || !v6r(&model[j]) {
                                continue;
                            }
                            let back = model[j].links.iter().any(|b| {
                                matches!(
                                    b.link_type,
                                    LinkTypeV3::PointToPoint | LinkTypeV3::Virtual
                                ) && b.neighbor_router_id == rid_of(i)
                            });
                            if !back {
                                continue;
                            }
                            let nd = d + u32::from(l.metric);
                            if nd
                                < dist
                                    .get(&VertexV3::Router(rid_of(j)))
                                    .copied()
                                    .unwrap_or(u32::MAX)
                            {
                                dist.insert(VertexV3::Router(rid_of(j)), nd);
                                changed = true;
                            }
                        }
                        LinkTypeV3::Transit => {
                            if !have_net
                                || (l.neighbor_interface_id, l.neighbor_router_id) != net_key
                            {
                                continue;
                            }
                            if !net_attached.contains(&rid_of(i)) {
                                continue;
                            }
                            let nd = d + u32::from(l.metric);
                            let key = VertexV3::Network {
                                dr_interface_id: net_key.0,
                                dr_router_id: net_key.1,
                            };
                            if nd < dist.get(&key).copied().unwrap_or(u32::MAX) {
                                dist.insert(key, nd);
                                changed = true;
                            }
                        }
                    }
                }
            }
            let key = VertexV3::Network {
                dr_interface_id: net_key.0,
                dr_router_id: net_key.1,
            };
            if let Some(dn) = dist.get(&key).copied().filter(|_| have_net) {
                for i in attached {
                    if !v6r(&model[*i]) {
                        continue;
                    }
                    let back = model[*i].links.iter().any(|b| {
                        matches!(b.link_type, LinkTypeV3::Transit)
                            && (b.neighbor_interface_id, b.neighbor_router_id) == net_key
                    });
                    if !back {
                        continue;
                    }
                    if dn
                        < dist
                            .get(&VertexV3::Router(rid_of(*i)))
                            .copied()
                            .unwrap_or(u32::MAX)
                    {
                        dist.insert(VertexV3::Router(rid_of(*i)), dn);
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
        let mut rng = XorShift(0x5340_0481_0001_dead);
        for _ in 0..300 {
            let (model, root, lsas, links) = random_topology(&mut rng, 5);
            let mut rig = Rig::new();
            for lsa in &lsas {
                rig.area.install(lsa.clone(), true, 0);
            }
            for (id, store) in &links {
                rig.attach(*id, store.clone());
            }
            let res = rig.run((root + 1) as u32);
            let attached: Vec<usize> = model
                .iter()
                .enumerate()
                .filter(|(_, m)| {
                    m.links
                        .iter()
                        .any(|l| matches!(l.link_type, LinkTypeV3::Transit))
                })
                .map(|(i, _)| i)
                .collect();
            let oracle = oracle_distances(&model, root, &attached);
            for (v, d) in &oracle {
                assert_eq!(
                    res.distances.get(v),
                    Some(d),
                    "vertex {v:?} root {} mismatch (fragments concatenated)",
                    root + 1
                );
            }
            for (v, d) in &res.distances {
                assert_eq!(oracle.get(v), Some(d), "vertex {v:?} not in the oracle");
            }
        }
    }

    #[test]
    fn property_fragments_match_the_single_fragment_form() {
        // The A.4.3 concatenation: splitting one router's links
        // across fragments NEVER changes distances or router routes.
        let mut rng = XorShift(0xca75_ed0f_0ca7_0001);
        for _ in 0..150 {
            let (model, root, lsas, links) = random_topology(&mut rng, 4);
            // The single-fragment rig: every router's links in LS ID 0
            // (plus the network-LSA as-is).
            let mut merged = Rig::new();
            for (i, m) in model.iter().enumerate() {
                let mut lsa = router_lsa((i + 1) as u32, 0, m.links.clone());
                if let LsaBodyV3::Router(r) = &mut lsa.body {
                    r.options = m.options;
                }
                merged.install(lsa);
            }
            for lsa in &lsas {
                if matches!(lsa.body, LsaBodyV3::Network(_)) {
                    merged.install(lsa.clone());
                }
            }
            for (id, store) in &links {
                merged.attach(*id, store.clone());
            }
            // The fragmented rig.
            let mut frag = Rig::new();
            for lsa in &lsas {
                frag.area.install(lsa.clone(), true, 0);
            }
            for (id, store) in &links {
                frag.attach(*id, store.clone());
            }
            let a = merged.run((root + 1) as u32);
            let b = frag.run((root + 1) as u32);
            assert_eq!(a.distances, b.distances, "fragment split changes distances");
            assert_eq!(a.routers, b.routers, "fragment split changes router routes");
        }
    }

    #[test]
    fn property_next_hops_are_min_cost_first_edges() {
        // Every router-destination next hop must be (the root's
        // outgoing Interface ID, the link-local of the first adjacent
        // router) of SOME minimum-cost path, and the set must cover
        // every distinct (interface, first-router) pair — the spf.rs
        // first-edge oracle, adapted to the v3 hop shape.
        let mut rng = XorShift(0xfeed_0c0a_11ce_0002);
        for _ in 0..200 {
            let (model, root, lsas, links) = random_topology(&mut rng, 4);
            let mut rig = Rig::new();
            for lsa in &lsas {
                rig.area.install(lsa.clone(), true, 0);
            }
            for (id, store) in &links {
                rig.attach(*id, store.clone());
            }
            let res = rig.run((root + 1) as u32);
            // (interface, router) -> link-local, from the root's link
            // stores (every root link carries its link-LSAs here).
            let linklocals: HashMap<(u32, RouterId), Ipv6Addr> = links
                .iter()
                .flat_map(|(id, store)| {
                    store.iter().filter_map(move |lsa| {
                        if let LsaBodyV3::Link(body) = &lsa.body {
                            Some((*id, lsa.header.adv_router, body.link_local_address))
                        } else {
                            None
                        }
                    })
                })
                .fold(HashMap::new(), |mut m, (i, r, a)| {
                    m.insert((i, r), a);
                    m
                });
            // Exhaustive simple-path enumeration over the model.
            let rid_of = |i: usize| RouterId((i + 1) as u32);
            let attached: Vec<usize> = model
                .iter()
                .enumerate()
                .filter(|(_, m)| {
                    m.links
                        .iter()
                        .any(|l| matches!(l.link_type, LinkTypeV3::Transit))
                })
                .map(|(i, _)| i)
                .collect();
            let v6r = |m: &ModelRouter| m.options.v6_bit() && m.options.r_bit();
            #[derive(Clone)]
            struct Walk {
                on_net: bool,
                router: usize,
                cost: u32,
                first_if: Option<u32>,
                first_router: Option<RouterId>,
                visited: Vec<usize>,
            }
            let mut best: HashMap<usize, (u32, std::collections::BTreeSet<(u32, RouterId)>)> =
                HashMap::new();
            let mut queue = vec![Walk {
                on_net: false,
                router: root,
                cost: 0,
                first_if: None,
                first_router: None,
                visited: vec![root],
            }];
            while let Some(w) = queue.pop() {
                if !w.on_net {
                    let entry = best
                        .entry(w.router)
                        .or_insert((u32::MAX, Default::default()));
                    if w.cost < entry.0 {
                        *entry = (w.cost, Default::default());
                    }
                    if w.cost == entry.0 {
                        if let (Some(f), Some(r)) = (w.first_if, w.first_router) {
                            entry.1.insert((f, r));
                        }
                    }
                }
                if w.visited.len() > 6 {
                    continue;
                }
                if w.on_net {
                    for j in &attached {
                        if !v6r(&model[*j]) || w.visited.contains(j) {
                            continue;
                        }
                        let back = model[*j].links.iter().any(|b| {
                            matches!(b.link_type, LinkTypeV3::Transit)
                                && b.neighbor_interface_id == 5
                                && b.neighbor_router_id == RouterId(0x64)
                        });
                        if !back {
                            continue;
                        }
                        let mut visited = w.visited.clone();
                        visited.push(*j);
                        queue.push(Walk {
                            on_net: false,
                            router: *j,
                            cost: w.cost, // network -> router is zero
                            first_if: w.first_if,
                            first_router: w.first_router.or(Some(rid_of(*j))),
                            visited,
                        });
                    }
                } else {
                    let i = w.router;
                    for l in &model[i].links {
                        match l.link_type {
                            LinkTypeV3::PointToPoint | LinkTypeV3::Virtual => {
                                let j = (l.neighbor_router_id.0 - 1) as usize;
                                if j >= model.len() || !v6r(&model[j]) || w.visited.contains(&j) {
                                    continue;
                                }
                                let back = model[j].links.iter().any(|b| {
                                    matches!(
                                        b.link_type,
                                        LinkTypeV3::PointToPoint | LinkTypeV3::Virtual
                                    ) && b.neighbor_router_id == rid_of(i)
                                });
                                if !back {
                                    continue;
                                }
                                let mut visited = w.visited.clone();
                                visited.push(j);
                                queue.push(Walk {
                                    on_net: false,
                                    router: j,
                                    cost: w.cost + u32::from(l.metric),
                                    first_if: w.first_if.or(Some(l.interface_id)),
                                    first_router: w.first_router.or(Some(l.neighbor_router_id)),
                                    visited,
                                });
                            }
                            LinkTypeV3::Transit => {
                                if !attached.contains(&i) {
                                    continue;
                                }
                                queue.push(Walk {
                                    on_net: true,
                                    router: i,
                                    cost: w.cost + u32::from(l.metric),
                                    // The FIRST edge only (an inner
                                    // transit hop never re-sets it).
                                    first_if: w.first_if.or(Some(l.interface_id)),
                                    first_router: w.first_router,
                                    visited: w.visited.clone(),
                                });
                            }
                        }
                    }
                }
            }
            // Compare against the SPF router routes.
            for route in &res.routers {
                let i = (route.router.0 - 1) as usize;
                let Some((cost, firsts)) = best.get(&i) else {
                    panic!("route to {} but no enumerated path", route.router.0);
                };
                assert_eq!(route.cost, *cost, "cost to router {}", route.router.0);
                let got: std::collections::BTreeSet<(u32, Option<Ipv6Addr>)> = route
                    .next_hops
                    .iter()
                    .map(|h| (h.interface_id, h.address))
                    .collect();
                let want: std::collections::BTreeSet<(u32, Option<Ipv6Addr>)> = firsts
                    .iter()
                    .map(|(iface, router)| (*iface, linklocals.get(&(*iface, *router)).copied()))
                    .collect();
                assert_eq!(
                    got, want,
                    "first-edge set to router {}: got {:?} want {:?}",
                    route.router.0, got, want
                );
            }
        }
    }
}
