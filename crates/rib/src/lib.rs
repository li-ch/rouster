//! The Routing Information Base.
//!
//! BIRD-style typed multi-table core (see docs/architecture.md): tables are
//! first-class objects; best-path selection uses administrative distance then
//! metric; the selected route is what gets programmed into the dataplane.

use std::cmp::Reverse;
use std::collections::{BTreeMap, BTreeSet};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use common::{
    Dataplane, DataplaneEvent, IpPrefix, Ipv4Prefix, Ipv6Prefix, NeighbourEntry, Nexthop,
    NexthopGroup, RouteEntry, RouteProtocol, TableId,
};
use tracing::{debug, info, instrument, warn};

/// PERF-P2's CPU-census phase timers (feature `cpu-census`; a no-op
/// without it, runtime-inert unless `ROUSTERD_CPU_CENSUS=1`).
pub mod cpucensus;

/// Observed state of one network interface, mirrored from the dataplane.
#[derive(Debug, Clone, Default)]
pub struct InterfaceState {
    pub name: String,
    pub is_up: bool,
    /// The kernel's `ifi_flags` word as last reported by the dataplane
    /// (`common::LinkFlags`: UP, RUNNING, BROADCAST, MULTICAST, LOOPBACK,
    /// …, unnamed bits retained). `is_up` stays the consumed signal for
    /// resolution/reconcile; the bits serve consumers that gate on them
    /// (ZAPI's interface mirror, the driver's loopback detection).
    pub flags: common::LinkFlags,
    /// Addresses configured on the interface (as host prefixes).
    pub addresses: Vec<IpPrefix>,
    /// Routing table bound to the interface when it is a VRF device (link
    /// kind "vrf"); `None` for every other link.
    pub vrf_table: Option<TableId>,
    /// Ifindex of the master device this interface is enslaved to (e.g. a
    /// VRF device); `None` when unenslaved.
    pub master_ifindex: Option<u32>,
}

/// One routing table. `TableId` follows Linux numbering (254 = main).
#[derive(Debug, Default)]
pub struct Table {
    /// All candidate routes per prefix, from every protocol.
    entries: BTreeMap<IpPrefix, Vec<RouteEntry>>,
}

impl Table {
    /// Offer a route to the table. Replaces any existing route from the same
    /// protocol with the same prefix.
    pub fn add(&mut self, entry: RouteEntry) {
        let candidates = self.entries.entry(entry.prefix).or_default();
        candidates.retain(|e| e.protocol != entry.protocol);
        candidates.push(entry);
    }

    /// Withdraw all routes of `protocol` for `prefix`. Returns true if any
    /// route was withdrawn.
    pub fn remove(&mut self, prefix: &IpPrefix, protocol: common::RouteProtocol) -> bool {
        let Some(candidates) = self.entries.get_mut(prefix) else {
            return false;
        };
        let before = candidates.len();
        candidates.retain(|e| e.protocol != protocol);
        let removed = candidates.len() != before;
        if candidates.is_empty() {
            self.entries.remove(prefix);
        }
        removed
    }

    /// The selected best route for a prefix: lowest administrative distance,
    /// then lowest metric.
    pub fn best(&self, prefix: &IpPrefix) -> Option<&RouteEntry> {
        self.entries
            .get(prefix)?
            .iter()
            .min_by_key(|e| (e.protocol.admin_distance(), e.metric))
    }

    pub fn iter(&self) -> impl Iterator<Item = (&IpPrefix, &Vec<RouteEntry>)> {
        self.entries.iter()
    }
}

/// The RIB: a set of typed routing tables, a mirror of the kernel FIB, and
/// mirrored interface/neighbour state.
///
/// TODO(phase-1): redistribution channels between tables (BIRD-style).
#[derive(Debug, Default)]
pub struct Rib {
    tables: BTreeMap<TableId, Table>,
    /// Kernel FIB mirror: kernel-origin routes observed on the dataplane
    /// (the ones Rouster did not program). Kept separate from `tables` so
    /// best-path selection never mixes observed state with protocol state.
    kernel_mirror: BTreeMap<TableId, Table>,
    /// What this RIB last programmed into the dataplane, keyed by
    /// (table, prefix). Reconcile diffs desired state against this. Values
    /// are the *resolved programming forms* (gateway hops rewritten to
    /// ifindex-carrying form), so a resolution change re-replaces the route.
    programmed: BTreeMap<(TableId, IpPrefix), RouteEntry>,
    /// Interface state mirrored from dataplane events, keyed by ifindex.
    interfaces: BTreeMap<u32, InterfaceState>,
    /// The CONNECT protocol table set: connected routes derived from the
    /// interface mirror ([`Rib::sync_connected`]), keyed like `tables`.
    /// Kept separate from the per-protocol tables — connected state is
    /// kernel-origin (the address lifecycle installs it), and the
    /// redistribute/best-path surfaces consume it through the explicit
    /// merged queries ([`Rib::best_with_connected`],
    /// [`Rib::connected_table`], [`Rib::connected_keys`]).
    connected: BTreeMap<TableId, Table>,
    /// Kernel neighbour (ARP/NDP) mirror, keyed by the kernel's neighbour
    /// identity (destination ip, link ifindex). Observed state only —
    /// neighbours are never programmed ([`Rib::lookup_neighbour`] is the
    /// read surface; nothing in reconcile touches this table).
    neighbours: BTreeMap<(IpAddr, u32), NeighbourEntry>,
    /// Nexthop-tracking (NHT) table, FRR-zebra-style: every gateway IP
    /// referenced by a protocol route (unresolved `Ipv4`/`Ipv6` hops) mapped
    /// to its current resolution — `None` means tracked but currently
    /// unresolved. This is bookkeeping for the query surface
    /// ([`Rib::lookup_nexthop`], [`Rib::unresolved_gateways`]); the
    /// reconcile path resolves fresh from the interface mirror so it is
    /// never stale. The key set is rebuilt from the protocol tables on
    /// interface events and config reloads, and extended incrementally by
    /// [`Rib::add_route`]; routes withdrawn through [`Rib::table_mut`] are
    /// picked up at the next rebuild.
    nht: BTreeMap<IpAddr, Option<Nexthop>>,
}

/// Linux main table (RT_TABLE_MAIN) — the table the routed NHT lookup
/// answers from (A23).
pub const MAIN_TABLE: TableId = 254;

impl Rib {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn table_mut(&mut self, id: TableId) -> &mut Table {
        self.tables.entry(id).or_default()
    }

    pub fn table(&self, id: TableId) -> Option<&Table> {
        self.tables.get(&id)
    }

    /// Mirrored interface state (ifindex → state).
    pub fn interfaces(&self) -> &BTreeMap<u32, InterfaceState> {
        &self.interfaces
    }

    /// Mirrored kernel neighbours, keyed by (destination ip, link ifindex).
    pub fn neighbours(&self) -> &BTreeMap<(IpAddr, u32), NeighbourEntry> {
        &self.neighbours
    }

    /// Neighbour mirror query: the current kernel entry for `ip` on
    /// `link_ifindex`, if any. `None` = no such neighbour (never observed,
    /// or deleted).
    pub fn lookup_neighbour(&self, ip: IpAddr, link_ifindex: u32) -> Option<&NeighbourEntry> {
        self.neighbours.get(&(ip, link_ifindex))
    }

    /// One mirrored kernel table (observation only; never a reconcile input).
    pub fn kernel_table(&self, id: TableId) -> Option<&Table> {
        self.kernel_mirror.get(&id)
    }

    /// The VRF device that owns `table`, as `(ifindex, mirrored state)`,
    /// when a mirrored link of kind VRF is bound to that table. This is
    /// the route→VRF association: [`TableId`]s already ride on every
    /// route and mirror entry (P0D); this query adds the device link, so
    /// "routes in table N" answers "routes in VRF vrf-test". Derived from
    /// the interface mirror (no second source of truth): a LinkDel of the
    /// VRF device drops the association immediately.
    pub fn vrf_of_table(&self, table: TableId) -> Option<(u32, &InterfaceState)> {
        self.interfaces
            .iter()
            .find(|(_, iface)| iface.vrf_table == Some(table))
            .map(|(&ifindex, iface)| (ifindex, iface))
    }

    /// Total number of mirrored kernel routes, across tables.
    pub fn kernel_route_count(&self) -> usize {
        self.kernel_mirror.values().map(|t| t.iter().count()).sum()
    }

    /// Every (table, prefix) key holding a Connected candidate — the exact
    /// surface a link/address event can change (the driver snapshots bests
    /// over these keys around such events so the redistribute fan-out
    /// covers precisely the prefixes connected-table sync can touch).
    pub fn connected_keys(&self) -> impl Iterator<Item = (TableId, IpPrefix)> + '_ {
        self.connected.iter().flat_map(|(&table_id, table)| {
            table
                .iter()
                .filter(|(_, candidates)| {
                    candidates
                        .iter()
                        .any(|e| e.protocol == RouteProtocol::Connected)
                })
                .map(move |(prefix, _)| (table_id, *prefix))
        })
    }

    /// The CONNECT table of one routing table id — the connected routes
    /// derived from the interface mirror (observation only, never a
    /// reconcile input).
    pub fn connected_table(&self, id: TableId) -> Option<&Table> {
        self.connected.get(&id)
    }

    /// The best route for `prefix` with the CONNECT table participating:
    /// a connected candidate wins at distance 0 (zebra semantics —
    /// nothing outranks a connected prefix), otherwise the protocol
    /// table's best answers. This merged view is the redistribute
    /// surface; [`Rib::table`] alone stays protocol-candidates-only.
    pub fn best_with_connected(&self, id: TableId, prefix: &IpPrefix) -> Option<RouteEntry> {
        self.connected
            .get(&id)
            .and_then(|t| t.best(prefix))
            .cloned()
            .or_else(|| self.table(id).and_then(|t| t.best(prefix)).cloned())
    }

    /// Rebuilds the CONNECT protocol table from the interface mirror:
    /// every address on every UP interface becomes a Connected route for
    /// its network prefix (nexthop = the interface), placed in the main
    /// table — or in the table of the VRF device the interface is enslaved
    /// to, matching where the kernel itself puts the route (W4 observed
    /// an enslaved member's connected route in the VRF's table, not 254).
    ///
    /// This is the zebra-faithful `ZEBRA_ROUTE_CONNECT` view:
    /// `redistribute connected` dumps it, and its candidates win
    /// best-path selection at distance 0 through
    /// [`Rib::best_with_connected`]. The routes live in a DEDICATED table
    /// set (not mixed into the per-protocol tables): connected state is
    /// kernel-origin (`RouteProtocol::is_kernel_origin` — the kernel
    /// installs each connected route as a product of the address
    /// lifecycle, `proto kernel scope link src <addr>`), so reconcile
    /// never programs it and the protocol-candidate tables stay free of
    /// observed state. Real zebra likewise leaves the kernel's own
    /// connected routes untouched (`ip route` on an FRR box shows them
    /// as `proto kernel`, never `proto zebra`).
    fn sync_connected(&mut self) {
        // Desired state, keyed (table, prefix); the lowest ifindex wins a
        // same-prefix tie so the rebuild is deterministic.
        let mut desired: BTreeMap<(TableId, IpPrefix), u32> = BTreeMap::new();
        for (&ifindex, iface) in &self.interfaces {
            if !iface.is_up {
                continue;
            }
            let table = iface
                .master_ifindex
                .and_then(|master| {
                    self.interfaces
                        .get(&master)
                        .and_then(|master_iface| master_iface.vrf_table)
                })
                .unwrap_or(MAIN_TABLE);
            for &prefix in &iface.addresses {
                let key = (table, network_prefix(prefix));
                desired
                    .entry(key)
                    .and_modify(|ix| *ix = (*ix).min(ifindex))
                    .or_insert(ifindex);
            }
        }
        // Withdraw Connected candidates that are no longer desired.
        let stale: Vec<(TableId, IpPrefix)> = self
            .connected_keys()
            .filter(|key| !desired.contains_key(key))
            .collect();
        for (table_id, prefix) in stale {
            if let Some(table) = self.connected.get_mut(&table_id) {
                table.remove(&prefix, RouteProtocol::Connected);
            }
        }
        // (Re)install the desired set; `Table::add` replaces a same-prefix
        // candidate so an ifindex change lands in one step.
        for ((table_id, prefix), ifindex) in desired {
            let mut entry = RouteEntry::new(
                prefix,
                RouteProtocol::Connected,
                NexthopGroup::single(Nexthop::IfIndex(ifindex)),
                0,
            );
            entry.table = table_id;
            self.connected.entry(table_id).or_default().add(entry);
        }
    }

    /// Resolve a gateway against the connected prefixes derived from the
    /// interface mirror (direct, single-hop resolution only).
    ///
    /// A gateway resolves when some UP interface carries an address whose
    /// prefix (address + prefix-len as a network) contains the gateway;
    /// longest prefix wins, ties break to the lowest ifindex (the mirror is
    /// keyed by ifindex, so this is deterministic). The resolved form
    /// carries the ifindex: `Ipv4(g) → Ipv4If(g, ix)`. Address families
    /// must match. `None` means the gateway is not directly reachable —
    /// routes using it are held in the RIB but not programmed
    /// (see [`Rib::reconcile`]).
    ///
    /// This is the DIRECT surface: on-link only. The routing consumer
    /// ([`Rib::resolve_nexthop_recursive`]) additionally walks the route
    /// tables for multi-hop chains; this plain form stays conservative
    /// so egress-derivation consumers (the SAV SIB ingest) keep a
    /// connectivity-check answer that does not depend on route state.
    pub fn resolve_nexthop(&self, gw: IpAddr) -> Option<Nexthop> {
        self.resolve_on_link(gw)
    }

    /// The routing-consumer resolver: on-link first, then the
    /// multi-hop walk of [`Rib::covering_route`] — a gateway reachable
    /// only through another route resolves through that route's own next
    /// hop, chaining until the chain lands on-link (FRR `nexthop_active`,
    /// frr-10.2.2 `zebra/zebra_nhg.c`). Cycles terminate the chain
    /// unresolved; so do a blackhole candidate and a candidate whose own
    /// gateway is held (see [`Rib::covering_route`] for the walk's exact
    /// scope and disclosed deviations). This is what reconcile's
    /// programming form, the NHT tracking table, and the ZAPI
    /// NEXTHOP_UPDATE answers resolve through.
    pub fn resolve_nexthop_recursive(&self, gw: IpAddr) -> Option<Nexthop> {
        self.resolve_with_visited(gw, &mut BTreeSet::new())
    }

    /// The on-link arm of resolution: the longest address-mirror prefix on
    /// an UP interface containing `gw` (direct, single-hop).
    fn resolve_on_link(&self, gw: IpAddr) -> Option<Nexthop> {
        let mut best: Option<(u8, u32)> = None;
        for (&ifindex, iface) in &self.interfaces {
            if !iface.is_up {
                continue;
            }
            for &prefix in &iface.addresses {
                let matched_len = match (prefix, gw) {
                    (IpPrefix::V4(p), IpAddr::V4(a)) if p.contains(a) => Some(p.prefix_len()),
                    (IpPrefix::V6(p), IpAddr::V6(a)) if p.contains(a) => Some(p.prefix_len()),
                    _ => None,
                };
                if let Some(len) = matched_len {
                    if best.is_none_or(|(best_len, _)| len > best_len) {
                        best = Some((len, ifindex));
                    }
                }
            }
        }
        best.map(|(_, ifindex)| match gw {
            IpAddr::V4(a) => Nexthop::Ipv4If(a, ifindex),
            IpAddr::V6(a) => Nexthop::Ipv6If(a, ifindex),
        })
    }

    /// Resolution with a visited set (the recursion's cycle guard: a chain
    /// that revisits a gateway terminates unresolved). On-link first, then
    /// one walk candidate — see [`Rib::covering_route`].
    fn resolve_with_visited(&self, gw: IpAddr, visited: &mut BTreeSet<IpAddr>) -> Option<Nexthop> {
        if let Some(hop) = self.resolve_on_link(gw) {
            return Some(hop);
        }
        if !visited.insert(gw) {
            return None; // cycle: gateway already on this chain
        }
        let candidate = self.covering_route(gw)?;
        match candidate.nexthops.hops().first() {
            // A device route adopts its ifindex for the gateway (FRR's
            // connected-match behavior, `zebra_nhg_connected_ifindex` in
            // the frr-10.2.2 source fetched 2026-10-10).
            Some((Nexthop::IfIndex(ifindex), _)) => Some(match gw {
                IpAddr::V4(a) => Nexthop::Ipv4If(a, *ifindex),
                IpAddr::V6(a) => Nexthop::Ipv6If(a, *ifindex),
            }),
            // Already ifindex-carrying: the matched route's own hop IS the
            // resolution (the observed gateway on the observed device).
            Some((hop @ (Nexthop::Ipv4If(..) | Nexthop::Ipv6If(..)), _)) => Some(*hop),
            // A blackhole match terminates the chain unresolved — the
            // gateway's traffic would be dropped, and rewriting a
            // `via <gw>` route into a blackhole would silently change its
            // forwarding semantics.
            Some((Nexthop::Blackhole, _)) => None,
            // A bare gateway recurses one level deeper.
            Some((Nexthop::Ipv4(next), _)) => self.resolve_with_visited(IpAddr::V4(*next), visited),
            Some((Nexthop::Ipv6(next), _)) => self.resolve_with_visited(IpAddr::V6(*next), visited),
            // No usable hop: the candidate itself is held (its gateway
            // never resolved). Held terminates the chain unresolved.
            None => None,
        }
    }

    /// The best non-default route covering `ip`, across the main table's
    /// three candidate sources — the per-protocol tables, the CONNECT
    /// table, and the kernel FIB mirror — chosen by longest prefix, then
    /// lowest (admin distance, metric). This mirrors zebra's RIB walk for
    /// nexthop resolution (`nexthop_active`, frr-10.2.2 `zebra/zebra_nhg.c`:
    /// a matched route's nexthops drive the resolution, connected matches
    /// adopt the ifindex, kernel/system matches count when the interface
    /// is up), with two disclosed deviations:
    ///
    /// 1. **No fall-through.** Exactly one candidate is consulted (the
    ///    best covering one); if its resolution fails (held/blackhole),
    ///    the walk does NOT continue to shorter prefixes — zebra's
    ///    `route_node_match` walks up the trie on an unusable node. The
    ///    single-candidate form is deterministic and pins the
    ///    held/blackhole-terminate semantics the mission names.
    /// 2. **The default prefix never answers this walk.** FRR gates the
    ///    default prefix on the registration's
    ///    `ZEBRA_NHT_RESOLVE_VIA_DEFAULT` flag (`zebra_rnh.c`, pinned in
    ///    docs/interop/zapi-10.2-pinned.md); Rouster applies that gate to
    ///    the whole resolver — the programming form and the NHT answer
    ///    can never disagree, and a gateway can only recurse into a
    ///    default route through the explicit flag-set surface
    ///    ([`Rib::lookup_nexthop_routed`]). FRR's route-nexthop recursion
    ///    itself is not so restricted; this is the conservative choice.
    fn covering_route(&self, ip: IpAddr) -> Option<&RouteEntry> {
        let sources = [
            self.tables.get(&MAIN_TABLE),
            self.connected.get(&MAIN_TABLE),
            self.kernel_mirror.get(&MAIN_TABLE),
        ];
        let mut candidates: Vec<(u8, &RouteEntry)> = Vec::new();
        for table in sources.into_iter().flatten() {
            for (prefix, _) in table.iter() {
                let len = match (prefix, ip) {
                    (IpPrefix::V4(p), IpAddr::V4(a)) if p.contains(a) => p.prefix_len(),
                    (IpPrefix::V6(p), IpAddr::V6(a)) if p.contains(a) => p.prefix_len(),
                    _ => continue,
                };
                // The default prefix never answers this walk (deviation 2).
                if len == 0 {
                    continue;
                }
                if let Some(best) = table.best(prefix) {
                    candidates.push((len, best));
                }
            }
        }
        candidates
            .into_iter()
            .max_by_key(|&(len, entry)| {
                (
                    len,
                    Reverse(entry.protocol.admin_distance()),
                    Reverse(entry.metric),
                )
            })
            .map(|(_, entry)| entry)
    }

    /// NHT query API — the stable surface the ZAPI server answers
    /// `NEXTHOP_UPDATE` from: the resolved hop for an arbitrary IP (not
    /// just tracked gateways), computed by
    /// [`Rib::resolve_nexthop_recursive`] (on-link, then the routed
    /// walk). `None` = unresolved.
    pub fn lookup_nexthop(&self, ip: IpAddr) -> Option<Nexthop> {
        self.resolve_nexthop_recursive(ip)
    }

    // (Historic: `confirm_neighbour` — the M3 neighbour-liveness gate —
    // was removed by the 2026-10-10 owner decision. Zebra-faithful NHT:
    // `nexthop_active` consults no neighbour table; the gate deadlocked
    // quiescent iBGP cold-start. Rationale: the interop doc's dated
    // amendment.)

    /// NHT query with the routing-table fallback zebra's RNH resolution
    /// has (`zebra_rnh_resolve_nexthop_entry` matches the RIB tables, not
    /// just connected prefixes): the routed walk of
    /// [`Rib::resolve_nexthop`] (on-link first, then non-default route
    /// candidates), plus the default-prefix arm gated on the client's
    /// `resolve_via_default` registration flag — the semantic ospfd sets
    /// for its NSSA default import check (`area <id> nssa
    /// default-information-originate` registers 0.0.0.0/0). Zebra lets
    /// the default prefix answer exactly flag-set registrations
    /// (`zebra_rnh.c`, pinned in docs/interop/zapi-10.2-pinned.md);
    /// flag-unset clients (staticd's gateway NHT, bgpd's neighbor NHT —
    /// both pinned fixtures send 0) never resolve through a default
    /// route. A matched default answers with its own observed hop; a
    /// bare-gateway hop recurses through the full resolver.
    ///
    /// Deliberately zebra-faithful (owner decision 2026-10-10): frr-10.2.2's
    /// `nexthop_active` (`zebra/zebra_nhg.c`) consults NO neighbour table,
    /// and neither do we — neighbour state is advisory only (mirror, logs,
    /// savd monitor). The M3 neighbour-confirmation gate was reverted for
    /// exactly this equivalence; the historic rationale lives in the
    /// interop doc's dated amendment.
    pub fn lookup_nexthop_routed(&self, ip: IpAddr, resolve_via_default: bool) -> Option<Nexthop> {
        if let Some(hop) = self.resolve_nexthop_recursive(ip) {
            return Some(hop);
        }
        if !resolve_via_default {
            return None;
        }
        // Main table only: NHT registrations are default-VRF today (the
        // ZAPI edge drops non-default-VRF routes for the same reason).
        let mirror = self.kernel_mirror.get(&MAIN_TABLE)?;
        let mut best: Option<(u8, &RouteEntry)> = None;
        for (_, candidates) in mirror.iter() {
            for entry in candidates {
                let matched = match (entry.prefix, ip) {
                    (IpPrefix::V4(p), IpAddr::V4(a)) if p.contains(a) => p.prefix_len(),
                    (IpPrefix::V6(p), IpAddr::V6(a)) if p.contains(a) => p.prefix_len(),
                    _ => continue,
                };
                if best.is_none_or(|(len, _)| matched > len) {
                    best = Some((matched, entry));
                }
            }
        }
        best.and_then(|(_, entry)| entry.nexthops.hops().first().map(|&(hop, _)| hop))
            .and_then(|hop| match hop {
                // A device-route adoption answers as-is; a gateway hop
                // answers as-is (zebra-faithful: no neighbour consult).
                Nexthop::IfIndex(_) | Nexthop::Blackhole => Some(hop),
                // A gateway hop recurses through the full resolver.
                Nexthop::Ipv4If(_, _) | Nexthop::Ipv6If(_, _) => Some(hop),
                // Bare gateway: full recursion through the resolver.
                Nexthop::Ipv4(g) => self.resolve_nexthop_recursive(IpAddr::V4(g)),
                Nexthop::Ipv6(g) => self.resolve_nexthop_recursive(IpAddr::V6(g)),
            })
    }

    /// Gateway IPs currently tracked by nexthop tracking but unresolved.
    /// ZAPI re-evaluates exactly these when interface events arrive and
    /// fans the answers out as `NEXTHOP_UPDATE` messages.
    pub fn unresolved_gateways(&self) -> impl Iterator<Item = IpAddr> + '_ {
        self.nht
            .iter()
            .filter_map(|(gw, resolution)| resolution.is_none().then_some(*gw))
    }

    /// Recomputes the NHT table: keys = gateway IPs referenced by protocol
    /// routes across all tables, values = current resolution. Runs on
    /// interface events and config reloads.
    fn rebuild_nht(&mut self) {
        let gateways: BTreeSet<IpAddr> = self
            .tables
            .values()
            .flat_map(|table| {
                table.iter().flat_map(|(_, candidates)| {
                    candidates.iter().flat_map(|e| gateway_ips(&e.nexthops))
                })
            })
            .collect();
        let nht = gateways
            .into_iter()
            .map(|gw| {
                let resolution = self.resolve_nexthop_recursive(gw);
                (gw, resolution)
            })
            .collect();
        self.nht = nht;
    }

    /// The programming form of a route: gateway hops rewritten to their
    /// resolved (ifindex-carrying) form and unresolved gateways dropped;
    /// `Blackhole`, `IfIndex`, and explicit-if hops are always eligible.
    /// `None` when no eligible hop remains — the route is held in the RIB
    /// but must not be programmed (an unresolved gateway handed to netlink
    /// verbatim gets rejected or misrouted).
    ///
    /// ECMP groups program their resolved subset; weights are preserved.
    fn resolved_programming_form(&self, entry: &RouteEntry) -> Option<RouteEntry> {
        let mut resolved = NexthopGroup::new();
        for &(hop, weight) in entry.nexthops.hops() {
            let hop = match hop {
                Nexthop::Ipv4(g) => match self.resolve_nexthop_recursive(IpAddr::V4(g)) {
                    Some(resolved_hop) => resolved_hop,
                    // Unresolved gateway: excluded from the programmed
                    // subset; if it was the only hop, the group is empty
                    // and the route is not programmed at all.
                    None => continue,
                },
                Nexthop::Ipv6(g) => match self.resolve_nexthop_recursive(IpAddr::V6(g)) {
                    Some(resolved_hop) => resolved_hop,
                    None => continue,
                },
                Nexthop::Blackhole
                | Nexthop::IfIndex(_)
                | Nexthop::Ipv4If(..)
                | Nexthop::Ipv6If(..) => hop,
            };
            resolved.add(hop, weight);
        }
        if resolved.is_empty() {
            return None;
        }
        let mut form = entry.clone();
        form.nexthops = resolved;
        Some(form)
    }

    /// Apply one dataplane event to the mirrored state.
    ///
    /// Address events for an interface we have not seen yet create a
    /// placeholder entry: kernel notification order is not guaranteed to
    /// put RTM_NEWLINK before RTM_NEWADDR.
    ///
    /// Link and address events can change gateway resolution, so each one
    /// re-runs nexthop tracking over all protocol routes. The caller is
    /// expected to follow with a reconcile pass (rousterd reconciles on
    /// every dataplane event).
    pub fn apply_event(&mut self, ev: &DataplaneEvent) {
        match ev {
            DataplaneEvent::LinkNew {
                ifindex,
                name,
                is_up,
                flags,
                vrf_table,
                master_ifindex,
            } => {
                let iface = self.interfaces.entry(*ifindex).or_default();
                iface.name = name.clone();
                iface.is_up = *is_up;
                // Each RTM_NEWLINK carries the link's full state: the VRF
                // fields and the flags word all overwrite unconditionally,
                // so (un)enslaving, re-binding a device, or flapping its
                // bits is reflected on the next notification.
                iface.flags = *flags;
                iface.vrf_table = *vrf_table;
                iface.master_ifindex = *master_ifindex;
                self.sync_connected();
                self.rebuild_nht();
            }
            DataplaneEvent::LinkDel { ifindex } => {
                self.interfaces.remove(ifindex);
                self.sync_connected();
                self.rebuild_nht();
            }
            DataplaneEvent::AddressNew { ifindex, prefix } => {
                let iface = self.interfaces.entry(*ifindex).or_default();
                if !iface.addresses.contains(prefix) {
                    iface.addresses.push(*prefix);
                }
                self.sync_connected();
                self.rebuild_nht();
            }
            DataplaneEvent::AddressDel { ifindex, prefix } => {
                if let Some(iface) = self.interfaces.get_mut(ifindex) {
                    iface.addresses.retain(|p| p != prefix);
                }
                self.sync_connected();
                self.rebuild_nht();
            }
            DataplaneEvent::RouteNew {
                table,
                prefix,
                protocol,
                metric,
                gateway,
                oif,
            } => {
                // Backends already filter self-originated notifications;
                // this is the second half of the feedback-loop defense.
                if !protocol.is_kernel_origin() {
                    return;
                }
                // Observed nexthop detail from the event: gateway+oif →
                // the ifindex-carrying form, gateway alone → bare gateway,
                // oif alone → device route. Never programmed — mirror
                // state only — but the NHT answer path resolves through
                // it (A23: ospfd's default-route import check).
                let mut nexthops = NexthopGroup::new();
                match (*gateway, *oif) {
                    (Some(g), Some(ix)) => nexthops.add(
                        match g {
                            IpAddr::V4(a) => Nexthop::Ipv4If(a, ix),
                            IpAddr::V6(a) => Nexthop::Ipv6If(a, ix),
                        },
                        1,
                    ),
                    (Some(g), None) => nexthops.add(
                        match g {
                            IpAddr::V4(a) => Nexthop::Ipv4(a),
                            IpAddr::V6(a) => Nexthop::Ipv6(a),
                        },
                        1,
                    ),
                    (None, Some(ix)) => nexthops.add(Nexthop::IfIndex(ix), 1),
                    (None, None) => {}
                }
                let mut entry = RouteEntry::new(*prefix, RouteProtocol::Kernel, nexthops, *metric);
                entry.table = *table;
                self.kernel_mirror.entry(*table).or_default().add(entry);
            }
            DataplaneEvent::RouteDel { table, prefix } => {
                if let Some(mirror) = self.kernel_mirror.get_mut(table) {
                    mirror.remove(prefix, RouteProtocol::Kernel);
                }
                // The kernel no longer has this route, whoever removed it.
                // Drop our programmed-set belief so a still-desired route
                // is reinstalled on the next reconcile pass.
                self.programmed.remove(&(*table, *prefix));
            }
            DataplaneEvent::NeighbourNew { entry } => {
                // Insert-or-replace: the kernel emits RTM_NEWNEIGH for both
                // creation and state/lladdr updates.
                self.neighbours
                    .insert((entry.ip, entry.link_ifindex), entry.clone());
            }
            DataplaneEvent::NeighbourDel { ip, link_ifindex } => {
                self.neighbours.remove(&(*ip, *link_ifindex));
            }
        }
    }

    /// Offer a route and return whether the best route for its prefix changed.
    ///
    /// Gateway nexthops of the new route enter nexthop tracking immediately.
    pub fn add_route(&mut self, entry: RouteEntry) {
        let _census = cpucensus::scope(&cpucensus::RIB_ADD_ROUTE);
        let table_id = entry.table;
        for gw in gateway_ips(&entry.nexthops) {
            let resolved = self.resolve_nexthop_recursive(gw);
            self.nht.entry(gw).or_insert(resolved);
        }
        self.table_mut(table_id).add(entry);
    }

    /// Every (table, prefix) key holding a static-protocol candidate —
    /// the exact surface a config reload can withdraw. The RIB driver
    /// snapshots bests over these keys plus the incoming ones so its
    /// redistribute fan-out covers precisely the prefixes a reload can
    /// touch.
    pub fn static_keys(&self) -> impl Iterator<Item = (TableId, IpPrefix)> + '_ {
        self.tables.iter().flat_map(|(&table_id, table)| {
            table
                .iter()
                .filter(|(_, candidates)| {
                    candidates
                        .iter()
                        .any(|e| e.protocol == RouteProtocol::Static)
                })
                .map(move |(prefix, _)| (table_id, *prefix))
        })
    }

    /// Replaces the static-protocol routes derived from configuration.
    ///
    /// Prefixes present before and absent now are withdrawn; new prefixes
    /// are added; unchanged ones keep their candidate state (soft
    /// reconfiguration — nothing bounces). A subsequent reconcile pass
    /// removes vanished prefixes from the kernel.
    pub fn reload_static(&mut self, routes: &[RouteEntry]) {
        let fresh: std::collections::BTreeSet<(TableId, IpPrefix)> =
            routes.iter().map(|r| (r.table, r.prefix)).collect();
        let vanished: Vec<(TableId, IpPrefix)> = self
            .static_keys()
            .filter(|key| !fresh.contains(key))
            .collect();
        for (table_id, prefix) in vanished {
            if let Some(table) = self.tables.get_mut(&table_id) {
                table.remove(&prefix, RouteProtocol::Static);
            }
        }
        for route in routes {
            self.add_route(route.clone());
        }
        // Withdrawn prefixes may leave gateways unreferenced; prune them so
        // the tracking surface stays exact across reloads.
        self.rebuild_nht();
    }

    /// Program the desired forwarding state into the dataplane, diff-based.
    ///
    /// Desired = best route per prefix across the protocol tables (never
    /// the kernel mirror), in resolved programming form: gateway hops are
    /// rewritten to ifindex-carrying form and a best route with no resolved
    /// hop is NOT desired — it stays in the RIB and is withdrawn from the
    /// kernel until its gateway re-resolves. The diff runs against what
    /// this RIB last programmed (also in resolved form, so a resolution
    /// change re-replaces the route): missing or changed routes are
    /// installed, stale ones are withdrawn, unchanged ones are left alone.
    /// Per-route errors are logged, not fatal — reconcile is periodic, so
    /// a failed route is retried on the next pass.
    #[instrument(skip(self, dp))]
    pub async fn reconcile<D: Dataplane + Sync>(&mut self, dp: &D) {
        let _census = cpucensus::scope(&cpucensus::RIB_DIFF_FULL);
        let mut to_install: Vec<((TableId, IpPrefix), RouteEntry)> = Vec::new();
        let mut desired_keys: std::collections::HashSet<(TableId, IpPrefix)> =
            std::collections::HashSet::new();
        for (&table_id, table) in &self.tables {
            for (prefix, _) in table.iter() {
                // A connected candidate MASKS the prefix (distance 0,
                // nothing outranks it) and is itself never programmed —
                // the kernel already holds it as `proto kernel scope
                // link src <addr>`, a product of the address lifecycle
                // (`Rib::sync_connected`). Replacing it would drop the
                // prefsrc source-selection attribute; while it rules,
                // no other candidate for the prefix programs either.
                if self
                    .connected
                    .get(&table_id)
                    .is_some_and(|t| t.best(prefix).is_some())
                {
                    continue;
                }
                let Some(best) = table.best(prefix) else {
                    continue;
                };
                match self.resolved_programming_form(best) {
                    Some(form) => {
                        let key = (table_id, *prefix);
                        desired_keys.insert(key);
                        if self.programmed.get(&key) != Some(&form) {
                            to_install.push((key, form));
                        }
                    }
                    None => debug!(
                        prefix = %best.prefix,
                        table_id,
                        "best route has no resolved nexthop; held in RIB, not programmed"
                    ),
                }
            }
        }
        let unchanged = desired_keys.len() - to_install.len();
        let stale_keys: Vec<(TableId, IpPrefix)> = self
            .programmed
            .keys()
            .filter(|key| !desired_keys.contains(key))
            .copied()
            .collect();
        drop(_census);
        self.reconcile_delta(dp, to_install, stale_keys, unchanged)
            .await;
    }

    /// The dirty-keys half of [`Self::reconcile`] — bench F8's hot
    /// path: the same desired-form/diff/install/withdraw logic
    /// restricted to exactly the prefixes a command batch touched,
    /// O(batch) instead of O(table). The full pass stays the safety
    /// net on its own triggers (tick, dataplane events, SIGHUP).
    pub async fn reconcile_keys<D: Dataplane + Sync>(
        &mut self,
        dp: &D,
        keys: &std::collections::BTreeSet<(TableId, IpPrefix)>,
    ) {
        let _census = cpucensus::scope(&cpucensus::RIB_DIFF_KEYS);
        let mut to_install: Vec<((TableId, IpPrefix), RouteEntry)> = Vec::new();
        let mut desired_keys: std::collections::HashSet<(TableId, IpPrefix)> =
            std::collections::HashSet::new();
        for &(table_id, prefix) in keys {
            // Connected-masked keys are desired-nothing: a previously
            // programmed route for them withdraws below.
            if self
                .connected
                .get(&table_id)
                .is_some_and(|t| t.best(&prefix).is_some())
            {
                continue;
            }
            if let Some(best) = self.tables.get(&table_id).and_then(|t| t.best(&prefix)) {
                if let Some(form) = self.resolved_programming_form(best) {
                    desired_keys.insert((table_id, prefix));
                    if self.programmed.get(&(table_id, prefix)) != Some(&form) {
                        to_install.push(((table_id, prefix), form));
                    }
                }
            }
        }
        let unchanged = desired_keys.len() - to_install.len();
        let stale_keys: Vec<(TableId, IpPrefix)> = keys
            .iter()
            .filter(|key| !desired_keys.contains(*key) && self.programmed.contains_key(key))
            .copied()
            .collect();
        drop(_census);
        self.reconcile_delta(dp, to_install, stale_keys, unchanged)
            .await;
    }

    /// The shared diff-apply phase: one pipelined install batch and
    /// one pipelined withdraw batch (bench F8 — no per-route
    /// round-trip waits), beliefs updated from the per-entry results:
    /// an install failure leaves no belief (retry next pass), a
    /// delete failure restores the withdrawn belief (retry next
    /// pass).
    async fn reconcile_delta<D: Dataplane + Sync>(
        &mut self,
        dp: &D,
        to_install: Vec<((TableId, IpPrefix), RouteEntry)>,
        stale_keys: Vec<(TableId, IpPrefix)>,
        unchanged: usize,
    ) {
        let _census = cpucensus::scope(&cpucensus::RIB_BATCH_AWAIT);
        let mut installed = 0usize;
        if !to_install.is_empty() {
            let entries: Vec<RouteEntry> =
                to_install.iter().map(|(_, entry)| entry.clone()).collect();
            let results = dp.route_replace_batch(&entries).await;
            for ((key, entry), result) in to_install.into_iter().zip(results) {
                match result {
                    Ok(()) => {
                        debug!(prefix = %entry.prefix, table_id = entry.table, "installed best route");
                        self.programmed.insert(key, entry);
                        installed += 1;
                    }
                    Err(e) => {
                        warn!(prefix = %entry.prefix, table_id = entry.table, %e, "route install failed; will retry")
                    }
                }
            }
        }

        let mut withdrawn = 0usize;
        // Belief removal precedes the delete so a failed delete is
        // restorable (the belief re-inserts below).
        let pairs: Vec<((TableId, IpPrefix), RouteEntry)> = stale_keys
            .into_iter()
            .filter_map(|key| self.programmed.remove(&key).map(|entry| (key, entry)))
            .collect();
        if !pairs.is_empty() {
            let entries: Vec<RouteEntry> = pairs.iter().map(|(_, entry)| entry.clone()).collect();
            let results = dp.route_delete_batch(&entries).await;
            for ((key, entry), result) in pairs.into_iter().zip(results) {
                match result {
                    Ok(()) => {
                        debug!(prefix = %entry.prefix, table_id = entry.table, "withdrawn stale route");
                        withdrawn += 1;
                    }
                    Err(e) => {
                        // The kernel most likely still holds the route; keep the
                        // belief so the next pass tries the withdrawal again.
                        warn!(prefix = %entry.prefix, table_id = entry.table, %e, "route withdrawal failed; will retry");
                        self.programmed.insert(key, entry);
                    }
                }
            }
        }

        if installed + withdrawn > 0 {
            info!(
                installed,
                withdrawn, unchanged, "reconcile programmed dataplane"
            );
        } else {
            debug!(unchanged, "reconcile: dataplane already in sync");
        }
    }
}

/// Gateway IPs referenced by a nexthop group in unresolved form (`Ipv4`/
/// `Ipv6` hops). Hops that already carry an ifindex, `IfIndex`, and
/// `Blackhole` need no tracking.
fn gateway_ips(group: &NexthopGroup) -> impl Iterator<Item = IpAddr> + '_ {
    group.hops().iter().filter_map(|&(hop, _)| match hop {
        Nexthop::Ipv4(g) => Some(IpAddr::V4(g)),
        Nexthop::Ipv6(g) => Some(IpAddr::V6(g)),
        _ => None,
    })
}

/// The network form of a host prefix (`192.0.2.1/24` → `192.0.2.0/24`) —
/// the prefix a connected route announces for a configured address.
fn network_prefix(prefix: IpPrefix) -> IpPrefix {
    match prefix {
        IpPrefix::V4(p) => {
            let addr = u32::from(p.addr());
            let len = p.prefix_len();
            let mask = if len == 0 { 0 } else { !0u32 << (32 - len) };
            let network = Ipv4Addr::from(addr & mask);
            IpPrefix::V4(Ipv4Prefix::new(network, len).expect("len preserved"))
        }
        IpPrefix::V6(p) => {
            let addr = u128::from(p.addr());
            let len = p.prefix_len();
            let mask = if len == 0 { 0 } else { !0u128 << (128 - len) };
            let network = Ipv6Addr::from(addr & mask);
            IpPrefix::V6(Ipv6Prefix::new(network, len).expect("len preserved"))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use common::{DataplaneError, Nexthop, NexthopGroup, RouteProtocol};
    use std::future::Future;

    fn entry(prefix: &str, proto: RouteProtocol, metric: u32) -> RouteEntry {
        RouteEntry::new(
            prefix.parse().unwrap(),
            proto,
            NexthopGroup::single(Nexthop::IfIndex(2)),
            metric,
        )
    }

    /// Dataplane mock that records installs and withdrawals. Its futures are
    /// `Ready`, so `block_on` below drives `reconcile` in a single poll.
    #[derive(Default)]
    struct MockDp {
        installed: std::sync::Mutex<Vec<RouteEntry>>,
        removed: std::sync::Mutex<Vec<RouteEntry>>,
    }

    impl MockDp {
        fn installed_prefixes(&self) -> Vec<IpPrefix> {
            self.installed
                .lock()
                .unwrap()
                .iter()
                .map(|e| e.prefix)
                .collect()
        }

        fn removed_prefixes(&self) -> Vec<IpPrefix> {
            self.removed
                .lock()
                .unwrap()
                .iter()
                .map(|e| e.prefix)
                .collect()
        }
    }

    impl Dataplane for MockDp {
        fn route_replace(
            &self,
            entry: &RouteEntry,
        ) -> impl Future<Output = Result<(), DataplaneError>> + Send {
            self.installed.lock().unwrap().push(entry.clone());
            std::future::ready(Ok(()))
        }

        fn route_delete(
            &self,
            entry: &RouteEntry,
        ) -> impl Future<Output = Result<(), DataplaneError>> + Send {
            self.removed.lock().unwrap().push(entry.clone());
            std::future::ready(Ok(()))
        }
    }

    /// Minimal executor for tests: nothing in the mock ever returns `Pending`
    /// for long, so a polling spin on a no-op waker is enough.
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

    #[test]
    fn reconcile_installs_desired_routes() {
        let mut rib = Rib::new();
        rib.add_route(entry("10.0.0.0/8", RouteProtocol::Static, 0));
        rib.add_route(entry("2001:db8::/32", RouteProtocol::Static, 0));
        // Kernel-mirror state must not widen the programmed set.
        rib.apply_event(&DataplaneEvent::RouteNew {
            table: 254,
            prefix: "198.18.0.0/15".parse().unwrap(),
            protocol: RouteProtocol::Kernel,
            metric: 0,
            gateway: None,
            oif: None,
        });

        let dp = MockDp::default();
        block_on(rib.reconcile(&dp));

        let mut got = dp.installed_prefixes();
        got.sort();
        assert_eq!(
            got,
            vec![
                "10.0.0.0/8".parse().unwrap(),
                "2001:db8::/32".parse().unwrap()
            ]
        );
        assert!(dp.removed_prefixes().is_empty());
    }

    #[test]
    fn reconcile_withdraws_stale_and_keeps_unchanged() {
        let mut rib = Rib::new();
        rib.add_route(entry("10.0.0.0/8", RouteProtocol::Static, 0));
        rib.add_route(entry("192.0.2.0/24", RouteProtocol::Static, 0));
        let dp = MockDp::default();
        block_on(rib.reconcile(&dp));
        assert_eq!(dp.installed_prefixes().len(), 2);

        // Withdraw one prefix at the RIB level; the other is unchanged and
        // must not be re-sent.
        rib.table_mut(254)
            .remove(&"10.0.0.0/8".parse().unwrap(), RouteProtocol::Static);
        block_on(rib.reconcile(&dp));
        assert_eq!(dp.removed_prefixes(), vec!["10.0.0.0/8".parse().unwrap()]);
        assert_eq!(dp.installed_prefixes().len(), 2);

        // A pass with no RIB change programs nothing.
        block_on(rib.reconcile(&dp));
        assert_eq!(dp.installed_prefixes().len(), 2);
        assert_eq!(dp.removed_prefixes().len(), 1);
    }

    #[test]
    fn reconcile_replaces_changed_best() {
        let mut rib = Rib::new();
        rib.add_route(entry("10.0.0.0/8", RouteProtocol::Ospf, 20));
        let dp = MockDp::default();
        block_on(rib.reconcile(&dp));

        // Same protocol, better metric: the programmed route is stale.
        rib.add_route(entry("10.0.0.0/8", RouteProtocol::Ospf, 10));
        block_on(rib.reconcile(&dp));

        let installed = dp.installed.lock().unwrap();
        assert_eq!(installed.len(), 2);
        assert_eq!(installed[1].metric, 10);
    }

    #[test]
    fn reload_withdraws_only_vanished_prefixes() {
        let mut rib = Rib::new();
        rib.add_route(entry("10.0.0.0/8", RouteProtocol::Static, 0));
        rib.add_route(entry("192.0.2.0/24", RouteProtocol::Static, 0));
        // Not config-owned: reload must leave it alone.
        rib.add_route(entry("203.0.113.0/24", RouteProtocol::Ospf, 10));
        let dp = MockDp::default();
        block_on(rib.reconcile(&dp));

        rib.reload_static(&[
            entry("10.0.0.0/8", RouteProtocol::Static, 0),
            entry("198.51.100.0/24", RouteProtocol::Static, 0),
        ]);

        let table = rib.table(254).unwrap();
        assert!(table.best(&"192.0.2.0/24".parse().unwrap()).is_none());
        assert!(table.best(&"10.0.0.0/8".parse().unwrap()).is_some());
        assert!(table.best(&"198.51.100.0/24".parse().unwrap()).is_some());
        assert!(table.best(&"203.0.113.0/24".parse().unwrap()).is_some());

        // The reconcile pass removes exactly the vanished prefix from the
        // dataplane and installs the new one.
        block_on(rib.reconcile(&dp));
        assert_eq!(dp.removed_prefixes(), vec!["192.0.2.0/24".parse().unwrap()]);
        assert_eq!(dp.installed_prefixes().len(), 4);
    }

    #[test]
    fn route_del_drops_programmed_belief_for_reinstall() {
        let mut rib = Rib::new();
        rib.add_route(entry("198.51.100.0/24", RouteProtocol::Static, 0));
        let dp = MockDp::default();
        block_on(rib.reconcile(&dp));

        // External deletion: the kernel notifies us the route is gone.
        rib.apply_event(&DataplaneEvent::RouteDel {
            table: 254,
            prefix: "198.51.100.0/24".parse().unwrap(),
        });
        block_on(rib.reconcile(&dp));

        let installed = dp.installed.lock().unwrap();
        assert_eq!(
            installed.len(),
            2,
            "still-desired route must be reinstalled after external delete"
        );
    }

    #[test]
    fn best_prefers_lower_admin_distance() {
        let mut rib = Rib::new();
        rib.add_route(entry("10.0.0.0/8", RouteProtocol::Ospf, 10));
        rib.add_route(entry("10.0.0.0/8", RouteProtocol::Static, 100));
        let best = rib.table(254).unwrap().best(&"10.0.0.0/8".parse().unwrap());
        assert_eq!(best.unwrap().protocol, RouteProtocol::Static);
    }

    #[test]
    fn same_protocol_falls_back_to_metric() {
        let mut rib = Rib::new();
        rib.add_route(entry("10.0.0.0/8", RouteProtocol::Ospf, 20));
        rib.add_route(entry("10.0.0.0/8", RouteProtocol::Ospf, 10));
        let best = rib.table(254).unwrap().best(&"10.0.0.0/8".parse().unwrap());
        assert_eq!(best.unwrap().metric, 10);
    }

    #[test]
    fn remove_withdraws_protocol_routes() {
        let mut rib = Rib::new();
        rib.add_route(entry("10.0.0.0/8", RouteProtocol::Bgp, 0));
        rib.add_route(entry("10.0.0.0/8", RouteProtocol::Ospf, 10));
        let table = rib.table_mut(254);
        assert!(table.remove(&"10.0.0.0/8".parse().unwrap(), RouteProtocol::Bgp));
        assert_eq!(
            table.best(&"10.0.0.0/8".parse().unwrap()).unwrap().protocol,
            RouteProtocol::Ospf
        );
    }

    #[test]
    fn interface_events_update_state() {
        let mut rib = Rib::new();
        rib.apply_event(&DataplaneEvent::LinkNew {
            ifindex: 2,
            name: "eth0".into(),
            is_up: true,
            flags: common::LinkFlags::up_broadcast(),
            vrf_table: None,
            master_ifindex: None,
        });
        rib.apply_event(&DataplaneEvent::AddressNew {
            ifindex: 2,
            prefix: "10.0.0.1/24".parse().unwrap(),
        });
        rib.apply_event(&DataplaneEvent::AddressNew {
            ifindex: 2,
            prefix: "2001:db8::1/64".parse().unwrap(),
        });

        let iface = rib.interfaces().get(&2).unwrap();
        assert_eq!(iface.name, "eth0");
        assert!(iface.is_up);
        assert_eq!(iface.addresses.len(), 2);

        // Duplicate address notification is idempotent.
        rib.apply_event(&DataplaneEvent::AddressNew {
            ifindex: 2,
            prefix: "10.0.0.1/24".parse().unwrap(),
        });
        assert_eq!(rib.interfaces().get(&2).unwrap().addresses.len(), 2);

        rib.apply_event(&DataplaneEvent::AddressDel {
            ifindex: 2,
            prefix: "10.0.0.1/24".parse().unwrap(),
        });
        let iface = rib.interfaces().get(&2).unwrap();
        assert_eq!(iface.addresses.len(), 1);
        assert_eq!(iface.addresses[0], "2001:db8::1/64".parse().unwrap());

        rib.apply_event(&DataplaneEvent::LinkDel { ifindex: 2 });
        assert!(rib.interfaces().get(&2).is_none());
    }

    #[test]
    fn address_before_link_creates_placeholder() {
        let mut rib = Rib::new();
        rib.apply_event(&DataplaneEvent::AddressNew {
            ifindex: 5,
            prefix: "10.0.0.1/24".parse().unwrap(),
        });
        let iface = rib.interfaces().get(&5).unwrap();
        assert_eq!(iface.name, "");
        assert!(!iface.is_up);
        assert_eq!(iface.addresses.len(), 1);

        rib.apply_event(&DataplaneEvent::LinkNew {
            ifindex: 5,
            name: "eth1".into(),
            is_up: true,
            flags: common::LinkFlags::up_broadcast(),
            vrf_table: None,
            master_ifindex: None,
        });
        let iface = rib.interfaces().get(&5).unwrap();
        assert_eq!(iface.name, "eth1");
        assert_eq!(iface.addresses.len(), 1);
    }

    /// The kernel's `ifi_flags` ride through the mirror whole: named bits
    /// (LOOPBACK/BROADCAST/MULTICAST/…) and unnamed ones land in
    /// `InterfaceState.flags` exactly as reported, a later RTM_NEWLINK
    /// replaces them, and an address event arriving before the link finds
    /// the placeholder's default (empty) word until the link event fills
    /// it — the ingress path for the ZAPI mirror's verbatim relay (A12).
    #[test]
    fn link_flags_carried_into_mirror() {
        let mut rib = Rib::new();
        rib.apply_event(&DataplaneEvent::LinkNew {
            ifindex: 1,
            name: "lo".into(),
            is_up: true,
            // Kernel lo: UP|RUNNING|LOOPBACK plus the (unnamed) NOARP bit.
            flags: common::LinkFlags::from_bits(common::LinkFlags::up_loopback().bits() | 0x80),
            vrf_table: None,
            master_ifindex: None,
        });
        let iface = rib.interfaces().get(&1).unwrap();
        assert_eq!(
            iface.flags,
            common::LinkFlags::from_bits(0xC9),
            "LOOPBACK 0x8 + RUNNING 0x40 + UP 0x1 + NOARP 0x80, unnamed bit retained"
        );
        assert!(iface.flags.contains(common::LinkFlags::LOOPBACK));

        // Admin down: the kernel re-reports with UP|RUNNING dropped (the
        // static capability bits stay); the mirror takes the new word.
        rib.apply_event(&DataplaneEvent::LinkNew {
            ifindex: 1,
            name: "lo".into(),
            is_up: false,
            flags: common::LinkFlags::LOOPBACK | common::LinkFlags::from_bits(0x80),
            vrf_table: None,
            master_ifindex: None,
        });
        let iface = rib.interfaces().get(&1).unwrap();
        assert!(!iface.is_up);
        assert!(!iface.flags.contains(common::LinkFlags::UP));
        assert!(iface.flags.contains(common::LinkFlags::LOOPBACK));

        // Placeholder (address before link) starts with the empty word.
        rib.apply_event(&DataplaneEvent::AddressNew {
            ifindex: 9,
            prefix: "192.0.2.1/24".parse().unwrap(),
        });
        assert_eq!(rib.interfaces().get(&9).unwrap().flags.bits(), 0);
        rib.apply_event(&link(9, "eth9", true));
        assert!(rib
            .interfaces()
            .get(&9)
            .unwrap()
            .flags
            .contains(common::LinkFlags::UP));
    }

    #[test]
    fn kernel_route_events_update_mirror() {
        let prefix: IpPrefix = "198.18.0.0/15".parse().unwrap();
        let mut rib = Rib::new();
        rib.apply_event(&DataplaneEvent::RouteNew {
            table: 254,
            prefix,
            protocol: RouteProtocol::Kernel,
            metric: 100,
            gateway: None,
            oif: None,
        });
        rib.apply_event(&DataplaneEvent::RouteNew {
            table: 255,
            prefix: "192.0.2.0/24".parse().unwrap(),
            protocol: RouteProtocol::Kernel,
            metric: 0,
            gateway: None,
            oif: None,
        });

        assert_eq!(rib.kernel_route_count(), 2);
        let mirror = rib.kernel_table(254).unwrap();
        let best = mirror.best(&prefix).unwrap();
        assert_eq!(best.protocol, RouteProtocol::Kernel);
        assert_eq!(best.metric, 100);
        // Mirror state must stay out of the protocol tables.
        assert!(rib.table(254).is_none_or(|t| t.best(&prefix).is_none()));

        // A newer notification for the same prefix replaces the old one.
        rib.apply_event(&DataplaneEvent::RouteNew {
            table: 254,
            prefix,
            protocol: RouteProtocol::Kernel,
            metric: 0,
            gateway: None,
            oif: None,
        });
        assert_eq!(
            rib.kernel_table(254).unwrap().best(&prefix).unwrap().metric,
            0
        );

        rib.apply_event(&DataplaneEvent::RouteDel { table: 254, prefix });
        assert!(rib.kernel_table(254).unwrap().best(&prefix).is_none());
        assert_eq!(rib.kernel_route_count(), 1);

        // Deleting an unknown prefix is a no-op.
        rib.apply_event(&DataplaneEvent::RouteDel {
            table: 254,
            prefix: "203.0.113.0/24".parse().unwrap(),
        });
        assert_eq!(rib.kernel_route_count(), 1);
    }

    /// A23: the routed NHT lookup — ospfd's NSSA default import check
    /// registers 0.0.0.0/0 with resolve_via_default and must be answered
    /// from the observed kernel mirror (the on-link-only answer of the
    /// staticd era stays for flag-unset registrations).
    #[test]
    fn routed_nht_lookup_answers_default_registration_from_mirror() {
        use std::net::Ipv4Addr;
        let mut rib = Rib::new();
        // Docker-bridge shape: default via an on-link gateway, connected
        // /24 as a device route, one UP interface carrying the /24.
        rib.apply_event(&DataplaneEvent::RouteNew {
            table: MAIN_TABLE,
            prefix: "0.0.0.0/0".parse().unwrap(),
            protocol: RouteProtocol::Kernel,
            metric: 0,
            gateway: Some(IpAddr::V4(Ipv4Addr::new(192, 168, 215, 1))),
            oif: Some(2),
        });
        rib.apply_event(&DataplaneEvent::RouteNew {
            table: MAIN_TABLE,
            prefix: "192.168.215.0/24".parse().unwrap(),
            protocol: RouteProtocol::Kernel,
            metric: 0,
            gateway: None,
            oif: Some(2),
        });
        rib.apply_event(&DataplaneEvent::LinkNew {
            ifindex: 2,
            name: "eth0".into(),
            is_up: true,
            flags: common::LinkFlags::up_broadcast(),
            vrf_table: None,
            master_ifindex: None,
        });
        rib.apply_event(&DataplaneEvent::AddressNew {
            ifindex: 2,
            prefix: "192.168.215.4/24".parse().unwrap(),
        });
        // Zebra-faithful (owner decision 2026-10-10): the default answers
        // from the mirror with NO neighbour confirmation.
        assert_eq!(
            rib.lookup_nexthop_routed(IpAddr::V4(Ipv4Addr::UNSPECIFIED), true),
            Some(Nexthop::Ipv4If(Ipv4Addr::new(192, 168, 215, 1), 2))
        );
        // Neighbour state is advisory only — even an INCOMPLETE entry
        // (no lladdr) never flips the answer.
        rib.apply_event(&neighbour_new("192.168.215.1", 2, None, 0x01));
        assert_eq!(
            rib.lookup_nexthop_routed(IpAddr::V4(Ipv4Addr::UNSPECIFIED), true),
            Some(Nexthop::Ipv4If(Ipv4Addr::new(192, 168, 215, 1), 2))
        );
        // Flag unset (staticd/bgpd fixtures): connected-only, and 0.0.0.0
        // is never on-link — the answer stays unresolved.
        assert_eq!(
            rib.lookup_nexthop_routed(IpAddr::V4(Ipv4Addr::UNSPECIFIED), false),
            None
        );
        // On-link still wins over the mirror for flag-set registrations —
        // with or without neighbour state.
        assert_eq!(
            rib.lookup_nexthop_routed("192.168.215.9".parse().unwrap(), true),
            Some(Nexthop::Ipv4If("192.168.215.9".parse().unwrap(), 2))
        );
        rib.apply_event(&neighbour_new("192.168.215.9", 2, Some(0x09), 0x80));
        assert_eq!(
            rib.lookup_nexthop_routed("192.168.215.9".parse().unwrap(), true),
            Some(Nexthop::Ipv4If("192.168.215.9".parse().unwrap(), 2))
        );
        // Fresh lookups only (event-driven re-eval is Z3B): deleting the
        // default drops the mirror answer; the connected /24 does not
        // cover 0.0.0.0.
        rib.apply_event(&DataplaneEvent::RouteDel {
            table: MAIN_TABLE,
            prefix: "0.0.0.0/0".parse().unwrap(),
        });
        assert_eq!(
            rib.lookup_nexthop_routed(IpAddr::V4(Ipv4Addr::UNSPECIFIED), true),
            None
        );
    }

    /// A23 edges of the routed lookup: a bare-gateway mirror hop needs one
    /// on-link level, non-main tables never answer, and families stay
    /// separate.
    #[test]
    fn routed_nht_lookup_bare_gateway_table_scope_and_family() {
        use std::net::{Ipv4Addr, Ipv6Addr};
        let mut rib = Rib::new();
        rib.apply_event(&DataplaneEvent::RouteNew {
            table: MAIN_TABLE,
            prefix: "0.0.0.0/0".parse().unwrap(),
            protocol: RouteProtocol::Kernel,
            metric: 0,
            gateway: Some(IpAddr::V4(Ipv4Addr::new(198, 51, 100, 1))),
            oif: None,
        });
        // A default in a non-main table must not answer.
        rib.apply_event(&DataplaneEvent::RouteNew {
            table: 5001,
            prefix: "0.0.0.0/0".parse().unwrap(),
            protocol: RouteProtocol::Kernel,
            metric: 0,
            gateway: Some(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 1))),
            oif: Some(9),
        });
        // No interface state yet: the bare gateway is not on-link either.
        assert_eq!(
            rib.lookup_nexthop_routed(IpAddr::V4(Ipv4Addr::UNSPECIFIED), true),
            None
        );
        // Bringing the gateway's prefix on-link completes the one
        // recursion level.
        rib.apply_event(&DataplaneEvent::LinkNew {
            ifindex: 3,
            name: "eth3".into(),
            is_up: true,
            flags: common::LinkFlags::up_broadcast(),
            vrf_table: None,
            master_ifindex: None,
        });
        rib.apply_event(&DataplaneEvent::AddressNew {
            ifindex: 3,
            prefix: "198.51.100.2/24".parse().unwrap(),
        });
        rib.apply_event(&neighbour_new("198.51.100.1", 3, Some(0x03), 0x80));
        assert_eq!(
            rib.lookup_nexthop_routed(IpAddr::V4(Ipv4Addr::UNSPECIFIED), true),
            Some(Nexthop::Ipv4If(Ipv4Addr::new(198, 51, 100, 1), 3))
        );
        // A v6 query does not match the v4 mirror entries.
        assert_eq!(
            rib.lookup_nexthop_routed(IpAddr::V6(Ipv6Addr::UNSPECIFIED), true),
            None
        );
    }

    #[test]
    fn mirror_ignores_self_originated_notifications() {
        let prefix: IpPrefix = "198.51.100.0/24".parse().unwrap();
        let mut rib = Rib::new();
        // The install echo of a route Rouster itself programmed must not
        // enter the mirror.
        rib.apply_event(&DataplaneEvent::RouteNew {
            table: 254,
            prefix,
            protocol: RouteProtocol::Static,
            metric: 0,
            gateway: None,
            oif: None,
        });
        assert_eq!(rib.kernel_route_count(), 0);

        // Nor may a self-originated echo evict mirrored kernel state.
        rib.apply_event(&DataplaneEvent::RouteNew {
            table: 254,
            prefix,
            protocol: RouteProtocol::Kernel,
            metric: 0,
            gateway: None,
            oif: None,
        });
        rib.apply_event(&DataplaneEvent::RouteNew {
            table: 254,
            prefix,
            protocol: RouteProtocol::Ospf,
            metric: 0,
            gateway: None,
            oif: None,
        });
        assert_eq!(rib.kernel_route_count(), 1);
    }

    // --- Neighbour mirror (W3) ---

    fn neighbour_new(ip: &str, ifindex: u32, mac_last: Option<u8>, state: u16) -> DataplaneEvent {
        let lladdr = mac_last.map(|last| vec![0x02, 0x00, 0x00, 0x00, 0x00, last]);
        DataplaneEvent::NeighbourNew {
            entry: common::NeighbourEntry::from_rtnetlink(
                ip.parse().unwrap(),
                ifindex,
                lladdr,
                state,
                0,
            ),
        }
    }

    #[test]
    fn neighbour_events_update_mirror() {
        let mut rib = Rib::new();
        rib.apply_event(&neighbour_new("192.0.2.11", 2, Some(0x11), 0x80));

        let entry = rib.lookup_neighbour(ip("192.0.2.11"), 2).unwrap();
        assert!(entry.state.contains(common::NeighbourState::PERMANENT));
        assert!(entry.is_up());
        assert_eq!(rib.neighbours().len(), 1);

        // RTM_NEWNEIGH for an existing key replaces (state/lladdr update).
        rib.apply_event(&neighbour_new("192.0.2.11", 2, Some(0x99), 0x02));
        let entry = rib.lookup_neighbour(ip("192.0.2.11"), 2).unwrap();
        assert!(entry.state.contains(common::NeighbourState::REACHABLE));
        assert_eq!(entry.lladdr.as_deref(), Some(&[0x02, 0, 0, 0, 0, 0x99][..]));
        assert_eq!(rib.neighbours().len(), 1, "replacement, not addition");

        // Deletion drops exactly the (ip, link) key.
        rib.apply_event(&DataplaneEvent::NeighbourDel {
            ip: ip("192.0.2.11"),
            link_ifindex: 2,
        });
        assert!(rib.lookup_neighbour(ip("192.0.2.11"), 2).is_none());
        assert_eq!(rib.neighbours().len(), 0);

        // Deleting an unknown key is a no-op (stale notifications).
        rib.apply_event(&DataplaneEvent::NeighbourDel {
            ip: ip("203.0.113.1"),
            link_ifindex: 9,
        });
        assert_eq!(rib.neighbours().len(), 0);
    }

    #[test]
    fn same_ip_on_two_links_are_distinct_neighbours() {
        let mut rib = Rib::new();
        rib.apply_event(&neighbour_new("192.0.2.7", 2, Some(0x07), 0x80));
        rib.apply_event(&neighbour_new("192.0.2.7", 3, Some(0x77), 0x02));
        assert_eq!(rib.neighbours().len(), 2);
        let on2 = rib.lookup_neighbour(ip("192.0.2.7"), 2).unwrap();
        let on3 = rib.lookup_neighbour(ip("192.0.2.7"), 3).unwrap();
        assert_eq!(on2.lladdr.as_deref(), Some(&[0x02, 0, 0, 0, 0, 0x07][..]));
        assert_eq!(on3.lladdr.as_deref(), Some(&[0x02, 0, 0, 0, 0, 0x77][..]));

        // Removing one leaves the other.
        rib.apply_event(&DataplaneEvent::NeighbourDel {
            ip: ip("192.0.2.7"),
            link_ifindex: 2,
        });
        assert!(rib.lookup_neighbour(ip("192.0.2.7"), 2).is_none());
        assert!(rib.lookup_neighbour(ip("192.0.2.7"), 3).is_some());
    }

    /// The mirror stores entries whole: the NDA_CACHEINFO ageing
    /// statistics and the NDA_PROTOCOL origin ride along uninterpreted
    /// (the SAV-hysteresis / NHT-liveness consumers read them later), and
    /// a replacement event refreshes them with the newly reported values.
    #[test]
    fn neighbour_mirror_preserves_cacheinfo_and_protocol() {
        let mut rib = Rib::new();
        let with_attrs = |ci: Option<u32>, proto: u8| DataplaneEvent::NeighbourNew {
            entry: common::NeighbourEntry::from_rtnetlink(
                ip("192.0.2.11"),
                2,
                Some(vec![0x02, 0, 0, 0, 0, 0x11]),
                0x80,
                0,
            )
            .with_cacheinfo(ci.map(|updated| common::NeighbourCacheInfo {
                confirmed: 100,
                used: 150,
                updated,
                refcnt: 1,
            }))
            .with_protocol(Some(common::NeighbourProtocol::from_bits(proto))),
        };

        rib.apply_event(&with_attrs(Some(300), 0x04)); // ip neigh add: RTPROT_STATIC
        let entry = rib.lookup_neighbour(ip("192.0.2.11"), 2).unwrap();
        let ci = entry.cacheinfo.expect("cacheinfo stored");
        assert_eq!(
            (ci.confirmed, ci.used, ci.updated, ci.refcnt),
            (100, 150, 300, 1)
        );
        assert_eq!(entry.protocol, Some(common::NeighbourProtocol::STATIC));

        // Replacement (re-confirmed entry) carries fresh timestamps.
        rib.apply_event(&with_attrs(Some(900), 0x04));
        let entry = rib.lookup_neighbour(ip("192.0.2.11"), 2).unwrap();
        assert_eq!(entry.cacheinfo.expect("refreshed").updated, 900);
        assert_eq!(rib.neighbours().len(), 1);
    }

    /// Neighbour events move EXACTLY the NHT answer surface (M3): the
    /// kernel route mirror, the programming resolution
    /// (`resolve_nexthop_recursive` — reconcile's input, matching Linux
    /// route-install semantics), and the plain on-link resolution all
    /// stay untouched, while the neighbour-gated NEXTHOP_UPDATE answer
    /// (`lookup_nexthop_routed`) flips with the neighbour's confirmation
    /// state. (W3 pinned the pre-M3 world — "neighbour events leave
    /// route and resolution state alone" — whose mirror/programming half
    /// this keeps verbatim; the answer half changed with M3's liveness
    /// gate, honestly.)
    #[test]
    fn neighbour_events_leave_route_and_resolution_state_alone() {
        let mut rib = Rib::new();
        rib.apply_event(&link(2, "eth0", true));
        rib.apply_event(&address(2, "192.0.2.1/24", true));
        rib.apply_event(&DataplaneEvent::RouteNew {
            table: 254,
            prefix: "198.18.0.0/15".parse().unwrap(),
            protocol: RouteProtocol::Kernel,
            metric: 0,
            gateway: None,
            oif: None,
        });
        let resolved = rib.resolve_nexthop(ip("192.0.2.7"));
        assert!(resolved.is_some());
        assert_eq!(rib.kernel_route_count(), 1);
        // Zebra-faithful NHT (owner decision 2026-10-10): connected is
        // enough — no neighbour confirmation required.
        assert_eq!(
            rib.lookup_nexthop_routed(ip("192.0.2.7"), false),
            Some(Nexthop::Ipv4If("192.0.2.7".parse().unwrap(), 2))
        );

        // A neighbour for the gateway IP appearing and disappearing
        // changes neither the programming resolution, the route mirror,
        // NOR the NHT answer (advisory data only).
        rib.apply_event(&neighbour_new("192.0.2.7", 2, Some(0x07), 0x80));
        assert_eq!(rib.resolve_nexthop(ip("192.0.2.7")), resolved);
        assert_eq!(rib.resolve_nexthop_recursive(ip("192.0.2.7")), resolved);
        assert_eq!(rib.kernel_route_count(), 1);
        assert_eq!(
            rib.lookup_nexthop_routed(ip("192.0.2.7"), false),
            Some(Nexthop::Ipv4If("192.0.2.7".parse().unwrap(), 2))
        );
        // Even an INCOMPLETE entry (lladdr absent) never flips the answer.
        rib.apply_event(&neighbour_new("192.0.2.7", 2, None, 0x01));
        assert!(rib.lookup_nexthop_routed(ip("192.0.2.7"), false).is_some());
        rib.apply_event(&neighbour_new("192.0.2.7", 2, Some(0x07), 0x80));
        rib.apply_event(&DataplaneEvent::NeighbourDel {
            ip: ip("192.0.2.7"),
            link_ifindex: 2,
        });
        assert_eq!(rib.resolve_nexthop(ip("192.0.2.7")), resolved);
        assert_eq!(rib.resolve_nexthop_recursive(ip("192.0.2.7")), resolved);
        assert_eq!(rib.kernel_route_count(), 1);
        assert_eq!(
            rib.lookup_nexthop_routed(ip("192.0.2.7"), false),
            Some(Nexthop::Ipv4If("192.0.2.7".parse().unwrap(), 2))
        );
    }

    // --- Nexthop resolution & tracking (P0B) ---

    fn link(ifindex: u32, name: &str, is_up: bool) -> DataplaneEvent {
        DataplaneEvent::LinkNew {
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

    fn address(ifindex: u32, prefix: &str, is_new: bool) -> DataplaneEvent {
        let prefix = prefix.parse().unwrap();
        if is_new {
            DataplaneEvent::AddressNew { ifindex, prefix }
        } else {
            DataplaneEvent::AddressDel { ifindex, prefix }
        }
    }

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    fn gw_entry(prefix: &str, gw: &str) -> RouteEntry {
        let hop = match ip(gw) {
            IpAddr::V4(a) => Nexthop::Ipv4(a),
            IpAddr::V6(a) => Nexthop::Ipv6(a),
        };
        RouteEntry::new(
            prefix.parse().unwrap(),
            RouteProtocol::Static,
            NexthopGroup::single(hop),
            0,
        )
    }

    #[test]
    fn resolve_gateway_on_connected_subnet() {
        let mut rib = Rib::new();
        rib.apply_event(&link(2, "eth0", true));
        rib.apply_event(&address(2, "10.0.0.1/24", true));

        let gw = ip("10.0.0.9");
        assert_eq!(
            rib.resolve_nexthop(gw),
            Some(Nexthop::Ipv4If("10.0.0.9".parse().unwrap(), 2))
        );
        // The NHT query API is the same resolution.
        assert_eq!(rib.lookup_nexthop(gw), rib.resolve_nexthop(gw));

        // Off-subnet and wrong-AF gateways do not resolve.
        assert_eq!(rib.resolve_nexthop(ip("10.0.1.9")), None);
        assert_eq!(rib.resolve_nexthop(ip("2001:db8::9")), None);
    }

    #[test]
    fn resolve_longest_prefix_wins() {
        let mut rib = Rib::new();
        rib.apply_event(&link(2, "eth0", true));
        rib.apply_event(&address(2, "10.0.0.1/24", true));
        rib.apply_event(&link(3, "eth1", true));
        rib.apply_event(&address(3, "10.0.0.5/30", true));

        // In both the /30 and the /24: the /30 (ifindex 3) wins.
        assert_eq!(
            rib.resolve_nexthop(ip("10.0.0.6")),
            Some(Nexthop::Ipv4If("10.0.0.6".parse().unwrap(), 3))
        );
        // Only in the /24.
        assert_eq!(
            rib.resolve_nexthop(ip("10.0.0.100")),
            Some(Nexthop::Ipv4If("10.0.0.100".parse().unwrap(), 2))
        );

        // Equal length on two interfaces: deterministic lowest ifindex.
        rib.apply_event(&link(5, "eth2", true));
        rib.apply_event(&address(5, "10.0.0.2/24", true));
        assert_eq!(
            rib.resolve_nexthop(ip("10.0.0.100")),
            Some(Nexthop::Ipv4If("10.0.0.100".parse().unwrap(), 2))
        );
    }

    #[test]
    fn gateway_on_down_interface_does_not_resolve() {
        let mut rib = Rib::new();
        rib.apply_event(&link(2, "eth0", false));
        rib.apply_event(&address(2, "10.0.0.1/24", true));
        assert_eq!(rib.resolve_nexthop(ip("10.0.0.9")), None);

        // A down interface must not contribute even with a longer prefix.
        rib.apply_event(&link(3, "eth1", true));
        rib.apply_event(&address(3, "10.0.0.1/24", true));
        rib.apply_event(&link(4, "eth2", false));
        rib.apply_event(&address(4, "10.0.0.5/30", true));
        assert_eq!(
            rib.resolve_nexthop(ip("10.0.0.6")),
            Some(Nexthop::Ipv4If("10.0.0.6".parse().unwrap(), 3))
        );

        // Link down unresolves; link up re-resolves.
        rib.apply_event(&link(3, "eth1", false));
        assert_eq!(rib.resolve_nexthop(ip("10.0.0.6")), None);
        rib.apply_event(&link(3, "eth1", true));
        assert_eq!(
            rib.resolve_nexthop(ip("10.0.0.6")),
            Some(Nexthop::Ipv4If("10.0.0.6".parse().unwrap(), 3))
        );

        // Link gone entirely: same effect.
        rib.apply_event(&DataplaneEvent::LinkDel { ifindex: 3 });
        assert_eq!(rib.resolve_nexthop(ip("10.0.0.6")), None);
    }

    #[test]
    fn address_delete_unresolves_and_route_is_withdrawn() {
        let mut rib = Rib::new();
        rib.apply_event(&link(2, "eth0", true));
        rib.apply_event(&address(2, "192.0.2.1/24", true));
        rib.add_route(gw_entry("198.51.100.0/24", "192.0.2.7"));

        let dp = MockDp::default();
        block_on(rib.reconcile(&dp));
        assert_eq!(
            dp.installed_prefixes(),
            vec!["198.51.100.0/24".parse().unwrap()]
        );

        // Deleting the carrying address unresolves the gateway; the route
        // is withdrawn from the dataplane but stays in the RIB.
        rib.apply_event(&address(2, "192.0.2.1/24", false));
        assert_eq!(
            rib.unresolved_gateways().collect::<Vec<_>>(),
            vec![ip("192.0.2.7")]
        );
        block_on(rib.reconcile(&dp));
        assert_eq!(
            dp.removed_prefixes(),
            vec!["198.51.100.0/24".parse().unwrap()]
        );
        assert!(
            rib.table(254)
                .unwrap()
                .best(&"198.51.100.0/24".parse().unwrap())
                .is_some(),
            "unresolved route must stay in the RIB"
        );

        // Re-adding the address re-resolves and the route is reinstalled,
        // now in resolved (ifindex-carrying) form.
        rib.apply_event(&address(2, "192.0.2.1/24", true));
        assert_eq!(rib.unresolved_gateways().count(), 0);
        block_on(rib.reconcile(&dp));
        let installed = dp.installed.lock().unwrap();
        assert_eq!(installed.len(), 2);
        assert_eq!(
            installed[1].nexthops.hops(),
            &[(Nexthop::Ipv4If("192.0.2.7".parse().unwrap(), 2), 1)]
        );
    }

    #[test]
    fn link_down_withdraws_but_keeps_route_in_rib() {
        let mut rib = Rib::new();
        rib.apply_event(&link(2, "eth0", true));
        rib.apply_event(&address(2, "192.0.2.1/24", true));
        rib.add_route(gw_entry("198.51.100.0/24", "192.0.2.7"));

        let dp = MockDp::default();
        block_on(rib.reconcile(&dp));
        assert_eq!(dp.installed_prefixes().len(), 1);

        rib.apply_event(&link(2, "eth0", false));
        block_on(rib.reconcile(&dp));
        assert_eq!(
            dp.removed_prefixes(),
            vec!["198.51.100.0/24".parse().unwrap()]
        );
        assert!(rib
            .table(254)
            .unwrap()
            .best(&"198.51.100.0/24".parse().unwrap())
            .is_some());

        // Interface recovery reinstalls without any RIB-level change.
        rib.apply_event(&link(2, "eth0", true));
        block_on(rib.reconcile(&dp));
        assert_eq!(dp.installed_prefixes().len(), 2);
    }

    #[test]
    fn unresolved_gateway_route_not_programmed() {
        let mut rib = Rib::new();
        // No interface state at all: the gateway cannot resolve.
        rib.add_route(gw_entry("198.51.100.0/24", "192.0.2.7"));

        let dp = MockDp::default();
        block_on(rib.reconcile(&dp));
        assert!(dp.installed_prefixes().is_empty());
        assert!(dp.removed_prefixes().is_empty());
        assert!(rib
            .table(254)
            .unwrap()
            .best(&"198.51.100.0/24".parse().unwrap())
            .is_some());
        // The gateway is tracked for ZAPI as long as it stays unresolved.
        assert_eq!(
            rib.unresolved_gateways().collect::<Vec<_>>(),
            vec![ip("192.0.2.7")]
        );

        // Resolution via an interface event makes it programmable.
        rib.apply_event(&link(2, "eth0", true));
        rib.apply_event(&address(2, "192.0.2.1/24", true));
        assert_eq!(rib.unresolved_gateways().count(), 0);
        block_on(rib.reconcile(&dp));
        assert_eq!(
            dp.installed_prefixes(),
            vec!["198.51.100.0/24".parse().unwrap()]
        );
    }

    #[test]
    fn blackhole_and_ifindex_routes_never_blocked() {
        let mut rib = Rib::new();
        // No interfaces mirrored: resolution cannot help, and must not need to.
        rib.add_route(RouteEntry::new(
            "203.0.113.0/24".parse().unwrap(),
            RouteProtocol::Static,
            NexthopGroup::single(Nexthop::Blackhole),
            0,
        ));
        rib.add_route(RouteEntry::new(
            "198.51.100.0/24".parse().unwrap(),
            RouteProtocol::Ospf,
            NexthopGroup::single(Nexthop::IfIndex(9)),
            10,
        ));

        let dp = MockDp::default();
        block_on(rib.reconcile(&dp));
        let mut got = dp.installed_prefixes();
        got.sort();
        assert_eq!(
            got,
            vec![
                "198.51.100.0/24".parse().unwrap(),
                "203.0.113.0/24".parse().unwrap()
            ]
        );
    }

    #[test]
    fn ipv6_gateway_resolution() {
        let mut rib = Rib::new();
        rib.apply_event(&link(2, "eth0", true));
        rib.apply_event(&address(2, "2001:db8:1::1/64", true));
        assert_eq!(
            rib.resolve_nexthop(ip("2001:db8:1::42")),
            Some(Nexthop::Ipv6If("2001:db8:1::42".parse().unwrap(), 2))
        );
        // v4 gateway does not resolve against a v6 prefix (and vice versa).
        assert_eq!(rib.resolve_nexthop(ip("192.0.2.7")), None);

        rib.add_route(gw_entry("2001:db8:2::/48", "2001:db8:1::42"));
        let dp = MockDp::default();
        block_on(rib.reconcile(&dp));
        let installed = dp.installed.lock().unwrap();
        assert_eq!(
            installed[0].nexthops.hops(),
            &[(Nexthop::Ipv6If("2001:db8:1::42".parse().unwrap(), 2), 1)]
        );
    }

    #[test]
    fn ecmp_group_programs_resolved_subset() {
        let mut rib = Rib::new();
        rib.apply_event(&link(2, "eth0", true));
        rib.apply_event(&address(2, "10.0.0.1/24", true));

        // One resolvable gateway, one unresolvable: the resolved subset is
        // programmed (all-or-none would refuse the route entirely).
        let mut group = NexthopGroup::new();
        group.add(Nexthop::Ipv4("10.0.0.9".parse().unwrap()), 1);
        group.add(Nexthop::Ipv4("192.0.2.9".parse().unwrap()), 1);
        rib.add_route(RouteEntry::new(
            "198.51.100.0/24".parse().unwrap(),
            RouteProtocol::Static,
            group,
            0,
        ));

        let dp = MockDp::default();
        block_on(rib.reconcile(&dp));
        {
            let installed = dp.installed.lock().unwrap();
            assert_eq!(
                installed[0].nexthops.hops(),
                &[(Nexthop::Ipv4If("10.0.0.9".parse().unwrap(), 2), 1)]
            );
        }

        // The second gateway resolving grows the programmed group back.
        rib.apply_event(&link(3, "eth1", true));
        rib.apply_event(&address(3, "192.0.2.1/24", true));
        block_on(rib.reconcile(&dp));
        let installed = dp.installed.lock().unwrap();
        assert_eq!(installed.len(), 2);
        assert_eq!(installed[1].nexthops.hops().len(), 2);
        assert!(dp.removed_prefixes().is_empty(), "replace, not withdraw");
    }

    #[test]
    fn resolution_ifindex_change_replaces_programmed_route() {
        let mut rib = Rib::new();
        rib.apply_event(&link(2, "eth0", true));
        rib.apply_event(&address(2, "10.0.0.1/24", true));
        rib.add_route(gw_entry("198.51.100.0/24", "10.0.0.6"));

        let dp = MockDp::default();
        block_on(rib.reconcile(&dp));

        // A longer connected prefix on another interface re-resolves the
        // gateway; reconcile must re-replace, not leave the old oif.
        rib.apply_event(&link(3, "eth1", true));
        rib.apply_event(&address(3, "10.0.0.5/30", true));
        block_on(rib.reconcile(&dp));

        let installed = dp.installed.lock().unwrap();
        assert_eq!(installed.len(), 2);
        assert_eq!(
            installed[1].nexthops.hops(),
            &[(Nexthop::Ipv4If("10.0.0.6".parse().unwrap(), 3), 1)]
        );
        assert!(dp.removed_prefixes().is_empty());
    }

    // --- Recursive multi-hop resolution (the routed walk) ---

    fn mirror_route(prefix: &str, gw: &str, oif: u32) -> DataplaneEvent {
        DataplaneEvent::RouteNew {
            table: MAIN_TABLE,
            prefix: prefix.parse().unwrap(),
            protocol: RouteProtocol::Kernel,
            metric: 0,
            gateway: Some(ip(gw)),
            oif: Some(oif),
        }
    }

    /// 1-, 2- and 3-hop chains all resolve through the walk to the
    /// ultimate on-link hop; every chain member's own route stays a bare
    /// `via <gw>` candidate while the RESOLVED forms carry the ifindex.
    #[test]
    fn recursive_resolution_chains_one_two_three_hops() {
        let mut rib = Rib::new();
        rib.apply_event(&link(2, "eth0", true));
        rib.apply_event(&address(2, "10.1.1.1/24", true));

        // 1-hop: 10.9.0.0/16 via 10.99.0.1 (off-link), covered by a
        // mirror route to 10.99.0.0/24 via the on-link 10.1.1.9.
        rib.apply_event(&DataplaneEvent::RouteNew {
            table: MAIN_TABLE,
            prefix: "10.99.0.0/24".parse().unwrap(),
            protocol: RouteProtocol::Kernel,
            metric: 0,
            gateway: Some(ip("10.1.1.9")),
            oif: Some(2),
        });
        rib.add_route(gw_entry("10.9.0.0/16", "10.99.0.1"));
        assert_eq!(
            rib.resolve_nexthop_recursive(ip("10.99.0.1")),
            Some(Nexthop::Ipv4If("10.1.1.9".parse().unwrap(), 2)),
            "1-hop: the covering route's own observed hop"
        );
        // And the off-link-gateway route is programmable through it.
        let dp = MockDp::default();
        block_on(rib.reconcile(&dp));
        let installed = dp.installed.lock().unwrap();
        assert!(installed.iter().any(|e| {
            e.prefix == "10.9.0.0/16".parse().unwrap()
                && e.nexthops.hops() == [(Nexthop::Ipv4If("10.1.1.9".parse().unwrap(), 2), 1)]
        }));

        // 2-hop: 198.18.0.1 covered by a static via 10.99.0.2 (bare),
        // which is itself covered by the mirror 10.99.0.0/24 route.
        rib.add_route(gw_entry("203.0.113.0/24", "198.18.0.1"));
        rib.add_route(gw_entry("198.18.0.0/15", "10.99.0.2"));
        assert_eq!(
            rib.resolve_nexthop_recursive(ip("198.18.0.1")),
            Some(Nexthop::Ipv4If("10.1.1.9".parse().unwrap(), 2))
        );

        // 3-hop: 100.64.0.1 via chain 100.64.0.0/10 -> 172.16.0.0/12 ->
        // the 198.18.0.0/15 static -> the mirror route -> on-link.
        rib.add_route(gw_entry("100.64.0.0/10", "172.16.0.1"));
        rib.add_route(gw_entry("172.16.0.0/12", "198.18.0.254"));
        assert_eq!(
            rib.resolve_nexthop_recursive(ip("100.64.0.1")),
            Some(Nexthop::Ipv4If("10.1.1.9".parse().unwrap(), 2)),
            "3-hop chain lands on the same ultimate hop"
        );

        // The plain surface stays direct (on-link only) for the same IP.
        assert_eq!(rib.resolve_nexthop(ip("100.64.0.1")), None);
    }

    /// Cycles terminate the chain unresolved: a two-gateway loop and a
    /// route whose gateway sits inside its own covering prefix never
    /// resolve.
    #[test]
    fn recursive_resolution_cycles_terminate_unresolved() {
        let mut rib = Rib::new();
        rib.apply_event(&link(2, "eth0", true));
        rib.apply_event(&address(2, "10.1.1.1/24", true));

        // A -> B -> A: both routes cover each other's gateway.
        rib.add_route(gw_entry("10.2.0.0/16", "10.3.0.1"));
        rib.add_route(gw_entry("10.3.0.0/16", "10.2.0.1"));
        assert_eq!(rib.resolve_nexthop_recursive(ip("10.2.0.1")), None);
        assert_eq!(rib.resolve_nexthop_recursive(ip("10.3.0.1")), None);

        // Self-covering: 10.4.0.0/16 via 10.4.0.1 — the route's own
        // prefix is the best cover of its gateway, recursing into
        // itself; the visited set halts it.
        rib.add_route(gw_entry("10.4.0.0/16", "10.4.0.1"));
        assert_eq!(rib.resolve_nexthop_recursive(ip("10.4.0.1")), None);
    }

    /// A blackhole candidate terminates the chain unresolved, and the
    /// walk does NOT fall through to a shorter covering prefix (the
    /// disclosed no-fall-through deviation, pinned).
    #[test]
    fn blackhole_candidate_terminates_without_fallthrough() {
        let mut rib = Rib::new();
        rib.apply_event(&link(2, "eth0", true));
        rib.apply_event(&address(2, "10.1.1.1/24", true));

        // Longest cover is a blackhole; a shorter cover would resolve.
        rib.add_route(RouteEntry::new(
            "10.9.9.0/24".parse().unwrap(),
            RouteProtocol::Static,
            NexthopGroup::single(Nexthop::Blackhole),
            0,
        ));
        rib.apply_event(&mirror_route("10.9.0.0/16", "10.1.1.9", 2));
        assert_eq!(
            rib.resolve_nexthop_recursive(ip("10.9.9.7")),
            None,
            "blackhole terminates the chain; no fall-through to the /16"
        );
    }

    /// A held candidate (its own gateway unresolved) terminates the chain
    /// unresolved — again without falling through to shorter prefixes.
    #[test]
    fn held_candidate_terminates_without_fallthrough() {
        let mut rib = Rib::new();
        rib.apply_event(&link(2, "eth0", true));
        rib.apply_event(&address(2, "10.1.1.1/24", true));

        // Longest cover's gateway is nowhere reachable (held); a shorter
        // cover exists and would resolve.
        rib.add_route(gw_entry("10.9.9.0/24", "100.64.0.1"));
        rib.apply_event(&mirror_route("10.9.0.0/16", "10.1.1.9", 2));
        assert_eq!(rib.resolve_nexthop_recursive(ip("10.9.9.7")), None);

        // The moment the held candidate's gateway comes on-link, the
        // chain completes.
        rib.apply_event(&link(3, "eth1", true));
        rib.apply_event(&address(3, "100.64.0.1/32", true));
        assert_eq!(
            rib.resolve_nexthop_recursive(ip("10.9.9.7")),
            Some(Nexthop::Ipv4If("100.64.0.1".parse().unwrap(), 3))
        );
    }

    /// The default prefix never answers the walk — a gateway covered only
    /// by a default route stays unresolved to the plain resolver, and the
    /// flag-set NHT surface (`lookup_nexthop_routed`) is the one path
    /// where the default may answer (A23 semantics, unchanged).
    #[test]
    fn default_prefix_answers_only_the_flag_set_surface() {
        let mut rib = Rib::new();
        rib.apply_event(&link(2, "eth0", true));
        rib.apply_event(&address(2, "10.1.1.1/24", true));
        rib.apply_event(&mirror_route("0.0.0.0/0", "10.1.1.9", 2));

        // 100.64.0.1 is covered only by the default route — the flag-set
        // NHT surface (`lookup_nexthop_routed`) is the one path where it
        // may answer, with no neighbour confirmation (zebra-faithful).
        assert_eq!(rib.resolve_nexthop_recursive(ip("100.64.0.1")), None);
        assert_eq!(rib.lookup_nexthop_routed(ip("100.64.0.1"), false), None);
        assert_eq!(
            rib.lookup_nexthop_routed(ip("100.64.0.1"), true),
            Some(Nexthop::Ipv4If("10.1.1.9".parse().unwrap(), 2))
        );
        // Neighbour state never flips the answer (advisory only).
        rib.apply_event(&neighbour_new("10.1.1.9", 2, None, 0x01));
        assert_eq!(
            rib.lookup_nexthop_routed(ip("100.64.0.1"), true),
            Some(Nexthop::Ipv4If("10.1.1.9".parse().unwrap(), 2))
        );
    }

    /// A kernel-mirror device route (oif-only hop) participates in the
    /// walk and adopts its ifindex for the gateway — the FRR
    /// connected-match behavior.
    #[test]
    fn mirror_device_route_adopts_its_ifindex() {
        let mut rib = Rib::new();
        rib.apply_event(&link(2, "eth0", true));
        rib.apply_event(&address(2, "10.1.1.1/24", true));
        // A mirror route with oif only (device route): IfIndex hop.
        rib.apply_event(&DataplaneEvent::RouteNew {
            table: MAIN_TABLE,
            prefix: "10.99.0.0/24".parse().unwrap(),
            protocol: RouteProtocol::Kernel,
            metric: 0,
            gateway: None,
            oif: Some(7),
        });
        assert_eq!(
            rib.resolve_nexthop_recursive(ip("10.99.0.1")),
            Some(Nexthop::Ipv4If("10.99.0.1".parse().unwrap(), 7)),
            "the device route's ifindex is adopted for the gateway"
        );
    }

    #[test]
    fn unresolved_gateways_prune_on_reload() {
        let mut rib = Rib::new();
        rib.add_route(gw_entry("198.51.100.0/24", "192.0.2.7"));
        assert_eq!(rib.unresolved_gateways().count(), 1);

        // Reload without the route: its gateway is no longer referenced.
        rib.reload_static(&[]);
        assert_eq!(rib.unresolved_gateways().count(), 0);

        // A resolved gateway is tracked but not reported unresolved.
        rib.apply_event(&link(2, "eth0", true));
        rib.apply_event(&address(2, "192.0.2.1/24", true));
        rib.add_route(gw_entry("203.0.113.0/24", "192.0.2.7"));
        assert_eq!(rib.unresolved_gateways().count(), 0);
        // Tracked-but-unresolved and resolved gateways coexist. (M2 note:
        // a gateway inside another route's prefix now resolves THROUGH
        // that route — the recursive-resolver milestone — so the
        // stays-unresolved exemplar is a gateway nothing covers.)
        rib.add_route(gw_entry("198.51.100.0/24", "100.64.0.1"));
        assert_eq!(
            rib.unresolved_gateways().collect::<Vec<_>>(),
            vec![ip("100.64.0.1")]
        );
    }

    // --- VRF device/table awareness (W4) ---

    /// A VRF device link event: kind vrf + bound table, nothing enslaved.
    fn vrf_link(ifindex: u32, name: &str, table: TableId, is_up: bool) -> DataplaneEvent {
        DataplaneEvent::LinkNew {
            ifindex,
            name: name.into(),
            is_up,
            flags: common::LinkFlags::UP,
            vrf_table: Some(table),
            master_ifindex: None,
        }
    }

    /// A member link event: enslaved to `master`, never a VRF itself.
    fn member_link(ifindex: u32, name: &str, master: Option<u32>, is_up: bool) -> DataplaneEvent {
        DataplaneEvent::LinkNew {
            ifindex,
            name: name.into(),
            is_up,
            flags: if is_up {
                common::LinkFlags::up_broadcast()
            } else {
                common::LinkFlags::default()
            },
            vrf_table: None,
            master_ifindex: master,
        }
    }

    #[test]
    fn vrf_link_event_binds_table_to_device() {
        let mut rib = Rib::new();
        rib.apply_event(&vrf_link(5, "vrf-test", 5001, true));

        let iface = rib.interfaces().get(&5).unwrap();
        assert_eq!(iface.name, "vrf-test");
        assert_eq!(iface.vrf_table, Some(5001));
        assert_eq!(iface.master_ifindex, None);

        // The route→VRF association surface: table 5001 answers with the
        // device that owns it; an unbound table answers None.
        let (ifindex, vrf) = rib.vrf_of_table(5001).unwrap();
        assert_eq!(ifindex, 5);
        assert_eq!(vrf.name, "vrf-test");
        assert!(rib.vrf_of_table(5002).is_none());
    }

    #[test]
    fn enslaved_link_records_master() {
        let mut rib = Rib::new();
        rib.apply_event(&vrf_link(5, "vrf-test", 5001, true));
        rib.apply_event(&member_link(2, "dummy0", Some(5), true));

        let dummy = rib.interfaces().get(&2).unwrap();
        assert_eq!(dummy.master_ifindex, Some(5));
        // Membership never makes a link a VRF device.
        assert_eq!(dummy.vrf_table, None);

        // Plain links carry neither payload (extend-not-redesign: the
        // pre-W4 event shape stays representable and defaults to none).
        rib.apply_event(&link(3, "eth0", true));
        let plain = rib.interfaces().get(&3).unwrap();
        assert_eq!(plain.vrf_table, None);
        assert_eq!(plain.master_ifindex, None);
    }

    #[test]
    fn vrf_association_survives_link_flap_and_enslavement_updates() {
        let mut rib = Rib::new();
        rib.apply_event(&vrf_link(5, "vrf-test", 5001, true));

        // Admin state changes re-emit RTM_NEWLINK; the binding must
        // survive (and a down VRF still owns its table — that is
        // observed state, not policy).
        rib.apply_event(&vrf_link(5, "vrf-test", 5001, false));
        assert_eq!(rib.interfaces().get(&5).unwrap().vrf_table, Some(5001));
        assert_eq!(rib.vrf_of_table(5001).unwrap().0, 5);

        // Enslaving and un-enslaving a member both arrive as full-state
        // RTM_NEWLINK notifications; the last one wins.
        rib.apply_event(&member_link(2, "dummy0", Some(5), true));
        assert_eq!(rib.interfaces().get(&2).unwrap().master_ifindex, Some(5));
        rib.apply_event(&member_link(2, "dummy0", None, true));
        assert_eq!(rib.interfaces().get(&2).unwrap().master_ifindex, None);
    }

    #[test]
    fn vrf_device_delete_drops_table_association() {
        let mut rib = Rib::new();
        rib.apply_event(&vrf_link(5, "vrf-test", 5001, true));
        assert!(rib.vrf_of_table(5001).is_some());

        rib.apply_event(&DataplaneEvent::LinkDel { ifindex: 5 });
        assert!(rib.interfaces().get(&5).is_none());
        assert!(
            rib.vrf_of_table(5001).is_none(),
            "the association derives from the interface mirror, so it drops with the device"
        );
    }

    #[test]
    fn kernel_routes_in_vrf_table_associate_with_vrf() {
        let prefix: IpPrefix = "10.9.0.0/16".parse().unwrap();
        let mut rib = Rib::new();
        rib.apply_event(&vrf_link(5, "vrf-test", 5001, true));
        rib.apply_event(&DataplaneEvent::RouteNew {
            table: 5001,
            prefix,
            protocol: RouteProtocol::Kernel,
            metric: 0,
            gateway: None,
            oif: None,
        });

        // The mirror holds the route under its table id (P0D), and the
        // table answers to the VRF device: route → table → VRF.
        let mirror = rib.kernel_table(5001).unwrap();
        assert_eq!(
            mirror.best(&prefix).unwrap().protocol,
            RouteProtocol::Kernel
        );
        let (ifindex, vrf) = rib.vrf_of_table(5001).unwrap();
        assert_eq!(ifindex, 5);
        assert_eq!(vrf.name, "vrf-test");
        assert_eq!(rib.kernel_route_count(), 1);

        // Route deletion removes the mirror entry but not the VRF device.
        rib.apply_event(&DataplaneEvent::RouteDel {
            table: 5001,
            prefix,
        });
        assert!(rib.kernel_table(5001).unwrap().best(&prefix).is_none());
        assert!(rib.vrf_of_table(5001).is_some());
    }

    /// VRF awareness is observation only tonight: an enslaved interface's
    /// addresses still resolve gateways exactly as before (no VRF-scoped
    /// resolution semantics — that is Phase-1+ redistribution work).
    #[test]
    fn vrf_awareness_does_not_change_gateway_resolution() {
        let mut rib = Rib::new();
        rib.apply_event(&vrf_link(5, "vrf-test", 5001, true));
        rib.apply_event(&member_link(2, "dummy0", Some(5), true));
        rib.apply_event(&address(2, "192.0.2.1/24", true));

        assert_eq!(
            rib.resolve_nexthop(ip("192.0.2.9")),
            Some(Nexthop::Ipv4If("192.0.2.9".parse().unwrap(), 2))
        );

        // Flapping the VRF device itself changes nothing for resolution.
        rib.apply_event(&vrf_link(5, "vrf-test", 5001, false));
        assert_eq!(
            rib.resolve_nexthop(ip("192.0.2.9")),
            Some(Nexthop::Ipv4If("192.0.2.9".parse().unwrap(), 2))
        );
    }

    /// Round-trip: a static route configured with `table <N>` where N is a
    /// VRF's table reconciles into that table (P0D behavior, now inside a
    /// recognized VRF), with the gateway resolved via the enslaved
    /// interface's connected prefix.
    #[test]
    fn vrf_table_static_route_round_trips_to_its_table() {
        let mut rib = Rib::new();
        rib.apply_event(&vrf_link(5, "vrf-test", 5001, true));
        rib.apply_event(&member_link(2, "dummy0", Some(5), true));
        rib.apply_event(&address(2, "192.0.2.1/24", true));

        let mut route = gw_entry("203.0.113.0/24", "192.0.2.9");
        route.table = 5001;
        rib.add_route(route);
        assert!(rib.vrf_of_table(5001).is_some(), "route's table is a VRF");

        let dp = MockDp::default();
        block_on(rib.reconcile(&dp));
        let installed = dp.installed.lock().unwrap();
        assert_eq!(installed.len(), 1);
        assert_eq!(
            installed[0].table, 5001,
            "programmed back into the VRF table"
        );
        assert_eq!(
            installed[0].nexthops.hops(),
            &[(Nexthop::Ipv4If("192.0.2.9".parse().unwrap(), 2), 1)],
            "gateway resolved through the enslaved member interface"
        );
    }

    // --- Connected protocol routes (the CONNECT table) ---

    /// Address events populate Connected routes in the main table: the
    /// network form of each address on an UP interface, nexthop = the
    /// interface, and the address's removal (or the link going away)
    /// withdraws them. The kernel FIB mirror is NOT the source — these
    /// are connected-table candidates for `redistribute connected` and
    /// distance-0 best-path masking.
    #[test]
    fn connected_routes_populate_from_address_events() {
        let mut rib = Rib::new();
        rib.apply_event(&link(2, "eth0", true));
        rib.apply_event(&address(2, "10.1.2.3/24", true));
        rib.apply_event(&address(2, "2001:db8:1::1/64", true));
        // Host prefix with host bits set: the connected route announces
        // the NETWORK form.
        rib.apply_event(&link(3, "lo", true));
        rib.apply_event(&address(3, "127.0.0.1/8", true));

        let best = rib
            .best_with_connected(MAIN_TABLE, &"10.1.2.0/24".parse().unwrap())
            .unwrap();
        assert_eq!(best.protocol, RouteProtocol::Connected);
        assert_eq!(best.metric, 0);
        assert_eq!(
            best.nexthops.hops(),
            &[(Nexthop::IfIndex(2), 1)],
            "connected routes point at the interface"
        );
        assert_eq!(
            rib.best_with_connected(MAIN_TABLE, &"127.0.0.0/8".parse().unwrap())
                .unwrap()
                .protocol,
            RouteProtocol::Connected
        );
        assert_eq!(
            rib.best_with_connected(MAIN_TABLE, &"2001:db8:1::/64".parse().unwrap())
                .unwrap()
                .protocol,
            RouteProtocol::Connected
        );

        // Duplicate notification is idempotent (same candidate replaced).
        rib.apply_event(&address(2, "10.1.2.3/24", true));
        assert!(rib
            .best_with_connected(MAIN_TABLE, &"10.1.2.0/24".parse().unwrap())
            .is_some());

        // Address removal withdraws exactly that connected prefix.
        rib.apply_event(&address(2, "10.1.2.3/24", false));
        assert!(rib
            .best_with_connected(MAIN_TABLE, &"10.1.2.0/24".parse().unwrap())
            .is_none());

        // Link down withdraws the interface's remaining connected routes
        // (v6), and link gone entirely does the same.
        rib.apply_event(&link(2, "eth0", false));
        assert!(rib
            .best_with_connected(MAIN_TABLE, &"2001:db8:1::/64".parse().unwrap())
            .is_none());
        rib.apply_event(&DataplaneEvent::LinkDel { ifindex: 3 });
        assert!(rib
            .best_with_connected(MAIN_TABLE, &"127.0.0.0/8".parse().unwrap())
            .is_none());
    }

    /// Connected routes are never programmed by reconcile, and a connected
    /// best MASKS other candidates for its prefix (nothing else programs
    /// while it rules — the kernel's own connected route is authoritative).
    /// When the connected candidate goes away, the next-best candidate
    /// programs normally.
    #[test]
    fn connected_routes_are_never_programmed() {
        let mut rib = Rib::new();
        rib.apply_event(&link(2, "eth0", true));
        rib.apply_event(&address(2, "10.1.2.3/24", true));
        // A static candidate for the same prefix: connected wins at
        // distance 0, and reconcile programs NEITHER.
        rib.add_route(RouteEntry::new(
            "10.1.2.0/24".parse().unwrap(),
            RouteProtocol::Static,
            NexthopGroup::single(Nexthop::Blackhole),
            0,
        ));
        assert_eq!(
            rib.best_with_connected(MAIN_TABLE, &"10.1.2.0/24".parse().unwrap())
                .unwrap()
                .protocol,
            RouteProtocol::Connected,
            "the merged best-path view is connected-masked"
        );

        let dp = MockDp::default();
        block_on(rib.reconcile(&dp));
        assert!(
            dp.installed_prefixes().is_empty(),
            "connected best: nothing programs, the kernel route stays"
        );

        // Address gone → connected candidate gone → static best programs.
        rib.apply_event(&address(2, "10.1.2.3/24", false));
        block_on(rib.reconcile(&dp));
        assert_eq!(
            dp.installed_prefixes(),
            vec!["10.1.2.0/24".parse().unwrap()]
        );

        // And back: the connected candidate returns and reconcile
        // withdraws the static route it now masks.
        rib.apply_event(&address(2, "10.1.2.3/24", true));
        block_on(rib.reconcile(&dp));
        assert_eq!(dp.removed_prefixes(), vec!["10.1.2.0/24".parse().unwrap()]);
    }

    /// An interface enslaved to a VRF device gets its connected routes in
    /// the VRF's table — where the kernel itself puts them (W4 observed
    /// table 5001 holding the member's connected route) — never in main.
    #[test]
    fn connected_routes_live_in_the_enslaving_vrfs_table() {
        let mut rib = Rib::new();
        rib.apply_event(&vrf_link(5, "vrf-test", 5001, true));
        rib.apply_event(&member_link(2, "dummy0", Some(5), true));
        rib.apply_event(&address(2, "192.0.2.1/24", true));
        // An unenslaved interface's connected route stays in main.
        rib.apply_event(&link(3, "eth1", true));
        rib.apply_event(&address(3, "10.9.9.1/24", true));

        assert_eq!(
            rib.best_with_connected(5001, &"192.0.2.0/24".parse().unwrap())
                .unwrap()
                .protocol,
            RouteProtocol::Connected
        );
        assert!(rib
            .best_with_connected(MAIN_TABLE, &"192.0.2.0/24".parse().unwrap())
            .is_none());
        assert_eq!(
            rib.best_with_connected(MAIN_TABLE, &"10.9.9.0/24".parse().unwrap())
                .unwrap()
                .protocol,
            RouteProtocol::Connected
        );

        // Un-enslaving the member moves its connected routes back to main.
        rib.apply_event(&member_link(2, "dummy0", None, true));
        assert!(rib
            .best_with_connected(MAIN_TABLE, &"192.0.2.0/24".parse().unwrap())
            .is_some());
        assert!(rib
            .best_with_connected(5001, &"192.0.2.0/24".parse().unwrap())
            .is_none());
    }

    /// connected_keys is the exact surface link/address events can change:
    /// the keys are present while candidates exist and disappear with them.
    #[test]
    fn connected_keys_track_the_connected_surface() {
        let mut rib = Rib::new();
        rib.apply_event(&link(2, "eth0", true));
        rib.apply_event(&address(2, "10.1.2.3/24", true));
        rib.apply_event(&link(5, "vrf-test-up", true));
        let mut keys: Vec<(TableId, IpPrefix)> = rib.connected_keys().collect();
        keys.sort();
        assert_eq!(
            keys,
            vec![(254, "10.1.2.0/24".parse().unwrap())],
            "link events alone contribute nothing"
        );

        rib.apply_event(&address(2, "10.1.2.3/24", false));
        assert_eq!(rib.connected_keys().count(), 0);
    }
}
