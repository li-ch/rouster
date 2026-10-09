//! The Routing Information Base.
//!
//! BIRD-style typed multi-table core (see docs/architecture.md): tables are
//! first-class objects; best-path selection uses administrative distance then
//! metric; the selected route is what gets programmed into the dataplane.

use std::collections::{BTreeMap, BTreeSet};
use std::net::IpAddr;

use common::{
    Dataplane, DataplaneEvent, IpPrefix, NeighbourEntry, Nexthop, NexthopGroup, RouteEntry,
    RouteProtocol, TableId,
};
use tracing::{debug, info, instrument, warn};

/// Observed state of one network interface, mirrored from the dataplane.
#[derive(Debug, Clone, Default)]
pub struct InterfaceState {
    pub name: String,
    pub is_up: bool,
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
/// TODO(phase-1): recursive (multi-hop) nexthop resolution; redistribution
/// channels between tables (BIRD-style).
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
    /// Recursive (multi-hop) resolution is deliberately not implemented
    /// yet; a gateway only reachable through another route stays `None`.
    pub fn resolve_nexthop(&self, gw: IpAddr) -> Option<Nexthop> {
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

    /// NHT query API — the stable surface the ZAPI server answers
    /// `NEXTHOP_UPDATE` from: the resolved hop for an arbitrary IP (not
    /// just tracked gateways), computed directly by
    /// [`Rib::resolve_nexthop`]. `None` = unresolved.
    pub fn lookup_nexthop(&self, ip: IpAddr) -> Option<Nexthop> {
        self.resolve_nexthop(ip)
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
                let resolution = self.resolve_nexthop(gw);
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
                Nexthop::Ipv4(g) => match self.resolve_nexthop(IpAddr::V4(g)) {
                    Some(resolved_hop) => resolved_hop,
                    // Unresolved gateway: excluded from the programmed
                    // subset; if it was the only hop, the group is empty
                    // and the route is not programmed at all.
                    None => continue,
                },
                Nexthop::Ipv6(g) => match self.resolve_nexthop(IpAddr::V6(g)) {
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
                vrf_table,
                master_ifindex,
            } => {
                let iface = self.interfaces.entry(*ifindex).or_default();
                iface.name = name.clone();
                iface.is_up = *is_up;
                // Each RTM_NEWLINK carries the link's full state: both VRF
                // fields overwrite unconditionally, so (un)enslaving or
                // re-binding a device is reflected on the next notification.
                iface.vrf_table = *vrf_table;
                iface.master_ifindex = *master_ifindex;
                self.rebuild_nht();
            }
            DataplaneEvent::LinkDel { ifindex } => {
                self.interfaces.remove(ifindex);
                self.rebuild_nht();
            }
            DataplaneEvent::AddressNew { ifindex, prefix } => {
                let iface = self.interfaces.entry(*ifindex).or_default();
                if !iface.addresses.contains(prefix) {
                    iface.addresses.push(*prefix);
                }
                self.rebuild_nht();
            }
            DataplaneEvent::AddressDel { ifindex, prefix } => {
                if let Some(iface) = self.interfaces.get_mut(ifindex) {
                    iface.addresses.retain(|p| p != prefix);
                }
                self.rebuild_nht();
            }
            DataplaneEvent::RouteNew {
                table,
                prefix,
                protocol,
                metric,
            } => {
                // Backends already filter self-originated notifications;
                // this is the second half of the feedback-loop defense.
                if !protocol.is_kernel_origin() {
                    return;
                }
                let mut entry = RouteEntry::new(
                    *prefix,
                    RouteProtocol::Kernel,
                    // Nexthop detail is not carried by the event; mirror
                    // entries are observed state and never programmed.
                    NexthopGroup::new(),
                    *metric,
                );
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
        let table_id = entry.table;
        for gw in gateway_ips(&entry.nexthops) {
            let resolved = self.resolve_nexthop(gw);
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
    pub async fn reconcile<D: Dataplane>(&mut self, dp: &D) {
        let mut desired: BTreeMap<(TableId, IpPrefix), RouteEntry> = BTreeMap::new();
        for (&table_id, table) in &self.tables {
            for (prefix, _) in table.iter() {
                let Some(best) = table.best(prefix) else {
                    continue;
                };
                match self.resolved_programming_form(best) {
                    Some(form) => {
                        desired.insert((table_id, *prefix), form);
                    }
                    None => debug!(
                        prefix = %best.prefix,
                        table_id,
                        "best route has no resolved nexthop; held in RIB, not programmed"
                    ),
                }
            }
        }

        let mut installed = 0usize;
        let mut unchanged = 0usize;
        for (key, best) in &desired {
            if self.programmed.get(key) == Some(best) {
                unchanged += 1;
                continue;
            }
            match dp.route_replace(best).await {
                Ok(()) => {
                    debug!(prefix = %best.prefix, table_id = best.table, "installed best route");
                    self.programmed.insert(*key, best.clone());
                    installed += 1;
                }
                Err(e) => {
                    warn!(prefix = %best.prefix, table_id = best.table, %e, "route install failed; will retry")
                }
            }
        }

        let mut withdrawn = 0usize;
        let stale: Vec<(TableId, IpPrefix)> = self
            .programmed
            .keys()
            .filter(|key| !desired.contains_key(key))
            .copied()
            .collect();
        for key in stale {
            let Some(entry) = self.programmed.remove(&key) else {
                continue;
            };
            match dp.route_delete(&entry).await {
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
            vrf_table: None,
            master_ifindex: None,
        });
        let iface = rib.interfaces().get(&5).unwrap();
        assert_eq!(iface.name, "eth1");
        assert_eq!(iface.addresses.len(), 1);
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
        });
        rib.apply_event(&DataplaneEvent::RouteNew {
            table: 255,
            prefix: "192.0.2.0/24".parse().unwrap(),
            protocol: RouteProtocol::Kernel,
            metric: 0,
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
        });
        assert_eq!(rib.kernel_route_count(), 0);

        // Nor may a self-originated echo evict mirrored kernel state.
        rib.apply_event(&DataplaneEvent::RouteNew {
            table: 254,
            prefix,
            protocol: RouteProtocol::Kernel,
            metric: 0,
        });
        rib.apply_event(&DataplaneEvent::RouteNew {
            table: 254,
            prefix,
            protocol: RouteProtocol::Ospf,
            metric: 0,
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

    /// Neighbour events are read-only awareness: they must not move the
    /// kernel route mirror, the programmed set, or gateway resolution.
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
        });
        let resolved = rib.resolve_nexthop(ip("192.0.2.7"));
        assert!(resolved.is_some());
        assert_eq!(rib.kernel_route_count(), 1);

        // A neighbour for the gateway IP appearing and disappearing changes
        // neither resolution (prefix-based tonight) nor the route mirror.
        rib.apply_event(&neighbour_new("192.0.2.7", 2, Some(0x07), 0x80));
        assert_eq!(rib.resolve_nexthop(ip("192.0.2.7")), resolved);
        assert_eq!(rib.kernel_route_count(), 1);
        rib.apply_event(&DataplaneEvent::NeighbourDel {
            ip: ip("192.0.2.7"),
            link_ifindex: 2,
        });
        assert_eq!(rib.resolve_nexthop(ip("192.0.2.7")), resolved);
        assert_eq!(rib.kernel_route_count(), 1);
    }

    // --- Nexthop resolution & tracking (P0B) ---

    fn link(ifindex: u32, name: &str, is_up: bool) -> DataplaneEvent {
        DataplaneEvent::LinkNew {
            ifindex,
            name: name.into(),
            is_up,
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
        // Tracked-but-unresolved and resolved gateways coexist.
        rib.add_route(gw_entry("198.51.100.0/24", "203.0.113.7"));
        assert_eq!(
            rib.unresolved_gateways().collect::<Vec<_>>(),
            vec![ip("203.0.113.7")]
        );
    }

    // --- VRF device/table awareness (W4) ---

    /// A VRF device link event: kind vrf + bound table, nothing enslaved.
    fn vrf_link(ifindex: u32, name: &str, table: TableId, is_up: bool) -> DataplaneEvent {
        DataplaneEvent::LinkNew {
            ifindex,
            name: name.into(),
            is_up,
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
}
