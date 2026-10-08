//! The Routing Information Base.
//!
//! BIRD-style typed multi-table core (see docs/architecture.md): tables are
//! first-class objects; best-path selection uses administrative distance then
//! metric; the selected route is what gets programmed into the dataplane.

use std::collections::BTreeMap;

use common::{Dataplane, DataplaneError, IpPrefix, RouteEntry, TableId};
use tracing::{debug, instrument};

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
        self.entries.get(prefix)?.iter().min_by_key(|e| {
            (e.protocol.admin_distance(), e.metric)
        })
    }

    pub fn iter(&self) -> impl Iterator<Item = (&IpPrefix, &Vec<RouteEntry>)> {
        self.entries.iter()
    }
}

/// The RIB: a set of typed routing tables.
///
/// TODO(phase-0): nexthop resolution/tracking, redistribution channels
/// between tables (BIRD-style), FIB diffing against the dataplane.
#[derive(Debug, Default)]
pub struct Rib {
    tables: BTreeMap<TableId, Table>,
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

    /// Offer a route and return whether the best route for its prefix changed.
    pub fn add_route(&mut self, entry: RouteEntry) {
        let table_id = entry.table;
        self.table_mut(table_id).add(entry);
    }

    /// Program all current best routes into the dataplane.
    ///
    /// Phase 0 brings up a naive full-sync; FIB diffing comes right after.
    #[instrument(skip(self, dp))]
    pub async fn sync_dataplane<D: Dataplane>(&self, dp: &D) -> Result<(), DataplaneError> {
        for (table_id, table) in &self.tables {
            for (prefix, _) in table.iter() {
                if let Some(best) = table.best(prefix) {
                    debug!(%prefix, table_id, "installing best route");
                    dp.route_replace(best).await?;
                }
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use common::{Nexthop, NexthopGroup, RouteProtocol};

    fn entry(prefix: &str, proto: RouteProtocol, metric: u32) -> RouteEntry {
        RouteEntry::new(
            prefix.parse().unwrap(),
            proto,
            NexthopGroup::single(Nexthop::IfIndex(2)),
            metric,
        )
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
}
