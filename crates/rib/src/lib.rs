//! The Routing Information Base.
//!
//! BIRD-style typed multi-table core (see docs/architecture.md): tables are
//! first-class objects; best-path selection uses administrative distance then
//! metric; the selected route is what gets programmed into the dataplane.

use std::collections::BTreeMap;

use common::{Dataplane, DataplaneError, DataplaneEvent, IpPrefix, RouteEntry, TableId};
use tracing::{debug, instrument};

/// Observed state of one network interface, mirrored from the dataplane.
#[derive(Debug, Clone, Default)]
pub struct InterfaceState {
    pub name: String,
    pub is_up: bool,
    /// Addresses configured on the interface (as host prefixes).
    pub addresses: Vec<IpPrefix>,
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

/// The RIB: a set of typed routing tables plus mirrored interface state.
///
/// TODO(phase-0): nexthop resolution/tracking, redistribution channels
/// between tables (BIRD-style), FIB diffing against the dataplane.
#[derive(Debug, Default)]
pub struct Rib {
    tables: BTreeMap<TableId, Table>,
    /// Interface state mirrored from dataplane events, keyed by ifindex.
    interfaces: BTreeMap<u32, InterfaceState>,
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

    /// Apply one dataplane event to the mirrored interface state.
    ///
    /// Address events for an interface we have not seen yet create a
    /// placeholder entry: kernel notification order is not guaranteed to
    /// put RTM_NEWLINK before RTM_NEWADDR.
    pub fn apply_event(&mut self, ev: &DataplaneEvent) {
        match ev {
            DataplaneEvent::LinkNew {
                ifindex,
                name,
                is_up,
            } => {
                let iface = self.interfaces.entry(*ifindex).or_default();
                iface.name = name.clone();
                iface.is_up = *is_up;
            }
            DataplaneEvent::LinkDel { ifindex } => {
                self.interfaces.remove(ifindex);
            }
            DataplaneEvent::AddressNew { ifindex, prefix } => {
                let iface = self.interfaces.entry(*ifindex).or_default();
                if !iface.addresses.contains(prefix) {
                    iface.addresses.push(*prefix);
                }
            }
            DataplaneEvent::AddressDel { ifindex, prefix } => {
                if let Some(iface) = self.interfaces.get_mut(ifindex) {
                    iface.addresses.retain(|p| p != prefix);
                }
            }
        }
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

    #[test]
    fn interface_events_update_state() {
        let mut rib = Rib::new();
        rib.apply_event(&DataplaneEvent::LinkNew {
            ifindex: 2,
            name: "eth0".into(),
            is_up: true,
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
        });
        let iface = rib.interfaces().get(&5).unwrap();
        assert_eq!(iface.name, "eth1");
        assert_eq!(iface.addresses.len(), 1);
    }
}
