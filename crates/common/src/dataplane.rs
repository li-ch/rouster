//! The dataplane abstraction.
//!
//! Everything that programs or observes the forwarding plane goes through this
//! trait: netlink (today), FPM/eBPF (later). No component outside the
//! dataplane crate(s) may talk to the kernel directly.

use std::fmt;
use std::future::Future;
use std::net::IpAddr;

use crate::neighbour::NeighbourEntry;
use crate::prefix::IpPrefix;
use crate::route::{RouteEntry, RouteProtocol, TableId};

/// Error type for dataplane operations.
#[derive(Debug, thiserror::Error)]
pub enum DataplaneError {
    #[error("dataplane I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("dataplane operation not supported: {0}")]
    Unsupported(&'static str),
    #[error("dataplane error: {0}")]
    Other(String),
}

/// Events observed from the forwarding plane (link, address, and route
/// changes).
///
/// The RIB consumes these for nexthop resolution, interface tracking, and
/// (for the route events) the kernel FIB mirror.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DataplaneEvent {
    LinkNew {
        ifindex: u32,
        name: String,
        is_up: bool,
        /// Routing table bound to the link when it is a VRF device (link
        /// kind "vrf", `IFLA_VRF_TABLE`); `None` for every other link kind.
        vrf_table: Option<TableId>,
        /// Ifindex of the master device the link is enslaved to via
        /// `IFLA_MASTER` (a VRF device in the VRF case; bridges and bonds
        /// use the same attribute); `None` when unenslaved.
        master_ifindex: Option<u32>,
    },
    LinkDel {
        ifindex: u32,
    },
    /// An address was configured on an interface (host prefix, e.g.
    /// 10.0.0.1/24 on eth0).
    AddressNew {
        ifindex: u32,
        prefix: IpPrefix,
    },
    AddressDel {
        ifindex: u32,
        prefix: IpPrefix,
    },
    /// A kernel-origin route was observed in the forwarding plane (mirror
    /// direction: routes we did NOT program ourselves; see
    /// [`RouteProtocol::is_kernel_origin`]).
    RouteNew {
        table: TableId,
        prefix: IpPrefix,
        protocol: RouteProtocol,
        metric: u32,
    },
    /// A route left the forwarding plane. Unlike [`DataplaneEvent::RouteNew`]
    /// this is not filtered by origin: whoever deleted it, the kernel no
    /// longer has it, and the RIB must drop its programmed-set belief so a
    /// still-desired route is reinstalled.
    RouteDel {
        table: TableId,
        prefix: IpPrefix,
    },
    /// A neighbour (ARP/NDP) entry was observed in the forwarding plane.
    /// Mirror direction only: neighbours are never programmed by Rouster
    /// (read-only awareness). Replacements arrive as `NeighbourNew` for an
    /// existing (ip, link) key.
    NeighbourNew {
        entry: NeighbourEntry,
    },
    /// A neighbour entry left the forwarding plane (RTM_DELNEIGH).
    NeighbourDel {
        ip: IpAddr,
        link_ifindex: u32,
    },
}

impl fmt::Display for DataplaneEvent {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DataplaneEvent::LinkNew {
                ifindex,
                name,
                is_up,
                vrf_table,
                master_ifindex,
            } => {
                write!(
                    f,
                    "link new: {name} (ifindex {ifindex}, {}",
                    if *is_up { "up" } else { "down" }
                )?;
                if let Some(table) = vrf_table {
                    write!(f, ", vrf table {table}")?;
                }
                if let Some(master) = master_ifindex {
                    write!(f, ", master ifindex {master}")?;
                }
                write!(f, ")")
            }
            DataplaneEvent::LinkDel { ifindex } => write!(f, "link del: ifindex {ifindex}"),
            DataplaneEvent::AddressNew { ifindex, prefix } => {
                write!(f, "addr new: {prefix} on ifindex {ifindex}")
            }
            DataplaneEvent::AddressDel { ifindex, prefix } => {
                write!(f, "addr del: {prefix} on ifindex {ifindex}")
            }
            DataplaneEvent::RouteNew {
                table,
                prefix,
                protocol,
                metric,
            } => write!(
                f,
                "route new: {prefix} table {table} proto {protocol:?} metric {metric}"
            ),
            DataplaneEvent::RouteDel { table, prefix } => {
                write!(f, "route del: {prefix} table {table}")
            }
            DataplaneEvent::NeighbourNew { entry } => {
                write!(f, "neighbour new: {entry}")
            }
            DataplaneEvent::NeighbourDel { ip, link_ifindex } => {
                write!(f, "neighbour del: {ip} dev {link_ifindex}")
            }
        }
    }
}

/// The forwarding-plane interface.
///
/// Implemented by `netlink-dp` today; FPM/eBPF backends plug in later without
/// touching the RIB or protocol crates.
pub trait Dataplane {
    /// Atomically install or replace a route (RTM_NEWROUTE NLM_F_REPLACE).
    fn route_replace(
        &self,
        entry: &RouteEntry,
    ) -> impl Future<Output = Result<(), DataplaneError>> + Send;

    /// Remove a route (RTM_DELROUTE).
    fn route_delete(
        &self,
        entry: &RouteEntry,
    ) -> impl Future<Output = Result<(), DataplaneError>> + Send;

    // TODO(phase-0): netns awareness; TODO(phase-1): nexthop-group
    // objects. (Initial dump + event stream for links — including VRF
    // device/table association —, addresses, routes, and neighbours is
    // done — see the netlink-dp backend.)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn link_new(vrf_table: Option<u32>, master_ifindex: Option<u32>) -> DataplaneEvent {
        DataplaneEvent::LinkNew {
            ifindex: 5,
            name: "vrf-test".into(),
            is_up: true,
            vrf_table,
            master_ifindex,
        }
    }

    /// A plain link renders exactly as before the VRF extension; a VRF
    /// device and an enslaved link each carry their new payload (smoke
    /// greps pin the same rendering live).
    #[test]
    fn link_new_display_carries_vrf_and_master_fields() {
        let plain = DataplaneEvent::LinkNew {
            ifindex: 2,
            name: "eth0".into(),
            is_up: false,
            vrf_table: None,
            master_ifindex: None,
        };
        assert_eq!(plain.to_string(), "link new: eth0 (ifindex 2, down)");

        let vrf = link_new(Some(5001), None);
        assert_eq!(
            vrf.to_string(),
            "link new: vrf-test (ifindex 5, up, vrf table 5001)"
        );

        let enslaved = link_new(None, Some(5));
        assert_eq!(
            enslaved.to_string(),
            "link new: vrf-test (ifindex 5, up, master ifindex 5)"
        );

        // A VRF device is never itself enslaved; a link may still carry
        // both payloads in a malformed stream — rendering covers it.
        let both = link_new(Some(5001), Some(9));
        assert_eq!(
            both.to_string(),
            "link new: vrf-test (ifindex 5, up, vrf table 5001, master ifindex 9)"
        );
    }
}
