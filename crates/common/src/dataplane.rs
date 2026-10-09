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
            } => write!(
                f,
                "link new: {name} (ifindex {ifindex}, {})",
                if *is_up { "up" } else { "down" }
            ),
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

    // TODO(phase-0): nexthop-group objects, VRF/netns awareness. (Initial
    // dump + event stream for links, addresses, routes, and neighbours is
    // done — see the netlink-dp backend.)
}
