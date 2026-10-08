//! Route entries exchanged between the RIB, protocols, and the dataplane.

use crate::nexthop::NexthopGroup;
use crate::prefix::IpPrefix;

/// Kernel routing table identifier (`RT_TABLE_MAIN` is 254 on Linux).
pub type TableId = u32;

/// Origin protocol of a route. Ordering of [`RouteProtocol::admin_distance`]
/// follows common router convention (lower wins).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum RouteProtocol {
    Kernel,
    Connected,
    Static,
    Bgp,
    Ospf,
    IsIs,
    Rip,
    /// SAV-generated or other locally synthesized entries.
    Local,
}

impl RouteProtocol {
    /// Administrative distance (lower is preferred).
    ///
    /// Roughly FRR/Cisco convention; single source of truth for the RIB's
    /// best-path selection.
    pub fn admin_distance(&self) -> u8 {
        match self {
            RouteProtocol::Connected => 0,
            RouteProtocol::Static => 1,
            RouteProtocol::Bgp => 20,
            RouteProtocol::Ospf => 110,
            RouteProtocol::IsIs => 115,
            RouteProtocol::Rip => 120,
            RouteProtocol::Local => 250,
            RouteProtocol::Kernel => 255,
        }
    }
}

/// One route offered to, or selected by, the RIB.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RouteEntry {
    pub prefix: IpPrefix,
    pub nexthops: NexthopGroup,
    pub metric: u32,
    pub protocol: RouteProtocol,
    pub table: TableId,
}

impl RouteEntry {
    pub fn new(
        prefix: IpPrefix,
        protocol: RouteProtocol,
        nexthops: NexthopGroup,
        metric: u32,
    ) -> Self {
        Self {
            prefix,
            nexthops,
            metric,
            protocol,
            table: 254, // RT_TABLE_MAIN
        }
    }
}
