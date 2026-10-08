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

    /// True for origins installed by the kernel itself or the boot process —
    /// routes Rouster did NOT program. Dataplane backends emit
    /// [`crate::DataplaneEvent::RouteNew`] mirror events only for
    /// kernel-origin routes; notifications echoing routes Rouster installed
    /// (static/bgp/ospf/rip/...) are suppressed to avoid feedback loops
    /// between the RIB and the kernel.
    pub fn is_kernel_origin(self) -> bool {
        matches!(self, RouteProtocol::Kernel | RouteProtocol::Connected)
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

#[cfg(test)]
mod tests {
    use super::*;

    /// The mirror feedback filter: self-originated protocols must not be
    /// classified as kernel-origin, so their install echoes are suppressed.
    #[test]
    fn kernel_origin_classification() {
        assert!(RouteProtocol::Kernel.is_kernel_origin());
        assert!(RouteProtocol::Connected.is_kernel_origin());
        for p in [
            RouteProtocol::Static,
            RouteProtocol::Bgp,
            RouteProtocol::Ospf,
            RouteProtocol::IsIs,
            RouteProtocol::Rip,
            RouteProtocol::Local,
        ] {
            assert!(!p.is_kernel_origin(), "{p:?} must not be kernel-origin");
        }
    }
}
