//! Shared types for the Rouster routing suite.
//!
//! Everything here is protocol- and platform-agnostic. Dataplane and
//! inter-component boundaries are defined in terms of these types.

pub mod dataplane;
pub mod neighbour;
pub mod nexthop;
pub mod prefix;
pub mod route;
pub mod rundir;

pub use dataplane::{
    Dataplane, DataplaneError, DataplaneEvent, LinkFlags, SavEnforce, SavMonitorCounts, SavProgram,
    SavProgramOp, SavUrpf,
};
pub use neighbour::{
    NeighbourCacheInfo, NeighbourEntry, NeighbourFlags, NeighbourProtocol, NeighbourState,
};
pub use nexthop::{Nexthop, NexthopGroup};
pub use prefix::{IpPrefix, Ipv4Prefix, Ipv6Prefix, PrefixError};
pub use route::{RouteEntry, RouteProtocol, TableId};
