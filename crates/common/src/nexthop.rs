//! Nexthop and nexthop-group (ECMP) types.

use std::net::{Ipv4Addr, Ipv6Addr};

/// A single nexthop.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Nexthop {
    Ipv4(Ipv4Addr),
    Ipv6(Ipv6Addr),
    /// Directly reachable via this interface index.
    IfIndex(u32),
    Ipv4If(Ipv4Addr, u32),
    Ipv6If(Ipv6Addr, u32),
    Blackhole,
}

/// An ECMP nexthop group: weighted set of nexthops.
///
/// Weights follow the Linux nexthop-group model (1..=255 relative weights).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct NexthopGroup {
    hops: Vec<(Nexthop, u8)>,
}

impl NexthopGroup {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn single(hop: Nexthop) -> Self {
        let mut g = Self::new();
        g.add(hop, 1);
        g
    }

    pub fn add(&mut self, hop: Nexthop, weight: u8) {
        self.hops.push((hop, weight.max(1)));
    }

    pub fn hops(&self) -> &[(Nexthop, u8)] {
        &self.hops
    }

    pub fn is_empty(&self) -> bool {
        self.hops.is_empty()
    }
}
