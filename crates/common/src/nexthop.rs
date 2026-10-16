//! Nexthop and nexthop-group (ECMP) types.

use std::net::{Ipv4Addr, Ipv6Addr};
use std::sync::Arc;

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
///
/// PERF-P3 (M3 L1, disclosed common-type change): the hops live behind
/// an `Arc` — a cloned group now SHARES its heap buffer instead of
/// duplicating it. The RIB-side consumers hold two copies of every
/// route's group (the candidate in the protocol table + the programmed
/// belief), and whole tables share one group (the PERF-P3 census: ONE
/// distinct group across a 100k-prefix single-upstream import); the
/// rib interns groups at its boundary so equal groups pin one buffer —
/// FRR's shared nexthop objects are the known art (structure learned,
/// no code copied). Builders keep the `add` append shape: a freshly
/// built group is exclusively owned, so `Arc::make_mut` never copies
/// during construction; only mutating a SHARED clone pays a
/// copy-on-write. `PartialEq`/hashing semantics are unchanged (the
/// `Arc` delegates by value).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct NexthopGroup {
    hops: Arc<Vec<(Nexthop, u8)>>,
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
        Arc::make_mut(&mut self.hops).push((hop, weight.max(1)));
    }

    pub fn hops(&self) -> &[(Nexthop, u8)] {
        &self.hops
    }

    pub fn is_empty(&self) -> bool {
        self.hops.is_empty()
    }

    /// Wraps an already-shared hop buffer (the interning counterpart:
    /// the rib's canonical-group cache hands out `Arc` clones and this
    /// rebuilds a group around one).
    pub fn from_shared(hops: Arc<Vec<(Nexthop, u8)>>) -> Self {
        Self { hops }
    }

    /// The shared storage handle — the rib-side interner's lookup key.
    pub fn as_shared(&self) -> &Arc<Vec<(Nexthop, u8)>> {
        &self.hops
    }
}
