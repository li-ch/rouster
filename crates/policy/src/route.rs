//! The route window a filter sees: `RouteView` + the policy-owned BGP
//! attribute model. [W1-a M1]
//!
//! BIRD precedent: "Filter gets the route, looks at its attributes and
//! modifies some of them if it wishes. At the end, it decides whether to
//! pass the changed route through (using accept) or whether to reject it."
//! — BIRD 2.x user guide, ch. 5 §5.1. Our `RouteView` is the read side of
//! that window; [`crate::RouteData`] is the owned snapshot filters mutate.

use common::{IpPrefix, NexthopGroup, RouteProtocol};
use std::fmt;

/// True if the first `n` bits of `a` and `b` are equal.
///
/// Shared bit-math for prefix-covering checks across both address
/// families (octet arrays of length 4 or 16).
pub(crate) fn common_bits_equal(a: &[u8], b: &[u8], n: usize) -> bool {
    for i in 0..n / 8 {
        if a[i] != b[i] {
            return false;
        }
    }
    let rem = n % 8;
    if rem == 0 {
        true
    } else {
        let mask = 0xffu8 << (8 - rem);
        (a[n / 8] & mask) == (b[n / 8] & mask)
    }
}

/// Maximum prefix length for the prefix's address family (32 / 128).
pub(crate) fn max_plen(p: &IpPrefix) -> u8 {
    match p {
        IpPrefix::V4(_) => 32,
        IpPrefix::V6(_) => 128,
    }
}

/// Prefix length of `p`.
pub(crate) fn plen(p: &IpPrefix) -> u8 {
    match p {
        IpPrefix::V4(x) => x.prefix_len(),
        IpPrefix::V6(x) => x.prefix_len(),
    }
}

/// Prefix `inner` is covered by `outer`: the first `outer`-len bits of
/// both addresses are equal (network containment); mixed families never
/// cover.
pub(crate) fn prefix_covers(outer: &IpPrefix, inner: &IpPrefix) -> bool {
    match (outer, inner) {
        (IpPrefix::V4(o), IpPrefix::V4(i)) => {
            let (oa, ia) = (o.addr().octets(), i.addr().octets());
            common_bits_equal(&oa, &ia, o.prefix_len() as usize)
        }
        (IpPrefix::V6(o), IpPrefix::V6(i)) => {
            let (oa, ia) = (o.addr().octets(), i.addr().octets());
            common_bits_equal(&oa, &ia, o.prefix_len() as usize)
        }
        _ => false,
    }
}

/// One BGP AS path segment (RFC 4271 §4.3; AS_SET per RFC 5065 usage).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AsSegment {
    Sequence(Vec<u32>),
    Set(Vec<u32>),
}

impl AsSegment {
    /// Number of AS numbers in this segment.
    pub fn len(&self) -> usize {
        match self {
            AsSegment::Sequence(v) | AsSegment::Set(v) => v.len(),
        }
    }

    /// True when the segment holds no AS numbers.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

/// A BGP AS path: an ordered list of segments.
///
/// Kept minimal and policy-owned: `common` has no BGP types yet; bgpd
/// (W2-d) will convert from its wire model into this one via `From`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AsPath {
    segments: Vec<AsSegment>,
}

impl AsPath {
    /// Path from a plain AS_SEQUENCE, e.g. `AsPath::from_sequence(&[65001,
    /// 65002])`.
    pub fn from_sequence(asns: &[u32]) -> Self {
        Self {
            segments: vec![AsSegment::Sequence(asns.to_vec())],
        }
    }

    pub fn from_segments(segments: Vec<AsSegment>) -> Self {
        Self { segments }
    }

    pub fn segments(&self) -> &[AsSegment] {
        &self.segments
    }

    /// Total number of AS numbers across segments (BIRD `bgp_path.len`).
    pub fn len(&self) -> usize {
        self.segments.iter().map(|s| s.len()).sum()
    }

    /// True when the path holds no AS numbers.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// First ASN (the neighbor side). `None` when the path is empty or
    /// starts with an AS_SET — BIRD §5.2: "first ... return zero if there
    /// is no appropriate ASN, for example if the path contains an AS set
    /// element as the first ... part"; we model that zero as `None`.
    pub fn first(&self) -> Option<u32> {
        match self.segments.first() {
            Some(AsSegment::Sequence(v)) => v.first().copied(),
            _ => None,
        }
    }

    /// Last ASN (the origin side); `None` on empty path or trailing AS_SET
    /// (BIRD `P.last`, §5.2).
    pub fn last(&self) -> Option<u32> {
        match self.segments.last() {
            Some(AsSegment::Sequence(v)) => v.last().copied(),
            _ => None,
        }
    }

    /// True when `asn` occurs anywhere in the path (BIRD §5.3:
    /// "number and bgppath ... returning true if the number is in the
    /// path").
    pub fn contains(&self, asn: u32) -> bool {
        self.segments.iter().any(|s| match s {
            AsSegment::Sequence(v) | AsSegment::Set(v) => v.contains(&asn),
        })
    }

    /// Prepend `asn` `times` times to the front of the path
    /// (BIRD `P.prepend(A)`, §5.2 — repeated application).
    pub fn prepend(&mut self, asn: u32, times: u16) {
        if times == 0 {
            return;
        }
        match self.segments.first_mut() {
            Some(AsSegment::Sequence(v)) => {
                for _ in 0..times {
                    v.insert(0, asn);
                }
            }
            _ => {
                let seq = vec![asn; times as usize];
                self.segments.insert(0, AsSegment::Sequence(seq));
            }
        }
    }

    /// Render the path the way FRR's AS-path regexes see it: ASNs
    /// space-separated, AS_SETs in `{a,b}`, so that `_` (which matches
    /// "space and comma , and AS set delimiter { and }" — FRR BGP docs,
    /// "BGP Regular Expressions") finds element boundaries.
    pub fn render(&self) -> String {
        let mut out = String::new();
        for seg in &self.segments {
            match seg {
                AsSegment::Sequence(v) => {
                    for asn in v {
                        if !out.is_empty() {
                            out.push(' ');
                        }
                        out.push_str(&asn.to_string());
                    }
                }
                AsSegment::Set(v) => {
                    if !out.is_empty() {
                        out.push(' ');
                    }
                    out.push('{');
                    out.push_str(
                        &v.iter()
                            .map(|a| a.to_string())
                            .collect::<Vec<_>>()
                            .join(","),
                    );
                    out.push('}');
                }
            }
        }
        out
    }
}

impl fmt::Display for AsPath {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.render())
    }
}

/// BGP origin attribute (RFC 4271 §4.3 / §5.1.4: IGP < EGP < Incomplete).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum BgpOrigin {
    Igp,
    Egp,
    Incomplete,
}

impl fmt::Display for BgpOrigin {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            BgpOrigin::Igp => "igp",
            BgpOrigin::Egp => "egp",
            BgpOrigin::Incomplete => "incomplete",
        };
        f.write_str(s)
    }
}

impl std::str::FromStr for BgpOrigin {
    type Err = ();

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "igp" => Ok(BgpOrigin::Igp),
            "egp" => Ok(BgpOrigin::Egp),
            "incomplete" => Ok(BgpOrigin::Incomplete),
            _ => Err(()),
        }
    }
}

/// Well-known (reserved) BGP communities, RFC 1997 §7 + graceful shutdown
/// (0xFFFF:4, draft "GRACEFUL BGP SESSION SHUTDOWN", now RFC 8326).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum WellKnownCommunity {
    /// NO_EXPORT (0xFFFF:0001).
    NoExport,
    /// NO_ADVERTISE (0xFFFF:0002).
    NoAdvertise,
    /// NO_EXPORT_SUBCONFED / local-AS (0xFFFF:0003).
    LocalAs,
    /// GRACEFUL_SHUTDOWN / gshut (0xFFFF:0004).
    Gshut,
}

impl WellKnownCommunity {
    /// The reserved 0xFFFF:nn pair encoding.
    pub fn as_pair(self) -> (u16, u16) {
        let lo = match self {
            WellKnownCommunity::NoExport => 1,
            WellKnownCommunity::NoAdvertise => 2,
            WellKnownCommunity::LocalAs => 3,
            WellKnownCommunity::Gshut => 4,
        };
        (0xffff, lo)
    }
}

impl fmt::Display for WellKnownCommunity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            WellKnownCommunity::NoExport => "no-export",
            WellKnownCommunity::NoAdvertise => "no-advertise",
            WellKnownCommunity::LocalAs => "local-AS",
            WellKnownCommunity::Gshut => "gshut",
        };
        f.write_str(s)
    }
}

/// A standard BGP community (RFC 1997): `asn:value` pair or well-known.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Community {
    Pair(u16, u16),
    WellKnown(WellKnownCommunity),
}

impl Community {
    /// Parse `65000:1`, `no-export`, `local-AS`, `gshut`, ... (FRR forms).
    pub fn parse(s: &str) -> Option<Self> {
        let wk = match s {
            "no-export" => WellKnownCommunity::NoExport,
            "no-advertise" => WellKnownCommunity::NoAdvertise,
            "local-AS" | "local-as" => WellKnownCommunity::LocalAs,
            "gshut" | "graceful-shutdown" => WellKnownCommunity::Gshut,
            _ => {
                let (a, b) = s.split_once(':')?;
                let asn: u16 = a.parse().ok()?;
                let val: u16 = b.parse().ok()?;
                return Some(Community::Pair(asn, val));
            }
        };
        Some(Community::WellKnown(wk))
    }
}

impl fmt::Display for Community {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Community::Pair(a, b) => write!(f, "{a}:{b}"),
            Community::WellKnown(w) => w.fmt(f),
        }
    }
}

/// Extended community kind. Minimal two-kind model (the route-target /
/// route-origin forms filters actually match on); the IPv4-administrator
/// and opaque forms are deferred (see docs/protocols/policy.md).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ExtCommunityKind {
    RouteTarget,
    RouteOrigin,
}

impl ExtCommunityKind {
    /// High-order octet + subtype per RFC 4360 §3: route-target 0x02/0x0002
    /// (two-octet AS specific), route-origin (route origin) 0x03/0x0002.
    pub fn type_octets(self) -> (u8, u8) {
        match self {
            ExtCommunityKind::RouteTarget => (0x02, 0x02),
            ExtCommunityKind::RouteOrigin => (0x03, 0x02),
        }
    }
}

/// An extended community in `AS:value` administrator form (RFC 4360 §4).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ExtCommunity {
    pub kind: ExtCommunityKind,
    /// Administrator field: 4-octet AS number.
    pub admin_as: u32,
    /// Assigned (local) number, 2 octets.
    pub assigned: u16,
}

impl fmt::Display for ExtCommunity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let k = match self.kind {
            ExtCommunityKind::RouteTarget => "rt",
            ExtCommunityKind::RouteOrigin => "ro",
        };
        write!(f, "{k} {}:{})", self.admin_as, self.assigned)
    }
}

/// BGP path attributes a filter can see or touch. Owned by policy; bgpd
/// converts in W2-d.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct BgpAttrs {
    pub as_path: AsPath,
    /// LOCAL_PREF (RFC 4271 §4.3; core semantics per §9.1.2.2). `None` =
    /// attribute not carried (iBGP-learned pre-policy state).
    pub local_pref: Option<u32>,
    /// MULTI_EXIT_DISC. `None` = absent.
    pub med: Option<u32>,
    pub origin: Option<BgpOrigin>,
    pub communities: Vec<Community>,
    pub ext_communities: Vec<ExtCommunity>,
    /// OTC / Only To Customer (RFC 9234 §5). `None` = absent.
    pub otc: Option<u32>,
}

impl BgpAttrs {
    /// Attribute set FRR gives a route being redistributed into BGP under
    /// a route-map: LOCAL_PREF 100, ORIGIN incomplete.
    ///
    /// Rationale: LOCAL_PREF 100 is the RFC 4271 default carried on iBGP;
    /// FRR's redistribute route-maps can set LOCAL_PREF on non-BGP routes
    /// (the attributes materialize at injection). ORIGIN for aggregated /
    /// redistributed routes is `incomplete` per RFC 4271 §5.1.4 guidance
    /// on synthesized paths — a disclosed choice, refined in W2-d.
    pub fn materialized_default() -> Self {
        Self {
            local_pref: Some(100),
            origin: Some(BgpOrigin::Incomplete),
            ..Self::default()
        }
    }
}

/// The generic, read-only window a filter sees (BIRD's implicit filter
/// route parameter, ch. 5 §5.5 "a filter is implicitly passed a route").
///
/// Data-only by design: no methods with side effects, no object-safety
/// constraints — implementers may keep it generic-friendly. Non-BGP
/// routes return `None` from [`RouteView::bgp_attrs`]; BIRD's "undefined
/// bgppath/*clist is empty for most purposes" (§5.5) is honored at
/// term-evaluation time, not here.
pub trait RouteView {
    /// Network prefix — the primary table key; read-only (BIRD `net`).
    fn prefix(&self) -> IpPrefix;
    /// Originating protocol (BIRD `source`).
    fn protocol(&self) -> RouteProtocol;
    /// Route metric.
    fn metric(&self) -> u32;
    /// Nexthop group (BIRD `gw`/multipath model flattened).
    fn nexthop_group(&self) -> &NexthopGroup;
    /// BGP path attributes, when the route is BGP.
    fn bgp_attrs(&self) -> Option<&BgpAttrs>;
}

/// Owned, mutable snapshot of a route used for filter evaluation.
///
/// Built once from any [`RouteView`] (`RouteData::from_view`), then
/// handed to `Filter::apply`, which mutates attributes in place — the
/// "compile once, evaluate many" hot path stays allocation-free (all
/// matching and set-actions operate on this buffer).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RouteData {
    pub prefix: IpPrefix,
    pub protocol: RouteProtocol,
    pub metric: u32,
    pub nexthops: NexthopGroup,
    /// `None` until a BGP-touching action materializes the default set.
    pub bgp: Option<BgpAttrs>,
}

impl RouteData {
    /// Snapshot a route view into the owned evaluation buffer.
    pub fn from_view<V: RouteView>(v: &V) -> Self {
        Self {
            prefix: v.prefix(),
            protocol: v.protocol(),
            metric: v.metric(),
            nexthops: v.nexthop_group().clone(),
            bgp: v.bgp_attrs().cloned(),
        }
    }

    /// BGP attrs, materializing the default set on first touch
    /// (FRR redistribute semantics — see `BgpAttrs::materialized_default`).
    pub fn bgp_or_materialize(&mut self) -> &mut BgpAttrs {
        self.bgp.get_or_insert_with(BgpAttrs::materialized_default)
    }

    /// BGP attrs when present, else `None` — evaluation read side.
    pub fn bgp(&self) -> Option<&BgpAttrs> {
        self.bgp.as_ref()
    }

    /// Prefix-length helper for tests in this crate.
    pub fn prefix_len(&self) -> u8 {
        match self.prefix {
            IpPrefix::V4(p) => p.prefix_len(),
            IpPrefix::V6(p) => p.prefix_len(),
        }
    }
}

/// Convenience view impl: an owned `RouteData` is itself a `RouteView`.
impl RouteView for RouteData {
    fn prefix(&self) -> IpPrefix {
        self.prefix
    }

    fn protocol(&self) -> RouteProtocol {
        self.protocol
    }

    fn metric(&self) -> u32 {
        self.metric
    }

    fn nexthop_group(&self) -> &NexthopGroup {
        &self.nexthops
    }

    fn bgp_attrs(&self) -> Option<&BgpAttrs> {
        self.bgp.as_ref()
    }
}

/// Test double: a BGP route with v4/v6 prefix and a path.
#[cfg(test)]
pub(crate) mod testutil {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    pub fn v4_route(prefix: &str, path: &[u32]) -> RouteData {
        RouteData {
            prefix: prefix.parse().expect("valid v4 prefix"),
            protocol: RouteProtocol::Bgp,
            metric: 0,
            nexthops: NexthopGroup::single(common::Nexthop::Ipv4(Ipv4Addr::LOCALHOST)),
            bgp: Some(BgpAttrs {
                as_path: AsPath::from_sequence(path),
                local_pref: Some(100),
                med: None,
                origin: Some(BgpOrigin::Igp),
                communities: Vec::new(),
                ext_communities: Vec::new(),
                otc: None,
            }),
        }
    }

    pub fn v6_route(prefix: &str, path: &[u32]) -> RouteData {
        RouteData {
            prefix: prefix.parse().expect("valid v6 prefix"),
            protocol: RouteProtocol::Bgp,
            metric: 0,
            nexthops: NexthopGroup::single(common::Nexthop::Ipv6(Ipv6Addr::LOCALHOST)),
            bgp: Some(BgpAttrs {
                as_path: AsPath::from_sequence(path),
                local_pref: Some(100),
                med: None,
                origin: Some(BgpOrigin::Igp),
                communities: Vec::new(),
                ext_communities: Vec::new(),
                otc: None,
            }),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn as_path_first_last_len() {
        let p = AsPath::from_sequence(&[65001, 65002, 65003]);
        assert_eq!(p.first(), Some(65001));
        assert_eq!(p.last(), Some(65003));
        assert_eq!(p.len(), 3);
        assert!(!p.is_empty());
        assert!(AsPath::default().is_empty());
    }

    #[test]
    fn as_path_set_first_last_none() {
        // BIRD §5.2: first/last return zero when the boundary element is
        // an AS set — modeled as None.
        let p = AsPath::from_segments(vec![
            AsSegment::Set(vec![65100, 65101]),
            AsSegment::Sequence(vec![65001]),
        ]);
        assert_eq!(p.first(), None);
        assert_eq!(p.last(), Some(65001));

        let q = AsPath::from_segments(vec![
            AsSegment::Sequence(vec![65001]),
            AsSegment::Set(vec![65100]),
        ]);
        assert_eq!(q.first(), Some(65001));
        assert_eq!(q.last(), None);
    }

    #[test]
    fn as_path_contains_and_prepend() {
        let mut p = AsPath::from_sequence(&[65002, 65003]);
        assert!(p.contains(65002));
        assert!(!p.contains(65001));
        p.prepend(65001, 2);
        assert_eq!(p.render(), "65001 65001 65002 65003");
        assert!(p.contains(65001));
    }

    #[test]
    fn as_path_render_with_set() {
        let p = AsPath::from_segments(vec![
            AsSegment::Sequence(vec![65001]),
            AsSegment::Set(vec![65100, 65101]),
        ]);
        assert_eq!(p.render(), "65001 {65100,65101}");
    }

    #[test]
    fn community_parse_forms() {
        assert_eq!(Community::parse("65000:1"), Some(Community::Pair(65000, 1)));
        assert_eq!(
            Community::parse("no-export"),
            Some(Community::WellKnown(WellKnownCommunity::NoExport))
        );
        assert_eq!(
            Community::parse("local-AS"),
            Some(Community::WellKnown(WellKnownCommunity::LocalAs))
        );
        assert_eq!(
            Community::parse("gshut"),
            Some(Community::WellKnown(WellKnownCommunity::Gshut))
        );
        assert_eq!(Community::parse("junk"), None);
        assert_eq!(Community::parse("70000:1"), None, "asn must fit u16");
    }

    #[test]
    fn common_bits_edge_cases() {
        let a = [0u8, 0, 0, 0];
        let b = [255u8, 255, 255, 255];
        assert!(common_bits_equal(&a, &b, 0), "/0 covers everything");
        assert!(!common_bits_equal(&a, &b, 1));
        let c = [10u8, 1, 2, 3];
        let d = [10u8, 1, 3, 3];
        assert!(common_bits_equal(&c, &d, 16));
        assert!(common_bits_equal(&c, &d, 23), "partial octet 7 bits");
        assert!(!common_bits_equal(&c, &d, 24));
    }

    #[test]
    fn prefix_covers_v4_v6() {
        let v4a: IpPrefix = "10.0.0.0/8".parse().unwrap();
        let v4b: IpPrefix = "10.1.2.0/24".parse().unwrap();
        let v6a: IpPrefix = "2001:db8::/32".parse().unwrap();
        let v6b: IpPrefix = "2001:db8:1::/48".parse().unwrap();
        let v6c: IpPrefix = "2001:db9::/48".parse().unwrap();
        assert!(prefix_covers(&v4a, &v4b));
        assert!(prefix_covers(&v6a, &v6b));
        assert!(!prefix_covers(&v6a, &v6c));
        assert!(prefix_covers(&v4a, &v4a), "self-cover");
        assert!(!prefix_covers(&v4a, &v6a), "mixed families never cover");
    }

    #[test]
    fn route_data_materializes_bgp_on_touch() {
        let mut r = testutil::v4_route("192.0.2.0/24", &[]);
        r.bgp = None;
        {
            let b = r.bgp_or_materialize();
            assert_eq!(b.local_pref, Some(100));
            assert_eq!(b.origin, Some(BgpOrigin::Incomplete));
        }
        assert!(r.bgp().is_some(), "attrs stay materialized");
    }
}
