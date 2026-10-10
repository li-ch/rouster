//! RFC 6811 §2 prefix-origin validation (ROV).
//!
//! The validation state of a Route is a pure function of the VRP set,
//! the Route Prefix, and the Route Origin ASN (RFC 6811 §2):
//!
//! - **Covered**: the VRP prefix length is ≤ the Route prefix length
//!   and the addresses agree on the VRP prefix's bits;
//! - **Matched**: Covered, Route prefix length ≤ VRP maximum length,
//!   and Route Origin ASN == VRP ASN;
//! - **NotFound**: no VRP Covers the Route Prefix;
//! - **Valid**: at least one VRP Matches;
//! - **Invalid**: at least one VRP Covers, but none Match.
//!
//! Two origin special cases come straight from §2 and its §2.1
//! pseudo-code: a Route Origin ASN of "NONE" (final AS_PATH segment
//! neither AS_SEQUENCE nor confederation — RFC 6811 §2's definition)
//! can never be Matched, and a VRP whose ASN is zero can never Match
//! (the pseudo-code's `entry->origin_as != 0`), which is what makes
//! AS 0 ROAs work as disavowal (RFC 6483 §4).

use common::IpPrefix;

use crate::vrp::{Vrp, VrpTable};

/// `common::IpPrefix` carries its length on the variants; expose it
/// for the validation math.
fn prefix_len(p: &IpPrefix) -> u8 {
    match p {
        IpPrefix::V4(v) => v.prefix_len(),
        IpPrefix::V6(v) => v.prefix_len(),
    }
}

/// The origin AS of a route per RFC 6811 §2: the rightmost AS of the
/// final AS_PATH segment if it is an AS_SEQUENCE; the local AS for
/// empty paths and confederation segments; NONE otherwise (aggregates
/// with a trailing AS_SET, etc.). NONE never Matches any VRP.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum OriginAsn {
    As(u32),
    None,
}

impl OriginAsn {
    pub fn new(asn: u32) -> Self {
        OriginAsn::As(asn)
    }
}

/// RFC 6811 §2's three validation states.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Validity {
    NotFound,
    Valid,
    Invalid,
}

impl Validity {
    /// The spelling bgpd's policy engine and FRR's `show ip route
    /// validation` surfaces use.
    pub fn as_str(self) -> &'static str {
        match self {
            Validity::NotFound => "NotFound",
            Validity::Valid => "Valid",
            Validity::Invalid => "Invalid",
        }
    }
}

impl std::fmt::Display for Validity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// The §2.1 pseudo-code, verbatim in structure: iterate covering VRPs,
/// return Valid on the first Match, Invalid if anything Covered but
/// nothing Matched, NotFound otherwise.
pub fn validate<'a, I>(vrps: I, route_prefix: &IpPrefix, route_origin: OriginAsn) -> Validity
where
    I: IntoIterator<Item = &'a Vrp>,
{
    let mut prefix_exists = false;
    for entry in vrps {
        if !entry.covers(route_prefix) {
            continue;
        }
        prefix_exists = true;
        if prefix_len(route_prefix) <= entry.max_len
            && route_origin != OriginAsn::None
            && entry.asn != 0
            && route_origin == OriginAsn::As(entry.asn)
        {
            return Validity::Valid;
        }
    }
    if prefix_exists {
        Validity::Invalid
    } else {
        Validity::NotFound
    }
}

impl VrpTable {
    /// Validate one (prefix, origin) announcement against this table.
    pub fn validate(&self, route_prefix: &IpPrefix, route_origin: OriginAsn) -> Validity {
        validate(self.iter(), route_prefix, route_origin)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pdu::PayloadFlags;

    fn add(t: &mut VrpTable, p: &str, max_len: u8, asn: u32) {
        t.apply(
            Vrp {
                prefix: p.parse().unwrap(),
                max_len,
                asn,
            },
            PayloadFlags::ANNOUNCE,
        )
        .unwrap();
    }

    fn table(vrps: &[(&str, u8, u32)]) -> VrpTable {
        let mut t = VrpTable::new();
        for (p, m, a) in vrps {
            add(&mut t, p, *m, *a);
        }
        t
    }

    fn check(t: &VrpTable, route: &str, origin: u32) -> Validity {
        t.validate(&route.parse().unwrap(), OriginAsn::As(origin))
    }

    // ---- RFC 6483 §2's route-validity table, instantiated. --------
    // The single-ROA matrix (ROA 192.0.2.0/24-24 AS 64512):
    //   non-intersecting / covering-aggregate → unknown (both columns);
    //   match prefix + matching AS → valid;
    //   match prefix + non-matching AS → invalid;
    //   more specific than ROA (beyond maxLength) → invalid (both).

    #[test]
    fn rfc6483_table_non_intersecting_unknown() {
        let t = table(&[("192.0.2.0/24", 24, 64512)]);
        assert_eq!(check(&t, "198.51.100.0/24", 64512), Validity::NotFound);
        assert_eq!(check(&t, "198.51.100.0/24", 64513), Validity::NotFound);
    }

    #[test]
    fn rfc6483_table_covering_aggregate_unknown() {
        // A /22 route aggregates the /24 ROA: the ROA does not Cover
        // it, so the outcome is unknown even for the ROA's own ASN.
        let t = table(&[("192.0.2.0/24", 24, 64512)]);
        assert_eq!(check(&t, "192.0.2.0/22", 64512), Validity::NotFound);
        assert_eq!(check(&t, "192.0.0.0/21", 64599), Validity::NotFound);
    }

    #[test]
    fn rfc6483_table_exact_prefix_matching_as_valid() {
        let t = table(&[("192.0.2.0/24", 24, 64512)]);
        assert_eq!(check(&t, "192.0.2.0/24", 64512), Validity::Valid);
    }

    #[test]
    fn rfc6483_table_exact_prefix_non_matching_as_invalid() {
        let t = table(&[("192.0.2.0/24", 24, 64512)]);
        assert_eq!(check(&t, "192.0.2.0/24", 64513), Validity::Invalid);
    }

    #[test]
    fn rfc6483_table_more_specific_beyond_maxlen_invalid() {
        // More specific than the ROA prefix with maxLength 24: invalid
        // for the ROA's own ASN too (Covered but not Matched).
        let t = table(&[("192.0.2.0/24", 24, 64512)]);
        assert_eq!(check(&t, "192.0.2.128/25", 64512), Validity::Invalid);
        assert_eq!(check(&t, "192.0.2.128/25", 64513), Validity::Invalid);
    }

    #[test]
    fn rfc6483_table_more_specific_within_maxlen_valid() {
        // Step 3 of the RFC 6483 §2 procedure: a maxLength that admits
        // more specifics lets the ROA's own ASN through.
        let t = table(&[("192.0.2.0/24", 26, 64512)]);
        assert_eq!(check(&t, "192.0.2.128/25", 64512), Validity::Valid);
        assert_eq!(check(&t, "192.0.2.192/26", 64512), Validity::Valid);
        assert_eq!(check(&t, "192.0.2.200/27", 64512), Validity::Invalid);
    }

    // ---- AS 0 disavowal (RFC 6483 §4). -----------------------------

    #[test]
    fn as0_roa_disavows_covered_space() {
        // "an AS 0 ROA to declare a default condition that any route
        // that is equal to or more specific than the prefix be
        // considered invalid".
        let t = table(&[("192.0.2.0/24", 32, 0)]);
        assert_eq!(check(&t, "192.0.2.0/24", 64512), Validity::Invalid);
        assert_eq!(check(&t, "192.0.2.77/32", 64512), Validity::Invalid);
        assert_eq!(check(&t, "192.0.2.77/32", 0), Validity::Invalid);
    }

    #[test]
    fn as0_roa_loses_to_a_matching_roa() {
        // "The route validation procedure will provide a valid outcome
        // if any ROA matches ... even if other valid ROAs would provide
        // an invalid validation outcome" — the disavowal is the floor,
        // not the verdict.
        let t = table(&[("192.0.2.0/24", 32, 0), ("192.0.2.128/25", 25, 64512)]);
        assert_eq!(check(&t, "192.0.2.128/25", 64512), Validity::Valid);
        // Outside the /25 the AS 0 ROA still rules.
        assert_eq!(check(&t, "192.0.2.0/24", 64512), Validity::Invalid);
    }

    // ---- Multi-ROA overlaps (covering vs conflicting). -------------

    #[test]
    fn overlapping_covering_vrps_conflicting_asns() {
        // Two VRPs cover the same more-specific route with different
        // ASNs; a route matching either is Valid, one matching neither
        // is Invalid.
        let t = table(&[("192.0.2.0/24", 25, 64512), ("192.0.2.128/25", 25, 64513)]);
        assert_eq!(check(&t, "192.0.2.128/25", 64512), Validity::Valid);
        assert_eq!(check(&t, "192.0.2.128/25", 64513), Validity::Valid);
        assert_eq!(check(&t, "192.0.2.128/25", 64514), Validity::Invalid);
    }

    #[test]
    fn same_prefix_two_asns_both_valid() {
        // Multi-homed origination: both ASNs are Valid, others Invalid.
        let t = table(&[("198.51.100.0/24", 24, 64512), ("198.51.100.0/24", 24, 64513)]);
        assert_eq!(check(&t, "198.51.100.0/24", 64512), Validity::Valid);
        assert_eq!(check(&t, "198.51.100.0/24", 64513), Validity::Valid);
        assert_eq!(check(&t, "198.51.100.0/24", 64514), Validity::Invalid);
        assert_eq!(check(&t, "198.51.100.128/25", 64512), Validity::Invalid);
    }

    #[test]
    fn maxlen_gap_between_covering_vrps() {
        // A short VRP with tight maxlen plus a long VRP with a loose
        // one; only the VRP whose maxlen admits the route can Match.
        let t = table(&[("10.0.0.0/8", 8, 64500), ("10.1.0.0/16", 24, 64501)]);
        assert_eq!(check(&t, "10.1.2.0/24", 64501), Validity::Valid);
        assert_eq!(check(&t, "10.1.2.0/23", 64501), Validity::Valid);
        assert_eq!(check(&t, "10.1.2.0/24", 64500), Validity::Invalid);
        // The /8 VRP only ever Matches an exact /8.
        assert_eq!(check(&t, "10.0.0.0/8", 64500), Validity::Valid);
        assert_eq!(check(&t, "10.2.0.0/16", 64500), Validity::Invalid);
    }

    // ---- Origin NONE and v6. ---------------------------------------

    #[test]
    fn origin_none_never_matches() {
        let t = table(&[("192.0.2.0/24", 24, 64512), ("192.0.2.0/24", 24, 0)]);
        // NONE is Covered-then-unmatched when covered...
        assert_eq!(
            t.validate(&"192.0.2.0/24".parse().unwrap(), OriginAsn::None),
            Validity::Invalid
        );
        // ...and plain NotFound when nothing covers.
        let empty = VrpTable::new();
        assert_eq!(
            empty.validate(&"192.0.2.0/24".parse().unwrap(), OriginAsn::None),
            Validity::NotFound
        );
    }

    #[test]
    fn v6_validation_full_lattice() {
        let t = table(&[("2001:db8:1::/48", 64, 64512), ("2001:db8:2::/48", 48, 0)]);
        assert_eq!(check(&t, "2001:db8:1::/48", 64512), Validity::Valid);
        assert_eq!(check(&t, "2001:db8:1:1::/64", 64512), Validity::Valid);
        assert_eq!(check(&t, "2001:db8:1:1::/65", 64512), Validity::Invalid);
        assert_eq!(check(&t, "2001:db8:1::/48", 64513), Validity::Invalid);
        assert_eq!(check(&t, "2001:db8:2::/48", 64512), Validity::Invalid); // AS0 space
        assert_eq!(check(&t, "2001:db8:3::/48", 64512), Validity::NotFound);
        // v4 routes are untouched by v6 VRPs.
        assert_eq!(check(&t, "192.0.2.0/24", 64512), Validity::NotFound);
    }

    #[test]
    fn validity_spelling() {
        assert_eq!(Validity::NotFound.as_str(), "NotFound");
        assert_eq!(Validity::Valid.as_str(), "Valid");
        assert_eq!(Validity::Invalid.as_str(), "Invalid");
    }
}
