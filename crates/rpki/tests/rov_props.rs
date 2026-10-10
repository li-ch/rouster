//! P2-c property tests: RFC 6811 §2 ROV over generated VRP sets.
//!
//! Five properties:
//!
//! 1. **soundness** — a Valid verdict implies some VRP in the table
//!    Covers the route prefix, admits its length under the VRP's max
//!    length, and carries the route's origin ASN (≠ 0, and the origin
//!    itself ≠ NONE by construction);
//! 2. **completeness** — announcing exactly the VRP being probed
//!    (prefix equal, max_len ≥ route length, ASN equal) makes the
//!    verdict Valid, whatever else the table holds;
//! 3. **removal monotonicity** — dropping VRPs can only degrade the
//!    verdict: NotFound stays NotFound, Invalid never becomes Valid,
//!    and Valid never becomes Invalid→Valid (Valid may fall to Invalid
//!    or NotFound, Invalid may fall to NotFound — the table's covers
//!    set only shrinks);
//! 4. **family isolation** — IPv4 VRPs never influence an IPv6
//!    verdict, and vice versa;
//! 5. **AS 0 never matches** — VRPs with origin AS 0 can produce
//!    Invalid or NotFound, never Valid (the `entry->origin_as != 0`
//!    clause of RFC 6811 §2.1).
//!
//! Determinism (W5B bar "seeds fixed"): every runner carries an
//! explicit [`proptest::test_runner::RngSeed::Fixed`]; `cargo test`
//! replays the same case sequence each run; `PROPTEST_RNG_SEED`
//! overrides for human exploration.

use common::{IpPrefix, Ipv4Prefix, Ipv6Prefix};
use proptest::prelude::*;
use proptest::test_runner::RngSeed;

use rpki::{OriginAsn, PayloadFlags, Validity, Vrp, VrpTable};

fn seeded(seed: u64) -> ProptestConfig {
    ProptestConfig {
        rng_seed: RngSeed::Fixed(seed),
        cases: 256,
        ..ProptestConfig::default()
    }
}

const SEED_SOUNDNESS: u64 = 0x7250_4301;
const SEED_COMPLETENESS: u64 = 0x7250_4302;
const SEED_REMOVAL: u64 = 0x7250_4303;
const SEED_FAMILY: u64 = 0x7250_4304;
const SEED_AS0: u64 = 0x7250_4305;

/// A canonical (network-masked) prefix: canonical form is what real
/// VRP ingestion carries, so containment comparisons are exact.
fn canonical_v4(addr: u32, plen: u8) -> IpPrefix {
    let mask = if plen == 0 { 0 } else { !0u32 << (32 - plen as u32) };
    IpPrefix::V4(Ipv4Prefix::new((addr & mask).into(), plen).unwrap())
}

fn canonical_v6(addr_hi: u64, addr_lo: u64, plen: u8) -> IpPrefix {
    let addr = ((addr_hi as u128) << 64) | addr_lo as u128;
    let mask = if plen == 0 {
        0
    } else {
        !0u128 << (128 - plen as u32)
    };
    IpPrefix::V6(Ipv6Prefix::new(((addr & mask) as u128).into(), plen).unwrap())
}

fn any_prefix() -> impl Strategy<Value = IpPrefix> {
    prop_oneof![
        (any::<u32>(), 0u8..=32).prop_map(|(a, p)| canonical_v4(a, p)),
        (any::<u64>(), any::<u64>(), 0u8..=128)
            .prop_map(|(h, l, p)| canonical_v6(h, l, p)),
    ]
}

fn any_vrp() -> impl Strategy<Value = Vrp> {
    (any_prefix(), any::<u16>()).prop_flat_map(|(prefix, extra)| {
        let max_min = match &prefix {
            IpPrefix::V4(v) => v.prefix_len(),
            IpPrefix::V6(v) => v.prefix_len(),
        };
        let max_max = match &prefix {
            IpPrefix::V4(_) => 32u8,
            IpPrefix::V6(_) => 128u8,
        };
        (Just(prefix), max_min..=max_max, any::<u32>(), Just(extra)).prop_map(
            |(prefix, max_len, asn, _)| Vrp {
                prefix,
                max_len,
                asn,
            },
        )
    })
}

fn table_of(vrps: &[Vrp]) -> VrpTable {
    let mut t = VrpTable::new();
    for v in vrps {
        t.apply(*v, PayloadFlags::ANNOUNCE).unwrap();
    }
    t
}

/// Independent restatement of RFC 6811 §2 "Covered"/"Matched" used as
/// the test-side reference model.
fn reference_matches(vrp: &Vrp, route: &IpPrefix, origin: u32) -> bool {
    let covered = match (&vrp.prefix, route) {
        (IpPrefix::V4(v), IpPrefix::V4(r)) => {
            v.prefix_len() <= r.prefix_len() && v.contains(r.addr())
        }
        (IpPrefix::V6(v), IpPrefix::V6(r)) => {
            v.prefix_len() <= r.prefix_len() && v.contains(r.addr())
        }
        _ => false,
    };
    let route_len = match route {
        IpPrefix::V4(v) => v.prefix_len(),
        IpPrefix::V6(v) => v.prefix_len(),
    };
    covered && route_len <= vrp.max_len && vrp.asn != 0 && vrp.asn == origin
}

proptest! {
    #![proptest_config(seeded(SEED_SOUNDNESS))]

    #[test]
    fn soundness_valid_implies_a_matching_vrp(
        vrps in prop::collection::vec(any_vrp(), 0..24),
        route in any_prefix(),
        origin in any::<u32>(),
    ) {
        let table = table_of(&vrps);
        let verdict = table.validate(&route, OriginAsn::As(origin));
        prop_assert_eq!(
            verdict,
            if vrps.iter().any(|v| reference_matches(v, &route, origin)) {
                Validity::Valid
            } else if vrps.iter().any(|v| v.covers(&route)) {
                Validity::Invalid
            } else {
                Validity::NotFound
            },
            "verdict diverged from the RFC 6811 §2 reference model"
        );
    }
}

proptest! {
    #![proptest_config(seeded(SEED_COMPLETENESS))]

    #[test]
    fn completeness_exact_vrp_makes_route_valid(
        others in prop::collection::vec(any_vrp(), 0..24),
        route in any_prefix(),
        slack in 0u8..8,
        origin in 1..u32::MAX,
    ) {
        let route_len = match &route {
            IpPrefix::V4(v) => v.prefix_len(),
            IpPrefix::V6(v) => v.prefix_len(),
        };
        let family_max = match &route {
            IpPrefix::V4(_) => 32u8,
            IpPrefix::V6(_) => 128u8,
        };
        let max_len = route_len.saturating_add(slack).min(family_max);
        let mut all = others;
        all.push(Vrp { prefix: route, max_len, asn: origin });
        let table = table_of(&all);
        prop_assert_eq!(table.validate(&route, OriginAsn::As(origin)), Validity::Valid);
    }
}

proptest! {
    #![proptest_config(seeded(SEED_REMOVAL))]

    #[test]
    fn removal_only_degrades_the_verdict(
        vrps in prop::collection::vec(any_vrp(), 1..24),
        drop in 0usize..24,
        route in any_prefix(),
        origin in any::<u32>(),
    ) {
        let table = table_of(&vrps);
        let before = table.validate(&route, OriginAsn::As(origin));
        let drop = drop % vrps.len();
        let survivors: Vec<Vrp> = vrps.iter().enumerate()
            .filter(|(i, _)| *i != drop)
            .map(|(_, v)| *v)
            .collect();
        let after = table_of(&survivors).validate(&route, OriginAsn::As(origin));
        let allowed = match before {
            Validity::NotFound => vec![Validity::NotFound],
            Validity::Invalid => vec![Validity::Invalid, Validity::NotFound],
            Validity::Valid => vec![Validity::Valid, Validity::Invalid, Validity::NotFound],
        };
        prop_assert!(allowed.contains(&after), "{before} degraded to {after}");
    }
}

proptest! {
    #![proptest_config(seeded(SEED_FAMILY))]

    #[test]
    fn families_never_cross(
        vrps in prop::collection::vec(any_vrp(), 0..24),
        probe_v4 in (any::<u32>(), 0u8..=32),
        probe_v6 in (any::<u64>(), any::<u64>(), 0u8..=128),
        origin in any::<u32>(),
    ) {
        let table = table_of(&vrps);
        let p4 = canonical_v4(probe_v4.0, probe_v4.1);
        let p6 = canonical_v6(probe_v6.0, probe_v6.1, probe_v6.2);
        // Only the same-family VRPs may appear in the reference model.
        for (route, same_family) in [(p4, true), (p6, false)] {
            let relevant: Vec<&Vrp> = table.iter()
                .filter(|v| matches!((&v.prefix, &route), (IpPrefix::V4(_), IpPrefix::V4(_)) | (IpPrefix::V6(_), IpPrefix::V6(_))))
                .collect();
            let expect = if relevant.iter().any(|v| reference_matches(v, &route, origin)) {
                Validity::Valid
            } else if relevant.iter().any(|v| v.covers(&route)) {
                Validity::Invalid
            } else {
                Validity::NotFound
            };
            prop_assert_eq!(table.validate(&route, OriginAsn::As(origin)), expect);
            let _ = same_family;
        }
    }
}

proptest! {
    #![proptest_config(seeded(SEED_AS0))]

    #[test]
    fn as0_vrps_never_validate(
        vrps in prop::collection::vec(any_vrp(), 0..24),
        route in any_prefix(),
        origin in any::<u32>(),
    ) {
        let all_as0: Vec<Vrp> = vrps.iter().map(|v| Vrp { asn: 0, ..*v }).collect();
        let table = table_of(&all_as0);
        let verdict = table.validate(&route, OriginAsn::As(origin));
        prop_assert_ne!(verdict, Validity::Valid, "AS 0 ROA matched a route");
    }
}
