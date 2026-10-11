//! W1-a M5 property suite: filter determinism, set-membership
//! consistency against brute-force oracles, and route-map→typed
//! compilation equivalence on generated programs.

use common::{IpPrefix, RouteProtocol};
use policy::route::{AsPath, BgpOrigin, Community, RouteData};
use policy::routemap::{
    compile_route_map, parse_policy_config, RmEntry, RmExit, RmMatch, RmPolicy, RmSet,
};
use policy::sets::{PrefixListVerdict, PrefixPattern, PrefixSet};
use policy::{Action, CommMode, FilterBuilder, Term, Verdict};
use proptest::prelude::*;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn p4(s: &str) -> IpPrefix {
    s.parse().unwrap()
}

fn route(prefix: &str, path: &[u32], comms: Vec<Community>, lp: u32, metric: u32) -> RouteData {
    let mut r = RouteData {
        prefix: p4(prefix),
        protocol: RouteProtocol::Bgp,
        metric,
        nexthops: common::NexthopGroup::new(),
        bgp: Some(policy::route::BgpAttrs {
            as_path: AsPath::from_sequence(path),
            local_pref: Some(lp),
            med: None,
            origin: Some(BgpOrigin::Igp),
            communities: comms,
            ext_communities: Vec::new(),
            otc: None,
        }),
    };
    r.nexthops
        .add(common::Nexthop::Ipv4("192.0.2.1".parse().unwrap()), 1);
    r
}

// ---------------------------------------------------------------------------
// 1. Filter determinism: same route + same program → same verdict and
//    same modified route, across repeated evaluations.
// ---------------------------------------------------------------------------

fn term_strategy() -> BoxedStrategy<Term> {
    let leaf = prop_oneof![
        Just(Term::True),
        Just(Term::False),
        (0u32..20).prop_map(|v| Term::LocalPrefIn(v * 10, v * 10 + 50)),
        (0u8..=32).prop_map(|v| Term::PrefixLen { min: v / 2, max: v }),
        (0u32..=65535).prop_map(Term::PathContains),
        Just(Term::PathEmpty),
        Just(Term::CommunityEmpty),
        prop::collection::vec(
            prop_oneof![
                Just(RouteProtocol::Bgp),
                Just(RouteProtocol::Static),
                Just(RouteProtocol::Ospf),
            ],
            1..3
        )
        .prop_map(Term::ProtocolIn),
        prop::collection::vec(
            prop_oneof![Just(BgpOrigin::Igp), Just(BgpOrigin::Incomplete),],
            1..2
        )
        .prop_map(Term::OriginIn),
    ];
    leaf.prop_recursive(3, 24, 3, |inner| {
        prop_oneof![
            prop::collection::vec(inner.clone(), 1..3).prop_map(Term::And),
            prop::collection::vec(inner.clone(), 1..3).prop_map(Term::Or),
            inner.clone().prop_map(|t| Term::Not(Box::new(t))),
        ]
    })
    .boxed()
}

fn action_strategy() -> BoxedStrategy<Action> {
    prop_oneof![
        Just(Action::Accept),
        Just(Action::Reject),
        (0u32..1000).prop_map(Action::SetLocalPref),
        (-100i64..100).prop_map(Action::AdjustLocalPref),
        (0u32..500).prop_map(Action::SetMed),
        (-50i64..50).prop_map(Action::AdjustMed),
        (0u32..100).prop_map(Action::SetMetric),
        Just(Action::SetOrigin(BgpOrigin::Egp)),
        (0u32..65535).prop_map(Action::SetOtc),
        (prop::collection::vec(0u16..10, 0..3), 0..2u8,).prop_map(|(vals, mode)| {
            Action::SetCommunities {
                list: vals
                    .into_iter()
                    .map(|v| Community::Pair(65000, v))
                    .collect(),
                mode: if mode == 0 {
                    CommMode::Replace
                } else {
                    CommMode::Add
                },
            }
        }),
        (0u32..65535, 0u16..4).prop_map(|(asn, times)| Action::PrependAsPath { asn, times }),
    ]
    .boxed()
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(128))]

    #[test]
    fn filter_determinism(terms in prop::collection::vec(term_strategy(), 1..4),
                          actions in prop::collection::vec(action_strategy(), 1..5),
                          lp in 0u32..300,
                          path in prop::collection::vec(1u32..100, 0..5),
                          comms in prop::collection::vec((0u16..10, 0u16..10), 0..4)) {
        let mut b = FilterBuilder::new();
        for t in terms {
            b.add_rule(t, actions.clone());
        }
        let filter = b.build().unwrap();

        let comms: Vec<Community> = comms.into_iter().map(|(a, v)| Community::Pair(a, v)).collect();
        let mk = || route("10.1.2.0/24", &path, comms.clone(), lp, 7);

        let mut r1 = mk();
        let v1 = filter.apply(&mut r1);
        let mut r2 = mk();
        let v2 = filter.apply(&mut r2);
        let mut r3 = mk();
        let v3 = filter.apply(&mut r3);
        prop_assert_eq!(v1, v2);
        prop_assert_eq!(v1, v3);
        prop_assert_eq!(r1.clone(), r2);
        prop_assert_eq!(r1, r3);
        prop_assert_eq!(v1.is_accept(), v1 == Verdict::Accept);
    }
}

// ---------------------------------------------------------------------------
// 2. Prefix-set membership vs a brute-force oracle (BIRD §5.2
//    semantics), including longest-match tags.
// ---------------------------------------------------------------------------

/// Independent oracle: integer bit-masking arithmetic instead of the
/// octet walk in `sets.rs`. BIRD §5.2: "Prefix ip1/len1 matches prefix
/// pattern ip2/len2{l,h} if the first min(len1, len2) bits of ip1 and
/// ip2 are identical and l <= len1 <= h."
fn oracle_covers(pat_addr: u32, pat_len: u8, lo: u8, hi: u8, probe: u32, probe_len: u8) -> bool {
    if !(lo <= probe_len && probe_len <= hi) {
        return false;
    }
    let n = probe_len.min(pat_len);
    if n == 0 {
        return true;
    }
    let mask: u32 = u32::MAX << (32 - n as usize);
    (pat_addr & mask) == (probe & mask)
}

fn pattern_strategy() -> BoxedStrategy<(u32, u8, u8, u8, Option<u32>)> {
    // (network addr, network len, low, high, tag)
    (
        prop_oneof![
            Just("10.0.0.0"),
            Just("10.42.0.0"),
            Just("192.0.2.0"),
            Just("198.51.100.0"),
            Just("0.0.0.0"),
            Just("203.0.113.128"),
        ],
        8u8..=29,
        0u8..=32,
    )
        .prop_map(|(addr_s, net_len, spread)| {
            let addr: u32 = addr_s.parse::<std::net::Ipv4Addr>().unwrap().into();
            let high = (net_len + spread).min(32);
            let tag = if spread % 3 == 0 {
                Some(spread as u32 + 1)
            } else {
                None
            };
            (addr, net_len, net_len.min(high), high, tag)
        })
        .boxed()
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(128))]

    #[test]
    fn prefix_set_matches_oracle(
        pats in prop::collection::vec(pattern_strategy(), 0..8),
        probe_addr in any::<u32>(),
        probe_len in 0u8..=32,
    ) {
        let mut set = PrefixSet::new();
        for &(addr, net_len, lo, hi, tag) in &pats {
            let a = std::net::Ipv4Addr::from(addr);
            let pattern = PrefixPattern::range(p4(&format!("{a}/{net_len}")), lo, hi).unwrap();
            let pattern = if let Some(t) = tag { pattern.with_tag(t) } else { pattern };
            set.add_pattern(pattern);
        }
        let probe_net = std::net::Ipv4Addr::from(probe_addr);
        let probe = p4(&format!("{probe_net}/{probe_len}"));

        // Brute-force oracle over the same pattern list.
        let mut oracle_matched = false;
        let mut oracle_tag: Option<u32> = None;
        let mut oracle_spec: i32 = -1;
        for &(addr, net_len, lo, hi, tag) in &pats {
            if oracle_covers(addr, net_len, lo, hi, probe_addr, probe_len) {
                oracle_matched = true;
                if (net_len as i32) > oracle_spec {
                    oracle_spec = net_len as i32;
                    oracle_tag = tag;
                }
            }
        }
        let got = set.matches(&probe);
        prop_assert_eq!(got.matched, oracle_matched);
        prop_assert_eq!(got.tag, oracle_tag);
    }
}

// ---------------------------------------------------------------------------
// 3. Route-map → typed compilation equivalence: a generated route-map,
//    compiled into a Filter, must agree with an independent interpreter
//    walking the parsed entries directly (verdict + final route state).
// ---------------------------------------------------------------------------

/// Independent FRR-semantics interpreter over the parsed document.
fn oracle_interpret(
    prefix_lists: &std::collections::BTreeMap<String, policy::sets::PrefixList>,
    access_lists: &std::collections::BTreeMap<String, policy::sets::AccessList>,
    as_lists: &std::collections::BTreeMap<String, policy::sets::AsPathAccessList>,
    comm_lists: &std::collections::BTreeMap<String, policy::sets::CommunityAccessList>,
    entries: &[RmEntry],
    route: &mut RouteData,
) -> Verdict {
    let mut i = 0usize;
    loop {
        let Some(e) = entries.get(i) else {
            return Verdict::Reject; // FRR implicit deny-all
        };
        let matched = e.matches.iter().all(|m| match m {
            RmMatch::PrefixList { names, .. } => names.iter().any(|n| {
                prefix_lists
                    .get(n)
                    .and_then(|l| l.first_match(&route.prefix))
                    == Some(PrefixListVerdict::Permit)
            }),
            // The generator does not emit access-list matches; the arm
            // keeps this interpreter total over the AST regardless.
            RmMatch::AccessList { name, .. } => {
                access_lists
                    .get(name)
                    .and_then(|l| l.first_match(&route.prefix))
                    == Some(PrefixListVerdict::Permit)
            }
            RmMatch::AsPath(n) => route
                .bgp()
                .map(|b| as_lists.get(n).and_then(|l| l.first_match(&b.as_path)) == Some(true))
                .unwrap_or(false),
            RmMatch::Community { names, exact } => names.iter().any(|n| {
                static EMPTY: [Community; 0] = [];
                let list = comm_lists.get(n);
                let comms = route.bgp().map_or(&EMPTY[..], |b| &b.communities);
                match list {
                    Some(l) if *exact => l.exact_match(comms) == Some(true),
                    Some(l) => l.first_match(comms) == Some(true),
                    None => false,
                }
            }),
            RmMatch::LocalPref(v) => route.bgp().and_then(|b| b.local_pref) == Some(*v),
            RmMatch::Metric(v) => route.metric == *v,
            RmMatch::SourceProtocol(ps) => ps.contains(&route.protocol),
        });
        if matched {
            match e.policy {
                RmPolicy::Deny => return Verdict::Reject,
                RmPolicy::Permit => {
                    for s in &e.sets {
                        oracle_apply_set(comm_lists, s, route);
                    }
                    match e.exit {
                        RmExit::None => return Verdict::Accept,
                        RmExit::Next => {}
                        RmExit::Goto(n) => {
                            let target = entries.iter().position(|x| x.seq >= n);
                            match target {
                                Some(j) if j > i => {
                                    i = j;
                                    continue;
                                }
                                // Generator only emits forward, valid
                                // targets; the compiler rejects the rest.
                                _ => return Verdict::Reject,
                            }
                        }
                    }
                }
            }
        }
        i += 1;
    }
}

fn oracle_apply_set(
    comm_lists: &std::collections::BTreeMap<String, policy::sets::CommunityAccessList>,
    s: &RmSet,
    r: &mut RouteData,
) {
    match s {
        RmSet::LocalPref(n) => {
            let b = r.bgp_or_materialize();
            b.local_pref = Some(n.resolve(b.local_pref.unwrap_or(0)));
        }
        RmSet::Community { list, mode } => {
            let b = r.bgp_or_materialize();
            match mode {
                CommMode::Replace => b.communities = list.clone(),
                CommMode::Add => {
                    for c in list {
                        if !b.communities.contains(c) {
                            b.communities.push(*c);
                        }
                    }
                }
            }
        }
        RmSet::CommunityDelete(n) => {
            if let Some(l) = comm_lists.get(n) {
                if let Some(b) = r.bgp.as_mut() {
                    b.communities
                        .retain(|c| !l.entries().iter().any(|e| e.communities.contains(c)));
                }
            }
        }
        RmSet::Origin(o) => r.bgp_or_materialize().origin = Some(*o),
        RmSet::Metric(n) => {
            let b = r.bgp_or_materialize();
            b.med = Some(n.resolve(b.med.unwrap_or(0)));
        }
        RmSet::AsPathPrepend { asns } => {
            // leftmost token ends up leftmost: prepend in reverse
            for &asn in asns.iter().rev() {
                r.bgp_or_materialize().as_path.prepend(asn, 1);
            }
        }
    }
}

#[derive(Debug, Clone)]
struct GenRouteMap {
    text: String,
    n_entries: usize,
}

fn route_map_strategy() -> BoxedStrategy<GenRouteMap> {
    (
        prop::collection::vec(
            (
                prop_oneof![
                    Just("10.0.0.0/8"),
                    Just("10.42.0.0/16"),
                    Just("192.0.2.0/24"),
                    Just("198.51.100.0/24"),
                    Just("0.0.0.0/0 le 32"),
                    Just("203.0.113.0/25 ge 26"),
                ],
                prop_oneof![Just("permit"), Just("deny")],
            ),
            1..3,
        ),
        prop::collection::vec(
            (
                prop_oneof![Just("^65001"), Just("_23456_"), Just("^65"), Just("_1_"),],
                prop_oneof![Just("permit"), Just("deny")],
            ),
            0..2,
        ),
        prop::collection::vec(
            (
                prop_oneof![Just("65000:1"), Just("65000:2 65000:3"), Just("no-export"),],
                prop_oneof![Just("permit"), Just("deny")],
            ),
            0..2,
        ),
        1usize..=4, // route-map entries
    )
        .prop_map(|(pls, asls, cls, n_entries)| {
            let mut text = String::new();
            for (i, (pat, verdict)) in pls.iter().enumerate() {
                text.push_str(&format!("ip prefix-list PL{i} {verdict} {pat}\n"));
            }
            for (i, (re, verdict)) in asls.iter().enumerate() {
                text.push_str(&format!("bgp as-path access-list AL{i} {verdict} {re}\n"));
            }
            for (i, (cs, verdict)) in cls.iter().enumerate() {
                text.push_str(&format!(
                    "bgp community-list standard CL{i} {verdict} {cs}\n"
                ));
            }
            for idx in 0..n_entries {
                let seq = 10 * (idx as u32 + 1);
                let policy = if idx % 2 == 0 { "permit" } else { "deny" };
                text.push_str(&format!("route-map gen {policy} {seq}\n"));
                if !pls.is_empty() && idx % 3 == 0 {
                    let i = idx % pls.len();
                    text.push_str(&format!(" match ip address prefix-list PL{i}\n"));
                }
                if !asls.is_empty() && idx % 2 == 1 {
                    let i = idx % asls.len();
                    text.push_str(&format!(" match as-path AL{i}\n"));
                }
                if !cls.is_empty() && idx % 4 == 2 {
                    let i = idx % cls.len();
                    text.push_str(&format!(" match community CL{i}\n"));
                }
                if idx % 2 == 0 {
                    text.push_str(&format!(" set local-preference {}\n", 50 + seq));
                }
                if idx % 3 == 1 {
                    text.push_str(" set community 65000:99 additive\n");
                }
                if idx % 3 == 2 {
                    text.push_str(" set origin incomplete\n");
                }
                if idx % 5 == 3 {
                    text.push_str(" set metric 42\n");
                }
                if idx % 7 == 4 {
                    text.push_str(" set as-path prepend 64512\n");
                }
                // exit policy: occasional forward continue
                if idx + 2 <= n_entries && idx % 2 == 0 {
                    let target = 10 * (idx as u32 + 2);
                    text.push_str(&format!(" continue {target}\n"));
                }
            }
            GenRouteMap { text, n_entries }
        })
        .boxed()
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(96))]

    #[test]
    fn route_map_compilation_equivalence(
        gen in route_map_strategy(),
        probe in prop_oneof![
            Just("10.0.0.0/8"),
            Just("10.42.7.0/24"),
            Just("10.99.0.0/16"),
            Just("192.0.2.128/25"),
            Just("198.51.100.0/24"),
            Just("203.0.113.200/32"),
            Just("0.0.0.0/0"),
        ],
        path in prop::collection::vec(prop_oneof![Just(65001u32), Just(65002), Just(23456), Just(1)], 0..4),
        comms in prop::collection::vec((0u16..3, 1u16..4), 0..3),
        lp in prop_oneof![Just(5u32), Just(50), Just(200)],
        metric in prop_oneof![Just(7u32), Just(42)],
    ) {
        let doc = parse_policy_config(&gen.text).expect("generated config must parse");
        let compiled = compile_route_map(&doc, "gen").expect("generated config must compile");
        let entries = &doc.route_maps["gen"].entries;

        let comms: Vec<Community> = comms.into_iter().map(|(a, v)| Community::Pair(a, v)).collect();
        let mk = || route(probe, &path, comms.clone(), lp, metric);

        // Compiled engine.
        let mut r1 = mk();
        let v1 = compiled.filter.apply(&mut r1);

        // Independent interpreter over the same parsed document.
        let mut r2 = mk();
        let v2 = oracle_interpret(
            &doc.prefix_lists,
            &doc.access_lists,
            &doc.as_path_lists,
            &doc.community_lists,
            entries,
            &mut r2,
        );

        prop_assert_eq!(v1, v2, "verdict mismatch for config:\n{}", gen.text);
        prop_assert_eq!(r1, r2, "route state mismatch for config:\n{}", gen.text);
        prop_assert_eq!(entries.len(), gen.n_entries);
    }
}

// ---------------------------------------------------------------------------
// Sanity: the determinism harness covers the goto control flow too
// (compiled route-maps are deterministic across repeated applies).
// ---------------------------------------------------------------------------

#[test]
fn compiled_route_maps_are_deterministic() {
    let text = "\
ip prefix-list a permit 10.0.0.0/8 le 32
route-map det permit 10
 match ip address prefix-list a
 set local-preference 111
 continue 30
route-map det deny 20
 match ip address prefix-list a
route-map det permit 30
 set community 65000:7 additive
";
    let doc = parse_policy_config(text).unwrap();
    let out = compile_route_map(&doc, "det").unwrap();
    let mk = || route("10.1.0.0/16", &[65001], vec![], 50, 1);
    let mut a = mk();
    let mut b = mk();
    assert_eq!(out.filter.apply(&mut a), out.filter.apply(&mut b));
    assert_eq!(a, b);
    assert_eq!(a.bgp().unwrap().local_pref, Some(111));
    assert_eq!(
        a.bgp().unwrap().communities,
        vec![Community::Pair(65000, 7)]
    );
    assert_eq!(Verdict::Accept, out.filter.apply(&mut mk()));
}
