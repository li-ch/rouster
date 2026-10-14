//! S10-c M1: the policy benchmark harness — `std::time::Instant` timing
//! over deterministically generated programs and routes.
//!
//! Fence constraints honored: NO bench dependency (criterion etc. are
//! NOT authorized — std timing is the harness); inputs are generated
//! from FIXED SEEDS so every run probes byte-identical data and the
//! printed numbers compare across code changes.
//!
//! Two tiers (the bar: harness green in the normal gate, heavy cases
//! `#[ignore]`d and documented):
//!
//! - **Gate tier** (`cargo test -p policy`): sub-second smoke cases —
//!   same generators, smallest scale; they prove the harness runs and
//!   the checksums are stable, not the recorded numbers.
//! - **Full matrix** (explicit): every scale case, `#[ignore]d`:
//!
//! ```text
//! cargo test -p policy --release --test bench -- --ignored --nocapture
//! ```
//!
//! Recorded numbers (release profile, machine noted) live in
//! docs/protocols/policy.md §8.
//!
//! Generator: splitmix64 (fixed seeds, no `rand`) — deterministic
//! across runs and machines. Pattern shape mix per set: 30% exact,
//! 40% or-longer, 25% range with low ≥ network length, 5% subsuming
//! (BIRD `-` shapes, low < network length — the linear-scan worst
//! case the §3.1 index must stay equivalent on). Probes are half
//! derived hits (subnets of generated networks) and half uniform
//! random addresses, so the match ratio is realistic rather than all
//! miss (a short-circuit-friendly lie). Each timing is the best of 3
//! reps; a checksum assertion inside the rep loop guards
//! determinism (a nondeterministic case invalidates its own timing).

use std::time::Instant;

use common::{IpPrefix, Nexthop, NexthopGroup, RouteProtocol};
use policy::route::{AsPath, BgpAttrs, BgpOrigin, Community, RouteData};
use policy::routemap::{compile_route_map, parse_policy_config};
use policy::sets::{
    AccessList, AccessListEntry, AsSet, PrefixList, PrefixListEntry, PrefixListVerdict,
    PrefixPattern, PrefixSet,
};
use policy::{Action, CommMode, CommunityPattern, CommunitySet, FilterBuilder, Term, Verdict};

// ---------------------------------------------------------------------------
// Deterministic RNG (splitmix64; fixed seeds only)
// ---------------------------------------------------------------------------

struct Rng(u64);

impl Rng {
    fn new(seed: u64) -> Self {
        Self(seed)
    }

    fn next_u64(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        z ^ (z >> 31)
    }

    fn below(&mut self, n: u64) -> u64 {
        self.next_u64() % n
    }
}

fn plen_of(p: &IpPrefix) -> u8 {
    match p {
        IpPrefix::V4(x) => x.prefix_len(),
        IpPrefix::V6(x) => x.prefix_len(),
    }
}

// ---------------------------------------------------------------------------
// Table printing
// ---------------------------------------------------------------------------

/// One benchmark row: what ran, the data shape, a determinism checksum
/// (`hits`/`checksum` must be identical across reps — asserted — and
/// across runs of the same seed), and the best-of-3 timing.
struct Row {
    name: &'static str,
    entries: usize,
    evals: usize,
    hits: u64,
    checksum: u64,
    best: std::time::Duration,
}

const REPS: usize = 3;

fn print_table(title: &str, checksum_meaning: &str, rows: &[Row]) {
    println!("== {title} ==  [checksum = {checksum_meaning}]");
    println!(
        "{:<30} {:>9} {:>9} {:>8} {:>12} {:>10} {:>10}",
        "case", "entries", "evals", "hits", "checksum", "best-ms", "ns/eval"
    );
    for r in rows {
        println!(
            "{:<30} {:>9} {:>9} {:>8} {:>12} {:>10.2} {:>10.1}",
            r.name,
            r.entries,
            r.evals,
            r.hits,
            r.checksum,
            r.best.as_secs_f64() * 1e3,
            r.best.as_nanos() as f64 / r.evals as f64
        );
    }
}

// ---------------------------------------------------------------------------
// Generators (v4 throughout; deterministic given the seed)
// ---------------------------------------------------------------------------

/// Deterministic pattern-shape mix (see module doc). Returns the set and
/// the generated networks (probe hits derive from them).
fn gen_prefix_set(n: usize, seed: u64) -> (PrefixSet, Vec<IpPrefix>) {
    let mut rng = Rng::new(seed);
    let mut set = PrefixSet::new();
    let mut networks = Vec::with_capacity(n);
    for i in 0..n {
        // Network: 10.a.b.0/len — nesting happens naturally as lengths vary.
        let a = rng.below(256) as u8;
        let b = rng.below(256) as u8;
        let len = 8 + rng.below(21) as u8; // 8..=28
        let addr = std::net::Ipv4Addr::new(10, a, b, 0);
        let prefix: IpPrefix = format!("{addr}/{len}").parse().unwrap();
        let pattern = match i % 20 {
            0..=5 => PrefixPattern::exact(prefix),      // 30%
            6..=13 => PrefixPattern::or_longer(prefix), // 40%
            14..=18 => {
                // 25%: range above the network length.
                let lo = len + 1 + rng.below(3) as u8;
                let hi = (len + 4 + rng.below(6) as u8).min(32);
                PrefixPattern::range(prefix, lo.min(hi), hi).unwrap()
            }
            _ => {
                // 5% subsuming (BIRD `-` shapes): low < network length.
                let lo = len.saturating_sub(1 + rng.below(6) as u8);
                PrefixPattern::range(prefix, lo, len).unwrap()
            }
        };
        let pattern = if i % 8 == 0 {
            pattern.with_tag(i as u32 + 1)
        } else {
            pattern
        };
        set.add_pattern(pattern);
        networks.push(prefix);
    }
    (set, networks)
}

/// Half derived hits (subnets of generated networks), half uniform
/// random addresses — a realistic match ratio, not an all-miss fast path.
fn gen_probes(k: usize, seed: u64, networks: &[IpPrefix]) -> Vec<IpPrefix> {
    let mut rng = Rng::new(seed ^ 0x5eed);
    let mut probes = Vec::with_capacity(k);
    for i in 0..k {
        let probe = if i % 2 == 0 && !networks.is_empty() {
            let net = networks[rng.below(networks.len() as u64) as usize];
            let IpPrefix::V4(v4) = net else {
                continue;
            };
            let len = v4.prefix_len();
            let oct = v4.addr().octets();
            let host = rng.below(1 << 8) as u8;
            let addr = std::net::Ipv4Addr::new(oct[0], oct[1], oct[2], host);
            format!("{addr}/{}", len + 1 + rng.below((32 - len) as u64) as u8)
                .parse()
                .unwrap()
        } else {
            let addr = std::net::Ipv4Addr::from((rng.below(1 << 32) as u32) & 0xff00_ff00); // sparse misses
            let len = 8 + rng.below(25) as u8;
            format!("{addr}/{len}").parse().unwrap()
        };
        probes.push(probe);
    }
    probes
}

/// FRR ordered prefix-list: seq-numbered permit/deny entries over the
/// same generated networks (permit/deny by deterministic parity+seed).
fn gen_prefix_list(n: usize, seed: u64) -> PrefixList {
    let mut rng = Rng::new(seed ^ 0x1111);
    let (_, networks) = gen_prefix_set(n, seed);
    let mut pl = PrefixList::new();
    for (i, net) in networks.iter().enumerate() {
        let len = plen_of(net);
        let pattern = if i % 3 == 0 {
            PrefixPattern::exact(*net)
        } else {
            PrefixPattern::range(*net, len, 32).unwrap() // le 32
        };
        pl.insert(PrefixListEntry {
            seq: 5 * (i as u32 + 1),
            verdict: if rng.below(2) == 0 {
                PrefixListVerdict::Permit
            } else {
                PrefixListVerdict::Deny
            },
            pattern,
        });
    }
    pl
}

/// Zebra-style access-list over the same networks (subnet-of default).
fn gen_access_list(n: usize, seed: u64) -> AccessList {
    let (_, networks) = gen_prefix_set(n, seed);
    let mut al = AccessList::new();
    for (i, net) in networks.iter().enumerate() {
        al.insert(AccessListEntry {
            seq: 5 * (i as u32 + 1),
            verdict: if i % 2 == 0 {
                PrefixListVerdict::Permit
            } else {
                PrefixListVerdict::Deny
            },
            pattern: PrefixPattern::or_longer(*net),
        });
    }
    al
}

/// Disjoint ASN intervals (binary-search membership — the contrast
/// column: the interval representation §3.2 already ships).
fn gen_as_set(n: usize, seed: u64) -> AsSet {
    let mut rng = Rng::new(seed ^ 0x2222);
    let mut set = AsSet::new();
    let mut next = 1u32;
    for _ in 0..n {
        let lo = next;
        let width = 1 + rng.below(16) as u32;
        set.insert_range(lo, lo + width);
        next = lo + width + 2 + rng.below(8) as u32; // keep disjoint
    }
    set
}

/// A generated route: prefix probe + BGP attrs (path, communities).
fn gen_route(prefix: IpPrefix, seed: u64) -> RouteData {
    let mut rng = Rng::new(seed);
    let path_len = rng.below(7) as usize;
    let path: Vec<u32> = (0..path_len)
        .map(|_| 64512 + rng.below(2000) as u32)
        .collect();
    let comms: Vec<Community> = (0..rng.below(4))
        .map(|i| Community::Pair(65000, 1 + (i % 8) as u16))
        .collect();
    let mut nexthops = NexthopGroup::new();
    nexthops.add(Nexthop::Ipv4("192.0.2.1".parse().unwrap()), 1);
    RouteData {
        prefix,
        protocol: RouteProtocol::Bgp,
        metric: rng.below(1000) as u32,
        nexthops,
        bgp: Some(BgpAttrs {
            as_path: AsPath::from_sequence(&path),
            local_pref: Some(50 + rng.below(200) as u32),
            med: None,
            origin: Some(BgpOrigin::Igp),
            communities: comms,
            ext_communities: Vec::new(),
            otc: None,
        }),
    }
}

// ---------------------------------------------------------------------------
// The timed operations
// ---------------------------------------------------------------------------

fn time_prefix_set(set: &PrefixSet, probes: &[IpPrefix]) -> (u64, u64) {
    let mut hits = 0u64;
    let mut tag_sum = 0u64;
    for p in probes {
        let m = set.matches(p);
        if m.matched {
            hits += 1;
        }
        if let Some(t) = m.tag {
            tag_sum += t as u64;
        }
    }
    (hits, tag_sum)
}

fn time_prefix_list(list: &PrefixList, probes: &[IpPrefix]) -> (u64, u64) {
    let mut hits = 0u64;
    let mut permits = 0u64;
    for p in probes {
        if let Some(v) = list.first_match(p) {
            hits += 1;
            if v == PrefixListVerdict::Permit {
                permits += 1;
            }
        }
    }
    (hits, permits)
}

fn time_access_list(list: &AccessList, probes: &[IpPrefix]) -> (u64, u64) {
    let mut hits = 0u64;
    let mut permits = 0u64;
    for p in probes {
        if let Some(v) = list.first_match(p) {
            hits += 1;
            if v == PrefixListVerdict::Permit {
                permits += 1;
            }
        }
    }
    (hits, permits)
}

fn time_as_set(set: &AsSet, asns: &[u32]) -> (u64, u64) {
    let mut hits = 0u64;
    let mut sum = 0u64;
    for &a in asns {
        if set.contains(a) {
            hits += 1;
            sum += a as u64;
        }
    }
    (hits, sum)
}

/// Best-of-REPS timing of a closure returning the checksum pair; the
/// checksum must be identical every rep or the case invalidates itself.
fn bench<F: FnMut() -> (u64, u64)>(mut f: F) -> ((u64, u64), std::time::Duration) {
    let checksum = f(); // warm-up: page-in, cache, JIT-free but branch-predict
    let mut best = std::time::Duration::MAX;
    for _ in 0..REPS {
        let t0 = Instant::now();
        let c = f();
        let dt = t0.elapsed();
        assert_eq!(c, checksum, "nondeterministic case — timing invalid");
        best = best.min(dt);
    }
    (checksum, best)
}

/// A representative generated program: 8 rules mixing set lookups,
/// prefix-length, path, and community terms over an `n`-entry set.
fn gen_filter(seed: u64, n: usize) -> (policy::Filter, PrefixSet) {
    let (set, _) = gen_prefix_set(n, seed);
    let mut as_set = AsSet::new();
    as_set.insert_range(64600, 64800);
    let mut comms = CommunitySet::new();
    comms.add_pattern(CommunityPattern::exact(65000, 3));
    let mut b = FilterBuilder::new();
    let ps = b.add_prefix_set(set.clone());
    let asx = b.add_as_set(as_set);
    let cs = b.add_community_set(comms);
    b.add_rule(
        Term::And(vec![
            Term::PrefixIn(ps),
            Term::PrefixTagIn(ps, vec![1, 9, 17, 25]),
        ]),
        vec![Action::SetLocalPref(200)],
    );
    b.add_rule(
        Term::And(vec![
            Term::PrefixIn(ps),
            Term::PrefixLen { min: 16, max: 28 },
        ]),
        vec![Action::SetCommunities {
            list: vec![Community::Pair(65000, 99)],
            mode: CommMode::Add,
        }],
    );
    b.add_rule(
        Term::And(vec![Term::PathIn(asx), Term::PathLen { min: 1, max: 6 }]),
        vec![],
    );
    b.add_rule(
        Term::PrefixLen { min: 8, max: 20 },
        vec![Action::SetMetric(42)],
    );
    b.add_rule(Term::CommunityAny(cs), vec![Action::AdjustLocalPref(10)]);
    b.add_rule(
        Term::And(vec![
            Term::PrefixLen { min: 8, max: 32 },
            Term::PathLen { min: 0, max: 8 },
        ]),
        vec![Action::PrependAsPath {
            asn: 64512,
            times: 1,
        }],
    );
    b.add_rule(Term::LocalPrefIn(60, 250), vec![Action::Accept]);
    let filter = b.default_verdict(Verdict::Reject).build().unwrap();
    (filter, set)
}

// ---------------------------------------------------------------------------
// Full-matrix tier: every case `#[ignore]`d; run explicitly (release
// profile for the recorded numbers — see module doc):
//   cargo test -p policy --release --test bench -- --ignored --nocapture
// ---------------------------------------------------------------------------

/// The prefix-set scale ladder: (100, 10k, 100k) entries × (1k, 100k)
/// evaluations — the full 8-combo matrix, the named §Deferred hotspot.
fn prefix_set_case(entries: usize, evals: usize) -> Row {
    let seed = 0x5100_0000 + entries as u64 * 31 + evals as u64;
    let (set, networks) = gen_prefix_set(entries, seed);
    let probes = gen_probes(evals, seed, &networks);
    let ((hits, tag_sum), best) = bench(|| time_prefix_set(&set, &probes));
    Row {
        name: "PrefixSet::matches",
        entries,
        evals,
        hits,
        checksum: tag_sum,
        best,
    }
}

#[test]
#[ignore = "full matrix (100/10k/100k entries x 1k/100k evals) — run explicitly: cargo test -p policy --release --test bench -- --ignored --nocapture"]
fn bench_prefix_set_full() {
    let rows = vec![
        prefix_set_case(100, 1_000),
        prefix_set_case(100, 100_000),
        prefix_set_case(10_000, 1_000),
        prefix_set_case(10_000, 100_000),
        prefix_set_case(100_000, 1_000),
        prefix_set_case(100_000, 100_000),
    ];
    print_table(
        "prefix-set lookup (BIRD longest-match + tag)",
        "sum of matched tags",
        &rows,
    );
}

#[test]
#[ignore = "full matrix — run explicitly: cargo test -p policy --release --test bench -- --ignored --nocapture"]
fn bench_ordered_lists_full() {
    // FRR ordered scans stay linear-by-design (first covering entry in
    // sequence order — §8 of docs/protocols/policy.md discloses why the
    // longest-match index does not apply to them).
    let mut rows = Vec::new();
    for entries in [1_000usize, 10_000] {
        let seed = 0xa100_0000 + entries as u64;
        let (_, networks) = gen_prefix_set(entries, seed);
        let probes = gen_probes(100_000, seed, &networks);
        let pl = gen_prefix_list(entries, seed);
        let ((hits, permits), best) = bench(|| time_prefix_list(&pl, &probes));
        rows.push(Row {
            name: "PrefixList::first_match",
            entries,
            evals: probes.len(),
            hits,
            checksum: permits,
            best,
        });
        let al = gen_access_list(entries, seed);
        let ((hits, permits), best) = bench(|| time_access_list(&al, &probes));
        rows.push(Row {
            name: "AccessList::first_match",
            entries,
            evals: probes.len(),
            hits,
            checksum: permits,
            best,
        });
    }
    print_table("FRR ordered first-match scans", "permit verdicts", &rows);
}

#[test]
#[ignore = "full matrix — run explicitly: cargo test -p policy --release --test bench -- --ignored --nocapture"]
fn bench_as_set_full() {
    // The contrast column: §3.2's interval representation is already
    // O(log n) — this pins what a non-linear set lookup costs.
    let seed = 0x3b00_0000;
    let set = gen_as_set(10_000, seed);
    let mut rng = Rng::new(seed ^ 77);
    let asns: Vec<u32> = (0..100_000).map(|_| 1 + rng.below(40_000) as u32).collect();
    let ((hits, sum), best) = bench(|| time_as_set(&set, &asns));
    print_table(
        "AS-set membership (interval binary search)",
        "sum of member ASNs",
        &[Row {
            name: "AsSet::contains",
            entries: 10_000,
            evals: asns.len(),
            hits,
            checksum: sum,
            best,
        }],
    );
}

#[test]
#[ignore = "full matrix — run explicitly: cargo test -p policy --release --test bench -- --ignored --nocapture"]
fn bench_filter_apply_full() {
    // The compiled-program hot path: 8 rules over a 1k-entry
    // prefix-set, applied to 100k generated routes. Each iteration
    // clones the pristine route into a scratch buffer (apply mutates
    // in place) — the clone cost is part of the row, disclosed by the
    // name. (The set is 1k, not 10k: the apply row should show the
    // rule-walk cost, not triple-scan one prefix-set 100k times — the
    // set-scale story is the dedicated ladder above.)
    let (filter, _) = gen_filter(0x9100_0001, 1_000);
    let (_, networks) = gen_prefix_set(1_000, 0x9100_0001);
    let probes = gen_probes(100_000, 0x9100_0001, &networks);
    let routes: Vec<RouteData> = probes
        .iter()
        .enumerate()
        .map(|(i, &p)| gen_route(p, 0x9100_0002 + i as u64))
        .collect();
    let ((accepts, metric_sum), best) = bench(|| {
        let mut acc = 0u64;
        let mut chk = 0u64;
        for r in &routes {
            let mut scratch = r.clone();
            if filter.apply(&mut scratch).is_accept() {
                acc += 1;
            }
            chk += scratch.metric as u64;
        }
        (acc, chk)
    });
    print_table(
        "Filter::apply (8 rules, 1k-entry prefix-set)",
        "sum of post-apply metrics",
        &[Row {
            name: "apply (incl. route clone)",
            entries: 8,
            evals: routes.len(),
            hits: accepts,
            checksum: metric_sum,
            best,
        }],
    );
}

#[test]
#[ignore = "100k-entry import — run explicitly: cargo test -p policy --release --test bench -- --ignored --nocapture"]
fn bench_route_map_parse_compile_full() {
    parse_compile_at(100_000);
}

// ---------------------------------------------------------------------------
// Gate tier: sub-second smoke cases (same generators, smallest scale —
// they prove the harness runs and the checksums are stable).
// ---------------------------------------------------------------------------

#[test]
fn bench_prefix_set_smoke() {
    let row = prefix_set_case(100, 1_000);
    print_table("prefix-set lookup (smoke)", "sum of matched tags", &[row]);
}

#[test]
fn bench_ordered_lists_smoke() {
    let seed = 0xa100_0000 + 1_000u64;
    let pl = gen_prefix_list(1_000, seed);
    let (_, networks) = gen_prefix_set(1_000, seed);
    let probes = gen_probes(1_000, seed, &networks);
    let ((hits, permits), best) = bench(|| time_prefix_list(&pl, &probes));
    print_table(
        "FRR ordered first-match scan (smoke)",
        "permit verdicts",
        &[Row {
            name: "PrefixList::first_match",
            entries: 1_000,
            evals: probes.len(),
            hits,
            checksum: permits,
            best,
        }],
    );
}

#[test]
fn bench_as_set_smoke() {
    let seed = 0x3b00_0000;
    let set = gen_as_set(10_000, seed);
    let mut rng = Rng::new(seed ^ 77);
    let asns: Vec<u32> = (0..10_000).map(|_| 1 + rng.below(40_000) as u32).collect();
    let ((hits, sum), best) = bench(|| time_as_set(&set, &asns));
    print_table(
        "AS-set membership (smoke)",
        "sum of member ASNs",
        &[Row {
            name: "AsSet::contains",
            entries: 10_000,
            evals: asns.len(),
            hits,
            checksum: sum,
            best,
        }],
    );
}

#[test]
fn bench_filter_apply_smoke() {
    let (filter, _) = gen_filter(0x9100_0001, 100);
    let (_, networks) = gen_prefix_set(100, 0x9100_0001);
    let probes = gen_probes(100, 0x9100_0001, &networks);
    let routes: Vec<RouteData> = probes
        .iter()
        .enumerate()
        .map(|(i, &p)| gen_route(p, 0x9100_0002 + i as u64))
        .collect();
    let ((accepts, metric_sum), best) = bench(|| {
        let mut acc = 0u64;
        let mut chk = 0u64;
        for r in &routes {
            let mut scratch = r.clone();
            if filter.apply(&mut scratch).is_accept() {
                acc += 1;
            }
            chk += scratch.metric as u64;
        }
        (acc, chk)
    });
    print_table(
        "Filter::apply (smoke)",
        "sum of post-apply metrics",
        &[Row {
            name: "apply (incl. route clone)",
            entries: 8,
            evals: routes.len(),
            hits: accepts,
            checksum: metric_sum,
            best,
        }],
    );
}

#[test]
fn bench_route_map_parse_compile_smoke() {
    parse_compile_at(100);
    parse_compile_at(10_000);
}

/// Import-path one-shot: parse + compile a generated FRR config of
/// `entries` prefix-list entries feeding one route-map entry.
fn parse_compile_at(entries: usize) {
    let (set, _) = gen_prefix_set(entries, 0xc100_0000 + entries as u64);
    let mut text = String::new();
    for (i, pat) in set.patterns().iter().enumerate() {
        let verdict = if i % 2 == 0 { "permit" } else { "deny" };
        text.push_str(&format!(
            "ip prefix-list BENCH seq {} {} {} le 32\n",
            5 * (i as u32 + 1),
            verdict,
            pat.prefix,
        ));
    }
    text.push_str("route-map bench permit 10\n match ip address prefix-list BENCH\n");
    let t0 = Instant::now();
    let doc = parse_policy_config(&text).expect("generated config parses");
    let parse_dt = t0.elapsed();
    let t1 = Instant::now();
    let out = compile_route_map(&doc, "bench").expect("generated config compiles");
    let compile_dt = t1.elapsed();
    println!(
        "== route-map import (one-shot) == entries {entries}: parse {:>8.2} ms, compile {:>8.2} ms ({} rules)",
        parse_dt.as_secs_f64() * 1e3,
        compile_dt.as_secs_f64() * 1e3,
        out.filter.rules().len()
    );
}
