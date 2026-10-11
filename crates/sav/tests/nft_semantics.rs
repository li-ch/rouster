//! nft ruleset semantics vs the reference pipeline — the M1 identity
//! proof for the nftables SAV backend.
//!
//! [`netlink_dp::sav_nft::ruleset`] generates the kernel ruleset from
//! a compiled op program; [`crate::table::evaluate`] is the reference
//! semantics of those ops (the GSC §3 four-step pipeline — the same
//! oracle the rp_filter backend's tests answer to). This file
//! interprets the GENERATED TEXT (not the generator's inputs) with a
//! small model of nft chain traversal — set membership, iifname
//! dispatch, first-match-wins with terminal verdicts, and sub-chain
//! fall-through to the router-scale chain — and asserts that for every
//! op matrix × probe grid the ruleset's verdict equals the reference
//! verdict, and that the verdict's enforcement word (drop/accept)
//! equals the deciding op's action.
//!
//! Placement: an integration test of the sav crate because the oracle
//! (`table::evaluate`) and the generator (`netlink-dp::sav_nft`) live
//! in different crates — the dependency only exists here, exactly the
//! dev-dependency the examples already use; a lib-level dep would
//! invert the architecture (the dataplane must not know the sav layer).

use std::collections::BTreeMap;
use std::net::IpAddr;

use common::{IpPrefix, SavProgram};
use netlink_dp::sav_nft::{ruleset, NFT_TABLE};
use sav::gen::UrpfMode;
use sav::mode::SavAction;
use sav::program::program;
use sav::table::{evaluate, SavOp, Verdict};

/// The probe answer of the interpreted ruleset: the deciding rule's
/// counter bucket (v_ = valid, i_ = invalid) and its enforcement word.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Model {
    /// No rule judged (the packet fell through everything) — Unknown.
    Unknown,
    Decided {
        invalid: bool,
        drops: bool,
    },
}

impl Model {
    fn verdict(self) -> Verdict {
        match self {
            Model::Unknown => Verdict::Unknown,
            Model::Decided { invalid, .. } => {
                if invalid {
                    Verdict::Invalid
                } else {
                    Verdict::Valid
                }
            }
        }
    }
}

/// A minimal nft chain-traversal model over the generator's exact line
/// shapes (see the generator's emission code): enough semantics to be
/// an honest oracle — set membership by prefix containment, `iifname`
/// dispatch and membership sets, first-match-wins with terminal
/// verdicts, and sub-chain fall-through to the router-scale chain.
struct RulesetModel {
    /// set name -> (is v6, prefixes)
    sets: BTreeMap<String, (bool, Vec<IpPrefix>)>,
    /// interface name -> chain name (the base chain's dispatch rules)
    dispatch: BTreeMap<String, String>,
    /// chain name -> its rule lines
    chains: BTreeMap<String, Vec<String>>,
    /// router-scale rule lines
    rs: Vec<String>,
}

impl RulesetModel {
    fn parse(text: &str) -> Self {
        let mut model = RulesetModel {
            sets: BTreeMap::new(),
            dispatch: BTreeMap::new(),
            chains: BTreeMap::new(),
            rs: Vec::new(),
        };
        let mut current_set: Option<String> = None;
        let mut current_chain: Option<String> = None;
        for raw in text.lines() {
            let line = raw.trim();
            if let Some(name) = current_set.take() {
                if line.starts_with("type ipv6_addr") {
                    model.sets.insert(name.clone(), (true, Vec::new()));
                    current_set = Some(name);
                } else if line.starts_with("type ipv4_addr") {
                    model.sets.insert(name.clone(), (false, Vec::new()));
                    current_set = Some(name);
                } else if let Some(rest) = line.strip_prefix("elements = { ") {
                    let prefixes = rest
                        .trim_end_matches('}')
                        .trim()
                        .split(", ")
                        .map(|p| p.parse().expect("valid prefix element"))
                        .collect();
                    model
                        .sets
                        .get_mut(&name)
                        .expect("type line precedes elements")
                        .1 = prefixes;
                    current_set = Some(name);
                } else if line != "}" {
                    // `flags interval`: stay in the set; the closing
                    // brace terminates it.
                    current_set = Some(name);
                }
                continue;
            }
            if let Some(name) = current_chain.take() {
                if line == "}" {
                    continue;
                }
                match name.as_str() {
                    "pre" => {
                        if let Some(rest) = line.strip_prefix("iifname \"") {
                            // `iifname "X" jump if_X_N`
                            let iface = rest.split('"').next().unwrap();
                            let target = line.rsplit("jump ").next().unwrap().trim();
                            model.dispatch.insert(iface.to_string(), target.to_string());
                        }
                        // `type filter ...` and `jump rs` are modeled
                        // structurally (fall-through goes to rs).
                    }
                    "rs" => {
                        if line.contains("counter name") {
                            model.rs.push(line.to_string());
                        }
                    }
                    other => {
                        if line.contains("counter name") {
                            model
                                .chains
                                .entry(other.to_string())
                                .or_default()
                                .push(line.to_string());
                        }
                    }
                }
                current_chain = Some(name);
                continue;
            }
            if let Some(rest) = line.strip_prefix("set ") {
                current_set = Some(rest.trim_end_matches('{').trim().to_string());
            } else if let Some(rest) = line.strip_prefix("chain ") {
                current_chain = Some(rest.trim_end_matches('{').trim().to_string());
            }
        }
        model
    }

    /// One probe: (source, ingress interface name) -> the ruleset's
    /// answer, following the base chain's traversal (per-interface
    /// chain first, fall-through to the router-scale chain).
    fn probe(&self, source: IpAddr, ingress: &str) -> Model {
        if let Some(target) = self.dispatch.get(ingress) {
            if let Some(m) = self.walk(&self.chains[target], source, ingress) {
                return m;
            }
        }
        self.walk(&self.rs, source, ingress)
            .unwrap_or(Model::Unknown)
    }

    /// Walk rule lines; Some(model) on the first matching rule (every
    /// generated match line is terminal), None on fall-through.
    fn walk(&self, rules: &[String], source: IpAddr, ingress: &str) -> Option<Model> {
        for rule in rules {
            if let Some((invalid, drops)) = self.match_rule(rule, source, ingress) {
                return Some(Model::Decided { invalid, drops });
            }
        }
        None
    }

    /// Parse one rule line: None = the rule does not match; otherwise
    /// (counter bucket is invalid?, verdict drops?).
    fn match_rule(&self, rule: &str, source: IpAddr, ingress: &str) -> Option<(bool, bool)> {
        let (body, tail) = rule
            .split_once("counter name ")
            .expect("rules carry counters");
        let (unit, verdict) = tail.split_once("\" ")?;
        let invalid = unit.trim_matches('"').starts_with("i_");
        let drops = verdict.trim() == "drop";
        // Phrase-level matching (the generator emits at most
        // `ip[6] saddr <ref>` + `iifname <ref>` in some order).
        let mut rest = body.trim();
        while !rest.is_empty() {
            if let Some(r) = rest.strip_prefix("ip saddr ") {
                let (matched, r) = self.match_saddr(r, source, false);
                if !matched {
                    return None;
                }
                rest = r.trim_start();
            } else if let Some(r) = rest.strip_prefix("ip6 saddr ") {
                let (matched, r) = self.match_saddr(r, source, true);
                if !matched {
                    return None;
                }
                rest = r.trim_start();
            } else if let Some(r) = rest.strip_prefix("iifname ") {
                let (matched, r) = self.match_iifname(r, ingress);
                if !matched {
                    return None;
                }
                rest = r.trim_start();
            } else {
                panic!("unparsed rule condition: {rule:?}");
            }
        }
        Some((invalid, drops))
    }

    /// `@set` or a literal prefix, up to the next condition.
    fn match_saddr<'a>(&self, rest: &'a str, source: IpAddr, v6: bool) -> (bool, &'a str) {
        if let Some(r) = rest.strip_prefix('@') {
            let (name, tail) = r.split_once(' ').unwrap_or((r, ""));
            let (set_v6, prefixes) = self.sets.get(name).expect("declared set");
            assert_eq!(*set_v6, v6, "family of set {name}");
            return (
                prefixes.iter().any(|p| prefix_contains_addr(*p, source)),
                tail,
            );
        }
        // literal prefix: up to the next ` iifname ` or end of body
        let end = rest.find(" iifname ").unwrap_or(rest.len());
        let (prefix, tail) = rest.split_at(end);
        let prefix: IpPrefix = prefix.trim().parse().expect("valid literal prefix");
        (prefix_contains_addr(prefix, source), tail)
    }

    /// `"x"` or `{ "a", "b" }`.
    fn match_iifname<'a>(&self, rest: &'a str, ingress: &str) -> (bool, &'a str) {
        if let Some(r) = rest.strip_prefix("{ ") {
            let (list, tail) = r.split_once(" }").unwrap_or((r, ""));
            let names: Vec<&str> = list.split(", ").map(|n| n.trim_matches('"')).collect();
            return (names.contains(&ingress), tail);
        }
        let (name, tail) = rest.split_once(' ').unwrap_or((rest, ""));
        (name.trim_matches('"') == ingress, tail)
    }
}

fn prefix_contains_addr(prefix: IpPrefix, addr: IpAddr) -> bool {
    match (prefix, addr) {
        (IpPrefix::V4(p), IpAddr::V4(a)) => {
            let len = p.prefix_len().min(32);
            let mask = if len == 0 { 0 } else { u32::MAX << (32 - len) };
            (u32::from(a) & mask) == (u32::from(p.addr()) & mask)
        }
        (IpPrefix::V6(p), IpAddr::V6(a)) => {
            let bits = p.prefix_len().min(128);
            let mask = |n: u8| if n == 0 { 0 } else { u128::MAX << (128 - n) };
            (u128::from(a) & mask(bits)) == (u128::from(p.addr()) & mask(bits))
        }
        _ => false,
    }
}

fn p(s: &str) -> IpPrefix {
    s.parse().unwrap()
}

fn ip(s: &str) -> IpAddr {
    s.parse().unwrap()
}

fn names() -> BTreeMap<u32, String> {
    [
        (2u32, "eth0"),
        (3, "eth1"),
        (4, "vethlegit"),
        (5, "eth5"),
        (6, "vethspoof"),
        (7, "eth7"),
        (9, "eth9"),
    ]
    .iter()
    .map(|&(ix, n)| (ix, n.to_string()))
    .collect()
}

fn iba(ifindex: u32, prefixes: &[&str], action: SavAction) -> SavOp {
    SavOp::IbaPermit {
        ifindex,
        prefixes: prefixes.iter().map(|s| p(s)).collect(),
        action,
        origin: None,
    }
}

/// The identity bar: for every probe in the grid, the interpreted
/// ruleset's verdict equals the reference `evaluate` verdict, and the
/// enforcement word equals the deciding op's action (monitor accepts,
/// drop drops). One shared runner; each matrix is one test.
fn assert_identity(ops: &[SavOp], mode: UrpfMode, probes: &[(&str, u32)]) {
    let prog: SavProgram = program(ops, mode);
    let rs = ruleset(&prog, &names()).expect("all ifindexes resolve");
    let model = RulesetModel::parse(&rs.text);
    for &(source, ingress) in probes {
        let reference = evaluate(ops, ip(source), ingress);
        let got = model.probe(ip(source), &names()[&ingress]);
        assert_eq!(
            got.verdict(),
            reference.verdict,
            "source {source} @ {ingress} ({}): ruleset {got:?} vs reference {}",
            names()[&ingress],
            reference.verdict
        );
        // Enforcement word: an INVALID verdict is dropped iff the
        // deciding op's action is Drop; a VALID verdict is always
        // accepted (drop mode drops invalid traffic only).
        if let (Model::Decided { invalid, drops }, Some(op)) = (got, reference.op) {
            let op_action = match op {
                SavOp::IbaPermit { action, .. }
                | SavOp::IbbBlock { action, .. }
                | SavOp::PbaPermit { action, .. }
                | SavOp::PbbBlock { action, .. } => *action,
            };
            let expected_drops = invalid && op_action.is_drop();
            assert_eq!(
                drops, expected_drops,
                "source {source} @ {ingress}: enforcement word vs deciding op's action"
            );
        }
    }
}

/// Matrix 1 — the W7 smoke topology: IBA on the egress interface and
/// an empty deny-all on the wrong one; drop action. Includes the
/// spoofed arrival (invalid), the legit arrival (valid), strangers on
/// both interfaces (invalid: not allowlisted), and an interface no op
/// covers (unknown).
#[test]
fn w7_topology_matrix() {
    let ops = [
        iba(4, &["198.51.100.0/24"], SavAction::Drop),
        iba(6, &[], SavAction::Drop),
    ];
    let probes: &[(&str, u32)] = &[
        ("198.51.100.9", 4), // legit arrival: allowlisted
        ("198.51.100.9", 6), // spoofed arrival: deny-all interface
        ("192.0.2.9", 6),    // stranger on the deny-all interface
        ("203.0.113.1", 4),  // stranger on the allowlist interface
        ("198.51.100.9", 9), // interface no op covers
        ("10.0.0.1", 9),     // ditto, v4 stranger
        ("2001:db8::1", 4),  // v6 source on a v4 allowlist interface
    ];
    assert_identity(&ops, UrpfMode::Strict, probes);
}

/// Matrix 2 — blocklist fall-through: IBB on eth0 with a router-scale
/// PBA behind it. A blocklisted source is invalid; a non-blocklisted
/// source falls through to the PBA (member valid, non-member invalid);
/// interfaces without the IBB go straight to the PBA.
#[test]
fn ibb_falls_through_to_router_scale() {
    let ops = [
        SavOp::IbbBlock {
            ifindex: 2,
            prefixes: vec![p("192.0.2.0/24")],
            action: SavAction::Drop,
            origin: None,
        },
        SavOp::PbaPermit {
            prefix: p("203.0.113.0/24"),
            ifindexes: vec![2, 3],
            action: SavAction::Drop,
            origin: None,
        },
    ];
    let probes: &[(&str, u32)] = &[
        ("192.0.2.9", 2),    // blocklisted: invalid (decided by IBB)
        ("203.0.113.9", 2),  // not blocklisted, PBA member: valid
        ("203.0.113.9", 3),  // PBA member on another interface: valid
        ("203.0.113.9", 7),  // PBA non-member: invalid
        ("198.51.100.9", 2), // neither blocklisted nor covered: unknown
        ("198.51.100.9", 9), // unknown interface, not covered
    ];
    assert_identity(&ops, UrpfMode::Strict, probes);
}

/// Matrix 3 — longest covering prefix: a /24 PBA and a /25 PBB over
/// the same space; sources inside the /25 answer the PBB, sources only
/// inside the /24 answer the PBA, at every arrival interface.
#[test]
fn longest_covering_prefix_decides() {
    let ops = [
        SavOp::PbaPermit {
            prefix: p("203.0.113.0/24"),
            ifindexes: vec![5],
            action: SavAction::Drop,
            origin: None,
        },
        SavOp::PbbBlock {
            prefix: p("203.0.113.128/25"),
            ifindexes: vec![5],
            action: SavAction::Drop,
            origin: None,
        },
    ];
    let probes: &[(&str, u32)] = &[
        ("203.0.113.200", 5), // inside /25: PBB member -> invalid
        ("203.0.113.200", 7), // inside /25: PBB non-member -> valid
        ("203.0.113.9", 5),   // only /24: PBA member -> valid
        ("203.0.113.9", 7),   // only /24: PBA non-member -> invalid
        ("198.51.100.1", 5),  // uncovered -> unknown
    ];
    assert_identity(&ops, UrpfMode::Strict, probes);
}

/// Matrix 4 — mixed actions: a monitor IBA interface ahead of a drop
/// router-scale op (IBA-decided packets take the IBA's action even
/// when invalid; the monitor never drops), and a v6 allowlist riding
/// the same inet table.
#[test]
fn mixed_actions_and_v6() {
    let ops = [
        iba(2, &["10.0.0.0/8"], SavAction::Monitor),
        iba(3, &["2001:db8::/48"], SavAction::Monitor),
        SavOp::PbaPermit {
            prefix: p("192.0.2.0/24"),
            ifindexes: vec![3],
            action: SavAction::Drop,
            origin: None,
        },
    ];
    let probes: &[(&str, u32)] = &[
        ("10.0.0.1", 2),         // monitor IBA valid: counted, accepted
        ("10.9.9.9", 2),         // monitor IBA invalid: counted, accepted (never dropped)
        ("2001:db8::1", 3),      // v6 allowlist valid
        ("2001:db8:ffff::1", 3), // v6 allowlist invalid (still monitor -> accept)
        ("192.0.2.9", 3),        // PBA member: valid + drop-capable
        ("192.0.2.9", 7),        // PBA non-member: invalid, dropped
    ];
    assert_identity(&ops, UrpfMode::Loose, probes);
}

/// Monitor-only programs generate no drop token anywhere in the file
/// (the workspace rule: monitor counts, never drops) — the structural
/// complement of the identity matrices above.
#[test]
fn monitor_programs_never_emit_a_drop() {
    let ops = [
        iba(6, &["198.51.100.0/24"], SavAction::Monitor),
        SavOp::PbbBlock {
            prefix: p("192.0.2.0/24"),
            ifindexes: vec![7],
            action: SavAction::Monitor,
            origin: None,
        },
    ];
    let prog = program(&ops, UrpfMode::Strict);
    let rs = ruleset(&prog, &names()).unwrap();
    assert!(!rs.text.contains("drop"), "monitor file:\n{}", rs.text);
    assert!(rs.text.contains(NFT_TABLE));
}
