//! SAV program → nftables ruleset translation (pure; no I/O).
//!
//! This is the precision surface the rp_filter backend cannot express
//! ([`crate::sav`] lists what it rejects): a wholly-owned
//! `table inet rouster_sav` enforcing the compiled rule CONTENT —
//! per-interface allowlists as interval sets, blocklists, router-scale
//! prefix ops — with monitor actions as named counters plus `accept`
//! (count without dropping, the thing a sysctl cannot do) and drop
//! actions as enforced denies. IPv6 rides the same table (the `inet`
//! family), and installing nothing outside the table means clear is a
//! single `destroy table` — no prior-value bookkeeping on shared kernel
//! state, unlike the sysctl surface.
//!
//! Enforcement shape (semantics identical to the reference pipeline in
//! `sav::table::evaluate`, the GSC §3 four steps — the sav-crate
//! integration test `tests/nft_semantics.rs` pins the equality over op
//! matrices):
//!
//! * one base chain at `prerouting` priority `raw` (the first filtering
//!   point; covers traffic to the router and through it) dispatches on
//!   `iifname` into per-interface chains;
//! * an interface with an allowlist op (IBA) gets a decisive chain:
//!   set match → `counter accept`, then a terminal deny counter
//!   (`drop` action) or count-only accept (`monitor` action) — IBA
//!   short-circuits everything below, so the chain never falls through;
//! * an interface with only a blocklist op (IBB) gets a chain whose
//!   match rules deny/terminal-accept but has NO terminal rule: a
//!   non-match falls through to the router-scale chain, exactly the
//!   reference pipeline's provisional-valid step;
//! * the router-scale chain holds the PBA/PBB ops in DESCENDING prefix
//!   length — first match is the longest covering prefix, the reference
//!   pipeline's step-4 selection (ties cannot both cover one address:
//!   at most one prefix per (family, length) contains a given source);
//! * `accept`/`drop` verdicts inside a jumped-to chain terminate the
//!   whole hook traversal (verified against nftables v1.0.9: a bare
//!   counter past an accepted sub-chain never increments), which is
//!   what makes the decisive chains decisive.
//!
//! Interval sets declare `auto-merge`: a daemon-fed allowlist can hold
//! a covering and a covered prefix at once (the SIB merges the
//! interface mirror's connected prefixes with RIB-derived ones), and a
//! plain interval set rejects overlapping elements ("conflicting
//! intervals specified", nftables v1.0.9) — auto-merge resolves them
//! to the union, which is the list's own semantics either way.
//!
//! The uRPF generator-semantics hint ([`common::SavUrpf`]) is ignored,
//! as `common::dataplane` documents for real rule engines: this backend
//! enforces the allowlist content itself. The pre-registered idiom for
//! the ladder named `fib saddr . iif` (the kernel-FIB uRPF lookup);
//! that expression enforces the FIB's own answer — the exact
//! approximation the rp_filter backend already discloses — so the
//! generator uses prefix sets instead. The precision gain over the
//! sysctl surface is the content: an operator allowlist narrower than
//! the FIB's egress membership is enforced as written (the
//! spoof-differential smoke's differential leg).
//!
//! Monitor counting: every verdict rule carries a named counter —
//! `v_<unit>` for valid, `i_<unit>` for invalid (unit = interface or
//! router-scale op index). [`parse_counter_packets`] reads them back
//! from `nft list counters` output; `unknown` stays 0 (packets no rule
//! judged never enter a rouster chain — nothing counts them, by
//! construction). Aggregate counts feed
//! [`crate::Dataplane::sav_monitor_counts`]; the per-op rows
//! ([`NftRuleset::counters`] + [`attribute_counts`]) feed
//! [`crate::Dataplane::sav_monitor_per_op`] — the per-rule counter
//! surface the daemon's status rides (GSC §4 "count", kernel-sourced).
//!
//! Determinism: the same program + ifindex→name map always generates a
//! byte-identical file (program ops arrive normalized; interface
//! iteration is BTree order; router-scale ops sort by descending prefix
//! length with canonical order as the stable tiebreak) — the executor's
//! churn guard compares file bytes to skip identical replays, which
//! also preserves kernel counters across re-evaluations.

use std::collections::{BTreeMap, BTreeSet};

use common::{IpPrefix, SavEnforce, SavMonitorCounts, SavProgram, SavProgramOp};

/// The wholly-owned table everything below lives in.
pub const NFT_TABLE: &str = "rouster_sav";
/// Table family: `inet` covers v4 and v6 in one table.
pub const NFT_FAMILY: &str = "inet";

/// A rule placement failure — never a silent skip (programming a rule
/// for a vanished interface would report protection that does not
/// exist; the sysctl backend errors the same way).
#[derive(Debug, PartialEq, Eq, thiserror::Error)]
pub enum RulesetError {
    #[error("ifindex {0} has no interface (cannot build nft ruleset)")]
    UnknownIfindex(u32),
}

/// The generated ruleset plus its placement summary.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct NftRuleset {
    /// The ruleset file body: `table inet rouster_sav { ... }`, or an
    /// EMPTY string for an empty program (nothing to enforce — the
    /// executor destroys any applied table and writes no file).
    pub text: String,
    /// One `(ifindex, name, action)` per per-interface chain, in
    /// ifindex order — the applied-state marker's content.
    pub interfaces: Vec<(u32, String, SavEnforce)>,
    /// The per-op counter attribution map (N6B): one `(op, valid-unit,
    /// invalid-unit)` per PLACED op, in emission order (interfaces by
    /// ifindex, then router-scale ops in rule order) — the units the
    /// ruleset names its `v_`/`i_` counters after, paired with the op
    /// whose verdicts they count. [`attribute_counts`] joins this map
    /// with `nft list counters` output into the per-op monitor rows
    /// ([`crate::Dataplane::sav_monitor_per_op`]). An IBB op's valid
    /// unit is a DEAD counter (its chain has no terminal rule, so no
    /// rule ever references it) — carried anyway so the map is total
    /// and the row's `valid` stays an honest 0. Ops in `ignored` have
    /// no rules and appear here not at all.
    pub counters: Vec<(SavProgramOp, String, String)>,
    /// Ops no rule could place (unreachable duplicates, or a blocklist
    /// under a decisive allowlist), with reasons — logged as warnings
    /// by the backend, never silently swallowed (same contract as the
    /// sysctl plan's `rejected` list).
    pub ignored: Vec<(SavProgramOp, &'static str)>,
}

/// Which enforcement surface a dataplane routes SAV ops to. The default
/// is the long-landed rp_filter sysctl backend; `Nft` selects this
/// module behind the same trait ops.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum SavBackend {
    /// rp_filter sysctls (FIB-enforced uRPF; no monitor counters).
    #[default]
    RpFilter,
    /// The nftables ruleset here (content-enforced; counter-bearing).
    Nft,
}

/// Translate a program into the nftables ruleset (see module docs for
/// the shape and its semantics). `names` resolves every ifindex any op
/// mentions — interface-scale ops build chains, router-scale ops match
/// `iifname` membership — and a missing ifindex is an error.
pub fn ruleset(
    program: &SavProgram,
    names: &BTreeMap<u32, String>,
) -> Result<NftRuleset, RulesetError> {
    // Step-2/3 op selection: per interface, the FIRST op of each kind
    // in canonical order is the one the reference pipeline consults
    // (`evaluate` uses `find`); a later same-kind op for the same
    // interface is unreachable and lands in `ignored`, disclosed.
    // The maps keep whole ops so `counters` below can pair units with
    // the op identity that placed them.
    let mut iba: BTreeMap<u32, &SavProgramOp> = BTreeMap::new();
    let mut ibb: BTreeMap<u32, &SavProgramOp> = BTreeMap::new();
    let mut router_scale: Vec<&SavProgramOp> = Vec::new();
    let mut ignored: Vec<(SavProgramOp, &'static str)> = Vec::new();

    for op in program.ops() {
        match op {
            SavProgramOp::IfaceAllow { ifindex, .. } => {
                if iba.contains_key(ifindex) {
                    ignored.push((
                        op.clone(),
                        "duplicate interface allowlist: the first op in canonical order is \
                         decisive (reference pipeline step 2); this one is unreachable",
                    ));
                } else {
                    iba.insert(*ifindex, op);
                }
            }
            SavProgramOp::IfaceBlock { ifindex, .. } => {
                if ibb.contains_key(ifindex) {
                    ignored.push((
                        op.clone(),
                        "duplicate interface blocklist: the first op in canonical order is \
                         the only one consulted (reference pipeline step 3); this one is \
                         unreachable",
                    ));
                } else {
                    ibb.insert(*ifindex, op);
                }
            }
            SavProgramOp::PrefixAllow { .. } | SavProgramOp::PrefixBlock { .. } => {
                router_scale.push(op);
            }
        }
    }

    // IBA is decisive: a blocklist on an IBA-covered interface never
    // runs (step 3 is only reached when step 2 did not decide).
    let mut ifindexes: BTreeSet<u32> = iba.keys().copied().collect();
    for (&ifindex, op) in &ibb {
        if iba.contains_key(&ifindex) {
            ignored.push((
                (*op).clone(),
                "interface allowlist (IBA) is decisive for this interface (reference pipeline \
                 step 2 short-circuits step 3); the blocklist is unreachable",
            ));
        } else {
            ifindexes.insert(ifindex);
        }
    }

    // Every ifindex any op mentions must resolve (chains and iifname
    // membership alike) — the never-a-silent-skip rule.
    let mentioned: BTreeSet<u32> = ifindexes
        .iter()
        .copied()
        .chain(router_scale.iter().flat_map(|op| match op {
            SavProgramOp::PrefixAllow { ifindexes, .. }
            | SavProgramOp::PrefixBlock { ifindexes, .. } => ifindexes.iter().copied(),
            _ => unreachable!("router-scale only"),
        }))
        .collect();
    let mut resolved: BTreeMap<u32, String> = BTreeMap::new();
    for ifindex in mentioned {
        let Some(name) = names.get(&ifindex) else {
            return Err(RulesetError::UnknownIfindex(ifindex));
        };
        resolved.insert(ifindex, name.clone());
    }

    // Router-scale order: v4 then v6, descending prefix length within a
    // family (longest covering prefix decides — cross-family order is
    // semantically irrelevant since a source matches only its own
    // family's prefixes, but grouping keeps the file readable);
    // canonical order is the stable tiebreak, which cannot change
    // semantics (at most one prefix per (family, length) covers a given
    // address) but keeps the file deterministic.
    router_scale.sort_by_key(|op| (prefix_family_rank(op), std::cmp::Reverse(prefix_len(op))));

    let mut interfaces = Vec::new();
    let mut counters: Vec<(SavProgramOp, String, String)> = Vec::new();
    let mut text = String::new();
    if ifindexes.is_empty() && router_scale.is_empty() {
        return Ok(NftRuleset {
            text,
            interfaces,
            counters,
            ignored,
        });
    }

    text.push_str("# rouster SAV enforcement (nftables backend): table inet ");
    text.push_str(NFT_TABLE);
    text.push_str(
        "\n# generated by rouster netlink-dp; replace semantics: the table is wholly\n\
                   # owned - identical replays are skipped, every change recreates it whole\n",
    );
    text.push_str("table ");
    text.push_str(NFT_FAMILY);
    text.push(' ');
    text.push_str(NFT_TABLE);
    text.push_str(" {\n");

    // Sets: allow/block, v4/v6, per interface in ifindex order.
    for (&ifindex, op) in &iba {
        let SavProgramOp::IfaceAllow { prefixes, .. } = op else {
            unreachable!("iba holds allow ops");
        };
        emit_set(
            &mut text,
            &set_name('a', '4', ifindex, &resolved),
            "ipv4_addr",
            v4(prefixes),
        );
        emit_set(
            &mut text,
            &set_name('a', '6', ifindex, &resolved),
            "ipv6_addr",
            v6(prefixes),
        );
    }
    for (&ifindex, op) in &ibb {
        if iba.contains_key(&ifindex) {
            continue; // unreachable under the decisive allowlist
        }
        let SavProgramOp::IfaceBlock { prefixes, .. } = op else {
            unreachable!("ibb holds block ops");
        };
        emit_set(
            &mut text,
            &set_name('b', '4', ifindex, &resolved),
            "ipv4_addr",
            v4(prefixes),
        );
        emit_set(
            &mut text,
            &set_name('b', '6', ifindex, &resolved),
            "ipv6_addr",
            v6(prefixes),
        );
    }

    // Counters: v/i per interface chain, then v/i per router-scale op.
    // Every declared unit is recorded against the op whose verdicts it
    // counts — the attribution map `sav_monitor_per_op` reads back.
    for &ifindex in &ifindexes {
        let name = &resolved[&ifindex];
        let (v_unit, i_unit) = (unit_name('v', ifindex, name), unit_name('i', ifindex, name));
        emit_counter(&mut text, &v_unit);
        emit_counter(&mut text, &i_unit);
        let op = iba
            .get(&ifindex)
            .or_else(|| ibb.get(&ifindex))
            .expect("ifindexes come from the op maps");
        interfaces.push((ifindex, name.clone(), action_of(op)));
        counters.push(((**op).clone(), v_unit, i_unit));
    }
    for (idx, op) in router_scale.iter().enumerate() {
        emit_counter(&mut text, &format!("v_rs{idx}"));
        emit_counter(&mut text, &format!("i_rs{idx}"));
        counters.push(((*op).clone(), format!("v_rs{idx}"), format!("i_rs{idx}")));
    }

    // Base chain: dispatch per-interface chains, then router-scale.
    text.push_str("    chain pre {\n");
    text.push_str("        type filter hook prerouting priority raw; policy accept;\n");
    for &ifindex in &ifindexes {
        let name = &resolved[&ifindex];
        line(
            &mut text,
            &format!(
                r#"        iifname "{name}" jump {}"#,
                chain_name(ifindex, name)
            ),
        );
    }
    if !router_scale.is_empty() {
        line(&mut text, "        jump rs");
    }
    text.push_str("    }\n");

    // Per-interface chains.
    for &ifindex in &ifindexes {
        let name = &resolved[&ifindex];
        line(
            &mut text,
            &format!("    chain {} {{", chain_name(ifindex, name)),
        );
        if let Some(op) = iba.get(&ifindex) {
            let SavProgramOp::IfaceAllow {
                prefixes, action, ..
            } = op
            else {
                unreachable!("iba holds allow ops");
            };
            // IBA: decisive. Set matches accept (valid); the terminal
            // rule decides everything else (invalid) — drop, or count
            // and accept under monitor.
            if !v4(prefixes).is_empty() {
                line(
                    &mut text,
                    &format!(
                        r#"        ip saddr @{} counter name "{}" accept"#,
                        set_name('a', '4', ifindex, &resolved),
                        unit_name('v', ifindex, name)
                    ),
                );
            }
            if !v6(prefixes).is_empty() {
                line(
                    &mut text,
                    &format!(
                        r#"        ip6 saddr @{} counter name "{}" accept"#,
                        set_name('a', '6', ifindex, &resolved),
                        unit_name('v', ifindex, name)
                    ),
                );
            }
            line(
                &mut text,
                &format!(
                    r#"        counter name "{}" {}"#,
                    unit_name('i', ifindex, name),
                    verdict_of(*action)
                ),
            );
        } else if let Some(op) = ibb.get(&ifindex) {
            let SavProgramOp::IfaceBlock {
                prefixes, action, ..
            } = op
            else {
                unreachable!("ibb holds block ops");
            };
            // IBB: a match is decided-invalid (terminal); a non-match
            // falls through to the router-scale chain — no terminal.
            let verdict = verdict_of(*action);
            if !v4(prefixes).is_empty() {
                line(
                    &mut text,
                    &format!(
                        r#"        ip saddr @{} counter name "{}" {verdict}"#,
                        set_name('b', '4', ifindex, &resolved),
                        unit_name('i', ifindex, name)
                    ),
                );
            }
            if !v6(prefixes).is_empty() {
                line(
                    &mut text,
                    &format!(
                        r#"        ip6 saddr @{} counter name "{}" {verdict}"#,
                        set_name('b', '6', ifindex, &resolved),
                        unit_name('i', ifindex, name)
                    ),
                );
            }
        }
        text.push_str("    }\n");
    }

    // Router-scale chain: descending prefix length = first match is the
    // longest covering prefix; both rules terminal (the op decides).
    if !router_scale.is_empty() {
        text.push_str("    chain rs {\n");
        for (idx, op) in router_scale.iter().enumerate() {
            match op {
                SavProgramOp::PrefixAllow {
                    prefix,
                    ifindexes,
                    action,
                } => {
                    // PBA: member arrivals are valid, everyone else invalid.
                    if !ifindexes.is_empty() {
                        emit_rs_rule(
                            &mut text,
                            prefix,
                            &member_match(ifindexes, &resolved),
                            'v',
                            idx,
                            "accept",
                        );
                    }
                    emit_rs_rule(&mut text, prefix, "", 'i', idx, verdict_of(*action));
                }
                SavProgramOp::PrefixBlock {
                    prefix,
                    ifindexes,
                    action,
                } => {
                    // PBB: member arrivals are invalid, everyone else valid.
                    if !ifindexes.is_empty() {
                        emit_rs_rule(
                            &mut text,
                            prefix,
                            &member_match(ifindexes, &resolved),
                            'i',
                            idx,
                            verdict_of(*action),
                        );
                    }
                    emit_rs_rule(&mut text, prefix, "", 'v', idx, "accept");
                }
                _ => unreachable!("router-scale only"),
            }
        }
        text.push_str("    }\n");
    }

    text.push_str("}\n");
    Ok(NftRuleset {
        text,
        interfaces,
        counters,
        ignored,
    })
}

/// The enforcement action of a placed op (interface- or router-scale).
fn action_of(op: &SavProgramOp) -> SavEnforce {
    match op {
        SavProgramOp::IfaceAllow { action, .. }
        | SavProgramOp::IfaceBlock { action, .. }
        | SavProgramOp::PrefixAllow { action, .. }
        | SavProgramOp::PrefixBlock { action, .. } => *action,
    }
}

/// Aggregate `nft list counters` output into the monitor counts: the
/// `v_*` counters sum into `valid`, `i_*` into `invalid` (the spoof
/// counter), `unknown` stays 0 (packets no rule judged never enter a
/// rouster chain). Parsing is lenient — a malformed block is skipped,
/// not fatal — mirroring the applied-state decoder's stance.
pub fn parse_counter_packets(text: &str, table: &str) -> BTreeMap<String, u64> {
    let mut packets = BTreeMap::new();
    let mut in_table = false;
    let mut current: Option<String> = None;
    for line in text.lines() {
        let line = line.trim();
        if let Some(name) = current.take() {
            // First line inside a counter block is "packets N bytes M".
            if let Some(rest) = line.strip_prefix("packets ") {
                if let Some(n) = rest
                    .split_whitespace()
                    .next()
                    .and_then(|n| n.parse::<u64>().ok())
                {
                    packets.insert(name, n);
                }
            }
            continue;
        }
        if let Some(rest) = line.strip_prefix("table ") {
            // "table inet <name> {"
            in_table = rest
                .split_whitespace()
                .nth(1)
                .is_some_and(|t| t.trim_end_matches('{') == table);
        } else if in_table && line.starts_with("counter ") && line.ends_with('{') {
            current = Some(
                line["counter ".len()..]
                    .trim_end_matches('{')
                    .trim()
                    .to_string(),
            );
        }
    }
    packets
}

/// The aggregate monitor counts of a per-counter packet map (see
/// [`parse_counter_packets`]): `v_` prefixed counters are valid, `i_`
/// invalid.
pub fn aggregate_counts(packets: &BTreeMap<String, u64>) -> SavMonitorCounts {
    let mut counts = SavMonitorCounts::default();
    for (name, &n) in packets {
        if name.starts_with("v_") {
            counts.valid += n;
        } else if name.starts_with("i_") {
            counts.invalid += n;
        }
    }
    counts
}

/// Join the ruleset's counter-units map ([`NftRuleset::counters`])
/// with a parsed `nft list counters` packet map into the per-op
/// monitor rows ([`crate::Dataplane::sav_monitor_per_op`]): each op
/// pairs with its two named counters' packets — the `v_` unit is its
/// valid bucket, the `i_` unit its invalid bucket; `unknown` stays 0
/// (packets no rule judged never enter a rouster chain, by
/// construction). Rows return in the program's canonical op order
/// (deterministic for consumers); a unit missing from the packet map
/// reads 0, never errors — a counter absent from the listing counted
/// nothing. The rows sum to [`aggregate_counts`] over the same packet
/// map: every unit the ruleset declares appears in exactly one row.
pub fn attribute_counts(
    counters: &[(SavProgramOp, String, String)],
    packets: &BTreeMap<String, u64>,
) -> Vec<(SavProgramOp, SavMonitorCounts)> {
    let mut rows: Vec<(SavProgramOp, SavMonitorCounts)> = counters
        .iter()
        .map(|(op, valid_unit, invalid_unit)| {
            (
                op.clone(),
                SavMonitorCounts {
                    valid: packets.get(valid_unit).copied().unwrap_or(0),
                    invalid: packets.get(invalid_unit).copied().unwrap_or(0),
                    unknown: 0,
                },
            )
        })
        .collect();
    rows.sort_by(|a, b| a.0.cmp(&b.0));
    rows
}

/// The terminal verdict an action maps to: drop enforces the deny,
/// monitor counts and accepts (never drops — the workspace rule).
fn verdict_of(action: SavEnforce) -> &'static str {
    match action {
        SavEnforce::Drop => "drop",
        SavEnforce::Monitor => "accept",
    }
}

/// One router-scale rule: `ip[6] saddr <prefix> <member-match> counter
/// name "<v|i>_rs<idx>" <verdict>` — terminal by construction.
fn emit_rs_rule(
    text: &mut String,
    prefix: &IpPrefix,
    member_match: &str,
    bucket: char,
    idx: usize,
    verdict: &str,
) {
    let fam = match prefix {
        IpPrefix::V4(_) => "ip",
        IpPrefix::V6(_) => "ip6",
    };
    line(
        text,
        &format!(
            r#"        {fam} saddr {prefix}{member_match} counter name "{bucket}_rs{idx}" {verdict}"#
        ),
    );
}

/// The `iifname` membership match of a router-scale op's interface set:
/// `iifname "a"` / `iifname { "a", "b" }`, names resolved from the
/// op's ifindexes. Empty sets emit nothing (the caller skips the rule).
fn member_match(ifindexes: &[u32], names: &BTreeMap<u32, String>) -> String {
    let names: Vec<&str> = ifindexes.iter().map(|ix| names[ix].as_str()).collect();
    match names.len() {
        0 => String::new(),
        1 => format!(r#" iifname "{}""#, names[0]),
        _ => {
            let quoted: Vec<String> = names.iter().map(|n| format!(r#""{n}""#)).collect();
            format!(" iifname {{ {} }}", quoted.join(", "))
        }
    }
}

fn emit_set(text: &mut String, name: &str, addr_type: &str, elements: Vec<String>) {
    if elements.is_empty() {
        return; // an empty half needs no set and matches nothing
    }
    text.push_str(&format!("    set {name} {{\n"));
    text.push_str(&format!("        type {addr_type}\n"));
    // auto-merge: an allowlist may hold a covering and a covered
    // prefix at once (the daemon's SIB merges the interface mirror's
    // connected prefixes with RIB-derived ones); a plain interval set
    // rejects overlapping elements ("conflicting intervals specified",
    // nftables v1.0.9). The resolution is the union — the list's own
    // semantics either way — and the declared elements stay the SIB's
    // list verbatim (nft itself stores the merged form).
    text.push_str("        flags interval\n");
    text.push_str("        auto-merge\n");
    text.push_str(&format!(
        "        elements = {{ {} }}\n",
        elements.join(", ")
    ));
    text.push_str("    }\n");
}

fn emit_counter(text: &mut String, name: &str) {
    text.push_str(&format!("    counter {name} {{\n"));
    text.push_str("        packets 0 bytes 0\n");
    text.push_str("    }\n");
}

fn set_name(kind: char, family: char, ifindex: u32, names: &BTreeMap<u32, String>) -> String {
    format!("{kind}{family}_{}_{}", sanitize(&names[&ifindex]), ifindex)
}

fn chain_name(ifindex: u32, name: &str) -> String {
    format!("if_{}_{}", sanitize(name), ifindex)
}

fn unit_name(bucket: char, ifindex: u32, name: &str) -> String {
    format!("{bucket}_{}_{}", sanitize(name), ifindex)
}

/// nft identifiers are `[A-Za-z_][A-Za-z0-9_]*`: interface names may
/// carry `-`/`.`/`:` (the kernel allows them), so every character
/// outside the identifier alphabet folds to `_`. The ifindex suffix
/// keeps units collision-free (`veth-a` vs `veth_a`).
fn sanitize(name: &str) -> String {
    name.chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '_' {
                c
            } else {
                '_'
            }
        })
        .collect()
}

/// The v4 half of a prefix list, sorted, deduplicated, rendered.
fn v4(prefixes: &[IpPrefix]) -> Vec<String> {
    render_half(prefixes, |p| matches!(p, IpPrefix::V4(_)))
}

/// The v6 half, same treatment.
fn v6(prefixes: &[IpPrefix]) -> Vec<String> {
    render_half(prefixes, |p| matches!(p, IpPrefix::V6(_)))
}

fn render_half(prefixes: &[IpPrefix], keep: impl Fn(&IpPrefix) -> bool) -> Vec<String> {
    let mut v: Vec<String> = prefixes
        .iter()
        .filter(|p| keep(p))
        .map(|p| p.to_string())
        .collect();
    v.sort();
    v.dedup();
    v
}

fn prefix_len(op: &SavProgramOp) -> u8 {
    match op {
        SavProgramOp::PrefixAllow { prefix, .. } | SavProgramOp::PrefixBlock { prefix, .. } => {
            match prefix {
                IpPrefix::V4(p) => p.prefix_len(),
                IpPrefix::V6(p) => p.prefix_len(),
            }
        }
        _ => u8::MAX,
    }
}

/// v4 ops sort before v6 (readability; semantically equivalent).
fn prefix_family_rank(op: &SavProgramOp) -> u8 {
    match op {
        SavProgramOp::PrefixAllow { prefix, .. } | SavProgramOp::PrefixBlock { prefix, .. } => {
            match prefix {
                IpPrefix::V4(_) => 0,
                IpPrefix::V6(_) => 1,
            }
        }
        _ => 2,
    }
}

fn line(text: &mut String, s: &str) {
    text.push_str(s);
    text.push('\n');
}

#[cfg(test)]
mod tests {
    use super::*;
    use common::{SavEnforce, SavProgramOp, SavUrpf};

    fn p(s: &str) -> IpPrefix {
        s.parse().unwrap()
    }

    fn names(pairs: &[(u32, &str)]) -> BTreeMap<u32, String> {
        pairs.iter().map(|&(ix, n)| (ix, n.to_string())).collect()
    }

    fn allow(ifindex: u32, prefixes: &[&str], action: SavEnforce) -> SavProgramOp {
        SavProgramOp::IfaceAllow {
            ifindex,
            prefixes: prefixes.iter().map(|s| p(s)).collect(),
            urpf: SavUrpf::Strict,
            action,
        }
    }

    fn chain_body<'a>(text: &'a str, name: &str) -> &'a str {
        text.split(&format!("chain {name} {{"))
            .nth(1)
            .unwrap_or_else(|| panic!("chain {name} missing"))
            .split("    }")
            .next()
            .unwrap()
    }

    /// The W7 topology in ruleset form: the egress interface's allow
    /// list and the wrong interface's empty deny-all — table, set,
    /// counters, dispatch, decisive chains, and drop-mode terminal.
    #[test]
    fn iba_drop_shape_is_table_set_counters_and_deny() {
        let program = SavProgram::from_ops([
            allow(4, &["198.51.100.0/24"], SavEnforce::Drop),
            allow(6, &[], SavEnforce::Drop),
        ]);
        let rs = ruleset(&program, &names(&[(4, "vethlegit"), (6, "vethspoof")])).unwrap();
        let text = rs.text;
        assert!(
            text.contains("table inet rouster_sav {"),
            "wholly-owned table"
        );
        assert!(
            text.contains("set a4_vethlegit_4 {"),
            "allowlist set, sanitized + ifindex"
        );
        assert!(text.contains("type ipv4_addr"));
        assert!(text.contains("flags interval"));
        assert!(text.contains("elements = { 198.51.100.0/24 }"));
        assert!(
            !text.contains("a4_vethspoof"),
            "empty allowlist gets no set"
        );
        assert!(text.contains("counter v_vethlegit_4 {"));
        assert!(text.contains("counter i_vethspoof_6 {"));
        assert!(text.contains("type filter hook prerouting priority raw; policy accept;"));
        assert!(text.contains(r#"iifname "vethlegit" jump if_vethlegit_4"#));
        assert!(text.contains(r#"ip saddr @a4_vethlegit_4 counter name "v_vethlegit_4" accept"#));
        // Deny-all: no set match line, the terminal decides.
        assert!(text.contains(r#"counter name "i_vethspoof_6" drop"#));
        assert!(
            text.contains(r#"counter name "i_vethlegit_4" drop"#),
            "terminal deny"
        );
        assert_eq!(
            rs.interfaces,
            vec![
                (4, "vethlegit".to_string(), SavEnforce::Drop),
                (6, "vethspoof".to_string(), SavEnforce::Drop)
            ]
        );
        assert!(rs.ignored.is_empty());
        assert!(
            !text.contains("jump rs"),
            "no router-scale ops, no rs chain"
        );
    }

    /// Monitor mode installs the same decisive chains but count-only:
    /// terminal is `accept`, never `drop` — the precision rp_filter
    /// lacks (it cannot count without dropping).
    #[test]
    fn monitor_mode_counts_and_never_drops() {
        let program = SavProgram::from_ops([allow(6, &["198.51.100.0/24"], SavEnforce::Monitor)]);
        let text = ruleset(&program, &names(&[(6, "vethspoof")])).unwrap().text;
        assert!(text.contains(r#"counter name "i_vethspoof_6" accept"#));
        assert!(!text.contains("drop"), "monitor never drops");
    }

    /// savd-on-nft (ADD-C1, failing first): the daemon's SIB merges
    /// the interface mirror's CONNECTED /24 with the redistribute
    /// push's RIB /25 into one IBA allowlist — a covering and a
    /// covered prefix in the same set. nftables rejects overlapping
    /// intervals in a plain interval set ("conflicting intervals
    /// specified", reproduced against nftables v1.0.9 — the first
    /// live savd `backend nft` start failed on exactly this), so
    /// every interval set declares `auto-merge`: the resolution is
    /// the union, which is the list's own semantics either way (a
    /// source in ANY listed prefix is allowed; blocklists the same
    /// for denying), and the declared elements stay the SIB's list
    /// verbatim (operator evidence; nft itself stores the merged
    /// form).
    #[test]
    fn overlapping_prefixes_in_one_allowlist_stay_loadable() {
        let program = SavProgram::from_ops([allow(
            4,
            &["198.51.100.0/24", "198.51.100.0/25", "fe80::/64"],
            SavEnforce::Monitor,
        )]);
        let rs = ruleset(&program, &names(&[(4, "vethlegit")])).unwrap();
        let set = rs
            .text
            .split("set a4_vethlegit_4 {")
            .nth(1)
            .expect("allowlist set present")
            .split("    }")
            .next()
            .unwrap();
        assert!(
            set.contains("flags interval") && set.contains("auto-merge"),
            "interval sets must auto-merge overlapping elements:\n{set}"
        );
        assert!(
            rs.text
                .contains("elements = { 198.51.100.0/24, 198.51.100.0/25 }"),
            "both prefixes stay declared (the SIB's list verbatim)"
        );
    }

    /// IBB: match rules are terminal denies, but the chain has NO
    /// terminal rule — a non-match falls through to the router-scale
    /// chain (reference step 3's provisional valid).
    #[test]
    fn ibb_match_denies_and_falls_through() {
        let program = SavProgram::from_ops([
            SavProgramOp::IfaceBlock {
                ifindex: 2,
                prefixes: vec![p("192.0.2.0/24")],
                action: SavEnforce::Drop,
            },
            SavProgramOp::PrefixAllow {
                prefix: p("203.0.113.0/24"),
                ifindexes: vec![5],
                action: SavEnforce::Drop,
            },
        ]);
        let text = ruleset(&program, &names(&[(2, "eth0"), (5, "eth5")]))
            .unwrap()
            .text;
        assert!(text.contains(r#"ip saddr @b4_eth0_2 counter name "i_eth0_2" drop"#));
        let body = chain_body(&text, "if_eth0_2");
        assert_eq!(
            body.trim().lines().count(),
            1,
            "one match rule, no terminal — falls through to rs:\n{body}"
        );
        assert!(text.contains("jump rs"), "rs reachable after fall-through");
    }

    /// Router-scale ops: longest covering prefix first; PBA splits
    /// member/non-member arrivals, PBB the inverse; both v4 and v6
    /// prefixes ride the same inet table (the sysctl surface cannot).
    #[test]
    fn router_scale_ops_descend_by_prefix_length() {
        let program = SavProgram::from_ops([
            SavProgramOp::PrefixAllow {
                prefix: p("203.0.113.0/24"),
                ifindexes: vec![2, 3],
                action: SavEnforce::Drop,
            },
            SavProgramOp::PrefixBlock {
                prefix: p("203.0.113.128/25"),
                ifindexes: vec![3],
                action: SavEnforce::Drop,
            },
            SavProgramOp::PrefixAllow {
                prefix: p("2001:db8::/48"),
                ifindexes: vec![2],
                action: SavEnforce::Monitor,
            },
        ]);
        let names = names(&[(2, "eth0"), (3, "eth1")]);
        let text = ruleset(&program, &names).unwrap().text;
        let body = chain_body(&text, "rs");
        let lines: Vec<&str> = body.trim().lines().collect();
        assert_eq!(lines.len(), 6, "two terminal rules per op:\n{body}");
        // /25 (longest) before /24; v6 after both.
        assert!(
            lines[0].contains("ip saddr 203.0.113.128/25"),
            "longest first"
        );
        assert!(
            lines[0].contains(r#"iifname "eth1""#) && lines[0].contains("i_rs0"),
            "{}",
            lines[0]
        );
        assert!(lines[1].contains("203.0.113.128/25") && lines[1].contains("v_rs0"));
        assert!(
            lines[2].contains("203.0.113.0/24")
                && lines[2].contains(r#"iifname { "eth0", "eth1" }"#),
            "member set match"
        );
        assert!(
            lines[3].contains("203.0.113.0/24")
                && lines[3].contains("i_rs1")
                && lines[3].contains("drop")
        );
        assert!(
            lines[4].contains("ip6 saddr 2001:db8::/48") && lines[4].contains(r#"iifname "eth0""#)
        );
        assert!(
            lines[5].contains("2001:db8::/48") && lines[5].contains("accept"),
            "monitor accepts"
        );
    }

    /// Mixed actions coexist per-op: an IBA interface can be monitor
    /// while a router-scale op drops (each op's action governs its own
    /// verdicts).
    #[test]
    fn mixed_actions_per_op() {
        let program = SavProgram::from_ops([
            allow(2, &["10.0.0.0/8"], SavEnforce::Monitor),
            SavProgramOp::PrefixAllow {
                prefix: p("192.0.2.0/24"),
                ifindexes: vec![5],
                action: SavEnforce::Drop,
            },
        ]);
        let text = ruleset(&program, &names(&[(2, "eth0"), (5, "eth5")]))
            .unwrap()
            .text;
        assert!(
            text.contains(r#"counter name "i_eth0_2" accept"#),
            "iba monitor terminal"
        );
        assert!(text.contains("i_rs0\" drop"), "pba drop for non-members");
    }

    /// Determinism: the same program and names regenerate a
    /// byte-identical file (the churn guard compares file bytes).
    #[test]
    fn ruleset_is_deterministic() {
        let program = SavProgram::from_ops([
            allow(4, &["198.51.100.0/24", "203.0.113.0/25"], SavEnforce::Drop),
            SavProgramOp::PrefixBlock {
                prefix: p("192.0.2.0/24"),
                ifindexes: vec![7, 4],
                action: SavEnforce::Monitor,
            },
        ]);
        let names = names(&[(4, "vethlegit"), (7, "veth-7")]);
        let a = ruleset(&program, &names).unwrap();
        let b = ruleset(&program, &names).unwrap();
        assert_eq!(a.text, b.text);
        assert_eq!(a, b);
    }

    /// Names with `-`/`.` fold to `_` and the ifindex suffix keeps
    /// `veth-a` and `veth_a` distinct (collision-free units).
    #[test]
    fn identifiers_sanitize_and_disambiguate() {
        let program = SavProgram::from_ops([
            allow(2, &["10.0.0.0/8"], SavEnforce::Drop),
            allow(3, &["10.0.1.0/24"], SavEnforce::Drop),
        ]);
        let text = ruleset(&program, &names(&[(2, "veth-a"), (3, "veth_a")]))
            .unwrap()
            .text;
        assert!(text.contains("set a4_veth_a_2 {") && text.contains("set a4_veth_a_3 {"));
        assert!(text.contains(r#"iifname "veth-a" jump if_veth_a_2"#));
        assert!(text.contains("set a4_veth_a_2 {") && text.contains("set a4_veth_a_3 {"));
    }

    /// Duplicate same-kind ops for one interface: the first (canonical
    /// order) is placed, later ones are unreachable and reported —
    /// reference-pipeline-faithful (`evaluate` consults the first),
    /// never a silent drop. An IBB under an IBA is equally unreachable.
    #[test]
    fn duplicate_and_shadowed_ops_report_the_unreachable_copy() {
        let program = SavProgram::from_ops([
            allow(2, &["10.0.0.0/8"], SavEnforce::Drop),
            allow(2, &["192.0.2.0/24"], SavEnforce::Monitor),
            SavProgramOp::IfaceBlock {
                ifindex: 2,
                prefixes: vec![p("203.0.113.0/24")],
                action: SavEnforce::Drop,
            },
        ]);
        let rs = ruleset(&program, &names(&[(2, "eth0")])).unwrap();
        assert_eq!(rs.ignored.len(), 2);
        assert!(rs.ignored[0].1.contains("decisive"), "{}", rs.ignored[0].1);
        assert!(
            rs.ignored[1].1.contains("short-circuits"),
            "{}",
            rs.ignored[1].1
        );
        assert!(rs.text.contains("10.0.0.0/8"));
        assert!(
            !rs.text.contains("192.0.2.0/24"),
            "unreachable copy not placed"
        );
        assert!(
            !rs.text.contains("203.0.113.0/24"),
            "shadowed blocklist not placed"
        );
    }

    /// A vanished interface is an error, never a silent skip — for
    /// interface-scale ops and router-scale membership alike.
    #[test]
    fn unknown_ifindex_is_an_error() {
        let iba = SavProgram::from_ops([allow(9, &["10.0.0.0/8"], SavEnforce::Drop)]);
        assert_eq!(
            ruleset(&iba, &names(&[])).unwrap_err(),
            RulesetError::UnknownIfindex(9)
        );
        let rs = SavProgram::from_ops([SavProgramOp::PrefixAllow {
            prefix: p("192.0.2.0/24"),
            ifindexes: vec![2, 9],
            action: SavEnforce::Drop,
        }]);
        assert_eq!(
            ruleset(&rs, &names(&[(2, "eth0")])).unwrap_err(),
            RulesetError::UnknownIfindex(9)
        );
    }

    /// An empty program generates no table (text empty): replace
    /// semantics reduce to removing whatever was applied.
    #[test]
    fn empty_program_generates_no_table() {
        let rs = ruleset(&SavProgram::new(), &names(&[])).unwrap();
        assert_eq!(rs.text, "");
        assert!(rs.interfaces.is_empty());
        assert!(rs.ignored.is_empty());
    }

    /// Counter parsing: only the named table's counters count, v_/i_
    /// buckets aggregate, foreign tables and table-less blocks are
    /// skipped leniently, unknown stays 0.
    #[test]
    fn counter_parsing_aggregates_our_table_only() {
        let text = "table inet rouster_sav {
\tcounter i_vethspoof_6 {
\t\tpackets 12 bytes 1008
\t}
\tcounter v_vethlegit_4 {
\t\tpackets 3 bytes 252
\t}
}
table inet other {
\tcounter i_evil {
\t\tpackets 99 bytes 99
\t}
}
counter loose {
    packets 7 bytes 7
}
garbage
";
        let packets = parse_counter_packets(text, NFT_TABLE);
        assert_eq!(packets.get("i_vethspoof_6"), Some(&12));
        assert_eq!(packets.get("v_vethlegit_4"), Some(&3));
        assert!(!packets.contains_key("i_evil"), "foreign table ignored");
        assert!(!packets.contains_key("loose"), "table-less block ignored");
        let counts = aggregate_counts(&packets);
        assert_eq!(counts.invalid, 12);
        assert_eq!(counts.valid, 3);
        assert_eq!(counts.unknown, 0, "nothing counts unknown by construction");
    }

    /// No table installed (fresh boot, post-clear): `nft list counters`
    /// answers nothing and the counts are honestly zero.
    #[test]
    fn absent_table_parses_to_zero_counts() {
        let packets = parse_counter_packets("", NFT_TABLE);
        assert!(packets.is_empty());
        assert_eq!(aggregate_counts(&packets), SavMonitorCounts::default());
        // The per-op join over the same emptiness: rows exist (the ops
        // are placed) but every bucket reads an honest 0.
        let rows = attribute_counts(
            &[(
                allow(4, &["10.0.0.0/8"], SavEnforce::Monitor),
                "v_x_4".into(),
                "i_x_4".into(),
            )],
            &packets,
        );
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].1, SavMonitorCounts::default());
    }

    /// The counters map (N6B) pairs every PLACED op with its two
    /// units, in emission order: interface ops by ifindex with their
    /// name-addressable units, router-scale ops in rule order (longest
    /// prefix first) with their positional rs units. Ignored
    /// (unreachable) ops appear not at all.
    #[test]
    fn counters_map_pairs_placed_ops_with_their_units() {
        let iba_op = allow(2, &["192.0.2.0/24"], SavEnforce::Drop);
        let pba = SavProgramOp::PrefixAllow {
            prefix: p("203.0.113.0/24"),
            ifindexes: vec![2, 3],
            action: SavEnforce::Drop,
        };
        let pbb = SavProgramOp::PrefixBlock {
            prefix: p("203.0.113.128/25"),
            ifindexes: vec![3],
            action: SavEnforce::Monitor,
        };
        let program = SavProgram::from_ops([
            iba_op.clone(),
            pbb.clone(),
            pba.clone(),
            // Unreachable: a second allow on ifindex 2 and a blocklist
            // under the decisive allowlist.
            allow(2, &["198.51.100.0/24"], SavEnforce::Monitor),
            SavProgramOp::IfaceBlock {
                ifindex: 2,
                prefixes: vec![p("10.0.0.0/8")],
                action: SavEnforce::Drop,
            },
        ]);
        let rs = ruleset(&program, &names(&[(2, "eth0"), (3, "eth1")])).unwrap();
        assert_eq!(rs.ignored.len(), 2, "the unreachable pair");
        let units_of = |op: &SavProgramOp| -> (String, String) {
            rs.counters
                .iter()
                .find(|(o, _, _)| o == op)
                .map(|(_, v, i)| (v.clone(), i.clone()))
                .unwrap_or_else(|| panic!("op {op} missing from the counters map"))
        };
        // Interface op: name-addressable units.
        assert_eq!(units_of(&iba_op), ("v_eth0_2".into(), "i_eth0_2".into()));
        // Router-scale: positional, in RULE order (the /25 PBB sorts
        // before the /24 PBA — longest covering prefix first).
        assert_eq!(units_of(&pbb), ("v_rs0".into(), "i_rs0".into()));
        assert_eq!(units_of(&pba), ("v_rs1".into(), "i_rs1".into()));
        assert_eq!(rs.counters.len(), 3, "only placed ops");
        // The declared units exist in the file (map and text agree).
        for (_, v, i) in &rs.counters {
            assert!(rs.text.contains(&format!("counter {v} {{")), "unit {v}");
            assert!(rs.text.contains(&format!("counter {i} {{")), "unit {i}");
        }
    }

    /// An IBB-only interface carries a DEAD valid unit (no terminal
    /// rule references it) — the map stays total so the row's valid
    /// bucket is an honest 0, and the invalid unit is the match rule's.
    #[test]
    fn ibb_op_carries_a_dead_valid_unit() {
        let program = SavProgram::from_ops([SavProgramOp::IfaceBlock {
            ifindex: 2,
            prefixes: vec![p("192.0.2.0/24")],
            action: SavEnforce::Drop,
        }]);
        let rs = ruleset(&program, &names(&[(2, "eth0")])).unwrap();
        assert_eq!(rs.counters.len(), 1);
        let (op, v, i) = &rs.counters[0];
        assert!(matches!(op, SavProgramOp::IfaceBlock { .. }));
        assert_eq!((v.as_str(), i.as_str()), ("v_eth0_2", "i_eth0_2"));
        // Only the invalid unit is referenced by a rule.
        assert!(rs.text.contains(&format!(r#"counter name "{i}""#)));
        assert!(!rs.text.contains(&format!(r#"counter name "{v}""#)));
    }

    /// The per-op join over real listing text: each op's row reads its
    /// own two counters, rows come back in canonical op order, and the
    /// rows sum EXACTLY to the aggregate over the same listing (every
    /// declared unit appears in exactly one row — the property that
    /// lets the daemon derive its aggregate line from the per-op read).
    #[test]
    fn attribute_counts_rows_read_their_own_counters_and_sum_to_the_aggregate() {
        let program = SavProgram::from_ops([
            allow(4, &["198.51.100.0/24"], SavEnforce::Monitor),
            allow(6, &[], SavEnforce::Monitor),
            SavProgramOp::PrefixBlock {
                prefix: p("203.0.113.0/24"),
                ifindexes: vec![6],
                action: SavEnforce::Monitor,
            },
        ]);
        let rs = ruleset(&program, &names(&[(4, "vethlegit"), (6, "vethspoof")])).unwrap();
        let listing = "table inet rouster_sav {
\tcounter i_vethspoof_6 {
\t\tpackets 12 bytes 1008
\t}
\tcounter v_vethlegit_4 {
\t\tpackets 3 bytes 252
\t}
\tcounter i_vethlegit_4 {
\t\tpackets 1 bytes 84
\t}
\tcounter v_rs0 {
\t\tpackets 2 bytes 168
\t}
\tcounter i_rs0 {
\t\tpackets 5 bytes 420
\t}
\tcounter v_vethspoof_6 {
\t\tpackets 0 bytes 0
\t}
}
";
        let packets = parse_counter_packets(listing, NFT_TABLE);
        let rows = attribute_counts(&rs.counters, &packets);
        assert_eq!(rows.len(), 3);
        // Canonical op order (SavProgram::from_ops order): the two
        // interface allows by ifindex, then the router-scale op.
        let shapes: Vec<String> = rows.iter().map(|(op, _)| op.to_string()).collect();
        assert_eq!(
            shapes,
            vec![
                "allow if#4 [198.51.100.0/24] strict monitor",
                "allow if#6 [] strict monitor",
                "block 203.0.113.0/24 if [6] monitor",
            ]
        );
        assert_eq!(
            rows[0].1,
            SavMonitorCounts {
                invalid: 1,
                valid: 3,
                unknown: 0
            },
            "vethlegit's own two units"
        );
        assert_eq!(
            rows[1].1,
            SavMonitorCounts {
                invalid: 12,
                valid: 0,
                unknown: 0
            },
            "the deny-all's invalid unit; its v_ unit counted 0"
        );
        assert_eq!(
            rows[2].1,
            SavMonitorCounts {
                invalid: 5,
                valid: 2,
                unknown: 0
            },
            "the PBB pair units, positional rs0"
        );
        // The sum property: rows sum to the aggregate over the same
        // listing, bucket for bucket.
        let sum = rows
            .iter()
            .fold(SavMonitorCounts::default(), |mut acc, (_, c)| {
                acc.invalid += c.invalid;
                acc.valid += c.valid;
                acc.unknown += c.unknown;
                acc
            });
        assert_eq!(sum, aggregate_counts(&packets));
    }

    /// v6 allowlists ride the same table: a v6 set under ip6 matching
    /// (mixed families split across their sets, both halves enforced).
    #[test]
    fn v6_allowlist_rides_the_inet_table() {
        let program = SavProgram::from_ops([allow(
            3,
            &["2001:db8::/48", "198.51.100.0/24"],
            SavEnforce::Drop,
        )]);
        let text = ruleset(&program, &names(&[(3, "eth0")])).unwrap().text;
        assert!(text.contains("set a6_eth0_3 {") && text.contains("type ipv6_addr"));
        assert!(text.contains(r#"ip6 saddr @a6_eth0_3 counter name "v_eth0_3" accept"#));
        assert!(text.contains(r#"ip saddr @a4_eth0_3 counter name "v_eth0_3" accept"#));
    }
}
