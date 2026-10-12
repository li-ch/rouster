//! The FRR route-map compatibility grammar: parser from frr.conf policy
//! stanzas into an AST, then compiler into the typed engine. [W1-a M4]
//!
//! This is the frr.conf-import *edge* (architecture invariant 1: FRR
//! compatibility lives in adapters, never core abstractions). The
//! grammar follows FRR 10.2 documented syntax:
//!
//! - `route-map NAME (permit|deny) ORDER` with match/set/call/exit
//!   clauses (FRR docs, "Route Maps"): "If a route-map entry does not explicitly
//!   specify any matching conditions, then it always matches"; permit +
//!   match applies Set Actions, then the Call Action, then the Exit
//!   Policy; deny + match
//!   finishes with deny; "The default action of a route-map, if no
//!   entries match, is to deny."
//! - Exit Policy: `on-match next`, `continue N`, `on-match goto N` —
//!   "goto N: Jump ahead to the first route-map entry whose order in the
//!   route-map is >= N. Jumping to a previous entry is not permitted."
//! - `ip|ipv6 prefix-list NAME [seq N] (permit|deny) PREFIX [le LEN]
//!   [ge LEN]` (FRR "Filtering — IP Prefix List": le/ge bounds; "If
//!   ge ... prefix length is greater than or equal"; no le/ge → exact).
//! - `access-list|ipv6 access-list NAME [seq N] (permit|deny)
//!   (PREFIX [exact-match]|any)` — zebra-style access-lists (FRR 10.2
//!   `lib/filter_cli.c`). Coverage default is the *inverse* of
//!   prefix-lists: subnet-of unless `exact-match`.
//! - `bgp as-path access-list WORD [seq N] permit|deny LINE` — LINE is
//!   a BGP regular expression.
//! - `bgp community-list standard NAME permit|deny COMMUNITY...` — an
//!   entry matches when the route carries all listed communities.
//!
//! Every keyword outside this grammar is a parse error carrying the
//! line number — never a silent drop.

use crate::asregex::AsRegex;
use crate::filter::{Action, CommMode, Filter, FilterBuilder, SetIndex, Term};
use crate::route::{BgpOrigin, Community};
use crate::sets::{
    AccessList, AccessListEntry, AsPathAccessList, AsPathListEntry, CommunityAccessList,
    CommunityListEntry, CommunitySet, PrefixList, PrefixListEntry, PrefixListVerdict,
    PrefixPattern,
};
use common::{IpPrefix, RouteProtocol};
use std::collections::BTreeMap;

/// Parse error with the offending line (1-based).
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub struct PolicyConfigError {
    pub line: u32,
    pub message: String,
}

impl std::fmt::Display for PolicyConfigError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "line {}: {}", self.line, self.message)
    }
}

fn err<T>(line: u32, message: impl Into<String>) -> Result<T, PolicyConfigError> {
    Err(PolicyConfigError {
        line,
        message: message.into(),
    })
}

/// FRR route-map entry match policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RmPolicy {
    Permit,
    Deny,
}

/// One match clause of a route-map entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RmMatch {
    /// `match ip|ipv6 address prefix-list NAME[,NAME...]`
    PrefixList { v6: bool, names: Vec<String> },
    /// `match ip|ipv6 address ACCESS_LIST` (zebra-style access-list)
    AccessList { v6: bool, name: String },
    /// `match as-path NAME`
    AsPath(String),
    /// `match community NAME[,NAME...] [exact-match]`
    Community { names: Vec<String>, exact: bool },
    /// `match local-preference VALUE`
    LocalPref(u32),
    /// `match metric VALUE`
    Metric(u32),
    /// `match source-protocol PROTO...`
    SourceProtocol(Vec<RouteProtocol>),
}

impl RmMatch {
    /// Same match kind (FRR: a repeated match of the same type replaces).
    fn kind(&self) -> &'static str {
        match self {
            RmMatch::PrefixList { .. } => "prefix-list",
            RmMatch::AccessList { .. } => "access-list",
            RmMatch::AsPath(_) => "as-path",
            RmMatch::Community { .. } => "community",
            RmMatch::LocalPref(_) => "local-preference",
            RmMatch::Metric(_) => "metric",
            RmMatch::SourceProtocol(_) => "source-protocol",
        }
    }
}

/// Numeric argument of a set clause: FRR `set local-preference 200` is
/// absolute; `+200` / `-200` are relative to the current value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RmNum {
    Absolute(u32),
    Relative(i64),
}

impl RmNum {
    /// Resolve against a base value with u32 saturation.
    pub fn resolve(self, base: u32) -> u32 {
        match self {
            RmNum::Absolute(v) => v,
            RmNum::Relative(d) => (base as i64 + d).clamp(0, u32::MAX as i64) as u32,
        }
    }
}

/// One set clause of a route-map entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RmSet {
    /// `set local-preference [+-]VALUE`
    LocalPref(RmNum),
    /// `set community COMM... [additive]` / `set community none`
    Community {
        list: Vec<Community>,
        mode: CommMode,
    },
    /// `set comm-list NAME delete` (FRR 10.2 CLI order — name first,
    /// `delete` last: `set comm-list <(1-99)|(100-500)|NAME> delete`,
    /// bgpd/bgp_routemap.c)
    CommunityDelete(String),
    /// `set origin egp|igp|incomplete`
    Origin(BgpOrigin),
    /// `set metric [+-]VALUE`
    Metric(RmNum),
    /// `set as-path prepend ASN...` (one token per prepend, reversed at
    /// compile time)
    AsPathPrepend { asns: Vec<u32> },
}

impl RmSet {
    fn kind(&self) -> &'static str {
        match self {
            RmSet::LocalPref(_) => "local-preference",
            RmSet::Community { .. } => "community",
            RmSet::CommunityDelete(_) => "comm-list",
            RmSet::Origin(_) => "origin",
            RmSet::Metric(_) => "metric",
            RmSet::AsPathPrepend { .. } => "as-path",
        }
    }
}

/// Exit policy of an entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RmExit {
    /// Finish and use the entry's policy (permit).
    None,
    /// `on-match next` / `continue` (no argument).
    Next,
    /// `continue N` / `on-match goto N`.
    Goto(u32),
}

/// One route-map entry (one `route-map NAME permit|deny SEQ` stanza).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RmEntry {
    pub seq: u32,
    pub line: u32,
    pub policy: RmPolicy,
    pub matches: Vec<RmMatch>,
    pub sets: Vec<RmSet>,
    /// `call NAME` — invoked after Set Actions (FRR "Route Maps": a
    /// deny return finishes and denies; a permit return proceeds to
    /// the exit policy). The u32 is the 1-based line of the `call`
    /// clause itself, so compile errors point at the call site
    /// (POL-1, owner-adjudicated).
    pub call: Option<(String, u32)>,
    pub exit: RmExit,
}

/// A parsed route-map: entries kept sorted by seq.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RouteMap {
    pub entries: Vec<RmEntry>,
}

impl RouteMap {
    /// Seq-sorted insert; same seq replaces the older entry (the FRR
    /// list convention — "the new list will overwrite the old list").
    fn insert(&mut self, e: RmEntry) {
        match self.entries.binary_search_by_key(&e.seq, |x| x.seq) {
            Ok(i) => self.entries[i] = e,
            Err(i) => self.entries.insert(i, e),
        }
    }
}

/// A whole parsed policy config: the supporting lists plus route-maps.
#[derive(Debug, Clone, Default)]
pub struct PolicyDocument {
    pub prefix_lists: BTreeMap<String, PrefixList>,
    pub access_lists: BTreeMap<String, AccessList>,
    pub as_path_lists: BTreeMap<String, AsPathAccessList>,
    pub community_lists: BTreeMap<String, CommunityAccessList>,
    pub route_maps: BTreeMap<String, RouteMap>,
    /// Non-fatal notes (ignored `description` lines etc.) — surfaced,
    /// never silently dropped.
    pub warnings: Vec<String>,
}

/// What `compile_route_map` produces.
#[derive(Debug, Clone)]
pub struct CompileOutput {
    pub filter: Filter,
    /// Non-fatal notes (unreachable clauses etc.).
    pub warnings: Vec<String>,
}

// ---------------------------------------------------------------------------
// Parser
// ---------------------------------------------------------------------------

/// Parse a policy config (route-map stanzas + supporting lists).
///
/// Anything outside the grammar — including B7-observed foreign stanzas
/// like `frr version`, `router bgp`, `ip route`, `line vty` — is an
/// error with its line number; the future frr.conf importer is expected
/// to section the file first (contract documented in
/// docs/protocols/policy.md).
pub fn parse_policy_config(text: &str) -> Result<PolicyDocument, PolicyConfigError> {
    let mut doc = PolicyDocument::default();
    // (route-map name, entry being accumulated)
    let mut open: Option<(String, RmEntry)> = None;

    for (idx, raw) in text.lines().enumerate() {
        let line_no = idx as u32 + 1;
        let line = raw.trim();
        if line.is_empty() || line == "!" {
            continue;
        }
        let toks: Vec<&str> = line.split_whitespace().collect();

        match toks[0] {
            "route-map" => parse_route_map_header(&toks, line_no, &mut open, &mut doc)?,
            "match" => parse_match(&toks, line_no, &mut open)?,
            "set" => parse_set(&toks, line_no, &mut open)?,
            "call" => parse_call(&toks, line_no, &mut open)?,
            "continue" | "on-match" => parse_exit(&toks, line_no, &mut open)?,
            "description" => {
                let Some((_, entry)) = open.as_mut() else {
                    return err(line_no, "`description` outside a route-map entry");
                };
                doc.warnings.push(format!(
                    "line {line_no}: route-map seq {} description ignored",
                    entry.seq
                ));
            }
            "access-list" => {
                close_entry(&mut open, &mut doc);
                parse_access_list(&toks, line_no, &mut doc)?;
            }
            "ip" | "ipv6" if toks.get(1) == Some(&"prefix-list") => {
                close_entry(&mut open, &mut doc);
                parse_prefix_list(&toks, line_no, &mut doc)?;
            }
            "ipv6" if toks.get(1) == Some(&"access-list") => {
                close_entry(&mut open, &mut doc);
                parse_access_list(&toks, line_no, &mut doc)?;
            }
            "ip" if toks.get(1) == Some(&"access-list") => {
                return err(
                    line_no,
                    "`ip access-list` (cisco-style/named ACL submode) is not supported at import (see docs/protocols/policy.md §Deferred)",
                );
            }
            "bgp" if toks.get(1) == Some(&"as-path") && toks.get(2) == Some(&"access-list") => {
                close_entry(&mut open, &mut doc);
                parse_as_path_list(&toks, line_no, &mut doc)?;
            }
            "bgp"
                if matches!(
                    toks.get(1),
                    Some(&"community-list")
                        | Some(&"extcommunity-list")
                        | Some(&"large-community-list")
                ) =>
            {
                close_entry(&mut open, &mut doc);
                parse_community_list(&toks, line_no, &mut doc)?;
            }
            other => {
                return err(
                    line_no,
                    format!("unknown directive `{other}` (policy grammar: route-map, access-list, ip/ipv6 prefix-list, bgp as-path access-list, bgp community-list)"),
                );
            }
        }
    }
    close_entry(&mut open, &mut doc);
    Ok(doc)
}

fn close_entry(open: &mut Option<(String, RmEntry)>, doc: &mut PolicyDocument) {
    if let Some((name, entry)) = open.take() {
        doc.route_maps.entry(name).or_default().insert(entry);
    }
}

fn parse_u32(line: u32, s: &str, what: &str) -> Result<u32, PolicyConfigError> {
    s.parse::<u32>().map_err(|_| PolicyConfigError {
        line,
        message: format!("invalid {what} `{s}`"),
    })
}

/// Parse a numeric set-clause argument: plain digits → absolute,
/// `+N`/`-N` → relative (FRR `set local-preference +N` docs).
fn parse_rm_num(line: u32, s: &str, what: &str) -> Result<RmNum, PolicyConfigError> {
    if let Some(d) = s.strip_prefix('+') {
        let v = d.parse::<i64>().map_err(|_| PolicyConfigError {
            line,
            message: format!("invalid {what} `{s}`"),
        })?;
        return Ok(RmNum::Relative(v));
    }
    if let Some(d) = s.strip_prefix('-') {
        let v = d.parse::<i64>().map_err(|_| PolicyConfigError {
            line,
            message: format!("invalid {what} `{s}`"),
        })?;
        return Ok(RmNum::Relative(-v));
    }
    let v = s.parse::<u32>().map_err(|_| PolicyConfigError {
        line,
        message: format!("invalid {what} `{s}`"),
    })?;
    Ok(RmNum::Absolute(v))
}

fn parse_route_map_header(
    toks: &[&str],
    line: u32,
    open: &mut Option<(String, RmEntry)>,
    doc: &mut PolicyDocument,
) -> Result<(), PolicyConfigError> {
    close_entry(open, doc);
    if toks.len() < 4 {
        return err(
            line,
            "route-map: expected `route-map NAME (permit|deny) SEQ`",
        );
    }
    let name = toks[1].to_string();
    let policy = match toks[2] {
        "permit" => RmPolicy::Permit,
        "deny" => RmPolicy::Deny,
        other => {
            return err(
                line,
                format!("route-map: expected permit|deny, got `{other}`"),
            )
        }
    };
    let seq = parse_u32(line, toks[3], "sequence")?;
    *open = Some((
        name,
        RmEntry {
            seq,
            line,
            policy,
            matches: Vec::new(),
            sets: Vec::new(),
            call: None,
            exit: RmExit::None,
        },
    ));
    Ok(())
}

fn parse_match(
    toks: &[&str],
    line: u32,
    open: &mut Option<(String, RmEntry)>,
) -> Result<(), PolicyConfigError> {
    let Some((_, entry)) = open.as_mut() else {
        return err(line, "`match` outside a route-map entry");
    };
    let m = match toks.get(1).copied() {
        Some("ip") | Some("ipv6") => {
            let v6 = toks[1] == "ipv6";
            if toks.get(2) != Some(&"address") {
                return err(
                    line,
                    format!(
                        "unsupported match `{}` (expected `address`)",
                        join_tail(toks, 1)
                    ),
                );
            }
            match toks.get(3).copied() {
                Some("prefix-list") => {
                    if toks.len() < 5 {
                        return err(line, "match ip address prefix-list: missing name");
                    }
                    let names = parse_name_list(toks[4]);
                    RmMatch::PrefixList { v6, names }
                }
                Some("prefix-len") => {
                    return err(
                        line,
                        "match ip address prefix-len: unsupported at import (see docs/protocols/policy.md §Deferred)",
                    );
                }
                Some(name) => {
                    // FRR "Route Maps": `match ip address ACCESS_LIST`
                    // references a zebra-style access-list.
                    RmMatch::AccessList {
                        v6,
                        name: name.to_string(),
                    }
                }
                None => {
                    return err(line, "match ip address: missing name");
                }
            }
        }
        Some("as-path") => {
            if toks.len() < 3 {
                return err(line, "match as-path: missing name");
            }
            RmMatch::AsPath(toks[2].to_string())
        }
        Some("community") => {
            if toks.len() < 3 {
                return err(line, "match community: missing name");
            }
            let exact = toks.last() == Some(&"exact-match");
            let mut names_toks = &toks[2..];
            if exact || toks.last() == Some(&"any") {
                names_toks = &names_toks[..names_toks.len() - 1];
            }
            if names_toks.is_empty() {
                return err(line, "match community: missing name");
            }
            RmMatch::Community {
                names: parse_name_list(&names_toks.join(" ")),
                exact,
            }
        }
        Some("local-preference") => {
            if toks.len() < 3 {
                return err(line, "match local-preference: missing value");
            }
            RmMatch::LocalPref(parse_u32(line, toks[2], "local-preference")?)
        }
        Some("metric") => {
            if toks.len() < 3 {
                return err(line, "match metric: missing value");
            }
            RmMatch::Metric(parse_u32(line, toks[2], "metric")?)
        }
        Some("source-protocol") => {
            if toks.len() < 3 {
                return err(line, "match source-protocol: missing protocol");
            }
            let mut protos = Vec::new();
            for t in &toks[2..] {
                let p = parse_protocol(t).ok_or_else(|| PolicyConfigError {
                    line,
                    message: format!("unknown source-protocol `{t}`"),
                })?;
                protos.push(p);
            }
            RmMatch::SourceProtocol(protos)
        }
        _ => {
            return err(line, format!("unsupported match `{}`", join_tail(toks, 1)));
        }
    };
    // FRR: a repeated match of the same type replaces the earlier one.
    if let Some(pos) = entry.matches.iter().position(|x| x.kind() == m.kind()) {
        entry.matches[pos] = m;
    } else {
        entry.matches.push(m);
    }
    Ok(())
}

fn parse_set(
    toks: &[&str],
    line: u32,
    open: &mut Option<(String, RmEntry)>,
) -> Result<(), PolicyConfigError> {
    let Some((_, entry)) = open.as_mut() else {
        return err(line, "`set` outside a route-map entry");
    };
    let s = match toks.get(1).copied() {
        Some("local-preference") => {
            if toks.len() < 3 {
                return err(line, "set local-preference: missing value");
            }
            RmSet::LocalPref(parse_rm_num(line, toks[2], "local-preference")?)
        }
        Some("community") => {
            if toks.len() < 3 {
                return err(line, "set community: missing value(s)");
            }
            let mut list = Vec::new();
            let mut mode = CommMode::Replace;
            for t in &toks[2..] {
                if *t == "additive" {
                    mode = CommMode::Add;
                    continue;
                }
                if *t == "none" {
                    list.clear();
                    continue;
                }
                let c = Community::parse(t).ok_or_else(|| PolicyConfigError {
                    line,
                    message: format!("invalid community `{t}`"),
                })?;
                list.push(c);
            }
            RmSet::Community { list, mode }
        }
        Some("comm-list") => {
            // FRR 10.2 CLI order (bgpd/bgp_routemap.c
            // set_community_delete_cmd): "set comm-list
            // <(1-99)|(100-500)|COMMUNITY_LIST_NAME> delete" — the
            // list name comes first, `delete` last.
            if toks.len() != 4 || toks[3] != "delete" {
                return err(
                    line,
                    format!(
                        "unsupported set `{}` (expected `comm-list NAME delete`)",
                        join_tail(toks, 1)
                    ),
                );
            }
            RmSet::CommunityDelete(toks[2].to_string())
        }
        Some("origin") => {
            if toks.len() < 3 {
                return err(line, "set origin: missing value");
            }
            let o = toks[2]
                .parse::<BgpOrigin>()
                .map_err(|_| PolicyConfigError {
                    line,
                    message: format!("invalid origin `{}` (egp|igp|incomplete)", toks[2]),
                })?;
            RmSet::Origin(o)
        }
        Some("metric") => {
            if toks.len() < 3 {
                return err(line, "set metric: missing value");
            }
            match toks[2] {
                "rtt" | "+rtt" | "-rtt" | "igp" | "aigp" => {
                    return err(
                        line,
                        format!(
                            "set metric `{}` requires live protocol state — unsupported at import",
                            toks[2]
                        ),
                    );
                }
                _ => RmSet::Metric(parse_rm_num(line, toks[2], "metric")?),
            }
        }
        Some("as-path") => match toks.get(2).copied() {
            Some("prepend") => {
                if toks.len() < 4 {
                    return err(line, "set as-path prepend: missing ASN(s)");
                }
                if toks[3] == "last-as" {
                    return err(line, "set as-path prepend last-as: unsupported at import");
                }
                let mut asns = Vec::new();
                for t in &toks[3..] {
                    asns.push(parse_u32(line, t, "AS number")?);
                }
                RmSet::AsPathPrepend { asns }
            }
            Some("exclude") => {
                return err(line, "set as-path exclude: unsupported at import (see docs/protocols/policy.md §Deferred)");
            }
            _ => {
                return err(line, format!("unsupported set `{}`", join_tail(toks, 1)));
            }
        },
        _ => {
            return err(line, format!("unsupported set `{}`", join_tail(toks, 1)));
        }
    };
    if let Some(pos) = entry.sets.iter().position(|x| x.kind() == s.kind()) {
        entry.sets[pos] = s;
    } else {
        entry.sets.push(s);
    }
    Ok(())
}

fn parse_exit(
    toks: &[&str],
    line: u32,
    open: &mut Option<(String, RmEntry)>,
) -> Result<(), PolicyConfigError> {
    let Some((_, entry)) = open.as_mut() else {
        return err(line, "exit-policy clause outside a route-map entry");
    };
    let exit = if toks[0] == "continue" {
        match toks.get(1).copied() {
            None => RmExit::Next,
            Some(n) => RmExit::Goto(parse_u32(line, n, "continue sequence")?),
        }
    } else {
        // on-match next | on-match goto N
        match toks.get(1).copied() {
            Some("next") if toks.len() == 2 => RmExit::Next,
            Some("goto") if toks.len() == 3 => {
                RmExit::Goto(parse_u32(line, toks[2], "goto sequence")?)
            }
            _ => {
                return err(
                    line,
                    format!("unsupported exit policy `{}` (expected `on-match next` or `on-match goto N`)", join_tail(toks, 0)),
                );
            }
        }
    };
    entry.exit = exit;
    Ok(())
}

/// `call NAME` — the Call Action of a route-map entry (FRR "Route
/// Maps": invoked after Set Actions; "If it returns deny ... the route
/// is denied, regardless of the Matching Policy or the Exit Policy").
fn parse_call(
    toks: &[&str],
    line: u32,
    open: &mut Option<(String, RmEntry)>,
) -> Result<(), PolicyConfigError> {
    let Some((_, entry)) = open.as_mut() else {
        return err(line, "`call` outside a route-map entry");
    };
    if toks.len() != 2 {
        return err(
            line,
            format!("call: expected `call NAME`, got `{}`", join_tail(toks, 0)),
        );
    }
    entry.call = Some((toks[1].to_string(), line));
    Ok(())
}

fn parse_prefix_list(
    toks: &[&str],
    line: u32,
    doc: &mut PolicyDocument,
) -> Result<(), PolicyConfigError> {
    // ip|ipv6 prefix-list NAME [seq N] [description D] (permit|deny) PREFIX [le E] [ge E]
    let mut i = 2usize; // skip "ip prefix-list"
    let Some(&name) = toks.get(i) else {
        return err(line, "prefix-list: missing name");
    };
    i += 1;
    let mut seq = None;
    if toks.get(i) == Some(&"seq") {
        let Some(n) = toks.get(i + 1) else {
            return err(line, "prefix-list seq: missing number");
        };
        seq = Some(parse_u32(line, n, "sequence")?);
        i += 2;
    }
    if toks.get(i) == Some(&"description") {
        return err(line, "prefix-list description: not supported at import (see docs/protocols/policy.md §Deferred)");
    }
    let verdict = match toks.get(i).copied() {
        Some("permit") => PrefixListVerdict::Permit,
        Some("deny") => PrefixListVerdict::Deny,
        _ => {
            return err(
                line,
                format!(
                    "prefix-list: expected permit|deny, got `{}`",
                    join_tail(toks, i)
                ),
            )
        }
    };
    i += 1;
    let Some(&prefix_s) = toks.get(i) else {
        return err(line, "prefix-list: missing prefix");
    };
    let prefix: IpPrefix = prefix_s.parse().map_err(|e| PolicyConfigError {
        line,
        message: format!("prefix-list: invalid prefix `{prefix_s}`: {e}"),
    })?;
    i += 1;
    let is_v6 = matches!(prefix, IpPrefix::V6(_));
    let want_v6 = toks[0] == "ipv6";
    if is_v6 != want_v6 {
        return err(
            line,
            format!(
                "prefix-list: {} list given {} prefix `{prefix_s}`",
                if want_v6 { "an IPv6" } else { "an IPv4" },
                if is_v6 { "an IPv6" } else { "an IPv4" },
            ),
        );
    }
    let plen = crate::route::plen(&prefix);
    let family_max = if is_v6 { 128 } else { 32 };
    // le/ge; "The order of the le and ge commands does not matter."
    let mut ge: Option<u8> = None;
    let mut le: Option<u8> = None;
    while let Some(&kw) = toks.get(i) {
        match kw {
            "ge" => {
                let Some(v) = toks.get(i + 1) else {
                    return err(line, "prefix-list ge: missing length");
                };
                ge = Some(parse_len(line, v, family_max)?);
                i += 2;
            }
            "le" => {
                let Some(v) = toks.get(i + 1) else {
                    return err(line, "prefix-list le: missing length");
                };
                le = Some(parse_len(line, v, family_max)?);
                i += 2;
            }
            _ => return err(line, format!("prefix-list: unexpected token `{kw}`")),
        }
    }
    // No le/ge → exact length. ge only → le = family max. le only →
    // ge = entry prefix length (Cisco/FRR convention).
    let (min_len, max_len) = match (ge, le) {
        (None, None) => (plen, plen),
        (Some(g), None) => (g, family_max),
        (None, Some(l)) => (plen, l),
        (Some(g), Some(l)) => (g, l),
    };
    if min_len > max_len {
        return err(
            line,
            format!("prefix-list: ge {min_len} greater than le {max_len}"),
        );
    }
    // FRR CLI validation: le/ge values must not be shorter than the
    // entry's own prefix length.
    if let Some(g) = ge {
        if g < plen {
            return err(
                line,
                format!("prefix-list: ge {g} is less than the prefix length {plen}"),
            );
        }
    }
    if let Some(l) = le {
        if l < plen {
            return err(
                line,
                format!("prefix-list: le {l} is less than the prefix length {plen}"),
            );
        }
    }
    let pattern = PrefixPattern::range(prefix, min_len, max_len)
        .map_err(|e| PolicyConfigError { line, message: e })?;
    let list = doc.prefix_lists.entry(name.to_string()).or_default();
    // FRR auto-numbering: a seq-less entry "will automatically pick the
    // next multiple of five" after the current last entry.
    let auto_seq = list.entries().last().map_or(5, |e| e.seq / 5 * 5 + 5);
    list.insert(PrefixListEntry {
        seq: seq.unwrap_or(auto_seq),
        verdict,
        pattern,
    });
    Ok(())
}

fn parse_len(line: u32, s: &str, max: u8) -> Result<u8, PolicyConfigError> {
    let v = s.parse::<u8>().map_err(|_| PolicyConfigError {
        line,
        message: format!("invalid prefix length `{s}`"),
    })?;
    if v > max {
        return err(
            line,
            format!("prefix length {v} exceeds family maximum {max}"),
        );
    }
    Ok(v)
}

/// Zebra-style access-list stanza (FRR 10.2 `lib/filter_cli.c`):
/// `access-list NAME [seq N] (permit|deny) (PREFIX [exact-match]|any)`
/// and the `ipv6 access-list` twin. Cisco-style entry forms
/// (`host A.B.C.D`, `A.B.C.D M.M.M.M`, destination parts) are refused —
/// see docs/protocols/policy.md §Deferred.
fn parse_access_list(
    toks: &[&str],
    line: u32,
    doc: &mut PolicyDocument,
) -> Result<(), PolicyConfigError> {
    let want_v6 = toks[0] == "ipv6";
    let mut i = if want_v6 { 2 } else { 1 };
    let Some(&name) = toks.get(i) else {
        return err(line, "access-list: missing name");
    };
    i += 1;
    let mut seq = None;
    if toks.get(i) == Some(&"seq") {
        let Some(n) = toks.get(i + 1) else {
            return err(line, "access-list seq: missing number");
        };
        seq = Some(parse_u32(line, n, "sequence")?);
        i += 2;
    }
    let verdict = match toks.get(i).copied() {
        Some("permit") => PrefixListVerdict::Permit,
        Some("deny") => PrefixListVerdict::Deny,
        _ => {
            return err(
                line,
                format!(
                    "access-list: expected permit|deny, got `{}`",
                    join_tail(toks, i)
                ),
            )
        }
    };
    i += 1;
    let Some(&value_s) = toks.get(i) else {
        return err(line, "access-list: missing prefix");
    };
    i += 1;
    let exact = toks.get(i) == Some(&"exact-match");
    if exact {
        i += 1;
    }
    if let Some(&t) = toks.get(i) {
        return err(line, format!("access-list: unexpected token `{t}`"));
    }

    let pattern = if value_s == "any" {
        if exact {
            // FRR CLI grammar: `exact-match` pairs with the PREFIX
            // alternative only (`A.B.C.D/M [exact-match]|any`).
            return err(line, "access-list: `any` takes no `exact-match`");
        }
        let any: IpPrefix = if want_v6 {
            "::/0".parse().expect("valid literal prefix")
        } else {
            "0.0.0.0/0".parse().expect("valid literal prefix")
        };
        PrefixPattern::or_longer(any)
    } else {
        let prefix: IpPrefix = value_s.parse().map_err(|e| PolicyConfigError {
            line,
            message: format!("access-list: invalid prefix `{value_s}`: {e}"),
        })?;
        let is_v6 = matches!(prefix, IpPrefix::V6(_));
        if is_v6 != want_v6 {
            return err(
                line,
                format!(
                    "access-list: {} list given {} prefix `{value_s}`",
                    if want_v6 { "an IPv6" } else { "an IPv4" },
                    if is_v6 { "an IPv6" } else { "an IPv4" },
                ),
            );
        }
        // FRR lib/filter.c filter_match_zebra: subnet-of by default
        // (prefix_match), equal prefix lengths additionally only with
        // `exact-match` — the inverse default of prefix-lists.
        if exact {
            PrefixPattern::exact(prefix)
        } else {
            PrefixPattern::or_longer(prefix)
        }
    };

    let list = doc.access_lists.entry(name.to_string()).or_default();
    // FRR auto-numbering (lib/filter_cli.c acl_get_seq): max existing
    // sequence + 5 (not the prefix-list "next multiple of five").
    let auto_seq = list.entries().last().map_or(5, |e| e.seq + 5);
    list.insert(AccessListEntry {
        seq: seq.unwrap_or(auto_seq),
        verdict,
        pattern,
    });
    Ok(())
}

fn parse_as_path_list(
    toks: &[&str],
    line: u32,
    doc: &mut PolicyDocument,
) -> Result<(), PolicyConfigError> {
    // bgp as-path access-list NAME [seq N] permit|deny REGEX(rest of line)
    let Some(&name) = toks.get(3) else {
        return err(line, "as-path access-list: missing name");
    };
    let mut i = 4usize;
    let mut seq = None;
    if toks.get(i) == Some(&"seq") {
        let Some(n) = toks.get(i + 1) else {
            return err(line, "as-path access-list seq: missing number");
        };
        seq = Some(parse_u32(line, n, "sequence")?);
        i += 2;
    }
    let permit = match toks.get(i).copied() {
        Some("permit") => true,
        Some("deny") => false,
        _ => {
            return err(
                line,
                format!(
                    "as-path access-list: expected permit|deny, got `{}`",
                    join_tail(toks, i)
                ),
            )
        }
    };
    i += 1;
    if i >= toks.len() {
        return err(line, "as-path access-list: missing regular expression");
    }
    let regex_s = toks[i..].join(" ");
    let regex = AsRegex::new(&regex_s).map_err(|e| PolicyConfigError {
        line,
        message: format!("as-path access-list: invalid regex `{regex_s}`: {e}"),
    })?;
    let list = doc.as_path_lists.entry(name.to_string()).or_default();
    let auto_seq = list.entries().last().map_or(5, |e| e.seq / 5 * 5 + 5);
    list.insert(AsPathListEntry {
        seq: seq.unwrap_or(auto_seq),
        permit,
        regex,
    });
    Ok(())
}

fn parse_community_list(
    toks: &[&str],
    line: u32,
    doc: &mut PolicyDocument,
) -> Result<(), PolicyConfigError> {
    match toks.get(1).copied() {
        Some("community-list") => {
            match toks.get(2).copied() {
                Some("standard") => {
                    let Some(&name) = toks.get(3) else {
                        return err(line, "community-list: missing name");
                    };
                    let mut i = 4usize;
                    let mut seq = None;
                    if toks.get(i) == Some(&"seq") {
                        let Some(n) = toks.get(i + 1) else {
                            return err(line, "community-list seq: missing number");
                        };
                        seq = Some(parse_u32(line, n, "sequence")?);
                        i += 2;
                    }
                    let permit = match toks.get(i).copied() {
                        Some("permit") => true,
                        Some("deny") => false,
                        _ => return err(line, format!("community-list: expected permit|deny, got `{}`", join_tail(toks, i))),
                    };
                    i += 1;
                    let mut comms = Vec::new();
                    for t in &toks[i..] {
                        let c = Community::parse(t).ok_or_else(|| PolicyConfigError {
                            line,
                            message: format!("community-list: invalid community `{t}`"),
                        })?;
                        comms.push(c);
                    }
                    let list = doc.community_lists.entry(name.to_string()).or_default();
                    let auto_seq = list.entries().last().map_or(1, |e| e.seq + 1);
                    list.insert(CommunityListEntry {
                        seq: seq.unwrap_or(auto_seq),
                        permit,
                        communities: comms,
                    });
                    Ok(())
                }
                Some("expanded") => err(
                    line,
                    "expanded community-lists (regex) are not supported at import (see docs/protocols/policy.md §Deferred)",
                ),
                _ => {
                    // Auto-detect form `bgp community-list NAME permit|deny ...`
                    // — deprecated in FRR 5.0; treat as unknown to avoid
                    // guessing the type.
                    err(
                        line,
                        "community-list: expected `standard` (auto-detect form is deprecated and unsupported)",
                    )
                }
            }
        }
        Some("extcommunity-list") | Some("large-community-list") => err(
            line,
            format!(
                "`{}` is not supported at import (see docs/protocols/policy.md §Deferred)",
                toks[1]
            ),
        ),
        _ => err(line, "unreachable community-list arm"),
    }
}

fn parse_name_list(s: &str) -> Vec<String> {
    s.split(',').map(|x| x.trim().to_string()).collect()
}

fn parse_protocol(s: &str) -> Option<RouteProtocol> {
    use RouteProtocol as Rp;
    Some(match s {
        "static" => Rp::Static,
        "bgp" => Rp::Bgp,
        "ospf" | "ospf6" => Rp::Ospf,
        "connected" => Rp::Connected,
        "kernel" => Rp::Kernel,
        "rip" => Rp::Rip,
        "isis" => Rp::IsIs,
        "local" => Rp::Local,
        _ => return None,
    })
}

fn join_tail(toks: &[&str], from: usize) -> String {
    toks.get(from..).map(|t| t.join(" ")).unwrap_or_default()
}

// ---------------------------------------------------------------------------
// Compiler: PolicyDocument → typed Filter
// ---------------------------------------------------------------------------

/// Compile one named route-map of the document into a typed filter.
///
/// Execution model (FRR "Route Maps" summary table):
/// - entry matches (AND of clauses; empty = always) + permit → apply
///   sets, then `call` (a deny return finishes and denies; a permit
///   return proceeds), then exit policy;
/// - entry matches + deny → deny (sets, call and exit policy on a
///   matched deny entry are unreachable — recorded as warnings);
/// - no match → next entry; nothing matched → implicit deny.
///
/// `call NAME` targets must be defined route-maps and acyclic — both
/// are compile errors carrying the `call` clause's own line; the cycle
/// error names the full cycle path (POL-1, owner-adjudicated — the
/// typed-engine convention for undefined references; FRR instead looks
/// the name up at apply time).
pub fn compile_route_map(
    doc: &PolicyDocument,
    name: &str,
) -> Result<CompileOutput, PolicyConfigError> {
    let mut out = compile_route_map_inner(doc, name, &[name])?;
    let mut warnings = doc.warnings.clone();
    warnings.append(&mut out.warnings);
    out.warnings = warnings;
    Ok(out)
}

/// `stack` is the chain of route-map names currently being compiled
/// (for `call` cycle detection); `name` is appended to it for
/// recursive compiles.
fn compile_route_map_inner(
    doc: &PolicyDocument,
    name: &str,
    stack: &[&str],
) -> Result<CompileOutput, PolicyConfigError> {
    let mut warnings = Vec::new();
    let rm = doc.route_maps.get(name).ok_or_else(|| PolicyConfigError {
        line: 0,
        message: format!("route-map `{name}` not found"),
    })?;

    let mut b = FilterBuilder::new(); // default verdict: Reject (implicit deny-all)
    let mut pl_idx: BTreeMap<String, SetIndex> = BTreeMap::new();
    let mut acl_idx: BTreeMap<String, SetIndex> = BTreeMap::new();
    let mut asl_idx: BTreeMap<String, SetIndex> = BTreeMap::new();
    let mut cl_idx: BTreeMap<String, SetIndex> = BTreeMap::new();
    let mut cl_removal: BTreeMap<String, CommunitySet> = BTreeMap::new();

    // Resolve a goto target: first entry with seq >= N after entry i.
    // FRR validates that the continue target exceeds the current
    // sequence ("Jumping to a previous entry is not permitted") — a
    // target <= the entry's own seq is a config error.
    let goto_target = |entries: &[RmEntry],
                       i: usize,
                       n: u32,
                       line: u32|
     -> Result<usize, PolicyConfigError> {
        if n <= entries[i].seq {
            return err(
                line,
                format!(
                    "continue/goto {n}: target must exceed the current sequence {} (backwards jumps are not permitted)",
                    entries[i].seq
                ),
            );
        }
        match entries[i + 1..].iter().position(|e| e.seq >= n) {
            Some(off) => Ok(i + 1 + off),
            None => err(
                line,
                format!("continue/goto {n}: no later entry with sequence >= {n}"),
            ),
        }
    };

    for (i, entry) in rm.entries.iter().enumerate() {
        // Terms
        let mut terms: Vec<Term> = Vec::new();
        for m in &entry.matches {
            match m {
                RmMatch::PrefixList { names, .. } => {
                    let mut ors = Vec::new();
                    for n in names {
                        let list = doc.prefix_lists.get(n).ok_or_else(|| PolicyConfigError {
                            line: entry.line,
                            message: format!("match: undefined prefix-list `{n}`"),
                        })?;
                        let idx = match pl_idx.get(n) {
                            Some(x) => *x,
                            None => {
                                let x = b.add_prefix_list(list.clone());
                                pl_idx.insert(n.clone(), x);
                                x
                            }
                        };
                        ors.push(Term::PrefixList(idx));
                    }
                    terms.push(or_or_identity(ors));
                }
                RmMatch::AccessList { name, .. } => {
                    let list = doc
                        .access_lists
                        .get(name)
                        .ok_or_else(|| PolicyConfigError {
                            line: entry.line,
                            message: format!("match: undefined access-list `{name}`"),
                        })?;
                    let idx = match acl_idx.get(name) {
                        Some(x) => *x,
                        None => {
                            let x = b.add_access_list(list.clone());
                            acl_idx.insert(name.clone(), x);
                            x
                        }
                    };
                    terms.push(Term::AccessList(idx));
                }
                RmMatch::AsPath(n) => {
                    let list = doc.as_path_lists.get(n).ok_or_else(|| PolicyConfigError {
                        line: entry.line,
                        message: format!("match: undefined as-path access-list `{n}`"),
                    })?;
                    let idx = match asl_idx.get(n) {
                        Some(x) => *x,
                        None => {
                            let x = b.add_as_path_list(list.clone());
                            asl_idx.insert(n.clone(), x);
                            x
                        }
                    };
                    terms.push(Term::PathList(idx));
                }
                RmMatch::Community { names, exact } => {
                    let mut ors = Vec::new();
                    for n in names {
                        let list = doc
                            .community_lists
                            .get(n)
                            .ok_or_else(|| PolicyConfigError {
                                line: entry.line,
                                message: format!("match: undefined community-list `{n}`"),
                            })?;
                        let idx = match cl_idx.get(n) {
                            Some(x) => *x,
                            None => {
                                let x = b.add_community_list(list.clone());
                                cl_idx.insert(n.clone(), x);
                                x
                            }
                        };
                        ors.push(if *exact {
                            Term::CommunityListExact(idx)
                        } else {
                            Term::CommunityList(idx)
                        });
                    }
                    terms.push(or_or_identity(ors));
                }
                RmMatch::LocalPref(v) => terms.push(Term::LocalPrefIn(*v, *v)),
                // FRR `match metric` compares the route metric.
                RmMatch::Metric(v) => terms.push(Term::MetricIn(*v, *v)),
                RmMatch::SourceProtocol(ps) => terms.push(Term::ProtocolIn(ps.clone())),
            }
        }

        // Actions
        let mut actions: Vec<Action> = Vec::new();
        match entry.policy {
            RmPolicy::Permit => {
                for s in &entry.sets {
                    match s {
                        RmSet::LocalPref(n) => match n {
                            crate::routemap::RmNum::Absolute(v) => {
                                actions.push(Action::SetLocalPref(*v));
                            }
                            crate::routemap::RmNum::Relative(d) => {
                                actions.push(Action::AdjustLocalPref(*d));
                            }
                        },
                        RmSet::Community { list, mode } => {
                            actions.push(Action::SetCommunities {
                                list: list.clone(),
                                mode: mode.clone(),
                            });
                        }
                        RmSet::CommunityDelete(n) => {
                            let list =
                                doc.community_lists
                                    .get(n)
                                    .ok_or_else(|| PolicyConfigError {
                                        line: entry.line,
                                        message: format!(
                                            "set comm-list delete: undefined community-list `{n}`"
                                        ),
                                    })?;
                            let set = match cl_removal.get(n) {
                                Some(x) => x.clone(),
                                None => {
                                    let x = list.to_removal_set();
                                    cl_removal.insert(n.clone(), x.clone());
                                    x
                                }
                            };
                            actions.push(Action::RemoveCommunities(set));
                        }
                        RmSet::Origin(o) => actions.push(Action::SetOrigin(*o)),
                        // FRR `set metric`: "When used with BGP, set the
                        // BGP attribute MED to a specific value."
                        RmSet::Metric(n) => match n {
                            crate::routemap::RmNum::Absolute(v) => {
                                actions.push(Action::SetMed(*v));
                            }
                            crate::routemap::RmNum::Relative(d) => {
                                actions.push(Action::AdjustMed(*d));
                            }
                        },
                        RmSet::AsPathPrepend { asns } => {
                            // `set as-path prepend A B C` puts A leftmost;
                            // prepend executes right-to-left.
                            for &asn in asns.iter().rev() {
                                actions.push(Action::PrependAsPath { asn, times: 1 });
                            }
                        }
                    }
                }
                // Call Action, after Set Actions (FRR "Route Maps").
                // The callee is compiled now. POL-1 (owner-adjudicated):
                // an undefined target is a compile error at the call
                // site's own line, and a cycle is rejected at load with
                // the full cycle path in the message — FRR looks the
                // name up at apply time instead.
                if let Some((callee, call_line)) = &entry.call {
                    if stack.contains(&callee.as_str()) {
                        let mut path: Vec<&str> = stack.to_vec();
                        path.push(callee);
                        return err(
                            *call_line,
                            format!(
                                "call `{callee}`: recursive route-map call (cycle: {})",
                                path.join(" -> ")
                            ),
                        );
                    }
                    if !doc.route_maps.contains_key(callee) {
                        return err(*call_line, format!("call: undefined route-map `{callee}`"));
                    }
                    let mut sub_stack: Vec<&str> = stack.to_vec();
                    sub_stack.push(callee);
                    // Structural warnings of the callee surface too
                    // (e.g. set clauses on its matched deny entries).
                    let mut sub_out = compile_route_map_inner(doc, callee, &sub_stack)?;
                    warnings.append(&mut sub_out.warnings);
                    let idx = b.add_call(sub_out.filter);
                    actions.push(Action::Call(idx));
                }
                // Exit policy (FRR Route Maps — Matching/Exit Policy):
                // none → finish and permit; next → fall through to the
                // next entry (no terminal action — the evaluator
                // advances); goto N → jump to the first entry with
                // order >= N.
                match entry.exit {
                    RmExit::None => actions.push(Action::Accept),
                    RmExit::Next => {}
                    RmExit::Goto(n) => {
                        let target = goto_target(&rm.entries, i, n, entry.line)?;
                        actions.push(Action::Goto(target));
                    }
                }
                b.add_rule(and_and_identity(terms), actions);
            }
            RmPolicy::Deny => {
                if !entry.sets.is_empty() {
                    warnings.push(format!(
                        "line {}: route-map seq {}: set clauses on a matched deny entry are never applied (ignored)",
                        entry.line, entry.seq
                    ));
                }
                if entry.call.is_some() {
                    warnings.push(format!(
                        "line {}: route-map seq {}: call on a matched deny entry is never applied (ignored)",
                        entry.line, entry.seq
                    ));
                }
                if entry.exit != RmExit::None {
                    warnings.push(format!(
                        "line {}: route-map seq {}: exit policy on a matched deny entry is unreachable (ignored)",
                        entry.line, entry.seq
                    ));
                }
                b.add_rule(and_and_identity(terms), vec![Action::Reject]);
            }
        }
    }
    let filter = b.build().map_err(|e| PolicyConfigError {
        line: 0,
        message: e,
    })?;
    Ok(CompileOutput { filter, warnings })
}

fn or_or_identity(mut ors: Vec<Term>) -> Term {
    match ors.len() {
        0 => Term::True,
        1 => ors.pop().expect("one"),
        _ => Term::Or(ors),
    }
}

fn and_and_identity(mut ts: Vec<Term>) -> Term {
    match ts.len() {
        0 => Term::True,
        1 => ts.pop().expect("one"),
        _ => Term::And(ts),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::filter::Verdict;
    use crate::route::testutil::v4_route;

    fn compile_ok(text: &str, name: &str) -> CompileOutput {
        let doc = parse_policy_config(text).expect("parse");
        compile_route_map(&doc, name).expect("compile")
    }

    #[test]
    fn frr_doc_example_route_map() {
        // FRR "Route Map Examples" — `route-map test permit 10 / match
        // ip address 10 / set local-preference 200` — with the
        // access-list form swapped to the supported prefix-list form
        // (mapping table in docs/protocols/policy.md).
        let out = compile_ok(
            "ip prefix-list 10 permit 192.0.2.0/24\nroute-map test permit 10\n match ip address prefix-list 10\n set local-preference 200\n",
            "test",
        );
        let mut r = v4_route("192.0.2.0/24", &[65001]);
        assert!(out.filter.apply(&mut r).is_accept());
        assert_eq!(r.bgp().unwrap().local_pref, Some(200));
        // Off-list route: no entry matches → implicit deny.
        let mut other = v4_route("198.51.100.0/24", &[65001]);
        assert_eq!(out.filter.apply(&mut other), Verdict::Reject);
    }

    #[test]
    fn deny_entry_and_implicit_deny_all() {
        // Canonical FRR deny pattern: the prefix-list PERMITS the bogons
        // and the route-map entry carries the deny — a prefix-list deny
        // inside a match clause is a no-match, not a route-map deny.
        let good = "\
ip prefix-list bogons permit 10.0.0.0/8 le 32
route-map peer-in deny 5
 match ip address prefix-list bogons
route-map peer-in permit 10
 set local-preference 120
";
        let out = compile_ok(good, "peer-in");
        let mut bogon = v4_route("10.1.2.0/24", &[65001]);
        assert_eq!(out.filter.apply(&mut bogon), Verdict::Reject, "deny 5 wins");
        let mut good_route = v4_route("203.0.113.0/24", &[65001]);
        assert_eq!(out.filter.apply(&mut good_route), Verdict::Accept);
        assert_eq!(good_route.bgp().unwrap().local_pref, Some(120));
    }

    #[test]
    fn continue_semantics() {
        // FRR exit policy: continue N jumps to the first entry with
        // order >= N; sets of earlier entries apply.
        let text = "\
ip prefix-list customers permit 198.51.100.0/24
route-map upstream-in permit 10
 match ip address prefix-list customers
 set local-preference 200
 continue 20
route-map upstream-in permit 20
 set community 65000:1 additive
 set origin incomplete
";
        let out = compile_ok(text, "upstream-in");
        let mut r = v4_route("198.51.100.0/24", &[65001, 65002]);
        assert_eq!(out.filter.apply(&mut r), Verdict::Accept);
        let b = r.bgp().unwrap();
        assert_eq!(b.local_pref, Some(200), "set in entry 10 applies");
        assert_eq!(
            b.communities,
            vec![Community::Pair(65000, 1)],
            "additive set in entry 20 applies"
        );
        assert_eq!(b.origin, Some(BgpOrigin::Incomplete));
        // Route outside the prefix-list skips entry 10; entry 20 has no
        // match clauses so it (and its sets) apply to every route.
        let mut r2 = v4_route("203.0.113.0/24", &[65001]);
        assert_eq!(out.filter.apply(&mut r2), Verdict::Accept);
        assert_eq!(
            r2.bgp().unwrap().local_pref,
            Some(100),
            "entry 10 untouched"
        );
        assert_eq!(
            r2.bgp().unwrap().communities,
            vec![Community::Pair(65000, 1)],
            "entry 20 matches all"
        );
    }

    #[test]
    fn on_match_next_and_empty_permit_tail() {
        let text = "\
ip prefix-list p10 permit 10.0.0.0/8 le 32
ip prefix-list p172 permit 172.16.0.0/12 le 32
route-map classify permit 10
 match ip address prefix-list p10
 set metric 10
 on-match next
route-map classify deny 20
 match ip address prefix-list p172
route-map classify permit 100
";
        let out = compile_ok(text, "classify");
        let mut r10 = v4_route("10.1.0.0/16", &[]);
        assert_eq!(out.filter.apply(&mut r10), Verdict::Accept);
        assert_eq!(r10.bgp().unwrap().med, Some(10), "sets applied, then next");
        let mut r172 = v4_route("172.16.5.0/24", &[]);
        assert_eq!(out.filter.apply(&mut r172), Verdict::Reject, "deny 20");
        let mut r192 = v4_route("192.0.2.0/24", &[]);
        assert_eq!(
            out.filter.apply(&mut r192),
            Verdict::Accept,
            "empty permit tail = permit-all"
        );
    }

    #[test]
    fn community_match_and_set() {
        let text = "\
bgp community-list standard KNOWN deny 65000:1
bgp community-list standard KNOWN permit
route-map comm permit 10
 match community KNOWN
 set community 65000:99 additive
";
        let out = compile_ok(text, "comm");
        let mut r = v4_route("192.0.2.0/24", &[65001]);
        r.bgp_or_materialize().communities = vec![Community::Pair(65000, 2)];
        assert_eq!(out.filter.apply(&mut r), Verdict::Accept);
        assert!(r
            .bgp()
            .unwrap()
            .communities
            .contains(&Community::Pair(65000, 99)));
        // Route carrying the denied community is filtered.
        let mut bad = v4_route("192.0.2.0/24", &[65001]);
        bad.bgp_or_materialize().communities = vec![Community::Pair(65000, 1)];
        assert_eq!(out.filter.apply(&mut bad), Verdict::Reject);
    }

    #[test]
    fn exact_match_community() {
        let text = "\
bgp community-list standard PAIR permit 65000:1 65000:2
route-map exact permit 10
 match community PAIR exact-match
";
        let out = compile_ok(text, "exact");
        let mk = |cs: Vec<Community>| {
            let mut r = v4_route("192.0.2.0/24", &[]);
            r.bgp_or_materialize().communities = cs;
            r
        };
        let mut both = mk(vec![Community::Pair(65000, 1), Community::Pair(65000, 2)]);
        assert_eq!(out.filter.apply(&mut both), Verdict::Accept);
        let mut one = mk(vec![Community::Pair(65000, 1)]);
        assert_eq!(out.filter.apply(&mut one), Verdict::Reject);
    }

    #[test]
    fn as_path_access_list_match() {
        // FRR bgpd doc example regexes, verbatim operators.
        let text = "\
bgp as-path access-list 99 permit _23456_
route-map aspath deny 10
 match as-path 99
route-map aspath permit 20
";
        let out = compile_ok(text, "aspath");
        let mut r = v4_route("192.0.2.0/24", &[65001, 23456]);
        assert_eq!(out.filter.apply(&mut r), Verdict::Reject);
        let mut r2 = v4_route("192.0.2.0/24", &[65001, 65002]);
        assert_eq!(out.filter.apply(&mut r2), Verdict::Accept);
    }

    #[test]
    fn comm_list_delete_and_metric_origin_prepends() {
        let text = "\
bgp community-list standard DEL permit 65000:1 65000:2
route-map polish permit 10
 set comm-list DEL delete
 set metric +50
 set origin egp
 set as-path prepend 64512 64513
";
        let out = compile_ok(text, "polish");
        let mut r = v4_route("192.0.2.0/24", &[65001]);
        r.bgp_or_materialize().communities = vec![
            Community::Pair(65000, 1),
            Community::Pair(65000, 2),
            Community::Pair(65000, 3),
        ];
        assert_eq!(out.filter.apply(&mut r), Verdict::Accept);
        let b = r.bgp().unwrap();
        assert_eq!(b.communities, vec![Community::Pair(65000, 3)]);
        assert_eq!(b.med, Some(50), "set metric +50 sets the MED");
        assert_eq!(b.origin, Some(BgpOrigin::Egp));
        assert_eq!(b.as_path.render(), "64512 64513 65001", "leftmost first");
    }

    #[test]
    fn match_local_pref_and_source_protocol() {
        let text = "\
route-map lp permit 10
 match local-preference 100
 match source-protocol bgp
";
        let out = compile_ok(text, "lp");
        let mut r = v4_route("192.0.2.0/24", &[65001]);
        assert_eq!(out.filter.apply(&mut r), Verdict::Accept);
        r.bgp_or_materialize().local_pref = Some(200);
        assert_eq!(out.filter.apply(&mut r), Verdict::Reject);
    }

    #[test]
    fn set_value_absolute_vs_relative() {
        // FRR: `set local-preference 250` is absolute; `+50` adds to the
        // current value; `-30` subtracts.
        let text = "\
route-map abs permit 10
 set local-preference 250
";
        let out = compile_ok(text, "abs");
        let mut r = v4_route("192.0.2.0/24", &[65001]);
        r.bgp_or_materialize().local_pref = Some(100);
        out.filter.apply(&mut r);
        assert_eq!(r.bgp().unwrap().local_pref, Some(250), "absolute replaces");

        let text2 = "\
route-map rel permit 10
 set local-preference +50
";
        let out2 = compile_ok(text2, "rel");
        out2.filter.apply(&mut r);
        assert_eq!(r.bgp().unwrap().local_pref, Some(300), "relative adds");

        let text3 = "\
route-map rel2 permit 10
 set local-preference -30
";
        let out3 = compile_ok(text3, "rel2");
        out3.filter.apply(&mut r);
        assert_eq!(r.bgp().unwrap().local_pref, Some(270), "relative subtracts");
    }

    #[test]
    fn ipv6_prefix_list_and_matches() {
        let text = "\
ipv6 prefix-list v6only permit 2001:db8::/32 ge 48 le 64
route-map v6 permit 10
 match ipv6 address prefix-list v6only
";
        let out = compile_ok(text, "v6");
        let mut r = crate::route::testutil::v6_route("2001:db8:1::/48", &[65001]);
        assert_eq!(out.filter.apply(&mut r), Verdict::Accept);
        let mut r2 = crate::route::testutil::v6_route("2001:db8::/32", &[65001]);
        assert_eq!(
            out.filter.apply(&mut r2),
            Verdict::Reject,
            "/32 below ge 48"
        );
    }

    #[test]
    fn b7_observed_fixture_rejected_with_line_numbers() {
        // test-z5b-bgpd-interop.sh r1 frr.conf, verbatim: the policy
        // grammar must refuse foreign stanzas loudly, never silently.
        let z5b_r1 = "\
frr version 10.2
frr defaults traditional
hostname r1
ip route 198.51.100.0/24 blackhole
router bgp 65000
 no bgp network import-check
 neighbor 192.168.215.3 remote-as 65000
 address-family ipv4 unicast
  network 203.0.113.0/24
  redistribute static
 exit-address-family
line vty
";
        let e = parse_policy_config(z5b_r1).unwrap_err();
        assert_eq!(e.line, 1, "first foreign directive is `frr version`");
        assert!(e.message.contains("unknown directive `frr`"));

        // test-z5-frr-interop.sh staticd config, verbatim.
        let z5 = "\
frr version 10.2
frr defaults traditional
hostname r1
ip route 203.0.113.0/24 blackhole
ip route 198.51.100.0/24 192.0.2.1
line vty
";
        let e = parse_policy_config(z5).unwrap_err();
        assert_eq!(e.line, 1);
    }

    #[test]
    fn b7_observed_indentation_and_bang_style() {
        // B7: vtysh writes node children indented; `!` separates stanzas
        // in frr.conf style. Route-map children parse with one leading
        // space exactly like the observed router-bgp children.
        let text = "\
ip prefix-list custs permit 198.51.100.0/24
!
route-map in-bound permit 10
 match ip address prefix-list custs
 set local-preference 150
!
route-map in-bound permit 20
";
        let out = compile_ok(text, "in-bound");
        let mut r = v4_route("198.51.100.0/24", &[65001]);
        assert_eq!(out.filter.apply(&mut r), Verdict::Accept);
        assert_eq!(r.bgp().unwrap().local_pref, Some(150));
    }

    #[test]
    fn unknown_keywords_error_with_line_numbers() {
        let cases = [
            (
                "route-map x permit 10\n match ip address prefix-len 12\n",
                2,
                "prefix-len",
            ),
            ("route-map x permit 10\n match peer 10.0.0.1\n", 2, "peer"),
            ("route-map x permit 10\n set weight 100\n", 2, "weight"),
            (
                "route-map x permit 10\n set as-path exclude 100\n",
                2,
                "exclude",
            ),
            ("match community A\n", 1, "outside"),
            ("frr version 10.2\n", 1, "unknown directive `frr`"),
            ("router bgp 65000\n", 1, "unknown directive `router`"),
            (
                "route-map x permit 10\n set community bogus\n",
                2,
                "invalid community",
            ),
            ("bgp community-list expanded E permit .*\n", 1, "expanded"),
            (
                "bgp large-community-list L permit 1:2:3\n",
                1,
                "large-community-list",
            ),
            ("set local-preference 5\n", 1, "outside"),
        ];
        for (text, want_line, needle) in cases {
            let e = parse_policy_config(text).unwrap_err();
            assert_eq!(e.line, want_line, "for input {text:?}: {}", e.message);
            assert!(
                e.message.contains(needle),
                "expected `{needle}` in `{}` (line {})",
                e.message,
                e.line
            );
        }
    }

    #[test]
    fn parse_error_line_numbers_and_values() {
        let e = parse_policy_config("ip prefix-list p permit 10.0.0.0/8 ge 40\n").unwrap_err();
        assert_eq!(e.line, 1);
        assert!(e.message.contains("exceeds"));
        let e = parse_policy_config("route-map x bogus 10\n").unwrap_err();
        assert!(e.message.contains("permit|deny"));
        let e = parse_policy_config("ip prefix-list p permit 300.0.0.0/8\n").unwrap_err();
        assert!(e.message.contains("invalid prefix"));
        // Undefined references surface at compile time with the entry line.
        let doc =
            parse_policy_config("route-map x permit 10\n match ip address prefix-list nope\n")
                .unwrap();
        let ce = compile_route_map(&doc, "x").unwrap_err();
        assert_eq!(ce.line, 1, "entry opened on line 1");
        assert!(ce.message.contains("undefined prefix-list"));
    }

    #[test]
    fn backwards_continue_is_rejected() {
        // Target below the entry's own sequence: FRR rejects backwards
        // (and self) jumps.
        let text = "\
route-map x permit 10
 continue 5
route-map x permit 20
";
        let doc = parse_policy_config(text).unwrap();
        let e = compile_route_map(&doc, "x").unwrap_err();
        assert!(e.message.contains("must exceed"), "{}", e.message);

        // Target above every entry: no later entry to jump to.
        let text2 = "\
route-map x permit 10
 continue 99
";
        let doc2 = parse_policy_config(text2).unwrap();
        let e2 = compile_route_map(&doc2, "x").unwrap_err();
        assert!(e2.message.contains("no later entry"), "{}", e2.message);
    }

    #[test]
    fn deny_entry_warnings_surface() {
        let text = "\
route-map x deny 10
 set local-preference 5
 continue 20
route-map x permit 20
";
        let doc = parse_policy_config(text).unwrap();
        let out = compile_route_map(&doc, "x").unwrap();
        assert!(out
            .warnings
            .iter()
            .any(|w| w.contains("set clauses on a matched deny")));
        assert!(out
            .warnings
            .iter()
            .any(|w| w.contains("exit policy on a matched deny")));
    }

    #[test]
    fn empty_and_missing_route_maps() {
        let doc = parse_policy_config("").unwrap();
        let e = compile_route_map(&doc, "ghost").unwrap_err();
        assert!(e.message.contains("not found"));
        let doc2 = parse_policy_config("route-map e permit 5\n").unwrap();
        let out = compile_route_map(&doc2, "e").unwrap();
        let mut r = v4_route("192.0.2.0/24", &[]);
        assert_eq!(
            out.filter.apply(&mut r),
            Verdict::Accept,
            "empty permit entry matches all"
        );
    }

    #[test]
    fn same_seq_replaces_and_sorting() {
        let text = "\
route-map x permit 20
route-map x deny 10
route-map x permit 10
";
        let doc = parse_policy_config(text).unwrap();
        let rm = doc.route_maps.get("x").unwrap();
        assert_eq!(rm.entries.len(), 2, "same seq replaces");
        assert_eq!(rm.entries[0].seq, 10);
        assert_eq!(rm.entries[0].policy, RmPolicy::Permit, "later line won");
        assert_eq!(rm.entries[1].seq, 20);
    }

    #[test]
    fn same_kind_match_replaces() {
        let text = "\
ip prefix-list a permit 10.0.0.0/8
ip prefix-list b permit 192.0.2.0/24
route-map x permit 10
 match ip address prefix-list a
 match ip address prefix-list b
";
        let out = compile_ok(text, "x");
        let mut r10 = v4_route("10.0.0.0/8", &[]);
        assert_eq!(
            out.filter.apply(&mut r10),
            Verdict::Reject,
            "first match clause replaced by second"
        );
        let mut r192 = v4_route("192.0.2.0/24", &[]);
        assert_eq!(out.filter.apply(&mut r192), Verdict::Accept);
    }

    #[test]
    fn comm_list_frr_token_order_regression() {
        // FRR 10.2 CLI (bgpd/bgp_routemap.c set_community_delete_cmd):
        // "set comm-list <(1-99)|(100-500)|COMMUNITY_LIST_NAME> delete"
        // — the name FIRST, `delete` LAST. Verbatim FRR configs must
        // parse; the previously-accepted inverted order must not.
        let text = "\
bgp community-list standard DEL permit 65000:1
route-map r permit 10
 set comm-list DEL delete
";
        let out = compile_ok(text, "r");
        let mut r = v4_route("192.0.2.0/24", &[65001]);
        r.bgp_or_materialize().communities = vec![Community::Pair(65000, 1), Community::Pair(1, 1)];
        assert_eq!(out.filter.apply(&mut r), Verdict::Accept);
        assert_eq!(r.bgp().unwrap().communities, vec![Community::Pair(1, 1)]);

        let e = parse_policy_config(
            "bgp community-list standard DEL permit 65000:1\nroute-map r permit 10\n set comm-list delete DEL\n",
        )
        .unwrap_err();
        assert_eq!(e.line, 3);
        assert!(e.message.contains("comm-list NAME delete"), "{}", e.message);
    }

    #[test]
    fn comm_list_exact_accepted_input_shape() {
        // POL-1 companion: the accepted shape is exactly FRR 10.2.2's
        // `set comm-list <(1-99)|(100-500)|NAME> delete` — numeric list
        // names included, `delete` last, nothing after it.
        let text = "\
bgp community-list standard 1 permit 65000:1 65000:2
route-map r permit 10
 set comm-list 1 delete
";
        let out = compile_ok(text, "r");
        let mut r = v4_route("192.0.2.0/24", &[65001]);
        r.bgp_or_materialize().communities = vec![
            Community::Pair(65000, 1),
            Community::Pair(65000, 2),
            Community::Pair(65000, 3),
        ];
        assert_eq!(out.filter.apply(&mut r), Verdict::Accept);
        assert_eq!(
            r.bgp().unwrap().communities,
            vec![Community::Pair(65000, 3)]
        );

        // Missing `delete` and trailing tokens are shape errors naming
        // the expected form.
        let e = parse_policy_config("route-map r permit 10\n set comm-list DEL\n").unwrap_err();
        assert_eq!(e.line, 2);
        assert!(e.message.contains("comm-list NAME delete"), "{}", e.message);
        let e = parse_policy_config("route-map r permit 10\n set comm-list DEL delete junk\n")
            .unwrap_err();
        assert_eq!(e.line, 2);
        assert!(e.message.contains("comm-list NAME delete"), "{}", e.message);
    }

    #[test]
    fn call_deny_return_short_circuits() {
        // FRR "Route Maps": the Call Action runs after Set Actions; "If
        // it returns deny ... the route is denied, regardless of the
        // Matching Policy or the Exit Policy." The callee's implicit
        // deny-all counts as a deny return.
        let text = "\
ip prefix-list bogon permit 10.0.0.0/8 le 32
route-map blocker deny 10
 match ip address prefix-list bogon
route-map blocker permit 20
route-map main permit 10
 set local-preference 200
 call blocker
";
        let out = compile_ok(text, "main");
        let mut bogon = v4_route("10.1.2.0/24", &[65001]);
        assert_eq!(
            out.filter.apply(&mut bogon),
            Verdict::Reject,
            "deny return finishes and denies"
        );
        assert_eq!(
            bogon.bgp().unwrap().local_pref,
            Some(200),
            "caller sets applied before the call"
        );
        // Permit return (callee's empty permit tail): the caller's
        // exit policy (none → permit) proceeds.
        let mut clean = v4_route("192.0.2.0/24", &[65001]);
        assert_eq!(out.filter.apply(&mut clean), Verdict::Accept);
        assert_eq!(clean.bgp().unwrap().local_pref, Some(200));
    }

    #[test]
    fn call_permit_return_runs_exit_policy() {
        // Permit return → matching+exit policy proceed: here
        // `on-match next`, so the next entry's sets apply on top.
        // (`set metric` maps to MED — docs/protocols/policy.md §6.5.)
        let text = "\
route-map sub permit 5
 set metric 42
route-map main permit 10
 set local-preference 150
 call sub
 on-match next
route-map main permit 20
 set origin egp
";
        let out = compile_ok(text, "main");
        let mut r = v4_route("192.0.2.0/24", &[65001]);
        assert_eq!(out.filter.apply(&mut r), Verdict::Accept);
        let b = r.bgp().unwrap();
        assert_eq!(b.local_pref, Some(150), "caller set before call");
        assert_eq!(b.med, Some(42), "callee set persists after permit return");
        assert_eq!(b.origin, Some(BgpOrigin::Egp), "next entry after call");
    }

    #[test]
    fn call_chain_a_to_b_to_c_evaluates() {
        // POL-1: a legitimate chain (A→B→C) compiles and evaluates —
        // caller sets first, then each callee's sets, innermost last.
        let text = "\
route-map c permit 5
 set origin egp
route-map b permit 10
 set metric 42
 call c
route-map a permit 10
 set local-preference 150
 call b
";
        let out = compile_ok(text, "a");
        let mut r = v4_route("192.0.2.0/24", &[65001]);
        assert_eq!(out.filter.apply(&mut r), Verdict::Accept);
        let b = r.bgp().unwrap();
        assert_eq!(b.local_pref, Some(150), "outermost caller's set");
        assert_eq!(b.med, Some(42), "middle callee's set");
        assert_eq!(b.origin, Some(BgpOrigin::Egp), "innermost callee's set");
        // Every link of the chain compiles standalone too.
        let mut rb = v4_route("192.0.2.0/24", &[]);
        assert!(compile_ok(text, "b").filter.apply(&mut rb).is_accept());
        assert_eq!(rb.bgp().unwrap().origin, Some(BgpOrigin::Egp));
        let mut rc = v4_route("192.0.2.0/24", &[]);
        assert!(compile_ok(text, "c").filter.apply(&mut rc).is_accept());
        assert_eq!(rc.bgp().unwrap().origin, Some(BgpOrigin::Egp));
    }

    #[test]
    fn call_mutual_non_cyclic_references_work() {
        // POL-1: cross-references that do not close a cycle stay legal.
        // second → first → shared is a DAG; each head compiles on its
        // own and the composed result evaluates end to end.
        let text = "\
route-map shared permit 5
 set origin egp
route-map first permit 10
 call shared
route-map second permit 10
 call first
";
        let out = compile_ok(text, "second");
        let mut r = v4_route("192.0.2.0/24", &[65001]);
        assert_eq!(out.filter.apply(&mut r), Verdict::Accept);
        assert_eq!(r.bgp().unwrap().origin, Some(BgpOrigin::Egp));
        let mut rf = v4_route("192.0.2.0/24", &[]);
        assert!(compile_ok(text, "first").filter.apply(&mut rf).is_accept());
        assert_eq!(rf.bgp().unwrap().origin, Some(BgpOrigin::Egp));
        let mut rs = v4_route("192.0.2.0/24", &[]);
        assert!(compile_ok(text, "shared").filter.apply(&mut rs).is_accept());
        assert_eq!(rs.bgp().unwrap().origin, Some(BgpOrigin::Egp));
    }

    #[test]
    fn call_undefined_target_and_cycles_are_compile_errors() {
        // POL-1 (owner-adjudicated): an undefined call target is a
        // compile error at the CALL SITE's line, not the entry header.
        let doc = parse_policy_config("route-map x permit 10\n call ghost\n").unwrap();
        let e = compile_route_map(&doc, "x").unwrap_err();
        assert_eq!(e.line, 2, "the `call` clause's own line");
        assert!(
            e.message.contains("undefined route-map `ghost`"),
            "{}",
            e.message
        );

        // Direct self-call and mutual cycles are compile errors whose
        // message names the full cycle path.
        let selfy = parse_policy_config("route-map x permit 10\n call x\n").unwrap();
        let e = compile_route_map(&selfy, "x").unwrap_err();
        assert_eq!(e.line, 2);
        assert!(e.message.contains("cycle: x -> x"), "{}", e.message);

        let mutual =
            parse_policy_config("route-map a permit 10\n call b\nroute-map b permit 10\n call a\n")
                .unwrap();
        let e = compile_route_map(&mutual.clone(), "a").unwrap_err();
        assert_eq!(e.line, 4, "b's `call a` (line 4) is the closing edge");
        assert!(e.message.contains("cycle: a -> b -> a"), "{}", e.message);
        let e = compile_route_map(&mutual, "b").unwrap_err();
        assert!(e.message.contains("cycle: b -> a -> b"), "{}", e.message);

        // A shared (non-cyclic) callee twice in one chain is fine.
        let dag = parse_policy_config(
            "route-map leaf permit 5\nroute-map mid permit 10\n call leaf\nroute-map top permit 20\n call leaf\n call mid\n",
        )
        .unwrap();
        assert!(compile_route_map(&dag, "top").is_ok());
    }

    #[test]
    fn call_on_deny_entry_warns() {
        let text = "\
route-map callee permit 5
route-map x deny 10
 call callee
";
        let doc = parse_policy_config(text).unwrap();
        let out = compile_route_map(&doc, "x").unwrap();
        assert!(out
            .warnings
            .iter()
            .any(|w| w.contains("call on a matched deny")));
    }

    #[test]
    fn access_list_stanza_and_match_integration() {
        // Zebra-style ACLs match SUBNET-OF by default (FRR
        // lib/filter.c filter_match_zebra) — the inverse of
        // prefix-lists; `exact-match` flips an entry to exact.
        let text = "\
access-list IN permit 10.0.0.0/8
access-list IN seq 3 deny 10.99.0.0/16
access-list IN deny 192.0.2.128/25 exact-match
access-list IN seq 100 permit any
route-map r permit 10
 match ip address IN
";
        let out = compile_ok(text, "r");
        // seq 5 (auto) permit 10/8 covers subnets...
        let mut r = v4_route("10.1.0.0/16", &[]);
        assert_eq!(out.filter.apply(&mut r), Verdict::Accept, "subnet-of");
        // ...but seq 3's deny of 10.99/16 comes first in seq order.
        let mut denied = v4_route("10.99.1.0/24", &[]);
        assert_eq!(out.filter.apply(&mut denied), Verdict::Reject, "seq order");
        // exact-match entry: the /25 is denied even though the
        // trailing `any` (seq 100) would permit it — seq 10 wins.
        let mut exact = v4_route("192.0.2.128/25", &[]);
        assert_eq!(out.filter.apply(&mut exact), Verdict::Reject);
        let mut other = v4_route("198.51.100.0/24", &[]);
        assert_eq!(
            out.filter.apply(&mut other),
            Verdict::Accept,
            "trailing permit any = permit-the-rest"
        );
    }

    #[test]
    fn access_list_default_is_subnet_of_prefix_list_default_is_exact() {
        // Pins the Q4 trap: same network spelling, opposite defaults.
        let acl_text = "\
access-list A permit 10.0.0.0/8
route-map a permit 10
 match ip address A
";
        let pl_text = "\
ip prefix-list P permit 10.0.0.0/8
route-map p permit 10
 match ip address prefix-list P
";
        let acl = compile_ok(acl_text, "a");
        let pl = compile_ok(pl_text, "p");
        let mut subnet = v4_route("10.1.0.0/16", &[]);
        assert_eq!(acl.filter.apply(&mut subnet), Verdict::Accept);
        assert_eq!(
            pl.filter.apply(&mut subnet),
            Verdict::Reject,
            "prefix-list without le/ge is exact"
        );
        // Subnet-of means the entry network itself and longer subnets
        // only — never a supernet.
        let mut supernet = v4_route("10.0.0.0/7", &[]);
        assert_eq!(
            acl.filter.apply(&mut supernet),
            Verdict::Reject,
            "supernet not covered"
        );
        let mut self_net = v4_route("10.0.0.0/8", &[]);
        assert_eq!(acl.filter.apply(&mut self_net), Verdict::Accept);
    }

    #[test]
    fn ipv6_access_list_stanza_and_match() {
        let text = "\
ipv6 access-list V6 deny 2001:db8:bad::/48
ipv6 access-list V6 permit 2001:db8::/32
route-map r permit 10
 match ipv6 address V6
";
        let out = compile_ok(text, "r");
        let mut bad = crate::route::testutil::v6_route("2001:db8:bad:1::/64", &[]);
        assert_eq!(out.filter.apply(&mut bad), Verdict::Reject);
        let mut good = crate::route::testutil::v6_route("2001:db8:1::/48", &[]);
        assert_eq!(out.filter.apply(&mut good), Verdict::Accept);
        // Family separation at the stanza level.
        let e = parse_policy_config("access-list A permit 2001:db8::/32\n").unwrap_err();
        assert!(
            e.message.contains("an IPv4 list given an IPv6 prefix"),
            "{}",
            e.message
        );
        let e = parse_policy_config("ipv6 access-list A permit 10.0.0.0/8\n").unwrap_err();
        assert!(
            e.message.contains("an IPv6 list given an IPv4 prefix"),
            "{}",
            e.message
        );
        // `any` is family-scoped: the v6 list's any must not leak v4.
        let v6any = compile_ok(
            "ipv6 access-list ALL permit any\nroute-map r permit 10\n match ipv6 address ALL\n",
            "r",
        );
        let mut v4 = v4_route("192.0.2.0/24", &[]);
        assert_eq!(v6any.filter.apply(&mut v4), Verdict::Reject);
    }

    #[test]
    fn access_list_seq_numbering_and_replaces() {
        // Auto-seq = max existing sequence + 5 (FRR filter_cli.c
        // acl_get_seq — NOT the prefix-list "next multiple of five").
        let doc = parse_policy_config(
            "\
access-list A permit 10.0.0.0/8
access-list A permit 192.0.2.0/24
access-list A seq 7 deny 198.51.100.0/24
access-list A permit 203.0.113.0/24
",
        )
        .unwrap();
        let al = doc.access_lists.get("A").unwrap();
        let seqs: Vec<u32> = al.entries().iter().map(|e| e.seq).collect();
        assert_eq!(seqs, vec![5, 7, 10, 15], "5; max=5→10; seq 7; max=10→15");
        // Same explicit seq replaces.
        let doc2 = parse_policy_config(
            "\
access-list A seq 5 permit 10.0.0.0/8
access-list A seq 5 deny 10.0.0.0/8
",
        )
        .unwrap();
        let al2 = doc2.access_lists.get("A").unwrap();
        assert_eq!(al2.entries().len(), 1);
        assert_eq!(al2.entries()[0].verdict, PrefixListVerdict::Deny);
    }

    #[test]
    fn access_list_undefined_reference_is_compile_error() {
        let doc = parse_policy_config("route-map x permit 10\n match ip address NOPE\n").unwrap();
        let e = compile_route_map(&doc, "x").unwrap_err();
        assert_eq!(e.line, 1);
        assert!(
            e.message.contains("undefined access-list `NOPE`"),
            "{}",
            e.message
        );
    }

    #[test]
    fn cisco_style_access_lists_refused() {
        // Cisco-style entry forms and the named-ACL submode stay
        // refused loudly (see docs/protocols/policy.md §Deferred):
        // the zebra form takes exactly PREFIX [exact-match]|any, so
        // the trailing cisco tokens are unexpected, `host` is not a
        // prefix, and the submode head is an explicit refusal.
        let e = parse_policy_config("access-list A permit 10.0.0.0 0.255.255.255\n").unwrap_err();
        assert_eq!(e.line, 1);
        assert!(e.message.contains("unexpected token"), "{}", e.message);
        let e = parse_policy_config("access-list A permit host 10.0.0.1\n").unwrap_err();
        assert!(
            e.message.contains("invalid prefix `host`") || e.message.contains("unexpected token"),
            "{}",
            e.message
        );
        let e = parse_policy_config("ip access-list extended A\n").unwrap_err();
        assert!(e.message.contains("not supported"), "{}", e.message);
        let e = parse_policy_config("access-list A remark hello\n").unwrap_err();
        assert!(e.message.contains("permit|deny"), "{}", e.message);
    }
}
