//! The typed filter language: match terms, boolean combinators, and
//! `then { accept; reject; set ...; }` actions over a compiled rule
//! list. [W1-a M2]
//!
//! BIRD precedent (2.x user guide ch. 5): filters are a small language
//! with `if`/boolean operators and no loops; "Filter gets the route,
//! looks at its attributes and modifies some of them if it wishes. At
//! the end, it decides whether to pass the changed route through (using
//! accept) or whether to reject it" (§5.1). Rouster expresses that
//! language as a Rust API first (a parser for BIRD syntax is not built
//! here): terms are data, a [`Filter`] builds once and evaluates many
//! times.
//!
//! Purity model: BIRD rejects the route on a runtime filter error
//! (§5.1) and treats undefined `bgppath`/`*clist` attributes as empty
//! "for most purposes" (§5.5). Rouster's engine is *total*: every term
//! evaluates to a bool — absent attributes make BGP-dependent terms
//! false, path/community "emptiness" terms follow BIRD and treat
//! absent-as-empty. There is no runtime error path; deviation disclosed
//! in docs/protocols/policy.md.
//!
//! Hot path: evaluation walks compiled `&Term`/`&Action` trees and
//! mutates the caller's [`RouteData`] buffer in place — no allocation,
//! except `Action::PrependAsPath` growing the path and community
//! `Add`/`Replace` rewrites, which are attribute edits by nature.

use crate::asregex::AsRegex;
use crate::route::{AsPath, AsSegment, BgpOrigin, Community, RouteData};
use crate::sets::{
    AccessList, AsPathAccessList, AsSet, CommunityAccessList, CommunitySet, ExtCommunitySet,
    PrefixList, PrefixListVerdict, PrefixSet,
};
use common::RouteProtocol;

/// Terminal decision for a route.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Verdict {
    /// Pass the (possibly modified) route through — BIRD `accept`.
    Accept,
    /// Drop the route — BIRD `reject`.
    Reject,
}

impl Verdict {
    pub fn is_accept(self) -> bool {
        matches!(self, Verdict::Accept)
    }
}

/// Optional route attribute, for `defined()`-style tests (BIRD §5.5).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Attr {
    /// Any BGP attribute block present (BGP route).
    Bgp,
    /// LOCAL_PREF present.
    LocalPref,
    /// MULTI_EXIT_DISC present.
    Med,
    /// ORIGIN present.
    Origin,
    /// OTC present (RFC 9234).
    Otc,
    /// At least one standard community present.
    Communities,
    /// At least one extended community present.
    ExtCommunities,
}

/// One element of a BIRD-style path mask `[= ... =]` (§5.2 bgpmask):
/// "`*` matches any (even empty) sequence of arbitrary AS numbers and
/// `?` matches one arbitrary AS number", numbers match themselves, and
/// "You can also use ranges (e.g. `[= * 3..5 2 100..200 * =]`) and sets
/// (e.g. `[= 1 2 [3, 5, 7] * =]`)".
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MaskToken {
    /// `*` — any sequence (including empty).
    Any,
    /// `?` — exactly one arbitrary ASN.
    AnyOne,
    /// A literal ASN.
    As(u32),
    /// An inclusive ASN range `a..b`.
    Range(u32, u32),
    /// A set of ASNs — one position matches any member.
    Set(Vec<u32>),
    /// `2+` — one or more of the inner token (BIRD §5.2: "the `+`
    /// operator which matches one or multiple instances of previous
    /// expression").
    Repeat(Box<MaskToken>),
}

/// A BIRD-style AS-path mask, matched with `[= ... =]` semantics.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AsPathMask {
    tokens: Vec<MaskToken>,
}

impl AsPathMask {
    pub fn new(tokens: Vec<MaskToken>) -> Self {
        Self { tokens }
    }

    pub fn tokens(&self) -> &[MaskToken] {
        &self.tokens
    }

    /// Does the path match the mask? Flattened walk: AS_SET elements act
    /// as one position that matches any token their members satisfy.
    pub fn matches(&self, path: &AsPath) -> bool {
        let elems = flatten(path);
        mask_rec(&self.tokens, 0, &elems, 0)
    }
}

fn flatten(path: &AsPath) -> Vec<AsElem> {
    let mut v = Vec::new();
    for seg in path.segments() {
        match seg {
            AsSegment::Sequence(asns) => v.extend(asns.iter().map(|&a| AsElem::Asn(a))),
            AsSegment::Set(asns) => v.push(AsElem::Set(asns.clone())),
        }
    }
    v
}

enum AsElem {
    Asn(u32),
    Set(Vec<u32>),
}

impl AsElem {
    fn satisfies(&self, tok: &MaskToken) -> bool {
        let hit = |a: u32| match tok {
            MaskToken::Any | MaskToken::AnyOne => true,
            MaskToken::As(x) => a == *x,
            MaskToken::Range(lo, hi) => *lo <= a && a <= *hi,
            MaskToken::Set(s) => s.contains(&a),
            MaskToken::Repeat(_) => unreachable!("handled in mask_rec"),
        };
        match self {
            AsElem::Asn(a) => hit(*a),
            AsElem::Set(members) => members.iter().any(|&a| hit(a)),
        }
    }
}

fn mask_rec(toks: &[MaskToken], ti: usize, elems: &[AsElem], ei: usize) -> bool {
    if ti == toks.len() {
        return ei == elems.len();
    }
    match &toks[ti] {
        MaskToken::Any => {
            // Try consuming 0..remaining positions (greedy or lazy —
            // exhaustive, order irrelevant to the result).
            for skip in 0..=(elems.len() - ei) {
                if mask_rec(toks, ti + 1, elems, ei + skip) {
                    return true;
                }
            }
            false
        }
        MaskToken::Repeat(inner) => {
            // One or more positions satisfying `inner`.
            let mut k = 1usize;
            while ei + k <= elems.len() {
                let upto = ei + k;
                let all_sat = (ei..upto).all(|p| elems[p].satisfies(inner));
                if !all_sat {
                    break;
                }
                if mask_rec(toks, ti + 1, elems, upto) {
                    return true;
                }
                k += 1;
            }
            false
        }
        _ => {
            ei < elems.len()
                && elems[ei].satisfies(&toks[ti])
                && mask_rec(toks, ti + 1, elems, ei + 1)
        }
    }
}

/// How a `set community` action combines with existing communities
/// (FRR: `set community X` replaces; `set community X additive` appends;
/// `set comm-list delete L` removes; "set community none" clears).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CommMode {
    /// Replace the whole attribute.
    Replace,
    /// Append, keeping existing members (FRR `additive`).
    Add,
}

/// One action in a `then { ... }` block.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Action {
    /// Terminal: pass the route (BIRD `accept`).
    Accept,
    /// Terminal: drop the route (BIRD `reject`).
    Reject,
    /// Control flow: continue evaluation at rule `index` (route-map
    /// `continue N` analog; builder validates the target).
    Goto(usize),
    /// Invoke a compiled sub-filter (FRR route-map `call NAME`). A
    /// deny return finishes and denies the route; a permit return
    /// continues with the remaining actions (FRR 10.2 "Route Maps":
    /// "If it returns deny ... the route is denied, regardless of the
    /// Matching Policy or the Exit Policy"). The index resolves
    /// against the owning filter's `calls` table.
    Call(usize),
    SetLocalPref(u32),
    /// Add (or, for negative values, subtract with saturation) — FRR
    /// `set local-preference +N` / `-N`.
    AdjustLocalPref(i64),
    SetMed(u32),
    AdjustMed(i64),
    SetMetric(u32),
    SetOrigin(BgpOrigin),
    SetOtc(u32),
    /// Communities: set/add the listed members (FRR `set community`
    /// with/without `additive`; empty list + Replace = `none`).
    SetCommunities {
        list: Vec<Community>,
        mode: CommMode,
    },
    /// Remove every community matching the set (BIRD `C.delete(P)`;
    /// FRR `set comm-list delete`).
    RemoveCommunities(CommunitySet),
    /// Prepend `asn` `times` times (BIRD `P.prepend(A)`; FRR
    /// `set as-path prepend`).
    PrependAsPath {
        asn: u32,
        times: u16,
    },
}

impl Action {
    fn apply(&self, r: &mut RouteData) {
        match self {
            Action::Accept | Action::Reject | Action::Goto(_) | Action::Call(_) => {}
            Action::SetLocalPref(v) => r.bgp_or_materialize().local_pref = Some(*v),
            Action::AdjustLocalPref(d) => {
                let b = r.bgp_or_materialize();
                let base = b.local_pref.unwrap_or(0) as i64;
                b.local_pref = Some(adjust_u32(base, *d));
            }
            Action::SetMed(v) => r.bgp_or_materialize().med = Some(*v),
            Action::AdjustMed(d) => {
                let b = r.bgp_or_materialize();
                let base = b.med.unwrap_or(0) as i64;
                b.med = Some(adjust_u32(base, *d));
            }
            Action::SetMetric(v) => r.metric = *v,
            Action::SetOrigin(o) => r.bgp_or_materialize().origin = Some(*o),
            Action::SetOtc(v) => r.bgp_or_materialize().otc = Some(*v),
            Action::SetCommunities { list, mode } => {
                let b = r.bgp_or_materialize();
                match mode {
                    CommMode::Replace => {
                        b.communities = list.clone();
                    }
                    CommMode::Add => {
                        for c in list {
                            if !b.communities.contains(c) {
                                b.communities.push(*c);
                            }
                        }
                    }
                }
            }
            Action::RemoveCommunities(set) => {
                if let Some(b) = r.bgp.as_mut() {
                    b.communities = set.difference(&b.communities);
                }
            }
            Action::PrependAsPath { asn, times } => {
                r.bgp_or_materialize().as_path.prepend(*asn, *times);
            }
        }
    }
}

fn adjust_u32(base: i64, delta: i64) -> u32 {
    (base + delta).clamp(0, u32::MAX as i64) as u32
}

/// Index into the filter's named-set tables, handed out by
/// [`FilterBuilder`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SetIndex {
    /// Table discriminator.
    pub kind: SetKind,
    /// Position in that table.
    pub idx: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SetKind {
    Prefix,
    PrefixList,
    AccessList,
    As,
    Community,
    ExtCommunity,
    AsPathList,
    CommunityList,
}

/// A match term — one boolean node of the filter's `when` expression.
#[derive(Debug, Clone)]
pub enum Term {
    True,
    False,
    And(Vec<Term>),
    Or(Vec<Term>),
    Not(Box<Term>),
    /// `defined(attr)` (BIRD §5.5).
    Defined(Attr),
    /// Route prefix ∈ prefix-set, BIRD `net ~ set` (§5.3).
    PrefixIn(SetIndex),
    /// Route prefix carries the prefix-set's longest-match tag.
    PrefixTagIn(SetIndex, Vec<u32>),
    /// Prefix-length range, BIRD `/len {low,high}` analog.
    PrefixLen {
        min: u8,
        max: u8,
    },
    /// FRR-ordered prefix-list scan (first covering entry's verdict;
    /// no cover → false, i.e. the list's default deny).
    PrefixList(SetIndex),
    /// FRR-ordered zebra-style access-list scan (`match ip address
    /// ACL`): true iff the first covering entry (subnet-of by
    /// default, exact only on `exact-match`) is a permit.
    AccessList(SetIndex),
    /// BIRD path-mask match, `bgp_path ~ [= ... =]` (§5.2).
    PathMask(AsPathMask),
    /// FRR AS-path regex match (`bgp as-path access-list` operators).
    PathRegex(AsRegex),
    /// Any ASN of the path in the AS-set — BIRD "bgppath and int set"
    /// (§5.3).
    PathIn(SetIndex),
    /// ASN occurs in the path — BIRD "number and bgppath" (§5.3).
    PathContains(u32),
    /// Path length range (BIRD `bgp_path.len`).
    PathLen {
        min: usize,
        max: usize,
    },
    /// Path empty; undefined = empty for BGP-path purposes on non-BGP
    /// routes too (BIRD §5.5).
    PathEmpty,
    /// Any community matches the set (FRR `match community` "any").
    CommunityAny(SetIndex),
    /// Route communities are exactly the set's members (FRR
    /// `match community ... exact-match`).
    CommunityExact(SetIndex),
    /// No communities carried (undefined = empty, BIRD §5.5).
    CommunityEmpty,
    /// Any extended community matches.
    ExtCommunityAny(SetIndex),
    /// FRR-ordered AS-path access-list scan (`bgp as-path access-list`):
    /// true iff the first matching regex is a permit.
    PathList(SetIndex),
    /// FRR-ordered standard community-list scan (`match community LIST`
    /// default/any mode): true iff the first entry whose communities
    /// are all carried is a permit. Undefined (empty) communities
    /// follow BIRD §5.5 emptiness, so a bare `permit` entry matches
    /// community-less routes too.
    CommunityList(SetIndex),
    /// `match community LIST exact-match`: true iff some entry's
    /// community set equals the route's and that entry is a permit.
    CommunityListExact(SetIndex),
    /// Protocol test (BIRD `source`; FRR `match source-protocol`).
    ProtocolIn(Vec<RouteProtocol>),
    /// BGP ORIGIN test.
    OriginIn(Vec<BgpOrigin>),
    /// LOCAL_PREF range; absent → false.
    LocalPrefIn(u32, u32),
    /// MED range; absent → false.
    MedIn(u32, u32),
    /// OTC range (RFC 9234); absent → false.
    OtcIn(u32, u32),
    /// Route metric range (FRR `match metric`).
    MetricIn(u32, u32),
}

impl Term {
    /// Evaluate the term against the route — pure, total, allocation-free.
    pub fn matches(&self, r: &RouteData, sets: &SetTables) -> bool {
        match self {
            Term::True => true,
            Term::False => false,
            Term::And(v) => v.iter().all(|t| t.matches(r, sets)),
            Term::Or(v) => v.iter().any(|t| t.matches(r, sets)),
            Term::Not(t) => !t.matches(r, sets),
            Term::Defined(a) => match a {
                Attr::Bgp => r.bgp().is_some(),
                Attr::LocalPref => r.bgp().and_then(|b| b.local_pref).is_some(),
                Attr::Med => r.bgp().and_then(|b| b.med).is_some(),
                Attr::Origin => r.bgp().and_then(|b| b.origin).is_some(),
                Attr::Otc => r.bgp().and_then(|b| b.otc).is_some(),
                Attr::Communities => r.bgp().map(|b| !b.communities.is_empty()).unwrap_or(false),
                Attr::ExtCommunities => r
                    .bgp()
                    .map(|b| !b.ext_communities.is_empty())
                    .unwrap_or(false),
            },
            Term::PrefixIn(s) => sets
                .prefix(s.idx)
                .is_some_and(|p| p.matches(&r.prefix).matched),
            Term::PrefixTagIn(s, tags) => sets
                .prefix(s.idx)
                .and_then(|p| p.matches(&r.prefix).tag)
                .is_some_and(|t| tags.contains(&t)),
            Term::PrefixLen { min, max } => (*min..=*max).contains(&r.prefix_len()),
            Term::PrefixList(s) => sets
                .prefix_list(s.idx)
                .is_some_and(|pl| pl.first_match(&r.prefix) == Some(PrefixListVerdict::Permit)),
            Term::AccessList(s) => sets
                .access_list(s.idx)
                .is_some_and(|al| al.first_match(&r.prefix) == Some(PrefixListVerdict::Permit)),
            Term::PathMask(m) => r.bgp().is_some_and(|b| m.matches(&b.as_path)),
            Term::PathRegex(re) => r.bgp().is_some_and(|b| re.matches_path(&b.as_path)),
            Term::PathIn(s) => sets
                .as_set(s.idx)
                .is_some_and(|a| r.bgp().is_some_and(|b| a.intersects_path(&b.as_path))),
            Term::PathContains(a) => r.bgp().is_some_and(|b| b.as_path.contains(*a)),
            Term::PathLen { min, max } => r
                .bgp()
                .is_some_and(|b| (*min..=*max).contains(&b.as_path.len())),
            Term::PathEmpty => r.bgp().is_none_or(|b| b.as_path.is_empty()),
            Term::CommunityAny(s) => sets
                .community(s.idx)
                .is_some_and(|cs| r.bgp().is_some_and(|b| cs.intersects(&b.communities))),
            Term::CommunityExact(s) => sets.community(s.idx).is_some_and(|cs| {
                r.bgp().is_some_and(|b| {
                    // Every route community must be in the set and vice
                    // versa — set equality with pattern members.
                    !b.communities.is_empty() && {
                        let mut left = b.communities.clone();
                        left.sort_unstable();
                        left.dedup();
                        let mut right: Vec<Community> = cs
                            .patterns()
                            .iter()
                            .filter_map(|p| p.asn.map(|a| Community::Pair(a, p.value_lo)))
                            .collect();
                        for w in cs.well_known() {
                            right.push(Community::WellKnown(*w));
                        }
                        right.sort_unstable();
                        right.dedup();
                        left == right
                    }
                })
            }),
            Term::CommunityEmpty => r.bgp().is_none_or(|b| b.communities.is_empty()),
            Term::ExtCommunityAny(s) => sets
                .ext_community(s.idx)
                .is_some_and(|es| r.bgp().is_some_and(|b| es.intersects(&b.ext_communities))),
            Term::PathList(s) => sets.as_path_list(s.idx).is_some_and(|l| {
                r.bgp()
                    .is_some_and(|b| l.first_match(&b.as_path) == Some(true))
            }),
            Term::CommunityList(s) => sets
                .community_list(s.idx)
                .is_some_and(|l| l.first_match(empty_when_no_bgp(r)) == Some(true)),
            Term::CommunityListExact(s) => sets
                .community_list(s.idx)
                .is_some_and(|l| l.exact_match(empty_when_no_bgp(r)) == Some(true)),
            Term::ProtocolIn(v) => v.contains(&r.protocol),
            Term::OriginIn(v) => r
                .bgp()
                .and_then(|b| b.origin)
                .is_some_and(|o| v.contains(&o)),
            Term::LocalPrefIn(lo, hi) => r
                .bgp()
                .and_then(|b| b.local_pref)
                .is_some_and(|v| (*lo..=*hi).contains(&v)),
            Term::MedIn(lo, hi) => r
                .bgp()
                .and_then(|b| b.med)
                .is_some_and(|v| (*lo..=*hi).contains(&v)),
            Term::OtcIn(lo, hi) => r
                .bgp()
                .and_then(|b| b.otc)
                .is_some_and(|v| (*lo..=*hi).contains(&v)),
            Term::MetricIn(lo, hi) => (*lo..=*hi).contains(&r.metric),
        }
    }
}

/// Communities of the route, absent-as-empty for non-BGP routes (BIRD
/// §5.5 undefined-clist emptiness).
fn empty_when_no_bgp(r: &RouteData) -> &[Community] {
    static EMPTY: [Community; 0] = [];
    r.bgp().map_or(&EMPTY, |b| &b.communities)
}

/// The named-set tables a compiled filter closes over.
#[derive(Debug, Clone, Default)]
pub struct SetTables {
    prefix: Vec<PrefixSet>,
    prefix_lists: Vec<PrefixList>,
    access_lists: Vec<AccessList>,
    as_sets: Vec<AsSet>,
    communities: Vec<CommunitySet>,
    ext_communities: Vec<ExtCommunitySet>,
    as_path_lists: Vec<AsPathAccessList>,
    community_lists: Vec<CommunityAccessList>,
}

impl SetTables {
    fn prefix(&self, i: usize) -> Option<&PrefixSet> {
        self.prefix.get(i)
    }

    fn prefix_list(&self, i: usize) -> Option<&PrefixList> {
        self.prefix_lists.get(i)
    }

    fn access_list(&self, i: usize) -> Option<&AccessList> {
        self.access_lists.get(i)
    }

    fn as_set(&self, i: usize) -> Option<&AsSet> {
        self.as_sets.get(i)
    }

    fn community(&self, i: usize) -> Option<&CommunitySet> {
        self.communities.get(i)
    }

    fn ext_community(&self, i: usize) -> Option<&ExtCommunitySet> {
        self.ext_communities.get(i)
    }

    fn as_path_list(&self, i: usize) -> Option<&AsPathAccessList> {
        self.as_path_lists.get(i)
    }

    fn community_list(&self, i: usize) -> Option<&CommunityAccessList> {
        self.community_lists.get(i)
    }
}

/// One rule: `when term then actions`.
#[derive(Debug, Clone)]
pub struct Rule {
    pub when: Term,
    pub then: Vec<Action>,
}

/// A compiled filter: rule list + closed-over sets + default verdict.
///
/// Evaluation order (the FRR route-map execution model, which subsumes
/// BIRD's if/then): rules run top-down; a rule whose `when` holds runs
/// its `then` actions in order — `Accept`/`Reject` terminate, `Goto(i)`
/// jumps forward to rule `i` (validated at build time), anything else
/// mutates the route; falling off the action list or an unmatched rule
/// advances to the next rule. No match anywhere → `default`
/// (BIRD-style filters should end in an explicit accept/reject; the
/// route-map compiler sets `Reject` per FRR's implicit deny-all).
#[derive(Debug, Clone)]
pub struct Filter {
    rules: Vec<Rule>,
    sets: SetTables,
    default: Verdict,
    /// Compiled sub-filters for `Action::Call` (FRR route-map `call`).
    /// Cycles are rejected at compile time, so recursion here is
    /// bounded by the (acyclic) call graph.
    calls: Vec<Filter>,
}

impl Filter {
    /// Evaluate: mutate `route` in place, return the verdict. Pure with
    /// respect to the filter; deterministic.
    pub fn apply(&self, route: &mut RouteData) -> Verdict {
        let mut i = 0usize;
        'outer: while i < self.rules.len() {
            let rule = &self.rules[i];
            if rule.when.matches(route, &self.sets) {
                for a in &rule.then {
                    match a {
                        Action::Accept => return Verdict::Accept,
                        Action::Reject => return Verdict::Reject,
                        Action::Goto(j) => {
                            i = *j;
                            continue 'outer;
                        }
                        Action::Call(idx) => {
                            // Deny return finishes and denies (FRR
                            // `call`); permit return falls through to
                            // the remaining actions. A dangling index
                            // (builder hands out only valid ones) fails
                            // closed, like dangling set indices.
                            match self.calls.get(*idx) {
                                Some(sub) => {
                                    if sub.apply(route) == Verdict::Reject {
                                        return Verdict::Reject;
                                    }
                                }
                                None => return Verdict::Reject,
                            }
                        }
                        _ => a.apply(route),
                    }
                }
            }
            i += 1;
        }
        self.default
    }

    /// Default verdict when no rule matched (or none terminated).
    pub fn default_verdict(&self) -> Verdict {
        self.default
    }

    pub fn rules(&self) -> &[Rule] {
        &self.rules
    }
}

/// Builds a filter: register named sets, add rules, finish. Validates
/// `Goto` targets (in range, strictly forward) so evaluation cannot
/// loop.
#[derive(Debug, Clone)]
pub struct FilterBuilder {
    rules: Vec<Rule>,
    sets: SetTables,
    default: Verdict,
    calls: Vec<Filter>,
}

impl Default for FilterBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl FilterBuilder {
    pub fn new() -> Self {
        Self {
            rules: Vec::new(),
            sets: SetTables::default(),
            default: Verdict::Reject,
            calls: Vec::new(),
        }
    }

    /// Override the default verdict (implicit final accept/reject).
    pub fn default_verdict(mut self, v: Verdict) -> Self {
        self.default = v;
        self
    }

    pub fn add_prefix_set(&mut self, set: PrefixSet) -> SetIndex {
        self.sets.prefix.push(set);
        SetIndex {
            kind: SetKind::Prefix,
            idx: self.sets.prefix.len() - 1,
        }
    }

    pub fn add_prefix_list(&mut self, list: PrefixList) -> SetIndex {
        self.sets.prefix_lists.push(list);
        SetIndex {
            kind: SetKind::PrefixList,
            idx: self.sets.prefix_lists.len() - 1,
        }
    }

    pub fn add_access_list(&mut self, list: AccessList) -> SetIndex {
        self.sets.access_lists.push(list);
        SetIndex {
            kind: SetKind::AccessList,
            idx: self.sets.access_lists.len() - 1,
        }
    }

    /// Register a compiled sub-filter for `Action::Call` (FRR
    /// route-map `call NAME`). The returned index is what
    /// `Action::Call` carries; the callee must be built (its own
    /// control flow validated) before being registered — cycles are
    /// the caller-compiler's responsibility to reject.
    pub fn add_call(&mut self, filter: Filter) -> usize {
        self.calls.push(filter);
        self.calls.len() - 1
    }

    pub fn add_as_set(&mut self, set: AsSet) -> SetIndex {
        self.sets.as_sets.push(set);
        SetIndex {
            kind: SetKind::As,
            idx: self.sets.as_sets.len() - 1,
        }
    }

    pub fn add_community_set(&mut self, set: CommunitySet) -> SetIndex {
        self.sets.communities.push(set);
        SetIndex {
            kind: SetKind::Community,
            idx: self.sets.communities.len() - 1,
        }
    }

    pub fn add_ext_community_set(&mut self, set: ExtCommunitySet) -> SetIndex {
        self.sets.ext_communities.push(set);
        SetIndex {
            kind: SetKind::ExtCommunity,
            idx: self.sets.ext_communities.len() - 1,
        }
    }

    pub fn add_as_path_list(&mut self, list: AsPathAccessList) -> SetIndex {
        self.sets.as_path_lists.push(list);
        SetIndex {
            kind: SetKind::AsPathList,
            idx: self.sets.as_path_lists.len() - 1,
        }
    }

    pub fn add_community_list(&mut self, list: CommunityAccessList) -> SetIndex {
        self.sets.community_lists.push(list);
        SetIndex {
            kind: SetKind::CommunityList,
            idx: self.sets.community_lists.len() - 1,
        }
    }

    /// Append a rule.
    pub fn add_rule(&mut self, when: Term, then: Vec<Action>) {
        self.rules.push(Rule { when, then });
    }

    /// Compile, validating control flow. FRR: "Jumping to a previous
    /// entry is not permitted" (Route Maps — Exit Policy); we reject
    /// non-forward gotos and equal-index self-targets as build errors.
    pub fn build(self) -> Result<Filter, String> {
        for (i, rule) in self.rules.iter().enumerate() {
            for a in &rule.then {
                if let Action::Goto(j) = a {
                    if *j >= self.rules.len() {
                        return Err(format!(
                            "rule {i}: goto target {j} out of range ({} rules)",
                            self.rules.len()
                        ));
                    }
                    if *j <= i {
                        return Err(format!(
                            "rule {i}: goto target {j} is not a later rule (FRR: backwards jumps not permitted)"
                        ));
                    }
                }
            }
        }
        Ok(Filter {
            rules: self.rules,
            sets: self.sets,
            default: self.default,
            calls: self.calls,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::route::testutil::{v4_route, v6_route};
    use crate::route::WellKnownCommunity;
    use crate::sets::{
        AccessList, AccessListEntry, CommunityPattern, PrefixListEntry, PrefixPattern,
    };
    use common::IpPrefix;

    fn prefix(s: &str) -> IpPrefix {
        s.parse().unwrap()
    }

    fn build(when: Term, then: Vec<Action>) -> Filter {
        let mut b = FilterBuilder::new();
        b.add_rule(when, then);
        b.build().unwrap()
    }

    #[test]
    fn accept_reject_and_defaults() {
        let f = build(Term::True, vec![Action::Accept]);
        let mut r = v4_route("192.0.2.0/24", &[65001]);
        assert_eq!(f.apply(&mut r), Verdict::Accept);

        let f = build(Term::False, vec![Action::Accept]);
        assert_eq!(
            f.apply(&mut r),
            Verdict::Reject,
            "no rule matched → default reject"
        );

        let mut b = FilterBuilder::new();
        b.add_rule(Term::False, vec![Action::Accept]);
        let f = b.default_verdict(Verdict::Accept).build().unwrap();
        assert_eq!(f.apply(&mut r), Verdict::Accept, "explicit default accept");
    }

    #[test]
    fn bird_doc_mask_examples() {
        // BIRD §5.2: path 4 3 2 1 → `* 4 3 *` true, `* 4 5 *` false.
        let p = AsPath::from_sequence(&[4, 3, 2, 1]);
        let m1 = AsPathMask::new(vec![
            MaskToken::Any,
            MaskToken::As(4),
            MaskToken::As(3),
            MaskToken::Any,
        ]);
        let m2 = AsPathMask::new(vec![
            MaskToken::Any,
            MaskToken::As(4),
            MaskToken::As(5),
            MaskToken::Any,
        ]);
        assert!(m1.matches(&p));
        assert!(!m2.matches(&p));
        // BIRD §5.2 `[= 1 2+ 3 =]`: "matches both path 1 2 3 and path
        // 1 2 2 2 3, but not 1 3 nor 1 2 4 3."
        let m3 = AsPathMask::new(vec![
            MaskToken::As(1),
            MaskToken::Repeat(Box::new(MaskToken::As(2))),
            MaskToken::As(3),
        ]);
        assert!(m3.matches(&AsPath::from_sequence(&[1, 2, 3])));
        assert!(m3.matches(&AsPath::from_sequence(&[1, 2, 2, 2, 3])));
        assert!(!m3.matches(&AsPath::from_sequence(&[1, 3])));
        assert!(!m3.matches(&AsPath::from_sequence(&[1, 2, 4, 3])));
    }

    #[test]
    fn mask_ranges_sets_and_question() {
        // BIRD §5.2: `[= * 3..5 2 100..200 * =]`, `[= 1 2 [3,5,7] * =]`.
        let m = AsPathMask::new(vec![
            MaskToken::Any,
            MaskToken::Range(3, 5),
            MaskToken::As(2),
            MaskToken::Range(100, 200),
            MaskToken::Any,
        ]);
        assert!(m.matches(&AsPath::from_sequence(&[4, 2, 150])));
        assert!(!m.matches(&AsPath::from_sequence(&[4, 2, 250])));
        let s = AsPathMask::new(vec![
            MaskToken::As(1),
            MaskToken::As(2),
            MaskToken::Set(vec![3, 5, 7]),
            MaskToken::Any,
        ]);
        assert!(s.matches(&AsPath::from_sequence(&[1, 2, 7])));
        assert!(!s.matches(&AsPath::from_sequence(&[1, 2, 4])));
        let q = AsPathMask::new(vec![MaskToken::As(1), MaskToken::AnyOne, MaskToken::As(3)]);
        assert!(q.matches(&AsPath::from_sequence(&[1, 99, 3])));
        assert!(!q.matches(&AsPath::from_sequence(&[1, 3])));
    }

    #[test]
    fn mask_against_as_set_element() {
        let p = AsPath::from_segments(vec![
            AsSegment::Sequence(vec![65001]),
            AsSegment::Set(vec![65100, 65101]),
            AsSegment::Sequence(vec![65002]),
        ]);
        let m = AsPathMask::new(vec![
            MaskToken::As(65001),
            MaskToken::Range(65100, 65100),
            MaskToken::As(65002),
        ]);
        assert!(m.matches(&p), "a set position matches if any member does");
        let m2 = AsPathMask::new(vec![
            MaskToken::As(65001),
            MaskToken::AnyOne,
            MaskToken::As(65002),
        ]);
        assert!(m2.matches(&p));
    }

    #[test]
    fn prefix_and_len_terms() {
        let mut b = FilterBuilder::new();
        let s = b.add_prefix_set(PrefixSet::from_patterns(vec![PrefixPattern::or_longer(
            prefix("10.0.0.0/8"),
        )
        .with_tag(7)]));
        b.add_rule(
            Term::And(vec![Term::PrefixIn(s), Term::PrefixTagIn(s, vec![7])]),
            vec![Action::Accept],
        );
        b.add_rule(Term::PrefixLen { min: 8, max: 16 }, vec![Action::Accept]);
        let f = b.build().unwrap();
        let mut r = v4_route("10.1.0.0/16", &[65001]);
        assert_eq!(f.apply(&mut r), Verdict::Accept, "tagged 10/8 member");
        let mut r = v4_route("192.0.2.0/24", &[65001]);
        assert_eq!(
            f.apply(&mut r),
            Verdict::Reject,
            "/24 outside 10/8 and outside len 8..16 → default reject"
        );
    }

    #[test]
    fn prefix_len_range_term_arithmetic() {
        let f = build(Term::PrefixLen { min: 8, max: 16 }, vec![Action::Accept]);
        let mut r16 = v4_route("10.1.0.0/16", &[]);
        assert_eq!(f.apply(&mut r16), Verdict::Accept);
        let mut r24 = v4_route("192.0.2.0/24", &[]);
        assert_eq!(f.apply(&mut r24), Verdict::Reject);
        let mut r128 = v6_route("2001:db8::/48", &[]);
        assert_eq!(f.apply(&mut r128), Verdict::Reject);
    }

    #[test]
    fn prefix_list_term_uses_frr_order() {
        let mut pl = PrefixList::new();
        pl.insert(PrefixListEntry {
            seq: 5,
            verdict: PrefixListVerdict::Deny,
            pattern: PrefixPattern::or_longer(prefix("10.0.0.0/8")),
        });
        pl.insert(PrefixListEntry {
            seq: 10,
            verdict: PrefixListVerdict::Permit,
            pattern: PrefixPattern::or_longer(prefix("10.42.0.0/16")),
        });
        let mut b = FilterBuilder::new();
        let idx = b.add_prefix_list(pl);
        b.add_rule(Term::PrefixList(idx), vec![Action::Accept]);
        let f = b.build().unwrap();
        let mut r = v4_route("10.42.0.0/24", &[]);
        assert_eq!(f.apply(&mut r), Verdict::Reject, "seq 5 deny wins first");
        let mut r = v4_route("192.0.2.0/24", &[]);
        assert_eq!(f.apply(&mut r), Verdict::Reject, "no match → default deny");
    }

    #[test]
    fn access_list_term_uses_subnet_of_default() {
        // The access-list coverage default is the inverse of the
        // prefix-list's: subnet-of unless exact-match.
        let mut al = AccessList::new();
        al.insert(AccessListEntry {
            seq: 5,
            verdict: PrefixListVerdict::Permit,
            pattern: PrefixPattern::or_longer(prefix("10.0.0.0/8")),
        });
        let mut b = FilterBuilder::new();
        let idx = b.add_access_list(al);
        b.add_rule(Term::AccessList(idx), vec![Action::Accept]);
        let f = b.build().unwrap();
        let mut r = v4_route("10.1.0.0/16", &[]);
        assert_eq!(f.apply(&mut r), Verdict::Accept, "subnet covered");
        let mut r = v4_route("10.0.0.0/7", &[]);
        assert_eq!(f.apply(&mut r), Verdict::Reject, "supernet not covered");
    }

    #[test]
    fn call_action_deny_short_circuits_and_permit_continues() {
        // FRR `call`: deny return finishes and denies regardless of
        // the caller's exit policy; permit return proceeds.
        let deny_all = {
            let mut b = FilterBuilder::new();
            b.add_rule(Term::False, vec![Action::Accept]);
            b.build().unwrap() // no rule matches → default reject
        };
        let permit_all = {
            let mut b = FilterBuilder::new();
            b.add_rule(Term::True, vec![Action::Accept]);
            b.build().unwrap()
        };

        let mut b = FilterBuilder::new();
        let deny_idx = b.add_call(deny_all);
        b.add_rule(
            Term::True,
            vec![
                Action::SetLocalPref(111),
                Action::Call(deny_idx),
                Action::Accept,
            ],
        );
        let f = b.build().unwrap();
        let mut r = v4_route("192.0.2.0/24", &[]);
        assert_eq!(f.apply(&mut r), Verdict::Reject, "deny return wins");
        assert_eq!(
            r.bgp().map(|b| b.local_pref),
            Some(Some(111)),
            "sets before the call still applied"
        );

        let mut b2 = FilterBuilder::new();
        let permit_idx = b2.add_call(permit_all);
        b2.add_rule(
            Term::True,
            vec![
                Action::SetLocalPref(222),
                Action::Call(permit_idx),
                Action::Accept,
            ],
        );
        let f2 = b2.build().unwrap();
        let mut r2 = v4_route("192.0.2.0/24", &[]);
        assert_eq!(
            f2.apply(&mut r2),
            Verdict::Accept,
            "permit return continues"
        );
        assert_eq!(r2.bgp().unwrap().local_pref, Some(222));

        // Dangling call index fails closed (builder never hands these
        // out; defense in depth).
        let mut b3 = FilterBuilder::new();
        b3.add_rule(Term::True, vec![Action::Call(99), Action::Accept]);
        let f3 = b3.build().unwrap();
        let mut r3 = v4_route("192.0.2.0/24", &[]);
        assert_eq!(f3.apply(&mut r3), Verdict::Reject);
    }

    #[test]
    fn community_terms() {
        let mut cs = CommunitySet::new();
        cs.add_pattern(CommunityPattern::exact(65000, 100));
        cs.add_well_known(WellKnownCommunity::NoExport);
        let mut b = FilterBuilder::new();
        let c = b.add_community_set(cs);
        b.add_rule(Term::CommunityAny(c), vec![Action::Accept]);
        let f_any = b.build().unwrap();
        let mut r = v4_route("192.0.2.0/24", &[65001]);
        r.bgp_or_materialize().communities = vec![Community::Pair(65000, 100)];
        assert_eq!(f_any.apply(&mut r), Verdict::Accept);
        r.bgp_or_materialize().communities = vec![Community::Pair(65000, 999)];
        assert_eq!(f_any.apply(&mut r), Verdict::Reject);

        // exact-match: route set must equal list set.
        let mut cs2 = CommunitySet::new();
        cs2.add_pattern(CommunityPattern::exact(65000, 1));
        cs2.add_pattern(CommunityPattern::exact(65000, 2));
        let mut b2 = FilterBuilder::new();
        let c2 = b2.add_community_set(cs2);
        b2.add_rule(Term::CommunityExact(c2), vec![Action::Accept]);
        let f_exact = b2.build().unwrap();
        r.bgp_or_materialize().communities =
            vec![Community::Pair(65000, 1), Community::Pair(65000, 2)];
        assert_eq!(f_exact.apply(&mut r), Verdict::Accept);
        r.bgp_or_materialize().communities = vec![Community::Pair(65000, 1)];
        assert_eq!(
            f_exact.apply(&mut r),
            Verdict::Reject,
            "subset is not exact"
        );
        // empty route communities: exact-match requires non-empty
        r.bgp_or_materialize().communities = vec![];
        assert_eq!(f_exact.apply(&mut r), Verdict::Reject);
    }

    #[test]
    fn undefined_attrs_follow_bird_emptiness() {
        // Non-BGP route: path/clist "undefined = empty" (BIRD §5.5).
        let mut r = v4_route("192.0.2.0/24", &[]);
        r.bgp = None;
        let t_empty = Term::PathEmpty;
        let sets = SetTables::default();
        assert!(t_empty.matches(&r, &sets));
        assert!(Term::CommunityEmpty.matches(&r, &sets));
        assert!(!Term::PathContains(65001).matches(&r, &sets));
        assert!(!Term::Defined(Attr::Bgp).matches(&r, &sets));
        assert!(!Term::LocalPrefIn(0, u32::MAX).matches(&r, &sets));
        // BGP route with empty path: also empty.
        let r2 = v4_route("192.0.2.0/24", &[]);
        assert!(Term::PathEmpty.matches(&r2, &sets));
    }

    #[test]
    fn set_actions_modify_route() {
        let f = build(
            Term::True,
            vec![
                Action::SetLocalPref(200),
                Action::AdjustLocalPref(50),
                Action::SetMed(10),
                Action::AdjustMed(-3),
                Action::SetOrigin(BgpOrigin::Egp),
                Action::SetOtc(64512),
                Action::SetCommunities {
                    list: vec![Community::Pair(65000, 1)],
                    mode: CommMode::Replace,
                },
                Action::SetCommunities {
                    list: vec![Community::Pair(65000, 2), Community::Pair(65000, 1)],
                    mode: CommMode::Add,
                },
                Action::Accept,
            ],
        );
        let mut r = v4_route("192.0.2.0/24", &[65001]);
        assert_eq!(f.apply(&mut r), Verdict::Accept);
        let b = r.bgp().unwrap();
        assert_eq!(b.local_pref, Some(250));
        assert_eq!(b.med, Some(7));
        assert_eq!(b.origin, Some(BgpOrigin::Egp));
        assert_eq!(b.otc, Some(64512));
        assert_eq!(
            b.communities,
            vec![Community::Pair(65000, 1), Community::Pair(65000, 2)],
            "replace then add, no duplicates"
        );
    }

    #[test]
    fn community_remove_and_clear() {
        let mut cs = CommunitySet::new();
        cs.add_pattern(CommunityPattern::any_value(65000));
        let f = build(
            Term::True,
            vec![Action::RemoveCommunities(cs), Action::Accept],
        );
        let mut r = v4_route("192.0.2.0/24", &[65001]);
        r.bgp_or_materialize().communities =
            vec![Community::Pair(65000, 1), Community::Pair(65001, 9)];
        f.apply(&mut r);
        assert_eq!(
            r.bgp().unwrap().communities,
            vec![Community::Pair(65001, 9)]
        );

        let clear = build(
            Term::True,
            vec![Action::SetCommunities {
                list: vec![],
                mode: CommMode::Replace,
            }],
        );
        clear.apply(&mut r);
        assert!(r.bgp().unwrap().communities.is_empty(), "none clears");
    }

    #[test]
    fn prepend_and_metric() {
        let f = build(
            Term::True,
            vec![
                Action::PrependAsPath {
                    asn: 65000,
                    times: 2,
                },
                Action::SetMetric(42),
                Action::Accept,
            ],
        );
        let mut r = v4_route("192.0.2.0/24", &[65001, 65002]);
        f.apply(&mut r);
        assert_eq!(r.bgp().unwrap().as_path.render(), "65000 65000 65001 65002");
        assert_eq!(r.metric, 42);
    }

    #[test]
    fn adjust_saturates() {
        let f = build(
            Term::True,
            vec![Action::AdjustLocalPref(-500), Action::Accept],
        );
        let mut r = v4_route("192.0.2.0/24", &[]);
        r.bgp_or_materialize().local_pref = Some(100);
        f.apply(&mut r);
        assert_eq!(r.bgp().unwrap().local_pref, Some(0));
    }

    #[test]
    fn goto_forward_and_validation() {
        let mut b = FilterBuilder::new();
        b.add_rule(Term::True, vec![Action::SetLocalPref(111), Action::Goto(2)]);
        b.add_rule(Term::True, vec![Action::Reject]);
        b.add_rule(Term::True, vec![Action::Accept]);
        let f = b.build().unwrap();
        let mut r = v4_route("192.0.2.0/24", &[]);
        assert_eq!(f.apply(&mut r), Verdict::Accept);
        assert_eq!(r.bgp().unwrap().local_pref, Some(111));

        let mut bad = FilterBuilder::new();
        bad.add_rule(Term::True, vec![Action::Goto(0)]);
        assert!(bad.build().is_err(), "self-goto rejected");

        let mut bad2 = FilterBuilder::new();
        bad2.add_rule(Term::True, vec![Action::Goto(5)]);
        assert!(bad2.build().is_err(), "out-of-range goto rejected");

        let mut bad3 = FilterBuilder::new();
        bad3.add_rule(Term::True, vec![Action::Goto(1)]);
        bad3.add_rule(Term::True, vec![Action::Goto(0)]);
        assert!(
            bad3.build().is_err(),
            "backwards goto rejected (FRR exit policy)"
        );
    }

    #[test]
    fn actions_on_non_bgp_materialize() {
        let f = build(Term::True, vec![Action::SetLocalPref(100), Action::Accept]);
        let mut r = v4_route("203.0.113.0/24", &[]);
        r.bgp = None;
        r.protocol = common::RouteProtocol::Static;
        assert_eq!(f.apply(&mut r), Verdict::Accept);
        let b = r.bgp().expect("attrs materialized");
        assert_eq!(b.local_pref, Some(100));
        assert_eq!(b.origin, Some(BgpOrigin::Incomplete));
    }

    #[test]
    fn protocol_and_origin_terms() {
        use common::RouteProtocol as Rp;
        let f = build(
            Term::ProtocolIn(vec![Rp::Static, Rp::Bgp]),
            vec![Action::Accept],
        );
        let mut r = v4_route("192.0.2.0/24", &[]);
        r.protocol = Rp::Static;
        assert_eq!(f.apply(&mut r), Verdict::Accept);
        r.protocol = Rp::Ospf;
        assert_eq!(f.apply(&mut r), Verdict::Reject);

        let g = build(
            Term::OriginIn(vec![BgpOrigin::Incomplete]),
            vec![Action::Accept],
        );
        let mut r2 = v4_route("192.0.2.0/24", &[]);
        r2.bgp_or_materialize().origin = Some(BgpOrigin::Incomplete);
        assert_eq!(g.apply(&mut r2), Verdict::Accept);
        r2.bgp_or_materialize().origin = Some(BgpOrigin::Igp);
        assert_eq!(g.apply(&mut r2), Verdict::Reject);
    }

    #[test]
    fn regex_and_as_set_terms() {
        let re = AsRegex::new("^65001_").unwrap();
        let mut as_set = AsSet::new();
        as_set.insert_range(64512, 64520);
        let mut b = FilterBuilder::new();
        let s = b.add_as_set(as_set);
        b.add_rule(
            Term::And(vec![
                Term::PathRegex(re),
                Term::Not(Box::new(Term::PathIn(s))),
            ]),
            vec![Action::Accept],
        );
        let f = b.build().unwrap();
        let mut r = v4_route("192.0.2.0/24", &[65001, 65002]);
        assert_eq!(f.apply(&mut r), Verdict::Accept);
        let mut r2 = v4_route("192.0.2.0/24", &[65001, 64515]);
        assert_eq!(f.apply(&mut r2), Verdict::Reject, "private ASN in path");
    }

    #[test]
    fn boolean_combinators_short_circuit_shape() {
        let t = Term::And(vec![
            Term::Or(vec![Term::False, Term::True]),
            Term::Not(Box::new(Term::False)),
        ]);
        let f = build(t, vec![Action::Accept]);
        let mut r = v4_route("192.0.2.0/24", &[]);
        assert_eq!(f.apply(&mut r), Verdict::Accept);
    }

    #[test]
    fn missing_set_index_fails_closed() {
        // A fabricated dangling index evaluates false (defense in depth;
        // builder hands out only valid indices).
        let t = Term::PrefixIn(SetIndex {
            kind: SetKind::Prefix,
            idx: 99,
        });
        let f = build(t, vec![Action::Accept]);
        let mut r = v4_route("192.0.2.0/24", &[]);
        assert_eq!(f.apply(&mut r), Verdict::Reject);
    }

    #[test]
    fn filter_is_deterministic_across_runs() {
        let mut b = FilterBuilder::new();
        let cs_idx = b.add_community_set({
            let mut cs = CommunitySet::new();
            cs.add_pattern(CommunityPattern::value_range(65000, 100, 199));
            cs
        });
        let ps_idx = b.add_prefix_set(PrefixSet::from_patterns(vec![PrefixPattern::or_longer(
            prefix("10.0.0.0/8"),
        )]));
        b.add_rule(
            Term::And(vec![Term::PrefixIn(ps_idx), Term::CommunityAny(cs_idx)]),
            vec![
                Action::SetLocalPref(300),
                Action::PrependAsPath {
                    asn: 65000,
                    times: 1,
                },
                Action::Accept,
            ],
        );
        b.add_rule(Term::PathEmpty, vec![Action::Reject]);
        let f = b.build().unwrap();
        let mk = || {
            let mut r = v4_route("10.9.9.0/24", &[65001]);
            r.bgp_or_materialize().communities = vec![Community::Pair(65000, 150)];
            r
        };
        let mut a = mk();
        let mut c1 = mk();
        let mut c2 = mk();
        let v1 = f.apply(&mut a);
        assert_eq!(v1, f.apply(&mut c1));
        assert_eq!(v1, f.apply(&mut c2));
        assert_eq!(c1, c2, "identical inputs → identical outputs");
    }
}
