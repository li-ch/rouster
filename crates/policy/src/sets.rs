//! Sets as data: named prefix-sets / AS-sets / community-sets, plus the
//! FRR-style ordered prefix-list the route-map compat layer compiles
//! against. [W1-a M3]
//!
//! BIRD precedent for prefix-set patterns (2.x user guide ch. 5 §5.2):
//! "Prefix ip1/len1 matches prefix pattern ip2/len2{l,h} if the first
//! min(len1, len2) bits of ip1 and ip2 are identical and l <= len1 <= h",
//! with `addr/len+` ≡ `addr/len{len,maxlen}` and `addr/len-` ≡
//! `addr/len{0,len}`. Longest-match tag annotation is Rouster's addition
//! (BIRD's `define` names constants; we tag entries) so a classifier set
//! can answer "which entry won".

use crate::route::{max_plen, AsPath, Community, ExtCommunity, WellKnownCommunity};
use common::IpPrefix;
use std::collections::HashMap;
use std::fmt;

/// Result of asking a prefix-set about a prefix.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PrefixMatch {
    /// True when any pattern covers the prefix.
    pub matched: bool,
    /// Longest-match tag of the winning pattern (most specific network;
    /// ties broken by declaration order — earliest wins).
    pub tag: Option<u32>,
}

/// One prefix-set pattern: `ip/len{low,high}` semantics (BIRD §5.2).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PrefixPattern {
    /// Pattern network.
    pub prefix: IpPrefix,
    /// Minimum prefix length a route must have (inclusive).
    pub min_len: u8,
    /// Maximum prefix length a route may have (inclusive).
    pub max_len: u8,
    /// Longest-match annotation (BIRD `define` analog).
    pub tag: Option<u32>,
}

impl PrefixPattern {
    /// Exact prefix (equivalent to BIRD `ip/len` with no `{low,high}`).
    pub fn exact(prefix: IpPrefix) -> Self {
        let len = crate::route::plen(&prefix);
        Self {
            prefix,
            min_len: len,
            max_len: len,
            tag: None,
        }
    }

    /// `addr/len+`: the network and all subnets (BIRD §5.2 shorthand).
    pub fn or_longer(prefix: IpPrefix) -> Self {
        let len = crate::route::plen(&prefix);
        Self {
            prefix,
            min_len: len,
            max_len: max_plen(&prefix),
            tag: None,
        }
    }

    /// `addr/len{low,high}` (BIRD §5.2); panics via builder validation
    /// instead — kept `try`-shaped for construction from config.
    pub fn range(prefix: IpPrefix, min_len: u8, max_len: u8) -> Result<Self, String> {
        let m = max_plen(&prefix);
        if min_len > max_len {
            return Err(format!(
                "prefix pattern {prefix}: low {min_len} greater than high {max_len}"
            ));
        }
        if max_len > m {
            return Err(format!(
                "prefix pattern {prefix}: high {max_len} exceeds family max {m}"
            ));
        }
        Ok(Self {
            prefix,
            min_len,
            max_len,
            tag: None,
        })
    }

    /// Attach the longest-match tag.
    pub fn with_tag(mut self, tag: u32) -> Self {
        self.tag = Some(tag);
        self
    }

    /// Does this pattern cover `prefix`? BIRD §5.2: "Prefix ip1/len1
    /// matches prefix pattern ip2/len2{l,h} if the first min(len1,
    /// len2) bits of ip1 and ip2 are identical and l <= len1 <= h."
    pub fn covers(&self, prefix: &IpPrefix) -> bool {
        if std::mem::discriminant(&self.prefix) != std::mem::discriminant(prefix) {
            return false; // never mix v4 and v6 (BIRD §5.2)
        }
        let l = crate::route::plen(prefix);
        if !(self.min_len <= l && l <= self.max_len) {
            return false;
        }
        // Compare min(l, pattern-len) leading bits.
        let n = l.min(self.specificity()) as usize;
        match (&self.prefix, prefix) {
            (IpPrefix::V4(o), IpPrefix::V4(i)) => {
                let (pa, aa) = (o.addr().octets(), i.addr().octets());
                crate::route::common_bits_equal(&pa, &aa, n)
            }
            (IpPrefix::V6(o), IpPrefix::V6(i)) => {
                let (pa, aa) = (o.addr().octets(), i.addr().octets());
                crate::route::common_bits_equal(&pa, &aa, n)
            }
            _ => false,
        }
    }

    /// FRR prefix-list coverage (different from BIRD's): the route
    /// prefix must be a *subnet* of the pattern network — the first
    /// `pattern-len` bits are equal — with the ge/le range applied.
    /// (FRR "Filtering — IP Prefix List": no le/ge → exact length.)
    pub fn covers_frr(&self, prefix: &IpPrefix) -> bool {
        if std::mem::discriminant(&self.prefix) != std::mem::discriminant(prefix) {
            return false;
        }
        let l = crate::route::plen(prefix);
        if !(self.min_len <= l && l <= self.max_len) {
            return false;
        }
        crate::route::prefix_covers(&self.prefix, prefix)
    }

    /// Specificity for longest-match: the pattern network's own length.
    pub fn specificity(&self) -> u8 {
        crate::route::plen(&self.prefix)
    }
}

impl fmt::Display for PrefixPattern {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}{{{}, {}}}", self.prefix, self.min_len, self.max_len)
    }
}

/// A named prefix-set: a bag of patterns, membership = any pattern covers
/// (BIRD prefix-set literal semantics), plus longest-match tag lookup.
///
/// Representation (S10-c M2, measured — §8 of docs/protocols/policy.md):
/// patterns stay the source of truth in declaration order, and an index
/// answers [`PrefixSet::matches`] without the full scan. The index is a
/// bucket map keyed by pattern NETWORK: a covering pattern whose network
/// length ≤ the probe length always sits at one of the probe's ancestor
/// networks (coverage requires the first min(len) bits equal), so the
/// lookup walks the probe's ancestors from most specific down —
/// O(probe length) hash probes, set size independent. Patterns with
/// `min_len <` network length (BIRD `-` shapes) can additionally cover
/// probes SHORTER than their network; those live in a linear side lane
/// (rare in real sets; a pathological all-`-` set degrades to the old
/// full scan — disclosed). Equivalence is property-pinned against the
/// linear-scan oracle (tests/property.rs).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PrefixSet {
    patterns: Vec<PrefixPattern>,
    /// Pattern indexes bucketed by their network (declaration order
    /// within a bucket). Only patterns that can never cover a probe
    /// shorter than their network (`min_len >=` network length).
    by_network: HashMap<IpPrefix, Vec<usize>>,
    /// Indexes of patterns with `min_len <` network length — they can
    /// win with a specificity above the probe length, which the
    /// ancestor walk cannot see. Scanned linearly with full `covers`.
    subsuming: Vec<usize>,
}

impl PrefixSet {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn from_patterns(patterns: Vec<PrefixPattern>) -> Self {
        let mut set = Self::new();
        for p in patterns {
            set.add_pattern(p);
        }
        set
    }

    /// Append one pattern (later patterns lose longest-match ties);
    /// the index updates incrementally.
    pub fn add_pattern(&mut self, pattern: PrefixPattern) {
        let idx = self.patterns.len();
        if pattern.min_len < crate::route::plen(&pattern.prefix) {
            self.subsuming.push(idx);
        } else {
            // Key by the MASKED network: `covers` ignores pattern
            // address bits beyond its length, so `10.42.201.0/12`
            // covers exactly what `10.32.0.0/12` does — the bucket key
            // must be the canonical form the probe walk computes.
            let key = ancestor_network(&pattern.prefix, crate::route::plen(&pattern.prefix));
            self.by_network.entry(key).or_default().push(idx);
        }
        self.patterns.push(pattern);
    }

    pub fn patterns(&self) -> &[PrefixPattern] {
        &self.patterns
    }

    /// Membership + longest-match tag: the covering pattern with the
    /// longest network wins; ties break toward the earliest declared.
    fn best_covering(&self, prefix: &IpPrefix) -> Option<&PrefixPattern> {
        let l = crate::route::plen(prefix);
        // Walk winner: deepest ancestor network holding a pattern whose
        // length bounds admit the probe; the bucket's first covering
        // pattern (declaration order) is that depth's winner.
        let mut walk: Option<usize> = None;
        for d in (0..=l).rev() {
            let key = ancestor_network(prefix, d);
            if let Some(bucket) = self.by_network.get(&key) {
                let hit = bucket.iter().copied().find(|&i| {
                    let p = &self.patterns[i];
                    p.min_len <= l && l <= p.max_len
                });
                if let Some(i) = hit {
                    walk = Some(i);
                    break;
                }
            }
        }
        // Lane winner: subsuming patterns, full coverage check, max
        // specificity then earliest declared.
        let mut lane: Option<usize> = None;
        for &i in &self.subsuming {
            let p = &self.patterns[i];
            if p.covers(prefix)
                && lane.is_none_or(|cur| {
                    let c = &self.patterns[cur];
                    p.specificity() > c.specificity()
                        || (p.specificity() == c.specificity() && i < cur)
                })
            {
                lane = Some(i);
            }
        }
        match (walk, lane) {
            (Some(w), None) => Some(&self.patterns[w]),
            (None, Some(s)) => Some(&self.patterns[s]),
            (Some(w), Some(s)) => {
                let (pw, ps) = (&self.patterns[w], &self.patterns[s]);
                if pw.specificity() > ps.specificity()
                    || (pw.specificity() == ps.specificity() && w < s)
                {
                    Some(pw)
                } else {
                    Some(ps)
                }
            }
            (None, None) => None,
        }
    }

    /// Membership + longest-match tag (see [`Self::best_covering`]).
    pub fn matches(&self, prefix: &IpPrefix) -> PrefixMatch {
        let best = self.best_covering(prefix);
        PrefixMatch {
            matched: best.is_some(),
            tag: best.and_then(|p| p.tag),
        }
    }
}

/// The `d`-bit ancestor network of `prefix` (its first `d` bits, zero
/// filled) — the walk key. d = 0 yields the family's default route.
fn ancestor_network(prefix: &IpPrefix, d: u8) -> IpPrefix {
    match prefix {
        IpPrefix::V4(p) => {
            let bits = u32::from(p.addr());
            let mask: u32 = if d == 0 {
                0
            } else {
                u32::MAX << (32 - d as usize)
            };
            IpPrefix::V4(
                common::Ipv4Prefix::new(std::net::Ipv4Addr::from(bits & mask), d)
                    .expect("ancestor length <= probe length <= 32"),
            )
        }
        IpPrefix::V6(p) => {
            let bits = u128::from(p.addr());
            let mask: u128 = if d == 0 {
                0
            } else {
                u128::MAX << (128 - d as usize)
            };
            IpPrefix::V6(
                common::Ipv6Prefix::new(std::net::Ipv6Addr::from(bits & mask), d)
                    .expect("ancestor length <= probe length <= 128"),
            )
        }
    }
}

impl fmt::Display for PrefixSet {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("[")?;
        for (i, p) in self.patterns.iter().enumerate() {
            if i > 0 {
                f.write_str(", ")?;
            }
            write!(f, "{p}")?;
        }
        f.write_str("]")
    }
}

/// Verdict carried by an ordered FRR prefix-list entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PrefixListVerdict {
    Permit,
    Deny,
}

/// One `ip prefix-list NAME [seq N] (permit|deny) PREFIX [le E] [ge E]`
/// entry (FRR "Filtering — IP Prefix List").
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PrefixListEntry {
    /// Manual sequence number; 5-step auto-numbering is the importer's
    /// job (FRR doc, `seq` paragraph) — the parser records what was
    /// written.
    pub seq: u32,
    pub verdict: PrefixListVerdict,
    pub pattern: PrefixPattern,
}

/// FRR-ordered prefix-list: entries evaluated in sequence order, first
/// covering entry decides; defined-but-no-match defaults to deny
/// ("If ip prefix-list is defined, and no match is found, default deny is
/// applied" — FRR Filtering docs).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PrefixList {
    entries: Vec<PrefixListEntry>,
}

impl PrefixList {
    pub fn new() -> Self {
        Self::default()
    }

    /// Insert keeping sequence order; an entry with the same seq replaces
    /// the old one ("If a list with the same sequential number as a
    /// previous list is created, the new list will overwrite the old
    /// list" — FRR Filtering docs).
    pub fn insert(&mut self, entry: PrefixListEntry) {
        match self.entries.binary_search_by_key(&entry.seq, |e| e.seq) {
            Ok(i) => self.entries[i] = entry,
            Err(i) => self.entries.insert(i, entry),
        }
    }

    pub fn entries(&self) -> &[PrefixListEntry] {
        &self.entries
    }

    /// First-match scan: `None` = no entry covered → default deny at the
    /// caller (FRR semantics).
    pub fn first_match(&self, prefix: &IpPrefix) -> Option<PrefixListVerdict> {
        self.entries
            .iter()
            .find(|e| e.pattern.covers_frr(prefix))
            .map(|e| e.verdict)
    }
}

impl fmt::Display for PrefixList {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for e in &self.entries {
            writeln!(
                f,
                "seq {} {} {}",
                e.seq,
                match e.verdict {
                    PrefixListVerdict::Permit => "permit",
                    PrefixListVerdict::Deny => "deny",
                },
                e.pattern
            )?;
        }
        Ok(())
    }
}

/// One zebra-style `access-list NAME [seq N] (permit|deny)
/// (PREFIX [exact-match]|any)` entry (FRR 10.2.2 `lib/filter_cli.c`,
/// `access_list_cmd` / `ipv6_access_list_cmd`).
///
/// Default coverage is **subnet-of** — FRR `lib/filter.c`
/// `filter_match_zebra` calls `prefix_match(entry, route)`, which is
/// true when the route prefix is a subnet of the entry network — with
/// `exact-match` additionally requiring equal prefix lengths. This is
/// the *inverse* default of `ip prefix-list` (exact unless `le`/`ge`),
/// which is why access-lists are their own type and never compiled
/// onto prefix-list semantics: `access-list A permit 10.0.0.0/8`
/// matches `10.1.0.0/16`; the prefix-list spelling does not.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AccessListEntry {
    pub seq: u32,
    pub verdict: PrefixListVerdict,
    /// Derived pattern: `or_longer` (subnet-of) by default, `exact`
    /// only with `exact-match`; `any` = or_longer of the zero prefix.
    pub pattern: PrefixPattern,
}

/// An ordered zebra-style access-list: entries evaluated in sequence
/// order, first covering entry decides; no match → deny (FRR
/// `access_list_apply`, lib/filter.c: "if access == NULL return
/// FILTER_DENY ... return FILTER_DENY" after the scan).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AccessList {
    entries: Vec<AccessListEntry>,
}

impl AccessList {
    pub fn new() -> Self {
        Self::default()
    }

    /// Insert keeping sequence order; same seq replaces (YANG
    /// frr-filter.yang keys access-list entries by `sequence`).
    pub fn insert(&mut self, entry: AccessListEntry) {
        match self.entries.binary_search_by_key(&entry.seq, |e| e.seq) {
            Ok(i) => self.entries[i] = entry,
            Err(i) => self.entries.insert(i, entry),
        }
    }

    pub fn entries(&self) -> &[AccessListEntry] {
        &self.entries
    }

    /// First-match scan with the access-list coverage rule (subnet-of
    /// unless the entry was written `exact-match`).
    pub fn first_match(&self, prefix: &IpPrefix) -> Option<PrefixListVerdict> {
        self.entries
            .iter()
            .find(|e| e.pattern.covers_frr(prefix))
            .map(|e| e.verdict)
    }
}

impl fmt::Display for AccessList {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for e in &self.entries {
            writeln!(
                f,
                "seq {} {} {}{}",
                e.seq,
                match e.verdict {
                    PrefixListVerdict::Permit => "permit",
                    PrefixListVerdict::Deny => "deny",
                },
                e.pattern.prefix,
                if e.pattern.min_len == e.pattern.max_len {
                    " exact-match"
                } else {
                    ""
                }
            )?;
        }
        Ok(())
    }
}

/// An AS-number set with an interval representation: sorted, merged,
/// non-overlapping `(lo, hi)` ranges, membership via binary search
/// (BIRD's `int set` with `a..b` ranges, §5.2).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AsSet {
    ranges: Vec<(u32, u32)>,
}

impl AsSet {
    pub fn new() -> Self {
        Self::default()
    }

    /// Build from singleton ASNs and ranges; duplicates and overlaps are
    /// merged away.
    pub fn from_elems(elems: Vec<(u32, u32)>) -> Self {
        let mut s = Self::new();
        for (lo, hi) in elems {
            s.insert_range(lo, hi);
        }
        s
    }

    /// Add one ASN.
    pub fn insert(&mut self, asn: u32) {
        self.insert_range(asn, asn);
    }

    /// Add `[lo, hi]` (inclusive); merges with existing ranges so the
    /// representation stays sorted and disjoint.
    pub fn insert_range(&mut self, lo: u32, hi: u32) {
        if lo > hi {
            return;
        }
        // Extend by one on both sides so adjacency (prev.hi + 1 == lo)
        // merges too, keeping the interval representation canonical.
        let lo_ext = lo.saturating_sub(1);
        let hi_ext = hi.saturating_add(1);
        let mut merged_lo = lo;
        let mut merged_hi = hi;
        let mut keep: Vec<(u32, u32)> = Vec::with_capacity(self.ranges.len() + 1);
        for &(a, b) in &self.ranges {
            if b >= lo_ext && a <= hi_ext {
                merged_lo = merged_lo.min(a);
                merged_hi = merged_hi.max(b);
            } else {
                keep.push((a, b));
            }
        }
        keep.push((merged_lo, merged_hi));
        keep.sort_unstable();
        self.ranges = keep;
    }

    /// Membership — O(log n) binary search over disjoint intervals.
    pub fn contains(&self, asn: u32) -> bool {
        let idx = self.ranges.partition_point(|&(_, hi)| hi < asn);
        matches!(self.ranges.get(idx), Some(&(lo, hi)) if lo <= asn && asn <= hi)
    }

    /// True when any ASN of the path is in the set (BIRD §5.3:
    /// "bgppath and int (number) set ... returning true if any ASN from
    /// the path is in the set").
    pub fn intersects_path(&self, path: &AsPath) -> bool {
        path.segments().iter().any(|seg| match seg {
            crate::route::AsSegment::Sequence(v) | crate::route::AsSegment::Set(v) => {
                v.iter().any(|&a| self.contains(a))
            }
        })
    }

    /// The canonical sorted, disjoint interval representation.
    pub fn ranges(&self) -> &[(u32, u32)] {
        &self.ranges
    }
}

impl fmt::Display for AsSet {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("[")?;
        for (i, (lo, hi)) in self.ranges.iter().enumerate() {
            if i > 0 {
                f.write_str(", ")?;
            }
            if lo == hi {
                write!(f, "{lo}")?;
            } else {
                write!(f, "{lo}..{hi}")?;
            }
        }
        f.write_str("]")
    }
}

/// One standard-community pattern: BIRD pair-set style
/// `(asn, value-range)` with `*` wildcards on either component (§5.2:
/// "expressions like (123,*) can be used to denote ranges").
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommunityPattern {
    /// `None` = wildcard (any ASN component).
    pub asn: Option<u16>,
    /// Inclusive value range; wildcard ASN still bounds the value.
    pub value_lo: u16,
    pub value_hi: u16,
}

impl CommunityPattern {
    /// Exact `asn:value`.
    pub fn exact(asn: u16, value: u16) -> Self {
        Self {
            asn: Some(asn),
            value_lo: value,
            value_hi: value,
        }
    }

    /// `(asn, *)`.
    pub fn any_value(asn: u16) -> Self {
        Self {
            asn: Some(asn),
            value_lo: 0,
            value_hi: u16::MAX,
        }
    }

    /// `(asn, lo..hi)` — BIRD pair-set range.
    pub fn value_range(asn: u16, lo: u16, hi: u16) -> Self {
        Self {
            asn: Some(asn),
            value_lo: lo,
            value_hi: hi,
        }
    }

    pub fn matches(&self, c: &Community) -> bool {
        match c {
            Community::WellKnown(_) => false,
            Community::Pair(a, v) => {
                self.asn.is_none_or(|x| x == *a) && self.value_lo <= *v && *v <= self.value_hi
            }
        }
    }
}

impl fmt::Display for CommunityPattern {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.asn {
            Some(a) => write!(f, "({a},")?,
            None => write!(f, "(*,")?,
        }
        if self.value_lo == 0 && self.value_hi == u16::MAX && self.asn.is_some() {
            f.write_str(" *)")
        } else if self.value_lo == self.value_hi {
            write!(f, " {})", self.value_lo)
        } else {
            write!(f, " {}..{})", self.value_lo, self.value_hi)
        }
    }
}

/// Well-known communities are matchable members too.
impl From<WellKnownCommunity> for CommunityPattern {
    fn from(w: WellKnownCommunity) -> Self {
        Self::exact(0xffff, w.as_pair().1)
    }
}

/// A community-set: patterns plus explicit well-known members.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CommunitySet {
    patterns: Vec<CommunityPattern>,
    well_known: Vec<WellKnownCommunity>,
}

impl CommunitySet {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn from_patterns(patterns: Vec<CommunityPattern>) -> Self {
        Self {
            patterns,
            well_known: Vec::new(),
        }
    }

    pub fn add_pattern(&mut self, p: CommunityPattern) {
        self.patterns.push(p);
    }

    pub fn add_well_known(&mut self, w: WellKnownCommunity) {
        if !self.well_known.contains(&w) {
            self.well_known.push(w);
        }
    }

    /// The explicit well-known members (exact-match semantics need them).
    pub fn well_known(&self) -> &[WellKnownCommunity] {
        &self.well_known
    }

    pub fn patterns(&self) -> &[CommunityPattern] {
        &self.patterns
    }

    /// Does this community match any pattern/member?
    pub fn matches(&self, c: &Community) -> bool {
        if let Community::WellKnown(w) = c {
            return self.well_known.contains(w);
        }
        self.patterns.iter().any(|p| p.matches(c))
    }

    /// True when any community of the route matches (FRR `match community`
    /// "any" semantics; BIRD §5.3 clist-and-set membership).
    pub fn intersects(&self, route: &[Community]) -> bool {
        route.iter().any(|c| self.matches(c))
    }

    /// Route communities kept after removing members of this set (BIRD
    /// `C.delete(P)`, §5.2).
    pub fn difference(&self, route: &[Community]) -> Vec<Community> {
        route.iter().copied().filter(|c| !self.matches(c)).collect()
    }
}

impl fmt::Display for CommunitySet {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("[")?;
        let mut first = true;
        for w in &self.well_known {
            if !first {
                f.write_str(", ")?;
            }
            write!(f, "{w}")?;
            first = false;
        }
        for p in &self.patterns {
            if !first {
                f.write_str(", ")?;
            }
            write!(f, "{p}")?;
            first = false;
        }
        f.write_str("]")
    }
}

/// One `bgp as-path access-list NAME [seq N] permit|deny LINE` entry
/// (FRR BGP docs, "Using AS Path in Route Map").
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AsPathListEntry {
    pub seq: u32,
    pub permit: bool,
    pub regex: crate::asregex::AsRegex,
}

/// An ordered AS-path access-list: first matching regex decides; no
/// match → deny (access-list convention).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AsPathAccessList {
    entries: Vec<AsPathListEntry>,
}

impl AsPathAccessList {
    pub fn new() -> Self {
        Self::default()
    }

    /// Seq-ordered insert; same seq replaces.
    pub fn insert(&mut self, entry: AsPathListEntry) {
        match self.entries.binary_search_by_key(&entry.seq, |e| e.seq) {
            Ok(i) => self.entries[i] = entry,
            Err(i) => self.entries.insert(i, entry),
        }
    }

    pub fn entries(&self) -> &[AsPathListEntry] {
        &self.entries
    }

    /// First-match scan: `Some(permit)` / `Some(deny)` / `None` (no
    /// match → the caller's default deny).
    pub fn first_match(&self, path: &AsPath) -> Option<bool> {
        self.entries
            .iter()
            .find(|e| e.regex.matches_path(path))
            .map(|e| e.permit)
    }
}

/// One `bgp community-list standard NAME permit|deny COMMUNITY...`
/// entry. An empty community list matches every route (FRR docs show
/// `bgp community-list standard FILTER permit` as permit-the-rest).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommunityListEntry {
    pub seq: u32,
    pub permit: bool,
    pub communities: Vec<Community>,
}

/// An ordered standard community-list: an entry matches when the route
/// carries *all* of its communities; first match decides; no match →
/// deny ("When there is no matched entry, deny will be [returned]" —
/// FRR BGP docs, Communities Attribute).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CommunityAccessList {
    entries: Vec<CommunityListEntry>,
}

impl CommunityAccessList {
    pub fn new() -> Self {
        Self::default()
    }

    /// Append in user-defined order — FRR community-lists have no seq
    /// numbers; "match will happen user defined order" (BGP docs,
    /// Communities Attribute).
    pub fn insert(&mut self, entry: CommunityListEntry) {
        self.entries.push(entry);
    }

    pub fn entries(&self) -> &[CommunityListEntry] {
        &self.entries
    }

    /// First-match scan over a route's communities.
    pub fn first_match(&self, route: &[Community]) -> Option<bool> {
        self.entries
            .iter()
            .find(|e| e.communities.iter().all(|c| route.contains(c)))
            .map(|e| e.permit)
    }

    /// Set-equality scan for `match community ... exact-match`: an
    /// entry matches when the route's community set equals the entry's.
    pub fn exact_match(&self, route: &[Community]) -> Option<bool> {
        let mut have = route.to_vec();
        have.sort_unstable();
        have.dedup();
        self.entries
            .iter()
            .find(|e| {
                let mut want = e.communities.clone();
                want.sort_unstable();
                want.dedup();
                want == have
            })
            .map(|e| e.permit)
    }

    /// Any-scan for `match community LIST any` (POL-2; FRR 10.2.2
    /// `community_list_any_match`, bgpd/bgp_clist.c:735): the route
    /// needs to carry just ONE community listed in some entry — the
    /// FRR loop is `for each route community (outer, in order)`
    /// × `for each entry (inner, in order)` with
    /// `community_include(entry, val)`, and the first hit's verdict
    /// wins. So a route whose values could hit entries with different
    /// verdicts resolves by its own community order, and an entry with
    /// no communities (the permit-the-rest tail) never hits in any
    /// mode (`community_include` of an empty entry is always false).
    /// No hit → `None` (a community-less route never hits either —
    /// FRR's match returns RMAP_OKAY there, which the route-map apply
    /// loop skips like a no-match).
    pub fn any_match(&self, route: &[Community]) -> Option<bool> {
        for c in route {
            for e in &self.entries {
                if e.communities.contains(c) {
                    return Some(e.permit);
                }
            }
        }
        None
    }

    /// Union of all communities across entries — the removal set for
    /// `set comm-list delete NAME` (FRR BGP docs example).
    pub fn to_removal_set(&self) -> CommunitySet {
        let mut cs = CommunitySet::new();
        for e in &self.entries {
            for &c in &e.communities {
                let (a, v) = match c {
                    Community::Pair(a, v) => (a, v),
                    Community::WellKnown(w) => w.as_pair(),
                };
                cs.add_pattern(CommunityPattern::exact(a, v));
            }
        }
        cs
    }
}

/// Extended-community pattern: kind + optional admin wildcard (minimal
/// `(kind, key, *)` model; IPv4-admin forms deferred).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExtCommunityPattern {
    pub kind: crate::route::ExtCommunityKind,
    /// `None` = any administrator AS.
    pub admin_as: Option<u32>,
}

impl ExtCommunityPattern {
    pub fn matches(&self, e: &ExtCommunity) -> bool {
        self.kind == e.kind && self.admin_as.is_none_or(|a| a == e.admin_as)
    }
}

/// An extended-community set.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ExtCommunitySet {
    patterns: Vec<ExtCommunityPattern>,
}

impl ExtCommunitySet {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn from_patterns(patterns: Vec<ExtCommunityPattern>) -> Self {
        Self { patterns }
    }

    pub fn patterns(&self) -> &[ExtCommunityPattern] {
        &self.patterns
    }

    pub fn intersects(&self, route: &[ExtCommunity]) -> bool {
        route
            .iter()
            .any(|e| self.patterns.iter().any(|p| p.matches(e)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use common::IpPrefix;

    fn p(s: &str) -> IpPrefix {
        s.parse().unwrap()
    }

    #[test]
    fn prefix_set_bird_doc_examples() {
        // BIRD §5.2: "[ 1.0.0.0/8, 2.0.0.0/8+, 3.0.0.0/8-, 4.0.0.0/8{16,24} ]"
        let set = PrefixSet::from_patterns(vec![
            PrefixPattern::exact(p("1.0.0.0/8")),
            PrefixPattern::or_longer(p("2.0.0.0/8")),
            PrefixPattern::range(p("3.0.0.0/8"), 0, 8).unwrap(),
            PrefixPattern::range(p("4.0.0.0/8"), 16, 24).unwrap(),
        ]);
        assert!(set.matches(&p("1.0.0.0/8")).matched, "exact member");
        assert!(!set.matches(&p("1.0.0.0/16")).matched, "exact means exact");
        assert!(set.matches(&p("2.9.9.0/24")).matched, "2/8+ covers subnets");
        assert!(set.matches(&p("3.0.0.0/8")).matched);
        // BIRD: 1.0.0.0/16 ~ [1.0.0.0/8-] is false — '-' is supernets only.
        assert!(!set.matches(&p("3.0.0.0/16")).matched);
        assert!(
            set.matches(&p("0.0.0.0/0")).matched,
            "3/8- covers the default"
        );
        assert!(set.matches(&p("4.1.1.0/20")).matched, "4/8 {{16,24}}");
        assert!(!set.matches(&p("4.1.1.0/25")).matched, "past high");
        assert!(!set.matches(&p("4.1.1.0/15")).matched, "below low");
    }

    #[test]
    fn prefix_set_slash_zero_and_slash_32() {
        // Edge prefixes: /0 covers everything; /32 only itself.
        let all = PrefixSet::from_patterns(vec![PrefixPattern::or_longer(p("0.0.0.0/0"))]);
        assert!(all.matches(&p("0.0.0.0/0")).matched);
        assert!(all.matches(&p("203.0.113.7/32")).matched);
        let host = PrefixSet::from_patterns(vec![PrefixPattern::exact(p("198.51.100.1/32"))]);
        assert!(host.matches(&p("198.51.100.1/32")).matched);
        assert!(!host.matches(&p("198.51.100.2/32")).matched);
        assert!(!host.matches(&p("198.51.100.0/24")).matched);
        // v6 /128
        let v6 = PrefixSet::from_patterns(vec![PrefixPattern::exact(p("2001:db8::1/128"))]);
        assert!(v6.matches(&p("2001:db8::1/128")).matched);
        assert!(!v6.matches(&p("2001:db8::2/128")).matched);
    }

    #[test]
    fn prefix_set_af_separation() {
        let v4 = PrefixSet::from_patterns(vec![PrefixPattern::or_longer(p("0.0.0.0/0"))]);
        assert!(!v4.matches(&p("::/0")).matched, "v4 set never matches v6");
    }

    #[test]
    fn prefix_set_duplicates_and_longest_match_tag() {
        // Covering duplicates: /8 and /16 both match a /24; the /16 (more
        // specific) wins and supplies the tag.
        let set = PrefixSet::from_patterns(vec![
            PrefixPattern::or_longer(p("10.0.0.0/8")).with_tag(1),
            PrefixPattern::or_longer(p("10.42.0.0/16")).with_tag(2),
        ]);
        let m = set.matches(&p("10.42.0.0/24"));
        assert!(m.matched);
        assert_eq!(m.tag, Some(2));
        // Outside the /16: the /8 wins.
        let m = set.matches(&p("10.7.0.0/24"));
        assert_eq!(m.tag, Some(1));
        // Exact duplicate patterns: first declared wins the tie.
        let dup = PrefixSet::from_patterns(vec![
            PrefixPattern::exact(p("192.0.2.0/24")).with_tag(10),
            PrefixPattern::exact(p("192.0.2.0/24")).with_tag(20),
        ]);
        assert_eq!(dup.matches(&p("192.0.2.0/24")).tag, Some(10));
    }

    #[test]
    fn prefix_pattern_range_validation() {
        assert!(PrefixPattern::range(p("10.0.0.0/8"), 24, 16).is_err());
        assert!(PrefixPattern::range(p("10.0.0.0/8"), 0, 33).is_err());
        assert!(PrefixPattern::range(p("2001:db8::/32"), 0, 128).is_ok());
        assert!(PrefixPattern::range(p("2001:db8::/32"), 0, 129).is_err());
    }

    /// S10-c M2: the bucket index + subsuming lane must be exactly the
    /// old linear scan. Reference implementation (the pre-index
    /// `matches`), compared over a shape-mixing set and a probe grid.
    fn linear_matches(patterns: &[PrefixPattern], prefix: &IpPrefix) -> PrefixMatch {
        let mut best: Option<&PrefixPattern> = None;
        for pat in patterns {
            if pat.covers(prefix) {
                match best {
                    Some(b) if b.specificity() >= pat.specificity() => {}
                    _ => best = Some(pat),
                }
            }
        }
        PrefixMatch {
            matched: best.is_some(),
            tag: best.and_then(|b| b.tag),
        }
    }

    #[test]
    fn indexed_matches_equal_the_linear_scan() {
        let shapes = [
            ("10.0.0.0/8", 8, 8),       // exact
            ("10.42.0.0/16", 16, 32),   // or-longer
            ("10.42.7.0/24", 20, 28),   // range above network length
            ("10.42.7.128/25", 16, 25), // subsuming: min < network len
            ("10.128.0.0/9", 0, 9),     // subsuming incl. the default
            ("192.0.2.0/24", 0, 24),    // subsuming, other branch
            ("0.0.0.0/0", 0, 32),       // everything
            ("10.42.7.192/26", 26, 26), // exact, under the /25
            // NON-CANONICAL networks (host bits set): `covers` ignores
            // address bits beyond the length, so these behave as their
            // masked forms (10.32.0.0/12, 10.0.0.0/9) — the index must
            // key the masked network (a divergence the S10-c bench
            // checksums caught; pinned here forever).
            ("10.42.201.0/12", 12, 20),
            ("10.42.201.0/9", 9, 9),
            ("2001:db8::/32", 32, 128),     // v6 or-longer
            ("2001:db8:1::/48", 32, 48),    // v6 subsuming
            ("2001:db8:1:2::/64", 64, 64),  // v6 exact
            ("2001:db8:ffff::/48", 40, 48), // v6 range, sibling branch
        ];
        let patterns: Vec<PrefixPattern> = shapes
            .iter()
            .enumerate()
            .map(|(i, &(net, lo, hi))| {
                PrefixPattern::range(p(net), lo, hi)
                    .unwrap()
                    .with_tag(i as u32 + 1)
            })
            .collect();
        // Same set two ways: bulk and incremental — identical results
        // and identical indexes (PartialEq compares both).
        let bulk = PrefixSet::from_patterns(patterns.clone());
        let mut incremental = PrefixSet::new();
        for pat in &patterns {
            incremental.add_pattern(pat.clone());
        }
        assert_eq!(bulk, incremental);

        let probes = [
            "0.0.0.0/0",
            "10.0.0.0/8",
            "10.0.0.0/7",
            "10.200.0.0/16",
            "10.42.0.0/16",
            "10.42.7.0/24",
            "10.42.7.128/25",
            "10.42.7.192/26",
            "10.42.7.200/29",
            "10.42.8.0/24",
            "10.42.0.0/15",
            "192.0.2.0/24",
            "192.0.2.128/26",
            "192.0.3.0/24",
            "0.0.0.0/1",
            "128.0.0.0/1",
            // aligned with the non-canonical networks' masked forms
            "10.32.0.0/12",
            "10.40.0.0/16",
            "10.47.255.0/24",
            "10.48.0.0/12",
            "10.0.0.0/9",
            "10.1.2.0/24",
            "10.128.0.0/9",
            "2001:db8::/32",
            "2001:db8::/31",
            "2001:db8:1::/48",
            "2001:db8:1:2::/64",
            "2001:db8:1:2:3::/80",
            "2001:db8:ffff::/48",
            "2001:db8:fffe::/48",
            "::/0",
            "2001:db8:1::/47",
        ];
        for probe in probes {
            let probe = p(probe);
            let got = bulk.matches(&probe);
            let want = linear_matches(&patterns, &probe);
            assert_eq!(
                got, want,
                "probe {probe}: indexed ({got:?}) != linear ({want:?})"
            );
            assert_eq!(incremental.matches(&probe), want, "incremental build");
        }
    }

    /// S10-c M2: cross-lane ties — a subsuming pattern and an
    /// ancestor-walk pattern with the SAME specificity must resolve to
    /// the earliest declared (the old scan's tie rule), and the empty
    /// set / no-cover probes still report no match.
    #[test]
    fn indexed_cross_lane_ties_follow_declaration_order() {
        // Same /24 network, two patterns: one subsuming ({16,24}), one
        // not ({24,28}) — both specificity 24 for a /24 probe; the
        // earliest declared wins.
        let a = PrefixPattern::range(p("192.0.2.0/24"), 16, 24)
            .unwrap()
            .with_tag(11);
        let b = PrefixPattern::range(p("192.0.2.0/24"), 24, 28)
            .unwrap()
            .with_tag(22);
        let set = PrefixSet::from_patterns(vec![a.clone(), b.clone()]);
        assert_eq!(
            set.matches(&p("192.0.2.128/25")).tag,
            Some(22),
            "only b covers /25"
        );
        assert_eq!(
            set.matches(&p("192.0.2.0/24")).tag,
            Some(11),
            "both cover /24 at specificity 24 — earliest declared"
        );
        let flipped = PrefixSet::from_patterns(vec![b, a]);
        assert_eq!(
            flipped.matches(&p("192.0.2.0/24")).tag,
            Some(22),
            "flipped declaration flips the tie"
        );
        // Empty set: no match, no tag.
        assert!(!PrefixSet::new().matches(&p("10.0.0.0/8")).matched);
        assert_eq!(PrefixSet::new().matches(&p("10.0.0.0/8")).tag, None);
    }

    #[test]
    fn prefix_list_first_match_and_default_deny() {
        let mut pl = PrefixList::new();
        pl.insert(PrefixListEntry {
            seq: 5,
            verdict: PrefixListVerdict::Deny,
            pattern: PrefixPattern::or_longer(p("10.0.0.0/8")),
        });
        pl.insert(PrefixListEntry {
            seq: 10,
            verdict: PrefixListVerdict::Permit,
            pattern: PrefixPattern::or_longer(p("10.42.0.0/16")),
        });
        // First match wins: 10.42/16 is inside 10/8 but seq 5 denies first.
        assert_eq!(
            pl.first_match(&p("10.42.0.0/24")),
            Some(PrefixListVerdict::Deny)
        );
        assert_eq!(
            pl.first_match(&p("10.7.0.0/24")),
            Some(PrefixListVerdict::Deny)
        );
        assert_eq!(
            pl.first_match(&p("192.0.2.0/24")),
            None,
            "no match → default deny"
        );
    }

    #[test]
    fn prefix_list_same_seq_overwrites_and_sorts() {
        let mut pl = PrefixList::new();
        pl.insert(PrefixListEntry {
            seq: 10,
            verdict: PrefixListVerdict::Deny,
            pattern: PrefixPattern::exact(p("10.0.0.0/8")),
        });
        pl.insert(PrefixListEntry {
            seq: 5,
            verdict: PrefixListVerdict::Permit,
            pattern: PrefixPattern::or_longer(p("10.0.0.0/8")),
        });
        assert_eq!(
            pl.entries()[0].seq,
            5,
            "sorted by seq regardless of insertion order"
        );
        pl.insert(PrefixListEntry {
            seq: 5,
            verdict: PrefixListVerdict::Deny,
            pattern: PrefixPattern::exact(p("10.0.0.0/8")),
        });
        assert_eq!(pl.entries().len(), 2, "same seq replaces");
        assert_eq!(pl.entries()[0].verdict, PrefixListVerdict::Deny);
    }

    #[test]
    fn access_list_subnet_of_default_exact_on_flag() {
        // FRR lib/filter.c filter_match_zebra: non-exact = prefix_match
        // (route is a SUBNET of the entry); exact-match additionally
        // requires equal prefix lengths.
        let mut al = AccessList::new();
        al.insert(AccessListEntry {
            seq: 5,
            verdict: PrefixListVerdict::Permit,
            pattern: PrefixPattern::or_longer(p("10.0.0.0/8")),
        });
        al.insert(AccessListEntry {
            seq: 10,
            verdict: PrefixListVerdict::Permit,
            pattern: PrefixPattern::exact(p("192.0.2.0/24")),
        });
        assert_eq!(
            al.first_match(&p("10.1.0.0/16")),
            Some(PrefixListVerdict::Permit)
        );
        assert_eq!(
            al.first_match(&p("10.0.0.0/8")),
            Some(PrefixListVerdict::Permit),
            "the entry network itself is covered"
        );
        assert_eq!(
            al.first_match(&p("10.0.0.0/7")),
            None,
            "supernet of the entry is NOT covered (subnet-of only)"
        );
        // exact entry: same length + same network only.
        assert_eq!(
            al.first_match(&p("192.0.2.0/24")),
            Some(PrefixListVerdict::Permit)
        );
        assert_eq!(
            al.first_match(&p("192.0.2.128/25")),
            None,
            "subnet does not match an exact-match entry"
        );
        // Family separation.
        assert_eq!(al.first_match(&p("2001:db8::/32")), None);
    }

    #[test]
    fn access_list_first_match_order_and_same_seq() {
        let mut al = AccessList::new();
        al.insert(AccessListEntry {
            seq: 5,
            verdict: PrefixListVerdict::Permit,
            pattern: PrefixPattern::or_longer(p("10.0.0.0/8")),
        });
        al.insert(AccessListEntry {
            seq: 10,
            verdict: PrefixListVerdict::Deny,
            pattern: PrefixPattern::or_longer(p("10.42.0.0/16")),
        });
        assert_eq!(
            al.first_match(&p("10.42.0.0/24")),
            Some(PrefixListVerdict::Permit),
            "seq 5 permit wins first despite the later deny"
        );
        // Same seq replaces.
        al.insert(AccessListEntry {
            seq: 5,
            verdict: PrefixListVerdict::Deny,
            pattern: PrefixPattern::or_longer(p("10.0.0.0/8")),
        });
        assert_eq!(al.entries().len(), 2);
        assert_eq!(
            al.first_match(&p("10.0.0.1/32")),
            Some(PrefixListVerdict::Deny)
        );
    }

    #[test]
    fn as_set_intervals_merge_and_query() {
        let mut s = AsSet::new();
        s.insert_range(10, 20);
        s.insert_range(21, 30); // adjacent → merges to 10..30
        s.insert_range(5, 7);
        s.insert(9); // adjacent to 10 → merges
        assert_eq!(s.ranges(), &[(5, 7), (9, 30)]);
        assert!(s.contains(5));
        assert!(s.contains(7));
        assert!(!s.contains(8));
        assert!(s.contains(9));
        assert!(s.contains(30));
        assert!(!s.contains(31));
        // Duplicates are absorbed.
        s.insert_range(10, 20);
        assert_eq!(s.ranges().len(), 2);
    }

    #[test]
    fn as_set_full_range_and_path_intersect() {
        let mut s = AsSet::new();
        s.insert_range(0, u32::MAX);
        assert!(s.contains(0));
        assert!(s.contains(u32::MAX));
        let path = AsPath::from_sequence(&[65001, 64512, 4200000000]);
        assert!(s.intersects_path(&path));
        let small = AsSet::from_elems(vec![(64512, 64512)]);
        assert!(small.intersects_path(&path));
        assert!(!AsSet::new().intersects_path(&path));
    }

    #[test]
    fn community_set_patterns() {
        let mut cs = CommunitySet::new();
        cs.add_pattern(CommunityPattern::exact(65000, 100));
        cs.add_pattern(CommunityPattern::value_range(65000, 200, 299));
        cs.add_well_known(WellKnownCommunity::NoExport);
        assert!(cs.matches(&Community::Pair(65000, 100)));
        assert!(cs.matches(&Community::Pair(65000, 250)));
        assert!(!cs.matches(&Community::Pair(65000, 300)));
        assert!(!cs.matches(&Community::Pair(65001, 100)));
        assert!(cs.matches(&Community::WellKnown(WellKnownCommunity::NoExport)));
        assert!(!cs.matches(&Community::WellKnown(WellKnownCommunity::Gshut)));
        let route = vec![Community::Pair(65000, 250), Community::Pair(65001, 1)];
        assert!(cs.intersects(&route));
        assert_eq!(cs.difference(&route), vec![Community::Pair(65001, 1)]);
    }

    #[test]
    fn community_pattern_wildcards() {
        let any_val = CommunityPattern::any_value(65000);
        assert!(any_val.matches(&Community::Pair(65000, 0)));
        assert!(any_val.matches(&Community::Pair(65000, u16::MAX)));
        assert!(!any_val.matches(&Community::Pair(65001, 0)));
        assert!(!any_val.matches(&Community::WellKnown(WellKnownCommunity::Gshut)));
        let full = CommunityPattern {
            asn: None,
            value_lo: 0,
            value_hi: u16::MAX,
        };
        assert!(full.matches(&Community::Pair(9999, 1)));
    }

    #[test]
    fn community_list_any_match_mode() {
        // POL-2: the any-scan (FRR 10.2.2 community_list_any_match,
        // bgp_clist.c:735) — one listed community suffices, and the
        // route's own community order picks the winning entry when
        // values could hit entries with different verdicts.
        let mut l = CommunityAccessList::new();
        l.insert(CommunityListEntry {
            seq: 1,
            permit: false, // deny if EITHER 65000:1 or 65000:2 is carried
            communities: vec![Community::Pair(65000, 1), Community::Pair(65000, 2)],
        });
        l.insert(CommunityListEntry {
            seq: 2,
            permit: true, // permit 65000:3
            communities: vec![Community::Pair(65000, 3)],
        });
        // Default mode (all-of): carrying only :1 does NOT hit entry 1.
        assert_eq!(l.first_match(&[Community::Pair(65000, 1)]), None);
        // Any mode: carrying :1 alone hits entry 1 → deny.
        assert_eq!(
            l.any_match(&[Community::Pair(65000, 1)]),
            Some(false),
            "any mode needs just one listed community"
        );
        // Verdict order: route order decides between overlapping
        // entries — [:3, :1] hits entry 2 first (permit), [:1, :3]
        // hits entry 1 (deny).
        assert_eq!(
            l.any_match(&[Community::Pair(65000, 3), Community::Pair(65000, 1)]),
            Some(true),
            "first route community (:3) hits the permit entry"
        );
        assert_eq!(
            l.any_match(&[Community::Pair(65000, 1), Community::Pair(65000, 3)]),
            Some(false),
            "first route community (:1) hits the deny entry"
        );
        // Empty route communities never hit (FRR: RMAP_OKAY → skipped).
        assert_eq!(l.any_match(&[]), None);
        // An unlisted community hits nothing.
        assert_eq!(l.any_match(&[Community::Pair(65001, 1)]), None);
    }

    #[test]
    fn community_list_any_mode_empty_entry_never_hits() {
        // community_include of a bare `permit` entry (no communities) is
        // always false in FRR's any-scan — the permit-the-rest tail is
        // a DEFAULT-mode construct only.
        let mut l = CommunityAccessList::new();
        l.insert(CommunityListEntry {
            seq: 1,
            permit: true,
            communities: vec![],
        });
        assert_eq!(
            l.first_match(&[Community::Pair(65000, 1)]),
            Some(true),
            "default mode: bare permit matches (empty all-of set)"
        );
        assert_eq!(
            l.any_match(&[Community::Pair(65000, 1)]),
            None,
            "any mode: bare permit never hits"
        );
    }

    #[test]
    fn ext_community_set() {
        let set = ExtCommunitySet::from_patterns(vec![ExtCommunityPattern {
            kind: crate::route::ExtCommunityKind::RouteTarget,
            admin_as: Some(65000),
        }]);
        let rt = ExtCommunity {
            kind: crate::route::ExtCommunityKind::RouteTarget,
            admin_as: 65000,
            assigned: 42,
        };
        let ro = ExtCommunity {
            kind: crate::route::ExtCommunityKind::RouteOrigin,
            admin_as: 65000,
            assigned: 42,
        };
        assert!(set.intersects(&[rt]));
        assert!(!set.intersects(&[ro]));
    }
}
