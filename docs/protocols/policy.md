# policy — the typed filter engine + FRR route-map import grammar

Status: v1 landed 2026-10-11 (weekend program stream W1-a); extended
the same night (micro M2) with `call`, zebra-style access-lists, and
the `set comm-list NAME delete` token-order fix; the morning
adjudication (POL-1 A) pinned the `call` error shape — undefined
target = compile error at the call site's own line, cycles rejected at
load with the full cycle path in the message. The 2026-10-14
adjudication wave (S7-d) ratified the ordered access-list
representation (POL-4), made `match community any` a real third mode
(POL-2), warn-ignored `description` lines in both route-map and
prefix-list stanzas (POL-5), and recorded the multi-name superset as
deliberate (POL-3). Scope:
`RouteView` (the generic route window), the BIRD-inspired typed filter
language as a Rust API, sets-as-data with longest-match tags, the
dependency-free FRR AS-path regex subset, the route-map
parser→compiler, and the property suite. bgpd consumes this in W2-d.

Crate: `crates/policy` (lib only; no daemon).

Primary prior art, cited per construct below:

- **BIRD 2.x user guide, ch. 5 "Filters"** — §5.1 (filter = look,
  modify, accept/reject), §5.2 (data types: prefix sets with
  `ip/len{low,high}` patterns, `+`/`-` shorthands; bgppath masks
  `[= ... =]` with `* ? +`, ranges, sets; clist/eclist operators),
  §5.3 (the `~` operator family), §5.5 (route attributes;
  undefined-bgppath/clist-is-empty rule), §5.6 (`accept`/`reject`).
  Fetched verbatim 2026-10-11 (`bird.network.cz/?get_doc&v=20&f=bird-5.html`).
- **FRR docs** — "Route Maps" (matching/set/exit-policy summary table;
  `continue`/`on-match` goto semantics; implicit deny-all), "Filtering"
  (prefix-list `le`/`ge` semantics, seq numbering, same-seq overwrite),
  BGP chapter "BGP Regular Expressions" (`_` ≡ `(^|[,{}()]|$)`),
  "Communities Attribute" (standard community-lists, `set comm-list
  delete`), "Using AS Path in Route Map" (`bgp as-path access-list`).
  Fetched 2026-10-11 (docs.frrouting.org, latest ≈ 10.x).
- **Observed-FRR evidence**: `away/2026-10-09/quarantine/B7-frr-conf-grammar.md`
  (14 accepted directive forms; no route-map stanza was observed in any
  executed config — see §6 Deviations).

## 1. Layers

| Module | What |
|---|---|
| `route` | `RouteView` trait; policy-owned BGP attribute model: `AsPath`/`AsSegment`, `Community`/`WellKnownCommunity`, `ExtCommunity`, `BgpOrigin`, `BgpAttrs`, `OTC`; `RouteData` (owned mutable evaluation buffer) |
| `sets` | `PrefixSet`/`PrefixPattern` (BIRD `{low,high}` semantics + longest-match tags), `PrefixList` (FRR ordered first-match), `AccessList` (FRR zebra-style ordered ACL, subnet-of default), `AsSet` (interval representation), `CommunitySet`/`CommunityPattern` (BIRD pair-set style), `ExtCommunitySet`, `AsPathAccessList`, `CommunityAccessList` |
| `asregex` | FRR AS-path regex subset as an NFA position-set simulation (no regex crate; no catastrophic backtracking) |
| `filter` | `Term` (match primitives + boolean combinators), `Action` (`accept`/`reject`/`set ...` + `Goto`/`Call` control flow), `Rule`, `Filter`/`FilterBuilder` |
| `routemap` | frr.conf policy stanzas → `PolicyDocument` AST → `compile_route_map` → typed `Filter` |

## 2. `RouteView` — the route window (M1)

BIRD §5.1: "Filter gets the route, looks at its attributes and modifies
some of them if it wishes. At the end, it decides whether to pass the
changed route through (using accept) or whether to reject it."
`RouteView` is the read side of that contract; it is data-only (no side
effects, no methods beyond field access):

```rust
pub trait RouteView {
    fn prefix(&self) -> IpPrefix;            // BIRD `net`, read-only
    fn protocol(&self) -> RouteProtocol;     // BIRD `source`
    fn metric(&self) -> u32;
    fn nexthop_group(&self) -> &NexthopGroup;
    fn bgp_attrs(&self) -> Option<&BgpAttrs>; // None = non-BGP route
}
```

`common`'s types are used where they exist (`IpPrefix`, `RouteProtocol`,
`NexthopGroup`); BGP path attributes are policy-owned minimal types
until bgpd (W2-d) implements the trait and converts. `RouteData` is the
owned snapshot filters mutate: `RouteData::from_view(&view)` once, then
`filter.apply(&mut data)` per pass.

BGP attribute model notes:

- `AsPath` is segments (`Sequence`/`Set`), BIRD §5.2 operator analogs:
  `first`/`last` (None on AS_SET boundary, BIRD models it as zero),
  `len`, `contains`, `prepend`.
- `BgpAttrs::materialized_default()` = LOCAL_PREF 100, ORIGIN
  incomplete — what a route being redistributed into BGP starts from
  (used when a `set` action touches a non-BGP route; FRR apply-set
  semantics; RFC 4271 §5.1.4 for the synthesized-path origin).

## 3. Sets as data (M3)

### 3.1 Prefix sets — BIRD `{low, high}` semantics

BIRD §5.2 verbatim: "Prefix ip1/len1 matches prefix pattern ip2/len2{l,h}
if the first min(len1, len2) bits of ip1 and ip2 are identical and
l <= len1 <= h." Shorthands: `addr/len+` ≡ `{len, maxlen}`, `addr/len-`
≡ `{0, len}`. v4/v6 never mix in one set (§5.2). `PrefixPattern::exact`
= no bounds.

**Longest-match tags**: each pattern may carry a `tag: Option<u32>`
(BIRD's `define` names constants; we tag entries). `PrefixSet::matches`
returns `{matched, tag}` where the winner is the covering pattern with
the longest network length; ties break toward the earliest declared
entry. Use: classifier sets (customer/transit/blackhole) that a filter
can branch on via `Term::PrefixTagIn`.

Representation: linear scan over patterns — sets are
configuration-sized (tens to hundreds), and patterns cannot be
interval-merged without losing tags. Disclosed, not benchmarked.

### 3.2 AS sets — interval representation

`AsSet` stores sorted, merged, disjoint `(lo, hi)` ranges (insert merges
adjacent ranges so the form stays canonical); membership is a binary
search — O(log n). BIRD §5.2 `int set` with `a..b` ranges. Edge cases
unit-tested: duplicates absorbed, adjacency merged, full `0..u32::MAX`,
path intersection.

### 3.3 Community sets

`CommunityPattern` is BIRD's pair-set `(asn, value-range)` with `*`
wildcard ASN; well-known communities (RFC 1997 + gshut RFC 8326) are
explicit members. `difference` implements BIRD `C.delete(P)` (§5.2) for
`RemoveCommunities`. Extended communities: minimal `rt`/`ro` +
AS-administrator form (RFC 4360 §3/§4); IPv4-admin and opaque kinds
deferred (§7).

### 3.4 FRR ordered lists (compat inputs)

- `PrefixList`: entries seq-sorted (same seq replaces — FRR "Filtering":
  "If a list with the same sequential number ... the new list will
  overwrite the old list"); first **covering** entry decides; defined
  but unmatched → deny. Coverage here is FRR's, *not* BIRD's: the route
  prefix must be a subnet of the entry network (first `len` bits equal)
  with `ge ≤ l ≤ le`; no `le`/`ge` → exact length; `ge` only → le = 32/128;
  `le` only → ge = entry length.
- `AsPathAccessList`: `bgp as-path access-list NAME [seq N]
  permit|deny REGEX`, first matching regex decides, no match → deny.
- `AccessList`: zebra-style `access-list|ipv6 access-list NAME
  [seq N] permit|deny (PREFIX [exact-match]|any)` (FRR 10.2
  `lib/filter_cli.c`). Entries are seq-sorted (same seq replaces; a
  seq-less entry gets max-existing + 5 — `acl_get_seq`, *not* the
  prefix-list "next multiple of five") and the first covering entry
  decides; no match → deny (`access_list_apply`). Coverage is
  **subnet-of by default** — `filter_match_zebra` calls
  `prefix_match(entry, route)` — with `exact-match` additionally
  requiring equal prefix lengths. This is the *inverse* default of
  `ip prefix-list` (exact unless `le`/`ge`): `access-list A permit
  10.0.0.0/8` matches `10.1.0.0/16`, the prefix-list spelling does
  not. `any` covers the whole family (`::/0` for the v6 twin).
- `CommunityAccessList`: standard lists in **user-defined order**
  (FRR: "match will happen user defined order"); an entry matches when
  the route carries all its communities (an entry with no communities
  matches everything — FRR's doc example `bgp community-list standard
  FILTER permit` is the permit-the-rest tail); no match → deny. The
  list also answers the other two `match community` modes: set
  equality (`exact_match`) and the any-scan (`any_match`, §6.11).

## 4. The typed filter language (M2)

Rust-API first: terms and actions are data; there is deliberately no
BIRD-syntax parser yet. A filter = ordered rules; a rule = `when` term
+ `then` actions. `FilterBuilder` registers named sets (returning
`SetIndex` handles) and rules, then `build()` validates control flow
(`Goto` targets must be in range and strictly later — FRR "Route Maps":
"Jumping to a previous entry is not permitted") and freezes everything
into a `Filter`.

Execution (one model subsumes BIRD if/then and FRR route-maps): rules
run top-down; a matching rule runs its actions in order —
`Accept`/`Reject` terminate, `Goto(i)` jumps forward, attribute actions
mutate the `RouteData` in place; falling off the action list or an
unmatched rule advances. No rule matched → `default_verdict` (builder
default `Reject`; BIRD-style filters should terminate explicitly, per
§5.1 "The filter must terminate with either accept or reject").

### 4.1 Terms

| Term | Meaning | Prior art |
|---|---|---|
| `True` / `False` / `And` / `Or` / `Not` | boolean combinators | BIRD §5.3 `&& \|\| !` |
| `Defined(Attr)` | attribute presence test | BIRD §5.5 `defined()` |
| `PrefixIn(PrefixSetId)` | `net ~ prefix-set` | BIRD §5.3 |
| `PrefixTagIn(id, tags)` | longest-match tag ∈ tags | Rouster (§3.1) |
| `PrefixLen {min,max}` | prefix-length range | BIRD `.len` + §5.2 patterns |
| `PrefixList(id)` | FRR ordered prefix-list scan (true iff first cover permits) | FRR Filtering |
| `AccessList(id)` | FRR ordered zebra-style access-list scan, subnet-of default (true iff first cover permits) | FRR Filtering / `match ip address ACL` |
| `PathMask(AsPathMask)` | BIRD mask `[= ... =]`: `As`, `Any` (`*`), `AnyOne` (`?`), `Range`, `Set`, `Repeat` (`2+`) | BIRD §5.2 bgpmask |
| `PathRegex(AsRegex)` | FRR regex (`^ $ _ . * + ? \| [] {} ()`) | FRR BGP RegEx |
| `PathIn(AsSetId)` | any path ASN in set | BIRD §5.3 |
| `PathContains(u32)` | ASN occurs in path | BIRD §5.3 |
| `PathLen {min,max}` / `PathEmpty` | length range / emptiness | BIRD `bgp_path.len` |
| `CommunityAny(id)` / `CommunityExact(id)` / `CommunityEmpty` | set intersects / set equality / no communities | FRR `match community [exact-match]`; BIRD §5.3 |
| `ExtCommunityAny(id)` | extended-community set intersects | BIRD eclist §5.3 |
| `PathList(id)` / `CommunityList(id)` / `CommunityListExact(id)` / `CommunityListAny(id)` | FRR ordered access-lists (community default/exact/any modes, §6.11) | FRR BGP docs |
| `ProtocolIn([RouteProtocol])` | origin-protocol test | BIRD `source`; FRR `match source-protocol` |
| `OriginIn([BgpOrigin])` | BGP ORIGIN test | BIRD `bgp_origin` |
| `LocalPrefIn(lo,hi)` / `MedIn` / `OtcIn` / `MetricIn` | numeric ranges (absent attr ⇒ false) | BIRD §5.5; FRR `match local-preference`/`metric` |

### 4.2 Actions

`Accept` (BIRD §5.6), `Reject`, `Goto(rule)` (FRR exit policy),
`Call(idx)` (FRR route-map `call NAME`: deny return finishes and
denies, permit return proceeds with the remaining actions — FRR 10.2
"Route Maps"; the index resolves into the owning filter's compiled
call table, cycles rejected at compile time);
`SetLocalPref`/`AdjustLocalPref`, `SetMed`/`AdjustMed`, `SetMetric`,
`SetOrigin`, `SetOtc` (RFC 9234); `SetCommunities {list, Replace|Add}`
(FRR `set community [additive]`; empty list + Replace = `none`);
`RemoveCommunities(CommunitySet)` (BIRD `C.delete(P)`; FRR
`set comm-list NAME delete`); `PrependAsPath {asn, times}` (BIRD
`P.prepend(A)`; FRR `set as-path prepend`).

### 4.3 Purity and totality (disclosed deviation)

BIRD §5.1: "If there is a runtime error in filter, the route is
rejected"; §5.5: undefined `bgppath`/`*clist` attributes count as empty
"for most purposes". Rouster's engine is **total** — every term is a
bool: BGP-dependent terms on a non-BGP route are false, `PathEmpty` /
`CommunityEmpty` / ordered community lists see absent-as-empty (BIRD
§5.5), and `defined()` exists for explicit presence tests. There is no
runtime-error-to-reject path; totality is what makes evaluation pure
and safely concurrent. Hot path: `Filter::apply` walks `&Term`/`&Action`
and mutates the caller's `RouteData` — no allocation except
community-list rewrites and path prepends (attribute edits by nature).
Not benchmarked; disclosed.

## 5. The route-map compatibility grammar (M4)

`parse_policy_config(text)` accepts exactly these stanzas (leading
whitespace tolerated — B7 observed vtysh-style indented children; blank
lines and `!` separators skipped):

```
route-map NAME (permit|deny) SEQ
 [description ...]              # accepted, warning-ignored
 match ip|ipv6 address ACCESS_LIST
 match ip|ipv6 address prefix-list NAME[,NAME...]
 match as-path NAME
 match community NAME[,NAME...] [exact-match|any]   # 3 modes, §6.11
 match local-preference VALUE
 match metric VALUE
 match source-protocol PROTO...            # static bgp ospf connected kernel rip isis local
 set local-preference VALUE|+VALUE|-VALUE
 set community COMM... [additive]|none
 set comm-list NAME delete                 # FRR CLI order: NAME first, delete last
 set origin egp|igp|incomplete
 set metric VALUE|+VALUE|-VALUE
 set as-path prepend ASN...
 call NAME                                 # after set actions; deny return denies
 continue [N]
 on-match next | on-match goto N
access-list NAME [seq N] (permit|deny) (PREFIX [exact-match]|any)
ipv6 access-list NAME [seq N] (permit|deny) (PREFIX [exact-match]|any)
ip|ipv6 prefix-list NAME [seq N] (permit|deny) PREFIX [le E] [ge E]
bgp as-path access-list NAME [seq N] (permit|deny) REGEX
bgp community-list standard NAME [seq N] (permit|deny) COMM...
```

**Anything else is a parse error carrying the line number — never a
silent drop.** This includes B7-observed foreign stanzas (`frr
version`, `router bgp`, `ip route`, `line vty`, ...): the policy
grammar is a *stanza-level* parser; the frr.conf importer (a later
edge stream) is expected to section the file first and hand this
parser only policy stanzas. The z5/z5b smoke configs verbatim
currently error at line 1 — asserted by unit test, so the contract
can't silently change.

Compilation (`compile_route_map(&doc, name)`) follows the FRR "Route
Maps" summary table:

- **Match** (all clauses AND'd; empty = always) + **permit** → apply
  sets, then `call` (FRR 10.2 "Route Maps": "If it returns deny ...
  the route is denied, regardless of the Matching Policy or the Exit
  Policy"; the callee's implicit deny-all counts as a deny return;
  a permit return proceeds), then exit policy (`None` → accept;
  `on-match next`/`continue` → fall through; `continue N`/
  `on-match goto N` → jump to the first entry with order ≥ N; target
  must exceed the current sequence — "jumping to a previous entry is
  not permitted"). `call NAME` targets must be defined route-maps and
  acyclic — both are compile errors carrying the `call` clause's own
  line number; the cycle error names the full cycle path (e.g.
  `a -> b -> a`). POL-1, owner-adjudicated: Rouster's undefined-ref
  convention — FRR instead looks the name up at apply time.
- **Match + deny** → deny immediately; set clauses and exit policy on a
  matched deny entry are unreachable — surfaced as compile warnings.
- **No match** → next entry. **Nothing matched** → implicit deny
  ("The default action of a route-map, if no entries match, is to
  deny").
- Same-kind match clauses replace earlier ones (FRR CLI behavior);
  comma-separated names inside one clause OR together.
- Same-seq route-map entries replace; entries sort by seq regardless of
  file order.
- `set local-preference 200` is absolute; `+200`/`-200` are relative
  (FRR documents both forms) — property-tested against an independent
  interpreter.

### Route-map → typed mapping table

| FRR construct | Typed form |
|---|---|
| `route-map N permit SEQ` | `Rule { when: AND(clauses), then: [sets…, Accept] }` |
| `route-map N deny SEQ` | `Rule { when: AND(clauses), then: [Reject] }` |
| no clauses | `Term::True` ("always matches") |
| `match ip address ACL` | `Term::AccessList(idx)` (zebra-style access-list) |
| `match ipv6 address ACL` | same (AF separation via pattern coverage) |
| `match ip address prefix-list X` | `Term::PrefixList(idx)` (+`Or` across names) |
| `match ipv6 address prefix-list X` | same (AF separation via pattern coverage) |
| `match as-path X` | `Term::PathList(idx)` |
| `match community X` | `Term::CommunityList(idx)` (default mode) |
| `match community X exact-match` | `Term::CommunityListExact(idx)` |
| `match community X any` | `Term::CommunityListAny(idx)` (POL-2 — a real mode since 2026-10-14; previously aliased default) |
| `match local-preference V` | `Term::LocalPrefIn(V, V)` |
| `match metric V` | `Term::MetricIn(V, V)` |
| `match source-protocol P...` | `Term::ProtocolIn([…])` |
| `set local-preference V / +V / -V` | `SetLocalPref(V)` / `AdjustLocalPref(±V)` |
| `set community A B additive` | `SetCommunities {list, Add}` (without `additive`: `Replace`) |
| `set community none` | `SetCommunities {[], Replace}` |
| `set comm-list X delete` | `RemoveCommunities(union of X's entries)` — FRR CLI order `NAME delete` (bgpd/bgp_routemap.c, 10.2) |
| `set origin egp|igp|incomplete` | `SetOrigin(BgpOrigin::…)` |
| `set metric V` | `SetMed(V)` / `AdjustMed(±V)` — "When used with BGP, set the BGP attribute MED" |
| `set as-path prepend A B C` | `PrependAsPath` ×3, executed right-to-left (A ends leftmost) |
| `call X` | `Action::Call(compiled X)` after the set actions; deny return → `Reject` |
| `continue N` / `on-match goto N` | `Action::Goto(first rule with seq ≥ N)` |
| `on-match next` / bare `continue` | fall-through (no terminal action) |
| implicit deny-all | `Filter` default verdict `Reject` |

## 6. Deviations and disclosed choices

1. **Fixtures**: B7 records zero route-map stanzas in any executed FRR
   config (the z-family smoke configs contain none). Grammar fixtures
   therefore come from (a) FRR's own documented examples and (b) the
   z5b r1 / z5 configs **verbatim as error-case fixtures** (asserting
   the first foreign line and its number). The B7-observed conventions
   that do carry over: leading-space indentation of stanza children,
   `!` separators, `no`-form rejection, hostname/`line vty` as foreign.
2. **BIRD-vs-FRR prefix coverage**: two different semantics, both
   implemented, deliberately separated — `PrefixPattern::covers`
   (BIRD `min(len1,len2)` bits + range, used by `PrefixSet`) vs
   `PrefixPattern::covers_frr` (subnet-of-entry + `le`/`ge`, used by
   `PrefixList`). Conflating them was caught by the BIRD §5.2 doc
   example `3.0.0.0/8-` covering `0.0.0.0/0` — now a unit test.
3. **Undefined references** (`match ... prefix-list UNDEFINED`,
   `match ip address UNDEFINED`, `call UNDEFINED`) are compile
   errors, not permit-all/no-match guesses. `call` errors carry the
   call clause's line number; `call` cycles are compile errors whose
   message names the full cycle path (`a -> b -> a`) — FRR would
   instead look the target up at apply time and loop/fail at runtime.
4. **Totality vs BIRD runtime errors** — see §4.3.
5. **`set metric`** maps to MED for BGP routes (FRR doc wording); the
   typed `Action::SetMetric` (route metric) has no route-map spelling.
6. **`description`** lines inside route-map entries are
   warning-ignored; `ip prefix-list NAME description` is an error (§7).
7. **AS_SET in masks**: a set element acts as one position matching any
   token its members satisfy (BIRD's first/last zero rule generalized).
8. **proptest** is a dev-dependency of this crate (the W5B/M3
   authorization named sav+rib; the W1-a milestone 5 requirement
   extends it — disclosed in the W1-a report).
9. **Access-list vs prefix-list coverage defaults** (M2): same network
   spelling, opposite defaults — access-list entries match subnet-of
   (exact only with `exact-match`), prefix-list entries match exact
   (subnets only via `le`/`ge`). Pinned by a unit test asserting the
   same `permit 10.0.0.0/8` line accepts `10.1.0.0/16` as an ACL and
   rejects it as a prefix-list. The representation behind this — the
   ordered `AccessList` type with its own `Term::AccessList`, never
   compiled onto `PrefixList` semantics — is the owner-adjudicated
   answer to POL-4 (2026-10-14 batch adjudication, Group D: "new
   ordered type — subnet-of default ≠ prefix-list semantics").
10. **`set comm-list` token order** (M2 fix): the parser originally
   required the inverted `set comm-list delete NAME`; FRR 10.2's CLI
   is `set comm-list NAME delete` (bgpd/bgp_routemap.c
   `set_community_delete_cmd`: "set comm-list
   <(1-99)|(100-500)|COMMUNITY_LIST_NAME> delete"). Verbatim FRR
   configs now parse; the inverted order is a parse error.
11. **`match community` three modes** (POL-2, owner-adjudicated
   2026-10-14): FRR 10.2.2 dispatches three evaluation paths in
   `route_match_community` (bgpd/bgp_routemap.c, selected by the
   trailing flag of `match_community_cmd`) — the default
   `community_list_match` (bgpd/bgp_clist.c:651: ordered entry scan;
   an entry matches when the route carries **all** its communities,
   `community_match`, bgpd/bgp_community.c:547: "Every community on
   com2 needs to be on com1 for this to match"; first matching
   entry's verdict), `exact-match` `community_list_exact_match`
   (bgp_clist.c:722: community-set equality via `community_cmp`), and
   `any` `community_list_any_match` (bgp_clist.c:735: the route needs
   just **one** listed community; the first hit — route-community
   order outer, entry order inner, `community_include` — entry's
   verdict; a community-less route makes FRR's match return RMAP_OKAY,
   which the route-map apply loop skips: no-match). Until this fix
   Rouster accepted `any` but compiled it identically to the default
   mode (the M2-disclosed deviation); each mode now maps to its own
   term. Grammar: the flag trails and is single (`exact-match any`
   together is a parse error); a lone `any` token names a list called
   "any" (FRR's flag alternation is optional), resolving as an
   undefined-list compile error.

## 7. §Deferred anchors

- W2-d: bgpd implements `RouteView`; wire the engine into the peer
  import/export seams (bgpd `rib` module's policy seams are
  accept-all v1).
- FRR constructs refused at import (all with line numbers):
  `match peer/src-peer/next-hop/evpn/tag/vpn`, `match ip|ipv6
  address prefix-len`, `match extcommunity/large-community/alias`,
  `match source-instance`, `set weight/tag/distance/as-path exclude
  [all]/replace/last-as/aigp-metric/min-metric/max-metric/sr-te/
  l3vpn/ip|ipv6 next-hop/table/large-community/extcommunity/
  extended-comm-list`, `set metric rtt|igp|aigp`, cisco-style and
  extended access-list forms (`host A.B.C.D`, `A.B.C.D M.M.M.M`,
  `access-list NAME ... ip <src> <dst>`, `ip access-list`
  named-ACL submode, `access-list NAME remark`), `bgp
  community-list expanded` (regex communities), numbered
  community-lists (FRR's `set comm-list <1-99|100-500>` numeric
  names refuse here as undefined named lists), `extcommunity-list`,
  `large-community-list`, the deprecated auto-detect `bgp
  community-list NAME ...` form, `no` forms of everything above.
- IPv4-administrator and opaque extended communities; large
  communities.
- A BIRD-syntax parser over the same `Term`/`Action` data (the
  language is Rust-API first by design; the parser is additive later).
- Prefix-set trie if sets grow beyond configuration scale.
- Benchmarks for the hot path (allocation-free claim is by
  construction, not measurement).
