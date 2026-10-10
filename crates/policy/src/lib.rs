//! Rouster `policy` — the typed, compiled filter engine (BIRD-inspired)
//! plus the FRR route-map compatibility grammar for frr.conf import.
//!
//! Architecture invariant 4 (docs/architecture.md): "Policy engine is
//! typed and compiled (BIRD-inspired); route-map grammar exists only as
//! an import-compatibility layer."
//!
//! Layers, bottom-up:
//!
//! - [`route`]: `RouteView` — the generic window a filter sees — and the
//!   policy-owned BGP attribute model (`AsPath`, communities, origin,
//!   OTC).
//! - [`sets`]: sets as data — prefix-sets with longest-match tags (BIRD
//!   prefix-set semantics), FRR-style ordered prefix-lists, interval
//!   AS-sets, community sets.
//! - [`asregex`]: the FRR AS-path regular-expression subset (`^ $ _ .  *
//!   + ? | []`) as a dependency-free NFA-simulation matcher.
//! - [`filter`]: the typed filter language — match terms, boolean
//!   combinators, `then { accept; reject; set ...; }` actions; a filter
//!   builds once and evaluates many times, purely and (on the hot path)
//!   allocation-free.
//! - [`routemap`]: the parser from FRR route-map/prefix-list/community-list
//!   syntax into the typed engine — the frr.conf-import edge. Unknown
//!   keywords are parse errors carrying line numbers, never silently
//!   dropped.

pub mod asregex;
pub mod filter;
pub mod route;
pub mod routemap;
pub mod sets;

pub use asregex::{AsRegex, AsRegexError};
pub use filter::{
    Action, AsPathMask, Attr, CommMode, Filter, FilterBuilder, MaskToken, Rule, SetIndex, SetKind,
    SetTables, Term, Verdict,
};
pub use route::{
    AsPath, AsSegment, BgpAttrs, BgpOrigin, Community, ExtCommunity, ExtCommunityKind, RouteData,
    RouteView, WellKnownCommunity,
};
pub use routemap::{
    compile_route_map, parse_policy_config, CompileOutput, PolicyConfigError, PolicyDocument,
    RmEntry, RmExit, RmMatch, RmNum, RmPolicy, RmSet, RouteMap,
};
pub use sets::{
    AsPathAccessList, AsPathListEntry, AsSet, CommunityAccessList, CommunityListEntry,
    CommunityPattern, CommunitySet, ExtCommunityPattern, ExtCommunitySet, PrefixList,
    PrefixListEntry, PrefixListVerdict, PrefixMatch, PrefixPattern, PrefixSet,
};
