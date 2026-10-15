//! Rouster `yang` — the YANG core (Phase 4 headline): a pure-Rust
//! RFC 7950-subset parser, data tree, and validator. The models live
//! in `yang/` at the repo root (embedded here at compile time);
//! configd consumes this crate as the internal source of truth
//! (architecture invariant 5), and vtyd's config mode rides the same
//! paths as a translator — never a second source of truth.
//!
//! # The subset, by RFC letter
//!
//! Implemented (see each module's docs for the exact sections):
//!
//! - lexing: §6.1 tokenization, §6.1.1 comments, §6.1.2 tokens,
//!   §6.1.3 quoting (+concatenation), §6.2 identifiers;
//! - statements: §6.3;
//! - modules: §7.1 module, §7.1.2 yang-version (1.1 only), §7.1.3
//!   namespace, §7.1.4 prefix, §7.1.5 import (single-file
//!   simplification; §7.1.5.1 revision-date parsed, not selecting),
//!   §7.1.6 include, §7.1.9 revision; §7.2 submodule (§7.2.2
//!   belongs-to);
//! - types: §7.3 typedef (§7.3.2 type, §7.3.4 default), §7.4 type,
//!   §9.2 integers (§9.2.1 lexical, §9.2.2 canonical, §9.2.4
//!   range), §9.4 string (§9.4.4 length, §9.4.5 pattern), §9.5
//!   boolean, §9.6 enumeration (§9.6.2 restriction narrows,
//!   §9.6.4 enum), §9.11 empty, §9.12 union; RFC 6991 §3.2's
//!   inet types re-derived natively (`inet:` pseudo-prefix);
//! - data: §7.5 container, §7.6 leaf (§7.6.4 default, §7.6.5
//!   mandatory), §7.7 leaf-list, §7.8 list (§7.8.2 key), §7.5.3
//!   must (§7.5.4.1 error-message) as the documented expression
//!   subset of `must.rs`, §7.21.1 config (inherited);
//! - constraints: §8.1 (data-tree validity: types, keys, must);
//! - JSON: RFC 7951 encoding for the subset (§5.1 leaf, §5.2
//!   container, §5.3 leaf-list, §5.4 list).
//!
//! NOT implemented — every one of these FAILS A SCHEMA LOAD with a
//! message naming the section (the machine-readable §Deferred):
//! grouping (§7.12), uses (§7.13), refine (§7.13.2), choice/case
//! (§7.9), anydata (§7.10), anyxml (§7.11), identity (§7.18),
//! extension (§7.19), feature/if-feature (§7.20.1/§7.20.2),
//! deviation (§7.20.3), rpc (§7.14), action (§7.15), notification
//! (§7.16), augment (§7.17), when (§7.21.5), presence containers
//! (§7.5.5), unique (§7.8.3), min/max-elements (§7.7.5/§7.7.6),
//! ordered-by (§7.7.7), decimal64 (§9.3), bits (§9.7), binary
//! (§9.8), leafref (§9.9), identityref (§9.10),
//! instance-identifier (§9.13), the §10 XPath function library,
//! multiple revisions per module (§5.1.1), deviations as conformance
//! statements (§5.6.3), and every XML consideration (§5.3, §7.x.6)
//! — this crate encodes JSON (RFC 7951) and line form, never XML.
//!
//! No dependencies beyond thiserror/tracing (workspace); the regex
//! engine for `pattern` facets is hand-written and deliberately
//! tiny (see `regex.rs` for its own §Deferred list).

pub mod data;
pub mod json;
pub mod lexer;
pub mod line;
pub mod must;
pub mod regex;
pub mod schema;
pub mod types;

pub use data::{DataError, DataTree, Origin, Path, PathSeg, Violation};
pub use schema::{
    parse_module_text, parse_statements, ContainerDef, DataDef, LeafDef, LeafListDef, ListDef,
    Module, ModuleKind, ModuleSet, Schema, SchemaError, Statement, TypeSpec, Typedef,
};
pub use types::{InetType, IntKind, Type};
