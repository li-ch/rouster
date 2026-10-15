//! The RESTCONF resource map on the YANG tree (S12-a M2) and the
//! mutation flow through the apply pipeline (M3) — the decision-C
//! scope: the operations on datastore subtrees, every verb routed
//! through the tree's own type checks and validation BEFORE
//! anything is written.
//!
//! # The resource map
//!
//! The datastore IS the canonical config (RFC 8040 §3.4's datastore
//! resource mapped onto `rouster.conf`); its JSON form is exactly
//! `configd dump --json`'s (RFC 7951, defaults filled — report-all,
//! `#unmodeled-<daemon>` the pass-through disclosure):
//!
//! | URL (under `/restconf/data`) | Tree target | RFC 8040 |
//! |---|---|---|
//! | `` (empty tail) | the whole datastore (dump shape) | §3.4 |
//! | `/router-id` | the configd-owned envelope leaf | §3.5 |
//! | `/<daemon>` | that section's bound tree | §3.5 |
//! | `/<daemon>/<path…>` | a subtree / leaf inside it | §3.5 |
//!
//! Path segments after the section accept BOTH key forms: the
//! RESTCONF API form `list=v1,v2` (§3.5.3: positional, key names
//! taken from the schema, values percent-decoded) and the YANG
//! predicate form `list[name=v1]` (what the in-house `Path` and the
//! vtyd seam speak — friendlier for scripted edits; an extension,
//! disclosed). Segments split on RAW bytes before percent-decoding,
//! so an encoded `%2F` inside a key value cannot split a segment.
//!
//! # The verbs (RFC 8040 §4; deviations disclosed)
//!
//! - **GET** (§4.3): the subtree as RFC 7951 JSON — 200, or 404
//!   with the §7.1 error form. `HEAD` answers GET with no body
//!   (§4.2), `OPTIONS` answers the Allow set (§4.1) — the server's
//!   half.
//! - **PUT** (§4.5): REPLACE the target subtree (delete + load;
//!   create when absent → 201 — including a whole missing `daemon`
//!   section). A body that fails JSON parsing, names an unknown
//!   member, trips a type check, or violates a `must`/mandatory is
//!   a **400 with per-path errors and the tree untouched** — no
//!   file is written until every gate passes (the tree's own
//!   validation, then the deep `--validate-config` gate — the
//!   pipeline's steps 1.4/1.5 reused, not reimplemented).
//! - **POST = merge** — RFC 8040's POST is create/RPC-invoke
//!   (§4.4); the merge semantics are the decision-C cut (the
//!   §4.6.1 plain-PATCH shape). `PATCH` is accepted as the same
//!   merge — for THAT verb this is conformant (§4.6). Lists merge
//!   by key (§7.8.2), leafs overwrite, leaf-lists append
//!   (appending a duplicate is a validate-time 400 — delete first).
//! - **DELETE** (§4.7): remove the target; 404 when absent. A
//!   section-level DELETE wipes the daemon's config (an empty body
//!   is a legitimate canonical section). Every mutation answers
//!   200/201 with the ack summary body rather than §4.7's bare 204
//!   — the body is the point (disclosed).
//!
//! # The two datastores (M3)
//!
//! `data` = the candidate (the canonical file); `running` = the
//! last CONFIRMED generation (`<run>/configd/current`) — the two
//! forms the suite has. RFC 8040 has ONE datastore resource (§3.4);
//! splitting it follows RFC 6241 §8.1's running/candidate
//! distinction and is disclosed as a Rouster extension. `running`
//! is read-only (mutations → 405).
//!
//! # What an accepted mutation does (M3)
//!
//! Render the mutated section FROM the tree (linebind render:
//! origins verbatim, synthesized nodes generated) → splice the new
//! body into the canonical file (only the targeted section's bytes
//! change) → run the FULL existing pipeline ([`crate::apply::apply`]:
//! bind, validate, deep gate, atomic writes, SIGHUP, post-signal
//! verification, auto-rollback) — the transactional guarantee is
//! configd's, the HTTP layer only maps verbs. The response carries
//! the per-daemon ack summary in `configd.status`'s vocabulary, as
//! JSON. A pipeline failure after staging (e.g. a refused reload
//! that auto-rolled back) is a 409 with the apply's own error
//! story; the canonical file then holds the staged-but-refused
//! bytes — the vtyd write-path precedent, disclosed.

use std::net::Ipv4Addr;
use std::path::PathBuf;

use yang::data::{DataTree, Node, NodeKind, Path, PathSeg};
use yang::json::{self, Json};
use yang::line::SourceLine;
use yang::schema::{DataDef, Schema};
use yang::types::Type;

use crate::apply::{self, ApplyOptions, ApplyReport, RollbackSource};
use crate::atomic::write_atomic;
use crate::tree::{self, Canonical, Daemon};
use crate::validate;
use crate::yangmode::{self, dialect_for, Bound};

/// The media type every JSON body carries (RFC 8040 §3.2's
/// yang-data form; the encoding itself is RFC 7951).
pub const JSON_MEDIA_TYPE: &str = "application/yang-data+json";

/// Where the server finds everything.
#[derive(Debug, Clone)]
pub struct Datastore {
    /// The canonical file — the CANDIDATE datastore (`/restconf/data`).
    pub canonical: PathBuf,
    /// The run dir: the RUNNING view reads `<run>/configd/current`;
    /// applies write generations and `configd.status` here.
    pub run_dir: PathBuf,
    /// The etc-dir daemon files render into (forwarded to apply).
    pub etc_dir: PathBuf,
}

impl Datastore {
    pub fn opts(&self) -> ApplyOptions {
        ApplyOptions {
            run_dir: self.run_dir.clone(),
            etc_dir: self.etc_dir.clone(),
        }
    }
}

/// A reply the server can write as-is.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Reply {
    pub status: u16,
    pub body: String,
}

impl Reply {
    fn json(status: u16, body: String) -> Reply {
        Reply { status, body }
    }
}

/// An API-level failure — always rendered as the RFC 8040 §7.1
/// error form (the §3.9 "errors" template; `error-tag` vocabulary
/// from the NETCONF RFC 6241 Appendix A set RESTCONF uses).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApiError {
    pub status: u16,
    pub tag: &'static str,
    pub message: String,
    /// `error-path` (§7.1) — the offending data path, when known.
    pub path: Option<String>,
}

impl ApiError {
    fn new(status: u16, tag: &'static str, message: impl Into<String>) -> ApiError {
        ApiError {
            status,
            tag,
            message: message.into(),
            path: None,
        }
    }

    pub fn not_found(message: impl Into<String>) -> ApiError {
        ApiError::new(404, "invalid-value", message)
    }

    pub fn bad_request(message: impl Into<String>) -> ApiError {
        ApiError::new(400, "invalid-value", message)
    }

    pub fn internal(message: impl Into<String>) -> ApiError {
        ApiError::new(500, "operation-failed", message)
    }

    /// The RFC 8040 §7.1 JSON rendering.
    pub fn body(&self) -> String {
        let mut err = format!(
            "{{\"error-type\":\"application\",\"error-tag\":\"{}\",\"error-message\":",
            self.tag
        );
        push_json_string(&self.message, &mut err);
        if let Some(path) = &self.path {
            err.push_str(",\"error-path\":");
            push_json_string(path, &mut err);
        }
        err.push('}');
        format!("{{\"ietf-restconf:errors\":{{\"error\":[{err}]}}}}")
    }

    fn into_reply(self) -> Reply {
        Reply::json(self.status, self.body())
    }
}

/// JSON string literal with escapes (the RFC 7951 §5.1 form; the
/// same escapes `crates/yang`'s encoder emits).
fn push_json_string(s: &str, out: &mut String) {
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('"');
}

// ---- the request target ----

/// Which datastore a target addresses.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Store {
    /// `/restconf/data` — the candidate (the canonical file).
    Candidate,
    /// `/restconf/running` — the last confirmed generation.
    Running,
}

/// Splits a request target into (store, tail). Rejects query
/// strings (the §4.8 parameters are not supported — disclosed).
pub fn split_target(target: &str) -> Result<(Store, &str), ApiError> {
    if target.contains('?') {
        return Err(ApiError::bad_request(
            "query parameters are not supported (RFC 8040 §4.8 is §Deferred)",
        ));
    }
    let stripped = target
        .strip_prefix("/restconf/data")
        .map(|tail| (Store::Candidate, tail))
        .or_else(|| {
            target
                .strip_prefix("/restconf/running")
                .map(|tail| (Store::Running, tail))
        });
    match stripped {
        Some((store, tail)) if tail.is_empty() || tail.starts_with('/') => Ok((store, tail)),
        // `/restconf/datastore…` is not this resource.
        _ => Err(ApiError::not_found(format!(
            "no such resource `{target}` (the datastore resources are /restconf/data and /restconf/running)"
        ))),
    }
}

/// One resolved resource.
#[derive(Debug, Clone)]
pub enum Target {
    /// The datastore root (the whole dump shape).
    Root,
    /// The configd-owned envelope leaf.
    RouterId,
    /// One daemon section + the path inside it (empty tail = the
    /// section root). `tree` is the section's bound tree when the
    /// section exists, else a fresh tree for the daemon's model
    /// (PUT may create the section; GET/DELETE 404 via `exists`).
    Section {
        daemon: Daemon,
        tail: Vec<PathSeg>,
        exists: bool,
        tree: DataTree,
    },
}

/// Resolves a store tail against the bound view.
pub fn resolve_target(tail: &str, bound: &Bound) -> Result<Target, ApiError> {
    let segs = parse_api_segments(tail)?;
    let mut it = segs.into_iter();
    let Some(first) = it.next() else {
        return Ok(Target::Root);
    };
    if first.keys.is_empty() && first.name == "router-id" {
        if it.next().is_some() {
            return Err(ApiError::not_found("`router-id` is a leaf"));
        }
        return Ok(Target::RouterId);
    }
    let Some(daemon) = Daemon::from_name(&first.name) else {
        return Err(ApiError::not_found(format!(
            "`{}` is not a datastore member (known: router-id, {})",
            first.name,
            Daemon::all()
                .iter()
                .map(|d| d.name())
                .collect::<Vec<_>>()
                .join(", ")
        )));
    };
    // The schema for the walk: the live section's, or the daemon
    // model's for a section the file does not carry (PUT creates).
    let (exists, tree) = match bound.section(daemon) {
        Some(section) => (true, section.tree.clone()),
        None => (false, DataTree::empty(schema_for_daemon(daemon))),
    };
    let mut tail: Vec<PathSeg> = Vec::new();
    for seg in it {
        let parents = tail.clone();
        tail.push(fill_positional(seg, &parents, &tree)?);
    }
    // Every segment must exist in the schema (a path the schema
    // does not define is a 404 here, not a 500 at load time).
    if !tail.is_empty() {
        walk_defs(&tree, &tail)?;
    }
    Ok(Target::Section {
        daemon,
        tail,
        exists,
        tree,
    })
}

fn schema_for_daemon(daemon: Daemon) -> Schema {
    let module = yang::models::module_for_daemon(daemon.name())
        .unwrap_or_else(|| panic!("every daemon has a model: {}", daemon.name()));
    yang::models::schema(module)
}

/// One decoded API-path segment in pre-schema form: positional key
/// values carry an empty key NAME (filled against the schema).
#[derive(Debug, Clone)]
struct ApiSeg {
    name: String,
    /// (name, value) — empty name = positional.
    keys: Vec<(String, String)>,
}

fn parse_api_segments(tail: &str) -> Result<Vec<ApiSeg>, ApiError> {
    let mut out = Vec::new();
    for raw in raw_segments(tail)? {
        let seg = percent_decode(&raw)?;
        if seg.is_empty() {
            return Err(ApiError::bad_request("empty path segment"));
        }
        if seg.contains('[') {
            // The YANG predicate form: reuse the in-house path
            // parser's segment validation (`name[k=v][k2=v2]`).
            let parsed = Path::parse(&format!("/{seg}"))
                .map_err(|e| ApiError::bad_request(format!("bad path segment `{seg}`: {e}")))?;
            let mut parsed = parsed.segs.into_iter();
            let Some(one) = parsed.next() else {
                return Err(ApiError::bad_request(format!("bad path segment `{seg}`")));
            };
            if parsed.next().is_some() {
                return Err(ApiError::bad_request(format!(
                    "segment `{seg}` carries more than one node"
                )));
            }
            out.push(ApiSeg {
                name: one.name,
                keys: one.keys,
            });
        } else if let Some((name, values)) = seg.split_once('=') {
            if name.is_empty() || values.is_empty() {
                return Err(ApiError::bad_request(format!(
                    "bad key form `{seg}` (expected `list=key[,key…]`)"
                )));
            }
            out.push(ApiSeg {
                name: name.to_string(),
                keys: values
                    .split(',')
                    .map(|v| (String::new(), v.to_string()))
                    .collect(),
            });
        } else {
            out.push(ApiSeg {
                name: seg,
                keys: Vec::new(),
            });
        }
    }
    Ok(out)
}

/// The raw (pre-decode) path segments of a tail.
fn raw_segments(tail: &str) -> Result<Vec<String>, ApiError> {
    if tail.is_empty() {
        return Ok(Vec::new());
    }
    let tail = tail
        .strip_prefix('/')
        .ok_or_else(|| ApiError::internal("split_target guaranteed a leading slash"))?;
    Ok(tail.split('/').map(str::to_string).collect())
}

/// Percent-decoding (RFC 3986 §2.1; `+` rides verbatim — this is a
/// path, not a form).
fn percent_decode(raw: &str) -> Result<String, ApiError> {
    let bytes = raw.as_bytes();
    let mut out: Vec<u8> = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' {
            let hex = bytes.get(i + 1..i + 3).ok_or_else(|| {
                ApiError::bad_request(format!("truncated percent-escape in `{raw}`"))
            })?;
            let digit = |b: u8| {
                (b as char)
                    .to_digit(16)
                    .ok_or_else(|| ApiError::bad_request(format!("bad percent-escape in `{raw}`")))
            };
            out.push((digit(hex[0])? * 16 + digit(hex[1])?) as u8);
            i += 3;
        } else {
            out.push(bytes[i]);
            i += 1;
        }
    }
    String::from_utf8(out)
        .map_err(|_| ApiError::bad_request(format!("path segment `{raw}` is not valid UTF-8")))
}

/// Fills positional key names against the schema walk so far (the
/// parent chain names the list's keys — RFC 8040 §3.5.3).
fn fill_positional(seg: ApiSeg, parents: &[PathSeg], tree: &DataTree) -> Result<PathSeg, ApiError> {
    if seg.keys.is_empty() || seg.keys.iter().all(|(k, _)| !k.is_empty()) {
        return Ok(PathSeg {
            name: seg.name,
            keys: seg.keys,
        });
    }
    let parent_defs = walk_defs(tree, parents)?;
    let siblings: Vec<DataDef> = match parent_defs.last() {
        Some(def) => children_of(def),
        None => module_defs(tree),
    };
    let def = siblings
        .iter()
        .find(|d| d.name() == seg.name)
        .ok_or_else(|| {
            ApiError::not_found(format!(
                "`{}` is not a child here (schema has: {})",
                seg.name,
                siblings
                    .iter()
                    .map(|d| d.name())
                    .collect::<Vec<_>>()
                    .join(", ")
            ))
        })?;
    let DataDef::List(list) = def else {
        return Err(ApiError::bad_request(format!(
            "`{}` is not a list (positional keys need one)",
            seg.name
        )));
    };
    if seg.keys.len() != list.keys.len() {
        return Err(ApiError::bad_request(format!(
            "list `{}` needs {} key value(s): `{}={}`",
            seg.name,
            list.keys.len(),
            seg.name,
            list.keys.join(",")
        )));
    }
    Ok(PathSeg {
        name: seg.name,
        keys: seg
            .keys
            .into_iter()
            .zip(list.keys.iter())
            .map(|((_, v), k)| (k.clone(), v))
            .collect(),
    })
}

/// The module's root data definitions (owned clones — the caller
/// mutates the tree while holding these; `DataDef` chains are small
/// schema fragments).
fn module_defs(tree: &DataTree) -> Vec<DataDef> {
    tree.schema.set.modules[&tree.schema.module].data.clone()
}

fn children_of(def: &DataDef) -> Vec<DataDef> {
    match def {
        DataDef::Container(c) => c.children.clone(),
        DataDef::List(l) => l.children.clone(),
        _ => Vec::new(),
    }
}

/// Walks the schema along segments, requiring each name to exist
/// (key completeness is `DataTree`'s check, with the precise §7.8.2
/// message). Returns the chain of definitions.
fn walk_defs(tree: &DataTree, segs: &[PathSeg]) -> Result<Vec<DataDef>, ApiError> {
    let mut chain = Vec::new();
    let mut children = module_defs(tree);
    for seg in segs {
        let def = children
            .iter()
            .find(|d| d.name() == seg.name)
            .cloned()
            .ok_or_else(|| {
                ApiError::not_found(format!(
                    "`{}` is not a child here (schema has: {})",
                    seg.name,
                    children
                        .iter()
                        .map(|d| d.name())
                        .collect::<Vec<_>>()
                        .join(", ")
                ))
            })?;
        children = children_of(&def);
        chain.push(def);
    }
    Ok(chain)
}

// ---- views ----

/// The candidate view: the canonical file parsed and bound.
pub fn load_candidate(store: &Datastore) -> Result<Bound, ApiError> {
    let bytes = std::fs::read(&store.canonical).map_err(|e| {
        ApiError::internal(format!(
            "cannot read the canonical {}: {e}",
            store.canonical.display()
        ))
    })?;
    let text = String::from_utf8(bytes)
        .map_err(|_| ApiError::internal("the canonical file is not valid UTF-8"))?;
    let parsed = tree::parse(&text)
        .map_err(|e| ApiError::internal(format!("the canonical file does not parse: {e}")))?;
    yangmode::bind(&parsed)
        .map_err(|e| ApiError::internal(format!("the canonical file does not bind: {e}")))
}

/// The running view: the last CONFIRMED generation's bytes.
pub fn load_running(store: &Datastore) -> Result<Bound, ApiError> {
    let bytes = apply::current_generation(&store.run_dir)
        .map_err(|e| ApiError::internal(format!("cannot read the generation store: {e}")))?;
    let bytes = bytes.ok_or_else(|| {
        ApiError::not_found(
            "no confirmed generation yet — nothing has been applied (the running view exists after the first apply)",
        )
    })?;
    let text = String::from_utf8(bytes)
        .map_err(|_| ApiError::internal("the current generation is not valid UTF-8"))?;
    let parsed = tree::parse(&text)
        .map_err(|e| ApiError::internal(format!("the current generation does not parse: {e}")))?;
    yangmode::bind(&parsed)
        .map_err(|e| ApiError::internal(format!("the current generation does not bind: {e}")))
}

// ---- GET ----

/// GET (and HEAD, whose body the server drops): the target's RFC
/// 7951 JSON. Pure read — no gates, no writes.
pub fn get(store: &Datastore, running: bool, tail: &str) -> Result<Reply, ApiError> {
    let bound = if running {
        load_running(store)?
    } else {
        load_candidate(store)?
    };
    let target = resolve_target(tail, &bound)?;
    match target {
        Target::Root => Ok(Reply::json(200, yangmode::dump_json(&bound))),
        Target::RouterId => match bound.router_id {
            Some((_, addr)) => Ok(Reply::json(200, format!("{{\"router-id\":\"{addr}\"}}"))),
            None => Err(ApiError::not_found("`router-id` is not set")),
        },
        Target::Section { daemon, tail, .. } => {
            let section = bound.section(daemon).ok_or_else(|| {
                ApiError::not_found(format!(
                    "no `daemon {}` section in the canonical config",
                    daemon.name()
                ))
            })?;
            get_section(section, daemon, &tail)
        }
    }
}

fn get_section(
    section: &crate::yangmode::SectionBind,
    daemon: Daemon,
    tail: &[PathSeg],
) -> Result<Reply, ApiError> {
    let mut tree = section.tree.clone();
    tree.default_fill();
    let mut body = if tail.is_empty() {
        yang::json::encode(&tree)
    } else {
        let path = Path {
            segs: tail.to_vec(),
        };
        let node = tree.get(&path).ok_or_else(|| {
            ApiError::not_found(format!(
                "`{}` does not exist in `daemon {}`",
                path.to_string_path(),
                daemon.name()
            ))
        })?;
        let chain = walk_defs(&section.tree, tail)?;
        let def = chain.last().expect("walk returned the final def");
        format!(
            "{{\"{}\":{}}}",
            tail.last().expect("nonempty").name,
            node_json(node, def)
        )
    };
    // The pass-through disclosure rides section-level replies (the
    // dump's placement).
    if tail.is_empty() && !section.report.unmodeled.is_empty() {
        let lines: Vec<String> = section
            .report
            .unmodeled
            .iter()
            .map(|l| l.to_string())
            .collect();
        let head = &body[..body.len() - 1]; // drop the closing brace
        body = format!(
            "{head},\"#unmodeled-{}\":[{}]}}",
            daemon.name(),
            lines.join(",")
        );
    }
    Ok(Reply::json(200, body))
}

/// A node encoded against its definition — the RFC 7951 shapes
/// (leafs §5.1, containers §5.2, leaf-lists §5.3, lists §5.4, type
/// mapping §6), members in schema order (the encoder's rule).
fn node_json(node: &Node, def: &DataDef) -> String {
    match (&node.kind, def) {
        (NodeKind::Leaf { value, .. }, DataDef::Leaf(leaf)) => {
            typed_json(value, leaf.resolved.as_ref())
        }
        (NodeKind::LeafList(values), DataDef::LeafList(ll)) => {
            let items: Vec<String> = values
                .iter()
                .map(|v| typed_json(&v.value, ll.resolved.as_ref()))
                .collect();
            format!("[{}]", items.join(","))
        }
        (NodeKind::Container(children), DataDef::Container(c)) => {
            format!("{{{}}}", children_json(children, &c.children))
        }
        (NodeKind::List(entries), DataDef::List(l)) => {
            let items: Vec<String> = entries
                .iter()
                .map(|entry| match &entry.kind {
                    NodeKind::Entry { children, .. } => {
                        format!("{{{}}}", children_json(children, &l.children))
                    }
                    _ => "null".to_string(),
                })
                .collect();
            format!("[{}]", items.join(","))
        }
        (NodeKind::Entry { children, .. }, DataDef::List(l)) => {
            format!("{{{}}}", children_json(children, &l.children))
        }
        // Opaque lines never encode (line-form-only; the disclosure
        // rides the #unmodeled member instead).
        _ => "null".to_string(),
    }
}

fn children_json(nodes: &[Node], defs: &[DataDef]) -> String {
    let mut out = String::new();
    let mut first = true;
    for def in defs {
        for node in nodes.iter().filter(|n| n.name == def.name()) {
            if matches!(node.kind, NodeKind::Opaque(_)) {
                continue;
            }
            if !first {
                out.push(',');
            }
            first = false;
            out.push_str(def.name());
            out.push(':');
            out.push_str(&node_json(node, def));
        }
    }
    out
}

fn typed_json(value: &str, ty: Option<&Type>) -> String {
    match ty {
        Some(Type::Int(_, _)) | Some(Type::Boolean) => value.to_string(),
        Some(Type::Empty) => "null".to_string(),
        _ => {
            let mut out = String::new();
            push_json_string(value, &mut out);
            out
        }
    }
}

// ---- mutations ----

/// The mutation verbs (RFC 8040 §4.5 PUT / §4.6.1 plain-PATCH
/// merge; §4.7 DELETE).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verb {
    Put,
    Merge,
    Delete,
}

impl Verb {
    /// The Allow-header word set for this edge.
    pub const ALLOW: &'static str = "OPTIONS, HEAD, GET, PUT, POST, PATCH, DELETE";
}

/// The full validate-first mutation flow (sync — file IO and the
/// apply pipeline; callers wrap in a blocking task under the
/// single-flight lock).
pub fn mutate(store: &Datastore, running: bool, verb: Verb, tail: &str, body: &[u8]) -> Reply {
    if running {
        return ApiError::new(
            405,
            "operation-not-supported",
            "the running view is read-only (the last confirmed generation) — mutate /restconf/data",
        )
        .into_reply();
    }
    let result = match verb {
        Verb::Put | Verb::Merge => mutate_data(store, verb, tail, body),
        Verb::Delete => delete_data(store, tail),
    };
    match result {
        Ok(reply) => reply,
        Err(err) => err.into_reply(),
    }
}

fn read_candidate(store: &Datastore) -> Result<(String, Canonical, Bound), ApiError> {
    let original = std::fs::read_to_string(&store.canonical).map_err(|e| {
        ApiError::internal(format!(
            "cannot read the canonical {}: {e}",
            store.canonical.display()
        ))
    })?;
    let parsed = tree::parse(&original)
        .map_err(|e| ApiError::internal(format!("the canonical file does not parse: {e}")))?;
    let bound = yangmode::bind(&parsed)
        .map_err(|e| ApiError::internal(format!("the canonical file does not bind: {e}")))?;
    Ok((original, parsed, bound))
}

fn mutate_data(store: &Datastore, verb: Verb, tail: &str, body: &[u8]) -> Result<Reply, ApiError> {
    let text = String::from_utf8(body.to_vec())
        .map_err(|_| ApiError::bad_request("the body is not valid UTF-8"))?;
    let value = json::parse(text.trim())
        .map_err(|e| ApiError::bad_request(format!("the body is not valid JSON: {e}")))?;

    let (original, parsed, bound) = read_candidate(store)?;
    let target = resolve_target(tail, &bound)?;

    let (new_text, created) = match target {
        Target::Root => {
            return Err(ApiError::new(
                405,
                "operation-not-supported",
                "PUT/POST on the datastore root is not defined (RFC 8040 §3.4); target a section or a path inside one",
            ))
        }
        Target::RouterId => (mutate_router_id(&parsed, &original, &value)?, false),
        Target::Section { daemon, tail, exists, tree } => {
            mutate_section(SectionEdit {
                original: &original,
                parsed: &parsed,
                daemon,
                tail: &tail,
                exists,
                tree,
                verb,
                value: &value,
            })?
        }
    };

    commit(store, new_text, verb, created)
}

fn delete_data(store: &Datastore, tail: &str) -> Result<Reply, ApiError> {
    let (original, parsed, bound) = read_candidate(store)?;
    let target = resolve_target(tail, &bound)?;

    let new_text = match target {
        Target::Root => {
            return Err(ApiError::new(
                405,
                "operation-not-supported",
                "DELETE on the datastore root is not defined (RFC 8040 §3.4)",
            ))
        }
        Target::RouterId => match parsed.router_id {
            Some((line, _)) => splice_out_lines(&original, line, line)?,
            None => return Err(ApiError::not_found("`router-id` is not set")),
        },
        Target::Section {
            daemon, tail, tree, ..
        } => {
            let section = parsed.section(daemon).ok_or_else(|| {
                ApiError::not_found(format!(
                    "no `daemon {}` section in the canonical config",
                    daemon.name()
                ))
            })?;
            if tail.is_empty() {
                // Section-level DELETE = wipe the daemon's config (a
                // legitimate empty body in the canonical grammar).
                splice_body(
                    &original,
                    section.header_line,
                    section.close_line.expect("parse guarantees the closer"),
                    "",
                )?
            } else {
                let mut tree = tree;
                let path = Path { segs: tail };
                tree.delete(&path).map_err(|e| {
                    let mut err = ApiError::not_found(e.to_string());
                    err.path = Some(path.to_string_path());
                    err
                })?;
                let body = render_mutated(tree, daemon)?;
                splice_body(
                    &original,
                    section.header_line,
                    section.close_line.expect("parse guarantees the closer"),
                    &body,
                )?
            }
        }
    };
    commit(store, new_text, Verb::Delete, false)
}

/// PUT/POST on the envelope leaf: set/overwrite the `router-id`
/// line (the address validated here — the bind gate follows).
fn mutate_router_id(parsed: &Canonical, original: &str, value: &Json) -> Result<String, ApiError> {
    let Json::Str(raw) = value else {
        return Err(ApiError::bad_request(
            "the body must be an IPv4 address string",
        ));
    };
    let addr: Ipv4Addr = raw
        .parse()
        .map_err(|_| ApiError::bad_request(format!("`{raw}` is not an IPv4 address")))?;
    match parsed.router_id {
        Some((line, _)) => splice_replace_line(original, line, &format!("router-id {addr}")),
        // Create (PUT or POST on an absent leaf): append a top-level
        // line — the canonical grammar is order-free up there.
        None => {
            let mut out = original.to_string();
            if !out.ends_with('\n') {
                out.push('\n');
            }
            out.push_str(&format!("router-id {addr}\n"));
            Ok(out)
        }
    }
}

/// The section-mutation inputs ([`mutate_section`]'s bundle).
struct SectionEdit<'a> {
    original: &'a str,
    parsed: &'a Canonical,
    daemon: Daemon,
    tail: &'a [PathSeg],
    exists: bool,
    tree: DataTree,
    verb: Verb,
    value: &'a Json,
}

/// PUT/POST on a daemon section: mutate the section's tree
/// (replacing it wholesale on section-level PUT), validate it,
/// render it — the caller commits. Returns (new canonical, created)
/// for the 200/201 distinction (§4.5).
fn mutate_section(edit: SectionEdit<'_>) -> Result<(String, bool), ApiError> {
    let SectionEdit {
        original,
        parsed,
        daemon,
        tail,
        exists,
        tree,
        verb,
        value,
    } = edit;
    let mut tree = tree;
    // Section-level PUT replaces the WHOLE tree (RFC 8040 §4.5);
    // everything else mutates in place.
    if verb == Verb::Put && tail.is_empty() {
        tree = DataTree::empty(tree.schema.clone());
    }
    let path = Path {
        segs: tail.to_vec(),
    };
    let existed = tree.get(&path).is_some();

    match verb {
        Verb::Put => {
            // Replace: drop the subtree if present (§4.5: PUT
            // creates when absent).
            if existed {
                tree.delete(&path).map_err(|e| {
                    let mut err = ApiError::bad_request(e.to_string());
                    err.path = Some(path.to_string_path());
                    err
                })?;
            }
            load_into(&mut tree, &path, value)?;
        }
        Verb::Merge => load_into(&mut tree, &path, value)?,
        Verb::Delete => unreachable!("delete_data handles DELETE"),
    }

    // The tree's own validation gate — every violation a 400 with
    // its data path (§7.1's error-path).
    let violations = tree.validate();
    if !violations.is_empty() {
        let details = violations
            .iter()
            .map(|v| v.to_string())
            .collect::<Vec<_>>()
            .join("; ");
        return Err(ApiError::new(400, "validation-failed", details));
    }

    let body = render_mutated(tree, daemon)?;
    let text = if let Some(section) = parsed.section(daemon) {
        splice_body(
            original,
            section.header_line,
            section.close_line.expect("parse guarantees the closer"),
            &body,
        )?
    } else {
        // A whole new section (PUT/POST creating one).
        append_section(original, daemon, &body)
    };
    Ok((text, !exists))
}

/// Renders a mutated tree back to section body bytes: the modeled
/// nodes SYNTHESIZED (a mutated leaf's old source line would
/// otherwise ride its origin — stale bytes for a changed value),
/// the unmodeled Opaque lines verbatim — the vtyd write path's
/// exact render discipline (modeled lines canonical, passthrough
/// byte-identical). Then a re-bind through configd's own
/// byte-stable render: the output is what the apply pipeline's
/// render emits, and a re-parse of it reproduces the tree.
fn render_mutated(mut tree: DataTree, daemon: Daemon) -> Result<String, ApiError> {
    strip_render_origins(&mut tree.children);
    let dialect = dialect_for(daemon);
    let lines = yang::line::render(&tree, &dialect);
    let sources: Vec<SourceLine> = lines
        .iter()
        .enumerate()
        .map(|(i, l)| SourceLine {
            line: i + 1,
            text: l.text.clone(),
        })
        .collect();
    let (rebound, _) = yang::line::parse(&tree.schema, &sources, &dialect)
        .map_err(|e| ApiError::internal(format!("the mutated section does not re-render: {e}")))?;
    let bind = crate::yangmode::SectionBind {
        daemon,
        tree: rebound,
        // The report is inert to render_daemon (it walks origins).
        report: yang::line::BindReport {
            modeled: 0,
            ignorable: 0,
            unmodeled: Vec::new(),
        },
    };
    Ok(yangmode::render_daemon(&bind))
}

/// Clears every render origin except the Opaque bucket's (the
/// unmodeled lines ARE content; modeled origins would render stale
/// bytes after a mutation — the synthesized form is the truth).
fn strip_render_origins(nodes: &mut [Node]) {
    for node in nodes {
        match &mut node.kind {
            NodeKind::Opaque(_) => {}
            NodeKind::Container(children) => {
                node.origin = None;
                strip_render_origins(children);
            }
            NodeKind::List(entries) => strip_render_origins(entries),
            NodeKind::Entry {
                children, openers, ..
            } => {
                openers.clear();
                node.origin = None;
                strip_render_origins(children);
            }
            NodeKind::Leaf { assignments, .. } => {
                node.origin = None;
                assignments.clear();
            }
            NodeKind::LeafList(values) => {
                node.origin = None;
                for v in values {
                    v.origin = None;
                }
            }
        }
    }
}

/// Appends a brand-new `daemon <name> { … }` section.
fn append_section(original: &str, daemon: Daemon, body: &str) -> String {
    let mut out = original.to_string();
    if !out.ends_with('\n') {
        out.push('\n');
    }
    out.push_str(&format!("daemon {} {{\n", daemon.name()));
    for line in body.lines() {
        out.push_str(line);
        out.push('\n');
    }
    out.push_str("}\n");
    out
}

/// Loads a decoded JSON value into the tree at `path` — every value
/// routes through `DataTree::set`/`set_leaf_list` (type checks,
/// §7.8.2 key-merge lists, §7.6.7 leaf overwrite). PUT callers
/// pre-delete; merge callers do not.
fn load_into(tree: &mut DataTree, path: &Path, value: &Json) -> Result<(), ApiError> {
    let err = |e: yang::data::DataError| -> ApiError {
        let mut err = ApiError::bad_request(e.to_string());
        err.path = Some(path.to_string_path());
        err
    };
    // The section root: the body's members address module-root defs.
    let root_members: Option<Vec<DataDef>> = if path.segs.is_empty() {
        Some(module_defs(tree))
    } else {
        None
    };
    if let Some(defs) = root_members {
        let Json::Obj(members) = value else {
            return Err(ApiError::bad_request(
                "the section body must be a JSON object",
            ));
        };
        for (key, v) in members {
            let def = defs.iter().find(|d| d.name() == key).ok_or_else(|| {
                ApiError::bad_request(format!("`{key}` is not in the section's model"))
            })?;
            load_into(
                tree,
                &Path {
                    segs: vec![seg_of(def)],
                },
                v,
            )?;
        }
        return Ok(());
    }

    let chain = walk_defs(tree, &path.segs)?;
    let Some(def) = chain.last().cloned() else {
        return Err(ApiError::internal(
            "walk_defs returned no def for a nonempty path",
        ));
    };
    match &def {
        DataDef::Leaf(_) => {
            let scalar = scalar_of(value)?;
            tree.set(path, &scalar, None).map_err(err)
        }
        DataDef::LeafList(_) => {
            let Json::Arr(items) = value else {
                return Err(ApiError::bad_request(format!(
                    "`{}` is a leaf-list: the body must be an array",
                    path.to_string_path()
                )));
            };
            for item in items {
                tree.set_leaf_list(path, &scalar_of(item)?, None)
                    .map_err(err)?;
            }
            Ok(())
        }
        DataDef::Container(cdef) => {
            let Json::Obj(members) = value else {
                return Err(ApiError::bad_request(format!(
                    "`{}` is a container: the body must be an object",
                    path.to_string_path()
                )));
            };
            tree.set_container(path).map_err(err)?;
            for (key, v) in members {
                let child = cdef
                    .children
                    .iter()
                    .find(|d| d.name() == key)
                    .ok_or_else(|| {
                        ApiError::bad_request(format!("`{key}` is not a member of `{}`", cdef.name))
                    })?;
                load_into(
                    tree,
                    &Path {
                        segs: path
                            .segs
                            .iter()
                            .cloned()
                            .chain(one(seg_of(child)))
                            .collect(),
                    },
                    v,
                )?;
            }
            Ok(())
        }
        DataDef::List(ldef) => {
            // A path whose last segment carries keys addresses ONE
            // entry (the body is its members); a keyless path
            // addresses the list (an array of entries, or one entry
            // object for single-entry writes).
            let keyed = path
                .segs
                .last()
                .map(|s| !s.keys.is_empty())
                .unwrap_or(false);
            if keyed {
                let Json::Obj(members) = value else {
                    return Err(ApiError::bad_request(format!(
                        "`{}` is a list entry: the body must be an object",
                        path.to_string_path()
                    )));
                };
                tree.set_container(path).map_err(err)?;
                load_entry_members(tree, path, ldef, members)?;
                Ok(())
            } else {
                let entries = match value {
                    Json::Arr(entries) => entries.as_slice(),
                    one @ Json::Obj(_) => std::slice::from_ref(one),
                    _ => {
                        return Err(ApiError::bad_request(format!(
                            "`{}` is a list: the body must be an array of objects",
                            path.to_string_path()
                        )))
                    }
                };
                for entry in entries {
                    let Json::Obj(members) = entry else {
                        return Err(ApiError::bad_request(format!(
                            "list `{}` entries must be objects",
                            ldef.name
                        )));
                    };
                    let mut keys = Vec::new();
                    for key in &ldef.keys {
                        let v = members.iter().find(|(k, _)| k == key).ok_or_else(|| {
                            ApiError::bad_request(format!(
                                "list `{}` entry misses key `{key}`",
                                ldef.name
                            ))
                        })?;
                        keys.push((key.clone(), scalar_of(&v.1)?));
                    }
                    let mut entry_segs = path.segs.clone();
                    entry_segs.last_mut().expect("nonempty").keys = keys;
                    let entry_path = Path { segs: entry_segs };
                    tree.set_container(&entry_path).map_err(err)?;
                    load_entry_members(tree, &entry_path, ldef, members)?;
                }
                Ok(())
            }
        }
    }
}

/// Loads one list entry's non-key members (key members ride the
/// path predicate — RFC 7951 §5.4; accepted, not re-assigned).
fn load_entry_members(
    tree: &mut DataTree,
    entry_path: &Path,
    ldef: &yang::schema::ListDef,
    members: &[(String, Json)],
) -> Result<(), ApiError> {
    for (key, v) in members {
        if ldef.keys.contains(key) {
            continue;
        }
        let child = ldef
            .children
            .iter()
            .find(|d| d.name() == key)
            .ok_or_else(|| {
                ApiError::bad_request(format!("`{key}` is not a member of `{}`", ldef.name))
            })?;
        load_into(
            tree,
            &Path {
                segs: entry_path
                    .segs
                    .iter()
                    .cloned()
                    .chain(one(seg_of(child)))
                    .collect(),
            },
            v,
        )?;
    }
    Ok(())
}

fn one(seg: PathSeg) -> std::iter::Once<PathSeg> {
    std::iter::once(seg)
}

fn seg_of(def: &DataDef) -> PathSeg {
    PathSeg {
        name: def.name().to_string(),
        keys: Vec::new(),
    }
}

fn scalar_of(value: &Json) -> Result<String, ApiError> {
    match value {
        Json::Str(s) => Ok(s.clone()),
        Json::Num(n) => Ok(n.clone()),
        Json::Bool(b) => Ok(b.to_string()),
        Json::Null => Ok(String::new()),
        _ => Err(ApiError::bad_request("expected a scalar value")),
    }
}

// ---- canonical splicing ----

/// Replaces the body lines between `header_line` and `close_line`
/// (1-based, exclusive) with `new_body` — only the targeted span's
/// bytes change; everything else rides verbatim.
fn splice_body(
    original: &str,
    header_line: usize,
    close_line: usize,
    new_body: &str,
) -> Result<String, ApiError> {
    let mut out = String::with_capacity(original.len());
    for (idx, line) in original.lines().enumerate() {
        let no = idx + 1;
        if no > header_line && no < close_line && no == header_line + 1 {
            for body in new_body.lines() {
                out.push_str(body);
                out.push('\n');
            }
            continue;
        }
        if no > header_line && no < close_line {
            continue;
        }
        out.push_str(line);
        out.push('\n');
    }
    Ok(out)
}

/// Replaces the single line `line` (1-based) with `new_line`.
fn splice_replace_line(original: &str, line: usize, new_line: &str) -> Result<String, ApiError> {
    let mut out = String::with_capacity(original.len());
    for (idx, text) in original.lines().enumerate() {
        if idx + 1 == line {
            out.push_str(new_line);
        } else {
            out.push_str(text);
        }
        out.push('\n');
    }
    Ok(out)
}

/// Removes lines `from..=to` (1-based, inclusive).
fn splice_out_lines(original: &str, from: usize, to: usize) -> Result<String, ApiError> {
    let mut out = String::with_capacity(original.len());
    for (idx, line) in original.lines().enumerate() {
        let no = idx + 1;
        if no >= from && no <= to {
            continue;
        }
        out.push_str(line);
        out.push('\n');
    }
    Ok(out)
}

// ---- the commit: gates, write, apply ----

/// Every mutation's tail: the full gate chain BEFORE any write
/// (structural parse, YANG bind+validate, the deep validation
/// gate), then the atomic canonical write, then the existing apply
/// pipeline — no new apply logic. The deep gate runs twice (here
/// pre-write, again inside the apply) — correctness over speed,
/// disclosed in docs/yang.md.
fn commit(
    store: &Datastore,
    new_text: String,
    verb: Verb,
    created: bool,
) -> Result<Reply, ApiError> {
    let parsed = tree::parse(&new_text)
        .map_err(|e| ApiError::bad_request(format!("the mutated canonical does not parse: {e}")))?;
    yangmode::bind(&parsed)
        .map_err(|e| ApiError::bad_request(format!("YANG validation refused the mutation: {e}")))?;
    let dirs = validate::search_dirs(None);
    let validation = validate::validate_canonical(&parsed, &dirs);
    if let Some(refusal) = validate::refusal_summary(&validation) {
        return Err(ApiError::new(
            400,
            "validation-failed",
            format!("semantic validation refused: {refusal}"),
        ));
    }
    write_atomic(&store.canonical, &new_text).map_err(|e| {
        ApiError::internal(format!(
            "cannot write the canonical {}: {e}",
            store.canonical.display()
        ))
    })?;
    match apply::apply(
        new_text.as_bytes(),
        RollbackSource::File(store.canonical.clone()),
        &store.opts(),
    ) {
        Ok(report) => Ok(Reply::json(
            if verb == Verb::Put && created {
                201
            } else {
                200
            },
            ack_summary(&report),
        )),
        Err(err) => Err(ApiError::new(
            409,
            "operation-failed",
            format!(
                "the apply failed after staging (the canonical file holds the staged bytes; \
                 if a reload was refused the auto-rollback ran — the daemons run the last \
                 confirmed config): {err}"
            ),
        )),
    }
}

/// The per-daemon ack summary in `configd.status`'s vocabulary, as
/// JSON (the M3 response body).
fn ack_summary(report: &ApplyReport) -> String {
    let daemons: Vec<String> = report
        .rendered
        .iter()
        .map(|(daemon, path, bytes)| {
            let outcome = report
                .outcomes
                .iter()
                .find(|(d, _)| d == daemon)
                .map(|(_, o)| o.word());
            let ack = report
                .acks
                .iter()
                .find(|(d, _)| d == daemon)
                .map(|(_, a)| a.word());
            let mut line = format!(
                "{{\"daemon\":\"{}\",\"file\":\"{}\",\"bytes\":{}",
                daemon.name(),
                path.display(),
                bytes
            );
            if let Some(result) = outcome {
                line.push_str(&format!(",\"result\":\"{result}\""));
            }
            if let Some(ack) = ack {
                line.push_str(&format!(",\"ack\":\"{ack}\""));
            }
            line.push('}');
            line
        })
        .collect();
    let mut hash = String::new();
    push_json_string(&report.hash, &mut hash);
    format!(
        "{{\"generation\":{},\"hash\":{},\"daemons\":[{}]}}",
        report.generation,
        hash,
        daemons.join(",")
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scratch(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "configd-restconf-{tag}-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join("run")).unwrap();
        std::fs::create_dir_all(dir.join("etc")).unwrap();
        dir
    }

    const CANONICAL: &str = "router-id 198.51.100.1\n\
                             ! operator comment\n\
                             daemon savd {\n\
                             mode strict\n\
                             poll 2\n\
                             }\n\
                             daemon bfdd {\n\
                             peer 192.0.2.9\n\
                             }\n";

    fn store(tag: &str) -> (Datastore, PathBuf) {
        let dir = scratch(tag);
        let canonical = dir.join("rouster.conf");
        std::fs::write(&canonical, CANONICAL).unwrap();
        (
            Datastore {
                canonical: canonical.clone(),
                run_dir: dir.join("run"),
                etc_dir: dir.join("etc"),
            },
            dir,
        )
    }

    #[test]
    fn error_bodies_are_the_rfc_8040_form() {
        let mut err = ApiError::not_found("`/nope` does not exist");
        err.path = Some("/restconf/data/nope".to_string());
        assert_eq!(
            err.body(),
            "{\"ietf-restconf:errors\":{\"error\":[{\"error-type\":\"application\",\
             \"error-tag\":\"invalid-value\",\"error-message\":\"`/nope` does not exist\",\
             \"error-path\":\"/restconf/data/nope\"}]}}"
        );
    }

    #[test]
    fn split_target_rejects_queries_and_unknown_roots() {
        assert_eq!(
            split_target("/restconf/data/savd").unwrap(),
            (Store::Candidate, "/savd")
        );
        assert_eq!(
            split_target("/restconf/running").unwrap(),
            (Store::Running, "")
        );
        assert!(split_target("/restconf/data?content=config").is_err());
        assert!(split_target("/restconf/datastore").is_err());
        assert!(split_target("/vty").is_err());
    }

    #[test]
    fn percent_decoding_handles_escapes_and_rejects_garbage() {
        assert_eq!(percent_decode("a%20b").unwrap(), "a b");
        assert_eq!(percent_decode("if%2Fname").unwrap(), "if/name");
        assert!(percent_decode("bad%2").is_err());
        assert!(percent_decode("bad%zz").is_err());
    }

    #[test]
    fn get_root_is_the_dump_shape() {
        let (store, _dir) = store("get-root");
        let reply = get(&store, false, "").unwrap();
        assert_eq!(reply.status, 200);
        assert!(
            reply.body.contains("\"router-id\":\"198.51.100.1\""),
            "{}",
            reply.body
        );
        assert!(reply.body.contains("\"savd\":"), "{}", reply.body);
    }

    #[test]
    fn get_section_and_leaf_wrap_the_member() {
        let (store, _dir) = store("get-leaf");
        let reply = get(&store, false, "/savd").unwrap();
        assert!(reply.body.contains("\"mode\":\"strict\""), "{}", reply.body);
        assert_eq!(
            get(&store, false, "/savd/poll").unwrap().body,
            "{\"poll\":2}"
        );
        // Both key forms address the list entry (bfdd's list is
        // keyed (address, multihop) — RFC 5882 §2's session
        // identity; both keys, either form).
        assert_eq!(
            get(
                &store,
                false,
                "/bfdd/peer[address=192.0.2.9][multihop=false]"
            )
            .unwrap()
            .status,
            200
        );
        assert_eq!(
            get(&store, false, "/bfdd/peer=192.0.2.9,false")
                .unwrap()
                .status,
            200
        );
        // Unknown paths and sections are 404s.
        assert_eq!(get(&store, false, "/savd/nope").unwrap_err().status, 404);
        assert_eq!(get(&store, false, "/nosuchd").unwrap_err().status, 404);
        assert_eq!(get(&store, false, "/ospfd").unwrap_err().status, 404);
    }

    #[test]
    fn running_view_before_any_apply_is_a_404() {
        let (store, _dir) = store("running-empty");
        let err = get(&store, true, "").unwrap_err();
        assert_eq!(err.status, 404);
        assert!(err.message.contains("no confirmed generation"));
    }

    #[test]
    fn put_leaf_mutates_canonical_and_applies() {
        let (store, dir) = store("put-leaf");
        let reply = mutate(&store, false, Verb::Put, "/savd/poll", b"3");
        assert_eq!(reply.status, 200, "{}", reply.body);
        assert!(reply.body.contains("\"daemon\":\"savd\""), "{}", reply.body);
        assert!(reply.body.contains("\"generation\":1"), "{}", reply.body);
        // The canonical gained exactly the new leaf; everything
        // else rides verbatim (comments included).
        let after = std::fs::read_to_string(&store.canonical).unwrap();
        assert!(after.contains("! operator comment"), "{after}");
        assert!(after.contains("poll 3"), "{after}");
        assert!(!after.contains("poll 2"), "{after}");
        // The apply ran: the rendered savd.conf follows.
        assert!(std::fs::read_to_string(dir.join("etc/savd.conf"))
            .unwrap()
            .contains("poll 3"));
        // And the running view exists and shows the new value.
        assert_eq!(
            get(&store, true, "/savd/poll").unwrap().body,
            "{\"poll\":3}"
        );
    }

    #[test]
    fn put_bad_value_is_a_400_and_the_tree_is_untouched() {
        let (store, _dir) = store("put-bad");
        let before = std::fs::read_to_string(&store.canonical).unwrap();
        let reply = mutate(&store, false, Verb::Put, "/savd/poll", b"0");
        assert_eq!(reply.status, 400, "{}", reply.body);
        assert!(reply.body.contains("error-path"), "{}", reply.body);
        // Nothing was written: canonical, renders, generations.
        assert_eq!(std::fs::read_to_string(&store.canonical).unwrap(), before);
        assert!(!store.run_dir.join("configd").exists());
        // Invalid JSON is a 400 too.
        let reply = mutate(&store, false, Verb::Put, "/savd/poll", b"{nope");
        assert_eq!(reply.status, 400);
        assert_eq!(std::fs::read_to_string(&store.canonical).unwrap(), before);
    }

    #[test]
    fn put_unknown_member_is_a_400() {
        let (store, _dir) = store("put-unknown");
        let reply = mutate(&store, false, Verb::Put, "/savd", b"{\"frobnicate\":7}");
        assert_eq!(reply.status, 400, "{}", reply.body);
        assert!(reply.body.contains("frobnicate"), "{}", reply.body);
    }

    #[test]
    fn a_must_violation_is_a_per_path_400() {
        // savd's drop-friction gate (the model's leaf `must`):
        // action drop needs the acknowledgement leaf.
        let (store, _dir) = store("must");
        let reply = mutate(
            &store,
            false,
            Verb::Merge,
            "/savd",
            b"{\"action\":\"drop\"}",
        );
        assert_eq!(reply.status, 400, "{}", reply.body);
        assert!(reply.body.contains("validation-failed"), "{}", reply.body);
        assert!(reply.body.contains("i-understand"), "{}", reply.body);
        // The satisfying leg is unreachable through tree edits
        // today: the model's must compares `= 'yes'` while boolean
        // canonicals are `true`/`false` — a pre-existing model/line
        // seam outside this stream's lane, disclosed in
        // docs/yang.md §Deferred; savd's own gate stays the real
        // friction.
    }

    #[test]
    fn post_merges_and_put_replaces() {
        let (store, _dir) = store("post-merge");
        // Merge a new interface stanza into savd.
        let reply = mutate(
            &store,
            false,
            Verb::Merge,
            "/savd/interface=veths1",
            b"{\"mode\":\"strict\"}",
        );
        assert_eq!(reply.status, 200, "{}", reply.body);
        let merged = get(&store, false, "/savd").unwrap();
        assert!(merged.body.contains("veths1"), "{}", merged.body);
        assert!(merged.body.contains("\"poll\":2"), "{}", merged.body);
        // Section-level PUT replaces: veths1 survives only if the
        // body carries it.
        let reply = mutate(
            &store,
            false,
            Verb::Put,
            "/savd",
            b"{\"mode\":\"strict\",\"poll\":5}",
        );
        assert_eq!(reply.status, 200, "{}", reply.body);
        let replaced = get(&store, false, "/savd").unwrap();
        assert!(replaced.body.contains("\"poll\":5"), "{}", replaced.body);
        assert!(!replaced.body.contains("veths1"), "{}", replaced.body);
    }

    #[test]
    fn put_creates_a_missing_section_with_201() {
        let (store, _dir) = store("put-create-section");
        let reply = mutate(
            &store,
            false,
            Verb::Put,
            "/ospfd",
            b"{\"router\":{\"ospf\":{\"router-id\":\"10.0.0.1\"}}}",
        );
        assert_eq!(reply.status, 201, "{}", reply.body);
        let after = std::fs::read_to_string(&store.canonical).unwrap();
        assert!(after.contains("daemon ospfd {"), "{after}");
        let reply = get(&store, false, "/ospfd").unwrap();
        assert!(reply.body.contains("10.0.0.1"), "{}", reply.body);
    }

    #[test]
    fn delete_absent_is_404_delete_leaf_removes() {
        let (store, _dir) = store("delete");
        assert_eq!(
            mutate(&store, false, Verb::Delete, "/savd/poll", &[]).status,
            200
        );
        let reply = mutate(&store, false, Verb::Delete, "/savd/poll", &[]);
        assert_eq!(reply.status, 404, "{}", reply.body);
        let after = std::fs::read_to_string(&store.canonical).unwrap();
        assert!(!after.contains("poll"), "{after}");
        assert!(after.contains("mode strict"), "{after}");
        // An absent section DELETE is a 404.
        assert_eq!(
            mutate(&store, false, Verb::Delete, "/ospfd", &[]).status,
            404
        );
    }

    #[test]
    fn mutations_on_running_are_refused() {
        let (store, _dir) = store("running-ro");
        let reply = mutate(&store, true, Verb::Put, "/savd/poll", b"9");
        assert_eq!(reply.status, 405);
        assert!(reply.body.contains("read-only"), "{}", reply.body);
    }

    #[test]
    fn router_id_get_put_delete() {
        let (store, _dir) = store("router-id");
        assert_eq!(
            get(&store, false, "/router-id").unwrap().body,
            "{\"router-id\":\"198.51.100.1\"}"
        );
        let reply = mutate(&store, false, Verb::Put, "/router-id", b"\"198.51.100.9\"");
        assert_eq!(reply.status, 200, "{}", reply.body);
        assert!(std::fs::read_to_string(&store.canonical)
            .unwrap()
            .contains("router-id 198.51.100.9"));
        assert_eq!(
            mutate(&store, false, Verb::Delete, "/router-id", &[]).status,
            200
        );
        assert!(!std::fs::read_to_string(&store.canonical)
            .unwrap()
            .contains("router-id"));
        assert_eq!(
            mutate(&store, false, Verb::Put, "/router-id", b"\"not-an-addr\"").status,
            400
        );
    }

    #[test]
    fn root_mutations_are_405() {
        let (store, _dir) = store("root-405");
        assert_eq!(mutate(&store, false, Verb::Put, "", b"{}").status, 405);
        assert_eq!(mutate(&store, false, Verb::Delete, "", &[]).status, 405);
    }

    #[test]
    fn splice_replaces_only_the_target_span() {
        let out = splice_body(CANONICAL, 3, 6, "mode loose\npoll 7").unwrap();
        let lines: Vec<&str> = out.lines().collect();
        assert_eq!(lines[0], "router-id 198.51.100.1");
        assert_eq!(lines[1], "! operator comment");
        assert_eq!(lines[2], "daemon savd {");
        assert_eq!(lines[3], "mode loose");
        assert_eq!(lines[4], "poll 7");
        assert_eq!(lines[5], "}");
        assert_eq!(lines[6], "daemon bfdd {");
        assert!(splice_out_lines(CANONICAL, 1, 1)
            .unwrap()
            .starts_with("! operator comment"));
    }

    #[test]
    fn mutated_canonical_round_trips_byte_stably() {
        // Mutate, then reload and re-render the SAME section with no
        // further change: the canonical must not move (the
        // render-stability contract).
        let (store, _dir) = store("stable");
        mutate(
            &store,
            false,
            Verb::Merge,
            "/savd",
            b"{\"poll\":4,\"hysteresis\":2}",
        );
        let once = std::fs::read_to_string(&store.canonical).unwrap();
        let parsed = tree::parse(&once).unwrap();
        let bound = yangmode::bind(&parsed).unwrap();
        let body = render_mutated(
            bound.section(Daemon::Savd).unwrap().tree.clone(),
            Daemon::Savd,
        )
        .unwrap();
        let again = splice_body(
            &once,
            parsed.section(Daemon::Savd).unwrap().header_line,
            parsed.section(Daemon::Savd).unwrap().close_line.unwrap(),
            &body,
        )
        .unwrap();
        assert_eq!(once, again);
    }
}
