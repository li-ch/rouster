//! The line binding ("linebind") — the bidirectional mapping
//! between the suite's daemon config line grammars (token-per-line,
//! FRR-shaped) and data-tree paths. This is Rouster's own
//! convention, not an RFC construct; its ancestors are FRR's
//! northbound (CLI commands generated from the schema) and the
//! models themselves — the binding is deliberately TABLE-DRIVEN OFF
//! THE SCHEMA so a model edit re-targets configd's parse and vtyd's
//! translator at once (invariant 5: one source of truth).
//!
//! # The binding rules (the whole grammar of the seam)
//!
//! 1. **Lines** are token-per-line (`split_whitespace`), the shape
//!    every daemon grammar in the suite shares. Blank / `!` / `#`
//!    lines are ignorable and ride the tree verbatim in document
//!    order (`NodeKind::Opaque`).
//! 2. **Context**: a line is interpreted against the stanza context
//!    left by the previous line — the deepest container/list node
//!    ENTERED by it. A first token that names no child of the
//!    context node retries at each ancestor up to the module root
//!    (deepest-first: savd's `mode` is the interface's while a
//!    stanza is open, the global's before any stanza).
//! 3. **Walk**: a token naming a container descends into it (so
//!    `router` `bgp` walks two levels). A token naming a list
//!    consumes the key values that follow — one token per key
//!    (§7.8.2); a BOOLEAN-typed key takes the FRR shorthand: the
//!    bare key name means `true`, its absence `false` (`peer <ip>
//!    multihop`).
//! 4. **Trailing statements** inside the entered node are
//!    `(name value...)` pairs: a leaf takes one value (type `empty`
//!    takes none; a boolean leaf may take the FRR shorthand — bare
//!    name = true); a leaf-list consumes every following token
//!    until one names a sibling child (the multi-value tail:
//!    `ip route <p> <gw> <gw> table <n>`); a container/list entered
//!    by a trailing token repeats rule 3 and continues.
//! 5. **Unknown lines** (no match at any depth) ride the tree's
//!    Opaque bucket, verbatim, disclosed — the daemon's own parser
//!    stays the semantic gate (configd's deep-validation step).
//! 6. After the line, the context is the deepest node ENTERED
//!    (containers/lists; trailing leaf statements do not enter).
//!    Re-entering a keyed list entry MERGES into it (§7.8.2) — the
//!    subset is deliberately more lenient than the daemon parsers,
//!    which refuse duplicates; the daemon's `--validate-config`
//!    remains authoritative.
//!
//! # Render (tree → lines)
//!
//! Every node keeps its [`crate::data::Origin`] — the exact source
//! line — so `render` in origin mode reproduces the input
//! byte-identically (configd's contract). Nodes created
//! programmatically (vtyd's edits) render SYNTHESIZED lines at one
//! space of indent per depth, booleans per the dialect: [`Boolean
//! LineForm::YesNo`] renders `echo yes` (savd/bfdd), the shorthand
//! renders the bare keyword for true and omits false (`passive`,
//! bgpd). Defaults never render (they are not operator intent).
//!
//! The savd positional quirk (a `mode` line following a `binding`
//! line attaches to the last interface in savd's parser, to the
//! global here) is a disclosed divergence — §Deferred in
//! docs/yang.md.

use crate::data::{DataError, DataTree, Node, NodeKind, Origin, Path, PathSeg};
use crate::schema::{DataDef, Schema};
use crate::types::Type;

/// One source config line.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SourceLine {
    pub line: usize,
    pub text: String,
}

/// How boolean leaves render when synthesized (parsed input accepts
/// `yes|no|true|false` everywhere).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum BooleanLineForm {
    /// `echo yes` / `echo no` (savd, bfdd).
    #[default]
    YesNo,
    /// `passive` present = true, absent = false (bgpd neighbors).
    Shorthand,
}

/// The per-module line dialect.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct LineDialect {
    pub boolean: BooleanLineForm,
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum LineError {
    #[error("line {line}: {reason}")]
    Line { line: usize, reason: String },
    #[error("data: {0}")]
    Data(#[from] DataError),
}

fn lerr(line: usize, reason: impl Into<String>) -> LineError {
    LineError::Line {
        line,
        reason: reason.into(),
    }
}

/// The parse report: the tree plus the disclosure counts.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BindReport {
    /// Lines that matched the model.
    pub modeled: usize,
    /// Ignorable lines (blank/comment) carried verbatim.
    pub ignorable: usize,
    /// Lines with no schema match at any depth — carried verbatim.
    pub unmodeled: Vec<usize>,
}

/// Binds daemon config lines to a tree for `schema`.
pub fn parse(
    schema: &Schema,
    lines: &[SourceLine],
    dialect: &LineDialect,
) -> Result<(DataTree, BindReport), LineError> {
    let mut tree = DataTree::empty(schema.clone());
    let mut report = BindReport {
        modeled: 0,
        ignorable: 0,
        unmodeled: Vec::new(),
    };
    // The context: (segment, def) from root to the deepest entered
    // node of the previous line.
    let module = schema.set.modules[&schema.module].clone();
    let mut ctx: Vec<(PathSeg, DataDef)> = Vec::new();

    for source in lines {
        let trimmed = source.text.trim();
        if trimmed.is_empty() || trimmed.starts_with('!') || trimmed.starts_with('#') {
            let origin = Origin {
                line: source.line,
                raw: source.text.clone(),
            };
            push_opaque(&mut tree, &ctx, origin);
            report.ignorable += 1;
            continue;
        }
        let tokens: Vec<&str> = trimmed.split_whitespace().collect();
        match walk_line(&mut tree, &module.data, &mut ctx, &tokens, source, dialect)? {
            WalkOutcome::Modeled => report.modeled += 1,
            WalkOutcome::Unmodeled => {
                let origin = Origin {
                    line: source.line,
                    raw: source.text.clone(),
                };
                push_opaque(&mut tree, &ctx, origin);
                report.unmodeled.push(source.line);
            }
        }
    }
    Ok((tree, report))
}

enum WalkOutcome {
    Modeled,
    Unmodeled,
}

/// Interprets one line (rules 2-6). `Ok(Unmodeled)` when no depth
/// matches (rule 5).
fn walk_line(
    tree: &mut DataTree,
    root_defs: &[DataDef],
    ctx: &mut Vec<(PathSeg, DataDef)>,
    tokens: &[&str],
    source: &SourceLine,
    dialect: &LineDialect,
) -> Result<WalkOutcome, LineError> {
    // Try the deepest context first, then ancestors, then root.
    for depth in (0..=ctx.len()).rev() {
        let (base_defs, base_segs): (Vec<DataDef>, Vec<PathSeg>) = if depth == 0 {
            (Vec::new(), Vec::new())
        } else {
            let segs: Vec<PathSeg> = ctx[..depth].iter().map(|(s, _)| s.clone()).collect();
            let defs: Vec<DataDef> = ctx[..depth].iter().map(|(_, d)| d.clone()).collect();
            (defs, segs)
        };
        let parent_defs: Vec<DataDef> = if depth == 0 {
            root_defs.to_vec()
        } else {
            children_defs(base_defs.last().expect("nonempty"))
                .cloned()
                .unwrap_or_default()
        };
        let Some(first) = tokens.first() else {
            return Err(lerr(source.line, "empty line"));
        };
        if !parent_defs.iter().any(|d| d.name() == *first) {
            continue; // try a shallower depth
        }
        // A match: walk it.
        let result = match walk_tokens(
            tree,
            &base_segs,
            &base_defs,
            &parent_defs,
            tokens,
            source,
            dialect,
        ) {
            Ok(r) => r,
            Err(fail) => {
                if fail.soft && depth > 0 {
                    continue; // the value does not fit HERE — a full-form grammar may own it shallower
                }
                return Err(fail.err);
            }
        };
        match result {
            Some(new_ctx) => {
                *ctx = new_ctx;
                return Ok(WalkOutcome::Modeled);
            }
            // Matched the name but the line's shape did not fit —
            // carried verbatim, disclosed (rule 5).
            None => return Ok(WalkOutcome::Unmodeled),
        }
    }
    Ok(WalkOutcome::Unmodeled)
}

/// A failed walk: `soft` marks a trailing-value type mismatch (the
/// line may belong to a shallower, full-form grammar — bgpd's
/// router-level `graceful-restart deferral` vs the neighbor's
/// `graceful-restart <secs>`); everything else is hard.
struct WalkFailure {
    err: LineError,
    soft: bool,
}

fn hard(e: LineError) -> WalkFailure {
    WalkFailure {
        err: e,
        soft: false,
    }
}

/// Walks the tokens from a matched start. Returns the new context
/// (Some) or None when the shape did not fit (disclosed unmodeled).
#[allow(clippy::type_complexity)]
fn walk_tokens(
    tree: &mut DataTree,
    base_segs: &[PathSeg],
    base_defs: &[DataDef],
    parent_defs: &[DataDef],
    tokens: &[&str],
    source: &SourceLine,
    _dialect: &LineDialect,
) -> Result<Option<Vec<(PathSeg, DataDef)>>, WalkFailure> {
    let origin = || {
        Some(Origin {
            line: source.line,
            raw: source.text.trim_end().to_string(),
        })
    };
    let mut segs: Vec<PathSeg> = base_segs.to_vec();
    let mut defs: Vec<DataDef> = base_defs.to_vec();
    let base_len = segs.len();
    let mut current_defs: Vec<DataDef> = parent_defs.to_vec();
    let mut idx = 0usize;
    // The absolute depth of the deepest ENTERED node (rule 6).
    let mut entered = segs.len();

    // ---- the walk (rule 3) ----
    while let Some(tok) = tokens.get(idx) {
        let Some(def) = current_defs.iter().find(|d| d.name() == *tok).cloned() else {
            break;
        };
        match &def {
            DataDef::Container(_) => {
                defs.push(def.clone());
                segs.push(seg_plain(tok));
                idx += 1;
                entered = segs.len();
                current_defs = children_defs(&def).cloned().unwrap_or_default();
                if current_defs.is_empty() {
                    break;
                }
            }
            DataDef::List(list_def) => {
                idx += 1;
                let mut keys = Vec::new();
                for key in &list_def.keys {
                    let key_leaf = list_def
                        .children
                        .iter()
                        .find_map(|c| match c {
                            DataDef::Leaf(l) if &l.name == key => Some(l.clone()),
                            _ => None,
                        })
                        .expect("schema resolved key leaves");
                    // Boolean shorthand (rule 3): the bare key name
                    // is true; a missing boolean key is false.
                    let is_boolean = matches!(key_leaf.resolved.as_ref(), Some(Type::Boolean));
                    match tokens.get(idx) {
                        Some(t) if *t == *key && is_boolean => {
                            keys.push((key.clone(), "true".to_string()));
                            idx += 1;
                        }
                        Some(t) if is_boolean && !names_child(&current_defs, t) => {
                            let v = bool_from_word(t).ok_or_else(|| {
                                hard(lerr(source.line, format!("bad boolean `{t}`")))
                            })?;
                            keys.push((key.clone(), v));
                            idx += 1;
                        }
                        Some(t) if !names_child(&current_defs, t) => {
                            keys.push((key.clone(), (*t).to_string()));
                            idx += 1;
                        }
                        Some(_) if is_boolean => {
                            // The token names a child (trailing
                            // statement): the key defaults false.
                            keys.push((key.clone(), "false".to_string()));
                        }
                        Some(t) => {
                            return Err(hard(lerr(
                                source.line,
                                format!("`{t}` does not fit list `{tok}`'s key `{key}`"),
                            )));
                        }
                        None if is_boolean => {
                            keys.push((key.clone(), "false".to_string()));
                        }
                        None => {
                            return Err(hard(lerr(
                                source.line,
                                format!("list `{tok}` misses key `{key}`"),
                            )));
                        }
                    }
                }
                defs.push(def.clone());
                segs.push(PathSeg {
                    name: def.name().to_string(),
                    keys,
                });
                entered = segs.len();
                current_defs = children_defs(&def).cloned().unwrap_or_default();
            }
            // A leaf/leaf-list named during the walk is a trailing
            // statement — the loop below consumes it.
            _ => break,
        }
    }

    // Touch every node entered by the WALK into existence, origin
    // sticking to the first line that created it.
    for depth in base_len + 1..=segs.len() {
        let prefix = Path {
            segs: segs[..depth].to_vec(),
        };
        // Only the deepest entered node carries the opener's bytes;
        // intermediate containers render synthesized (or nothing).
        let node_origin = if depth == segs.len() { origin() } else { None };
        tree.set_container_with_origin(&prefix, node_origin)
            .map_err(|e| hard(lerr(source.line, e.to_string())))?;
    }
    // Key leaves are members too (RFC 7951 §5.4) — set them without
    // origins (the opener line renders once, from the entry).
    for (i, (seg, def)) in segs.iter().zip(defs.iter()).enumerate() {
        if matches!(def, DataDef::List(_)) && !seg.keys.is_empty() {
            for (k, v) in &seg.keys {
                let mut p = Path {
                    segs: segs[..=i].to_vec(),
                };
                p.segs.push(seg_plain(k));
                tree.set(&p, v, None).map_err(|e| WalkFailure {
                    err: lerr(source.line, e.to_string()),
                    soft: false,
                })?;
            }
        }
    }

    // ---- trailing statements (rule 4) ----
    // Rule 4b: when the walk ended inside a list ENTRY, bare values
    // (tokens naming no child) append to the list's FIRST leaf-list
    // child — the FRR positional-argument shape
    // (`ip route <prefix> <gateway>... [table <n>]`).
    let positional: Option<String> = match (defs.last(), segs.last()) {
        (Some(DataDef::List(l)), Some(seg)) if !seg.keys.is_empty() => {
            l.children.iter().find_map(|c| match c {
                DataDef::LeafList(ll) => Some(ll.name.clone()),
                _ => None,
            })
        }
        _ => None,
    };
    let mut tail_defs: Vec<DataDef> = current_defs.clone();
    let mut tail_segs: Vec<PathSeg> = segs.clone();
    // The def of the node trailing statements sit in (rule 4c).
    let mut tail_base_def: Option<DataDef> = defs.last().cloned();
    while idx < tokens.len() {
        let tok = tokens[idx];
        let Some(def) = tail_defs.iter().find(|d| d.name() == tok).cloned() else {
            let Some(ll_name) = &positional else {
                // Rule 4c: positional leafs in a CONTAINER — bare
                // values assign to the container's leafs in
                // declaration order (`send-lifetime 0 infinite`).
                if let Some(DataDef::Container(c)) = &tail_base_def {
                    let leafs: Vec<_> = c
                        .children
                        .iter()
                        .filter_map(|d| match d {
                            DataDef::Leaf(l) => Some(l.clone()),
                            _ => None,
                        })
                        .collect();
                    if !leafs.is_empty() {
                        let mut assigned = false;
                        for leaf in &leafs {
                            let Some(t) = tokens.get(idx) else { break };
                            if names_child(&tail_defs, t) {
                                break;
                            }
                            let mut path = Path {
                                segs: tail_segs.clone(),
                            };
                            path.segs.push(seg_plain(&leaf.name));
                            tree.set(&path, t, origin()).map_err(|e| WalkFailure {
                                err: lerr(source.line, e.to_string()),
                                soft: true,
                            })?;
                            idx += 1;
                            assigned = true;
                        }
                        if assigned {
                            continue;
                        }
                    }
                }
                return Ok(None); // shape does not fit — disclosed unmodeled
            };
            let mut path = Path {
                segs: tail_segs.clone(),
            };
            path.segs.push(seg_plain(ll_name));
            while let Some(t) = tokens.get(idx) {
                if names_child(&tail_defs, t) {
                    break;
                }
                tree.set_leaf_list(&path, t, origin())
                    .map_err(|e| WalkFailure {
                        err: lerr(source.line, e.to_string()),
                        soft: true,
                    })?;
                idx += 1;
            }
            continue;
        };
        match &def {
            DataDef::Leaf(leaf) => {
                idx += 1;
                let ty = leaf.resolved.clone().expect("resolved at build");
                let mut path = Path {
                    segs: tail_segs.clone(),
                };
                path.segs.push(seg_plain(tok));
                let value = if matches!(ty, Type::Empty) {
                    String::new()
                } else if matches!(ty, Type::Boolean) {
                    match tokens.get(idx) {
                        Some(t) if !names_child(&tail_defs, t) => {
                            let v = bool_from_word(t).ok_or_else(|| {
                                hard(lerr(
                                    source.line,
                                    format!("`{tok}` wants yes|no, got `{t}`"),
                                ))
                            })?;
                            idx += 1;
                            v
                        }
                        // FRR shorthand: the bare keyword is true.
                        _ => "true".to_string(),
                    }
                } else {
                    let Some(t) = tokens.get(idx) else {
                        return Err(hard(lerr(source.line, format!("`{tok}` needs a value"))));
                    };
                    idx += 1;
                    (*t).to_string()
                };
                tree.set(&path, &value, origin()).map_err(|e| WalkFailure {
                    err: lerr(source.line, e.to_string()),
                    soft: true,
                })?;
            }
            DataDef::LeafList(_) => {
                idx += 1;
                let mut path = Path {
                    segs: tail_segs.clone(),
                };
                path.segs.push(seg_plain(tok));
                while let Some(t) = tokens.get(idx) {
                    if names_child(&tail_defs, t) {
                        break;
                    }
                    tree.set_leaf_list(&path, t, origin())
                        .map_err(|e| WalkFailure {
                            err: lerr(source.line, e.to_string()),
                            soft: true,
                        })?;
                    idx += 1;
                }
            }
            DataDef::Container(_) => {
                idx += 1;
                tail_segs.push(seg_plain(tok));
                tail_defs = children_defs(&def).cloned().unwrap_or_default();
                tail_base_def = Some(def.clone());
                tree.set_container_with_origin(
                    &Path {
                        segs: tail_segs.clone(),
                    },
                    origin(),
                )
                .map_err(|e| WalkFailure {
                    err: lerr(source.line, e.to_string()),
                    soft: true,
                })?;
            }
            DataDef::List(list_def) => {
                idx += 1;
                let mut keys = Vec::new();
                for key in &list_def.keys {
                    let Some(t) = tokens.get(idx) else {
                        return Err(hard(lerr(
                            source.line,
                            format!("list `{tok}` misses key `{key}`"),
                        )));
                    };
                    keys.push((key.clone(), (*t).to_string()));
                    idx += 1;
                }
                let entry_seg = PathSeg {
                    name: def.name().to_string(),
                    keys,
                };
                tail_segs.push(entry_seg.clone());
                tail_defs = children_defs(&def).cloned().unwrap_or_default();
                tree.set_container_with_origin(
                    &Path {
                        segs: tail_segs.clone(),
                    },
                    origin(),
                )
                .map_err(|e| WalkFailure {
                    err: lerr(source.line, e.to_string()),
                    soft: true,
                })?;
                // The entry's key leaves (RFC 7951 §5.4).
                for (k, v) in &entry_seg.keys {
                    let mut p = Path {
                        segs: tail_segs.clone(),
                    };
                    p.segs.last_mut().expect("nonempty").keys = Vec::new();
                    // Route through the keyed entry, not the keyless list.
                    p.segs.last_mut().expect("nonempty").keys = entry_seg.keys.clone();
                    p.segs.push(seg_plain(k));
                    tree.set(&p, v, None).map_err(|e| WalkFailure {
                        err: lerr(source.line, e.to_string()),
                        soft: false,
                    })?;
                }
            }
        }
    }

    // The new context (rule 6): the deepest ENTERED node.
    let new_ctx: Vec<(PathSeg, DataDef)> = segs
        .iter()
        .zip(defs.iter())
        .take(entered)
        .map(|(s, d)| (s.clone(), d.clone()))
        .collect();
    Ok(Some(new_ctx))
}

fn seg_plain(name: &str) -> PathSeg {
    PathSeg {
        name: name.to_string(),
        keys: Vec::new(),
    }
}

fn names_child(defs: &[DataDef], token: &str) -> bool {
    defs.iter().any(|d| d.name() == token)
}

fn bool_from_word(word: &str) -> Option<String> {
    match word {
        "yes" | "true" | "on" => Some("true".to_string()),
        "no" | "false" | "off" => Some("false".to_string()),
        _ => None,
    }
}

fn children_defs(def: &DataDef) -> Option<&Vec<DataDef>> {
    match def {
        DataDef::Container(c) => Some(&c.children),
        DataDef::List(l) => Some(&l.children),
        _ => None,
    }
}

/// Appends an ignorable/unmodeled origin as deep as the current
/// context exists (never creating nodes for it).
fn push_opaque(tree: &mut DataTree, ctx: &[(PathSeg, DataDef)], origin: Origin) {
    let segs: Vec<PathSeg> = ctx.iter().map(|(s, _)| s.clone()).collect();
    if segs.is_empty() {
        tree.children.push(Node {
            name: format!("#opaque-{}", origin.line),
            kind: NodeKind::Opaque(vec![origin]),
            origin: None,
        });
        return;
    }
    if let Some(children) = tree.children_of_mut_at(&segs) {
        if let Some(node) = children
            .iter_mut()
            .rev()
            .find(|n| matches!(n.kind, NodeKind::Opaque(_)))
        {
            if let NodeKind::Opaque(lines) = &mut node.kind {
                lines.push(origin);
                return;
            }
        }
        children.push(Node {
            name: format!("#opaque-{}", origin.line),
            kind: NodeKind::Opaque(vec![origin]),
            origin: None,
        });
    } else {
        tree.children.push(Node {
            name: format!("#opaque-{}", origin.line),
            kind: NodeKind::Opaque(vec![origin]),
            origin: None,
        });
    }
}

// ---- render ----

/// Renders the tree back to lines. Origin-carrying nodes emit their
/// verbatim source lines (byte-identical); synthesized nodes emit
/// generated lines (one space of indent per depth; defaults and
/// `false` shorthand booleans are omitted).
pub fn render(tree: &DataTree, dialect: &LineDialect) -> Vec<SourceLine> {
    let module = tree.schema.set.modules[&tree.schema.module].clone();
    let mut out = Vec::new();
    // A source line emits exactly once: several nodes may share a
    // line (an entry and the statements its opener carried), so the
    // cursor skips repeats (line numbers are unique per file).
    let mut last_line: Option<usize> = None;
    render_children(
        &tree.children,
        &module.data,
        0,
        dialect,
        &mut out,
        &[],
        &mut last_line,
    );
    out
}

/// Emits a source-line origin unless its line already emitted (a
/// line's opener carries the statements that shared it).
fn emit_origin(o: &Origin, out: &mut Vec<SourceLine>, last_line: &mut Option<usize>) {
    if *last_line == Some(o.line) {
        return;
    }
    *last_line = Some(o.line);
    out.push(SourceLine {
        line: o.line,
        text: o.raw.clone(),
    });
}

fn render_children(
    nodes: &[Node],
    defs: &[DataDef],
    depth: usize,
    dialect: &LineDialect,
    out: &mut Vec<SourceLine>,
    key_names: &[String],
    last_line: &mut Option<usize>,
) {
    for node in nodes {
        match &node.kind {
            NodeKind::Opaque(lines) => {
                for o in lines {
                    emit_origin(o, out, last_line);
                }
            }
            NodeKind::Container(children) => {
                if let Some(o) = &node.origin {
                    emit_origin(o, out, last_line);
                } else if !children.is_empty() {
                    out.push(SourceLine {
                        line: 0,
                        text: format!("{}{}", " ".repeat(depth), node.name),
                    });
                }
                let children_defs = defs
                    .iter()
                    .find_map(|d| match d {
                        DataDef::Container(c) if c.name == node.name => Some(&c.children),
                        _ => None,
                    })
                    .cloned()
                    .unwrap_or_default();
                render_children(
                    children,
                    &children_defs,
                    depth + 1,
                    dialect,
                    out,
                    key_names,
                    last_line,
                );
            }
            NodeKind::List(entries) => {
                let list_defs = defs
                    .iter()
                    .find_map(|d| match d {
                        DataDef::List(l) if l.name == node.name => Some(l.children.clone()),
                        _ => None,
                    })
                    .unwrap_or_default();
                let key_names_owned: Vec<String> = defs
                    .iter()
                    .find_map(|d| match d {
                        DataDef::List(l) if l.name == node.name => Some(l.keys.clone()),
                        _ => None,
                    })
                    .unwrap_or_default();
                for entry in entries {
                    let NodeKind::Entry { keys, children, .. } = &entry.kind else {
                        continue;
                    };
                    if let NodeKind::Entry { openers, .. } = &entry.kind {
                        for o in openers {
                            emit_origin(o, out, last_line);
                        }
                    }
                    if entry.origin.is_none() {
                        let mut text = format!("{}{}", " ".repeat(depth), node.name);
                        for (k, v) in keys {
                            let key_bool = defs.iter().find_map(|d| match d {
                                DataDef::List(l) if l.name == node.name => {
                                    l.children.iter().find_map(|c| match c {
                                        DataDef::Leaf(leaf) if &leaf.name == k => {
                                            leaf.resolved.clone()
                                        }
                                        _ => None,
                                    })
                                }
                                _ => None,
                            });
                            match key_bool {
                                Some(Type::Boolean) if v == "true" => {
                                    text.push(' ');
                                    text.push_str(k);
                                }
                                Some(Type::Boolean) => {}
                                _ => {
                                    text.push(' ');
                                    text.push_str(v);
                                }
                            }
                        }
                        out.push(SourceLine { line: 0, text });
                    }
                    render_children(
                        children,
                        &list_defs,
                        depth + 1,
                        dialect,
                        out,
                        &key_names_owned,
                        last_line,
                    );
                }
            }
            NodeKind::Entry { children, .. } => {
                let list_defs = defs
                    .iter()
                    .find_map(|d| match d {
                        DataDef::List(l) if l.name == node.name => Some(l.children.clone()),
                        _ => None,
                    })
                    .unwrap_or_default();
                render_children(
                    children,
                    &list_defs,
                    depth + 1,
                    dialect,
                    out,
                    &[],
                    last_line,
                );
            }
            NodeKind::Leaf {
                value,
                from_default,
                ..
            } => {
                if *from_default {
                    continue;
                }
                // Synthesized key leaves render inside the entry's
                // opener line, never as their own line.
                if node.origin.is_none() && key_names.contains(&node.name) {
                    continue;
                }
                if let Some(o) = &node.origin {
                    emit_origin(o, out, last_line);
                    continue;
                }
                let ty = defs.iter().find_map(|d| match d {
                    DataDef::Leaf(leaf) if leaf.name == node.name => leaf.resolved.clone(),
                    _ => None,
                });
                match ty.as_ref() {
                    Some(Type::Empty) => out.push(SourceLine {
                        line: 0,
                        text: format!("{}{}", " ".repeat(depth), node.name),
                    }),
                    Some(Type::Boolean) => match dialect.boolean {
                        BooleanLineForm::YesNo => out.push(SourceLine {
                            line: 0,
                            text: format!(
                                "{}{} {}",
                                " ".repeat(depth),
                                node.name,
                                if value == "true" { "yes" } else { "no" }
                            ),
                        }),
                        BooleanLineForm::Shorthand => {
                            if value == "true" {
                                out.push(SourceLine {
                                    line: 0,
                                    text: format!("{}{}", " ".repeat(depth), node.name),
                                });
                            }
                            // false = absent.
                        }
                    },
                    _ => out.push(SourceLine {
                        line: 0,
                        text: format!("{}{} {}", " ".repeat(depth), node.name, value),
                    }),
                }
            }
            NodeKind::LeafList(values) => {
                let ty = defs.iter().find_map(|d| match d {
                    DataDef::LeafList(ll) if ll.name == node.name => ll.resolved.clone(),
                    _ => None,
                });
                for v in values {
                    if let Some(o) = &v.origin {
                        emit_origin(o, out, last_line);
                        continue;
                    }
                    let text = match ty.as_ref() {
                        Some(Type::Boolean) | Some(Type::Empty) => {
                            format!("{}{}", " ".repeat(depth), node.name)
                        }
                        _ => format!("{}{} {}", " ".repeat(depth), node.name, v.value),
                    };
                    out.push(SourceLine { line: 0, text });
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::schema::ModuleSet;

    fn schema_for(module_name: &str, text: &str) -> crate::schema::Schema {
        let set =
            ModuleSet::build(vec![(format!("{module_name}.yang"), text.to_string())]).unwrap();
        set.schema(module_name).unwrap()
    }

    fn lines(text: &str) -> Vec<SourceLine> {
        text.lines()
            .enumerate()
            .map(|(i, l)| SourceLine {
                line: i + 1,
                text: l.to_string(),
            })
            .collect()
    }

    fn rendered(text: &str) -> String {
        text.lines()
            .map(|l| l.trim_end())
            .collect::<Vec<_>>()
            .join("\n")
            + "\n"
    }

    const SAVD: &str = "module savd {\n  yang-version 1.1;\n  namespace \"urn:r:savd\";\n  prefix savd;\n  leaf mode { type enumeration { enum strict; enum loose; enum fp; enum efp; } default strict; }\n  leaf action { type enumeration { enum monitor; enum drop; } default monitor; }\n  leaf i-understand-drop-mode { type boolean; default false; }\n  leaf poll { type uint32 { range 1..max; } default 5; }\n  list interface {\n    key \"name\";\n    leaf name { type rc-name; }\n    leaf mode { type enumeration { enum strict; enum loose; enum fp; enum efp; enum barsav; } }\n    leaf role { type enumeration { enum customer; enum peer; enum provider; } }\n    leaf remote-as { type uint32; }\n  }\n  list binding {\n    key \"prefix\";\n    leaf prefix { type inet:ip-prefix; }\n    leaf-list interface { type string; }\n  }\n  typedef rc-name { type string { length 1..15; } }\n}\n";

    #[test]
    fn savd_grammar_binds_positional_stanzas() {
        let schema = schema_for("savd", SAVD);
        let input = "mode loose\ninterface vethlegit\n  mode strict\n  remote-as 65001\nbinding 192.0.2.0/24 interface vethlegit vethother\n";
        let (tree, report) = parse(&schema, &lines(input), &LineDialect::default()).unwrap();
        assert_eq!(report.modeled, 5);
        assert!(report.unmodeled.is_empty());
        assert!(matches!(
            &tree.get(&Path::parse("/mode").unwrap()).unwrap().kind,
            NodeKind::Leaf { value, from_default: false, .. } if value == "loose"
        ));
        assert!(matches!(
            &tree.get(&Path::parse("/interface[name=vethlegit]/mode").unwrap())
            .unwrap()
                .kind,
            NodeKind::Leaf { value, from_default: false, .. } if value == &"strict".to_string()
        ));
        assert!(matches!(
            tree.get(&Path::parse("/binding[prefix=192.0.2.0/24]/interface").unwrap())
                .unwrap()
                .kind,
            NodeKind::LeafList(_)
        ));
    }

    #[test]
    fn byte_identical_round_trip_with_comments_and_unknowns() {
        let schema = schema_for("savd", SAVD);
        let input =
            "! savd config\nmode strict\n\ninterface vethlegit\n  mode strict\nfrobnicate 7\n";
        let (tree, report) = parse(&schema, &lines(input), &LineDialect::default()).unwrap();
        assert_eq!(report.unmodeled, vec![6]);
        let out = render(&tree, &LineDialect::default());
        let text: String = out.iter().map(|l| format!("{}\n", l.text)).collect();
        assert_eq!(text, rendered(input));
    }

    #[test]
    fn key_leaves_exist_for_the_json_view() {
        let schema = schema_for("savd", SAVD);
        let (tree, _) = parse(
            &schema,
            &lines("interface vethlegit\n  mode loose\n"),
            &LineDialect::default(),
        )
        .unwrap();
        assert!(matches!(
            &tree.get(&Path::parse("/interface[name=vethlegit]/name").unwrap())
            .unwrap()
                .kind,
            NodeKind::Leaf { value, from_default: false, .. } if value == &"vethlegit".to_string()
        ));
    }

    const BFDD: &str = "module bfdd {\n  yang-version 1.1;\n  namespace \"urn:r:bfdd\";\n  prefix bfdd;\n  list peer {\n    key \"address multihop\";\n    leaf address { type inet:ip-address; }\n    leaf multihop { type boolean; default false; }\n    leaf transmit-interval { type uint32 { range 1..60000; } default 300; }\n    leaf passive { type boolean; default false; }\n    leaf local-address { type inet:ip-address; }\n  }\n}\n";

    #[test]
    fn boolean_key_shorthand_binds_multihop() {
        let schema = schema_for("bfdd", BFDD);
        let (tree, _) = parse(
            &schema,
            &lines("peer 192.0.2.9 multihop\n  transmit-interval 300\npeer 2001:db8::9\n"),
            &LineDialect::default(),
        )
        .unwrap();
        // Same address, different multihop: two distinct entries
        // (§7.8.2), exactly bfdd's (ip, multihop) peer identity.
        assert!(tree
            .get(&Path::parse("/peer[address=192.0.2.9][multihop=true]").unwrap())
            .is_some());
        assert!(tree
            .get(&Path::parse("/peer[address=192.0.2.9][multihop=false]").unwrap())
            .is_none());
        assert!(tree
            .get(&Path::parse("/peer[address=2001:db8::9][multihop=false]").unwrap())
            .is_some());
        // The stanza line rode the OPEN peer (192.0.2.9 multihop):
        // ctx semantics, exactly bfdd's parser.
        assert!(matches!(
            &tree.get(&Path::parse("/peer[address=192.0.2.9][multihop=true]/transmit-interval").unwrap())
            .unwrap()
                .kind,
            NodeKind::Leaf { value, from_default: false, .. } if value == &"300".to_string()
        ));
    }

    const ROUTERD: &str = "module rousterd {\n  yang-version 1.1;\n  namespace \"urn:r:rousterd\";\n  prefix r;\n  container ip {\n    list route {\n      key \"prefix\";\n      leaf prefix { type inet:ipv4-prefix; }\n      leaf-list nexthop {\n        type union { type inet:ipv4-address; type enumeration { enum blackhole; } }\n      }\n      leaf table { type uint32 { range 1..max; } }\n    }\n  }\n  container zapi {\n    leaf socket { type string; }\n  }\n}\n";

    #[test]
    fn multi_value_tail_stops_at_sibling_keywords() {
        let schema = schema_for("rousterd", ROUTERD);
        let (tree, report) = parse(
            &schema,
            &lines(
                "ip route 203.0.113.0/24 blackhole\nip route 198.51.100.0/24 192.0.2.1 192.0.2.2 table 202\nzapi socket /run/rouster/zapi.api\n",
            ),
            &LineDialect::default(),
        )
        .unwrap();
        assert_eq!(report.modeled, 3);
        let nh = match &tree
            .get(&Path::parse("/ip/route[prefix=198.51.100.0/24]/nexthop").unwrap())
            .unwrap()
            .kind
        {
            NodeKind::LeafList(values) => {
                values.iter().map(|v| v.value.clone()).collect::<Vec<_>>()
            }
            _ => panic!(),
        };
        assert_eq!(nh, vec!["192.0.2.1", "192.0.2.2"]);
        assert!(matches!(
            &tree.get(&Path::parse("/ip/route[prefix=198.51.100.0/24]/table").unwrap())
            .unwrap()
                .kind,
            NodeKind::Leaf { value, from_default: false, .. } if value == &"202".to_string()
        ));
        assert!(report.unmodeled.is_empty());
    }

    const OSPFD: &str = "module ospfd {\n  yang-version 1.1;\n  namespace \"urn:r:ospfd\";\n  prefix o;\n  container router {\n    container ospf {\n      leaf router-id { type inet:ipv4-address; }\n      list area {\n        key \"id\";\n        leaf id { type string; }\n        list interface {\n          key \"name\";\n          leaf name { type string; }\n          leaf cost { type uint32; }\n        }\n        list network {\n          key \"prefix\";\n          leaf prefix { type inet:ipv4-prefix; }\n          leaf area { type string; }\n        }\n      }\n    }\n  }\n  container key {\n    list chain {\n      key \"name\";\n      leaf name { type string; }\n      list key {\n        key \"id\";\n        leaf id { type uint8; }\n        leaf key-string { type string; }\n      }\n    }\n  }\n}\n";

    #[test]
    fn ospfd_nested_stanzas_and_two_word_walks() {
        let schema = schema_for("ospfd", OSPFD);
        let input = "router ospf\n  router-id 10.0.0.1\n  area 0.0.0.0\n    interface eth0\n      cost 10\n    network 10.0.0.0/24 area 0.0.0.0\nkey chain kc1\n  key 1\n    key-string old-secret\n";
        let (tree, report) = parse(&schema, &lines(input), &LineDialect::default()).unwrap();
        assert!(report.unmodeled.is_empty(), "{:?}", report.unmodeled);
        assert!(matches!(
            &tree.get(&Path::parse("/router/ospf/area[id=0.0.0.0]/interface[name=eth0]/cost").unwrap())
            .unwrap()
                .kind,
            NodeKind::Leaf { value, from_default: false, .. } if value == &"10".to_string()
        ));
        assert!(tree
            .get(
                &Path::parse("/router/ospf/area[id=0.0.0.0]/network[prefix=10.0.0.0/24]/area")
                    .unwrap()
            )
            .is_some());
        assert!(tree
            .get(&Path::parse("/key/chain[name=kc1]/key[id=1]/key-string").unwrap())
            .is_some());
        // Byte-identical render.
        let out = render(&tree, &LineDialect::default());
        let text: String = out.iter().map(|l| format!("{}\n", l.text)).collect();
        assert_eq!(text, rendered(input));
    }

    #[test]
    fn synthesized_render_indents_and_dialects_booleans() {
        let schema = schema_for("savd", SAVD);
        // Build programmatically (no origins).
        let mut tree = DataTree::empty(schema.clone());
        tree.set(&Path::parse("/mode").unwrap(), "loose", None)
            .unwrap();
        tree.set(
            &Path::parse("/interface[name=eth0]/name").unwrap(),
            "eth0",
            None,
        )
        .unwrap();
        tree.set(
            &Path::parse("/interface[name=eth0]/mode").unwrap(),
            "strict",
            None,
        )
        .unwrap();
        tree.set(
            &Path::parse("/i-understand-drop-mode").unwrap(),
            "true",
            None,
        )
        .unwrap();
        let out = render(&tree, &LineDialect::default());
        let text: Vec<&str> = out.iter().map(|l| l.text.as_str()).collect();
        assert_eq!(
            text,
            vec![
                "mode loose",
                "interface eth0",
                " mode strict",
                "i-understand-drop-mode yes"
            ]
        );
    }

    #[test]
    fn malformed_lines_error_with_line_numbers() {
        let schema = schema_for("savd", SAVD);
        // `mode` value outside the enumeration.
        let e = parse(&schema, &lines("mode nosuch\n"), &LineDialect::default()).unwrap_err();
        assert!(e.to_string().contains("line 1"), "{e}");
        // A leaf with no value.
        let e2 = parse(
            &schema,
            &lines("interface eth0\n  remote-as\n"),
            &LineDialect::default(),
        )
        .unwrap_err();
        assert!(e2.to_string().contains("line 2"), "{e2}");
        // A bad boolean word.
        let e3 = parse(&schema, &lines("interface eth0\n"), &LineDialect::default());
        assert!(e3.is_ok());
        let _ = e3;
    }
}
