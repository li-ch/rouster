//! The in-memory data tree — RFC 7950 §8.1 "Constraints on Data"
//! (a data tree is valid when every leaf matches its type
//! constraints, all list keys are present, and every `must`
//! expression evaluates true), §7.6.1 default values (default
//! filling), §7.6.5 mandatory, §7.7 leaf-list uniqueness, §7.5.3
//! must evaluation.
//!
//! The tree is bound to one module of a [`Schema`] (the subset has
//! no cross-module data composition — augment §7.17 is out). Nodes
//! keep their document order and, when built from a config file,
//! their [`Origin`] — the source line number and raw text. That is
//! what lets configd render byte-identical files FROM the tree (the
//! render walks the tree's origins, never the section text) while
//! the typed view feeds validation and the JSON dump.
//!
//! Paths address nodes absolutely: `/interfaces/interface[name=eth0]
//! /mtu`. Setting creates missing intermediate containers and list
//! entries (NETCONF merge semantics; re-entering a keyed entry
//! merges into it — §7.8.2: the keys identify the entry) and
//! overwrites an existing leaf (§7.6.7); deleting prunes empty
//! ancestors (the subset has no presence containers — §7.5.5 is
//! §Deferred — so an empty container does not exist, §7.5.1's rule
//! for non-presence containers).

use std::fmt;

use crate::must::PathResolver;
use crate::schema::{DataDef, Schema};

/// One absolute path segment: a node name plus, for list entries,
/// the key predicates that select the entry.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct PathSeg {
    pub name: String,
    /// `(key-leaf-name, value)` pairs (§7.8.2).
    pub keys: Vec<(String, String)>,
}

impl fmt::Display for PathSeg {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.name)?;
        for (k, v) in &self.keys {
            write!(f, "[{k}={v}]")?;
        }
        Ok(())
    }
}

/// An absolute data-tree path.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Path {
    pub segs: Vec<PathSeg>,
}

impl Path {
    /// Parses `/name/list[key=value]/name` (the internal form; the
    /// `must` subset's richer grammar lives in `must.rs`).
    pub fn parse(input: &str) -> Result<Path, DataError> {
        let mut segs = Vec::new();
        // Split on '/' at bracket depth zero — key values may carry
        // '/' (IPv4 prefixes).
        let mut depth = 0usize;
        let mut part = String::new();
        for c in input.chars() {
            match c {
                '[' if depth == 0 => {
                    depth += 1;
                    part.push(c);
                }
                ']' if depth > 0 => {
                    depth -= 1;
                    part.push(c);
                }
                '/' if depth == 0 => {
                    if !part.is_empty() {
                        segs.push(parse_seg(&part)?);
                    }
                    part.clear();
                }
                c => part.push(c),
            }
        }
        if depth != 0 {
            return Err(DataError::BadPath(format!("`{input}` has an unclosed `[`")));
        }
        if !part.is_empty() {
            segs.push(parse_seg(&part)?);
        }
        Ok(Path { segs })
    }

    /// The path rendered as a string.
    pub fn to_string_path(&self) -> String {
        if self.segs.is_empty() {
            return "/".to_string();
        }
        let mut out = String::new();
        for seg in &self.segs {
            out.push('/');
            out.push_str(&seg.to_string());
        }
        out
    }
}

impl fmt::Display for Path {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.to_string_path())
    }
}

/// Where a node came from — the config file's line and verbatim
/// text (render reproduces these bytes exactly), or nothing (the
/// node was created programmatically and renders synthesized).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Origin {
    pub line: usize,
    pub raw: String,
}

/// One data node.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Node {
    pub name: String,
    pub kind: NodeKind,
    pub origin: Option<Origin>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NodeKind {
    Container(Vec<Node>),
    /// A list's entries in document order; each entry is an
    /// [`NodeKind::Entry`] carrying all its keys (§7.8.2: an entry
    /// is created with every key leaf assigned).
    List(Vec<Node>),
    Entry {
        keys: Vec<(String, String)>,
        children: Vec<Node>,
        /// Every opener line that entered this entry, in order — a
        /// config may re-open a stanza (`interface eth0` twice);
        /// the render reproduces each opener, so merged entries
        /// never lose source lines (the merge is §7.8.2: the keys
        /// identify the entry).
        openers: Vec<Origin>,
    },
    Leaf {
        value: String,
        from_default: bool,
        /// Every assignment line, in order (re-assignments keep
        /// their source lines — bfdd/savd accept repeated stanza
        /// lines, last value wins, and the render reproduces every
        /// line). Programmatic/default sets carry no origin.
        assignments: Vec<Origin>,
    },
    LeafList(Vec<LeafListValue>),
    /// Unmodeled or ignorable source lines (comments, blanks, and
    /// lines the owning daemon's grammar accepts but the model does
    /// not cover — configd's pass-through discipline, disclosed in
    /// docs/yang.md). Rendered verbatim, in order.
    Opaque(Vec<Origin>),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LeafListValue {
    pub value: String,
    pub origin: Option<Origin>,
}

/// A validation violation — precise paths by the house contract:
/// the data-tree path plus, when known, the originating line.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Violation {
    pub path: String,
    pub line: Option<usize>,
    pub kind: ViolationKind,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ViolationKind {
    /// §7.6.5: a mandatory leaf is absent.
    MissingMandatory { leaf: String },
    /// §7.5.3: a `must` expression evaluated false.
    MustFailed { expr: String, message: String },
    /// §7.7: duplicate leaf-list values.
    DuplicateLeafList { value: String },
    /// §7.8.2: a list entry is missing a key leaf value.
    MissingKey { key: String },
}

impl fmt::Display for Violation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.path)?;
        if let Some(line) = self.line {
            write!(f, " (line {line})")?;
        }
        match &self.kind {
            ViolationKind::MissingMandatory { leaf } => {
                write!(f, ": mandatory leaf `{leaf}` is missing (RFC 7950 §7.6.5)")
            }
            ViolationKind::MustFailed { message, .. } => {
                write!(f, ": must violated (RFC 7950 §7.5.3): {message}")
            }
            ViolationKind::DuplicateLeafList { value } => {
                write!(f, ": duplicate leaf-list value `{value}` (RFC 7950 §7.7)")
            }
            ViolationKind::MissingKey { key } => {
                write!(f, ": list entry is missing key `{key}` (RFC 7950 §7.8.2)")
            }
        }
    }
}

/// Data-tree errors — set/get/delete time (validation issues are
/// [`Violation`]s, not errors: a tree can exist while invalid).
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum DataError {
    #[error("path {path}: {reason}")]
    Path { path: String, reason: String },
    #[error("bad path `{0}`")]
    BadPath(String),
}

fn parse_seg(part: &str) -> Result<PathSeg, DataError> {
    let (name, rest) = match part.split_once('[') {
        Some((name, rest)) => (name, Some(rest)),
        None => (part, None),
    };
    let mut keys = Vec::new();
    if let Some(rest) = rest {
        let Some(preds) = rest.strip_suffix(']') else {
            return Err(DataError::BadPath(format!("`{part}` has no closing `]`")));
        };
        for pred in preds.split("][") {
            let Some((k, v)) = pred.split_once('=') else {
                return Err(DataError::BadPath(format!(
                    "predicate `{pred}` is not name=value"
                )));
            };
            keys.push((k.to_string(), v.to_string()));
        }
    }
    Ok(PathSeg {
        name: name.to_string(),
        keys,
    })
}

fn derr(path: &Path, reason: impl Into<String>) -> DataError {
    DataError::Path {
        path: path.to_string_path(),
        reason: reason.into(),
    }
}

/// A document-ordered data tree bound to one schema module.
#[derive(Debug, Clone)]
pub struct DataTree {
    pub schema: Schema,
    pub children: Vec<Node>,
}

impl DataTree {
    /// An empty tree for the schema's module.
    pub fn empty(schema: Schema) -> DataTree {
        DataTree {
            schema,
            children: Vec::new(),
        }
    }

    /// The owning module's name.
    pub fn module(&self) -> &str {
        &self.schema.module
    }

    // ---- set/get/delete ----

    /// Sets a leaf value (creating intermediates). The value is
    /// type-checked (§9) and canonicalized; replacing an existing
    /// leaf overwrites it and clears `from_default`.
    pub fn set(
        &mut self,
        path: &Path,
        value: &str,
        origin: Option<Origin>,
    ) -> Result<(), DataError> {
        let (chain, leaf) = self.leaf_def(path)?;
        let r#type = leaf.resolved.clone().expect("resolved at build");
        if !leaf.config {
            return Err(derr(path, "config false data cannot be written (§7.21.1)"));
        }
        let canonical = r#type.check(value).map_err(|e| derr(path, e))?;
        let name = leaf.name.clone();
        let cursor = self.descend_for_create(path, &chain)?;
        match cursor.iter_mut().find(|n| n.name == name) {
            Some(node) => match &mut node.kind {
                NodeKind::Leaf {
                    value,
                    from_default,
                    assignments,
                } => {
                    *value = canonical;
                    *from_default = false;
                    if let Some(o) = &origin {
                        assignments.push(o.clone());
                    }
                    if node.origin.is_none() {
                        node.origin = origin;
                    }
                    Ok(())
                }
                _ => Err(derr(path, format!("`{name}` is not a leaf"))),
            },
            None => {
                let assignments = origin.as_ref().map(|o| vec![o.clone()]).unwrap_or_default();
                cursor.push(Node {
                    name,
                    kind: NodeKind::Leaf {
                        value: canonical,
                        from_default: false,
                        assignments,
                    },
                    origin,
                });
                Ok(())
            }
        }
    }

    /// Appends a value to a leaf-list (§7.7). Duplicates are a
    /// validate-time violation, not a set-time error (§7.7.3).
    pub fn set_leaf_list(
        &mut self,
        path: &Path,
        value: &str,
        origin: Option<Origin>,
    ) -> Result<(), DataError> {
        let (chain, def) = self.leaf_list_def(path)?;
        let r#type = def.resolved.clone().expect("resolved at build");
        if !def.config {
            return Err(derr(path, "config false data cannot be written (§7.21.1)"));
        }
        let canonical = r#type.check(value).map_err(|e| derr(path, e))?;
        let name = def.name.clone();
        let cursor = self.descend_for_create(path, &chain)?;
        match cursor.iter_mut().find(|n| n.name == name) {
            Some(node) => match &mut node.kind {
                NodeKind::LeafList(values) => {
                    values.push(LeafListValue {
                        value: canonical,
                        origin,
                    });
                    Ok(())
                }
                _ => Err(derr(path, format!("`{name}` is not a leaf-list"))),
            },
            None => {
                cursor.push(Node {
                    name,
                    kind: NodeKind::LeafList(vec![LeafListValue {
                        value: canonical,
                        origin,
                    }]),
                    origin: None,
                });
                Ok(())
            }
        }
    }

    /// Gets the node at `path` (leaf, container, list, or entry).
    pub fn get(&self, path: &Path) -> Option<&Node> {
        self.node_at(path)
    }

    /// Deletes the node at `path` (a leaf, a whole list entry, a
    /// container, or a keyless list); empty ancestors are pruned
    /// (§7.5.1: a non-presence container exists iff it has
    /// children).
    pub fn delete(&mut self, path: &Path) -> Result<(), DataError> {
        let Some((last, ancestors)) = path.segs.split_last() else {
            return Err(derr(path, "cannot delete the tree root"));
        };
        let parent = self
            .children_of_mut_at(ancestors)
            .ok_or_else(|| derr(path, "parent does not exist"))?;
        let removed = if last.keys.is_empty() {
            let before = parent.len();
            parent.retain(|n| n.name != last.name);
            parent.len() != before
        } else {
            // The entry lives under the list node of that name.
            let mut removed = false;
            for node in parent.iter_mut() {
                if node.name == last.name {
                    if let NodeKind::List(entries) = &mut node.kind {
                        let before = entries.len();
                        entries.retain(|e| {
                            !matches!(&e.kind, NodeKind::Entry { keys, .. } if keys == &last.keys)
                        });
                        removed = entries.len() != before;
                    }
                }
            }
            removed
        };
        if !removed {
            return Err(derr(path, "node does not exist"));
        }
        self.prune_empty(ancestors);
        Ok(())
    }

    /// Prunes the node at `path` if it is now empty, cascading
    /// upward (§7.5.1: a non-presence container exists iff it has
    /// children; the subset extends the rule to empty lists).
    fn prune_empty(&mut self, path: &[PathSeg]) {
        let Some((last, parent)) = path.split_last() else {
            self.children.retain(|n| !node_is_empty(n));
            return;
        };
        let mut removed = false;
        if let Some(siblings) = self.children_of_mut_at(parent) {
            if last.keys.is_empty() {
                let before = siblings.len();
                siblings.retain(|n| !(n.name == last.name && node_is_empty(n)));
                removed = siblings.len() != before;
            } else {
                for node in siblings.iter_mut() {
                    if node.name == last.name {
                        if let NodeKind::List(entries) = &mut node.kind {
                            let before = entries.len();
                            entries.retain(|e| !node_is_empty(e));
                            removed = entries.len() != before;
                        }
                    }
                }
            }
        }
        if removed {
            self.prune_empty(parent);
        } else if let Some(children) = self.children_of_mut_at(path) {
            // The node stays; prune its own empty children.
            children.retain(|n| !node_is_empty(n));
        }
    }

    // ---- schema walks ----

    /// The leaf definition for the path's final segment plus the
    /// definitions of every ANCESTOR segment (owned clones — the
    /// tree is mutated right after).
    fn leaf_def(&self, path: &Path) -> Result<(Vec<DataDef>, crate::schema::LeafDef), DataError> {
        let (chain, last) = self.data_def_chain(path)?;
        match last {
            DataDef::Leaf(leaf) => Ok((chain.into_iter().cloned().collect(), leaf.clone())),
            other => Err(derr(
                path,
                format!("`{}` is a {}, not a leaf", other.name(), kind_word(other)),
            )),
        }
    }

    fn leaf_list_def(
        &self,
        path: &Path,
    ) -> Result<(Vec<DataDef>, crate::schema::LeafListDef), DataError> {
        let (chain, last) = self.data_def_chain(path)?;
        match last {
            DataDef::LeafList(ll) => Ok((chain.into_iter().cloned().collect(), ll.clone())),
            other => Err(derr(
                path,
                format!(
                    "`{}` is a {}, not a leaf-list",
                    other.name(),
                    kind_word(other)
                ),
            )),
        }
    }

    /// Walks the schema along the path: (ancestor definitions,
    /// final definition). Final segments may be any data kind;
    /// mid-path segments must be containers or lists, and list
    /// segments must carry all their keys (§7.8.2).
    fn data_def_chain(&self, path: &Path) -> Result<(Vec<&DataDef>, &DataDef), DataError> {
        let module = &self.schema.set.modules[&self.schema.module];
        let mut defs: Vec<&DataDef> = Vec::new();
        let mut children: &Vec<DataDef> = &module.data;
        let last = path.segs.len().saturating_sub(1);
        if path.segs.is_empty() {
            return Err(derr(path, "path addresses the module root"));
        }
        for (idx, seg) in path.segs.iter().enumerate() {
            let found = children
                .iter()
                .find(|d| d.name() == seg.name)
                .ok_or_else(|| {
                    derr(
                        path,
                        format!(
                            "`{}` is not a child of `{}` (schema has: {})",
                            seg.name,
                            if idx == 0 {
                                self.schema.module.clone()
                            } else {
                                path.segs[idx - 1].name.clone()
                            },
                            children
                                .iter()
                                .map(|d| d.name())
                                .collect::<Vec<_>>()
                                .join(", ")
                        ),
                    )
                })?;
            if idx == last {
                return Ok((defs, found));
            }
            match found {
                DataDef::Container(c) => {
                    defs.push(found);
                    children = &c.children;
                }
                DataDef::List(l) => {
                    if seg.keys.len() != l.keys.len() {
                        return Err(derr(
                            path,
                            format!(
                                "list `{}` needs all {} keys in its predicate (§7.8.2)",
                                l.name,
                                l.keys.len()
                            ),
                        ));
                    }
                    defs.push(found);
                    children = &l.children;
                }
                _ => {
                    return Err(derr(
                        path,
                        format!(
                            "`{}` is a leaf/leaf-list and cannot have children",
                            seg.name
                        ),
                    ));
                }
            }
        }
        unreachable!("the loop returns on the final segment")
    }

    /// Walks/creates the tree down to the final segment's PARENT,
    /// returning that parent's mutable children.
    fn descend_for_create<'a>(
        &'a mut self,
        path: &Path,
        chain: &[DataDef],
    ) -> Result<&'a mut Vec<Node>, DataError> {
        let Some((_last, ancestors)) = path.segs.split_last() else {
            return Ok(&mut self.children);
        };
        let mut children = &mut self.children;
        for (idx, seg) in ancestors.iter().enumerate() {
            let Some(def) = chain.get(idx) else {
                return Err(derr(path, "schema chain mismatch"));
            };
            match def {
                DataDef::Container(_) => {
                    let node = ensure_container(children, &seg.name);
                    children = match &mut node.kind {
                        NodeKind::Container(c) => c,
                        _ => return Err(derr(path, format!("`{}` is not a container", seg.name))),
                    };
                }
                DataDef::List(l) => {
                    let node = ensure_entry(children, &seg.name, &seg.keys, &l.keys, path, None)?;
                    children = match &mut node.kind {
                        NodeKind::Entry { children, .. } => children,
                        _ => unreachable!("ensure_entry built an Entry"),
                    };
                }
                other => {
                    return Err(derr(
                        path,
                        format!(
                            "`{}` is a {} and cannot contain children",
                            seg.name,
                            kind_word(other)
                        ),
                    ));
                }
            }
        }
        Ok(children)
    }

    /// Ensures the container (or list entry) at `path` exists —
    /// creating intermediates — without touching any leaf. The JSON
    /// decoder uses this before filling members.
    pub fn set_container(&mut self, path: &Path) -> Result<(), DataError> {
        self.set_container_with_origin(path, None)
    }

    /// [`DataTree::set_container`], attaching `origin` to nodes it
    /// CREATES (never overwriting an existing node's origin — the
    /// first line that created a stanza keeps its bytes).
    pub fn set_container_with_origin(
        &mut self,
        path: &Path,
        origin: Option<Origin>,
    ) -> Result<(), DataError> {
        let (chain, last) = self.data_def_chain(path)?;
        match last {
            DataDef::Container(_) | DataDef::List(_) => {}
            other => {
                return Err(derr(
                    path,
                    format!(
                        "`{}` is a {}, not a container or list",
                        other.name(),
                        kind_word(other)
                    ),
                ))
            }
        }
        let mut chain: Vec<DataDef> = chain.into_iter().cloned().collect();
        chain.push(last.clone());
        let mut children = &mut self.children;
        for (idx, seg) in path.segs.iter().enumerate() {
            let Some(def) = chain.get(idx) else {
                return Err(derr(path, "schema chain mismatch"));
            };
            match def {
                DataDef::Container(_) => {
                    let node = ensure_container(children, &seg.name);
                    if node.origin.is_none() {
                        node.origin = origin.clone();
                    }
                    children = match &mut node.kind {
                        NodeKind::Container(c) => c,
                        _ => return Err(derr(path, format!("`{}` is not a container", seg.name))),
                    };
                }
                DataDef::List(l) => {
                    // Only the DEEPEST node of a line's walk carries
                    // the opener (callers pass None for ancestors).
                    let opener = if idx == path.segs.len() - 1 {
                        origin.clone()
                    } else {
                        None
                    };
                    let node = ensure_entry(children, &seg.name, &seg.keys, &l.keys, path, opener)?;
                    if node.origin.is_none() {
                        node.origin = origin.clone();
                    }
                    children = match &mut node.kind {
                        NodeKind::Entry { children, .. } => children,
                        _ => unreachable!("ensure_entry built an Entry"),
                    };
                }
                other => {
                    return Err(derr(
                        path,
                        format!(
                            "`{}` is a {} and cannot contain children",
                            seg.name,
                            kind_word(other)
                        ),
                    ));
                }
            }
        }
        Ok(())
    }

    fn node_at(&self, path: &Path) -> Option<&Node> {
        let mut children: &[Node] = &self.children;
        let last = path.segs.len().saturating_sub(1);
        for (idx, seg) in path.segs.iter().enumerate() {
            let node = find_child(children, seg)?;
            if idx == last {
                return Some(node);
            }
            children = node_children(node)?;
        }
        None
    }

    pub(crate) fn children_of_mut_at(&mut self, path: &[PathSeg]) -> Option<&mut Vec<Node>> {
        let mut children = &mut self.children;
        for seg in path {
            let node = find_child_mut(children, seg)?;
            children = match &mut node.kind {
                NodeKind::Container(c) => c,
                NodeKind::Entry { children, .. } => children,
                _ => return None,
            };
        }
        Some(children)
    }

    // ---- default-fill and validation (§7.6.1, §8.1) ----

    /// Fills absent leaves with their declared defaults (§7.6.4's
    /// default, applied per §7.6.1), marking them `from_default`.
    /// Idempotent: a second fill finds nothing absent. Defaults
    /// materialize only along branches that exist (the subset's
    /// rule: no presence containers, so absent branches are absent
    /// by operator intent).
    pub fn default_fill(&mut self) {
        let module = self.schema.set.modules[&self.schema.module].clone();
        fill_defaults(&mut self.children, &module.data);
    }

    /// Validates the tree (§8.1): mandatory leaves (§7.6.5), list
    /// keys present (§7.8.2), leaf-list uniqueness (§7.7), and
    /// every `must` (§7.5.3) — collecting all violations with their
    /// precise paths and origin lines. Type validity was enforced
    /// at set time; nothing type-invalid can be in the tree.
    pub fn validate(&self) -> Vec<Violation> {
        let module = self.schema.set.modules[&self.schema.module].clone();
        let mut out = Vec::new();
        validate_children(
            &self.children,
            &module.data,
            &mut Vec::new(),
            &mut out,
            self,
        );
        out
    }

    /// Flattens every node origin + opaque line into SOURCE order
    /// (sorted by line number, one emission per line) — the
    /// byte-stable render input configd uses. Merged stanza openers
    /// keep every line; statements that shared an opener line emit
    /// once (the opener carries them).
    pub fn source_lines(&self) -> Vec<Origin> {
        let mut out = Vec::new();
        collect_lines(&self.children, &mut out);
        out.sort_by_key(|o| o.line);
        out.dedup_by_key(|o| o.line);
        out
    }

    /// The resolver for `must` evaluation (context = the node's own
    /// path).
    pub fn resolver(&self) -> TreeResolver<'_> {
        TreeResolver { tree: self }
    }
}

// ---- child lookup (list segments may address the list or an entry) ----

fn find_child<'a>(children: &'a [Node], seg: &PathSeg) -> Option<&'a Node> {
    if let Some(list) = children
        .iter()
        .find(|n| n.name == seg.name && matches!(n.kind, NodeKind::List(_)))
    {
        if seg.keys.is_empty() {
            return Some(list);
        }
        let NodeKind::List(entries) = &list.kind else {
            unreachable!("matched a List");
        };
        return entries
            .iter()
            .find(|e| entry_keys_match(&e.kind, &seg.keys));
    }
    children
        .iter()
        .find(|n| n.name == seg.name && entry_keys_match(&n.kind, &seg.keys))
}

fn find_child_mut<'a>(children: &'a mut [Node], seg: &PathSeg) -> Option<&'a mut Node> {
    if children
        .iter()
        .any(|n| n.name == seg.name && matches!(n.kind, NodeKind::List(_)))
    {
        if seg.keys.is_empty() {
            return children
                .iter_mut()
                .find(|n| n.name == seg.name && matches!(n.kind, NodeKind::List(_)));
        }
        for node in children.iter_mut() {
            if node.name == seg.name {
                if let NodeKind::List(entries) = &mut node.kind {
                    if let Some(pos) = entries
                        .iter()
                        .position(|e| entry_keys_match(&e.kind, &seg.keys))
                    {
                        return Some(&mut entries[pos]);
                    }
                }
            }
        }
        return None;
    }
    children
        .iter_mut()
        .find(|n| n.name == seg.name && entry_keys_match(&n.kind, &seg.keys))
}

/// A `must`-evaluation adapter over the tree.
pub struct TreeResolver<'a> {
    tree: &'a DataTree,
}

impl PathResolver for TreeResolver<'_> {
    fn leaf_value(&self, context: &[String], path: &crate::must::Path) -> Option<String> {
        let abs = self.resolve(context, path)?;
        match self.tree.node_at(&abs)?.kind {
            NodeKind::Leaf { ref value, .. } => Some(value.clone()),
            _ => None,
        }
    }

    fn node_exists(&self, context: &[String], path: &crate::must::Path) -> bool {
        let Some(abs) = self.resolve(context, path) else {
            return false;
        };
        self.tree.node_at(&abs).is_some()
    }
}

impl TreeResolver<'_> {
    /// Resolves a must-path (relative/absolute, `.`/`..`, single
    /// key predicates) against a context path.
    fn resolve(&self, context: &[String], path: &crate::must::Path) -> Option<Path> {
        let base: Vec<PathSeg> = if path.absolute {
            Vec::new()
        } else {
            context.iter().map(|s| parse_ctx_seg(s)).collect()
        };
        let mut segs = base;
        for step in &path.steps {
            match step.name.as_str() {
                "." => {}
                ".." => {
                    segs.pop();
                }
                name => {
                    let keys = match &step.key {
                        Some((k, v)) => vec![(k.clone(), v.clone())],
                        None => Vec::new(),
                    };
                    segs.push(PathSeg {
                        name: strip_module_prefix(name),
                        keys,
                    });
                }
            }
        }
        Some(Path { segs })
    }
}

fn parse_ctx_seg(s: &str) -> PathSeg {
    Path::parse(&format!("/{s}"))
        .unwrap_or_default()
        .segs
        .into_iter()
        .next()
        .unwrap_or_default()
}

fn strip_module_prefix(name: &str) -> String {
    match name.split_once(':') {
        Some((_, tail)) => tail.to_string(),
        None => name.to_string(),
    }
}

fn ensure_container<'a>(children: &'a mut Vec<Node>, name: &str) -> &'a mut Node {
    if let Some(pos) = children
        .iter()
        .position(|n| n.name == name && matches!(n.kind, NodeKind::Container(_)))
    {
        return &mut children[pos];
    }
    children.push(Node {
        name: name.to_string(),
        kind: NodeKind::Container(Vec::new()),
        origin: None,
    });
    children.last_mut().expect("just pushed")
}

fn ensure_entry<'a>(
    children: &'a mut Vec<Node>,
    name: &str,
    seg_keys: &[(String, String)],
    def_keys: &[String],
    path: &Path,
    opener: Option<Origin>,
) -> Result<&'a mut Node, DataError> {
    // Every schema key must appear in the predicate.
    let mut keys = Vec::new();
    for def_key in def_keys {
        let Some((_, v)) = seg_keys.iter().find(|(k, _)| k == def_key) else {
            return Err(derr(
                path,
                format!("list `{name}` predicate misses key `{def_key}` (§7.8.2)"),
            ));
        };
        keys.push((def_key.clone(), v.clone()));
    }
    let list = ensure_list(children, name);
    let NodeKind::List(entries) = &mut list.kind else {
        unreachable!("ensure_list built a List");
    };
    if let Some(pos) = entries
        .iter()
        .position(|n| entry_keys_match(&n.kind, &keys))
    {
        // A re-opened stanza: keep the opener's line (render
        // reproduces every opener); node.origin keeps the first.
        let entry = &mut entries[pos];
        if let Some(o) = opener {
            if let NodeKind::Entry { openers, .. } = &mut entry.kind {
                openers.push(o);
            }
        }
        return Ok(entry);
    }
    let openers = opener.clone().map(|o| vec![o]).unwrap_or_default();
    entries.push(Node {
        name: name.to_string(),
        kind: NodeKind::Entry {
            keys,
            children: Vec::new(),
            openers,
        },
        origin: opener,
    });
    Ok(entries.last_mut().expect("just pushed"))
}

fn ensure_list<'a>(children: &'a mut Vec<Node>, name: &str) -> &'a mut Node {
    if let Some(pos) = children
        .iter()
        .position(|n| n.name == name && matches!(n.kind, NodeKind::List(_)))
    {
        return &mut children[pos];
    }
    children.push(Node {
        name: name.to_string(),
        kind: NodeKind::List(Vec::new()),
        origin: None,
    });
    children.last_mut().expect("just pushed")
}

fn entry_keys_match(kind: &NodeKind, keys: &[(String, String)]) -> bool {
    match kind {
        NodeKind::Entry { keys: k, .. } => k == keys,
        // Non-entry nodes match only keyless segments.
        _ => keys.is_empty(),
    }
}

fn node_children(node: &Node) -> Option<&Vec<Node>> {
    match &node.kind {
        NodeKind::Container(c) => Some(c),
        NodeKind::List(_) => None,
        NodeKind::Entry { children, .. } => Some(children),
        _ => None,
    }
}

fn node_is_empty(node: &Node) -> bool {
    match &node.kind {
        NodeKind::Container(c) => c.is_empty() || c.iter().all(node_is_empty),
        NodeKind::List(entries) => entries.is_empty(),
        NodeKind::Entry { children, .. } => {
            children.is_empty() || children.iter().all(node_is_empty)
        }
        NodeKind::LeafList(values) => values.is_empty(),
        NodeKind::Opaque(lines) => lines.is_empty(),
        NodeKind::Leaf { .. } => false,
    }
}

fn collect_lines(nodes: &[Node], out: &mut Vec<Origin>) {
    for node in nodes {
        if let Some(origin) = &node.origin {
            if !matches!(node.kind, NodeKind::Entry { .. } | NodeKind::Leaf { .. }) {
                out.push(origin.clone());
            }
        }
        match &node.kind {
            NodeKind::Container(children) => {
                collect_lines(children, out);
            }
            NodeKind::Entry {
                children, openers, ..
            } => {
                out.extend(openers.iter().cloned());
                collect_lines(children, out);
            }
            NodeKind::List(entries) => collect_lines(entries, out),
            NodeKind::Opaque(lines) => out.extend(lines.iter().cloned()),
            NodeKind::LeafList(values) => {
                for v in values {
                    if let Some(origin) = &v.origin {
                        out.push(origin.clone());
                    }
                }
            }
            NodeKind::Leaf { assignments, .. } => {
                out.extend(assignments.iter().cloned());
            }
        }
    }
}

fn kind_word(def: &DataDef) -> &'static str {
    match def {
        DataDef::Container(_) => "container",
        DataDef::List(_) => "list",
        DataDef::Leaf(_) => "leaf",
        DataDef::LeafList(_) => "leaf-list",
    }
}

fn fill_defaults(nodes: &mut Vec<Node>, defs: &[DataDef]) {
    for def in defs {
        let DataDef::Leaf(leaf) = def else { continue };
        let Some(default) = &leaf.default else {
            continue;
        };
        let exists = nodes
            .iter()
            .any(|n| n.name == leaf.name && matches!(n.kind, NodeKind::Leaf { .. }));
        if !exists {
            nodes.push(Node {
                name: leaf.name.clone(),
                kind: NodeKind::Leaf {
                    value: default.clone(),
                    from_default: true,
                    assignments: Vec::new(),
                },
                origin: None,
            });
        }
    }
    for node in nodes.iter_mut() {
        match &mut node.kind {
            NodeKind::Container(children) | NodeKind::Entry { children, .. } => {
                if let Some(def_children) = children_defs(defs, &node.name) {
                    let owned = def_children.clone();
                    fill_defaults(children, &owned);
                }
            }
            NodeKind::List(entries) => {
                if let Some(def_children) = children_defs(defs, &node.name) {
                    let owned = def_children.clone();
                    for entry in entries.iter_mut() {
                        if let NodeKind::Entry { children, .. } = &mut entry.kind {
                            fill_defaults(children, &owned);
                        }
                    }
                }
            }
            _ => {}
        }
    }
}

fn children_defs<'a>(defs: &'a [DataDef], name: &str) -> Option<&'a Vec<DataDef>> {
    defs.iter().find_map(|d| match d {
        DataDef::Container(c) if c.name == name => Some(&c.children),
        DataDef::List(l) if l.name == name => Some(&l.children),
        _ => None,
    })
}

fn validate_children(
    nodes: &[Node],
    defs: &[DataDef],
    path: &mut Vec<String>,
    out: &mut Vec<Violation>,
    tree: &DataTree,
) {
    for def in defs {
        match def {
            DataDef::Leaf(leaf) => {
                if !leaf.mandatory {
                    continue;
                }
                let present = nodes.iter().any(|n| {
                    n.name == leaf.name
                        && matches!(
                            &n.kind,
                            NodeKind::Leaf {
                                from_default: false,
                                ..
                            }
                        )
                });
                if !present {
                    let mut full = path.clone();
                    full.push(leaf.name.clone());
                    out.push(Violation {
                        path: format!("/{}", full.join("/")),
                        line: None,
                        kind: ViolationKind::MissingMandatory {
                            leaf: leaf.name.clone(),
                        },
                    });
                }
            }
            DataDef::LeafList(_) => {
                for node in nodes.iter().filter(|n| n.name == def.name()) {
                    if let NodeKind::LeafList(values) = &node.kind {
                        let mut seen = Vec::new();
                        for v in values {
                            if seen.contains(&v.value) {
                                let mut full = path.clone();
                                full.push(node.name.clone());
                                out.push(Violation {
                                    path: format!("/{}", full.join("/")),
                                    line: v.origin.as_ref().map(|o| o.line),
                                    kind: ViolationKind::DuplicateLeafList {
                                        value: v.value.clone(),
                                    },
                                });
                            }
                            seen.push(v.value.clone());
                        }
                    }
                }
            }
            DataDef::Container(c) => {
                for node in nodes.iter().filter(|n| n.name == c.name) {
                    if let NodeKind::Container(children) = &node.kind {
                        path.push(c.name.clone());
                        check_musts(def, path, node, out, tree);
                        validate_children(children, &c.children, path, out, tree);
                        path.pop();
                    }
                }
            }
            DataDef::List(l) => {
                for node in nodes.iter().filter(|n| n.name == l.name) {
                    if let NodeKind::List(entries) = &node.kind {
                        for entry in entries {
                            let NodeKind::Entry { keys, children, .. } = &entry.kind else {
                                continue;
                            };
                            for key in &l.keys {
                                if !keys.iter().any(|(k, _)| k == key) {
                                    path.push(l.name.clone());
                                    out.push(Violation {
                                        path: format!("/{}", path.join("/")),
                                        line: entry.origin.as_ref().map(|o| o.line),
                                        kind: ViolationKind::MissingKey { key: key.clone() },
                                    });
                                    path.pop();
                                }
                            }
                            path.push(render_entry_seg(&l.name, keys));
                            check_musts(def, path, entry, out, tree);
                            let owned = l.children.clone();
                            validate_children(children, &owned, path, out, tree);
                            path.pop();
                        }
                    }
                }
            }
        }
    }
}

fn render_entry_seg(name: &str, keys: &[(String, String)]) -> String {
    let mut out = name.to_string();
    for (k, v) in keys {
        out.push_str(&format!("[{k}={v}]"));
    }
    out
}

fn check_musts(
    def: &DataDef,
    path: &[String],
    node: &Node,
    out: &mut Vec<Violation>,
    tree: &DataTree,
) {
    for must in def.musts() {
        let ctx: Vec<String> = path.to_vec();
        if let Err(crate::must::MustError::Violated { src, message, .. }) =
            must.def.check(&tree.resolver(), &ctx)
        {
            out.push(Violation {
                path: format!("/{}", path.join("/")),
                line: node.origin.as_ref().map(|o| o.line),
                kind: ViolationKind::MustFailed { expr: src, message },
            });
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::schema::ModuleSet;

    fn tree() -> DataTree {
        let text = "module m {\n  yang-version 1.1;\n  namespace \"urn:x\";\n  prefix m;\n  container interfaces {\n    list interface {\n      key \"name\";\n      leaf name { type string; }\n      leaf mtu { type uint16 { range 1280..9216; } default 1500; }\n      leaf mode { type enumeration { enum strict; enum loose; } }\n      leaf required-when { type string; mandatory true; }\n    }\n  }\n  container sav {\n    leaf action { type enumeration { enum monitor; enum drop; } default monitor; }\n    leaf ack { type enumeration { enum yes; enum no; } default no; }\n    must \"not(action = 'drop') or ack = 'yes'\" {\n      error-message \"drop mode needs the friction acknowledgement\";\n    }\n  }\n}\n";
        let set = ModuleSet::build(vec![("m.yang".into(), text.into())]).unwrap();
        DataTree::empty(set.schema("m").unwrap())
    }

    fn p(s: &str) -> Path {
        Path::parse(s).unwrap()
    }

    #[test]
    fn set_creates_intermediates_and_canonicalizes() {
        let mut t = tree();
        t.set(&p("/interfaces/interface[name=eth0]/mtu"), "9000", None)
            .unwrap();
        assert_eq!(
            t.get(&p("/interfaces/interface[name=eth0]/mtu"))
                .unwrap()
                .kind,
            NodeKind::Leaf {
                value: "9000".into(),
                from_default: false,
                assignments: Vec::new()
            }
        );
        // Canonical integer form (§9.2.2).
        t.set(&p("/interfaces/interface[name=eth1]/mtu"), "+1500", None)
            .unwrap();
        assert_eq!(
            t.get(&p("/interfaces/interface[name=eth1]/mtu"))
                .unwrap()
                .kind,
            NodeKind::Leaf {
                value: "1500".into(),
                from_default: false,
                assignments: Vec::new()
            }
        );
    }

    #[test]
    fn set_type_checks_against_the_schema() {
        let mut t = tree();
        let e = t
            .set(&p("/interfaces/interface[name=eth0]/mtu"), "90000", None)
            .unwrap_err();
        assert!(e.to_string().contains("65535"), "{e}");
        let e2 = t
            .set(&p("/interfaces/interface[name=eth0]/mode"), "nope", None)
            .unwrap_err();
        assert!(e2.to_string().contains("enumeration"), "{e2}");
        let e3 = t
            .set(
                &p("/interfaces/interface[name=eth0]/nonexistent"),
                "1",
                None,
            )
            .unwrap_err();
        assert!(e3.to_string().contains("not a child"), "{e3}");
    }

    #[test]
    fn unknown_paths_and_missing_keys_are_errors() {
        let mut t = tree();
        assert!(t.set(&p("/nope/x"), "1", None).is_err());
        // A list segment without its full key predicate.
        assert!(t
            .set(&p("/interfaces/interface/mtu"), "1500", None)
            .is_err());
    }

    #[test]
    fn list_entries_merge_by_key_and_delete_only_the_named_one() {
        let mut t = tree();
        t.set(&p("/interfaces/interface[name=eth0]/mtu"), "1280", None)
            .unwrap();
        t.set(&p("/interfaces/interface[name=eth1]/mtu"), "9000", None)
            .unwrap();
        // Re-set on the same key merges (§7.8.2: keys identify).
        t.set(&p("/interfaces/interface[name=eth0]/mode"), "loose", None)
            .unwrap();
        let entries = match &t.get(&p("/interfaces/interface")).unwrap().kind {
            NodeKind::List(entries) => entries.len(),
            _ => panic!("expected a list"),
        };
        assert_eq!(entries, 2);
        // Delete one entry; the other survives.
        t.delete(&p("/interfaces/interface[name=eth0]")).unwrap();
        assert!(t.get(&p("/interfaces/interface[name=eth0]/mtu")).is_none());
        assert!(t.get(&p("/interfaces/interface[name=eth1]/mtu")).is_some());
    }

    #[test]
    fn delete_prunes_empty_ancestors() {
        let mut t = tree();
        t.set(&p("/interfaces/interface[name=eth0]/mtu"), "1500", None)
            .unwrap();
        t.delete(&p("/interfaces/interface[name=eth0]/mtu"))
            .unwrap();
        // The empty entry pruned, then the empty list, then the
        // empty container: nothing remains.
        assert!(t.get(&p("/interfaces")).is_none());
        assert!(t.source_lines().is_empty());
    }

    #[test]
    fn delete_missing_node_is_an_error_naming_the_path() {
        let mut t = tree();
        let e = t
            .delete(&p("/interfaces/interface[name=eth0]/mtu"))
            .unwrap_err();
        assert!(e.to_string().contains("does not exist"), "{e}");
    }

    #[test]
    fn default_fill_materializes_and_is_idempotent() {
        let mut t = tree();
        t.set(&p("/interfaces/interface[name=eth0]/mode"), "strict", None)
            .unwrap();
        t.default_fill();
        let mtu = t.get(&p("/interfaces/interface[name=eth0]/mtu")).unwrap();
        assert_eq!(
            mtu.kind,
            NodeKind::Leaf {
                value: "1500".into(),
                from_default: true,
                assignments: Vec::new()
            }
        );
        // Second fill changes nothing.
        let before = format!("{:?}", t.children);
        t.default_fill();
        assert_eq!(before, format!("{:?}", t.children));
        // An operator-set leaf is never overwritten by a default.
        t.set(&p("/interfaces/interface[name=eth1]/mtu"), "9000", None)
            .unwrap();
        t.default_fill();
        assert_eq!(
            t.get(&p("/interfaces/interface[name=eth1]/mtu"))
                .unwrap()
                .kind,
            NodeKind::Leaf {
                value: "9000".into(),
                from_default: false,
                assignments: Vec::new()
            }
        );
        // Absent branches are not created by the fill.
        assert!(t.get(&p("/sav/action")).is_none());
    }

    #[test]
    fn mandatory_enforcement_reports_precise_paths() {
        let mut t = tree();
        t.set(&p("/interfaces/interface[name=eth0]/mode"), "strict", None)
            .unwrap();
        let violations = t.validate();
        assert_eq!(violations.len(), 1, "{violations:?}");
        assert!(matches!(
            &violations[0].kind,
            ViolationKind::MissingMandatory { leaf } if leaf == "required-when"
        ));
        assert_eq!(
            violations[0].path,
            "/interfaces/interface[name=eth0]/required-when"
        );
        // Satisfy it and the tree validates clean.
        t.set(
            &p("/interfaces/interface[name=eth0]/required-when"),
            "x",
            None,
        )
        .unwrap();
        assert!(t.validate().is_empty());
    }

    #[test]
    fn must_violation_carries_the_error_message_and_line() {
        let mut t = tree();
        t.set(
            &p("/sav/action"),
            "drop",
            Some(Origin {
                line: 7,
                raw: "action drop".into(),
            }),
        )
        .unwrap();
        t.set(&p("/sav/ack"), "no", None).unwrap();
        let violations = t.validate();
        assert_eq!(violations.len(), 1, "{violations:?}");
        let ViolationKind::MustFailed { message, .. } = &violations[0].kind else {
            panic!()
        };
        assert!(message.contains("friction"), "{message}");
        assert_eq!(violations[0].path, "/sav");
        // ack=yes satisfies the must.
        t.set(&p("/sav/ack"), "yes", None).unwrap();
        assert!(t.validate().is_empty());
    }

    #[test]
    fn leaf_list_appends_and_flags_duplicates_at_validate() {
        let text = "module m2 {\n  yang-version 1.1;\n  namespace \"urn:y\";\n  prefix m2;\n  container binding {\n    leaf-list interface { type string; }\n  }\n}\n";
        let set = ModuleSet::build(vec![("m2.yang".into(), text.into())]).unwrap();
        let mut t = DataTree::empty(set.schema("m2").unwrap());
        t.set_leaf_list(&p("/binding/interface"), "eth0", None)
            .unwrap();
        t.set_leaf_list(&p("/binding/interface"), "eth1", None)
            .unwrap();
        assert!(t.validate().is_empty());
        t.set_leaf_list(&p("/binding/interface"), "eth0", None)
            .unwrap();
        let v = t.validate();
        assert_eq!(v.len(), 1);
        assert!(matches!(v[0].kind, ViolationKind::DuplicateLeafList { .. }));
    }

    #[test]
    fn opaque_lines_ride_document_order() {
        let mut t = tree();
        t.set(
            &p("/interfaces/interface[name=eth0]/mode"),
            "strict",
            Some(Origin {
                line: 3,
                raw: "interface eth0".into(),
            }),
        )
        .unwrap();
        t.children.push(Node {
            name: "! comment".into(),
            kind: NodeKind::Opaque(vec![Origin {
                line: 9,
                raw: "! tail comment".into(),
            }]),
            origin: None,
        });
        let origins = t.source_lines();
        let lines: Vec<(usize, &str)> = origins.iter().map(|o| (o.line, o.raw.as_str())).collect();
        assert_eq!(lines, vec![(3, "interface eth0"), (9, "! tail comment")]);
    }

    #[test]
    fn path_parse_and_render_round_trip() {
        let p1 = p("/interfaces/interface[name=eth0][vrf=red]/mtu");
        assert_eq!(
            p1.to_string_path(),
            "/interfaces/interface[name=eth0][vrf=red]/mtu"
        );
        assert!(Path::parse("/interface[name=eth0").is_err());
        assert!(Path::parse("/interface[eth0]").is_err());
        assert_eq!(Path::default().to_string_path(), "/");
    }
}
