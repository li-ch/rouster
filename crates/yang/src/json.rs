//! JSON encoding of data trees — RFC 7951 "JSON Encoding of Data
//! Modeled with YANG", the subset form: §5.1 leaf, §5.2 container,
//! §5.3 leaf-list, §5.4 list, §6 type mapping (integers as JSON
//! numbers, booleans as JSON booleans, `empty` as `null`, strings/
//! enumerations/inet values as JSON strings).
//!
//! (RESTCONF's RFC 8040 §5.2 is what POINTS at this encoding — its
//! §5.3 is "RESTCONF Metadata"; the encoding itself is RFC 7951.
//! Cited honestly per the house rule.)
//!
//! Names (RFC 7951 §4): member names are the unqualified node
//! identifiers — the subset's trees bind exactly one module, and
//! §4 permits the unqualified form when the module is the same as
//! the parent's; a cross-module member would need the qualified
//! `module:name` form this encoder never produces.
//!
//! Lists (§5.4): "encoded as a name/array pair" whose elements are
//! objects; key leaves appear as ordinary members. The input-side
//! decoder accepts exactly what the encoder produces (plus any
//! member order — JSON objects are unordered, §3) and routes every
//! value through [`crate::data::DataTree::set`], so a decoded tree
//! carries the same type guarantees as a built one.

use crate::data::{DataTree, Node, NodeKind};
use crate::schema::DataDef;
use crate::types::Type;

/// Encodes the tree (RFC 7951 form). Defaults appear only if
/// [`DataTree::default_fill`] materialized them (the caller's
/// choice — there is no with-defaults protocol negotiation here,
/// and none is pretended to).
pub fn encode(tree: &DataTree) -> String {
    let module = &tree.schema.set.modules[&tree.schema.module];
    let mut out = String::new();
    out.push('{');
    encode_children(&tree.children, &module.data, &mut out, 0);
    out.push('}');
    out
}

fn encode_children(nodes: &[Node], defs: &[DataDef], out: &mut String, depth: usize) {
    let mut first = true;
    for def in defs {
        for node in nodes.iter().filter(|n| n.name == def.name()) {
            // Opaque lines never encode (line-form-only; disclosed).
            if matches!(node.kind, NodeKind::Opaque(_)) {
                continue;
            }
            if !first {
                out.push(',');
            }
            first = false;
            encode_node(node, def, out, depth);
        }
    }
}

fn encode_node(node: &Node, def: &DataDef, out: &mut String, depth: usize) {
    let _ = depth;
    write_json_string(def.name(), out);
    out.push(':');
    match (&node.kind, def) {
        (NodeKind::Container(children), DataDef::Container(cdef)) => {
            out.push('{');
            encode_children(children, &cdef.children, out, depth + 1);
            out.push('}');
        }
        (NodeKind::List(entries), DataDef::List(ldef)) => {
            out.push('[');
            for (i, entry) in entries.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                out.push('{');
                if let NodeKind::Entry { children, .. } = &entry.kind {
                    encode_children(children, &ldef.children, out, depth + 1);
                }
                out.push('}');
            }
            out.push(']');
        }
        (NodeKind::Entry { children, .. }, DataDef::List(ldef)) => {
            // A bare entry outside a list cannot occur via the tree
            // API; encode its children defensively.
            out.push('{');
            encode_children(children, &ldef.children, out, depth + 1);
            out.push('}');
        }
        (NodeKind::Leaf { value, .. }, DataDef::Leaf(leaf)) => {
            let ty = leaf.resolved.as_ref().expect("resolved at build");
            encode_typed(value, ty, out);
        }
        (NodeKind::LeafList(values), DataDef::LeafList(ll)) => {
            let ty = ll.resolved.as_ref().expect("resolved at build");
            out.push('[');
            for (i, v) in values.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                encode_typed(&v.value, ty, out);
            }
            out.push(']');
        }
        _ => {
            // Node kind disagrees with schema (cannot happen — set
            // enforces kinds); encode as null rather than panic.
            out.push_str("null");
        }
    }
}

fn encode_typed(value: &str, ty: &Type, out: &mut String) {
    match ty {
        Type::Int(_, _) => {
            // Canonical integer form is already enforced by set().
            out.push_str(value);
        }
        Type::Boolean => out.push_str(value),
        Type::Empty => out.push_str("null"),
        _ => write_json_string(value, out),
    }
}

fn write_json_string(s: &str, out: &mut String) {
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

// ---- decode ----

/// A decoded JSON value (the encoder's own shape: objects, arrays,
/// strings, numbers, booleans, null).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Json {
    Null,
    Bool(bool),
    Num(String),
    Str(String),
    Arr(Vec<Json>),
    Obj(Vec<(String, Json)>),
}

impl Json {
    pub fn get(&self, key: &str) -> Option<&Json> {
        match self {
            Json::Obj(members) => members.iter().find(|(k, _)| k == key).map(|(_, v)| v),
            _ => None,
        }
    }
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum JsonError {
    #[error("JSON syntax: {0}")]
    Syntax(String),
    #[error("data error: {0}")]
    Data(String),
}

/// Parses the encoder's canonical JSON (a lenient-enough subset for
/// any member order and ordinary whitespace).
pub fn parse(input: &str) -> Result<Json, JsonError> {
    let chars: Vec<char> = input.chars().collect();
    let mut pos = 0usize;
    let value = parse_value(&chars, &mut pos)?;
    skip_ws(&chars, &mut pos);
    if pos != chars.len() {
        return Err(JsonError::Syntax("trailing characters".into()));
    }
    Ok(value)
}

fn skip_ws(chars: &[char], pos: &mut usize) {
    while *pos < chars.len() && chars[*pos].is_whitespace() {
        *pos += 1;
    }
}

fn parse_value(chars: &[char], pos: &mut usize) -> Result<Json, JsonError> {
    skip_ws(chars, pos);
    match chars.get(*pos) {
        Some('{') => {
            *pos += 1;
            let mut members = Vec::new();
            skip_ws(chars, pos);
            if chars.get(*pos) == Some(&'}') {
                *pos += 1;
                return Ok(Json::Obj(members));
            }
            loop {
                skip_ws(chars, pos);
                let key = parse_string(chars, pos)?;
                skip_ws(chars, pos);
                if chars.get(*pos) != Some(&':') {
                    return Err(JsonError::Syntax("expected `:`".into()));
                }
                *pos += 1;
                let value = parse_value(chars, pos)?;
                members.push((key, value));
                skip_ws(chars, pos);
                match chars.get(*pos) {
                    Some(',') => {
                        *pos += 1;
                    }
                    Some('}') => {
                        *pos += 1;
                        return Ok(Json::Obj(members));
                    }
                    _ => return Err(JsonError::Syntax("expected `,` or `}`".into())),
                }
            }
        }
        Some('[') => {
            *pos += 1;
            let mut items = Vec::new();
            skip_ws(chars, pos);
            if chars.get(*pos) == Some(&']') {
                *pos += 1;
                return Ok(Json::Arr(items));
            }
            loop {
                let value = parse_value(chars, pos)?;
                items.push(value);
                skip_ws(chars, pos);
                match chars.get(*pos) {
                    Some(',') => {
                        *pos += 1;
                    }
                    Some(']') => {
                        *pos += 1;
                        return Ok(Json::Arr(items));
                    }
                    _ => return Err(JsonError::Syntax("expected `,` or `]`".into())),
                }
            }
        }
        Some('"') => Ok(Json::Str(parse_string(chars, pos)?)),
        Some('t') => {
            expect_word(chars, pos, "true")?;
            Ok(Json::Bool(true))
        }
        Some('f') => {
            expect_word(chars, pos, "false")?;
            Ok(Json::Bool(false))
        }
        Some('n') => {
            expect_word(chars, pos, "null")?;
            Ok(Json::Null)
        }
        Some(c) if c.is_ascii_digit() || *c == '-' => {
            let start = *pos;
            while *pos < chars.len()
                && (chars[*pos].is_ascii_digit()
                    || matches!(chars[*pos], '-' | '.' | 'e' | 'E' | '+'))
            {
                *pos += 1;
            }
            Ok(Json::Num(chars[start..*pos].iter().collect()))
        }
        other => Err(JsonError::Syntax(format!(
            "unexpected `{}`",
            other.map(|c| c.to_string()).unwrap_or_else(|| "end".into())
        ))),
    }
}

fn expect_word(chars: &[char], pos: &mut usize, word: &str) -> Result<(), JsonError> {
    for c in word.chars() {
        if chars.get(*pos) != Some(&c) {
            return Err(JsonError::Syntax(format!("expected `{word}`")));
        }
        *pos += 1;
    }
    Ok(())
}

fn parse_string(chars: &[char], pos: &mut usize) -> Result<String, JsonError> {
    if chars.get(*pos) != Some(&'"') {
        return Err(JsonError::Syntax("expected a string".into()));
    }
    *pos += 1;
    let mut out = String::new();
    while let Some(&c) = chars.get(*pos) {
        match c {
            '"' => {
                *pos += 1;
                return Ok(out);
            }
            '\\' => {
                *pos += 1;
                match chars.get(*pos) {
                    Some('"') => out.push('"'),
                    Some('\\') => out.push('\\'),
                    Some('/') => out.push('/'),
                    Some('n') => out.push('\n'),
                    Some('r') => out.push('\r'),
                    Some('t') => out.push('\t'),
                    Some('b') => out.push('\u{8}'),
                    Some('f') => out.push('\u{c}'),
                    Some('u') => {
                        let hex: String = chars[*pos + 1..(*pos + 5).min(chars.len())]
                            .iter()
                            .collect();
                        let code = u32::from_str_radix(&hex, 16)
                            .map_err(|_| JsonError::Syntax("bad \\u escape".into()))?;
                        out.push(char::from_u32(code).unwrap_or('\u{fffd}'));
                        *pos += 4;
                    }
                    _ => return Err(JsonError::Syntax("bad escape".into())),
                }
                *pos += 1;
            }
            c => {
                out.push(c);
                *pos += 1;
            }
        }
    }
    Err(JsonError::Syntax("unterminated string".into()))
}

/// Loads an encoded tree back into a fresh tree for the same
/// schema. Every value routes through [`DataTree::set`] /
/// [`set_leaf_list`] — type checks and defaults behave exactly as
/// the built-tree path.
pub fn decode(tree: &DataTree, input: &str) -> Result<DataTree, JsonError> {
    let value = parse(input)?;
    let mut out = DataTree::empty(tree.schema.clone());
    let Json::Obj(members) = value else {
        return Err(JsonError::Syntax("the root must be an object".into()));
    };
    let module = out.schema.set.modules[&out.schema.module].clone();
    for (key, v) in &members {
        let def = module
            .data
            .iter()
            .find(|d| d.name() == key)
            .ok_or_else(|| JsonError::Data(format!("`{key}` is not in the schema root")))?;
        load_node(&mut out, &[], def, v).map_err(JsonError::Data)?;
    }
    Ok(out)
}

fn load_node(
    tree: &mut DataTree,
    parent: &[crate::data::PathSeg],
    def: &DataDef,
    value: &Json,
) -> Result<(), String> {
    let mut path: Vec<crate::data::PathSeg> = parent.to_vec();
    path.push(crate::data::PathSeg {
        name: def.name().to_string(),
        keys: Vec::new(),
    });
    let path = crate::data::Path { segs: path };
    match (def, value) {
        (DataDef::Leaf(_), v) => {
            let s = scalar(v)?;
            tree.set(&path, &s, None).map_err(|e| e.to_string())
        }
        (DataDef::LeafList(_), Json::Arr(items)) => {
            for item in items {
                let s = scalar(item)?;
                tree.set_leaf_list(&path, &s, None)
                    .map_err(|e| e.to_string())?;
            }
            Ok(())
        }
        (DataDef::Container(cdef), Json::Obj(members)) => {
            // Touch the container into existence.
            tree.set_container(&path).map_err(|e| e.to_string())?;
            for (key, v) in members {
                let child = cdef
                    .children
                    .iter()
                    .find(|d| d.name() == key)
                    .ok_or_else(|| format!("`{key}` is not a child of `{}`", cdef.name))?;
                load_node(tree, &path.segs, child, v)?;
            }
            Ok(())
        }
        (DataDef::List(ldef), Json::Arr(entries)) => {
            for entry in entries {
                let Json::Obj(members) = entry else {
                    return Err(format!("list `{}` entries must be objects", ldef.name));
                };
                // §5.4: the key members select the entry.
                let mut keys = Vec::new();
                for key in &ldef.keys {
                    let v = members
                        .iter()
                        .find(|(k, _)| k == key)
                        .ok_or_else(|| format!("list entry misses key `{key}`"))?;
                    keys.push((key.clone(), scalar(&v.1)?));
                }
                let mut entry_path = path.clone();
                entry_path.segs.last_mut().expect("nonempty").keys = keys.clone();
                tree.set_container(&entry_path).map_err(|e| e.to_string())?;
                // The key leaves are members too (RFC 7951 §5.4).
                for (k, v) in &keys {
                    let mut kp = entry_path.clone();
                    kp.segs.last_mut().expect("nonempty").keys = Vec::new();
                    kp.segs.last_mut().expect("nonempty").keys = keys.clone();
                    kp.segs.push(crate::data::PathSeg {
                        name: k.clone(),
                        keys: Vec::new(),
                    });
                    tree.set(&kp, v, None).map_err(|e| e.to_string())?;
                }
                for (key, v) in members {
                    if ldef.keys.contains(key) {
                        continue;
                    }
                    let child = ldef
                        .children
                        .iter()
                        .find(|d| d.name() == key)
                        .ok_or_else(|| format!("`{key}` is not a child of `{}`", ldef.name))?;
                    load_node(tree, &entry_path.segs, child, v)?;
                }
            }
            Ok(())
        }
        _ => Err(format!(
            "`{}`: value shape does not match the node kind",
            def.name()
        )),
    }
}

fn scalar(v: &Json) -> Result<String, String> {
    match v {
        Json::Str(s) => Ok(s.clone()),
        Json::Num(n) => Ok(n.clone()),
        Json::Bool(b) => Ok(b.to_string()),
        Json::Null => Ok(String::new()),
        _ => Err("expected a scalar".to_string()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::data::{DataTree, Path};

    fn tree() -> DataTree {
        let text = "module j {\n  yang-version 1.1;\n  namespace \"urn:j\";\n  prefix j;\n  container interfaces {\n    list interface {\n      key \"name\";\n      leaf name { type string; }\n      leaf mtu { type uint16; }\n      leaf enabled { type boolean; }\n      leaf-list alias { type string; }\n    }\n  }\n}\n";
        let set = crate::schema::ModuleSet::build(vec![("j.yang".into(), text.into())]).unwrap();
        DataTree::empty(set.schema("j").unwrap())
    }

    #[test]
    fn encodes_leafs_containers_lists_and_leaf_lists() {
        let mut t = tree();
        t.set(
            &Path::parse("/interfaces/interface[name=eth0]/name").unwrap(),
            "eth0",
            None,
        )
        .unwrap();
        t.set(
            &Path::parse("/interfaces/interface[name=eth0]/mtu").unwrap(),
            "9000",
            None,
        )
        .unwrap();
        t.set(
            &Path::parse("/interfaces/interface[name=eth0]/enabled").unwrap(),
            "true",
            None,
        )
        .unwrap();
        t.set_leaf_list(
            &Path::parse("/interfaces/interface[name=eth0]/alias").unwrap(),
            "wan",
            None,
        )
        .unwrap();
        let json = encode(&t);
        assert_eq!(
            json,
            "{\"interfaces\":{\"interface\":[{\"name\":\"eth0\",\"mtu\":9000,\"enabled\":true,\"alias\":[\"wan\"]}]}}"
        );
    }

    #[test]
    fn round_trip_preserves_the_typed_tree() {
        let mut t = tree();
        t.set(
            &Path::parse("/interfaces/interface[name=eth0]/name").unwrap(),
            "eth0",
            None,
        )
        .unwrap();
        t.set(
            &Path::parse("/interfaces/interface[name=eth0]/mtu").unwrap(),
            "9000",
            None,
        )
        .unwrap();
        t.set(
            &Path::parse("/interfaces/interface[name=eth1]/name").unwrap(),
            "eth1",
            None,
        )
        .unwrap();
        t.set_leaf_list(
            &Path::parse("/interfaces/interface[name=eth1]/alias").unwrap(),
            "lan",
            None,
        )
        .unwrap();
        let once = encode(&t);
        let back = decode(&t, &once).unwrap();
        let twice = encode(&back);
        assert_eq!(once, twice);
    }

    #[test]
    fn strings_are_escaped() {
        let mut t = tree();
        t.set(
            &Path::parse("/interfaces/interface[name=x]/name").unwrap(),
            "a\"b\\c\n",
            None,
        )
        .unwrap();
        let json = encode(&t);
        assert!(json.contains("a\\\"b\\\\c\\n"), "{json}");
        let back = decode(&t, &json).unwrap();
        assert_eq!(encode(&back), json);
    }

    #[test]
    fn malformed_json_is_rejected() {
        assert!(parse("{").is_err());
        assert!(parse("{\"a\":}").is_err());
        assert!(parse("[1,]").is_err());
        assert!(parse("nul").is_err());
        assert!(parse("{}x").is_err());
    }

    #[test]
    fn decode_rejects_unknown_members_and_bad_values() {
        let mut t = tree();
        t.set(
            &Path::parse("/interfaces/interface[name=eth0]/name").unwrap(),
            "eth0",
            None,
        )
        .unwrap();
        let e = decode(&t, "{\"nope\":1}").unwrap_err();
        assert!(e.to_string().contains("nope"), "{e}");
        let e2 = decode(
            &t,
            "{\"interfaces\":{\"interface\":[{\"name\":\"e\",\"mtu\":99999}]}}",
        )
        .unwrap_err();
        assert!(
            e2.to_string().contains("99999") || e2.to_string().contains("mtu"),
            "{e2}"
        );
    }
}
