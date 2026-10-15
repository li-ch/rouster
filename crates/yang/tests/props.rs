//! Property tests — the W5B convention (proptest, dev-only).
//!
//! Two properties, both per the S11-a prompt:
//!
//! 1. **Round-trip equivalence** (`tree → serialized → tree`): for
//!    any config text the linebind accepts, rendering the tree and
//!    re-binding reproduces the same source lines byte-for-byte
//!    (configd's render contract), and the RFC 7951 JSON view
//!    survives encode → decode → encode unchanged.
//! 2. **Default-fill idempotence**: filling defaults twice equals
//!    filling once (§7.6.1), and never overwrites an operator-set
//!    leaf.

use proptest::{collection, option, prelude::*};

use yang::data::{DataTree, Origin, Path};
use yang::json;
use yang::line::{render, LineDialect, SourceLine};

/// The property schema: a slice of the savd model (leafs, lists,
/// leaf-lists, defaults, a must) — small enough to generate over,
/// rich enough to exercise every tree feature.
const SCHEMA: &str = "module prop {\n  yang-version 1.1;\n  namespace \"urn:r:prop\";\n  prefix p;\n  leaf mode { type enumeration { enum strict; enum loose; enum fp; } default strict; }\n  leaf poll { type uint32 { range 1..600; } default 5; }\n  leaf ack { type boolean; default false; }\n  list interface {\n    key \"name\";\n    leaf name { type string { length 1..8; } }\n    leaf imode { type enumeration { enum strict; enum loose; } default loose; }\n    leaf mtu { type uint16 { range 1280..9216; } default 1500; }\n    must \"not(name = 'bad')\" { error-message \"no bad names\"; }\n  }\n  list binding {\n    key \"prefix\";\n    leaf prefix { type inet:ip-prefix; }\n    leaf-list interface { type string; }\n  }\n}\n";

fn schema() -> yang::Schema {
    let set = yang::ModuleSet::build(vec![("prop.yang".into(), SCHEMA.into())]).unwrap();
    set.schema("prop").unwrap()
}

fn source_lines(text: &str) -> Vec<SourceLine> {
    text.lines()
        .enumerate()
        .map(|(i, l)| SourceLine {
            line: i + 1,
            text: l.trim_end().to_string(),
        })
        .collect()
}

fn rendered_text(lines: &[SourceLine]) -> String {
    let mut out = String::new();
    for l in lines {
        out.push_str(&l.text);
        out.push('\n');
    }
    out
}

/// Interface names: non-empty, bounded, never "bad" (the must).
fn iface_name() -> impl Strategy<Value = String> {
    "[a-z]{1,4}[0-9]{0,2}".prop_filter("not `bad`", |s| s != "bad")
}

fn mode() -> impl Strategy<Value = String> {
    prop_oneof![
        Just("strict".into()),
        Just("loose".into()),
        Just("fp".into())
    ]
}

fn prefix4() -> impl Strategy<Value = String> {
    (10u8..200, any::<u8>(), any::<u8>(), 24u8..32u8)
        .prop_map(|(a, b, c, len)| format!("{}.{}.{}.0/{}", a, b, c, len - (len % 8)))
}

/// A random valid config body for the property schema.
fn config_body() -> impl Strategy<Value = String> {
    (
        option::of(mode()),
        option::of(1u32..600u32),
        option::of(Just("yes".to_string())),
        collection::vec(iface_name(), 0..4),
        collection::vec(
            (
                iface_name(),
                option::of(1280u16..9216u16),
                option::of(mode()),
            ),
            0..4,
        ),
        collection::vec((prefix4(), collection::vec(iface_name(), 1..3)), 0..3),
    )
        .prop_map(|(mode, poll, ack, comments, ifaces, bindings)| {
            let mut out = String::new();
            if let Some(m) = mode {
                out.push_str(&format!("mode {m}\n"));
            }
            if let Some(p) = poll {
                out.push_str(&format!("poll {p}\n"));
            }
            if ack.is_some() {
                out.push_str("ack yes\n");
            }
            for _ in comments {
                out.push_str("! note\n");
            }
            for (name, mtu, imode) in ifaces {
                out.push_str(&format!("interface {name}\n"));
                if let Some(m) = mtu {
                    out.push_str(&format!(" mtu {m}\n"));
                }
                if let Some(m) = imode {
                    out.push_str(&format!(" mode {m}\n"));
                }
            }
            for (p, names) in bindings {
                // One `interface` keyword, then the bare names —
                // the leaf-list's positional tail — distinct per
                // binding (savd's duplicate-name rule).
                let mut unique: Vec<&String> = Vec::new();
                for n in &names {
                    if !unique.contains(&n) {
                        unique.push(n);
                    }
                }
                let joined = unique
                    .iter()
                    .map(|n| n.to_string())
                    .collect::<Vec<_>>()
                    .join(" ");
                out.push_str(&format!("binding {p} interface {joined}\n"));
            }
            out
        })
}

fn bind(text: &str) -> DataTree {
    let s = schema();
    let (tree, report) = yang::line::parse(&s, &source_lines(text), &LineDialect::default())
        .expect("generated configs bind");
    assert!(
        report.unmodeled.is_empty(),
        "unmodeled: {:?}",
        report.unmodeled
    );
    tree
}

proptest! {
    /// Round-trip 1 (line form): text → tree → source lines → text
    /// is a fixed point — configd's byte-stability, as a property
    /// (source order = line order; merged stanza openers keep every
    /// line).
    #[test]
    fn line_round_trip_is_a_fixed_point(text in config_body()) {
        let tree = bind(&text);
        let lines = tree
            .source_lines()
            .iter()
            .map(|o| o.raw.clone())
            .collect::<Vec<_>>();
        let once = if lines.is_empty() {
            String::new()
        } else {
            format!("{}\n", lines.join("\n"))
        };
        prop_assert_eq!(&once, &text);
        // And the synthesized render of the same tree is also
        // stable round-trip (line form through the dialect path).
        let rendered = rendered_text(&render(&tree, &LineDialect::default()));
        let tree2 = bind(&rendered);
        prop_assert_eq!(
            rendered_text(&render(&tree2, &LineDialect::default())),
            rendered
        );
    }

    /// Round-trip 2 (RFC 7951): tree → JSON → tree → JSON is a
    /// fixed point (defaults filled on both sides, so the JSON
    /// view is the full data set).
    #[test]
    fn json_round_trip_is_a_fixed_point(text in config_body()) {
        let mut tree = bind(&text);
        tree.default_fill();
        let once = json::encode(&tree);
        let back = json::decode(&tree, &once).expect("decode of own encoding");
        let twice = json::encode(&back);
        prop_assert_eq!(once, twice);
    }

    /// Default-fill idempotence: fill twice equals fill once, and
    /// the fill never touches operator-set values.
    #[test]
    fn default_fill_is_idempotent(text in config_body()) {
        let mut tree = bind(&text);
        tree.default_fill();
        let once = format!("{:?}", tree.children);
        tree.default_fill();
        prop_assert_eq!(once, format!("{:?}", tree.children));
        // The fill is also lossless for rendering: it introduces no
        // source lines (defaults render as nothing).
        prop_assert_eq!(
            tree.source_lines()
                .iter()
                .map(|o| (o.line, o.raw.clone()))
                .collect::<Vec<_>>(),
            bind(&text)
                .source_lines()
                .iter()
                .map(|o| (o.line, o.raw.clone()))
                .collect::<Vec<_>>()
        );
    }

    /// Validation is a pure function of the tree: validate, fill,
    /// validate again — the verdict set is unchanged (defaults are
    /// not mandatory leaves, §7.6.5's rule).
    #[test]
    fn validation_is_stable_across_default_fill(text in config_body()) {
        let mut tree = bind(&text);
        let before = tree.validate();
        tree.default_fill();
        prop_assert_eq!(before, tree.validate());
    }

    /// Every tree built by the bind validates clean: the generator
    /// only produces schema-conformant configs, so violations would
    /// mean the validator lies.
    #[test]
    fn generated_configs_validate_clean(text in config_body()) {
        let tree = bind(&text);
        prop_assert!(tree.validate().is_empty(), "{:?}", tree.validate());
    }

    /// set/get round-trips values (canonical form), for random
    /// paths into the generated trees.
    #[test]
    fn set_then_get_returns_the_value(
        text in config_body(),
        name in iface_name(),
        mtu in 1280u16..9216u16,
    ) {
        let mut tree = bind(&text);
        let path = Path::parse(&format!("/interface[name={name}]/mtu")).unwrap();
        tree.set(&path, &mtu.to_string(), Some(Origin { line: 99, raw: format!("interface {name}") }))
            .expect("set is well-typed");
        match &tree.get(&path).expect("node exists").kind {
            yang::data::NodeKind::Leaf { value, from_default, .. } => {
                prop_assert_eq!(value, &mtu.to_string());
                prop_assert!(!from_default);
            }
            other => prop_assert!(false, "unexpected kind {other:?}"),
        }
    }
}
