//! The M4 flip's own tests: the YANG render is byte-identical to
//! the legacy section-split render (the e2e suite runs flipped and
//! stays green untouched — that is the outer proof; this is the
//! direct one), `dump --json` emits the documented RFC 7951 form,
//! and the YANG gate refuses what the models type (one layer
//! earlier than the daemon, same line).

use std::collections::BTreeMap;

use configd::tree::{parse, Daemon};
use configd::{render_all_sections, yangmode};

fn canonical(text: &str) -> configd::tree::Canonical {
    parse(text).unwrap_or_else(|e| panic!("canonical rejected: {e}"))
}

/// Corpus across every daemon section: realistic bodies with
/// comments, blanks, indentation, trailing blanks — everything the
/// byte-stability contract covers.
fn corpus() -> Vec<&'static str> {
    vec![
        "daemon rousterd {\nzapi socket /run/rouster/zserv.api\nip route 203.0.113.0/24 blackhole\nip route 198.51.100.0/24 192.0.2.1 192.0.2.2 table 202\n}\n",
        "daemon savd {\nmode strict\ninterface veths1\n  mode strict\ninterface veths2\n  mode barsav\n  role customer\n  remote-as 65001\nbinding 192.0.2.0/24 interface veths1 veths2\npoll 3\n\n! trailing comment\n   \n}\n",
        "daemon bfdd {\npeer 192.0.2.9\n  transmit-interval 300\npeer 198.51.100.9 multihop\n  local-address 198.51.100.1\n  echo yes\n}\n",
        "daemon ospfd {\nzapi socket /run/rouster/zapi.api\nrouter ospf\n router-id 10.0.0.1\n area 0.0.0.0\n  interface eth0\n   cost 10\n  network 10.0.0.0/24 area 0.0.0.0\n redistribute static\n}\n",
        "daemon bgpd {\nrouter bgp 65000\n bgp router-id 10.0.0.1\n neighbor 192.0.2.9 remote-as 65001\n neighbor 192.0.2.9 passive\n network 203.0.113.0/24\n}\n",
    ]
}

#[test]
fn yang_render_is_byte_identical_to_the_section_split_render() {
    for text in corpus() {
        let tree = canonical(text);
        let bound = yangmode::bind(&tree).unwrap();
        let from_trees: BTreeMap<Daemon, String> = yangmode::render_all(&bound);
        let legacy: BTreeMap<Daemon, String> = render_all_sections(&tree);
        assert_eq!(from_trees, legacy, "byte drift for:\n{text}");
    }
}

#[test]
fn every_corpus_section_binds_and_validates() {
    for text in corpus() {
        let tree = canonical(text);
        let bound = yangmode::bind(&tree).unwrap();
        for section in &bound.sections {
            assert!(
                section.report.unmodeled.is_empty(),
                "{}: unmodeled {:?}",
                section.daemon.name(),
                section.report.unmodeled
            );
        }
    }
}

#[test]
fn bind_refuses_a_type_violation_with_the_line() {
    // The smoke's BAD shape: savd's `mode nosuch`.
    let tree = canonical("daemon savd {\ninterface veths1\n  mode nosuch\n}\n");
    let err = yangmode::bind(&tree).unwrap_err();
    assert!(err.to_string().contains("line 3"), "{err}");
}

#[test]
fn bind_refuses_a_must_violation() {
    // savd drop mode without the friction acknowledgement.
    let tree = canonical("daemon savd {\naction drop\n}\n");
    let err = yangmode::bind(&tree).unwrap_err();
    assert!(err.to_string().contains("i-understand-drop-mode"), "{err}");
}

#[test]
fn unmodeled_lines_bind_but_disclose() {
    // A line the savd model does not carry (an unknown directive)
    // is pass-through: bind OK, unmodeled names the line.
    let tree = canonical("daemon savd {\nmode strict\nfrobnicate 7\n}\n");
    let bound = yangmode::bind(&tree).unwrap();
    let savd = bound.section(Daemon::Savd).unwrap();
    assert_eq!(savd.report.unmodeled, vec![3]);
    // And the render keeps the line verbatim.
    let rendered = yangmode::render_daemon(savd);
    assert_eq!(rendered, "mode strict\nfrobnicate 7\n");
}

#[test]
fn dump_json_is_the_documented_form() {
    let tree = canonical(
        "router-id 198.51.100.1\ndaemon savd {\nmode strict\npoll 3\n}\ndaemon bfdd {\npeer 192.0.2.9\n}\n",
    );
    let bound = yangmode::bind(&tree).unwrap();
    let json = yangmode::dump_json(&bound);
    // router-id at the top; per-daemon RFC 7951 members; defaults
    // filled (savd's action/hysteresis/... appear).
    assert!(
        json.starts_with("{\"router-id\":\"198.51.100.1\""),
        "{json}"
    );
    // Members appear in schema order (RFC 7951: object member
    // order is arbitrary; ours is deterministic = schema order).
    assert!(json.contains("\"savd\":{\"mode\":\"strict\""), "{json}");
    assert!(json.contains("\"poll\":3"), "{json}");
    assert!(json.contains("\"action\":\"monitor\""), "{json}");
    assert!(
        json.contains("\"bfdd\":{\"peer\":[{\"address\":\"192.0.2.9\",\"multihop\":false,\"transmit-interval\":300,\"receive-interval\":300,\"echo-interval\":300,\"detect-multiplier\":3,\"echo\":false,\"passive\":false,\"demand\":false,\"version-negotiation\":false}]}"),
        "{json}"
    );
    // The JSON round-trips through the yang crate's own decoder.
    let value = yang::json::parse(&json).expect("valid JSON");
    assert!(value.get("savd").is_some());
}

#[test]
fn no_router_id_renders_null_in_the_dump() {
    let tree = canonical("daemon savd {\nmode strict\n}\n");
    let bound = yangmode::bind(&tree).unwrap();
    assert!(yangmode::dump_json(&bound).starts_with("{\"router-id\":null"));
}
