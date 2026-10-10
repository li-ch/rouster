//! Lib-level behavior: fixture-corpus parsing, rendering, the args
//! grammar, and pid liveness.

use std::path::PathBuf;
use std::process::Command as Spawn;

use rousterctl::args::{self, Command};
use rousterctl::liveness::{pid_state, PidState};
use rousterctl::status::{ConfigLine, MonitorLine, RuleLine, SavStatus};

fn fixture(name: &str) -> String {
    let path = format!("{}/tests/fixtures/{name}", env!("CARGO_MANIFEST_DIR"));
    std::fs::read_to_string(&path).unwrap_or_else(|err| panic!("fixture {name}: {err}"))
}

fn parse_fixture(name: &str) -> SavStatus {
    SavStatus::parse(&fixture(name))
}

// ---------------------------------------------------------------- parse

/// Today's exact shape (the A21 renderings savd's own tests pin)
/// parses into every field.
#[test]
fn today_shape_parses_completely() {
    let st = parse_fixture("savd-status-today.status");
    assert_eq!(st.version.as_deref(), Some("0.0.0"));
    assert_eq!(st.pid, Some(4242));
    assert_eq!(
        st.config,
        ConfigLine {
            mode: Some("strict-uRPF".into()),
            action: Some("monitor".into()),
            poll_secs: Some(5),
            interfaces: Some(2),
            bindings: Some(0),
        }
    );
    assert_eq!(st.evaluated, Some(true));
    assert_eq!(st.installed_claim, Some(2));
    assert_eq!(st.rules.len(), 2);
    assert_eq!(
        st.rules[0],
        RuleLine::IfaceAllow {
            ifindex: 2,
            prefixes: vec!["198.51.100.0/24".into()],
            urpf: "strict".into(),
            action: "monitor".into(),
        }
    );
    assert_eq!(
        st.rules[1],
        RuleLine::IfaceAllow {
            ifindex: 3,
            prefixes: vec![],
            urpf: "strict".into(),
            action: "monitor".into(),
        }
    );
    assert_eq!(
        st.monitor,
        MonitorLine {
            source: Some("simulation".into()),
            invalid: Some(0),
            valid: Some(0),
            unknown: Some(0),
        }
    );
    assert_eq!(st.unknown_lines, 0);
}

/// All four op shapes — both polarities, both scales, multi-member
/// sets, drop actions, the dataplane counts source — parse.
#[test]
fn all_four_op_kinds_and_dataplane_counts_parse() {
    let st = parse_fixture("savd-status-all-op-kinds.status");
    assert_eq!(st.pid, Some(63_000));
    assert_eq!(st.config.action.as_deref(), Some("drop"));
    assert_eq!(st.config.poll_secs, Some(30));
    assert_eq!(st.installed_claim, Some(6));
    assert_eq!(st.rules.len(), 6);
    assert_eq!(
        st.rules[0],
        RuleLine::IfaceAllow {
            ifindex: 2,
            prefixes: vec!["198.51.100.0/24".into(), "203.0.113.0/24".into()],
            urpf: "strict".into(),
            action: "drop".into(),
        }
    );
    assert_eq!(
        st.rules[1],
        RuleLine::IfaceBlock {
            ifindex: 7,
            prefixes: vec!["192.0.2.0/26".into()],
            action: "drop".into(),
        }
    );
    assert_eq!(
        st.rules[2],
        RuleLine::PrefixAllow {
            prefix: "2001:db8:1::/48".into(),
            ifindexes: vec![2, 3],
            action: "monitor".into(),
        }
    );
    assert_eq!(
        st.rules[3],
        RuleLine::PrefixBlock {
            prefix: "2001:db8:dead::/64".into(),
            ifindexes: vec![4],
            action: "drop".into(),
        }
    );
    assert_eq!(
        st.rules[4],
        RuleLine::IfaceAllow {
            ifindex: 9,
            prefixes: vec![],
            urpf: "loose".into(),
            action: "monitor".into(),
        }
    );
    assert_eq!(
        st.rules[5],
        RuleLine::PrefixBlock {
            prefix: "192.0.2.128/25".into(),
            ifindexes: vec![7, 9],
            action: "monitor".into(),
        }
    );
    assert_eq!(
        st.monitor,
        MonitorLine {
            source: Some("dataplane".into()),
            invalid: Some(7),
            valid: Some(5),
            unknown: Some(3),
        }
    );
}

/// The never-evaluated pre-first-evaluate shape.
#[test]
fn never_evaluated_shape_parses() {
    let st = parse_fixture("savd-status-never-evaluated.status");
    assert_eq!(st.evaluated, Some(false));
    assert_eq!(st.installed_claim, Some(0));
    assert!(st.rules.is_empty());
    assert_eq!(st.config.mode.as_deref(), Some("loose-uRPF"));
}

/// The tolerance contract: fields the daemon may ADD (uptime, extra
/// config keywords, extra monitor counters) are ignored; a rule shape
/// this version does not know degrades to Raw verbatim; an unknown
/// line kind is counted, not mistaken for a rule.
#[test]
fn future_fields_are_tolerated() {
    let st = parse_fixture("savd-status-future-fields.status");
    assert_eq!(st.version.as_deref(), Some("2.0.0"));
    assert_eq!(
        st.pid,
        Some(51_234),
        "extra header fields don't hide the pid"
    );
    assert_eq!(
        st.config.mode.as_deref(),
        Some("EFP-uRPF"),
        "an unknown mode string is preserved verbatim"
    );
    assert_eq!(st.config.bindings, Some(1));
    assert_eq!(st.installed_claim, Some(1));
    assert_eq!(
        st.rules.len(),
        1,
        "the trailing unknown tokens degrade to Raw"
    );
    assert_eq!(
        st.rules[0],
        RuleLine::Raw("allow if#2 [198.51.100.0/24] strict monitor expires-in 120s".into()),
        "no operator data is lost"
    );
    assert_eq!(st.unknown_lines, 1, "`agent session ...` is not a rule");
    assert_eq!(st.monitor.unknown, Some(3));
    assert_eq!(st.monitor.valid, Some(2));
}

/// Malformed KNOWN lines parse defensively: bad numbers leave their
/// fields unset, bad rule shapes go Raw, nothing panics.
#[test]
fn malformed_known_lines_are_defensive() {
    let st = parse_fixture("savd-status-malformed.status");
    assert_eq!(st.version.as_deref(), Some("x.y"));
    assert_eq!(st.pid, None);
    assert_eq!(st.config.mode.as_deref(), Some("bogus"));
    assert_eq!(st.config.poll_secs, None);
    assert_eq!(st.installed_claim, None);
    assert_eq!(st.rules.len(), 2);
    assert!(matches!(st.rules[0], RuleLine::Raw(_)), "if#NaN goes Raw");
    assert!(
        matches!(st.rules[1], RuleLine::Raw(_)),
        "bare `rule allow` goes Raw"
    );
    assert_eq!(
        st.monitor.invalid, None,
        "invalid=x leaves the counter unset"
    );
    assert_eq!(st.monitor.valid, Some(0), "its sibling still parses");
    assert_eq!(
        st.unknown_lines, 1,
        "`installed rules` (no count) is unrecognized"
    );
}

// --------------------------------------------------------------- render

/// Byte offsets where 2+ spaces begin a new cell (cells never contain
/// double spaces), for the alignment assertions.
fn column_offsets(line: &str) -> Vec<usize> {
    let mut offsets = Vec::new();
    let mut spaces = 0;
    for (idx, byte) in line.bytes().enumerate() {
        if byte == b' ' {
            spaces += 1;
        } else {
            if spaces >= 2 || offsets.is_empty() {
                offsets.push(idx);
            }
            spaces = 0;
        }
    }
    offsets
}

/// The rule table is genuinely aligned: header and every row share
/// their column positions, and every rule has a row.
#[test]
fn terminal_render_aligns_the_rule_table() {
    let st = parse_fixture("savd-status-all-op-kinds.status");
    let text = st.render_terminal(PidState::Running);
    let lines: Vec<&str> = text.lines().collect();
    let header_idx = lines
        .iter()
        .position(|l| l.contains("POLARITY"))
        .expect("a column header row");
    let header = lines[header_idx];
    for word in ["IDX", "POLARITY", "TARGET", "MEMBERS", "URPF", "ACTION"] {
        assert!(header.contains(word), "column {word} present");
    }
    let rows = &lines[header_idx + 1..header_idx + 1 + st.rules.len()];
    assert_eq!(rows.len(), st.rules.len(), "one row per rule");
    for row in rows {
        assert_eq!(
            column_offsets(row),
            column_offsets(header),
            "row `{row}` aligns with the header"
        );
    }
}

/// The render carries the liveness assessment, the config, the
/// installed count, and the monitor counters.
#[test]
fn terminal_render_carries_every_section() {
    let st = parse_fixture("savd-status-all-op-kinds.status");
    let text = st.render_terminal(PidState::Dead);
    assert!(text.contains("savd 0.1.3"));
    assert!(text.contains("pid 63000"));
    assert!(text.contains("dead"), "the assessment renders");
    assert!(text.contains("installed 6 rules"));
    assert!(text.contains("dataplane"));
    assert!(text.contains("invalid=7"));
    assert!(text.contains("action drop"));
}

/// The never-evaluated shape renders without an empty table.
#[test]
fn terminal_render_of_never_evaluated_has_no_table() {
    let st = parse_fixture("savd-status-never-evaluated.status");
    let text = st.render_terminal(PidState::Unknown);
    assert!(text.contains("installed 0 rules (never evaluated)"));
    assert!(!text.contains("POLARITY"), "no empty table");
    assert!(text.contains("unknown"));
}

/// The JSON form is one object with the agreed field names, and
/// escaping keeps hostile raw rules legal JSON.
#[test]
fn json_render_has_the_agreed_shape() {
    let st = parse_fixture("savd-status-today.status");
    let json = st.render_json(PidState::Running);
    assert!(json.starts_with('{') && json.ends_with('}'), "one object");
    assert!(json.contains("\"daemon\":\"savd\""));
    assert!(json.contains("\"version\":\"0.0.0\""));
    assert!(json.contains("\"pid\":4242"));
    assert!(json.contains("\"pid_state\":\"running\""));
    assert!(json.contains("\"kind\":\"iface-allow\""));
    assert!(json.contains("\"ifindex\":2"));
    assert!(json.contains("\"prefixes\":[\"198.51.100.0/24\"]"));
    assert!(json.contains("\"urpf\":\"strict\""));
    assert!(json.contains("\"action\":\"monitor\""));
    assert!(json.contains("\"source\":\"simulation\""));
    assert!(json.contains("\"evaluated\":true"));
    assert!(json.contains("\"installed_rules\":2"));
    assert!(json.contains("\"unknown_lines\":0"));
}

#[test]
fn json_render_escapes_and_nulls() {
    let hostile = SavStatus {
        rules: vec![RuleLine::Raw("weird \"rule\" \\".into())],
        ..SavStatus::default()
    };
    let json = hostile.render_json(PidState::Unknown);
    assert!(json.contains("\\\"rule\\\""), "quotes escaped");
    assert!(json.contains("\\\\"), "backslashes escaped");
    assert!(json.contains("\"pid\":null"), "missing pid is null");

    let malformed = parse_fixture("savd-status-malformed.status");
    let json = malformed.render_json(PidState::Unknown);
    assert!(json.contains("\"pid\":null"));
    assert!(
        json.contains("\"kind\":\"raw\""),
        "Raw rules stay machine-visible"
    );
    assert!(json.contains("\"unknown_lines\":1"));
}

// ----------------------------------------------------------------- args

fn argv(items: &[&str]) -> Vec<String> {
    items.iter().map(|s| (*s).to_string()).collect()
}

#[test]
fn args_parse_the_v1_grammar() {
    let cli = args::parse(&argv(&["show", "sav"])).unwrap();
    assert_eq!(cli.command, Command::ShowSav { json: false });
    assert_eq!(cli.run_dir, PathBuf::from("/run/rouster"), "the default");

    let cli = args::parse(&argv(&["--run-dir", "/tmp/rr", "show", "sav", "--json"])).unwrap();
    assert_eq!(cli.command, Command::ShowSav { json: true });
    assert_eq!(cli.run_dir, PathBuf::from("/tmp/rr"));

    assert_eq!(
        args::parse(&argv(&["status"])).unwrap().command,
        Command::Status
    );
    assert_eq!(
        args::parse(&argv(&["--help"])).unwrap().command,
        Command::Help
    );
    assert_eq!(args::parse(&argv(&["-h"])).unwrap().command, Command::Help);
    assert_eq!(
        args::parse(&argv(&["--version"])).unwrap().command,
        Command::Version
    );
    assert_eq!(
        args::parse(&argv(&["-V"])).unwrap().command,
        Command::Version
    );
}

#[test]
fn args_reject_the_usage_errors() {
    let cases: [&[&str]; 9] = [
        &[],
        &["frobnicate"],
        &["show"],
        &["show", "ip"],
        &["show", "sav", "extra"],
        &["--wat"],
        &["--run-dir"],
        &["--json", "show", "sav"],
        &["status", "--json"],
    ];
    for case in cases {
        assert!(
            args::parse(&argv(case)).is_err(),
            "expected a usage error for {case:?}"
        );
    }
}

#[test]
fn help_text_lists_every_subcommand_and_flag() {
    let help = args::help_text();
    for needle in [
        "show sav",
        "status",
        "--run-dir",
        "--json",
        "--version",
        "--help",
        "/run/rouster",
        "2 usage",
        "3 not found",
        "4 not running",
    ] {
        assert!(help.contains(needle), "help must mention {needle}");
    }
}

// ------------------------------------------------------------- liveness

#[test]
fn liveness_assesses_live_and_dead_pids() {
    assert_eq!(pid_state(std::process::id()), PidState::Running);
    let mut child = Spawn::new("/bin/sleep").arg("30").spawn().unwrap();
    let pid = child.id();
    assert_eq!(pid_state(pid), PidState::Running);
    child.kill().unwrap();
    child.wait().unwrap();
    assert_eq!(pid_state(pid), PidState::Dead);
    assert_eq!(pid_state(0), PidState::Dead, "pid 0 is never a daemon");
}
