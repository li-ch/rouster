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

// ------------------------------------------------------ rousterd dump

use rousterctl::rousterd::RousterdStatus;

fn parse_rousterd(name: &str) -> RousterdStatus {
    RousterdStatus::parse(&fixture(name))
}

/// The full fixture (generated from the writer's real render over a
/// populated mock rib — crates/rousterd status tests pin the same
/// text) parses into every field.
#[test]
fn rousterd_full_fixture_parses_completely() {
    let st = parse_rousterd("rousterd-status-full.status");
    assert_eq!(st.version.as_deref(), Some("0.0.0"));
    assert_eq!(st.pid, Some(4242));
    assert_eq!(st.router_id.as_deref(), Some("198.51.100.1"));
    assert_eq!(st.interfaces_claim, Some(4));
    assert_eq!(st.interfaces.len(), 4);
    let eth0 = &st.interfaces[1];
    assert_eq!(eth0.name.as_deref(), Some("eth0"));
    assert_eq!(eth0.ifindex, Some(2));
    assert_eq!(eth0.up, Some(true));
    assert_eq!(
        eth0.flags.as_deref(),
        Some("UP|BROADCAST|RUNNING|MULTICAST")
    );
    assert_eq!(eth0.vrf.as_deref(), Some("-"));
    assert_eq!(eth0.vrf_table, None);
    assert_eq!(eth0.addresses, vec!["192.0.2.1/24", "2001:db8::1/64"]);
    // The VRF device carries its bound table; the member its master.
    assert_eq!(st.interfaces[2].vrf_table, Some(1001));
    assert_eq!(st.interfaces[3].vrf.as_deref(), Some("vrf-blue"));

    assert_eq!(st.neighbours_claim, Some(2));
    assert_eq!(st.neighbours.len(), 2);
    assert_eq!(
        st.neighbours[0].ip.map(|ip| ip.to_string()).as_deref(),
        Some("192.0.2.10")
    );
    assert_eq!(st.neighbours[0].ifindex, Some(2));
    assert_eq!(st.neighbours[0].state.as_deref(), Some("INCOMPLETE"));
    assert_eq!(st.neighbours[0].lladdr.as_deref(), Some("-"));

    assert_eq!(st.tables_claim, Some(2));
    assert_eq!(st.tables[0].id, Some(254));
    assert_eq!(st.tables[0].routes, Some(1));
    assert_eq!(st.tables[0].prefixes, Some(1));
    assert_eq!(st.tables[0].connected, Some(3));
    assert_eq!(st.tables[0].kernel, Some(1));
    assert_eq!(st.tables[0].vrf.as_deref(), Some("-"));
    assert_eq!(st.tables[1].vrf.as_deref(), Some("vrf-blue"));
    assert_eq!(st.unknown_lines, 0);
}

/// The tolerance contract: added fields ride along, unknown lines are
/// counted, and a `state` word with an unknown bit still parses.
#[test]
fn rousterd_future_fields_are_tolerated() {
    let st = parse_rousterd("rousterd-status-future-fields.status");
    assert_eq!(st.version.as_deref(), Some("2.0.0"));
    assert_eq!(
        st.pid,
        Some(51_234),
        "extra header fields don't hide the pid"
    );
    assert_eq!(
        st.router_id.as_deref(),
        Some("192.0.2.1"),
        "trailing keywords dropped"
    );
    assert_eq!(st.interfaces.len(), 2);
    let eth0 = &st.interfaces[0];
    assert_eq!(eth0.ifindex, Some(2), "mtu/type ride along harmlessly");
    assert_eq!(eth0.vrf_table, None);
    assert_eq!(
        eth0.addresses,
        vec!["192.0.2.1/24 preferred lifetime 2592000s"],
        "the address child is kept verbatim (added fields included)"
    );
    assert_eq!(
        st.neighbours[0].state.as_deref(),
        Some("REACHABLE|CONFIRMED"),
        "unknown state bits stay verbatim"
    );
    assert_eq!(
        st.tables[0].kernel,
        Some(3),
        "trailing `label main` ignored"
    );
    assert_eq!(
        st.unknown_lines, 1,
        "`agent session ...` is not a known line"
    );
}

/// Malformed KNOWN lines parse defensively: bad numbers leave their
/// fields unset, nothing panics.
#[test]
fn rousterd_malformed_lines_are_defensive() {
    let st = parse_rousterd("rousterd-status-malformed.status");
    assert_eq!(st.version.as_deref(), Some("x.y"));
    assert_eq!(st.pid, None);
    assert_eq!(st.router_id, None, "not-an-ip is dropped, not guessed");
    let eth0 = &st.interfaces[0];
    assert_eq!(eth0.name.as_deref(), Some("eth0"));
    assert_eq!(eth0.ifindex, None, "NaN ifindex leaves the field unset");
    assert_eq!(
        eth0.flags, None,
        "a bare `flags` word leaves the field unset"
    );
    assert_eq!(eth0.up, Some(true));
    assert_eq!(
        eth0.addresses,
        vec!["not-a-prefix"],
        "children stay verbatim"
    );
    assert_eq!(st.neighbours.len(), 0, "not-an-ip neighbours are dropped");
    assert_eq!(st.tables.len(), 1, "the id still parses");
    assert_eq!(st.tables[0].routes, None, "`many` leaves the count unset");
    assert_eq!(
        st.unknown_lines, 2,
        "the bare `interface` and `neighbours one` lines count"
    );
}

/// Neighbour filters: bare address, CIDR containment, either family;
/// a family mismatch selects nothing.
#[test]
fn rousterd_neighbour_filters_match_prefix_and_family() {
    let st = parse_rousterd("rousterd-status-full.status");
    let all = st.neighbours_matching(None);
    assert_eq!(all.len(), 2);
    let exact = st.neighbours_matching(Some("192.0.2.10"));
    assert_eq!(exact.len(), 1, "a bare address is a /32");
    let wide = st.neighbours_matching(Some("192.0.2.0/24"));
    assert_eq!(wide.len(), 1);
    let contained = st.neighbours_matching(Some("198.51.100.0/25"));
    assert_eq!(contained.len(), 1, "198.51.100.9 falls inside the /25");
    let miss = st.neighbours_matching(Some("198.51.100.64/26"));
    assert!(miss.is_empty(), ".9 is outside the upper /26");
    let wrong_family = st.neighbours_matching(Some("2001:db8::/32"));
    assert!(wrong_family.is_empty(), "a v6 filter never matches v4 rows");
    assert!(rousterctl::rousterd::valid_filter("2001:db8::1"));
    assert!(rousterctl::rousterd::valid_filter("10.0.0.0/8"));
    assert!(!rousterctl::rousterd::valid_filter("10.0.0.0/33"));
    assert!(!rousterctl::rousterd::valid_filter("wat"));
}

/// Interface name filtering: exact name selects one row, a miss is
/// detectable.
#[test]
fn rousterd_interface_name_filter_selects() {
    let st = parse_rousterd("rousterd-status-full.status");
    assert_eq!(st.interfaces_matching(None).len(), 4);
    let one = st.interfaces_matching(Some("eth1"));
    assert_eq!(one.len(), 1);
    assert_eq!(one[0].vrf.as_deref(), Some("vrf-blue"));
    assert!(st.interfaces_matching(Some("eth9")).is_empty());
    let miss = st.render_interfaces(Some("eth9"));
    assert_eq!(miss, "(no interface named eth9 in the published dump)");
}

/// The VRF view: a VRF device, its member count, and the owning
/// table's counters.
#[test]
fn rousterd_vrf_view_derives_members_and_counts() {
    let st = parse_rousterd("rousterd-status-full.status");
    let vrfs = st.vrfs();
    assert_eq!(vrfs.len(), 1);
    assert_eq!(vrfs[0].name, "vrf-blue");
    assert_eq!(vrfs[0].ifindex, Some(5));
    assert_eq!(vrfs[0].table, 1001);
    assert_eq!(vrfs[0].members, 1, "eth1 is enslaved to vrf-blue");
    assert_eq!(vrfs[0].up, Some(true));
    assert_eq!(vrfs[0].counts.as_ref().and_then(|t| t.kernel), Some(1));
    assert_eq!(vrfs[0].counts.as_ref().and_then(|t| t.routes), Some(0));
}

/// The terminal tables are genuinely aligned (the same byte-offset
/// proof the sav table uses).
#[test]
fn render_aligns_the_rousterd_tables() {
    let st = parse_rousterd("rousterd-status-full.status");
    for (text, header_word) in [
        (st.render_interfaces(None), "IFINDEX"),
        (st.render_neighbours(None), "LLADDR"),
        (st.render_rib_summary(), "PREFIXES"),
    ] {
        let lines: Vec<&str> = text.lines().collect();
        let header_idx = lines
            .iter()
            .position(|l| l.contains(header_word))
            .expect("a column header row");
        let header = lines[header_idx];
        for row in &lines[header_idx + 1..] {
            assert_eq!(
                column_offsets(row),
                column_offsets(header),
                "row `{row}` aligns with the header"
            );
        }
    }
}

/// The JSON forms: one object each, the agreed field names, nulls for
/// unset pieces.
#[test]
fn rousterd_json_renders_have_the_agreed_shape() {
    let st = parse_rousterd("rousterd-status-full.status");
    let json = st.render_interfaces_json(PidState::Running, None);
    assert!(json.starts_with('{') && json.ends_with('}'));
    assert!(json.contains("\"daemon\":\"rousterd\""));
    assert!(json.contains("\"pid\":4242"));
    assert!(json.contains("\"pid_state\":\"running\""));
    assert!(json.contains("\"router_id\":\"198.51.100.1\""));
    assert!(json.contains("\"name\":\"eth0\""));
    assert!(json.contains("\"vrf\":null"), "- renders as null");
    assert!(json.contains("\"addresses\":[\"192.0.2.1/24\",\"2001:db8::1/64\"]"));

    let json = st.render_neighbours_json(PidState::Dead, Some("192.0.2.0/24"));
    assert!(json.contains("\"ip\":\"192.0.2.10\""));
    assert!(json.contains("\"pid_state\":\"dead\""));
    assert!(
        !json.contains("198.51.100.9"),
        "the filter applies to JSON too"
    );

    let json = st.render_vrfs_json(PidState::Unknown);
    assert!(json.contains("\"name\":\"vrf-blue\""));
    assert!(json.contains("\"table\":1001"));
    assert!(json.contains("\"members\":1"));
    assert!(json.contains("\"pid_state\":\"unknown\""));

    let json = st.render_rib_summary_json(PidState::Running);
    assert!(json.contains("\"table\":254"));
    assert!(json.contains("\"connected\":3"));
    assert!(json.contains("\"vrf\":null"), "- renders as null");

    let malformed = parse_rousterd("rousterd-status-malformed.status");
    let json = malformed.render_rib_summary_json(PidState::Unknown);
    assert!(json.contains("\"routes\":null"), "unset counts are null");
    assert!(json.contains("\"pid\":null"));
}

// ------------------------------------------------------- args (v2)

#[test]
fn args_parse_the_v2_grammar() {
    let cli = args::parse(&argv(&["show", "interface"])).unwrap();
    assert_eq!(
        cli.command,
        Command::ShowInterface {
            name: None,
            json: false
        }
    );
    let cli = args::parse(&argv(&["show", "interface", "eth0", "--json"])).unwrap();
    assert_eq!(
        cli.command,
        Command::ShowInterface {
            name: Some("eth0".into()),
            json: true
        }
    );
    let cli = args::parse(&argv(&["show", "neighbour", "192.0.2.0/24", "--json"])).unwrap();
    assert_eq!(
        cli.command,
        Command::ShowNeighbour {
            prefix: Some("192.0.2.0/24".into()),
            json: true
        },
        "the flag may sit after the positional"
    );
    // ...but never before the subcommand (the v1 position rule).
    assert!(args::parse(&argv(&["--json", "show", "neighbour"])).is_err());
    assert_eq!(
        args::parse(&argv(&["show", "vrf"])).unwrap().command,
        Command::ShowVrf { json: false }
    );
    assert_eq!(
        args::parse(&argv(&["show", "rib", "summary", "--json"]))
            .unwrap()
            .command,
        Command::ShowRibSummary { json: true }
    );
}

#[test]
fn args_reject_the_v2_usage_errors() {
    let cases: [&[&str]; 7] = [
        &["show", "ip"],
        &["show", "rib"],
        &["show", "rib", "detail"],
        &["show", "interface", "eth0", "eth1"],
        &["show", "vrf", "extra"],
        &["--json"],
        &["--json", "status"],
    ];
    for case in cases {
        assert!(
            args::parse(&argv(case)).is_err(),
            "expected a usage error for {case:?}"
        );
    }
}

#[test]
fn help_text_lists_the_v2_table() {
    let help = args::help_text();
    for needle in [
        "show sav",
        "show interface",
        "show neighbour",
        "show vrf",
        "show rib summary",
        "rousterd.status",
        "filter that",
    ] {
        assert!(help.contains(needle), "help must mention {needle}");
    }
}
