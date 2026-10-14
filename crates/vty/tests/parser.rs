//! Session behavior through the pure state machine: abbreviations,
//! ambiguity errors, `?` trees, mode transitions, and the parse-only
//! config mode (the B7 observed grammar subset).

use std::path::PathBuf;

use vty::session::{Outcome, ServerInfo, Session};

fn session() -> Session {
    Session::new(
        "rouster".into(),
        ServerInfo {
            bind: "127.0.0.1".into(),
            port: 2626,
            run_dir: PathBuf::from("/nonexistent-run-dir"),
            canonical: PathBuf::from("/nonexistent-canonical/rouster.conf"),
            etc_dir: PathBuf::from("/nonexistent-etc"),
            started: std::time::Instant::now(),
            pid: 4242,
        },
    )
}

/// Feeds a line, ignoring the outcome (mode-change commands).
fn feed(session: &mut Session, line: &str) {
    let _ = session.handle_line(line);
}

fn lines(session: &mut Session, line: &str) -> Vec<String> {
    match session.handle_line(line) {
        Outcome::Lines(lines) => lines,
        Outcome::Close => panic!("`{line}` unexpectedly closed the session"),
    }
}

fn joined(session: &mut Session, line: &str) -> String {
    lines(session, line).join("\n")
}

#[test]
fn abbreviations_match_their_full_commands() {
    let mut s = session();
    feed(&mut s, "enable");
    assert!(joined(&mut s, "sh ver").contains("vtysh-compatible VTY server"));
    assert!(joined(&mut s, "show ver").contains("Run dir"));
}

#[test]
fn ambiguity_is_an_error_naming_both_candidates() {
    let mut s = session();
    // `e` prefixes `enable` and `exit` in user mode.
    let text = joined(&mut s, "e");
    assert!(
        text.starts_with("% Ambiguous command: e (enable, exit)"),
        "{text}"
    );
}

#[test]
fn unambiguous_prefixes_resolve() {
    let mut s = session();
    feed(&mut s, "en");
    assert_eq!(s.prompt(), "rouster# ");
}

#[test]
fn unknown_commands_use_the_b7_error_shape() {
    let mut s = session();
    feed(&mut s, "enable");
    // B7 §4.1: real FRR 10.2.2 produced exactly this shape for
    // `router static`.
    assert_eq!(
        joined(&mut s, "router static"),
        "% Unknown command: router static"
    );
}

#[test]
fn incomplete_commands_say_so() {
    let mut s = session();
    feed(&mut s, "enable");
    assert_eq!(joined(&mut s, "show"), "% Incomplete command.");
    // `do` is the config-mode escape hatch; there it is incomplete
    // (in exec modes it is simply not a command).
    feed(&mut s, "conf t");
    assert_eq!(joined(&mut s, "do"), "% Incomplete command.");
}

#[test]
fn invalid_params_name_the_expectation() {
    let mut s = session();
    feed(&mut s, "enable");
    feed(&mut s, "conf t");
    assert_eq!(
        joined(&mut s, "ip route 203.0.113.0/33 blackhole"),
        "% Invalid input: 203.0.113.0/33 — expected <A.B.C.D/M>"
    );
}

#[test]
fn help_at_root_lists_the_mode_commands() {
    let mut s = session();
    let text = joined(&mut s, "?");
    assert!(text.contains("enable"));
    assert!(text.contains("exit"));
    assert!(
        !text.contains("configure"),
        "user mode must not list configure"
    );
    feed(&mut s, "enable");
    let text = joined(&mut s, "?");
    assert!(text.contains("configure"));
    assert!(text.contains("disable"));
    // The show targets appear one level down.
    let text = joined(&mut s, "sh ?");
    assert!(text.contains("sav"));
    assert!(text.contains("bfd"));
}

#[test]
fn help_mid_tree_lists_children_alphabetically() {
    let mut s = session();
    feed(&mut s, "enable");
    let text = joined(&mut s, "sh ?");
    let version = text.find("version").expect("version listed");
    let sav = text.find("sav").expect("sav listed");
    assert!(sav < version, "alphabetical: sav before version");
}

#[test]
fn help_after_a_full_command_offers_cr() {
    let mut s = session();
    feed(&mut s, "enable");
    assert!(joined(&mut s, "sh ver ?").contains("<cr>"));
}

#[test]
fn no_space_help_lists_completions() {
    let mut s = session();
    assert!(joined(&mut s, "sh?").starts_with("show"));
}

#[test]
fn param_help_shows_placeholders() {
    let mut s = session();
    feed(&mut s, "enable");
    feed(&mut s, "conf t");
    let text = joined(&mut s, "ip route ?");
    assert!(text.contains("<A.B.C.D/M>"));
}

#[test]
fn mode_transitions_walk_the_full_stack() {
    let mut s = session();
    assert_eq!(s.prompt(), "rouster> ");
    feed(&mut s, "enable");
    assert_eq!(s.prompt(), "rouster# ");
    feed(&mut s, "conf t");
    assert_eq!(s.prompt(), "rouster(config)# ");
    feed(&mut s, "router bgp 65000");
    assert_eq!(s.prompt(), "rouster(config-router)# ");
    feed(&mut s, "address-family ipv4 unicast");
    assert_eq!(s.prompt(), "rouster(config-router-af)# ");
    feed(&mut s, "end");
    assert_eq!(s.prompt(), "rouster# ");
}

#[test]
fn exit_pops_one_mode_and_closes_at_the_bottom() {
    let mut s = session();
    feed(&mut s, "enable");
    feed(&mut s, "conf t");
    feed(&mut s, "router bgp 65000");
    feed(&mut s, "exit");
    assert_eq!(s.prompt(), "rouster(config)# ");
    feed(&mut s, "exit");
    assert_eq!(s.prompt(), "rouster# ");
    feed(&mut s, "exit");
    assert_eq!(s.prompt(), "rouster> ");
    assert_eq!(s.handle_line("exit"), Outcome::Close);
}

#[test]
fn exit_address_family_and_exit_both_leave_the_af_node() {
    let mut s = session();
    feed(&mut s, "enable");
    feed(&mut s, "conf t");
    feed(&mut s, "router bgp 65000");
    feed(&mut s, "address-family ipv4 unicast");
    feed(&mut s, "exit-address-family");
    assert_eq!(s.prompt(), "rouster(config-router)# ");
    feed(&mut s, "address-family ipv4 unicast");
    feed(&mut s, "exit");
    assert_eq!(s.prompt(), "rouster(config-router)# ");
}

#[test]
fn configure_terminal_is_enable_only() {
    let mut s = session();
    assert_eq!(joined(&mut s, "conf t"), "% Unknown command: conf t");
}

#[test]
fn disable_drops_to_user_mode() {
    let mut s = session();
    feed(&mut s, "enable");
    feed(&mut s, "dis");
    assert_eq!(s.prompt(), "rouster> ");
}

#[test]
fn do_runs_exec_commands_from_config_mode() {
    let mut s = session();
    feed(&mut s, "enable");
    feed(&mut s, "conf t");
    assert!(joined(&mut s, "do sh ver").contains("vtysh-compatible"));
}

#[test]
fn list_shows_the_mode_commands() {
    let mut s = session();
    let text = joined(&mut s, "list");
    assert!(text.contains("show version"));
    assert!(!text.contains("show sav"));
    feed(&mut s, "enable");
    assert!(joined(&mut s, "list").contains("show sav"));
}

#[test]
fn hostname_changes_the_prompt_and_the_config() {
    let mut s = session();
    feed(&mut s, "enable");
    feed(&mut s, "conf t");
    feed(&mut s, "hostname edge-9");
    assert_eq!(s.prompt(), "edge-9(config)# ");
    feed(&mut s, "end");
    let text = joined(&mut s, "show running-config");
    assert!(text.contains("hostname edge-9"));
    // A second hostname replaces, not accumulates.
    feed(&mut s, "conf t");
    feed(&mut s, "hostname edge-10");
    feed(&mut s, "end");
    let text = joined(&mut s, "show running-config");
    assert!(text.contains("hostname edge-10"));
    assert!(!text.contains("hostname edge-9"));
}

#[test]
fn static_routes_round_trip_through_no_forms() {
    let mut s = session();
    feed(&mut s, "enable");
    feed(&mut s, "conf t");
    feed(&mut s, "ip route 203.0.113.0/24 blackhole");
    feed(&mut s, "ip route 198.51.100.0/24 192.0.2.1");
    feed(&mut s, "ipv6 route 2001:db8::/32 blackhole");
    feed(&mut s, "end");
    let text = joined(&mut s, "show running-config");
    assert!(text.contains("ip route 203.0.113.0/24 blackhole"));
    assert!(text.contains("ip route 198.51.100.0/24 192.0.2.1"));
    assert!(text.contains("ipv6 route 2001:db8::/32 blackhole"));
    // Negate the gateway route only; the others survive.
    feed(&mut s, "conf t");
    feed(&mut s, "no ip route 198.51.100.0/24 192.0.2.1");
    feed(&mut s, "end");
    let text = joined(&mut s, "show running-config");
    assert!(!text.contains("198.51.100.0/24"));
    assert!(text.contains("203.0.113.0/24"));
}

#[test]
fn router_bgp_lines_project_into_the_canonical_bgpd_section() {
    let mut s = session();
    feed(&mut s, "enable");
    feed(&mut s, "conf t");
    feed(&mut s, "frr version 10.2");
    feed(&mut s, "frr defaults traditional");
    feed(&mut s, "router bgp 65000");
    feed(&mut s, "no bgp network import-check");
    feed(&mut s, "bgp router-id 192.0.2.254");
    feed(&mut s, "neighbor 192.0.2.2 remote-as 65000");
    feed(&mut s, "address-family ipv4 unicast");
    feed(&mut s, "network 203.0.113.0/24");
    feed(&mut s, "redistribute static");
    feed(&mut s, "exit-address-family");
    feed(&mut s, "exit");
    assert_eq!(s.prompt(), "rouster(config)# ");
    feed(&mut s, "line vty");
    feed(&mut s, "route-map RM-IN permit 10");
    feed(&mut s, "end");
    let text = joined(&mut s, "show running-config");
    for needle in [
        "! vtyd: frr version 10.2",
        "! vtyd: frr defaults traditional",
        "! vtyd: line vty",
        "daemon bgpd {",
        "route-map RM-IN permit 10",
        "router bgp 65000",
        // The two lines bgpd's grammar does not accept ride as
        // comments (S8-c: preserved for display, poisonous to
        // nothing); the rest is bgpd.conf's flat stanza shape.
        "! no bgp network import-check",
        "bgp router-id 192.0.2.254",
        "neighbor 192.0.2.2 remote-as 65000",
        "network 203.0.113.0/24",
        "! redistribute static",
    ] {
        assert!(text.contains(needle), "missing {needle:?} in:\n{text}");
    }
    assert!(text.ends_with('}'), "section closed:\n{text}");
    // And nothing leaked into a rousterd section (no statics).
    assert!(!text.contains("daemon rousterd"));
}

#[test]
fn write_hands_the_merged_canonical_to_the_backend() {
    // A recording backend: the configd contract in test form.
    struct Recorder {
        written: std::sync::Mutex<Vec<String>>,
    }
    impl vty::writer::WriteBackend for Recorder {
        fn write(&self, canonical: &str) -> Vec<String> {
            self.written.lock().unwrap().push(canonical.to_string());
            vec!["configd: generation 9 recorded".into()]
        }
    }
    let mut s = session();
    s.writer = Some(std::sync::Arc::new(Recorder {
        written: std::sync::Mutex::new(Vec::new()),
    }));
    feed(&mut s, "enable");
    feed(&mut s, "conf t");
    feed(&mut s, "ip route 203.0.113.0/24 blackhole");
    feed(&mut s, "end");
    let text = joined(&mut s, "write memory");
    // The naming disclosure, then the backend's report verbatim.
    assert!(text.contains("write memory = write file here"));
    assert!(text.contains("configd: generation 9 recorded"));
}

#[test]
fn an_unwired_write_says_so_honestly() {
    let mut s = session();
    feed(&mut s, "enable");
    let text = joined(&mut s, "wr");
    assert!(text.contains("% Write path not wired"));
    // And `write file` parses to the same action everywhere.
    feed(&mut s, "conf t");
    assert!(joined(&mut s, "write file").contains("% Write path not wired"));
}

#[test]
fn empty_line_and_whitespace_are_quiet() {
    let mut s = session();
    assert_eq!(lines(&mut s, ""), Vec::<String>::new());
    assert_eq!(lines(&mut s, "   "), Vec::<String>::new());
}

#[test]
fn quit_closes_like_exit() {
    let mut s = session();
    assert_eq!(s.handle_line("quit"), Outcome::Close);
}

#[test]
fn user_mode_show_sav_is_unknown() {
    let mut s = session();
    assert_eq!(joined(&mut s, "show sav"), "% Unknown command: show sav");
}

#[test]
fn enable_is_idempotent_from_enable_mode() {
    let mut s = session();
    feed(&mut s, "enable");
    feed(&mut s, "enable");
    assert_eq!(s.prompt(), "rouster# ");
    feed(&mut s, "exit");
    assert_eq!(s.prompt(), "rouster> ");
}

// ------------------------------------------------ the rousterd views

// ------------------------------------------------ the rousterd views

/// A scratch run dir with a rousterd dump fixture published as
/// `rousterd.status`.
fn rib_dir(tag: &str, fixture: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("vty-parser-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let source = format!("{}/tests/fixtures/{fixture}", env!("CARGO_MANIFEST_DIR"));
    std::fs::copy(source, dir.join("rousterd.status")).unwrap();
    dir
}

/// An enabled session reading the given run dir.
fn enabled_session(run_dir: PathBuf) -> Session {
    let mut s = session();
    s.info.run_dir = run_dir;
    feed(&mut s, "enable");
    s
}

#[test]
fn show_interface_parses_and_renders_the_dump() {
    let mut s = enabled_session(rib_dir("rd-iface", "rousterd-status-full.status"));
    let text = joined(&mut s, "show interface");
    assert!(text.contains("Interface"), "the Cisco-style header");
    assert!(text.contains("eth0"));
    assert!(text.contains("192.0.2.1/24"));
    assert!(text.contains("vrf-blue"));
    assert!(text.contains("router-id 198.51.100.1"));
}

#[test]
fn show_ip_interface_is_the_frr_named_view() {
    let mut s = enabled_session(rib_dir("rd-frr-name", "rousterd-status-full.status"));
    let text = joined(&mut s, "show ip interface");
    assert!(text.contains("eth0"), "same data under the FRR name");
    // The abbreviated forms work like every other command.
    assert_eq!(joined(&mut s, "sh ip int"), text);
}

#[test]
fn show_interface_name_filter_selects_and_misses() {
    let mut s = enabled_session(rib_dir("rd-iface-name", "rousterd-status-full.status"));
    let text = joined(&mut s, "show interface eth1");
    assert!(text.contains("eth1"));
    assert!(!text.contains("eth0"), "the filter selects");
    let miss = joined(&mut s, "show interface eth9");
    assert!(
        miss.contains("% Unknown interface: eth9"),
        "the Cisco error shape"
    );
}

#[test]
fn show_neighbor_renders_and_filters_either_family() {
    let mut s = enabled_session(rib_dir("rd-neigh", "rousterd-status-full.status"));
    let text = joined(&mut s, "show neighbor");
    assert!(text.contains("Neighbor"));
    assert!(text.contains("02:00:00:00:00:11"));
    let filtered = joined(&mut s, "show neighbor 192.0.2.0/24");
    assert!(filtered.contains("192.0.2.10"));
    assert!(!filtered.contains("198.51.100.9"));
    let v6 = joined(&mut s, "show neighbor 2001:db8::/32");
    assert!(v6.contains("No neighbor matches"), "the honest empty");
    let miss = joined(&mut s, "show neighbor wat");
    assert!(
        miss.contains("% Invalid input"),
        "the param kind rejects a bad token"
    );
}

#[test]
fn show_vrf_and_route_summary_render() {
    let mut s = enabled_session(rib_dir("rd-vrf", "rousterd-status-full.status"));
    let vrf = joined(&mut s, "show vrf");
    assert!(vrf.contains("vrf-blue"));
    assert!(vrf.contains("1001"), "the bound table renders");
    let summary = joined(&mut s, "show ip route summary");
    assert!(summary.contains("table"));
    assert!(summary.contains("vrf-blue"), "the VRF association renders");
    assert!(summary.contains("connected"));
    // The rousterctl-parity name works too.
    assert_eq!(joined(&mut s, "show rib summary"), summary);
    // Abbreviated, FRR-style.
    assert_eq!(joined(&mut s, "sh ip ro su"), summary);
}

#[test]
fn the_rousterd_views_complain_honestly_without_a_dump() {
    let dir = std::env::temp_dir().join(format!("vty-parser-rd-none-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let mut s = enabled_session(dir.clone());
    for command in [
        "show interface",
        "show ip interface",
        "show neighbor",
        "show vrf",
        "show ip route summary",
        "show rib summary",
    ] {
        let text = joined(&mut s, command);
        assert!(
            text.contains("% No rousterd status published"),
            "{command} complains about the missing dump"
        );
    }
    let _ = std::fs::remove_dir_all(dir);
}

#[test]
fn future_dump_fields_are_tolerated() {
    let mut s = enabled_session(rib_dir("rd-future", "rousterd-status-future-fields.status"));
    let text = joined(&mut s, "show interface");
    assert!(text.contains("eth0"));
    assert!(
        text.contains("1 unrecognized line"),
        "the disclosure renders"
    );
}

#[test]
fn user_mode_cannot_run_the_rousterd_views() {
    let mut s = session();
    s.info.run_dir = rib_dir("rd-user", "rousterd-status-full.status");
    let text = joined(&mut s, "show interface");
    assert!(text.contains("% Unknown command"), "enable-mode commands");
}
