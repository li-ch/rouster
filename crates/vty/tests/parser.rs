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
fn router_bgp_lines_nest_in_the_b7_shape() {
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
        "frr version 10.2",
        "frr defaults traditional",
        "hostname rouster",
        "route-map RM-IN permit 10",
        "router bgp 65000",
        " no bgp network import-check",
        " bgp router-id 192.0.2.254",
        " neighbor 192.0.2.2 remote-as 65000",
        " address-family ipv4 unicast",
        "  network 203.0.113.0/24",
        "  redistribute static",
        " exit-address-family",
        "!\nline vty\nend",
    ] {
        assert!(text.contains(needle), "missing {needle:?} in:\n{text}");
    }
}

#[test]
fn write_discloses_the_deferral_honestly() {
    let mut s = session();
    feed(&mut s, "enable");
    let text = joined(&mut s, "write memory");
    assert!(text.contains("% Configuration apply is deferred"));
    assert!(text.contains("§Deferred"));
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
