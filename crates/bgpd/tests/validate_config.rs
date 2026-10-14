//! `bgpd --validate-config` (the S8-a rider): configd's pre-apply
//! gate daemon half, exercised against the REAL binary. The arm
//! exits before the runtime, sockets, or sessions, so it is
//! host-runnable anywhere — which is exactly what configd's
//! `validate` verb (S8-c) depends on.

use std::path::PathBuf;
use std::process::Command;

fn scratch(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "bgpd-validate-{tag}-{}-{}",
        std::process::id(),
        line!()
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn run(args: &[&str]) -> (Option<i32>, String) {
    let output = Command::new(env!("CARGO_BIN_EXE_bgpd"))
        .args(args)
        .output()
        .expect("spawn bgpd");
    (
        output.status.code(),
        String::from_utf8_lossy(&output.stderr).into_owned(),
    )
}

#[test]
fn a_valid_config_exits_zero_with_the_counts() {
    let dir = scratch("ok");
    let file = dir.join("bgpd.conf");
    std::fs::write(
        &file,
        "router bgp 65000\n\
         bgp router-id 10.0.0.1\n\
         neighbor 192.0.2.9 remote-as 65001\n\
         neighbor 198.51.100.9 remote-as 65002\n\
         network 203.0.113.0/24\n",
    )
    .unwrap();
    let (code, stderr) = run(&["--validate-config", file.to_str().unwrap()]);
    assert_eq!(code, Some(0), "stderr: {stderr}");
    let ok_lines: Vec<_> = stderr.lines().filter(|l| l.contains(": OK (")).collect();
    assert_eq!(ok_lines.len(), 1, "stderr: {stderr}");
    assert!(stderr.contains("local AS 65000"), "stderr: {stderr}");
    assert!(stderr.contains("2 neighbors"), "stderr: {stderr}");
    assert!(stderr.contains("1 networks"), "stderr: {stderr}");
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn a_parse_error_exits_one_with_the_line_numbered_error_verbatim() {
    let dir = scratch("parse");
    let file = dir.join("bgpd.conf");
    // Line 3: router-id is not an IPv4 address.
    std::fs::write(
        &file,
        "router bgp 65000\n\
         bgp router-id 10.0.0.1\n\
         bgp router-id not-an-ip\n",
    )
    .unwrap();
    let (code, stderr) = run(&["--validate-config", file.to_str().unwrap()]);
    assert_eq!(code, Some(1), "stderr: {stderr}");
    assert!(stderr.contains("line 3:"), "stderr: {stderr}");
    assert!(
        stderr.contains("router-id expects an IPv4 address"),
        "stderr: {stderr}"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn a_missing_router_id_with_neighbors_exits_one() {
    let dir = scratch("norid");
    let file = dir.join("bgpd.conf");
    std::fs::write(
        &file,
        "router bgp 65000\n\
         neighbor 192.0.2.9 remote-as 65001\n",
    )
    .unwrap();
    let (code, stderr) = run(&["--validate-config", file.to_str().unwrap()]);
    assert_eq!(code, Some(1), "stderr: {stderr}");
    assert!(
        stderr.contains("`bgp router-id` is required when neighbors are configured"),
        "stderr: {stderr}"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn a_broken_route_map_exits_one_with_its_file_line_number() {
    let dir = scratch("policy");
    let file = dir.join("bgpd.conf");
    // The route-map names a prefix-list that does not exist — a
    // startup refusal (never silent), carrying the stanza's own line.
    std::fs::write(
        &file,
        "router bgp 65000\n\
         bgp router-id 10.0.0.1\n\
         neighbor 192.0.2.9 remote-as 65001\n\
         import INBOUND\n\
         route-map INBOUND permit 10\n\
         match ip address prefix-list MISSING\n",
    )
    .unwrap();
    let (code, stderr) = run(&["--validate-config", file.to_str().unwrap()]);
    assert_eq!(code, Some(1), "stderr: {stderr}");
    // The error carries the route-map stanza's own file line (5 —
    // the `route-map INBOUND permit 10` head) and names the filter.
    assert!(
        stderr.contains("line 5:"),
        "the policy line number rides: {stderr}"
    );
    assert!(
        stderr.contains("MISSING"),
        "the unknown filter is named: {stderr}"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn a_broken_vrp_file_exits_one_with_its_own_line_number() {
    let dir = scratch("vrp");
    let file = dir.join("bgpd.conf");
    let vrp = dir.join("vrps.conf");
    std::fs::write(
        &vrp,
        "# fixtures\nvrp 203.0.113.0/24 max 24 as 65001\nvrp nonsense\n",
    )
    .unwrap();
    std::fs::write(
        &file,
        "router bgp 65000\n\
         bgp router-id 10.0.0.1\n\
         rpki\n\
         vrp-file vrps.conf\n",
    )
    .unwrap();
    // The vrp-file path is resolved relative to the config's
    // directory (the daemon resolves relative to cwd; the test runs
    // the binary with the config's dir as cwd for the same effect).
    let output = Command::new(env!("CARGO_BIN_EXE_bgpd"))
        .arg("--validate-config")
        .arg(file.to_str().unwrap())
        .current_dir(&dir)
        .output()
        .expect("spawn bgpd");
    let stderr = String::from_utf8_lossy(&output.stderr).into_owned();
    assert_eq!(output.status.code(), Some(1), "stderr: {stderr}");
    assert!(
        stderr.contains("line 3:"),
        "the vrp-file's own line: {stderr}"
    );
    assert!(stderr.contains("vrp-file"), "the file is named: {stderr}");
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn an_unreadable_file_exits_one_with_the_read_complaint() {
    let dir = scratch("absent");
    let (code, stderr) = run(&["--validate-config", dir.join("nope.conf").to_str().unwrap()]);
    assert_eq!(code, Some(1), "stderr: {stderr}");
    assert!(stderr.contains("cannot read"), "stderr: {stderr}");
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn a_bad_rpki_cache_address_exits_one() {
    let dir = scratch("cache");
    let file = dir.join("bgpd.conf");
    std::fs::write(
        &file,
        "router bgp 65000\n\
         bgp router-id 10.0.0.1\n\
         rpki\n\
         cache not-an-address 3323\n",
    )
    .unwrap();
    let (code, stderr) = run(&["--validate-config", file.to_str().unwrap()]);
    assert_eq!(code, Some(1), "stderr: {stderr}");
    assert!(
        stderr.contains("rpki cache `not-an-address` is not an address"),
        "stderr: {stderr}"
    );
    let _ = std::fs::remove_dir_all(&dir);
}
