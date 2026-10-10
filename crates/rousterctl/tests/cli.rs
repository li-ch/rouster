//! Binary behavior: help/version rendering, exit codes, and the
//! run-dir flows end-to-end through the real executable.

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

fn ctl(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_rousterctl"))
        .args(args)
        .output()
        .expect("spawn rousterctl")
}

fn out(output: &Output) -> String {
    String::from_utf8_lossy(&output.stdout).into_owned()
}

fn err(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
}

fn scratch(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("rousterctl-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn fixture(name: &str) -> String {
    let path = format!("{}/tests/fixtures/{name}", env!("CARGO_MANIFEST_DIR"));
    std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("fixture {name}: {e}"))
}

/// A pid that was alive and is now reaped — deterministically dead.
fn dead_pid() -> u32 {
    let mut child = Command::new("/bin/sleep")
        .arg("30")
        .spawn()
        .expect("spawn sleep");
    let pid = child.id();
    child.kill().expect("kill sleep");
    child.wait().expect("reap sleep");
    pid
}

/// Today's fixture with its header pid rewritten, for tests that need
/// a specific live or dead one.
fn status_with_pid(name: &str, pid: u32) -> String {
    fixture(name).replace("pid 4242", &format!("pid {pid}"))
}

fn dir_arg(dir: &Path) -> String {
    dir.to_str().expect("utf-8 temp path").to_string()
}

#[test]
fn help_renders_every_subcommand_and_flag() {
    let output = ctl(&["--help"]);
    assert_eq!(output.status.code(), Some(0));
    let text = out(&output);
    for needle in [
        "show sav",
        "status",
        "--run-dir",
        "--json",
        "--version",
        "/run/rouster",
    ] {
        assert!(text.contains(needle), "help must mention {needle}");
    }
    assert_eq!(ctl(&["-h"]).status.code(), Some(0));
}

#[test]
fn version_prints_the_package_version() {
    let output = ctl(&["--version"]);
    assert_eq!(output.status.code(), Some(0));
    assert_eq!(out(&output).trim(), env!("CARGO_PKG_VERSION"));
    assert_eq!(ctl(&["-V"]).status.code(), Some(0));
}

#[test]
fn bare_invocation_and_usage_errors_exit_2() {
    let cases: [&[&str]; 5] = [&[], &["frobnicate"], &["--wat"], &["show"], &["--run-dir"]];
    for case in cases {
        let output = ctl(case);
        assert_eq!(output.status.code(), Some(2), "{case:?}");
        assert!(!err(&output).is_empty(), "the complaint lands on stderr");
    }
    let complaint = err(&ctl(&["frobnicate"]));
    assert!(
        complaint.contains("frobnicate"),
        "the offending token is named"
    );
    assert!(
        complaint.contains("SUBCOMMANDS"),
        "usage errors print the help"
    );
}

#[test]
fn show_sav_renders_the_published_status() {
    let dir = scratch("show-ok");
    std::fs::write(dir.join("savd.status"), fixture("savd-status-today.status")).unwrap();
    std::fs::write(dir.join("savd.pid"), format!("{}\n", std::process::id())).unwrap();
    let output = ctl(&["--run-dir", &dir_arg(&dir), "show", "sav"]);
    assert_eq!(output.status.code(), Some(0));
    let text = out(&output);
    assert!(text.contains("198.51.100.0/24"), "the rule set renders");
    assert!(text.contains("strict"));
    assert!(text.contains("monitor"));
    assert!(text.contains("installed 2 rules"));
    assert!(text.contains("running"), "the liveness assessment renders");
    let _ = std::fs::remove_dir_all(dir);
}

#[test]
fn show_sav_json_emits_the_machine_form() {
    let dir = scratch("show-json");
    std::fs::write(dir.join("savd.status"), fixture("savd-status-today.status")).unwrap();
    std::fs::write(dir.join("savd.pid"), format!("{}\n", std::process::id())).unwrap();
    let output = ctl(&["--run-dir", &dir_arg(&dir), "show", "sav", "--json"]);
    assert_eq!(output.status.code(), Some(0));
    let text = out(&output).trim().to_string();
    assert!(text.starts_with('{') && text.ends_with('}'));
    assert!(text.contains("\"daemon\":\"savd\""));
    assert!(text.contains("\"pid_state\":\"running\""));
    assert!(text.contains("\"kind\":\"iface-allow\""));
    let _ = std::fs::remove_dir_all(dir);
}

#[test]
fn show_sav_without_a_status_file_exits_3() {
    let dir = scratch("show-missing");
    let output = ctl(&["--run-dir", &dir_arg(&dir), "show", "sav"]);
    assert_eq!(output.status.code(), Some(3));
    assert!(
        err(&output).contains("savd.status"),
        "the missing file is named"
    );
    let _ = std::fs::remove_dir_all(dir);
}

#[test]
fn show_sav_with_a_dead_pidfile_exits_4_and_still_renders() {
    let dir = scratch("show-dead-pidfile");
    std::fs::write(dir.join("savd.status"), fixture("savd-status-today.status")).unwrap();
    std::fs::write(dir.join("savd.pid"), format!("{}\n", dead_pid())).unwrap();
    let output = ctl(&["--run-dir", &dir_arg(&dir), "show", "sav"]);
    assert_eq!(output.status.code(), Some(4));
    assert!(
        out(&output).contains("198.51.100.0/24"),
        "the last-known record still renders"
    );
    assert!(err(&output).to_lowercase().contains("not running"));
    let _ = std::fs::remove_dir_all(dir);
}

#[test]
fn show_sav_with_a_dead_header_pid_and_no_pidfile_exits_4() {
    let dir = scratch("show-dead-header");
    std::fs::write(
        dir.join("savd.status"),
        status_with_pid("savd-status-today.status", dead_pid()),
    )
    .unwrap();
    let output = ctl(&["--run-dir", &dir_arg(&dir), "show", "sav"]);
    assert_eq!(output.status.code(), Some(4));
    let _ = std::fs::remove_dir_all(dir);
}

#[test]
fn show_sav_tolerates_the_future_format() {
    let dir = scratch("show-future");
    std::fs::write(
        dir.join("savd.status"),
        fixture("savd-status-future-fields.status"),
    )
    .unwrap();
    std::fs::write(dir.join("savd.pid"), format!("{}\n", std::process::id())).unwrap();
    let output = ctl(&["--run-dir", &dir_arg(&dir), "show", "sav"]);
    assert_eq!(
        output.status.code(),
        Some(0),
        "unknown lines are not errors"
    );
    assert!(
        out(&output).contains("expires-in 120s"),
        "unknown rule shapes stay visible"
    );
    let _ = std::fs::remove_dir_all(dir);
}

#[test]
fn status_inventories_a_running_savd() {
    let dir = scratch("status-running");
    std::fs::write(dir.join("savd.status"), fixture("savd-status-today.status")).unwrap();
    std::fs::write(dir.join("savd.pid"), format!("{}\n", std::process::id())).unwrap();
    let output = ctl(&["--run-dir", &dir_arg(&dir), "status"]);
    assert_eq!(output.status.code(), Some(0));
    let text = out(&output);
    assert!(text.contains("running"));
    assert!(text.contains("status published"));
    let _ = std::fs::remove_dir_all(dir);
}

#[test]
fn status_notes_a_running_daemon_with_no_status_yet() {
    let dir = scratch("status-no-status");
    std::fs::write(dir.join("savd.pid"), format!("{}\n", std::process::id())).unwrap();
    let output = ctl(&["--run-dir", &dir_arg(&dir), "status"]);
    assert_eq!(output.status.code(), Some(0));
    assert!(
        out(&output).contains("no status published"),
        "running-but-early is not stale"
    );
    let _ = std::fs::remove_dir_all(dir);
}

#[test]
fn status_names_stale_files_and_exits_4() {
    let dir = scratch("status-stale");
    std::fs::write(dir.join("savd.status"), fixture("savd-status-today.status")).unwrap();
    std::fs::write(dir.join("savd.pid"), format!("{}\n", dead_pid())).unwrap();
    let output = ctl(&["--run-dir", &dir_arg(&dir), "status"]);
    assert_eq!(output.status.code(), Some(4));
    assert!(out(&output).to_lowercase().contains("stale"));
    let _ = std::fs::remove_dir_all(dir);
}

#[test]
fn status_on_an_absent_run_dir_exits_0() {
    let dir = scratch("status-absent").join("never-created");
    let output = ctl(&["--run-dir", &dir_arg(&dir), "status"]);
    assert_eq!(
        output.status.code(),
        Some(0),
        "nothing running is a fine answer"
    );
    assert!(out(&output).to_lowercase().contains("not running"));
}

#[test]
fn status_lists_run_dir_sockets() {
    let dir = scratch("status-sock");
    let listener =
        std::os::unix::net::UnixListener::bind(dir.join("zapi.sock")).expect("bind socket");
    let output = ctl(&["--run-dir", &dir_arg(&dir), "status"]);
    assert_eq!(output.status.code(), Some(0));
    assert!(
        out(&output).contains("zapi.sock"),
        "the socket is inventoried"
    );
    drop(listener);
    let _ = std::fs::remove_dir_all(dir);
}
