//! `savd --validate-config` (S8-c M1): the pre-apply gate's daemon
//! half, exercised against the REAL binary. The arm exits before any
//! netlink/ZAPI setup, so it is host-runnable anywhere — which is
//! exactly what configd's `validate`/apply gate depends on.

use std::path::PathBuf;
use std::process::Command;

fn scratch(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "savd-validate-{tag}-{}-{}",
        std::process::id(),
        line!()
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn run(args: &[&str]) -> (Option<i32>, String) {
    let output = Command::new(env!("CARGO_BIN_EXE_savd"))
        .args(args)
        .output()
        .expect("spawn savd");
    (
        output.status.code(),
        String::from_utf8_lossy(&output.stderr).into_owned(),
    )
}

#[test]
fn a_valid_config_exits_zero_with_the_parsed_summary() {
    let dir = scratch("ok");
    let file = dir.join("savd.conf");
    std::fs::write(
        &file,
        "mode strict\npoll 2\ninterface veths1\n  mode strict\nbinding 192.0.2.0/24 interface veths1\n",
    )
    .unwrap();
    let (code, stderr) = run(&["--validate-config", file.to_str().unwrap()]);
    assert_eq!(code, Some(0), "stderr: {stderr}");
    // One OK line (the daemon's tracing startup line may precede it).
    let ok_lines: Vec<_> = stderr.lines().filter(|l| l.contains(": OK (")).collect();
    assert_eq!(ok_lines.len(), 1, "stderr: {stderr}");
    // The SavdConfig Display summary rides the OK line.
    assert!(stderr.contains("poll 2s"), "stderr: {stderr}");
    assert!(stderr.contains("interfaces 1"), "stderr: {stderr}");
    assert!(stderr.contains("bindings 1"), "stderr: {stderr}");
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn a_bad_line_exits_one_with_the_line_numbered_error_verbatim() {
    let dir = scratch("bad");
    let file = dir.join("savd.conf");
    // Line 2 carries the error: an unknown mode token (a lone bad
    // `mode` line, so the duplicate-global check does not fire first).
    std::fs::write(&file, "poll 2\nmode nosuch\n").unwrap();
    let (code, stderr) = run(&["--validate-config", file.to_str().unwrap()]);
    assert_eq!(code, Some(1), "stderr: {stderr}");
    assert!(stderr.contains("line 2:"), "stderr: {stderr}");
    assert!(stderr.contains("bad mode `nosuch`"), "stderr: {stderr}");
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn the_drop_friction_gate_refuses_without_the_ack_line() {
    let dir = scratch("drop");
    let file = dir.join("savd.conf");
    // Parses line-wise, but `action drop` without the friction ack is
    // a refusal — the gate runs inside parse_savd_config, so the
    // validate arm must refuse it too (configd's pre-apply gate
    // depends on exactly this).
    std::fs::write(&file, "mode strict\naction drop\n").unwrap();
    let (code, stderr) = run(&["--validate-config", file.to_str().unwrap()]);
    assert_eq!(code, Some(1), "stderr: {stderr}");
    assert!(
        stderr.contains("i-understand-drop-mode"),
        "the friction complaint: {stderr}"
    );
    // And with the ack, the same config validates.
    std::fs::write(
        &file,
        "mode strict\naction drop\ni-understand-drop-mode yes\n",
    )
    .unwrap();
    let (code, stderr) = run(&["--validate-config", file.to_str().unwrap()]);
    assert_eq!(code, Some(0), "stderr: {stderr}");
    assert!(stderr.contains("action drop"), "stderr: {stderr}");
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn an_unreadable_file_exits_one_with_the_read_complaint() {
    let dir = scratch("absent");
    let (code, stderr) = run(&["--validate-config", dir.join("nope.conf").to_str().unwrap()]);
    assert_eq!(code, Some(1), "stderr: {stderr}");
    assert!(stderr.contains("cannot read"), "stderr: {stderr}");
    // The flag without a path is a usage complaint, not a panic.
    let (code, stderr) = run(&["--validate-config"]);
    assert_eq!(code, Some(1), "stderr: {stderr}");
    assert!(
        stderr.contains("--validate-config requires a path"),
        "stderr: {stderr}"
    );
}
