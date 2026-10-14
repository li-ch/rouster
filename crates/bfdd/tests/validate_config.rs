//! `bfdd --validate-config` (S8-c M1): the pre-apply gate's daemon
//! half, exercised against the REAL binary. The arm exits before any
//! socket/session setup, so it is host-runnable anywhere (macOS
//! included) — which is exactly what configd's `validate`/apply gate
//! depends on. (Flag only: bfdd's transports are S8-c's fence.)

use std::path::PathBuf;
use std::process::Command;

fn scratch(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "bfdd-validate-{tag}-{}-{}",
        std::process::id(),
        line!()
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn run(args: &[&str]) -> (Option<i32>, String) {
    let output = Command::new(env!("CARGO_BIN_EXE_bfdd"))
        .args(args)
        .output()
        .expect("spawn bfdd");
    (
        output.status.code(),
        String::from_utf8_lossy(&output.stderr).into_owned(),
    )
}

#[test]
fn a_valid_config_exits_zero_with_the_peer_count() {
    let dir = scratch("ok");
    let file = dir.join("bfdd.conf");
    std::fs::write(
        &file,
        "peer 192.0.2.9\n  transmit-interval 300\npeer 198.51.100.9 multihop\n",
    )
    .unwrap();
    let (code, stderr) = run(&["--validate-config", file.to_str().unwrap()]);
    assert_eq!(code, Some(0), "stderr: {stderr}");
    // One OK line (the daemon's tracing startup line may precede it).
    let ok_lines: Vec<_> = stderr.lines().filter(|l| l.contains(": OK (")).collect();
    assert_eq!(ok_lines.len(), 1, "stderr: {stderr}");
    assert!(stderr.contains("2 peers"), "stderr: {stderr}");
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn a_duplicate_peer_exits_one_with_the_line_numbered_error_verbatim() {
    let dir = scratch("dup");
    let file = dir.join("bfdd.conf");
    // Line 3 carries the error: RFC 5882 §2's one-session-per-DP
    // invariant, enforced at parse time.
    std::fs::write(
        &file,
        "peer 192.0.2.9\n  transmit-interval 300\npeer 192.0.2.9\n",
    )
    .unwrap();
    let (code, stderr) = run(&["--validate-config", file.to_str().unwrap()]);
    assert_eq!(code, Some(1), "stderr: {stderr}");
    assert!(stderr.contains("line 3:"), "stderr: {stderr}");
    assert!(stderr.contains("duplicate peer"), "stderr: {stderr}");
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn a_stanza_line_before_any_peer_exits_one_naming_the_line() {
    let dir = scratch("loose");
    let file = dir.join("bfdd.conf");
    std::fs::write(
        &file,
        "! comment\n  transmit-interval 300\npeer 192.0.2.9\n",
    )
    .unwrap();
    let (code, stderr) = run(&["--validate-config", file.to_str().unwrap()]);
    assert_eq!(code, Some(1), "stderr: {stderr}");
    assert!(stderr.contains("line 2:"), "stderr: {stderr}");
    assert!(
        stderr.contains("expected `peer <ip> [multihop]`"),
        "stderr: {stderr}"
    );
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
