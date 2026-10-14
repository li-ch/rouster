//! `rousterd --validate-config` (S8-c M1): the pre-apply gate's
//! daemon half, exercised against the REAL binary. The arm exits
//! before any dataplane construction, so it is host-runnable
//! anywhere (macOS included) — which is exactly what configd's
//! `validate`/apply gate depends on.

use std::path::PathBuf;
use std::process::Command;

fn scratch(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "rousterd-validate-{tag}-{}-{}",
        std::process::id(),
        line!()
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn run(args: &[&str]) -> (Option<i32>, String) {
    let output = Command::new(env!("CARGO_BIN_EXE_rousterd"))
        .args(args)
        .output()
        .expect("spawn rousterd");
    (
        output.status.code(),
        String::from_utf8_lossy(&output.stderr).into_owned(),
    )
}

#[test]
fn a_valid_config_exits_zero_with_a_one_line_ok_on_stderr() {
    let dir = scratch("ok");
    let file = dir.join("rouster.conf");
    std::fs::write(
        &file,
        "ip route 203.0.113.0/24 blackhole\nip route 198.51.100.0/24 192.0.2.1\n",
    )
    .unwrap();
    let (code, stderr) = run(&["--validate-config", file.to_str().unwrap()]);
    assert_eq!(code, Some(0), "stderr: {stderr}");
    assert_eq!(stderr.lines().count(), 1, "exactly one OK line");
    assert!(stderr.contains("OK"), "stderr: {stderr}");
    assert!(stderr.contains("2 static routes"), "stderr: {stderr}");
    assert!(stderr.contains("zapi socket off"), "stderr: {stderr}");
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn an_invalid_config_exits_one_with_the_line_numbered_error_verbatim() {
    let dir = scratch("bad");
    let file = dir.join("rouster.conf");
    // Line 3 carries the error: an address-family mismatch.
    std::fs::write(
        &file,
        "! comment\nip route 203.0.113.0/24 blackhole\nip route 2001:db8::/32 blackhole\n",
    )
    .unwrap();
    let (code, stderr) = run(&["--validate-config", file.to_str().unwrap()]);
    assert_eq!(code, Some(1), "stderr: {stderr}");
    // The parser's own wording, with its line number, surfaced as-is.
    assert!(stderr.contains("line 3:"), "stderr: {stderr}");
    assert!(
        stderr.contains("address family mismatch"),
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
    // And the flag without a path is a usage complaint, not a panic.
    let (code, stderr) = run(&["--validate-config"]);
    assert_eq!(code, Some(1), "stderr: {stderr}");
    assert!(
        stderr.contains("--validate-config requires a path"),
        "stderr: {stderr}"
    );
}

#[test]
fn the_zapi_socket_line_counts_as_on() {
    let dir = scratch("zapi");
    let file = dir.join("rouster.conf");
    std::fs::write(&file, "zapi socket /run/rouster/zserv.api\n").unwrap();
    let (code, stderr) = run(&["--validate-config", file.to_str().unwrap()]);
    assert_eq!(code, Some(0), "stderr: {stderr}");
    assert!(stderr.contains("zapi socket on"), "stderr: {stderr}");
    let _ = std::fs::remove_dir_all(&dir);
}
