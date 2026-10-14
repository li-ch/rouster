//! `ospfd --validate-config` (S8-b M4): the pre-apply gate's daemon
//! half, exercised against the REAL binary. The arm exits before any
//! socket/runtime setup, so it is host-runnable anywhere (macOS
//! included) — exactly what configd's `validate`/apply gate depends
//! on. Same contract as the siblings' (bfdd/bgpd/savd/rousterd):
//! 0/1 exit, one per-line stderr.

use std::path::PathBuf;
use std::process::Command;

fn scratch(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "ospfd-validate-{tag}-{}-{}",
        std::process::id(),
        line!()
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn run(args: &[&str]) -> (Option<i32>, String) {
    let output = Command::new(env!("CARGO_BIN_EXE_ospfd"))
        .args(args)
        .output()
        .expect("spawn ospfd");
    (
        output.status.code(),
        String::from_utf8_lossy(&output.stderr).into_owned(),
    )
}

#[test]
fn a_valid_config_exits_zero_with_the_counts() {
    let dir = scratch("ok");
    let file = dir.join("ospfd.conf");
    std::fs::write(
        &file,
        concat!(
            "router ospf\n",
            " router-id 10.255.2.1\n",
            " rfc1583-compatibility disabled\n",
            " area 0.0.0.0\n",
            "  interface eth0\n",
            "   authentication key-chain kc1\n",
            "key chain kc1\n",
            " key 1\n",
            "  key-string s\n",
            "  cryptographic-algorithm md5\n",
        ),
    )
    .unwrap();
    let (code, stderr) = run(&["--validate-config", file.to_str().unwrap()]);
    assert_eq!(code, Some(0), "stderr: {stderr}");
    let ok_lines: Vec<_> = stderr.lines().filter(|l| l.contains(": OK (")).collect();
    assert_eq!(ok_lines.len(), 1, "stderr: {stderr}");
    assert!(stderr.contains("1 areas"), "stderr: {stderr}");
    assert!(stderr.contains("1 key chains"), "stderr: {stderr}");
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn a_bad_line_exits_one_naming_the_line() {
    let dir = scratch("bad");
    let file = dir.join("ospfd.conf");
    std::fs::write(
        &file,
        "router ospf\n router-id 10.255.2.1\n area 0.0.0.0\n  interface eth0\n   frob 1\n",
    )
    .unwrap();
    let (code, stderr) = run(&["--validate-config", file.to_str().unwrap()]);
    assert_eq!(code, Some(1), "stderr: {stderr}");
    assert!(stderr.contains("line 5:"), "stderr: {stderr}");
    // The unknown key-chain reference names its line too.
    std::fs::write(
        &file,
        "router ospf\n area 0.0.0.0\n  interface eth0\n   authentication key-chain nosuch\n",
    )
    .unwrap();
    let (code, stderr) = run(&["--validate-config", file.to_str().unwrap()]);
    assert_eq!(code, Some(1), "stderr: {stderr}");
    assert!(stderr.contains("line 4:"), "stderr: {stderr}");
    assert!(stderr.contains("unknown key chain"), "stderr: {stderr}");
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
