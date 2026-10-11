//! Renderer suite over the fixture corpus — the rousterctl
//! approach copied into vty tests: today's shapes pin the render,
//! future-field shapes prove tolerance, malformed shapes prove the
//! parse never fails.

use std::path::{Path, PathBuf};

use vty::render;

fn scratch(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("vty-render-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn fixture(name: &str) -> String {
    let path = format!("{}/tests/fixtures/{name}", env!("CARGO_MANIFEST_DIR"));
    std::fs::read_to_string(&path).unwrap_or_else(|err| panic!("fixture {name}: {err}"))
}

/// Publishes a fixture into a scratch run dir under its canonical
/// name (daemon inferred from the fixture file name). No pidfile is
/// written: the status header's pid carries the liveness assessment
/// (the run-dir contract).
fn publish(dir: &Path, name: &str, text: &str) {
    let file = if name.starts_with("savd") {
        "savd.status"
    } else {
        "bfdd.status"
    };
    std::fs::write(dir.join(file), text).unwrap();
}

/// A pid that was alive and is now reaped — deterministically dead.
fn dead_pid() -> u32 {
    let mut child = std::process::Command::new("/bin/sleep")
        .arg("30")
        .spawn()
        .expect("spawn sleep");
    let pid = child.id();
    child.kill().expect("kill sleep");
    child.wait().expect("reap sleep");
    pid
}

fn show_sav(dir: &Path, rules_only: bool) -> String {
    render::show_sav(dir, rules_only).join("\n")
}

fn show_bfd(dir: &Path, summary_only: bool) -> String {
    render::show_bfd(dir, summary_only).join("\n")
}

#[test]
fn show_sav_renders_todays_fixture_with_the_rule_table() {
    let dir = scratch("sav-today");
    publish(&dir, "savd-today", &fixture("savd-status-today.status"));
    let text = show_sav(&dir, false);
    assert!(text.contains("savd 0.0.0"));
    assert!(text.contains("mode strict-uRPF"));
    assert!(text.contains("installed 2 rules"));
    assert!(text.contains("IDX"));
    assert!(text.contains("allow"));
    assert!(text.contains("198.51.100.0/24"));
    assert!(text.contains("monitor"));
    let _ = std::fs::remove_dir_all(&dir);
}

/// The per-op `count` lines (GSC §4 "count"): a backend-sourced
/// status renders one line per judged op under the monitor line —
/// the op body verbatim (provenance included), counters re-rendered
/// from what was recognized. `show sav rules` stays table-only.
#[test]
fn show_sav_renders_the_per_op_count_lines() {
    let dir = scratch("sav-counts");
    publish(&dir, "savd-counts", &fixture("savd-status-counts.status"));
    let text = show_sav(&dir, false);
    assert!(text.contains("monitor  source dataplane"));
    assert!(
        text.contains(
            "count  iba permit #2 [198.51.100.0/24] monitor (from fib)  invalid=1  valid=6  unknown=0"
        ),
        "the per-op rows render under the monitor line: {text}"
    );
    assert!(text.contains("count  pbb block 203.0.113.0/24 [6] monitor (from bgp)"));
    let rules_only = show_sav(&dir, true);
    assert!(
        !rules_only.contains("count  "),
        "rules-only stays table-only"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn show_sav_rules_prints_only_the_table() {
    let dir = scratch("sav-rules");
    publish(
        &dir,
        "savd-rules",
        &fixture("savd-status-all-op-kinds.status"),
    );
    let text = show_sav(&dir, true);
    assert!(text.starts_with("IDX"));
    assert!(!text.contains("config mode"));
    // The monitor summary line is excluded (the word `monitor`
    // still appears — it is a rule action in the table).
    assert!(!text.contains("monitor source"));
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn show_sav_renders_every_op_kind() {
    let dir = scratch("sav-kinds");
    publish(
        &dir,
        "savd-kinds",
        &fixture("savd-status-all-op-kinds.status"),
    );
    let text = show_sav(&dir, false);
    for needle in [
        "if#2",
        "[198.51.100.0/24, 203.0.113.0/24]",
        "2001:db8:1::/48",
        "loose",
        "strict",
    ] {
        assert!(text.contains(needle), "missing {needle} in:\n{text}");
    }
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn show_sav_tolerates_the_future_format() {
    let dir = scratch("sav-future");
    publish(
        &dir,
        "savd-future",
        &fixture("savd-status-future-fields.status"),
    );
    let text = show_sav(&dir, false);
    // Recognized fields ride along.
    assert!(text.contains("EFP-uRPF"));
    assert!(text.contains("bindings 1"));
    // The unknown `agent` line is counted, not fatal.
    assert!(text.contains("1 unrecognized line"));
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn show_sav_never_fails_on_the_malformed_fixture() {
    let dir = scratch("sav-malformed");
    publish(
        &dir,
        "savd-malformed",
        &fixture("savd-status-malformed.status"),
    );
    let text = show_sav(&dir, false);
    assert!(!text.contains("% No savd status published"));
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn show_sav_marks_never_evaluated() {
    let dir = scratch("sav-never");
    publish(
        &dir,
        "savd-never",
        &fixture("savd-status-never-evaluated.status"),
    );
    let text = show_sav(&dir, false);
    assert!(text.contains("(never evaluated)"));
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn show_sav_without_a_status_file_complains_honestly() {
    let dir = scratch("sav-missing");
    let text = show_sav(&dir, false);
    assert!(text.starts_with("% No savd status published at "));
    assert!(text.trim_end().ends_with("savd.status"));
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn show_sav_flags_a_dead_header_pid_as_stale_but_still_renders() {
    let dir = scratch("sav-stale");
    let pid = dead_pid();
    let text = fixture("savd-status-today.status").replace("pid 4242", &format!("pid {pid}"));
    publish(&dir, "savd-stale", &text);
    let out = show_sav(&dir, false);
    assert!(out.contains("DEAD (stale run-dir files)"));
    assert!(out.contains("% savd pid"));
    assert!(out.contains("last-known record"));
    // The record still renders.
    assert!(out.contains("198.51.100.0/24"));
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn show_bfd_renders_sessions_and_transitions() {
    let dir = scratch("bfd-today");
    publish(&dir, "bfdd-today", &fixture("bfdd-status-today.status"));
    let text = show_bfd(&dir, false);
    assert!(text.contains("bfdd 0.0.0"));
    assert!(text.contains("peers 3"));
    assert!(text.contains("peer 192.0.2.2 state Up"));
    assert!(text.contains("peer 2001:db8::2 state Down"));
    assert!(text.contains("last-transition Up -> Down"));
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn show_bfd_summary_counts_states() {
    let dir = scratch("bfd-summary");
    publish(&dir, "bfdd-summary", &fixture("bfdd-status-today.status"));
    let text = show_bfd(&dir, true);
    assert!(text.contains("peers 3"));
    assert!(text.contains("Up 2"));
    assert!(text.contains("Down 1"));
    assert!(!text.contains("session peer"));
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn show_bfd_tolerates_the_future_format() {
    let dir = scratch("bfd-future");
    publish(
        &dir,
        "bfdd-future",
        &fixture("bfdd-status-future-fields.status"),
    );
    let text = show_bfd(&dir, false);
    assert!(text.contains("AdminDown"));
    // peers line kept its count despite the added field.
    assert!(text.contains("peers 1"));
    // The unknown `agent` line counted.
    assert!(text.contains("1 unrecognized line"));
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn show_bfd_never_fails_on_the_malformed_fixture() {
    let dir = scratch("bfd-malformed");
    publish(
        &dir,
        "bfdd-malformed",
        &fixture("bfdd-status-malformed.status"),
    );
    let text = show_bfd(&dir, false);
    // The one session with a parseable peer survives with unset
    // numerics rendered as `?`.
    assert!(text.contains("peer 192.0.2.2 state Up"));
    assert!(text.contains("diag ?"));
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn show_bfd_on_never_started_renders_zero_peers() {
    let dir = scratch("bfd-zero");
    publish(
        &dir,
        "bfdd-zero",
        &fixture("bfdd-status-never-started.status"),
    );
    let text = show_bfd(&dir, false);
    assert!(text.contains("peers 0"));
    let text = show_bfd(&dir, true);
    assert!(text.contains("states (none)"));
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn show_bfd_without_a_status_file_complains_honestly() {
    let dir = scratch("bfd-missing");
    let text = show_bfd(&dir, false);
    assert!(text.starts_with("% No bfdd status published at "));
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn show_bfd_flags_a_dead_pid_as_stale() {
    let dir = scratch("bfd-stale");
    let pid = dead_pid();
    let text = fixture("bfdd-status-today.status").replace("pid 4711", &format!("pid {pid}"));
    publish(&dir, "bfdd-stale", &text);
    let out = show_bfd(&dir, false);
    assert!(out.contains("DEAD (stale run-dir files)"));
    assert!(out.contains("% bfdd pid"));
    let _ = std::fs::remove_dir_all(&dir);
}
