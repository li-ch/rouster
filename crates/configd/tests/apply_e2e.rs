//! End-to-end apply over a temp run-dir (Phase 4, M4): the full
//! pipeline — canonical file → render → atomic write → pid
//! resolution → SIGHUP — against REAL processes standing in for the
//! daemons, no docker needed.
//!
//! What is real here: the stand-ins are live OS processes owning
//! their own pidfiles (the savd shape) and a status-file header pid
//! (rousterd's live word), so pid resolution, the liveness probe,
//! and the SIGHUP delivery all cross the real kernel boundary — a
//! delivered HUP touches a marker file, which is exactly the
//! observable behavior change a landed daemon's reload would show.
//! What stands in: the daemons themselves. No Rouster daemon binary
//! is host-runnable off Linux (netlink-dp fails construction on
//! non-Linux by design), so the real-daemon proof rides the docker
//! smoke (`scripts/test-configd-smoke.sh`): configd applies a
//! changed savd/bfdd config and the daemons' published status files
//! change. This test pins everything the smoke should not have to.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Duration;

use configd::apply::{apply_file, rollback, ApplyOptions, DaemonOutcome};
use configd::status;
use configd::tree::Daemon;

/// A stand-in daemon: writes its pid like savd (`pidfile`), or
/// publishes a status header like rousterd (`status`), then traps
/// SIGHUP — the observable reload.
///
/// The savd-shaped stand-in is a small honest daemon (S8-c M3): on
/// SIGHUP it re-reads its rendered config file and REPUBLISHES a
/// `savd.status` whose `config` line carries the projection the
/// post-signal verification checks (`poll <N>s interfaces <n>
/// bindings <n>`), exactly like the real savd does. A config
/// containing the marker word `refused-load` is REFUSED: the daemon
/// keeps its running config and republishes THAT (mtime advances,
/// content stays old) — the observable refused reload.
///
/// Process hygiene, deliberately boring: stdio goes to null (a
/// stand-in must never hold the test harness's output pipe open
/// past its own death), and `Drop` kills the loop even on a failed
/// assertion mid-test (a leaked `while :; do sleep` would outlive
/// the harness and wedge any piped consumer).
struct Standin {
    child: std::process::Child,
    marker: PathBuf,
}

impl Standin {
    fn spawn(tag: &str, root: &Path, mode: StandinMode) -> Self {
        let marker = root.join(format!("{tag}.hup"));
        let _ = fs::remove_file(&marker);
        let script = match mode {
            StandinMode::Pidfile => format!(
                "echo $$ > '{pidfile}'\n\
                 CONF='{conf}'\n\
                 STATUS='{status_file}'\n\
                 publish() {{\n\
                 poll=$(grep -E '^poll ' \"$CONF\" 2>/dev/null | head -1 | awk '{{print $2}}')\n\
                 poll=${{poll:-5}}\n\
                 ifc=$(grep -cE '^interface ' \"$CONF\" 2>/dev/null); ifc=${{ifc:-0}}\n\
                 bind=$(grep -cE '^binding ' \"$CONF\" 2>/dev/null); bind=${{bind:-0}}\n\
                 printf 'savd 0.0.0 pid %s\\nconfig mode strict-uRPF action monitor poll %ss interfaces %s bindings %s collision ignore hysteresis 3s backend rp_filter\\n' $$ \"$poll\" \"$ifc\" \"$bind\" > \"$STATUS\"\n\
                 }}\n\
                 onhup() {{\n\
                 if grep -q refused-load \"$CONF\" 2>/dev/null; then\n\
                 sleep 0.3\n\
                 touch \"$STATUS\"\n\
                 else\n\
                 publish\n\
                 fi\n\
                 touch '{marker}'\n\
                 }}\n\
                 trap onhup HUP\n\
                 publish\n\
                 while :; do sleep 0.2; done\n",
                pidfile = root.join("run/savd.pid").display(),
                conf = root.join("etc/savd.conf").display(),
                status_file = root.join("run/savd.status").display(),
                marker = marker.display(),
            ),
            StandinMode::StatusHeader => format!(
                "printf 'rousterd 0.0.0 pid %s\\n' $$ > '{status}'\n\
                 trap \"touch '{marker}'\" HUP\n\
                 while :; do sleep 0.2; done\n",
                status = root.join("run/rousterd.status").display(),
                marker = marker.display(),
            ),
        };
        let child = Command::new("sh")
            .arg("-c")
            .arg(script)
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
            .expect("spawn stand-in daemon");
        Self { child, marker }
    }

    /// Waits for the marker (the HUP's observable effect).
    fn hup_landed(&self) -> bool {
        for _ in 0..50 {
            if self.marker.exists() {
                return true;
            }
            std::thread::sleep(Duration::from_millis(100));
        }
        false
    }

    /// Waits for the savd-shaped stand-in's status to carry the
    /// given poll cadence (the post-reload word).
    fn wait_status(&self, run_dir: &Path, poll_secs: &str) -> bool {
        let wanted = format!("poll {poll_secs}s ");
        for _ in 0..50 {
            if let Ok(text) = fs::read_to_string(run_dir.join("savd.status")) {
                if text.contains(&wanted) {
                    return true;
                }
            }
            std::thread::sleep(Duration::from_millis(100));
        }
        false
    }
}

impl Drop for Standin {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

enum StandinMode {
    Pidfile,
    StatusHeader,
}

struct Temp {
    root: PathBuf,
}

impl Temp {
    fn new(tag: &str) -> Self {
        let root = std::env::temp_dir().join(format!(
            "configd-e2e-{tag}-{}-{}",
            std::process::id(),
            tag.replace('-', "_")
        ));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(root.join("run")).unwrap();
        fs::create_dir_all(root.join("etc")).unwrap();
        Self { root }
    }

    fn opts(&self) -> ApplyOptions {
        ApplyOptions {
            run_dir: self.root.join("run"),
            etc_dir: self.root.join("etc"),
        }
    }
}

impl Drop for Temp {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}

fn canonical(poll: u32) -> String {
    format!(
        "router-id 198.51.100.1\n\
         daemon rousterd {{\n\
         zapi socket /run/rouster/zserv.api\n\
         }}\n\
         daemon savd {{\n\
         mode strict\n\
         poll {poll}\n\
         }}\n\
         daemon bfdd {{\n\
         peer 192.0.2.9\n\
         }}\n"
    )
}

fn write(path: &Path, text: &str) {
    fs::write(path, text).unwrap();
}

fn outcome(report: &configd::ApplyReport, daemon: Daemon) -> &DaemonOutcome {
    report
        .outcomes
        .iter()
        .find(|(d, _)| *d == daemon)
        .map(|(_, o)| o)
        .expect("outcome present")
}

#[test]
fn apply_signals_live_daemons_and_records_the_generation() {
    let temp = Temp::new("full");
    let opts = temp.opts();

    // Two live stand-ins: savd (pidfile) and rousterd (status header).
    let savd = Standin::spawn("savd", &temp.root, StandinMode::Pidfile);
    let rousterd = Standin::spawn("rousterd", &temp.root, StandinMode::StatusHeader);
    // Let the pidfile/status land before the first apply.
    std::thread::sleep(Duration::from_millis(300));
    // bfdd: a dead pid in its pidfile (a SIGKILL aftermath).
    write(&temp.root.join("run/bfdd.pid"), "999999\n");

    let file = temp.root.join("rouster.conf");
    write(&file, &canonical(2));
    let report = apply_file(&file, &opts).expect("apply succeeds");

    // Rendered files, byte-exact.
    assert_eq!(
        fs::read_to_string(temp.root.join("etc/savd.conf")).unwrap(),
        "mode strict\npoll 2\n"
    );
    assert_eq!(
        fs::read_to_string(temp.root.join("etc/rouster.conf")).unwrap(),
        "zapi socket /run/rouster/zserv.api\n"
    );

    // Live daemons were signaled, with the stand-ins' real pids.
    match outcome(&report, Daemon::Savd) {
        DaemonOutcome::Signaled { pid } => assert_eq!(*pid, savd.child.id()),
        other => panic!("savd should be signaled, got {other:?}"),
    }
    match outcome(&report, Daemon::Rousterd) {
        DaemonOutcome::Signaled { pid } => assert_eq!(*pid, rousterd.child.id()),
        other => panic!("rousterd should be signaled, got {other:?}"),
    }
    // The dead bfdd pid is not a failure.
    assert_eq!(outcome(&report, Daemon::Bfdd), &DaemonOutcome::NotRunning);

    // The HUPs actually landed (the markers are the behavior change).
    assert!(savd.hup_landed(), "savd stand-in saw SIGHUP");
    assert!(rousterd.hup_landed(), "rousterd stand-in saw SIGHUP");

    // Status file: the tolerant reader sees the same facts.
    let published = status::read(&opts.run_dir).expect("status published");
    assert_eq!(published.generation, Some(1));
    assert_eq!(published.hash.as_deref(), Some(report.hash.as_str()));
    assert_eq!(published.router_id.as_deref(), Some("198.51.100.1"));
    assert!(published
        .daemons
        .contains(&("savd".to_string(), "signaled".to_string())));
    assert!(published
        .daemons
        .contains(&("bfdd".to_string(), "not-running".to_string())));

    // Second apply with a changed body: new marker round-trip.
    fs::remove_file(&savd.marker).unwrap();
    write(&file, &canonical(3));
    let second = apply_file(&file, &opts).expect("second apply succeeds");
    assert_eq!(second.generation, 2);
    assert!(savd.hup_landed(), "savd stand-in saw the reload SIGHUP");
    assert_eq!(
        fs::read_to_string(temp.root.join("etc/savd.conf")).unwrap(),
        "mode strict\npoll 3\n"
    );

    // Rollback: the previous generation's bytes, as generation 3.
    let rolled = rollback(&opts).expect("rollback succeeds");
    assert_eq!(rolled.generation, 3);
    assert_eq!(
        fs::read_to_string(temp.root.join("etc/savd.conf")).unwrap(),
        "mode strict\npoll 2\n"
    );
    assert!(matches!(
        outcome(&rolled, Daemon::Savd),
        DaemonOutcome::Signaled { .. }
    ));

    drop(savd);
    drop(rousterd);
}

#[test]
fn dead_pidfile_daemon_waits_for_next_start_without_failing_apply() {
    let temp = Temp::new("dead");
    let opts = temp.opts();
    // No pidfiles, no status: nothing is running at all.
    let file = temp.root.join("rouster.conf");
    write(&file, &canonical(9));
    let report = apply_file(&file, &opts).expect("apply succeeds with nothing running");
    for daemon in [Daemon::Rousterd, Daemon::Savd, Daemon::Bfdd] {
        assert_eq!(outcome(&report, daemon), &DaemonOutcome::NotRunning);
    }
    // The files are still in place for the next start.
    assert!(temp.root.join("etc/savd.conf").exists());
    // And a later daemon start (pidfile appears) is signaled on the
    // next apply — the pidfile arriving is enough.
    let savd = Standin::spawn("savd", &temp.root, StandinMode::Pidfile);
    std::thread::sleep(Duration::from_millis(300));
    write(&file, &canonical(10));
    let report = apply_file(&file, &opts).expect("apply succeeds");
    assert!(matches!(
        outcome(&report, Daemon::Savd),
        DaemonOutcome::Signaled { .. }
    ));
    assert!(savd.hup_landed());
    drop(savd);
}

#[test]
fn rejected_canonical_leaves_running_files_untouched() {
    let temp = Temp::new("refuse");
    let opts = temp.opts();
    let file = temp.root.join("rouster.conf");
    write(&file, &canonical(5));
    apply_file(&file, &opts).expect("first apply");
    let good = fs::read_to_string(temp.root.join("etc/savd.conf")).unwrap();

    // A structurally-broken superset is refused, nothing changes.
    write(&file, "daemon savd {\nmode broken-but-pass-through\n");
    let err = apply_file(&file, &opts).unwrap_err();
    assert!(err.to_string().contains("never closed"));
    assert_eq!(
        fs::read_to_string(temp.root.join("etc/savd.conf")).unwrap(),
        good
    );
}

/// The canonical with a poison body line: parses structurally, no
/// daemon binary on this host validates it (skip), but the LIVE
/// daemon refuses the reload — the S8-c M3 machinery must catch it
/// via the status-file disagreement and auto-rollback.
fn canonical_with_poison(poll: u32) -> String {
    format!(
        "daemon savd {{\n\
         mode strict\n\
         poll {poll}\n\
         ! refused-load\n\
         }}\n"
    )
}

#[test]
fn a_refused_reload_auto_rolls_back_to_the_last_confirmed_generation() {
    let temp = Temp::new("autorollback");
    let opts = temp.opts();
    let savd = Standin::spawn("savd", &temp.root, StandinMode::Pidfile);
    std::thread::sleep(Duration::from_millis(300));

    // Generation 1: a clean load the daemon confirms.
    let file = temp.root.join("rouster.conf");
    write(&file, &canonical(2));
    let first = apply_file(&file, &opts).expect("clean first apply");
    assert_eq!(first.generation, 1);
    assert!(savd.wait_status(&opts.run_dir, "2"));

    // Generation 2 attempt: the daemon refuses the reload (keeps
    // poll 2, republishes it) — the apply must fail AND the system
    // must be back on generation 1's content, as a NEW generation.
    write(&file, &canonical_with_poison(3));
    let err = apply_file(&file, &opts).unwrap_err();
    match &err {
        configd::ApplyError::AutoRolledBack {
            daemon,
            to,
            now,
            revert,
            ..
        } => {
            assert_eq!(*daemon, Daemon::Savd);
            assert_eq!(*to, 1, "reverted to the last confirmed generation");
            assert_eq!(*now, 2, "the revert is itself a new generation");
            assert_eq!(revert.generation, 2);
            assert_eq!(
                revert.source,
                configd::RollbackSource::AutoRevert { from: 1 }
            );
        }
        other => panic!("expected AutoRolledBack, got {other:?}"),
    }
    assert!(err.to_string().contains("refused the reload"));

    // The rendered file is back to the confirmed content, and the
    // daemon's own word matches it (the revert was confirmed too).
    assert_eq!(
        fs::read_to_string(temp.root.join("etc/savd.conf")).unwrap(),
        "mode strict\npoll 2\n"
    );
    assert!(savd.wait_status(&opts.run_dir, "2"));

    // The published status describes the revert, and the pointers
    // advanced honestly (current = generation 2, the revert).
    let published = status::read(&opts.run_dir).expect("status published by the revert");
    assert_eq!(published.generation, Some(2));
    assert!(published
        .source
        .as_deref()
        .unwrap_or_default()
        .contains("auto-rollback to generation 1"));
    assert!(published
        .acks
        .contains(&("savd".to_string(), "confirmed".to_string())));
    let store = opts.run_dir.join("configd");
    assert!(fs::read_to_string(store.join("current"))
        .unwrap()
        .starts_with("000002-"));

    // And the operator can still roll back explicitly from here
    // (previous names generation 1) — the store is consistent.
    assert!(rollback(&opts).is_ok());

    drop(savd);
}

#[test]
fn a_first_apply_refusal_without_a_confirmed_generation_is_an_honest_error() {
    let temp = Temp::new("firstrefusal");
    let opts = temp.opts();
    let savd = Standin::spawn("savd", &temp.root, StandinMode::Pidfile);
    std::thread::sleep(Duration::from_millis(300));

    // The FIRST apply is refused: nothing confirmed exists to revert
    // to. The daemon keeps its running config; the on-disk file
    // holds the refused bytes; no status is published.
    let file = temp.root.join("rouster.conf");
    write(&file, &canonical_with_poison(9));
    let err = apply_file(&file, &opts).unwrap_err();
    match &err {
        configd::ApplyError::LoadRefusedNoPrevious { daemon, .. } => {
            assert_eq!(*daemon, Daemon::Savd);
        }
        other => panic!("expected LoadRefusedNoPrevious, got {other:?}"),
    }
    assert!(err.to_string().contains("no confirmed generation"));
    assert!(err.to_string().contains("refused bytes"));
    // The refused bytes are on disk (disclosed), the daemon kept its
    // running word, and no generation/store/status exists at all.
    assert!(fs::read_to_string(temp.root.join("etc/savd.conf"))
        .unwrap()
        .contains("refused-load"));
    assert!(savd.wait_status(&opts.run_dir, "5")); // its startup word (default poll)
    assert!(!opts.run_dir.join("configd").exists());
    assert!(!opts.run_dir.join("configd.status").exists());

    drop(savd);
}
