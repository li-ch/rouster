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
/// SIGHUP to touch a marker — the observable reload.
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
                 trap \"touch '{marker}'\" HUP\n\
                 while :; do sleep 0.2; done\n",
                pidfile = root.join("run/savd.pid").display(),
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
