//! The pre-apply gate end-to-end (S8-c M2): `apply` runs each
//! section's rendered bytes through the owning daemon's
//! `--validate-config` BEFORE any file is written — pinned here with
//! stand-in daemon binaries and a controlled `ROUSTER_DAEMON_BIN_DIR`
//! (this file is its own test binary/process, so the env var cannot
//! race the lib unit tests; the three tests serialize on one mutex
//! because the env var IS process-global between them).
//!
//! The stand-ins speak exactly the daemon-side contract the S8-c
//! riders landed: `--help` mentions `--validate-config`;
//! `--validate-config <path>` exits 0, or exits 1 with a
//! line-numbered complaint when the rendered bytes carry the marker
//! word `REFUSE-ME`.

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, MutexGuard, OnceLock};

use configd::apply::{apply_file, ApplyOptions};

/// Serializes the tests (the env var is process-global).
fn env_lock() -> MutexGuard<'static, ()> {
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(()))
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

struct Temp {
    root: PathBuf,
}

impl Temp {
    fn new(tag: &str) -> Self {
        let root = std::env::temp_dir().join(format!(
            "configd-gate-{tag}-{}-{}",
            std::process::id(),
            tag.replace('-', "_")
        ));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(root.join("run")).unwrap();
        fs::create_dir_all(root.join("etc")).unwrap();
        fs::create_dir_all(root.join("bin")).unwrap();
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

/// The stand-in daemon binary (the S8-c rider contract in one case
/// arm).
fn standin_daemon(dir: &Path, name: &str) {
    let path = dir.join(name);
    fs::write(
        &path,
        "#!/bin/sh\n\
         case \"$1\" in\n\
         --help) echo 'usage: standin --config <PATH> [--validate-config <PATH>]'; exit 0;;\n\
         --validate-config) shift; if grep -q REFUSE-ME \"$1\"; then \
         echo \"standin: $1: line 1: refused by the standin parser\" >&2; exit 1; fi; \
         echo \"standin: $1: OK\" >&2; exit 0;;\n\
         esac\n\
         exit 2\n",
    )
    .unwrap();
    let mut perms = fs::metadata(&path).unwrap().permissions();
    perms.set_mode(0o755);
    fs::set_permissions(&path, perms).unwrap();
}

fn canonical(savd_body: &str, bfdd_body: &str) -> String {
    format!("daemon savd {{\n{savd_body}}}\ndaemon bfdd {{\n{bfdd_body}}}\n")
}

#[test]
fn a_daemon_refusal_stops_the_apply_before_any_file_is_written() {
    let _env = env_lock();
    let temp = Temp::new("refuse");
    standin_daemon(&temp.root.join("bin"), "savd");
    standin_daemon(&temp.root.join("bin"), "bfdd");
    std::env::set_var("ROUSTER_DAEMON_BIN_DIR", temp.root.join("bin"));

    // A good first apply: files land, generation 1.
    let file = temp.root.join("rouster.conf");
    fs::write(&file, canonical("mode strict\n", "peer 192.0.2.9\n")).unwrap();
    apply_file(&file, &temp.opts()).expect("clean apply passes the gate");

    // Now a canonical whose savd section the daemon parser refuses
    // (the marker word): the apply must fail BEFORE any file is
    // touched — the earlier savd.conf is untouched, no new
    // generation, and the error carries the daemon's line-numbered
    // complaint verbatim.
    let good_savd = fs::read_to_string(temp.root.join("etc/savd.conf")).unwrap();
    fs::write(&file, canonical("mode REFUSE-ME\n", "peer 198.51.100.9\n")).unwrap();
    let err = apply_file(&file, &temp.opts()).expect_err("the gate refuses");
    assert!(
        err.to_string().contains("semantic validation refused"),
        "{err}"
    );
    assert!(err.to_string().contains("line 1:"), "{err}");
    assert!(
        err.to_string().contains("refused by the standin parser"),
        "{err}"
    );
    assert!(err.to_string().contains("savd"), "names the daemon: {err}");
    assert_eq!(
        fs::read_to_string(temp.root.join("etc/savd.conf")).unwrap(),
        good_savd,
        "the refused apply wrote nothing"
    );
    assert!(
        !temp.root.join("etc/bfdd.conf").exists()
            || fs::read_to_string(temp.root.join("etc/bfdd.conf"))
                .unwrap()
                .contains("192.0.2.9"),
        "the bfdd file is also untouched (the gate runs before all writes)"
    );
    let current = fs::read_to_string(temp.root.join("run/configd/current"))
        .unwrap()
        .trim()
        .to_string();
    assert!(
        current.starts_with("000001-"),
        "generation unchanged: {current}"
    );

    std::env::remove_var("ROUSTER_DAEMON_BIN_DIR");
}

#[test]
fn absent_binaries_are_disclosed_skips_and_the_apply_proceeds() {
    let _env = env_lock();
    let temp = Temp::new("skips");
    // An empty bin dir: no daemon binary anywhere configd can see.
    std::env::set_var("ROUSTER_DAEMON_BIN_DIR", temp.root.join("bin"));

    let file = temp.root.join("rouster.conf");
    fs::write(&file, canonical("mode strict\n", "peer 192.0.2.9\n")).unwrap();
    let report = apply_file(&file, &temp.opts()).expect("skips never fail an apply");
    assert_eq!(report.validations.len(), 2);
    for (daemon, verdict) in &report.validations {
        assert_eq!(
            verdict,
            &configd::validate::Validation::Skipped(configd::validate::SkipReason::NoBinary),
            "{daemon:?}"
        );
    }
    // The files still rendered and the generation still recorded.
    assert!(temp.root.join("etc/savd.conf").exists());
    assert_eq!(report.generation, 1);

    std::env::remove_var("ROUSTER_DAEMON_BIN_DIR");
}

#[test]
fn a_flagless_binary_is_a_skip_but_a_flagful_one_still_gates() {
    let _env = env_lock();
    let temp = Temp::new("mixed");
    // savd knows the flag; rousterd predates it.
    standin_daemon(&temp.root.join("bin"), "savd");
    let old = temp.root.join("bin/rousterd");
    fs::write(
        &old,
        "#!/bin/sh\necho 'usage: an older rousterd --config <PATH>'\nexit 0\n",
    )
    .unwrap();
    let mut perms = fs::metadata(&old).unwrap().permissions();
    perms.set_mode(0o755);
    fs::set_permissions(&old, perms).unwrap();
    std::env::set_var("ROUSTER_DAEMON_BIN_DIR", temp.root.join("bin"));

    // The flagless daemon's section is validated structurally only;
    // the flagful one's refusal still fails the apply.
    let file = temp.root.join("rouster.conf");
    fs::write(
        &file,
        format!(
            "daemon rousterd {{\nip route 203.0.113.0/24 blackhole\n}}\n{}",
            canonical("mode REFUSE-ME\n", "")
        ),
    )
    .unwrap();
    let err = apply_file(&file, &temp.opts()).expect_err("savd refuses");
    assert!(
        err.to_string().contains("refused by the standin parser"),
        "{err}"
    );

    // And with savd clean, the same canonical applies — rousterd's
    // skip disclosed in the report.
    fs::write(
        &file,
        format!(
            "daemon rousterd {{\nip route 203.0.113.0/24 blackhole\n}}\n{}",
            canonical("mode strict\n", "")
        ),
    )
    .unwrap();
    let report = apply_file(&file, &temp.opts()).expect("applies with a disclosed skip");
    let rousterd_verdict = report
        .validations
        .iter()
        .find(|(d, _)| *d == configd::tree::Daemon::Rousterd)
        .map(|(_, v)| v.clone())
        .expect("rousterd validated");
    assert_eq!(
        rousterd_verdict,
        configd::validate::Validation::Skipped(configd::validate::SkipReason::NoFlag)
    );

    std::env::remove_var("ROUSTER_DAEMON_BIN_DIR");
}
