//! Pid sources, liveness, and the SIGHUP send (Phase 4, M2 step 3).
//!
//! The actuation surface is exactly the run-dir contract
//! (docs/operator-surfaces.md §2): `savd.pid` and `bfdd.pid` are the
//! pidfiles those daemons write; rousterd has no pidfile, but its
//! `rousterd.status` header pid is its live word (§2.3) — parsed with
//! the ONE shared reader, `common::rundir`. ospfd and bgpd publish
//! neither pid nor status, and more fundamentally have **no SIGHUP
//! arm** (their signal wiring is SIGTERM/SIGINT only), so configd
//! never signals them: a SIGHUP under the default disposition would
//! terminate the daemon. Rendering + writing their files is safe (the
//! next start picks them up); the signal arms are the §Deferred ask
//! recorded in docs/protocols/config.md.
//!
//! Liveness mirrors rousterctl's documented method (§2.2): Linux
//! probes `/proc/<pid>` existence; other Unixes shell out to
//! `kill -0` and read "operation not permitted" as alive (EPERM: the
//! process exists, it just is not ours to signal). Pid 0 is fenced
//! off before any probe (`kill -0 0` would signal the whole group).
//! Sending uses the same shell route (`sh -c 'kill -HUP <pid>'`) —
//! std has no signal-send API and the crate takes no new
//! dependencies (fence); the shell builtin kill is present on every
//! target (busybox sh in the containers, /bin/sh on dev hosts).
//!
//! Residual caveat, inherited from §2.2 and accepted: none of this
//! proves the pid still *is* the daemon — pid reuse can fool it.

use std::path::{Path, PathBuf};

use common::rundir;

/// Where a daemon's pid comes from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PidSource {
    /// A daemon-written pidfile (`<run-dir>/savd.pid`, `<run-dir>/bfdd.pid`).
    Pidfile(PathBuf),
    /// The `rousterd.status` header pid (rousterd's live word — it
    /// writes no pidfile).
    StatusHeader(PathBuf),
    /// The daemon publishes no pid (ospfd, bgpd today).
    None,
}

/// Pid liveness assessment (the §2.2 vocabulary).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Liveness {
    Alive,
    Dead,
    /// The probe itself failed (never guess).
    Unknown,
}

/// Probes whether `pid` is alive (the §2.2 method; pid 0 fenced).
pub fn liveness(pid: u32) -> Liveness {
    if pid == 0 {
        return Liveness::Dead;
    }
    if Path::new(&format!("/proc/{pid}")).exists() {
        return Liveness::Alive;
    }
    // No /proc (or the pid is not there and we double-check the
    // non-proc way): `kill -0`, reading EPERM as alive.
    match run_kill(pid, "0") {
        Ok(()) => Liveness::Alive,
        Err(KillError::NotPermitted) => Liveness::Alive,
        Err(KillError::NoProcess) => Liveness::Dead,
        Err(KillError::Other(_)) => {
            // On Linux with /proc missing the pid, NoProcess should
            // have been the answer; treat anything unclassifiable as
            // unknown rather than guessing.
            Liveness::Unknown
        }
    }
}

/// Why a `kill` shell-out failed.
#[derive(Debug, Clone, PartialEq, Eq)]
enum KillError {
    /// "operation not permitted" — the process exists.
    NotPermitted,
    /// "no such process".
    NoProcess,
    Other(String),
}

fn run_kill(pid: u32, sig: &str) -> Result<(), KillError> {
    let output = std::process::Command::new("sh")
        .arg("-c")
        .arg(format!("kill -{sig} {pid}"))
        .output()
        .map_err(|e| KillError::Other(e.to_string()))?;
    if output.status.success() {
        return Ok(());
    }
    let stderr = String::from_utf8_lossy(&output.stderr).to_lowercase();
    if stderr.contains("not permitted") || stderr.contains("permission denied") {
        Err(KillError::NotPermitted)
    } else if stderr.contains("no such process") || stderr.contains("not found") {
        Err(KillError::NoProcess)
    } else {
        Err(KillError::Other(stderr))
    }
}

/// Reads a pid from a pidfile: trimmed digits, 0 fenced off, anything
/// else is no pid (a malformed pidfile must not abort an apply of the
/// other daemons — the outcome records `bad-pidfile`).
pub fn read_pidfile(path: &Path) -> Option<u32> {
    let text = std::fs::read_to_string(path).ok()?;
    let pid: u32 = text.trim().parse().ok()?;
    (pid != 0).then_some(pid)
}

/// Reads rousterd's pid from its status file's header line (the
/// tolerant shared reader never fails; a missing header pid is no
/// pid).
pub fn read_status_header_pid(path: &Path) -> Option<u32> {
    let text = std::fs::read_to_string(path).ok()?;
    rundir::parse_rousterd(&text).pid
}

/// Resolves a daemon's pid from its source.
pub fn resolve_pid(source: &PidSource) -> Option<u32> {
    match source {
        PidSource::Pidfile(path) => read_pidfile(path),
        PidSource::StatusHeader(path) => read_status_header_pid(path),
        PidSource::None => None,
    }
}

/// Sends SIGHUP to `pid`. The error string carries the shell's
/// complaint for the per-daemon apply outcome.
pub fn send_sighup(pid: u32) -> Result<(), String> {
    if pid == 0 {
        return Err("pid 0 fenced off".to_string());
    }
    match run_kill(pid, "HUP") {
        Ok(()) => Ok(()),
        Err(KillError::NotPermitted) => {
            Err("operation not permitted (process exists, not ours to signal)".to_string())
        }
        Err(KillError::NoProcess) => Err("no such process".to_string()),
        Err(KillError::Other(note)) => Err(note),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pid_zero_is_fenced() {
        assert_eq!(liveness(0), Liveness::Dead);
        assert_eq!(send_sighup(0), Err("pid 0 fenced off".to_string()));
    }

    #[test]
    fn own_process_is_alive() {
        assert_eq!(liveness(std::process::id()), Liveness::Alive);
    }

    #[test]
    fn an_unlikely_pid_is_dead() {
        // Pid 4194304 is beyond the default Linux pid_max and far
        // above macOS's observed range; no /proc entry, kill -0 says
        // no such process.
        assert_eq!(liveness(4_194_304), Liveness::Dead);
    }

    #[test]
    fn sighup_reaches_a_real_process() {
        // A real kernel round-trip: spawn `sleep`, HUP it via the
        // shell route, and observe the default-disposition death.
        let mut child = std::process::Command::new("sleep")
            .arg("30")
            .spawn()
            .expect("spawn sleep");
        let pid = child.id();
        assert_eq!(liveness(pid), Liveness::Alive);
        send_sighup(pid).expect("SIGHUP delivered");
        let status = child.wait().expect("wait for the child");
        assert!(
            !status.success(),
            "SIGHUP under the default disposition terminates sleep"
        );
        #[cfg(unix)]
        {
            use std::os::unix::process::ExitStatusExt;
            // SIGHUP is 1 everywhere POSIX; naming the constant would
            // need libc (fence: no new deps).
            assert_eq!(status.signal(), Some(1));
        }
        assert_eq!(liveness(pid), Liveness::Dead);
    }

    #[test]
    fn pidfile_round_trip_and_garbage() {
        let dir = std::env::temp_dir().join(format!("configd-pid-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let pf = dir.join("savd.pid");
        std::fs::write(&pf, format!("{}\n", std::process::id())).unwrap();
        assert_eq!(read_pidfile(&pf), Some(std::process::id()));
        // Garbage, zero, and empty are all "no pid".
        std::fs::write(&pf, "not-a-pid\n").unwrap();
        assert_eq!(read_pidfile(&pf), None);
        std::fs::write(&pf, "0\n").unwrap();
        assert_eq!(read_pidfile(&pf), None);
        std::fs::write(&pf, "").unwrap();
        assert_eq!(read_pidfile(&pf), None);
        assert_eq!(read_pidfile(&dir.join("absent.pid")), None);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn status_header_pid_via_the_shared_reader() {
        let dir = std::env::temp_dir().join(format!("configd-statuspid-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let sf = dir.join("rousterd.status");
        std::fs::write(&sf, "rousterd 0.0.0 pid 4242\nrouter-id 198.51.100.1\n").unwrap();
        assert_eq!(read_status_header_pid(&sf), Some(4242));
        // Tolerance: added fields and unknown lines ride along.
        std::fs::write(&sf, "rousterd 0.0.0 pid 4243 extra-field\nweird line\n").unwrap();
        assert_eq!(read_status_header_pid(&sf), Some(4243));
        // No header pid → no pid, not a failure.
        std::fs::write(&sf, "interfaces 0\n").unwrap();
        assert_eq!(read_status_header_pid(&sf), None);
        assert_eq!(read_status_header_pid(&dir.join("absent.status")), None);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn resolve_pid_dispatches_by_source() {
        let dir = std::env::temp_dir().join(format!("configd-resolve-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("savd.pid"), "777\n").unwrap();
        std::fs::write(dir.join("rousterd.status"), "rousterd 0.0.0 pid 888\n").unwrap();
        assert_eq!(
            resolve_pid(&PidSource::Pidfile(dir.join("savd.pid"))),
            Some(777)
        );
        assert_eq!(
            resolve_pid(&PidSource::StatusHeader(dir.join("rousterd.status"))),
            Some(888)
        );
        assert_eq!(resolve_pid(&PidSource::None), None);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
