//! Pid liveness without dependencies — the rousterctl method
//! (`docs/operator-surfaces.md` §2.2), kept in-crate so the two
//! edge adapters stay decoupled; consolidation is a §Deferred
//! candidate, not this crate's call.
//!
//! Linux: `/proc/<pid>` existence — no signal rights needed.
//! macOS and the other Unixes: `/bin/kill -0 <pid>` — success is
//! alive, "operation not permitted" is also alive (EPERM: the
//! process exists, it just is not ours to signal), anything else is
//! dead. A pid we cannot assess is [`PidState::Unknown`], never
//! guessed. Pid 0 is fenced off before any probe (`kill -0 0` would
//! signal the whole process group). Residual caveat, accepted: none
//! of these prove the pid still *is* the daemon — pid reuse can
//! fool them.

/// The assessment of a recorded pid.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PidState {
    /// A process with that pid exists.
    Running,
    /// No process with that pid exists.
    Dead,
    /// Could not assess (the liveness probe itself failed).
    Unknown,
}

impl PidState {
    /// How show commands name the assessment.
    pub fn assessment(self) -> &'static str {
        match self {
            PidState::Running => "running",
            PidState::Dead => "DEAD (stale run-dir files)",
            PidState::Unknown => "liveness unknown",
        }
    }
}

/// Is there a process with this pid?
pub fn pid_state(pid: u32) -> PidState {
    // Pid 0 is never a daemon — and `kill -0 0` would signal the
    // whole process group, so it is fenced off before any probe.
    if pid == 0 {
        return PidState::Dead;
    }
    if cfg!(target_os = "linux") {
        let path = format!("/proc/{pid}");
        return if std::path::Path::new(&path).exists() {
            PidState::Running
        } else {
            PidState::Dead
        };
    }
    match std::process::Command::new("/bin/kill")
        .arg("-0")
        .arg(pid.to_string())
        .output()
    {
        Ok(output) if output.status.success() => PidState::Running,
        Ok(output) => {
            // EPERM: the process exists but is not ours to signal.
            let complaint = String::from_utf8_lossy(&output.stderr).to_lowercase();
            if complaint.contains("operation not permitted") {
                PidState::Running
            } else {
                PidState::Dead
            }
        }
        Err(_) => PidState::Unknown,
    }
}

/// The pid a `<daemon>.pid` file names (first line), if numeric.
pub fn read_pidfile(path: &std::path::Path) -> Option<u32> {
    let text = std::fs::read_to_string(path).ok()?;
    text.lines().next()?.trim().parse().ok()
}
