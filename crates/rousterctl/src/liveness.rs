//! Pid liveness without dependencies.
//!
//! Linux: `/proc/<pid>` existence — no signal rights needed. macOS and
//! the other Unixes: `/bin/kill -0 <pid>` (`kill(1)`, not the
//! syscall — std has no signal binding). `kill -0` succeeding means
//! alive; failing with "operation not permitted" also means alive
//! (the process exists but is not ours to signal); anything else is
//! dead. A pid we cannot assess at all is [`PidState::Unknown`], never
//! guessed. Caveat disclosed in docs/operator-surfaces.md: none of
//! these checks prove the pid still *is* savd — pid reuse can fool
//! them; v1 accepts that residual.

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

/// Is there a process with this pid?
pub fn pid_state(pid: u32) -> PidState {
    // Pid 0 is never a daemon — and `kill -0 0` would signal the whole
    // process group, so it is fenced off before any probe runs.
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
