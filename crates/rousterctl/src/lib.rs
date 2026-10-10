//! rousterctl — the Rouster operator CLI (v1).
//!
//! v1 is deliberately daemonless and std-only: every answer it gives
//! comes from files a Rouster daemon already publishes in the run dir
//! (`/run/rouster` by default) — today that is savd's pidfile and
//! status file (the A21 surface). Nothing here invents an IPC
//! protocol; if a future surface needs one, that is an owner decision.
//!
//! Layout: [`args`] parses the command line, [`status`] parses and
//! re-renders `savd.status` (tolerantly — the daemon's format may
//! grow), [`liveness`] answers "is that pid alive", and [`run`] wires
//! them into the operator-facing exit codes.

pub mod args;
pub mod liveness;
pub mod run;
pub mod status;

/// The CLI's own version (the crate version).
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
