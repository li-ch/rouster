//! rousterctl — the Rouster operator CLI.
//!
//! Deliberately daemonless and std-only: every answer it gives comes
//! from files a Rouster daemon already publishes in the run dir
//! (`/run/rouster` by default) — savd's pidfile and status file, and
//! rousterd's status dump (the A21 surfaces). Nothing here invents
//! an IPC protocol; if a future surface needs one, that is an owner
//! decision.
//!
//! Layout: [`args`] parses the command line, [`status`] renders
//! `savd.status` while [`rousterd`] renders `rousterd.status` (both
//! parsed by the ONE shared tolerant reader, `common::rundir` — the
//! N8 consolidation; the daemons' formats may grow),
//! [`liveness`] answers "is that pid alive", and [`run`] wires them
//! into the operator-facing exit codes.

pub mod args;
pub mod liveness;
pub mod rousterd;
pub mod run;
pub mod status;

/// The CLI's own version (the crate version).
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
