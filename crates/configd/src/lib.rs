//! Rouster `configd` — the transactional config manager (Phase 4
//! opener, the K3 direction: the config-manager is the target,
//! file+SIGHUP the interim it orchestrates).
//!
//! One canonical `rouster.conf` superset composes every daemon's
//! config. The pipeline (milestones land in order):
//!
//! 1. **Parse** the canonical file into a section tree with line
//!    numbers ([`tree`]) — structural validation only; semantic
//!    validation stays with each daemon at reload time.
//! 2. **Render** each daemon's file from its section, byte-stable.
//! 3. **Apply** transactionally: atomic temp+rename writes to each
//!    daemon's config path, SIGHUP to every armed daemon in
//!    dependency order (rousterd first, protocols after), a
//!    generation recorded under `<run-dir>/configd/` (current +
//!    previous), and a status file at `<run-dir>/configd.status`.
//!    Rollback v1 is explicit: `configd rollback` re-applies the
//!    previous generation.
//!
//! Canonical grammar owner: `docs/protocols/config.md` (the apply
//! pipeline diagram, the run-dir contract extension, and §Deferred
//! live there).

pub mod tree;

pub use tree::{parse, BodyLine, Canonical, Daemon, ParseError, Section};
