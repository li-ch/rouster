//! Rouster `configd` — the transactional config manager (Phase 4
//! opener, the K3 direction: the config-manager is the target,
//! file+SIGHUP the interim it orchestrates).
//!
//! One canonical `rouster.conf` superset composes every daemon's
//! config. The pipeline:
//!
//! 1. **Parse** the canonical file into a section tree with line
//!    numbers ([`tree`]) — structural validation only; semantic
//!    validation stays with each daemon at reload time.
//! 2. **Render** each daemon's file from its section, byte-stable
//!    ([`render`]).
//! 3. **Apply** transactionally ([`apply`]): atomic temp+rename
//!    writes to each daemon's config path, SIGHUP to every armed
//!    daemon in dependency order (rousterd first, protocols after),
//!    a generation recorded under `<run-dir>/configd/` (current +
//!    previous), and the status file published at
//!    `<run-dir>/configd.status` ([`status`]). Rollback v1 is
//!    explicit: `rollback` re-applies the previous generation.
//!    Automatic rollback on daemon error is §Deferred (it needs
//!    daemon status-file semantics beyond v1).
//!
//! Canonical grammar owner: `docs/protocols/config.md` (the apply
//! pipeline diagram, the run-dir contract extension, and §Deferred
//! live there).

pub mod apply;
pub mod atomic;
pub mod render;
pub mod signal;
pub mod status;
pub mod tree;
pub mod validate;
pub mod verify;
pub mod yangmode;

pub use apply::{
    apply, apply_file, rollback, ApplyError, ApplyOptions, ApplyReport, DaemonOutcome,
    RollbackSource, KEEP_GENERATIONS,
};
pub use render::{render_all as render_all_sections, render_daemon as render_section_text};
pub use status::{parse_status, read as read_status, ConfigdStatus};
pub use tree::{parse, BodyLine, Canonical, Daemon, ParseError, Section};
pub use validate::{
    refusal_summary, validate_canonical, validate_rendered, SkipReason, Validation,
};
pub use verify::{Ack, Projection, VERIFY_TIMEOUT};
// The YANG render is THE render (invariant 5); the legacy
// section-split renderer stays exported as the byte-identity
// oracle for tests and the `--no-yang` escape.
pub use yangmode::{
    bind, dialect_for, dump_json, render_all, render_daemon, Bound, SectionBind, YangError,
};
