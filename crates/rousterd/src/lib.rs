//! rousterd library pieces shared by the `rousterd` and `staticd`
//! binaries and the integration tests.
//!
//! - [`config`]: the Phase 0/1 line-format config parser (one parser, no
//!   forks — `staticd` and rousterd's legacy direct-load both use it).
//! - [`driver`]: the RIB driver — the main loop's ZAPI-command slice,
//!   runnable in-process against any dataplane (the staticd e2e test).
//! - [`logging`]: tracing init with ANSI only on a TTY (files stay
//!   grepable; both daemon binaries call it).
//! - [`staticd`]: the static-route daemon logic (FRR-shape: config → ZAPI
//!   client of rousterd). The canonical static-route path since Z4.

pub mod config;
pub mod driver;
pub mod logging;
pub mod staticd;
