//! Rouster `vty` — the vtysh-compatible VTY server, v1.
//!
//! An interactive Cisco-style command surface at the management
//! edge (architecture invariant 1: compatibility adapters live at
//! the edge, never in core abstractions). v1 is a plain TCP line
//! protocol — disclosed, not a secret pty; real `vtysh` expects its
//! own pty/unix-socket plumbing, which is §Deferred until a capture
//! pins it. Every answer comes from the run-dir contract
//! (`docs/operator-surfaces.md`): `savd.status`, `savd.pid`,
//! `bfdd.status`, `bfdd.pid`, `rousterd.status` — file reads only,
//! no IPC inventions.
//!
//! Layout: [`tree`] is the table-driven Cisco command parser (word
//! tree, abbreviated unambiguous commands, `?` help, ambiguity
//! errors); [`session`] is the per-connection state machine (mode
//! stack user/enable/configure-family); [`commands`] registers the
//! v1 command table per mode; [`config`] is the session config tree
//! (the quarantine-B7 observed frr.conf grammar subset, typed);
//! [`writer`] is the write path (S8-c M4): the canonical merge —
//! session edits accumulate into the `rouster.conf` shape, `write
//! file`/`write memory` stage it atomically and spawn `configd
//! apply` (the CLI surface, no IPC invention), and `show
//! running-config` renders the merged canonical view;
//! [`savparse`]/[`bfdparse`]/ [`ribparse`]/[`liveness`] read the run
//! dir through the ONE shared reader (`common::rundir`, the N8
//! consolidation — the first two are re-exports, the third is this
//! crate's claim-less projection); [`render`] renders the `show`
//! outputs; [`protocol`] pins the wire framing; [`server`]/
//! [`client`] are the TCP halves; the `vtyd` binary wires config
//! file, flags, and signals.

pub mod bfdparse;
pub mod client;
pub mod commands;
pub mod config;
pub mod liveness;
pub mod protocol;
pub mod render;
pub mod ribparse;
pub mod savparse;
pub mod server;
pub mod session;
pub mod tree;
pub mod writer;

/// The daemon's own version (the crate version).
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
