//! The RESTCONF-shaped northbound edge (S12-a, the owner's gNMI
//! decision C — docs/yang.md §gNMI-transport): an HTTP/1.1 server
//! on the landed YANG tree ops + the RFC 7951 dump. **A deliberate
//! SUBSET of RFC 8040, disclosed** — the operations on datastore
//! subtrees, not the full protocol (the omissions table with their
//! RFC citations lives in docs/yang.md's implementation section).
//!
//! The layers:
//!
//! - [`http`] — the hand-rolled HTTP/1.1 core (M1): bounded request
//!   parsing, status lines, connection-per-request, no chunked, no
//!   keep-alive (each disclosed there);
//! - [`resources`] — the resource map on the tree (M2): the API
//!   path → tree path mapping, subtree GETs in RFC 7951 JSON, and
//!   PUT (replace) / POST+PATCH (merge) / DELETE mutations that all
//!   route through the tree's type checks + validation BEFORE
//!   anything is written — a bad body is a 400 and the tree is
//!   untouched;
//! - [`server`] — the tokio listener (M1/M3): one task per
//!   connection, graceful shutdown, the single-flight mutation lock
//!   (RFC 8040 §3.4.1's edit-collision discipline), and the apply
//!   integration — an accepted mutation rewrites the canonical file
//!   and runs the existing render→signal→verify/auto-rollback
//!   pipeline, so the transactional guarantee is configd's, the
//!   HTTP layer only maps verbs.
//!
//! The two datastores (M3), the two forms the suite actually has:
//!
//! | URL | What it is | Mutations |
//! |---|---|---|
//! | `/restconf/data` | the CANDIDATE — the canonical file's bound trees (what the next apply pushes; RFC 8040 §3.4's datastore resource, mapped onto the file) | yes |
//! | `/restconf/running` | the RUNNING tree — the last CONFIRMED generation's bound trees (what the daemons actually run; a Rouster extension — RFC 8040 has one datastore resource — keyed to RFC 6241 §8.1's running/candidate distinction) | no (405) |
//!
//! Security posture v1, PROMINENT: plain HTTP on loopback by
//! default, **no authentication** — RFC 8040 §2 expects HTTPS+auth;
//! the options (a local unix-socket alternative, TLS via rustls)
//! are an owner dependency decision, §Deferred in docs/yang.md.
//!
//! gNMI stays the documented next step (decision C's own terms):
//! the datastore semantics this edge pins are exactly the ones a
//! gNMI `Get`/`Set` maps onto — the mapping table is in docs/yang.md
//! so nothing is lost when option A is wanted.

pub mod http;
pub mod resources;
pub mod server;

pub use crate::yangmode::{RESTCONF_DEFAULT_BIND, RESTCONF_DEFAULT_PORT};
