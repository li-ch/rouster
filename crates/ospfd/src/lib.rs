//! Rouster `ospfd` — the OSPF daemon (Phase 3, stream W2-e).
//!
//! Scope v1 (RFC-cited throughout the modules):
//! - LSA codec: RFC 2328 §A.4 (the 20-byte header §A.4.1, router
//!   §A.4.2, network §A.4.3, summary §A.4.4, AS-external §A.4.5) with
//!   the Fletcher LS checksum of §12.1.7 and the signed sequence
//!   number space of §12.1.6.
//! - Link state database: typed store keyed (LS type, LS ID, adv
//!   router) per §12.2, the "which instance is newer" ordering of
//!   §13.1, install semantics of §13.2 and the aging/MaxAge rules of
//!   §14 (Appendix B constants).
//! - SPF: the §16.1 two-stage Dijkstra (stub networks in stage two),
//!   §16.1.1 next-hop calculation and §16.1.1/§16.8 equal-cost
//!   multipath, with a pure clock-injected scheduling wrapper.
//! - Packets and adjacency: the §A.2/A.3 packet codecs (Hello, DD,
//!   LSR, LSU, LSAck), the neighbor state machine of §10.1-10.3, the
//!   adjacency decision of §10.4, DBD master/slave exchange per
//!   §10.6-10.8 and the flooding procedure of §13 as pure,
//!   message-driven, clock-injected state machines.
//!
//! AF-generic design (architecture invariant 3, the Holo pattern):
//! the header, LSDB ordering, SPF skeleton and neighbor FSM are
//! address-family independent; the v2 bodies in `lsa` are the IPv4
//! seam, and every v6 divergence point is documented where it will
//! bite (see `docs/protocols/ospf.md`).
//!
//! The OSPFv3 codec family (`lsa_v3` + `packet_v3`, RFC 5340
//! Appendices A.3/A.4) proves the seam claim: parallel modules
//! sharing `LsaType`/`RouterId`/`LinkStateId`, the Fletcher
//! placement and the packet spines, with no v2 code moved. Codecs
//! only — the v6 runtime (transport, SPF, LSDB placement) is
//! §Deferred.
//!
//! Incremental SPF (§16.5/§16.6) and inter-area/external route
//! calculation (§16.2-§16.4) are §Deferred (anchors in the stream
//! report).

pub mod auth;
pub mod checksum;
pub mod config;
pub mod daemon;
pub mod error;
pub mod exchange;
pub mod iface;
pub mod ifdump;
pub mod lsa;
pub mod lsa_v3;
pub mod lsdb;
pub mod neighbor;
pub mod origination;
pub mod packet;
pub mod packet_v3;
pub mod spf;
pub mod transport;
pub mod wire;
pub mod zedge;

/// Architectural constants (RFC 2328 Appendix B).
///
/// - `LS_REFRESH_TIME` (30 min): max time between distinct
///   originations of an LSA; when a self-originated LSA's age reaches
///   it, a new instance is originated (§12.4's refresh path).
/// - `MIN_LS_INTERVAL` (5 s): min time between own originations.
/// - `MIN_LS_ARRIVAL` (1 s): min time between received instances.
/// - `MAX_AGE` (1 h): flush threshold; MaxAge LSAs are not used in
///   the routing calculation (§14).
/// - `CHECK_AGE` (5 min): periodic checksum re-verification stride.
/// - `MAX_AGE_DIFF` (15 min): age dispersion bound in the §13.1
///   tiebreak.
/// - `LS_INFINITY` (0xffffff): the 24-bit unreachable metric.
pub const LS_REFRESH_TIME: u16 = 1800;
pub const MIN_LS_INTERVAL: u16 = 5;
pub const MIN_LS_ARRIVAL: u16 = 1;
pub const MAX_AGE: u16 = 3600;
pub const CHECK_AGE: u16 = 300;
pub const MAX_AGE_DIFF: u16 = 900;
pub const LS_INFINITY: u32 = 0x00ff_ffff;

/// §12.1.6's sequence number bounds, re-exported for the LSDB.
pub use lsa::{INITIAL_SEQUENCE_NUMBER, MAX_SEQUENCE_NUMBER};
