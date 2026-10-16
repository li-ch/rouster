//! Rouster `isisd` — the IS-IS daemon (Phase 5 opener, stream S10-a).
//!
//! The TLV-native link-state IGP: ISO 10589 (RFC 1142 carries the DP
//! text) + RFC 1195 (Integrated IS-IS), RFC 5301 (dynamic hostname),
//! RFC 5305 (wide metrics — TLVs 22/135), RFC 5303 (the p2p three-way
//! handshake, TLV 240), with FRR 10.2.2 `isisd` as the interop
//! oracle. Built on the ospfd architecture as template:
//!
//! - **Codec** (`wire`, `checksum`, `system`, `tlv`, `pdu`): the
//!   common PDU header, the IIH/LSP/CSNP/PSNP families and the core
//!   TLV set — strict length validation everywhere (the house rule),
//!   unknown TLVs carried opaquely per ISO §9.7's "shall be
//!   ignored".
//! - **LSPDB** (`lspdb`): keyed by LSP id, the ISO §7.3.16
//!   "determining the latest information" ordering lattice,
//!   remaining-lifetime aging with a clock injected, CSNP/PSNP-driven
//!   synchronisation, purge tombstones.
//! - **SPF** (`spf`): the per-level Dijkstra over IS-reachability
//!   TLVs — wide metrics preferred, narrow fallback — with overload
//!   and attached-bit handling; pure and property-tested against a
//!   brute-force oracle (the ospfd recipe).
//! - **Adjacency** (`adjacency`): the IIH state machine —
//!   Down/Initializing/Up with RFC 5303's three-way option, area and
//!   level checks, MTU matching.
//! - **Transport** (`transport`): Ethernet framing + the Linux
//!   AF_PACKET ethertype-0x00FE socket (cfg-gated; EPERM-skipping
//!   tests elsewhere — the ospfd raw-socket pattern).
//! - **Daemon** (`config`, `zedge`, `daemon`): net entity titles,
//!   interface stanzas, the zapi client edge (route type 9 — ISIS),
//!   the run loop.

pub mod adjacency;
pub mod auth;
pub mod checksum;
pub mod config;
pub mod daemon;
pub mod error;
pub mod lan;
pub mod lspdb;
pub mod pdu;
pub mod spf;
pub mod system;
pub mod tlv;
pub mod transport;
pub mod wire;
pub mod zedge;

/// Architectural constants (ISO 10589's protocol constants; the
/// values as deployed and cross-checked against FRR 10.2.2).
///
/// - `MAX_AGE` (1200 s): the LSP remaining lifetime a source sets at
///   origination (ISO §7.3.16.3: "the source … shall set the
///   Remaining Lifetime to MaxAge").
/// - `ZERO_AGE_LIFETIME` (60 s): how long a purged (zero-lifetime)
///   LSP is retained before deletion (ISO §7.3.16.4.c).
/// - `MINIMUM_LSP_TRANSMISSION_INTERVAL` (5 s): the pacing floor for
///   retransmitting the same LSP on a circuit (ISO §7.3.15.6).
/// - `MAX_SEQUENCE_NUMBER` (0xFFFFFFFE): the top of the sequence
///   space before the wrap shutdown (ISO §7.3.16.1's SequenceModulus
///   minus one).
/// - `MAX_LINK_METRIC` (2^24 - 1): a link at the top of the wide
///   metric space is excluded from normal SPF (RFC 5305 §3).
/// - `MAX_PATH_METRIC` (0xFE000000): prefixes/paths at or above this
///   are excluded from normal SPF (RFC 5305 §3/§4).
pub const MAX_AGE: u16 = 1200;
pub const ZERO_AGE_LIFETIME: u16 = 60;
pub const MINIMUM_LSP_TRANSMISSION_INTERVAL: u16 = 5;
pub const MAX_SEQUENCE_NUMBER: u32 = 0xffff_fffe;
pub const MAX_LINK_METRIC: u32 = 0x00ff_ffff;
pub const MAX_PATH_METRIC: u32 = 0xfe00_0000;
