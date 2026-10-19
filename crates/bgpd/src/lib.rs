//! Rouster `bgpd` — the BGP daemon (Phase 2 stream P2-b).
//!
//! Scope v1 (RFC-cited throughout the modules):
//! - Wire codec: RFC 4271 §4 messages, RFC 5492/9072 capabilities and
//!   extended OPEN parameters, RFC 4760 MP_REACH/MP_UNREACH for
//!   IPv4/IPv6 unicast, RFC 2918 route refresh, RFC 6793 4-octet AS
//!   numbers (AS_TRANS bridging), RFC 1997 communities, and
//!   unknown-transitive passthrough per RFC 4271 §4.3/§5.
//! - Session FSM: the RFC 4271 §8 six states, event table and timers
//!   as a pure, clock-injected core.
//! - RIB: per-peer Adj-RIB-In, §9.1 best-path selection, accept-all
//!   import/export behind a policy trait seam.
//! - ZAPI client edge: NHT registration for peer addresses + RIB view
//!   pushes (the savd/W8 idioms); best paths export to the zebra.
//!
//! The BGP-signaling SAVNET hook is deliberately absent
//! (`experimental-savnet`, §Deferred — anchor in the stream report).

#![forbid(unsafe_code)]

pub mod attr;
pub mod capability;
#[cfg(feature = "mem-census")]
pub mod census;
pub mod config;
pub mod daemon;
pub mod error;
/// F10 establishment profiling (runtime-gated; see the module doc).
pub mod estprof;
pub mod fsm;
pub mod message;
pub mod peer;
pub mod policy_engine;
pub mod rib;
pub mod rov;
pub mod wire;
pub mod zedge;

/// The reserved two-octet AS number that stands in for non-mappable
/// four-octet AS numbers (RFC 6793: AS_TRANS = 23456).
pub const AS_TRANS: u16 = 23456;
