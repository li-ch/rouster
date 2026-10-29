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

/// speaker-opt lever 1 (away/2026-10-27 Q6): `BGPD_QUIET_INGEST=1`
/// sheds the two per-route INFO log surfaces on the bulk-ingest hot
/// path — the per-UPDATE `UPDATE received` line (sampled to one line
/// per [`QUIET_UPDATE_EVERY`] messages, keeping the first line so the
/// harness first-UPDATE/EOR oracle basis is exact) and the per-route
/// `route add/delete -> zebra` export lines — plus the ANSI escapes
/// on what remains. The 2026-10-28 decomposition: a full-feed run
/// writes 556,132 UPDATE lines + 1,126,490 export lines (294.8 MB);
/// decode + sink walls are 1.24 s + 1.56 s of the 4.91 s EOR window,
/// leaving ~2.1 s of un-instrumented middle where the UPDATE line is
/// the dominant known term. Runtime-gated like `BGPD_EST_PROFILE`/
/// `BGPD_MEM_CENSUS` so one binary serves both shapes; default OFF =
/// every line logs exactly as before.
pub fn quiet_ingest() -> bool {
    static QUIET: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    *QUIET.get_or_init(|| env_flag(std::env::var_os("BGPD_QUIET_INGEST").as_deref()))
}

/// speaker-opt lever 2 (away/2026-10-27 Q6): `BGPD_FAST_ELECTION=1`
/// arms the single-candidate fast path in
/// [`LocRib::recompute_prefix`](crate::rib::LocRib::recompute_prefix):
/// with exactly one candidate the §9.1 ladder returns it by
/// construction, so the generic arm's score/alive vectors and
/// unconditional winner clone are skipped, and a re-announcement of
/// the identical path compares (Arc pointer-shortcut `Route::eq`)
/// before any clone — allocation-free unchanged. The 2026-10-28
/// decomposition put the sink (announce + per-prefix recompute) at
/// 1.56 s of the 4.91 s EOR window; the bulk-ingest shape is one
/// peer, one fresh candidate per prefix. Runtime-gated like
/// [`quiet_ingest`]; default OFF = the generic arm everywhere.
pub fn fast_election() -> bool {
    static FAST: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    *FAST.get_or_init(|| env_flag(std::env::var_os("BGPD_FAST_ELECTION").as_deref()))
}

/// ablation lever (ToN revision Part 5 P0): `ROUSTER_ATTR_INTERN=0`
/// disables cross-UPDATE attribute-tuple sharing in
/// [`LocRib`](crate::rib::LocRib): each UPDATE's decoded tuple is
/// allocated once for the routes that UPDATE carries, and equal
/// tuples across UPDATEs no longer collapse to one
/// [`Arc`](std::sync::Arc) — the natural non-interning
/// implementation, exactly the comparison the revision's
/// workload-diversity sweeps need (speaker memory with sharing vs
/// without). Default ON (unset or any value other than `0`):
/// interning as shipped. Semantics are unchanged either way; only
/// the sharing and its sweep machinery differ.
pub fn attr_intern() -> bool {
    static INTERN: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    *INTERN.get_or_init(
        || !matches!(std::env::var_os("ROUSTER_ATTR_INTERN").as_deref(), Some(v) if v == "0"),
    )
}

/// The BGPD_* runtime gates' pure core (unit-tested): set and not `0`
/// (the `BGPD_EST_PROFILE` shape).
fn env_flag(v: Option<&std::ffi::OsStr>) -> bool {
    v.is_some_and(|v| !v.is_empty() && v != "0")
}

/// The quiet-mode per-UPDATE line cadence (speaker-opt lever 1):
/// 65,536 messages → 9 lines on the 556,132-UPDATE full feed.
pub const QUIET_UPDATE_EVERY: u64 = 65_536;

/// Whether the per-UPDATE log line fires for message ordinal `idx`
/// (0-based): always when not quiet; when quiet, message 0 plus every
/// [`QUIET_UPDATE_EVERY`]-th after it (the first-UPDATE timestamp the
/// EOR oracle anchors on stays line-precise).
pub fn update_line_sampled(idx: u64, quiet: bool) -> bool {
    !quiet || idx.is_multiple_of(QUIET_UPDATE_EVERY)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn quiet_ingest_env_parsing() {
        // The BGPD_EST_PROFILE shape: unset/0/empty off, anything
        // else on. OsStr comparisons, so no lossy UTF-8 assumption
        // (shared by quiet_ingest and fast_election).
        assert!(!env_flag(None));
        assert!(!env_flag(Some(std::ffi::OsStr::new("0"))));
        assert!(!env_flag(Some(std::ffi::OsStr::new(""))));
        assert!(env_flag(Some(std::ffi::OsStr::new("1"))));
        assert!(env_flag(Some(std::ffi::OsStr::new("on"))));
    }

    #[test]
    fn quiet_ingest_samples_update_lines_at_64k() {
        // Not quiet: every UPDATE logs (the baseline shape).
        for idx in [0u64, 1, 65_535, 65_536, 556_131] {
            assert!(update_line_sampled(idx, false), "idx {idx}");
        }
        // Quiet: message 0 logs (the oracle's first-UPDATE anchor),
        // then one line per QUIET_UPDATE_EVERY; nothing between.
        assert!(update_line_sampled(0, true));
        assert!(!update_line_sampled(1, true));
        assert!(!update_line_sampled(65_535, true));
        assert!(update_line_sampled(65_536, true));
        assert!(!update_line_sampled(65_537, true));
    }
}
