//! The PERF-P2 CPU census, daemon side (feature `cpu-census`,
//! env-gated at runtime by `ROUSTERD_CPU_CENSUS=1`; the PERF-M1
//! mem-census precedent).
//!
//! `rd_apply` wraps the whole `RibDriver::apply` per ZAPI command —
//! CPU-bound wall (best-path reads, RIB mutation, push fan-out) that
//! CONTAINS the rib crate's `rib_add_route` phase; census tables must
//! not sum the two as disjoint shares. `rd_push` counts session pushes
//! queued (the fan-out lever's numerator). `rd_status_publish` times
//! the status-file write itself so the census's own artifact cost is
//! disclosed, not hidden.
//!
//! The status file carries the union of this table and the rib /
//! netlink-dp tables as additive `cpucensus <crate> <name> ...` lines
//! (the v1 tolerance contract: unknown lines are counted and dropped
//! by every consumer).

/// One timed phase. With the feature: cumulative nanos plus a call
/// count. Without: the name alone.
#[cfg(feature = "cpu-census")]
pub struct Phase {
    pub name: &'static str,
    nanos: std::sync::atomic::AtomicU64,
    count: std::sync::atomic::AtomicU64,
}

#[cfg(not(feature = "cpu-census"))]
pub struct Phase {
    pub name: &'static str,
}

impl Phase {
    #[cfg(feature = "cpu-census")]
    pub const fn new(name: &'static str) -> Self {
        Self {
            name,
            nanos: std::sync::atomic::AtomicU64::new(0),
            count: std::sync::atomic::AtomicU64::new(0),
        }
    }

    #[cfg(not(feature = "cpu-census"))]
    pub const fn new(name: &'static str) -> Self {
        Self { name }
    }

    /// Counts one occurrence (for the count-only rows).
    #[cfg(feature = "cpu-census")]
    pub fn bump(&self) {
        self.count.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    }

    #[cfg(not(feature = "cpu-census"))]
    pub fn bump(&self) {}
}

macro_rules! phases {
    ($($(#[$meta:meta])* $name:ident => $text:literal),+ $(,)?) => {
        $(
            $(#[$meta])*
            pub static $name: Phase = Phase::new($text);
        )+
        /// Every phase this crate times, in table order.
        pub static PHASES: &[&Phase] = &[$(&$name),+];
    };
}

phases! {
    /// `RibDriver::apply` per ZAPI command (wall; CPU-bound body that
    /// contains `rib_add_route`).
    RD_APPLY => "rd_apply",
    /// Session pushes queued through `RibDriver::push` (count only).
    RD_PUSH => "rd_push",
    /// The status-file publish (the census's own artifact cost).
    RD_STATUS_PUBLISH => "rd_status_publish",
}

/// Whether the census is armed (`ROUSTERD_CPU_CENSUS=1`).
#[cfg(feature = "cpu-census")]
pub fn enabled() -> bool {
    static ON: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    *ON.get_or_init(|| std::env::var("ROUSTERD_CPU_CENSUS").as_deref() == Ok("1"))
}

#[cfg(not(feature = "cpu-census"))]
pub fn enabled() -> bool {
    false
}

/// Times the enclosing scope into `phase` when armed.
#[cfg(feature = "cpu-census")]
pub struct Scope(Option<(&'static Phase, std::time::Instant)>);

#[cfg(not(feature = "cpu-census"))]
pub struct Scope;

#[cfg(feature = "cpu-census")]
impl Drop for Scope {
    fn drop(&mut self) {
        if let Some((phase, start)) = self.0 {
            phase
                .nanos
                .fetch_add(start.elapsed().as_nanos() as u64, Ordering::Relaxed);
            phase.count.fetch_add(1, Ordering::Relaxed);
        }
    }
}

#[cfg(feature = "cpu-census")]
use std::sync::atomic::Ordering;

/// Opens a [`Scope`] for `phase`.
#[cfg(feature = "cpu-census")]
pub fn scope(phase: &'static Phase) -> Scope {
    use std::time::Instant;
    Scope(enabled().then(|| (phase, Instant::now())))
}

#[cfg(not(feature = "cpu-census"))]
pub fn scope(_phase: &'static Phase) -> Scope {
    Scope
}

/// The census snapshot: `(name, cumulative nanos, call count)` rows.
pub fn snapshot() -> Vec<(&'static str, u64, u64)> {
    #[cfg(feature = "cpu-census")]
    {
        PHASES
            .iter()
            .map(|p| {
                (
                    p.name,
                    p.nanos.load(std::sync::atomic::Ordering::Relaxed),
                    p.count.load(std::sync::atomic::Ordering::Relaxed),
                )
            })
            .collect()
    }
    #[cfg(not(feature = "cpu-census"))]
    {
        Vec::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn snapshot_lists_every_phase() {
        let rows = snapshot();
        let names: Vec<&str> = rows.iter().map(|(n, _, _)| *n).collect();
        if cfg!(feature = "cpu-census") {
            assert_eq!(names, vec!["rd_apply", "rd_push", "rd_status_publish"]);
        } else {
            assert!(rows.is_empty());
        }
    }
}
