//! The PERF-P2 CPU census (feature `cpu-census`, env-gated at runtime
//! by `ROUSTERD_CPU_CENSUS=1`): phase timers over the RIB's hot paths,
//! so the optimization order is evidence, not fashion.
//!
//! Method notes (the receipts depend on these):
//! - Phases are **wall-clock scopes** (`Instant` deltas accumulated in
//!   atomics, read on the daemon's status-publish cadence). During the
//!   CPU-bound ingest sections wall approximates CPU; phases that
//!   contain an `.await` on the dataplane (`rib_batch_await`) also
//!   contain kernel-side wait and are disclosed as wall, not CPU, in
//!   every table built from them.
//! - Nesting: `rib_add_route` runs inside the daemon-side apply phase
//!   (rousterd's `rd_apply`); a census table must not sum the two as
//!   disjoint shares.
//! - Without the feature the module compiles to no-op statics and a
//!   zero-sized guard (clean receipts stay byte-comparable); with the
//!   feature it is still runtime-inert until the env var arms it — one
//!   `OnceLock`-cached branch per scope.

/// One timed phase. With the feature: cumulative nanos plus a call
/// count. Without: the name alone (a ZST-like static).
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
    RIB_ADD_ROUTE => "rib_add_route",
    /// The desired-form/diff computation of the FULL reconcile pass
    /// (the tick/event safety net) — non-await portion only.
    RIB_DIFF_FULL => "rib_diff_full",
    /// The same computation restricted to a command batch's dirty keys
    /// (bench F8's hot path).
    RIB_DIFF_KEYS => "rib_diff_keys",
    /// The awaited install/withdraw batches (route_replace_batch /
    /// route_delete_batch). WALL time: includes waiting on kernel ACKs,
    /// so it overcounts CPU whenever the pipeline is not saturated.
    RIB_BATCH_AWAIT => "rib_batch_await",
}

/// Whether the census is armed (`ROUSTERD_CPU_CENSUS=1` in the
/// daemon's environment). Always false without the feature.
#[cfg(feature = "cpu-census")]
pub fn enabled() -> bool {
    static ON: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    *ON.get_or_init(|| std::env::var("ROUSTERD_CPU_CENSUS").as_deref() == Ok("1"))
}

#[cfg(not(feature = "cpu-census"))]
pub fn enabled() -> bool {
    false
}

/// Times the enclosing scope into `phase` when armed. Without the
/// feature (or unarmed) it is a zero-sized no-op.
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

/// Opens a [`Scope`] for `phase` (the call sites stay unconditional;
/// the clean build compiles them to nothing).
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

// The atomic import lives behind the feature; pull it under the same
// gate as the Drop impl that uses it.
#[cfg(feature = "cpu-census")]
use std::sync::atomic::Ordering;

#[cfg(test)]
mod tests {
    use super::*;

    /// The phases are distinct, in table order, and the snapshot
    /// carries their (static) names — the status-file lines are built
    /// from exactly these.
    #[test]
    fn snapshot_lists_every_phase() {
        let rows = snapshot();
        let names: Vec<&str> = rows.iter().map(|(n, _, _)| *n).collect();
        if cfg!(feature = "cpu-census") {
            assert_eq!(
                names,
                vec![
                    "rib_add_route",
                    "rib_diff_full",
                    "rib_diff_keys",
                    "rib_batch_await",
                ]
            );
        } else {
            assert!(rows.is_empty());
        }
    }
}
