//! The PERF-P2 CPU census, netlink side (feature `cpu-census`,
//! env-gated at runtime by `ROUSTERD_CPU_CENSUS=1`; the PERF-M1
//! mem-census precedent).
//!
//! Method notes:
//! - `nl_build` and `nl_encode_tail` are CPU-bound scopes (message
//!   construction). `nl_request` is WALL: it wraps the rtnetlink
//!   request future (send → kernel → ACK wake), so it contains
//!   kernel-side wait whenever the 512-deep pipeline is not
//!   saturating the socket. Census tables must not sum it as CPU.
//! - The notification counters (`nl_events_rx`, `nl_events_dropped`)
//!   are counts, not times: the receive loop idles in `.await`, so a
//!   wall timer there measures silence, not work.
//! - Without the feature this module compiles to no-op statics and a
//!   zero-sized guard; with it, it stays runtime-inert until armed.

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
        self.count
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
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
    /// `build_message` per programmed route (the encode path).
    NL_BUILD => "nl_build",
    /// The rtnetlink request future (send + ACK wait). WALL, not CPU.
    NL_REQUEST => "nl_request",
    /// Inner netlink messages consumed by the event loop (count only).
    NL_EVENTS_RX => "nl_events_rx",
    /// Of those, the non-kernel-origin echoes the feedback filter
    /// drops (count only) — the install storm's own notifications.
    NL_EVENTS_DROPPED => "nl_events_dropped",
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
            assert_eq!(
                names,
                vec![
                    "nl_build",
                    "nl_request",
                    "nl_events_rx",
                    "nl_events_dropped"
                ]
            );
        } else {
            assert!(rows.is_empty());
        }
    }
}
