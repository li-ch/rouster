//! F10 establishment profiling (S15-a): per-phase wall timing inside
//! bgpd, runtime-gated by `BGPD_EST_PROFILE=1` so ONE binary serves
//! both the clean receipt runs (gate off: one relaxed atomic load per
//! note site) and the diagnosis runs (gate on).
//!
//! The phases separate the F10 candidate causes by measurement:
//!
//! - `accept_us` — the `listener.accept()` await per loop iteration
//!   (queue wait + syscall). A serialized accept loop shows it growing
//!   with the session ordinal.
//! - `lookup_us` — the neighbor lookup + clone in the accept loop
//!   (the per-peer config recompute candidate).
//! - `spawn_gap_us` — accept-return → the per-connection task's first
//!   instruction (tokio spawn + scheduling; the task-setup candidate's
//!   scheduling half).
//! - `register_us` + `construct_us` — the session-launch construction:
//!   the registry slot, the eviction/stop channels, the session config
//!   resolve, `PeerSession::new` (the task/allocator-setup candidate's
//!   allocation half).
//! - `open_us` / `openproc_us` — task-start → the peer's OPEN
//!   processed, and the OPEN-processing wall itself (decode rides the
//!   frame-drain `decode_us`).
//! - `est_us` — task-start → the Established transition (the
//!   FSM-to-Established wall).
//! - `dump_us` — the initial Adj-RIB-Out dump at Established.
//! - `update_us` / `update_n` / `eor_us` / `decode_us` — the per-session
//!   UPDATE import path: sink announce/withdraw wall (RIB lock wait +
//!   work, inseparable by construction — the sink call is the unit),
//!   message counts, EOR handling, and frame decode.
//!
//! Emission: one `EST-PROF-EST` line at the Established transition and
//! one `EST-PROF-END` line at session end, both to stderr (the bench
//! harness captures bgpd's stderr) in `key=value` form — deliberately
//! NOT through tracing, so the profiler's own cost stays out of the
//! subscriber's formatting path and the lines stay trivially greppable.
//!
//! Scoping: keyed by peer address (one live session per neighbor by
//! the registry's construction; a re-connect overwrites — a bench-shape
//! disclosure, not a production observability surface).

use std::collections::BTreeMap;
use std::net::IpAddr;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Mutex, OnceLock};
use std::time::Instant;

/// Per-session phase accumulators (microseconds; walls, so concurrent
/// sessions' phases overlap — the diagnosis table reads them per
/// session and as demand totals, never as disjoint CPU partitions).
#[derive(Default)]
struct Phases {
    t_start: Option<Instant>,
    accept_us: u64,
    lookup_us: u64,
    spawn_gap_us: u64,
    register_us: u64,
    construct_us: u64,
    open_us: u64,
    openproc_us: u64,
    est_us: u64,
    est_seq: u32,
    dump_us: u64,
    update_us: u64,
    update_n: u32,
    eor_us: u64,
    decode_us: u64,
    frames_n: u32,
    end: Option<String>,
}

fn enabled() -> bool {
    static ENABLED: OnceLock<bool> = OnceLock::new();
    *ENABLED.get_or_init(|| std::env::var_os("BGPD_EST_PROFILE").is_some_and(|v| v != "0"))
}

fn collector() -> &'static Mutex<BTreeMap<IpAddr, Phases>> {
    static COLLECTOR: OnceLock<Mutex<BTreeMap<IpAddr, Phases>>> = OnceLock::new();
    COLLECTOR.get_or_init(|| Mutex::new(BTreeMap::new()))
}

static EST_COUNTER: AtomicU32 = AtomicU32::new(0);

/// A profiler checkpoint: `Some(start instant)` only when profiling is
/// on, so the un-profiled path pays one relaxed atomic read per site.
pub fn now() -> Option<Instant> {
    enabled().then(Instant::now)
}

/// Elapsed micros of an optional checkpoint (zero when off/unset).
fn since(t: &Option<Instant>) -> u64 {
    t.map(|t| t.elapsed().as_micros() as u64).unwrap_or(0)
}

fn with<F: FnOnce(&mut Phases)>(peer: IpAddr, f: F) {
    if !enabled() {
        return;
    }
    let mut map = collector().lock().unwrap();
    f(map.entry(peer).or_default());
}

/// The per-connection task's first instruction: anchors every
/// task-start-relative phase and closes the accept-to-spawn gap.
pub fn task_started(peer: IpAddr, accepted_at: Option<Instant>) {
    with(peer, |p| {
        p.spawn_gap_us = since(&accepted_at);
        p.t_start = Some(Instant::now());
    });
}

pub fn note_accept(peer: IpAddr, waited: Option<Instant>) {
    with(peer, |p| p.accept_us = since(&waited));
}

pub fn note_lookup(peer: IpAddr, t: Option<Instant>) {
    with(peer, |p| p.lookup_us += since(&t));
}

pub fn note_register(peer: IpAddr, t: Option<Instant>) {
    with(peer, |p| p.register_us += since(&t));
}

pub fn note_construct(peer: IpAddr, t: Option<Instant>) {
    with(peer, |p| p.construct_us += since(&t));
}

/// The peer's OPEN was processed (validation + our OPEN/KEEPALIVE out).
pub fn note_open(peer: IpAddr, openproc: Option<Instant>) {
    with(peer, |p| {
        p.openproc_us = since(&openproc);
        if let Some(t0) = p.t_start {
            p.open_us = t0.elapsed().as_micros() as u64;
        }
    });
}

/// The Established transition: emits the EST line (session live).
pub fn note_established(peer: IpAddr) {
    let mut line = None;
    with(peer, |p| {
        if let Some(t0) = p.t_start {
            p.est_us = t0.elapsed().as_micros() as u64;
        }
        p.est_seq = EST_COUNTER.fetch_add(1, Ordering::Relaxed) + 1;
        line = Some(format!(
            "EST-PROF-EST peer={peer} seq={} accept_us={} lookup_us={} \
             spawn_gap_us={} register_us={} construct_us={} open_us={} \
             openproc_us={} est_us={}",
            p.est_seq,
            p.accept_us,
            p.lookup_us,
            p.spawn_gap_us,
            p.register_us,
            p.construct_us,
            p.open_us,
            p.openproc_us,
            p.est_us
        ));
    });
    if let Some(line) = line {
        eprintln!("{line}");
    }
}

pub fn note_dump(peer: IpAddr, t: Option<Instant>) {
    with(peer, |p| p.dump_us += since(&t));
}

pub fn note_update(peer: IpAddr, t: Option<Instant>) {
    with(peer, |p| {
        p.update_us += since(&t);
        p.update_n += 1;
    });
}

pub fn note_eor(peer: IpAddr, t: Option<Instant>) {
    with(peer, |p| p.eor_us += since(&t));
}

pub fn note_decode(peer: IpAddr, t: Option<Instant>) {
    with(peer, |p| {
        p.decode_us += since(&t);
        p.frames_n += 1;
    });
}

/// Session end: emits the END line with the import-path totals.
pub fn note_end(peer: IpAddr, end: &str) {
    let mut line = None;
    with(peer, |p| {
        p.end = Some(end.to_string());
        line = Some(format!(
            "EST-PROF-END peer={peer} seq={} est_us={} dump_us={} \
             update_us={} update_n={} eor_us={} decode_us={} frames_n={} end={end}",
            p.est_seq,
            p.est_us,
            p.dump_us,
            p.update_us,
            p.update_n,
            p.eor_us,
            p.decode_us,
            p.frames_n
        ));
    });
    if let Some(line) = line {
        eprintln!("{line}");
    }
}
