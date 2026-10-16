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
//! one `EST-PROF-END` line at session end, plus a periodic
//! `EST-PROF-SNAP` aggregate line (the harness kills the daemon with
//! sessions still live, so the snapshot series — not the END lines —
//! carries the import-path totals in bench shape). `BGPD_EST_PROFILE=1`
//! emits to stderr; `BGPD_EST_PROFILE=<path>` appends to a dedicated
//! file (the bench shape: tracing's stdout and the profiler's stderr
//! are separate buffers into one redirect, which can interleave
//! mid-line — the dedicated file avoids that entirely). `key=value`
//! form, deliberately NOT through tracing, so the profiler's own cost
//! stays out of the subscriber's formatting path.
//!
//! Scoping: keyed by peer address (one live session per neighbor by
//! the registry's construction; a re-connect overwrites — a bench-shape
//! disclosure, not a production observability surface).

use std::collections::BTreeMap;
use std::io::Write;
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
    *ENABLED.get_or_init(|| output_path().is_some())
}

/// `Some(None)` = stderr; `Some(Some(path))` = dedicated append file.
fn output_path() -> Option<Option<std::path::PathBuf>> {
    static PATH: OnceLock<Option<Option<std::path::PathBuf>>> = OnceLock::new();
    PATH.get_or_init(|| match std::env::var_os("BGPD_EST_PROFILE") {
        None => None,
        Some(v) if v == "0" => None,
        Some(v) if v == "1" => Some(None),
        Some(v) => Some(Some(std::path::PathBuf::from(v))),
    })
    .clone()
}

/// One line to the profiler's sink (dedicated file, else stderr).
fn emit(line: &str) {
    match output_path() {
        Some(Some(path)) => {
            if let Ok(mut f) = std::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(path)
            {
                let _ = writeln!(f, "{line}");
                let _ = f.flush();
            }
        }
        _ => eprintln!("{line}"),
    }
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
        emit(&line);
    }
}

/// One aggregate demand line across all sessions (ms, cumulative).
/// Accept waits > 1 s are the idle pre-burst wait (the listener armed
/// long before the fleet's first connect) and are excluded from the
/// accept sum — a profiler heuristic, disclosed here.
pub fn snapshot(t_ms: u128) {
    if !enabled() {
        return;
    }
    let mut peers = 0usize;
    let mut established = 0usize;
    let (mut accept, mut lookup, mut spawn_gap) = (0u64, 0u64, 0u64);
    let (mut register, mut construct) = (0u64, 0u64);
    let (mut open, mut openproc, mut est_wall, mut dump) = (0u64, 0u64, 0u64, 0u64);
    let (mut update, mut update_n) = (0u64, 0u64);
    let (mut eor, mut decode, mut frames_n) = (0u64, 0u64, 0u64);
    {
        let map = collector().lock().unwrap();
        for p in map.values() {
            peers += 1;
            established += usize::from(p.est_seq > 0);
            if p.accept_us <= 1_000_000 {
                accept += p.accept_us;
            }
            lookup += p.lookup_us;
            spawn_gap += p.spawn_gap_us;
            register += p.register_us;
            construct += p.construct_us;
            open += p.open_us;
            openproc += p.openproc_us;
            est_wall += p.est_us;
            dump += p.dump_us;
            update += p.update_us;
            update_n += p.update_n as u64;
            eor += p.eor_us;
            decode += p.decode_us;
            frames_n += p.frames_n as u64;
        }
    }
    emit(&format!(
        "EST-PROF-SNAP t_ms={t_ms} peers={peers} established={established} \
         accept_ms={} lookup_ms={} spawn_gap_ms={} register_ms={} \
         construct_ms={} open_ms={} openproc_ms={} est_wall_ms={} \
         dump_ms={} update_ms={} update_n={} eor_ms={} decode_ms={} frames_n={}",
        accept / 1000,
        lookup / 1000,
        spawn_gap / 1000,
        register / 1000,
        construct / 1000,
        open / 1000,
        openproc / 1000,
        est_wall / 1000,
        dump / 1000,
        update / 1000,
        update_n,
        eor / 1000,
        decode / 1000,
        frames_n
    ));
}

/// The periodic reporter (the bench window kills the daemon with
/// sessions still live, so the snapshot series carries the totals).
/// Called once from `Daemon::run` when profiling is on.
pub fn spawn_reporter() {
    if !enabled() {
        return;
    }
    let start = Instant::now();
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(std::time::Duration::from_millis(200)).await;
            snapshot(start.elapsed().as_millis());
        }
    });
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
        emit(&line);
    }
}
