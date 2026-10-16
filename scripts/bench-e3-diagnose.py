#!/usr/bin/env python3
"""bench-e3-diagnose.py — fold the F10 establishment-phase lines.

Parses the per-session `EST-PROF-EST` lines and the periodic
`EST-PROF-SNAP` aggregate lines bgpd emits under BGPD_EST_PROFILE
(crates/bgpd/src/estprof.rs; the bench harness copies them to
<run>/estprof.log), joins them with the fleet's injector timeline, and
prints the diagnosis table:

  - per-phase p50/p95/max across sessions (ms) — separates the F10
    candidates: accept-loop serialization (accept_us), per-session
    task/allocator setup (spawn_gap/register/construct), per-peer
    config recompute (lookup_us + construct's config resolve);
  - the EST-PROF-SNAP demand totals (the bench window kills the daemon
    with sessions live, so the LAST snapshot's cumulative sums are the
    window totals): update_ms/eor_ms/decode_ms attribute the import
    path; est_wall_ms is the FSM handshake wait demand;
  - ordinal correlations (first-half vs last-half means) — which phases
    grow with the session ordinal;
  - the client-side (injector) established-offset distribution.

Usage: bench-e3-diagnose.py <run-dir> [<run-dir> ...]
"""
import argparse
import glob
import json
import re
import sys
from pathlib import Path

ANSI = re.compile(r"\x1b\[[0-9;]*m")
FLEET_RE = re.compile(r"REPLAY-(START|ESTABLISHED|FIRST-UPDATE|LAST-UPDATE) wall=([\d.]+)")

PER_PHASES = [
    "accept_us", "lookup_us", "spawn_gap_us", "register_us",
    "construct_us", "open_us", "openproc_us", "est_us",
]
SNAP_PHASES = [
    "accept_ms", "lookup_ms", "spawn_gap_ms", "register_ms",
    "construct_ms", "open_ms", "openproc_ms", "est_wall_ms",
    "dump_ms", "update_ms", "eor_ms", "decode_ms",
]
# per-session accept_us > 1 s is the idle pre-burst wait (the listener
# armed long before the fleet's first connect); excluded per the
# estprof.rs snapshot heuristic.
IDLE_ACCEPT_US = 1_000_000


def parse_kv(line):
    out = {}
    for token in ANSI.sub("", line).split():
        if "=" in token:
            k, v = token.split("=", 1)
            try:
                out[k] = float(v) if "." in v else int(v)
            except ValueError:
                out[k] = v
    return out


def load_run(run_dir):
    run_dir = Path(run_dir)
    est, snaps = {}, []
    sources = [run_dir / "estprof.log", run_dir / "sut-bgpd.log"]
    for src in sources:
        if not src.exists():
            continue
        for line in src.read_text(errors="replace").splitlines():
            if line.startswith("EST-PROF-EST "):
                kv = parse_kv(line[len("EST-PROF-EST "):])
                if "peer" in kv:
                    est[kv["peer"]] = kv
            elif line.startswith("EST-PROF-SNAP "):
                kv = parse_kv(line[len("EST-PROF-SNAP "):])
                if "t_ms" in kv:
                    snaps.append(kv)
        if src.name == "estprof.log":
            break  # dedicated file: complete, no fallback needed
    fleet = []
    for f in sorted(glob.glob(str(run_dir / "fleet" / "inj-*.txt"))):
        marks = {}
        for kind, wall in FLEET_RE.findall(open(f, errors="replace").read()):
            marks[kind] = float(wall)
        if marks:
            fleet.append(marks)
    return est, snaps, fleet


def fmt_ms(v_us):
    return "-" if v_us is None else f"{v_us / 1000:.3f}"


def diagnose_run(run_dir, out):
    est, snaps, fleet = load_run(run_dir)
    print(f"== {run_dir}: fleet={len(fleet)} est_lines={len(est)} snaps={len(snaps)}",
          file=out)
    rows = sorted(est.values(), key=lambda r: r.get("seq", 0))
    if rows:
        print(f"  per-session phases ({len(rows)} sessions, ms):", file=out)
        print(f"  {'phase':<14}{'p50':>9}{'p95':>9}{'max':>9}{'sum':>10}", file=out)
        for p in PER_PHASES:
            vals = sorted(r[p] for r in rows if p in r and isinstance(r[p], int))
            if p == "accept_us":
                vals = [v for v in vals if v <= IDLE_ACCEPT_US]
            if not vals:
                continue
            half = len(vals) // 2
            print(f"  {p:<14}{fmt_ms(vals[half]):>9}{fmt_ms(vals[int(.95 * len(vals)) - 1]):>9}"
                  f"{fmt_ms(vals[-1]):>9}{fmt_ms(sum(vals)):>10}", file=out)
        for p in ("accept_us", "spawn_gap_us", "open_us", "est_us"):
            seqd = [r.get(p) for r in rows if isinstance(r.get(p), int)]
            if not seqd:
                continue
            seqd = [v for v in seqd if p != "accept_us" or v <= IDLE_ACCEPT_US]
            half = len(seqd) // 2
            fm = sum(seqd[:half]) / max(half, 1)
            lm = sum(seqd[half:]) / max(len(seqd) - half, 1)
            print(f"  {p}: first-half mean {fmt_ms(fm)}ms last-half {fmt_ms(lm)}ms"
                  f" (x{lm / max(fm, 1):.2f})", file=out)
    if snaps:
        last = snaps[-1]
        print(f"  last SNAP t_ms={last.get('t_ms')} established={last.get('established')}"
              f" (demand totals, ms):", file=out)
        for p in SNAP_PHASES:
            if p in last:
                print(f"    {p:<14}{last[p]:>10}", file=out)
        for p in ("update_n", "frames_n", "peers"):
            if p in last:
                print(f"    {p:<14}{last[p]:>10}", file=out)
    if fleet:
        t0 = min(m.get("START", 0) for m in fleet)
        walls = sorted(m["ESTABLISHED"] - t0 for m in fleet if "ESTABLISHED" in m)
        if walls:
            print(f"  client est-offset ms: p50={walls[len(walls) // 2] * 1e3:.1f}"
                  f" p90={walls[int(.9 * len(walls)) - 1] * 1e3:.1f}"
                  f" max={walls[-1] * 1e3:.1f}", file=out)
    return snaps[-1] if snaps else None


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("dirs", nargs="+", help="run dirs")
    ap.add_argument("--json", action="store_true", help="emit per-run last-snap sums as JSON")
    args = ap.parse_args()
    all_sums = {}
    for d in args.dirs:
        last = diagnose_run(d, sys.stdout)
        if last:
            all_sums[d] = {k: last.get(k) for k in SNAP_PHASES}
    if args.json and all_sums:
        print(json.dumps(all_sums, indent=1))


if __name__ == "__main__":
    main()
