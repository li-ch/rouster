#!/usr/bin/env python3
"""bench-e3-diagnose.py — fold the F10 establishment-phase lines.

Parses the per-session `EST-PROF-EST` / `EST-PROF-END` lines bgpd emits
under BGPD_EST_PROFILE=1 (crates/bgpd/src/estprof.rs) from a run dir's
sut-bgpd.log, joins them with the fleet's injector timeline, and prints
the diagnosis table: per-phase p50/p95/max across sessions (µs), the
cross-session demand totals (ms), and the phase-vs-established-ordinal
correlation that separates the F10 candidates:

  - accept-loop serialization -> accept_us growing with seq
  - per-session task/allocator setup -> spawn_gap/register/construct
  - per-peer config recompute -> lookup_us (+ construct's config part)
  - import-path cost -> update_us/eor_us/decode_us totals vs the
    establishment-only phases (confirm with the TABLE=1 A/B cell)

Usage: bench-e3-diagnose.py <run-dir> [<run-dir> ...]   (one per line)
       bench-e3-diagnose.py --json <cell-dir>            (summary.json blob)
"""
import argparse
import glob
import json
import re
import sys
from pathlib import Path

FLEET_RE = re.compile(r"REPLAY-(START|ESTABLISHED|FIRST-UPDATE|LAST-UPDATE) wall=([\d.]+)")

PHASES = [
    "accept_us", "lookup_us", "spawn_gap_us", "register_us",
    "construct_us", "open_us", "openproc_us", "est_us",
    "dump_us", "update_us", "eor_us", "decode_us",
]


def parse_kv(line):
    return {k: v for k, v in (p.split("=", 1) for p in line.split())}


def pct(sorted_vals, q):
    if not sorted_vals:
        return None
    i = min(len(sorted_vals) - 1, int(q * len(sorted_vals)))
    return sorted_vals[i]


def load_run(run_dir):
    run_dir = Path(run_dir)
    est, end = {}, {}
    log = run_dir / "sut-bgpd.log"
    if log.exists():
        for line in log.read_text(errors="replace").splitlines():
            if line.startswith("EST-PROF-EST "):
                kv = parse_kv(line[len("EST-PROF-EST "):])
                if "peer" in kv:
                    est[kv["peer"]] = kv
            elif line.startswith("EST-PROF-END "):
                kv = parse_kv(line[len("EST-PROF-END "):])
                if "peer" in kv:
                    end[kv["peer"]] = kv
    fleet = []
    for f in sorted(glob.glob(str(run_dir / "fleet" / "inj-*.txt"))):
        marks = {}
        for kind, wall in FLEET_RE.findall(open(f, errors="replace").read()):
            marks[kind] = float(wall)
        if marks:
            fleet.append(marks)
    return est, end, fleet


def fmt_us(v):
    return "-" if v is None else f"{v / 1000:.3f}"


def diagnose_run(run_dir, out):
    est, end, fleet = load_run(run_dir)
    n = len(fleet)
    rows = []
    for peer, kv in est.items():
        row = {"peer": peer}
        row.update({k: int(kv[k]) for k in PHASES if k in kv})
        if peer in end:
            e = end[peer]
            row.update({k: int(e[k]) for k in PHASES if k in e})
            for k in ("update_n", "frames_n"):
                if k in e:
                    row[k] = int(e[k])
        rows.append(row)
    rows.sort(key=lambda r: int(r.get("seq", 0) or 0))
    print(f"== {run_dir}: fleet={n} est_lines={len(est)} end_lines={len(end)}", file=out)
    if not rows:
        print("  (no EST-PROF lines — was BGPD_EST_PROFILE=1 set?)", file=out)
        return None
    # per-phase table across sessions
    print(f"  {'phase':<14}{'p50_ms':>9}{'p95_ms':>9}{'max_ms':>9}{'sum_ms':>10}  sum/est", file=out)
    sums = {}
    for p in PHASES:
        vals = sorted(r[p] for r in rows if p in r)
        if not vals:
            continue
        s = sum(vals)
        sums[p] = s
        print(f"  {p:<14}{fmt_us(pct(vals, .5)):>9}{fmt_us(pct(vals, .95)):>9}"
              f"{fmt_us(vals[-1]):>9}{fmt_us(s):>10}  {s / 1e6:.3f}s", file=out)
    if rows and "update_n" in rows[0]:
        print(f"  update_n total={sum(r.get('update_n', 0) for r in rows)}"
              f" frames_n total={sum(r.get('frames_n', 0) for r in rows)}", file=out)
    # ordinal correlation: est_us / accept_us / spawn_gap_us vs seq
    for p in ("accept_us", "spawn_gap_us", "open_us", "est_us"):
        vals = [r.get(p) for r in rows]
        if vals and vals[0] is not None:
            half = len(vals) // 2
            first, last = vals[:half], vals[half:] or vals[:1]
            fm = sum(first) / len(first)
            lm = sum(last) / len(last)
            print(f"  {p}: first-half mean {fm:.0f}us last-half mean {lm:.0f}us (x{lm / max(fm, 1):.2f})", file=out)
    # client side
    if fleet:
        t0 = min(m.get("START", 0) for m in fleet)
        walls = [m["ESTABLISHED"] - t0 for m in fleet if "ESTABLISHED" in m]
        if walls:
            walls.sort()
            print(f"  client est-offset ms: p50={walls[len(walls) // 2] * 1e3:.1f}"
                  f" p90={walls[int(.9 * len(walls)) - 1] * 1e3:.1f} max={walls[-1] * 1e3:.1f}", file=out)
    return sums


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("dirs", nargs="+", help="run dirs (or cell dir with --json)")
    ap.add_argument("--json", action="store_true", help="emit a JSON blob of per-run sums")
    args = ap.parse_args()
    out = sys.stdout
    all_sums = {}
    for d in args.dirs:
        sums = diagnose_run(d, out)
        if sums:
            all_sums[d] = sums
    if args.json and all_sums:
        print(json.dumps(all_sums, indent=1))


if __name__ == "__main__":
    main()
