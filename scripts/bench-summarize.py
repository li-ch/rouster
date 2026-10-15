#!/usr/bin/env python3
"""Fold bench-e1-ingest run artifacts into per-run metrics + summary.

Per run dir:
  - parse the SUT bgpd log (rouster) for first-UPDATE / End-of-RIB
    timestamps and UPDATE counts (ANSI stripped);
  - parse the injector log for DRIVER-FIRST-LINE / DRIVER-LAST-LINE;
  - join the poll CSV for main-table prefix series, per-daemon CPU
    jiffies and RSS peaks.

summary.json: median + p95 over the measured runs (run-1 is the
declared warmup when more than one run exists). Descriptive numbers
only — no comparative prose (docs/benchmarks.md claim policy).
"""
import argparse
import csv
import json
import re
import statistics
from pathlib import Path

ANSI = re.compile(r"\x1b\[[0-9;]*m")
TS = re.compile(r"^(\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d+Z)")


def iso_to_s(stamp):
    import datetime
    return datetime.datetime.strptime(
        stamp, "%Y-%m-%dT%H:%M:%S.%f%z"
    ).timestamp()


def parse_bgpd_log(path):
    first_upd = last_upd = eor = None
    n_upd = n_malformed = n_rejected = 0
    if not path.exists():
        return {}
    with path.open(errors="replace") as fh:
        for line in fh:
            line = ANSI.sub("", line)
            m = TS.match(line)
            ts = iso_to_s(m.group(1)) if m else None
            if "UPDATE received" in line:
                n_upd += 1
                if first_upd is None and ts:
                    first_upd = ts
                if ts:
                    last_upd = ts
            elif "End-of-RIB received" in line:
                if ts:
                    eor = ts
            elif "malformed message" in line:
                n_malformed += 1
            elif "UPDATE rejected" in line:
                n_rejected += 1
    return {
        "first_update_s": first_upd,
        "last_update_s": last_upd,
        "eor_s": eor,
        "update_msgs": n_upd,
        "malformed": n_malformed,
        "rejected": n_rejected,
    }


def parse_injector_log(path):
    out = {}
    if not path.exists():
        return out
    for line in path.read_text(errors="replace").splitlines():
        m = re.search(r"REPLAY-(FIRST|LAST)-UPDATE .*wall=([\d.]+)", line)
        if m:
            out[f"driver_{m.group(1).lower()}_wall"] = float(m.group(2))
        m = re.search(r"REPLAY-LAST-UPDATE .*routes=(\d+) msgs=(\d+)", line)
        if m:
            out["replay_routes"] = int(m.group(1))
            out["replay_msgs"] = int(m.group(2))
    return out


def parse_poll(path):
    rows = []
    with path.open() as fh:
        for row in csv.DictReader(fh):
            rows.append(row)
    if not rows:
        return {}
    def fnum(row, key):
        v = row.get(key, "")
        return float(v) if v not in ("", None) else None
    out = {
        "poll_t0": float(rows[0]["t_host"]),
        "poll_tend": float(rows[-1]["t_host"]),
        "main_prefixes_last": None,
        "pfxrcd_last": None,
    }
    def to_int(v):
        try:
            return int(v)
        except (TypeError, ValueError):
            return None
    out["main_prefixes_last"] = to_int(rows[-1].get("sut_prefixes_main"))
    out["pfxrcd_last"] = to_int(rows[-1].get("sut_pfxrcd"))
    peak_main = 0
    for r in rows:
        v = to_int(r.get("sut_prefixes_main"))
        if v:
            peak_main = max(peak_main, v)
    out["main_prefixes_peak"] = peak_main
    out["main_prefixes_at_100k_s"] = None
    for r in rows:
        v = to_int(r.get("sut_prefixes_main"))
        if v is not None and v >= 100_000:
            out["main_prefixes_at_100k_s"] = float(r["t_host"])
            break
    # CPU seconds + RSS from the LAST poll row (cumulative jiffies).
    for tag in ("sut_bgpd", "sut_zebra", "inj"):
        u = fnum(rows[-1], f"{tag}_utime")
        s = fnum(rows[-1], f"{tag}_stime")
        out[f"{tag}_cpu_jiffies"] = (u + s) if u is not None and s is not None else None
        hwm = [fnum(r, f"{tag}_hwm_kb") for r in rows]
        rss = [fnum(r, f"{tag}_rss_kb") for r in rows]
        hwm = [x for x in hwm if x is not None]
        rss = [x for x in rss if x is not None]
        out[f"{tag}_hwm_kb"] = max(hwm) if hwm else None
        out[f"{tag}_rss_final_kb"] = rss[-1] if rss else None
        out[f"{tag}_rss_empty_kb"] = rss[0] if rss else None
    # first row where main prefixes > 0 (coarse external first-route)
    for r in rows:
        v = to_int(r.get("sut_prefixes_main")) or to_int(r.get("sut_pfxrcd"))
        if v:
            out["first_route_poll_s"] = float(r["t_host"])
            break
    return out


def parse_poll_complete(path):
    if not path.exists():
        return None
    m = re.search(r"POLL-COMPLETE ([\d.]+)", path.read_text())
    return float(m.group(1)) if m else None


def run_metrics(run_dir, clk_tck):
    m = {"run": run_dir.name}
    m.update(parse_bgpd_log(run_dir / "sut-bgpd.log"))
    m.update(parse_injector_log(run_dir / "injector.log"))
    m.update(parse_poll(run_dir / "poll.csv"))
    m["poll_complete_s"] = parse_poll_complete(run_dir / "poller.log")
    off = run_dir / "clock-offset.txt"
    if off.exists():
        d = {}
        for kv in off.read_text().split():
            k, _, v = kv.partition("=")
            try:
                d[k] = float(v)
            except ValueError:
                pass
        m.update(d)
    # derived wall times
    if m.get("first_update_s") and m.get("eor_s"):
        m["wall_bgp_level_s"] = m["eor_s"] - m["first_update_s"]
    t0 = m.get("driver_first_wall") or m.get("first_route_poll_s")
    if t0 and m.get("poll_complete_s"):
        m["wall_external_s"] = m["poll_complete_s"] - t0
    if clk_tck:
        for tag in ("sut_bgpd", "sut_zebra", "inj"):
            j = m.get(f"{tag}_cpu_jiffies")
            if j is not None:
                m[f"{tag}_cpu_s"] = round(j / clk_tck, 3)
    return m


AGG = [
    "wall_bgp_level_s", "wall_external_s",
    "sut_bgpd_cpu_s", "sut_zebra_cpu_s", "inj_cpu_s",
    "sut_bgpd_hwm_kb", "sut_zebra_hwm_kb",
    "sut_bgpd_rss_final_kb", "sut_zebra_rss_final_kb",
    "sut_bgpd_rss_empty_kb", "sut_zebra_rss_empty_kb",
]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out-dir", required=True)
    ap.add_argument("--mode", choices=["rouster", "frr"], required=True)
    ap.add_argument("--target-count", type=int, required=True)
    ap.add_argument("--clk-tck", type=float, default=100.0)
    args = ap.parse_args()

    out = Path(args.out_dir)
    runs = []
    for run_dir in sorted(out.glob("run-*")):
        if not (run_dir / "poll.csv").exists():
            continue
        m = run_metrics(run_dir, args.clk_tck)
        (run_dir / "metrics.json").write_text(json.dumps(m, indent=1) + "\n")
        runs.append(m)

    measured = runs[1:] if len(runs) > 1 else runs
    summary = {
        "mode": args.mode,
        "target_count": args.target_count,
        "runs_total": len(runs),
        "runs_measured": len(measured),
        "per_run": runs,
        "aggregate": {},
    }
    for key in AGG:
        vals = [r[key] for r in measured if r.get(key) is not None]
        if len(vals) >= 2:
            summary["aggregate"][key] = {
                "median": round(statistics.median(vals), 3),
                "p95": round(
                    statistics.quantiles(vals, n=20)[-1]
                    if len(vals) >= 3 else max(vals), 3),
                "min": round(min(vals), 3),
                "max": round(max(vals), 3),
            }
        elif vals:
            summary["aggregate"][key] = {"only": round(vals[0], 3)}
    (out / "summary.json").write_text(json.dumps(summary, indent=1) + "\n")
    print(json.dumps(summary["aggregate"], indent=1))


if __name__ == "__main__":
    main()
