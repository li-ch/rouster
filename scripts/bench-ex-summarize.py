#!/usr/bin/env python3
"""bench-ex-summarize.py — fold E2/E3/E4 bench artifacts into metrics.

Three modes, one file (the S14-b PERF-X stream; bench-summarize.py
stays the E1 receipt tool, untouched):

--e4  per run: parse observe.csv (kernel bgp count series + /proc
      jiffies/RSS) + injector launch + SUT logs; wall
      first-kernel-route→target (the programming window) and
      launch→target; rousterd/bgpd CPU over the window; RSS of the
      pair; malformed/rejected; netlink rcvbuf overruns. Aggregate
      median/p95 over measured runs (run-1 = warmup).

--e2  per run: parse the flap tool's FLAP-* epoch marks (VM clock ->
      host clock via clock-offset.txt) + observe.csv main/kernel
      series; per round: withdraw trough (min main count), the
      reconvergence wall (reannounce-done -> count restored, both the
      SUT-own-count basis and the kernel-count basis), session
      survival, storm CPU (STEADY→ROUNDS-DONE), RSS. Aggregate over
      rounds and measured runs.

--e3  per cell (n<N>-c<C>/): parse fleet/inj-*.log REPLAY-START /
      REPLAY-ESTABLISHED epochs (VM clock -> host clock), the poller
      CSV, SUT cross-counts; wall first-connect→all-established,
      sessions/s, failures, SUT CPU. Aggregate over measured runs.

Descriptive numbers only — no comparative prose (docs/benchmarks.md
claim policy).
"""
import argparse
import csv
import glob
import json
import re
import statistics
from pathlib import Path

ANSI = re.compile(r"\x1b\[[0-9;]*m")
TS = re.compile(r"^(\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d+Z)")


def to_int(v):
    try:
        return int(v)
    except (TypeError, ValueError):
        return None


def to_float(v):
    try:
        return float(v)
    except (TypeError, ValueError):
        return None


def clock_offset(run_dir):
    off = run_dir / "clock-offset.txt"
    if off.exists():
        d = {}
        for kv in off.read_text().split():
            k, _, v = kv.partition("=")
            try:
                d[k] = float(v)
            except ValueError:
                pass
        return d.get("host_minus_vm", 0.0)
    return 0.0


def read_rows(path):
    if not path.exists():
        return []
    with path.open() as fh:
        return list(csv.DictReader(fh))


def parse_bgpd_log(path):
    out = {"malformed": 0, "rejected": 0, "updates": 0, "established": 0}
    if not path.exists():
        return out
    for line in path.open(errors="replace"):
        line = ANSI.sub("", line)
        if "UPDATE received" in line:
            out["updates"] += 1
        elif "malformed message" in line:
            out["malformed"] += 1
        elif "UPDATE rejected" in line:
            out["rejected"] += 1
        elif "session Established" in line:
            out["established"] += 1
    return out


def parse_rousterd_log(path):
    if not path.exists():
        return {"netlink_rcvbuf_overruns": 0}
    text = path.read_text(errors="replace")
    return {"netlink_rcvbuf_overruns": text.count("netlink socket buffer full")}


def proc_series(rows):
    """Sparse /proc columns -> list of (t, tag, jiffies, rss)."""
    out = []
    for r in rows:
        t = to_float(r.get("t_host"))
        if t is None:
            continue
        for tag in ("sut_bgpd", "sut_zebra"):
            u, s = to_float(r.get(f"{tag}_utime")), to_float(r.get(f"{tag}_stime"))
            if u is not None and s is not None:
                out.append((t, tag, u + s, to_float(r.get(f"{tag}_rss_kb"))))
    return out


def cpu_between(series, tag, t0, t1, clk):
    vals = [(t, j) for t, g, j, _ in series if g == tag and t0 <= t <= t1]
    if len(vals) < 2:
        return None
    return round((vals[-1][1] - vals[0][1]) / clk, 3)


def rss_bounds(rows, tag):
    rss = [to_float(r.get(f"{tag}_rss_kb")) for r in rows]
    hwm = [to_float(r.get(f"{tag}_hwm_kb")) for r in rows]
    rss = [x for x in rss if x is not None]
    hwm = [x for x in hwm if x is not None]
    if not rss:
        return {}
    return {"rss_empty_kb": rss[0], "rss_final_kb": rss[-1],
            "rss_peak_kb": max(rss), "hwm_kb": max(hwm) if hwm else None}


def agg(vals):
    vals = [v for v in vals if v is not None]
    if not vals:
        return {}
    if len(vals) == 1:
        return {"only": round(vals[0], 3)}
    return {
        "median": round(statistics.median(vals), 3),
        "p95": round(statistics.quantiles(vals, n=20)[-1]
                     if len(vals) >= 3 else max(vals), 3),
        "min": round(min(vals), 3),
        "max": round(max(vals), 3),
    }


# ---------------------------------------------------------------- E4
def summarize_e4(args):
    out = Path(args.out_dir)
    need = args.target_count - max(2, args.target_count // 200)
    runs = []
    for run_dir in sorted(out.glob("run-*")):
        rows = read_rows(run_dir / "observe.csv")
        if not rows:
            continue
        m = {"run": run_dir.name}
        # kernel series: prefer the high-resolution in-container poll
        # (VM-clock ns -> host epoch via clock-offset); fall back to
        # the observer CSV's kernel column when absent.
        kern = []
        poll = run_dir / "poll.csv"
        if poll.exists():
            off = clock_offset(run_dir)
            for line in poll.read_text().splitlines():
                parts = line.split()
                if len(parts) == 2:
                    try:
                        kern.append((float(parts[0]) + off, int(parts[1])))
                    except ValueError:
                        pass
        if not kern:
            kern = [(to_float(r["t_host"]), to_int(r.get("kernel_bgp")))
                    for r in rows if to_int(r.get("kernel_bgp")) is not None]
        launch = to_float((run_dir / "injector-launch.txt").read_text().strip()) \
            if (run_dir / "injector-launch.txt").exists() else None
        t_first = next((t for t, k in kern if k > 0), None)
        t_prev0 = next((kern[i - 1][0] for i, (t, k) in enumerate(kern)
                        if k > 0 and i > 0), None)
        t_done = None
        for i in range(len(kern) - 2):
            if kern[i][1] >= need and kern[i + 1][1] >= need and kern[i + 2][1] >= need:
                t_done = kern[i][0]
                break
        accepted = kern[-1][1] if kern else None
        m["accepted"] = accepted
        if t_first and t_done:
            span = t_done - t_first
            gap = (t_first - t_prev0) if t_prev0 else None
            if span > max(0.02, (gap or 0)):
                m["wall_program_s"] = round(span, 3)
                m["routes_per_s"] = round((accepted or need) / span, 1)
            else:
                # the whole pass fit inside one poll gap: the honest
                # statement is an upper bound on the wall (and thus a
                # lower bound on the rate), not a measurement.
                bound = t_done - t_prev0 if t_prev0 else None
                m["wall_program_upper_bound_s"] = round(bound, 3) if bound else None
                if bound and bound > 0:
                    m["routes_per_s_lower_bound"] = round(
                        (accepted or need) / bound, 1)
        if launch and t_done:
            m["wall_total_s"] = round(t_done - launch, 3)
        series = proc_series(rows)
        if t_first and t_done:
            m["rousterd_cpu_window_s"] = cpu_between(
                series, "sut_zebra", t_first - 0.5, t_done + 0.5, args.clk_tck)
            m["bgpd_cpu_window_s"] = cpu_between(
                series, "sut_bgpd", t_first - 0.5, t_done + 0.5, args.clk_tck)
        # full-run CPU (always available; window CPU is empty when the
        # window is shorter than the /proc sampling cadence)
        if series:
            for tag, name in (("sut_zebra", "rousterd"), ("sut_bgpd", "bgpd")):
                cpu = cpu_between(series, tag, series[0][0] - 1,
                                  series[-1][0] + 1, args.clk_tck)
                if cpu is not None:
                    m[f"{name}_cpu_total_s"] = cpu
        for tag, name in (("sut_zebra", "rousterd"), ("sut_bgpd", "bgpd")):
            b = rss_bounds(rows, tag)
            for k, v in b.items():
                m[f"{name}_{k}"] = v
        m.update(parse_bgpd_log(run_dir / "sut-bgpd.log"))
        m.update(parse_rousterd_log(run_dir / "rousterd.log"))
        # injector evidence
        it = run_dir / "injector.txt"
        if it.exists():
            for line in it.read_text(errors="replace").splitlines():
                mm = re.search(r"REPLAY-LAST-UPDATE .*routes=(\d+) msgs=(\d+)", line)
                if mm:
                    m["replay_routes"] = int(mm.group(1))
                    m["replay_msgs"] = int(mm.group(2))
        (run_dir / "metrics.json").write_text(json.dumps(m, indent=1) + "\n")
        runs.append(m)

    measured = runs[1:] if len(runs) > 1 else runs
    summary = {
        "experiment": "e4", "mode": "rouster",
        "target_count": args.target_count, "need": need,
        "runs_total": len(runs), "runs_measured": len(measured),
        "per_run": runs,
        "aggregate": {},
        "frr_derived": {
            "basis": "§R FRR-full entry: zebra 9.67 CPU-s for 1,126,490 routes",
            "routes_per_cpu_s": round(1126490 / 9.67, 1),
        },
    }
    for key in ("wall_program_s", "wall_program_upper_bound_s",
                "wall_total_s", "routes_per_s", "routes_per_s_lower_bound",
                "rousterd_cpu_window_s", "bgpd_cpu_window_s",
                "rousterd_cpu_total_s", "bgpd_cpu_total_s",
                "rousterd_rss_peak_kb", "bgpd_rss_peak_kb",
                "accepted", "malformed", "rejected",
                "netlink_rcvbuf_overruns"):
        summary["aggregate"][key] = agg([r.get(key) for r in measured])
    (out / "summary.json").write_text(json.dumps(summary, indent=1) + "\n")
    print(json.dumps(summary["aggregate"], indent=1))


# ---------------------------------------------------------------- E2
def summarize_e2(args):
    out = Path(args.out_dir)
    need = args.target_count - max(2, args.target_count // 200)
    subset_n = None
    runs = []
    for run_dir in sorted(out.glob("run-*")):
        rows = read_rows(run_dir / "observe.csv")
        flap = run_dir / "flap.txt"
        if not rows or not flap.exists():
            continue
        off = clock_offset(run_dir)
        marks = {}
        aborted = False
        for line in flap.read_text(errors="replace").splitlines():
            mm = re.match(r"(FLAP-[A-Z0-9-]+).*wall=([\d.]+)", line)
            if mm:
                marks[mm.group(1)] = float(mm.group(2)) + off  # -> host clock
            if "FLAP-ABORT" in line or "FLAP-ERROR" in line:
                aborted = True
            if line.startswith("FLAP-SUBSET"):
                sm = re.search(r"size=(\d+)", line)
                if sm:
                    subset_n = int(sm.group(1))
        m = {"run": run_dir.name, "aborted": aborted,
             "flap_marks": len(marks)}
        # main + kernel series; kernel prefers the high-resolution
        # in-container poll (VM-clock -> host epoch via clock-offset)
        main = [(to_float(r["t_host"]), to_int(r.get("main_prefixes")))
                for r in rows if to_int(r.get("main_prefixes")) is not None]
        kern = []
        poll = run_dir / "poll.csv"
        if poll.exists():
            for line in poll.read_text().splitlines():
                parts = line.split()
                if len(parts) == 2:
                    try:
                        kern.append((float(parts[0]) + off, int(parts[1])))
                    except ValueError:
                        pass
        if not kern:
            kern = [(to_float(r["t_host"]), to_int(r.get("kernel_bgp")))
                    for r in rows if to_int(r.get("kernel_bgp")) is not None]
        loaded = max((v for _, v in main), default=None)
        m["main_peak"] = loaded
        m["kernel_peak"] = max((v for _, v in kern), default=None)

        def restored(series, t_after, target):
            """First t in series ≥ t_after with value ≥ target held by
            the following row (or itself if last)."""
            cands = [(t, v) for t, v in series if t >= t_after]
            for i, (t, v) in enumerate(cands):
                nxt = cands[i + 1][1] if i + 1 < len(cands) else v
                if v >= target and nxt >= target:
                    return t
            return None

        rounds = []
        for r in range(1, args.rounds + 1):
            ws = marks.get(f"FLAP-ROUND-{r}-WITHDRAW-START")
            ad = marks.get(f"FLAP-ROUND-{r}-ANNOUNCE-DONE")
            if ws is None or ad is None:
                continue
            # trough between withdraw start and announce start
            astart = marks.get(f"FLAP-ROUND-{r}-ANNOUNCE-START", ad)
            trough = min((v for t, v in main if ws <= t <= astart), default=None)
            rec_main = restored(main, ad, need)
            rec_kern = restored(kern, ad, (loaded or need) - max(2, need // 200))
            rd = {"round": r,
                  "trough_main": trough,
                  "reconverge_main_s": round(rec_main - ad, 3) if rec_main else None,
                  "reconverge_kernel_s": round(rec_kern - ad, 3) if rec_kern else None,
                  "round_wall_s": round((rec_main or rec_kern or astart) - ws, 3)
                  if (rec_main or rec_kern) else None}
            rounds.append(rd)
        m["rounds"] = rounds
        m["rounds_completed"] = len(rounds)
        # storm CPU: STEADY -> ROUNDS-DONE
        series = proc_series(rows)
        st, rd_done = marks.get("FLAP-STEADY"), marks.get("FLAP-ROUNDS-DONE")
        if st and rd_done:
            for tag, name in (("sut_bgpd", "speaker"), ("sut_zebra", "core")):
                m[f"{name}_cpu_storm_s"] = cpu_between(
                    series, tag, st, rd_done + 2, args.clk_tck)
        for tag, name in (("sut_bgpd", "speaker"), ("sut_zebra", "core")):
            for k, v in rss_bounds(rows, tag).items():
                m[f"{name}_{k}"] = v
        m.update(parse_bgpd_log(run_dir / "sut-bgpd.log"))
        m.update(parse_rousterd_log(run_dir / "rousterd.log"))
        if (run_dir / "bgpd.log").exists():  # frr side
            m.update(parse_bgpd_log(run_dir / "bgpd.log"))
        m.update(parse_rousterd_log(run_dir / "zebra.log"))
        (run_dir / "metrics.json").write_text(json.dumps(m, indent=1) + "\n")
        runs.append(m)

    measured = runs[1:] if len(runs) > 1 else runs
    all_rec_main = [rd["reconverge_main_s"] for r in measured
                    for rd in r.get("rounds", [])]
    all_rec_kern = [rd["reconverge_kernel_s"] for r in measured
                    for rd in r.get("rounds", [])]
    all_round_wall = [rd["round_wall_s"] for r in measured
                      for rd in r.get("rounds", [])]
    summary = {
        "experiment": "e2", "mode": args.mode,
        "target_count": args.target_count, "need": need,
        "flap_every": args.flap_every, "subset_size": subset_n,
        "runs_total": len(runs), "runs_measured": len(measured),
        "per_run": runs,
        "aggregate": {
            "reconverge_main_s": agg(all_rec_main),
            "reconverge_kernel_s": agg(all_rec_kern),
            "round_wall_s": agg(all_round_wall),
            "rounds_completed_per_run": agg([r.get("rounds_completed")
                                             for r in measured]),
            "speaker_cpu_storm_s": agg([r.get("speaker_cpu_storm_s")
                                        for r in measured]),
            "core_cpu_storm_s": agg([r.get("core_cpu_storm_s") for r in measured]),
            "aborted_runs": sum(1 for r in measured if r.get("aborted")),
            "malformed_total": sum(r.get("malformed", 0) for r in measured),
            "rejected_total": sum(r.get("rejected", 0) for r in measured),
        },
    }
    (out / "summary.json").write_text(json.dumps(summary, indent=1) + "\n")
    print(json.dumps(summary["aggregate"], indent=1))


# ---------------------------------------------------------------- E3
def summarize_e3(args):
    out = Path(args.out_dir)
    runs = []
    for run_dir in sorted(out.glob("run-*")):
        fleet = sorted(glob.glob(str(run_dir / "fleet" / "inj-*.txt")))
        if not fleet:
            continue
        off = clock_offset(run_dir)
        starts, ests = [], []
        for f in fleet:
            text = open(f, errors="replace").read()
            ms = re.search(r"REPLAY-START wall=([\d.]+)", text)
            me = re.search(r"REPLAY-ESTABLISHED wall=([\d.]+)", text)
            if ms:
                starts.append(float(ms.group(1)) + off)
            if me:
                ests.append(float(me.group(1)) + off)
        m = {"run": run_dir.name, "fleet": len(fleet),
             "established": len(ests)}
        if starts and ests:
            t_first, t_last = min(starts), max(ests)
            m["wall_first_connect_to_all_s"] = round(t_last - t_first, 3)
            m["sessions_per_s"] = round(len(ests) / (t_last - t_first), 1)
            m["start_spread_s"] = round(max(starts) - min(starts), 3)
            m["est_spread_s"] = round(max(ests) - min(ests), 3)
        # release-basis wall: the common T0 the fleet was released at
        t0f = run_dir / "t0.txt"
        if t0f.exists() and ests:
            try:
                t0 = float(t0f.read_text().strip()) + off
                m["wall_release_to_all_s"] = round(max(ests) - t0, 3)
            except ValueError:
                pass
        m["failures"] = len(fleet) - len(ests)
        # poller.log holds CSV rows (one per poll) plus markers
        prows = []
        if (run_dir / "poller.log").exists():
            lines = (run_dir / "poller.log").read_text().splitlines()
            csv_lines = [l for l in lines if re.match(r"^\d", l)]
            if csv_lines:
                header = ("t_host,established,sut_established,bgpd_jiffies,"
                          "zebra_jiffies,bgpd_rss_kb,zebra_rss_kb")
                prows = list(csv.DictReader([header] + csv_lines))
        if prows:
            last = prows[-1]
            m["sut_established_final"] = to_int(last.get("sut_established"))
            first_j = to_int(prows[0].get("bgpd_jiffies"))
            last_j = to_int(last.get("bgpd_jiffies"))
            first_z = to_int(prows[0].get("zebra_jiffies"))
            last_z = to_int(last.get("zebra_jiffies"))
            if first_j is not None and last_j is not None:
                m["speaker_cpu_s"] = round((last_j - first_j) / args.clk_tck, 3)
            if first_z is not None and last_z is not None:
                m["core_cpu_s"] = round((last_z - first_z) / args.clk_tck, 3)
            m["speaker_rss_kb"] = to_int(last.get("bgpd_rss_kb"))
            m["core_rss_kb"] = to_int(last.get("zebra_rss_kb"))
        (run_dir / "metrics.json").write_text(json.dumps(m, indent=1) + "\n")
        runs.append(m)

    measured = runs[1:] if len(runs) > 1 else runs
    summary = {
        "experiment": "e3", "mode": args.mode,
        "sessions": args.sessions, "sut_cores": args.cores,
        "runs_total": len(runs), "runs_measured": len(measured),
        "per_run": runs,
        "aggregate": {},
    }
    for key in ("wall_first_connect_to_all_s", "wall_release_to_all_s",
                "sessions_per_s",
                "failures", "speaker_cpu_s", "core_cpu_s",
                "speaker_rss_kb", "core_rss_kb", "start_spread_s",
                "sut_established_final"):
        summary["aggregate"][key] = agg([r.get(key) for r in measured])
    (out / "summary.json").write_text(json.dumps(summary, indent=1) + "\n")
    print(json.dumps(summary["aggregate"], indent=1))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--e2", action="store_true")
    ap.add_argument("--e3", action="store_true")
    ap.add_argument("--e4", action="store_true")
    ap.add_argument("--mode", choices=["rouster", "frr"])
    ap.add_argument("--out-dir", required=True)
    ap.add_argument("--target-count", type=int)
    ap.add_argument("--clk-tck", type=float, default=100.0)
    ap.add_argument("--flap-every", type=int, default=10)
    ap.add_argument("--rounds", type=int, default=10)
    ap.add_argument("--sessions", type=int)
    ap.add_argument("--cores", default="")
    args = ap.parse_args()
    if args.e4:
        summarize_e4(args)
    elif args.e2:
        summarize_e2(args)
    elif args.e3:
        summarize_e3(args)
    else:
        ap.error("pick one of --e2/--e3/--e4")


if __name__ == "__main__":
    main()
