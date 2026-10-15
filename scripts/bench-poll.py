#!/usr/bin/env python3
"""The E1 external observer: per-second poll of both bench containers.

One row per poll, written to a CSV; completion detection per SUT type:
  - rouster: rousterd main-table prefixes (native status dump
    /run/rouster/rousterd.status, refreshed at rousterd's 10 s
    reconcile cadence) + bgpd's own 'End-of-RIB received' log line.
  - frr:    vtysh 'show bgp ipv4 unicast summary json' pfxRcd +
    zebra's 'show ip route summary' main-table count.

Also samples /proc for the SUT daemons and the injector (CPU jiffies,
VmRSS/VmHWM) each poll — the E5 RSS series rides the same loop.

The CSV plus the raw per-poll /proc samples are the run's evidence;
bench-summarize.py folds them into the run metrics.
"""
import argparse
import csv
import re
import subprocess
import sys
import time

FIELDS = [
    "t_host",
    "sut_prefixes_main",
    "sut_eor_seen",
    "sut_pfxrcd",
    "sut_bgpd_utime",
    "sut_bgpd_stime",
    "sut_bgpd_rss_kb",
    "sut_bgpd_hwm_kb",
    "sut_zebra_utime",
    "sut_zebra_stime",
    "sut_zebra_rss_kb",
    "sut_zebra_hwm_kb",
    "inj_utime",
    "inj_stime",
    "inj_rss_kb",
    "inj_hwm_kb",
]

# rouster: one docker exec reads both daemons' /proc records.
PROC_ROUSTER = (
    "for n in rouster-bgpd rousterd; do p=$(pidof $n | awk '{print $1}'); "
    "[ -n \"$p\" ] || continue; "
    "a=$(awk '{print $14, $15}' /proc/$p/stat); "
    "r=$(awk '/VmRSS/{print $2}' /proc/$p/status); "
    "h=$(awk '/VmHWM/{print $2}' /proc/$p/status); "
    "echo \"$n $a $r $h\"; done"
)
# frr: bgpd + zebra.
PROC_FRR = (
    "for n in bgpd zebra; do p=$(pidof $n | awk '{print $1}'); "
    "[ -n \"$p\" ] || continue; "
    "a=$(awk '{print $14, $15}' /proc/$p/stat); "
    "r=$(awk '/VmRSS/{print $2}' /proc/$p/status); "
    "h=$(awk '/VmHWM/{print $2}' /proc/$p/status); "
    "echo \"$n $a $r $h\"; done"
)
# injector: the in-repo mrt-replay tool (D1(c) switch).
PROC_INJ = (
    "for p in $(pidof mrt-replay 2>/dev/null); do "
    "a=$(awk '{print $14, $15}' /proc/$p/stat); "
    "r=$(awk '/VmRSS/{print $2}' /proc/$p/status); "
    "h=$(awk '/VmHWM/{print $2}' /proc/$p/status); "
    "echo \"inj $a $r $h\"; done"
)


def sh(container, body, timeout=15):
    try:
        out = subprocess.run(
            ["docker", "exec", container, "sh", "-c", body],
            capture_output=True, text=True, timeout=timeout,
        )
        return out.stdout.strip()
    except subprocess.TimeoutExpired:
        return ""


def parse_proc(text):
    """'name utime stime rss hwm' lines -> dict keyed by name."""
    d = {}
    for line in text.splitlines():
        parts = line.split()
        if len(parts) == 5:
            d[parts[0]] = parts[1:5]
    return d


def poll_rouster(sut, status_file, bgpd_log):
    prefixes = ""
    m = re.search(r"^table 254 routes \d+ prefixes (\d+)", sh(
        sut, f"cat {status_file} 2>/dev/null"), re.M)
    if m:
        prefixes = m.group(1)
    eor = "yes" if "End-of-RIB received" in sh(
        sut, f"tail -c 65536 {bgpd_log} 2>/dev/null") else "no"
    return prefixes, eor


def poll_frr(sut):
    out = sh(sut, "vtysh -c 'show bgp ipv4 unicast summary json' 2>/dev/null")
    m = re.search(r'"pfxRcd"\s*:\s*(\d+)', out)
    pfxrcd = m.group(1) if m else ""
    zout = sh(sut, "vtysh -c 'show ip route summary' 2>/dev/null")
    zm = re.search(r"^Totals\s+(\d+)", zout, re.M)
    # FRR 10.2 zebra summary: per-source rows then "Totals <routes> <fib>"
    return pfxrcd, (zm.group(1) if zm else "")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--sut-container", required=True)
    ap.add_argument("--inj-container", required=True)
    ap.add_argument("--mode", choices=["rouster", "frr"], required=True)
    ap.add_argument("--target-count", type=int, required=True)
    ap.add_argument("--timeout", type=int, default=3600)
    ap.add_argument("--settle", type=int, default=30)
    ap.add_argument("--interval", type=float, default=1.0)
    ap.add_argument("--csv", required=True)
    ap.add_argument("--status-file", default="/run/rouster/rousterd.status")
    ap.add_argument("--bgpd-log", default="/var/log/rouster-bgpd.log")
    args = ap.parse_args()

    proc_sut = PROC_ROUSTER if args.mode == "rouster" else PROC_FRR
    complete_at = None
    eor_at = None
    eor_seen_sticky = False
    complete_streak = 0
    t_start = time.time()

    with open(args.csv, "w", newline="") as fh:
        w = csv.DictWriter(fh, FIELDS)
        w.writeheader()
        while True:
            now = time.time()
            if now - t_start > args.timeout:
                print("POLL-TIMEOUT", file=sys.stderr)
                break
            row = {f: "" for f in FIELDS}
            row["t_host"] = f"{now:.6f}"

            sut_p = parse_proc(sh(args.sut_container, proc_sut))
            inj_p = parse_proc(sh(args.inj_container, PROC_INJ))
            for name, tag in (("rouster-bgpd", "sut_bgpd"), ("rousterd", "sut_zebra"),
                              ("bgpd", "sut_bgpd"), ("zebra", "sut_zebra"),
                              ("inj", "inj")):
                if name in sut_p:
                    u, s, r, h = sut_p[name]
                    row[f"{tag}_utime"] = u
                    row[f"{tag}_stime"] = s
                    row[f"{tag}_rss_kb"] = r
                    row[f"{tag}_hwm_kb"] = h
                elif name in inj_p:
                    u, s, r, h = inj_p[name]
                    row[f"inj_utime"] = u
                    row[f"inj_stime"] = s
                    row[f"inj_rss_kb"] = r
                    row[f"inj_hwm_kb"] = h

            if args.mode == "rouster":
                prefixes, eor = poll_rouster(
                    args.sut_container, args.status_file, args.bgpd_log)
                # Completion is count-based (the plan's own definition:
                # RIB count reaching the dump's prefix count). exabgp
                # sends an EOR marker right at session establishment,
                # so EOR arrival alone cannot mean "table complete";
                # it is recorded for the timeline only.
                if eor == "yes" and eor_at is None:
                    eor_at = now
                row["sut_prefixes_main"] = prefixes
                row["sut_eor_seen"] = eor
                need = args.target_count - max(2, args.target_count // 200)
                done = (
                    prefixes.isdigit()
                    and int(prefixes) >= need
                )
            else:
                pfxrcd, ztotal = poll_frr(args.sut_container)
                row["sut_pfxrcd"] = pfxrcd
                row["sut_prefixes_main"] = ztotal
                # A SUT may legitimately reject a few feed routes
                # (policy/parse); completion is the plateau at >=99%
                # of the dump count, with exact finals recorded.
                need = args.target_count - max(2, args.target_count // 200)
                have = max(
                    int(pfxrcd) if pfxrcd.isdigit() else 0,
                    int(ztotal) if ztotal.isdigit() else 0,
                )
                done = have >= need

            w.writerow(row)
            fh.flush()
            if done:
                complete_streak += 1
                if complete_at is None:
                    complete_at = now
                if complete_streak >= 3:
                    print(f"POLL-COMPLETE {complete_at:.6f}", file=sys.stderr)
                    time.sleep(args.settle)
                    # one final row after settle for final RSS
                    row["t_host"] = f"{time.time():.6f}"
                    w.writerow(row)
                    break
            else:
                complete_streak = 0
            elapsed = time.time() - now
            if elapsed < args.interval:
                time.sleep(args.interval - elapsed)

    print(
        f"POLL-DONE complete_at={complete_at} eor_at={eor_at} "
        f"rows={len(FIELDS)}",
        file=sys.stderr,
    )


if __name__ == "__main__":
    main()
