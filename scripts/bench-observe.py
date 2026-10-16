#!/usr/bin/env python3
"""bench-observe.py — the E2/E3/E4 external observer (S14-b PERF-X).

A generic per-iteration poller writing one CSV row per pass. Unlike
bench-poll.py (the E1 observer, kept untouched for the E1 receipts),
this one can take its observations from SEPARATE containers so the
observer's own CPU never runs on the SUT's pinned cores (§F):

  --sut-container   the SUT (status file / vtysh / /proc reads)
  --kernel-container  where `ip route show proto 186 | wc -l` runs —
                    for E4 this is a THIRD container sharing the
                    SUT's network namespace but pinned OFF the SUT
                    cpuset (the pre-registered E4 observation shape);
                    for E2/E3 it may be the SUT itself or the same
                    third-container trick.
  --inj-container   optional (E2's flap injector /proc legs).

Per row: host wall + monotonic clocks, kernel bgp route count, the
SUT's own main-table count (rouster status file / FRR vtysh), EOR
flag (rouster), per-daemon /proc jiffies + VmRSS/VmHWM (every
--proc-every rows), and per-leg wall times in ms (the P0-b lesson:
observer cost is evidence too).

Completion is optional and orthogonal: --complete-on kernel|main|none
with --target-count (the E1 tolerance: target − max(2, 0.5%)), a
streak of --streak consecutive passing rows, then --settle seconds
and one final row. --stop-file ends the loop regardless (the E2
harness touches it when the flap tool exits). The post-first-route
stall guard (--stall-after) fails fast on the P0-b wedged-SUT
signature (frozen count + frozen CPU on both daemons).
"""
import argparse
import csv
import re
import subprocess
import sys
import time

FIELDS = [
    "t_host", "t_mono",
    "kernel_bgp",
    "main_prefixes", "sut_eor_seen", "sut_pfxrcd",
    "sut_bgpd_utime", "sut_bgpd_stime",
    "sut_bgpd_rss_kb", "sut_bgpd_hwm_kb",
    "sut_zebra_utime", "sut_zebra_stime",
    "sut_zebra_rss_kb", "sut_zebra_hwm_kb",
    "inj_utime", "inj_stime", "inj_rss_kb", "inj_hwm_kb",
    "iter_ms", "kernel_ms", "main_ms", "proc_sut_ms", "proc_inj_ms",
]

PROC_ROUSTER = (
    "for n in rouster-bgpd rousterd; do p=$(pidof $n | awk '{print $1}'); "
    "[ -n \"$p\" ] || continue; "
    "a=$(awk '{print $14, $15}' /proc/$p/stat); "
    "r=$(awk '/VmRSS/{print $2}' /proc/$p/status); "
    "h=$(awk '/VmHWM/{print $2}' /proc/$p/status); "
    "echo \"$n $a $r $h\"; done"
)
PROC_FRR = (
    "for n in bgpd zebra; do p=$(pidof $n | awk '{print $1}'); "
    "[ -n \"$p\" ] || continue; "
    "a=$(awk '{print $14, $15}' /proc/$p/stat); "
    "r=$(awk '/VmRSS/{print $2}' /proc/$p/status); "
    "h=$(awk '/VmHWM/{print $2}' /proc/$p/status); "
    "echo \"$n $a $r $h\"; done"
)
PROC_INJ = (
    "for p in $(pidof python3 mrt-replay 2>/dev/null); do "
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


def timed_sh(container, body, timeout=15):
    t0 = time.monotonic()
    out = sh(container, body, timeout)
    return out, round((time.monotonic() - t0) * 1000.0, 3)


def parse_proc(text):
    d = {}
    for line in text.splitlines():
        parts = line.split()
        if len(parts) == 5:
            d[parts[0]] = parts[1:5]
    return d


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--sut-container", required=True)
    ap.add_argument("--kernel-container")
    ap.add_argument("--inj-container")
    ap.add_argument("--mode", choices=["rouster", "frr"], required=True)
    ap.add_argument("--interval", type=float, default=0.3)
    ap.add_argument("--timeout", type=int, default=1800)
    ap.add_argument("--csv", required=True)
    ap.add_argument("--proc-every", type=int, default=3)
    ap.add_argument("--complete-on", choices=["kernel", "main", "none"],
                    default="none")
    ap.add_argument("--target-count", type=int, default=0)
    ap.add_argument("--streak", type=int, default=3)
    ap.add_argument("--settle", type=int, default=20)
    ap.add_argument("--stop-file")
    ap.add_argument("--stall-after", type=int, default=0)
    ap.add_argument("--status-file", default="/run/rouster/rousterd.status")
    ap.add_argument("--bgpd-log", default="/var/log/rouster-bgpd.log")
    args = ap.parse_args()

    kernel_c = args.kernel_container or args.sut_container
    proc_sut = PROC_ROUSTER if args.mode == "rouster" else PROC_FRR
    need = args.target_count - max(2, args.target_count // 200) \
        if args.target_count else 0

    complete_at = None
    complete_streak = 0
    stall_sig = None
    stall_since = None
    first_route_at = None
    t_start = time.time()
    seq = 0

    def stop_now():
        if args.stop_file:
            import os
            if os.path.exists(args.stop_file):
                return True
        return False

    with open(args.csv, "w", newline="") as fh:
        w = csv.DictWriter(fh, FIELDS)
        w.writeheader()
        while True:
            now = time.time()
            mono = time.monotonic()
            if now - t_start > args.timeout:
                print("OBSERVE-TIMEOUT", file=sys.stderr)
                break
            row = {f: "" for f in FIELDS}
            row["t_host"] = f"{now:.6f}"
            row["t_mono"] = f"{mono:.6f}"

            kout, row["kernel_ms"] = timed_sh(
                kernel_c, "ip route show proto 186 2>/dev/null | grep -c .")
            if kout.isdigit():
                row["kernel_bgp"] = kout

            if args.mode == "rouster":
                text, row["main_ms"] = timed_sh(
                    args.sut_container, f"cat {args.status_file} 2>/dev/null")
                m = re.search(r"^table 254 routes \d+ prefixes (\d+)", text, re.M)
                if m:
                    row["main_prefixes"] = m.group(1)
                tail = sh(args.sut_container,
                          f"tail -c 65536 {args.bgpd_log} 2>/dev/null")
                row["sut_eor_seen"] = "yes" if "End-of-RIB received" in tail else "no"
            else:
                out, row["main_ms"] = timed_sh(
                    args.sut_container,
                    "vtysh -c 'show ip route summary' 2>/dev/null")
                zm = re.search(r"^Totals\s+(\d+)", out, re.M)
                if zm:
                    row["main_prefixes"] = zm.group(1)
                bout = sh(
                    args.sut_container,
                    "vtysh -c 'show bgp ipv4 unicast summary json' 2>/dev/null")
                bm = re.search(r'"pfxRcd"\s*:\s*(\d+)', bout)
                if bm:
                    row["sut_pfxrcd"] = bm.group(1)

            seq += 1
            if seq % args.proc_every == 1:
                sut_proc, row["proc_sut_ms"] = timed_sh(
                    args.sut_container, proc_sut)
                sut_p = parse_proc(sut_proc)
                for name, tag in (("rouster-bgpd", "sut_bgpd"),
                                  ("rousterd", "sut_zebra"),
                                  ("bgpd", "sut_bgpd"), ("zebra", "sut_zebra")):
                    if name in sut_p:
                        u, s, r, h = sut_p[name]
                        row[f"{tag}_utime"] = u
                        row[f"{tag}_stime"] = s
                        row[f"{tag}_rss_kb"] = r
                        row[f"{tag}_hwm_kb"] = h
                if args.inj_container:
                    inj_proc, row["proc_inj_ms"] = timed_sh(
                        args.inj_container, PROC_INJ)
                    inj_p = parse_proc(inj_proc)
                    if "inj" in inj_p:
                        u, s, r, h = inj_p["inj"]
                        row["inj_utime"] = u
                        row["inj_stime"] = s
                        row["inj_rss_kb"] = r
                        row["inj_hwm_kb"] = h

            row["iter_ms"] = round((time.monotonic() - mono) * 1000.0, 3)
            w.writerow(row)
            fh.flush()

            def val(row, key):
                v = row.get(key, "")
                try:
                    return int(v)
                except (TypeError, ValueError):
                    return None

            if first_route_at is None and (
                    (val(row, "kernel_bgp") or 0) > 0
                    or (val(row, "main_prefixes") or 0) > 0):
                first_route_at = now

            # post-first-route stall guard: frozen kernel count AND
            # frozen CPU on both SUT daemons for --stall-after seconds.
            if args.stall_after and first_route_at is not None:
                jiffies = []
                for tag in ("sut_bgpd", "sut_zebra"):
                    u, s = row.get(f"{tag}_utime", ""), row.get(f"{tag}_stime", "")
                    if u and s:
                        jiffies.append(int(u) + int(s))
                k = val(row, "kernel_bgp")
                if k is not None and len(jiffies) == 2:
                    sig = (k, jiffies[0], jiffies[1])
                    if sig == stall_sig:
                        if stall_since is not None and \
                                mono - stall_since >= args.stall_after:
                            print(f"OBSERVE-STALL frozen {args.stall_after}s "
                                  f"at kernel={k}", file=sys.stderr)
                            break
                    else:
                        stall_sig = sig
                        stall_since = mono

            if args.complete_on != "none" and need:
                if args.complete_on == "kernel":
                    have = val(row, "kernel_bgp")
                else:
                    have = max(filter(None, (val(row, "main_prefixes"),
                                             val(row, "sut_pfxrcd"))),
                               default=None)
                if have is not None and have >= need:
                    complete_streak += 1
                    if complete_at is None:
                        complete_at = now
                    if complete_streak >= args.streak:
                        print(f"OBSERVE-COMPLETE {complete_at:.6f}",
                              file=sys.stderr)
                        time.sleep(args.settle)
                        row["t_host"] = f"{time.time():.6f}"
                        row["t_mono"] = f"{time.monotonic():.6f}"
                        for f in ("iter_ms", "kernel_ms", "main_ms",
                                  "proc_sut_ms", "proc_inj_ms"):
                            row[f] = ""
                        w.writerow(row)
                        break
                else:
                    complete_streak = 0
                    complete_at = None

            if stop_now():
                print("OBSERVE-STOPFILE", file=sys.stderr)
                break
            elapsed = time.time() - now
            if elapsed < args.interval:
                time.sleep(args.interval - elapsed)

    print(f"OBSERVE-DONE complete_at={complete_at} "
          f"first_route_at={first_route_at}", file=sys.stderr)


if __name__ == "__main__":
    main()
