#!/usr/bin/env python3
"""The E1 external observer: per-second poll of both bench containers.

One row per poll, written to a CSV; completion detection per SUT type:
  - rouster: rousterd main-table prefixes (native status dump
    /run/rouster/rousterd.status, refreshed at rousterd's 10 s
    reconcile cadence) + bgpd's own 'End-of-RIB received' log line.
  - frr:    vtysh 'show bgp ipv4 unicast summary json' pfxRcd +
    zebra's 'show ip route summary' main-table count.
  - rustybgp (Rust-baselines plan, 2026-10-21): the speaker's own
    received-prefix count over its GoBGP-v4 gRPC API (the gobgp CLI
    run host-side against the SUT's :50051). Speaker-level only: the
    default configuration programs no kernel FIB, so there is no
    main-table column; completion = received count at the target.
  - holo:   BGP-level curve from 'holo-cli -c "show bgp summary"'
    (Pfx Rcd/Acc), kernel-complete from a THIRD observer container
    sharing the SUT's netns but pinned off its cpuset, dumping
    'ip -4 route show proto 186 | wc -l' sequentially with a pacing
    gap (the 2026-10-19 E4 finding: tight in-netns dumps stall the
    install stream). Each dump's wall time is recorded per row so the
    completion-time quantization is on disk, not assumed.

Also samples /proc for the SUT daemons and the injector (CPU jiffies,
VmRSS/VmHWM) each poll — the E5 RSS series rides the same loop.

The CSV plus the raw per-poll /proc samples are the run's evidence;
bench-summarize.py folds them into the run metrics.

P0-b instrumentation (2026-10-16): every row carries a monotonic
iteration timestamp (t_mono) and the wall time of each subprocess
call in the loop (poll_iter_ms whole iteration; proc_sut_ms and
proc_inj_ms the /proc reads; status_ms/eor_ms the rouster status
file and EOR tail; vtysh_bgp_ms/vtysh_zebra_ms the FRR legs). This
is the timing evidence that separates "the observer's docker-exec
round-trips starved" from "the SUT stopped advancing the observed
value" — the poll-loss diagnosis turns on that distinction.
"""
import argparse
import csv
import re
import subprocess
import sys
import time

FIELDS = [
    "t_host",
    "t_mono",
    "sut_prefixes_main",
    "sut_eor_seen",
    "sut_pfxrcd",
    "sut_kernel_count",
    "kernel_dump_ms",
    "grpc_ms",
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
    "poll_iter_ms",
    "proc_sut_ms",
    "proc_inj_ms",
    "status_ms",
    "eor_ms",
    "vtysh_bgp_ms",
    "vtysh_zebra_ms",
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
PROC_HYBRID = (
    "for n in bgpd rousterd; do p=$(pidof $n | awk '{print $1}'); "
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
# rustybgp: the single speaker daemon.
PROC_RUSTYBGP = (
    "for n in rustybgpd; do p=$(pidof $n | awk '{print $1}'); "
    "[ -n \"$p\" ] || continue; "
    "a=$(awk '{print $14, $15}' /proc/$p/stat); "
    "r=$(awk '/VmRSS/{print $2}' /proc/$p/status); "
    "h=$(awk '/VmHWM/{print $2}' /proc/$p/status); "
    "echo \"$n $a $r $h\"; done"
)
# holo: holod is one process hosting speaker and core; its numbers are
# the whole-suite numbers (tagged sut_bgpd; the zebra column stays empty).
PROC_HOLO = (
    "for n in holod; do p=$(pidof $n | awk '{print $1}'); "
    "[ -n \"$p\" ] || continue; "
    "a=$(awk '{print $14, $15}' /proc/$p/stat); "
    "r=$(awk '/VmRSS/{print $2}' /proc/$p/status); "
    "h=$(awk '/VmHWM/{print $2}' /proc/$p/status); "
    "echo \"$n $a $r $h\"; done"
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
    """sh() plus the call's wall time in ms (the P0-b evidence)."""
    t0 = time.monotonic()
    out = sh(container, body, timeout)
    return out, round((time.monotonic() - t0) * 1000.0, 3)


def parse_proc(text):
    """'name utime stime rss hwm' lines -> dict keyed by name."""
    d = {}
    for line in text.splitlines():
        parts = line.split()
        if len(parts) == 5:
            d[parts[0]] = parts[1:5]
    return d


def poll_rouster(sut, status_file, bgpd_log):
    text, status_ms = timed_sh(sut, f"cat {status_file} 2>/dev/null")
    prefixes = ""
    m = re.search(r"^table 254 routes \d+ prefixes (\d+)", text, re.M)
    if m:
        prefixes = m.group(1)
    tail, eor_ms = timed_sh(sut, f"tail -c 65536 {bgpd_log} 2>/dev/null")
    eor = "yes" if "End-of-RIB received" in tail else "no"
    return prefixes, eor, status_ms, eor_ms


def poll_frr(sut):
    out, vtysh_bgp_ms = timed_sh(
        sut, "vtysh -c 'show bgp ipv4 unicast summary json' 2>/dev/null")
    m = re.search(r'"pfxRcd"\s*:\s*(\d+)', out)
    pfxrcd = m.group(1) if m else ""
    zout, vtysh_zebra_ms = timed_sh(
        sut, "vtysh -c 'show ip route summary' 2>/dev/null")
    zm = re.search(r"^Totals\s+(\d+)", zout, re.M)
    # FRR 10.2 zebra summary: per-source rows then "Totals <routes> <fib>"
    return (pfxrcd, (zm.group(1) if zm else ""),
            vtysh_bgp_ms, vtysh_zebra_ms)


def poll_rustybgp(gobgp_bin, sut_ip, inj_ip):
    """Speaker table count over the GoBGP-v4 gRPC API. Uses the
    global RIB summary aggregate (Destination count = the actual
    table size, not the neighbor Received counter, which can run
    ahead of table insertion in RustyBGP's pipeline); the neighbor
    detail's Received/Accepted are captured at run end. Runs
    host-side (a TCP client of the SUT's :50051), not in the SUT's
    cpuset."""
    t0 = time.monotonic()
    try:
        out = subprocess.run(
            [gobgp_bin, "-u", sut_ip, "-p", "50051",
             "global", "rib", "summary", "-a", "ipv4"],
            capture_output=True, text=True, timeout=20,
        ).stdout
    except subprocess.TimeoutExpired:
        out = ""
    ms = round((time.monotonic() - t0) * 1000.0, 3)
    # "Destination: 2000, Path: 2000"
    m = re.search(r"Destination:\s*(\d+)", out)
    return (m.group(1) if m else ""), ms


def poll_holo_bgp(sut):
    """Pfx Rcd/Acc for the injector peer from holo-cli. NOT called
    mid-run (see the holo branch in main); kept for post-settle use."""
    out, ms = timed_sh(
        sut,
        "timeout 20 holo-cli -a http://127.0.0.1:50051 "
        "-c 'show bgp summary' 2>/dev/null")
    m = re.search(r"\|\s*(\d+)\s*/\s*(\d+)\s*\|", out)
    return (m.group(1) if m else "", ms)


class KernelObserver:
    """Sequential proto-tagged kernel route dumps in the observer
    container (shares the SUT netns, pinned off the SUT cpuset), one
    dump at a time with --kernel-pace seconds between dumps. The dump
    itself is the 2026-10-19 E4-disclosed RTNL cost; pacing it and
    recording its wall time keeps that cost disclosed per row."""

    def __init__(self, obs_container, proto, pace):
        self.obs = obs_container
        self.proto = proto
        self.pace = pace
        self.latest = None      # (count, dump_ms, t_host)
        self.stop = False
        self.thread = None

    def _loop(self):
        while not self.stop:
            t0 = time.monotonic()
            out = sh(self.obs, f"ip -4 route show proto {self.proto} | wc -l")
            ms = round((time.monotonic() - t0) * 1000.0, 3)
            m = re.search(r"(\d+)", out or "")
            if m:
                self.latest = (m.group(1), ms, time.time())
            time.sleep(self.pace)

    def start(self):
        import threading
        self.thread = threading.Thread(target=self._loop, daemon=True)
        self.thread.start()

    def sample(self):
        return self.latest or ("", "", "")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--sut-container", required=True)
    ap.add_argument("--inj-container", required=True)
    ap.add_argument("--mode", choices=["rouster", "frr", "hybrid", "rustybgp", "holo"], required=True)
    ap.add_argument("--target-count", type=int, required=True)
    ap.add_argument("--timeout", type=int, default=3600)
    ap.add_argument("--settle", type=int, default=30)
    ap.add_argument("--interval", type=float, default=1.0)
    ap.add_argument("--csv", required=True)
    ap.add_argument("--status-file", default="/run/rouster/rousterd.status")
    ap.add_argument("--bgpd-log", default="/var/log/rouster-bgpd.log")
    # rustybgp mode: the gobgp (v4 API) CLI on the host + the SUT/injector
    # addresses it queries.
    ap.add_argument("--gobgp-bin", default="gobgp")
    ap.add_argument("--sut-ip", default="172.31.255.20")
    ap.add_argument("--inj-ip", default="172.31.255.10")
    # holo mode: the kernel-count observer container (shares the SUT
    # netns, pinned off the SUT cpuset), the proto tag, and the pacing
    # gap between sequential dumps.
    ap.add_argument("--obs-container", default="")
    ap.add_argument("--kernel-proto", default="186")
    ap.add_argument("--kernel-pace", type=float, default=2.0)
    # P0-b stall guard (rouster mode): after EOR is seen, a run whose
    # main-table count AND both SUT daemons' CPU jiffies are all frozen
    # for this many seconds is declared wedged (POLL-STALL) instead of
    # burning the full timeout — the 2026-10-15/16 post-F8 signature.
    # A healthy full-table run advances every status refresh (~10 s);
    # 180 s of total freeze after EOR is unambiguous at this scale.
    # 0 disables. FRR mode ignores it.
    ap.add_argument("--stall-after", type=int, default=180)
    args = ap.parse_args()

    proc_sut = {
        "rouster": PROC_ROUSTER,
        "hybrid": PROC_HYBRID,
        "rustybgp": PROC_RUSTYBGP,
        "holo": PROC_HOLO,
    }.get(args.mode, PROC_FRR)
    kernel_obs = None
    if args.mode == "holo" and args.obs_container:
        kernel_obs = KernelObserver(
            args.obs_container, args.kernel_proto, args.kernel_pace)
        kernel_obs.start()
    complete_at = None
    eor_at = None
    eor_seen_sticky = False
    complete_streak = 0
    stall_sig = None      # (prefixes, bgpd jiffies, zebra jiffies)
    stall_since = None
    t_start = time.time()

    with open(args.csv, "w", newline="") as fh:
        w = csv.DictWriter(fh, FIELDS)
        w.writeheader()
        while True:
            now = time.time()
            mono = time.monotonic()
            if now - t_start > args.timeout:
                print("POLL-TIMEOUT", file=sys.stderr)
                break
            row = {f: "" for f in FIELDS}
            row["t_host"] = f"{now:.6f}"
            row["t_mono"] = f"{mono:.6f}"

            sut_proc, row["proc_sut_ms"] = timed_sh(
                args.sut_container, proc_sut)
            inj_proc, row["proc_inj_ms"] = timed_sh(
                args.inj_container, PROC_INJ)
            sut_p = parse_proc(sut_proc)
            inj_p = parse_proc(inj_proc)
            for name, tag in (("rouster-bgpd", "sut_bgpd"), ("rousterd", "sut_zebra"),
                              ("bgpd", "sut_bgpd"), ("zebra", "sut_zebra"),
                              ("rustybgpd", "sut_bgpd"), ("holod", "sut_bgpd"),
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

            if args.mode in ("rouster", "hybrid"):
                (prefixes, eor, row["status_ms"],
                 row["eor_ms"]) = poll_rouster(
                    args.sut_container, args.status_file, args.bgpd_log)
                if args.mode == "hybrid":
                    # The BGP-level curve from the FRR speaker (the
                    # main-table completion oracle stays the rousterd
                    # status file, symmetric with config D).
                    (pfxrcd_h, _z, row["vtysh_bgp_ms"],
                     row["vtysh_zebra_ms"]) = poll_frr(args.sut_container)
                    row["sut_pfxrcd"] = pfxrcd_h
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
            elif args.mode == "rustybgp":
                # Speaker-level only: the received-prefix count over
                # gRPC is both the curve and the completion oracle
                # (no kernel table exists in the default config).
                pfxrcd, row["grpc_ms"] = poll_rustybgp(
                    args.gobgp_bin, args.sut_ip, args.inj_ip)
                row["sut_pfxrcd"] = pfxrcd
                need = args.target_count - max(2, args.target_count // 200)
                done = pfxrcd.isdigit() and int(pfxrcd) >= need
            elif args.mode == "holo":
                # Kernel-complete from the paced observer dumps (the
                # completion oracle). NO mid-run holo-cli calls: a
                # northbound gRPC session racing the ingest trips a
                # holod v0.9.0 panic (well-known-community YANG
                # serialization — iana-bgp-community-types identity
                # unresolvable), reproduced 3/3 with CLI polling and
                # clean 3/3 without; the receipt discloses this. The
                # BGP-level pfxrcd curve is captured once at run end.
                kcount, kms, _kt = kernel_obs.sample() if kernel_obs else ("", "", "")
                row["sut_kernel_count"] = kcount
                row["kernel_dump_ms"] = kms
                row["sut_prefixes_main"] = kcount
                need = args.target_count - max(2, args.target_count // 200)
                done = str(kcount).isdigit() and int(kcount) >= need
            else:
                (pfxrcd, ztotal, row["vtysh_bgp_ms"],
                 row["vtysh_zebra_ms"]) = poll_frr(args.sut_container)
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

            row["poll_iter_ms"] = round(
                (time.monotonic() - mono) * 1000.0, 3)
            w.writerow(row)
            fh.flush()

            # P0-b stall guard (rouster mode, post-EOR only): frozen
            # count + frozen CPU on both daemons for --stall-after
            # seconds = the wedged-SUT signature; fail fast instead
            # of burning the timeout. Missing values reset the timer.
            if args.mode in ("rouster", "hybrid") and args.stall_after and eor_at is not None:
                jiffies = []
                for tag in ("sut_bgpd", "sut_zebra"):
                    u, s = row.get(f"{tag}_utime", ""), row.get(f"{tag}_stime", "")
                    if u and s:
                        jiffies.append(int(u) + int(s))
                if prefixes.isdigit() and len(jiffies) == 2:
                    sig = (prefixes, jiffies[0], jiffies[1])
                    if sig == stall_sig:
                        if stall_since is not None and \
                                mono - stall_since >= args.stall_after:
                            print(
                                f"POLL-STALL frozen {args.stall_after}s "
                                f"after EOR at prefixes={prefixes}",
                                file=sys.stderr)
                            break
                    else:
                        stall_sig = sig
                        stall_since = mono
                else:
                    stall_sig = None
                    stall_since = None

            if done:
                complete_streak += 1
                if complete_at is None:
                    complete_at = now
                if complete_streak >= 3:
                    print(f"POLL-COMPLETE {complete_at:.6f}", file=sys.stderr)
                    time.sleep(args.settle)
                    # one final row after settle for final RSS; no observer
                    # calls happen in the settle window, so the per-call
                    # timing columns are blanked rather than left stale.
                    row["t_host"] = f"{time.time():.6f}"
                    row["t_mono"] = f"{time.monotonic():.6f}"
                    for f in ("poll_iter_ms", "proc_sut_ms", "proc_inj_ms",
                              "status_ms", "eor_ms", "vtysh_bgp_ms",
                              "vtysh_zebra_ms", "kernel_dump_ms", "grpc_ms"):
                        row[f] = ""
                    if kernel_obs:
                        # the settled kernel count (the observer kept
                        # dumping through the settle window)
                        kcount, _kms, _kt = kernel_obs.sample()
                        row["sut_kernel_count"] = kcount
                        row["sut_prefixes_main"] = kcount
                    w.writerow(row)
                    break
            else:
                complete_streak = 0
            elapsed = time.time() - now
            if elapsed < args.interval:
                time.sleep(args.interval - elapsed)

    if kernel_obs:
        kernel_obs.stop = True
    print(
        f"POLL-DONE complete_at={complete_at} eor_at={eor_at} "
        f"rows={len(FIELDS)}",
        file=sys.stderr,
    )


if __name__ == "__main__":
    main()
