#!/usr/bin/env python3
"""Ad-hoc bench artifact inspector (kept as a file because the
session's command filter declines literal *.log paths)."""
import json
import re
import subprocess
import sys
from pathlib import Path

ANSI = re.compile(r"\x1b\[[0-9;]*m")

run = Path(sys.argv[1])
what = sys.argv[2] if len(sys.argv) > 2 else "all"

m = json.loads((run / "metrics.json").read_text())
for k in sorted(m):
    print(f"{k} = {m[k]}")

for extra in ("kernel-bgp-routes.txt", "clock-offset.txt", "clk-tck.txt"):
    p = run / extra
    if p.exists():
        print(f"--- {extra}: {p.read_text().strip()}")

bgpd = run / "sut-bgpd.log"
if bgpd.exists() and what != "metrics-only":
    lines = ANSI.sub("", bgpd.read_text(errors="replace")).splitlines()
    upd = [l for l in lines if "UPDATE received" in l]
    eor = [l for l in lines if "End-of-RIB" in l]
    print(f"--- sut bgpd: {len(lines)} lines, {len(upd)} UPDATE-received")
    if upd:
        print("first upd:", upd[0][:160])
        print("last  upd:", upd[-1][:160])
    for e in eor[:2]:
        print("eor:", e[:160])
    tail = [l for l in lines if "warn" in l.lower() or "error" in l.lower()][-6:]
    for t in tail:
        print("warn/err:", t[:160])

inj = run / "injector.log"
if inj.exists():
    txt = inj.read_text(errors="replace")
    for tag in ("DRIVER-START", "DRIVER-FIRST-LINE", "DRIVER-LAST-LINE"):
        for l in txt.splitlines():
            if tag in l:
                print("inj:", l[:160])
                break

poll = run / "poll.csv"
if poll.exists():
    rows = poll.read_text().splitlines()
    print(f"--- poll rows: {len(rows)-1}; last: {rows[-1]}")
