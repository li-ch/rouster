#!/usr/bin/env python3
"""The exabgp API driver for the E1 replay bench.

exabgp runs this process (docker/bench/exabgp-*.conf wires it as the
`replay` process, encoder text); it writes announce lines to stdout
and exabgp turns each into a BGP UPDATE.

Env:
  FEED       path to the announce file (one `announce route ...` line
             per prefix, produced by scripts/bench-mrt2announce.py)
  REPLAY_RATE  target lines/s; 0 or unset = unlimited (the S0 gate
             shape). Pacing is coarse (burst-sleep), sufficient for
             E1's single-shot replay shape.

Observability: one stderr line at start, at the first line, and at
the last line written (host-time monotonic + wall clock), so the
injector side of first-UPDATE/last-UPDATE is timestamped
independently of the SUT.
"""
import os
import sys
import time

feed = os.environ["FEED"]
rate = float(os.environ.get("REPLAY_RATE", "0"))

t0 = time.time()
print(f"DRIVER-START mono={time.monotonic():.6f} wall={t0:.6f}", file=sys.stderr, flush=True)
with open(feed, "r", buffering=1024 * 1024) as f:
    sent = 0
    burst = max(1, int(rate / 20)) if rate else 0
    for line in f:
        if sent == 0:
            print(
                f"DRIVER-FIRST-LINE mono={time.monotonic():.6f} wall={time.time():.6f}",
                file=sys.stderr,
                flush=True,
            )
        sys.stdout.write(line)
        sent += 1
        if burst and sent % burst == 0:
            time.sleep(0.05)
    sys.stdout.flush()
print(
    f"DRIVER-LAST-LINE mono={time.monotonic():.6f} wall={time.time():.6f} lines={sent}",
    file=sys.stderr,
    flush=True,
)
# Keep the process alive briefly so exabgp's reads drain cleanly.
time.sleep(30)
