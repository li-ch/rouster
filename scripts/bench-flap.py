#!/usr/bin/env python3
"""bench-flap.py — the E2 churn injector (S14-b PERF-X stream).

A minimal single-session BGP speaker that drives the E2 flap storm:
it announces the pinned table (the bench-mrt2announce.py derivative
of the §R route-views dump — same surgery as mrt-replay: NEXT_HOP
rewritten to the injector address, the injector AS prepended), then
for R rounds withdraws and re-announces a fixed subset of the table
(every Nth prefix). Identical on both SUTs (the §F fairness rule:
the injector actions are the same bytes on the same schedule).

Why a Python injector: the in-repo mrt-replay (the E1 injector) has
no withdraw mode and its session lingers uncontrolled — E2 needs
protocol-level withdraw+reannounce bursts on the SAME session that
announced the table. This tool is that one addition; the announce
side mirrors mrt-replay's packing (consecutive same-attribute routes
packed to --pack prefixes per UPDATE, lowest-peer-index pick already
baked into the announce file).

Emit lines (all wall=<epoch seconds>, stderr, flushed):
  FLAP-ESTABLISHED / FLAP-ANNOUNCED (routes msgs) / FLAP-EOR /
  FLAP-STEADY / per round: FLAP-ROUND-<r>-WITHDRAW-START,
  -WITHDRAW-DONE, -ANNOUNCE-START, -ANNOUNCE-DONE /
  FLAP-ROUNDS-DONE / FLAP-LINGER-END.
The summarizer joins these marks against bench-observe.py's count
series to compute per-round reconvergence walls.
"""
import argparse
import copy
import re
import socket
import sys
import threading
import time

LINE_RE = re.compile(
    r"^announce route (\d+\.\d+\.\d+\.\d+/\d+) next-hop (\d+\.\d+\.\d+\.\d+)"
    r"(?: med (\d+))?(?: as-path \[([^\]]*)\])?"
    r"(?: origin (\w+))?(?: community \[([^\]]*)\])?"
    r"(?: large-community \[([^\]]*)\])?"
)


def now():
    return time.time()


def log(msg):
    print(f"{msg} wall={now():.6f}", flush=True)


def bgp_frame(msg_type, body):
    return b"\xff" * 16 + (19 + len(body)).to_bytes(2, "big") + bytes([msg_type]) + body


def open_body(asn, hold, router_id):
    caps = bytes([65, 4]) + asn.to_bytes(4, "big") + bytes([2, 0])
    b = bytearray()
    b.append(4)
    b += (asn & 0xFFFF).to_bytes(2, "big")
    b += hold.to_bytes(2, "big")
    b += bytes(int(x) for x in router_id.split("."))
    b.append(2 + len(caps))
    b.append(2)
    b.append(len(caps))
    b += caps
    return bytes(b)


def nlri(prefix):
    addr, plen = prefix.split("/")
    plen = int(plen)
    nbytes = (plen + 7) // 8
    return bytes([plen]) + bytes(int(x) for x in addr.split(".")[:nbytes])


def attr(flags, atype, value):
    if len(value) > 255 or flags & 0x10:
        return bytes([flags | 0x10 if len(value) > 255 else flags, atype]) \
            + len(value).to_bytes(2, "big") + value
    return bytes([flags, atype, len(value)]) + value


class Attrs:
    """Path attributes parsed from one announce line; the tuple of
    raw fields is the packing key (identical keys share an UPDATE)."""

    def __init__(self, m):
        self.next_hop = m.group(2)
        self.med = m.group(3)
        self.as_path = m.group(4).split() if m.group(4) else []
        origin = m.group(5) or "igp"
        self.origin = {"igp": 0, "egp": 1, "incomplete": 2}[origin]
        self.communities = m.group(6).split() if m.group(6) else []
        self.large = m.group(7).split() if m.group(7) else []

    def with_community(self, asn, val):
        """A copy of these attrs plus one community (asn, val) — the
        E7 novelty lever: each round/cycle mints tuples never seen
        before, exercising the intern stores' sweep-and-plateau path."""
        clone = copy.copy(self)
        clone.communities = list(self.communities) + [f"{asn}:{val}"]
        return clone

    def key(self):
        return (self.next_hop, self.med, tuple(self.as_path), self.origin,
                tuple(self.communities), tuple(self.large))

    def encode(self):
        out = b""
        out += attr(0x40, 1, bytes([self.origin]))
        # exabgp notation: bare ASNs form AS_SEQUENCE runs, parenthesized
        # groups are AS_SETs (RFC 4271 §4.3; only 16 of 100k feed lines).
        seq, segs = [], []
        for mset, masn in re.findall(r"\(([^)]*)\)|(\d+)", " ".join(self.as_path)):
            if mset is not None and mset != "":
                if seq:
                    segs.append((2, seq))
                    seq = []
                segs.append((1, mset.split()))
            elif masn:
                seq.append(masn)
        if seq:
            segs.append((2, seq))
        path = b""
        for stype, members in segs:
            # a segment carries at most 255 ASNs (RFC 4271 §4.3)
            for i in range(0, len(members), 255):
                chunk = members[i:i + 255]
                path += bytes([stype, len(chunk)])
                for a in chunk:
                    path += int(a).to_bytes(4, "big")
        out += attr(0x40, 2, path)
        out += attr(0x40, 3, bytes(int(x) for x in self.next_hop.split(".")))
        if self.med is not None:
            out += attr(0x80, 4, int(self.med).to_bytes(4, "big"))
        if self.communities:
            # each community is two 16-bit values (RFC 1997)
            v = b"".join(
                ((int(parts[0]) << 16) | int(parts[1])).to_bytes(4, "big")
                for parts in (c.split(":") for c in self.communities))
            out += attr(0xC0, 8, v)
        if self.large:
            # three 32-bit values each (RFC 8092)
            v = b"".join(
                b"".join(int(p).to_bytes(4, "big") for p in lc.split(":"))
                for lc in self.large)
            out += attr(0xC0, 32, v)
        return out


def read_frame(sock):
    hdr = b""
    while len(hdr) < 19:
        chunk = sock.recv(19 - len(hdr))
        if not chunk:
            raise ConnectionError("peer closed")
        hdr += chunk
    length = int.from_bytes(hdr[16:18], "big")
    body = b""
    while len(body) < length - 19:
        chunk = sock.recv(length - 19 - len(body))
        if not chunk:
            raise ConnectionError("peer closed mid-body")
        body += chunk
    return hdr[18], body


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--peer", required=True)
    ap.add_argument("--local-as", type=int, default=65412)
    ap.add_argument("--peer-as", type=int, default=65000)
    ap.add_argument("--router-id", required=True)
    ap.add_argument("--announce", required=True)
    ap.add_argument("--limit", type=int, default=100000)
    ap.add_argument("--flap-every", type=int, default=10,
                    help="withdraw/reannounce every Nth prefix")
    ap.add_argument("--rounds", type=int, default=10)
    ap.add_argument("--hold", type=int, default=90)
    ap.add_argument("--pack", type=int, default=64)
    ap.add_argument("--withdraw-pack", type=int, default=200)
    ap.add_argument("--steady-wait", type=float, default=15.0)
    ap.add_argument("--round-gap", type=float, default=2.0)
    ap.add_argument("--linger", type=float, default=20.0)
    # E7 long-lived-memory shape: --novel-rounds makes every round's
    # re-announcement carry a per-round unique community (novel intern
    # tuples each round); --full-cycles appends that many full-table
    # withdraw/re-announce cycles (novel tuples each cycle when
    # --novel-rounds is set).
    ap.add_argument("--novel-rounds", action="store_true")
    ap.add_argument("--novel-comm-as", type=int, default=65412)
    ap.add_argument("--full-cycles", type=int, default=0)
    args = ap.parse_args()

    entries = []  # (prefix_str, Attrs)
    with open(args.announce, errors="replace") as fh:
        for line in fh:
            if len(entries) >= args.limit:
                break
            m = LINE_RE.match(line.strip())
            if m:
                entries.append((m.group(1), Attrs(m)))
    if not entries:
        print("FLAP-ERROR no parseable announce lines", file=sys.stderr, flush=True)
        return 1
    log(f"FLAP-PARSED routes={len(entries)}")

    subset = [e for i, e in enumerate(entries) if i % args.flap_every == 0]
    print(f"FLAP-SUBSET size={len(subset)} every={args.flap_every}",
          file=sys.stderr, flush=True)

    sock = socket.create_connection(
        (args.peer.split(":")[0], int(args.peer.split(":")[1])), timeout=30)
    sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    sock.settimeout(120)
    send_lock = threading.Lock()

    def send(frame):
        with send_lock:
            sock.sendall(frame)

    sock.sendall(bgp_frame(1, open_body(args.local_as, args.hold, args.router_id)))
    t, body = read_frame(sock)
    if t != 1:
        print(f"FLAP-ERROR expected OPEN got {t}", file=sys.stderr, flush=True)
        return 1
    sock.sendall(bgp_frame(4, b""))
    t, _ = read_frame(sock)
    if t != 4:
        print(f"FLAP-ERROR expected KEEPALIVE got {t}", file=sys.stderr, flush=True)
        return 1
    log("FLAP-ESTABLISHED")

    running = True

    def reader():
        """Answer KEEPALIVEs; record NOTIFICATION and exit."""
        nonlocal running
        try:
            while True:
                t, body = read_frame(sock)
                if t == 4:
                    try:
                        send(bgp_frame(4, b""))
                    except OSError:
                        return
                elif t == 3:
                    print(f"FLAP-NOTIFICATION code={body[0] if body else -1} "
                          f"subcode={body[1] if len(body) > 1 else -1}",
                          file=sys.stderr, flush=True)
                    running = False
                    return
        except (ConnectionError, OSError):
            running = False

    threading.Thread(target=reader, daemon=True).start()

    def ka_timer():
        period = max(args.hold / 3.0, 5.0)
        while True:
            time.sleep(period)
            try:
                send(bgp_frame(4, b""))
            except OSError:
                return

    threading.Thread(target=ka_timer, daemon=True).start()

    def send_grouped(items, kind):
        """items: [(prefix, Attrs)] — announce packing (mrt-replay's:
        consecutive identical attrs up to --pack per UPDATE)."""
        msgs = 0
        routes = 0
        cur = None
        nlris = []

        def flush():
            nonlocal msgs, routes, cur, nlris
            if not nlris:
                return
            attr_bytes = cur.encode()
            body = b"\x00\x00" + len(attr_bytes).to_bytes(2, "big") \
                + attr_bytes + b"".join(nlris)
            send(bgp_frame(2, body))
            msgs += 1
            routes += len(nlris)
            nlris = []

        for prefix, a in items:
            if cur is not None and (a.key() != cur.key() or len(nlris) >= args.pack):
                flush()
            cur = a
            nlris.append(nlri(prefix))
        flush()
        return routes, msgs

    def send_withdraws(prefixes):
        """Withdraw-only UPDATEs, --withdraw-pack NLRI per message."""
        msgs = 0
        for i in range(0, len(prefixes), args.withdraw_pack):
            chunk = prefixes[i:i + args.withdraw_pack]
            wlri = b"".join(nlri(p) for p in chunk)
            body = len(wlri).to_bytes(2, "big") + wlri + b"\x00\x00"
            send(bgp_frame(2, body))
            msgs += 1
        return msgs

    log(f"FLAP-ANNOUNCE-START routes={len(entries)}")
    routes, msgs = send_grouped(entries, "announce")
    send(bgp_frame(2, b"\x00\x00\x00\x00"))  # EOR
    log(f"FLAP-ANNOUNCED routes={routes} msgs={msgs + 1}")

    time.sleep(args.steady_wait)
    log("FLAP-STEADY")

    for r in range(1, args.rounds + 1):
        prefixes = [p for p, _ in subset]
        log(f"FLAP-ROUND-{r}-WITHDRAW-START prefixes={len(prefixes)}")
        wmsgs = send_withdraws(prefixes)
        log(f"FLAP-ROUND-{r}-WITHDRAW-DONE msgs={wmsgs}")
        time.sleep(args.round_gap)
        log(f"FLAP-ROUND-{r}-ANNOUNCE-START")
        if args.novel_rounds:
            novel = [(p, a.with_community(args.novel_comm_as, r))
                     for p, a in subset]
        else:
            novel = subset
        routes, msgs = send_grouped(novel, "announce")
        log(f"FLAP-ROUND-{r}-ANNOUNCE-DONE routes={routes} msgs={msgs}"
            f" novel={args.novel_rounds}")
        time.sleep(args.round_gap)
        if not running:
            print(f"FLAP-ABORT round={r} session lost", file=sys.stderr, flush=True)
            return 1
    log("FLAP-ROUNDS-DONE")

    for c in range(1, args.full_cycles + 1):
        log(f"FLAP-CYCLE-{c}-FULL-WITHDRAW-START prefixes={len(entries)}")
        wmsgs = send_withdraws([p for p, _ in entries])
        log(f"FLAP-CYCLE-{c}-FULL-WITHDRAW-DONE msgs={wmsgs}")
        time.sleep(args.round_gap)
        if args.novel_rounds:
            cyc = [(p, a.with_community(args.novel_comm_as, 10000 + c))
                   for p, a in entries]
        else:
            cyc = entries
        routes, msgs = send_grouped(cyc, "announce")
        send(bgp_frame(2, b"\x00\x00\x00\x00"))
        log(f"FLAP-CYCLE-{c}-REANNOUNCED routes={routes} msgs={msgs + 1}")
        time.sleep(args.round_gap)
        if not running:
            print(f"FLAP-ABORT cycle={c} session lost", file=sys.stderr, flush=True)
            return 1
    if args.full_cycles:
        # settle on a full, stable table so the final RSS is the
        # post-churn plateau the E7 question asks about.
        time.sleep(args.steady_wait)
        log("FLAP-POST-CYCLE-STEADY")

    time.sleep(args.linger)
    log("FLAP-LINGER-END")
    try:
        sock.close()
    except OSError:
        pass
    return 0


if __name__ == "__main__":
    sys.exit(main())
