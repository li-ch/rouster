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
    """Scripted event-sequence driver (the E1 differential cell).

    --ops is a comma list; each op:
      A            announce the whole table
      W<n>         withdraw every nth prefix (1-based index % n == 0)
      R<n>         re-announce every nth prefix with a novel community
                   (replacement semantics; same prefixes, new attrs)
      X            close the session (socket close)
    Markers SEQ-<op>-<seq>-BEGIN/DONE with counts are printed per op.
    """
    ap = argparse.ArgumentParser()
    ap.add_argument("--peer", required=True)
    ap.add_argument("--local-as", type=int, default=65412)
    ap.add_argument("--peer-as", type=int, default=65000)
    ap.add_argument("--router-id", required=True)
    ap.add_argument("--announce", required=True)
    ap.add_argument("--limit", type=int, default=10000)
    ap.add_argument("--hold", type=int, default=90)
    ap.add_argument("--pack", type=int, default=64)
    ap.add_argument("--ops", required=True)
    ap.add_argument("--novel-as", type=int, default=65412)
    ap.add_argument("--gap", type=float, default=2.0)
    args = ap.parse_args()

    entries = []
    with open(args.announce, errors="replace") as fh:
        for line in fh:
            if len(entries) >= args.limit:
                break
            m = LINE_RE.match(line.strip())
            if m:
                entries.append((m.group(1), Attrs(m)))
    if not entries:
        print("SEQ-ERROR no parseable announce lines", file=sys.stderr, flush=True)
        return 1
    log(f"SEQ-PARSED routes={len(entries)}")

    sock = None
    send_lock = threading.Lock()
    running = True

    def connect():
        nonlocal sock, running
        running = True
        s = socket.create_connection(
            (args.peer.split(":")[0], int(args.peer.split(":")[1])), timeout=30)
        s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        s.settimeout(120)
        sock = s
        s.sendall(bgp_frame(1, open_body(args.local_as, args.hold, args.router_id)))
        t, body = read_frame(s)
        if t != 1:
            print(f"SEQ-ERROR expected OPEN got {t}", file=sys.stderr, flush=True)
            return False
        s.sendall(bgp_frame(4, b""))
        t, _ = read_frame(s)
        if t != 4:
            print(f"SEQ-ERROR expected KEEPALIVE got {t}", file=sys.stderr, flush=True)
            return False
        log("SEQ-ESTABLISHED")
        return True

    def reader():
        nonlocal running
        try:
            while True:
                t, body = read_frame(sock)
                if t == 4:
                    try:
                        with send_lock:
                            sock.sendall(bgp_frame(4, b""))
                    except OSError:
                        return
                elif t == 3:
                    print(f"SEQ-NOTIFICATION code={body[0] if body else -1}",
                          file=sys.stderr, flush=True)
                    running = False
                    return
        except (ConnectionError, OSError):
            running = False

    def ka_timer():
        period = max(args.hold / 3.0, 5.0)
        while True:
            time.sleep(period)
            try:
                with send_lock:
                    sock.sendall(bgp_frame(4, b""))
            except OSError:
                return

    def send_grouped(items):
        msgs = 0; routes = 0; cur = None; nlris = []
        def flush():
            nonlocal msgs, routes, cur, nlris
            if not nlris:
                return
            attr_bytes = cur.encode()
            body = b"\x00\x00" + len(attr_bytes).to_bytes(2, "big") \
                + attr_bytes + b"".join(nlris)
            with send_lock:
                sock.sendall(bgp_frame(2, body))
            msgs += 1; routes += len(nlris); nlris = []
        for prefix, a in items:
            if cur is not None and (a.key() != cur.key() or len(nlris) >= args.pack):
                flush()
            cur = a
            nlris.append(nlri(prefix))
        flush()
        return routes, msgs

    def send_withdraws(prefixes):
        msgs = 0
        for i in range(0, len(prefixes), 200):
            chunk = prefixes[i:i + 200]
            wlri = b"".join(nlri(p) for p in chunk)
            body = len(wlri).to_bytes(2, "big") + wlri + b"\x00\x00"
            with send_lock:
                sock.sendall(bgp_frame(2, body))
            msgs += 1
        return msgs

    if not connect():
        return 1
    threading.Thread(target=reader, daemon=True).start()
    threading.Thread(target=ka_timer, daemon=True).start()

    novel_seq = 0
    for op in args.ops.split(","):
        if not running:
            log(f"SEQ-OP-{op}-SKIPPED session lost")
            break
        log(f"SEQ-OP-{op}-BEGIN")
        if op == "A":
            r, m = send_grouped(entries)
            with send_lock:
                sock.sendall(bgp_frame(2, b"\x00\x00\x00\x00"))
            log(f"SEQ-OP-A-DONE routes={r} msgs={m + 1}")
        elif op.startswith("W") or op.startswith("R"):
            n = int(op[1:])
            subset = [e for i, e in enumerate(entries) if (i + 1) % n == 0]
            if op.startswith("W"):
                m = send_withdraws([p for p, _ in subset])
                log(f"SEQ-OP-{op}-DONE prefixes={len(subset)} msgs={m}")
            else:
                novel_seq += 1
                novel = [(p, a.with_community(args.novel_as, 900 + novel_seq))
                         for p, a in subset]
                r, m = send_grouped(novel)
                log(f"SEQ-OP-{op}-DONE prefixes={len(subset)} routes={r} msgs={m} novel_seq={novel_seq}")
        elif op == "X":
            with send_lock:
                try:
                    sock.sendall(bgp_frame(3, b""))  # NOTIFY close
                except OSError:
                    pass
                try:
                    sock.close()
                except OSError:
                    pass
            running = False
            log("SEQ-OP-X-DONE closed")
            time.sleep(args.gap)
            if not connect():
                return 1
            threading.Thread(target=reader, daemon=True).start()
            threading.Thread(target=ka_timer, daemon=True).start()
        else:
            print(f"SEQ-ERROR unknown op {op}", file=sys.stderr, flush=True)
            return 1
        time.sleep(args.gap)
    log("SEQ-ALL-DONE")
    time.sleep(3)
    try:
        sock.close()
    except OSError:
        pass
    return 0


if __name__ == "__main__":
    sys.exit(main())
