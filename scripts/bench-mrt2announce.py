#!/usr/bin/env python3
"""MRT TABLE_DUMP_V2 (RFC 6396) RIB dump -> exabgp announce-file converter.

Reads a route-views style rib.*.bz2 (or raw) TABLE_DUMP_V2 dump,
picks ONE deterministic path per IPv4-unicast prefix (the entry with
the lowest peer index — deterministic across runs), rewrites NEXT_HOP
to a parameterized injector address, and writes exabgp text-API
announce lines.

Attribute rule (recorded for the ledger): keep ORIGIN, AS_PATH, MED,
COMMUNITY, LARGE_COMMUNITY; drop the rest (AGGREGATOR, etc.).

Usage:
  mrt2announce.py <dump.(bz2|mrt)> <out.announce> [--next-hop A.B.C.D]
                  [--limit N] [--offset N] [--stats-out FILE]
"""
import argparse
import bz2
import ipaddress
import json
import struct
import sys

TABLE_DUMP_V2 = 13
RIB_IPV4_UNICAST = 2  # RFC 6396: 1=PEER_INDEX_TABLE, 2=RIB_IPV4_UNICAST


def open_mrt(path):
    if path.endswith(".bz2"):
        return bz2.open(path, "rb")
    return open(path, "rb")


def parse_attrs(data):
    """BGP path attributes -> dict of parsed values we keep."""
    out = {}
    i = 0
    n = len(data)
    while i + 3 <= n:
        flags = data[i]
        atype = data[i + 1]
        i += 2
        if flags & 0x10:  # extended length
            alen = struct.unpack_from("!H", data, i)[0]
            i += 2
        else:
            alen = data[i]
            i += 1
        raw = data[i : i + alen]
        i += alen
        if atype == 1:  # ORIGIN
            out["origin"] = {0: "igp", 1: "egp", 2: "incomplete"}.get(
                raw[0], "incomplete"
            )
        elif atype == 2:  # AS_PATH (assume 4-byte ASNs, route-views modern)
            segs = []
            j = 0
            while j + 2 <= len(raw) and alen >= 6:
                stype = raw[j]
                slen = raw[j + 1]
                j += 2
                asn = " ".join(
                    str(x) for x in struct.unpack_from(f"!{slen}I", raw, j)
                )
                j += 4 * slen
                if stype == 2:  # AS_SEQUENCE
                    segs.append(asn)
                elif stype == 1:  # AS_SET
                    segs.append(f"({asn})")
            out["as_path"] = " ".join(segs)
            out["as_path_raw"] = raw
        elif atype == 3:  # NEXT_HOP (recorded, rewritten at emit time)
            out["next_hop_raw"] = raw
        elif atype == 4:  # MED
            out["med"] = struct.unpack("!I", raw)[0] if len(raw) == 4 else None
        elif atype == 8:  # COMMUNITY
            comms = []
            for k in range(0, len(raw) - 1, 4):
                hi, lo = struct.unpack_from("!HH", raw, k)
                comms.append(f"{hi}:{lo}")
            out["community"] = " ".join(comms)
        elif atype == 32:  # LARGE_COMMUNITY
            comms = []
            for k in range(0, len(raw) - 1, 12):
                a, b, c = struct.unpack_from("!III", raw, k)
                comms.append(f"{a}:{b}:{c}")
            out["large_community"] = " ".join(comms)
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("dump")
    ap.add_argument("out")
    ap.add_argument("--next-hop", default=None)
    ap.add_argument("--limit", type=int, default=0)
    ap.add_argument("--prepend-as", type=int, default=0)
    ap.add_argument("--offset", type=int, default=0)
    ap.add_argument("--stats-out", default=None)
    args = ap.parse_args()

    n_prefixes = 0
    n_entries = 0
    n_emitted = 0
    skipped = 0
    as4 = True
    with open_mrt(args.dump) as f, open(args.out, "w") as o:
        while True:
            hdr = f.read(12)
            if len(hdr) < 12:
                break
            _ts, mtype, msubtype, mlen = struct.unpack("!IHHI", hdr)
            body = f.read(mlen)
            if mtype != TABLE_DUMP_V2 or msubtype != RIB_IPV4_UNICAST:
                continue
            # RFC 6396 13.2: Sequence Number (4) | Prefix Length | Prefix
            # | Entry Count (2) | RIB Entries
            p = 4
            plen = body[p]
            nbytes = (plen + 7) // 8
            prefix = ipaddress.IPv4Network(
                (bytes(body[p + 1 : p + 1 + nbytes] + b"\x00" * (4 - nbytes)), plen),
                strict=False,
            )
            p += 1 + nbytes
            ecount = struct.unpack_from("!H", body, p)[0]
            p += 2
            best = None  # lowest peer index wins
            for _ in range(ecount):
                peer_idx, _orig = struct.unpack_from("!HI", body, p)
                p += 6
                alen = struct.unpack_from("!H", body, p)[0]
                p += 2
                attrs = parse_attrs(body[p : p + alen])
                p += alen
                n_entries += 1
                if best is None or peer_idx < best[0]:
                    best = (peer_idx, attrs)
            n_prefixes += 1
            if n_prefixes <= args.offset or (
                args.limit and n_emitted >= args.limit
            ):
                continue
            _, a = best
            if "as_path" not in a or "origin" not in a:
                skipped += 1
                continue
            line = f"announce route {prefix} next-hop {args.next_hop}"
            if args.prepend_as:
                a["as_path"] = f"{args.prepend_as} " + a["as_path"]
            line += f" as-path [ {a['as_path']} ] origin {a['origin']}"
            if a.get("med") is not None:
                line += f" med {a['med']}"
            if a.get("community"):
                line += f" community [ {a['community']} ]"
            if a.get("large_community"):
                line += f" large-community [ {a['large_community']} ]"
            o.write(line + "\n")
            n_emitted += 1

    stats = {
        "dump": args.dump,
        "ipv4_unicast_prefixes": n_prefixes,
        "rib_entries": n_entries,
        "emitted": n_emitted,
        "skipped_no_aspath_or_origin": skipped,
        "pick_rule": "lowest peer-index entry per prefix",
        "attrs_kept": [
            "ORIGIN",
            "AS_PATH",
            "MED",
            "COMMUNITY",
            "LARGE_COMMUNITY",
        ],
        "next_hop_rewrite": args.next_hop,
        "prepend_as": args.prepend_as,
        "offset": args.offset,
        "limit": args.limit,
        "as4": as4,
    }
    js = json.dumps(stats, indent=1)
    if args.stats_out:
        with open(args.stats_out, "w") as so:
            so.write(js + "\n")
    print(js)


if __name__ == "__main__":
    main()
