# rpki — RTR client and ROV/ASPA library

Status: **Phase 2, stream P2-c** (2026-10-10/11); **real-cache
interop executed** against gortr v0.14.7 on 2026-10-11 (N7 — see
"Real-cache interop" below). `crates/rpki` is a library for the edge —
bgpd's import policy is the consumer; no daemon this round. Everything
below cites the exact section that pins it.

Sources (fetched 2026-10-10):

- **RFC 8210** — The RPKI-to-Router Protocol, September 2017.
- **draft-ietf-sidrops-8210bis-27** — 8210bis, August 2026 (still in
  the IESG stream, not yet an RFC as of fetch date).
- **RFC 6811** — BGP Prefix Origin Validation, January 2013.
- **RFC 6483** — Validation of Route Origination Using the RPKI and
  ROAs, February 2012 (the validity-state table and AS 0 disavowal).
- **draft-ietf-sidrops-aspa-verification-28** — ASPA-based AS_PATH
  verification, August 2026 (still a draft; the
  "RFC 8416/RFC 9234-era" model the plan points at — RFC 9234 itself
  covers roles/OTC, not the verification algorithm).

## PDU table (RFC 8210 §5; 8210bis-27 §5)

Every PDU: `version(1) type(1) field16(2) length(4)` big-endian;
`length` counts the whole PDU including header; the 64 KiB cap is
8210bis-27 §5. Reserved "zero" fields and reserved flag bits are sent
as zero and ignored on receipt (§5.1).

| Type | PDU | Dir | Length | field16 | Body |
|---|---|---|---|---|---|
| 0 | Serial Notify | C→R | 12 | Session ID | Serial Number |
| 1 | Serial Query | R→C | 12 | Session ID | Serial Number |
| 2 | Reset Query | R→C | 8 | zero | — |
| 3 | Cache Response | C→R | 8 | Session ID | — |
| 4 | IPv4 Prefix | C→R | 20 | zero | flags, prefix-len, max-len, zero, IPv4 prefix, ASN |
| 5 | *reserved* | — | — | — | — |
| 6 | IPv6 Prefix | C→R | 32 | zero | flags, prefix-len, max-len, zero, IPv6 prefix, ASN |
| 7 | End of Data | C→R | 12 (v0) / 24 (v1+) | Session ID | Serial [+ refresh, retry, expire] |
| 8 | Cache Reset | C→R | 8 | zero | — |
| 9 | Router Key | C→R | 32+n | flags+zero (byte 2 = flags) | SKI (20 octets), ASN, subjectPublicKeyInfo (DER, n octets) |
| 10 | Error Report | both | 16+n+m | Error Code | encapsulated-PDU length + PDU (n), text length + UTF-8 text (m) |
| 11 | ASPA (v2 only) | C→R | 12+4k | flags+zero (byte 2 = flags) | Customer ASN, k Provider ASNs (strictly increasing, unique) |

Version epochs: v0 = RFC 6810 (EoD carries no timing parameters —
12 bytes; Router Key and ASPA do not exist), v1 = RFC 8210 (adds
Router Key, timing, negotiation), v2 = 8210bis-27 (adds the ASPA PDU,
error codes 9–12, the PDU ordering rules of its §11, the 64 KiB cap).

Flags (§5.1): lowest bit 1 = announce, 0 = withdraw; a withdraw
deletes the record with the *exact same* tuple. For ASPA (bis §5.12)
an announcement *replaces* the previous record for the same customer
ASN; a withdrawal is exactly 12 bytes; an announcement must carry at
least one provider, and a multi-provider list must not contain AS 0 —
violations are the router's Error Code 9.

Error codes (§12; bis §12 adds 9–12): 0 Corrupt Data, 1 Internal
Error, 2 No Data Available, 3 Invalid Request, 4 Unsupported Protocol
Version, 5 Unsupported PDU Type, 6 Withdrawal of Unknown Record,
7 Duplicate Announcement Received, 8 Unexpected Protocol Version,
9 ASPA Provider List Error, 10 Transport Error, 11 Ordering Error,
12 Cache Restart, 13 Cache Shutdown. Fatal ⇒ drop the session and
flush all data learned from that cache; 2/4/12/13 are non-fatal.

Strictness (the workspace A19 lesson): exact lengths for fixed PDUs,
full byte accounting for variable ones, `max_len >= prefix_len`,
prefix lengths within family bounds, ASPA provider lists strictly
increasing, version/type compatibility enforced (Router Key ≥ v1,
ASPA = v2). Error Reports decode at any protocol version — §7 says an
unknown version gets terminated "unless the received PDU is itself an
Error Report", so the codec must be able to read them regardless.

## Session (RFC 8210 §7–§8; bis §7–§8)

Negotiation (§7/bis §7): the router opens with Reset Query (or Serial
Query when it holds unexpired data and remembers the Session ID) at
its highest version; a cache answering Error Code 4 names its own
version C — the router re-queries at C unless C already failed (then
the transport is abandoned; version 0 failing is "hopeless"). Once
fixed, the version holds for the session's life; a different version
on a later PDU is Error Code 8 + drop (Error Reports excepted).

```
      Cache                                     Router (rouster)
        |                                          |
        |<------------- Reset Query (v2) -----------|  connect: no data yet
        |                                          |
        |------------ Cache Response ------------->|  tables cleared (reset response)
        |------------ IPv4/6 Prefix PDUs --------->|  VRPs applied (dup→code 7,
        |------------ ASPA PDU(s) ---------------->|  unknown-withdraw→code 6)
        |------------ Router Key PDU(s) ---------->|
        |------------ End of Data (serial,timing)->|  state Fresh, timers armed
        |                                          |
        |<------------- Serial Query (sid,serial)--|  refresh poll = keep-alive (§6)
        |------------ Cache Response ------------->|  deltas applied
        |------------ End of Data ---------------->|  state Serial
        |                                          |
        |------------- Serial Notify (hint) ------>|  MAY trigger an early query (§8.2)
        |                                          |
        |  (cache cannot serve that serial)        |
        |------------ Cache Reset ---------------->|  router falls back to Reset Query (§8.3)
        |                                          |
        |------------ Error Report (fatal) ------->|  session drops, data flushed (§12)
```

Timing (§6, from End of Data): refresh 1..86400 s (default 3600) —
polls double as the application-layer keep-alive (§8.1); retry
1..7200 s (default 600) between failed polls and reconnects; expire
600..172800 s (default 7200) — data MUST NOT be retained past it
without a successful poll (the client flushes on expiry, across
reconnects).

Client implementation notes (`crates/rpki/src/client.rs`):

- Reader task frames PDUs off a split TCP stream; the session loop
  selects over inbound PDUs, the refresh/expire timers, and shutdown
  (tokio time throughout — the clock is injectable via `start_paused`
  in tests).
- A Cache Response to a Reset Query clears the VRP/ASPA/router-key
  tables before applying (§5.5: it "sends the set of all data records
  it has"); a response to a Serial Query applies deltas.
- Session-ID change on a serial exchange = Error Code 0 + drop + full
  flush (§5.1); this holds for *any* PDU once the version is
  negotiated, including a Serial Notify carrying a foreign Session ID;
  End-of-Data's Session ID must equal the Cache Response's (§5.8).
- Cache Reset (§8.3): re-query with Reset Query on the same
  connection. No Data Available (§8.4): mark `NoData`, retry with
  Reset Query after the Retry Interval. Cache Restart/Shutdown
  (bis §8.5/§8.6): close, retry later; shutdown also flushes.
- Fatal errors anywhere ⇒ send the Error Report (encapsulating the
  offending PDU, truncated at 1 KiB per §5.11's allowance), drop,
  flush (bis §12).
- Cache state exposed to the consumer: `None / Negotiating /
  Receiving / Fresh / Serial / NoData`, with `session_id`, `serial`,
  `timing`, `protocol_version` — one `Arc<Mutex<CacheTables>>`.
- `ClientConfig::max_version` caps the negotiation offer (bis §7
  starts at the router's highest version); the default is
  `HIGHEST_VERSION`. Negotiation outcomes (agreed version, versions
  already offered) persist across reconnects, and a session that ends
  before its first End of Data reconnects after a short fixed delay
  (1 s), not the §6 default Retry Interval — the §8.4 No-Data retry
  follows the same rule pre-sync (see "Real-cache interop" for the
  gortr behaviors that forced each).
- The §6 expire deadline is raced everywhere data is held: inside the
  session, during the between-connection waits (a cache that died
  with its port refusing connections parks the client where no
  session timer is armed), and the §8.4 No-Data sleep. It stays
  disarmed while a Cache Response sequence is open, and a session
  that dies inside one flushes the partial table.

## ROV (RFC 6811 §2, exactly)

Over the VRP set `((prefix, max_len, asn))` and a route `(prefix,
origin ASN)`:

- **Covered** — VRP prefix length ≤ route prefix length and the two
  addresses identical on every bit the VRP prefix names (equal or
  more-specific; never across families).
- **Matched** — Covered, route prefix length ≤ VRP max length, and
  route origin ASN == VRP ASN.
- **NotFound** — nothing Covers. **Valid** — something Matches.
  **Invalid** — something Covers, nothing Matches.

Two §2 special cases: origin "NONE" (final AS_PATH segment not an
AS_SEQUENCE/confederation — aggregates) never Matches; a VRP with
ASN 0 never Matches (the pseudo-code's `entry->origin_as != 0`), which
is what turns AS 0 ROAs into disavowal: everything they cover becomes
Invalid *unless* another ROA Matches it (RFC 6483 §4 — the AS 0 ROA
is the floor, not the verdict).

`VrpTable::validate(prefix, origin)` implements §2.1's pseudo-code
verbatim. Property tests (fixed seeds) check soundness against an
independent reference model, completeness of the exact-VRP announce,
removal-only-degrades monotonicity, family isolation, and
AS0-never-Valid.

## ASPA (draft-ietf-sidrops-aspa-verification-28 §4–§6)

Model: customer AS → set of provider ASes (U-SPAS, §5.3). Over RTR v2
one ASPA PDU per CAS, announcements replace (bis §5.12). The object
model can also hold an *empty* provider set ("no providers" — an
AS0-ASPA equivalent); the wire cannot (announcements need ≥1
provider), so that state is API-only today.

`authorized(x, y)` (§5.3 Figure 2): **No Attestation** when x has no
U-SPAS entry; **Provider+** when y is in it; else **Not Provider+**.

Verification walks the COMPRESSED_AS_PATH (§5.2; consecutive duplicate
ASNs removed; AS(1) = origin, AS(N) = most recently added) as an
up-ramp from AS(1) plus a down-ramp from AS(N), each hop meaning
customer-to-provider:

```
   AS(L) ................ AS(K)      <- apexes
      \                    /
       (down-ramp)      (up-ramp)
          \                /
          AS(N)         AS(1)  (origin)
             \          /
        verifier AS(N+1)
```

§5.4 bounds each ramp from the authorization outcomes
(max/min up-ramp from the first *Not Provider+* / first non-*Provider+*
hop ascending; max/min down-ramp from the topmost such hop descending,
as `N - J + 1`). Then:

- **Upstream** (§5.5; received from customer/peer, RS↔RS-client):
  empty path, neighbor mismatch (RS-client behind a transparent RS
  excepted), or any AS_SET ⇒ Invalid; `max_up_ramp < N` ⇒ Invalid;
  `min_up_ramp < N` ⇒ Unknown; else Valid.
- **Downstream** (§5.6; received from provider): same prerequisites
  (neighbor check always strict); `max_up + max_down < N` ⇒ Invalid;
  `min_up + min_down < N` ⇒ Unknown; else Valid — the two ramps must
  be able to tile the path; ambiguity (No Attestation) is Unknown,
  never a guess.

`PeerRelation` maps RFC 9234 roles onto procedure choice (§6.3).
Mitigation (§5.7) is policy, not this library: Invalid ⇒ reject-eligibility
is bgpd's call; Unknown ranks with Valid.

## Deviations / interpretations (all test-pinned)

1. ASPA provider-list wire violations (non-increasing, duplicate) are
   codec-level decode errors; the §5.12 semantic ones (announcement
   with no providers, AS 0 among several providers, withdrawal with
   providers) decode and are reported as Error Code 9 by the session
   layer — that split keeps the mandated error behavior reachable.
2. An ASPA announcement identical to the active record is Error Code 7
   ("duplicate"); a *different* provider set replaces (bis §5.12
   replacement text wins over the §12 code-7 gloss for the same CAS).
3. The client treats any well-formed non-Error PDU as fixing the
   session version (bis §7 says the Cache Response does; a Cache Reset
   in reply to a Serial Query is handled the same way rather than
   dropped).
4. `Timing` values are honored as given (no §6 range clamping); the
   v0 fallback timing is the §6 defaults. The refresh countdown
   restarts only at End-of-Data receipt (§6's "Countdown for this
   timer starts upon receipt of the containing End Of Data PDU"), so
   an unanswered poll is bounded by the expire deadline rather than a
   send-time re-arm.
5. A session that ends between a Cache Response and its End of Data
   flushes everything (§5.5's reset response already cleared the old
   table; a half-applied delta set is not data either). The RFC is
   silent on incomplete sequences; discarding is the conservative
   reading of §6's successful-poll premise (test-pinned, scenario
   15). The connect attempt itself is not raced against the expire
   deadline — the OS bounds it (SYN retries) far below any sane
   Expire Interval.

## Real-cache interop (gortr, executed 2026-10-11)

`scripts/test-rpki-gortr.sh` proves the client against a REAL cache —
`gortr:local` (Cloudflare GoRTR v0.14.7, linux/amd64 under emulation)
— fully offline. **Trust posture: this is a protocol interop test,
not a web-of-trust validation** — the cache serves an unsigned local
JSON file with `-verify=false -checktime=false`; no TAL, no RRDP, no
repository fetch. The invocation that works offline (there is no
baked VRP data in the image — mount your own):

```sh
docker run -d --name rouster-rpki-gortr -p 127.0.0.1:8282:8282 \
  -v "$DATA":/data:ro gortr:local \
  -cache /data/rpki.json -verify=false -checktime=false \
  -rtr.sessionid 42 -rtr.refresh 10 -rtr.retry 5 -rtr.expire 30 \
  -refresh 5 -loglevel debug
```

(`-cache` takes a plain file path — only `http(s)://` prefixes go to
HTTP; `-rtr.*` set the End-of-Data timing; `-refresh` is the file
re-fetch period, also reactive to SIGHUP.) Input shape:
`{"metadata": {...}, "roas": [{"prefix": "192.0.2.0/24",
"maxLength": 24, "asn": "AS64512", "ta": "n7"}]}` — `asn` is the
string `"AS…"`.

What the run pinned (gortr v0.14.7 behavior, all live-captured):

- **RTR v0/v1 only.** A v2 Reset Query is answered by a **silent
  close — zero bytes, no Error Report** (the code-4 branch exists in
  its sources but `EnforceVersion` is never set). The §7 downgrade
  arm is therefore unreachable against it; `ClientConfig::max_version`
  (default [`HIGHEST_VERSION`]) is the operator's pin — the smoke and
  `rtr-check` pass `--max-version 1`.
- **Serial starts at 0** and advances only when the file content hash
  changes; an identical re-fetch bumps nothing.
- **Serial Notify** (same session ID, new serial) rides the OPEN
  connection on a data change; the delta is exact-tuple (withdraw of
  the changed tuple + announces) — matching `vrp.rs` semantics 1:1.
- **Serial Query for a serial it cannot serve** (fresh instance, any
  serial ≠ current) → **Cache Reset**, exercising the §8.3
  Reset-Query fallback live.
- A **fresh gortr whose initial file read failed** (a swap racing the
  entrypoint) answers the first Reset Query with **Error Code 2** —
  not an empty CacheResponse — and its `-refresh` timer recovers the
  data seconds later.
- **No Router Key or ASPA PDUs, ever** (v1 only): those tables stay
  empty against gortr; `router_keys.is_empty()` is asserted, not
  assumed away.

Fixes the run surfaced (each with a failing-first mock test in
`tests/session_client.rs`, scenarios 10–15): the `max_version` pin;
negotiation memory across reconnects (bis §7); fast reconnect before
the first End of Data (also the §8.4 No-Data retry — the 600 s §6
default must not gate a pre-sync cache); the §6 expire deadline raced
in the between-session waits (a dead cache whose port refuses
connections used to park the client where no timer watched expiry);
and mid-load semantics (expire disarmed while a Cache Response
sequence is open + a flush of the partial table when the session dies
inside one — a half-streamed load is not data).

`crates/rpki/src/bin/rtr-check.rs` is the live probe: it prints every
cache-state transition (a driver script can watch the session live)
and exits 0 only when its `--expect-*` assertions and `--rov
PREFIX,ASN,Verdict` samples all hold. Terminal-state assertions arm
only after the first observed transition, so `--expect-state None`
(the expire-flush leg) matches the flush, not the virgin snapshot.

## §Deferred (owner-authorized follow-ups)

1. **A second, version-2 cache.** gortr v0.14.7 cannot exercise the
   v2 surface (ASPA PDUs, Router Keys, error codes 9–12); routinator
   (or StayRTR with v2 support, if any) remains the deferred second
   cache — no such image is cached and no pulls are authorized. When
   one lands, the assertions to add: negotiation at v2, an ASPA
   table actually filling, and Router Key storage over the wire.
2. **Fuzzing** the PDU codec with cargo-fuzz (AGENTS.md invariant 7
   applies once a fuzz harness exists for the other wire codecs).
3. **bgpd wiring**: policy conditions `rpki valid|invalid|notfound`
   and `aspa ...` over the shared tables, plus the BIRD-style
   `rpki reload` settle-time revalidation.
4. **SSH transport** (RFC 8210 §9) — TCP only this round.
