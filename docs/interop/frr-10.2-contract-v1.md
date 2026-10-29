# FRR 10.2.2 behavioral contract — v1 (FROZEN 2026-10-29)

The frozen, versioned classification table for the ToN revision's
conformance campaign (revision plan Part 5 P0-conformance, prompt
phase 2). Sources: `docs/interop/frr-10.2-interop.md` (live
interop evidence), `docs/interop/zapi-10.2-pinned.md` (the pinned
corpus), the smoke inventory (`scripts/run-smokes.sh`), and the
measured differential cells of `docs/benchmarks.md` §R.

**Freeze rule.** This table does not change after phase 3 starts.
A mismatch the campaign later finds becomes a disclosed exception
recorded against the row, never a quiet reclassification. A
contract change requires a new version file (v2) with a dated
change log; v1 rows and their classifications stand as history.

**Classification vocabulary** (the paper §III-C set):
- **Matched** — incumbent behavior intentionally preserved.
- **Intentionally changed** — incumbent behavior deliberately not
  preserved (an improvement is still a compatibility difference).
- **Permitted difference** — representation, ordering, batching, or
  other predeclared observable slack.
- **Unsupported** — outside the supported scope; fails visibly.

## The table

| # | Behavior | FRR 10.2.2 behavior | Rouster behavior | Classification | Test IDs |
|---|---|---|---|---|---|
| 1 | ZAPI framing | 10-byte header, marker 254, v6; partial/coalesced reads; mid-frame close ends stream | Same, byte-pinned | Matched | zapi fixtures (staticd/bgpd/ospfd-10.2.2.log, m4-capture); `crates/zapi` round-trip tests |
| 2 | Connect contract | HELLO echo, interface/address dump, router-id answer, label-manager connect result | Same | Matched | test-z5-frr-interop.sh; test-z5b-bgpd-interop.sh (3-connection set); test-z5c-ospfd-interop.sh |
| 3 | Interface mirror | ifi_flags verbatim, IFNAMSIZ 16, addresses per interface | Same (kernel flags relayed whole) | Matched | fixtures; test-ospf-frr-interop.sh (ADD-C2 dynamic-address variant); W1B link-flags tests |
| 4 | Route ingestion | ROUTE_ADD/DELETE, types 0–10, v4+v6 unicast | Same; vrf_id≠0 dropped with log | Matched | fixtures; e1diff full-table (§R 2026-10-28: 1,126,480 pairs identical, onlyD=1 default-route) |
| 5 | Default-route install | Announced 0/0 from the peer does not install | Installs it | Intentionally changed (disclosed; the standing onlyD=1 delta) | e1diff §R 2026-10-28; e1rand 0/0-excluded oracle rule |
| 6 | Disconnect ownership (ZAPI client) | zebra removes a disconnecting client's routes on socket close | Routes persist until displaced (no reliable retraction view for a crashed daemon) | Intentionally changed (disclosed) | unit: resync/adoption tests; e5recover §R (speaker-crash cells, both systems measured) |
| 7 | Reconnect | zebra never re-syncs a client that does not re-register; clients re-send registrations | Identity-keyed adoption: remembered subscriptions, idempotent best-route replay, delta push; NHT registrations not replayed | Intentionally changed (extension beyond zebra; unmodified clients tolerate it) | unit: reconnect-delta tests; test-z5d-ospfd-redistribute.sh; e5cycles §R (6/6 exact) |
| 8 | Core restart | zebra crash: clients re-attach and re-push (harness-limited stale-persist observation) | Nothing survives; clients must re-attach and re-push | Permitted difference (both require client re-attach; recovery timing differs, §R e5recover) | e5recover §R (per-system cells, no shared oracle) |
| 9 | Nexthop resolution basis | nexthop_active: route-based, no neighbour consultation | Route-based (M3 gate reverted 2026-10-10); connected coverage + kernel-route mirror fallback (under-approximation disclosed) | Matched; fallback-source deviation disclosed | test-z5e-ospfd-nht.sh; Z3/Z3B suites; rib NHT tests |
| 10 | NHT re-evaluation triggers | Route and link events re-resolve registered interests | Reconcile tick re-resolves on flips (ab533d5) | Matched | unit: tick_nht_flips_a_registration_after_the_covering_route_arrives; e45igp §R (10k paths, all modes) |
| 11 | Redistribution | Dump on register, best-change push, DEL on withdrawal, reload-consistent | Same (W2 answers: initial dump, ADD and DEL, SIGHUP parity) | Matched | test-z5d-ospfd-redistribute.sh; test-ospf-frr-interop.sh (both directions); M2 reload tests |
| 12 | BFD relay plane | Dest register/update/deregister relay; state fan-out (26) to all client senders; REPLAY (30) both forms; status bitmask UP=4 | Same, wire-pinned | Matched | test-bfd-zapi.sh (live: FRR bgpd client, Up both sides, down fan-out); test-bfd-frr-interop.sh (pure FRR bfdd peering); W1-b fixtures |
| 13 | BFD client attach (FRR bfdd to our core) | bfdd attaches to its own zebra | FRR bfdd as a Rouster-core client not exercised | Unsupported (deferred; disclosed in paper Table II) | none (the deferral is the classification) |
| 14 | Stale completion | dplane ack correlation | Sequence-correlated idempotent replaces; 10 s timeout ×3 re-issues; late completion discarded | Matched (semantics); representation permitted difference | unit: ACK-timeout/re-issue/overrun; e5backend §R (3/3 exact) |
| 15 | Netlink overrun | — | Classified resync: interface/address re-dump; route truth via reconcile | Permitted difference (recovery mechanism is ours; outcome equality tested) | unit: overrun classification; F9 harness receipts §R |
| 16 | Blackhole type | REJECT bh_type distinguishable | Uniform RTN_BLACKHOLE | Permitted difference (cosmetic, disclosed) | test-z5-frr-interop.sh kernel read |
| 17 | Unsupported messages | — | Unknown logged, connection stays; malformed body skips message; framing violation closes | Unsupported (visible-fail policy) | unit: unknown-message test |
| 18 | Explicit scope exclusions | — | MPLS/SR, label/table managers beyond connect, EVPN/L2, PIM, policy/ipset/NHG/opaque/TC, per-VRF tables, CAPABILITIES/VRF_ADD/ROUTE_NOTIFY_OWNER pushes | Unsupported | fixtures (absence); Table II |
| 19 | Selection/ECMP representation | Multi-path kernel form | ECMP representation slack | Permitted difference | p0c ECMP smoke |
| 20 | Wire quirks | MAC truncation 6→4, VRF on header vrf_id, main-table 31-push omits table-ID + nexthop flag 0x04 | Reproduced verbatim | Matched (quirk reproduction) | M4/M6 fixtures; codec tests |

Rows 6, 7, 8, 13, 16 are the pre-declared differences; the campaign
may not reclassify a observed mismatch into any of them after the
freeze without a v2 entry naming the date and the triggering seed.

## e1rand v2 grammar (design, frozen with this table)

Base (v1, §R 2026-10-21): schedule = `A` (full-table announce) then
4–8 ops over {`W<n>`, `R<n>`}, n ∈ 2..25, seed-driven; oracle =
set arithmetic computed from the schedule, independent of both
implementations; 0/0 excluded from the expected set (row 5).

v2 adds five lifecycle operations, each with a phase-conditional
oracle:

| Op | Injection | During-window expectation | Post-stabilization expectation |
|---|---|---|---|
| `D` (client disconnect) | kill -9 the SUT speaker (bgpd) mid-schedule | Divergence declared under row 6 (incumbent removes, we persist) | After re-attach + config re-push: exact set equality |
| `Rc` (reconnect) | restart the speaker; config re-pushed | replay in flight | Exact set equality; zero duplicate prefixes |
| `N` (nexthop change) | re-announce a drawn prefix subset with the alternate injector nexthop | — | Exact (prefix, via) pair equality on the changed subset |
| `Rs` (speaker restart under load) | kill -9 during an announce burst | row 6 window | Exact set equality after replay |
| `K` (delayed kernel completion) | SIGSTOP the SUT core 10 s at a drawn point | install stream stalled | After resume: exact set equality; timing not compared (recovery timing is the §R e5backend cell's subject) |

Draw rule: each seed draws 6–12 ops from {W, R} plus 2–4 lifecycle
ops from {D, Rc, N, Rs, K}, interleaved by the seed's RNG; core
restart is excluded from the shared-oracle grammar (row 8: no
shared oracle is meaningful) and belongs to the failure-injection
campaign instead.

Scale: 25 seeds per system; seeds 21–25 held out (run only after
the freeze, in phase 4). Schedules are generated from the same seed
for both systems, byte-identical announce inputs per §F.

## Coverage matrix (shape, to be filled by phase 4)

| Contract row | Test types exercised | Ops covered (v2 grammar) | Sequences (count × length) | Untested combinations |
|---|---|---|---|---|
| 1–5, 9–12, 14–20 | fixture / unit / live smoke / differential per row | … | … | … |
| 6 (disconnect) | e5recover cells + e1rand D/Rs | … | … | graceful-stop variant (SIGTERM vs kill -9) |
| 7 (reconnect) | e5cycles + e1rand Rc | … | … | concurrent double-client reconnect |
| 8 (core restart) | e5recover per-system only | excluded from shared oracle | — | shared-oracle form (declared impossible) |

Phase 4 fills the cells with measured counts and lists every
untested combination by name; the paper's conformance subsection
publishes the matrix in compact form.
