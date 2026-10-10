# ospfd — the Rouster OSPF daemon (Phase 3, stream W2-e)

Status: core opened 2026-10-11 (W2-e day 1, commits `2fda837`..):
the LSA codec, the link-state database, the intra-area SPF engine and
the neighbor/adjacency cores, all pure, clock-injected and
RFC-cited. The daemon shell (config parser landed; sockets/interop)
is the day-2 pickup.

## Layout

| Module | What |
|---|---|
| `checksum` | The two OSPF checksums, never to be confused: the LSA Fletcher-16 (§12.1.7, ISO 8473 via RFC 1008, FRR-pinned placement math) and the packet IP one's-complement (§A.3.1, auth-field-excluded) |
| `lsa` | The 20-byte header (§A.4.1) and the v2 bodies: router §A.4.2, network §A.4.3, summary §A.4.4, AS-external §A.4.5; signed sequence space §12.1.6; strict length/count validation |
| `lsdb` | The typed store keyed (LS type, LS ID, adv router) (§12.2); the §13.1 "which instance is newer" ordering; §13.2 install with contents-difference SPF gating and the MinLSArrival guard; §14 aging/MaxAge/refresh bookkeeping; §12.1.6 rollover guard |
| `spf` | The §16.1 two-stage Dijkstra (stub networks in stage two), §16.1.1 per-path next hops, §16.1 step-3 network-before-router tiebreak, equal-cost accumulation, TransitCapability; the pure throttle scheduler |
| `packet` | §A.3 codecs: header, Hello, DBD, LSR, LSU, LSAck with packet checksum verification |
| `neighbor` | The §10.3 neighbor state table, §10.5 Hello processing, §10.6-§10.8 DBD master/slave exchange, §13 flooding steps 1-8 as `flood_step` |
| `config` | `ospfd.conf` grammar (A11/B7 conventions): router-id, area, interface stanzas, network bindings, redistribute static |
| `bin/ospfd` | Day 2 (see §Deferred) |

## Pinned design decisions

- **Both checksums verified against real wire data.** The Fletcher
  placement arithmetic is pinned to FRR 10.2.2's `fletcher_checksum`
  (0-based offsets, checksum at relative 14 from `options`), and both
  algorithms reproduce a real OSPFv2 capture byte-for-byte (31
  packets, 19 LSAs; the corpus lives in the test modules as goldens).
- **The LSA V/E/B flags are V=0x04, E=0x02, B=0x01.** The §A.4.2
  ASCII diagram is ambiguous under casual reading; FRR
  (`ROUTER_LSA_{VIRTUAL,EXTERNAL,BORDER}`) and Wireshark agree on
  the bit assignment above, and the capture corpus corroborates.
- **Sequence numbers compare as signed i32** (§12.1.6): raw 0 is a
  legal old instance; 0x80000000 alone is reserved. Only that value
  is rejected on decode.
- **Network→router graph edges cost zero** (§A.4.3): each router pays
  only its own outgoing interface metric; RT2's metric to a transit
  network never contributes to the root's cost of reaching RT2
  through it.
- **Candidate pop order is (distance, network-before-router,
  insertion FIFO)** — the §16.1 step-3 tiebreak plus FRR's
  non-unique-skiplist FIFO among equals. The insertion component is
  load-bearing: it is what lets late relaxations merge equal-cost hop
  sets into still-pending candidates.
- **§16.1.1 next hops are computed per-path.** A vertex carries both
  its own route hops and the set children inherit; a root-attached
  transit network that also merges a through-router equal-cost path
  hands children both the direct Link-Data-derived hop and the
  inherited one. Collapsing these per-vertex silently drops
  equal-cost first edges (found by the first-edge oracle property
  test).
- **On-tree vertices are not re-relaxed** (§16.1 step 2c, FRR's
  literal reading) — with the pop order above this loses nothing on
  legal inputs where zero-cost edges only occur network→router (the
  tiebreak covers exactly that case).
- **§13's step order is exact**: the request-list BadLSReq (step 6)
  fires before the same-instance implied ack (step 7).
- **Incremental SPF (§16.5/§16.6) is deferred**: v1 always recomputes
  (the RFC explicitly permits any algorithm producing the identical
  tree), behind the pure throttle scheduler (FRR-parity defaults
  0/50/5000 ms — the RFC is silent on scheduling values).
- **Router flags reserved bits are rejected on decode; DBD flag
  reserved bits likewise.** Reserved-bit leniency is a fingerprinting
  and fuzzing hazard; the capture corpus shows real senders zero
  them. (LS age above MaxAge is likewise refused.)
- **DoNotAge (RFC 3623 lineage) is carried, not honored**: the age's
  bit 15 is masked for aging/MaxAge arithmetic; DNA semantics are
  §Deferred.

## AF-generic seams (architecture invariant 3)

The header, LSDB, SPF skeleton and neighbor FSM are
address-family-independent; OSPFv3 must extend this codebase, not
fork it. The concrete seams, documented where they bite:

- `LsaType` is u16-backed (v2 encodes the low byte in the header's
  type octet; v3 puts the full 16 bits in the header and drops the
  header Options octet — the `Options` field then lives in Hello/DBD
  bodies and per-LSA).
- `RouterId` and `LinkStateId` are u32 newtypes. v2 *interprets* the
  Link State ID as an IPv4 address; v3 treats it as an opaque
  type-specific value. The header codec never touches `Ipv4Addr`.
- The v2 bodies in `lsa` are the IPv4 seam. v3 replaces them with new
  `LsaBody` variants: the router-LSA links carry interface IDs
  instead of Link Data + TOS tails; the network-LSA collapses to an
  Options field (no attached-router list — v3 router-LSAs list the
  network's DR); summary/external become prefix-based
  (Inter-Area-Prefix / Inter-Area-Router / AS-External with
  LSA-prefix encoding).
- The packet header loses Area ID/AuType/Auth in v3 (instance ID +
  options instead) and the v6 checksum runs over a IPv6
  pseudo-header. `packet.rs`'s body codecs are v2-shaped; the
  framing/length/checksum plumbing is shared.
- SPF operates on `(LsaType, LinkStateId, RouterId)` vertices and
  never on addresses; only the §16.1.1 next-hop *interpretation*
  (Link Data as an interface address) and the stub-network mask
  arithmetic are v2-specific.

## §Deferred (day-2 anchors)

- The daemon shell + real sockets: OSPF needs raw IP protocol 89 with
  IP_ADD_MEMBERSHIP on 224.0.0.5/224.0.0.6 and TTL 1 (§A.1).
  std::net joins the group and sets the TTL but has **no raw
  sockets** (probed 2026-10-11); socket2 — already a workspace
  member adopted by bfdd under owner decision A1 — is the path, but
  the W2-e fence gates it as a STOP-and-record. Anchor:
  `crates/ospfd/src/lib.rs` module list + the W2-e report.
- `scripts/test-ospf-frr-interop.sh`: p2p adjacency to a real FRR
  10.2.2 ospfd (frr-testbed, cached image), 15 s probe, LSDB
  convergence, static→redistribute both directions.
- Interface state machine (§9.1-§9.4) and DR/BDR election (§9.4);
  broadcast-network origination (network-LSA by the DR, §12.4.2).
- Multi-packet DBD walks (the §10.8 summary-list drain loop) — the
  pure `process_dbd` handles the sequencing spine; the daemon layer
  owns the MTU-bounded packing.
- Retransmission lists and LSAck scheduling (§13.3/§13.5-§13.7) —
  `flood_step` returns the decisions; the lists live with neighbors.
- Inter-area (§16.2-§16.4), incremental SPF (§16.5/§16.6), virtual
  links (§15), stub/NSSA areas (§3.6), authentication (Appendix D),
  graceful restart (RFC 3623), DNA honoring, OSPFv3 bodies.
- The SAVNET intra-domain IGP signaling hook
  (`experimental-savnet`) — anchor `crates/ospfd/src/neighbor.rs`
  (`flood_step`'s InstallAndFlood) once the draft's wire format is
  pinned.
