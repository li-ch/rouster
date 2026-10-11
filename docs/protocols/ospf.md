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

## Day-2 additions (2026-10-10/11, the transport + daemon + interop)

- **socket2 adopted for ospfd** (owner decision A1, adopted
  2026-10-11; the Day-1 STOP resolved). `transport.rs` owns the raw
  proto-89 socket: 224.0.0.5 join, IP_MULTICAST_IF, TTL 1 on both
  arms, AllDRouters join/leave on §9.4 role. Two disclosed fences:
  no receive-side TTL check (socket2 0.6.5 has no recvmsg cmsg
  parser — the bfdd wall) and no SO_BINDTODEVICE (the same crate
  version) — the daemon demultiplexes by on-link source instead.
  The safe-IO seam: socket2's recv wants `MaybeUninit` buffers, so
  the armed fd is dup'ed into a tokio `UdpSocket` (same kernel
  socket) for safe async send/recv.
- **The wire bug the interop caught**: §A.3.3 has NO padding between
  the I/M/MS octet and the DD sequence number — Day-1's codec wrote
  (and read, symmetric, so its own tests passed) two spurious pad
  bytes; FRR 10.2.2 rejected the DDs ("undersized (2 B) trailing
  LSA header"). Golden: an empty ExStart DD is exactly 32 bytes.
- **The daemon** (`daemon.rs` + `exchange.rs` + `bin/ospfd.rs`):
  §10.8's MTU-bounded DD drain with the master's terminator rounds
  and duplicate echoes, §10.9 request rounds, §13.3-§13.7
  retransmission lists (RxmtInterval 5 s), §14 aging/flush,
  §12.4.1/.2/.3 origination with MinLSInterval retries, the FRR-parity
  SPF throttle, route diffing to ZEBRA_ROUTE_ADD/DELETE, and a
  §16.4-lite external calculation (§16.4.1 steps 1-5 in the
  single-area form: ASBR distance from the intra-area table; the
  type-4 inter-area lookup is deferred with §16.2-§16.3).
- **The zapi edge** (`zedge.rs`, the bgpd idioms): HELLO as OSPF
  (7), `redistribute static` registration → the
  REDISTRIBUTE_ROUTE_ADD/DEL pushes become §12.4.3
  origination/withdrawal. Router ID and interface addresses come
  from config (no ROUTER_ID_ADD/INTERFACE_ADD_REQUEST — the zapi
  client exposes no raw send; disclosed).
- **The p2p next-hop seam**: no LSA carries the p2p neighbor's
  address (Link Data is the advertiser's own); the adjacency (the
  Hello source) does — the daemon decorates the gateway at export
  (`p2p_peer_address`), keeping SPF pure over LSAs.
- **Interop**: `scripts/test-ospf-frr-interop.sh` — Full adjacency
  with real FRR 10.2.2 over a p2p link, LSDB convergence both ways,
  static→redistribute BOTH directions (ours → FRR's kernel; FRR's →
  our §16.4 → kernel via rousterd), 30 s soak, exit 0 twice
  back-to-back. FRR sets the type-5 forwarding address to a via-us
  static's nexthop (§12.4.3), so the reverse direction uses a
  blackhole static (FA 0.0.0.0) — a topology note, not a workaround.

## Day-3 additions (2026-10-11, the N2 night slice: broadcast + §13.4)

- **The §9.4 election is exact now** (two W2-e deviations corrected
  against the FRR 10.2.2 oracle, `ospf_ism.c:ospf_dr_election`):
  step (2) excludes self-declared-DR routers from BDR election, and
  step (4)'s repeat runs with our claims updated to the first
  round — so a lone broadcast router ends **DR with BDR 0.0.0.0**
  ("No backup designated router on this network", probed live on
  the oracle). The election reports the step-(7) identity-change
  flags that drive AdjOK? re-evaluation.
- **Broadcast networks run in the daemon** (§7.3): Hello-driven
  claim tracking per neighbor, §9.2's BackupSeen (both forms,
  Waiting-only) and NeighborChange (all five causes) via the pure
  `hello_interface_events` table, the WaitTimer
  (RouterDeadInterval) election, priority-0 interfaces entering
  DR Other at InterfaceUp (§9.3), our Hellos carrying the elected
  DR/BDR claims (§A.3.2), §10.4's AdjOK? answer (adjacent only
  with/toward the DR/BDR; DROther pairs stop at 2-Way), §12.4.2
  network-LSA origination by the DR (attached = Full set + self,
  re-originated on adjacency changes, flushed on losing DR or the
  last Full adjacency), and §12.4.1.2's exact three shapes for the
  broadcast interface description (type-2 transit with the
  adjacency gate; the type-3 stub Waiting form otherwise).
- **§13.3 broadcast flooding + §A.1 memberships**: new LSAs
  multicast on broadcast networks — AllSPFRouters from the DR/BDR,
  AllDRouters from DR Others (whose 224.0.0.6 receives are then
  DR/BDR-only, gated on ingress); retransmissions stay unicast.
  The run loop joins/leaves AllDRouters on §9.4 role changes
  (the sockopt surface is interior-mutable — the Arc'd socket
  shape, no unsafe).
- **§13.4 re-adoption**: a received newer self-originated LSA (the
  restart-against-a-stale-peer case) advances the sequence
  tracking one past the received instance (`Lsdb::
  readopt_self_originated`) and re-originates; the no-longer-wanted
  cases (no route, no longer DR, Router-ID-changed network-LSA)
  prematurely age and reflood (§14.1).
- **Interop**: `scripts/test-ospf-broadcast-interop.sh` — a
  four-router broadcast network (FRR DR + rouster BDR + FRR DROther
  + rouster DROther), exit 0 twice back-to-back: all four agree on
  the election, the §10.4 matrix holds across implementations
  (FRR shows our DROther at `2-Way/DROther`; we log the
  stays-2-Way line for FRR's), the DR's network-LSA lists all four
  attached routers, and a redistributed static lands in our
  DROther's kernel `via` the DR's address — the §16.1.1 case-two
  pseudo-node next hop.

## §Deferred (updated day-3 anchors)

- Inter-area routes (§16.2-§16.3 + the type-4 lookup §16.4-lite
  shortcuts), incremental SPF (§16.5/§16.6), virtual links (§15),
  stub/NSSA areas (§3.6), authentication (Appendix D), graceful
  restart (RFC 3623), DNA honoring, OSPFv3 bodies.
- NBMA and Point-to-MultiPoint networks (§C.3) — the unicast-hello
  and per-neighbor-poll machinery; the §9.4 election's NBMA step
  (6) rides with it.
- Receive-side TTL verification (needs the recvmsg cmsg walk — a
  libc or socket2 upgrade); SO_BINDTODEVICE-style interface scoping.
- Interface link-state tracking (InterfaceUp fires at construction
  v1); the zapi interface dump as the address source.
- The SAVNET intra-domain IGP signaling hook
  (`experimental-savnet`) — anchor `crates/ospfd/src/neighbor.rs`
  (`flood_step`'s InstallAndFlood) once the draft's wire format is
  pinned.
