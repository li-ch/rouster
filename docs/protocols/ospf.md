# ospfd — the Rouster OSPF daemon (Phase 3, stream W2-e)

Status: core opened 2026-10-11 (W2-e day 1, commits `2fda837`..):
the LSA codec, the link-state database, the intra-area SPF engine and
the neighbor/adjacency cores, all pure, clock-injected and
RFC-cited. Day 2 added the raw-socket transport, the daemon and the
FRR interop. The N2/N3 night slices (2026-10-11/12) added broadcast
networks (§9.4 election, §12.4.2, §13.3), multi-area inter-area
routing — the router-wide §16.2/§16.4 walk and the §12.4.3 ABR
duties — stub areas and NSSA (RFC 3101), Appendix D + RFC 5709
authentication, incremental SPF (§16.5/§16.6), virtual links
(§15/§D.3), and the OSPFv3 codecs (N2B, RFC 5340). The S7-a round
(2026-10-14) landed the OSPFv3 RUNTIME — the v6 transport, the
AF-generic seams cashed as code, and the live FRR ospf6d interop
(see the OSPFv3 runtime section). The S8-b round (2026-10-14
evening) closed the security lane: the v6 cmsg receive read-back
(the audited recvmsg, AGENTS.md's named exception), the RFC 8177
key chains feeding BOTH crypto engines, and the RFC1583Compatibility
knob (O-2, default enabled per §C.1). The S10-b round
(2026-10-15) closed the v3 runtime remainder (the full §4.8 SPF, the
broadcast arm, the IAPRs), the NSSA translator election (RFC 3101
§3.1), `area range`, and the virtual-link tails (§16.1 step 4, the
live vlink interop).

## Layout

| Module | What |
|---|---|
| `checksum` | The two OSPF checksums, never to be confused: the LSA Fletcher-16 (§12.1.7, ISO 8473 via RFC 1008, FRR-pinned placement math) and the packet IP one's-complement (§A.3.1, auth-field-excluded) |
| `lsa` | The 20-byte header (§A.4.1) and the v2 bodies: router §A.4.2, network §A.4.3, summary §A.4.4, AS-external §A.4.5; signed sequence space §12.1.6; strict length/count validation |
| `lsa_v3` | The OSPFv3 LSA codecs (RFC 5340 §A.4): the 16-bit LS type, the A.4.1 prefix triple, the seven v3 bodies + the U-bit `Unknown`, 24-bit Options |
| `packet_v3` | The OSPFv3 packet codecs (RFC 5340 §A.3): the 16-byte header with Instance ID, Hello/DBD/LSR/LSU/LSAck, the IPv6 pseudo-header checksum |
| `lsdb` | The typed store keyed (LS type, LS ID, adv router) (§12.2); the §13.1 "which instance is newer" ordering; §13.2 install with contents-difference SPF gating and the MinLSArrival guard; §14 aging/MaxAge/refresh bookkeeping; §12.1.6 rollover guard |
| `spf` | The §16.1 two-stage Dijkstra (stub networks in stage two), §16.1.1 per-path next hops, §16.1 step-3 network-before-router tiebreak, equal-cost accumulation, TransitCapability; the §16.1-step-4 tree parents + vlink endpoint addresses; the pure throttle scheduler |
| `spf_v3` | The OSPFv3 intra-area SPF (RFC 5340 §4.8.1/§4.8.2): transit vertices keyed (DR Interface ID, DR Router ID), the A.4.3 fragment concatenation with lowest-LS-ID flags, the V6/R gate, link-LSA next hops, the IAPR stage-two walk |
| `packet` | §A.3 codecs: header, Hello, DBD, LSR, LSU, LSAck with packet checksum verification |
| `neighbor` | The §10.3 neighbor state table, §10.5 Hello processing, §10.6-§10.8 DBD master/slave exchange, §13 flooding steps 1-8 as `flood_step` |
| `iface` | The §9 interface state machine and the §9.4 DR election (broadcast networks), pure and AF-generic |
| `origination` | The §12.4 LSA builders: router (§12.4.1), network (§12.4.2), summary incl. type-4 (§12.4.3/§A.4.4), AS-external (§12.4.4/§A.4.5) |
| `auth` | OSPFv2 packet authentication: Appendix D AuTypes (null/password/crypto) + RFC 5709 HMAC-SHA-256 and the legacy keyed-MD5 (D.4.3 step 6, RFC 1321) digest trailers |
| `keychain` | The RFC 8177 key chains: named chains of keys (id, algorithm, secret, send/accept lifetimes), the accept-any-live/send-highest rollover selection, and the resolution to Appendix-D engine views |
| `transport` | The raw-socket transports: v4 (§A.1: proto 89, AllSPF/AllDR 224.0.0.5/6 joins, TTL 1) and v6 (RFC 5340 §A.1: the proto-89 v6 socket bound to the interface's link-local, ff02::5/6 joins by ifindex, multicast hop limit 1, the audited RFC 3542 cmsg read-back for hop limit + true destination — AGENTS.md's named exception) |
| `exchange` | The §10.6-§10.9 adjacency conversation as daemon-side bookkeeping: DD drain, request lists, §13.3-§13.7 retransmissions |
| `daemon` | The v2 run loop: per-interface sockets, §14 aging/hellos, the router-wide §16 walk (intra/inter/external), the ABR/ASBR duties |
| `daemon_v3` | The OSPFv3 runtime (RFC 5340): the same run-loop shape over the v6 transport, Router-ID neighbors, Instance-ID dispatch, scope-aware flooding (link-LSAs in per-interface stores), v3 origination, §16.4-lite exports |
| `zedge` | ospfd as a zebra client: HELLO attach, `redistribute static` → §12.4.4 origination/withdrawal, route export |
| `wire` | Checked little helpers over byte slices — the house codec convention (A19: never trust counts) |
| `config` | `ospfd.conf` grammar (A11/B7 conventions): router-id, area, interface stanzas, network bindings, redistribute static, the RFC 8177 `key chain` stanza + interface references, `rfc1583-compatibility`, `area <id> range` (advertise status + cost), the NSSA translator role/stability, the v3 interface `prefix` lines |
| `bin/ospfd` | Thin shell (bgpd/savd shape): config → sockets → zedge → the daemon run loop |

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

**The v3 codec slice landed (N2B, 2026-10-11): the seams held.**
`lsa_v3.rs` + `packet_v3.rs` are *parallel* v3 modules (the Holo
placement — separate per-version bodies over the shared core), and
the v2 codecs are untouched: nothing the LSDB, aging, flooding
decisions or checksums need had to move. What the v3 family
confirmed concretely:

- The Fletcher-16 placement (offset 14 from byte 2, field at 16-17)
  and the signed sequence space port **verbatim** — the v3 tests
  re-verify both.
- The LSU count + per-LSA length probe, the LSR 12-byte-entry
  arithmetic and the bare-header DBD/LSAck shapes port with only the
  header codec swapped.
- The two real design moves were exactly the two the priming notes
  predicted: the **U-bit unknown-type tolerance** (v3's `Unknown`
  body with raw bytes for byte-faithful flooding — the opposite of
  v2's reject; the reserved S2/S1 scope `0b11` is still rejected)
  and the **pseudo-header checksum inputs** (encode/decode take
  `(src: Ipv6Addr, dst: Ipv6Addr)`; the transport supplies the real
  socket addresses when a v6 runtime exists).
- Curated strictness for v3 (recorded, RFC-cited in the tests):
  unknown **Options**/PrefixOptions bits are carried and ignored
  (A.2's "ignore the unrecognized bits" — the deliberate exception
  to the reserved-bit house rule), the deprecated x-bits (router
  flags 0x08, options 0x04, prefix-options 0x04) are set-0/ignored,
  and structural reserved fields (the prefix triple's 16-bit zero,
  the router-link reserved octet, the five bits above E/F/T, the
  DBD preamble's reserved octets, the LSR entry's reserved halfword)
  reject non-zero as in v2.
- v3-only facts pinned: the DBD preamble is 12 bytes (the
  MTU + reserved-octet + flags row keeps the no-padding lesson —
  an empty ExStart DBD is exactly 28 bytes); Hello's dead interval
  is 16-bit; DR/BDR are Router IDs; the LSR entry's LS type is the
  16-bit v3 type under a 16-bit reserved halfword; NSSA 0x2007
  shares the AS-external body decode (A.4.8) with the FA-must-be-
  global rule (A.4.7: never `::`, never `fe80::/10`).

Decisions behind the slice (the notes' stop-and-record items):
5340 fixed layouts first — RFC 8362's E-LSAs are deferred (the live
oracle FRR 10.2.2 ospf6d speaks legacy shapes); parallel
`LsaBodyV3` enum rather than widening the v2 enum (keeps
`Lsa::decode` single-entry per family; a shared trait can come with
the first code that processes both); Instance ID decode-and-carry
only (equality is interface-layer); the Nt bit decode-carry only
(RFC 3101 v3 translation semantics ride with future type-7 work);
no test-oracle corpus existed, so goldens are hand-derived from the
RFC diagrams and byte-pinned in comments — the wire-truth leg (a
live FRR ospf6d interop, v6 sockets and all) is the recorded
follow-up below.

## Day-2 additions (2026-10-10/11, the transport + daemon + interop)

- **socket2 adopted for ospfd** (owner decision A1, adopted
  2026-10-11; the Day-1 STOP resolved). `transport.rs` owns the raw
  proto-89 socket: 224.0.0.5 join, IP_MULTICAST_IF, TTL 1 on both
  arms, AllDRouters join/leave on §9.4 role. The safe-IO seam:
  socket2's recv wants `MaybeUninit` buffers, so the armed fd is
  dup'ed into a tokio `UdpSocket` (same kernel socket) for safe async
  send/recv.
- **The receive-side TTL check is CLOSED (night N1, 2026-10-12)**
  — with no cmsg at all: a raw `SOCK_RAW` socket delivers the whole
  IPv4 header with every datagram (raw(7)/raw(4)), and the TTL octet
  (header offset 8) is read pure by the existing `parse_ipv4`.
  `IP_RECVTTL` (ip(7)) is the UDP/TCP-socket mechanism for the same
  readout — a raw v4 socket never needs it (the disclosed
  raw-vs-UDP cmsg difference). Enforced: a UNICAST exchange packet
  (DD/LSR/LSU/LSAck, p2p Hellos) arriving with TTL != 1 is dropped
  and counted (`Ospfd::dropped_degraded_ttl`, INFO-logged per drop) —
  §A.1 mandates TTL 1 on every OSPF send, so a degraded TTL means the
  packet was relayed, not sent by an on-link peer. Multicast Hellos
  keep the kernel's rule: no receive check (RFC 2328 places no
  receive-side TTL rule; §A.1's TTL-1 is a transmit mandate — FRR
  checks nothing on receive either). The OSPFv3 runtime's v6 raw
  socket WILL need the cmsg walk (RFC 3542 §6 `IPV6_RECVHOPLIMIT`:
  raw v6 sockets do not deliver the IPv6 header) — recorded in
  §Deferred.
- **SO_BINDTODEVICE remains fenced** (socket2 0.6.5 has no
  `bind_device`), so a per-interface socket cannot scope its
  *reception*; every raw proto-89 socket in the process receives
  every OSPF packet. The daemon demultiplexes by on-link source
  address (the zapi-interface-mirror test) and processes each packet
  exactly once, on the socket of the interface the source is on.
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
  §16.4-lite external calculation (§16.4 steps 1-5 in the
  single-area form: ASBR distance from the intra-area table; the
  type-4 inter-area lookup is deferred with §16.2-§16.3).
- **The zapi edge** (`zedge.rs`, the bgpd idioms): HELLO as OSPF
  (7), `redistribute static` registration → the
  REDISTRIBUTE_ROUTE_ADD/DEL pushes become §12.4.4
  origination/withdrawal. Router ID comes from config (no
  ROUTER_ID_ADD — the zapi client exposes no raw send; disclosed).
  Interface addresses: DYNAMIC as of ADD-C2 — ospfd requests the
  INTERFACE_ADD dump at startup (`ifdump`: the empty-body request,
  the savd causality-marker bounding the no-end-of-dump burst) and
  merges it with the config, static `address` lines the fallback;
  see the ADD-C2 section below.
- **The p2p next-hop seam**: no LSA carries the p2p neighbor's
  address (Link Data is the advertiser's own); the adjacency (the
  Hello source) does — the daemon decorates the gateway at export
  (`p2p_peer_address`), keeping SPF pure over LSAs.
- **Interop**: `scripts/test-ospf-frr-interop.sh` — Full adjacency
  with real FRR 10.2.2 over a p2p link, LSDB convergence both ways,
  static→redistribute BOTH directions (ours → FRR's kernel; FRR's →
  our §16.4 → kernel via rousterd), 30 s soak, exit 0 twice
  back-to-back. FRR sets the type-5 forwarding address to a via-us
  static's nexthop (§12.4.4), so the reverse direction uses a
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

## Inter-area (2026-10-11, the N2 M4 slice)

- **Multi-area landed**: the config takes multiple `area` stanzas
  (interfaces bind to their area), the daemon keeps one LSDB + SPF
  throttle + router-LSA origination per area, AS-external LSAs are
  mirrored into every area's database (§7: "considered to be part
  of each area's link-state database" — one origination, identical
  instances, `Lsdb::mirror_originated`), and flooding is scoped
  (types 1-4 same-area; type-5 AS-wide, received ones re-flooded
  out the other areas per §13 step 1f). The router-LSA's B-bit
  follows ABR status (§A.4.2).
- **§16's walk is router-wide now**: intra-area SPF per area, the
  §16.2 inter-area routes from the examined area's summary-LSAs
  (backbone when multi-area — "only backbone summary-LSAs are
  examined"; the single area otherwise), with steps (1)-(7)
  verbatim including the intra-always-preferred rule and the
  equal-cost merge; the full §16.4 external calculation with the
  type-4 ASBR lookup and §16.4.1's preference order
  (RFC1583Compatibility disabled — FRR 10.2.2's probed default:
  intra-non-backbone first, intra-backbone and inter-area equal,
  then least cost, largest area ID) and the forwarding-address
  resolution; export diff over intra + inter + external.
- **§12.4.3's ABR duties**: type-3 summaries for the
  inter-area-eligible networks (intra routes into every other area
  incl. the backbone; inter-area routes into non-backbone areas
  only), type-4s for the preferred ASBR paths (ABR destinations
  skipped per the first bullet), the split-horizon and own-area and
  LSInfinity gates, metric = the routing-table cost, and the
  withdrawal flush (premature age + reflood) for summaries no
  longer justified. **Disclosed**: no configured `area range`
  support yet — the §12.4.3 default (one type-3 per network)
  applies; the coalescing/aggregation rules land with range config.
- **Interop**: `scripts/test-ospf-interarea-interop.sh` — rouster as
  the ABR between two real FRR ospfd (an FRR ABR with a dummy area
  2 on the area-0 side; an FRR ASBR redistributing a blackhole
  static in area 1), exit 0 twice back-to-back: our type-3 for the
  area-1 network sits in FRR's area-0 database beside FRR's own and
  lands in FRR's KERNEL via us (O IA); FRR's type-3 for its area-2
  network reaches our §16.2 and our kernel via FRR; our type-4 for
  the area-1 ASBR sits in FRR's asbr-summary table and FRR resolves
  the redistributed static through us into its kernel.

## NSSA interop (2026-10-11, the N3 wire proof)

- **`scripts/test-ospf-nssa-interop.sh`** — rouster as the NSSA
  border router between real FRR 10.2.2 (r1 backbone-only; r3 the
  NSSA-internal ASBR redistributing a blackhole static), exit 0
  twice back-to-back, quarantine under the night program's n3/nssa.
  The wire proofs: r2-r3 Full ACROSS the NSSA (the N-bit agreement
  with real FRR, RFC 3101 §2.1); FRR's type-7 arrives with **P set
  and FA = its own NSSA interface address** (the captured §2.4 wire
  shape — FRR fills the type-7 FA where its type-5s use 0.0.0.0 for
  blackholes); **our §3.2 translation lands as a type-5 in r1's
  area-0 database (advertising router = us, FA copied) and r1's
  KERNEL routes the external proto ospf via us**; our own §2.5 calc
  installs the type-7's route via r3; our type-7 default sits in
  r3's NSSA database.
- **Two FRR divergences pinned live** (the A19/A23 discipline):
  1. RFC 3101 §3.1's "NSSA border routers must set the E-bit in the
     Type-1 router-LSAs of their non-stub areas" is LOAD-BEARING —
     without it FRR will not resolve our translated type-5s at all
     (the ASBR lookup fails); we set it via `nssa_border()`.
  2. FRR 10.2.2 does NOT install a foreign border type-7 default
     into its OSPF route table — neither the RFC's P-clear form
     (§2.4's letter, what we send) nor a P-set form (tested). The
     LSA is accepted and stored (database-proven). Suspected gate:
     FRR's translator election (the Nt bit, §3.1 — §Deferred with
     the election machinery).

## Stub areas (2026-10-11, the N3 M1 slice)

- **`area <id> stub [no-summary]` + `area <id> default-cost <n>`**
  land in the config grammar (FRR's area-parameter shape; parameter
  lines may reopen a declared area; the backbone cannot be stub —
  §3.6; default-cost defaults to 1, FRR parity). `redistribute
  static` with no external-capable area attached is a configuration
  error (§3.6: "AS boundary routers cannot be placed internal to stub
  areas").
- **The area kind threads everywhere E-capability matters**: our
  Hellos and DBD Options carry E clear in stub areas; §10.5's E-bit
  agreement check (landed Day 1) now enforces §3.6's "all routers
  belonging to an area agree" on the wire — a stub-area core drops
  E-set Hellos and no neighbor forms.
- **Flooding admission** (§13 step 3 receive-side): `AreaAdmission`
  (`neighbor.rs`) — type-5s are silently discarded in stub areas;
  FRR's totally-stubby (`no-summary`) discards type-3/4s too.
- **Type-5 scope**: origination picks the first external-capable
  area as the type-5 master, and both the §7 mirroring and the §13
  step-1f re-flood skip stub areas entirely — a stub area's LSDB
  holds no type-5s and no type-4s.
- **The ABR's stub duties** (§12.4.3.1/§C.2): into a stub area the
  ABR originates ONLY the default summary-LSA (type-3, LS ID
  0.0.0.0, mask 0.0.0.0, metric = the area's `default-cost`) —
  no per-network type-3s beyond the plain-stub set, no type-4s
  (§12.4.3's ASBR-destination rules make them meaningless without
  type-5s), and the internal routers resolve 0.0.0.0/0 through §16.2
  at cost BR-distance + default-cost.
- **§13.4 fix riding along**: `wants_to_originate` now answers true
  for summaries the fresh table still justifies (the N2 comment
  said "none are originated yet" — stale since M4); a newer
  echoed self-summary is re-adopted, not flushed.

## NSSA (2026-10-11, the N3 M2 slice — RFC 3101)

- **`area <id> nssa [no-summary] [default-information-originate]`**
  + `default-cost` reuse (metric of the area default). The
  `default-information-originate` FRR knob is accepted for grammar
  compatibility but is a no-op in behavior: RFC 3101 §2.4's "NSSA
  border routers **must** originate an LSA for the default
  destination into all their directly attached NSSAs" is implemented
  unconditionally; FRR 10.2.2 conditions it on the NHT import check
  (A23's `z5e` probe — `ospf_abr_nssa_type7_defaults` fires off the
  NEXTHOP_UPDATE answer; our zedge has no NHT registration yet, so
  the RFC form landed and the FRR difference is recorded here).
- **The type-7 LSA** (`LsaType::NSSA`, header type 7): the body is
  the AS-external shape (RFC 3101 Appendix C) — one `LsaBody::
  AsExternal` serving both wire types; the P-bit rides the header
  Options' N/P position (`Options::NP`).
- **N-bit agreement** (RFC 3101 §2.1): NSSA Hellos/DBD Options carry
  N set + E clear; §10.5 processing additionally verifies the N-bit
  matches the area type and rejects E&N both set.
- **Flooding scope** (§2.3): type-7s are area-scoped like types 1/2
  — admitted only in their NSSA, discarded in normal/stub areas;
  type-5s are still never flooded into an NSSA.
- **Origination** (§2.4): a redistributed route becomes a type-7 in
  every attached NSSA alongside the type-5 in the normal areas. The
  P-bit follows the RFC's both-forms rule — set for an NSSA-internal
  ASBR (with FA = the router's own NSSA interface address; P-set
  demands non-zero FA per §2.3), clear for a border router that also
  originates the type-5.
- **The border defaults** (§2.4/§2.7): plain NSSA → type-7 default
  (P clear, metric = default-cost); totally-NSSA (`no-summary`) →
  type-3 default (§2.7's protection against diverting intra-AS
  traffic out a type-7 default). Summaries (type-3s) are imported
  into plain NSSAs; type-4s never are.
- **§2.5 route calculation**: the type-7s of every attached NSSA are
  examined alongside the type-5s — the ASBR/forwarding-address
  lookups restricted to intra-area paths through the originating
  NSSA ([NSSA] paragraphs verbatim), the border-router skip rules
  for type-7 defaults, and §2.5 step (6)(e)'s preference ladder
  (type-7-P-set > type-5 > type-7-P-clear, higher Router ID last).
- **§3.2 translation**: the border router translates every
  translatable type-7 (P set + non-zero FA) into a type-5 — same
  network/mask/metric/FA/tag, advertising router = the translator,
  flooded into the normal areas; flushed when the source stops being
  translatable. v1 scope, disclosed: NSSATranslatorRole is
  effectively Always (no Candidate election, no Nt bit, no
  TranslatorStabilityInterval — single-ABR lab shape), no Type-7
  address ranges, the type-7 default never translates, and §3.2's
  LS-ID remapping on type-5 collisions is absent.
- **Riding fixes**: the daemon now floods summary originations and
  flushes on the real wire path (N2 built them into a dropped local
  vector — only RxmtInterval retransmits delivered them), and §12.4
  refresh re-originates every self-originated LSA (summaries and
  externals used to age to MaxAge silently).

## Authentication (2026-10-11, the N3 M3 slice — Appendix D + RFC 5709)

- **Three modes per interface** (`auth.rs`): Null (D.1), simple
  password (D.2 — `authentication-key <1-8 chars>`, null-padded to
  the 64-bit field per D.4.2 step 3), and cryptographic (D.3/D.4.3
  — `authentication message-digest` +
  `message-digest-key <id> <md5|hmac-sha-256> <key>`, plus
  `authentication key-chain <name>`; see the S8-b section below).
  FRR 10.2's `message-digest-key` only accepts `md5`; its
  HMAC-SHA-256 rides the key-chain path (frr-10.2 `lib/keychain.c`'s
  algo table: internal-crypto builds resolve `md5` +
  `hmac-sha-256` only) — our spelling of the RFC 5709 digest as an
  explicit keyword was the disclosed N3 deviation, resolved S8-b
  (both spellings parse; chains and static keys select either
  engine).
- **Verification order** (D.5, implemented in
  `Ospfd::authenticate`): authentication precedes ALL §8.2
  processing; a failed packet is silently discarded — no neighbor
  event fires, so the ONLY neighbor-state effect of sustained
  failure is the Inactivity Timer's Down transition (tested in
  exactly that shape). Simple mode: checksum (D.5.2 step 1, the
  codec's existing auth-excluded checksum) then field equality
  (step 2). Crypto mode (D.5.3): Key-ID lookup, then the per-neighbor
  sequence check ("less than the recorded value" discards; equal
  passes for retransmissions), then the digest; the accepted
  sequence is recorded (D.3) and reset on the neighbor's Down
  transition.
- **The Figure-18 field** (D.3): `CryptoAuthData` views the 64 bits
  as zero octets + Key ID + Auth Data Len + sequence. In crypto mode
  the packet checksum stays 0 (D.4.3 step 2 — `Packet::encode`
  branches on AuType; `Packet::decode_crypto` skips the checksum,
  splits the appended trailer at `header.length`, and hands the
  trailer to the caller for MAC verification). The MAC input is
  packet ‖ Apad (RFC 5709 §3.3: `0x878FE1F3` × 8).
- **One sequence counter per interface** (D.4.3 step 5's
  non-decreasing rule): the daemon's Hellos/floods and every
  conversation share an atomic counter — the first cut had two
  counters and the DBD stream legitimately ran "backwards" against
  the hello stream (caught by the daemon-level sign/verify test).
- **The digest primitives are hand-rolled pure safe Rust**
  (`sha256`/`hmac_sha256` in `auth.rs`) — verified against FIPS
  180-4 and RFC 4231 test-case vectors — because the standing fence
  admits no new dependencies. Swapping to the `sha2`/`hmac` crates
  is an owner decision (recorded); the module boundary is drawn so
  the swap is one file, and so OSPFv3's RFC 7166 trailer can reuse
  the MAC/Apad/replay skeleton (the 64-bit descriptor view is the
  only v2-specific part).
- **No live FRR auth interop leg yet** (disclosed): the wire
  conventions are RFC/ADD-A2-pinned and vector-tested; an
  FRR-10.2.2 key-chain HMAC-SHA-256 leg is the natural next interop.

## Key chains and both crypto engines (2026-10-14, the S8-b lane)

- **The RFC 8177 key chain stanza (O-8)** lives in ospfd's own
  config at FRR's frr.conf placement — depth-0 `key chain <name>`
  beside `router ospf` (either order parses; a depth-0 stanza line
  closes whatever is open), nesting `key <1-255>` (the Figure-18
  octet — 8177's uint64 narrowed to what the v2 wire stamps) →
  `key-string`, `cryptographic-algorithm <md5|hmac-sha-256>`,
  `send-lifetime/accept-lifetime <start> <end|infinite>`. RFC 8177
  §2.2's required key-string and crypto-algorithm are enforced at
  the stanza close with line numbers; lifetimes default to ALWAYS
  when absent. v1 disclosure: lifetime seconds live on the daemon's
  INJECTED clock (wall-clock/NTP-anchored lifetimes — what
  cross-router rollover actually needs, 8177 §2.4's
  time-synchronization recommendation — swap in at the `now` seam
  without touching the model).
- **Interfaces reference a chain by name** — `authentication
  key-chain <name>` (FRR's `ip ospf authentication key-chain` form);
  references resolve at parse end so the stanza may precede or
  follow the router stanza. Per-interface v1 (area-level auth is
  not in the grammar at all).
- **Both engines are first-class now**: keyed-MD5 (RFC 2328
  D.4.3(6) — MD5(packet ‖ key), the 16-byte trailer; RFC 1321
  vectors) joins HMAC-SHA-256, selectable per key in a chain AND in
  the static `message-digest-key <id> md5 <key>` form (FRR's own
  keyword — the N3-era grammar rejection is gone; the disclosed
  N3 deviation flips to "both spellings parse"). MD5's collision
  weaknesses are the known cost of interop with deployed peers;
  `hmac-sha-256` stays the recommended configuration.
- **Rollover semantics v1 (disclosed)**: accept-any-live /
  send-highest — the receiver accepts any key whose accept lifetime
  is live (RFC 2328 D.5.3 step 1), the sender stamps the live key
  with the most recent send-lifetime start (D.4.3's
  "most recent KeyStartGenerate"; 8177 §2.3's permission). Equal
  starts break deterministically to the higher Key ID (8177 leaves
  it unspecified). The daemon carries a per-interface LIVE send
  view refreshed on every tick/packet — a rollover advances within
  one tick. **Fail-closed**: a chain with no live send key degrades
  to the Null view — the interface transmits AuType-0 packets any
  crypto-configured peer discards by D.5, so the adjacency dies by
  its own timers rather than by unsigned garbage passing anywhere.
  Retransmitted conversation packets replay the field they were
  built with (the accept overlap is what makes that safe).
- **The knob (O-2)**: `rfc1583-compatibility <enabled|disabled>`
  under `router ospf` — RFC 2328 §C.1's global item, **default
  ENABLED per the RFC's letter** ("Set to 'enabled' by default";
  FRR 10.2.2's probed default is disabled — the divergence is
  deliberate and recorded here). Gates the §16.4 step-(3) ASBR-path
  preference: disabled prunes per §16.4.1 (intra-area non-backbone
  paths always most preferred), enabled applies no pruning — both
  then least cost, largest area ID. Wired at the external
  calculation and the §12.4.3 type-4 pick (the same preference
  FRR's ospf_abr task applies).

## Incremental SPF (2026-10-11, the N3 M4 slice — §16.5/§16.6)

- **The RFC's "incremental" means class- and area-scoped reruns, not
  Dijkstra subtree pruning** (the survey's naming caution: FRR/Cisco
  iSPF is a proprietary technique nobody in the BIRD/Holo survey
  implements either). What landed:
- **Per-area §16.1 caching**: each area keeps its last `SpfResult`;
  the router-wide §16 walk recomputes Dijkstra only for areas whose
  own topology changed (their own FRR-parity 0/50/5000 ms throttle —
  the N2 disclosure "recomputes ALL areas" is closed); unchanged
  areas reuse the cache. A `table_dirty` flag runs the §16.2/§16.4/
  export walk alone — the AS-scope class (type-5 installs, summary
  metric changes, type-7s) never recomputes an SPT (§16.5/§16.6's
  "not necessary to recalculate the entire routing table").
- **Class-based dirtying** at every change site: router/network-LSA
  changes mark the area; summary/external classes mark the table
  (`after_report` classifies per LSA type; so do the aging flushes).
- **Tests**: only-changed-areas-recompute (run counters), the AS-
  scope class updating routes with zero SPT runs, per-area backoff
  independence (a flap storm backs off ITS scheduler while a quiet
  area runs at the initial delay), and the W5B fixed-seed agreement
  property — randomized LSDB mutation sequences, incremental vs a
  forced-full twin, identical routing tables every step and strictly
  fewer §16.1 runs.

## Virtual links (2026-10-11, the N3 M5 slice — §15/§D.3)

- **`area <id> virtual-link <router-id>`** (FRR grammar; the
  directive lives under the TRANSIT area's stanza). Validation:
  virtual links never transit the backbone (§15) and never a stub
  area (§3.6).
- **One synthetic interface per virtual link** — a member of the
  BACKBONE (its conversations, Hellos and floods carry area 0; the
  LSDB is area 0's) riding the transit area. Unnumbered-p2p shape:
  no DR election, no network-LSA, no stub link.
- **Endpoint resolution** (§15: "the other endpoint's address is
  discovered by looking up the router ID in the routing table"):
  after each area walk, the transit area's intra-area path to the
  peer Router ID supplies the endpoint address (the p2p adjacency's
  peer address). No Hellos before resolution; the conversation's
  destination tracks re-resolution. Disclosed v1: the directly-
  connected transit shape (the resolved next hop IS the endpoint's
  own address); multi-hop transit endpoints take the §15 routing
  refinement.
- **Wire shape**: virtual-link Hellos are unicast to the resolved
  endpoint; backbone-area packets arriving on a non-backbone
  interface demultiplex to our virtual link for that area (§15's
  tunneled-in-IP model at the daemon level). The daemon's bin opens
  the vlink's socket on the transit interface's address (v1).
- **§D.3/§12.4.1**: the backbone router-LSA carries one type-4
  (virtual) link per Full endpoint — Link ID = the endpoint's Router
  ID, Link Data = our address on the transit network (RFC 2328 names
  the MIB-II ifIndex for the unnumbered form — disclosed deviation;
  SPF treats type 4 exactly like a type-1 router edge). The TRANSIT
  area's router-LSA sets the V-bit (§A.4.2) — the TransitCapability
  input to §16.1.
- **The e2e proof** (`virtual_link_joins_a_partitioned_backbone`):
  two ABRs split area 0 between them, joined only by the vlink over
  area 1 — the vlink resolves, forms Full over unicast
  backbone-area packets, the type-4 links land in the backbone
  router-LSAs, the V-bit in the transit router-LSAs, and the two
  halves route each other's stub networks. §16.3's
  transit-summary refinement rides §Deferred below.

## The zapi interface dump as the address source (2026-10-11, ADD-C2)

- **ospfd is a zapi interface-dump consumer now** (`ifdump.rs`): at
  startup, before the core constructs, the daemon's zapi session
  HELLOs as OSPF, sends the empty-body INTERFACE_ADD (the
  registration request every FRR daemon sends), then a transient
  dummy NEXTHOP_REGISTER as the savd causality marker — the marker's
  NEXTHOP_UPDATE can only follow the server's processing of the dump
  request on the same session, so it is the deterministic dump-end
  delimiter (ZAPI has no end-of-dump marker). All pre-modeled
  message types; no new pins were needed (the W-series had already
  modeled INTERFACE_ADD/DELETE/ADDRESS_ADD/DELETE both directions).
- **Merge semantics — dump wins, config falls back**: a configured
  interface picks up its first non-secondary IPv4 address (mask from
  the prefix length; v6 skipped for this v2 daemon; secondary-only
  or v6-only keeps the static `address` line), its live link state,
  and nothing else. Interfaces the dump does not know keep their
  static config verbatim (standalone mode — no zapi socket — is
  exactly the v1 behavior, `link_state` absent).
- **Live link state at construction**: `IFF_UP|IFF_RUNNING` and not
  `IFF_LOOPBACK` (the flags word INTERFACE_ADD relays verbatim from
  the kernel). An interface the dump reports down — or a loopback,
  hello-less stub with no `passive` knob yet — does NOT fire §9.3's
  InterfaceUp: it sits in Down, sends no Hellos (the new tick gate:
  §9.3/§C.3's "Down sends none" — previously unreachable, every
  interface fired InterfaceUp at construction), and contributes no
  router-LSA links (§12.4.1's state filter already excluded Down).
  ONGOING tracking (INTERFACE_UP/DOWN pushes flipping a running
  interface) remains §Deferred — this is the startup snapshot.
- **MTU deliberately NOT overlaid** (disclosed): the wire body
  carries it, but rousterd's interface mirror does not — the dump
  frames stamp the codec default 1500 on every interface, which
  would stomp an operator's `mtu 9000` with a fabricated value.
  Rides §Deferred until the mirror carries the kernel's MTU.
- **One session, one HELLO**: the dump runs on the connection that
  becomes the resident zedge (`zedge::connect` + `spawn_with_client`)
  — the old connect-retry-spawn path is unchanged for callers that
  skip the dump.
- **Tests**: 11 unit tests over the collector/merge (primary
  selection skipping v6+secondary, the pending-address ordering
  bag, delete handling, loopback-not-usable, mask edges), 2
  daemon-level tests (a merged-down interface: Down, silent on the
  tick, linkless in the router-LSA; Some(true)/None exactly the v1
  construction), 2 integration tests over a real `zapi::serve`
  socket (the z5-family convention) driving a canned interface
  mirror through the server's actual dump encode → client decode →
  merge → `Ospfd::new`. The interop smoke grew
  `ROUSTER_OSPF_DYNAMIC_ADDRESS=1`: r2's ospfd.conf carries no
  `address` line — the dump feeds eth0 — with the dump log line
  machine-checked before the adjacency legs.

## The OSPFv3 runtime (2026-10-14, S7-a — the AF-generic proof, live)

The v3 daemon runs: `address-family ipv6-unicast` under `router
ospf` selects the `daemon_v3` core in the same `ospfd` binary; the
interface stanza carries the §2.5 `link-local` source, `instance-id`
(A.3.1) and an optional `ifindex` pin. The AF-generic scorecard,
honestly — what one codebase serves both families vs what RFC 5340
genuinely diverges on:

- **Shared, as the design promised (and now as CODE, not claims):**
  - `Lsdb<T: LsaInstance>` — ONE implementation of §12.2/§13.1/
    §13.2/§14 for both families (v2 is the default type parameter;
    v3 instantiates `Lsdb<LsaV3>` through the new
    `LsaHeaderInfo`/`LsaInstance` traits).
  - The §10.3 neighbor FSM table AND the §10.6 master/slave core —
    `NeighborFsm::process_dbd_view(DdView)` is family-neutral (v2's
    DBD and v3's DBD both map onto the view; `neighbor_options`
    widened u8→u32 for Options24).
  - The §10.5 event ladder (`process_hello_v3` checks the v3
    parameter set — intervals + E-bit, no mask — and fires the same
    events).
  - The checksums, the codec spines, the §12.4 constants, the zapi
    edge (`zedge` learned the family: HELLO OSPF/OSPF6, redistribute
    afi 1/2, the push filter), and the run-loop skeleton
    (sockets → mpsc → clock-injected core → wire obligations).
- **v3-specific, where the RFC diverges:** Router-ID neighbors with
  link-local addresses learned as Hello sources (§4.2.2.1); the
  Instance-ID discard; **flooding scope** (§3.2/§4.5.2 — link-LSAs
  live in per-interface stores and never leave the link, area/AS
  LSAs re-flood out other interfaces); the v3 origination set
  (router-LSA with interface-ID p2p links §4.4.3.1, the link-LSA
  carrying the link-local §2.5/A.4.9 with LS ID = Interface ID, and
  0x4005 externals for redistributed v6 statics); the A.3.1 16-byte
  packet header with its pseudo-header checksum inputs (src, dst);
  and the destination-trial decode (below).
- **The disclosed mirror:** the conversation bookkeeping
  (§10.8/§10.9/§13.3-§13.7) in `daemon_v3.rs` is exchange.rs's shape
  re-typed for v3, not a shared generic — the v2 `Conversation` is
  v2-`Packet`-typed end to end, and generifying it means rewriting
  the v2 daemon in the same breath. The FSM table and the LSDB it
  drives ARE shared; the send-obligation plumbing is mirrored.
  Recorded as the honest reading of "fix the seam, don't fork": the
  seam was fixed where the claim was cheap to cash (LSDB, FSM,
  hello ladder, codecs), mirrored where the rewrite would have put
  the v2 interop at risk in the same change.

**The v6 transport walls — the cmsg wall is CLOSED (S8-b, the
audited read-back):** a raw IPv6 socket delivers NO IPv6 header, and
the received hop limit + true destination ride RFC 3542 cmsgs no
safe API in the dependency set reads (every recvmsg wrapper needs
`unsafe`). The owner's 2026-10-14 AGENTS.md exception names the v6
cmsg read-back helper in `transport.rs` explicitly: `recvmsg_v6_ctl`
+ `arm_v6_recv_pktinfo` carry the bfdd audited-block treatment —
mandatory audit comments, target-pinned cmsg constants, kernel
round-trip tests on both families where the host permits, and the
libc entry is the one audited `setsockopt` (socket2 0.6.5 exposes
no `IPV6_RECVPKTINFO` setter). The v3 pump runs the read-back on its
own blocking thread (nonblocking poll rhythm, weak-Arc Drop
shutdown); the pseudo-header destination is the pktinfo cmsg's REAL
address now, with §4.2's candidate trial (`decode_v3_dst`) as the
fallback, and a unicast packet with a degraded hop limit is dropped
and counted — the v2 N1 rule mirrored (RFC 5340 §A.1 mandates hop
limit 1 on the multicast arm; our unicast transmit arm carries a
local parity of 1). The ifindex source is a pure `/proc/net/if_inet6`
parse (no libc `if_nametoindex` — FFI stays fenced outside the one
audited call).

**The interop evidence** (`scripts/test-ospfv3-frr-interop.sh`,
exit 0 twice back-to-back; quarantine under
`away/2026-10-14/quarantine/n3v6/`, env-overridable): Full adjacency
with real FRR 10.2.2 ospf6d over a p2p v6 network (link-local
sources only, ff02::5 hellos, instance ID 0 both sides); both LSDBs
holding the other's router- AND link-LSAs (both flooding scopes);
and a redistributed v6 static BOTH directions landing in the peer's
kernel `proto ospf` **via the advertiser's link-local through
rousterd** — ours (0x4005, E2) resolved by FRR's link-LSA next-hop
lookup, FRR's installed by our §16.4-lite direct-ASBR calculation
exported as `Nexthop::Ipv6If(gw, ifindex)`; 30 s soak stable, no
zapi reconnects.

**Two wire truths the live oracle pinned** (the N2B report's
recorded test-oracle gap, closed):

1. **The AS-external body's Referenced LS Type sits in the prefix
   row's third halfword** (A.4.7's `PrefixLength | PrefixOptions |
   Referenced LS Type` row — the slot the generic A.4.1 triple
   reserves as zero), NOT after the address prefix. N2B's
   hand-derived golden pinned the wrong placement (its symmetric
   encode/decode round-tripped); FRR's `ospf6_lsa_examin` rejected
   every type-5 with "anomaly in AS-External LSA" until the diagram
   row layout landed. The golden test now pins the placement
   byte-exactly.
2. **Every `vtysh -b` re-apply flaps ospf6d's adjacencies** — the v2
   interop's retry-until-visible config loop cannot be reused; the
   script applies at most twice and waits for visibility by other
   means. (Also benign and probed: FRR 10.2.2 ospf6d receives its
   own multicast hellos via the kernel loop and drops them as
   "Duplicate Router-ID" at hello cadence — upstream cosmetic.)

Rig note: the containers run `--privileged` — docker-desktop ships
fresh netns interfaces with `disable_ipv6=1` and the sysctl write
needs `/proc/sys` writable; the caps-only v2 rig shape cannot bring
v6 up. Disclosed in the script header.

## The S10-b round (2026-10-15): the v3 runtime remainder, the NSSA translator, ranges, vlink tails

### The full v3 SPF (RFC 5340 §4.8.1/§4.8.2)

`spf_v3` replaces the S7-a §16.4-lite direct-ASBR interim in the v3
daemon's walk. The three §Deferred-named specifics, each pinned by a
dedicated test and the property batteries (a Bellman-Ford oracle over
random fragmented topologies, a fragment-split equivalence property,
the first-edge next-hop oracle in the v3 hop shape):

- **Transit vertices key on (DR Interface ID, DR Router ID)** — the
  network-LSA's (LS ID, Advertising Router) pair (§4.8.1's vertex ID);
  two networks sharing a DR Interface ID stay distinct (tested).
- **The A.4.3 multiple-router-LSA concatenation**: all fragments of
  one router process as an aggregate (links concatenated), with the
  Options and Nt/V/E/B bits taken from the fragment with the
  SMALLEST Link State ID — the V-bit on a higher fragment is ignored
  for TransitCapability (tested both ways). Origination stays
  single-fragment while links fit (disclosed).
- **§4.8.2 next hops**: the adjacent router's link-local comes from
  its link-LSA in the outgoing link's link-local-scope store (the
  RFC's primary path); the hop also carries the adjacent Router ID
  (`via`) for the RFC's Hello-source fallback (the daemon substitutes
  the adjacency's Hello source when the link-LSA is not there yet);
  an IAPR referencing a directly-connected network-LSA takes the
  no-address form ("the next hop is solely the outgoing link").
- Stage two walks the intra-area-prefix-LSAs (referenced router OR
  network vertex, NU-bit prefixes excluded); §4.8.1 step 2b's V6/R
  gate excludes non-transit routers.
- The daemon: the SPT runs on the v2 engine's FRR-parity throttle
  with §16.5's class split (router/network LSAs recompute the SPT;
  IAPR/external installs rerun the table walk on the cached result);
  the external calculation resolves ASBRs THROUGH the tree (multi-hop
  ASBRs route — tested over a three-core chain), with §4.8.5's F-bit
  forwarding-address longest-prefix resolution.

### The v3 broadcast arm + the IAPRs

- **The §9.4 election over v3 Router-ID claims**: the shared
  `hello_interface_events`/`elect_dr` machinery wired over v3
  identities — DR/BDR claims are Router IDs (§A.3.2) riding the
  shared election's identity slot (`rid_identity` — compared, never
  interpreted as an address); BackupSeen/NeighborChange/WaitTimer
  fire; §10.4's broadcast AdjOK answer applies (adjacent with/toward
  the DR/BDR only).
- **The ff02::6 receive gate** (§4.2/§A.1): AllDRouters packets
  process on the DR/BDR only; the run loop reconciles the socket's
  ff02::6 membership to the elected role (S7-a's armed join arm,
  now driven). Floods on broadcast links go multicast per §13.3 —
  ff02::5 from the DR/BDR, ff02::6 from DR Others (retransmissions
  unicast).
- **The DR duties**: the network-LSA (§4.4.3.3 — LS ID = the DR's
  Interface ID, attached = the Full set + self, Options = the OR of
  the attached routers' link-LSAs) and the network-referenced IAPR
  (§4.4.3.9 part 1 — every fully-adjacent router's link-LSA prefixes
  at metric 0, NU/LA skipped, duplicates OR-combined), flushed on
  losing DR; the router-referenced IAPR (§4.4.3.9 part 2 — the p2p
  interfaces' configured prefixes at the interface output cost).
  Interface prefixes are configured per interface (`prefix <v6/len>`)
  and ride the link-LSA (§4.4.3.8).
- Riding fix: origination dirty flags survive MinLSInterval
  rejections (a cleared-on-reject flag stranded the updated LSA
  content — found by the broadcast mesh test).
- Live state: the pure three-core broadcast mesh test covers the
  election agreement, the §10.4 matrix, the network-LSA + IAPR
  contents, and the DROther's SPF installing peers' prefixes as
  directly connected; a broadcast leg against FRR ospf6d is §Deferred
  (the p2p FRR leg stays the v3 interop).

### The NSSA translator remainder (RFC 3101 §3.1/§3.2/E)

- **The election**: `area <id> nssa translate-candidate|translate-always`
  (FRR's spellings; default Candidate per Appendix D.1) +
  `translate-stability-interval <1-3600>` (default 40 s). The
  Candidate election runs in the §16 walk over the §3.1 list (border
  routers reachable over the NSSA AND the transit topology); an
  Nt-set or higher-ID member outranks us; a deposed translator keeps
  translating through the stability interval (the tick forces a walk
  at the deadline; the retirement flush runs there).
- **The Nt bit** (Appendix B, router-LSA flag 0x10 — the W bit 0x08
  and the top reserved bits stay rejected): set in the router-LSA
  originated INTO the NSSA while the translator state is
  enabled/elected; SPF's router flags carry (B, E, Nt) per area.
- **Type-7 address ranges** = the configured `area <id> range` list
  on the NSSA: §3.2 step (1)'s most-specific DoNotAdvertise
  suppression; step (3)'s aggregation (path type 2 when any member is
  type 2, metric = highest type-1 cost / highest type-2 cost + 1, FA
  0.0.0.0, one type-5 per range, members suppressed, our own
  same-[addr,mask] type-5s joining the metric computation); step
  (2)'s plain translation with the highest-Router-ID equivalence
  rule; and the LS-ID host-bit remapping when the natural ID is
  taken by one of our own type-5s describing a different network.
- **Appendix E**: a border router now INSTALLS the foreign P-clear
  type-7 default locally (never propagating — §3.2 never translates
  a P-clear default). Divergence from FRR 10.2.2 (which stores the
  LSA but installs no route — probed live in the N3 interop): the
  RFC appendix's technique wins here.

### Area ranges (§12.4.3 + §16.2(3))

`area <id> range <a.b.c.d/m> [advertise|not-advertise] [cost <n>]`.
Each ACTIVE range of the range-owning area (at least one
contributing intra-area route) coalesces its members into ONE
summary advertised into every other admitting area — metric = the
members' minimum cost or the configured `cost` override, mask = the
RANGE's — with the members' own summaries suppressed;
DoNotAdvertise suppresses them outright; the split-horizon gate
applies to the contributing set. §16.2 step (3): a foreign summary
describing a network inside one of OUR actively-advertised ranges is
not installed (differential-tested — a foreign summary outside the
ranges still installs).

### The virtual-link tails (§15/§16.1 step 4/§12.4.1)

- **§16.1 step 4's endpoint resolution**: the SPF tree tracks each
  router vertex's parent and reports X's interface address pointing
  back at X's parent; the §15 resolution uses it — the MULTI-HOP
  transit shape resolves the peer's OWN transit-facing address, not
  the first-hop gateway (v1's interim, kept as the fallback). The
  type-4 Link Data keeps §16.1 step 4's address form, with a
  synthetic MIB-II ifIndex fallback for the unnumbered form.
- **§15's routed packets**: the vlink socket carries TTL 64 (§A.1
  scopes TTL-1 to multicast; the packets are IP-forwarded through
  the transit area), the receive-side N1 TTL check exempts vlink
  endpoints, and the run loop's on-link demux accepts the RESOLVED
  vlink peer addresses.
- **§13.5's sequence-aware retransmission clearing** (direct and
  implied acks): an ack for an OLDER instance does not retire a
  newer queued retransmission — the MinLSArrival same-instance race
  stranded re-originated LSAs forever; found live against FRR.
- **The live interop leg** (`scripts/test-ospf-vlink-interop.sh`,
  exit 0 twice back-to-back): the partitioned backbone joined by a
  virtual link between two rouster endpoints over a REAL FRR 10.2.2
  transit — transit Full both sides, both §16.1-step-4 resolutions
  on the wire, the vlink adjacencies Full, the backbone databases
  joined, r1's area-0 stub routed into r2's kernel through the vlink
  and r2's redistributed static into r1's, 20 s soak. Rig truths:
  the transit box must ip_forward (FRR zebra enables it; rousterd
  does not yet), and FRR-side vlink ENDPOINTS do not come up against
  our zebra (FRR's vlink socket wants a kernel "VLINK0" interface
  and its up-state rides zebra NHT our zapi server does not feed) —
  both endpoints run ours; the FRR-endpoint form stays §Deferred.

## The S10-e round (2026-10-15): the v3 interop REDIST-IN flake

The `test-ospfv3-frr-interop.sh` REDIST-IN machine check ("our ospfd
installed FRR's external route") failed ~half the runs after S10-b
landed. Root cause (ours, `daemon_v3`): the own router-LSA
re-origination at adjacency FULL is MinLSInterval-deferred (FULL
arrives <5 s after the t=0 startup origination) and lands later from
the tick retry — and that landing did not re-dirty the SPF. The cached
§4.8 result therefore kept the pre-adjacency graph (`routers=[]`)
forever whenever the peer sent no post-Full router-LSA refresh (FRR
refreshes ~5 s after ITS Full — its LSA min-arrival — so whether the
refresh re-dirtied our SPF before the external arrived was a pure
race); every §16.4 external then resolved its ASBR against an empty
routers set and never installed. The green runs were green only via
FRR's refresh. Fix: `originate_router_lsa` marks the SPF dirty when a
landed instance changed contents — the parity the v2 seam always had
(`daemon.rs` marks on every own router-LSA origination). Pinned by
`deferred_own_router_lsa_landing_reruns_spf_and_installs_external`
(the silent-peer shape; it fails exactly on the field symptom without
the fix) and six consecutive green interop runs. Riding along: the
§16.4 skip reasons and the SPF-ran router set now log under
`ROUSTER_OSPFV3_TRACE` (the instrumentation that caught it).

## §Deferred (updated S10-b, 2026-10-15)

- §16.3 (transit areas' summary-LSAs — the V-bit lands with the
  virtual links, the summary rules themselves remain); graceful
  restart (RFC 3623); DNA honoring.
- **OSPFv3 runtime remainder** (S10-b closed the SPF, the broadcast
  arm, and the IAPRs; what remains): multi-area v3; RFC 8362 E-LSAs
  (O-12: 5340 fixed layouts first — the live oracle speaks legacy);
  RFC 5838 address-family instances; v3 auth (IPsec/RFC 4552,
  trailer/RFC 7166 — the auth.rs MAC skeleton is v3-ready); virtual
  links with v3 semantics (global-scope sources; the §4.8.1 step-4
  LA-bit neighbor-address rule); the ifdump v6 link-local merge (the
  static `link-local` line is the source); NSSA-in-v3 (type-7 0x2007
  rides the shared external codec; the §2.x v3 semantics — including
  the v3 form of the S10-b translator election — do not); the
  multiple-fragment v3 router-LSA ORIGINATION (the SPF consumer
  concatenates; origination stays single-fragment while links fit);
  the FRR broadcast leg for v3 (the p2p leg stays the interop).
- **The FRR-side vlink endpoint**: FRR 10.2.2's vlink endpoint
  against our zebra does not come up (its vlink socket binds to a
  kernel "VLINK0" interface — ENODEV without one — and even with a
  dummy VLINK0 its receive path discards our backbone-area packets
  on the transit interface with "ospf_read invalid Area ID"; its
  up-state rides zebra NHT our zapi server does not feed). The live
  vlink leg runs both endpoints as rouster over an FRR transit; the
  FRR-endpoint form wants zapi-server NHT first (an owner decision
  on rousterd's zapi surface).
- vlink auth (v1 rides the transit interface's auth); §16.3.
- NBMA and Point-to-MultiPoint networks (§C.3).
- The walker-hoist-into-common owner decision (bfdd's copy now has a
  sibling); SO_BINDTODEVICE-style interface scoping rides with it.
- Auth remainder: the live FRR key-chain interop leg (FRR 10.2.2's
  `key chain` with hmac-sha-256/md5), wall-clock/NTP-anchored
  lifetimes (v1 rides the injected clock — the `now` seam is the
  swap point), RFC 8177's wider algorithm set / hex key-strings /
  duration-based lifetimes, per-area auth surfaces, and the
  `sha2`/`hmac` crate swap (owner decision; one-file change).
- Interface link-state tracking ONGOING (the dump's startup snapshot
  landed with ADD-C2); the MTU overlay once the interface mirror
  carries the kernel's MTU; `passive-interface` (loopbacks as
  stub-only members).
- The SAVNET intra-domain IGP signaling wire protocol
  (`experimental-savnet`) once the draft's format is pinned. The
  in-process half LANDED (2026-10-11) behind the flag: see
  [savnet.md](savnet.md).
