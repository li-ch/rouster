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

## §Deferred (updated day-3 anchors)

- §16.3 (transit areas' summary-LSAs — only meaningful with virtual
  links, which set TransitCapability); incremental SPF (§16.5/§16.6);
  virtual links (§15); authentication
  (Appendix D); graceful restart (RFC 3623); DNA honoring; OSPFv3
  bodies (the ladder's codecs-only scope).
- NSSA remainder: translator election (Nt bit, Candidate role,
  TranslatorStabilityInterval — RFC 3101 §3.1), Type-7 address
  ranges, §3.2 LS-ID remapping, the Appendix E P-bit-default
  install technique, keyed-MD5 (AuType 2 legacy digest).
- `area range` configuration — §12.4.3's address-range
  coalescing/DoNotAdvertise (the per-network default is implemented);
  §16.2 step (3)'s own-active-range check rides with it.
- RFC1583Compatibility is fixed at "disabled" (FRR parity) — no
  configuration knob yet.
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
