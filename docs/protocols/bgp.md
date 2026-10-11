# bgpd — the Rouster BGP daemon (Phase 2 stream P2-b, W2-d)

Status: v1 landed 2026-10-10 (P2-b, commits `6068045`..`e52826c`):
RFC 4271 base + capabilities + MP-BGP v4/v6 unicast + route refresh +
4-octet AS, a pure FSM, the §9.1 decision process, the ZAPI client
edge, and a two-green-runs interop smoke against real FRR 10.2.2
bgpd. W2-d (2026-10-11, `f034b08`..) added the typed policy engine in
the decision path, RPKI/ROV + OTC roles, ASPA verification, §6.8
collision detection, and the policy interop smoke. N5 (2026-10-11,
`ff58d91`..) added RFC 7606 revised error handling, route-server
mode v1, and RFC 4724 graceful restart.

## Layout

| Module | What |
|---|---|
| `message` | Header/OPEN/UPDATE/NOTIFICATION/KEEPALIVE/ROUTE-REFRESH framing (RFC 4271 §4; refresh RFC 2918 §3) |
| `capability` | RFC 5492 capability triples; extended OPEN optional parameters per RFC 9072 |
| `attr` | Path-attribute model: §4.3 flags, AS_PATH (RFC 6793 4-octet, AS_TRANS=23456 bridging), communities (RFC 1997), MP_REACH/MP_UNREACH (RFC 4760), OTC (RFC 9234 type 35), unknown-transitive passthrough with the partial bit forced |
| `fsm` | The §8 six-state machine, table-driven, pure and clock-injected |
| `peer` | Session runtime: framed IO, hold/keepalive timers, §6.2 OPEN checks, §9.5 AS-loop rejection, RFC 2918 refresh answers (inbound requests + outbound soft-reset hook), MRAI gate, Adj-RIB-In sink / Adj-RIB-Out source traits, `SessionShared` (the §6.8 observability) |
| `rib` | Adj-RIBs-In + Loc-RIB, `best_path` = the §9.1.2.2 ladder, Import/Export policy seams (§9.2.1 Phase 1/3) |
| `policy_engine` | The typed-engine bridge: `PolicyView` (bgpd's `RouteView`), wire↔policy attribute conversion with replace-or-insert write-back, `ImportPipeline`/`ExportPipeline`, config→filter compilation |
| `rov` | RPKI-derived validation: RFC 6811 §2 ROV, RFC 9234 §5 OTC ingress/egress by role, ASPA verification (draft-ietf-sidrops-aspa-verification-28 §5.5/§5.6), `vrp-file` fixture grammar, RTR table source |
| `zedge` | ZAPI client edge: NHT for peer addresses (connector gate), interface mirror, best-path export to the zebra |
| `daemon` | Listener (TCP 179 default, `listen-port` knob), per-neighbor connectors (§10 ConnectRetry, exponential 1 s→120 s), §6.8 collision resolution (BGP-ID tiebreak, Cease 6/7 to losers, challenger adoption via stream replay), graceful stop |
| `config` | `bgpd.conf` grammar (A11/B7 conventions) + policy-stanza extraction + `rpki`/`aspa`/role knobs + N5 neighbor knobs (`update-error-handling`, `route-server`, `graceful-restart`) |
| `bin/bgpd` | Thin shell (savd shape): config → filters/validation → Loc-RIB → zedge → daemon |

## Pinned design decisions

- **SIGTERM → NOTIFICATION Cease** (§6.7 sanctions a locally-chosen
  close; the Established Event 2 row prescribes Cease). Verified on
  the wire: FRR records `Notification received (Cease/Administrative
  Shutdown)`.
- **SIGUSR1 → ROUTE-REFRESH** (RFC 2918) to every Established peer —
  and since W2-d a true *soft inbound reset*: the peer's Adj-RIB-In is
  cleared when the request is sent, so the re-advertised set rebuilds
  against the current import policy (rejected or omitted prefixes
  vanish). Runtime policy *reload* is still §Deferred (YANG/
  rousterd-owned); the reset mechanism is the knob an operator uses
  after a restart.
- **MRAI default 0** (off) — modern practice: FRR ships MRAI disabled
  (v1 parity, pinned in config.rs) and BIRD has no MRAI at all; the
  delay trades convergence speed for message-rate smoothing and the
  research line (JIT-MRAI) argues for per-prefix pacing instead.
  RFC 4271 §10's 30 s eBGP / 5 s iBGP remain the documented tuning
  anchor; per-prefix MRAI queues are §Deferred.
- **§9.1.2.2 e) (interior cost) skipped** — the RFC allows skipping
  when no cost can be determined; no IGP exists yet.
- **DelayOpen always FALSE**; Events 16/17 and 24/25 unified per
  identical table handling; Events 14/15 stay at the TCP layer.
- **§6.8 collision: BGP-Identifier tiebreak.** A second connection
  for a busy neighbor triggers a resolver that reads the challenger's
  OPEN and applies §6.8's rule verbatim — "the connection initiated
  by the BGP speaker with the higher BGP Identifier MUST be retained"
  — and never preempts an Established session. Losers receive
  NOTIFICATION Cease with RFC 4486 subcode 7 (Collision Resolution
  Failure), not a silent TCP close. A winning challenger is adopted
  with its consumed OPEN frame replayed ahead of the live stream
  (`ReplayStream`, split halves, no unsafe). Two peer-initiated
  connections give the tiebreak nothing to decide — first-wins.

### Policy in the decision path (W2-d)

- **Import** (§9.2.1 Phase 1): every Adj-RIB-In route runs
  `ValidationGate` → compiled `policy::Filter`. The seams return
  transformed routes (`ImportPolicy::import`), so set-actions mutate
  attributes *before* best-path (§9.1.1's degree-of-preference hook);
  rejected prefixes never become candidates.
- **Export** (Phase 3): `ExportPolicy::export` gates the Adj-RIB-Out —
  including locally-originated `network` announcements (FRR neighbor
  route-map semantics), with the §9.2.2 reflection floor kept.
- **The bridge**: bgpd's wire model converts into the policy engine's
  owned model once per evaluation (`PolicyView`, the W1-a §Deferred
  "bgpd implements RouteView" anchor); edits splice back
  replace-or-insert per attribute; NEXT_HOP/MP_REACH/passthrough
  attributes are never touched. `metric` maps to MED (BIRD
  `bgp_metric`; FRR's documented `set metric` behavior).
- **Unconfigured = accept-all = v1 behavior** — both interop smokes
  (the unmodified P2-b one and the policy one) run the same daemon.

### RFC 7606 revised error handling (N5 M1)

The UPDATE decoder applies the §7 per-attribute disposition table
(`attr::rfc7606_disposition`, table-driven and cited row by row) by
default; the RFC 4271 §6.3 session-reset behavior remains available
per neighbor as `neighbor X update-error-handling strict-rfc4271`
(default `rfc7606`). The implemented rows (subcodes as the strict
decoder produces them):

- **Treat-as-withdraw**: ORIGIN (any malformation), AS_PATH, NEXT_HOP,
  MULTI_EXIT_DISC, COMMUNITIES ("not a non-zero multiple of 4"), AS4_PATH,
  OTC (disclosed judgment — §7 does not list type 35; discarding a
  malformed OTC would silently change leak eligibility), LOCAL_PREF
  from iBGP, missing well-known mandatory attributes, and
  Optional/Transitive flag conflicts for every attribute (§7's general
  flags rule).
- **Attribute discard**: LOCAL_PREF from eBGP, ATOMIC_AGGREGATE (len ≠ 0),
  AGGREGATOR/AS4_AGGREGATOR (wrong length) — the route processes
  normally without the attribute; later occurrences of a duplicate
  attribute (§7) are discarded too.
- **Session reset** (unchanged by RFC 7606): message-level framing
  overruns (Malformed Attribute List), unrecognized well-known
  attributes (§6.3), unparseable MP_REACH/MP_UNREACH content
  (§5: next-hop length inconsistencies and bad NLRI keep the reset),
  and duplicate MP_REACH/MP_UNREACH.

Treat-as-withdraw withdraws the UPDATE's own NLRI from the
Adj-RIB-In (`peer.rs` logs "treated as withdrawal"); attribute
discards log and process. The strict mode also now carries the
§6.3-prescribed subcode on its NOTIFICATION (previously flattened
to 1).

### Route-server mode v1 (N5 M2)

`neighbor X route-server` marks an RS client (FRR
`neighbor PEER route-server-client`, doc/user/routeserver.rst: it
"enables the transparent mode for the specified peer. This means
that some BGP attributes (as-path, next-hop and MED) of the routes
announced to that peer are not modified"). v1 semantics:

- Client→client reflection is **transparent**: the client's own
  AS_PATH (no RS AS prepended), the origin client's NEXT_HOP, and
  the MED ride through unchanged; the never-reflect-to-origin floor
  stays.
- FRR's transparency check requires BOTH ends to be clients
  (bgp_route.c); likewise an RS-client target receives only other
  clients' routes — "Those peers that are configured as RS-clients do
  not receive any announce from the `Main` Loc-RIB". Normal peers
  still receive client routes through the Main Loc-RIB with the usual
  eBGP AS prepend.
- **The RS RIB stays out of the kernel**: bests learned from RS
  clients never produce ZAPI route adds (`rib::zebra_commands` —
  FRR's view semantics: "Routes selected by the view are not
  installed into the kernel routing table").
- Interop: `scripts/test-bgp-rs-interop.sh` — our RS between two real
  FRR 10.2.2 clients; asserts path exactly the origin client's,
  preserved next hop + MED 77, and an empty RS kernel. FRR clients
  need `no bgp enforce-first-as` (FRR's own docs note) and
  `no bgp ebgp-requires-policy`.
- §Deferred: per-client Loc-RIBs and route-server-maps (FRR's
  dedicated-RIB model with import/export policies per client),
  client→normal-peer policy mediation.

### Graceful restart (N5 M3, RFC 4724)

- **Capability** (code 64): the R bit (top bit of the 2-octet field) +
  12-bit Restart Time + per-family `<AFI, SAFI, flags>` triples with
  the F bit.
- **Receiving side (§4.1)** — on for any peer that advertises the
  capability: a lost session RETAINS the peer's routes marked stale
  (still best-path candidates) instead of deleting them; on
  re-establishment the R bit decides — set: stale kept until the
  per-family End-of-RIB marker; clear: flushed immediately at
  Established. The per-family EOR flush and the daemon-armed
  restart-timer flush (advertised Restart Time after session loss)
  sweep what remains. A received NOTIFICATION or our own ManualStop is
  a deliberate close — the RFC 4271 delete.
- **Sending side (disclosed scope)**: `neighbor X graceful-restart
  <1-4095>` advertises the capability with that Restart Time (R
  clear, F bits clear) and Established closes each family's initial
  dump with its End-of-RIB marker (v4: the bare minimum UPDATE; MP:
  an empty MP_UNREACH — sent unconditionally, RFC 4724 §3 recommends
  EOR generally). The full restarting-speaker machinery (preserving
  forwarding state, setting the R bit, deferring route selection) is
  §Deferred.
- §Deferred: per-family F-bit granularity (v1 treats the family
  presence + R bit coarsely), the RFC 8542 long-lived stale timers,
  BFD-triggered early flush.

### ADD-PATH receive (N5B, RFC 7911)

- **Scope: receive-only, both unicast families.** `neighbor X addpath
  rx` (off by default, BIRD-shaped — FRR's receive side is default-on
  with `disable-addpath-rx`; ours is opt-in) advertises capability 69
  with Send/Receive 1 for v4+v6 in ONE instance (§4's single-instance
  MUST — the capability model carries a tuple list). The knob parses
  nothing else: `addpath tx`/`both` are startup errors naming the
  §Deferred send side, never silently-dead knobs.
- **Negotiation (§5's MUSTs)**: `Negotiated.add_path_rx_v4/v6` is
  the effective receive direction — locally configured rx AND the
  peer offered S/R 2 or 3 for the family. A Send/Receive value
  outside 1..=3 makes the whole capability "treated as not
  understood and ignored" (§4) — every family reads 0 then, not just
  the offending tuple.
- **Extended NLRI (§3)**: when (and only when) the direction is on,
  every NLRI field of that family — top-level NLRI and withdrawn for
  v4, MP_REACH/MP_UNREACH lists for v6 — decodes and encodes as
  `Path Identifier (4) | Length (1) | Prefix`. The context is a
  session fact threaded like `asn4` (`AddPathCtx`), never a wire
  fact. The codec refuses a nonzero path id under the classic gate
  (§5's send-side MUST, loud local error — never silently flattened).
- **The /0 hazard, pinned**: extended bytes under a classic gate read
  the path ID's top octet as the prefix length — ids 1..255 decode as
  `0.0.0.0/0` with trailing garbage. Posture is **capability trust**:
  the negotiation gate is the correctness mechanism (both tests that
  mis-gated decode error loudly with INVALID_NETWORK_FIELD; the
  aligned-poison case is unreachable in operation because the decode
  context comes from the OPENs, not the bytes). No defensive
  heuristic — legitimate default routes would not survive one.
- **Storage (§5)**: Adj-RIB-In is keyed (peer, prefix, path-id) —
  sibling paths from one peer coexist, the same key replaces, a
  withdrawal of an unseen key is silently ignored (§5 SHOULD), and
  the decision process is otherwise unchanged: every sibling is an
  ordinary §9.1 candidate, the Loc-RIB still elects exactly one best
  per prefix, zebra sees no difference. Path IDs are the peer's
  local, opaque matter (§2) — never assumed stable across its
  restart (the §5 GR caution).
- Interop: `scripts/test-bgp-addpath-interop.sh` — a real FRR 10.2.2
  hub (`addpath-tx-best-selected 2`, two leaf ASes announcing the
  same prefix) sends two paths; asserted on our side: two distinct
  path ids logged, session clean, exactly one kernel route.

### RPKI (W2-d)

- **ROV** (RFC 6811 §2): validity computed at import from the VRP
  table (RTR cache session or `vrp-file` fixture), recorded on the
  stored route (`Route.rov`, show-output surface) and enforced by
  `reject-invalid` (default **true** — the RFC's recommended local
  policy for Invalid; Valid/NotFound pass). ANP (augmented path
  selection) is not implemented — validity does not alter the §9.1
  ladder.
- **OTC / roles** (RFC 9234 §4/§5): per-neighbor `role
  customer|peer|provider`. Ingress: OTC from a customer is a route
  leak (ineligible); OTC from a peer is ineligible unless it equals
  the peer's AS; routes from providers/peers lacking OTC get OTC :=
  the remote AS. Egress (eBGP): OTC := local AS is synthesized toward
  customers and peers when absent; OTC-bearing routes are never
  propagated to peers or providers; once set, preserved unchanged.
  Validation only runs on eBGP-learned routes (validity is an edge
  property).
- **ASPA** (draft-ietf-sidrops-aspa-verification-28): verification at
  import when the neighbor has a role (role → PeerRelation, §6.3);
  `aspa advisory` (default v1) records the verdict on the path only;
  `aspa enforce` additionally rejects Invalid. Unknown is never
  rejected. No role → no verification (the procedure selection keys
  off RFC 9234 roles).

## Config

```text
zapi socket /var/run/frr/zserv.api     # optional: standalone mode without it
listen-port 179                         # high port for unprivileged tests
hold-time 90                            # §10 default
router bgp 65000
 bgp router-id 10.0.0.1                 # required with neighbors (v1)
 neighbor 192.0.2.9 remote-as 65001
 neighbor 192.0.2.9 passive
 neighbor 192.0.2.9 timers 10 30
 neighbor 192.0.2.9 mrai 5              # default 0 (off)
 neighbor 192.0.2.9 role peer           # RFC 9234: customer|peer|provider
 neighbor 192.0.2.9 update-error-handling rfc7606   # default | strict-rfc4271 (N5)
 neighbor 192.0.2.9 route-server        # RS client, transparent reflection (N5)
 neighbor 192.0.2.9 graceful-restart 120  # sending-side capability 1..=4095 (N5)
 neighbor 192.0.2.9 addpath rx           # RFC 7911 receive, default off (N5B)
 network 203.0.113.0/24
 import INBOUND                         # names a route-map (below)
 export OUTBOUND
rpki
 cache 192.0.2.10 3323                  # RTR session (RFC 8210) — or:
 vrp-file /etc/rouster/vrps.conf        # static fixture (mutually exclusive)
 reject-invalid true                    # default true (RFC 6811 §2)
aspa advisory                           # advisory (default) | enforce
route-map INBOUND permit 10
 match ip address prefix-list CUST
 set local-preference 200
ip prefix-list CUST seq 5 permit 203.0.113.0/24
```

Policy stanzas (`route-map` including its `call` children,
`access-list`, `ipv6 access-list`, `ip|ipv6 prefix-list`,
`bgp as-path access-list`, `bgp community-list standard`) are
extracted verbatim into a blank-padded fragment (file line numbers
preserved) and compiled at startup by the W1-a grammar
(`policy_engine::compile_named_policy`); unknown filter names and
grammar errors are startup failures, never silent. The `vrp-file`
grammar: `vrp <prefix> max <len> as <asn>` and
`aspa <asn> provider <asn>...`, `#` comments, line-numbered errors.

## FRR interop notes (pinned by the smokes)

- FRR binds :179 only once a `router bgp` instance exists; a
  `vtysh -b` pushed before bgpd's zebra view is up silently drops the
  whole router-bgp stanza (retry until the neighbor appears).
- FRR 10.2 defaults to the RFC 8212 eBGP deny-all — interop configs
  need `no bgp ebgp-requires-policy` (z5b's iBGP never hit it).
- FRR records received Cease in `show bgp neighbor`'s Last reset line,
  not in bgpd.log at default log config.

## §Deferred anchors

Per-prefix MRAI queues · MRAI defaults beyond the knob · runtime
policy/config reload (the soft-reset mechanism exists; reload is
rousterd/YANG territory) · iBGP propagation of ROV/ASPA validity ·
ROV-informed path selection (ANP) · RFC 9234 RS/RS-client roles and
the role-mismatch NOTIFICATION (subcode 11) · RFC 7606: AFI/SAFI
disable (the fourth §2 approach) — receive-side treats unparseable MP
content as a session reset · full two-connection §6.8 daemon
integration test (the verdict table, replay adapter, and session
observability are tested; the accept-path dance is smoke-covered by
its dormancy) · route-server: per-client Loc-RIBs + route-server-maps
(FRR's dedicated-RIB model), client→normal-peer policy mediation ·
graceful restart: the restarting-speaker machinery (forwarding-state
preservation, R bit on our restart, selection deferral), per-family
F-bit granularity, RFC 8542 long-lived stale, BFD early flush ·
route next-hop resolution (v1: single-hop peers only) · v6 listener
side · ADD-PATH (RFC 7911) send side: the per-peer path-ID allocator
(FRR-style monotonic counter is a convention, not an RFC MUST — §2
requires only per-neighbor uniqueness and own-ID regeneration on
re-advertisement), the selection modes (all-paths /
best-per-AS / best-selected N, FRR's knob semantics), the
"SHOULD include the best path" rule, per-family knob granularity,
and the pre-RFC PATHS-LIMIT / dynamic-capability IDR drafts
(explicitly out) — the receive side (capability, extended-NLRI codec,
keyed Adj-RIB-In) landed (N5B) · interface up/down mirror tracking.

The `experimental-savnet` hook LANDED (2026-10-11) behind the flag,
in-process only: `peer.rs` `on_message`'s UPDATE arm reports
installs/withdraws (Adj-RIB-In granularity) and the Established /
teardown transitions report adjacency to a hosted
`sav::agent::SavAgent` — see [savnet.md](savnet.md). The
draft-dependent BGP-signaling wire protocol stays deferred with it.
