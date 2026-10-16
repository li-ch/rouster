# bgpd — the Rouster BGP daemon (Phase 2 stream P2-b, W2-d)

Status: v1 landed 2026-10-10 (P2-b, commits `6068045`..`e52826c`):
RFC 4271 base + capabilities + MP-BGP v4/v6 unicast + route refresh +
4-octet AS, a pure FSM, the §9.1 decision process, the ZAPI client
edge, and a two-green-runs interop smoke against real FRR 10.2.2
bgpd. W2-d (2026-10-11, `f034b08`..) added the typed policy engine in
the decision path, RPKI/ROV + OTC roles, ASPA verification, §6.8
collision detection, and the policy interop smoke. N5 (2026-10-11,
`ff58d91`..) added RFC 7606 revised error handling, route-server
mode v1, and RFC 4724 graceful restart. N5B (2026-10-11, `ca7567d`)
landed the honest `Nlri { prefix, path_id }` message model (the B-22
refactor) with ADD-PATH receive. S7-b (2026-10-14, `875da2a`..)
added ADD-PATH transmit (B-19/B-21), the RFC 4724 §4.1
restarting-speaker duties, and the §9.2/RFC 4456 iBGP dissemination
rules. S13-b (2026-10-16, `a366fd8`..) added the RFC 4271 §6.3
first-AS enforcement (F3) and iBGP propagation of ROV validity.

## Layout

| Module | What |
|---|---|
| `message` | Header/OPEN/UPDATE/NOTIFICATION/KEEPALIVE/ROUTE-REFRESH framing (RFC 4271 §4; refresh RFC 2918 §3) |
| `capability` | RFC 5492 capability triples; extended OPEN optional parameters per RFC 9072 |
| `attr` | Path-attribute model: §4.3 flags, AS_PATH (RFC 6793 4-octet, AS_TRANS=23456 bridging), communities (RFC 1997), MP_REACH/MP_UNREACH (RFC 4760), OTC (RFC 9234 type 35), unknown-transitive passthrough with the partial bit forced |
| `fsm` | The §8 six-state machine, table-driven, pure and clock-injected |
| `peer` | Session runtime: framed IO, hold/keepalive timers, §6.2 OPEN checks, §9.5 AS-loop rejection, §6.3 first-AS enforcement (F3), RFC 2918 refresh answers (inbound requests + outbound soft-reset hook), MRAI gate, Adj-RIB-In sink / Adj-RIB-Out source traits, `SessionShared` (the §6.8 observability) |
| `rib` | Adj-RIBs-In + Loc-RIB, `best_path` = the §9.1.2.2 ladder, Import/Export policy seams (§9.2.1 Phase 1/3) |
| `policy_engine` | The typed-engine bridge: `PolicyView` (bgpd's `RouteView`), wire↔policy attribute conversion with replace-or-insert write-back, `ImportPipeline`/`ExportPipeline`, config→filter compilation |
| `rov` | RPKI-derived validation: RFC 6811 §2 ROV, RFC 9234 §5 OTC ingress/egress by role, ASPA verification (draft-ietf-sidrops-aspa-verification-28 §5.5/§5.6), `vrp-file` fixture grammar, RTR table source |
| `zedge` | ZAPI client edge: NHT for peer addresses (connector gate), interface mirror, best-path export to the zebra |
| `daemon` | Listener (TCP 179 default, `listen-port` knob), per-neighbor connectors (§10 ConnectRetry, exponential 1 s→120 s), §6.8 collision resolution (BGP-ID tiebreak, Cease 6/7 to losers, challenger adoption via stream replay), graceful stop |
| `config` | `bgpd.conf` grammar (A11/B7 conventions) + policy-stanza extraction + `rpki`/`aspa`/role knobs + N5/S7-b neighbor knobs (`update-error-handling`, `route-server`, `graceful-restart helper|<secs>` + `graceful-restart deferral`, `addpath rx|tx|both`, `route-reflector-client`) |
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

### RFC 7606 revised error handling (N5 M1, restaged S8-a)

The UPDATE decode path is structured around `attr::UpdateOutcome`
(B-1): **Clean / Discarded(causes) / Withdrawn { routes, causes }**,
with the session reset remaining the `Err` side — the explicit third
disposition §2 names, and §3(j) handled structurally: `Withdrawn`
carries exactly the successfully parsed NLRI/MP sets, and an UPDATE
whose NLRI cannot be parsed is the `Err` reset ("the 'session reset'
approach ... MUST be followed"). The per-attribute dispositions come
from the §7 table (`attr::rfc7606_disposition`, table-driven and
cited row by row); the RFC 4271 §6.3 session-reset behavior remains
available per neighbor as `neighbor X update-error-handling
strict-rfc4271` (default `rfc7606`). The implemented rows (subcodes
as the strict decoder produces them):

- **Treat-as-withdraw** (§3(e), §7): ORIGIN (any malformation),
  AS_PATH, NEXT_HOP, MULTI_EXIT_DISC, COMMUNITIES ("not a non-zero
  multiple of 4"), AS4_PATH (§8 mirrors AS_PATH), OTC (disclosed
  judgment — §7 does not list type 35; discarding a malformed OTC
  would silently change leak eligibility), LOCAL_PREF from iBGP,
  missing well-known mandatory attributes (§3(d), folded into the
  outcome at the UPDATE level), and Optional/Transitive flag
  conflicts for every attribute (§3(c)).
- **Attribute discard** (§3(f), §7): LOCAL_PREF from eBGP,
  ATOMIC_AGGREGATE (len ≠ 0), AGGREGATOR/AS4_AGGREGATOR (wrong
  length) — the route processes normally without the attribute;
  later occurrences of a duplicate attribute (§3(g)) are discarded
  too.
- **Session reset** (unchanged by RFC 7606): message-level framing
  overruns (Malformed Attribute List, §3(b)), unrecognized well-known
  attributes (§6.3), unparseable MP_REACH/MP_UNREACH content (§5.3:
  next-hop length inconsistencies and bad NLRI keep the reset),
  duplicate MP_REACH/MP_UNREACH (§3(g)), and **§5.2's escalation**: a
  treat-as-withdraw-class error in an UPDATE that carries path
  attributes other than a lone MP_UNREACH but "doesn't encode any
  reachable NLRI" voids treat-as-withdraw — "we cannot be confident
  that the NLRI have been successfully parsed as Section 3 (j)
  requires" — and the session reset runs with the triggering error's
  subcode. Attribute-discard errors never escalate (§5.2's "other
  than 'attribute discard'").

Treat-as-withdraw withdraws the UPDATE's own NLRI from the
Adj-RIB-In; attribute discards log and process. Both arms carry §6's
debugging facility — "logging an error listing the NLRI involved and
containing the entire malformed UPDATE message" (the raw frame, hex,
rides `DecodedFrame` to the log line). The strict mode carries the
§6.3-prescribed subcode on its NOTIFICATION.

**The send side of §5.1 (B-4)**: "An UPDATE message MUST NOT contain
more than one of the following: non-empty Withdrawn Routes field,
non-empty NLRI field, MP_REACH_NLRI attribute, and MP_UNREACH_NLRI
attribute" — `BgpUpdate::validate_single_route_container` is the
encode hard-reject (we must not send what §5.1 forbids), checked at
the top of `encode`; the End-of-RIB shapes pass (the v4 marker carries
none of the four, a family's MP marker exactly one). The receive side
stays tolerant per the same section ("an implementation MUST still be
prepared to receive these fields in any position or combination"),
pinned by the merge-decode test, which builds the mixed frame by hand
since the codec now refuses to produce it.

**Strict capability trust (B-23)**: the receive side never guesses an
encoding from the bytes. ADD-PATH NLRI decodes extended only where
the §5 negotiation said so (the negotiated fact, not a wire guess —
the classic/extended mis-gates are loud errors, not fallbacks); the
RFC 9072 extended-parameters detection is that RFC's own type-255
rule. The one heuristic the audit found is deleted: an MP_REACH next
hop whose length the family cannot produce is rejected as a §5.3
next-hop length inconsistency (session reset) — the old
`MpNextHop::Raw` arm zero-padded such bytes and passed them
downstream, a guess on attacker input.

### Route-server mode v1 (N5 M2)

`neighbor X route-server` marks an RS client (FRR
`neighbor PEER route-server-client`, doc/user/routeserver.rst: it
"enables the transparent mode for the specified peer. This means
that some BGP attributes (as-path, next-hop and MED) of the routes
announced to that peer are not modified"). v1 semantics:

- Client→client reflection is **transparent**: the client's own
  AS_PATH (no RS AS prepended) and the origin client's NEXT_HOP ride
  through unchanged; the never-reflect-to-origin floor stays. The
  **B-10 RS export set is stripped**: the origin client's MED
  (RFC 4271 §5.1.4 — "The MULTI_EXIT_DISC attribute received from a
  neighboring AS MUST NOT be propagated to other neighboring ASes";
  FRR's transparency note names MED, but the RFC's MUST NOT wins),
  LOCAL_PREF (§5.1.5 — "A BGP speaker MUST NOT include this attribute
  in UPDATE messages it sends to external peers"; an RS client is
  another AS), and OTC (RFC 9234 — a client's OTC never re-attributes
  to another client; the §5 ingress leak rule covers role-configured
  clients, the strip is the export-side belt for role-less ones; the
  §5 egress synthesis OTC := local AS toward RS-Clients stays with
  the role machinery, §Deferred).
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
  preserved next hop, MED 77 stripped (c1 sends it under a route-map;
  B-10's §5.1.4 rule keeps the RS from forwarding it), and an empty
  RS kernel. S7-b extended
  it bidirectional: c2 announces too, c1 pulls the reverse reflection
  with `clear bgp ... soft in` (RFC 2918 — our refresh answer), path
  exactly 65002 / next hop c2 / AS 65000 never appears, each client
  peers with the RS only, and the kernel check covers both prefixes.
  FRR clients need `no bgp enforce-first-as` (FRR's own docs note)
  and `no bgp ebgp-requires-policy`.
- §Deferred: per-client Loc-RIBs and route-server-maps (FRR's
  dedicated-RIB model with import/export policies per client),
  client→normal-peer policy mediation.

### Graceful restart (N5 M3 + S7-b, RFC 4724)

- **Capability** (code 64): the R bit (top bit of the 2-octet field) +
  12-bit Restart Time + per-family `<AFI, SAFI, flags>` triples with
  the F bit.
- **Receiving speaker (§4.2)** — on for any peer that advertises the
  capability: a lost session RETAINS the peer's routes marked stale
  (still best-path candidates) instead of deleting them; on
  re-establishment the R bit decides — set: stale kept until the
  per-family End-of-RIB marker; clear: flushed immediately at
  Established. The per-family EOR flush and the daemon-armed
  restart-timer flush (advertised Restart Time after session loss)
  sweep what remains. A received NOTIFICATION or our own ManualStop is
  a deliberate close — the RFC 4271 delete.
- **Restarting speaker (§4.1, S7-b)**: `neighbor X graceful-restart
  <1-4095>` roles the neighbor restart-capable — the capability is
  advertised with that Restart Time (F bits clear), and when a
  GR-negotiated session to the neighbor is lost ABNORMALLY (transport
  failure, hold expiry — our ManualStop and the peer's NOTIFICATION
  are deliberate closes, not restarts; table-tested), the daemon marks
  the neighbor and the NEXT session announces the Restart State bit.
  That session performs §4.1's duties: the initial Adj-RIB-Out dump is
  DEFERRED until the peer's End-of-RIB or the
  Selection_Deferral_Timer (`graceful-restart deferral <1-3600>`
  router-level, default 120 s — §4.1's configurable upper bound); the
  expired timer first flushes the retained stale (re-selection), then
  the dump runs and closes with our EOR ("the End-of-RIB marker MUST
  be sent" after the initial update). The forwarding window is the
  in-process one: stale retention produces no best-path change, so
  nothing withdraws from the kernel through the grace (pinned by
  test). `neighbor X graceful-restart helper` is the receiving-only
  role made explicit (nothing advertised). True process-restart
  RIB/forwarding persistence stays zedge/kernel territory (disclosed:
  memory-only bgpd's model).
- **EOR emission**: Established closes each family's initial dump with
  its End-of-RIB marker (v4: the bare minimum UPDATE; MP: an empty
  MP_UNREACH — sent unconditionally, RFC 4724 §3 recommends EOR
  generally; a restarting session's marker follows its deferred dump).
- **Graceful Notification (RFC 8538, B-7)**: the N bit — "The second
  most significant bit is defined in this document as the Graceful
  Notification ('N') bit" (§2) — rides every GR capability bgpd
  advertises. Receive side (§4.1): a NOTIFICATION from an N-advertising
  peer that is not a Hard Reset is a graceful close — the peer's
  routes are retained marked stale, swept by the existing §4.2
  machinery (re-establishment flush, the restart timer). A Hard
  Reset — Cease subcode 9 whose data portion carries the encapsulated
  reason `ErrCode | Subcode | Data` (§3.1) — is §3.2's exception: the
  speaker "MUST terminate the BGP session following the standard
  procedures in [RFC4271]" (the plain delete). Send side (§5.1's
  table): toward an N peer the permanent Cease reasons (1 Max
  Prefixes, 2 Administrative Shutdown, 3 Peer De-configured) are sent
  as a Hard Reset wrapping the reason (our SIGTERM/ManualStop lands
  here); transient Cease subcodes 5-8 ride plain ("Graceful Cease");
  Administrative Reset (4) is the table's "user control" row — v1
  sends it plain, a knob waits for a user; non-Cease error codes are
  never wrapped ("use of Hard Reset does not appear to be
  indicated"). A peer without the N bit changes nothing (the RFC 4724
  §4.2 deliberate close).
- §Deferred: per-family F-bit granularity (v1 treats the family
  presence + R bit coarsely; the deferral ends at the FIRST family's
  EOR), the RFC 8542 long-lived stale timers, BFD-triggered early
  flush, cross-process restart persistence, the RFC 8538 subcode-4
  user-control knob.

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
- **RFC 7911 errata status (B-20, re-checked 2026-10-14)**: none
  recorded — the errata database's entry for 7911 reads "No matching
  errata found" and the RFC info page carries no "Errata Exist"
  badge. ADD-A8's caution ("errata status unverifiable tonight") is
  closed: the RFC can be cited without an errata qualifier.

### iBGP dissemination (S7-b: RFC 4271 §9.2 + RFC 4456 clients)

- **§9.2**: "When a BGP speaker receives an UPDATE message from an
  internal peer, the receiving BGP speaker SHALL NOT re-distribute the
  routing information contained in that UPDATE message to other
  internal peers (unless the speaker acts as a BGP Route
  Reflector)" — `rib::ibgp_readvertisement_allowed` is the export
  gate, table-tested: an iBGP-learned best never reaches another
  internal peer's Adj-RIB-Out, external peers still get it (local AS
  prepended, no LOCAL_PREF).
- **RFC 4456, client config only**: `neighbor X
  route-reflector-client` marks the iBGP peer; §4's reflection table
  rides the export path — a route from a client reflects to ALL iBGP
  peers, a route from a non-client to clients only. The full RR
  feature is NOT claimed: ORIGINATOR_ID/CLUSTER_LIST loop prevention
  is §Deferred (v1 relies on the never-reflect-to-origin floor),
  disclosed.
- **§9.1.3 floor**: "A route SHALL NOT be installed in the Adj-Rib-Out
  unless the destination, and NEXT_HOP described by this route, may be
  forwarded appropriately by the Routing Table" — `rib::forwardable`
  (v4 NEXT_HOP / v6 MP_REACH presence; full §9.1.2.1 resolvability
  stays §Deferred with route next-hop resolution).
- **§5.1.5 LOCAL_PREF shape**: synthesized (100 — the §9.1.1 degree of
  preference materialized) toward internal peers when missing,
  stripped toward external peers, applied to learned AND
  locally-originated exports.
- **eBGP LOCAL_PREF reset-at-import (B-3, §5.1.5's receive side)**:
  "If it is contained in an UPDATE message that is received from an
  external peer, then this attribute MUST be ignored by the receiving
  speaker" — `rib::reset_external_local_pref` replaces any external
  LOCAL_PREF with the local default (100, FRR convention) at
  Adj-RIB-In insertion, before the import policy (a route-map `set
  local-preference` still overrides). An external peer can therefore
  never rig the §9.1.2.2 a) ladder; iBGP values are kept. (Citation
  note: the sheet's "§5.1.4 check" lands here as §5.1.5 — §5.1.4 is
  MULTI_EXIT_DISC, whose "MUST NOT be propagated to other neighboring
  ASes" is the B-10 RS MED strip's rule.)

### ADD-PATH transmit (S7-b, RFC 7911)

The send side of N5B's receive leg (B-19/B-21 per the sheet):

- **Knob (B-21)**: `neighbor X addpath rx|tx|both` — BIRD-shaped,
  default off (the N5B `addpath rx` widened; `tx`/`both` are no longer
  startup errors). The OPEN advertises ONE capability instance (§4)
  with Send/Receive 1 (rx), 2 (tx), or 3 (both) per enabled family.
- **Negotiation (§5's mirrored MUST)**: `Negotiated.add_path_tx_v4/v6`
  is the effective transmit direction — locally configured tx AND the
  peer offered S/R 1 or 3 (willing to receive), matrix-tested.
- **Path-ID allocation (B-19)**: per-peer `prefix → id` map backed by
  a monotonic counter from 1 — a convention stricter than the RFC
  (§2 requires only per-neighbor uniqueness and own-ID regeneration on
  re-advertisement). Stability is the point: a prefix keeps its id
  across re-advertisements (refresh re-dumps included — tested), ids
  are never reused after withdrawal, and a withdrawal carries exactly
  the id its announcement used (§5's replacement key). Ids are stamped
  at the session send choke point onto every negotiated family's NLRI
  field (v4 top-level + withdrawn, v6 MP lists) and encoded via
  `BgpUpdate::encode_frame_with` under the §3 extended form; the
  classic-gate refusal stays the mis-gate backstop. The export seam
  (`LocRibOut`) still produces id 0 — received ids never leak to
  another peer (§2).
- §Deferred: the selection modes (`addpath-tx-all-paths` /
  `bestpath-per-AS` / `best-selected N`, FRR's knob semantics — v1
  advertises the single best per prefix), §5's "SHOULD include the
  best route" beyond that shape, per-family knob granularity
  (`addpath` covers both unicast families), and the pre-RFC
  extensions FRR already ships knobs for (B-25, named so the scope
  creep stays visible): `draft-abraitis-idr-addpath-paths-limit`
  (-04, the PATHS-LIMIT capability bounding received paths — ADD-A8
  recorded it under an `ietf-idr` prefix; it is an individual draft)
  with its Cease companion
  `draft-abraitis-idr-maximum-paths-subcode`, and
  `draft-ietf-idr-dynamic-cap` (-19, the DYNAMIC-CAP message —
  mid-session capability revision without a session reset).

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
  OTC/role rules run on eBGP-learned routes (roles are edge
  concepts); ROV validity (S13-b) records on internal paths too —
  RFC 6811 §2's verdict is a pure prefix/origin function, computed
  at import either way, record-only for iBGP (reject-invalid stays
  the eBGP posture).
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
 neighbor 192.0.2.9 graceful-restart 120  # restart-capable role, 1..=4095 (N5 + S7-b)
 neighbor 192.0.2.9 graceful-restart helper  # receiving-only role (S7-b)
 graceful-restart deferral 120          # RFC 4724 §4.1 Selection_Deferral_Timer (S7-b)
 neighbor 192.0.2.9 addpath both        # RFC 7911 rx|tx|both, default off (N5B + S7-b)
 neighbor 10.0.0.9 remote-as 65000
 neighbor 10.0.0.9 route-reflector-client  # RFC 4456 client (S7-b)
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

## Bench round 2026-10-15: F1/F5/F7 fixed, F8 open

The pre-registered bench round (docs/benchmarks.md §R) measured
full-table ingestion and found three bgpd-side defects, fixed in
commit `47ef0ee`:

- **F1 — O(n²) ingestion.** `RibSink::announce`/`withdraw` ran the
  full-table `recompute()` per UPDATE (union + sort + per-prefix
  flatten of every peer's Adj-RIB-In). The hot path now calls
  `LocRib::recompute_prefix` — the §9.1 decision process is
  per-prefix, and the `Nlri` key orders by prefix first, so each
  peer's Adj-RIB-In range-scans in O(log n). Bulk `recompute()`
  stays for session-level events (peer clear, stale flush, soft
  reset) and delegates per prefix; an equivalence test pins
  incremental == bulk (same best table, same change stream).
- **F7 — session-loop read drop.** The select! reader
  (`read_frame_with`) is a multi-`read_exact` future: once the
  19-byte header (or part of the body) was consumed, a timer branch
  winning the select dropped the future and its buffered bytes —
  wire-proven by the bench tee-proxy (a clean 7,966-frame stream
  desynced bgpd where FRR consumed it). Reads now append into a
  persistent session buffer via one bounded `read` (cancel-safe:
  Ready implies the branch runs) and frames drain synchronously
  after every select cycle.
- **F5 — hot-path logging.** The per-UPDATE info line builds counts,
  no longer the full announced-prefix string list.

Receipts (§R, post-fix entry): full 1,126,490-prefix table at EOR in
4.73 s median (≈238k routes/s), zero malformed, zero rejected,
unpaced at hold 90 — where the pre-fix reader desynced at 120 msg/s
paced.

- **F8 — FIXED (commit `5afbba6`, same day): the FIB programming
  path.** The Dataplane trait gained `route_replace_batch`/
  `route_delete_batch` (sequential defaults; netlink-dp overrides
  with 512-in-flight pipelined requests, every ACK still verified,
  ordered results), the ZAPI hot path reconciles dirty keys only
  (O(batch); the 10 s tick, dataplane events, and SIGHUP keep the
  full pass), and the reconcile tick uses `MissedTickBehavior::Delay`.
  Post-fix §R entry: full table in-kernel **17.1 s median**
  (rousterd 10.9 CPU-s, was 235; total SUT CPU 21.3 s vs FRR's
  20.7), EOR 6.07 s with installs overlapping the ingest. Harness
  follow-up noted: the main-table poll's netlink dump starves under
  the install storm on short runs — poll the status socket instead.
- **F3 — FIXED (S13-b, 2026-10-16, commit `a366fd8`): first-AS
  enforcement.** RFC 4271 §6.3: "If the UPDATE message is received
  from an external peer, the local system MAY check whether the
  leftmost (with respect to the position of octets in the protocol
  message) AS in the AS_PATH attribute is equal to the autonomous
  system number of the peer that sent the message. If the check
  determines this is not the case, the Error Subcode MUST be set to
  Malformed AS_PATH" — with the §6.3 preamble's Error Code (UPDATE
  Message Error): the violation answers NOTIFICATION 3/11 and resets
  the session (FRR's default-on `bgp enforce-first-as`,
  `aspath_firstas_check`). `AsPath::leftmost_as` is the first AS of
  the first segment when it is an AS_SEQUENCE — an empty path or a
  leading AS_SET has none and fails the equality (FRR parity). The
  check lives at import in `peer.rs` `on_message`'s UPDATE arm,
  before the RFC 7606 disposition arms (FRR enforces at
  attribute-parse time); iBGP is exempt by the rule's own scope
  ("received from an external peer" — §9.2 dissemination leaves an
  internal path untouched). Ten tests pin it, four with byte-level
  NOTIFICATION pins (bad first AS, empty path, leading AS_SET,
  withdrawal-carrying UPDATE), plus the ordering pin (a bad first AS
  resets even when a second, attribute-discard-class defect rides
  the same UPDATE) and the iBGP exemptions (any-shape path, empty
  path). The interop leg (`test-bgp-frr-interop.sh` F3-FIRST-AS, the
  z-smoke pattern): a crafted third AS streams a byte-exact bad-path
  UPDATE and the exact 21-octet 3/11 NOTIFICATION is asserted as the
  session's final frame. The bench feed stays valid: mrt-replay's
  symmetric prepend (`--prepend-as $INJ_AS`, the AS both SUTs'
  neighbor lines name) puts the injector's AS at the front of every
  replayed path — exactly what the check requires — pinned by test
  for the three dump shapes (leading sequence, leading AS_SET,
  multi-segment). The disable knob (FRR's `no bgp enforce-first-as`
  — needed by an RS-client of a foreign RS, whose reflected paths
  open with the origin client's AS) is §Deferred with no v1 user.
  A drive-by the smoke re-run exposed: the F5 counts-only log line
  had broken the four smokes' prefix/path-id greps (red since
  2026-10-15); the line now carries counts plus a bounded four-entry
  NLRI preview (path ids included) — O(1), never the full list.

## §Deferred anchors

Per-prefix MRAI queues · MRAI defaults beyond the knob · runtime
policy/config reload (the soft-reset mechanism exists; reload is
rousterd/YANG territory) · iBGP propagation of ASPA/OTC validity
(the ROV half LANDED S13-b: RFC 6811 §2's prefix/origin verdict
records on internal paths for show output — record-only, enforcement
stays the eBGP edge posture; ASPA/OTC stay eBGP-only, their
procedures key on the edge role) · first-AS disable knob (FRR's `no
bgp enforce-first-as` — an RS-client of a foreign RS needs it; no v1
user) ·
ROV-informed path selection (ANP) · RFC 9234 RS/RS-client roles and
the role-mismatch NOTIFICATION (subcode 11) · RFC 7606: AFI/SAFI
disable (the fourth §2 approach) — receive-side treats unparseable MP
content as a session reset · full two-connection §6.8 daemon
integration test (the verdict table, replay adapter, and session
observability are tested; the accept-path dance is smoke-covered by
its dormancy) · route-server: per-client Loc-RIBs + route-server-maps
(FRR's dedicated-RIB model), client→normal-peer policy mediation,
the RFC 9234 §5 egress synthesis OTC := local AS toward RS-Clients
(the B-10 strip handles the never-re-attribute half) · graceful
restart: per-family F-bit granularity (and the deferral's
first-EOR coarseness), RFC 8542 long-lived stale, BFD early flush,
cross-process restart persistence (the §4.1 in-process duties landed
S7-b; RFC 8538's N bit + Hard Reset landed S8-a — the subcode-4
user-control knob remains) · route next-hop resolution (v1:
single-hop peers only; the §9.1.3 floor checks next-hop presence,
not §9.1.2.1 resolvability) · RFC 4456: ORIGINATOR_ID/CLUSTER_LIST
loop prevention and cluster-id config (the client-config reflection
table landed S7-b) · v6 listener side · ADD-PATH (RFC 7911): the
selection modes (all-paths / best-per-AS / best-selected N, FRR's
knob semantics — v1 transmits the single best per prefix under its
own ids), per-family knob granularity, and the pre-RFC extensions
FRR ships knobs for — `draft-abraitis-idr-addpath-paths-limit` +
`draft-abraitis-idr-maximum-paths-subcode`,
`draft-ietf-idr-dynamic-cap` (B-25, named) — both directions landed
(receive N5B, transmit S7-b; errata status verified clean S8-a) ·
interface up/down mirror tracking.

The `experimental-savnet` hook LANDED (2026-10-11) behind the flag,
in-process only: `peer.rs` `on_message`'s UPDATE arm reports
installs/withdraws (Adj-RIB-In granularity) and the Established /
teardown transitions report adjacency to a hosted
`sav::agent::SavAgent` — see [savnet.md](savnet.md). The
draft-dependent BGP-signaling wire protocol stays deferred with it.
