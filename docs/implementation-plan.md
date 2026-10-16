# Rouster — Implementation Plan

Date: 2026-10-08
Status: Initial plan (pre-implementation)
Companion docs: [architecture.md](architecture.md) (core/edge architecture decision)

Rouster is a routing protocol suite in Rust: a BIRD-style typed multi-table
core + Holo-style async, AF-generic protocol crates, FRR compatibility (ZAPI,
vtysh, frr.conf) at the edge, and native source address validation (SAVNET
first, BAR-SAV later). The feasibility research behind this plan lives outside
the repo (it is prior research, not project documentation).

---

## 1. Design principles

1. **ZAPI-compatible, not ZAPI-compatible-later.** The zebra-equivalent speaks ZAPI to FRR daemons from the first milestone → every milestone is testable against production-grade protocols.
2. **Single binary by default, optional process isolation.** Internally one Tokio binary with async tasks per protocol; each protocol can additionally be packaged as its own binary speaking the internal bus, for operators who want FRR-style isolation. Memory-safety crashes are eliminated by the language; task-level panic isolation + supervision recovers most of the rest.
3. **YANG-native northbound + a vtysh-compatible CLI shim.** Model-driven core (like Holo), with Cisco-style CLI as a translation layer for operator adoption. The shim is a translator, never the config system.
4. **Rust's wins, loudly:** no unsafe in protocol code, fuzz the codecs, per-neighbor BGP parallelism.
5. **SAV as a first-class citizen.** Source address validation (SAVNET) is a committed workstream, not an afterthought — see §4.

---

## 2. Phase plan

### Phase 0 — Skeleton & dataplane spike (4–6 weeks)

- Cargo workspace: `crates/{rib, zapi, netlink-dp, common}`.
- `netlink-dp`: interface/address/route/neighbour sync via `rtnetlink`; route add/delete/replace with nexthop groups; netns/VRF awareness.
- `rib`: BIRD-style typed multi-table core from day one (not a zebra clone): administrative distance + metric selection, nexthop resolution/tracking.
- Deliverable: a daemon that mirrors kernel RIB, installs/removes static routes from a config file. Tested in Containerlab/netns topologies.

### Phase 1 — ZAPI server + interop with FRR (6–8 weeks)

- `zapi`: codec for ZAPI header + core messages (interface add/update, router-id, route add/delete, nexthop tracking, redistribute).
- Run **real FRR `bgpd`/`ospfd` against the Rust zebra** in topotests-style containers.
- `staticd` equivalent (trivial on top of RIB) + ZAPI client for it.
- Deliverable: FRR bgpd establishes peers and its routes appear in the kernel via the Rust zebra. This is the credibility milestone.

### Phase 1.5 — `savd` core (SAVNET, ~4–6 weeks on top of Phase 1)

SAVNET splits into a stable part (build now) and a draft-tracking part (feature-flagged, see §4):

- **SAV Information Base (SIB):** source-prefix ↔ interface bindings from RIB/FIB, config, and (later) protocol-learned info.
- **Validation-mode rule model** per draft-ietf-savnet-general-sav-capabilities: IBA-SAV / IBB-SAV (interface-scale allow/blocklist), PBA-SAV / PBB-SAV (router-scale prefix-based allow/blocklist).
- **SAV Table Manager:** compiles rules into dataplane enforcement — nftables/eBPF/kernel uRPF (`fib_validate_source`) on Linux; behind the dataplane trait (see architecture.md).
- **Local rule generation without new wire protocols:** strict/loose/FP-uRPF/EFP-uRPF (RFC 3704/8704) equivalence from RIB data — natively what SAVOP bolts onto FRR.
- Deliverable: SAV rules enforced in netns/Containerlab topologies, verified with spoofed-traffic tests; modes default to log/monitor before drop.

### Phase 2 — First native protocol: BFD, then BGP (8–12 weeks)

- `bfdd` in Rust (small, self-contained, high value, timer-heavy — a great Tokio fit; RFC 5880/5881/5882/5883).
- `bgpd` v1: FSM, 4-byte AS, MP-BGP (IPv4/IPv6 unicast), route refresh, capabilities, RIB-in/out, ZAPI client.
- **RPKI from the start:** RTR client (RFC 8210/8210bis), ROV states into policy; ASPA path verification + RFC 9234 roles/OTC (this leapfrogs FRR, which has no ASPA as of 2026-03, and matches BIRD).
- Policy engine is the typed, BIRD-inspired one (compiled, typed filters), with a route-map compatibility grammar layered on top for frr.conf import.
- BGP-carried intra-domain SAVNET signaling hook (the intra-domain SAVNET signaling drafts — names omitted on purpose: drafts rotate, see the SAVNET workstream rules in §4), behind `experimental-savnet`.
- Fuzz the BGP codec (cargo-fuzz), interop vs. FRR/BIRD/GoBGP in CI.

### Phase 3 — IGP: OSPFv2 (10–14 weeks)

- LSA database, flooding, SPF (with back-off), areas/stub/NSSA, authentication.
- AF-generic single codebase (Holo pattern) — OSPFv3 then falls out nearly free.
- IGP-carried intra-domain SAVNET signaling (same deliberately unnamed drafts — §4 tracks what is stable), behind `experimental-savnet`.

### Phase 4 — Management plane (parallel track, from Phase 1 on)

- vtysh-compatible VTY server (Cisco-style) for zebra/static/bfd/bgp subset.
- YANG-modeled config core + gRPC/gNMI northbound (evaluate reusing Holo's YANG crates — MIT licensed).
- Unified `rouster.conf`-style file + transactional apply.

### Phase 5+ — Breadth (each its own project)

- OSPFv3 (cheap after AF-generic Phase 3), IS-IS, RIPng, PIM, LDP/MPLS, EVPN/VPN, SRv6, FPM client, BMP.
- Inter-domain SAVNET architecture (draft-ietf-savnet-inter-domain-architecture) as drafts mature.
- **BAR-SAV module** (after ASPA/ROA/BGP RIB all exist): derive per-interface permissible source-prefix allowlists from BGP UPDATE AS_PATHs + ASPA + ROA (draft-ietf-sidrops-bar-sav); a small incremental module at that point, not a project. SAVNET stays ahead of BAR-SAV in priority (owner decision).

---

## 3. Testing & CI strategy (from day one)

- Containerlab/netns topologies in CI; interop matrix vs. FRR (both directions: FRR-zebra + rouster-bgpd, rouster-zebra + FRR-bgpd).
- Packet-level fuzzing for every codec; RFC conformance checklist per protocol (Holo's RFC list is a good template).
- SAV: spoofed-traffic tests in netns topologies; improper-block/improper-permit metrics; design for SAVOP interop testing and contribute conformance findings back to the SAVNET WG.
- Long-running full-table BGP soak tests (route-views feeds) once bgpd exists.

---

## 4. SAVNET workstream rules

Owner decision (2026-10-08): **SAVNET must be implemented, and takes priority over BAR-SAV.**

- The router-local SAV machinery (SIB, four validation modes, table manager, uRPF-family generation) is stable and built immediately (Phase 1.5).
- All draft-dependent wire protocols (intra-domain IGP/BGP signaling, inter-domain architecture) are behind an `experimental-savnet` feature flag; wire codecs are isolated; implemented draft versions are pinned in docs; expect breaking changes as drafts evolve.
- False-positive safety: modes default to "log/monitor" before "drop"; per-mode enablement; validation-state observability (unknown ≠ invalid).

Strategic note: no general-purpose routing suite (FRR, BIRD, Holo) has native SAVNET; the only running code is the SAVOP research playground bolted onto FRR. A memory-safe, YANG-managed suite with first-class SAV would be the reference implementation the WG currently lacks — and a natural candidate for IETF hackathon interop visibility.

---

## 5. Team / effort reality check

- Phase 0–2 to a demo-able, genuinely useful system (zebra + static + savd core + BFD + BGP subset with FRR interop): roughly **7–10 months for 1–2 strong Rust/networking engineers** (Phase 1.5 included).
- "Feature parity with FRR" overall: not a sane near-term goal; treat FRR as the spec/oracle, not the finish line.

---

## 6. Key risks

| Risk | Mitigation |
|---|---|
| ZAPI drift across FRR versions | Pin supported FRR versions; version negotiation; interop CI gates |
| BGP policy complexity (route-maps) | Define a sane subset early; YANG policy model as the real API |
| SAVNET drafts are unstable; wire formats can change | Feature-flag all draft-dependent code; isolate wire codecs; pin implemented draft versions in docs |
| SAV dataplane enforcement is Linux-specific (nftables/eBPF/uRPF semantics) | Keep it behind the dataplane trait; netns integration tests from day one |
| SAV improper block (false positives) can blackhole legitimate traffic | Default modes to "log/monitor" before "drop"; per-mode enablement; unknown ≠ invalid |
| Only SAVOP exists as SAVNET prior art; few interop partners | Design for SAVOP interop testing; contribute findings back to the WG |
| Scope creep into multicast/MPLS/SRv6 | Explicitly out of scope until Phase 5 |
| Duplicating Holo | Decide build-vs-join per component; reuse Holo crates where design allows |
| Dataplane beyond kernel netlink | Abstract dataplane trait from Phase 0 (netlink now, FPM/eBPF later) |

---

## Appendix A — Naming

**Rouster** (router + Rust). Binary `rousterd`, CLI `rousterctl`, config `rouster.conf`, socket dir `/run/rouster/`. Common pronunciation will drift to "rooster" — accepted; it accidentally preserves the BIRD bird-lineage theme. Collision check (2026-10-08): no routing/networking daemon named Rouster found; one dormant unrelated repo exists (`chorankates/rouster`, a Ruby VM-testing tool) — different domain, acceptable. Spelling proximity to "roster" — expect to spell it out verbally. Rejected candidates: Osprey (taken by a network-visibility product), Tern (intermediate choice, superseded same day), Halcyon, Skua, Ironbird.

## Appendix B — Repository layout decision

Owner decision (2026-10-08): all Rouster code and project documentation live in this repository (`rouster/`), which will be open-sourced. Prior research documents live outside the repo.

## Appendix C — Status notes (append-only)

Ticks cite the overnight program's append-only stage ledger
(`away/2026-10-09/LEDGER.md`, outside this repo; `W#`/`M#` are its
lines, which carry the commit hashes and name the per-stage reports).
The phase text above is unchanged; this block is status only.

- 2026-10-09 — Phase 0 (netlink-dp sync surface): the neighbour half of
  "interface/address/route/neighbour sync" landed — kernel ARP/NDP dump
  plus live add/replace/del events mirrored into the RIB (LEDGER W3).
  VRF awareness landed — devices recognized with their table ids and
  enslavement, VRF-table routes mirrored and programmed back without
  leaking into table 254 (LEDGER W4). Netns awareness remains open:
  `setns(2)` has no safe wrapper under the no-unsafe/no-new-deps fence —
  BLOCKED with a design recommendation recorded for the owner (LEDGER
  W4).
- 2026-10-09 — Phase 0 (rib): reconcile-diff partition invariants are
  property-pinned against a reference model — partition totality,
  keep-iff-unchanged, stable fixpoint, 10k-case stress green (LEDGER
  M3, W5B convention).
- 2026-10-09 — Phase 1 (credibility milestone): DELIVERED — two real
  FRR 10.2.2 bgpd instances peer iBGP Established through rousterd and
  BGP-learned prefixes reach the kernel `proto bgp`, stable over a 60 s
  soak with zero reconnects (LEDGER W1: PEER, ROUTE-KERNEL, STABLE).
  ospfd followed the same night — Full adjacency, each remote loopback
  installed `proto ospf` in both directions (LEDGER W1B). Results and
  deviations: `docs/interop/frr-10.2-interop.md` (Z5B/Z5C sections).
- 2026-10-09 — Phase 1 (ZAPI breadth): ROUTER_ID_ADD is answered with a
  derived ROUTER_ID_UPDATE (live-validated by ospfd, no config pin) and
  registered sessions are re-pushed the id whenever the derived value
  changes on an address/link event, mirroring zebra's `rid_clients`
  (LEDGER W2, W1B; micro A2),
  REDISTRIBUTE_ADD registrations get an initial best-route dump, and
  REDISTRIBUTE_ROUTE_DEL is modeled and pushed on best-route
  withdrawal, with the whole bgpd interop flow re-run green after those
  changes (LEDGER W2, W1B). Config reload now pushes redistribute
  ADD/DEL for changed bests and stays silent on identical reloads
  (LEDGER M2). BFD_CLIENT_REGISTER is recorded and its no-reply is
  source-verified against frr 10.2.2 `zebra_ptm.c` (LEDGER M1).
- 2026-10-09 — Phase 1.5 (savd core): delivered end-to-end — SIB with
  typed source-prefix/interface bindings ingested from the RIB (LEDGER W5);
  the IBA/IBB/PBA/PBB rule model plus uRPF-family rule generation
  and the table manager, RFC-cited table-driven tests, FP approximation
  disclosed (LEDGER W6); enforcement through the Dataplane trait with an
  rp_filter sysctl backend (nft absent from all cached images),
  spoof-block/legit-pass tests and a monitor-before-drop default
  (LEDGER W7); the savd daemon wired as a ZAPI client of the RIB,
  monitor-only by default with drop refusal tested, neighbour-based
  monitor feed (LEDGER W8). SIB ingest invariants are property-pinned
  against a reference model, 10k-case stress green (LEDGER W5B).
- 2026-10-10 — Phase 1 / Phase 1.5 delivered, consolidated: the
  2026-10-09/10 overnight program closed 49/49 stages PASS — LEDGER W1–W8,
  W1B, W5B, M1–M6, A1–A23 — ending at HEAD `59412d4`, 53 commits ahead of
  its baseline `5fc0446`, gate green (fmt/clippy clean, 317 tests / 0
  failed; RETURN_REPORT §5 — which also corrects the A23 LEDGER line's
  "314/0" arithmetic typo to 317/0, §4). Open items are fenced owner
  decisions (netns wrapper, nft-carrying image, direction-B interop),
  not gaps in the delivered scope (RETURN_REPORT §7).
- 2026-10-10 — Phase 1 (ZAPI breadth, ADD stages): the run-smokes.sh
  runner discovers every scripts/test-*.sh with a bounded docker
  pre-flight and per-script logs (LEDGER M4); first-HELLO establish-dump
  via remembered registrations, DEL replay for vanished routes,
  adopt/unregister lifecycle (LEDGER M6); cmd-11 both flavors
  wire-captured from real zebra and pinned (LEDGER A5); real ifi_flags
  carried end-to-end netlink → rib → ZAPI INTERFACE_ADD, replacing the
  lo-name convention (LEDGER A12); z5b unpinned router-id — both bgpds
  take rousterd's derived ROUTER_ID_UPDATE (LEDGER A13); genuine defect
  found and fixed: route-type numbering corrected to SYSTEM=0/KERNEL=1/
  CONNECT=2/LOCAL=3 per frr-10.2.2 route_types.txt, pinned doc corrected
  (LEDGER A19); ospfd NHT registrations answered with routed resolution
  from the kernel mirror, live-driving NSSA type-7 default origination
  (LEDGER A23). Supporting: cacheinfo provenance mirrored into route
  entries (A3), VRF enslavement live link events (A4), p0c ECMP smoke
  read-side fixed via an iproute2 helper (A16).
- 2026-10-10 — Phase 1.5 (savd polish + SIB depth, ADD stages): event-
  driven evaluation plus RFC 8704 §3.6.2 deletion hysteresis (LEDGER A10);
  config `binding` lines feed the SIB's Config origin (A11); sav_install
  churn guard on identical replays (A17); backend monitor counts preferred
  over simulation with disclosed fallback (A18); rule-diff logging at
  member granularity (A20); run-dir operator surface — pidfile, status
  file, `savd --show` (A21); binding TTL + sweep, mechanism ready for the
  future SAVNET agent (A22); multi-prefix --iba (A9). SIB property depth:
  replace_origin batch-atomicity and remove + covering-fallback pinned
  against the reference model (A14, A15, W5B convention); GSC
  merge-by-subtraction policy (A6); rule provenance tracking (A7); boot-id
  stamped state for restart idempotence (A8).

- 2026-10-10 (later) — Owner decision: M3's neighbour-liveness gate on
  the NEXTHOP_UPDATE answer is REVERTED; NHT resolution is route-based,
  zebra-faithful (`nexthop_active` consults no neighbour table). The
  neighbour mirror stays advisory (logs, M4 session pushes, savd
  monitor). Motivation and alternatives considered: the interop doc's
  "Owner decision (2026-10-10)" section. Same-day follow-ups: MIT
  license adopted; four parallel day-streams (S1 zebra-core incl. both
  previously-fenced ZAPI edges, S2 sav polish, S3 rousterctl v1, S4
  docs/OSS prep) + S5 integration all landed; 16/16 smokes, 383/0.

- 2026-10-11 — Phase 2 opens GREEN: three parallel streams landed in one
  day — bfdd (RFC 5880-5883 codec/state machine/transports/daemon, live
  Up-flap interop vs FRR bfdd ×2), bgpd core (RFC 4271/4760 codec, §8
  FSM, §9.1 decision process, RIB + ZAPI client, live eBGP peering vs
  FRR bgpd with UPDATE/refresh/soak/Cease observed ×2; two of our
  protocol bugs fixed, four FRR-side facts pinned), rpki (RTR codec,
  VRP/ROV per RFC 6811, ASPA lattice, mock-cache session client).
  Integration pass: fmt/clippy sweep over stream tails, 18/18 smokes
  (incl. the two new interop legs), workspace 640/0. Protocol docs
  indexed. Evidence: away/2026-10-11/reports/P2-{a,b,c}.md.

- 2026-10-11 (later) — Owner decisions A-K adopted (sheet:
  away/2026-10-11/weekend/DECISIONS.md): socket2 in (A1, wired for
  bfdd's BFD TTL/hop-limit/auth); gortr:local + rouster-nft:local
  images built while the owner was present (B1/E1 — the real-cache RTR
  runbook and the W7B nftables backend are unblocked); SIB fold-in
  deferred with the DIRECTION RATIFIED — the SIB will consume the
  explicit rib surfaces (C2); netns stays per-process, no unsafe (F2);
  mirrored test helpers stay (G2); tokio test-util ratified (H1);
  sync-RPC hazard documented-only (I2); registration restart hole
  accepted (J2); vtyd apply direction = config-manager target,
  file+SIGHUP interim (K3); CI = private GitHub + Linux Actions (D1 —
  workflow staged, repo creation is the owner's).

- 2026-10-11/12 (weekend program, closed by the W3 integration pass) —
  six streams COMPLETE-VERIFIED at HEAD `ea8e9dc` (baseline `4837f67`,
  640/0): the `policy` crate — typed filter engine (BIRD-cited
  semantics), sets-as-data, the FRR AS-path regex as a dependency-free
  NFA, route-map grammar→compiler, property suite (W1-a); the ZAPI BFD
  family pinned against real 10.2.2 speakers both directions + codec
  arms + rousterd relay/fan-out + `bfdd --zapi` dynamic sessions +
  live smoke (W1-b); vtyd v1, the vtysh-compatible VTY server
  (word-tree grammar, Cisco modes, B7 config subset parse-only)
  (W1-c); bgpd's decision path — the policy engine live via
  `RouteView` (import/export mutating seams), ROV + OTC/roles (RFC
  6811/9234), ASPA verification, §6.8 collision detection, RFC 2918
  soft reset, policy interop smoke vs real FRR (W2-d); ospfd Phase 3 —
  LSA codec, LSDB (§13), two-stage SPF (§16.1), adjacency/flooding
  cores, then Day 2: raw-socket transport, the daemon, and FRR
  interop (Full adjacency + both redistribute directions; six
  wire-found bugs fixed and pinned) (W2-e); operator surfaces round 2
  — the rousterd.status dump + rousterctl/vty consumers + live smoke
  (W2-f). Integration gate re-run by W3-h: fmt + clippy -D warnings
  clean, workspace 1052/0 three consecutive runs (no flakes), smokes
  23/23 (baseline 18 + bfd-zapi-pin-capture, bfd-zapi,
  bgp-policy-interop, ospf-frr-interop, vty-smoke). Docs folded:
  index rows for policy/vty/ospf + the operator-surfaces v2 row,
  interop-doc sections for the two new FRR legs. Owner-decision delta
  to ratify: A1's scope was read as dependency-level and extended to
  ospfd (raw proto 89 + multicast joins) per W2-e's Day-1 STOP
  recommendation — zero lock changes. Evidence:
  away/2026-10-11/weekend/reports/ (W1-a, W1-b, W1-c, W2-d, W2-e,
  W2-f, W3-integration).

- 2026-10-11 (night program, stage N4) — **C2 executed + the SAVNET
  agent interface landed** (4 commits, 927f358..138d731): the SIB
  consumes the S1 explicit rib surfaces — bindings derive from the
  merged `best_with_connected` view (a connected candidate masks a
  protocol best at distance 0) and gateway egress resolves through
  `resolve_nexthop_recursive` (S1 deviations carried: no
  fall-through, /0 never answers; kernel mirror walks, never binds).
  The property suite's reference model learned both sources and
  re-pinned (8 properties) plus 3 new ones (connected fold-in over an
  interface mirror, walk-stress with in-prefix gateways,
  empty-surface equivalence vs the legacy derivation — the
  byte-identical-when-empty bar). The `experimental-savnet` feature
  (default OFF, the workspace's first) gates the in-process
  `SavAgent` interface: bgpd's `on_message` UPDATE arm reports
  installs/withdraws (Adj-RIB-In granularity) + Established/teardown
  adjacency; ospfd reports the `InstallAndFlood` changed-key products
  as LsaChanged events + adjacency from both report consumers; savd
  hosts the monitor-only default `MonitorAgent` (log-before-drop:
  suggestions log, nothing enforces — no landed path turns one into a
  Binding or a rule). No wire protocols, no serialization, no
  sockets; no new crates (optional path-deps, rpki precedent). Gates:
  default workspace 1106/0, fmt+clippy -D warnings clean, and the
  three cfg-on legs green (sav 121, bgpd 173, ospfd 173; the prompt's
  singular "one cfg-on compile+test leg" read as one per wired crate
  — disclosed). 23 new tests (7 default + 16 cfg-on). Design note:
  docs/protocols/savnet.md (interface, flag, what stays out until
  drafts stabilize).

- 2026-10-11/12 (night program, closed by the M5 close-out) — all
  thirteen LEDGER lines PASS: the OSPF breadth slices (N2 broadcast
  networks + inter-area/ABR, N2B the OSPFv3 codecs on the AF-generic
  seams, N3 stub areas + NSSA per RFC 3101, Appendix D + RFC 5709
  auth, §16.5 incremental SPF, §15 virtual links), the SAVNET SIB
  fold-in + agent interface (N4, ticked above), bgpd (N5 RFC 7606
  revised error handling + route-server v1 + RFC 4724 graceful
  restart; N5B ADD-PATH receive per RFC 7911), the nft SAV backend
  on the Dataplane trait with the spoof-differential smoke (N6) and
  per-op monitor counters through to rousterctl/vty (N6B), the gortr
  real-cache RPKI interop runbook + client fixes (N7), the
  common::rundir reader consolidation (N8), and micros M1 (bgpd's
  single-hop BFD register family pinned, first DEREGISTER/UPDATE
  wire evidence), M2 (`call` + zebra-style access-lists + the
  `set comm-list` token-order fix), M4 (the vtyd config-apply
  design recorded in docs/protocols/vty.md). Close-out swept the
  docs index one-liners and fixed the P1-noted ospf citation drift
  (AS-external/forwarding-address sites cite §12.4.4, not §12.4.3;
  the external calculation's numbered steps are §16.4's — in
  ospf.md, the interop doc, and the mirrored ospfd code comments).
  Gate re-run at close by M5: fmt + clippy -D warnings clean,
  workspace 1262/0 (night baseline 1052/0).

- 2026-10-11/12 (night program, ADD-C2) — ospfd takes interface
  addresses from the ZAPI interface dump (`crates/ospfd/src/ifdump.rs`):
  the startup session HELLOs as OSPF, requests the dump (the
  empty-body INTERFACE_ADD), and bounds the burst with the savd
  causality marker (a dummy NEXTHOP_REGISTER's UPDATE is the
  deterministic dump-end — ZAPI has no end-of-dump marker); all
  pre-modeled message types, no new pins. The merge is dump-wins /
  static-falls-back: first non-secondary IPv4 address (mask from the
  prefix len; v6 skipped for the v2 daemon), live link state from the
  relayed ifi_flags (a dump-reported down/loopback interface stays in
  Down — no InterfaceUp at construction, no Hellos under the new §9.3
  tick gate, no router-LSA links); MTU deliberately not overlaid (the
  interface mirror carries none — a fabricated 1500 would stomp
  operator config; disclosed). The dump's session becomes the
  resident zedge (one socket, one HELLO; `zedge::connect` +
  `spawn_with_client`). Tests: 13 unit/daemon-level + 2 real-socket
  integration tests through `zapi::serve`'s actual dump encode; the
  interop smoke gained `ROUSTER_OSPF_DYNAMIC_ADDRESS=1` (no static
  `address` line, dump log line machine-checked) — BOTH modes PASS
  against the cached FRR 10.2.2 testbed (dynamic: Full adjacency,
  redistribute both directions, 30 s soak, exit 0). Gate: fmt +
  clippy -D warnings clean, workspace tests 0 failures.

- 2026-10-12 — Morning adjudication (night sheet CI-1/CI-2/POL-1/SAV-1/
  RH-1): socket2→ospfd ratified (N1 unblocked); CI = GitHub mirror
  github.com/li-ch/rouster with Actions (Gitee stays the public face;
  mirror reachable over SSH from this host); policy `call` semantics =
  compile-error on undefined, cycle-reject at load, comm-list token
  order fixed in M2; the expired cheng-draft citations generalized
  (this doc, Phase 2/3 lines); rousterctl→common ratified for the
  rundir reader (N8).

- 2026-10-12 (afternoon) — Owner decision: the audited unsafe block.
  BFD's receive-side TTL/hop-limit read-back is CLOSED (the AGENTS.md
  no-unsafe exception names exactly `arm_v4_recv_ttl` + `recvmsg_ctl`
  in bfdd's transport; both audited, kernel-proven on macOS AND via
  the Linux CI). The kernel tests that pinned it caught three real
  target-layout facts: macOS cmsg types 24/47 vs Linux 2/51, the
  4-byte `cmsg_len`, and macOS's single-byte v4 / native-order v6
  cmsg data. P2-a's deviation 1 is gone; only the multihop
  minimum-hop threshold remains unenforced local policy.

- 2026-10-14 — Batch adjudication (the 80 open sheet items): landed
  behavior ratified; all open recommendations adopted (O-1 FA=0.0.0.0
  + later knob; O-2 RFC1583 config-expose default-enabled; O-8 key
  chain stanza adopted — queued with the OSPF follow-ups; POL-2/4/5
  dispatched as the S7-d policy wave; SAV-2/4/7/8 directions recorded;
  CI-3/4 closed moot under the mirror). Sheet fully closed; queues in
  away/2026-10-14/STATE.jsonl.

- 2026-10-14 (round close) — S7 round GREEN: four parallel streams
  landed + integration pass. OSPFv3 daemon LIVE (Full adjacency with
  real FRR ospf6d, routes both directions via link-local advertisers;
  a real N2B codec bug fixed en route — A.4.7's Referenced-LS-Type
  placement); bgpd robustness (ADD-PATH tx, GR restarting-speaker
  §4.1 with citation fix, §9.2/iBGP + RR clients, bidirectional RS
  interop ×2); configd v1 (Phase 4 opens: canonical grammar,
  transactional apply + rollback, CLI, real-daemon smoke); the
  adjudication wave (POL-2/3/4/5 + SAV-3/4/7 doc pins). Gate
  1383/0 ×3 stable, clippy clean, smoke suite 34/34 (after one +x
  fix), CI green. Reports: away/2026-10-14/reports/S7-{a,b,c,d}.md.

- 2026-10-14 (evening, round close) — S8 round GREEN after a
  mid-round platform-quota kill (streams respawned from their prompt
  files with adopt-or-revert resume discipline; 7 pre-kill milestones
  counted as landed). Delivered: bgpd's ENTIRE B-item ledger (7606
  structured outcomes + treat-as-withdraw, §5.1.5-verified LOCAL_PREF
  reset, encode-side mixed guard, Hard Reset, RS export strip,
  capability-trust cleanup, errata re-check, drafts named); the
  security completion wave (v6 cmsg read-back closed under the widened
  AGENTS.md exception, RFC 8177 key chains feeding both crypto
  engines, RFC1583 knob); the operator loop (validate flags across
  the fleet, configd deep validation + auto-rollback, vtyd's write
  path over configd). Integration: two load-coupled flakes root-caused
  and hardened (configd's shared-seq race → validate-lock; vty
  one-shot client timeout → transport-only retry), 8× workspace
  stability green, gate 1468/0, smokes 34/34, CI pending push.
  Reports: away/2026-10-14/reports/S8-{a,b,c}.md.

- 2026-10-14 (night, round close) — S9 round GREEN + **v0.1.0
  RELEASED**: BAR-SAV landed (the sidrops -10 algorithm, pinned and
  step-cited: cone walk + provider subtraction, RuleOrigin::BarSav
  provenance through both backends, monitor-default, the bgpd
  read-only feed, and a live spoof-differential against real FRR
  peers — the SAVNET complement the plan pre-registered as "a small
  incremental module"); docker smokes in CI (the frr-testbed recipe
  reversed in-repo — alpine APK frr=10.2.2-r0, provenance anchored,
  34/34 equivalence, nightly smokes.yml); CHANGELOG + workspace
  0.1.0 + README status + the v0.1.0 tag (verified in an isolated
  worktree after a version-pinning test was made bump-proof).
  Gate 1498/0 ×3, smokes 35/35, CI green.

- 2026-10-15 — S10 round GREEN, Phase 5 opened: **IS-IS live** (the
  full TLV stack — codec/LSPDB/SPF/adjacency/AF_PACKET transport
  with the 802.3+LLC trap solved — at Up three-way adjacency with
  real FRR isisd and redistributed routes in both kernels);
  ospfd's depth queue cleared (full v3 SPF with A.4.3 fragments,
  broadcast arm + IAPRs, NSSA translator, area ranges, the
  virtual-link interop leg ×2); the polish lane (31× PrefixSet
  index with bench-proven equivalence, BAR-SAV's ASPA edges);
  CI smoke parity (all 16 nightly failures root-caused — runner
  kernel modules, AppArmor, uid/gortr, rp_filter defaults — and
  passing). The escalated v3 REDIST-IN flake was OURS: the
  deferred own router-LSA landing never re-dirtied the v3 SPF
  (green runs raced FRR's 5s refresh); fixed with the v2-parity
  mark-dirty + regression test (4e0910a). Gate 1623/0, smokes
  37/37 in 1392 s.

- 2026-10-15 (later) — S11 round GREEN, invariant 5 landed: the YANG
  core (pure-Rust RFC 7950 subset — parser/types/tree/validator,
  72 RFC-cited tests + the property suite), the seven-model set in
  yang/*.yang with the conformance corpus, configd's FLIP (the YANG
  tree is the internal source of truth; text grammar remains the
  edge; renders byte-identical, pinned against the legacy
  renderer), the vtyd translator seam (config edits = tree ops,
  show running-config renders from the tree), and the gNMI
  transport evaluation in docs/yang.md (options A-D, recommendation
  C RESTCONF-shaped edge, OWNER DECISION BLOCK unfilled). Gate
  1715/0 (+92), fmt/clippy clean incl. an integration sweep over a
  concurrent session's mrt-replay tail.

- 2026-10-15 (evening) — Owner decision (docs/yang.md §gNMI-transport):
  **C adopted** — the RESTCONF-shaped HTTP/1.1 edge on the landed
  tree ops + RFC 7951 dump, no new dependencies; gNMI remains the
  documented next step (A's datastore semantics map identically).
  Dispatched as the S12 stream.

- 2026-10-15 (night) — S12 round GREEN, invariant 5 COMPLETE: the
  RESTCONF-shaped HTTP/1.1 edge (gNMI decision C) — hand-rolled
  HTTP core over tokio, the RFC 8040-subset resource map on the
  YANG tree (GET/PUT/POST/PATCH/DELETE in RFC 7951 JSON,
  validate-first mutations riding the apply/auto-rollback
  pipeline), the /data-vs-/running datastore split, the restconfd
  binary + restconf stanza + dry-run mode, the disclosed loopback/
  no-auth v1 posture, and the gNMI mapping table (option A's path
  preserved). One real bug fixed en route (linebind stale-origin
  preference after tree mutation). Gate 1769/0 (+54), both new +
  existing smokes green (38 scripts).

- 2026-10-15 (night, bench round + fix round) — the pre-registered
  benchmark program (docs/benchmarks.md, decisions D1–D6
  owner-ratified) ran E1/E5/E7 against FRR 10.2.2 and found two
  real bgpd defects plus one rousterd bottleneck: **F1** (O(n²)
  LocRib::recompute per UPDATE — full-table ingestion projected to
  weeks), **F7** (the session select! dropped framed bytes under a
  timer race; tee-proxy wire-proven), **F8** (rousterd FIB
  programming ≈4.8k routes/s vs FRR zebra's 9.67 CPU-s — OPEN,
  owner decision). Fix round `47ef0ee`: recompute_prefix (per-prefix
  §9.1 election, O(log n) Nlri range-scan, incremental==bulk
  equivalence test), the cancel-safe persistent-read session loop,
  counts-only UPDATE logging (F5). Gate 1770/0, clippy clean. §R
  post-fix entry: full 1,126,490-prefix table at EOR **4.73 s
  median (≈238k routes/s), zero malformed, zero rejected, unpaced
  at hold 90**; end-to-end 247.8 s dominated by F8. D3's nightly
  bench job landed (`bench.yml`). The in-repo mrt-replay injector
  (225k routes/s, zero new deps) is a keeper dev tool. Evidence:
  away/2026-10-15/bench/ (REPORT.md + state + captures).

- 2026-10-15/16 (night, F8 fix round) — **F8 FIXED** (`5afbba6`,
  owner-authorized after the diagnosis): pipelined route
  programming (Dataplane batch methods with sequential defaults;
  netlink-dp overrides at 512-in-flight, every ACK verified,
  ordered results), dirty-key reconcile on the ZAPI hot path
  (O(batch); tick/events/SIGHUP keep the full pass), inline
  scan-and-diff (no desired-state map), reconcile-tick
  MissedTickBehavior::Delay. Gate: fmt + clippy (host + musl)
  clean, workspace 1770/0 (M3 partition properties unchanged).
  §R post-F8 entry: **full table in-kernel 17.1 s median (was
  247.8 s; FRR 30.36 s)**, total SUT CPU 21.3 s (FRR's ledgered
  20.7), EOR 6.07 s with installs overlapping the ingest, 0
  malformed / 0 rejected on all six runs. rousterd ≈65k routes/s
  effective (was ≈4.8k). Harness follow-up recorded: the
  main-table poll's netlink dump starves on short install-storm
  runs — poll the status socket instead. Comparative claims stay
  closed on darwin-vm (17.1 vs 30.36 = 1.78×, under the 2× rule);
  the descriptive claim is licensed.

- 2026-10-16 — S13 round GREEN, the v1.0 tail CLOSED: IS-IS
  depth (RFC 5302 inter-area + the §3.10.2 ladder, broadcast/DIS/
  pseudonode circuits with a new interop smoke, TLV 10 + RFC 5304
  auth with key chains, fragment families + pacing + RFC 7987
  lifetimes, the admin knobs; a live bug fixed — L1L2 never ran
  its L1 database); F3 first-AS enforcement (RFC 4271 §6.3,
  byte-pinned 3/11, iBGP-exempt; +the F5 log regression the smoke
  re-run caught); RESTCONF v2 (unix socket default with 0660 bits
  as access control, constant-time bearer token, TLS as a
  documented owner block); the fuzz upgrade (six cargo-fuzz
  targets + nightly CI; the first dispatch caught a real u32 OOB
  panic in the RTR ERROR_REPORT decoder — fixed with a bounds
  check + regression test). Gate 1845/0 ×3, smokes 39/39. One
  new owner item: zapi INTERFACE_ADD hw_addr (blocks FRR's IS-IS
  broadcast SNPA; the ask documented in isisd §Deferred).
