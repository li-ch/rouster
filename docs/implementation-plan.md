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
- BGP-carried intra-domain SAVNET signaling hook (draft-cheng-savnet-intra-domain-sav-bgp), behind `experimental-savnet`.
- Fuzz the BGP codec (cargo-fuzz), interop vs. FRR/BIRD/GoBGP in CI.

### Phase 3 — IGP: OSPFv2 (10–14 weeks)

- LSA database, flooding, SPF (with back-off), areas/stub/NSSA, authentication.
- AF-generic single codebase (Holo pattern) — OSPFv3 then falls out nearly free.
- IGP-carried intra-domain SAVNET signaling (draft-cheng-savnet-intra-domain-sav-igp), behind `experimental-savnet`.

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
  derived ROUTER_ID_UPDATE (live-validated by ospfd, no config pin),
  REDISTRIBUTE_ADD registrations get an initial best-route dump, and
  REDISTRIBUTE_ROUTE_DEL is modeled and pushed on best-route
  withdrawal, with the whole bgpd interop flow re-run green after those
  changes (LEDGER W2, W1B). Config reload now pushes redistribute
  ADD/DEL for changed bests and stays silent on identical reloads
  (LEDGER M2). BFD_CLIENT_REGISTER is recorded and its no-reply is
  source-verified against frr 10.2.2 `zebra_ptm.c` (LEDGER M1).
- 2026-10-09 — Phase 1.5 (savd core): delivered end-to-end — SIB with
  typed source-prefix/interface bindings ingested from the RIB (LEDGER
  W5); the IBA/IBB/PBA/PBB rule model plus uRPF-family rule generation
  and the table manager, RFC-cited table-driven tests, FP approximation
  disclosed (LEDGER W6); enforcement through the Dataplane trait with an
  rp_filter sysctl backend (nft absent from all cached images),
  spoof-block/legit-pass tests and a monitor-before-drop default
  (LEDGER W7); the savd daemon wired as a ZAPI client of the RIB,
  monitor-only by default with drop refusal tested, neighbour-based
  monitor feed (LEDGER W8). SIB ingest invariants are property-pinned
  against a reference model, 10k-case stress green (LEDGER W5B).
