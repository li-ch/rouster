# Rouster documentation — index

| Document | What it is |
|---|---|
| [architecture.md](architecture.md) | The core decision record: why Rouster is not an FRR clone — BIRD/Holo core, FRR compatibility at the edge only, SAV as a first-class subsystem. Architecture changes are owner decisions; this doc is the rationale, not a tutorial. |
| [implementation-plan.md](implementation-plan.md) | Phases, design principles, testing/CI strategy, SAVNET workstream rules, risks. Appendix C is the **append-only** status log — every tick cites its evidence. |
| [interop/zapi-10.2-pinned.md](interop/zapi-10.2-pinned.md) | **Ground truth for the ZAPI codec**: command numbers and body layouts pinned against the real FRR 10.2.2 binary (wire capture + oracle + binary extraction). The `crates/zapi` codec defers to this file, never to memory or other FRR versions. |
| [interop/frr-10.2-interop.md](interop/frr-10.2-interop.md) | FRR 10.2.2 interop results, per smoke script, with deviations and reproduce commands. Grows as new interop scenarios land. |
| operator-surfaces.md | The operator surfaces: `rousterctl` (v2 adds the `rousterd.status` dump consumers — interface/neighbour/vrf/rib summary), exit codes, the run-dir contract (`/run/rouster/` — who writes which file, who reads it), and the vtyd/vtysh shim mapping. The CLI never writes the run dir. |
| protocols/bfd.md | The `bfdd` daemon: RFC 5880-5883 scope, the state-machine reading decisions, FRR interop facts, the ZAPI-BFD wire family (pinned against real FRR 10.2.2), and the `--zapi` client edge. |
| protocols/bgp.md | The `bgpd` core: v1 scope (codec/FSM/§9.1/RIB/ZAPI), the policy engine bridge + RPKI/ROV/OTC/ASPA decision path (W2-d), §6.8 collision detection, and the deferred anchors (route-server, experimental-savnet hook). |
| protocols/ospf.md | The `ospfd` daemon: RFC 2328 LSA codec, LSDB (§13), two-stage SPF (§16.1), adjacency/flooding cores, the Day-2 raw-socket transport + daemon + FRR interop, and the AF-generic seams for the OSPFv3 fold-out. |
| protocols/policy.md | The `policy` crate: the typed filter engine (BIRD-cited semantics), sets-as-data with longest-match tags, the dependency-free FRR AS-path regex NFA, and the route-map parser→compiler — consumed by bgpd's import/export seams. |
| protocols/savnet.md | The `experimental-savnet` flag: the in-process SAVNET agent interface (SavAgent), the monitor-only default agent savd hosts, the honest process-topology scoping, and what stays out until the IETF drafts stabilize. |
| protocols/rpki.md | The `rpki` library: RTR PDU table, session diagram, RFC 6811 ROV + ASPA semantics with citations, and the real-cache interop runbook. |
| protocols/vty.md | The `vtyd` server: the vtysh-compatible word-tree grammar, Cisco session modes, the B7-observed config subset (parse-only v1), and the run-dir show commands (sav/bfd/rousterd dump). |

Repo-level entry points: [README.md](../README.md) (what runs today,
quickstart) and [CONTRIBUTING.md](../CONTRIBUTING.md) (gates, commit and
wire-format conventions).

## Ground truth: how wire formats are established

FRR's ZAPI is not fully specified in prose — the developer guide defers
message definitions to headers, and details drift across FRR versions.
Rouster therefore pins every wire fact empirically, and the pinned doc is
the only authority:

- **Pin, never guess.** A new message or body field enters the codec only
  after it has been observed on the wire against FRR 10.2.2 (e.g. via the
  `crates/zapi` dev tools — `zapi-sniff`, `zapi-notify-probe`,
  `zapi-neigh-probe`, driven by `scripts/test-m4-pin-capture.sh` for
  in-window kernel/zebra mutations), cross-checked
  against a real zebra oracle or the binary's own message table, and
  written into [interop/zapi-10.2-pinned.md](interop/zapi-10.2-pinned.md)
  together with its capture fixture.
- **Deviations are recorded, not absorbed.** When a real daemon behaves
  differently than assumed, the pinned doc gains a deviation note and the
  codec follows the observation.
- **One FRR version is the pin.** Findings from other FRR versions are
  noted as such and do not move the codec.

The same discipline applies to draft-dependent SAVNET wire protocols:
they live behind the `experimental-savnet` feature flag with their
implemented draft versions pinned in docs (implementation-plan §4).
