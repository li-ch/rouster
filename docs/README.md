# Rouster documentation — index

| Document | What it is |
|---|---|
| [architecture.md](architecture.md) | The core decision record: why Rouster is not an FRR clone — BIRD/Holo core, FRR compatibility at the edge only, SAV as a first-class subsystem. Architecture changes are owner decisions; this doc is the rationale, not a tutorial. |
| [implementation-plan.md](implementation-plan.md) | Phases, design principles, testing/CI strategy, SAVNET workstream rules, risks. Appendix C is the **append-only** status log — every tick cites its evidence. |
| [interop/zapi-10.2-pinned.md](interop/zapi-10.2-pinned.md) | **Ground truth for the ZAPI codec**: command numbers and body layouts pinned against the real FRR 10.2.2 binary (wire capture + oracle + binary extraction). The `crates/zapi` codec defers to this file, never to memory or other FRR versions. |
| [interop/frr-10.2-interop.md](interop/frr-10.2-interop.md) | FRR 10.2.2 interop results, per smoke script, with deviations and reproduce commands. Grows as new interop scenarios land. |
| operator-surfaces.md | The `rousterctl` v1 operator CLI: command table, exit codes, and the run-dir contract (`/run/rouster/` — who writes which file, who reads it). v1 reads only; the CLI never writes the run dir. |

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
