# Rouster — Architecture Decision: compatibility at the edge, modern core inside

Date: 2026-10-08
Status: Decided
Companion docs: [implementation-plan.md](implementation-plan.md)

Rouster is **not** an FRR clone. It fuses BIRD's and Holo's core architecture,
keeps FRR compatibility strictly at the edge, and adds native source address
validation. This document records why.

---

## 1. Is FRR's architecture actually worse?

Mostly yes at the *code-architecture* level; no at the *operational-model* level.

| Aspect | FRR | BIRD | Holo |
|---|---|---|---|
| Process model | Multi-process, one daemon per protocol, ZAPI IPC | Single process, unified core; BIRD 3 adds threads | Single binary, Tokio tasks |
| Protocol code reuse | Weak: `ospfd`/`ospf6d`, `ripd`/`ripngd` are parallel codebases | Unified AF handling since 2.0 (channels) | Strong: generics → one codebase per protocol family |
| Config model | String CLI first (vtysh); YANG/mgmtd bolted on, transition still ongoing | Config-file + filter language first; soft reconfig as core concept | YANG-native, transactional, rollback |
| Event model | Single-threaded event loop per daemon | Single-threaded (v2) → multithreaded (v3) | Multi-core async from day one |
| Memory safety | C; recurring ZAPI/parsing CVE-class bugs | C; disciplined but still C | Rust |
| Fault isolation | **Real process isolation**: one daemon crash doesn't take others down | Process-global | Task-level only |

FRR's weaknesses are largely *age* (Zebra → Quagga → FRR lineage since ~1996): duplicated per-AF daemons, stringly-typed CLI core, northbound retrofitted. Its multi-process model isn't stupid — it buys crash isolation and independent daemon upgrades — but in Rust much of that motivation evaporates: memory-safety crashes are gone, and Tokio tasks + panic isolation + supervision recover the rest in-process.

---

## 2. Consequence: compatibility at the edge, modern core inside

```
                ┌───────────── Rouster (single binary, Tokio) ──────────────┐
                │                                                           │
  vtysh ──────▶│  compat edge: vtysh CLI shim · frr.conf importer          │
  FRR daemons─▶│ compat edge: ZAPI server (zebra-equivalent endpoint)      |
  gNMI/gRPC───▶│  native edge: YANG-modeled transactional northbound       │
                │                                                           │
                │  core: unified RIB (multi-table, nexthop tracking)        │
                │        AF-generic protocol crates (OSPFv2/v3 one codebase)│
                │        policy engine (route-map-like, compiled, typed)    │
                │        SAV: SIB · validation-mode rules · table manager   │
                │                                                           │
                │  dataplane trait → netlink (now) · FPM/eBPF (later)       │
                └───────────────────────────────────────────────────────────┘
```

Take from each:
- **From Holo (core):** single-binary async design; AF-generic protocol code via Rust generics; YANG-native transactional config as the *primary* model.
- **From BIRD (core):** routing tables as first-class objects with explicit channels between them; a real, typed policy language instead of FRR's route-map sprawl; soft-reconfiguration semantics (change config without bouncing sessions).
- **From FRR (edge only):** ZAPI server so existing FRR `bgpd`/`ospfd` can attach (migration path); vtysh-compatible CLI and frr.conf import for operator familiarity. These are *adapters*, never core abstractions.
- **Optional process isolation:** allow packaging each protocol as its own binary speaking the internal bus, for operators who want FRR-style isolation — but default deployment is one binary.

What we explicitly drop from FRR's model: per-AF duplicated daemons, string-based CLI as the source of truth, one-event-loop-per-daemon, ZAPI as the *internal* architecture (it's an interop surface only).

---

## 3. Consequences for the phase plan

- Phase 0–1 (zebra-equiv + ZAPI server): the RIB is built BIRD-style (typed multi-table core), not as a zebra clone.
- Phase 2 bgpd: RTR client + ASPA from the start; policy engine is the typed BIRD-inspired one, with a route-map compatibility grammar layered on top for frr.conf import.
- Phase 3 OSPF: AF-generic single codebase (Holo pattern) — OSPFv3 then falls out nearly free.
- Phase 4 management: YANG-native is primary; vtysh shim is a translator, not the config system.
- SAV (Phase 1.5+) lives in the core as a first-class subsystem (SIB + rule model + table manager), enforcing via the dataplane trait.
