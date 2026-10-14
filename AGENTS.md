# AGENTS.md — Rouster

Guidance for any agent (or human) working in this repository.

## Identity

**Rouster = router + Rust.** A routing protocol suite in Rust: BIRD-style typed
multi-table core + Holo-style async/AF-generic protocol crates, FRR
compatibility at the edge, and native source address validation. This repo will
be open-sourced; write code and docs accordingly.

## Architecture invariants (rationale: docs/architecture.md)

1. **Core/edge split.** FRR compatibility (ZAPI server, vtysh shim, frr.conf import) lives in edge adapters only — never in core abstractions.
2. **RIB is BIRD-style:** typed multi-table core with explicit channels; soft-reconfiguration semantics (config changes must not bounce sessions).
3. **Protocol crates are AF-generic** via Rust generics — one codebase per protocol family (OSPFv2+v3 share code; no `ospfd`/`ospf6d`-style duplication).
4. **Policy engine is typed and compiled** (BIRD-inspired); route-map grammar exists only as an import-compatibility layer.
5. **YANG-native transactional config is primary**; vtysh is a translator on top, never the source of truth.
6. **All dataplane programming goes through the `Dataplane` trait** (`crates/common/src/dataplane.rs`): netlink today, FPM/eBPF later. No direct rtnetlink calls outside `netlink-dp`.
7. **No `unsafe` in protocol code.** Fuzz every wire codec (cargo-fuzz) before calling it done. **Named exception (owner decisions 2026-10-12 and 2026-10-14):** the receive-side TTL/hop-limit read-back — the audited `recvmsg`/`setsockopt` helpers, each carrying its audit comment: `arm_v4_recv_ttl` + `recvmsg_ctl` in `crates/bfdd/src/transport.rs`, and the v6 cmsg read-back helper in `crates/ospfd/src/transport.rs` (same pattern, same audit discipline). The invariant otherwise stands absolute.

## SAVNET rules

- SAV is a first-class subsystem: SIB + IBA/IBB/PBA/PBB validation modes + SAV table manager. Priority is **SAVNET above BAR-SAV** (owner decision).
- Draft-dependent wire protocols (intra-domain IGP/BGP signaling, inter-domain) go behind the `experimental-savnet` feature flag; pin implemented draft versions in docs; isolate wire codecs.
- Enforcement defaults to log/monitor before drop; per-mode enablement; unknown ≠ invalid.

## Testing bar

- `cargo test` green per crate.
- netns/Containerlab integration topologies for anything that touches the kernel.
- FRR interop both directions (FRR-zebra + rouster protocol, rouster zebra + FRR protocol) once ZAPI lands.
- SAV: spoofed-traffic tests measuring improper block / improper permit.

## Conventions

- Tokio async everywhere; `thiserror` for error types; `tracing` for logs.
- Phase plan and workstream status: `docs/implementation-plan.md`. Update docs in the same change that alters plans or behavior.
- Commit messages: imperative mood, scope prefix (e.g. `rib: add best-path selection`).
