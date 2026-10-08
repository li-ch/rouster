# Rouster

A routing protocol suite in Rust — router + rust.

BIRD-style typed multi-table core + Holo-style async/AF-generic protocol crates,
FRR compatibility (ZAPI, vtysh, frr.conf) at the edge, and native source address
validation (SAVNET first, BAR-SAV later).

## Documentation

- [docs/implementation-plan.md](docs/implementation-plan.md) — design principles, phase plan, SAVNET workstream, risks
- [docs/architecture.md](docs/architecture.md) — why Rouster is not an FRR clone: modern core, compatibility at the edge

Status: pre-scaffolding.

## Planned layout (Phase 0)

```
rouster/
  Cargo.toml          # workspace
  crates/
    rousterd/         # main daemon binary
    rib/              # BIRD-style typed multi-table RIB core
    netlink-dp/       # Linux netlink dataplane (rtnetlink)
    zapi/             # FRR ZAPI codec + server (interop edge)
    common/           # shared types: prefixes, nexthops, ifaces
```
