# Changelog

All notable changes to Rouster are documented here. The format
follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and
the project versions its workspace as a whole.

## [0.1.0] — 2026-10-14

The first tagged release: the ZAPI-interop core, all four
SAVNET slices, three native protocol daemons with live
FRR-interop proof on every wire, and the management plane's
foundation — gated at 1468 tests, a 34-script container smoke
suite, and Linux CI.

### Added — zebra-equivalent core

- `rousterd`: BIRD-style typed multi-table RIB over a Linux
  netlink dataplane — interface/address/route/neighbour mirroring,
  static-route programming (ECMP, non-main tables, VRF devices and
  their tables), SIGHUP config reload with redistribute-diff
  fan-out, recursive multi-hop nexthop resolution, neighbour-gated
  NEXTHOP_UPDATE answers (zebra-faithful by owner decision), and
  interface/neighbour/VRF session pushes at the ZAPI edge.

### Added — the ZAPI edge, pinned against real FRR 10.2.2

- Unmodified `staticd`, `bgpd`, and `ospfd` attach to rousterd as
  their zebra; their routes reach the kernel through the Rust RIB.
- The wire codec is byte-pinned against the real binary
  (`docs/interop/zapi-10.2-pinned.md`): route-type numbering,
  ROUTE_NOTIFY_OWNER both flavors, BFD registration semantics,
  neighbour messages, the interface dump's VRF header — captured
  from live exchanges, never guessed.
- Session-establish registration replay (identity-keyed, ADD+DEL
  delta) heals reconnecting clients that omit re-registration.

### Added — native protocol daemons

- `bgpd`: RFC 4271 FSM/codec, 4-byte AS, MP-BGP v4/v6, route
  refresh, ADD-PATH both directions, route reflection and
  route-server mode, graceful restart (helper and restarting
  speaker, RFC 8538 Hard Reset), RFC 7606 revised error handling,
  RFC 4271 §9.2 dissemination rules — with RPKI from the start:
  RTR client (RFC 8210, interop-proven against a real gortr cache),
  RFC 6811 ROV, ASPA verification, RFC 9234 roles/OTC.
- `ospfd`: the RFC 2328 stack end-to-end (LSDB, flooding, SPF with
  back-off and partial recompute, broadcast networks and DR
  election, inter-area summary, stub/NSSA, Appendix-D auth with
  MD5 + HMAC-SHA-256 key chains, virtual links) — and OSPFv3 on
  the same AF-generic codebase, at Full adjacency with real FRR
  ospf6d.
- `bfdd`: RFC 5880–5883 (the exact state machine, single-hop
  TTL-255 enforcement receive-side on both address families,
  multihop, echo, the ZAPI-BFD integration).

### Added — source address validation

- `savd` + the `sav` crate: the SAV Information Base, the
  IBA/IBB/PBA/PBB validation-mode rule model, uRPF-family
  generation (RFC 3704/8704 incl. deletion hysteresis), the
  GSC §3 merge-by-subtraction policy, provenance-tracked rules,
  enforcement behind the dataplane trait with `rp_filter` and
  nftables backends, spoof-differential smokes, and the
  monitor-only default with explicit drop opt-in.
- The SAVNET agent interface behind `experimental-savnet`
  (in-process hooks; no draft wire protocols on by default).

### Added — policy and management

- `policy`: the typed, BIRD-cited filter engine with the FRR
  route-map compatibility grammar (call/cycle-checked, community
  modes, ordered access-lists).
- `vtyd` (vtysh-compatible VTY server), `configd` (transactional
  config manager: canonical grammar, deep validation, atomic apply,
  generations, auto-rollback), `rousterctl` (read-only operator
  CLI), and the run-dir contract binding them
  (`docs/operator-surfaces.md`).

### Infrastructure

- Linux CI (fmt, clippy -D warnings on host and musl targets,
  full test suite, smoke-script syntax) on every push; the smoke
  suite (34 scripts) runs the full interop matrix locally.
- MIT license; public mirrors on Gitee and GitHub.

[0.1.0]: https://gitee.com/drchenli/rouster/releases/tag/v0.1.0

## [1.0.0] — 2026-10-16

The goals-metting release: every plan pillar landed and live-proven.

### Added since 0.1.0

- **IS-IS** (`isisd`): the full TLV stack — RFC 5302 inter-area
  with the §3.10.2 preference ladder, broadcast/LAN circuits with
  DIS election and pseudonode LSPs, RFC 5304 HMAC-MD5 auth with
  key chains, LSP fragment families with §7.3.15 pacing and
  RFC 7987 lifetimes, the administrative knobs — at Full adjacency
  with real FRR isisd and routes exchanged both directions.
- **BGP hardening**: RFC 7606 revised error handling (structured
  outcomes, treat-as-withdraw), graceful restart both roles with
  Hard Reset, ADD-PATH both directions, route-server mode,
  RFC 4271 §6.3 first-AS enforcement, iBGP ROV-validity
  propagation, route reflection.
- **Management plane complete**: the YANG core (pure-Rust RFC 7950
  subset, seven models, configd's tree-as-source-of-truth flip,
  vtyd the translator), the RESTCONF-shaped HTTP northbound with
  Unix-socket default + constant-time bearer token.
- **Security**: BFD receive-side TTL enforcement on both address
  families (kernel-proven), OSPFv3's v6 cmsg read-back, key chains
  across IS-IS and OSPF.
- **Benchmarks**: the frozen-claim-policy program — full 1.126M-
  prefix table in-kernel in 17.1 s median (FRR's ledgered 30.36 s
  on the same rig; comparative claims stay closed under the
  darwin-vm rule), 1845 tests, 39 smoke scripts, nightly docker CI
  + fuzz CI (whose first dispatch caught a real OOB in the RTR
  decoder).

[1.0.0]: https://gitee.com/drchenli/rouster/releases/tag/v1.0.0
