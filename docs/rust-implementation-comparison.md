# Rust routing implementations — feature and protocol comparison

Status: verified 2026-10-21 against primary sources (pinned below).
Purpose: the factual basis for any claim about how \sys's coverage
compares with other Rust implementations. Companion to the
2026-10-21 Rust-baselines measurements (benchmarks.md §R; receipts
away/2026-10-21/bench/rust-baselines/) — this file covers WHAT the
systems implement, that work covered HOW they perform.

## Sources and pins (all read this session)

| system | version / pin | source read |
|---|---|---|
| \sys (Rouster) | repo @0cf568f | crates/ doc-headers, source |
| Holo | v0.9.0 = 947daeb (2026-02-21, latest release) | clone on dgx-spark-1: workspace crates, holo-daemon features, holo-ospf/src/ospfv3/ |
| RustyBGP | 3dbf3e1 (2026-10-19 master) | clone on dgx-spark-1: README feature list, daemon/packet source |
| rustbgpd | README @main, baseline v0.79.0 (accessed 2026-10-21) | raw README via proxy (clone blocked) |
| Rotonda | 59350bb (2026-09-10 master) | clone on dgx-spark-1: README, Cargo.toml |

Upstreams move fast: both RustyBGP and rustbgpd now ship features
beyond what the paper's related-work pass described (both gained
RPKI and more); re-verify before citing numbers from this file after
any upstream release.

## The matrix

N = native (implemented in the system's own crates).
Attach = available by attaching the incumbent's unmodified daemon
through the system's compatibility boundary (only \sys has one).
"opt-in" = present but not in the default configuration.

| capability | Rouster (native) | Rouster (+attached FRR 10.2.2) | Holo v0.9.0 | RustyBGP | rustbgpd | Rotonda |
|---|---|---|---|---|---|---|
| BGP IPv4/v6 unicast | N | N | N | N | N | N |
| BGP L3VPN / EVPN / BGP-LS / Flowspec / SR Policy / MUP / RTC | — | N (via FRR bgpd) | — | N (EVPN relay 1-5) | N (reflection, scoped; FlowSpec controller) | — (Flowspec not a target) |
| BGP route reflector / route server / confederation | — | N (via FRR bgpd) | RR | N | N (its primary role) | route-server shaped |
| ADD-PATH (RFC 7911) | codec support; negotiated use not claimed | N (via FRR bgpd) | ? | N | N | — |
| Graceful restart | restarting-speaker side (RFC 4724 deferral) | N (via FRR bgpd) | ? | N + LLGR (9494) | ? | — |
| OSPFv2 | N | N (FRR ospfd also) | N | — | — | — |
| OSPFv3 | — (AF-generic design; v3 = separate codec layer, not built) | N (FRR ospf6d) | N | — | — | — |
| IS-IS | N (ISO 10589 + RFC 1195, wide metrics, p2p 3-way, SPF) | N (FRR isisd also) | N (incl. RFC 5310/7602 auth) | — | — | — |
| RIP / LDP / VRRP / IGMP | — | — | N (RIP, LDP, VRRP; IGMP present but disabled as non-functional) | — | — | — |
| BFD | N (RFC 5880/5881/5883; FRR bfdd attaches through the relay) | N | N | N | — | — |
| Static routing | N | N (FRR staticd also) | — | — (connected redistribution only) | — | — |
| Kernel FIB programming | N (netlink proto 186, pipelined; measured) | N (measured, configs A/B/D) | N (netlink proto 186; measured) | opt-in (`[zebra.config]`; measured at 2k) | opt-in | — (in-memory RIB; not its role) |
| RPKI RTR + ROV | N (rpki crate; feeds bgpd import policy) | N (via native) | — | N (RFC 6810/8210) | N | RPKI types via routecore/rpki-rs deps |
| ASPA verification | N | — | — | — | — | — |
| Source address validation (SAV) | N (SIB + BAR-SAV + SAVNET-designed; nftables monitor/drop + rp_filter backends) | — | — | — | — | — |
| Incumbent compatibility (ZAPI server; unmodified FRR daemons attach; mixed operation) | N (bgpd, staticd, ospfd, ospf6d, isisd, bfdd, mgmtd) | — | — | — | — | — |
| Management plane | vtysh-compatible VTY; rousterctl | (FRR vtysh) | gRPC + gNMI northbound + CLI (YANG-modeled config) | gRPC (GoBGP v4 API) + GoBGP CLI | gRPC + `rbgp` CLI | HTTP/JSON API + Roto filter language |
| BMP / MRT tooling | MRT replay injector (bench tool) | — | — | N (BMP, MRT) | N (BMP, MRT) | N (BMP sessions, MRT import) |

"?" = not established this pass; do not claim either way without
checking the upstream source.

## The honest reading

1. **Native protocol breadth: Rouster is not the broadest Rust
   suite, and must not be claimed as one.** Holo natively ships
   more routing protocols (OSPFv3, RIP, LDP, VRRP against our
   OSPFv2/IS-IS/BFD/static; both have BGP and IS-IS). The
   BGP-centric systems are deeper in BGP address families than our
   native speaker (v4/v6 unicast only): RustyBGP and rustbgpd carry
   L3VPN/EVPN/BGP-LS/Flowspec-class families we do not implement
   natively.
2. **The breadth claim that IS true is the deployed-system view
   through the compatibility boundary**: a Rouster deployment runs
   the incumbent's unmodified daemons (bgpd with its full family
   set, ospf6d, isisd, staticd, bfdd, mgmtd) on the Rouster core,
   mixed with native daemons. No other Rust system admits incumbent
   daemons; Holo and the BGP speakers are clean-break designs. This
   is the paper's thesis, and it is an architecture claim, not a
   protocol-count claim.
3. **Rouster-unique capabilities**: native SAV (rule derivation
   from BGP+ROA/ASPA state, nftables monitor/drop and rp_filter
   backends) and ASPA verification alongside ROV. RPKI itself is
   NOT unique among Rust implementations: RustyBGP and rustbgpd
   both list it. Frame ours as "RPKI from the start, feeding import
   policy", never as the only Rust RPKI.
4. **Kernel FIB**: all three measured Rust systems program the
   kernel; the difference is posture, not existence — Rouster and
   Holo install by default (Rouster's bounded pipelined path is the
   measured differentiator), RustyBGP's and rustbgpd's integration
   is opt-in and route-server-oriented.

## Claim guardrails (for paper/site/fact-sheet text)

- No "most complete Rust suite" / "more protocols than the others"
  claim in any direction. The one-sentence form that survives
  review: "\sys is not the broadest native Rust suite; it is the
  one an incumbent deployment can enter without leaving its
  daemons behind, plus native SAV and RPKI/ASPA validation."
- Both directions stay publishable (benchmarks.md claim policy §2):
  if a comparison table is ever published, Holo's broader IGP set
  and the BGP speakers' family depth appear in it.
- The paper's standing rule ("no protocol breadth claims", CLAUDE.md
  numbers-register) is why this matrix lives here and not in the
  manuscript.
