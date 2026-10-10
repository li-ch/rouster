# bgpd — the Rouster BGP daemon (Phase 2, stream P2-b)

Status: v1 landed 2026-10-10 (commits `6068045`..`e52826c`). Scope:
RFC 4271 base + capabilities + MP-BGP v4/v6 unicast + route refresh +
4-octet AS, a pure FSM, the §9.1 decision process, the ZAPI client
edge, and a two-green-runs interop smoke against real FRR 10.2.2
bgpd.

## Layout

| Module | What |
|---|---|
| `message` | Header/OPEN/UPDATE/NOTIFICATION/KEEPALIVE/ROUTE-REFRESH framing (RFC 4271 §4; refresh RFC 2918 §3) |
| `capability` | RFC 5492 capability triples; extended OPEN optional parameters per RFC 9072 |
| `attr` | Path-attribute model: §4.3 flags, AS_PATH (RFC 6793 4-octet, AS_TRANS=23456 bridging), communities (RFC 1997), MP_REACH/MP_UNREACH (RFC 4760), unknown-transitive passthrough with the partial bit forced |
| `fsm` | The §8 six-state machine, table-driven, pure and clock-injected |
| `peer` | Session runtime: framed IO, hold/keepalive timers, §6.2 OPEN checks, §9.5 AS-loop rejection, RFC 2918 refresh answers, MRAI gate, Adj-RIB-In sink / Adj-RIB-Out source traits |
| `rib` | Adj-RIBs-In + Loc-RIB, `best_path` = the §9.1.2.2 ladder, Import/Export policy seams (accept-all v1) |
| `zedge` | ZAPI client edge: NHT for peer addresses (connector gate), interface mirror, best-path export to the zebra |
| `daemon` | Listener (TCP 179 default, `listen-port` knob), per-neighbor connectors (§10 ConnectRetry, exponential 1 s→120 s), §6.8 first-wins collision admission, graceful stop |
| `config` | `bgpd.conf` grammar (A11/B7 conventions) |
| `bin/bgpd` | Thin shell (savd shape): config → Loc-RIB → zedge → daemon |

## Pinned design decisions

- **SIGTERM → NOTIFICATION Cease** (§6.7 sanctions a locally-chosen
  close; the Established Event 2 row prescribes Cease). Verified on
  the wire: FRR records `Notification received (Cease/Administrative
  Shutdown)`.
- **SIGUSR1 → ROUTE-REFRESH** (RFC 2918) to every Established peer —
  the on-demand refresh knob.
- **MRAI default 0** (FRR parity; RFC 4271 §10 suggests 30 s eBGP /
  5 s iBGP — tuning §Deferred). Coarse per-peer gate, clock-injected.
- **§9.1.2.2 e) (interior cost) skipped** — the RFC allows skipping
  when no cost can be determined; no IGP exists yet.
- **DelayOpen always FALSE**; Events 16/17 and 24/25 unified per
  identical table handling; Events 14/15 stay at the TCP layer.
- **§6.8 collision: first-wins** at the daemon (one session per
  neighbor); the BGP-ID tiebreak is §Deferred.

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
 neighbor 192.0.2.9 mrai 5
 network 203.0.113.0/24
 network 2001:db8:1::/48
```

## FRR interop notes (pinned by the smoke)

- FRR binds :179 only once a `router bgp` instance exists; a
  `vtysh -b` pushed before bgpd's zebra view is up silently drops the
  whole router-bgp stanza (retry until the neighbor appears).
- FRR 10.2 defaults to the RFC 8212 eBGP deny-all — interop configs
  need `no bgp ebgp-requires-policy` (z5b's iBGP never hit it).
- FRR records received Cease in `show bgp neighbor`'s Last reset line,
  not in bgpd.log at default log config.

## §Deferred anchors

Collision BGP-ID tiebreak (§6.8) · per-prefix MRAI queues · MRAI
defaults · the typed policy engine (Import/Export seams exist,
accept-all ships) · route-server mode · route next-hop resolution
(v1: single-hop peers only) · v6 listener side · the
`experimental-savnet` BGP-signaling hook (trait seam absent by
mission; anchor: `peer.rs` `on_message`) · graceful-restart ·
ADD-PATH · interface up/down mirror tracking.
