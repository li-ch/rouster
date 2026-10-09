# FRR 10.2.2 interop — direction A (real staticd → rouster zebra → kernel)

Result: **PASS** (2026-10-09, rerun of the overnight-blocked Z5; docker
recovered). A real, unmodified FRR 10.2.2 `staticd` attached to `rousterd`
over ZAPI and installed its configured static routes into the Linux kernel
through Rouster's RIB and netlink dataplane. FRR-zebra was replaced by
rousterd; nothing else changed on the FRR side. This is the direction-A half
of the repo testing bar ("FRR interop both directions"); the reverse
direction (rouster staticd against real zebra) remains future work. The
bgpd variant of this direction (Z5B) passed on 2026-10-09 — see "Z5B
result" below.

Reproduce: `scripts/test-z5-frr-interop.sh` (musl `rousterd` →
`docker cp` into a `frr-testbed:10.2.2` container → real
`/usr/lib/frr/staticd` + `mgmtd` → `vtysh -b` config push → assert both
prefixes in `ip route show proto static`). Two consecutive clean runs.
Evidence archived under `away/2026-10-08/quarantine/z5/` (rousterd.log,
staticd.log, mgmtd.log, routes.txt, env.txt).

## What passed

- **Attach**: staticd connected to `/var/run/frr/zserv.api` (0666), sent
  HELLO (proto byte 4 = static, instance 0, session 0), got the echo, and
  completed its registration burst (INTERFACE_ADD requests, ROUTER_ID_ADD,
  ROUTE_NOTIFY_REQUEST) with zero header- or body-decode errors in
  rousterd's log. The session stayed up for the whole run.
- **Interface state sync**: staticd accepted the mirrored INTERFACE_ADD +
  INTERFACE_ADDRESS_ADD stream for lo/eth0/dummy0 — proven by staticd's own
  next-step behavior: it recognized the gateway 192.0.2.1 as a local
  connected address on dummy0 (`Warning!! Local connected address is
  configured as Gateway IP((192.0.2.1))` in staticd.log) and steered the
  gateway route accordingly. (Before the IFNAMSIZ fix this same sync
  failed — see deviations.)
- **Routes into the kernel through rousterd**: with
  `ip route 203.0.113.0/24 blackhole` and
  `ip route 198.51.100.0/24 192.0.2.1` in frr.conf, the kernel shows:

      198.51.100.0/24 via 192.0.2.1 dev dummy0 proto static
      blackhole 203.0.113.0/24 proto static

  The gateway route is programmed in resolved form
  (`Ipv4If(192.0.2.1, <dummy0 ifindex>)`, table 254) by the P0B
  resolution tracker. Note the blackhole appears as kernel `blackhole`
  (RTN_BLACKHOLE): Rouster's `Nexthop::Blackhole` does not model FRR's
  NULL-vs-REJECT bh_type distinction on the programming side, so FRR's
  `blackhole` (bh_type REJECT on the wire) lands as a blackhole, not a
  prohibit/unreachable route. Cosmetic today; worth modeling if parity
  matters later.

## Message flow observed (rousterd + staticd logs, final run)

1. rousterd resident, config = `zapi socket /var/run/frr/zserv.api`; dummy0
   with 192.0.2.1/24 exists BEFORE startup so the initial mirror carries
   the connected prefix.
2. `zapi: listening` → staticd connect → HELLO → `zapi: session
   established id=1 protocol=4` (~2 s later).
3. staticd registration burst; our INTERFACE_ADD mirror dump answers its
   empty INTERFACE_ADD requests (no decode errors; staticd logs the
   local-gateway warning once its interface DB is populated).
4. `vtysh -b` pushes frr.conf through mgmtd (~2 s after attach): staticd
   immediately sends both ROUTE_ADDs — `zapi: route add
   prefix=203.0.113.0/24` and `prefix=198.51.100.0/24`
   (`entry.protocol=Static`).
5. Driver applies both to the RIB; one reconcile pass programs them:
   `reconcile programmed dataplane installed=2 withdrawn=0`.
6. staticd did NOT send NEXTHOP_REGISTER for 192.0.2.1 in this flow: with
   working interface state it resolved the (local) gateway itself. The
   NHT answer path (immediate NEXTHOP_UPDATE + Z3B event-driven flips)
   was therefore not exercised by this topology; it remains covered by
   the Z3/Z3B/Z4 host-side test suites. A future variant pointing the
   static route at an OFF-subnet gateway would exercise it live.

## Deviations found between the pinned doc and reality

1. **INTERFACE_ADD ifname width is 16 bytes, not 20** (Z5-fix, corrected in
   `docs/interop/zapi-10.2-pinned.md` and the codec): FRR-on-Linux reads
   the system `IFNAMSIZ` (16); the doc's "exactly 20 bytes" was a
   misreading. With a 20-byte field staticd consumed 4 padding bytes as
   the ifindex, registered every interface with ifindex 0, and rejected
   all INTERFACE_ADDRESS_ADDs (`Cannot find IF 1 in VRF 0` x10). It did
   not disconnect or crash — routes still installed once config arrived —
   but interface-dependent behavior was broken. Fixed:
   `ZAPI_IFNAMSIZ = 16` in `crates/zapi/src/message.rs`; all tests stayed
   green (encode/decode share the constant).
2. **The Z5 prompt's launch recipe does not exist in this build** (already
   known to Z1, reconfirmed): `staticd -f` is an unrecognized option, and
   10.2 daemons do not auto-read daemon-specific configs. Config delivery
   that actually works: run `mgmtd` alongside staticd and boot-push
   `/etc/frr/frr.conf` with `vtysh -b`. Without mgmtd, `vtysh -b`
   reports success but applies nothing (per-daemon config-marking comes
   up empty), and `vtysh -d staticd -c 'conf t'` fails outright with
   "mgmtd is not running". mgmtd's commit is asynchronous — the route
   adds trail the `vtysh -b` return by a few seconds.
3. **mgmtd demands NET_RAW + SYS_ADMIN at privs_init** (pinned doc
   operational finding 7 — same class as zebra). The test container runs
   with `--cap-add NET_ADMIN,NET_RAW,SYS_ADMIN` (Z1 oracle-run precedent;
   still a non-privileged container). Starting mgmtd as the `frr` user
   does NOT avoid it. mgmtd itself made no zserv connection in the
   observed runs (its zclient is on-demand), so only staticd's session
   hits the ZAPI server.

## Known-stubbed / not-yet-exercised behaviors

- **Redistribute push**: implemented and tested host-side (Z2B + Z3B),
  but staticd never registers REDISTRIBUTE interest, so no
  REDISTRIBUTE_ROUTE_ADD crossed the wire in this run. bgpd with
  `redistribute static` (Z5B) would exercise it for real.
- **NHT eventing**: see message-flow note 6 — not exercised by this
  topology's local gateway.
- **ROUTE_NOTIFY_REQUEST / ROUTER_ID_ADD**: recorded, no notifications
  pushed (no ROUTE_NOTIFY_OWNER, no ROUTER_ID_UPDATE) — staticd tolerates
  both today; revisit if route-owner status ever matters.
- **VRF_ADD / INTERFACE_LINK_PARAMS replay** (what a fresh oracle-zebra
  sends a new client): not sent; staticd did not miss them here.

## bgpd follow-up (Z5B, pre-registered stretch)

Same container shape, swap staticd for
`/usr/lib/frr/bgpd -d -z /var/run/frr/zserv.api` with mgmtd + `vtysh -b`
pushing an iBGP config: two bgpd instances in one container (`-N other`
pathspace for the second), loopback-based neighbor addresses on dummy
interfaces, assert a BGP-learned route reaches the kernel via rousterd.
Bars (from the Z5 prompt): bgpd attaches, HELLO/NHT/redistribute exchange
captured to quarantine, route in kernel = full success; attach-only =
partial. Watch items grounded in tonight's evidence: bgpd's 3 zclient
connections (main/aux/label-manager — the server already assigns
per-connection owner ids), LABEL_MANAGER_CONNECT must be answered (it is),
and bgpd's synchronous RPCs make an unanswered message a stall, unlike
staticd's fire-and-forget route adds.

## Z5B result — PASS (2026-10-09, W1)

Two real FRR 10.2.2 bgpd instances peer iBGP (AS 65000) while BOTH use
rousterd as their zebra over ZAPI, and a BGP-learned route lands in the
kernel through rousterd — the implementation-plan Phase-1 credibility
milestone. Reproduce: `scripts/test-z5b-bgpd-interop.sh` (two consecutive
clean runs). Evidence archived under `away/2026-10-09/quarantine/z5b/`
(rousterd.log, bgpd.log, mgmtd.log, staticd.log per side + routes/bgp/env).

What passed:

- **Attach, x2 with zero deadlock**: each bgpd opened its full 3-connection
  set (main `redist_default`=10, auxiliary =18, label-manager session=1)
  against its own rousterd; `session established` logged for all, and the
  counts never grew during a 60 s post-route soak — no reconnect, no stall
  (Z1's hazard: bgpd deadlocks against a silent zebra; answered messages
  were sufficient: HELLO echo, LABEL_MANAGER_CONNECT result, NEXTHOP_UPDATE
  on register, INTERFACE_ADD mirror dump).
- **PEER**: `show bgp neighbor` reports `BGP state = Established` on both
  sides over the docker bridge eth0 pair.
- **ROUTE-KERNEL**: bgpd r2 sent `zapi: route add
  prefix=203.0.113.0/24 entry.protocol=Bgp`; its rousterd programmed
  `203.0.113.0/24 via <r1-eth0> dev eth0 proto bgp` (RTPROT_BGP 186).
- **Redistribute channel live for real**: bgpd r1's `redistribute static`
  (REDISTRIBUTE_ADD), then staticd's late ROUTE_ADD for
  198.51.100.0/24 blackhole triggered the Z3B push —
  `pushing REDISTRIBUTE_ROUTE_ADD id=2` — and bgpd ACCEPTED the Z2B
  SPEC-encoded body (first live validation of that encoder), advertised it
  iBGP, and r2's kernel gained the second `proto bgp` prefix. Full circle:
  staticd → rousterd RIB → REDISTRIBUTE push → bgpd → iBGP → bgpd →
  rousterd → kernel.

Deviations disclosed:

1. **Two containers on the docker default bridge instead of one container
   with `-N other`** (pre-registered shape): bgpd refuses a neighbor whose
   address appears in its own zebra-mirrored connected prefixes —
   `% Can not configure the local system as neighbor` (it consults the
   INTERFACE_ADD mirror rousterd serves). In one shared kernel both peers'
   addresses are local to both bgpds, so the iBGP session cannot form; two
   containers restore disjoint mirrors and are the realistic shape. Probed
   along the way: `-z` DOES override `-N` for the zserv path ("‑z option
   overrides ‑N option for zebra named socket path" in the daemon banner),
   and pathspace `other` socket/config dirs work (`/var/run/frr/other/`,
   `/etc/frr/other/`) — the mechanism is fine, the topology was not.
2. **`echo 186 bgp >> /etc/iproute2/rt_protos`** in both containers: the
   testbed image ships no name for RTPROT_BGP; the mapping is what a real
   FRR install provides. Harness-only.
3. **`NO_COLOR=1` in front of rousterd** inside the script (tracing-subscriber
   honors it) so quarantine logs are ANSI-free; the in-daemon logging
   default is untouched (G2/W2 item).
4. **`bgp router-id` pinned in config** on both bgpds: our zebra records
   ROUTER_ID_ADD but never answers with ROUTER_ID_UPDATE, so bgp router-id
   selection is config-pinned to keep the topology independent of that gap
   (bgpd tolerated the missing answer — session, route exchange and EoR all
   fine — the pin is belt-and-braces, and ROUTER_ID_UPDATE is on the W2
   list).
5. **Two-phase `vtysh -b`** on r1: the initial redistribute dump on
   registration is NOT implemented (disclosed Z3 cut), so the static route
   is added by a second push after the REDISTRIBUTE_ADD registration is
   provably in place — deterministic ordering instead of a race.

Known-stubbed, bgpd-tolerated (same session as staticd's findings):
ROUTE_NOTIFY_REQUEST and ROUTER_ID_ADD remain recorded-only; no
REDISTRIBUTE_ROUTE_DEL (32) on withdrawal; no GET_LABEL_CHUNK answers
(none requested — no MPLS config); no VRF_ADD replay; no ROUTE_NOTIFY_OWNER.
