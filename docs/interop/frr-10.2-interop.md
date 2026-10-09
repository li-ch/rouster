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

Known-stubbed, bgpd-tolerated (same session as staticd's findings; as of
the Z5B runs — W2 has since landed the ROUTER_ID_ADD → ROUTER_ID_UPDATE
answer, the initial redistribute dump and REDISTRIBUTE_ROUTE_DEL, see the
Z5C section for the live validation):
ROUTE_NOTIFY_REQUEST and ROUTER_ID_ADD remain recorded-only; no
REDISTRIBUTE_ROUTE_DEL (32) on withdrawal; no GET_LABEL_CHUNK answers
(none requested — no MPLS config); no VRF_ADD replay; no ROUTE_NOTIFY_OWNER.

## ospfd follow-up (Z5C, W1B continuation)

Same container shape with `/usr/lib/frr/ospfd -d -z …`: the pre-registered
loopback-pair topology — each router's `lo` carries a distinct /32
(10.255.1.1, 10.255.2.1) before rousterd starts, `network` statements
enable OSPF on the bridge transit subnet and advertise the loopbacks as
stub networks. ospfd attaches, the two ospfds form a Full area-0
adjacency over the docker bridge, and each side's OSPF-learned route to
the OTHER side's loopback lands in the kernel through rousterd
(`proto ospf`, RTPROT_OSPF 188). ospfd gated on two answers bgpd never
exercised, both fixed as minimal answers in W1B (see the Z5C result).

## Z5C result — PASS (2026-10-09, W1B)

Two real FRR 10.2.2 ospfd instances reach Full adjacency while BOTH use
rousterd as their zebra over ZAPI, and each kernel gains the remote
loopback /32 as an OSPF route programmed by rousterd. Reproduce:
`scripts/test-z5c-ospfd-interop.sh` (two consecutive clean runs).
Evidence archived under `away/2026-10-09/quarantine/z5c/` (rousterd.log,
ospfd.log, mgmtd.log, routes/ospf/env per side).

What passed:

- **Attach, single zclient**: each ospfd opened exactly ONE zapi
  connection (unlike bgpd's three); `session established id=1
  protocol=7` per rousterd, count never grew through the 60 s post-route
  soak. Initial burst (zapi-sniff capture, now the
  `crates/zapi/tests/fixtures/ospfd-10.2.2.log` fixture): HELLO
  (redist_default=7 = the OSPF bit), INTERFACE_ADD request,
  BFD_CLIENT_REGISTER (pid, recorded no-reply, tolerated), ROUTER_ID_ADD
  (AFI_IP), a second INTERFACE_ADD request.
- **Router-id from the ROUTER_ID_UPDATE answer — no config pin**: W2's
  answer got its first live validation; both ospfds show
  `Router ID: 10.255.x.1` (their own loopback /32, derived by rousterd),
  and the adjacency forms with distinct ids. This retires W1's bgpd
  deviation-4 workaround pattern for ospfd (no `ospf router-id` line in
  the configs).
- **Adjacency**: `show ip ospf neighbor` reports `Full/DR` and
  `Full/Backup` on the two sides (DR election over the bridge works;
  OSPF multicast 224.0.0.5 passes between containers on the docker
  default bridge).
- **ROUTE-KERNEL, both directions**: r1 kernel
  `10.255.2.1 via 192.168.215.4 dev eth0 proto ospf metric 10` after
  r1's rousterd logged `zapi: route add prefix=10.255.2.1/32
  entry.protocol=Ospf`; symmetric on r2 for 10.255.1.1/32. ospfd also
  installs its own loopback and the transit stub network `proto ospf`
  (both through rousterd — FRR behavior, kept).

Minimal answers implemented in W1B (both live-required by ospfd,
tolerated-and-unused by staticd/bgpd):

1. **INTERFACE_ADD mirror now carries link flags** — the RIB mirror
   tracks only up/down, so the dump's u64 flags word was 0 and ospfd
   reported `eth0 is down` (`if_is_operative` needs IFF_UP|IFF_RUNNING)
   and, without BROADCAST|MULTICAST, would fall back to the
   non-broadcast network type that never multicasts hellos. The server
   now synthesizes the classic bits per link kind (loopback names get
   IFF_LOOPBACK; down links carry none). Real zebra relays the kernel's
   `ifi_flags`; carrying the real flags through the RIB mirror is future
   polish.
2. **Router-id derivation excludes 127/8** — every Linux `lo` carries
   127.0.0.1, and the derived answer handed exactly that: both ospfds
   came up as `Router ID: 127.0.0.1` and same-id neighbors can never
   become adjacent. zebra's `IPV4_NET127` rule is now mirrored in the
   driver's derivation.

Deviations disclosed (harness-level, same class as Z5B's):

- Two containers on the docker default bridge (W1's proven shape), not
  the one-container probe: same mirror-disjointness rationale.
- `echo 188 ospf >> /etc/iproute2/rt_protos` in both containers: the
  testbed image ships no name for RTPROT_OSPF; the mapping is what a
  real FRR install provides.
- `NO_COLOR=1` in front of rousterd stays as belt-and-braces (W3's
  TTY detection already keeps files ANSI-free).

## Same-window ZAPI-edge follow-ups (2026-10-09, after the Z5B/Z5C runs)

The Z5B/Z5C results above ran against the server as stages W1/W1B left
it. Later stages of the same overnight window changed the edge further;
each item cites the program ledger (`away/2026-10-09/LEDGER.md`):

- **W2 closed the Z5B deferred list, then re-ran the bgpd flow green**
  ("REGRESS incl. bonus z5b" — LEDGER W2): ROUTER_ID_ADD is answered
  with a derived ROUTER_ID_UPDATE; a REDISTRIBUTE_ADD registration gets
  an initial best-route dump (so Z5B's deviation-5 two-phase `vtysh -b`
  can collapse to single-phase); best-route withdrawal now pushes
  REDISTRIBUTE_ROUTE_DEL (32), which the Z5B topology never exercised.
  ROUTE_NOTIFY_REQUEST (126) stays unanswered by design: no
  zebra→client ROUTE_NOTIFY_OWNER (11) wire bytes exist in any capture,
  so 11 is marked NOT-PINNED in the golden doc and the request warns
  loudly (LEDGER W2).
- **BFD_CLIENT_REGISTER (36): recorded, and the no-reply is now
  source-verified, not inferred** — frr 10.2.2 `zebra/zebra_ptm.c`
  writes nothing back in either HAVE_BFDD variant and the sender
  fire-and-forgets; the pinned doc's cmd-36 byte sample was corrected
  to the real fixture bytes (LEDGER M1). Z5C's tolerated-no-reply
  observation matches zebra's exact behavior.
- **Config reload keeps the redistribute channel honest**: SIGHUP
  reloads push REDISTRIBUTE_ROUTE_ADD/DEL for changed bests exactly
  like route commands do, and byte-identical reloads stay silent
  (LEDGER M2) — the soft-reconfiguration an FRR peer observes now
  extends to the reload path.
- **Kernel-side VRF awareness landed ahead of the ZAPI VRF fields**:
  netlink-dp recognizes VRF devices (kind, IFLA_VRF_TABLE, IFLA_MASTER
  enslavement) and mirrors/programs their route tables without leaking
  into table 254 (LEDGER W4); ZAPI interface/route VRF-table fields
  remain a fenced follow-up (W4 report §Deferred 2), and the VRF_ADD
  replay note above is unchanged.
- **Rouster's own savd is now a third ZAPI client**: it couples to the
  RIB through existing message types only (redistribute feed +
  dummy-register marker), monitor-only by default, fed by neighbour
  observations at ARP/NDP granularity (LEDGER W8).
- **All four FRR-facing smokes re-validated in one sequential run**:
  `scripts/run-smokes.sh` ran the full 12-script suite in 301 s — 11/12
  PASS (z4/z5/z5b/z5c all green); the single red is the p0c ECMP
  smoke's own read-side defect — busybox 1.37.0 hides ECMP members
  while the product's multipath route is proven correct via iproute2
  kernel read — not an interop failure (LEDGER M4).
