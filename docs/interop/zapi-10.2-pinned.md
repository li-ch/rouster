# ZAPI pinned against FRR 10.2.2

Empirical wire capture + binary extraction, 2026-10-08 (Z1). This document
pins the Zebra Protocol (ZAPI) command numbers and observed body formats for
**FRR 10.2.2** (`zebra version 10.2.2`, docker image `frr-testbed:10.2.2`,
linux/arm64). It replaces the "fill in during Phase 1" TODO in
`crates/zapi/src/message.rs` with concrete numbers and becomes the golden
reference for the Z2 codec; captured fixtures live in
`crates/zapi/tests/fixtures/{staticd,bgpd}-10.2.2.log`.

## Header (confirmed on every captured message)

10 bytes, big-endian: `u16 length` (incl. header), `u8 marker=254`,
`u8 version=6`, `u32 vrf_id`, `u16 command`. All 38 captured messages
(staticd + bgpd, incl. reconnects) had marker 254, version 6, vrf_id 0.
This matches `crates/zapi/src/header.rs` — the existing codec is correct.

## How the numbers were pinned (evidence classes)

Three independent methods, all against the same 10.2.2 build:

1. **EMPIRICAL** — captured on the wire by masquerading as zebra
   (`crates/zapi/src/bin/zapi-sniff.rs`, a Unix-socket listener that logs
   every message FRR daemons send to it; fixtures cited inline).
2. **ORACLE** — a real zebra+daemon pair in the container: zebra's own debug
   log names messages it receives (`client 17 says hello...` — the FD, not a
   protocol field), and `vtysh -d zebra -c "show zebra client"` prints
   `Last Sent Cmd: ZEBRA_INTERFACE_LINK_PARAMS` (41) — cross-checks the
   table below.
3. **BINARY** — the number→name table was extracted from the FRR 10.2.2
   build itself: `libfrr.so.0.0.0` contains the `zapi_msg.c` message table
   whose entries hold name-string pointers laid out in enum order in
   `.data.rel.ro` (RELR relocations, in-place addends). Method is offline and
   deterministic; every wire-observed number matches it.

WebFetch of `lib/zapi_msg.h` (tags frr-10.2 / frr-10.2.2 / master via
raw.githubusercontent and jsdelivr) failed (404 through the configured
mirror), and the FRR dev guide's Zebra chapter documents no message bodies
("definitions ... can be found at lib/zclient.h"). Hence the BINARY method;
if source access returns, diff this table against `zapi_msg.h` — expect zero
differences for indices that are not holes.

## Command number table (0–154)

Evidence per entry: **E** = EMPIRICAL (wire-captured tonight, fixture-cited),
**B** = BINARY (extracted from the build's own table), holes marked `reserved
(unknown)`. Wire-confirmed entries carry the observing daemon.

| # | Name | Ev | Notes |
|---|------|----|-------|
| 0 | ZEBRA_INTERFACE_ADD | E | empty body, sent 2–3x per connect by staticd+bgpd = interface-state registration request |
| 1 | ZEBRA_INTERFACE_DELETE | B | |
| 2 | ZEBRA_INTERFACE_ADDRESS_ADD | B | zebra pushed 2 in oracle run |
| 3 | ZEBRA_INTERFACE_ADDRESS_DELETE | B | |
| 4 | ZEBRA_INTERFACE_UP | B | |
| 5 | ZEBRA_INTERFACE_DOWN | B | |
| 6 | ZEBRA_INTERFACE_SET_MASTER | B | |
| 7 | *reserved (hole in build's table)* | B | |
| 8 | ZEBRA_INTERFACE_SET_PROTODOWN | B | |
| 9 | ZEBRA_ROUTE_ADD | E | staticd, carries prefix (below) |
| 10 | ZEBRA_ROUTE_DELETE | E | staticd, on reconnect |
| 11 | ZEBRA_ROUTE_NOTIFY_OWNER | B | |
| 12 | ZEBRA_REDISTRIBUTE_ADD | E | bgpd `redistribute static` |
| 13 | ZEBRA_REDISTRIBUTE_DELETE | B | (`no redistribute static` did NOT emit one before zebra ack — see findings) |
| 14 | ZEBRA_REDISTRIBUTE_DEFAULT_ADD | B | |
| 15 | ZEBRA_REDISTRIBUTE_DEFAULT_DELETE | B | |
| 16 | ZEBRA_ROUTER_ID_ADD | E | staticd+bgpd, body `0001` |
| 17 | ZEBRA_ROUTER_ID_DELETE | B | |
| 18 | ZEBRA_ROUTER_ID_UPDATE | B | zebra→client |
| 19 | ZEBRA_HELLO | E | first message on every connection; staticd+bgpd (3 connections) |
| 20 | ZEBRA_CAPABILITIES | B | zebra→client |
| 21 | ZEBRA_NEXTHOP_REGISTER | E | staticd (192.0.2.1) + bgpd (10.9.9.9) |
| 22 | ZEBRA_NEXTHOP_UNREGISTER | B | |
| 23 | ZEBRA_NEXTHOP_UPDATE | B | zebra→client |
| 24 | ZEBRA_INTERFACE_NBR_ADDRESS_ADD | B | |
| 25 | ZEBRA_INTERFACE_NBR_ADDRESS_DELETE | B | |
| 26 | ZEBRA_INTERFACE_BFD_DEST_UPDATE | B | |
| 27 | ZEBRA_BFD_DEST_REGISTER | B | |
| 28 | ZEBRA_BFD_DEST_DEREGISTER | B | |
| 29 | ZEBRA_BFD_DEST_UPDATE | B | |
| 30 | ZEBRA_BFD_DEST_REPLAY | B | |
| 31 | ZEBRA_REDISTRIBUTE_ROUTE_ADD | B | zebra→client |
| 32 | ZEBRA_REDISTRIBUTE_ROUTE_DEL | B | zebra→client |
| 33 | ZEBRA_VRF_ADD | B | zebra pushed 1 in oracle run |
| 34 | ZEBRA_VRF_DELETE | B | |
| 35 | ZEBRA_VRF_LABEL | B | |
| 36 | ZEBRA_BFD_CLIENT_REGISTER | E | bgpd, body = u32 pid |
| 37 | ZEBRA_BFD_CLIENT_DEREGISTER | B | |
| 38 | ZEBRA_INTERFACE_ENABLE_RADV | B | |
| 39 | ZEBRA_INTERFACE_DISABLE_RADV | B | |
| 40 | ZEBRA_NEXTHOP_LOOKUP_MRIB | B | |
| 41 | ZEBRA_INTERFACE_LINK_PARAMS | E | `Last Sent Cmd` in zebra's `show zebra client` (ORACLE) |
| 42 | ZEBRA_MPLS_LABELS_ADD | B | |
| 43 | ZEBRA_MPLS_LABELS_DELETE | B | |
| 44 | ZEBRA_MPLS_LABELS_REPLACE | B | |
| 45 | ZEBRA_SR_POLICY_SET | B | |
| 46 | ZEBRA_SR_POLICY_DELETE | B | |
| 47 | ZEBRA_SR_POLICY_NOTIFY_STATUS | B | |
| 48 | ZEBRA_IPMR_ROUTE_STATS | B | |
| 49 | ZEBRA_LABEL_MANAGER_CONNECT | E | bgpd 3rd connection, at startup |
| 50 | ZEBRA_LABEL_MANAGER_CONNECT_ASYNC | B | |
| 51 | ZEBRA_GET_LABEL_CHUNK | B | |
| 52 | ZEBRA_RELEASE_LABEL_CHUNK | B | |
| 53 | ZEBRA_FEC_REGISTER | B | |
| 54 | ZEBRA_FEC_UNREGISTER | B | |
| 55 | ZEBRA_FEC_UPDATE | B | |
| 56 | ZEBRA_ADVERTISE_DEFAULT_GW | B | |
| 57 | ZEBRA_ADVERTISE_SVI_MACIP | B | |
| 58 | ZEBRA_ADVERTISE_SUBNET | B | |
| 59 | ZEBRA_ADVERTISE_ALL_VNI | B | |
| 60 | ZEBRA_LOCAL_ES_ADD | B | |
| 61 | ZEBRA_LOCAL_ES_DEL | B | |
| 62 | ZEBRA_REMOTE_ES_VTEP_ADD | B | |
| 63 | ZEBRA_REMOTE_ES_VTEP_DEL | B | |
| 64 | ZEBRA_LOCAL_ES_EVI_ADD | B | |
| 65 | ZEBRA_LOCAL_ES_EVI_DEL | B | |
| 66 | ZEBRA_VNI_ADD | B | |
| 67 | ZEBRA_VNI_DEL | B | |
| 68 | ZEBRA_L3VNI_ADD | B | |
| 69 | ZEBRA_L3VNI_DEL | B | |
| 70 | ZEBRA_REMOTE_VTEP_ADD | B | |
| 71 | ZEBRA_REMOTE_VTEP_DEL | B | |
| 72 | ZEBRA_MACIP_ADD | B | |
| 73 | ZEBRA_MACIP_DEL | B | |
| 74 | ZEBRA_IP_PREFIX_ROUTE_ADD | B | |
| 75 | ZEBRA_IP_PREFIX_ROUTE_DEL | B | |
| 76 | ZEBRA_REMOTE_MACIP_ADD | B | |
| 77 | ZEBRA_REMOTE_MACIP_DEL | B | |
| 78 | ZEBRA_DUPLICATE_ADDR_DETECTION | B | |
| 79 | ZEBRA_PW_ADD | B | |
| 80 | ZEBRA_PW_DELETE | B | |
| 81 | ZEBRA_PW_SET | B | |
| 82 | ZEBRA_PW_UNSET | B | |
| 83 | ZEBRA_PW_STATUS_UPDATE | B | |
| 84 | ZEBRA_RULE_ADD | B | |
| 85 | ZEBRA_RULE_DELETE | B | |
| 86 | ZEBRA_RULE_NOTIFY_OWNER | B | |
| 87 | ZEBRA_TABLE_MANAGER_CONNECT | B | |
| 88 | ZEBRA_GET_TABLE_CHUNK | B | |
| 89 | ZEBRA_RELEASE_TABLE_CHUNK | B | |
| 90 | ZEBRA_IPSET_CREATE | B | |
| 91 | ZEBRA_IPSET_DESTROY | B | |
| 92 | ZEBRA_IPSET_ENTRY_ADD | B | |
| 93 | ZEBRA_IPSET_ENTRY_DELETE | B | |
| 94 | ZEBRA_IPSET_NOTIFY_OWNER | B | |
| 95 | ZEBRA_IPSET_ENTRY_NOTIFY_OWNER | B | |
| 96 | ZEBRA_IPTABLE_ADD | B | |
| 97 | ZEBRA_IPTABLE_DELETE | B | |
| 98 | ZEBRA_IPTABLE_NOTIFY_OWNER | B | |
| 99 | ZEBRA_VXLAN_FLOOD_CONTROL | B | |
| 100 | ZEBRA_VXLAN_SG_ADD | B | |
| 101 | ZEBRA_VXLAN_SG_DEL | B | |
| 102 | ZEBRA_VXLAN_SG_REPLAY | B | |
| 103 | ZEBRA_MLAG_PROCESS_UP | B | |
| 104 | ZEBRA_MLAG_PROCESS_DOWN | B | |
| 105 | ZEBRA_MLAG_CLIENT_REGISTER | B | |
| 106 | ZEBRA_MLAG_CLIENT_UNREGISTER | B | |
| 107 | ZEBRA_MLAG_FORWARD_MSG | B | |
| 108 | ZEBRA_NHG_ADD | B | |
| 109 | ZEBRA_NHG_DEL | B | |
| 110 | ZEBRA_NHG_NOTIFY_OWNER | B | |
| 111 | ZEBRA_EVPN_REMOTE_NH_ADD | B | |
| 112 | ZEBRA_EVPN_REMOTE_NH_DEL | B | |
| 113 | ZEBRA_SRV6_LOCATOR_ADD | B | |
| 114 | ZEBRA_SRV6_LOCATOR_DELETE | B | |
| 115 | ZEBRA_SRV6_MANAGER_GET_LOCATOR_CHUNK | B | |
| 116 | ZEBRA_SRV6_MANAGER_RELEASE_LOCATOR_CHUNK | B | |
| 117 | ZEBRA_SRV6_MANAGER_GET_LOCATOR | B | |
| 118 | ZEBRA_SRV6_MANAGER_GET_SRV6_SID | B | |
| 119 | ZEBRA_SRV6_MANAGER_RELEASE_SRV6_SID | B | |
| 120 | ZEBRA_ERROR | B | |
| 121 | ZEBRA_CLIENT_CAPABILITIES | B | |
| 122 | ZEBRA_OPAQUE_MESSAGE | B | |
| 123 | ZEBRA_OPAQUE_REGISTER | B | |
| 124 | ZEBRA_OPAQUE_UNREGISTER | B | |
| 125 | ZEBRA_NEIGH_DISCOVER | B | |
| 126 | ZEBRA_ROUTE_NOTIFY_REQUEST | E | staticd, body `01` |
| 127 | ZEBRA_CLIENT_CLOSE_NOTIFY | B | |
| 128 | ZEBRA_NEIGH_ADDED | B | |
| 129 | ZEBRA_NEIGH_REMOVED | B | |
| 130 | ZEBRA_NEIGH_GET | B | |
| 131 | ZEBRA_NEIGH_REGISTER | B | |
| 132 | ZEBRA_NEIGH_UNREGISTER | B | |
| 133 | ZEBRA_NEIGH_IP_ADD | B | |
| 134 | ZEBRA_NEIGH_IP_DEL | B | |
| 135 | ZEBRA_CONFIGURE_ARP | B | |
| 136 | ZEBRA_GRE_GET | B | |
| 137 | ZEBRA_GRE_UPDATE | B | |
| 138 | ZEBRA_GRE_SOURCE_SET | B | |
| 139 | ZEBRA_TC_QDISC_INSTALL | B | |
| 140 | ZEBRA_TC_QDISC_UNINSTALL | B | |
| 141 | ZEBRA_TC_CLASS_ADD | B | |
| 142 | ZEBRA_TC_CLASS_DELETE | B | |
| 143 | ZEBRA_TC_FILTER_ADD | B | |
| 144 | ZEBRA_TC_FILTER_DELETE | B | |
| 145 | ZEBRA_OPAQUE_NOTIFY | B | |
| 146 | ZEBRA_SRV6_SID_NOTIFY | B | |
| 147–149 | *reserved (holes in build's table)* | B | |
| 150 | ZEBRA_CLIENT_GR_CAPABILITIES | B | |
| 151 | ZEBRA_CLIENT_ROUTE_UPDATE_COMPLETE | B | |
| 152 | ZEBRA_CLIENT_ROUTE_UPDATE_PENDING | B | |
| 153 | ZEBRA_CLIENT_GR_DISABLE | B | |
| 154 | ZEBRA_CLIENT_RIB_STALE_TIME | B | |

Route-type numbers seen inside bodies (EMPIRICAL): static = 4 (ROUTE_ADD of
staticd, REDISTRIBUTE_ADD of static type, staticd HELLO byte 0), BGP = 10
(bgpd HELLO byte 0, LABEL_MANAGER_CONNECT byte 0). Note this is +1 vs the
classic FRR `ZEBRA_ROUTE_*` numbering (static 3, BGP 9) — Z2 must pin the
full route-type enum the same way before encoding types.

## Observed client→zebra bodies (EMPIRICAL, from fixtures)

Bodies are the bytes between the 10-byte header and `length`. Hex below is
verbatim fixture content.

### ZEBRA_HELLO (19) — 8 bytes, four observed variants

| sender | body | note |
|---|---|---|
| staticd | `04 00000000 000000` | first msg on connect |
| bgpd main zclient | `0a 00000000 000000` | |
| bgpd 2nd zclient | `12 00000000 000000` | |
| bgpd label-mgr zclient | `0a 00000000 000101` | |

Byte 0 matches the daemon's protocol number (static=4, bgp=10) on three of
four (the `12` on bgpd's second client is unexplained — possibly proto+flags
or a client-id). Trailing `0101` on the label-manager connection only.
Exact field semantics (session_id? instance? redist_default?) unresolved —
Z2 must decode against `zclient_send_hello` in lib/zclient.c. Zebra's log
line "client 17 says hello and bids fair to announce only static routes"
confirms the message announces the daemon's route type; the 17 is the
client's file descriptor, not a wire field.

### ZEBRA_INTERFACE_ADD (0) as registration request — empty body

Sent by staticd (2x) and bgpd (1x per zclient) immediately after HELLO;
the empty INTERFACE_ADD is the "I want interface state" registration, zebra
replies with real INTERFACE_ADD messages per interface (not captured —
masquerade never answers).

### ZEBRA_ROUTE_ADD (9) — staticd, blackhole route `203.0.113.0/24` (27-byte body)

```
04 0000 00000041 0000 0003 01 02 18 cb007100 01000000 0006 0001 01
|  |    |        |         |     |  |
|  |    |        |         |     |  prefixlen=0x18 (24)
|  |    |        |         |     +-- prefix follows (2 = ?)
|  |    |        |         +-- afi/safi region: 03 01 02 undecoded
|  |    |        +-- message bitmask / length region: 0000 0003 01 partially undecoded
|  |    +-- flags u32 = 0x00000041 = INTERNAL|STATIC (per zebra.h bit names)
+-- type = 4 (static)
```
Confirmed fields: type byte at offset 0; flags 0x41 at offsets 3–6
(INTERNAL|STATIC — SPEC-assisted read); prefixlen 0x18 at offset 13; prefix
`cb007100` = 203.0.113.0 at offsets 14–17; tail `01000000 0006 0001 01`
contains the blackhole nexthop (undecoded). Route fields between flags and
prefix remain for Z2 to pin against `zapi_route_encode` (lib/zapi_route.c).

### ZEBRA_ROUTE_DELETE (10) — staticd, on reconnect, `198.51.100.0/24` (20-byte body)

`04 0000 00000041 0000 0003 01 02 18 c6336400 0001` — same skeleton:
type=4, flags 0x41, prefixlen 24 at offset 13, prefix `c6336400` =
198.51.100.0 at 14–17. Emitted during the post-reconnect re-registration
(gateway route was in NHT-wait; staticd deletes it before re-adding the
blackhole one).

### ZEBRA_NEXTHOP_REGISTER (21) — 11-byte body, two samples

| sender | body | decoded tail |
|---|---|---|
| staticd (gateway 192.0.2.1) | `00 0000 01 0002 20 c0000201` | plen=32, 192.0.2.1 |
| bgpd (neighbor 10.9.9.9) | `01 0000 01 0002 20 0a090909` | plen=32, 10.9.9.9 |

Layout: byte0 differs (0 staticd / 1 bgpd — likely a flags/connected byte),
`01 0002` region constant (afi/safi?), `20` = prefixlen 32, then the 4-byte
IPv4 address. Exactly one REGISTER per tracked prefix, sent when the prefix
becomes interesting (static route gateway configured / BGP neighbor created).

### ZEBRA_REDISTRIBUTE_ADD (12) — bgpd `redistribute static`, 4-byte body

`01 04 0000` = afi 1 (IPv4) | route type 4 (static) | instance 0. Note:
`no redistribute static` (REDISTRIBUTE_DELETE, 13) did NOT appear in the
capture — bgpd appears to require the ADD to be acked/processed before
issuing the delete, or defers it; unvalidated either way.

### ZEBRA_ROUTER_ID_ADD (16) — 2-byte body `0001`

Sent by staticd and bgpd in the connect burst (u16, value 1).

### ZEBRA_BFD_CLIENT_REGISTER (36) — 4-byte body = u32 pid

bgpd: `000000a2` (=162) and later `00000175` (=373) — both match the bgpd
process pid at capture time. High confidence.

### ZEBRA_LABEL_MANAGER_CONNECT (49) — 3-byte body `0a 0000`

bgpd's third zclient connection at startup: proto 10 (BGP) + u16 0.

### ZEBRA_ROUTE_NOTIFY_REQUEST (126) — 1-byte body `01`

staticd connect burst (wants route-owner status notifications).

## Zebra→client bodies — SPEC-REFERENCE, unvalidated tonight

The masquerade captures only client→zebra traffic. The three the ZAPI server
must emit first are (encoders in lib/zapi_msg.c; layouts not verifiable from
the dev guide, which documents none of them):

- **ZEBRA_INTERFACE_ADD (0)** — `zsend_interface_add`/`zebra_interface_add`
  encoding (ifname, ifindex, status, MAC, MTU, speed... plus per-address
  INTERFACE_ADDRESS_ADD messages). Oracle run shows a fresh client gets
  VRF_ADD x1, Connected x4, Intf Addr x2, then INTERFACE_LINK_PARAMS (41)
  last (`show zebra client` counters) — the reply stream shape is known even
  though bytes weren't captured.
- **ZEBRA_NEXTHOP_UPDATE (23)** — `zsend_nexthop_update` (prefix, vrf id,
  flags, nexthop list with type/gateway/ifindex/metric/weight).
- **ZEBRA_ROUTER_ID_UPDATE (18)** — `zsend_router_id_update` (afi + address).

Z2 should capture these by extending zapi-sniff into a responding proxy
(relay between daemon and real zebra, logging both directions) or by
speaking enough client-side ZAPI to solicit them.

## Operational findings (relevant to the ZAPI server)

1. **Socket permissions**: FRR daemons drop privileges to user `frr`;
   connecting to a Unix socket requires WRITE permission on the socket file.
   A root-owned 755 socket is unreachable — staticd silently retried forever.
   The real server must create the socket frr-owned or 666 (zapi-sniff now
   chmods 666; zebra's own socket is `srwxrwx--- frr:frrvty`).
2. **HELLO echo reply is accepted**: replying to HELLO (19) with the same
   8-byte body echoed back does not disconnect the daemon; staticd and bgpd
   both proceed to their registration burst and stay connected. A minimal
   HELLO responder is sufficient to keep clients attached.
3. **bgpd blocks on synchronous zebra RPCs**: with a non-responding zebra,
   applying `router bgp 65000` via vtysh hangs bgpd's main loop (it never
   completes; label-manager/other round-trips suspected). Incremental
   changes (redistribute toggle, new neighbor) do NOT block. The ZAPI server
   must answer LABEL_MANAGER_CONNECT and friends or bgpd config stalls.
4. **Daemons do not auto-read `/etc/frr/<daemon>.conf`** in this build;
   config reaches them via vtysh/mgmtd push. (`vtysh -d <daemon> -c "conf
   t"` requires mgmtd running in 10.2 for config transactions; `vtysh -b`
   boot-push works without it.)
5. **Reconnect behavior**: both daemons retry the zserv socket (~5–10 s
   backoff) and re-send the full registration burst (HELLO, INTERFACE_ADD
   requests, ROUTER_ID_ADD, ROUTE_NOTIFY_REQUEST; staticd additionally
   re-sends its ROUTE_ADDs; bgpd did not re-send NEXTHOP_REGISTER or
   REDISTRIBUTE_ADD on reconnect in the capture window).
6. **bgpd uses multiple zclient connections** to zebra (observed: 3 — main,
   a second (proto byte 0x12), and a label-manager client), each with its
   own HELLO. A ZAPI server must handle several connections per daemon.
7. **zebra needs CAP_NET_ADMIN, CAP_NET_RAW, CAP_SYS_ADMIN** in containers
   (privs_init fails and exits otherwise) — affects any test harness that
   runs the real zebra.

## Open questions for Z2

- Exact HELLO field semantics (byte 0 = protocol; the `0x12` variant; the
  `0101` tail on the label-manager connection).
- Full route-type enum (observed static=4, bgp=10 — likely +1 vs classic
  numbering; needs the same pinning treatment).
- Undecoded regions of ROUTE_ADD (message bitmask, afi/safi block, nexthop
  list encoding for blackhole and gateway forms).
- The reserved holes 7, 147–149 and REDISTRIBUTE_DELETE conditions.
- All zebra→client bodies (see SPEC-REFERENCE section).
