# ZAPI pinned against FRR 10.2.2

Empirical wire capture + binary extraction, 2026-10-08 (Z1); body layouts
decoded, source-verified and corrected 2026-10-08 (Z2 — see "Z2 codec
findings" below). This document pins the Zebra Protocol (ZAPI) command
numbers and observed body formats for **FRR 10.2.2** (`zebra version
10.2.2`, docker image `frr-testbed:10.2.2`, linux/arm64). It replaces the
"fill in during Phase 1" TODO in `crates/zapi/src/message.rs` with concrete
numbers and becomes the golden reference for the Z2 codec; captured
fixtures live in `crates/zapi/tests/fixtures/{staticd,bgpd}-10.2.2.log`.
Z2 also retrieved the real 10.2.2 sources (`lib/zclient.h`, `lib/zclient.c`,
`zebra/zebra_rnh.c`, `lib/zebra.h`) through an alternate reader after Z1's
mirror 404s — corrections are marked **Z2-fix** inline and listed in the Z2
section.

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

## Command number table (0–146)

Evidence per entry: **E** = EMPIRICAL (wire-captured tonight, fixture-cited),
**B** = BINARY (extracted from the build's own table), **SRC** = verified
against the frr-10.2.2 source (`lib/zclient.h` fetched by Z2), holes marked
`reserved (unknown)`. Wire-confirmed entries carry the observing daemon.

| # | Name | Ev | Notes |
|---|------|----|-------|
| 0 | ZEBRA_INTERFACE_ADD | E | empty body, sent 2–3x per connect by staticd+bgpd = interface-state registration request |
| 1 | ZEBRA_INTERFACE_DELETE | B | |
| 2 | ZEBRA_INTERFACE_ADDRESS_ADD | B | zebra pushed 2 in oracle run |
| 3 | ZEBRA_INTERFACE_ADDRESS_DELETE | B | |
| 4 | ZEBRA_INTERFACE_UP | B | |
| 5 | ZEBRA_INTERFACE_DOWN | B | |
| 6 | ZEBRA_INTERFACE_SET_MASTER | B | |
| 7 | ZEBRA_INTERFACE_SET_ARP | B, SRC | **Z2-fix**: NOT a hole — `zebra_message_types_t` has SET_ARP here (zclient.h); the binary extraction missed it |
| 8 | ZEBRA_INTERFACE_SET_PROTODOWN | B | |
| 9 | ZEBRA_ROUTE_ADD | E | staticd, carries prefix (below) |
| 10 | ZEBRA_ROUTE_DELETE | E | staticd, on reconnect |
| 11 | ZEBRA_ROUTE_NOTIFY_OWNER | B, E | **A5-fix**: body layout PINNED by wire capture (was NOT-PINNED — W2) — see the A5 addendum. Asynchronous: pushed when an owned route's status is decided; zebra sends NO synchronous reply to ROUTE_NOTIFY_REQUEST (126) |
| 12 | ZEBRA_REDISTRIBUTE_ADD | E | bgpd `redistribute static` |
| 13 | ZEBRA_REDISTRIBUTE_DELETE | B | (`no redistribute static` did NOT emit one before zebra ack — see findings) |
| 14 | ZEBRA_REDISTRIBUTE_DEFAULT_ADD | B | |
| 15 | ZEBRA_REDISTRIBUTE_DEFAULT_DELETE | B | |
| 16 | ZEBRA_ROUTER_ID_ADD | E | staticd+bgpd, body `0001` |
| 17 | ZEBRA_ROUTER_ID_DELETE | B | |
| 18 | ZEBRA_ROUTER_ID_UPDATE | B | zebra→client |
| 19 | ZEBRA_HELLO | E | first message on every connection; staticd+bgpd (3 connections) |
| 20 | ZEBRA_CAPABILITIES | B | zebra→client |
| 21 | ZEBRA_NEXTHOP_REGISTER | E | staticd (192.0.2.1) + bgpd (10.9.9.9) + ospfd (0.0.0.0/0, A23) |
| 22 | ZEBRA_NEXTHOP_UNREGISTER | B | never seen: not on ospfd graceful shutdown either (A23) |
| 23 | ZEBRA_NEXTHOP_UPDATE | B | zebra→client |
| 24 | ZEBRA_INTERFACE_NBR_ADDRESS_ADD | B | |
| 25 | ZEBRA_INTERFACE_NBR_ADDRESS_DELETE | B | |
| 26 | ZEBRA_INTERFACE_BFD_DEST_UPDATE | B, **E** | **W1-b-fix**: zebra→client BFD state push, body PINNED by wire capture in three states (DOWN/UP/DOWN) — see the W1-b addendum |
| 27 | ZEBRA_BFD_DEST_REGISTER | B, **E** | **W1-b-fix**: bgpd multihop frame pinned; single-hop pinned by Phase B acceptance |
| 28 | ZEBRA_BFD_DEST_DEREGISTER | B, SRC | **W1-b**: no daemon observed sending one; body source-pinned (same layout); zebra sends no reply |
| 29 | ZEBRA_BFD_DEST_UPDATE | B, **E** | **W1-b-fix**: bgpd re-install frame pinned (byte-identical to its REGISTER body); as zebra→client never observed (26 is the push) |
| 30 | ZEBRA_BFD_DEST_REPLAY | B, **E** | **W1-b-fix**: bfdd sends it at connect, body = pid u32 |
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
| 126 | ZEBRA_ROUTE_NOTIFY_REQUEST | E | staticd, body `01`; zebra sends no reply — the answer is the later ROUTE_NOTIFY_OWNER (11) push (A5) |
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
| 146 | ZEBRA_SRV6_SID_NOTIFY | B | **Z2-fix**: `zebra_message_types_t` ENDS here (147 entries, 0..=146) |
| 147–149 | *not part of the message enum* | SRC | **Z2-fix**: no such commands; the extractor overran the table |
| 150 | ~~ZEBRA_CLIENT_GR_CAPABILITIES~~ | | **Z2-fix**: member of `enum zserv_client_capabilities` (values 1..), NOT a zserv command — misattributed by the binary extraction |
| 151 | ~~ZEBRA_CLIENT_ROUTE_UPDATE_COMPLETE~~ | | same misattribution |
| 152 | ~~ZEBRA_CLIENT_ROUTE_UPDATE_PENDING~~ | | same misattribution |
| 153 | ~~ZEBRA_CLIENT_GR_DISABLE~~ | | same misattribution |
| 154 | ~~ZEBRA_CLIENT_RIB_STALE_TIME~~ | | same misattribution |

Route-type numbers seen inside bodies (EMPIRICAL): static = 4 (ROUTE_ADD of
staticd, REDISTRIBUTE_ADD of static type, staticd HELLO byte 0), BGP = 10
(bgpd HELLO byte 0, LABEL_MANAGER_CONNECT byte 0), connected = 2 (**A19**:
live ospfd `redistribute connected` REDISTRIBUTE_ADD capture, body
`01 02 0000`). **Z2, corrected by A19**: the earlier "+1 shift, SYSTEM=1,
connected=3" inference was wrong — the frr-10.2.2 tag's `lib/route_types.txt`
(expanded by `lib/route_types.pl`, which assigns `#define <name> <index>`
sequentially FROM 0) inserts **ZEBRA_ROUTE_LOCAL=3** between CONNECT and
STATIC; that insertion (not a shift of the whole table) is what lifts
static=4..bgp=10 above the pre-LOCAL values. Final table: system=0,
kernel=1, connected=2, local=3, static=4, rip=5, ripng=6, ospf=7, ospf6=8,
isis=9, bgp=10, pim=11, eigrp=12, nhrp=13, hsls=14, olsr=15, table=16,
ldp=17, vnc=18, vnc-direct=19, vnc-rh=20, bgp-direct=21, bgp-direct-ext=22,
babel=23, sharp=24, pbr=25, bfd=26, openfabric=27, vrrp=28, nhg=29, srte=30,
**table-direct=31** (closing the W2-era "number still unpinned" note).

## Observed client→zebra bodies (EMPIRICAL, from fixtures)

Bodies are the bytes between the 10-byte header and `length`. Hex below is
verbatim fixture content.

### ZEBRA_HELLO (19) — 8 bytes, four observed variants

| sender | body | note |
|---|---|---|
| staticd | `04 00000000 000000` | first msg on connect |
| bgpd main zclient | `0a 00000000 000000` | |
| bgpd 2nd zclient | `12 00000000 000000` | |
| bgpd label-mgr zclient | `0a 00000000 0001 01` | |

**Z2 decoded** (`zclient_send_hello`): `redist_default` u8 | `instance`
u16 | `session_id` u32 | `synchronous` u8. Byte 0 = the client's announced
route type (static=4, BGP=10; the `12` on bgpd's auxiliary client is its
`redist_default` — which proto that is remains open, but the field is
certain). The label-manager client's trailing `0101` = session_id 1 +
synchronous 1 (it runs with `zclient_options_sync`). Zebra's log line
"client 17 says hello and bids fair to announce only static routes"
confirms byte 0 announces the daemon's route type; the 17 is the client's
file descriptor, not a wire field.

### ZEBRA_INTERFACE_ADD (0) as registration request — empty body

Sent by staticd (2x) and bgpd (1x per zclient) immediately after HELLO;
the empty INTERFACE_ADD is the "I want interface state" registration, zebra
replies with real INTERFACE_ADD messages per interface (not captured —
masquerade never answers).

### ZEBRA_ROUTE_ADD (9) — staticd, blackhole route `203.0.113.0/24` (27-byte body)

```
04 0000 00000041 00000003 01 02 18 cb0071 0001 00000000 06 00 01 01
|  |    |        |        |  |  |  |      |    |         |  |  |  |
|  |    |        |        |  |  |  |      |    |         |  |  |  distance=1 (message bit 0x02)
|  |    |        |        |  |  |  |      |    |         |  |  bh_type=1 (REJECT)
|  |    |        |        |  |  |  |      |    |         |  nh flags=0
|  |    |        |        |  |  |  |      |    |         type=6 BLACKHOLE
|  |    |        |        |  |  |  |      |    vrf_id u32=0 (nexthop)
|  |    |        |        |  |  |  |      nexthop count u16=1
|  |    |        |        |  |  |  PSIZE(24)=3 address bytes = 203.0.113
|  |    |        |        |  |  prefixlen 24
|  |    |        |        |  family=2 (AF_INET)
|  |    |        |        safi=1 (SAFI_UNICAST)
|  |    |        message u32 = 0x03 = NEXTHOP|DISTANCE
|  |    flags u32 = 0x41 = ALLOW_RECURSION|RR_USE_DISTANCE (Z2-fix, see below)
+-- type = 4 (static)
```

**Z2 decoded** (`zapi_route_encode`): `type` u8 | `instance` u16 | `flags`
u32 | `message` u32 | `safi` u8 | prefix {family u8, prefixlen u8,
**PSIZE(prefixlen)** address bytes — 3 for a /24, not 4} | then fields
gated by `message` bits, in order: SRCPFX (plen + PSIZE bytes), NHG (u32),
NEXTHOPs (count **u16**, each `vrf_id` u32 + `type` u8 + `flags` u8 +
type-specific + gated extras), BACKUP_NEXTHOPs (count u16), DISTANCE u8,
METRIC u32, TAG u32, MTU u32, TABLEID u32, OPAQUE (len u16 + bytes).
Nexthop types: 1 IFINDEX, 2 IPV4, 3 IPV4_IFINDEX, 4 IPV6, 5 IPV6_IFINDEX,
6 BLACKHOLE (bh_type: 0 NULL, 1 REJECT). The address of a blackhole or
gateway nexthop is always followed by ifindex u32 for types 2-5.
**Z2-fix on flags**: 0x41 is NOT classic "INTERNAL|STATIC" — 10.2.2's
`ZEBRA_FLAG_*` are ALLOW_RECURSION 0x01, SELFROUTE 0x02, IBGP 0x04,
SELECTED 0x08, FIB_OVERRIDE 0x10, EVPN_ROUTE 0x20, RR_USE_DISTANCE 0x40, ...

### ZEBRA_ROUTE_DELETE (10) — staticd, on reconnect, `198.51.100.0/24` (20-byte body)

`04 0000 00000041 00000003 01 02 18 c63364 0000 01` — same skeleton;
**Z2 decoded** tail: nexthop count u16 = 0 (a delete carries no nexthops
but keeps the NEXTHOP message bit) + distance u8 = 1. Emitted during the
post-reconnect re-registration (gateway route was in NHT-wait; staticd
deletes it before re-adding the blackhole one).

### ZEBRA_NEXTHOP_REGISTER (21) — 11-byte body, three samples

| sender | body | decoded |
|---|---|---|
| staticd (gateway 192.0.2.1) | `00 00 0001 0002 20 c0000201` | connected=0, safi=1, 192.0.2.1/32 |
| bgpd (neighbor 10.9.9.9) | `01 00 0001 0002 20 0a090909` | connected=1, safi=1, 10.9.9.9/32 |
| ospfd (A23; `area 0.0.0.1 nssa default-information-originate`) | `00 01 0001 0002 00 00000000` | connected=0, **resolve_via_default=1**, safi=1, 0.0.0.0/0 |

**Z2 decoded** (`zclient_send_rnh`): `connected` u8 | `resolve_via_default`
u8 | `safi` u16 | prefix {family **u16**, prefixlen u8, full 4/16 address
bytes}. Exactly one REGISTER per tracked prefix, sent when the prefix
becomes interesting (static route gateway configured / BGP neighbor
created).

**A23 ospfd trigger** (SRC, frr-10.2.2 tag): the ONLY NHT sender in
ospfd is `ospf_zebra_import_default_route` (`ospfd/ospf_zebra.c`),
called from `ospf_area_nssa_default_originate_set/unset`
(`ospfd/ospfd.c`) when the NSSA default-originate refcount crosses 0/1
— registering the IPv4 default `0.0.0.0/0` with
`resolve_via_default=true` (the "force" argument of the FRR call is
that flag). The answer is consumed by `ospf_zebra_import_check_update`:
`nssa_default_import_check.status = !!nexthop_num`, driving
`ospf_abr_nssa_type7_defaults` (type-7 default origination). Graceful
SIGTERM sends REDISTRIBUTE_DELETE (13) but NOT cmd 22 — pinned on the
wire (z5e phase 1; capture `crates/zapi/tests/fixtures/
ospfd-nht-10.2.2-sniff.log`).

**A23 answer semantics** (SRC, `zebra/zebra_rnh.c`): zebra resolves an
RNH from the **route tables** (`zebra_rnh_resolve_nexthop_entry`,
route_node_match walking up), and the default prefix may answer ONLY a
`ZEBRA_NHT_RESOLVE_VIA_DEFAULT`-flagged registration (or a per-VRF
knob). Rousterd's answer now mirrors the flag-gated part: on-link
first, then longest-prefix over the observed kernel mirror (main
table) for flag-set registrations; flag-unset clients keep the
connected-only answer (an under-approximation of zebra's rib_match,
disclosed — the staticd/bgpd fixtures' behavior is unchanged).

### ZEBRA_REDISTRIBUTE_ADD (12) — bgpd `redistribute static`, 4-byte body

`01 04 0000` = afi 1 (IPv4) | route type 4 (static) | instance 0. Note:
`no redistribute static` (REDISTRIBUTE_DELETE, 13) did NOT appear in the
capture — bgpd appears to require the ADD to be acked/processed before
issuing the delete, or defers it; unvalidated either way.

### ZEBRA_ROUTER_ID_ADD (16) — 2-byte body `0001`

**Z2 decoded** (`zclient_send_router_id_update`): `afi` u16 — value 1 =
AFI_IP. Sent by staticd and bgpd in the connect burst.

### ZEBRA_BFD_CLIENT_REGISTER (36) — 4-byte body = u32 pid

bgpd: `00000175` (=373, bgpd-10.2.2.log:6 and :24 — two connections) and
`00000217` (=535, bgpd-10.2.2.log:37, post-restart); ospfd sends it too
(`00000027` =39, ospfd-10.2.2.log:6). The pid is the sender's `getpid()`
(`bfd_client_sendmsg`, `lib/bfd.c`). **M1-fix**: this section previously
cited a sample `000000a2` (=162) that appears in NO fixture — an unbacked
citation (B10 drift 1), corrected to the fixture bytes above.
**Zebra side SRC-verified (M1)** — `zebra_ptm_bfd_client_register`
(`zebra/zebra_ptm.c`, frr-10.2.2 tag via jsdelivr, fetched like Z2B):
bumps `client->bfd_client_reg_cnt` and forwards the pid to the BFD daemon
(both `HAVE_BFDD` build variants); zebra writes **NO reply on the zapi
socket**, and the sender fire-and-forgets (no synchronous wait). A
conforming server therefore records the registration and stays silent —
implemented in `crates/zapi/src/server.rs` (M1).

### ZEBRA_LABEL_MANAGER_CONNECT (49) — 3-byte body `0a 0000`

bgpd's third zclient connection at startup: proto 10 (BGP) + u16 0.

### ZEBRA_ROUTE_NOTIFY_REQUEST (126) — 1-byte body `01`

staticd connect burst (wants route-owner status notifications). No
synchronous reply exists — the answer is the asynchronous
ROUTE_NOTIFY_OWNER (11) push (A5 addendum).

## Zebra→client bodies — SRC-VERIFIED layouts, still not wire-captured

The masquerade captures only client→zebra traffic, so these layouts come
from the 10.2.2 source read side (`zebra_interface_state_read`,
`zebra_interface_address_read`, `zebra_send_rnh_update`,
`zebra_router_id_update_read` in `lib/zclient.c` / `zebra/zebra_rnh.c`) —
fetched by Z2 — and are implemented + synthetic-round-trip-tested in
`crates/zapi/src/message.rs` (`SPEC` tags). Still worth capturing for real
(Z5) by extending zapi-sniff into a responding proxy:

- **ZEBRA_INTERFACE_ADD/DELETE (0/1)**: ifname exactly **16 bytes on Linux**
  (`IFNAMSIZ`; **Z5-fix** — was documented as 20, a misreading: FRR does not
  widen names on the wire, `zclient.c` reads the system `IFNAMSIZ`, which is
  16 on Linux. A 20-byte field makes the client eat 4 padding bytes as the
  ifindex and reject every INTERFACE_ADDRESS_ADD with "Cannot find IF") |
  ifindex u32 | status u8 | flags u64 | ptm_enable u8 | ptm_status u8 |
  metric u32 | speed u32 | txqlen u32 | mtu u32 | mtu6 u32 | bandwidth u32 |
  link_ifindex u32 | ll_type u32 | hw_addr_len u32 +
  min(len,20) bytes | link_params_status u8 [+ link-params blob]. Note the
  layout diagram inside `zclient.c`'s comment block is STALE — the code
  above is what 10.2.2 parses. Oracle run shows a fresh client gets VRF_ADD
  x1, Connected x4, Intf Addr x2, then INTERFACE_LINK_PARAMS (41) last.
- **ZEBRA_INTERFACE_ADDRESS_ADD/DELETE (2/3)**: ifindex u32 | flags u8 |
  family u8 | address bytes (4/16) | prefixlen u8 (AFTER the address) |
  destination bytes (all-zero = none).
- **ZEBRA_NEXTHOP_UPDATE (23)** (`zebra_send_rnh_update`): message u32 |
  safi u16 | registered prefix {family u16, plen u8, addr} | resolved
  prefix {same} | [srte_color u32 if SRTE bit] | route type u8 | instance
  u16 | distance u8 | metric u32 | nexthop count **u8** | nexthops
  (`zapi_nexthop_encode` shape). Unresolved updates zero the tail fields.
- **ZEBRA_ROUTER_ID_UPDATE (18)**: family u8 | address bytes | prefixlen
  u8 (after the address).
- **ZEBRA_REDISTRIBUTE_ROUTE_ADD/DEL (31/32)** (`zsend_redistribute_route`,
  `zebra/zapi_msg.c` — reached by Z2B where Z2 could not): a plain
  `zapi_route_encode` body — the SAME shape as client→zebra ROUTE_ADD (9).
  Bit policy: safi always 1 (SAFI_UNICAST); DISTANCE, METRIC and MTU
  message bits ALWAYS set (fields present even when zero); TAG bit only
  when tag != 0; NEXTHOP bit + list only when the route has >= 1 ACTIVE
  nexthop (no bit at all for zero — unlike staticd's ROUTE_ADD delete,
  which kept the bit with count 0); SRCPFX iff srcdest. The pushed route
  type is the ORIGINAL route's (static=4 to a client that ran
  `redistribute static`); flags are `re->flags` passed through (e.g.
  SELECTED 0x08 for the best path). Table-direct routes rewrite type to
  ZEBRA_ROUTE_TABLE_DIRECT and instance to the table id (number still
  unpinned — `route_types.h` unreachable).
- **LABEL_MANAGER_CONNECT reply** (client→zebra cmd 49 answered by zebra):
  proto u8 + instance u16 + result u8 — Z3 must answer this or bgpd hangs
  (operational finding 3).

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

## Z2 codec findings (2026-10-08, stage Z2)

The codec lives in `crates/zapi/src/message.rs` (code) and
`crates/zapi/tests/golden.rs` (fixture goldens). Method: Z1's WebFetch
mirror 404s did not reproduce through the alternate web reader — Z2
retrieved the real frr-10.2.2 `lib/zclient.h`, `lib/zclient.c`,
`zebra/zebra_rnh.c` and `lib/zebra.h` (jsdelivr/raw through webReader;
`lib/route_types.h` and `zebra/zapi_msg.c` stayed unreachable). Every
layout below is the source's own encode/decode order, and every fixture
body (all 38 messages) decodes exactly and re-encodes byte-identically.

Corrections to Z1's table (all disclosed, none silent):

1. **Command 7 is ZEBRA_INTERFACE_SET_ARP**, not a hole — the binary
   extraction missed one entry. The enum is `0..=146` (147 members).
2. **150–154 were misattributed**: those names belong to
   `enum zserv_client_capabilities`, not `zebra_message_types_t`. There are
   no zserv commands above 146; the codec maps 147+ to `Unknown`.
3. **ROUTE flags 0x41 ≠ INTERNAL|STATIC**: 10.2.2's `ZEBRA_FLAG_*` are
   ALLOW_RECURSION=0x01 ... RR_USE_DISTANCE=0x40; 0x41 is that pair. The
   Z1 reading applied classic pre-renumbering values.
4. **ROUTE_ADD prefix address bytes are PSIZE(plen)-sized** (3 for a /24) —
   Z1's annotation assumed a full 4-byte word, which made the tail look
   undecodable. With PSIZE the whole 27-byte body parses exactly:
   count u16=1 + nh{vrf 0, BLACKHOLE, flags 0, bh_type 1} + distance 1.

Resolved Z1 open questions: HELLO field semantics (redist_default u8,
instance u16, session_id u32, synchronous u8 — the label-mgr `0101` tail is
session 1 + synchronous 1); route-type numbering (+1 shift confirmed,
SYSTEM=1 base, per `lib/zebra.h`'s include of route_types.h); the ROUTE_ADD
middle region (`message` u32 at [7..11], `safi` u8 at [11]); the nexthop
list encoding; NEXTHOP_REGISTER widths; ROUTER_ID_ADD = afi u16.

Still open (for Z3/Z5):

- Which protocol bgpd's auxiliary zclient announces (`redist_default`
  0x12 = 18 — field certain, value's meaning not).
- `resolve_via_default`/`connected` semantics beyond the observed bits.
- Wire-capturing the zebra→client side (proxy zapi-sniff) to validate the
  SRC-VERIFIED layouts against real bytes.
- REDISTRIBUTE_DELETE emission conditions (Z1 never caught one on the wire).
- `lib/route_types.h` full table (route types other than static/BGP remain
  shift-inferred: kernel 2, connected 3, rip 5, ripng 6, ospf 7, ospf6 8,
  isis 9).

## Z2B addendum (2026-10-08, stage Z2 continuation ladder)

Z2B (encode REDISTRIBUTE_ROUTE_ADD for Z3's redistribute support) retrieved
the previously unreachable `zebra/zapi_msg.c` — frr-10.2.2 tag via
raw.githubusercontent through the alternate web reader (the jsdelivr
package-size refusal and Z1's mirror 404s both bypassed) — and pinned
`zsend_redistribute_route`: command 31 (and 32) carry a plain
`zapi_route_encode` body with the bit policy recorded in the zebra→client
list above. Implemented as `ZapiMessage::RedistributeRouteAdd` +
`ZapiRoute::redistribute_push` in `crates/zapi/src/message.rs` (SPEC:
source-verified, not yet wire-captured — Z5's proxy sniff should confirm;
command 31 decode is now modeled and errors loudly on drift). DEL (32)
shares the exact body shape but stayed outside Z2B's scope (still
`Unknown` passthrough). This is an extension, not a correction: no fixture
contradicted the doc (the fixtures are client→zebra and cannot carry 31).
Z2's open item "wire-capture the zebra→client side" now covers this
layout too.

## M6 addendum (2026-10-09, reconnect redistribute resync)

Operational finding 5 (bgpd's reconnect burst omits REDISTRIBUTE_ADD)
left a stale-client window: the registration dump of 58b0dbe fires only
when cmd 12 arrives, so a reconnecting bgpd that ran `redistribute
static` waits for static routes nobody will resend (B1's deadlock-risk
D2). Whether real-world bgpd re-registers on reconnect is unpinned — the
capture window says no, FRR's `zclient` is built to re-send
registrations (`zclient_send_reg_requests`) — so rousterd now tolerates
both: on the FIRST HELLO of a connection the server reports the client's
identity — `(redist_default, instance, session_id)` straight from the
HELLO body — to the RIB driver, which (a) re-adopts the redistribute
registrations it remembers for that identity and (b) dumps the current
state as a delta: one REDISTRIBUTE_ROUTE_ADD (31) per present best route
of the registered types (the same `zsend_redistribute_route` body and
bit policy as the registration dump — an idempotent refresh, so the ADD
half is not a true delta) plus one REDISTRIBUTE_ROUTE_DEL (32) per route
the identity was last told about that no longer exists. The per-route
DEL semantics mirror zebra's `redistribute_delete` sweep, applied at
reconnect instead of at an explicit REDISTRIBUTE_DELETE (which no capture
has ever shown a daemon send); the DEL body is the row-32 twin of the
ADD. This is an extension past real zebra, which never re-syncs a client
that does not re-register. Disclosed approximations, all in-process only:

- Identity is inferred from HELLO fields; the observed pairs distinguish
  staticd (4,0,0) and bgpd's three connections (10/0/0, 0x12/0/0,
  10/0/1). A hypothetical daemon colliding on the triple would be
  conflated; nothing observed does.
- The delta baseline ("what the identity was last told") advances only
  on pushes that were actually queued; queued ≠ delivered (a client
  dying with a full socket loses the distinction — D4's class). A push
  dropped for a full queue counts as never told, so the next establish
  re-sends it as an ADD.
- Nothing survives a rousterd restart: remembered registrations and the
  baseline are in-memory, so D2's daemon-restart flavor (state lost on
  both sides) is narrowed, not closed — the reconnect-within-process
  flavor is covered.
- NEXTHOP_REGISTER gets no equivalent replay yet (finding 5's other
  half): D2's neighbor-NHT staleness after reconnect is still open.

Implemented in `crates/zapi/src/server.rs` (first-HELLO trigger,
`RibCommand::SessionEstablished`) and `crates/rousterd/src/driver.rs`
(identity-keyed registration memory, adoption, delta dump).

## M4 addendum (2026-10-10): neighbour messages + VRF/table fields, wire-captured

Method: new `crates/zapi/src/bin/zapi-neigh-probe.rs` (client twin of
zapi-sniff, zapi-notify-probe pattern) against a real zebra 10.2.2 in
frr-testbed with a VRF device (`vrf-test`, table 5001) + enslaved
`dummy0` in place before connect; the driving script
(`scripts/test-m4-pin-capture.sh`) mutates neighbours and static routes
during the 25 s window. Raw capture committed at
`crates/zapi/tests/fixtures/m4-capture/neigh-probe.log` (two runs).

### ZEBRA_NEIGH_REGISTER (131) — body source-pinned, acceptance wire-proven

Body is exactly `afi` u16 (cached frr-10.2.2 `lib/zclient.c`
`zclient_register_neigh`); the probe sent `0001` (AFI_IP) and zebra
REGISTERED the interest — neighbour changes then pushed. UNREGISTER
(132) is the mirror image (same body; source).

### ZEBRA_NEIGH_ADDED (128) / ZEBRA_NEIGH_REMOVED (129) — wire-pinned

`zsend_neighbor_notify` bodies, matching `zclient_neigh_ip_encode` byte
for byte (the client-side reader was already in the cached zclient.c):

```
family(in) u8 (2=AF_INET, 10=AF_INET6)
ip.addr          4/16 bytes (family-sized)
family(out) u8   2 when a link-layer exists, 0 (AF_UNSPEC) when not
out.addr         FOUR bytes — the sockunion's v4-sized body carries only
                 the FIRST 4 BYTES of the 6-byte MAC (live frames for
                 lladdr 02:00:00:00:00:99 and ...:aa are byte-IDENTICAL;
                 the MAC is truncated on the wire, a real FRR quirk)
ip_len u32 BE    6 for a MAC entry, 0 without one
ifindex u32 BE
ndm_state u32 BE NUD value (0x80 PERMANENT observed; 0x20 FAILED)
```

Observed frames (192.168.215.99 on eth0, ifindex 2):

- add `lladdr 02:00:00:00:00:99 nud permanent` → cmd 128, 22-byte body
  `02 c0a8d763 02 02000000 00000006 00000002 00000080`.
- replace to `lladdr ...:aa` → cmd 128 AGAIN, byte-identical body (the
  changed MAC bytes 5-6 do not fit the 4-byte field).
- delete → cmd 128 FIRST with the no-link-layer body
  (`02 c0a8d763 00 00000000 00000002 00000020` — the kernel's
  pre-DELNEIGH NEWNEIGH(FAILED), W3's observation, IS forwarded as an
  ADDED-flavour frame with ndm=FAILED), THEN cmd 129 with the SAME
  18-byte body. REMOVED is exactly the encode's `out == NULL` branch:
  family_out 0, ip_len 0, ndm_state = ZEBRA_NEIGH_STATE_FAILED (0x20).
- Neighbour changes on a VRF-SLAVE interface (dummy0 in vrf-test) push
  NOTHING to a vrf-0 registration: the per-client interest is a
  per-(afi, vrf) bitmap (source: `zebra_neigh_register` handler,
  `client->neighinfo[afi]`), so pushes are vrf-scoped.

### INTERFACE_ADD under a VRF — the VRF rides the HEADER, not the body

With vrf-test (ifindex 3, table 5001) + enslaved dummy0 (ifindex 4):

- dummy0's INTERFACE_ADD arrives with **header vrf_id = 3** (the vrf
  device's ifindex in this capture) and body ifindex 4;
  `link_ifindex` stays 0 — enslavement is NOT expressed in the body.
  Its INTERFACE_ADDRESS_ADD frames also carry header vrf_id = 3.
- The VRF device itself dumps as a normal interface (ifname vrf-test,
  ifindex 3, header vrf_id 3, 6-byte hw_addr, mtu 65775) — vrf devices
  are dumped, not filtered.
- eth0 (a veth) shows `link_ifindex = 2425` — that is the veth PEER
  (IFLA_LINK, `eth0@if2425`), NOT a master field; link_ifindex is the
  link peer.
- Each interface's dump is followed by INTERFACE_LINK_PARAMS (41),
  5-byte body `ifindex u32 BE + status u8 0`.

### VRF_ADD (33) at connect — one per VRF

A fresh client receives TWO VRF_ADD frames (76-byte bodies): default
and vrf-test. First body word reads as a LITTLE-ENDIAN u32 equal to the
VRF's table id (254 for default, 5001 for vrf-test — both frames
consistent); the name rides a 16-byte field at offset 40. Raw bytes in
the fixture; the LE-table reading is an interpretation, not a
source-verified field map.

### REDISTRIBUTE_ROUTE_ADD (31) — live frame pins three deltas

The main-table static (`ip route 203.0.113.0/24 blackhole` via vtysh)
pushed to the vrf-0 static-registered probe:

- **No TABLEID field**: message bits are NEXTHOP|DISTANCE|METRIC|MTU
  (0x17) with tableid absent — the TABLEID bit is NOT set for a
  main-table (254) route (Z2B's source-read bit policy, now
  wire-confirmed).
- **The blackhole nexthop carries flags 0x04** (ZEBRA_NEXTHOP_FLAG_
  ACTIVE) — our Z2B SPEC encoder wrote 0; corrected in this change
  (bgpd consumed the flags-0 form live in z5b, so both interoperate,
  but 0x04 is what zebra sends).
- The static route configured with `table 5001` pushed NOTHING to the
  vrf-0 registration (it is a default-vrf-owned static installing into
  table 5001; no redistribute push for it reached the vrf-0 registrant
  within the window) — the TABLEID-carrying push shape for non-main
  tables remains UNPINNED (no client registered in that VRF; the probe
  would need a vrf-3-scoped REDISTRIBUTE_ADD).

## W1-b addendum (2026-10-10/11): the BFD message family, wire-pinned both directions

Method, phase by phase (`scripts/test-bfd-zapi-pin-capture.sh`; evidence
under `away/2026-10-11/weekend/quarantine/bfd-zapi/`, absolute — the S5
lesson):

- **Phase A** (client→zebra side): zapi-sniff masquerades as zebra; a
  REAL bfdd and a REAL bgpd attach via `-z`, configs delivered via each
  daemon's own `-f` file (vtysh `-b` pushes do not stick without mgmtd —
  finding 4; and bgpd config apply additionally blocks on a silent
  LABEL_MANAGER_CONNECT — finding 3, now driven by zapi-sniff's
  `--respond-labelmgr` reply). Capture `phase-a-sniff.log`.
- **Phase B** (zebra→client side): real zebra + mgmtd + real bfdd in one
  container, the rouster bfdd (musl) as the UDP peer in a second; the
  NEW client twin `crates/zapi/src/bin/zapi-bfd-probe.rs` connects to
  the real zserv socket, sends HELLO + BFD_CLIENT_REGISTER (36) + a
  single-hop BFD_DEST_REGISTER (27) for the peer container's address,
  and records every push. Captures `phase-b-probe.log` (up/down cycle)
  and `phase-b-probe-dereg.log` (deregister window).

### ZEBRA_BFD_DEST_REGISTER (27) / BFD_DEST_UPDATE (29) — client→zebra — E

bgpd, multihop neighbor (`neighbor 198.51.100.9 ebgp-multihop 5`,
`update-source <eth0>`, `neighbor ... bfd`), 30-byte body, captured
twice — as 27 at config apply and as the byte-identical body under 29
when the bfd command re-fires on the already-installed session:

```text
body = 00000052 0002 c6336409 0000012c 0000012c 03 01 0002 c0a8d704 ff 00 00 00
       |        |    |         |         |        |  |  |    |        |  |  |  +-- profilelen u8 = 0
       |        |    |         |         |        |  |  |    |        |  |  +-- cbit u8 = 0
       |        |    |         |         |        |  |  |    |        |  +----- ifnamelen u8 = 0 (mhop suppresses)
       |        |    |         |         |        |  |  |    |        +-------- hops u8 = 255 (p->ttl)
       |        |    |         |         |        |  |  |    +-- src = 192.168.215.4 (update-source)
       |        |    |         |         |        |  |  +-- family u16 = 2 (again)
       |        |    |         |         |        |  +-- mhop u8 = 1
       |        |    |         |         |        +-- detection_multiplier u8 = 3
       |        |    |         |         +-- min_tx u32 ms = 300 (BFD_DEF_MIN_TX)
       |        |    |         +-- min_rx u32 ms = 300
       |        |    +-- dst = 198.51.100.9
       |        +-- family u16 = AF_INET
       +-- pid u32 = 0x52 (bgpd's getpid(); zebra keys the fan-out on it)
```

Layout cross-verified against `zclient_bfd_command` (frr-10.2.2
`lib/bfd.c`, HAVE_BFDD>0 variant — every field, in order, big-endian).
The single-hop form differs only in mhop=0, src=0.0.0.0, hops=1, and
ifnamelen>0 + name when the client knows the egress interface — the
encoder branch is source-read; the single-hop frame is pinned by
ACCEPTANCE in Phase B (the probe's 30-byte single-hop register created
a live session), not by a bgpd-emitted capture (see deviations below).
The timers are MILLISECONDS on the wire (300 = 300 ms).

### ZEBRA_BFD_DEST_REPLAY (30) — bfdd→zebra — E

bfdd's connect burst is HELLO + INTERFACE_ADD (empty) + this, 4-byte
body = the daemon's pid as u32 BE (`0000001e`, bfdd was pid 30). Zebra
uses the sender of this command as "the BFD daemon" to forward
registrations to (the M1 server note: registrations replay to it on
client reconnect).

### ZEBRA_INTERFACE_BFD_DEST_UPDATE (26) — zebra→client — E

The push a registered client receives when a destination's state
changes. 21-byte body, captured in THREE states by the Phase B probe
(register → DOWN, session Up → UP, peer container killed → DOWN):

```text
DOWN @register : 00000000 02 c0a8d705 20 00000002 02 00000000 20 00
UP             : 00000002 02 c0a8d705 20 00000001 02 00000000 20 00
DOWN @failure  : 00000002 02 c0a8d705 20 00000002 02 00000000 20 00
                |        |  |         |  |         |  |         |  +-- remote_cbit u8
                |        |  |         |  |         |  |         +-- src.plen u8 = 32
                |        |  |         |  |         |  +-- src = 0.0.0.0 (single-hop wildcard)
                |        |  |         |  |         +-- src.family u8 = AF_INET
                |        |  |         |  +-- status u32 BE: 2 = BFD_STATUS_DOWN, 1 = BFD_STATUS_UP
                |        |  |         +-- dst.plen u8 = 32
                |        |  +-- dst = 192.168.215.5 (the registered destination)
                |        +-- dst.family u8 = AF_INET
                +-- ifindex u32: 0 at register time, 2 (egress eth0) once zebra resolved it
```

Layout cross-verified against `bfd_get_peer_info` (frr-10.2.2
`lib/bfd.c`) — note the prefix families are u8 here (NOT the u16 of the
register) and addresses are full family-length. ZEBRA_BFD_DEST_UPDATE
(29) in the zebra→client direction was never observed — every push was
command 26.

Pinned behaviors:

1. **Registration acceptance is timer-faithful**: the probe's register
   (100 ms × 3) produced an FRR bfdd dynamic session showing exactly
   those timers (`vtysh -d bfdd 'show bfd peers'`: `Peer Type:
   dynamic`, local timers 100/100/3).
2. **Fan-out is per-client, not per-registrant**: every client that
   sent BFD_CLIENT_REGISTER (36) receives updates for ANY destination —
   probe 1 (still connected, registered for .5) received the DOWN push
   for probe 2's freshly-registered 203.0.113.9.
3. **DEREGISTER (28) draws no reply** — the probe's mid-window
   deregister (source-shaped body, byte-same layout as the register)
   produced zero frames back in the 12 s remainder of its window. 28
   stays E-absent: no FRR daemon was observed SENDING one in any
   capture window (the `no neighbor ... bfd` vtysh toggle never emitted
   one — bgpd appears to keep the session armed); the body layout is
   source-pinned (`zclient_bfd_command` sends the identical tail for
   all three commands).

### Trigger conditions for bgpd's REGISTER (live findings)

- bgpd arms BFD at config-apply time ONLY when `_bfd_sess_valid`
  passes: multihop REQUIRES a local address (i.e. `update-source`
  configured or a learned `su_local`); without it bgpd logs
  `_bfd_sess_valid: multi hop but no local address provided` and sends
  nothing.
- Against a masquerade zebra, bgpd classified even an on-link neighbor
  (`neighbor <bridge-gw> bfd`) as multi-hop until NHT resolved — with
  interface dumps (`--respond-iface`) AND NHT answers
  (`--respond-nht`), plus `bgp router-id` set, bgpd still showed
  `BFD: Type: multi hop` for the on-link neighbor in-window; the
  bgpd-emitted single-hop REGISTER frame therefore remains unpinned
  (source-read + Phase B acceptance only — disclosed). bgpd without a
  router-id refuses connections (`bgp_connect: BGP identifier is
  missing`) but this does not block the REGISTER.

## A5 addendum (2026-10-09): ROUTE_NOTIFY_OWNER (11) wire-captured

The W2 gap ("body NOT-PINNED — neither source-read nor wire-captured")
is closed in both directions. Method: `crates/zapi/src/bin/zapi-notify-probe.rs`
(the CLIENT twin of zapi-sniff — connects to a REAL zebra's zserv socket,
sends the staticd-shaped burst HELLO + ROUTE_NOTIFY_REQUEST(126, body `01`)
+ ROUTE_ADD of blackhole 203.0.113.0/24, logs every frame back) against
zebra 10.2.2 in the frr-testbed container. Logs quarantined under
`away/2026-10-09/quarantine/a5/`.

Captured frames (26 bytes total, body 16 each) — both flavors:

```text
INSTALLED : hdr=001afe0600000000000b body=020000000218cb007100000000fe0101
REMOVED   : hdr=001afe0600000000000b body=030000000218cb007100000000fe0101
```

Body layout, cross-checked against `zapi_route_notify_decode`
(`lib/zclient.c`, frr-10.2.2):

| field | size | captured | note |
|-------|------|----------|------|
| note | u32, **little-endian raw C-enum copy** | `02000000` = 2 (INSTALLED), `03000000` = 3 (REMOVED) | `enum zapi_route_notify_owner`: 0 FAIL_INSTALL, 1 BETTER_ADMIN_WON, 2 INSTALLED, 3 REMOVED, 4 REMOVE_FAIL. Zebra `stream_put`s the enum `sizeof()`-sized (4), NOT `stream_putc` |
| family | u8 | `02` | AF_INET (AF_INET6 = 10) |
| prefixlen | u8 | `18` = 24 | |
| address | **full family byte-length** (4/16) | `cb0071 00` | NOT the PSIZE(plen) of ROUTE_ADD — `zapi_route_notify_decode` reads `prefix_blen` |
| tableid | u32 big-endian | `000000fe` = 254 | RT_TABLE_MAIN |
| afi | u8 | `01` | AFI_IP |
| safi | u8 | `01` | SAFI_UNICAST |

Pinned behaviors:

1. **No synchronous reply to 126.** The only frames a fresh client
   receives after the burst are the connect pushes CAPABILITIES (20,
   body `000000000000000100000000`) and VRF_ADD (33, 76-byte body
   naming `default`) — then, 14 ms after the ROUTE_ADD, exactly one
   ROUTE_NOTIFY_OWNER with note=INSTALLED. No HELLO echo either: real
   zebra 10.2.2 does NOT echo HELLO (extension of operational finding 2
   — our echo is accepted by staticd/bgpd, so it stays).
2. **INSTALLED is kernel-true.** `ip route` inside the window shows
   `blackhole 203.0.113.0/24 proto static metric 20`; a mid-session
   ROUTE_DELETE in the exact W1 fixture shape (20 bytes, u16 nexthop
   count 0 + distance) is answered 13 ms later with note=REMOVED and
   the kernel route disappears; zebra's own disconnect line then reads
   "0 static routes removed from the rib".
3. **ROUTE_DELETE shape is load-bearing.** An early probe run sent a
   19-byte delete (nexthop count truncated to u8-width); zebra 10.2.2
   parses that as count=1, tries to read the phantom nexthop's vrf
   u32, logs `stream_getl2: Attempt to get long out of bounds (size:
   29, getp: 29, endp: 29)` and silently skips the message — no
   removal, no notify, connection stays up. Encode deletes with the
   full u16 count.
4. **Server behavior.** Rouster's ZAPI server records the request flag
   (`ZapiSession::route_notify`) and writes no reply — the pinned
   zebra-faithful answer. Pushing the 11 frames needs per-route
   reconcile feedback the driver does not surface to sessions yet
   (disclosed; same deferral class as W2's deferred items). The codec
   (`ZapiMessage::RouteNotifyOwner`) round-trips both captured frames;
   the probe's live decode lines in
   `away/2026-10-09/quarantine/a5/notify-cap4-removed.log` show the
   new codec parsing the real zebra frames as they arrive.
