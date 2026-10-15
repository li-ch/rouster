# isisd — the Rouster IS-IS daemon (Phase 5 opener, stream S10-a)

The TLV-native link-state IGP: ISO 10589 (RFC 1142 carries the DP
text — clause numbers cited throughout are that numbering, the
prompt's §7.3.10 pointer included), RFC 1195 (Integrated IS-IS), RFC
5301 (dynamic hostname), RFC 5303 (the p2p three-way handshake), RFC
5305 (wide metrics — TLVs 22/135), with FRR 10.2.2 `isisd` as the
interop oracle (byte-for-byte parity claims below were verified
against its source and on the wire).

## Layout

| module | what |
|--------|------|
| `wire` | the checked Reader/put convention (the ospfd/bgpd house rule) |
| `checksum` | the ISO 8473 Fletcher, span `pdu[12..]`, FRR's `fletcher_checksum(pdu + 12, pdu_len - 12, 12)` arithmetic |
| `system` | SystemId/LspId/NeighborId + the per-field level-bit asymmetry |
| `tlv` | the core TLV set (1, 2, 8, 9, 10, 22, 128/129/130, 132, 135, 137, 240) |
| `pdu` | the common header + LAN IIH/P2P IIH/LSP/CSNP/PSNP codecs |
| `lspdb` | the ordering lattice, aging, purge tombstones, CSNP/PSNP sync, the sequence lollipop |
| `spf` | the per-level Dijkstra, property-tested against Bellman-Ford |
| `adjacency` | the p2p IIH FSM with RFC 5303's table |
| `transport` | Ethernet framing + the Linux AF_PACKET socket |
| `config` | `isisd.conf` grammar (NET, is-type, interface stanzas) |
| `zedge` | the zapi client edge (route type 9 — ISIS, distance 115) |
| `daemon` | the run loop: IIHs, LSPDBs, origination/refresh, sync, SPF → zapi |

## Pinned design decisions

### The codec (M1)

- **Strictness**: discriminator 0x83, versions 1, the family's exact
  length indicator (27/20/27/33/17 — FRR `pdu_size` parity), ID length
  0 (= 6) only, exact PDU length, no trailing bytes. Reserved bits are
  ignored per ISO §9.1 ("transmitted as zero, and ignored on
  receipt"). Zero LSP checksums are rejected — stricter than FRR's
  `iso_csum_verify`, which accepts a zero-zero field (disclosed
  divergence; no healthy originator emits one).
- **TLV tolerances, spec-pinned**: unknown TLV codes are carried
  opaquely (ISO §9.7 "shall be ignored") so flooding is
  byte-preserving; repeatable TLVs stay separate instances
  (RFC 1195 §5.2 "may occur multiple times"); padding is opaque.
- **The narrow IS-reachability entry (TLV 2)** follows the deployed
  11-octet metrics-first form (RFC 5305 §3's description; FRR's
  `pack_item_oldstyle_reach` writes exactly it). The DP-10589
  virtual-flag form never appears on wires.
- **TLV 135's control octet**: up/down (0x80), sub-TLV-present
  (0x40), 6-bit prefix length; minimal prefix octets; the sub-TLV
  length byte only when the presence bit is set (RFC 5305 §4).

### The LSPDB (M2)

- **The ordering lattice** (ISO §7.3.16.3): sequence first; at equal
  sequence a purge (zero lifetime) beats a live copy, the stored
  tombstone beats a received live equal; equal-sequence-different-
  checksum is §7.3.16.2's confusion case → purge one copy and flood.
  Property-tested (antisymmetry + composition, 512 proptest cases;
  transitivity; install convergence under random arrival orders).
- **Aging** is clock-injected (`now` in seconds everywhere); expiry
  produces the §7.3.16.4 synchronized purge (header-only tombstone +
  the flood PDU), and tombstones drop after `ZERO_AGE_LIFETIME`.
- **Sequence numbers** (§7.3.16.1): first LSP numbered 1, next-greater
  reoriginations, rebind on seeing a higher own-LSP sequence;
  exhaustion models the wrap-disable (restart-at-1 after the wait is
  §Deferred — it needs daemon-level timer machinery).
- **CSNP/PSNP sync** (§7.3.15.2): a CSNP's entries split into
  requests (missing or theirs newer → PSNP) and sends (ours newer);
  a PSNP's matching entries are acks, older ones resends. CSNP bodies
  chunk at 15 entries per TLV 9 (16 octets each, 255-byte values).

### SPF (M3)

- Wide preferred, narrow fallback, per-LSP: a TLV-22-bearing LSP is
  read wide (TLV 2 ignored); a TLV-2-only LSP falls back narrow.
  Prefixes under the same rule (135 first, else 128/130).
- Exclusions: purged LSPs; overload blocks transit but not the
  overloaded IS's own prefixes (ISO §9.8's "to another IS through");
  RFC 5305's max-metric links (2^24−1) and prefixes
  (≥ MAX_PATH_METRIC).
- **Attached bit**: an L1 run collects the reachable attached L2 ISs
  as RFC 1195 §3.10.1's default-route candidates (nearest first,
  equal-cost load-split allowed); the daemon installs 0.0.0.0/0
  toward the nearest.
- Property-tested against a brute-force Bellman-Ford oracle on 300
  seeded topologies (the ospfd recipe) + next-hops-are-direct-
  neighbours and route-composition properties.

### Adjacency (M4)

- RFC 5303's three-way state table as a pure function, verified to
  match FRR 10.2.2's `isis_adj_process_threeway` cell-for-cell.
  **Wire values: 0 = Up, 1 = Initializing, 2 = Down** (§3.1 — the
  opposite of a natural reading; FRR's enum agrees).
- Acceptance: own-sysid discard, PDU length vs MTU, the three-way
  neighbor pair match-or-discard (§3.2), RFC 1195 §5.2's OSI-only
  rejection when NLPID 0xCC is absent.
- Area/level (ISO §8.2.4.2): a shared area admits any level mix;
  disjoint areas only L2 ("marked Level 2 Only"); neither-L2 disjoint
  is rejected.
- MTU matching is transmit-side padding (§8.2.3's maxsize−1 with the
  LLC accounted) plus the receive upper bound; FRR enforces no
  lower bound either (disclosed).

### Transport (M5/M6) — the two live-found traps

- **The 0x00FE ethertype is a phantom on Ethernet**: 0x00FE = 254 is
  below the 802.3/DIX threshold of 1536, so a receiver's
  `eth_type_trans` classifies the frame as 802.3 and hands the stack
  `ETH_P_802_2` — ethertype-matched filters (FRR's BPF, an AF_PACKET
  protocol filter) never see it. **IS-IS on Ethernet is the 802.3+LLC
  form** (`length | FE FE 03 | PDU`) — FRR's LAN TX path, including
  its p2p-over-broadcast-interface hellos to All-ISs
  09:00:2b:00:00:05. We emit the LLC form (length ≤ 0x5ff, FRR's
  `isis_ethertype`, 0x8870 above); we accept it, FRR's 0x8870
  variant, and the bare 0x00FE form on RX.
- **The socket is ETH_P_ALL + userspace filtering** (FRR does
  ETH_P_ALL + BPF; we filter purely in `parse_frame` — no BPF, no
  unsafe).
- **The audited safe TX seam**: socket2 0.6.5 has no link-layer
  `SockAddr` (rust-lang/socket2#522), so `send_to` carries a
  `sockaddr_in6` that overlays `sockaddr_ll` field-for-field
  (`sin6_port`↔`sll_protocol`, `sin6_flowinfo`↔`sll_ifindex`,
  `sin6_addr`↔hatype/pkttype/halen/MAC). The kernel's `packet_snd`
  never reads `sll_family` (verified in the v6.6 source, quoted in
  `transport.rs`); the failure mode of a future kernel that starts
  checking is a plain `EINVAL`. No unsafe anywhere — the audited
  exception does NOT extend here, per the S10-a prompt.
- Fences (disclosed): no per-interface bind (`packet_bind` DOES check
  the family), so one socket sees all interfaces — demultiplexed by
  source MAC (one circuit per daemon in v1); self-loopback (both the
  kernel's PACKET_OUTGOING copy and the bridge's multicast
  reflection) dropped by the same MAC rule.

### Daemon (M5)

- One p2p circuit; `is-type level-1-2` runs both levels' databases on
  it (LSP exchange and SPF per level; L1 routes preferred over L2 —
  RFC 1195 §3.10.1).
- Own-LSP origination/refresh (§7.3.14's regeneration window), the
  adjacency in TLV 22, the interface prefix and redistributed
  statics in TLV 135.
- CSNP on adjacency establishment (§7.3.18), PSNP acks on p2p LSP
  receipts, our-copy resend for old instances.
- Route export through the zapi edge (protocol IsIs, distance 115);
  kernel routes land `proto isis` (RTPROT_ISIS = 187 — the netlink-dp
  one-liner, see the S10-a report).

## The interop smoke (M6)

`scripts/test-isis-frr-interop.sh` — our isisd against the real
FRR 10.2.2 isisd over the docker bridge (`isis network point-to-point`
on the FRR side), both zebras = rousterd. Machine checks: ATTACH
(protocol=9 both), ADJACENCY-BOTH (FRR `show isis neighbor` Up +
our `adjacency UP` log), LSDB-BOTH (each LSPDB holds the other's
LSP; our SPF installs FRR-derived routes), REDIST-OUT (198.51.100.0/24
via staticd → our TLV 135 → FRR's kernel `via us`), REDIST-IN
(203.0.113.0/24 via FRR's TLV 135 → our SPF → r2 kernel `proto isis`
via FRR), 30 s SOAK. Green ×2; self-cleaning; quarantine under
`away/2026-10-14/quarantine/isis/`.

FRR-side bring-up notes baked into the script: `router isis <TAG>`
must precede `ip router isis <TAG>` on the interface (northbound
area-tag validation); FRR's per-circuit is-type defaults to L1 while
our area runs L2 (`isis circuit-type level-2` pinned both sides);
FRR's redistribute syntax is `redistribute ipv4 static level-2`;
LSP IDs display as dynamic hostnames (RFC 5301).

## §Deferred (the Day-2 pickup list)

- **L1/L2 ladders beyond one area**: inter-area prefix movement
  (RFC 5302 up/down semantics on re-advertisement), L2→L1 leaking,
  the full RFC 1195 §3.10.2 route-preference ladder (the daemon
  prefers L1 over L2; the finer external-metric ordering is
  unimplemented).
- **Broadcast/LAN circuits**: DIS election, pseudonode LSPs, the LAN
  SPF fan-out (the codec and FSM layers already carry the shapes;
  the spf graph skips pseudonodes and the daemon ignores LAN IIHs).
- **LSP fragmenting** beyond fragment 0 (`ISIS_MIN_LSP_BUF`-driven
  splitting of TLV sets).
- **Authentication**: TLV 10 shapes are modeled; cleartext/HMAC-MD5
  enforcement (RFC 5304), key chains (the ospfd keychain crate
  pattern), and SNP authentication modes are not wired.
- **Prefix suppression**, **BFD for IS-IS adjacencies**, **MT
  routing** (RFC 5120), **overload on-startup / max-metric**
  administrative knobs, **SPF throttling** (the daemon runs SPF on
  change), **LSP refresh jitter**, **ISO 10589 §7.3.15.6 rate
  limiting** beyond the constant.
- **RFC 7987** (minimum remaining lifetime for purges) — purges are
  handled per plain §7.3.16.4.
- **metric-style narrow/transition origination** (the grammar parses
  them; only wide is originated).
- **IPv6** (NLPID 0x8E, TLV 236, multi-topology): the AF-generic
  invariant's IS-IS seam is `tlv.rs`'s v4-specific entries.
- The netlink-dp `IsIs→RTPROT_ISIS` one-liner was this stream's one
  cross-fence edit (disclosed in the report); adjudication may want
  to fold it into netlink-dp's own change discipline.
