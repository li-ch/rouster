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

- One circuit per daemon (p2p or broadcast — `network
  point-to-point|broadcast`); `is-type level-1-2` runs both levels'
  databases on it (LSP exchange and SPF per level; the RFC 1195
  §3.10.2 preference ladder orders the results — see the S13-a
  section). S13-a fixed `active_levels()`: it had yielded the slot's
  `is_some()` where callers read a level flag, so an L1L2 daemon ran
  its L2 database twice and never its L1 one (invisible while every
  config and smoke was L2-only).
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

## S13-a — the Day-2 closeout

### Inter-area prefix movement and the §3.10.2 ladder (M1)

- **The ladder** (RFC 1195 §3.10.2, quoted): for one prefix, "routes
  learned via level 1 routing" beat level 2 routes; among
  same-level candidates, "Routes using internal metrics only are
  always preferred to routes using external metrics"; then the
  shortest path (equal-cost load-splitting permitted — v1 installs
  the deterministic first next hop). Implemented as a
  `(level, external, metric)` preference key over both levels' SPF
  results.
- **L2→L1 leaking** behind `redistribute level-2 into level-1`
  (opt-in): the L2 view's prefixes re-advertised into our L1 LSP with
  the up/down bit set — RFC 5302 §2: "L1L2 routers MUST set this bit
  to one for prefixes that are derived from L2 routing and are
  advertised into L1 LSPs". Excluded: prefixes the L1 area already
  reaches (leaking would only shadow local routing), L2 copies that
  already carry the bit (leaked down from a higher domain), and our
  own origins.
- **L1→L2 movement** (the border's area-prefix re-advertisement):
  L1-learned prefixes ride our L2 LSP with the bit clear, honouring
  RFC 5302's loop prevention MUST NOT: "Prefixes with the up/down bit
  set that are learned via L1 routing MUST NOT be advertised by L1L2
  routers back into L2". `Route` carries the bit from both
  advertisement families (TLV 135's control octet; the
  default-metric octet's bit 7 on TLV 128/130, which RFC 5302
  redefined).
- Both inter-area sets re-originate only on change; leaked metrics
  are the source level's total (distance + prefix metric).

### Broadcast/LAN circuits (M2)

- **DIS election** (ISO §8.4.4, verbatim): "A LAN Designated
  Intermediate System is the highest priority Intermediate system in
  a particular set on the LAN, with numerically highest MAC source
  lANAddress breaking ties" — the set being ourselves plus the
  systems with Up adjacencies, with §8.4.4's standing condition that
  an IS "shall not declare itself" DIS "until it has at least one Up
  Intermediate system adjacency on the circuit". Preemptive
  (§7.2.3's resignation on takeover), per level, our LAN ID =
  systemID + nonzero Local Circuit ID.
- **The LAN IIH dance**: acceptance per §8.4.1.2/§8.4.1.3 (disjoint
  areas reject at L1 only; L2 always accepts), the Up condition of
  §8.4.1.5 ("R reports this circuit's lANAddress in its Level n LAN
  IIH PDUs" — the CODE 6 SNPA list), hold expiry per §8.4.1.5.
  CODE 6 lists Up AND Initializing neighbours — FRR 10.2.2's
  `isis_adj_build_neigh_list` parity; listing only Up would deadlock
  the first-heard dance.
- **Pseudonode LSPs** (§7.2.3): the DIS originates one reporting "a
  link to each of the Intermediate systems ... with a zero metric"
  (itself included, §7.3.8's "own systemID with an appended zero
  octet"); resignation purges it at the stored sequence.
- **The LAN SPF fan-out**: graph vertices are full (system,
  pseudonode) ids — a router LSP's pseudonode adjacency entry is an
  edge to the LAN vertex at the circuit metric, and the pseudonode
  LSP fans out at metric zero. Next hops resolve THROUGH the LAN to
  the member itself (frames cross the segment straight to its MAC);
  the per-endpoint LAN costing is ISO's (each side pays only its own
  attachment). The Bellman-Ford oracle and both property tests run
  over random LAN topologies.
- The DIS duty: periodic CSNPs every CompleteSNPInterval (§7.3.15.3,
  10 s), hellos at a third of the interval (§9.5's
  dRISISHelloTimer); broadcast LSP receipts are not PSNP-acked (the
  DIS CSNP carries the ack). Interface knobs: `network broadcast`,
  `priority <0-127>`.

### Authentication (M3)

- **TLV 10 cleartext** (ISO §9.7) and **HMAC-MD5** (RFC 5304): type
  54, a 17-octet TLV value with **no Key ID** (§3.4 rejected one);
  the digest over the PDU with the auth value zeroed and, for LSPs,
  the Checksum and Remaining Lifetime zeroed too (§2) — so
  re-flooding decrements never break it. Engines: MD5 (RFC 1321)
  and HMAC-MD5 (RFC 2104) in pure safe Rust, the ospfd `auth.rs`
  pattern, self-verified against the RFCs' vectors (RFC 1321 A.5,
  RFC 2202).
- **Key chains** (RFC 8177, the ospfd `keychain.rs` shape): send =
  the live key with the most recent start; accept = any key inside
  its accept window — i.e. RFC 5304 §2's multiple-password
  permission, since nothing on the wire names the key.
- **Grammar**: `area-password|domain-password cleartext|hmac-md5
  <secret> [snp-auth off|send-only|validate]` — the per-level
  passwords (§7.3.7/§7.3.9) and the SNP modes (`send-only` is RFC
  5304's transition mode; ISO's default with a password set is
  validate).
- Every origination signs BEFORE its database install (the stored
  and flooded copies must agree, or §7.3.16.2's confusion purge
  would meet our own unsigned checksum); hellos sign after the MTU
  padding (RFC 5304 §2); receive drops unsigned/incorrect PDUs when
  the level's password is configured ("MUST discard"); the purges we
  initiate carry the TLV (the unauthenticated-purge prohibition).
  Elided, disclosed: the per-circuit hello password — p2p IIHs sign
  with the level password of their circuit type.

### Fragments, pacing, lifetimes (M4)

- **Fragmenting** (§7.3.4): the TLV set splits across the LSP number
  space — area addresses only in fragment 0, IS-neighbour entries in
  the lowest fragments ahead of every prefix family, entry-granular
  splitting under the 255-octet TLV value cap, the 256-fragment
  ceiling, emptied higher fragments purged. Per-fragment sequence
  counters (§7.3.16.1: "different values of LSP number are
  independent"); refresh reissues only the stale fragment (§7.3.4h).
  The SPF merges families per §7.2.5 ("If an LSP with LSP number 0
  is not present, or has a zero Remaining Lifetime, fragments n>0
  shall be ignored"); the type block reads from fragment 0.
- **Refresh jitter** (§7.3.5 + §10.1): fragment 0 refreshes at the
  plain window; higher fragments stagger by up to 25%
  (deterministic per LSP id) so a large family does not refresh in
  one burst.
- **Circuit pacing** (§7.3.15.5/§7.3.15.6): the 5 s same-LSP
  transmission interval and the 30-LSPs-per-second circuit cap
  (1000/33); blocked LSPs queue, the pump rescans every tick (the
  §7.3.15.6 floor), and a paced head blocks no fresher LSP.
- **RFC 7987**: a newer received LSP with remaining lifetime below
  MaxAge is stored at MaxAge (the step added to §7.3.15.1.e(1)) —
  the lifetime is covered by neither the checksum nor the HMAC, so
  corruption can only shorten an LSP's life up to the originator's
  own refresh.

### The administrative knobs (M5)

- `set-overload-bit [on-startup <secs>] [suppress-prefixes]` — the
  LSPDBOL (§9.8) rides our LSPs; suppress-prefixes originates no
  prefixes while overloaded (TLV 132 stays).
- `prefix-suppression` (interface) — the connected prefix leaves
  TLV 135; redistributed prefixes stay.
- `spf-throttle <initial-ms> <increment-ms> <max-ms>` — the ospfd
  `SpfScheduler` back-off pattern; `(0, 0, 0)` (default) computes on
  change.
- `metric-style narrow|transition` now originates: narrow emits
  TLV 2 + TLV 128 (the deployed 11/12-octet forms, S-octets 0x80,
  up/down on the default-metric octet, metrics clamped to the
  six-bit space); transition carries both families (RFC 1195's
  transition mode).

### The broadcast interop smoke

`scripts/test-isis-broadcast-interop.sh` — the p2p smoke's LAN leg:
FRR 10.2.2 in default broadcast mode against our `network broadcast`
daemon at priority 100. Machine checks: ATTACH, ADJACENCY-BOTH (the
CODE 6 dance), **DIS-US** (FRR's database holds OUR pseudonode LSP
`rouster-r2.01-00` and no r1 one), LSDB-BOTH, REDIST both
directions through the LAN, 30 s SOAK.

## §Deferred (the remaining list)

- **IPv6** (NLPID 0x8E, TLV 236, multi-topology): the AF-generic
  invariant's IS-IS seam is `tlv.rs`'s v4-specific entries.
- **BFD for IS-IS adjacencies**; **MT routing** (RFC 5120) and its
  TLV 22/135 sub-TLV consumers; **RFC 5310** (SHA-family
  authentication).
- **Key-chain rollover on wall-clock time** (RFC 8177's §2.4 —
  cross-router rollover wants NTP-anchored lifetimes; the model and
  selection rules are in, the config exposes one always-live key).
- **Leaking policy** (route-map-style filtering of what moves
  between levels; v1 leaks all qualifying prefixes).
- **The ES neighbours options** (TLV 3/4?) and OSI-only forwarding —
  the v4-only v1 daemon rejects OSI-only peers.
- Timed rollover + per-circuit transmit passwords beyond the
  level-password elision (ISO §7.3.7's circuitTransmitPassword).
- The netlink-dp `IsIs→RTPROT_ISIS` one-liner was S10-a's one
  cross-fence edit (disclosed in its report); adjudication may want
  to fold it into netlink-dp's own change discipline.
