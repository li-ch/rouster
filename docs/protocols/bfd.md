# BFD (bfdd) — design and status

Status: Phase 2 stream P2-a, delivered 2026-10-10 (commits
`af2e58f` codec → `5d6c7f3` state machine → `51b17d7` transports →
`900a65d` daemon → smoke); W1-b (2026-10-10/11) added the zapi edge
(dynamic sessions, `--zapi`) and the socket2 transmit-hop-limit fix.
RFCs implemented: **5880** (base),
**5881** (IPv4/IPv6 single hop),**5882** (application of BFD — the
shutdown rule and the one-session-per-path model),
**5883** (multihop). Positioning: BIRD-style pure core, FRR
compatibility at the wire (this protocol *is* its own wire — no FRR
surface needed beyond behaving identically on UDP, plus the zapi
daemon protocol W1-b pinned).

## Layer map

| Layer | File | RFC anchors |
|---|---|---|
| Control packet codec | `crates/bfdd/src/packet.rs` | 5880 §4.1, §5, §6.7, §6.8.6 steps 1–6 |
| Session state machine | `crates/bfdd/src/session.rs` | 5880 §6.1, §6.5, §6.6, §6.8.1–§6.8.9, App. A |
| UDP transports + session loop | `crates/bfdd/src/transport.rs` | 5881 §4/§5, 5883 §3, 5880 §6.8.2/§6.8.7 |
| Daemon (config, listeners, status) | `crates/bfdd/src/daemon.rs`, `src/bin/bfdd.rs` | 5882 §2/§8, A21 conventions |
| ZAPI edge (dynamic sessions) | `crates/bfdd/src/zapi.rs` | the W1-b pins (`docs/interop/zapi-10.2-pinned.md`) |
| Interop smoke (peer-to-peer) | `scripts/test-bfd-frr-interop.sh` | both directions vs FRR 10.2.2 bfdd |
| Interop smoke (zapi) | `scripts/test-bfd-zapi.sh` | bgpd → rousterd → dynamic session → bgpd |

The state machine is pure and clock-free (`SessionSm`); the session
loop owns every timer; the daemon owns sockets and the operator
surface. This is the savd shape (thin binary, testable core).

## Design decisions (with RFC citations)

- **Receive procedure split at step 6/7.** `BfdPacket::decode`
  implements §6.8.6 steps 1–6 (version, length, truncation,
  multiplier, reserved M bit, My Discriminator) in the RFC's order;
  `SessionSm::receive` implements steps 7–25. The split is the RFC's
  own: the first half validates the packet in isolation.
- **Init + received-Down stays Init.** The normative §6.8.6
  pseudocode has no Init→Down edge on a received Down (Init waits for
  its own Detection Time); the §6.1 diagram suggests one. We follow
  the pseudocode — the "MUST be followed, in the order specified"
  text — and test the divergence explicitly. FRR takes the same
  reading.
- **Not-Up transmit floor is §6.8.3-exact:** Desired Min Tx is
  floored at 1 s whenever the session is not Up, and the floored
  value is what §6.8.4's detection formula reads (tested).
- **Detection-time math per §6.8.4's four formulas**, including the
  remote-Demand asymmetry (local multiplier, not the remote's) and
  the async form's remote-written multiplier.
- **Jitter per §6.8.7:** [75%, 100%) of the negotiated interval for
  multipliers above 1, [75%, 90%] for exactly 1 — property-tested
  over 10k pseudo-random draws (no proptest in this crate; the
  hand-rolled xorshift loop is the substitute, disclosed).
- **Timer changes take effect on transition (§6.8.2):** every
  transmission — periodic, transition-triggered, Final-carrying,
  timeout-signalling — reschedules the periodic deadline from the
  current state machine math. Missing this produced exactly the bug
  it sounds like: a 1 s-floored deadline surviving the Up transition
  starved FRR's freshly-negotiated 300 ms Detection Time (found in
  the interop smoke, fixed, and now asserted flap-free there).
- **Shutdown holds AdminDown ≥ 1 Detection Time** (RFC 5882 §8)
  before stopping transmission — per-session, awaited.
- **One session per data protocol path** (RFC 5882 §2): the config
  keys peers on (address, multihop); duplicates are rejected.
- **Version:** 1 only (§6.8.6 step 1 discards others). Appendix A's
  v0 compatibility is implemented behind an opt-in per-peer flag
  (`version-negotiation yes`) — switch-to-0 on receiving v0,
  switch-back-to-1 on receiving v1 AdminDown — because it is
  non-normative and FRR 10.2 speaks only v1.
- **Authentication:** Simple Password (§6.7.2) verifies byte-exact.
  The keyed digest types (§6.7.3–§6.7.6) parse and account exactly
  but never verify — MD5/SHA1 primitives would be new dependencies
  (fence), so a session configured for one is refused rather than
  silently not verifying. Received packets with A set that we cannot
  verify are discarded per step 12 semantics.
- **Echo (§5.7/§6.8.9), time-boxed scope:** PDU codec (magic +
  discriminator + sequence — the §6.8.9 "your own content"
  demultiplex key), UDP reflector on 3785 for both AFs with the
  discriminator as the loop guard, session-side transmission/expiry
  arms. FRR-on-Linux reflects v4 echo in its forwarding plane via
  AF_PACKET (raw sockets — out of scope), so v4 echo interop with
  FRR is not expected; v6-shaped UDP reflection and rouster↔rouster
  echo work. RTT measurement is not implemented.

## Socket topology (FRR-compatible)

Shared receive sockets on 3784 (single-hop, RFC 5881 §4) / 4784
(multihop, RFC 5883 §3) per address family; one connected transmit
socket per session with a source port in 49152–65535 (§4) and TTL
255 (§5; also satisfies FRR's multihop minimum-hop threshold).
Demultiplexing: by Your Discriminator once learned, by (peer,
path) while bootstrapping (§6.8.6 steps 7–9; RFC 5883 §3's address
pair). One demux table, shared with the listeners, rewritten on
reload.

## Deviations (fences, disclosed)

1. **Receive-side TTL/hop-limit check not enforced** (5881 §5
   SHOULD): reading the received TTL needs the recvmsg cmsg.
   socket2 (adopted, owner decision A1) can ARM reception
   (`set_recv_hoplimit_v6`) but 0.6.5 hands the control buffer back
   as `&mut [MaybeUninit<u8>]` with no safe initialized-prefix read,
   ships no cmsg parser and no `set_recv_ttl_v4`; libc's setsockopt +
   a hand-rolled cmsghdr cast are both unsafe — the no-unsafe fence
   stands. The SAFE half is landed and unit-tested
   (`transport.rs`: `parse_cmsgs`, `received_hop_limit`); a fence
   lift makes it a wiring change. v4 receive is fail-open; transmit
   TTL 255 is proven by FRR's checker (the interop smoke).
2. **Keyed digest auth unimplemented** (RFC 5880 §6.7.3–§6.7.6):
   parses and accounts exactly but never verifies — MD5/SHA1
   primitives would be new dependencies (fence); a session configured
   for one is refused rather than silently not verifying. Nothing to
   wire at the socket layer: 5880's keyed digests live IN the packet,
   not in socket options.
3. **IPv6 transmit hop limit: CLOSED** (W1-b, M6) — every v6
   transmit socket now carries `IPV6_UNICAST_HOPS` = 255 via socket2
   (std/mio reach IP_TTL only); asserted by read-back.
4. **No static-config growth from zapi sessions:** dynamic
   (client-created) sessions arrive through the zapi edge (below) and
   live outside `bfd.conf`; a config reload does not remove them
   (their lifetime is the registrant's DEREGISTER or the edge's
   disconnect).

## Config (`bfd.conf`-shaped)

```
peer <ip> [multihop]
  local-address <ip>          # default: routed (wildcard)
  transmit-interval <ms>      # default 300 (FRR parity)
  receive-interval <ms>       # default 300
  detect-multiplier <n>       # default 3
  echo <yes|no>               # default no
  echo-interval <ms>          # default 300
  passive <yes|no>            # default no (§6.1)
  demand <yes|no>             # default no (§6.6)
  version-negotiation <yes|no># default no (App. A)
  password <key-id> <secret>  # §6.7.2, 1..16 bytes
```

Line grammar per the savd conventions (blank/`!`/`#` ignored,
line-numbered errors). SIGHUP reload diffs sessions: unchanged peers
never bounce (discriminator stability asserted in tests), changed
peers restart, removed peers get the RFC 5882 §8 hold. A timer-only
change restarts the session (soft in-place update via §6.8.2 poll
sequence is §Deferred).

## Operator surface (A21)

- `/run/rouster/bfdd.status` — refreshed on every session change and
  once per second: one `session` line per peer (state, diagnostic,
  discriminators, detection time, transmit interval) plus the last
  RFC-named transition. `bfdd --show` prints it.
- `/run/rouster/bfdd.pid` — pidfile, removed on clean exits.
- Transitions log at INFO with the §6.8.6/§6.8.8/§6.8.9 cause names
  (e.g. `Up -> Down (Neighbor Signaled Session Down (3), received
  Down while Up (RFC 5880 §6.8.6 step 23))`).

## Interop evidence

`scripts/test-bfd-frr-interop.sh` (run twice, both exit 0,
self-cleaning): FRR 10.2.2 zebra + mgmtd + **real bfdd** in one
container, Rouster bfdd (musl) in another, docker bridge, 100 ms × 3
timers both sides. Machine-checked: both sides reach Up (vtysh
`show bfd peers` `Status: up`; our status file `state Up` with the
remote discriminator learned); the handshake is flap-free (exactly
one Up-entry, zero Up→Down transitions — the §6.8.2 regression
guard); `docker kill` of the Rouster container leaves FRR at
`Status: down / Diagnostics: control detection time expired`
(§6.8.8). Captures under `away/2026-10-11/quarantine/bfd/`.

## The zapi edge (W1-b): dynamic sessions over the pinned daemon protocol

`bfdd --zapi <SOCKET>` (default off) connects to a rousterd (the
savd shape) and speaks the wire-pinned BFD daemon protocol
(`docs/interop/zapi-10.2-pinned.md`, W1-b addendum): the connect
burst is HELLO (redist byte 0x1a) + the empty INTERFACE_ADD + the
4-byte REPLAY that claims the daemon role; forwarded
REGISTER/UPDATE/DEREGISTER (27/29/28) become dynamic sessions
(timers, multihop and source address straight off the wire; an
UPDATE restarts with the new parameters — the reload rule); every
state transition is reported back as the 25-byte REPLAY form (pid +
the 26 tuple: dst at host length, the lib/bfd.h status bitmask,
wildcard src, ifindex 0). Reconnect re-sends the burst, so a
restarted rousterd replays what it remembers.

`scripts/test-bfd-zapi.sh` (exit 0 twice): rousterd + rouster bfdd
--zapi + a REAL FRR bgpd in one container, a real FRR bfdd as the
peer in another — bgpd's `neighbor ... bfd` (multihop +
update-source form, the pinned trigger) registers through rousterd
to the dynamic session, both BFD sides reach Up, bgpd's neighbor
carries live BFD state, and killing the peer container lands the
DOWN report in bgpd through the 26 fan-out.

## §Deferred

- ~~zapi integration~~ — LANDED (W1-b): pins in the 10.2 pinned doc,
  codec arms, rousterd relay + fan-out, `bfdd --zapi`, the
  `test-bfd-zapi.sh` smoke (the section above).
- **Receive-TTL check on v4** (the §5 SHOULD): the safe half is
  landed (`parse_cmsgs`/`received_hop_limit`, unit-tested); landing
  the kernel half needs the no-unsafe fence lifted (socket2 0.6.5
  has no safe cmsg read-back — deviation 1 above).
- **bgpd-emitted single-hop REGISTER frame**: pinned only by source
  + Phase B acceptance (bgpd classifies NHT-unresolved neighbors as
  multihop; the pinned doc's W1-b addendum has the finding).
- **Soft timer update on reload** (announce via §6.8.2 poll sequence
  instead of restarting the session; ~1 h at
  `crates/bfdd/src/daemon.rs` reload).
- **Echo RTT measurement** (timestamps in the EchoPdu's reserved
  space + the status surface; ~40 min).
- **Echo E2E test** (two rouster daemons in separate netns with echo
  enabled; the loopback path is unit-tested but not
  over-the-wire-tested, ~1 h).
