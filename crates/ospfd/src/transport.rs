//! The raw-socket transport (RFC 2328 §A.1): OSPF runs directly over
//! IP protocol 89, multicasts to AllSPFRouters (224.0.0.5) /
//! AllDRouters (224.0.0.6), and every packet carries TTL 1.
//!
//! socket2 (owner decision A1, adopted 2026-10-11, extended to ospfd
//! per the Day-1 recommendation) supplies the raw socket
//! (`Type::RAW` + `Protocol::from(89)`), the multicast group join
//! (`IP_ADD_MEMBERSHIP` via `join_multicast_v4`), the egress
//! interface selection (`IP_MULTICAST_IF`), and the TTL arms
//! (`IP_MULTICAST_TTL` / unicast `IP_TTL`, both 1 per §A.1).
//!
//! The safe-I/O seam: socket2 0.6.5's receive calls take
//! `&mut [MaybeUninit<u8>]`, whose read-back needs `unsafe` — banned.
//! The datagram syscall family itself is type-agnostic, so the armed
//! socket's fd is `dup`ed into a [`tokio::net::UdpSocket`] (a dup'd
//! fd shares the same kernel socket: every socket2-set option
//! applies). That gives fully safe async `recv_from`/`send_to` with
//! real readiness, the bfdd `spawn_socket_pump` convention without
//! its polling loop.
//!
//! The receive-side TTL check is CLOSED (night N1, 2026-10-12) — and
//! it needed no cmsg at all. The raw-socket semantics differ from the
//! UDP cmsg path bfdd needs: on a raw `SOCK_RAW` socket the kernel
//! delivers the whole IPv4 header with every datagram (raw(7),
//! raw(4)) — the TTL octet at offset 8 is part of the buffer, read
//! pure by [`parse_ipv4`] alongside src/dst/IHL/length. `IP_RECVTTL`
//! (ip(7)) is the *UDP/TCP-socket* mechanism for the same readout;
//! a raw socket never needs it for v4. Enforced: a unicast exchange
//! packet arriving with TTL != 1 is dropped and counted (§A.1
//! mandates TTL 1 on every OSPF send, so a degraded TTL unicast
//! cannot be from an on-link peer); multicast Hellos keep the
//! kernel's rule — no receive check (RFC 2328 places none; §A.1's
//! TTL-1 is a transmit mandate). The OSPFv3 runtime's v6 raw socket
//! needed the cmsg walk (RFC 3542 §6: raw v6 sockets do NOT deliver
//! the IPv6 header) — it has one now, the audited read-back block in
//! the v6 section below (S8-b, 2026-10-14; the AGENTS.md owner-named
//! exception, the bfdd audited-block discipline).
//!
//! One disclosed fence remains, inherited from the bfdd W1-b M6
//! precedent:
//!
//! - **No SO_BINDTODEVICE** — socket2 0.6.5 has no `bind_device`,
//!   so a per-interface socket cannot scope its *reception*; every
//!   raw proto-89 socket in the process receives every OSPF packet.
//!   The daemon demultiplexes by on-link source address (the
//!   zapi-interface-mirror test) and processes each packet exactly
//!   once, on the socket of the interface the source is on.
//!
//! The IP header itself is parsed pure ([`parse_ipv4`]) — Linux and
//! the BSDs both deliver received raw datagrams with the IP header
//! in the buffer (raw(7), raw(4)).

use std::collections::HashMap;
use std::io;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};
use std::os::fd::AsRawFd;

use socket2::{Domain, Protocol, Socket, Type};

use crate::packet::{ALL_D_ROUTERS, ALL_SPF_ROUTERS, IP_PROTO_OSPF};

/// §A.1: all OSPF protocol packets are sent with TTL 1.
pub const OSPF_TTL: u32 = 1;

/// RFC 5340 §A.1: the multicast Hop Limit value (and our unicast
/// parity — see the v6 module note).
pub const OSPF_HOP_LIMIT: u32 = 1;

/// One received datagram after IP-header parsing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Received {
    /// The sender's IP address (§10.5's "source IP address" — the
    /// p2p next-hop address SPF hands out, §16.1.1).
    pub src: Ipv4Addr,
    /// The destination address (224.0.0.5/224.0.0.6 multicast or us).
    pub dst: Ipv4Addr,
    /// The received TTL (the header's octet 8). The raw-socket
    /// readout for the unicast receive-side check: §A.1 mandates
    /// TTL 1 on every OSPF send, so a unicast exchange packet with
    /// a degraded TTL cannot have come from an on-link peer.
    pub ttl: u8,
    /// The OSPF packet bytes (header first), starting at IHL*4.
    pub payload: Vec<u8>,
}

/// Whether `dst` is one of OSPF's two multicast addresses
/// (AllSPFRouters/AllDRouters). Multicast receive keeps the kernel's
/// rule — no TTL check (RFC 2328 places no receive-side rule; §A.1's
/// TTL-1 mandate is on transmit).
pub fn is_multicast_dst(dst: Ipv4Addr) -> bool {
    dst == ALL_SPF_ROUTERS || dst == ALL_D_ROUTERS
}

/// The unicast receive-side TTL policy (night N1): §A.1's single-hop
/// intent pins every OSPF packet's transmit TTL at 1, so a unicast
/// exchange packet (DD/LSR/LSU/LSAck, p2p Hellos) must arrive with
/// TTL 1 — a degraded TTL means the packet was relayed, and it is
/// dropped. (TTL 0 never reaches a socket; the kernel discards it.)
pub fn unicast_ttl_ok(ttl: u8) -> bool {
    ttl == OSPF_TTL as u8
}

/// Parse one IPv4 datagram header: (src, dst, IHL, total length,
/// TTL).
///
/// Total length bounds the payload against receive-buffer padding;
/// a total length beyond the buffer (or a truncated header) is a
/// malformed datagram → `None`. Pure, table-tested.
pub fn parse_ipv4(buf: &[u8]) -> Option<(Ipv4Addr, Ipv4Addr, usize, usize, u8)> {
    if buf.len() < 20 {
        return None;
    }
    let version = buf[0] >> 4;
    if version != 4 {
        return None;
    }
    let ihl = (buf[0] & 0x0f) as usize * 4;
    if ihl < 20 || ihl > buf.len() {
        return None;
    }
    let total_len = u16::from_be_bytes([buf[2], buf[3]]) as usize;
    if total_len < ihl || total_len > buf.len() {
        return None;
    }
    let src = Ipv4Addr::new(buf[12], buf[13], buf[14], buf[15]);
    let dst = Ipv4Addr::new(buf[16], buf[17], buf[18], buf[19]);
    Some((src, dst, ihl, total_len, buf[8]))
}

/// Slice the OSPF payload out of one received raw datagram.
pub fn extract_ospf(buf: &[u8]) -> Option<Received> {
    let (src, dst, ihl, total_len, ttl) = parse_ipv4(buf)?;
    Some(Received {
        src,
        dst,
        ttl,
        payload: buf[ihl..total_len].to_vec(),
    })
}

/// One per-interface OSPF raw socket: sends carry TTL 1
/// (multicast and unicast), multicasts egress via the interface's
/// own address (`IP_MULTICAST_IF`), and 224.0.0.5 is joined at open
/// (224.0.0.6 joins/leaves follow the §9.4 DR/BDR role).
///
/// All OSPF sockets in one process receive every proto-89 datagram
/// (no SO_BINDTODEVICE in socket2 0.6.5 — see the module fence
/// note); the daemon demultiplexes by on-link source.
pub struct OspfRawSocket {
    /// The socket2 handle: the sockopt surface (multicast joins,
    /// TTLs) on the kernel socket both handles share. Mutex so the
    /// §9.4 DR/BDR role changes can join/leave AllDRouters through
    /// the shared handle the run loop holds (`Arc`), without
    /// unsafe or a full-socket lock around the async IO (the join
    /// and leave lock only for the duration of the sockopt call).
    socket: std::sync::Mutex<Socket>,
    /// The dup'd-fd tokio handle for the safe async IO path.
    io: tokio::net::UdpSocket,
    /// The interface's own address: the multicast egress selector
    /// and the group-join interface argument.
    pub ifaddr: Ipv4Addr,
    /// Whether 224.0.0.6 (AllDRouters) is currently joined.
    joined_dr: std::sync::atomic::AtomicBool,
}

impl OspfRawSocket {
    /// Open and arm the socket on `ifaddr`: proto 89, AllSPFRouters
    /// membership, egress interface, TTL 1 on both arms, multicast
    /// loopback off (§A.1's link-local intent; self-originated
    /// packets are dropped by Router ID at dispatch anyway).
    pub fn open(ifaddr: Ipv4Addr) -> io::Result<Self> {
        let socket = Socket::new(
            Domain::IPV4,
            Type::RAW,
            Some(Protocol::from(IP_PROTO_OSPF as std::os::raw::c_int)),
        )?;
        socket.join_multicast_v4(&ALL_SPF_ROUTERS, &ifaddr)?;
        socket.set_multicast_if_v4(&ifaddr)?;
        socket.set_multicast_ttl_v4(OSPF_TTL)?;
        socket.set_multicast_loop_v4(false)?;
        socket.set_ttl_v4(OSPF_TTL)?;
        socket.set_nonblocking(true)?;
        // The safe-I/O seam (module note): dup the armed fd into a
        // tokio UdpSocket — same kernel socket, safe recv/send.
        use std::os::fd::AsFd;
        let dup = socket.as_fd().try_clone_to_owned()?;
        let std_sock = std::net::UdpSocket::from(dup);
        let io = tokio::net::UdpSocket::from_std(std_sock)?;
        Ok(Self {
            socket: std::sync::Mutex::new(socket),
            io,
            ifaddr,
            joined_dr: std::sync::atomic::AtomicBool::new(false),
        })
    }

    /// §9.4/§A.1: join AllDRouters when this interface elects itself
    /// DR or BDR (packets to 224.0.0.6 must be received).
    pub fn join_all_drouters(&self) -> io::Result<()> {
        if !self
            .joined_dr
            .swap(true, std::sync::atomic::Ordering::SeqCst)
        {
            self.socket
                .lock()
                .expect("ospf socket lock")
                .join_multicast_v4(&ALL_D_ROUTERS, &self.ifaddr)?;
        }
        Ok(())
    }

    /// The inverse when the role is lost.
    pub fn leave_all_drouters(&self) -> io::Result<()> {
        if self
            .joined_dr
            .swap(false, std::sync::atomic::Ordering::SeqCst)
        {
            self.socket
                .lock()
                .expect("ospf socket lock")
                .leave_multicast_v4(&ALL_D_ROUTERS, &self.ifaddr)?;
        }
        Ok(())
    }

    /// The async IO handle (readiness + safe send/recv).
    pub fn io(&self) -> &tokio::net::UdpSocket {
        &self.io
    }

    /// Send an OSPF packet to AllSPFRouters (224.0.0.5) — Hellos,
    /// and the broadcast-network floods (§A.1).
    pub async fn send_multicast(&self, packet: &[u8]) -> io::Result<usize> {
        self.io
            .send_to(
                packet,
                SocketAddr::V4(SocketAddrV4::new(ALL_SPF_ROUTERS, 0)),
            )
            .await
    }

    /// Send an OSPF packet to AllDRouters (224.0.0.6) — a DR Other's
    /// broadcast-network flood (§13.3/§A.1).
    pub async fn send_multicast_drouters(&self, packet: &[u8]) -> io::Result<usize> {
        self.io
            .send_to(packet, SocketAddr::V4(SocketAddrV4::new(ALL_D_ROUTERS, 0)))
            .await
    }

    /// Send an OSPF packet unicast to `dst` — the p2p/adjacency
    /// conversation packets (DD, LSR, LSU, direct LSAck; §A.1).
    pub async fn send_unicast(&self, packet: &[u8], dst: Ipv4Addr) -> io::Result<usize> {
        self.io
            .send_to(packet, SocketAddr::V4(SocketAddrV4::new(dst, 0)))
            .await
    }

    /// Receive one raw datagram (IP header included in the buffer on
    /// Linux and the BSDs); `None` on a malformed header.
    pub async fn recv(&self, buf: &mut [u8]) -> io::Result<Option<Received>> {
        let (n, _addr) = self.io.recv_from(buf).await?;
        Ok(extract_ospf(&buf[..n]))
    }
}

// ---------------------------------------------------------------------------
// The OSPFv3 transport (RFC 5340 §A.1) — raw IPv6 proto 89.
//
// What the RFC mandates, pinned exactly (§A.1's encapsulation bullets):
//
// - **Multicast hop limit 1** — "packets sent to these addresses
//   should have their IPv6 Hop Limit set to 1" for AllSPFRouters
//   (ff02::5) and AllDRouters (ff02::6), both link-local scope. This
//   is a *multicast-only* mandate: unlike RFC 2328 §A.1's blanket
//   TTL-1-on-every-packet rule, RFC 5340 places NO hop-limit rule on
//   the unicast conversation/virtual-link packets. We arm
//   `IPV6_MULTICAST_HOPS = 1` (the mandated arm) and
//   `IPV6_UNICAST_HOPS = 1` (the link-local single-hop intent, a
//   local choice consistent with every real v3 stack's observation;
//   disclosed as such).
// - **AllSPFRouters joined always**; **AllDRouters joined only while
//   the interface is DR or BDR** ("Both the Designated Router and
//   Backup Designated Router must be prepared to receive packets
//   destined to this address").
// - **The receive-side hop limit and the true destination are READ
//   BACK now** (S8-b, 2026-10-14 — the audited cmsg block, AGENTS.md's
//   owner-named exception): a raw IPv6 socket does NOT deliver the
//   IPv6 header in the buffer (ipv6(7)/RFC 3542 §6 — the v4 raw
//   trick does not port), so both ride control messages —
//   `IPV6_RECVHOPLIMIT` (socket2's safe setter) and
//   `IPV6_RECVPKTINFO` ([`arm_v6_recv_pktinfo`], the audited
//   `libc::setsockopt` — socket2 0.6.5 has no setter) — read by
//   [`recvmsg_v6_ctl`], the audited recvmsg (the bfdd
//   `recvmsg_ctl` treatment: audit comments, target-pinned cmsg
//   constants, kernel round-trip tests). Enforcement: a UNICAST v3
//   packet (DD/LSR/LSU/LSAck — not ff02::5/6) arriving with a
//   degraded hop limit is dropped and counted, the v6 mirror of the
//   v2 N1 rule — keyed on our own documented unicast hops-1 parity
//   (RFC 5340 §A.1 mandates the multicast arm only; v3 virtual
//   links, the legitimate multi-hop unicast, are §Deferred). The
//   `None` cmsg path is fail-open, disclosed (bfdd's rule).
// - **The pseudo-header destination is the REAL address now**: the
//   v3 checksum covers the real (src, dst), and the dst comes from
//   the `IPV6_PKTINFO` cmsg (the first 16 bytes of the
//   `in6_pktinfo`). [`decode_v3_dst`]'s candidate trial remains as
//   the FALLBACK for the no-cmsg path (§4.2's destination list is
//   still the spec's own enumeration of what the address can be).
//
// The v6 socket is BOUND to the interface's link-local address (the
// RFC's source-address rule, §2.5: "OSPF packets are sent using the
// interface's associated link-local unicast address as the source
// address") — binding both pins our source and scopes reception to
// the link (the closest safe substitute for the v2 SO_BINDTODEVICE
// fence, which stands here too: socket2 0.6.5 has no bind_device).

/// RFC 5340 §A.1: AllSPFRouters — "Hello packets are always sent to
/// this destination", plus certain flooding packets.
pub const ALL_SPF_ROUTERS_V6: Ipv6Addr = Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 5);
/// RFC 5340 §A.1: AllDRouters — flooding packets the DR/BDR receive.
pub const ALL_D_ROUTERS_V6: Ipv6Addr = Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 6);

/// Whether `dst` is one of OSPFv3's two link-local multicast
/// destinations (the receive-side class distinction: an ff02::5/6
/// packet is the multicast arm of §A.1, anything else is a unicast
/// exchange).
pub fn is_multicast_dst_v6(dst: Ipv6Addr) -> bool {
    dst == ALL_SPF_ROUTERS_V6 || dst == ALL_D_ROUTERS_V6
}

/// One received v6 datagram. The IPv6 header is NOT in the buffer
/// (raw v6 sockets deliver payload only) and the hop limit / true
/// destination are not readable without the cmsg walk — the two
/// §Deferred read-backs above. The source comes from recv_from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReceivedV6 {
    pub src: Ipv6Addr,
    pub payload: Vec<u8>,
}

/// Resolve an interface name to its kernel ifindex by parsing
/// `/proc/net/if_inet6` (Linux — the platform the daemon targets; on
/// other hosts this returns an error and callers fall back to a
/// supplied index). Pure std, no libc `if_nametoindex` (that call is
/// FFI — the unsafe fence).
pub fn ifindex_of(name: &str) -> io::Result<u32> {
    let text = std::fs::read_to_string("/proc/net/if_inet6")?;
    parse_if_inet6(&text)
        .remove(name)
        .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, format!("no ifindex for {name}")))
}

/// Parse `/proc/net/if_inet6` lines
/// (`<addr> <ifindex-hex> <plen> <scope> <flags> <name>`) into a
/// name → ifindex map. Malformed lines are skipped (the file's shape
/// is a kernel ABI, but a defensive parse costs nothing).
pub fn parse_if_inet6(text: &str) -> HashMap<String, u32> {
    let mut map = HashMap::new();
    for line in text.lines() {
        let mut fields = line.split_whitespace();
        let Some(_addr) = fields.next() else { continue };
        let Some(index) = fields.next().and_then(|f| u32::from_str_radix(f, 16).ok()) else {
            continue;
        };
        // plen, scope, flags — skipped.
        let _plen = fields.next();
        let _scope = fields.next();
        let _flags = fields.next();
        if let Some(name) = fields.next() {
            map.insert(name.to_string(), index);
        }
    }
    map
}

/// Try decoding an OSPFv3 packet against the interface's candidate
/// destination set (§4.2's list, the share our socket can know: the
/// two multicast groups and our own link-local) and return the packet
/// plus the destination that verified. `None` when no candidate
/// verifies (wrong interface / corrupted / not for us).
pub fn decode_v3_dst(
    buf: &[u8],
    src: Ipv6Addr,
    own_link_local: Ipv6Addr,
) -> Option<(crate::packet_v3::PacketV3, Ipv6Addr)> {
    for dst in [ALL_SPF_ROUTERS_V6, ALL_D_ROUTERS_V6, own_link_local] {
        if let Ok(packet) = crate::packet_v3::PacketV3::decode(buf, src, dst) {
            return Some((packet, dst));
        }
    }
    None
}

// ---------------------------------------------------------------------------
// The audited v6 cmsg read-back (S8-b, 2026-10-14). AGENTS.md's
// no-unsafe invariant carries a NAMED exception for exactly this
// block (owner decisions 2026-10-12 and 2026-10-14): the receive-side
// hop-limit + destination read-back on the OSPFv3 raw socket — the
// bfdd `arm_v4_recv_ttl`/`recvmsg_ctl` treatment, same pattern, same
// audit discipline: the two unsafe lines below each carry their audit
// comment, the kernel cmsg layouts are target-pinned empirically (the
// kernel round-trip tests), and the parsers themselves are pure safe
// byte-walks. Everything else in this crate stays unsafe-free.
// ---------------------------------------------------------------------------

/// cmsg constants for the v6 walk: `IPPROTO_IPV6` (41) as the level,
/// and the cmsg KINDS the target's kernel actually delivers.
/// Hop limit: RFC 3542's type is 51; Linux delivers 52 (the modern
/// `IPV6_HOPLIMIT`; 51 is the 2292-era constant), macOS/BSD deliver
/// 47 — all pinned empirically (the bfdd UDP round-trips first, the
/// raw-socket round-trip below re-pins the same values on proto 89).
const IPPROTO_IPV6_CMSG: u32 = 41;
#[cfg(any(target_os = "linux", target_os = "android"))]
const IPV6_HOPLIMIT_CMSG_KINDS: [u32; 2] = [51, 52];
#[cfg(not(any(target_os = "linux", target_os = "android")))]
const IPV6_HOPLIMIT_CMSG_KINDS: [u32; 2] = [51, 47];
/// Destination: the `in6_pktinfo` cmsg — RFC 3542's type is
/// `IPV6_PKTINFO`; Linux delivers 50, macOS/BSD 46 (pinned by the
/// same round-trip tests). The payload is the `struct in6_pktinfo`:
/// the 16-byte destination address followed by a native-order u32
/// ifindex.
#[cfg(any(target_os = "linux", target_os = "android"))]
const IPV6_PKTINFO_CMSG_KINDS: [u32; 2] = [50, 2]; // 2 = IPV6_2292PKTINFO
#[cfg(not(any(target_os = "linux", target_os = "android")))]
const IPV6_PKTINFO_CMSG_KINDS: [u32; 1] = [46];

/// One parsed control message: level, type, and the data bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RawCmsg<'a> {
    pub level: u32,
    pub kind: u32,
    pub data: &'a [u8],
}

/// Walks a recvmsg control buffer, safely: the `cmsghdr` fields are
/// read bytewise (`from_ne_bytes` — no pointer casts, no unsafe).
/// Layout on the unix targets (the bfdd walker's pinned shapes, host
/// cfg'd): `cmsg_len` — `size_t` (8 bytes) on Linux, `socklen_t`
/// (4 bytes) on macOS/the BSDs — then `cmsg_level` and `cmsg_type`
/// u32 (4+4), then the data; the next header starts at `cmsg_len`
/// rounded up to the `cmsg_len` alignment. Malformed tails stop the
/// walk.
pub fn parse_cmsgs(mut ctrl: &[u8]) -> Vec<RawCmsg<'_>> {
    let mut out = Vec::new();
    #[cfg(any(target_os = "linux", target_os = "android"))]
    const LEN_SIZE: usize = std::mem::size_of::<usize>(); // size_t, 8
    #[cfg(not(any(target_os = "linux", target_os = "android")))]
    const LEN_SIZE: usize = 4; // socklen_t is u32 on macOS/BSD
    const ALIGN: usize = LEN_SIZE;
    loop {
        if ctrl.len() < LEN_SIZE + 4 + 4 {
            break;
        }
        let mut len_buf = [0u8; 8];
        len_buf[..LEN_SIZE].copy_from_slice(&ctrl[..LEN_SIZE]);
        let cmsg_len = usize::from_ne_bytes(len_buf);
        let level_at = LEN_SIZE;
        let kind_at = LEN_SIZE + 4;
        if cmsg_len < LEN_SIZE + 8 || cmsg_len > ctrl.len() {
            break; // malformed tail: stop walking
        }
        let level = u32::from_ne_bytes(ctrl[level_at..level_at + 4].try_into().expect("4 bytes"));
        let kind = u32::from_ne_bytes(ctrl[kind_at..kind_at + 4].try_into().expect("4 bytes"));
        out.push(RawCmsg {
            level,
            kind,
            data: &ctrl[LEN_SIZE + 8..cmsg_len],
        });
        let step = cmsg_len.div_ceil(ALIGN) * ALIGN;
        if step >= ctrl.len() {
            break;
        }
        ctrl = &ctrl[step..];
    }
    out
}

/// Extracts the received IPv6 hop limit from a control buffer — a
/// native-order u32 (both targets; pinned empirically). `None` when
/// the buffer carries no hop-limit cmsg (the unarmed path).
pub fn received_hop_limit_v6(ctrl: &[u8]) -> Option<u32> {
    parse_cmsgs(ctrl)
        .into_iter()
        .find(|c| c.level == IPPROTO_IPV6_CMSG && IPV6_HOPLIMIT_CMSG_KINDS.contains(&c.kind))
        .and_then(|c| {
            let raw: [u8; 4] = c.data.try_into().ok()?;
            Some(u32::from_ne_bytes(raw))
        })
}

/// Extracts the received IPv6 destination address from a control
/// buffer — the first 16 bytes of the `in6_pktinfo`. `None` when the
/// buffer carries no pktinfo cmsg.
pub fn received_dst_v6(ctrl: &[u8]) -> Option<Ipv6Addr> {
    parse_cmsgs(ctrl)
        .into_iter()
        .find(|c| c.level == IPPROTO_IPV6_CMSG && IPV6_PKTINFO_CMSG_KINDS.contains(&c.kind))
        .and_then(|c| {
            let addr: [u8; 16] = c.data.get(..16)?.try_into().ok()?;
            Some(Ipv6Addr::from(addr))
        })
}

/// The unicast receive-side hop-limit policy — the v6 mirror of
/// [`unicast_ttl_ok`]: our own unicast arm carries hop 1 (the
/// documented local parity; RFC 5340 §A.1 mandates the multicast arm
/// only), so a unicast exchange packet with a degraded hop limit
/// cannot have come from an on-link peer. `None` (no cmsg — the
/// unarmed path) is fail-open, disclosed. v3 virtual links are
/// §Deferred; they legitimately cross hops and will need this
/// relaxed.
pub fn unicast_hop_limit_ok(hop_limit: u32) -> bool {
    hop_limit == OSPF_HOP_LIMIT
}

/// Control-buffer size for the read-back: one hop-limit cmsg
/// (header + 4) + one pktinfo cmsg (header + 20) plus alignment
/// margin.
pub const CTL_BUFSZ_V6: usize = 96;

/// Arms the destination read-back (`IPV6_RECVPKTINFO`) on a v6
/// socket so the kernel attaches the `in6_pktinfo` control message.
/// socket2 0.6.5 has no setter for it — this is the audited
/// `libc::setsockopt` (AGENTS.md's owner-named exception,
/// 2026-10-14; the bfdd `arm_v4_recv_ttl` precedent):
///
/// SAFETY: `optval` is a pointer to a live `c_int` of value 1 for the
/// duration of the call; `optlen` is exactly `size_of::<c_int>()`;
/// the level/optname pair is the RFC 3542 §6-documented
/// `IPPROTO_IPV6`/`IPV6_RECVPKTINFO` (libc constants match every
/// target we build: Linux 49, macOS 61). The call cannot observe the
/// pointer after it returns.
pub fn arm_v6_recv_pktinfo(sock: &Socket) -> io::Result<()> {
    let one: libc::c_int = 1;
    let rc = unsafe {
        libc::setsockopt(
            sock.as_raw_fd(),
            libc::IPPROTO_IPV6,
            libc::IPV6_RECVPKTINFO,
            &one as *const libc::c_int as *const libc::c_void,
            std::mem::size_of::<libc::c_int>() as libc::socklen_t,
        )
    };
    if rc == -1 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

/// One received datagram through the audited read-back: the payload
/// slice borrows the caller's buffer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReadbackV6<'a> {
    /// The sender (the kernel-filled address).
    pub src: Ipv6Addr,
    /// The TRUE destination from the `in6_pktinfo` cmsg (`None` when
    /// the kernel attached none — the fail-open path).
    pub dst: Option<Ipv6Addr>,
    /// The received hop limit from its cmsg (`None` likewise).
    pub hop_limit: Option<u32>,
    /// The OSPF packet bytes (no IPv6 header — the raw v6 rule).
    pub payload: &'a [u8],
}

/// One `recvmsg` with a control buffer on a NONBLOCKING v6 raw
/// socket — the audited read-back (AGENTS.md's owner-named exception;
/// `WouldBlock` when idle, which is what makes the poll-loop +
/// Drop-shutdown discipline in the daemon's pump work). The audited
/// unsafe lines (owner-approved 2026-10-14):
///
/// SAFETY (control read): after `recvmsg`, `msg.control_len()` is the
/// kernel-reported count of INITIALIZED bytes in `ctrl`; the kernel
/// never writes past the buffer it was handed (truncation sets
/// MSG_CTRUNC, it never overflows), and `from_raw_parts` reads
/// exactly that prefix within this function's scope.
///
/// SAFETY (payload read): `recvmsg` returns the count of initialized
/// bytes in the iovec; `slice_assume_init_ref` re-interprets exactly
/// that prefix. Both slices are consumed only by the safe byte-wise
/// parsers (`parse_cmsgs` and friends) or copied out before the
/// buffers are reused.
pub fn recvmsg_v6_ctl<'a>(
    sock: &Socket,
    buf: &'a mut [std::mem::MaybeUninit<u8>],
    ctrl: &mut [std::mem::MaybeUninit<u8>],
) -> io::Result<ReadbackV6<'a>> {
    // A per-family dummy address the kernel fills in: a bound v6 raw
    // socket only ever sees v6 senders, so the storage always fits.
    let mut addr: socket2::SockAddr =
        std::net::SocketAddrV6::new(std::net::Ipv6Addr::UNSPECIFIED, 0, 0, 0).into();
    let mut iov = [socket2::MaybeUninitSlice::new(buf)];
    let mut msg = socket2::MsgHdrMut::new()
        .with_addr(&mut addr)
        .with_buffers(&mut iov)
        .with_control(ctrl);
    let len = sock.recvmsg(&mut msg, 0)?;
    let clen = msg.control_len();
    let ctl = unsafe { std::slice::from_raw_parts(ctrl.as_ptr() as *const u8, clen) };
    let dst = received_dst_v6(ctl);
    let hop_limit = received_hop_limit_v6(ctl);
    let src = match addr.as_socket() {
        Some(SocketAddr::V6(v6)) => *v6.ip(),
        _ => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "non-v6 sender on v6 socket",
            ))
        }
    };
    let payload = unsafe { std::slice::from_raw_parts(buf.as_ptr() as *const u8, len) };
    Ok(ReadbackV6 {
        src,
        dst,
        hop_limit,
        payload,
    })
}

/// One per-interface OSPFv3 raw socket: bound to the interface's
/// link-local address (the §2.5 source rule), AllSPFRouters joined at
/// open, multicast hop limit 1 (§A.1), unicast hops 1 (local parity),
/// hop-limit + pktinfo receive read-back armed (the audited cmsg
/// block above — [`recv_ctl`] is the reader).
pub struct OspfV6RawSocket {
    /// The socket2 handle: the sockopt surface (multicast joins,
    /// hops) shared by both handles (see the v2 struct's note).
    socket: std::sync::Mutex<Socket>,
    /// The dup'd-fd tokio handle for the safe async IO path.
    io: tokio::net::UdpSocket,
    /// The interface's link-local address — our packet source (§2.5)
    /// and the unicast candidate in the destination trial.
    pub link_local: Ipv6Addr,
    /// The kernel interface index: the multicast join/egress argument
    /// and (by §A.2/C.1 convention) our OSPFv3 Interface ID.
    pub ifindex: u32,
    /// Whether ff02::6 (AllDRouters) is currently joined.
    joined_dr: std::sync::atomic::AtomicBool,
}

impl OspfV6RawSocket {
    /// Open and arm the socket on the interface's link-local address:
    /// proto 89, bound to `link_local` (scope `ifindex`), AllSPFRouters
    /// membership, multicast egress `ifindex`, hop limits, receive
    /// arming, multicast loopback off.
    pub fn open(link_local: Ipv6Addr, ifindex: u32) -> io::Result<Self> {
        let socket = Socket::new(
            Domain::IPV6,
            Type::RAW,
            Some(Protocol::from(IP_PROTO_OSPF as std::os::raw::c_int)),
        )?;
        // §2.5: the link-local source. The scope id in the sockaddr
        // selects the interface for the (per-link ambiguous) address.
        socket.bind(&socket2::SockAddr::from(SocketAddrV6::new(
            link_local, 0, 0, ifindex,
        )))?;
        socket.join_multicast_v6(&ALL_SPF_ROUTERS_V6, ifindex)?;
        socket.set_multicast_if_v6(ifindex)?;
        // §A.1's hop-limit mandate is the multicast arm; the unicast
        // arm is local parity (documented above).
        socket.set_multicast_hops_v6(OSPF_HOP_LIMIT)?;
        socket.set_unicast_hops_v6(OSPF_HOP_LIMIT)?;
        socket.set_multicast_loop_v6(false)?;
        // The receive-side read-back arming (RFC 3542 §6): both
        // cmsgs on, so [`recv_ctl`] finds them attached — the walls
        // were the reader, not the setters (see the audited block).
        socket.set_recv_hoplimit_v6(true)?;
        arm_v6_recv_pktinfo(&socket)?;
        socket.set_nonblocking(true)?;
        // The safe-I/O seam (the v2 module note), v6 flavor.
        use std::os::fd::AsFd;
        let dup = socket.as_fd().try_clone_to_owned()?;
        let std_sock = std::net::UdpSocket::from(dup);
        let io = tokio::net::UdpSocket::from_std(std_sock)?;
        Ok(Self {
            socket: std::sync::Mutex::new(socket),
            io,
            link_local,
            ifindex,
            joined_dr: std::sync::atomic::AtomicBool::new(false),
        })
    }

    /// §A.1: join AllDRouters when this interface elects itself DR or
    /// BDR.
    pub fn join_all_drouters(&self) -> io::Result<()> {
        if !self
            .joined_dr
            .swap(true, std::sync::atomic::Ordering::SeqCst)
        {
            self.socket
                .lock()
                .expect("ospf v6 socket lock")
                .join_multicast_v6(&ALL_D_ROUTERS_V6, self.ifindex)?;
        }
        Ok(())
    }

    /// The inverse when the role is lost.
    pub fn leave_all_drouters(&self) -> io::Result<()> {
        if self
            .joined_dr
            .swap(false, std::sync::atomic::Ordering::SeqCst)
        {
            self.socket
                .lock()
                .expect("ospf v6 socket lock")
                .leave_multicast_v6(&ALL_D_ROUTERS_V6, self.ifindex)?;
        }
        Ok(())
    }

    /// The async IO handle (readiness + safe send/recv).
    pub fn io(&self) -> &tokio::net::UdpSocket {
        &self.io
    }

    /// Send an OSPFv3 packet to AllSPFRouters (ff02::5) — Hellos and
    /// the p2p/broadcast-DR floods (§A.1).
    pub async fn send_multicast(&self, packet: &[u8]) -> io::Result<usize> {
        self.io
            .send_to(
                packet,
                SocketAddr::V6(SocketAddrV6::new(ALL_SPF_ROUTERS_V6, 0, 0, 0)),
            )
            .await
    }

    /// Send an OSPFv3 packet to AllDRouters (ff02::6) — a DR Other's
    /// broadcast-network flood (§4.5.2/§A.1).
    pub async fn send_multicast_drouters(&self, packet: &[u8]) -> io::Result<usize> {
        self.io
            .send_to(
                packet,
                SocketAddr::V6(SocketAddrV6::new(ALL_D_ROUTERS_V6, 0, 0, 0)),
            )
            .await
    }

    /// Send an OSPFv3 packet unicast to `dst` — the conversation
    /// packets (DD, LSR, LSU, direct LSAck; §A.1).
    pub async fn send_unicast(&self, packet: &[u8], dst: Ipv6Addr) -> io::Result<usize> {
        self.io
            .send_to(packet, SocketAddr::V6(SocketAddrV6::new(dst, 0, 0, 0)))
            .await
    }

    /// Receive one raw datagram. The buffer holds ONLY the OSPF
    /// packet (no IPv6 header — the v6 raw-socket rule); the source
    /// comes from recv_from.
    pub async fn recv(&self, buf: &mut [u8]) -> io::Result<Option<ReceivedV6>> {
        let (n, addr) = self.io.recv_from(buf).await?;
        let src = match addr.ip() {
            std::net::IpAddr::V6(v6) => v6,
            std::net::IpAddr::V4(_) => return Ok(None),
        };
        Ok(Some(ReceivedV6 {
            src,
            payload: buf[..n].to_vec(),
        }))
    }

    /// One NONBLOCKING audited read-back receive ([`recvmsg_v6_ctl`])
    /// on the kernel socket: the payload plus the TRUE destination
    /// and the received hop limit from their cmsgs. `WouldBlock` when
    /// idle — the production pump polls (10 ms rhythm, the bfdd
    /// discipline; a parked blocking recvmsg cannot be woken portably
    /// and would wedge a same-process restart). The sockopt mutex is
    /// held only for the syscall's (immediate) duration, so the §9.4
    /// role join/leave stays responsive.
    pub fn recv_ctl<'a>(
        &self,
        buf: &'a mut [std::mem::MaybeUninit<u8>],
        ctrl: &mut [std::mem::MaybeUninit<u8>],
    ) -> io::Result<ReadbackV6<'a>> {
        let guard = self.socket.lock().expect("ospf v6 socket lock");
        recvmsg_v6_ctl(&guard, buf, ctrl)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A hand-built IPv4 datagram (20-byte header + payload).
    fn datagram(
        version_ihl: u8,
        total_len: u16,
        ttl: u8,
        src: [u8; 4],
        dst: [u8; 4],
        payload: &[u8],
    ) -> Vec<u8> {
        let mut buf = vec![version_ihl, 0];
        buf.extend_from_slice(&total_len.to_be_bytes());
        // id(2) + flags/frag(2) + ttl(1) + proto 89(1) + checksum(2)
        buf.extend_from_slice(&[0, 0, 0, 0, ttl, 89, 0, 0]);
        buf.extend_from_slice(&src);
        buf.extend_from_slice(&dst);
        buf.extend_from_slice(payload);
        buf
    }

    #[test]
    fn parses_a_well_formed_datagram() {
        let pkt = datagram(
            0x45,
            20 + 8,
            1,
            [10, 77, 0, 1],
            [224, 0, 0, 5],
            &[0x02, 0x01, 0, 0, 1, 2, 3, 4],
        );
        let rec = extract_ospf(&pkt).unwrap();
        assert_eq!(rec.src, Ipv4Addr::new(10, 77, 0, 1));
        assert_eq!(rec.dst, ALL_SPF_ROUTERS);
        assert_eq!(rec.payload, vec![0x02, 0x01, 0, 0, 1, 2, 3, 4]);
    }

    #[test]
    fn ihl_options_are_honored() {
        // IHL=6 → 24-byte header; the payload starts past the
        // options words.
        let mut pkt = datagram(0x46, 24 + 4, 1, [1, 1, 1, 1], [224, 0, 0, 5], &[9, 9, 9, 9]);
        // Grow the header region to 24 bytes: insert one option word
        // (4 bytes) before the payload and re-stamp the length.
        for _ in 0..4 {
            pkt.insert(20, 0xaa);
        }
        pkt[2..4].copy_from_slice(&((24 + 4) as u16).to_be_bytes());
        let rec = extract_ospf(&pkt).unwrap();
        assert_eq!(rec.payload, vec![9, 9, 9, 9]);
    }

    #[test]
    fn malformed_headers_are_rejected() {
        // Not version 4.
        assert!(
            extract_ospf(&datagram(0x55, 28, 1, [1, 1, 1, 1], [2, 2, 2, 2], &[0; 8])).is_none()
        );
        // Total length beyond the buffer.
        assert!(
            extract_ospf(&datagram(0x45, 999, 1, [1, 1, 1, 1], [2, 2, 2, 2], &[0; 8])).is_none()
        );
        // Total length shorter than the header.
        assert!(
            extract_ospf(&datagram(0x45, 12, 1, [1, 1, 1, 1], [2, 2, 2, 2], &[0; 8])).is_none()
        );
        // Truncated buffer.
        assert!(
            extract_ospf(&datagram(0x45, 28, 1, [1, 1, 1, 1], [2, 2, 2, 2], &[0; 8])[..10])
                .is_none()
        );
        // IHL < 5.
        assert!(
            extract_ospf(&datagram(0x44, 16, 1, [1, 1, 1, 1], [2, 2, 2, 2], &[0; 8])).is_none()
        );
    }

    #[test]
    fn total_length_truncates_buffer_padding() {
        // The kernel can deliver more bytes than the datagram claims
        // (e.g. on some loopback paths); the payload must follow the
        // header's total length, not the receive count.
        let mut pkt = datagram(0x45, 24, 1, [1, 1, 1, 1], [2, 2, 2, 2], &[7, 7, 7, 7]);
        pkt.extend_from_slice(&[0xff, 0xff]); // padding beyond total_len
        let rec = extract_ospf(&pkt).unwrap();
        assert_eq!(rec.payload, vec![7, 7, 7, 7]);
    }

    /// The TTL readout (octet 8 of the delivered header — raw(7)):
    /// the raw-socket read that closes the receive-side wall without
    /// any cmsg (the header is always in the buffer on raw sockets,
    /// unlike the UDP/TCP-socket IP_RECVTTL path bfdd needs).
    #[test]
    fn ttl_reads_back_from_the_delivered_header() {
        let on_link = datagram(0x45, 28, 1, [1, 1, 1, 1], [2, 2, 2, 2], &[0; 8]);
        assert_eq!(extract_ospf(&on_link).unwrap().ttl, 1, "§A.1's TTL-1 send");

        let degraded = datagram(0x45, 28, 63, [1, 1, 1, 1], [2, 2, 2, 2], &[0; 8]);
        assert_eq!(
            extract_ospf(&degraded).unwrap().ttl,
            63,
            "a relayed packet's TTL"
        );

        let max = datagram(0x45, 28, 255, [1, 1, 1, 1], [2, 2, 2, 2], &[0; 8]);
        assert_eq!(extract_ospf(&max).unwrap().ttl, 255);

        // The readout survives option words (IHL=6, TTL at offset 8).
        let mut opt = datagram(0x46, 28, 7, [1, 1, 1, 1], [2, 2, 2, 2], &[0; 8]);
        for _ in 0..4 {
            opt.insert(20, 0xaa);
        }
        assert_eq!(extract_ospf(&opt).unwrap().ttl, 7);
    }

    /// The receive-side policy table (night N1): unicast exchange
    /// packets must carry TTL 1 (§A.1's transmit mandate makes any
    /// other value non-on-link); multicast Hellos keep the kernel's
    /// rule — no check, so the policy functions never apply to them.
    #[test]
    fn unicast_ttl_policy() {
        assert!(unicast_ttl_ok(1), "the on-link pass value");
        assert!(!unicast_ttl_ok(63), "relayed — drop");
        assert!(!unicast_ttl_ok(255), "far end — drop");
        assert!(is_multicast_dst(ALL_SPF_ROUTERS));
        assert!(is_multicast_dst(ALL_D_ROUTERS));
        assert!(!is_multicast_dst(Ipv4Addr::new(192, 0, 2, 1)));
    }

    /// Opens the real raw socket. On unprivileged runs this fails
    /// with EPERM — the test then skips (the container interop leg
    /// is the wire proof; this pins the arming on any privileged
    /// host, the Linux gate included). Tokio-flavored because
    /// `open`'s safe-I/O seam registers the dup'd fd with the
    /// reactor (`from_std` needs one — a plain #[test] panics
    /// where raw sockets are permitted, e.g. in a NET_RAW container).
    #[tokio::test]
    async fn raw_socket_opens_and_arms_ttl() {
        let sock = match OspfRawSocket::open(Ipv4Addr::LOCALHOST) {
            Ok(sock) => sock,
            Err(err) if err.kind() == io::ErrorKind::PermissionDenied => {
                eprintln!("skipping: raw sockets need root here ({err})");
                return;
            }
            Err(err) => panic!("unexpected open error: {err}"),
        };
        // §A.1 transmit TTLs, read back through socket2 (std has no
        // getters for the multicast arm).
        assert_eq!(
            sock.socket
                .lock()
                .expect("socket lock")
                .multicast_ttl_v4()
                .unwrap(),
            OSPF_TTL
        );
        assert_eq!(
            sock.socket.lock().expect("socket lock").ttl_v4().unwrap(),
            OSPF_TTL
        );
        assert!(!sock
            .socket
            .lock()
            .expect("socket lock")
            .multicast_loop_v4()
            .unwrap());
        // AllDRouters join/leave round-trips (interior-mutable: the
        // shared-handle shape the run loop drives on §9.4 role
        // changes).
        sock.join_all_drouters().unwrap();
        sock.join_all_drouters().unwrap(); // idempotent
        sock.leave_all_drouters().unwrap();
        sock.leave_all_drouters().unwrap(); // idempotent
    }

    /// The wire proof of the TTL readout: two real raw proto-89
    /// sockets on loopback — the sender degrades its TTL to 63, the
    /// receiver reads it back from the delivered header octet
    /// (raw(7)). Privileged-gated like `raw_socket_opens_and_arms_ttl`
    /// (raw sockets need root), and skip-gated again on platforms
    /// whose loopback path does not deliver local raw traffic — the
    /// container interop leg is the wire proof there.
    #[tokio::test]
    async fn raw_loopback_reads_back_the_header_ttl() {
        let sender = match OspfRawSocket::open(Ipv4Addr::LOCALHOST) {
            Ok(s) => s,
            Err(err) if err.kind() == io::ErrorKind::PermissionDenied => {
                eprintln!("skipping: raw sockets need root here ({err})");
                return;
            }
            Err(err) => panic!("unexpected open error: {err}"),
        };
        let receiver = match OspfRawSocket::open(Ipv4Addr::LOCALHOST) {
            Ok(s) => s,
            Err(err) if err.kind() == io::ErrorKind::PermissionDenied => {
                eprintln!("skipping: raw sockets need root here ({err})");
                return;
            }
            Err(err) => panic!("unexpected open error: {err}"),
        };
        // Degrade the transmit TTL to a routed-looking value (63).
        sender
            .socket
            .lock()
            .expect("socket lock")
            .set_ttl_v4(63)
            .unwrap();
        sender
            .send_unicast(&[0x02, 0x01], Ipv4Addr::LOCALHOST)
            .await
            .unwrap();

        let mut buf = vec![0u8; 65535];
        let read =
            tokio::time::timeout(std::time::Duration::from_secs(2), receiver.recv(&mut buf)).await;
        let received = match read {
            Ok(Ok(Some(received))) => received,
            Ok(Ok(None)) | Ok(Err(_)) | Err(_) => {
                eprintln!("skipping: no loopback raw delivery here (platform routing)");
                return;
            }
        };
        assert_eq!(
            received.ttl, 63,
            "the header's TTL octet is the raw-socket readout"
        );
        assert_eq!(received.src, Ipv4Addr::LOCALHOST);
    }

    // ----- The OSPFv3 transport tests (RFC 5340 §A.1) -----

    /// The two link-local multicast constants and the destination
    /// class split (§A.1 / §4.2's destination list).
    #[test]
    fn v6_multicast_constants_and_dst_class() {
        assert_eq!(ALL_SPF_ROUTERS_V6.octets()[0..2], [0xff, 0x02]);
        assert_eq!(ALL_SPF_ROUTERS_V6.octets()[15], 5, "ff02::5");
        assert_eq!(ALL_D_ROUTERS_V6.octets()[15], 6, "ff02::6");
        assert!(is_multicast_dst_v6(ALL_SPF_ROUTERS_V6));
        assert!(is_multicast_dst_v6(ALL_D_ROUTERS_V6));
        assert!(!is_multicast_dst_v6("fe80::1".parse().unwrap()));
        assert!(!is_multicast_dst_v6("2001:db8::1".parse().unwrap()));
    }

    /// `/proc/net/if_inet6` parsing: the name → ifindex map from the
    /// kernel ABI's line shape (addr, ifindex-hex, plen, scope,
    /// flags, name). Malformed lines are skipped.
    #[test]
    fn parses_proc_net_if_inet6() {
        let text = "fe800000000000000000000000000001 02 80 10 80 eth0\n\
                    00000000000000000000000000000000 01 80 10 80 lo\n\
                    garbage\n\
                    fe800000000000000000000000000002 ff 80 10 80 eth1\n";
        let map = parse_if_inet6(text);
        assert_eq!(map.get("lo"), Some(&1), "hex 01");
        assert_eq!(map.get("eth0"), Some(&2), "hex 02");
        assert_eq!(map.get("eth1"), Some(&0xff), "hex ff");
        assert!(!map.contains_key("garbage"));
        assert_eq!(parse_if_inet6("").len(), 0);
        // ifindex_of reads the real file when there is one (Linux);
        // elsewhere it errors NotFound — both outcomes are fine here,
        // the parse logic is what this pins.
        match ifindex_of("lo0").or_else(|_| ifindex_of("lo")) {
            Ok(idx) => assert!(idx > 0),
            Err(e) => assert_eq!(e.kind(), io::ErrorKind::NotFound),
        }
    }

    /// The destination-trial decode (the §4.2 destination list as the
    /// pseudo-header candidate set): a packet encoded for ff02::5
    /// verifies against ff02::5, a unicast one against the peer's
    /// link-local, and corruption fails every candidate.
    #[test]
    fn v3_dst_trial_picks_the_verifying_destination() {
        use crate::lsa::RouterId;
        use crate::lsa_v3::Options24;
        use crate::packet_v3::{HelloV3, PacketBodyV3, PacketHeaderV3, PacketV3};
        let src: Ipv6Addr = "fe80::a1".parse().unwrap();
        let own: Ipv6Addr = "fe80::b2".parse().unwrap();
        let hello = PacketV3 {
            header: PacketHeaderV3 {
                version: 3,
                packet_type: 1,
                length: 0,
                router_id: RouterId(1),
                area_id: 0,
                checksum: 0,
                instance_id: 0,
            },
            body: PacketBodyV3::Hello(HelloV3 {
                interface_id: 3,
                router_priority: 1,
                options: Options24(Options24::V6 | Options24::E | Options24::R),
                hello_interval: 10,
                router_dead_interval: 40,
                designated_router: RouterId(0),
                backup_designated_router: RouterId(0),
                neighbors: vec![],
            }),
        };
        let bytes = hello.encode(src, ALL_SPF_ROUTERS_V6);
        let (back, dst) = decode_v3_dst(&bytes, src, own).expect("multicast candidate verifies");
        assert_eq!(dst, ALL_SPF_ROUTERS_V6);
        assert_eq!(back.header.router_id, RouterId(1));

        let bytes = hello.encode(src, own);
        let (_, dst) = decode_v3_dst(&bytes, src, own).expect("unicast candidate verifies");
        assert_eq!(dst, own);

        // Corrupted payload verifies against nothing.
        let mut bad = hello.encode(src, ALL_SPF_ROUTERS_V6);
        let last = bad.len() - 1;
        bad[last] ^= 0xff;
        assert!(decode_v3_dst(&bad, src, own).is_none());
        // The wrong source address fails too (pseudo-header covers it).
        let bytes = hello.encode(src, ALL_SPF_ROUTERS_V6);
        let other_src: Ipv6Addr = "fe80::c3".parse().unwrap();
        assert!(decode_v3_dst(&bytes, other_src, own).is_none());
    }

    /// The arming read-back (privileged-gated like the v4 test): the
    /// §A.1 multicast hop limit 1, the unicast hops parity, the
    /// IPV6_RECVHOPLIMIT arming, and the AllDRouters join/leave
    /// round-trip.
    #[tokio::test]
    async fn raw_v6_socket_opens_and_arms_hop_limits() {
        // Loopback is index 1 on every supported host.
        let ifindex = ifindex_of("lo0").or_else(|_| ifindex_of("lo")).unwrap_or(1);
        let sock = match OspfV6RawSocket::open(Ipv6Addr::LOCALHOST, ifindex) {
            Ok(sock) => sock,
            Err(err) if err.kind() == io::ErrorKind::PermissionDenied => {
                eprintln!("skipping: raw v6 sockets need root here ({err})");
                return;
            }
            Err(err) => panic!("unexpected v6 open error: {err}"),
        };
        let guard = sock.socket.lock().expect("socket lock");
        // §A.1: the multicast Hop Limit mandate.
        assert_eq!(guard.multicast_hops_v6().unwrap(), OSPF_HOP_LIMIT);
        // The unicast hops parity (local choice, documented).
        assert_eq!(guard.unicast_hops_v6().unwrap(), OSPF_HOP_LIMIT);
        // RFC 3542 §6: the receive arming is on (the read-back is
        // the deferred cmsg walk).
        assert!(guard.recv_hoplimit_v6().unwrap());
        assert!(!guard.multicast_loop_v6().unwrap());
        drop(guard);
        sock.join_all_drouters().unwrap();
        sock.join_all_drouters().unwrap(); // idempotent
        sock.leave_all_drouters().unwrap();
        sock.leave_all_drouters().unwrap(); // idempotent
    }

    /// The wire proof of the v6 transport and the destination trial:
    /// two real raw proto-89 v6 sockets on loopback — a multicast
    /// send to ff02::5 and a unicast send — both received, decoded,
    /// and attributed to the right destination by the pseudo-header.
    /// Privileged-gated like the v4 loopback test.
    #[tokio::test]
    async fn raw_v6_loopback_roundtrips_and_trials_the_dst() {
        let ifindex = ifindex_of("lo0").or_else(|_| ifindex_of("lo")).unwrap_or(1);
        let mk = || match OspfV6RawSocket::open(Ipv6Addr::LOCALHOST, ifindex) {
            Ok(s) => Ok(s),
            Err(err) if err.kind() == io::ErrorKind::PermissionDenied => {
                eprintln!("skipping: raw v6 sockets need root here ({err})");
                Err(())
            }
            Err(err) => panic!("unexpected v6 open error: {err}"),
        };
        let sender = match mk() {
            Ok(s) => s,
            Err(()) => return,
        };
        let receiver = match mk() {
            Ok(s) => s,
            Err(()) => return,
        };
        // A minimal but well-formed Hello (checksum valid for the
        // real addresses — the trial decodes it below).
        use crate::lsa::RouterId;
        use crate::lsa_v3::Options24;
        use crate::packet_v3::{HelloV3, PacketBodyV3, PacketHeaderV3, PacketV3};
        let hello = PacketV3 {
            header: PacketHeaderV3 {
                version: 3,
                packet_type: 1,
                length: 0,
                router_id: RouterId(0x0a00_0001),
                area_id: 0,
                checksum: 0,
                instance_id: 0,
            },
            body: PacketBodyV3::Hello(HelloV3 {
                interface_id: 7,
                router_priority: 1,
                options: Options24(Options24::V6 | Options24::E | Options24::R),
                hello_interval: 10,
                router_dead_interval: 40,
                designated_router: RouterId(0),
                backup_designated_router: RouterId(0),
                neighbors: vec![],
            }),
        };
        let mut buf = vec![0u8; 65535];
        async fn try_recv(receiver: &OspfV6RawSocket, buf: &mut [u8]) -> Option<ReceivedV6> {
            match tokio::time::timeout(std::time::Duration::from_secs(2), receiver.recv(buf)).await
            {
                Ok(Ok(Some(received))) => Some(received),
                _ => None,
            }
        }

        // Multicast leg: ff02::5 on the loopback link.
        sender
            .send_multicast(&hello.encode(Ipv6Addr::LOCALHOST, ALL_SPF_ROUTERS_V6))
            .await
            .unwrap();
        let Some(received) = try_recv(&receiver, &mut buf).await else {
            eprintln!("skipping: no loopback v6 multicast delivery here");
            return;
        };
        assert_eq!(received.src, Ipv6Addr::LOCALHOST);
        let (packet, dst) = decode_v3_dst(&received.payload, received.src, receiver.link_local)
            .expect("multicast candidate verifies on real wire bytes");
        assert_eq!(dst, ALL_SPF_ROUTERS_V6);
        assert_eq!(packet.header.router_id, RouterId(0x0a00_0001));

        // Unicast leg: straight to our own bound address.
        sender
            .send_unicast(
                &hello.encode(Ipv6Addr::LOCALHOST, Ipv6Addr::LOCALHOST),
                Ipv6Addr::LOCALHOST,
            )
            .await
            .unwrap();
        let Some(received) = try_recv(&receiver, &mut buf).await else {
            eprintln!("skipping: no loopback v6 unicast delivery here");
            return;
        };
        let (_, dst) =
            decode_v3_dst(&received.payload, received.src, receiver.link_local).expect("");
        assert_eq!(dst, Ipv6Addr::LOCALHOST, "the unicast candidate verified");
    }

    // ----- The audited v6 cmsg read-back (S8-b, RFC 3542 §6) ------

    /// Synthetic-cmsg goldens build the HOST's native `cmsg_len`
    /// width (the kernel round-trips below pin the real ones).
    #[cfg(any(target_os = "linux", target_os = "android"))]
    const GOLDEN_LEN_SIZE: usize = std::mem::size_of::<usize>();
    #[cfg(not(any(target_os = "linux", target_os = "android")))]
    const GOLDEN_LEN_SIZE: usize = 4;

    fn put_cmsg_len(buf: &mut Vec<u8>, len: u32) {
        let raw = (len as usize).to_ne_bytes();
        buf.extend_from_slice(&raw[..GOLDEN_LEN_SIZE]);
    }

    fn hoplimit_cmsg(hl: u32) -> Vec<u8> {
        let mut ctrl = Vec::new();
        put_cmsg_len(&mut ctrl, (GOLDEN_LEN_SIZE + 8 + 4) as u32);
        ctrl.extend_from_slice(&IPPROTO_IPV6_CMSG.to_ne_bytes());
        ctrl.extend_from_slice(&IPV6_HOPLIMIT_CMSG_KINDS[0].to_ne_bytes());
        ctrl.extend_from_slice(&hl.to_ne_bytes()); // native order, both targets
        ctrl
    }

    fn pktinfo_cmsg(dst: Ipv6Addr, ifindex: u32) -> Vec<u8> {
        let mut ctrl = Vec::new();
        put_cmsg_len(&mut ctrl, (GOLDEN_LEN_SIZE + 8 + 20) as u32);
        ctrl.extend_from_slice(&IPPROTO_IPV6_CMSG.to_ne_bytes());
        ctrl.extend_from_slice(&IPV6_PKTINFO_CMSG_KINDS[0].to_ne_bytes());
        ctrl.extend_from_slice(&dst.octets()); // the in6_pktinfo address
        ctrl.extend_from_slice(&ifindex.to_ne_bytes());
        ctrl
    }

    /// The safe half of the read-back: the hop-limit cmsg parses with
    /// its native-order u32, the pktinfo cmsg yields the destination,
    /// and the alignment walk survives a two-message buffer with
    /// padding (the shapes the kernel round-trips pin for real).
    #[test]
    fn v6_cmsg_parser_goldens() {
        assert_eq!(received_hop_limit_v6(&hoplimit_cmsg(1)), Some(1));
        assert_eq!(received_hop_limit_v6(&hoplimit_cmsg(63)), Some(63));
        let dst: Ipv6Addr = "fe80::a1".parse().unwrap();
        assert_eq!(received_dst_v6(&pktinfo_cmsg(dst, 3)), Some(dst));

        // Both cmsgs in one control buffer, hoplimit first with
        // padding to the alignment boundary: the walk finds both.
        let mut both = hoplimit_cmsg(1);
        let first = GOLDEN_LEN_SIZE + 8 + 4;
        both.resize(first.div_ceil(GOLDEN_LEN_SIZE) * GOLDEN_LEN_SIZE, 0);
        both.extend_from_slice(&pktinfo_cmsg(ALL_SPF_ROUTERS_V6, 7));
        assert_eq!(received_hop_limit_v6(&both), Some(1));
        assert_eq!(received_dst_v6(&both), Some(ALL_SPF_ROUTERS_V6));
        assert_eq!(parse_cmsgs(&both).len(), 2);
    }

    /// The parsers' edges: truncated pktinfo data, foreign cmsgs,
    /// empty buffers, and malformed tails all degrade to None/stop
    /// (never a wrong answer).
    #[test]
    fn v6_cmsg_extraction_edges() {
        // A pktinfo header promising 20 bytes but carrying 10.
        let mut short = Vec::new();
        put_cmsg_len(&mut short, (GOLDEN_LEN_SIZE + 8 + 20) as u32);
        short.extend_from_slice(&IPPROTO_IPV6_CMSG.to_ne_bytes());
        short.extend_from_slice(&IPV6_PKTINFO_CMSG_KINDS[0].to_ne_bytes());
        short.extend_from_slice(&[0u8; 10]);
        assert_eq!(received_dst_v6(&short), None, "truncated pktinfo");
        // A foreign cmsg (level 0 = SOL_IP) is ignored by both.
        let mut foreign = Vec::new();
        put_cmsg_len(&mut foreign, (GOLDEN_LEN_SIZE + 8 + 4) as u32);
        foreign.extend_from_slice(&0u32.to_ne_bytes()); // level SOL_IP
        foreign.extend_from_slice(&2u32.to_ne_bytes()); // type 2
        foreign.extend_from_slice(&255u32.to_ne_bytes());
        assert_eq!(received_hop_limit_v6(&foreign), None, "v4 cmsg ignored");
        assert_eq!(received_dst_v6(&foreign), None);
        // Empty and truncated buffers.
        assert_eq!(received_hop_limit_v6(&[]), None);
        assert_eq!(received_dst_v6(&[]), None);
        assert!(parse_cmsgs(&hoplimit_cmsg(1)[..GOLDEN_LEN_SIZE + 4]).is_empty());
        // A hop-limit cmsg with short data (len says 4, data says 2).
        let mut skinny = Vec::new();
        put_cmsg_len(&mut skinny, (GOLDEN_LEN_SIZE + 8 + 4) as u32);
        skinny.extend_from_slice(&IPPROTO_IPV6_CMSG.to_ne_bytes());
        skinny.extend_from_slice(&IPV6_HOPLIMIT_CMSG_KINDS[0].to_ne_bytes());
        skinny.extend_from_slice(&[1u8, 0]);
        assert_eq!(received_hop_limit_v6(&skinny), None, "data under 4 bytes");
    }

    /// The unicast receive-side hop policy (the v6 mirror of the N1
    /// v4 rule): our unicast arm sends hop 1, so 1 is the only pass
    /// value; `None` (no cmsg) is fail-open, disclosed.
    #[test]
    fn unicast_hop_policy() {
        assert!(unicast_hop_limit_ok(1), "the on-link pass value");
        assert!(!unicast_hop_limit_ok(63), "relayed — drop");
        assert!(!unicast_hop_limit_ok(255), "far end — drop");
        // The fail-open composition the daemon applies (None = no
        // cmsg — the unarmed path, disclosed).
        assert!(Option::<u32>::None
            .map(unicast_hop_limit_ok)
            .unwrap_or(true));
    }

    /// The kernel round-trip on UDP loopback (unprivileged — the
    /// arming, the audited recvmsg, and the parsers against the REAL
    /// kernel cmsgs): the sent hop limit and the true destination
    /// read back through [`recvmsg_v6_ctl`]; WouldBlock when idle.
    #[test]
    fn udp_v6_roundtrip_reads_back_hop_and_dst() {
        let sender = Socket::new(Domain::IPV6, Type::DGRAM, Some(Protocol::UDP)).unwrap();
        sender
            .bind(&"[::1]:0".parse::<SocketAddr>().unwrap().into())
            .unwrap();
        let receiver = Socket::new(Domain::IPV6, Type::DGRAM, Some(Protocol::UDP)).unwrap();
        receiver
            .bind(&"[::1]:0".parse::<SocketAddr>().unwrap().into())
            .unwrap();
        receiver.set_recv_hoplimit_v6(true).unwrap();
        arm_v6_recv_pktinfo(&receiver).unwrap();
        receiver.set_nonblocking(true).unwrap();
        let dst = receiver.local_addr().unwrap().as_socket().unwrap();

        // Idle socket: the nonblocking recvmsg returns WouldBlock.
        let mut payload = [std::mem::MaybeUninit::<u8>::uninit(); 64];
        let mut ctrl = [std::mem::MaybeUninit::<u8>::uninit(); CTL_BUFSZ_V6];
        assert_eq!(
            recvmsg_v6_ctl(&receiver, &mut payload, &mut ctrl)
                .unwrap_err()
                .kind(),
            io::ErrorKind::WouldBlock
        );

        for sent in [1u32, 64] {
            sender.set_unicast_hops_v6(sent).unwrap();
            sender.send_to(b"probe", &dst.into()).unwrap();
            let read = loop {
                match recvmsg_v6_ctl(&receiver, &mut payload, &mut ctrl) {
                    Ok(read) => break read,
                    Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                        std::thread::sleep(std::time::Duration::from_millis(5));
                    }
                    Err(e) => panic!("recvmsg failed: {e}"),
                }
            };
            assert_eq!(read.payload, b"probe");
            assert_eq!(read.src, Ipv6Addr::LOCALHOST);
            assert_eq!(read.hop_limit, Some(sent), "sent hop {sent} reads back");
            assert_eq!(read.dst, Some(Ipv6Addr::LOCALHOST), "the true dst");
            assert_eq!(unicast_hop_limit_ok(sent), sent == 1);
        }
    }

    /// The wire proof on the REAL transport: raw proto-89 v6 sockets
    /// on loopback — a multicast send to ff02::5 and unicast sends at
    /// hops 1 and 63 — all read back through the audited [`recv_ctl`]
    /// (hop limit AND true destination, the read-backs the S7-a
    /// interim stood in for). Privileged-gated like the other raw
    /// tests (root opens raw sockets; the interop leg is the proof
    /// elsewhere).
    #[tokio::test]
    async fn raw_v6_readback_roundtrips_the_real_wire() {
        let ifindex = ifindex_of("lo0").or_else(|_| ifindex_of("lo")).unwrap_or(1);
        let mk = || match OspfV6RawSocket::open(Ipv6Addr::LOCALHOST, ifindex) {
            Ok(s) => Ok(s),
            Err(err) if err.kind() == io::ErrorKind::PermissionDenied => {
                eprintln!("skipping: raw v6 sockets need root here ({err})");
                Err(())
            }
            Err(err) => panic!("unexpected v6 open error: {err}"),
        };
        let sender = match mk() {
            Ok(s) => s,
            Err(()) => return,
        };
        let receiver = match mk() {
            Ok(s) => s,
            Err(()) => return,
        };
        let mut payload = [std::mem::MaybeUninit::<u8>::uninit(); 65535];
        let mut ctrl = [std::mem::MaybeUninit::<u8>::uninit(); CTL_BUFSZ_V6];
        // Bounded poll: a platform whose loopback does not deliver
        // raw v6 skips the leg (the interop rig is the wire proof
        // there).
        #[derive(Debug, Default)]
        struct Readback {
            src: Option<Ipv6Addr>,
            dst: Option<Ipv6Addr>,
            hop_limit: Option<u32>,
            #[allow(dead_code)] // symmetry: the legs assert src/dst/hop
            payload: Vec<u8>,
        }

        fn read_one(
            receiver: &OspfV6RawSocket,
            payload: &mut [std::mem::MaybeUninit<u8>],
            ctrl: &mut [std::mem::MaybeUninit<u8>],
        ) -> Option<Readback> {
            for _ in 0..400 {
                match receiver.recv_ctl(payload, ctrl) {
                    Ok(read) => {
                        return Some(Readback {
                            src: Some(read.src),
                            dst: read.dst,
                            hop_limit: read.hop_limit,
                            payload: read.payload.to_vec(),
                        });
                    }
                    Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                        std::thread::sleep(std::time::Duration::from_millis(5));
                    }
                    Err(e) => panic!("recvmsg failed: {e}"),
                }
            }
            None
        }

        // Multicast leg: ff02::5, hop 1 (the §A.1-mandated arm).
        sender
            .send_multicast(&[0x03, 0x00, 0x00, 0x00])
            .await
            .unwrap();
        let Some(read) = read_one(&receiver, &mut payload, &mut ctrl) else {
            eprintln!("skipping: no loopback v6 multicast delivery here");
            return;
        };
        assert_eq!(
            read.hop_limit,
            Some(1),
            "ff02::5 carries hop 1 (§A.1's mandate)"
        );
        assert_eq!(read.dst, Some(ALL_SPF_ROUTERS_V6), "the true multicast dst");
        assert_eq!(read.src, Some(Ipv6Addr::LOCALHOST));

        // Unicast leg at our parity hop 1: passes the verdict.
        sender
            .send_unicast(&[0x04, 0x00, 0x00, 0x00], Ipv6Addr::LOCALHOST)
            .await
            .unwrap();
        let Some(read) = read_one(&receiver, &mut payload, &mut ctrl) else {
            eprintln!("skipping: no loopback v6 unicast delivery here");
            return;
        };
        assert_eq!(read.hop_limit, Some(1));
        assert_eq!(read.dst, Some(Ipv6Addr::LOCALHOST));
        assert!(unicast_hop_limit_ok(read.hop_limit.unwrap()));

        // Degraded unicast (hops 63): the read-back still works — and
        // the verdict drops it, the receive-side rule the read-back
        // feeds.
        sender
            .socket
            .lock()
            .expect("socket lock")
            .set_unicast_hops_v6(63)
            .unwrap();
        sender
            .send_unicast(&[0x05, 0x00, 0x00, 0x00], Ipv6Addr::LOCALHOST)
            .await
            .unwrap();
        let Some(read) = read_one(&receiver, &mut payload, &mut ctrl) else {
            eprintln!("skipping: no loopback v6 unicast delivery here");
            return;
        };
        assert_eq!(read.hop_limit, Some(63), "the degraded value reads back");
        assert!(
            !unicast_hop_limit_ok(read.hop_limit.unwrap()),
            "relayed — drop"
        );
    }
}
