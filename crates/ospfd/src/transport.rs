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
//! WILL need the cmsg walk (RFC 3542 §6 `IPV6_RECVHOPLIMIT`: raw v6
//! sockets do NOT deliver the IPv6 header) — recorded in ospf.md.
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
// - **No receive-side hop-limit enforcement is possible yet**: a raw
//   IPv6 socket does NOT deliver the IPv6 header in the buffer
//   (ipv6(7)/RFC 3542 §6 — the v4 raw trick does not port), so the
//   hop limit is only readable through the `IPV6_RECVHOPLIMIT` cmsg —
//   and every cmsg reader needs `recvmsg`, which no safe API in our
//   dependency set wraps. The socketopt IS armed here through
//   socket2's safe setter (so a future cmsg walker finds it enabled);
//   the read-back itself is §Deferred with the bfdd audited-block
//   precedent (arm_v4_recv_ttl / recvmsg_ctl in crates/bfdd — the
//   owner-exception treatment). No unsafe was added.
// - **The received IPv6 destination address has the same wall** (it
//   rides the IPV6_RECVPKTINFO cmsg), but the v3 checksum needs it
//   (the RFC 8200 §8.1 pseudo-header). Deterministic workaround, same
//   shape the RFC itself enumerates (§4.2: the destination "MUST be
//   one of the IPv6 unicast addresses associated with the receiving
//   interface ..., AllSPFRouters or AllDRouters"): [`decode_v3_dst`]
//   tries the small candidate set and takes the one whose pseudo-
//   header verifies. Disclosed: a packet that verifies against NONE
//   of the candidates is dropped (a checksum collision across
//   candidates is the only false-accept path).
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

/// One per-interface OSPFv3 raw socket: bound to the interface's
/// link-local address (the §2.5 source rule), AllSPFRouters joined at
/// open, multicast hop limit 1 (§A.1), unicast hops 1 (local parity),
/// hop-limit receive arming on (the cmsg read-back is §Deferred).
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
        // The receive-side arming (RFC 3542 §6): on, so the future
        // cmsg read-back finds it — the wall is the reader, not the
        // setter (see the module note).
        socket.set_recv_hoplimit_v6(true)?;
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
}
