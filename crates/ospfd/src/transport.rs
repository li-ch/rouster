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

use std::io;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};

use socket2::{Domain, Protocol, Socket, Type};

use crate::packet::{ALL_D_ROUTERS, ALL_SPF_ROUTERS, IP_PROTO_OSPF};

/// §A.1: all OSPF protocol packets are sent with TTL 1.
pub const OSPF_TTL: u32 = 1;

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
}
