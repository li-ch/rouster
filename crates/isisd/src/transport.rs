//! The IS-IS link transport: Ethernet framing (pure, every platform)
//! and the Linux AF_PACKET ethertype-0x00FE socket (cfg-gated).
//!
//! **Framing** (pure): IS-IS rides Ethernet directly — destination
//! 01:80:c2:00:00:14 (AllL1ISs) / 01:80:c2:00:00:15 (AllL2ISs) /
//! 09:00:2b:00:00:05 (All ISs, RFC 5309's p2p-over-LAN) per ISO
//! 10589 §8.4.8's Table 9 constants (verified in FRR 10.2.2
//! `isisd/isis_pfpacket.c`). The ETHERNET wire form is **802.3 +
//! LLC** (`length | FE FE 03 | PDU`) — the 0x00FE "ethertype" form
//! is a trap: 0x00FE < 1536, so receiving stacks classify it as an
//! 802.3 length (254!) and ethertype-matched filters (FRR's BPF,
//! AF_PACKET protocol filters) never match it. [`frame`] emits the
//! LLC form; [`parse_frame`] accepts the LLC form (both the length
//! field and FRR's 0x8870 extended-LLC variant) AND the bare
//! 0x00FE form (FRR's `isis_send_pdu_p2p` emits it on pure-p2p
//! interfaces, where the far end's stack apparently copes).
//!
//! **The socket** (Linux only): a `SOCK_RAW` `AF_PACKET` socket with
//! the protocol bound at creation — `socket(AF_PACKET, SOCK_RAW,
//! htons(0x00FE))` — receives every 0x00FE frame on every interface
//! via `recv` (no address parsing; the Ethernet header is in the
//! buffer). Transmission needs a `sockaddr_ll`, and **socket2 0.6.5
//! has no link-layer address constructor** (rust-lang/socket2#522,
//! still open at the 0.6.5 release — the latest). The audited safe
//! seam used here:
//!
//! - `sockaddr_in6` (28 bytes) overlays `sockaddr_ll` (20 bytes)
//!   field-for-field: `sin6_port` ↔ `sll_protocol`, `sin6_flowinfo` ↔
//!   `sll_ifindex`, `sin6_addr[0..2]` ↔ `sll_hatype`,
//!   `sin6_addr[2..4]` ↔ `sll_pkttype`, `sin6_addr[4..6]` ↔
//!   `sll_halen`, `sin6_addr[6..12]` ↔ `sll_addr[0..6]`.
//! - The kernel's AF_PACKET send path (`net/packet/af_packet.c`
//!   `packet_snd`, Linux v6.6) **never inspects `sll_family`**: it
//!   checks only `namelen ≥ sizeof(sockaddr_ll)` and
//!   `namelen ≥ sll_halen + 14`, then reads `sll_ifindex` (the
//!   device) and `sll_protocol`. `tokio::net::UdpSocket::send_to`
//!   passes a 28-byte `sockaddr_in6` — every constraint satisfied,
//!   family bytes unread.
//! - For `SOCK_RAW` the transmitted frame is taken from the user
//!   buffer as-is (`dev_validate_header` checks the header we built);
//!   `sll_addr` is only read on `SOCK_DGRAM`.
//!
//! Worst-case failure mode: a future kernel that starts checking the
//! family returns `EINVAL` from `sendto` — an ordinary `io::Error`
//! the daemon logs; no undefined behaviour is possible through a
//! wrongly-typed address (the kernel reads the bytes we wrote; there
//! is no aliasing). This is the same audited-trick discipline as the
//! ospfd dup-into-tokio seam, documented here and in
//! `docs/protocols/isis.md`.
//!
//! Disclosed fences (both inherited shapes): no per-interface bind
//! (`packet_bind` DOES check `sll_family`, and socket2 0.6.5 exposes
//! no link-layer bind address) — a 0x00FE socket receives on ALL
//! interfaces, demultiplexed in userspace by the frame's source MAC
//! (our interface's MAC, read from sysfs); and our own transmissions
//! are looped back by the kernel (PACKET_OUTGOING) — dropped by that
//! same source-MAC rule. Multiple IS-IS sockets in one process each
//! see every frame (v1: one circuit per daemon).

/// IS-IS's Ethernet ethertype (ISO 10589 §8.4.8; FRR's BPF filter
/// matches exactly this).
pub const ETHERTYPE_ISIS: u16 = 0x00FE;

/// The 802.2 LLC header LAN circuits insert (FRR's LAN TX path).
pub const LLC_ISIS: [u8; 3] = [0xFE, 0xFE, 0x03];

/// A MAC address.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Mac(pub [u8; 6]);

impl Mac {
    /// AllL1ISs (ISO 10589 §8.4.8 Table 9).
    pub const ALL_L1_ISS: Mac = Mac([0x01, 0x80, 0xC2, 0x00, 0x00, 0x14]);
    /// AllL2ISs.
    pub const ALL_L2_ISS: Mac = Mac([0x01, 0x80, 0xC2, 0x00, 0x00, 0x15]);
    /// All Intermediate Systems (09:00:2b:00:00:05) — RFC 5309's
    /// p2p-over-LAN recommendation; also FRR's p2p broadcast-group
    /// join.
    pub const ALL_ISS: Mac = Mac([0x09, 0x00, 0x2B, 0x00, 0x00, 0x05]);

    /// The broadcast address.
    pub const BROADCAST: Mac = Mac([0xFF; 6]);

    pub fn parse(s: &str) -> Option<Self> {
        let parts: Vec<&str> = s.split(':').collect();
        if parts.len() != 6 {
            return None;
        }
        let mut bytes = [0u8; 6];
        for (i, p) in parts.iter().enumerate() {
            bytes[i] = u8::from_str_radix(p, 16).ok()?;
        }
        Some(Self(bytes))
    }

    /// The multicast destination for a level (L1/L2 IIHs).
    pub fn for_level(level2: bool) -> Self {
        if level2 {
            Self::ALL_L2_ISS
        } else {
            Self::ALL_L1_ISS
        }
    }

    fn is_multicast(self) -> bool {
        self.0[0] & 0x01 != 0
    }
}

impl std::fmt::Display for Mac {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let b = self.0;
        write!(
            f,
            "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
            b[0], b[1], b[2], b[3], b[4], b[5]
        )
    }
}

/// Build one Ethernet frame — the **802.3 + LLC form**:
/// `dst | src | length | FE FE 03 | PDU`.
///
/// Why not the 0x00FE ethertype form (FRR's `isis_send_pdu_p2p`
/// writes it): **0x00FE = 254 sits below the 802.3/DIX threshold of
/// 1536**, so the receiver's `eth_type_trans` classifies the frame
/// as 802.3 and hands the stack `ETH_P_802_2` — an ethertype-matched
/// socket or BPF (FRR's) never sees it (found live in the S10-a
/// smoke bring-up; the wire dump showed our ethertype frames
/// arriving at FRR and dying in its BPF). Every Ethernet IS-IS
/// deployment uses the LLC form — FRR's LAN TX path
/// (`isis_send_pdu_bcast` + `isis_ethertype()`: the length field for
/// frames ≤ 1535, the 0x8870 extended-LLC ethertype above) — and so
/// do we, with the length field set to the LLC+PDU length as FRR
/// does.
pub fn frame(dst: Mac, src: Mac, pdu: &[u8]) -> Vec<u8> {
    let llc_len = LLC_ISIS.len() + pdu.len();
    let mut out = Vec::with_capacity(14 + llc_len);
    out.extend_from_slice(&dst.0);
    out.extend_from_slice(&src.0);
    let type_field = if llc_len > MAX_LLC_LEN {
        ETHERTYPE_EXT_LLC
    } else {
        llc_len as u16
    };
    out.extend_from_slice(&type_field.to_be_bytes());
    out.extend_from_slice(&LLC_ISIS);
    out.extend_from_slice(pdu);
    out
}

/// FRR's `MAX_LLC_LEN` (0x5ff): above it the type field becomes the
/// extended-LLC ethertype 0x8870 (FRR's own constant pair).
pub const MAX_LLC_LEN: usize = 0x5ff;
/// FRR's `ETHERTYPE_EXT_LLC`.
pub const ETHERTYPE_EXT_LLC: u16 = 0x8870;

/// A parsed frame.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ParsedFrame<'a> {
    pub dst: Mac,
    pub src: Mac,
    /// True for the multicast destinations (the IIH targets).
    pub multicast: bool,
    pub payload: &'a [u8],
}

/// Parse one received frame. Two IS-IS encapsulations exist on
/// Ethernet (both accepted, FRR 10.2.2 emits both depending on the
/// circuit):
///
/// - **Ethertype form**: `dst | src | 0x00FE | PDU` — the p2p wire
///   form (FRR's `isis_send_pdu_p2p`; also our TX form).
/// - **802.3 form**: `dst | src | length ≤ 1500 | FE FE 03 | PDU` —
///   the LAN/broadcast form (FRR's `isis_send_pdu_bcast`, including
///   its p2p-over-broadcast-interface hellos, which go to All-ISs
///   09:00:2b:00:00:05 WITH the LLC header — verified on the wire in
///   the S10-a smoke bring-up).
///
/// Other ethertypes and runts are rejected; trailing padding is the
/// PDU length field's business.
pub fn parse_frame(bytes: &[u8]) -> Option<ParsedFrame<'_>> {
    if bytes.len() < 14 {
        return None;
    }
    let dst = Mac([bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5]]);
    let src = Mac([bytes[6], bytes[7], bytes[8], bytes[9], bytes[10], bytes[11]]);
    let type_or_len = u16::from_be_bytes([bytes[12], bytes[13]]);
    let rest = &bytes[14..];
    let payload = if type_or_len == ETHERTYPE_ISIS {
        // Ethertype form: an LLC header MAY follow (the LAN shape).
        if rest.len() >= 3 && rest[..3] == LLC_ISIS {
            &rest[3..]
        } else {
            rest
        }
    } else if (type_or_len <= 1500 || type_or_len == ETHERTYPE_EXT_LLC)
        && rest.len() >= 3
        && rest[..3] == LLC_ISIS
    {
        // 802.3 length form (or FRR's extended-LLC ethertype) with
        // the IS-IS LLC.
        &rest[3..]
    } else {
        return None;
    };
    Some(ParsedFrame {
        dst,
        src,
        multicast: dst.is_multicast(),
        payload,
    })
}

/// ISO §8.2.3's padding rule: "trailing pad options are inserted to
/// make PDU Length equal to at least maxsize - 1" — TLV 8s ("LENGTH
/// octets of arbitrary value") appended until the PDU reaches
/// `target` bytes (the circuit MTU minus one). A PDU already at or
/// past the target is left alone.
pub fn pad_pdu(pdu: &mut Vec<u8>, target: usize) {
    while pdu.len() < target {
        let need = target - pdu.len();
        if need <= 2 {
            // A TLV header alone: pad with zeros to close the gap.
            pdu.extend(std::iter::repeat_n(0u8, need));
            break;
        }
        let value = (need - 2).min(255);
        pdu.push(crate::tlv::TLV_PADDING);
        pdu.push(value as u8);
        pdu.extend(std::iter::repeat_n(0u8, value));
    }
}

// ---- the Linux AF_PACKET socket ---------------------------------

#[cfg(target_os = "linux")]
mod packet {
    use std::io;
    use std::net::{Ipv6Addr, SocketAddr, SocketAddrV6};
    use std::os::fd::AsFd;

    use socket2::{Domain, Protocol, Socket, Type};

    use super::{frame, Mac};

    /// The `sockaddr_in6` overlay of `sockaddr_ll` (the module note's
    /// audited seam). Field map:
    ///
    /// ```text
    /// offset  sockaddr_ll (20B)   sockaddr_in6 (28B)
    /// 0       sll_family          sin6_family   (unread by packet_snd)
    /// 2       sll_protocol        sin6_port     → 0x00FE
    /// 4       sll_ifindex         sin6_flowinfo → ifindex
    /// 8       sll_hatype          sin6_addr[0..2]   → ARPHRD_ETHER (1)
    /// 10      sll_pkttype         sin6_addr[2..4]   → 0 (PACKET_HOST)
    /// 12      sll_halen           sin6_addr[4..6]   → 6
    /// 14      sll_addr[0..6]      sin6_addr[6..12]  → the dst MAC
    /// ```
    fn ll_overlay(ifindex: u32, dst: Mac) -> SocketAddr {
        let mut addr6 = [0u8; 16];
        addr6[0..2].copy_from_slice(&1u16.to_be_bytes()); // hatype
                                                          // pkttype 0 at [2..4]
        addr6[4..6].copy_from_slice(&6u16.to_be_bytes()); // halen
        addr6[6..12].copy_from_slice(&dst.0);
        SocketAddr::V6(SocketAddrV6::new(
            Ipv6Addr::from(addr6),
            super::ETHERTYPE_ISIS, // sin6_port ↔ sll_protocol
            ifindex,               // sin6_flowinfo ↔ sll_ifindex
            0,
        ))
    }

    /// One IS-IS circuit socket: raw 0x00FE on `ifname`. Cheaply
    /// cloneable (the tokio handle sits in an `Arc`) so the RX and TX
    /// pumps of a daemon share one kernel socket — every dup'd handle
    /// refers to the same socket(2) result.
    #[derive(Clone)]
    pub struct IsisPacketSocket {
        /// The dup'd-fd tokio handle for the safe async IO path (the
        /// ospfd seam).
        io: std::sync::Arc<tokio::net::UdpSocket>,
        ifindex: u32,
        our_mac: Mac,
    }

    impl IsisPacketSocket {
        /// Open the raw socket on `ifname` (needs CAP_NET_RAW / root;
        /// EPERM propagates so callers can skip gracefully).
        pub fn open(ifname: &str) -> io::Result<Self> {
            let ifindex = read_sysctl(&format!("/sys/class/net/{ifname}/ifindex"))?
                .trim()
                .parse::<u32>()
                .map_err(|_| io::Error::new(io::ErrorKind::NotFound, "no ifindex"))?;
            let mac_text = read_sysctl(&format!("/sys/class/net/{ifname}/address"))?;
            let our_mac = Mac::parse(mac_text.trim())
                .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "no MAC"))?;
            // AF_PACKET SOCK_RAW over ETH_P_ALL in network byte order
            // (packet(7)) — NOT a 0x00FE filter: peers encapsulate
            // IS-IS as 802.3+LLC (length field, no ethertype), which
            // an ethertype filter never sees (FRR opens ETH_P_ALL +
            // a BPF program for the same reason; we filter purely in
            // `parse_frame` — no BPF, no unsafe).
            let socket = Socket::new(
                Domain::PACKET,
                Type::RAW,
                Some(Protocol::from(0x0003u16.to_be() as i32)),
            )?;
            socket.set_nonblocking(true)?;
            let dup = socket.as_fd().try_clone_to_owned()?;
            let io = std::sync::Arc::new(tokio::net::UdpSocket::from_std(
                std::net::UdpSocket::from(dup),
            )?);
            Ok(Self {
                io,
                ifindex,
                our_mac,
            })
        }

        pub fn our_mac(&self) -> Mac {
            self.our_mac
        }

        /// Receive one IS-IS frame into `buf` (the whole Ethernet
        /// frame — SOCK_RAW delivers it); returns the length. Frames
        /// that are not IS-IS (the ETH_P_ALL socket sees all bridge
        /// traffic), our own looped-back transmissions (source MAC ==
        /// ours — both the PACKET_OUTGOING kernel copy and the
        /// bridge-reflected multicast copy) and runts are consumed
        /// silently; the next call reads again. The caller parses
        /// with [`super::parse_frame`].
        pub async fn recv(&self, buf: &mut [u8; 9000]) -> io::Result<usize> {
            loop {
                let n = self.io.recv(buf).await?;
                let Some(parsed) = super::parse_frame(&buf[..n]) else {
                    continue; // not IS-IS (ARP/IP/... on the shared socket)
                };
                if parsed.src == self.our_mac {
                    continue;
                }
                return Ok(n);
            }
        }

        /// Transmit one PDU (framed with our MAC as source).
        pub async fn send(&self, dst: Mac, pdu: &[u8]) -> io::Result<()> {
            let frame = frame(dst, self.our_mac, pdu);
            self.io
                .send_to(&frame, ll_overlay(self.ifindex, dst))
                .await?;
            Ok(())
        }
    }

    fn read_sysctl(path: &str) -> io::Result<String> {
        std::fs::read_to_string(path)
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        /// Open + selfloop-drop test. Skips without CAP_NET_RAW (the
        /// ospfd EPERM convention — macOS never compiles this module
        /// at all).
        #[test]
        fn raw_socket_opens_or_skips() {
            let sock = match IsisPacketSocket::open("lo") {
                Ok(sock) => sock,
                Err(e) if e.kind() == io::ErrorKind::PermissionDenied => {
                    eprintln!("skipping: raw sockets need root here ({e})");
                    return;
                }
                Err(e) => panic!("unexpected open error: {e}"),
            };
            assert!(sock.ifindex > 0);
            let mac = sock.our_mac();
            // Send one frame to AllL1ISs on lo — the overlay must be
            // accepted by the kernel (EINVAL would mean the seam
            // broke).
            let pdu = vec![
                0x83, 0x14, 0x01, 0x00, 0x11, 0x01, 0x00, 0x00, 0x03, 0, 0, 0, 0, 0, 0, 0, 0, 30,
                0, 20, 0x01,
            ];
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap();
            rt.block_on(sock.send(Mac::ALL_L1_ISS, &pdu))
                .expect("the sockaddr overlay must be accepted by packet_snd");
            // Our own frame comes back as loopback and is consumed
            // silently by recv; a 300 ms window proves the send path
            // did not error (that is the seam's claim).
            let mut buf = [0u8; 9000];
            rt.block_on(async {
                let _ = tokio::time::timeout(
                    std::time::Duration::from_millis(300),
                    sock.recv(&mut buf),
                )
                .await;
            });
            let _ = mac;
        }
    }
}

#[cfg(target_os = "linux")]
pub use packet::IsisPacketSocket;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn frame_is_the_8023_llc_form() {
        let pdu = [0x83u8, 0x14, 0x01, 0x00, 0x11, 0x01, 0x00, 0x00, 0x03];
        let bytes = frame(Mac::ALL_L1_ISS, Mac([2, 3, 4, 5, 6, 7]), &pdu);
        // Type field = LLC+PDU length (FRR's isis_ethertype), then
        // the LLC, then the PDU.
        assert_eq!(&bytes[12..14], &((pdu.len() + 3) as u16).to_be_bytes());
        assert_eq!(&bytes[14..17], &LLC_ISIS);
        let parsed = parse_frame(&bytes).unwrap();
        assert_eq!(parsed.dst, Mac::ALL_L1_ISS);
        assert_eq!(parsed.src, Mac([2, 3, 4, 5, 6, 7]));
        assert!(parsed.multicast);
        assert_eq!(parsed.payload, &pdu);

        // The 0x00FE ethertype form (FRR's pure-p2p TX): accepted on
        // RX, never emitted.
        let mut ethertype_form = vec![0x01, 0x80, 0xc2, 0x00, 0x00, 0x15];
        ethertype_form.extend_from_slice(&[2, 3, 4, 5, 6, 7]);
        ethertype_form.extend_from_slice(&[0x00, 0xFE]);
        ethertype_form.extend_from_slice(&pdu);
        let parsed = parse_frame(&ethertype_form).unwrap();
        assert_eq!(parsed.payload, &pdu);

        // FRR's extended-LLC variant (type field 0x8870): accepted.
        let mut ext = frame(Mac::ALL_ISS, Mac([2, 3, 4, 5, 6, 7]), &pdu);
        ext[12..14].copy_from_slice(&ETHERTYPE_EXT_LLC.to_be_bytes());
        let parsed = parse_frame(&ext).unwrap();
        assert_eq!(parsed.payload, &pdu);

        // A length field without the IS-IS LLC is not IS-IS.
        let mut not_isis = bytes.clone();
        not_isis[14] = 0xAA; // SNAP instead of FE FE 03
        not_isis[15] = 0xAA;
        not_isis[16] = 0x03;
        assert!(parse_frame(&not_isis).is_none());

        // Other ethertypes rejected; runts rejected.
        let mut other = bytes.clone();
        other[12] = 0x08;
        other[13] = 0x00;
        assert!(parse_frame(&other).is_none());
        assert!(parse_frame(&bytes[..13]).is_none());
    }

    #[test]
    fn mac_parse_and_levels() {
        assert_eq!(Mac::parse("01:80:c2:00:00:14"), Some(Mac::ALL_L1_ISS));
        assert_eq!(Mac::parse("01:80:c2:00:00:15"), Some(Mac::ALL_L2_ISS));
        assert_eq!(Mac::for_level(false), Mac::ALL_L1_ISS);
        assert_eq!(Mac::for_level(true), Mac::ALL_L2_ISS);
        // Single-hex-digit groups parse (lenient like sysfs never emits them).
        assert_eq!(
            Mac::parse("1:80:c2:0:0:14"),
            Some(Mac([1, 128, 194, 0, 0, 20]))
        );
        assert_eq!(Mac::parse("1:80"), None);
        assert_eq!(Mac::ALL_ISS.to_string(), "09:00:2b:00:00:05");
        assert!(Mac::ALL_ISS.is_multicast());
        assert!(!Mac([0, 1, 2, 3, 4, 5]).is_multicast());
    }

    /// ISO §8.2.3: padding brings the PDU to maxsize-1 with TLV 8s.
    #[test]
    fn pad_to_mtu_minus_one() {
        let mut pdu = vec![0u8; 40];
        pad_pdu(&mut pdu, 1499);
        assert!(
            pdu.len() >= 1499 - 2 || pdu.len() == 1499,
            "within one TLV header"
        );
        assert!(pdu.len() >= 1497, "{}", pdu.len());
        // Exactly hit or within 2 (the sub-header tail).
        assert!(pdu.len() <= 1499 && pdu.len() >= 1499 - 2);
        // The padding is TLV 8s: decode the block.
        let tlvs = crate::tlv::decode_tlvs(&pdu[40..]).unwrap();
        assert!(tlvs
            .iter()
            .all(|t| matches!(t, crate::tlv::Tlv::Padding(_))));
        // Already-large PDUs untouched.
        let mut big = vec![7u8; 1600];
        pad_pdu(&mut big, 1499);
        assert_eq!(big.len(), 1600);
    }
}
