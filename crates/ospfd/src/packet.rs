//! The OSPF packet codecs (RFC 2328 §A.3): the common 24-byte header
//! (§A.3.1) and the five packet types — Hello (§A.3.2), Database
//! Description (§A.3.3), Link State Request (§A.3.4), Link State
//! Update (§A.3.5), Link State Acknowledgment (§A.3.6).
//!
//! Checksums: the packet Checksum field is the standard IP
//! one's-complement sum over everything **except the 64-bit
//! Authentication field** (§A.3.1) — [`internet_checksum`] over
//! bytes `[0..16) + [24..len)` with the field zeroed. That exact
//! convention is verified against 31 real packets in
//! `checksum.rs`'s tests.
//!
//! AF-generic seam (v6): OSPFv3 moves the area ID, AuType and
//! Authentication out of the header (IPv6 instance ID + options
//! replace them) and changes every body except the DD sequencing
//! spine; the type/length/ID framing and the I/M/MS + DD-seq
//! mechanics port as-is.

use std::net::Ipv4Addr;

use crate::checksum::internet_checksum;
use crate::error::OspfError;
use crate::lsa::{LinkStateId, Lsa, LsaHeader, Options, RouterId};
use crate::wire::{put_u16, put_u32, put_u8, Reader};

/// AllSPFRouters (§A.1): 224.0.0.5.
pub const ALL_SPF_ROUTERS: Ipv4Addr = Ipv4Addr::new(224, 0, 0, 5);
/// AllDRouters (§A.1): 224.0.0.6.
pub const ALL_D_ROUTERS: Ipv4Addr = Ipv4Addr::new(224, 0, 0, 6);

/// OSPF is IP protocol 89 (§A.1).
pub const IP_PROTO_OSPF: u8 = 89;

/// The 24-byte common header (§A.3.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PacketHeader {
    /// Version 2.
    pub version: u8,
    /// 1=Hello, 2=DBD, 3=LSR, 4=LSU, 5=LSAck.
    pub packet_type: u8,
    /// Including this header.
    pub length: u16,
    pub router_id: RouterId,
    pub area_id: u32,
    pub checksum: u16,
    /// Authentication type (Appendix D); 0 = Null.
    pub au_type: u16,
    /// The 64-bit Authentication field (excluded from the checksum).
    pub authentication: u64,
}

impl PacketHeader {
    pub const WIRE_SIZE: usize = 24;

    pub fn decode(r: &mut Reader<'_>) -> Result<Self, OspfError> {
        let field = "OSPF packet header";
        let version = r.u8().ok_or(OspfError::Truncated {
            field,
            need: 1,
            have: 0,
        })?;
        if version != 2 {
            return Err(OspfError::BadVersion(version));
        }
        let packet_type = r.u8().ok_or(OspfError::Truncated {
            field,
            need: 1,
            have: 0,
        })?;
        if !(1..=5).contains(&packet_type) {
            return Err(OspfError::BadPacketType(packet_type));
        }
        let length = r.u16().ok_or(OspfError::Truncated {
            field,
            need: 2,
            have: 0,
        })?;
        let router_id = RouterId(r.u32().ok_or(OspfError::Truncated {
            field,
            need: 4,
            have: 0,
        })?);
        let area_id = r.u32().ok_or(OspfError::Truncated {
            field,
            need: 4,
            have: 0,
        })?;
        let checksum = r.u16().ok_or(OspfError::Truncated {
            field,
            need: 2,
            have: 0,
        })?;
        let au_type = r.u16().ok_or(OspfError::Truncated {
            field,
            need: 2,
            have: 0,
        })?;
        let mut auth = [0u8; 8];
        for b in auth.iter_mut() {
            *b = r.u8().ok_or(OspfError::Truncated {
                field,
                need: 1,
                have: 0,
            })?;
        }
        if length < Self::WIRE_SIZE as u16 {
            return Err(OspfError::BadLength {
                field: "packet length",
                declared: length as usize,
                actual: Self::WIRE_SIZE,
            });
        }
        Ok(Self {
            version,
            packet_type,
            length,
            router_id,
            area_id,
            checksum,
            au_type,
            authentication: u64::from_be_bytes(auth),
        })
    }

    pub fn encode(&self, buf: &mut Vec<u8>) {
        put_u8(buf, self.version);
        put_u8(buf, self.packet_type);
        put_u16(buf, self.length);
        put_u32(buf, self.router_id.0);
        put_u32(buf, self.area_id);
        put_u16(buf, self.checksum);
        put_u16(buf, self.au_type);
        buf.extend_from_slice(&self.authentication.to_be_bytes());
    }
}

/// A full decoded packet: header plus typed body.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Packet {
    pub header: PacketHeader,
    pub body: PacketBody,
}

/// The five bodies (§A.3.2-A.3.6).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PacketBody {
    Hello(Hello),
    DbDescription(DbDescription),
    LsRequest(LsRequest),
    LsUpdate(LsUpdate),
    LsAck(LsAck),
}

impl PacketBody {
    pub fn packet_type(&self) -> u8 {
        match self {
            Self::Hello(_) => 1,
            Self::DbDescription(_) => 2,
            Self::LsRequest(_) => 3,
            Self::LsUpdate(_) => 4,
            Self::LsAck(_) => 5,
        }
    }
}

/// The Hello packet (§A.3.2).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Hello {
    pub network_mask: Ipv4Addr,
    pub hello_interval: u16,
    pub options: Options,
    pub router_priority: u8,
    pub router_dead_interval: u32,
    pub designated_router: Ipv4Addr,
    pub backup_designated_router: Ipv4Addr,
    /// Router IDs seen recently — the 2-way check list (§10.5).
    pub neighbors: Vec<RouterId>,
}

/// The Database Description packet (§A.3.3).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DbDescription {
    pub interface_mtu: u16,
    pub options: Options,
    /// I: first in the sequence.
    pub init: bool,
    /// M: more to follow.
    pub more: bool,
    /// MS: sender is master.
    pub master: bool,
    pub dd_sequence: u32,
    /// LSA headers describing the sender's database.
    pub lsa_headers: Vec<LsaHeader>,
}

impl DbDescription {
    /// The flags octet (§A.3.3 diagram: 0|0|0|0|0|I|M|MS).
    fn flags(&self) -> u8 {
        (u8::from(self.init) << 2) | (u8::from(self.more) << 1) | u8::from(self.master)
    }

    fn from_parts(mtu: u16, options: u8, flags: u8, seq: u32, headers: Vec<LsaHeader>) -> Self {
        Self {
            interface_mtu: mtu,
            options: Options(options),
            init: flags & 0x04 != 0,
            more: flags & 0x02 != 0,
            master: flags & 0x01 != 0,
            dd_sequence: seq,
            lsa_headers: headers,
        }
    }
}

/// One entry of a Link State Request (§A.3.4): the (type, LS ID,
/// adv router) triple — note the wire LS type here is a full 32-bit
/// field.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct LsRequestId {
    pub ls_type: u32,
    pub link_state_id: LinkStateId,
    pub adv_router: RouterId,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LsRequest {
    pub requests: Vec<LsRequestId>,
}

/// The Link State Update packet (§A.3.5).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LsUpdate {
    pub lsas: Vec<Lsa>,
}

/// The Link State Acknowledgment packet (§A.3.6): bare LSA headers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LsAck {
    pub headers: Vec<LsaHeader>,
}

impl Packet {
    /// Encode the whole packet: length filled, packet checksum
    /// computed over `[0..16) + [24..)` with the field zeroed.
    pub fn encode(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(64);
        let mut hdr = self.header;
        hdr.packet_type = self.body.packet_type();
        hdr.version = 2;
        hdr.encode(&mut buf);
        self.encode_body(&mut buf);
        let len = buf.len() as u16;
        buf[2..4].copy_from_slice(&len.to_be_bytes());
        if self.header.au_type == 2 {
            // RFC 2328 D.4.3 step 2: in cryptographic-auth mode "the
            // checksum field is not calculated; it is set to zero" —
            // the appended MAC is the integrity check; the caller
            // appends the trailer (auth::encode_for_wire).
            buf[12] = 0;
            buf[13] = 0;
            let _ = &mut hdr;
            return buf;
        }
        // Checksum region: bytes [0..16) then [24..), auth excluded,
        // checksum field zeroed during computation (§A.3.1).
        let mut region = buf[..16].to_vec();
        region[12] = 0;
        region[13] = 0;
        region.extend_from_slice(&buf[24..]);
        let csum = internet_checksum(&region);
        buf[12..14].copy_from_slice(&csum.to_be_bytes());
        let _ = &mut hdr;
        buf
    }

    fn encode_body(&self, buf: &mut Vec<u8>) {
        match &self.body {
            PacketBody::Hello(h) => {
                put_u32(buf, u32::from(h.network_mask));
                put_u16(buf, h.hello_interval);
                put_u8(buf, h.options.0);
                put_u8(buf, h.router_priority);
                put_u32(buf, h.router_dead_interval);
                put_u32(buf, u32::from(h.designated_router));
                put_u32(buf, u32::from(h.backup_designated_router));
                for n in &h.neighbors {
                    put_u32(buf, n.0);
                }
            }
            PacketBody::DbDescription(d) => {
                // §A.3.3: MTU(2) + Options(1) + I/M/MS(1) + DD
                // sequence(4) — NO padding octets (the Day-1 pad was
                // a wire bug FRR 10.2.2 caught: "undersized (2 B)
                // trailing LSA header").
                put_u16(buf, d.interface_mtu);
                put_u8(buf, d.options.0);
                put_u8(buf, d.flags());
                put_u32(buf, d.dd_sequence);
                for h in &d.lsa_headers {
                    h.encode(buf);
                }
            }
            PacketBody::LsRequest(q) => {
                for r in &q.requests {
                    put_u32(buf, r.ls_type);
                    put_u32(buf, r.link_state_id.0);
                    put_u32(buf, r.adv_router.0);
                }
            }
            PacketBody::LsUpdate(u) => {
                put_u32(buf, u.lsas.len() as u32);
                for lsa in &u.lsas {
                    buf.extend_from_slice(&lsa.encode());
                }
            }
            PacketBody::LsAck(a) => {
                for h in &a.headers {
                    h.encode(buf);
                }
            }
        }
    }

    /// Decode and validate a whole packet: header framing (length ==
    /// buffer), checksum verification, body parsing with exact count
    /// arithmetic, and type agreement between header and body.
    pub fn decode(buf: &[u8]) -> Result<Self, OspfError> {
        let mut r = Reader::new(buf);
        let header = PacketHeader::decode(&mut r)?;
        if header.length as usize != buf.len() {
            return Err(OspfError::BadLength {
                field: "packet length",
                declared: header.length as usize,
                actual: buf.len(),
            });
        }
        // §A.3.1 checksum verification.
        let mut region = buf[..16].to_vec();
        region[12] = 0;
        region[13] = 0;
        region.extend_from_slice(&buf[24..]);
        let computed = internet_checksum(&region);
        if computed != header.checksum {
            return Err(OspfError::ChecksumMismatch {
                header: header.checksum,
                computed,
            });
        }
        let body = match header.packet_type {
            1 => PacketBody::Hello(Self::decode_hello(&mut r)?),
            2 => PacketBody::DbDescription(Self::decode_dbd(&mut r)?),
            3 => PacketBody::LsRequest(Self::decode_lsr(&mut r)?),
            4 => PacketBody::LsUpdate(Self::decode_lsu(&mut r, buf)?),
            5 => PacketBody::LsAck(Self::decode_lsack(&mut r)?),
            other => return Err(OspfError::BadPacketType(other)),
        };
        if !r.is_empty() {
            return Err(OspfError::Trailing {
                field: "packet body",
                count: r.remaining(),
            });
        }
        Ok(Self { header, body })
    }

    /// Decode a cryptographic-auth packet (AuType 2, RFC 2328
    /// D.5.3): the OSPF packet proper runs to `header.length`, the
    /// appended digest trailer follows (RFC 5709 §3.1: not counted
    /// in the OSPF packet's own Length field, but included in the
    /// IP Length field). The checksum is NOT verified (D.4.3(2)
    /// leaves it 0); MAC verification is the caller's D.5.3(3).
    /// Returns the packet and the trailer bytes.
    pub fn decode_crypto(buf: &[u8]) -> Result<(Self, Vec<u8>), OspfError> {
        let mut r = Reader::new(buf);
        let header = PacketHeader::decode(&mut r)?;
        if header.au_type != 2 {
            return Err(OspfError::Config(format!(
                "decode_crypto on AuType {au}",
                au = header.au_type
            )));
        }
        if header.length as usize > buf.len() {
            return Err(OspfError::BadLength {
                field: "packet length",
                declared: header.length as usize,
                actual: buf.len(),
            });
        }
        let trailer = buf[header.length as usize..].to_vec();
        let body_buf = &buf[..header.length as usize];
        let mut br = Reader::new(body_buf);
        // Walk the 24-byte header fields.
        for _ in 0..6 {
            let _ = br.u32();
        }
        let body = match header.packet_type {
            1 => PacketBody::Hello(Self::decode_hello(&mut br)?),
            2 => PacketBody::DbDescription(Self::decode_dbd(&mut br)?),
            3 => PacketBody::LsRequest(Self::decode_lsr(&mut br)?),
            4 => PacketBody::LsUpdate(Self::decode_lsu(&mut br, body_buf)?),
            5 => PacketBody::LsAck(Self::decode_lsack(&mut br)?),
            other => return Err(OspfError::BadPacketType(other)),
        };
        if !br.is_empty() {
            return Err(OspfError::Trailing {
                field: "packet body",
                count: br.remaining(),
            });
        }
        Ok((Self { header, body }, trailer))
    }

    fn decode_hello(r: &mut Reader<'_>) -> Result<Hello, OspfError> {
        let field = "Hello body";
        let need = |r: &Reader<'_>, n: usize| OspfError::Truncated {
            field,
            need: n,
            have: r.remaining(),
        };
        let network_mask = Ipv4Addr::from(r.u32().ok_or_else(|| need(r, 4))?);
        let hello_interval = r.u16().ok_or_else(|| need(r, 2))?;
        let options = Options(r.u8().ok_or_else(|| need(r, 1))?);
        let router_priority = r.u8().ok_or_else(|| need(r, 1))?;
        let router_dead_interval = r.u32().ok_or_else(|| need(r, 4))?;
        let designated_router = Ipv4Addr::from(r.u32().ok_or_else(|| need(r, 4))?);
        let backup_designated_router = Ipv4Addr::from(r.u32().ok_or_else(|| need(r, 4))?);
        let mut neighbors = Vec::new();
        while !r.is_empty() {
            let id = r.u32().ok_or_else(|| need(r, 4))?;
            neighbors.push(RouterId(id));
        }
        Ok(Hello {
            network_mask,
            hello_interval,
            options,
            router_priority,
            router_dead_interval,
            designated_router,
            backup_designated_router,
            neighbors,
        })
    }

    fn decode_dbd(r: &mut Reader<'_>) -> Result<DbDescription, OspfError> {
        let field = "DBD body";
        let need = |r: &Reader<'_>, n: usize| OspfError::Truncated {
            field,
            need: n,
            have: r.remaining(),
        };
        let interface_mtu = r.u16().ok_or_else(|| need(r, 2))?;
        let options = Options(r.u8().ok_or_else(|| need(r, 1))?);
        let flags = r.u8().ok_or_else(|| need(r, 1))?;
        if flags & 0xf8 != 0 {
            return Err(OspfError::ReservedBits {
                field: "DBD flags",
                value: flags,
            });
        }
        let dd_sequence = r.u32().ok_or_else(|| need(r, 4))?;
        let mut headers = Vec::new();
        while !r.is_empty() {
            headers.push(LsaHeader::decode(r)?);
        }
        Ok(DbDescription::from_parts(
            interface_mtu,
            options.0,
            flags,
            dd_sequence,
            headers,
        ))
    }

    fn decode_lsr(r: &mut Reader<'_>) -> Result<LsRequest, OspfError> {
        let field = "LSR body";
        let mut requests = Vec::new();
        while !r.is_empty() {
            if r.remaining() < 12 {
                return Err(OspfError::Truncated {
                    field,
                    need: 12,
                    have: r.remaining(),
                });
            }
            let ls_type = r.u32().expect("checked");
            let link_state_id = LinkStateId(r.u32().expect("checked"));
            let adv_router = RouterId(r.u32().expect("checked"));
            requests.push(LsRequestId {
                ls_type,
                link_state_id,
                adv_router,
            });
        }
        Ok(LsRequest { requests })
    }

    fn decode_lsu(r: &mut Reader<'_>, buf: &[u8]) -> Result<LsUpdate, OspfError> {
        let field = "LSU body";
        let count = r.u32().ok_or(OspfError::Truncated {
            field,
            need: 4,
            have: 0,
        })? as usize;
        let mut lsas = Vec::with_capacity(count.min(1024));
        for _ in 0..count {
            // Each LSA's extent comes from its own header length; the
            // count must not overrun the packet (A19).
            let mut probe = Reader::new(r.peek_remaining());
            let hdr = LsaHeader::decode(&mut probe)?;
            if hdr.length as usize > r.remaining() {
                return Err(OspfError::BadLength {
                    field: "LSA length in LSU",
                    declared: hdr.length as usize,
                    actual: r.remaining(),
                });
            }
            let take = r.take(hdr.length as usize).expect("bounds checked above");
            lsas.push(Lsa::decode(take)?);
            let _ = buf;
        }
        Ok(LsUpdate { lsas })
    }

    fn decode_lsack(r: &mut Reader<'_>) -> Result<LsAck, OspfError> {
        let mut headers = Vec::new();
        while !r.is_empty() {
            headers.push(LsaHeader::decode(r)?);
        }
        Ok(LsAck { headers })
    }
}

/// Test/codec helpers: encode an LSA and re-read its header with the
/// checksum/length filled in (the DBD/LSAck representation), and the
/// same normalization for whole-LSA comparisons.
impl Lsa {
    #[cfg(test)]
    pub fn encode_then_header(&self) -> LsaHeader {
        let bytes = self.encode();
        Lsa::decode_header(&bytes[..LsaHeader::WIRE_SIZE]).unwrap()
    }

    #[cfg(test)]
    pub fn with_computed_header(&self) -> Lsa {
        let bytes = self.encode();
        Lsa::decode(&bytes).expect("re-encode must decode")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::lsa::{LinkType, LsaBody, LsaType, RouterLink, RouterLsa, INITIAL_SEQUENCE_NUMBER};
    use crate::wire::unhex;

    fn hdr(router_id: &str, packet_type: u8) -> PacketHeader {
        PacketHeader {
            version: 2,
            packet_type,
            length: 0,
            router_id: RouterId::from_ipv4(router_id.parse().unwrap()),
            area_id: 0,
            checksum: 0,
            au_type: 0,
            authentication: 0,
        }
    }

    #[test]
    fn real_hello_round_trips_and_verifies() {
        // The real-capture Hello (checksum 0x273b): mask /24, interval
        // 10, options E, priority 1, dead 40, DR 192.168.170.8, BDR
        // 0.0.0.0, no neighbors.
        let bytes = unhex(
            "0201002cc0a8aa0800000001273b00000000000000000000\
             ffffff00000a020100000028c0a8aa0800000000",
        );
        let pkt = Packet::decode(&bytes).unwrap();
        let PacketBody::Hello(ref h) = pkt.body else {
            panic!()
        };
        assert_eq!(h.network_mask, "255.255.255.0".parse::<Ipv4Addr>().unwrap());
        assert_eq!(h.hello_interval, 10);
        assert!(h.options.e_bit());
        assert_eq!(h.router_priority, 1);
        assert_eq!(h.router_dead_interval, 40);
        assert_eq!(
            h.designated_router,
            "192.168.170.8".parse::<Ipv4Addr>().unwrap()
        );
        assert_eq!(h.backup_designated_router, Ipv4Addr::UNSPECIFIED);
        assert!(h.neighbors.is_empty());
        assert_eq!(pkt.encode(), bytes, "byte-exact round trip");
    }

    /// Encode fills the header's length/checksum (and inner LSA
    /// headers' checksum/length); compare modulo those.
    fn with_computed_header(mut pkt: Packet) -> Packet {
        let bytes = pkt.encode();
        pkt.header.length = u16::from_be_bytes([bytes[2], bytes[3]]);
        pkt.header.checksum = u16::from_be_bytes([bytes[12], bytes[13]]);
        if let PacketBody::LsUpdate(u) = &mut pkt.body {
            for lsa in &mut u.lsas {
                *lsa = lsa.with_computed_header();
            }
        }
        pkt
    }

    #[test]
    fn hello_with_neighbors_round_trips() {
        // §10.5's 2-way check: the neighbor list is what drives
        // TwoWayReceived/OneWayReceived.
        let pkt = Packet {
            header: hdr("1.1.1.1", 1),
            body: PacketBody::Hello(Hello {
                network_mask: "255.255.255.0".parse().unwrap(),
                hello_interval: 10,
                options: Options(0x02),
                router_priority: 0,
                router_dead_interval: 40,
                designated_router: Ipv4Addr::UNSPECIFIED,
                backup_designated_router: Ipv4Addr::UNSPECIFIED,
                neighbors: vec![
                    RouterId::from_ipv4("2.2.2.2".parse().unwrap()),
                    RouterId::from_ipv4("3.3.3.3".parse().unwrap()),
                ],
            }),
        };
        let bytes = pkt.encode();
        assert_eq!(bytes.len(), 24 + 20 + 8);
        let back = Packet::decode(&bytes).unwrap();
        assert_eq!(back, with_computed_header(pkt));
    }

    fn sample_lsa() -> Lsa {
        Lsa {
            header: LsaHeader {
                ls_age: 1,
                options: Options(0x02),
                ls_type: LsaType::ROUTER,
                link_state_id: LinkStateId::from_ipv4("1.1.1.1".parse().unwrap()),
                adv_router: RouterId::from_ipv4("1.1.1.1".parse().unwrap()),
                seq: INITIAL_SEQUENCE_NUMBER,
                checksum: 0,
                length: 0,
            },
            body: LsaBody::Router(RouterLsa {
                v_bit: false,
                e_bit: true,
                b_bit: false,
                nt_bit: false,
                links: vec![RouterLink {
                    link_id: LinkStateId::from_ipv4("10.0.0.2".parse().unwrap()),
                    link_data: u32::from("10.0.0.1".parse::<Ipv4Addr>().unwrap()),
                    link_type: LinkType::PointToPoint,
                    metric: 5,
                    tos: vec![],
                }],
            }),
        }
    }

    #[test]
    fn dbd_empty_exstart_is_exactly_32_bytes() {
        // §A.3.3 with no LSA headers: 24-byte common header + 8-byte
        // DBD preamble (MTU, options, flags, sequence) — no padding.
        // Pinned by FRR 10.2.2's own "Packet Len 32" dump and its
        // "undersized (2 B) trailing" rejection of the padded form
        // (the Day-1 wire bug the interop caught).
        let dd = DbDescription {
            interface_mtu: 1500,
            options: Options(0x02),
            init: true,
            more: true,
            master: true,
            dd_sequence: 0x3879fa0b,
            lsa_headers: vec![],
        };
        let packet = Packet {
            header: PacketHeader {
                version: 2,
                packet_type: 2,
                length: 0,
                router_id: RouterId::from_ipv4("10.255.1.1".parse().unwrap()),
                area_id: 0,
                checksum: 0,
                au_type: 0,
                authentication: 0,
            },
            body: PacketBody::DbDescription(dd),
        };
        let bytes = packet.encode();
        assert_eq!(bytes.len(), 32, "no pad octets in the DD preamble");
        let back = Packet::decode(&bytes).unwrap();
        assert_eq!(back.body, packet.body);
        assert_eq!(back.header.router_id, packet.header.router_id);
        assert_eq!(back.header.length, 32);
    }

    #[test]
    fn dbd_flags_and_headers_round_trip() {
        // The §A.3.3 flags octet: 0|0|0|0|0|I|M|MS.
        let d = DbDescription {
            interface_mtu: 1500,
            options: Options(0x02),
            init: true,
            more: true,
            master: true,
            dd_sequence: 0x1234,
            lsa_headers: vec![sample_lsa().encode_then_header()],
        };
        let pkt = Packet {
            header: hdr("1.1.1.1", 2),
            body: PacketBody::DbDescription(d),
        };
        let bytes = pkt.encode();
        assert_eq!(bytes[24 + 2 + 1], 0x07, "I|M|MS all set");
        let back = Packet::decode(&bytes).unwrap();
        assert_eq!(back, with_computed_header(pkt));
    }

    #[test]
    fn lsr_lsu_lsack_round_trip() {
        let lsa = sample_lsa();
        let lsa_bytes = lsa.encode();
        let lsa_hdr = Lsa::decode_header(&lsa_bytes[..LsaHeader::WIRE_SIZE]).unwrap();

        let lsr = Packet {
            header: hdr("2.2.2.2", 3),
            body: PacketBody::LsRequest(LsRequest {
                requests: vec![LsRequestId {
                    ls_type: 1,
                    link_state_id: LinkStateId::from_ipv4("1.1.1.1".parse().unwrap()),
                    adv_router: RouterId::from_ipv4("1.1.1.1".parse().unwrap()),
                }],
            }),
        };
        assert_eq!(
            Packet::decode(&lsr.encode()).unwrap(),
            with_computed_header(lsr)
        );

        let lsu = Packet {
            header: hdr("2.2.2.2", 4),
            body: PacketBody::LsUpdate(LsUpdate {
                lsas: vec![lsa.clone()],
            }),
        };
        let encoded = lsu.encode();
        let back = Packet::decode(&encoded).unwrap();
        assert_eq!(back, with_computed_header(lsu));
        let PacketBody::LsUpdate(u) = back.body else {
            unreachable!()
        };
        assert_eq!(u.lsas[0].encode(), lsa_bytes);

        let ack = Packet {
            header: hdr("2.2.2.2", 5),
            body: PacketBody::LsAck(LsAck {
                headers: vec![lsa_hdr],
            }),
        };
        assert_eq!(
            Packet::decode(&ack.encode()).unwrap(),
            with_computed_header(ack)
        );
    }

    #[test]
    fn packet_checksum_corruption_detected() {
        let pkt = Packet {
            header: hdr("1.1.1.1", 1),
            body: PacketBody::Hello(Hello {
                network_mask: "255.255.255.0".parse().unwrap(),
                hello_interval: 10,
                options: Options(0x02),
                router_priority: 1,
                router_dead_interval: 40,
                designated_router: Ipv4Addr::UNSPECIFIED,
                backup_designated_router: Ipv4Addr::UNSPECIFIED,
                neighbors: vec![],
            }),
        };
        let mut bytes = pkt.encode();
        bytes[28] ^= 0x01; // flip a body bit
        assert!(matches!(
            Packet::decode(&bytes).unwrap_err(),
            OspfError::ChecksumMismatch { .. }
        ));
        // Flipping only the auth field is undetectable by design.
        let mut bytes = pkt.encode();
        bytes[20] ^= 0xff;
        assert!(Packet::decode(&bytes).is_ok());
    }

    #[test]
    fn every_truncation_rejected() {
        let pkt = Packet {
            header: hdr("1.1.1.1", 1),
            body: PacketBody::Hello(Hello {
                network_mask: "255.255.255.0".parse().unwrap(),
                hello_interval: 10,
                options: Options(0x02),
                router_priority: 1,
                router_dead_interval: 40,
                designated_router: Ipv4Addr::UNSPECIFIED,
                backup_designated_router: Ipv4Addr::UNSPECIFIED,
                neighbors: vec![RouterId::from_ipv4("9.9.9.9".parse().unwrap())],
            }),
        };
        let bytes = pkt.encode();
        for cut in 0..bytes.len() {
            assert!(Packet::decode(&bytes[..cut]).is_err(), "cut {cut}");
        }
        // Length mismatch in an intact buffer.
        let mut bad = bytes.clone();
        bad[2..4].copy_from_slice(&((bytes.len() - 1) as u16).to_be_bytes());
        let mut region = bad[..16].to_vec();
        region[12] = 0;
        region[13] = 0;
        region.extend_from_slice(&bad[24..]);
        let c = internet_checksum(&region);
        bad[12..14].copy_from_slice(&c.to_be_bytes());
        assert!(matches!(
            Packet::decode(&bad).unwrap_err(),
            OspfError::BadLength { .. }
        ));
    }

    #[test]
    fn bad_version_and_type_rejected() {
        let mut bytes = Packet {
            header: hdr("1.1.1.1", 1),
            body: PacketBody::Hello(Hello {
                network_mask: "255.255.255.0".parse().unwrap(),
                hello_interval: 10,
                options: Options(0x02),
                router_priority: 1,
                router_dead_interval: 40,
                designated_router: Ipv4Addr::UNSPECIFIED,
                backup_designated_router: Ipv4Addr::UNSPECIFIED,
                neighbors: vec![],
            }),
        }
        .encode();
        bytes[0] = 3;
        let mut region = bytes[..16].to_vec();
        region[12] = 0;
        region[13] = 0;
        region.extend_from_slice(&bytes[24..]);
        let c = internet_checksum(&region);
        bytes[12..14].copy_from_slice(&c.to_be_bytes());
        assert_eq!(
            Packet::decode(&bytes).unwrap_err(),
            OspfError::BadVersion(3)
        );

        let mut bytes2 = bytes.clone();
        bytes2[0] = 2;
        bytes2[1] = 9;
        let mut region = bytes2[..16].to_vec();
        region[12] = 0;
        region[13] = 0;
        region.extend_from_slice(&bytes2[24..]);
        let c = internet_checksum(&region);
        bytes2[12..14].copy_from_slice(&c.to_be_bytes());
        assert_eq!(
            Packet::decode(&bytes2).unwrap_err(),
            OspfError::BadPacketType(9)
        );
    }

    #[test]
    fn lsu_count_overrun_rejected() {
        // #LSAs claims 2 but only one LSA fits (A19: never trust
        // counts).
        let lsa = sample_lsa();
        let mut pkt = Packet {
            header: hdr("2.2.2.2", 4),
            body: PacketBody::LsUpdate(LsUpdate { lsas: vec![lsa] }),
        }
        .encode();
        pkt[24..28].copy_from_slice(&2u32.to_be_bytes());
        // Repair the packet checksum so we reach the count logic.
        let mut region = pkt[..16].to_vec();
        region[12] = 0;
        region[13] = 0;
        region.extend_from_slice(&pkt[24..]);
        let c = internet_checksum(&region);
        pkt[12..14].copy_from_slice(&c.to_be_bytes());
        let plen = pkt.len() as u16;
        pkt[2..4].copy_from_slice(&plen.to_be_bytes());
        let mut region = pkt[..16].to_vec();
        region[12] = 0;
        region[13] = 0;
        region.extend_from_slice(&pkt[24..]);
        let c = internet_checksum(&region);
        pkt[12..14].copy_from_slice(&c.to_be_bytes());
        assert!(Packet::decode(&pkt).is_err());
        let _ = &mut pkt;
    }

    #[test]
    fn multicast_constants() {
        assert_eq!(ALL_SPF_ROUTERS, "224.0.0.5".parse::<Ipv4Addr>().unwrap());
        assert_eq!(ALL_D_ROUTERS, "224.0.0.6".parse::<Ipv4Addr>().unwrap());
        assert_eq!(IP_PROTO_OSPF, 89);
    }
}
