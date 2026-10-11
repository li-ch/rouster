//! The OSPFv3 packet codecs (RFC 5340 Appendix A.3): the 16-byte
//! common header (§A.3.1) and the five packet types — Hello (§A.3.2),
//! Database Description (§A.3.3), Link State Request (§A.3.4), Link
//! State Update (§A.3.5), Link State Acknowledgment (§A.3.6).
//!
//! N2B ladder scope: **codecs only** — no v6 sockets, no instance-ID
//! dispatch (the Instance ID is decoded and carried; equality
//! matching is interface-layer, §A.3.1), no ff02::5/6 constants.
//!
//! The checksum is a *different animal* from v2's: the standard IPv6
//! upper-layer checksum — the 16-bit one's complement of the one's
//! complement sum of the **entire packet** (header included, nothing
//! excluded) prepended with the IPv6 pseudo-header of RFC 8200 §8.1
//! (src, dst, Upper-Layer Packet Length = the OSPF header's length
//! field, Next Header = 89). The source and destination addresses
//! are therefore *codec inputs*: [`PacketV3::encode`] takes
//! `(src, dst)` and [`PacketV3::decode`] verifies against them —
//! the transport will supply the real socket addresses later.
//!
//! Shared with v2 (the AF-generic spine): the 1-5 packet-type
//! numbering, the framing/length-exactness discipline, the DBD
//! I/M/MS + DD-sequence mechanics, the LSR 12-byte entry size (the
//! remaining-bytes < 12 → truncated arithmetic), the LSU
//! count + per-LSA length-probe loop (the A19 lesson) and the
//! bare-header LSAck shape.

use std::net::Ipv6Addr;

use crate::checksum::internet_checksum;
use crate::error::OspfError;
use crate::lsa::{LinkStateId, LsaType, RouterId};
use crate::lsa_v3::{LsaHeaderV3, LsaV3, Options24};
use crate::wire::{put_u16, put_u32, put_u8, Reader};

/// The 16-byte OSPFv3 common header (RFC 5340 A.3.1): Version(1)=3 |
/// Type(1) | Packet length(2) | Router ID(4) | Area ID(4) |
/// Checksum(2) | Instance ID(1) | 0(1). The Area ID stays; the v2
/// AuType/Authentication fields are gone (auth moved to IPsec/AH —
/// RFC 4552 lineage; neither is in tonight's scope).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PacketHeaderV3 {
    pub version: u8,
    /// 1=Hello, 2=DBD, 3=LSR, 4=LSU, 5=LSAck (same table as v2).
    pub packet_type: u8,
    /// Including this header.
    pub length: u16,
    pub router_id: RouterId,
    pub area_id: u32,
    pub checksum: u16,
    /// Multiple OSPFv3 instances may share a link; received packets
    /// whose Instance ID differs from the interface's are discarded
    /// (A.3.1). Decoded and carried only — matching is
    /// interface-layer.
    pub instance_id: u8,
}

impl PacketHeaderV3 {
    pub const WIRE_SIZE: usize = 16;

    pub fn decode(r: &mut Reader<'_>) -> Result<Self, OspfError> {
        let field = "OSPFv3 packet header";
        let version = r.u8().ok_or(OspfError::Truncated {
            field,
            need: 1,
            have: 0,
        })?;
        if version != 3 {
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
        let instance_id = r.u8().ok_or(OspfError::Truncated {
            field,
            need: 1,
            have: 0,
        })?;
        // The trailing reserved octet: "SHOULD be set to 0 when
        // sending ... MUST be ignored when receiving" (A.3.1) —
        // read and discarded.
        let _reserved = r.u8().ok_or(OspfError::Truncated {
            field,
            need: 1,
            have: 0,
        })?;
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
            instance_id,
        })
    }

    pub fn encode(&self, buf: &mut Vec<u8>) {
        put_u8(buf, self.version);
        put_u8(buf, self.packet_type);
        put_u16(buf, self.length);
        put_u32(buf, self.router_id.0);
        put_u32(buf, self.area_id);
        put_u16(buf, self.checksum);
        put_u8(buf, self.instance_id);
        put_u8(buf, 0); // the reserved octet (SHOULD 0, A.3.1)
    }
}

/// A decoded OSPFv3 packet: header plus typed body.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PacketV3 {
    pub header: PacketHeaderV3,
    pub body: PacketBodyV3,
}

/// The five bodies (RFC 5340 A.3.2-A.3.6) — the same five-type
/// numbering as v2 with v3-shaped fields.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PacketBodyV3 {
    Hello(HelloV3),
    DbDescription(DbDescriptionV3),
    LsRequest(LsRequestV3),
    LsUpdate(LsUpdateV3),
    LsAck(LsAckV3),
}

impl PacketBodyV3 {
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

/// The OSPFv3 Hello packet (A.3.2): Interface ID, Rtr Priority +
/// 24-bit Options, HelloInterval, RouterDeadInterval (16 bits here,
/// not v2's 32), DR/BDR as **Router IDs** (v3 neighbors are always
/// identified by Router ID, §2.11), then the seen-neighbor IDs. No
/// Network Mask — the per-link (not per-subnet) model, §2.1.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HelloV3 {
    /// 32-bit interface identifier (e.g. the MIB-II ifIndex).
    pub interface_id: u32,
    pub router_priority: u8,
    pub options: Options24,
    pub hello_interval: u16,
    pub router_dead_interval: u16,
    pub designated_router: RouterId,
    pub backup_designated_router: RouterId,
    /// Router IDs seen recently — the 2-way check list (§10.5
    /// lineage via [OSPFV2]).
    pub neighbors: Vec<RouterId>,
}

/// The OSPFv3 Database Description packet (A.3.3): a 12-byte
/// preamble — the reserved-octet + 24-bit Options word, Interface
/// MTU, the 0(5)|I|M|MS flags octet, the DD sequence number — then
/// bare 20-byte LSA headers. The I/M/MS + DD-sequence spine is
/// byte-identical in spirit to v2 (and keeps the no-padding lesson:
/// there are exactly 12 preamble bytes, none spurious).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DbDescriptionV3 {
    pub interface_mtu: u16,
    pub options: Options24,
    /// I: first in the sequence.
    pub init: bool,
    /// M: more to follow.
    pub more: bool,
    /// MS: sender is master.
    pub master: bool,
    pub dd_sequence: u32,
    pub lsa_headers: Vec<LsaHeaderV3>,
}

impl DbDescriptionV3 {
    /// The flags octet (A.3.3 diagram: 0|0|0|0|0|I|M|MS).
    fn flags(&self) -> u8 {
        (u8::from(self.init) << 2) | (u8::from(self.more) << 1) | u8::from(self.master)
    }
}

/// One Link State Request entry (A.3.4): 12 bytes — 16 reserved
/// bits, the 16-bit v3 LS type, the Link State ID and the
/// Advertising Router. Same entry size as v2's 32-bit-type form.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct LsRequestV3Entry {
    pub ls_type: LsaType,
    pub link_state_id: LinkStateId,
    pub adv_router: RouterId,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LsRequestV3 {
    pub requests: Vec<LsRequestV3Entry>,
}

/// The OSPFv3 Link State Update packet (A.3.5): the # LSAs count
/// then the LSAs, each extent from its own header length (the A19
/// length probe, unchanged from v2).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LsUpdateV3 {
    pub lsas: Vec<LsaV3>,
}

/// The OSPFv3 Link State Acknowledgment packet (A.3.6): bare LSA
/// headers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LsAckV3 {
    pub headers: Vec<LsaHeaderV3>,
}

/// Build the IPv6 pseudo-header (RFC 8200 §8.1, as incorporated by
/// A.3.1): src(16) | dst(16) | Upper-Layer Packet Length(4) | zero
/// (3) | Next Header 89(1).
fn pseudo_header(src: Ipv6Addr, dst: Ipv6Addr, ospf_length: u16) -> Vec<u8> {
    let mut pseudo = Vec::with_capacity(40);
    pseudo.extend_from_slice(&src.octets());
    pseudo.extend_from_slice(&dst.octets());
    put_u32(&mut pseudo, ospf_length as u32);
    put_u8(&mut pseudo, 0);
    put_u8(&mut pseudo, 0);
    put_u8(&mut pseudo, 0);
    put_u8(&mut pseudo, crate::packet::IP_PROTO_OSPF);
    pseudo
}

/// The OSPFv3 packet checksum over the whole packet (checksum field
/// zeroed) prepended with the pseudo-header. The pseudo-header is 40
/// bytes, so the packet's checksum field (packet offset 12) sits at
/// region offset 52.
fn v3_checksum(buf: &[u8], src: Ipv6Addr, dst: Ipv6Addr) -> u16 {
    let mut region = pseudo_header(src, dst, u16::from_be_bytes([buf[2], buf[3]]));
    region.extend_from_slice(buf);
    region[40 + 12] = 0;
    region[40 + 13] = 0;
    internet_checksum(&region)
}

impl PacketV3 {
    /// Encode the whole packet: length filled, version forced to 3,
    /// checksum computed over the entire packet plus the IPv6
    /// pseudo-header built from `(src, dst)` (A.3.1).
    pub fn encode(&self, src: Ipv6Addr, dst: Ipv6Addr) -> Vec<u8> {
        let mut buf = Vec::with_capacity(64);
        let mut hdr = self.header;
        hdr.packet_type = self.body.packet_type();
        hdr.version = 3;
        hdr.encode(&mut buf);
        self.encode_body(&mut buf);
        let len = buf.len() as u16;
        buf[2..4].copy_from_slice(&len.to_be_bytes());
        let csum = v3_checksum(&buf, src, dst);
        buf[12..14].copy_from_slice(&csum.to_be_bytes());
        buf
    }

    fn encode_body(&self, buf: &mut Vec<u8>) {
        match &self.body {
            PacketBodyV3::Hello(h) => {
                put_u32(buf, h.interface_id);
                put_u8(buf, h.router_priority);
                h.options.put(buf);
                put_u16(buf, h.hello_interval);
                put_u16(buf, h.router_dead_interval);
                put_u32(buf, h.designated_router.0);
                put_u32(buf, h.backup_designated_router.0);
                for n in &h.neighbors {
                    put_u32(buf, n.0);
                }
            }
            PacketBodyV3::DbDescription(d) => {
                // A.3.3's three 4-byte rows: 0(1)+Options(3), then
                // MTU(2) + 0(1) + 0(5bits)|I|M|MS(1), then the DD
                // sequence — exactly 12 preamble bytes, none spurious
                // (the Day-1 v2 lesson at v3's different size).
                put_u8(buf, 0);
                d.options.put(buf);
                put_u16(buf, d.interface_mtu);
                put_u8(buf, 0);
                put_u8(buf, d.flags());
                put_u32(buf, d.dd_sequence);
                for h in &d.lsa_headers {
                    h.encode(buf);
                }
            }
            PacketBodyV3::LsRequest(q) => {
                for rq in &q.requests {
                    put_u16(buf, 0); // the reserved halfword
                    put_u16(buf, rq.ls_type.0);
                    put_u32(buf, rq.link_state_id.0);
                    put_u32(buf, rq.adv_router.0);
                }
            }
            PacketBodyV3::LsUpdate(u) => {
                put_u32(buf, u.lsas.len() as u32);
                for lsa in &u.lsas {
                    buf.extend_from_slice(&lsa.encode());
                }
            }
            PacketBodyV3::LsAck(a) => {
                for h in &a.headers {
                    h.encode(buf);
                }
            }
        }
    }

    /// Decode and validate a whole OSPFv3 packet: header framing
    /// (length == buffer), the pseudo-header checksum against
    /// `(src, dst)`, body parsing with exact count arithmetic, and
    /// type agreement between header and body.
    pub fn decode(buf: &[u8], src: Ipv6Addr, dst: Ipv6Addr) -> Result<Self, OspfError> {
        let mut r = Reader::new(buf);
        let header = PacketHeaderV3::decode(&mut r)?;
        if header.length as usize != buf.len() {
            return Err(OspfError::BadLength {
                field: "packet length",
                declared: header.length as usize,
                actual: buf.len(),
            });
        }
        // A.3.1 checksum verification: entire packet + pseudo-header.
        let computed = v3_checksum(buf, src, dst);
        if computed != header.checksum {
            return Err(OspfError::ChecksumMismatch {
                header: header.checksum,
                computed,
            });
        }
        let body = match header.packet_type {
            1 => PacketBodyV3::Hello(Self::decode_hello(&mut r)?),
            2 => PacketBodyV3::DbDescription(Self::decode_dbd(&mut r)?),
            3 => PacketBodyV3::LsRequest(Self::decode_lsr(&mut r)?),
            4 => PacketBodyV3::LsUpdate(Self::decode_lsu(&mut r)?),
            5 => PacketBodyV3::LsAck(Self::decode_lsack(&mut r)?),
            other => return Err(OspfError::BadPacketType(other)),
        };
        if !r.is_empty() {
            return Err(OspfError::Trailing {
                field: "OSPFv3 packet body",
                count: r.remaining(),
            });
        }
        Ok(Self { header, body })
    }

    fn decode_hello(r: &mut Reader<'_>) -> Result<HelloV3, OspfError> {
        let field = "Hello(v3) body";
        let need = |r: &Reader<'_>, n: usize| OspfError::Truncated {
            field,
            need: n,
            have: r.remaining(),
        };
        let interface_id = r.u32().ok_or_else(|| need(r, 4))?;
        let router_priority = r.u8().ok_or_else(|| need(r, 1))?;
        let options = Options24::read(r, field)?;
        let hello_interval = r.u16().ok_or_else(|| need(r, 2))?;
        let router_dead_interval = r.u16().ok_or_else(|| need(r, 2))?;
        let designated_router = RouterId(r.u32().ok_or_else(|| need(r, 4))?);
        let backup_designated_router = RouterId(r.u32().ok_or_else(|| need(r, 4))?);
        let mut neighbors = Vec::new();
        while !r.is_empty() {
            let id = r.u32().ok_or_else(|| need(r, 4))?;
            neighbors.push(RouterId(id));
        }
        Ok(HelloV3 {
            interface_id,
            router_priority,
            options,
            hello_interval,
            router_dead_interval,
            designated_router,
            backup_designated_router,
            neighbors,
        })
    }

    fn decode_dbd(r: &mut Reader<'_>) -> Result<DbDescriptionV3, OspfError> {
        let field = "DBD(v3) body";
        let need = |r: &Reader<'_>, n: usize| OspfError::Truncated {
            field,
            need: n,
            have: r.remaining(),
        };
        let reserved = r.u8().ok_or_else(|| need(r, 1))?;
        if reserved != 0 {
            return Err(OspfError::ReservedBits {
                field: "DBD(v3) options word",
                value: reserved,
            });
        }
        let options = Options24::read(r, field)?;
        let interface_mtu = r.u16().ok_or_else(|| need(r, 2))?;
        let reserved = r.u8().ok_or_else(|| need(r, 1))?;
        if reserved != 0 {
            return Err(OspfError::ReservedBits {
                field: "DBD(v3) MTU",
                value: reserved,
            });
        }
        let flags = r.u8().ok_or_else(|| need(r, 1))?;
        if flags & 0xf8 != 0 {
            return Err(OspfError::ReservedBits {
                field: "DBD(v3) flags",
                value: flags,
            });
        }
        let dd_sequence = r.u32().ok_or_else(|| need(r, 4))?;
        let mut headers = Vec::new();
        while !r.is_empty() {
            headers.push(LsaHeaderV3::decode(r)?);
        }
        Ok(DbDescriptionV3 {
            interface_mtu,
            options,
            init: flags & 0x04 != 0,
            more: flags & 0x02 != 0,
            master: flags & 0x01 != 0,
            dd_sequence,
            lsa_headers: headers,
        })
    }

    fn decode_lsr(r: &mut Reader<'_>) -> Result<LsRequestV3, OspfError> {
        let field = "LSR(v3) body";
        let mut requests = Vec::new();
        while !r.is_empty() {
            if r.remaining() < 12 {
                return Err(OspfError::Truncated {
                    field,
                    need: 12,
                    have: r.remaining(),
                });
            }
            let reserved = r.u16().expect("checked");
            if reserved != 0 {
                return Err(OspfError::ReservedBits16 {
                    field: "LSR(v3) entry",
                    value: reserved,
                });
            }
            let ls_type = LsaType(r.u16().expect("checked"));
            let link_state_id = LinkStateId(r.u32().expect("checked"));
            let adv_router = RouterId(r.u32().expect("checked"));
            requests.push(LsRequestV3Entry {
                ls_type,
                link_state_id,
                adv_router,
            });
        }
        Ok(LsRequestV3 { requests })
    }

    fn decode_lsu(r: &mut Reader<'_>) -> Result<LsUpdateV3, OspfError> {
        let field = "LSU(v3) body";
        let count = r.u32().ok_or(OspfError::Truncated {
            field,
            need: 4,
            have: 0,
        })? as usize;
        let mut lsas = Vec::with_capacity(count.min(1024));
        for _ in 0..count {
            // Each LSA's extent comes from its own header length; the
            // count must not overrun the packet (A19 — unchanged).
            let mut probe = Reader::new(r.peek_remaining());
            let hdr = LsaHeaderV3::decode(&mut probe)?;
            if hdr.length as usize > r.remaining() {
                return Err(OspfError::BadLength {
                    field: "LSA length in LSU",
                    declared: hdr.length as usize,
                    actual: r.remaining(),
                });
            }
            let take = r.take(hdr.length as usize).expect("bounds checked above");
            lsas.push(LsaV3::decode(take)?);
        }
        Ok(LsUpdateV3 { lsas })
    }

    fn decode_lsack(r: &mut Reader<'_>) -> Result<LsAckV3, OspfError> {
        let mut headers = Vec::new();
        while !r.is_empty() {
            headers.push(LsaHeaderV3::decode(r)?);
        }
        Ok(LsAckV3 { headers })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::lsa::INITIAL_SEQUENCE_NUMBER;
    use crate::lsa_v3::{LinkTypeV3, LsaBodyV3, RouterLinkV3, RouterLsaV3};

    // Test-oracle disclosure: hand-derived goldens pinned to the
    // RFC 5340 A.3 diagrams (no real v6 corpus exists tonight; the
    // live FRR ospf6d interop leg is the recorded follow-up).

    const SRC: Ipv6Addr = Ipv6Addr::new(0xfe80, 0, 0, 0, 0x0200, 0x0011, 0x00ff, 0x1111);
    const DST: Ipv6Addr = Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 0x0005);

    fn hdr(router_id: u32, packet_type: u8) -> PacketHeaderV3 {
        PacketHeaderV3 {
            version: 3,
            packet_type,
            length: 0,
            router_id: RouterId(router_id),
            area_id: 0,
            checksum: 0,
            instance_id: 0,
        }
    }

    /// Fill in the computed length/checksum (and inner LSA headers)
    /// so round trips compare modulo exactly those fields.
    fn with_computed(mut pkt: PacketV3) -> PacketV3 {
        let bytes = pkt.encode(SRC, DST);
        pkt.header.length = u16::from_be_bytes([bytes[2], bytes[3]]);
        pkt.header.checksum = u16::from_be_bytes([bytes[12], bytes[13]]);
        if let PacketBodyV3::LsUpdate(u) = &mut pkt.body {
            for lsa in &mut u.lsas {
                *lsa = lsa.with_computed_header();
            }
        }
        pkt
    }

    impl LsaV3 {
        #[cfg(test)]
        pub(crate) fn with_computed_header(&self) -> LsaV3 {
            let bytes = self.encode();
            LsaV3::decode(&bytes).expect("re-encode must decode")
        }
    }

    fn sample_router_lsa_v3() -> LsaV3 {
        LsaV3 {
            header: crate::lsa_v3::LsaHeaderV3 {
                ls_age: 1,
                ls_type: LsaType::V3_ROUTER,
                link_state_id: LinkStateId(0),
                adv_router: RouterId(0x0a00_0001),
                seq: INITIAL_SEQUENCE_NUMBER,
                checksum: 0,
                length: 0,
            },
            body: LsaBodyV3::Router(RouterLsaV3 {
                nt_bit: false,
                v_bit: false,
                e_bit: true,
                b_bit: false,
                options: Options24(Options24::V6 | Options24::E),
                links: vec![RouterLinkV3 {
                    link_type: LinkTypeV3::PointToPoint,
                    metric: 5,
                    interface_id: 1,
                    neighbor_interface_id: 2,
                    neighbor_router_id: RouterId(0x0a00_0002),
                }],
            }),
        }
    }

    fn sample_hello() -> PacketV3 {
        PacketV3 {
            header: hdr(0x0a00_0001, 1),
            body: PacketBodyV3::Hello(HelloV3 {
                interface_id: 9,
                router_priority: 1,
                options: Options24(Options24::V6 | Options24::E | Options24::R),
                hello_interval: 10,
                router_dead_interval: 40,
                designated_router: RouterId(0x0a00_0009),
                backup_designated_router: RouterId(0),
                neighbors: vec![RouterId(0x0a00_0002)],
            }),
        }
    }

    #[test]
    fn v3_header_is_16_bytes_instance_id_carried() {
        // A.3.1: Version(1) Type(1) Length(2) RouterID(4) AreaID(4)
        // Checksum(2) InstanceID(1) 0(1).
        let mut pkt = sample_hello();
        pkt.header.instance_id = 64;
        let bytes = pkt.encode(SRC, DST);
        assert_eq!(bytes.len(), 16 + 20 + 4, "header + hello body + 1 neighbor");
        assert_eq!(bytes[0], 3, "version");
        assert_eq!(bytes[1], 1, "Hello");
        assert_eq!(
            u16::from_be_bytes([bytes[2], bytes[3]]) as usize,
            bytes.len()
        );
        assert_eq!(&bytes[4..8], &0x0a00_0001u32.to_be_bytes());
        assert_eq!(&bytes[8..12], &0u32.to_be_bytes(), "area 0");
        assert!(bytes[12] != 0 || bytes[13] != 0, "checksum filled");
        assert_eq!(bytes[14], 64, "instance id");
        assert_eq!(bytes[15], 0, "reserved octet");
        let back = PacketV3::decode(&bytes, SRC, DST).unwrap();
        assert_eq!(back.header.instance_id, 64);
        // The reserved octet is MUST-ignore (A.3.1): a nonzero value
        // does not reject the packet.
        let mut b = bytes.clone();
        b[15] = 0xff;
        // Repair checksum (byte 15 is covered).
        let mut region = pseudo_header(SRC, DST, b.len() as u16);
        region.extend_from_slice(&b);
        region[40 + 12] = 0;
        region[40 + 13] = 0;
        let c = internet_checksum(&region);
        b[12..14].copy_from_slice(&c.to_be_bytes());
        assert!(
            PacketV3::decode(&b, SRC, DST).is_ok(),
            "reserved octet ignored"
        );
        // Version gate.
        let mut b = bytes;
        b[0] = 2;
        let mut region = pseudo_header(SRC, DST, u16::from_be_bytes([b[2], b[3]]));
        region.extend_from_slice(&b);
        region[40 + 12] = 0;
        region[40 + 13] = 0;
        let c = internet_checksum(&region);
        b[12..14].copy_from_slice(&c.to_be_bytes());
        assert_eq!(
            PacketV3::decode(&b, SRC, DST).unwrap_err(),
            OspfError::BadVersion(2)
        );
    }

    #[test]
    fn hello_v3_golden_layout() {
        // A.3.2 byte-by-byte: InterfaceID(4), RtrPriority(1) +
        // Options(3), HelloInterval(2), RouterDeadInterval(2),
        // DR ID(4), BDR ID(4), neighbors.
        let pkt = sample_hello();
        let bytes = pkt.encode(SRC, DST);
        assert_eq!(&bytes[16..20], &9u32.to_be_bytes(), "interface ID");
        assert_eq!(bytes[20], 1, "priority");
        assert_eq!(&bytes[21..24], &[0x00, 0x00, 0x13], "V6|E|R options");
        assert_eq!(&bytes[24..26], &10u16.to_be_bytes());
        assert_eq!(
            &bytes[26..28],
            &40u16.to_be_bytes(),
            "dead interval is 16-bit"
        );
        assert_eq!(
            &bytes[28..32],
            &0x0a00_0009u32.to_be_bytes(),
            "DR as Router ID"
        );
        assert_eq!(&bytes[32..36], &0u32.to_be_bytes(), "no BDR");
        assert_eq!(&bytes[36..40], &0x0a00_0002u32.to_be_bytes(), "neighbor");
        assert_eq!(
            PacketV3::decode(&bytes, SRC, DST).unwrap(),
            with_computed(pkt)
        );
        // No network mask anywhere (§2.1's per-link model) — the
        // first body byte IS the interface ID.
        assert_eq!(bytes[16], 0, "interface ID high octet, not a mask");
    }

    #[test]
    fn dbd_v3_preamble_is_exactly_12_bytes() {
        // A.3.3: three 4-byte rows after the 16-byte header — the
        // 0|Options word, MTU+0|I|M|MS, DD sequence. An empty
        // ExStart DBD is 28 bytes, no padding (the Day-1 v2 lesson
        // carried into v3's different preamble size).
        let dd = DbDescriptionV3 {
            interface_mtu: 1500,
            options: Options24(Options24::V6 | Options24::E),
            init: true,
            more: true,
            master: true,
            dd_sequence: 0x3879fa0b,
            lsa_headers: vec![],
        };
        let pkt = PacketV3 {
            header: hdr(0x0a00_0001, 2),
            body: PacketBodyV3::DbDescription(dd),
        };
        let bytes = pkt.encode(SRC, DST);
        assert_eq!(bytes.len(), 28, "16 header + 12 preamble");
        assert_eq!(bytes[16], 0, "reserved octet above Options");
        assert_eq!(&bytes[17..20], &[0x00, 0x00, 0x03]);
        assert_eq!(&bytes[20..22], &1500u16.to_be_bytes());
        assert_eq!(bytes[22], 0, "the reserved octet beside I/M/MS");
        assert_eq!(bytes[23], 0x07, "0(5)|I|M|MS");
        assert_eq!(&bytes[24..28], &0x3879fa0bu32.to_be_bytes());
        assert_eq!(
            PacketV3::decode(&bytes, SRC, DST).unwrap(),
            with_computed(pkt)
        );
        // Reserved flags and the reserved octets reject.
        let mut b = bytes.clone();
        b[23] |= 0x10;
        let mut region = pseudo_header(SRC, DST, b.len() as u16);
        region.extend_from_slice(&b);
        region[40 + 12] = 0;
        region[40 + 13] = 0;
        let c = internet_checksum(&region);
        b[12..14].copy_from_slice(&c.to_be_bytes());
        assert!(matches!(
            PacketV3::decode(&b, SRC, DST).unwrap_err(),
            OspfError::ReservedBits {
                field: "DBD(v3) flags",
                ..
            }
        ));
        // With a v3 LSA header inside (the 20-byte no-Options form).
        let lsa = sample_router_lsa_v3();
        let lsa_bytes = lsa.encode();
        let lsa_hdr = LsaV3::decode_header(&lsa_bytes[..20]).unwrap();
        let pkt = PacketV3 {
            header: hdr(0x0a00_0001, 2),
            body: PacketBodyV3::DbDescription(DbDescriptionV3 {
                interface_mtu: 1500,
                options: Options24(Options24::V6 | Options24::E),
                init: false,
                more: true,
                master: false,
                dd_sequence: 7,
                lsa_headers: vec![lsa_hdr],
            }),
        };
        let bytes = pkt.encode(SRC, DST);
        assert_eq!(bytes.len(), 28 + 20);
        // The v3 LSA header inside: age first, then the 16-bit type.
        assert_eq!(&bytes[28..30], &1u16.to_be_bytes(), "LS age");
        assert_eq!(&bytes[30..32], &0x2001u16.to_be_bytes(), "LS type");
        assert_eq!(
            PacketV3::decode(&bytes, SRC, DST).unwrap(),
            with_computed(pkt)
        );
    }

    #[test]
    fn lsr_v3_entries_and_reserved_rejected() {
        // A.3.4: 12-byte entries — 16 reserved bits over the 16-bit
        // LS type, then LS ID and Advertising Router.
        let pkt = PacketV3 {
            header: hdr(0x0a00_0002, 3),
            body: PacketBodyV3::LsRequest(LsRequestV3 {
                requests: vec![
                    LsRequestV3Entry {
                        ls_type: LsaType::V3_ROUTER,
                        link_state_id: LinkStateId(0),
                        adv_router: RouterId(0x0a00_0001),
                    },
                    LsRequestV3Entry {
                        ls_type: LsaType::V3_LINK,
                        link_state_id: LinkStateId(9),
                        adv_router: RouterId(0x0a00_0003),
                    },
                ],
            }),
        };
        let bytes = pkt.encode(SRC, DST);
        assert_eq!(bytes.len(), 16 + 24);
        assert_eq!(&bytes[16..20], &[0x00, 0x00, 0x20, 0x01]);
        assert_eq!(&bytes[28..32], &[0x00, 0x00, 0x00, 0x08]);
        assert_eq!(
            PacketV3::decode(&bytes, SRC, DST).unwrap(),
            with_computed(pkt)
        );
        // The reserved halfword rejects nonzero (house style; the
        // RFC shows 0 — real senders zero it).
        let mut b = bytes.clone();
        b[16] = 0x12;
        let mut region = pseudo_header(SRC, DST, b.len() as u16);
        region.extend_from_slice(&b);
        region[40 + 12] = 0;
        region[40 + 13] = 0;
        let c = internet_checksum(&region);
        b[12..14].copy_from_slice(&c.to_be_bytes());
        assert!(matches!(
            PacketV3::decode(&b, SRC, DST).unwrap_err(),
            OspfError::ReservedBits16 {
                field: "LSR(v3) entry",
                value: 0x1200
            }
        ));
        // The remaining < 12 → Truncated arithmetic ports.
        let mut b = bytes[..16 + 12 + 6].to_vec();
        let n = b.len() as u16;
        b[2..4].copy_from_slice(&n.to_be_bytes());
        let mut region = pseudo_header(SRC, DST, n);
        region.extend_from_slice(&b);
        region[40 + 12] = 0;
        region[40 + 13] = 0;
        let c = internet_checksum(&region);
        b[12..14].copy_from_slice(&c.to_be_bytes());
        assert!(matches!(
            PacketV3::decode(&b, SRC, DST).unwrap_err(),
            OspfError::Truncated {
                field: "LSR(v3) body",
                need: 12,
                ..
            }
        ));
    }

    #[test]
    fn lsu_lsack_v3_round_trip_and_count_overrun() {
        let lsa = sample_router_lsa_v3();
        let lsa_bytes = lsa.encode();
        let lsa_hdr = LsaV3::decode_header(&lsa_bytes[..20]).unwrap();

        let lsu = PacketV3 {
            header: hdr(0x0a00_0002, 4),
            body: PacketBodyV3::LsUpdate(LsUpdateV3 {
                lsas: vec![lsa.clone()],
            }),
        };
        let encoded = lsu.encode(SRC, DST);
        // 16 header + 4 count + the LSA (its own length).
        assert_eq!(encoded.len(), 16 + 4 + lsa_bytes.len());
        let back = PacketV3::decode(&encoded, SRC, DST).unwrap();
        assert_eq!(back, with_computed(lsu));
        let PacketBodyV3::LsUpdate(u) = back.body else {
            unreachable!()
        };
        assert_eq!(u.lsas[0].encode(), lsa_bytes);

        // A19: the count must not overrun the packet.
        let mut pkt = encoded.clone();
        pkt[16..20].copy_from_slice(&2u32.to_be_bytes());
        let mut region = pseudo_header(SRC, DST, pkt.len() as u16);
        region.extend_from_slice(&pkt);
        region[40 + 12] = 0;
        region[40 + 13] = 0;
        let c = internet_checksum(&region);
        pkt[12..14].copy_from_slice(&c.to_be_bytes());
        assert!(PacketV3::decode(&pkt, SRC, DST).is_err());

        let ack = PacketV3 {
            header: hdr(0x0a00_0002, 5),
            body: PacketBodyV3::LsAck(LsAckV3 {
                headers: vec![lsa_hdr],
            }),
        };
        assert_eq!(ack.encode(SRC, DST).len(), 16 + 20);
        assert_eq!(
            PacketV3::decode(&ack.encode(SRC, DST), SRC, DST).unwrap(),
            with_computed(ack)
        );
    }

    #[test]
    fn pseudo_header_checksum_sensitivity() {
        // A.3.1: the checksum covers the ENTIRE packet (header
        // included) plus the IPv6 pseudo-header — flipping a source
        // or destination address bit must fail verification.
        let bytes = sample_hello().encode(SRC, DST);
        // Sanity: it verifies as-sent...
        assert!(PacketV3::decode(&bytes, SRC, DST).is_ok());
        // ...and every single-bit body corruption is caught.
        for i in 16..bytes.len() {
            let mut corrupt = bytes.clone();
            corrupt[i] ^= 0x01;
            assert!(
                matches!(
                    PacketV3::decode(&corrupt, SRC, DST).unwrap_err(),
                    OspfError::ChecksumMismatch { .. }
                ),
                "byte {i} corruption undetected"
            );
        }
        // ...and header bytes too (nothing is excluded, unlike v2's
        // auth-field exclusion).
        for i in [0usize, 4, 8, 14] {
            let mut corrupt = bytes.clone();
            corrupt[i] ^= 0x01;
            assert!(
                PacketV3::decode(&corrupt, SRC, DST).is_err(),
                "header byte {i} corruption undetected"
            );
        }
        // Different src or dst at decode time: pseudo-header mismatch.
        let other_src = Ipv6Addr::new(0xfe80, 0, 0, 0, 0x0200, 0x0011, 0x00ff, 0x1112);
        let other_dst = Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 0x0006);
        assert!(matches!(
            PacketV3::decode(&bytes, other_src, DST).unwrap_err(),
            OspfError::ChecksumMismatch { .. }
        ));
        assert!(matches!(
            PacketV3::decode(&bytes, SRC, other_dst).unwrap_err(),
            OspfError::ChecksumMismatch { .. }
        ));
        // The same packet computed with the swapped pair also
        // verifies against the swapped pair (the inputs are
        // genuinely mixed in).
        let swapped = sample_hello().encode(DST, SRC);
        assert!(PacketV3::decode(&swapped, DST, SRC).is_ok());
    }

    #[test]
    fn pseudo_header_layout() {
        // RFC 8200 §8.1 via A.3.1: src(16) dst(16) length(4) 0(3)
        // next-header 89(1).
        let src = "fe80::1".parse::<Ipv6Addr>().unwrap();
        let dst = "ff02::5".parse::<Ipv6Addr>().unwrap();
        let pseudo = pseudo_header(src, dst, 44);
        assert_eq!(pseudo.len(), 40);
        assert_eq!(&pseudo[0..16], &src.octets());
        assert_eq!(&pseudo[16..32], &dst.octets());
        assert_eq!(&pseudo[32..36], &44u32.to_be_bytes(), "upper-layer length");
        assert_eq!(&pseudo[36..39], &[0, 0, 0]);
        assert_eq!(pseudo[39], 89, "next header = OSPF");
    }

    #[test]
    fn checksum_hand_computed_vector() {
        // Independent hand computation for a minimal even-length
        // packet, guarding against a symmetric-encode/decode bug:
        // sum the pseudo-header and packet as 16-bit words by hand
        // and complement.
        let pkt = PacketV3 {
            header: hdr(0, 5),
            body: PacketBodyV3::LsAck(LsAckV3 { headers: vec![] }),
        };
        let bytes = pkt.encode(SRC, DST);
        assert_eq!(bytes.len(), 16, "empty LSAck is just the header");
        let mut sum: u32 = 0;
        let mut words = Vec::new();
        words.extend_from_slice(&SRC.octets());
        words.extend_from_slice(&DST.octets());
        words.extend_from_slice(&16u32.to_be_bytes());
        words.extend_from_slice(&[0, 0, 0, 89]);
        let mut packet_zeroed = bytes.clone();
        packet_zeroed[12] = 0;
        packet_zeroed[13] = 0;
        words.extend_from_slice(&packet_zeroed);
        for c in words.as_chunks::<2>().0 {
            sum += u16::from_be_bytes(*c) as u32;
        }
        while sum >> 16 != 0 {
            sum = (sum & 0xffff) + (sum >> 16);
        }
        let expect = !(sum as u16);
        assert_eq!(u16::from_be_bytes([bytes[12], bytes[13]]), expect);
        let want = {
            let mut v = vec![0x03, 0x05, 0x00, 0x10, 0, 0, 0, 0, 0, 0, 0, 0];
            put_u16(&mut v, expect);
            v.extend_from_slice(&[0x00, 0x00]);
            v
        };
        assert_eq!(bytes, want);
    }

    #[test]
    fn every_truncation_rejected() {
        let bytes = sample_hello().encode(SRC, DST);
        for cut in 0..bytes.len() {
            assert!(
                PacketV3::decode(&bytes[..cut], SRC, DST).is_err(),
                "cut {cut}"
            );
        }
        // Length mismatch in an intact buffer.
        let mut bad = bytes.clone();
        let n = bad.len() as u16 - 1;
        bad[2..4].copy_from_slice(&n.to_be_bytes());
        let mut region = pseudo_header(SRC, DST, u16::from_be_bytes([bad[2], bad[3]]));
        region.extend_from_slice(&bad);
        region[40 + 12] = 0;
        region[40 + 13] = 0;
        let c = internet_checksum(&region);
        bad[12..14].copy_from_slice(&c.to_be_bytes());
        assert!(matches!(
            PacketV3::decode(&bad, SRC, DST).unwrap_err(),
            OspfError::BadLength { .. }
        ));
        // Bad packet type.
        let mut b = bytes;
        b[1] = 9;
        let mut region = pseudo_header(SRC, DST, u16::from_be_bytes([b[2], b[3]]));
        region.extend_from_slice(&b);
        region[40 + 12] = 0;
        region[40 + 13] = 0;
        let c = internet_checksum(&region);
        b[12..14].copy_from_slice(&c.to_be_bytes());
        assert_eq!(
            PacketV3::decode(&b, SRC, DST).unwrap_err(),
            OspfError::BadPacketType(9)
        );
    }
}
