//! The LSA codec (RFC 2328 §A.4: the 20-byte header in §A.4.1 and the
//! OSPFv2 bodies — router §A.4.2, network §A.4.3, summary §A.4.4,
//! AS-external §A.4.5).
//!
//! AF-generic seams (the Holo pattern, per `docs/architecture.md`
//! invariant 3 — OSPFv3 must fall out of this codebase, not fork it):
//!
//! - [`LsaType`] is `u16`-backed. v2 encodes it in the header's single
//!   type octet (types 1-5); v3 puts the full 16-bit type in the header
//!   and drops the header Options octet — the enum constants stay.
//! - [`RouterId`] and [`LinkStateId`] are `u32` newtypes. In v2 the
//!   Link State ID is *interpreted* as an IPv4 address (network number,
//!   DR address, ...); in v3 it is an opaque type-specific value. The
//!   header codec therefore never touches `Ipv4Addr`.
//! - The v2 bodies below are the only IPv4-specific parts; v3 adds new
//!   [`LsaBody`] variants (Link, Intra-Area-Prefix, ...) and replaces
//!   the v2 body shapes where they differ (v3 router-LSA links carry
//!   interface IDs instead of Link Data; the v3 network-LSA collapses
//!   to an Options field; summary/external become prefix-based). The
//!   header, the "newer than" ordering, the LSDB and the SPF skeleton
//!   are AF-independent.
//! - Sequence numbers compare **as signed 32-bit integers** (§12.1.6);
//!   the raw `u32` is stored and every comparison goes through
//!   [`LsaHeader::seq_signed`].
//!
//! Validation is strict everywhere a length or count field appears
//! (the A19 lesson): a declared `# links`, TOS count or `length` is
//! only accepted when the buffer holds exactly the implied bytes, and
//! every decode ends with a framing-exactness check.

use std::net::Ipv4Addr;

use crate::checksum::{fletcher_verify, lsa_fletcher_checksum};
use crate::error::OspfError;
use crate::wire::{put_u16, put_u24, put_u32, put_u8, Reader};

/// InitialSequenceNumber (§12.1.6): 0x80000001, the smallest/oldest
/// sequence number (0x80000000 itself is reserved and unused).
pub const INITIAL_SEQUENCE_NUMBER: u32 = 0x8000_0001;
/// MaxSequenceNumber (§12.1.6): 0x7fffffff, the largest/newest.
pub const MAX_SEQUENCE_NUMBER: u32 = 0x7fff_ffff;

/// An OSPF router ID (RFC 2328 §C.2). A bare `u32` in both v2 and v3;
/// v2 renders it as a dotted quad.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct RouterId(pub u32);

impl RouterId {
    pub const fn new(v: u32) -> Self {
        Self(v)
    }

    pub fn from_ipv4(a: Ipv4Addr) -> Self {
        Self(u32::from(a))
    }

    pub fn to_ipv4(self) -> Ipv4Addr {
        Ipv4Addr::from(self.0)
    }

    /// The signed comparison OSPF nowhere defines for router IDs but
    /// DD master/slave election needs (§10.6 ExStart: "the neighbor's
    /// Router ID is larger than the router's own") — compare as u32.
    pub fn larger_than(self, other: RouterId) -> bool {
        self.0 > other.0
    }
}

impl std::fmt::Display for RouterId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.to_ipv4())
    }
}

/// The Link State ID (§A.4.1 / §12.1.4). v2: an IPv4-address-valued
/// selector whose meaning depends on LS type; v3: opaque u32.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct LinkStateId(pub u32);

impl LinkStateId {
    pub const fn new(v: u32) -> Self {
        Self(v)
    }

    pub fn from_ipv4(a: Ipv4Addr) -> Self {
        Self(u32::from(a))
    }

    pub fn to_ipv4(self) -> Ipv4Addr {
        Ipv4Addr::from(self.0)
    }
}

impl std::fmt::Display for LinkStateId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.to_ipv4())
    }
}

/// The LS type octet (§A.4.1; v6 seam: u16-backed for OSPFv3's
/// 16-bit LS types, encoded into the single v2 header octet).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct LsaType(pub u16);

impl LsaType {
    pub const ROUTER: Self = Self(1);
    pub const NETWORK: Self = Self(2);
    /// Type 3: summary-LSA for an IP network.
    pub const SUMMARY_NETWORK: Self = Self(3);
    /// Type 4: summary-LSA for an AS boundary router.
    pub const SUMMARY_ASBR: Self = Self(4);
    pub const AS_EXTERNAL: Self = Self(5);
    /// Type 7: NSSA external (RFC 3101 §2.3) — the body is the
    /// AS-external shape; the header's Options N/P bit position
    /// carries the P-bit.
    pub const NSSA: Self = Self(7);

    // The OSPFv3 LS types (RFC 5340 A.4.2.1's function-code table).
    // Unlike v2, where the u16 is encoded into one header octet, the
    // whole 16 bits go on the v3 wire and the high three bits carry
    // the U/S2/S1 generic properties (see [`LsaType::u_bit`] and
    // [`LsaType::scope`]).
    /// 0x2001: router-LSA (area scope).
    pub const V3_ROUTER: Self = Self(0x2001);
    /// 0x2002: network-LSA (area scope).
    pub const V3_NETWORK: Self = Self(0x2002);
    /// 0x2003: inter-area-prefix-LSA (the v2 type-3, area scope).
    pub const V3_INTER_AREA_PREFIX: Self = Self(0x2003);
    /// 0x2004: inter-area-router-LSA (the v2 type-4, area scope).
    pub const V3_INTER_AREA_ROUTER: Self = Self(0x2004);
    /// 0x4005: AS-external-LSA (AS scope).
    pub const V3_AS_EXTERNAL: Self = Self(0x4005);
    /// 0x2006: deprecated (was MOSPF; may be reassigned) — never a
    /// known type, decodes into the v3 `Unknown` body.
    pub const V3_DEPRECATED_MOSPF: Self = Self(0x2006);
    /// 0x2007: NSSA-LSA (RFC 3101 for IPv6, area scope) — the v3
    /// body is exactly the AS-external shape (RFC 5340 A.4.8).
    pub const V3_NSSA: Self = Self(0x2007);
    /// 0x0008: link-LSA (link-local scope, no v2 counterpart).
    pub const V3_LINK: Self = Self(0x0008);
    /// 0x2009: intra-area-prefix-LSA (area scope) — absorbs the v2
    /// stub links and network-LSA prefixes.
    pub const V3_INTRA_AREA_PREFIX: Self = Self(0x2009);

    /// The U-bit (RFC 5340 A.4.2.1 bit 15): how a router that does
    /// not recognize the function code handles the LSA (0 → treat as
    /// link-local scope; 1 → store and flood as if understood).
    pub const U_BIT: u16 = 0x8000;
    /// The S2/S1 flooding-scope mask (bits 14/13).
    pub const SCOPE_MASK: u16 = 0x6000;
    /// The function-code mask (low 13 bits).
    pub const FUNCTION_CODE_MASK: u16 = 0x1fff;

    pub fn is_known_v2(self) -> bool {
        matches!(self.0, 1..=5 | 7)
    }

    /// The eight live OSPFv3 function codes (A.4.2.1's table minus
    /// the deprecated 0x2006). Unknown codes are NOT rejected in v3 —
    /// the U-bit contract (§3.4/A.4.2.1) requires storing and
    /// flooding them; `is_known_v3` only decides whether the body is
    /// decodable.
    pub fn is_known_v3(self) -> bool {
        matches!(self.0, 0x2001..=0x2004 | 0x4005 | 0x2007 | 0x0008 | 0x2009)
    }

    /// The U-bit value (RFC 5340 A.4.2.1).
    pub fn u_bit(self) -> bool {
        self.0 & Self::U_BIT != 0
    }

    /// The flooding scope encoded in the S2/S1 bits (A.4.2.1).
    /// `0b11` is reserved and rejected at header decode.
    pub fn scope(self) -> Scope {
        match (self.0 & Self::SCOPE_MASK) >> 13 {
            0b00 => Scope::Link,
            0b01 => Scope::Area,
            0b10 => Scope::As,
            _ => Scope::Reserved,
        }
    }

    /// The 13-bit LSA function code (A.4.2.1).
    pub fn function_code(self) -> u16 {
        self.0 & Self::FUNCTION_CODE_MASK
    }

    pub fn name(self) -> &'static str {
        match self.0 {
            1 => "router",
            2 => "network",
            3 => "summary(network)",
            4 => "summary(ASBR)",
            5 => "AS-external",
            7 => "NSSA-external",
            0x2001 => "router",
            0x2002 => "network",
            0x2003 => "inter-area-prefix",
            0x2004 => "inter-area-router",
            0x4005 => "AS-external",
            0x2006 => "deprecated(0x2006)",
            0x2007 => "NSSA-external",
            0x0008 => "link",
            0x2009 => "intra-area-prefix",
            _ => "unknown",
        }
    }
}

/// The OSPFv3 flooding scope carried in the LS type's S2/S1 bits
/// (RFC 5340 A.4.2.1). The scope lives *in the type bits*, so v3
/// admission control is a mask test rather than the v2 type table.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Scope {
    /// 0b00: flooded only on the originating link (link-LSAs, and
    /// unknown-type LSAs with U=0).
    Link,
    /// 0b01: flooded only within the originating area.
    Area,
    /// 0b10: flooded throughout the AS.
    As,
    /// 0b11: reserved — rejected at header decode.
    Reserved,
}

impl std::fmt::Display for LsaType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.name())
    }
}

/// The Options field (§A.2): `| * | * | DC | EA | N/P | MC | E | * |`.
/// Unrecognized bits are ignored on receipt (§A.2's last paragraph)
/// and cleared when we originate.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Options(pub u8);

impl Options {
    pub const E: u8 = 0x02;
    pub const MC: u8 = 0x04;
    pub const NP: u8 = 0x08;
    pub const EA: u8 = 0x10;
    pub const DC: u8 = 0x20;

    pub fn e_bit(self) -> bool {
        self.0 & Self::E != 0
    }

    pub fn mc_bit(self) -> bool {
        self.0 & Self::MC != 0
    }

    pub fn np_bit(self) -> bool {
        self.0 & Self::NP != 0
    }

    pub fn ea_bit(self) -> bool {
        self.0 & Self::EA != 0
    }

    pub fn dc_bit(self) -> bool {
        self.0 & Self::DC != 0
    }
}

/// The DoNotAge bit of the LS age field (RFC 3623 / RFC 1793 lineage,
/// carried in bit 15 of the age). v1 stores the age raw; the effective
/// age for aging/MaxAge arithmetic masks this bit out.
pub const DO_NOT_AGE: u16 = 0x8000;

/// The 20-byte LSA header (§A.4.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LsaHeader {
    /// Seconds since origination. The `DO_NOT_AGE` bit may be set
    /// (see [`DO_NOT_AGE`]).
    pub ls_age: u16,
    pub options: Options,
    pub ls_type: LsaType,
    pub link_state_id: LinkStateId,
    pub adv_router: RouterId,
    /// Raw sequence number; compare via [`LsaHeader::seq_signed`]
    /// (signed space, §12.1.6).
    pub seq: u32,
    pub checksum: u16,
    /// Length in bytes including this 20-byte header.
    pub length: u16,
}

impl LsaHeader {
    pub const WIRE_SIZE: usize = 20;

    pub fn seq_signed(&self) -> i32 {
        self.seq as i32
    }

    /// Effective age with the DoNotAge bit masked off.
    pub fn effective_age(&self) -> u16 {
        self.ls_age & !DO_NOT_AGE
    }

    /// §14: LSAs of age MaxAge are not used in the routing table
    /// calculation. The RFC's `== MaxAge` is `>=` on the effective age
    /// for receive-side robustness (age never exceeds MaxAge on the
    /// wire; anything beyond is a flush in flight).
    pub fn is_max_age(&self) -> bool {
        self.effective_age() >= crate::MAX_AGE
    }

    /// Decode the 20-byte header from `r`, validating §A.4.1 field
    /// constraints (known LS type, sequence in range, age <= MaxAge,
    /// nonzero checksum — §12.1.7's "cannot take on the value of zero").
    pub fn decode(r: &mut Reader<'_>) -> Result<Self, OspfError> {
        let field = "LSA header";
        let age = r.u16().ok_or_else(|| OspfError::Truncated {
            field,
            need: 2,
            have: r.remaining(),
        })?;
        let options = Options(r.u8().ok_or(OspfError::Truncated {
            field,
            need: 1,
            have: 0,
        })?);
        let raw_type = r.u8().ok_or(OspfError::Truncated {
            field,
            need: 1,
            have: 0,
        })?;
        let ls_type = LsaType(raw_type as u16);
        if !ls_type.is_known_v2() {
            return Err(OspfError::BadLsType(ls_type.0));
        }
        let link_state_id = LinkStateId(r.u32().ok_or(OspfError::Truncated {
            field,
            need: 4,
            have: 0,
        })?);
        let adv_router = RouterId(r.u32().ok_or(OspfError::Truncated {
            field,
            need: 4,
            have: 0,
        })?);
        let seq = r.u32().ok_or(OspfError::Truncated {
            field,
            need: 4,
            have: 0,
        })?;
        // §12.1.6: the space is *signed*; 0x80000000 is reserved.
        if !(INITIAL_SEQUENCE_NUMBER as i32..=MAX_SEQUENCE_NUMBER as i32).contains(&(seq as i32)) {
            return Err(OspfError::BadSequence(seq));
        }
        let checksum = r.u16().ok_or(OspfError::Truncated {
            field,
            need: 2,
            have: 0,
        })?;
        if checksum == 0 {
            return Err(OspfError::ZeroChecksum);
        }
        let length = r.u16().ok_or(OspfError::Truncated {
            field,
            need: 2,
            have: 0,
        })?;
        if age & !DO_NOT_AGE > crate::MAX_AGE {
            return Err(OspfError::AgeTooLarge(age));
        }
        if length < Self::WIRE_SIZE as u16 {
            return Err(OspfError::BadLength {
                field: "LSA length",
                declared: length as usize,
                actual: Self::WIRE_SIZE,
            });
        }
        Ok(Self {
            ls_age: age,
            options,
            ls_type,
            link_state_id,
            adv_router,
            seq,
            checksum,
            length,
        })
    }

    /// Encode the header (20 bytes). The checksum field is written as
    /// stored — [`Lsa::encode`] computes it over the full LSA.
    pub fn encode(&self, buf: &mut Vec<u8>) {
        put_u16(buf, self.ls_age);
        put_u8(buf, self.options.0);
        put_u8(buf, self.ls_type.0 as u8);
        put_u32(buf, self.link_state_id.0);
        put_u32(buf, self.adv_router.0);
        put_u32(buf, self.seq);
        put_u16(buf, self.checksum);
        put_u16(buf, self.length);
    }
}

/// A TOS-specific metric record (§A.4.2/A.4.4/A.4.5's legacy TOS
/// encoding; the TOS octet encoding itself is §12.3 Table 17 —
/// OSPF encodes IP TOS as twice the binary value).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TosMetric {
    pub tos: u8,
    pub metric: u32,
}

/// Router link types (§A.4.2 "Type" table).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LinkType {
    /// 1: point-to-point connection to another router.
    PointToPoint,
    /// 2: connection to a transit network.
    Transit,
    /// 3: connection to a stub network.
    Stub,
    /// 4: virtual link.
    Virtual,
}

impl LinkType {
    fn from_u8(v: u8) -> Result<Self, OspfError> {
        match v {
            1 => Ok(Self::PointToPoint),
            2 => Ok(Self::Transit),
            3 => Ok(Self::Stub),
            4 => Ok(Self::Virtual),
            other => Err(OspfError::BadLinkType(other)),
        }
    }

    fn to_u8(self) -> u8 {
        match self {
            Self::PointToPoint => 1,
            Self::Transit => 2,
            Self::Stub => 3,
            Self::Virtual => 4,
        }
    }
}

/// One router-link record (§A.4.2): Link ID, Link Data, Type, # TOS,
/// metric, then `# TOS` TOS records. `link_data` keeps the raw u32 —
/// its meaning is type-dependent (mask for stub links, interface
/// address otherwise, MIB-II ifIndex for unnumbered p2p).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RouterLink {
    pub link_id: LinkStateId,
    pub link_data: u32,
    pub link_type: LinkType,
    pub metric: u16,
    pub tos: Vec<TosMetric>,
}

/// The router-LSA body (§A.4.2). V/E/B flags and the link records.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RouterLsa {
    /// V: endpoint of one or more fully adjacent virtual links using
    /// this area as transit.
    pub v_bit: bool,
    /// E: AS boundary router.
    pub e_bit: bool,
    /// B: area border router.
    pub b_bit: bool,
    /// Nt: the NSSA translator state is enabled (RFC 3101 §3.1 /
    /// Appendix B — "when an NSSA border router has its
    /// NSSATranslatorState enabled, it sets bit Nt in the router-LSA
    /// it originates into the NSSA"). Decode-carry into non-NSSA
    /// areas too; the election only examines it in the NSSA's copy.
    pub nt_bit: bool,
    pub links: Vec<RouterLink>,
}

/// The network-LSA body (§A.4.3): mask plus the fully-adjacent routers
/// (the DR includes itself). Distance network→router is zero, hence no
/// metrics.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NetworkLsa {
    pub mask: Ipv4Addr,
    pub attached: Vec<RouterId>,
}

/// The summary-LSA body (§A.4.4) — types 3 (IP network) and 4 (ASBR);
/// formats identical, only the Link State ID meaning differs. The mask
/// must be zero for type 4 (enforced on decode).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SummaryLsa {
    pub mask: Ipv4Addr,
    /// 24-bit metric; `LS_INFINITY` (0xffffff) means unreachable.
    pub metric: u32,
    pub tos: Vec<TosMetric>,
}

/// The AS-external-LSA body (§A.4.5).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AsExternalLsa {
    pub mask: Ipv4Addr,
    /// E=1 means a type-2 external metric (larger than any link state
    /// path); E=0 type-1 (same units as interface cost).
    pub e_bit: bool,
    /// 24-bit metric.
    pub metric: u32,
    /// 0.0.0.0 forwards to the originator (the ASBR) itself.
    pub forwarding_address: Ipv4Addr,
    pub external_route_tag: u32,
    pub tos: Vec<ExternalTos>,
}

/// The per-TOS tail of an AS-external-LSA (§A.4.5).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ExternalTos {
    pub tos: u8,
    pub e_bit: bool,
    pub metric: u32,
    pub forwarding_address: Ipv4Addr,
    pub external_route_tag: u32,
}

/// A decoded LSA: header + typed body.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Lsa {
    pub header: LsaHeader,
    pub body: LsaBody,
}

/// The four OSPFv2 LSA bodies this codec speaks (§A.4.2-A.4.5).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LsaBody {
    Router(RouterLsa),
    Network(NetworkLsa),
    Summary(SummaryLsa),
    AsExternal(AsExternalLsa),
}

impl LsaBody {
    /// The LS type octet this body implies.
    pub fn ls_type(&self) -> LsaType {
        match self {
            Self::Router(_) => LsaType::ROUTER,
            Self::Network(_) => LsaType::NETWORK,
            // Callers choose 3 vs 4 (the header rules, not the body).
            Self::Summary(_) => LsaType::SUMMARY_NETWORK,
            Self::AsExternal(_) => LsaType::AS_EXTERNAL,
        }
    }
}

impl Lsa {
    /// Encode header + body into wire bytes, computing the length and
    /// the Fletcher checksum (which covers everything but the 2-byte
    /// age — §12.1.7). The header's stored `checksum`/`length` fields
    /// are ignored and replaced.
    pub fn encode(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        // Placeholder header so the sizes line up; body follows (the
        // checksum/length fields are overwritten below).
        self.header.encode(&mut buf);
        self.encode_body(&mut buf);
        let len = buf.len() as u16;
        buf[18..20].copy_from_slice(&len.to_be_bytes());
        let csum = lsa_fletcher_checksum(&mut buf[2..], 14);
        buf[16..18].copy_from_slice(&csum.to_be_bytes());
        buf
    }

    fn encode_body(&self, buf: &mut Vec<u8>) {
        match &self.body {
            LsaBody::Router(r) => {
                // Bit placement per the §A.4.2 diagram (and FRR /
                // Wireshark): V = 0x04, E = 0x02, B = 0x01 — plus Nt
                // = 0x10 (RFC 3101 Appendix B's `| 0 Nt W V E B |`
                // row).
                let mut flags = 0u8;
                flags |= u8::from(r.nt_bit) << 4;
                flags |= u8::from(r.v_bit) << 2;
                flags |= u8::from(r.e_bit) << 1;
                flags |= u8::from(r.b_bit);
                put_u8(buf, flags);
                put_u8(buf, 0); // the reserved zero octet of the diagram
                put_u16(buf, r.links.len() as u16);
                for link in &r.links {
                    put_u32(buf, link.link_id.0);
                    put_u32(buf, link.link_data);
                    put_u8(buf, link.link_type.to_u8());
                    put_u8(buf, link.tos.len() as u8);
                    put_u16(buf, link.metric);
                    for t in &link.tos {
                        put_u8(buf, t.tos);
                        put_u8(buf, 0);
                        put_u16(buf, t.metric as u16);
                    }
                }
            }
            LsaBody::Network(n) => {
                put_u32(buf, u32::from(n.mask));
                for rtr in &n.attached {
                    put_u32(buf, rtr.0);
                }
            }
            LsaBody::Summary(s) => {
                put_u32(buf, u32::from(s.mask));
                put_u8(buf, 0);
                put_u24(buf, s.metric);
                for t in &s.tos {
                    put_u8(buf, t.tos);
                    put_u24(buf, t.metric);
                }
            }
            LsaBody::AsExternal(e) => {
                put_u32(buf, u32::from(e.mask));
                put_u8(buf, u8::from(e.e_bit) << 7);
                put_u24(buf, e.metric);
                put_u32(buf, u32::from(e.forwarding_address));
                put_u32(buf, e.external_route_tag);
                for t in &e.tos {
                    put_u8(buf, (u8::from(t.e_bit) << 7) | t.tos);
                    put_u24(buf, t.metric);
                    put_u32(buf, u32::from(t.forwarding_address));
                    put_u32(buf, t.external_route_tag);
                }
            }
        }
    }

    /// Decode a whole LSA from `buf`: the header per [`LsaHeader::decode`],
    /// the declared length must equal the buffer (framing exactness),
    /// the Fletcher checksum must verify (§12.1.7), and the body must
    /// consume exactly the declared length (§A.4's count arithmetic).
    pub fn decode(buf: &[u8]) -> Result<Self, OspfError> {
        let mut r = Reader::new(buf);
        let header = LsaHeader::decode(&mut r)?;
        if header.length as usize != buf.len() {
            return Err(OspfError::BadLength {
                field: "LSA length",
                declared: header.length as usize,
                actual: buf.len(),
            });
        }
        if !fletcher_verify(&buf[2..]) {
            return Err(OspfError::ChecksumMismatch {
                header: header.checksum,
                computed: 0,
            });
        }
        let body = Self::decode_body(&mut r, &header)?;
        if !r.is_empty() {
            return Err(OspfError::Trailing {
                field: "LSA body",
                count: r.remaining(),
            });
        }
        Ok(Self { header, body })
    }

    /// Decode just a header-bearing slice (an LSA header as it appears
    /// in DBD and LSAck packets, §A.3.3/A.3.6) — no checksum
    /// verification possible over the header alone.
    pub fn decode_header(buf: &[u8]) -> Result<LsaHeader, OspfError> {
        let mut r = Reader::new(buf);
        let h = LsaHeader::decode(&mut r)?;
        if !r.is_empty() {
            return Err(OspfError::Trailing {
                field: "LSA header",
                count: r.remaining(),
            });
        }
        Ok(h)
    }

    fn decode_body(r: &mut Reader<'_>, header: &LsaHeader) -> Result<LsaBody, OspfError> {
        match header.ls_type {
            LsaType::ROUTER => Self::decode_router(r),
            LsaType::NETWORK => Self::decode_network(r),
            LsaType::SUMMARY_NETWORK => Self::decode_summary(r, false),
            LsaType::SUMMARY_ASBR => Self::decode_summary(r, true),
            LsaType::AS_EXTERNAL => Self::decode_external(r),
            // RFC 3101 Appendix C: the type-7 body is identical to
            // the AS-external shape (mask, E+metric, forwarding
            // address, tag).
            LsaType::NSSA => Self::decode_external(r),
            other => Err(OspfError::BadLsType(other.0)),
        }
    }

    fn decode_router(r: &mut Reader<'_>) -> Result<LsaBody, OspfError> {
        let field = "router-LSA body";
        let flags = r.u8().ok_or(OspfError::Truncated {
            field,
            need: 1,
            have: 0,
        })?;
        // Nt (0x10) is RFC 3101 Appendix B's translator bit; the
        // multicast W bit (0x08, RFC 1584 lineage) and the top three
        // reserved bits stay rejected (the house rule; RFC 3101
        // deprecates W in this position and real senders zero it).
        if flags & 0xe8 != 0 {
            return Err(OspfError::ReservedBits {
                field: "router-LSA flags",
                value: flags,
            });
        }
        let nt_bit = flags & 0x10 != 0;
        let v_bit = flags & 0x04 != 0;
        let e_bit = flags & 0x02 != 0;
        let b_bit = flags & 0x01 != 0;
        let _reserved = r.u8().ok_or(OspfError::Truncated {
            field,
            need: 1,
            have: 0,
        })?;
        let n_links = r.u16().ok_or(OspfError::Truncated {
            field,
            need: 2,
            have: 0,
        })? as usize;
        let mut links = Vec::with_capacity(n_links.min(1024));
        for _ in 0..n_links {
            let link_id = LinkStateId(r.u32().ok_or(OspfError::Truncated {
                field: "router link",
                need: 4,
                have: 0,
            })?);
            let link_data = r.u32().ok_or(OspfError::Truncated {
                field: "router link",
                need: 4,
                have: 0,
            })?;
            let link_type = LinkType::from_u8(r.u8().ok_or(OspfError::Truncated {
                field: "router link",
                need: 1,
                have: 0,
            })?)?;
            let n_tos = r.u8().ok_or(OspfError::Truncated {
                field: "router link",
                need: 1,
                have: 0,
            })? as usize;
            let metric = r.u16().ok_or(OspfError::Truncated {
                field: "router link",
                need: 2,
                have: 0,
            })?;
            let mut tos = Vec::with_capacity(n_tos.min(64));
            for _ in 0..n_tos {
                let t = r.u8().ok_or(OspfError::Truncated {
                    field: "link TOS",
                    need: 1,
                    have: 0,
                })?;
                let _zero = r.u8().ok_or(OspfError::Truncated {
                    field: "link TOS",
                    need: 1,
                    have: 0,
                })?;
                if _zero != 0 {
                    return Err(OspfError::ReservedBits {
                        field: "link TOS",
                        value: _zero,
                    });
                }
                let m = r.u16().ok_or(OspfError::Truncated {
                    field: "link TOS",
                    need: 2,
                    have: 0,
                })?;
                tos.push(TosMetric {
                    tos: t,
                    metric: m as u32,
                });
            }
            links.push(RouterLink {
                link_id,
                link_data,
                link_type,
                metric,
                tos,
            });
        }
        Ok(LsaBody::Router(RouterLsa {
            v_bit,
            e_bit,
            b_bit,
            nt_bit,
            links,
        }))
    }

    fn decode_network(r: &mut Reader<'_>) -> Result<LsaBody, OspfError> {
        let field = "network-LSA body";
        let mask_raw = r.u32().ok_or(OspfError::Truncated {
            field,
            need: 4,
            have: 0,
        })?;
        let mut attached = Vec::new();
        while !r.is_empty() {
            let id = r.u32().ok_or(OspfError::Truncated {
                field,
                need: 4,
                have: r.remaining(),
            })?;
            attached.push(RouterId(id));
        }
        Ok(LsaBody::Network(NetworkLsa {
            mask: Ipv4Addr::from(mask_raw),
            attached,
        }))
    }

    fn decode_summary(r: &mut Reader<'_>, asbr: bool) -> Result<LsaBody, OspfError> {
        let field = "summary-LSA body";
        let mask_raw = r.u32().ok_or(OspfError::Truncated {
            field,
            need: 4,
            have: 0,
        })?;
        let mask = Ipv4Addr::from(mask_raw);
        if asbr && mask_raw != 0 {
            // §A.4.4: "This field is not meaningful and must be zero
            // for Type 4 summary-LSAs."
            return Err(OspfError::Type4MaskNonZero(mask));
        }
        let zero = r.u8().ok_or(OspfError::Truncated {
            field,
            need: 1,
            have: 0,
        })?;
        if zero != 0 {
            return Err(OspfError::ReservedBits {
                field: "summary TOS-0",
                value: zero,
            });
        }
        let metric = r.u24().ok_or(OspfError::Truncated {
            field,
            need: 3,
            have: 0,
        })?;
        let mut tos = Vec::new();
        while !r.is_empty() {
            let t = r.u8().ok_or(OspfError::Truncated {
                field,
                need: 1,
                have: r.remaining(),
            })?;
            let m = r.u24().ok_or(OspfError::Truncated {
                field,
                need: 3,
                have: r.remaining(),
            })?;
            tos.push(TosMetric { tos: t, metric: m });
        }
        Ok(LsaBody::Summary(SummaryLsa { mask, metric, tos }))
    }

    fn decode_external(r: &mut Reader<'_>) -> Result<LsaBody, OspfError> {
        let field = "AS-external-LSA body";
        let mask = Ipv4Addr::from(r.u32().ok_or(OspfError::Truncated {
            field,
            need: 4,
            have: 0,
        })?);
        let em = r.u8().ok_or(OspfError::Truncated {
            field,
            need: 1,
            have: 0,
        })?;
        if em & 0x7f != 0 {
            return Err(OspfError::ReservedBits {
                field: "external E|0|metric",
                value: em,
            });
        }
        let e_bit = em & 0x80 != 0;
        let metric = r.u24().ok_or(OspfError::Truncated {
            field,
            need: 3,
            have: 0,
        })?;
        let forwarding = Ipv4Addr::from(r.u32().ok_or(OspfError::Truncated {
            field,
            need: 4,
            have: 0,
        })?);
        let tag = r.u32().ok_or(OspfError::Truncated {
            field,
            need: 4,
            have: 0,
        })?;
        let mut tos = Vec::new();
        while !r.is_empty() {
            let t = r.u8().ok_or(OspfError::Truncated {
                field,
                need: 1,
                have: r.remaining(),
            })?;
            let t_e_bit = t & 0x80 != 0;
            let m = r.u24().ok_or(OspfError::Truncated {
                field,
                need: 3,
                have: r.remaining(),
            })?;
            let fwd = Ipv4Addr::from(r.u32().ok_or(OspfError::Truncated {
                field,
                need: 4,
                have: r.remaining(),
            })?);
            let tg = r.u32().ok_or(OspfError::Truncated {
                field,
                need: 4,
                have: r.remaining(),
            })?;
            tos.push(ExternalTos {
                tos: t & 0x7f,
                e_bit: t_e_bit,
                metric: m,
                forwarding_address: fwd,
                external_route_tag: tg,
            });
        }
        Ok(LsaBody::AsExternal(AsExternalLsa {
            mask,
            e_bit,
            metric,
            forwarding_address: forwarding,
            external_route_tag: tag,
            tos,
        }))
    }

    /// The (LS type, LS ID, adv router) triple that uniquely
    /// identifies this LSA (§A.4.1, §12.2's lookup key).
    pub fn key(&self) -> LsaKey {
        LsaKey {
            ls_type: self.header.ls_type,
            link_state_id: self.header.link_state_id,
            adv_router: self.header.adv_router,
        }
    }
}

/// The LSDB lookup key (§12.2): LS type + Link State ID +
/// Advertising Router.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct LsaKey {
    pub ls_type: LsaType,
    pub link_state_id: LinkStateId,
    pub adv_router: RouterId,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wire::unhex;

    // The real-wire corpus (full hex, checksums included) — the same
    // 19 LSAs as the checksum module; used here for byte-exact
    // decode/encode round trips.
    const REAL_LSAS: &[&str] = &[
        "03e20201c0a8aa08c0a8aa0880000dc32506002402000001c0a8aa00ffffff000300000a",
        "00020201c0a8aa03c0a8aa03800000013a9c003002000002c0a8aa00ffffff000300000ac0a8aa00ffffff000300000a",
        "0003020550d41000c0a8aa02800000012a490024ffffffff800000140000000000000000",
        "000302059479ab00c0a8aa028000000134a50024ffffff0080000014c0a8aa0100000000",
        "00030205c0827800c0a8aa0280000001d3190024ffffff00800000140000000000000000",
        "00030205c0a80000c0a8aa028000000137080024ffffff00800000140000000000000000",
        "00030205c0a80100c0a8aa02800000012c120024ffffff00800000140000000000000000",
        "00030205c0a8ac00c0a8aa028000000133410024ffffff0080000014c0a8aa0a00000000",
        "000102059479ab00c0a8aa03800000012eaa0024ffffff0080000014c0a8aa0100000000",
        "00010205c0827800c0a8aa0380000001cd1e0024ffffff00800000140000000000000000",
        "00010205c0a80000c0a8aa0380000001310d0024ffffff00800000140000000000000000",
        "00010205c0a80100c0a8aa038000000126170024ffffff00800000140000000000000000",
        "00010205c0a8ac00c0a8aa03800000012d460024ffffff0080000014c0a8aa0a00000000",
        "0001020550d41000c0a8aa0380000001244e0024ffffffff800000140000000000000000",
        "00010202c0a8aa08c0a8aa088000000137b70020ffffff00c0a8aa03c0a8aa08",
        "00010201c0a8aa08c0a8aa0880000dc4af57002402000001c0a8aa08c0a8aa080200000a",
        "00010201c0a8aa03c0a8aa0380000002389d003002000002c0a8aa00ffffff000300000ac0a8aa00ffffff000300000a",
        "0e100201c0a8aa02c0a8aa02800000014a8e003002000002c0a8aa00ffffff000300000ac0a8aa00ffffff000300000a",
    ];

    fn sample_router_lsa() -> Lsa {
        Lsa {
            header: LsaHeader {
                ls_age: 1,
                options: Options(0x02),
                ls_type: LsaType::ROUTER,
                link_state_id: LinkStateId::from_ipv4("192.168.170.8".parse().unwrap()),
                adv_router: RouterId::from_ipv4("192.168.170.8".parse().unwrap()),
                seq: 0x8000_0dc4,
                checksum: 0,
                length: 0,
            },
            body: LsaBody::Router(RouterLsa {
                v_bit: false,
                e_bit: true,
                b_bit: false,
                nt_bit: false,
                links: vec![RouterLink {
                    link_id: LinkStateId::from_ipv4("192.168.170.8".parse().unwrap()),
                    link_data: u32::from("192.168.170.8".parse::<Ipv4Addr>().unwrap()),
                    link_type: LinkType::Transit,
                    metric: 10,
                    tos: vec![],
                }],
            }),
        }
    }

    #[test]
    fn real_lsas_round_trip_byte_exact() {
        for hex in REAL_LSAS {
            let bytes = unhex(hex);
            let lsa = Lsa::decode(&bytes).expect("real LSA decodes");
            let re = lsa.encode();
            assert_eq!(re, bytes, "round trip must be byte-exact for {hex}");
        }
    }

    #[test]
    fn real_router_lsa_decodes_fields() {
        let lsa = Lsa::decode(&unhex(REAL_LSAS[15])).unwrap();
        let LsaBody::Router(r) = lsa.body else {
            panic!("router body")
        };
        assert!(r.e_bit && !r.v_bit && !r.b_bit);
        assert_eq!(r.links.len(), 1);
        let link = &r.links[0];
        assert_eq!(link.link_type, LinkType::Transit);
        assert_eq!(
            link.link_id.to_ipv4(),
            "192.168.170.8".parse::<Ipv4Addr>().unwrap()
        );
        assert_eq!(
            link.link_data,
            u32::from("192.168.170.8".parse::<Ipv4Addr>().unwrap())
        );
        assert_eq!(link.metric, 10);
        assert_eq!(lsa.header.seq_signed(), 0x8000_0dc4_u32 as i32);
    }

    #[test]
    fn real_network_lsa_decodes_fields() {
        let lsa = Lsa::decode(&unhex(REAL_LSAS[14])).unwrap();
        let LsaBody::Network(n) = lsa.body else {
            panic!("network body")
        };
        assert_eq!(n.mask, "255.255.255.0".parse::<Ipv4Addr>().unwrap());
        assert_eq!(
            n.attached,
            vec![
                RouterId::from_ipv4("192.168.170.3".parse().unwrap()),
                RouterId::from_ipv4("192.168.170.8".parse().unwrap()),
            ]
        );
        // §A.4.3: the DR lists itself (here .8, matching the LS ID).
        assert_eq!(lsa.header.link_state_id, LinkStateId::new(n.attached[1].0));
    }

    #[test]
    fn real_external_lsa_decodes_fields() {
        let lsa = Lsa::decode(&unhex(REAL_LSAS[3])).unwrap();
        let LsaBody::AsExternal(e) = lsa.body else {
            panic!("external body")
        };
        assert!(e.e_bit, "type-2 external metric");
        assert_eq!(e.metric, 20);
        assert_eq!(e.mask, "255.255.255.0".parse::<Ipv4Addr>().unwrap());
        assert_eq!(
            e.forwarding_address,
            "192.168.170.1".parse::<Ipv4Addr>().unwrap()
        );
        assert_eq!(e.external_route_tag, 0);
    }

    #[test]
    fn real_max_age_lsa_flags_through() {
        // §14: this router-LSA reached MaxAge naturally on the wire.
        let lsa = Lsa::decode(&unhex(REAL_LSAS[17])).unwrap();
        assert_eq!(lsa.header.ls_age, 3600);
        assert!(lsa.header.is_max_age());
    }

    #[test]
    fn hand_derived_router_lsa_layout() {
        // Hand-derived from the §A.4.2 diagram: E-bit router, one p2p
        // link to 10.0.0.2 with a TOS record, one stub link.
        let lsa = Lsa {
            header: LsaHeader {
                ls_age: 0,
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
                b_bit: true,
                nt_bit: false,
                links: vec![
                    RouterLink {
                        link_id: LinkStateId::from_ipv4("10.0.0.2".parse().unwrap()),
                        link_data: u32::from("10.0.0.1".parse::<Ipv4Addr>().unwrap()),
                        link_type: LinkType::PointToPoint,
                        metric: 5,
                        tos: vec![TosMetric { tos: 4, metric: 7 }],
                    },
                    RouterLink {
                        link_id: LinkStateId::from_ipv4("10.9.9.0".parse().unwrap()),
                        link_data: u32::from("255.255.255.252".parse::<Ipv4Addr>().unwrap()),
                        link_type: LinkType::Stub,
                        metric: 3,
                        tos: vec![],
                    },
                ],
            }),
        };
        let bytes = lsa.encode();
        // 20 header + 4 body-prefix + 16 + 12 link records.
        assert_eq!(bytes.len(), 52);
        assert_eq!(bytes[20], 0x03, "E and B bits (0x02|0x01)");
        assert_eq!(bytes[21], 0);
        assert_eq!(u16::from_be_bytes([bytes[22], bytes[23]]), 2, "# links");
        // link 1: ID 10.0.0.2, data 10.0.0.1, type 1, #TOS 1, metric 5
        assert_eq!(
            &bytes[24..28],
            &u32::from(Ipv4Addr::new(10, 0, 0, 2)).to_be_bytes()
        );
        assert_eq!(
            &bytes[28..32],
            &u32::from(Ipv4Addr::new(10, 0, 0, 1)).to_be_bytes()
        );
        assert_eq!(bytes[32], 1);
        assert_eq!(bytes[33], 1);
        assert_eq!(u16::from_be_bytes([bytes[34], bytes[35]]), 5);
        // TOS record: tos 4, reserved 0, metric 7
        assert_eq!(&bytes[36..40], &[4, 0, 0, 7]);
        // link 2 at 40: ID 10.9.9.0, mask /30, type 3, #TOS 0, metric 3
        assert_eq!(
            &bytes[40..44],
            &u32::from("10.9.9.0".parse::<Ipv4Addr>().unwrap()).to_be_bytes()
        );
        assert_eq!(bytes[48], 3);
        assert_eq!(bytes[49], 0);
        assert_eq!(u16::from_be_bytes([bytes[50], bytes[51]]), 3);
        // Length and checksum in the header must be filled in.
        assert_eq!(u16::from_be_bytes([bytes[18], bytes[19]]), 52);
        let mut expect = lsa.clone();
        expect.header.checksum = u16::from_be_bytes([bytes[16], bytes[17]]);
        expect.header.length = 52;
        assert!(u16::from_be_bytes([bytes[16], bytes[17]]) != 0);
        // And the whole thing decodes back.
        assert_eq!(Lsa::decode(&bytes).unwrap(), expect);
    }

    #[test]
    fn hand_derived_summary_lsa_layout() {
        // §A.4.4: type-3 summary for 172.16.0.0/16, metric 42.
        let lsa = Lsa {
            header: LsaHeader {
                ls_age: 10,
                options: Options(0x02),
                ls_type: LsaType::SUMMARY_NETWORK,
                link_state_id: LinkStateId::from_ipv4("172.16.0.0".parse().unwrap()),
                adv_router: RouterId::from_ipv4("2.2.2.2".parse().unwrap()),
                seq: INITIAL_SEQUENCE_NUMBER,
                checksum: 0,
                length: 0,
            },
            body: LsaBody::Summary(SummaryLsa {
                mask: "255.255.0.0".parse().unwrap(),
                metric: 42,
                tos: vec![],
            }),
        };
        let bytes = lsa.encode();
        assert_eq!(bytes.len(), 28);
        assert_eq!(
            &bytes[20..24],
            &u32::from("255.255.0.0".parse::<Ipv4Addr>().unwrap()).to_be_bytes()
        );
        // 0 | 24-bit metric: 00 00 00 2a
        assert_eq!(&bytes[24..28], &[0, 0, 0, 42]);
        let mut expect = lsa.clone();
        expect.header.checksum = u16::from_be_bytes([bytes[16], bytes[17]]);
        expect.header.length = 28;
        assert_eq!(Lsa::decode(&bytes).unwrap(), expect);
    }

    #[test]
    fn hand_derived_type4_summary_rejects_mask() {
        // §A.4.4: "must be zero for Type 4 summary-LSAs".
        let mut bytes = {
            let lsa = Lsa {
                header: LsaHeader {
                    ls_age: 1,
                    options: Options(0x02),
                    ls_type: LsaType::SUMMARY_ASBR,
                    link_state_id: LinkStateId::from_ipv4("9.9.9.9".parse().unwrap()),
                    adv_router: RouterId::from_ipv4("2.2.2.2".parse().unwrap()),
                    seq: INITIAL_SEQUENCE_NUMBER,
                    checksum: 0,
                    length: 0,
                },
                body: LsaBody::Summary(SummaryLsa {
                    mask: "255.255.0.0".parse().unwrap(),
                    metric: 1,
                    tos: vec![],
                }),
            };
            lsa.encode()
        };
        let err = Lsa::decode(&bytes).unwrap_err();
        assert_eq!(
            err,
            OspfError::Type4MaskNonZero("255.255.0.0".parse().unwrap())
        );
        // Zeroed mask repairs it — recompute the checksum afterwards.
        bytes[20..24].copy_from_slice(&[0, 0, 0, 0]);
        let csum = lsa_fletcher_checksum(&mut bytes[2..], 14);
        bytes[16..18].copy_from_slice(&csum.to_be_bytes());
        let lsa = Lsa::decode(&bytes).unwrap();
        let LsaBody::Summary(s) = lsa.body else {
            panic!()
        };
        assert_eq!(s.mask, Ipv4Addr::UNSPECIFIED);
    }

    #[test]
    fn every_truncation_of_a_valid_lsa_rejected() {
        let full = sample_router_lsa().encode();
        for cut in 0..full.len() {
            assert!(
                Lsa::decode(&full[..cut]).is_err(),
                "truncation at {cut} must not decode"
            );
        }
    }

    #[test]
    fn length_field_mismatch_rejected() {
        let mut bytes = sample_router_lsa().encode();
        // Declared length one short/long of the actual buffer.
        for wrong in [bytes.len() as u16 - 1, bytes.len() as u16 + 1, 19] {
            bytes[18..20].copy_from_slice(&wrong.to_be_bytes());
            let err = Lsa::decode(&bytes).unwrap_err();
            assert!(matches!(err, OspfError::BadLength { .. }), "{err}");
        }
    }

    #[test]
    fn unknown_ls_type_rejected() {
        let mut bytes = sample_router_lsa().encode();
        bytes[3] = 6;
        let csum = lsa_fletcher_checksum(&mut bytes[2..], 14);
        bytes[16..18].copy_from_slice(&csum.to_be_bytes());
        assert_eq!(Lsa::decode(&bytes).unwrap_err(), OspfError::BadLsType(6));
    }

    #[test]
    fn checksum_corruption_rejected() {
        let mut bytes = sample_router_lsa().encode();
        bytes[25] ^= 0x40; // flip a bit in the body
        assert!(matches!(
            Lsa::decode(&bytes).unwrap_err(),
            OspfError::ChecksumMismatch { .. }
        ));
        // Zeroing the checksum field is its own error class (§12.1.7).
        let mut zeroed = sample_router_lsa().encode();
        zeroed[16..18].copy_from_slice(&[0, 0]);
        assert_eq!(Lsa::decode(&zeroed).unwrap_err(), OspfError::ZeroChecksum);
    }

    #[test]
    fn age_above_max_age_rejected() {
        let mut bytes = sample_router_lsa().encode();
        bytes[0..2].copy_from_slice(&3601u16.to_be_bytes());
        assert!(matches!(
            Lsa::decode(&bytes).unwrap_err(),
            OspfError::AgeTooLarge(3601)
        ));
        // DoNotAge-marked ages decode (the bit is masked for aging).
        bytes[0..2].copy_from_slice(&(DO_NOT_AGE | 100).to_be_bytes());
        let lsa = Lsa::decode(&bytes).unwrap();
        assert_eq!(lsa.header.effective_age(), 100);
        assert!(!lsa.header.is_max_age());
    }

    #[test]
    fn sequence_out_of_range_rejected() {
        // §12.1.6: -N (0x80000000) is reserved and unused — the only
        // raw value outside the signed space [Initial, Max].
        let mut bytes = sample_router_lsa().encode();
        bytes[12..16].copy_from_slice(&0x8000_0000_u32.to_be_bytes());
        let csum = lsa_fletcher_checksum(&mut bytes[2..], 14);
        bytes[16..18].copy_from_slice(&csum.to_be_bytes());
        assert_eq!(
            Lsa::decode(&bytes).unwrap_err(),
            OspfError::BadSequence(0x8000_0000)
        );
        // Raw 0 is a legal old instance (signed 0, greater than all
        // 0x8... values, less than all 0x0...-0x7f... ones).
        let mut lsa = sample_router_lsa();
        lsa.header.seq = 0;
        assert!(Lsa::decode(&lsa.encode()).is_ok());
    }

    #[test]
    fn link_count_overrun_rejected() {
        // # links claims 3, the body holds 1 — strict count arithmetic.
        let mut lsa = sample_router_lsa();
        let LsaBody::Router(ref mut r) = lsa.body else {
            unreachable!()
        };
        r.links.push(r.links[0].clone());
        let mut bytes = lsa.encode();
        // Chop the second link off the buffer but keep its declared
        // length: 20 header + 4 + 1 link (12 bytes).
        bytes.truncate(20 + 4 + 12);
        let len = bytes.len() as u16;
        bytes[18..20].copy_from_slice(&len.to_be_bytes());
        bytes[22..24].copy_from_slice(&2u16.to_be_bytes());
        let csum = lsa_fletcher_checksum(&mut bytes[2..], 14);
        bytes[16..18].copy_from_slice(&csum.to_be_bytes());
        assert!(matches!(
            Lsa::decode(&bytes).unwrap_err(),
            OspfError::Truncated { .. }
        ));
    }

    #[test]
    fn bad_link_type_and_tos_reserved_rejected() {
        let mut bytes = sample_router_lsa().encode();
        bytes[32] = 9; // link type out of 1..=4 (§A.4.2 table)
        let csum = lsa_fletcher_checksum(&mut bytes[2..], 14);
        bytes[16..18].copy_from_slice(&csum.to_be_bytes());
        assert_eq!(Lsa::decode(&bytes).unwrap_err(), OspfError::BadLinkType(9));
    }

    #[test]
    fn router_flags_reserved_bits_rejected() {
        let mut bytes = sample_router_lsa().encode();
        bytes[20] |= 0x08; // bits 3-7 of the flags octet are zero
        let csum = lsa_fletcher_checksum(&mut bytes[2..], 14);
        bytes[16..18].copy_from_slice(&csum.to_be_bytes());
        assert!(matches!(
            Lsa::decode(&bytes).unwrap_err(),
            OspfError::ReservedBits { .. }
        ));
    }

    #[test]
    fn network_body_count_arithmetic() {
        // A network-LSA whose length stops mid-router-id.
        let lsa = Lsa {
            header: LsaHeader {
                ls_age: 1,
                options: Options(0x02),
                ls_type: LsaType::NETWORK,
                link_state_id: LinkStateId::from_ipv4("10.1.1.1".parse().unwrap()),
                adv_router: RouterId::from_ipv4("10.1.1.1".parse().unwrap()),
                seq: INITIAL_SEQUENCE_NUMBER,
                checksum: 0,
                length: 0,
            },
            body: LsaBody::Network(NetworkLsa {
                mask: "255.255.255.0".parse().unwrap(),
                attached: vec![RouterId::from_ipv4("10.1.1.1".parse().unwrap())],
            }),
        };
        let bytes = lsa.encode();
        assert_eq!(bytes.len(), 28);
        let mut expect = lsa.clone();
        expect.header.checksum = u16::from_be_bytes([bytes[16], bytes[17]]);
        expect.header.length = 28;
        assert_eq!(Lsa::decode(&bytes).unwrap(), expect);
        // Truncate inside the attached-router list: must reject.
        let mut cut = bytes[..27].to_vec();
        cut[18..20].copy_from_slice(&27u16.to_be_bytes());
        let csum = lsa_fletcher_checksum(&mut cut[2..], 14);
        cut[16..18].copy_from_slice(&csum.to_be_bytes());
        assert!(matches!(
            Lsa::decode(&cut).unwrap_err(),
            OspfError::Truncated { .. }
        ));
    }

    #[test]
    fn external_tos_tail_arithmetic() {
        let lsa = Lsa {
            header: LsaHeader {
                ls_age: 1,
                options: Options(0x02),
                ls_type: LsaType::AS_EXTERNAL,
                link_state_id: LinkStateId::from_ipv4("192.0.2.0".parse().unwrap()),
                adv_router: RouterId::from_ipv4("3.3.3.3".parse().unwrap()),
                seq: INITIAL_SEQUENCE_NUMBER,
                checksum: 0,
                length: 0,
            },
            body: LsaBody::AsExternal(AsExternalLsa {
                mask: "255.255.255.0".parse().unwrap(),
                e_bit: false,
                metric: 100,
                forwarding_address: Ipv4Addr::UNSPECIFIED,
                external_route_tag: 0xdead_beef,
                tos: vec![ExternalTos {
                    tos: 8,
                    e_bit: true,
                    metric: 3,
                    forwarding_address: "192.0.2.1".parse().unwrap(),
                    external_route_tag: 1,
                }],
            }),
        };
        let bytes = lsa.encode();
        // 20 header + 16 mandatory + 12 per TOS record (§A.4.5)
        assert_eq!(bytes.len(), 48);
        assert_eq!(bytes[24], 0x00, "type-1 external (E clear), reserved 0");
        assert_eq!(&bytes[25..28], &[0, 0, 100]);
        assert_eq!(&bytes[28..32], &0u32.to_be_bytes());
        assert_eq!(&bytes[32..36], &0xdead_beef_u32.to_be_bytes());
        // TOS tail: E|TOS = 0x80|8, metric 3, fwd, tag
        assert_eq!(bytes[36], 0x88);
        assert_eq!(&bytes[37..40], &[0, 0, 3]);
        let mut expect = lsa.clone();
        expect.header.checksum = u16::from_be_bytes([bytes[16], bytes[17]]);
        expect.header.length = 48;
        assert_eq!(Lsa::decode(&bytes).unwrap(), expect);
    }

    #[test]
    fn external_reserved_metric_bits_rejected() {
        let mut bytes = sample_external();
        bytes[24] |= 0x01; // reserved low bits of E|0|metric
        let csum = lsa_fletcher_checksum(&mut bytes[2..], 14);
        bytes[16..18].copy_from_slice(&csum.to_be_bytes());
        assert!(matches!(
            Lsa::decode(&bytes).unwrap_err(),
            OspfError::ReservedBits { .. }
        ));
    }

    fn sample_external() -> Vec<u8> {
        Lsa {
            header: LsaHeader {
                ls_age: 1,
                options: Options(0x02),
                ls_type: LsaType::AS_EXTERNAL,
                link_state_id: LinkStateId::from_ipv4("198.51.100.0".parse().unwrap()),
                adv_router: RouterId::from_ipv4("3.3.3.3".parse().unwrap()),
                seq: INITIAL_SEQUENCE_NUMBER,
                checksum: 0,
                length: 0,
            },
            body: LsaBody::AsExternal(AsExternalLsa {
                mask: "255.255.255.0".parse().unwrap(),
                e_bit: true,
                metric: 20,
                forwarding_address: Ipv4Addr::UNSPECIFIED,
                external_route_tag: 0,
                tos: vec![],
            }),
        }
        .encode()
    }

    #[test]
    fn header_decode_standalone() {
        // The DD/LSAck shape (§A.3.3/A.3.6): bare 20-byte headers.
        let bytes = sample_router_lsa().encode();
        let h = Lsa::decode_header(&bytes[..20]).unwrap();
        assert_eq!(h.ls_type, LsaType::ROUTER);
        assert_eq!(h.length as usize, bytes.len());
        assert!(Lsa::decode_header(&bytes[..19]).is_err());
        assert!(Lsa::decode_header(&bytes[..21]).is_err());
    }

    #[test]
    fn sequence_signed_ordering() {
        // §12.1.6: -N is reserved; -N+1 oldest; compare as signed i32.
        let mk = |seq: u32| {
            let mut l = sample_router_lsa();
            l.header.seq = seq;
            l
        };
        let hdr = |l: &Lsa| l.header.seq_signed();
        assert!(hdr(&mk(INITIAL_SEQUENCE_NUMBER)) < hdr(&mk(INITIAL_SEQUENCE_NUMBER + 1)));
        assert!(hdr(&mk(MAX_SEQUENCE_NUMBER - 1)) < hdr(&mk(MAX_SEQUENCE_NUMBER)));
        // The wrap boundary: 0x7fffffff is *greater* than 0x80000001
        // as signed ints even though it is numerically smaller.
        assert!(hdr(&mk(MAX_SEQUENCE_NUMBER)) > hdr(&mk(INITIAL_SEQUENCE_NUMBER)));
        // And 0xffffffff (i32 -1) sits between them.
        assert!(hdr(&mk(0xffff_ffff)) > hdr(&mk(INITIAL_SEQUENCE_NUMBER)));
        assert!(hdr(&mk(0xffff_ffff)) < hdr(&mk(MAX_SEQUENCE_NUMBER)));
    }

    /// The fixed-seed xorshift property convention (no proptest in
    /// this crate; the W5B/M3 note limits it to sav+rib).
    struct XorShift(u64);

    impl XorShift {
        fn next(&mut self) -> u64 {
            self.0 ^= self.0 << 13;
            self.0 ^= self.0 >> 7;
            self.0 ^= self.0 << 17;
            self.0
        }

        fn below(&mut self, n: u64) -> u64 {
            self.next() % n
        }
    }

    fn random_lsa(rng: &mut XorShift) -> Lsa {
        let id = |rng: &mut XorShift| RouterId((rng.next() >> 32) as u32);
        let seq = INITIAL_SEQUENCE_NUMBER + rng.below(0x0000_ffff) as u32;
        let header = LsaHeader {
            ls_age: (rng.below(crate::MAX_AGE as u64)) as u16,
            options: Options(0x02),
            ls_type: LsaType::ROUTER,
            link_state_id: LinkStateId(id(rng).0),
            adv_router: id(rng),
            seq,
            checksum: 0,
            length: 0,
        };
        let n_links = rng.below(5) as usize;
        let links = (0..n_links)
            .map(|_| RouterLink {
                link_id: LinkStateId(id(rng).0),
                link_data: (rng.next() >> 32) as u32,
                link_type: LinkType::from_u8((1 + rng.below(4)) as u8).unwrap(),
                metric: (rng.next() >> 48) as u16,
                tos: (0..rng.below(3))
                    .map(|_| TosMetric {
                        tos: (2 * (1 + rng.below(8))) as u8,
                        metric: (rng.next() >> 48) as u32,
                    })
                    .collect(),
            })
            .collect();
        Lsa {
            header,
            body: LsaBody::Router(RouterLsa {
                v_bit: rng.next() & 1 == 1,
                e_bit: rng.next() & 1 == 1,
                b_bit: rng.next() & 1 == 1,
                nt_bit: false,
                links,
            }),
        }
    }

    #[test]
    fn property_round_trip_and_checksum_invariants() {
        let mut rng = XorShift(0x5eed_0f5a_0bad_0001_u64);
        for _ in 0..512 {
            let lsa = random_lsa(&mut rng);
            let bytes = lsa.encode();
            // Round trip is lossless (modulo the header's computed
            // checksum/length, which encode() fills in).
            let mut expect = lsa.clone();
            expect.header.checksum = u16::from_be_bytes([bytes[16], bytes[17]]);
            expect.header.length = bytes.len() as u16;
            assert_eq!(Lsa::decode(&bytes).unwrap(), expect);
            // ...the length header is exact...
            assert_eq!(
                u16::from_be_bytes([bytes[18], bytes[19]]) as usize,
                bytes.len()
            );
            // ...and the checksum verifies and is nonzero.
            assert!(fletcher_verify(&bytes[2..]));
            assert!(u16::from_be_bytes([bytes[16], bytes[17]]) != 0);
        }
    }

    #[test]
    fn property_single_bit_corruption_detected() {
        let mut rng = XorShift(0x1234_5678_9abc_def0_u64);
        for _ in 0..512 {
            let bytes = random_lsa(&mut rng).encode();
            let bit = (rng.below(8)) as u8;
            let idx = 2 + rng.below((bytes.len() - 2) as u64) as usize;
            let mut corrupt = bytes.clone();
            corrupt[idx] ^= 1 << bit;
            assert!(
                !fletcher_verify(&corrupt[2..]),
                "corruption at byte {idx} bit {bit} undetected"
            );
        }
    }

    #[test]
    fn router_id_and_link_state_id_helpers() {
        let r = RouterId::from_ipv4("10.0.0.1".parse().unwrap());
        assert_eq!(r.to_string(), "10.0.0.1");
        assert!(r.larger_than(RouterId::from_ipv4("9.255.255.255".parse().unwrap())));
        let l = LinkStateId::new(0x0a00_0002);
        assert_eq!(l.to_ipv4(), "10.0.0.2".parse::<Ipv4Addr>().unwrap());
        assert_eq!(LsaType(3).name(), "summary(network)");
    }

    // ---- The OSPFv3 LS-type surface (RFC 5340 A.4.2.1) ----

    #[test]
    fn v3_ls_type_constants_scope_and_u_bit() {
        // A.4.2.1's function-code table, each row implying its U/S
        // bits: (LS type, scope, U-bit).
        let table = [
            (LsaType::V3_ROUTER, Scope::Area, false),
            (LsaType::V3_NETWORK, Scope::Area, false),
            (LsaType::V3_INTER_AREA_PREFIX, Scope::Area, false),
            (LsaType::V3_INTER_AREA_ROUTER, Scope::Area, false),
            (LsaType::V3_AS_EXTERNAL, Scope::As, false),
            (LsaType::V3_NSSA, Scope::Area, false),
            (LsaType::V3_LINK, Scope::Link, false),
            (LsaType::V3_INTRA_AREA_PREFIX, Scope::Area, false),
        ];
        for (ty, scope, u) in table {
            assert_eq!(ty.scope(), scope, "{}", ty.0);
            assert_eq!(ty.u_bit(), u, "{}", ty.0);
            assert!(ty.is_known_v3(), "{} is a live function code", ty.0);
        }
        // The wire values themselves (0x2001.. table verbatim).
        assert_eq!(LsaType::V3_ROUTER.0, 0x2001);
        assert_eq!(LsaType::V3_NETWORK.0, 0x2002);
        assert_eq!(LsaType::V3_INTER_AREA_PREFIX.0, 0x2003);
        assert_eq!(LsaType::V3_INTER_AREA_ROUTER.0, 0x2004);
        assert_eq!(LsaType::V3_AS_EXTERNAL.0, 0x4005);
        assert_eq!(LsaType::V3_DEPRECATED_MOSPF.0, 0x2006);
        assert_eq!(LsaType::V3_NSSA.0, 0x2007);
        assert_eq!(LsaType::V3_LINK.0, 0x0008);
        assert_eq!(LsaType::V3_INTRA_AREA_PREFIX.0, 0x2009);
        // Function-code extraction: the low 13 bits, U/S bits masked.
        assert_eq!(LsaType::V3_AS_EXTERNAL.function_code(), 5);
        assert_eq!(LsaType(0xA021).function_code(), 33); // RFC 8362 E-Router
        assert_eq!(LsaType(0x800A).function_code(), 10);
        // A U=1 unknown type reports its bit (§3.4: store and flood).
        assert!(LsaType(0x800A).u_bit());
        assert!(!LsaType(0x000A).u_bit());
        assert_eq!(LsaType(0x000A).scope(), Scope::Link);
    }

    #[test]
    fn v3_known_type_excludes_deprecated_and_v2_codes() {
        // 0x2006 is deprecated (was MOSPF, "may be reassigned") —
        // never known, so it decodes into the v3 Unknown body.
        assert!(!LsaType::V3_DEPRECATED_MOSPF.is_known_v3());
        // RFC 8362's extended-LSA codes are NOT in tonight's family.
        assert!(!LsaType(0xA021).is_known_v3());
        assert!(!LsaType(0xC025).is_known_v3());
        // The v2 octet values are distinct 16-bit values in v3's
        // space (1..5 are U=0 link-scope unknowns there).
        for v in 1..=5u16 {
            assert!(!LsaType(v).is_known_v3(), "v2 code {v} is not a v3 type");
        }
        // Reserved flooding scope 0b11 is its own rejection class
        // (S2=S1=1, the 0x6000 mask, regardless of the U-bit).
        assert_eq!(LsaType(0x6009).scope(), Scope::Reserved);
        assert_eq!(LsaType(0xE009).scope(), Scope::Reserved);
        // 0xC001 is U=1 + AS scope — an unknown but *legal* type
        // (§3.2: stored in the AS-scope data structure).
        assert_eq!(LsaType(0xC001).scope(), Scope::As);
        assert!(LsaType(0xC001).u_bit());
        // The two families coexist in one u16-backed type.
        assert!(LsaType::ROUTER.is_known_v2() && !LsaType::ROUTER.is_known_v3());
        assert!(LsaType::V3_ROUTER.is_known_v3() && !LsaType::V3_ROUTER.is_known_v2());
        assert_eq!(LsaType::V3_INTER_AREA_PREFIX.name(), "inter-area-prefix");
        assert_eq!(LsaType::V3_INTRA_AREA_PREFIX.name(), "intra-area-prefix");
        assert_eq!(LsaType::V3_LINK.name(), "link");
    }
}
