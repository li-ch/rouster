//! The BGP path-attribute model and codec (RFC 4271 §4.3, §5; MP
//! attributes per RFC 4760; communities per RFC 1997; AS4 attributes
//! per RFC 6793).
//!
//! Model rules:
//! - Well-known attributes decode into typed variants with their flags
//!   checked against §4.3's table (violations are Attribute Flags
//!   Errors, subcode 4).
//! - Unknown *optional* attributes are carried as
//!   [`PathAttribute::Unknown`] and re-advertised verbatim with the
//!   partial bit set (§5: "if ... recognized ... pass it along"; §4.3
//!   partial semantics for unrecognised transitive ones).
//! - An unknown attribute *without* the optional bit is an Unrecognized
//!   Well-known Attribute (§6.3, subcode 2).
//! - [`AsPath`] decodes both 2- and 4-octet AS numbers (RFC 6793 §4/5);
//!   the width is the session's negotiated encoding, supplied by the
//!   caller — the wire bytes alone do not carry it.

use std::net::{Ipv4Addr, Ipv6Addr};

use common::IpPrefix;

use crate::error::{self, BgpError, BgpResult};
use crate::wire::{put_u16, put_u32, Reader};

pub mod attr_type {
    pub const ORIGIN: u8 = 1;
    pub const AS_PATH: u8 = 2;
    pub const NEXT_HOP: u8 = 3;
    pub const MULTI_EXIT_DISC: u8 = 4;
    pub const LOCAL_PREF: u8 = 5;
    pub const ATOMIC_AGGREGATE: u8 = 6;
    pub const AGGREGATOR: u8 = 7;
    pub const COMMUNITIES: u8 = 8;
    pub const MP_REACH_NLRI: u8 = 14;
    pub const MP_UNREACH_NLRI: u8 = 15;
    pub const AS4_PATH: u8 = 17;
    pub const AS4_AGGREGATOR: u8 = 18;
}

/// Attribute flag bits (RFC 4271 §4.3).
pub mod attr_flag {
    pub const OPTIONAL: u8 = 0x80;
    pub const TRANSITIVE: u8 = 0x40;
    pub const PARTIAL: u8 = 0x20;
    pub const EXTENDED_LENGTH: u8 = 0x10;
}

/// The flags a well-known attribute must carry (§4.3): not optional,
/// transitive, not partial, not extended (unless the value needs it).
const WELL_KNOWN_FLAGS: u8 = attr_flag::TRANSITIVE;
/// Optional non-transitive (MED, MP_REACH, MP_UNREACH): 0x80.
const OPTIONAL_NON_TRANSITIVE: u8 = attr_flag::OPTIONAL;
/// Optional transitive (AGGREGATOR, COMMUNITIES, AS4_*): 0xC0.
const OPTIONAL_TRANSITIVE: u8 = attr_flag::OPTIONAL | attr_flag::TRANSITIVE;

/// ORIGIN values (RFC 4271 §4.3 / §5.1.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Origin {
    Igp,
    Egp,
    Incomplete,
}

impl Origin {
    pub fn as_u8(self) -> u8 {
        match self {
            Self::Igp => 0,
            Self::Egp => 1,
            Self::Incomplete => 2,
        }
    }

    fn from_u8(v: u8) -> Option<Self> {
        match v {
            0 => Some(Self::Igp),
            1 => Some(Self::Egp),
            2 => Some(Self::Incomplete),
            _ => None,
        }
    }
}

/// One AS_PATH segment: `AS_SET` (type 1) or `AS_SEQUENCE` (type 2)
/// (RFC 4271 §4.3).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AsSegment {
    Set(Vec<u32>),
    Sequence(Vec<u32>),
}

impl AsSegment {
    fn seg_type(&self) -> u8 {
        match self {
            Self::Set(_) => 1,
            Self::Sequence(_) => 2,
        }
    }

    pub fn path_count(&self) -> usize {
        match self {
            // An AS_SET counts as 1 (§9.1.2.2 a)).
            Self::Set(_) => 1,
            Self::Sequence(v) => v.len(),
        }
    }
}

/// An AS_PATH (or AS4_PATH — same encoding, wider ASes when
/// negotiated).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct AsPath {
    pub segments: Vec<AsSegment>,
}

impl AsPath {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn sequence(asns: impl IntoIterator<Item = u32>) -> Self {
        Self {
            segments: vec![AsSegment::Sequence(asns.into_iter().collect())],
        }
    }

    /// Length for the §9.1.2.2 a) tiebreak: sum of segment path counts.
    pub fn path_length(&self) -> usize {
        self.segments.iter().map(|s| s.path_count()).sum()
    }

    /// The rightmost AS_SEQUENCE element (the neighbor-AS seed for the
    /// §9.1.2.2 c) MED comparability rule), if any.
    pub fn neighbor_as(&self) -> Option<u32> {
        self.segments.iter().rev().find_map(|s| match s {
            AsSegment::Sequence(v) => v.last().copied(),
            AsSegment::Set(_) => None,
        })
    }

    fn encode(&self, out: &mut Vec<u8>, asn4: bool) {
        for seg in &self.segments {
            let asns = match seg {
                AsSegment::Set(v) => v,
                AsSegment::Sequence(v) => v,
            };
            out.push(seg.seg_type());
            out.push(asns.len() as u8);
            for asn in asns {
                if asn4 {
                    put_u32(out, *asn);
                } else {
                    put_u16(out, asn_widen(*asn));
                }
            }
        }
    }

    fn decode(buf: &[u8], asn4: bool) -> BgpResult<Self> {
        let mut r = Reader::new(buf);
        let mut segments = Vec::new();
        while !r.is_empty() {
            let seg_type = r
                .u8()
                .ok_or_else(|| as_path_error("truncated AS_PATH segment header"))?;
            let count = r
                .u8()
                .ok_or_else(|| as_path_error("truncated AS_PATH segment count"))?;
            let width = if asn4 { 4 } else { 2 };
            let bytes = r
                .take(count as usize * width)
                .ok_or_else(|| as_path_error("AS_PATH segment overruns attribute"))?;
            let asns: Vec<u32> = bytes
                .chunks_exact(width)
                .map(|c| {
                    if asn4 {
                        u32::from_be_bytes([c[0], c[1], c[2], c[3]])
                    } else {
                        u16::from_be_bytes([c[0], c[1]]) as u32
                    }
                })
                .collect();
            match seg_type {
                1 => segments.push(AsSegment::Set(asns)),
                2 => segments.push(AsSegment::Sequence(asns)),
                other => {
                    return Err(as_path_error(format!(
                        "unknown AS_PATH segment type {other}"
                    )))
                }
            }
        }
        Ok(Self { segments })
    }
}

fn as_path_error(what: impl Into<String>) -> BgpError {
    BgpError::notify(
        error::error_code::UPDATE_MESSAGE,
        error::update_subcode::MALFORMED_AS_PATH,
        what,
    )
}

/// A 2-octet encoding of a 4-octet AS: values that don't map become
/// AS_TRANS 23456 (RFC 6793 §4: non-mappable four-octet AS numbers are
/// represented by the reserved AS_TRANS).
fn asn_widen(asn: u32) -> u16 {
    if asn > u16::MAX as u32 {
        crate::AS_TRANS
    } else {
        asn as u16
    }
}

/// MP_REACH next hop (RFC 4760 §3): the length field decides the form.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MpNextHop {
    V4(Ipv4Addr),
    V6 {
        global: Ipv6Addr,
        link_local: Option<Ipv6Addr>,
    },
    /// An opaque next hop for an AFI/SAFI bgpd does not understand —
    /// kept verbatim, never routed through.
    Raw([u8; 16]),
}

impl MpNextHop {
    fn encode(&self, out: &mut Vec<u8>) -> usize {
        match self {
            Self::V4(a) => {
                out.extend_from_slice(&a.octets());
                4
            }
            Self::V6 {
                global,
                link_local: Some(ll),
            } => {
                out.extend_from_slice(&global.octets());
                out.extend_from_slice(&ll.octets());
                32
            }
            Self::V6 {
                global,
                link_local: None,
            } => {
                out.extend_from_slice(&global.octets());
                16
            }
            Self::Raw(bytes) => {
                out.extend_from_slice(bytes);
                bytes.len()
            }
        }
    }
}

/// MP_REACH_NLRI (attribute 14, RFC 4760 §3).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MpReach {
    pub afi: u16,
    pub safi: u8,
    pub next_hop: MpNextHop,
    pub nlri: Vec<IpPrefix>,
}

/// MP_UNREACH_NLRI (attribute 15, RFC 4760 §4).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MpUnreach {
    pub afi: u16,
    pub safi: u8,
    pub withdrawn: Vec<IpPrefix>,
}

/// One path attribute, typed for the ones v1 understands.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PathAttribute {
    Origin(Origin),
    AsPath(AsPath),
    NextHop(Ipv4Addr),
    Med(u32),
    LocalPref(u32),
    AtomicAggregate,
    Aggregator {
        asn: u32,
        addr: Ipv4Addr,
    },
    Communities(Vec<u32>),
    MpReach(MpReach),
    MpUnreach(MpUnreach),
    /// RFC 6793 AS4_PATH: kept decoded so a 2-octet session can still
    /// inspect the real path (v1: passthrough).
    As4Path(AsPath),
    As4Aggregator {
        asn: u32,
        addr: Ipv4Addr,
    },
    /// Unrecognized optional attribute, bytes verbatim; re-advertised
    /// with the partial bit forced (§5).
    Unknown {
        attr_type: u8,
        flags: u8,
        value: Vec<u8>,
    },
}

impl PathAttribute {
    pub fn attr_type(&self) -> u8 {
        match self {
            Self::Origin(_) => attr_type::ORIGIN,
            Self::AsPath(_) => attr_type::AS_PATH,
            Self::NextHop(_) => attr_type::NEXT_HOP,
            Self::Med(_) => attr_type::MULTI_EXIT_DISC,
            Self::LocalPref(_) => attr_type::LOCAL_PREF,
            Self::AtomicAggregate => attr_type::ATOMIC_AGGREGATE,
            Self::Aggregator { .. } => attr_type::AGGREGATOR,
            Self::Communities(_) => attr_type::COMMUNITIES,
            Self::MpReach(_) => attr_type::MP_REACH_NLRI,
            Self::MpUnreach(_) => attr_type::MP_UNREACH_NLRI,
            Self::As4Path(_) => attr_type::AS4_PATH,
            Self::As4Aggregator { .. } => attr_type::AS4_AGGREGATOR,
            Self::Unknown { attr_type, .. } => *attr_type,
        }
    }

    /// The flags this attribute must carry on the wire (§4.3 tables).
    fn expected_flags(&self) -> Option<u8> {
        match self {
            Self::Origin(_)
            | Self::AsPath(_)
            | Self::NextHop(_)
            | Self::LocalPref(_)
            | Self::AtomicAggregate => Some(WELL_KNOWN_FLAGS),
            Self::Med(_) | Self::MpReach(_) | Self::MpUnreach(_) => Some(OPTIONAL_NON_TRANSITIVE),
            Self::Aggregator { .. }
            | Self::Communities(_)
            | Self::As4Path(_)
            | Self::As4Aggregator { .. } => Some(OPTIONAL_TRANSITIVE),
            Self::Unknown { .. } => None,
        }
    }

    fn encode_value(&self, out: &mut Vec<u8>, asn4: bool) {
        match self {
            Self::Origin(o) => out.push(o.as_u8()),
            Self::AsPath(p) => p.encode(out, asn4),
            // AS4_PATH is always 4-octet ASes, whatever the session
            // encoding (RFC 6793 §4.2) — its purpose is carrying the
            // wide path across 2-octet speakers.
            Self::As4Path(p) => p.encode(out, true),
            Self::NextHop(a) => out.extend_from_slice(&a.octets()),
            Self::Med(v) | Self::LocalPref(v) => put_u32(out, *v),
            Self::AtomicAggregate => {}
            Self::Aggregator { asn, addr } | Self::As4Aggregator { asn, addr } => {
                if asn4 {
                    put_u32(out, *asn);
                } else {
                    put_u16(out, asn_widen(*asn));
                }
                out.extend_from_slice(&addr.octets());
            }
            Self::Communities(cs) => {
                for c in cs {
                    put_u32(out, *c);
                }
            }
            Self::MpReach(mp) => {
                put_u16(out, mp.afi);
                out.push(mp.safi);
                let mut nh = Vec::new();
                let nh_len = mp.next_hop.encode(&mut nh);
                out.push(nh_len as u8);
                out.extend_from_slice(&nh);
                out.push(0); // Reserved: MUST be 0 (RFC 4760 §3)
                for prefix in &mp.nlri {
                    encode_prefix(out, *prefix);
                }
            }
            Self::MpUnreach(mp) => {
                put_u16(out, mp.afi);
                out.push(mp.safi);
                for prefix in &mp.withdrawn {
                    encode_prefix(out, *prefix);
                }
            }
            Self::Unknown { value, .. } => out.extend_from_slice(value),
        }
    }
}

/// NLRI prefix encoding shared by the NLRI, withdrawn-routes and MP
/// fields: 1 length octet + `ceil(len/8)` address octets, host order,
/// trailing bits zero.
pub fn encode_prefix(out: &mut Vec<u8>, prefix: IpPrefix) {
    match prefix {
        IpPrefix::V4(p) => {
            out.push(p.prefix_len());
            let bytes = p.addr().octets();
            let n = prefix_bytes(p.prefix_len());
            out.extend_from_slice(&bytes[..n]);
        }
        IpPrefix::V6(p) => {
            out.push(p.prefix_len());
            let bytes = p.addr().octets();
            let n = prefix_bytes(p.prefix_len());
            out.extend_from_slice(&bytes[..n]);
        }
    }
}

/// Decodes one prefix from the reader for the family in context: the
/// base UPDATE's NLRI/withdrawn fields are IPv4-only (RFC 4271 §4.3),
/// MP fields follow their AFI. Trailing bits beyond the prefix length
/// are masked to their canonical zero form (senders SHOULD zero them;
/// we do not reject, RFC 4271 §4.3 NLRI note).
pub fn decode_prefix(r: &mut Reader<'_>, v6: bool) -> BgpResult<IpPrefix> {
    let invalid_network = || {
        BgpError::notify(
            error::error_code::UPDATE_MESSAGE,
            error::update_subcode::INVALID_NETWORK_FIELD,
            "malformed NLRI prefix",
        )
    };
    let len = r.u8().ok_or_else(invalid_network)?;
    let v6 = match (v6, len) {
        (false, 0..=32) => false,
        (true, 0..=128) => true,
        _ => return Err(invalid_network()),
    };
    let n = prefix_bytes(len);
    let bytes = r.take(n).ok_or_else(invalid_network)?;
    let mut full = [0u8; 16];
    full[..n].copy_from_slice(bytes);
    // Mask trailing bits to canonical form.
    let rem = len % 8;
    if rem != 0 {
        let last = n - 1;
        full[last] &= 0xffu8 << (8 - rem);
    }
    if v6 {
        Ok(IpPrefix::V6(
            common::Ipv6Prefix::new(Ipv6Addr::from(full), len)
                .map_err(|e| BgpError::local(e.to_string()))?,
        ))
    } else {
        Ok(IpPrefix::V4(
            common::Ipv4Prefix::new(Ipv4Addr::new(full[0], full[1], full[2], full[3]), len)
                .map_err(|e| BgpError::local(e.to_string()))?,
        ))
    }
}

fn prefix_bytes(len: u8) -> usize {
    (len as usize).div_ceil(8)
}

/// Decodes a whole attribute list (the `Path Attributes` field of an
/// UPDATE). Duplicate well-known attributes are a Malformed Attribute
/// List (§6.3, subcode 1).
pub fn decode_attributes(buf: &[u8], asn4: bool) -> BgpResult<Vec<PathAttribute>> {
    let mut r = Reader::new(buf);
    let mut attrs = Vec::new();
    let mut seen: Vec<u8> = Vec::new();
    while !r.is_empty() {
        let flags = r
            .u8()
            .ok_or_else(|| attr_truncated("attribute flags octet"))?;
        let attr_type = r
            .u8()
            .ok_or_else(|| attr_truncated("attribute type octet"))?;
        let length = if flags & attr_flag::EXTENDED_LENGTH != 0 {
            r.u16()
                .ok_or_else(|| attr_truncated("extended attribute length"))? as usize
        } else {
            r.u8().ok_or_else(|| attr_truncated("attribute length"))? as usize
        };
        let value = r.take(length).ok_or_else(|| {
            BgpError::notify(
                error::error_code::UPDATE_MESSAGE,
                error::update_subcode::ATTRIBUTE_LENGTH_ERROR,
                format!("attribute {attr_type} length {length} overruns message"),
            )
        })?;

        let well_known = flags & attr_flag::OPTIONAL == 0;
        if well_known {
            if attr_type > attr_type::MP_UNREACH_NLRI && !known_type(attr_type) {
                // A well-known attribute we do not recognize (§6.3).
                return Err(BgpError::notify(
                    error::error_code::UPDATE_MESSAGE,
                    error::update_subcode::UNRECOGNIZED_WELL_KNOWN_ATTRIBUTE,
                    format!("unrecognized well-known attribute {attr_type}"),
                ));
            }
            if seen.contains(&attr_type) {
                return Err(BgpError::notify(
                    error::error_code::UPDATE_MESSAGE,
                    error::update_subcode::MALFORMED_ATTRIBUTE_LIST,
                    format!("duplicate well-known attribute {attr_type}"),
                ));
            }
            seen.push(attr_type);
        }

        let attr = decode_one(attr_type, flags, value, asn4)?;
        attrs.push(attr);
    }
    Ok(attrs)
}

fn known_type(attr_type: u8) -> bool {
    matches!(
        attr_type,
        attr_type::ORIGIN
            | attr_type::AS_PATH
            | attr_type::NEXT_HOP
            | attr_type::LOCAL_PREF
            | attr_type::ATOMIC_AGGREGATE
    )
}

fn attr_truncated(what: &str) -> BgpError {
    BgpError::notify(
        error::error_code::UPDATE_MESSAGE,
        error::update_subcode::ATTRIBUTE_LENGTH_ERROR,
        format!("truncated {what}"),
    )
}

fn flags_error(attr_type: u8, flags: u8) -> BgpError {
    BgpError::notify(
        error::error_code::UPDATE_MESSAGE,
        error::update_subcode::ATTRIBUTE_FLAGS_ERROR,
        format!("attribute {attr_type} flags {flags:#04x} violate §4.3"),
    )
}

fn length_error(attr_type: u8, expected: usize, got: usize) -> BgpError {
    BgpError::notify(
        error::error_code::UPDATE_MESSAGE,
        error::update_subcode::ATTRIBUTE_LENGTH_ERROR,
        format!("attribute {attr_type} length {got}, expected {expected} (§4.3)"),
    )
}

fn decode_one(attr_type: u8, flags: u8, value: &[u8], asn4: bool) -> BgpResult<PathAttribute> {
    match attr_type {
        attr_type::ORIGIN => {
            if flags & !attr_flag::EXTENDED_LENGTH != WELL_KNOWN_FLAGS {
                return Err(flags_error(attr_type, flags));
            }
            if value.len() != 1 {
                return Err(length_error(attr_type, 1, value.len()));
            }
            let origin = Origin::from_u8(value[0]).ok_or_else(|| {
                BgpError::notify(
                    error::error_code::UPDATE_MESSAGE,
                    error::update_subcode::INVALID_ORIGIN,
                    format!("invalid ORIGIN value {:#04x}", value[0]),
                )
            })?;
            Ok(PathAttribute::Origin(origin))
        }
        attr_type::AS_PATH => {
            check_well_known_flags(attr_type, flags)?;
            Ok(PathAttribute::AsPath(AsPath::decode(value, asn4)?))
        }
        attr_type::NEXT_HOP => {
            check_well_known_flags(attr_type, flags)?;
            if value.len() != 4 {
                return Err(length_error(attr_type, 4, value.len()));
            }
            let addr = Ipv4Addr::new(value[0], value[1], value[2], value[3]);
            if !valid_next_hop(addr) {
                return Err(BgpError::notify(
                    error::error_code::UPDATE_MESSAGE,
                    error::update_subcode::INVALID_NEXT_HOP,
                    format!("syntactically invalid NEXT_HOP {addr} (§6.3)"),
                ));
            }
            Ok(PathAttribute::NextHop(addr))
        }
        attr_type::MULTI_EXIT_DISC => {
            if flags & !attr_flag::EXTENDED_LENGTH != OPTIONAL_NON_TRANSITIVE {
                return Err(flags_error(attr_type, flags));
            }
            u32_from(value, attr_type).map(PathAttribute::Med)
        }
        attr_type::LOCAL_PREF => {
            check_well_known_flags(attr_type, flags)?;
            u32_from(value, attr_type).map(PathAttribute::LocalPref)
        }
        attr_type::ATOMIC_AGGREGATE => {
            check_well_known_flags(attr_type, flags)?;
            if !value.is_empty() {
                return Err(length_error(attr_type, 0, value.len()));
            }
            Ok(PathAttribute::AtomicAggregate)
        }
        attr_type::AGGREGATOR | attr_type::AS4_AGGREGATOR => {
            if flags & !attr_flag::EXTENDED_LENGTH != OPTIONAL_TRANSITIVE {
                return Err(flags_error(attr_type, flags));
            }
            let expect = if asn4 { 8 } else { 6 };
            if value.len() != expect {
                return Err(length_error(attr_type, expect, value.len()));
            }
            let (asn, addr) = if asn4 {
                (
                    u32::from_be_bytes([value[0], value[1], value[2], value[3]]),
                    Ipv4Addr::new(value[4], value[5], value[6], value[7]),
                )
            } else {
                (
                    u16::from_be_bytes([value[0], value[1]]) as u32,
                    Ipv4Addr::new(value[2], value[3], value[4], value[5]),
                )
            };
            if attr_type == attr_type::AGGREGATOR {
                Ok(PathAttribute::Aggregator { asn, addr })
            } else {
                Ok(PathAttribute::As4Aggregator { asn, addr })
            }
        }
        attr_type::COMMUNITIES => {
            if flags & !attr_flag::EXTENDED_LENGTH != OPTIONAL_TRANSITIVE {
                return Err(flags_error(attr_type, flags));
            }
            if !value.len().is_multiple_of(4) {
                return Err(BgpError::notify(
                    error::error_code::UPDATE_MESSAGE,
                    error::update_subcode::OPTIONAL_ATTRIBUTE_ERROR,
                    "COMMUNITIES length not a multiple of 4 (RFC 1997 §2)",
                ));
            }
            let communities = value
                .as_chunks::<4>()
                .0
                .iter()
                .map(|c| u32::from_be_bytes([c[0], c[1], c[2], c[3]]))
                .collect();
            Ok(PathAttribute::Communities(communities))
        }
        attr_type::MP_REACH_NLRI => {
            if flags & !attr_flag::EXTENDED_LENGTH != OPTIONAL_NON_TRANSITIVE {
                return Err(flags_error(attr_type, flags));
            }
            let mut r = Reader::new(value);
            let afi = r
                .u16()
                .ok_or_else(|| mp_malformed("truncated MP_REACH AFI"))?;
            let safi = r
                .u8()
                .ok_or_else(|| mp_malformed("truncated MP_REACH SAFI"))?;
            let nh_len = r
                .u8()
                .ok_or_else(|| mp_malformed("truncated MP_REACH next-hop length"))?
                as usize;
            let nh_bytes = r
                .take(nh_len)
                .ok_or_else(|| mp_malformed("MP_REACH next hop overruns attribute"))?;
            let next_hop = match (afi, safi, nh_len) {
                (1, 1, 4) => MpNextHop::V4(Ipv4Addr::new(
                    nh_bytes[0],
                    nh_bytes[1],
                    nh_bytes[2],
                    nh_bytes[3],
                )),
                (2, 1, 16) => MpNextHop::V6 {
                    global: ipv6_from(&nh_bytes[..16]),
                    link_local: None,
                },
                (2, 1, 32) => MpNextHop::V6 {
                    global: ipv6_from(&nh_bytes[..16]),
                    link_local: Some(ipv6_from(&nh_bytes[16..32])),
                },
                _ => {
                    if nh_len > 16 {
                        return Err(mp_malformed("MP_REACH next-hop length too large"));
                    }
                    let mut raw = [0u8; 16];
                    raw[..nh_len].copy_from_slice(nh_bytes);
                    MpNextHop::Raw(raw)
                }
            };
            // Reserved octet: MUST be 0 on send, SHOULD be ignored on
            // receipt (RFC 4760 §3) — accepted silently.
            r.take(1)
                .ok_or_else(|| mp_malformed("truncated MP_REACH reserved octet"))?;
            let v6 = afi == 2;
            let mut nlri = Vec::new();
            while !r.is_empty() {
                nlri.push(decode_prefix(&mut r, v6)?);
            }
            Ok(PathAttribute::MpReach(MpReach {
                afi,
                safi,
                next_hop,
                nlri,
            }))
        }
        attr_type::MP_UNREACH_NLRI => {
            if flags & !attr_flag::EXTENDED_LENGTH != OPTIONAL_NON_TRANSITIVE {
                return Err(flags_error(attr_type, flags));
            }
            let mut r = Reader::new(value);
            let afi = r
                .u16()
                .ok_or_else(|| mp_malformed("truncated MP_UNREACH AFI"))?;
            let safi = r
                .u8()
                .ok_or_else(|| mp_malformed("truncated MP_UNREACH SAFI"))?;
            let v6 = afi == 2;
            let mut withdrawn = Vec::new();
            while !r.is_empty() {
                withdrawn.push(decode_prefix(&mut r, v6)?);
            }
            Ok(PathAttribute::MpUnreach(MpUnreach {
                afi,
                safi,
                withdrawn,
            }))
        }
        attr_type::AS4_PATH => {
            if flags & !attr_flag::EXTENDED_LENGTH != OPTIONAL_TRANSITIVE {
                return Err(flags_error(attr_type, flags));
            }
            // AS4_PATH is always 4-octet ASes, regardless of the
            // session encoding (RFC 6793 §4.2 note: NEW speakers encode
            // AS4_PATH with 4-octet).
            Ok(PathAttribute::As4Path(AsPath::decode(value, true)?))
        }
        _ => Ok(PathAttribute::Unknown {
            attr_type,
            flags,
            value: value.to_vec(),
        }),
    }
}

fn ipv6_from(bytes: &[u8]) -> Ipv6Addr {
    let mut full = [0u8; 16];
    full.copy_from_slice(bytes);
    Ipv6Addr::from(full)
}

fn check_well_known_flags(attr_type: u8, flags: u8) -> BgpResult<()> {
    if flags & !attr_flag::EXTENDED_LENGTH != WELL_KNOWN_FLAGS {
        return Err(flags_error(attr_type, flags));
    }
    Ok(())
}

fn u32_from(value: &[u8], attr_type: u8) -> BgpResult<u32> {
    if value.len() != 4 {
        return Err(length_error(attr_type, 4, value.len()));
    }
    Ok(u32::from_be_bytes([value[0], value[1], value[2], value[3]]))
}

fn mp_malformed(what: &str) -> BgpError {
    BgpError::notify(
        error::error_code::UPDATE_MESSAGE,
        error::update_subcode::OPTIONAL_ATTRIBUTE_ERROR,
        format!("{what} (RFC 4760)"),
    )
}

/// Syntactically invalid NEXT_HOPs per RFC 4271 §6.3: the examples the
/// RFC lists as detectable — 0.0.0.0, multicast (224/4), and
/// 240.0.0.0/4 (class E, includes the all-ones broadcast).
fn valid_next_hop(addr: Ipv4Addr) -> bool {
    let [a, _, _, _] = addr.octets();
    !(addr.is_unspecified() || a >= 224)
}

/// Encodes the full attribute list. Well-known/typed attributes carry
/// their §4.3 flags; unknown ones carry their received flags with the
/// partial bit forced.
pub fn encode_attributes(attrs: &[PathAttribute], out: &mut Vec<u8>, asn4: bool) -> BgpResult<()> {
    for attr in attrs {
        let mut value = Vec::new();
        attr.encode_value(&mut value, asn4);
        let mut flags = match attr.expected_flags() {
            Some(f) => f,
            None => {
                let PathAttribute::Unknown { flags, .. } = attr else {
                    unreachable!("expected_flags None only for Unknown")
                };
                *flags | attr_flag::PARTIAL
            }
        };
        if value.len() > u8::MAX as usize {
            flags |= attr_flag::EXTENDED_LENGTH;
        }
        out.push(flags);
        out.push(attr.attr_type());
        if flags & attr_flag::EXTENDED_LENGTH != 0 {
            put_u16(out, value.len() as u16);
        } else {
            out.push(value.len() as u8);
        }
        out.extend_from_slice(&value);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn p4(s: &str) -> IpPrefix {
        s.parse().unwrap()
    }

    fn attrs_bytes(attrs: &[PathAttribute], asn4: bool) -> Vec<u8> {
        let mut out = Vec::new();
        encode_attributes(attrs, &mut out, asn4).unwrap();
        out
    }

    #[test]
    fn origin_round_trip_and_flags() {
        let attrs = [PathAttribute::Origin(Origin::Igp)];
        let bytes = attrs_bytes(&attrs, false);
        assert_eq!(bytes, vec![0x40, 1, 1, 0], "well-known flags 0x40, IGP=0");
        assert_eq!(decode_attributes(&bytes, false).unwrap().to_vec(), attrs);
    }

    #[test]
    fn as_path_two_and_four_octet() {
        let attrs = [PathAttribute::AsPath(AsPath::sequence([65001, 65002]))];
        let two = attrs_bytes(&attrs, false);
        assert_eq!(two, vec![0x40, 2, 6, 2, 2, 0xfd, 0xe9, 0xfd, 0xea]);
        assert_eq!(decode_attributes(&two, false).unwrap().to_vec(), attrs);
        let four = attrs_bytes(&attrs, true);
        // 2-octet segment header + 2 x 4-octet AS = 10 value bytes.
        assert_eq!(
            four,
            vec![0x40, 2, 10, 2, 2, 0, 0, 0xfd, 0xe9, 0, 0, 0xfd, 0xea]
        );
        assert_eq!(decode_attributes(&four, true).unwrap().to_vec(), attrs);
    }

    #[test]
    fn non_mappable_asn_uses_as_trans() {
        let attrs = [PathAttribute::AsPath(AsPath::sequence([4200000001]))];
        let two = attrs_bytes(&attrs, false);
        // 4200000001 > 65535 -> 23456 (0x5BA0) per RFC 6793 §4
        assert_eq!(two[5..7], [0x5b, 0xa0]);
    }

    #[test]
    fn as_set_counts_one_in_path_length() {
        let path = AsPath {
            segments: vec![
                AsSegment::Sequence(vec![1, 2, 3]),
                AsSegment::Set(vec![4, 5, 6]),
                AsSegment::Sequence(vec![7]),
            ],
        };
        assert_eq!(
            path.path_length(),
            5,
            "3 (sequence) + 1 (set) + 1 (sequence)"
        );
    }

    #[test]
    fn med_local_pref_communities_round_trip() {
        let attrs = vec![
            PathAttribute::Med(100),
            PathAttribute::LocalPref(200),
            PathAttribute::Communities(vec![0xFFFF_FF01, 65001 << 16 | 100]),
        ];
        let bytes = attrs_bytes(&attrs, false);
        assert_eq!(decode_attributes(&bytes, false).unwrap(), attrs);
    }

    #[test]
    fn mp_reach_v6_round_trip() {
        let attrs = vec![PathAttribute::MpReach(MpReach {
            afi: 2,
            safi: 1,
            next_hop: MpNextHop::V6 {
                global: "2001:db8::1".parse().unwrap(),
                link_local: Some("fe80::1".parse().unwrap()),
            },
            nlri: vec![p4("2001:db8:1::/48")],
        })];
        let bytes = attrs_bytes(&attrs, true);
        // 16+16 next hop, reserved 0, then /48 = 6 bytes NLRI
        let decoded = decode_attributes(&bytes, true).unwrap();
        assert_eq!(decoded, attrs);
        if let PathAttribute::MpReach(mp) = &decoded[0] {
            assert_eq!(bytes.len(), 4 + 2 + 1 + 1 + 32 + 1 + 6);
            assert_eq!(mp.nlri, vec![p4("2001:db8:1::/48")]);
        } else {
            panic!("mp reach lost");
        }
    }

    #[test]
    fn mp_reach_next_hop_length_overrun_rejected() {
        // flags 0x80, type 14, len, afi=2 safi=1 nh_len=16 but only 4 bytes
        let bytes = vec![0x80, 14, 7, 0x00, 0x02, 0x01, 16, 1, 2, 3, 4];
        let err = decode_attributes(&bytes, true).unwrap_err();
        assert_eq!(
            err.notification,
            Some((3, error::update_subcode::OPTIONAL_ATTRIBUTE_ERROR))
        );
    }

    #[test]
    fn mp_reach_missing_reserved_octet_rejected() {
        // afi=1 safi=1 nh_len=4 nh=4 bytes, nothing after (reserved missing)
        let bytes = vec![0x80, 14, 7, 0x00, 0x01, 0x01, 4, 10, 0, 0, 1];
        assert!(decode_attributes(&bytes, false).is_err());
    }

    #[test]
    fn unknown_optional_attr_passes_through_with_partial() {
        let bytes = vec![0xC0, 99, 2, 0xAA, 0xBB];
        let decoded = decode_attributes(&bytes, false).unwrap();
        match &decoded[0] {
            PathAttribute::Unknown { flags, value, .. } => {
                assert_eq!(*flags, 0xC0);
                assert_eq!(value, &vec![0xAA, 0xBB]);
            }
            other => panic!("expected unknown, got {other:?}"),
        }
        let re = attrs_bytes(&decoded, false);
        // partial bit now forced on re-advertisement
        assert_eq!(re[0], 0xE0);
    }

    #[test]
    fn unrecognized_well_known_attr_rejected() {
        // type 99 without optional bit
        let bytes = vec![0x40, 99, 2, 0xAA, 0xBB];
        let err = decode_attributes(&bytes, false).unwrap_err();
        assert_eq!(
            err.notification,
            Some((3, error::update_subcode::UNRECOGNIZED_WELL_KNOWN_ATTRIBUTE))
        );
    }

    #[test]
    fn duplicate_well_known_rejected() {
        let mut bytes = attrs_bytes(&[PathAttribute::Origin(Origin::Egp)], false);
        bytes.extend_from_slice(&attrs_bytes(&[PathAttribute::Origin(Origin::Igp)], false));
        let err = decode_attributes(&bytes, false).unwrap_err();
        assert_eq!(
            err.notification,
            Some((3, error::update_subcode::MALFORMED_ATTRIBUTE_LIST))
        );
    }

    #[test]
    fn invalid_origin_value_rejected() {
        let bytes = vec![0x40, 1, 1, 7];
        let err = decode_attributes(&bytes, false).unwrap_err();
        assert_eq!(
            err.notification,
            Some((3, error::update_subcode::INVALID_ORIGIN))
        );
    }

    #[test]
    fn next_hop_syntactic_checks() {
        for bad in ["0.0.0.0", "224.0.0.1", "255.255.255.255", "240.0.0.1"] {
            let addr: Ipv4Addr = bad.parse().unwrap();
            let bytes = vec![0x40, 3, 4]
                .into_iter()
                .chain(addr.octets())
                .collect::<Vec<_>>();
            let err = decode_attributes(&bytes, false).unwrap_err();
            assert_eq!(
                err.notification,
                Some((3, error::update_subcode::INVALID_NEXT_HOP)),
                "{bad} must be Invalid NEXT_HOP"
            );
        }
    }

    #[test]
    fn attribute_length_overrun_rejected() {
        // declares 8 bytes of AS_PATH, provides none
        let bytes = vec![0x40, 2, 8];
        let err = decode_attributes(&bytes, false).unwrap_err();
        assert_eq!(
            err.notification,
            Some((3, error::update_subcode::ATTRIBUTE_LENGTH_ERROR))
        );
    }

    #[test]
    fn extended_length_round_trip() {
        // An AS_PATH with >255 bytes of value forces extended length.
        let asns: Vec<u32> = (0..100).collect();
        let attrs = [PathAttribute::AsPath(AsPath::sequence(asns.clone()))];
        let bytes = attrs_bytes(&attrs, true);
        assert_eq!(
            bytes[0] & attr_flag::EXTENDED_LENGTH,
            attr_flag::EXTENDED_LENGTH
        );
        assert_eq!(&bytes[2..4], &(bytes.len() as u16 - 4).to_be_bytes());
        assert_eq!(decode_attributes(&bytes, true).unwrap().to_vec(), attrs);
    }

    #[test]
    fn as_path_segment_overrun_rejected() {
        // count says 3 ASes (2-octet each = 6 bytes), only 2 present
        let bytes = vec![0x40, 2, 3, 2, 3, 0x00, 0x01];
        let err = decode_attributes(&bytes, false).unwrap_err();
        assert_eq!(
            err.notification,
            Some((3, error::update_subcode::MALFORMED_AS_PATH))
        );
    }

    #[test]
    fn unknown_segment_type_rejected() {
        let bytes = vec![0x40, 2, 4, 3, 1, 0x00, 0x01];
        let err = decode_attributes(&bytes, false).unwrap_err();
        assert_eq!(
            err.notification,
            Some((3, error::update_subcode::MALFORMED_AS_PATH))
        );
    }

    #[test]
    fn flags_violation_rejected_for_med_marked_transitive() {
        // MED with 0xC0 (optional transitive) violates §4.3
        let bytes = vec![0xC0, 4, 4, 0, 0, 0, 100];
        let err = decode_attributes(&bytes, false).unwrap_err();
        assert_eq!(
            err.notification,
            Some((3, error::update_subcode::ATTRIBUTE_FLAGS_ERROR))
        );
    }

    #[test]
    fn nlri_prefix_round_trip_and_masking() {
        let mut out = Vec::new();
        encode_prefix(&mut out, p4("203.0.113.128/25"));
        assert_eq!(out, vec![25, 203, 0, 113, 128]);
        let mut r = Reader::new(&out);
        assert_eq!(
            decode_prefix(&mut r, false).unwrap(),
            p4("203.0.113.128/25")
        );

        // Dirty trailing bits are canonicalized, not rejected.
        let mut r = Reader::new(&[25, 203, 0, 113, 131]);
        assert_eq!(
            decode_prefix(&mut r, false).unwrap(),
            p4("203.0.113.128/25")
        );
    }

    #[test]
    fn nlri_prefix_length_bounds() {
        assert!(
            decode_prefix(&mut Reader::new(&[0]), false).is_ok(),
            "/0 is valid"
        );
        assert!(
            decode_prefix(&mut Reader::new(&[33]), false).is_err(),
            ">32 invalid for v4 NLRI"
        );
        assert!(
            decode_prefix(&mut Reader::new(&[33, 0x20]), true).is_err(),
            "incomplete v6"
        );
    }

    #[test]
    fn prefix_length_129_rejected() {
        assert!(decode_prefix(&mut Reader::new(&[129]), true).is_err());
    }

    #[test]
    fn as4_path_always_four_octet() {
        let path = AsPath::sequence([4200000001, 65002]);
        let bytes = attrs_bytes(&[PathAttribute::As4Path(path.clone())], false);
        let decoded = decode_attributes(&bytes, false).unwrap();
        // Even on a 2-octet session AS4_PATH decodes 4-octet ASNs.
        assert_eq!(decoded[0], PathAttribute::As4Path(path));
    }

    #[test]
    fn neighbor_as_is_rightmost_sequence_element() {
        let path = AsPath {
            segments: vec![
                AsSegment::Sequence(vec![64512, 65001]),
                AsSegment::Set(vec![7, 8]),
            ],
        };
        assert_eq!(path.neighbor_as(), Some(65001));
    }

    /// Property-style: random attribute permutations round-trip. A tiny
    /// xorshift stands in for a proptest dependency (no-nightly fuzz
    /// substitute, disclosed) — 256 structured cases per run.
    #[test]
    fn random_attribute_lists_round_trip() {
        let mut rng = 0x9e3779b97f4a7c15u64;
        let mut next = move || {
            rng ^= rng << 13;
            rng ^= rng >> 7;
            rng ^= rng << 17;
            rng
        };
        for round in 0..256u32 {
            let asn4 = next() % 2 == 0;
            let mut attrs = vec![
                PathAttribute::Origin(match next() % 3 {
                    0 => Origin::Igp,
                    1 => Origin::Egp,
                    _ => Origin::Incomplete,
                }),
                PathAttribute::AsPath(AsPath::sequence([65001 + (next() % 500) as u32])),
            ];
            if next() % 2 == 0 {
                attrs.push(PathAttribute::Med((next() % 1_000_000) as u32));
            }
            if next() % 2 == 0 {
                attrs.push(PathAttribute::LocalPref((next() % 1000) as u32 + 1));
            }
            if next() % 2 == 0 {
                attrs.push(PathAttribute::Communities(vec![
                    (next() as u32) << 16 | (next() % 65536) as u32,
                ]));
            }
            if next() % 2 == 0 {
                attrs.push(PathAttribute::MpReach(MpReach {
                    afi: 2,
                    safi: 1,
                    next_hop: MpNextHop::V6 {
                        global: "2001:db8::1".parse().unwrap(),
                        link_local: None,
                    },
                    nlri: vec![p4(&format!("2001:db8:{round:x}::/64"))],
                }));
            }
            let bytes = attrs_bytes(&attrs, asn4);
            assert_eq!(
                decode_attributes(&bytes, asn4).unwrap(),
                attrs,
                "round {round} asn4={asn4}"
            );
        }
    }
}
