//! The BGP message framing and per-type codecs (RFC 4271 §4):
//! marker/length/type header (§4.1), OPEN (§4.2, with capabilities per
//! RFC 5492 and extended optional parameters per RFC 9072), UPDATE
//! (§4.3, MP_REACH/MP_UNREACH per RFC 4760), NOTIFICATION (§4.5),
//! KEEPALIVE (§4.4), and ROUTE-REFRESH (RFC 2918 §3, message type 5).
//!
//! Every length and count field is validated against the bytes that
//! actually follow before it is believed (the A19 lesson), and every
//! rejection carries the NOTIFICATION (code, subcode) the RFC's §6
//! handling rules prescribe for it.

use std::net::Ipv4Addr;

use common::IpPrefix;

use crate::attr::{
    decode_attributes, decode_prefix, encode_attributes, encode_prefix, AsPath, Origin,
    PathAttribute,
};
use crate::capability::{decode_capabilities, encode_capabilities, Capability};
use crate::error::{self, BgpError, BgpResult};
use crate::wire::{put_u16, Reader};

/// Marker: 16 octets of all ones (RFC 4271 §4.1).
pub const BGP_MARKER: [u8; 16] = [0xff; 16];
/// Header length (§4.1).
pub const BGP_HEADER_LEN: u16 = 19;
/// Maximum message length (§4.1: 4096 octets).
pub const BGP_MAX_MESSAGE_LEN: u16 = 4096;

pub mod message_type {
    pub const OPEN: u8 = 1;
    pub const UPDATE: u8 = 2;
    pub const NOTIFICATION: u8 = 3;
    pub const KEEPALIVE: u8 = 4;
    pub const ROUTE_REFRESH: u8 = 5;
}

/// One BGP message, decoded. The session's negotiated AS width
/// (`asn4`, set when both sides advertised the RFC 6793 capability)
/// governs AS_PATH AS size on both directions — it is an argument,
/// never a wire fact.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BgpMessage {
    Open(BgpOpen),
    Update(BgpUpdate),
    Notification(BgpNotification),
    Keepalive,
    RouteRefresh(BgpRouteRefresh),
}

impl BgpMessage {
    pub fn message_type(&self) -> u8 {
        match self {
            Self::Open(_) => message_type::OPEN,
            Self::Update(_) => message_type::UPDATE,
            Self::Notification(_) => message_type::NOTIFICATION,
            Self::Keepalive => message_type::KEEPALIVE,
            Self::RouteRefresh(_) => message_type::ROUTE_REFRESH,
        }
    }

    /// Full encoded frame (header + body), RFC-capped at 4096 octets.
    pub fn encode(&self, asn4: bool) -> BgpResult<Vec<u8>> {
        let mut body = Vec::new();
        match self {
            Self::Open(open) => open.encode(&mut body),
            Self::Update(update) => update.encode(&mut body, asn4)?,
            Self::Notification(n) => n.encode(&mut body),
            Self::Keepalive => {}
            Self::RouteRefresh(rr) => rr.encode(&mut body),
        }
        let length = BGP_HEADER_LEN + body.len() as u16;
        if length > BGP_MAX_MESSAGE_LEN {
            return Err(BgpError::local(format!(
                "message needs {length} octets, over the 4096 cap (§4.1)"
            )));
        }
        let mut frame = Vec::with_capacity(length as usize);
        frame.extend_from_slice(&BGP_MARKER);
        put_u16(&mut frame, length);
        frame.push(self.message_type());
        frame.extend_from_slice(&body);
        Ok(frame)
    }

    /// Decodes one frame (header + body; `buf` must be exactly one
    /// message — the session layer frames first).
    pub fn decode(buf: &[u8], asn4: bool) -> BgpResult<Self> {
        let mut r = Reader::new(buf);
        let marker = r.take(16).ok_or_else(|| BgpError::local("short header"))?;
        if marker != BGP_MARKER {
            return Err(BgpError::notify(
                error::error_code::MESSAGE_HEADER,
                error::header_subcode::CONNECTION_NOT_SYNCHRONIZED,
                "marker is not all ones (§6.1)",
            ));
        }
        let length = r.u16().ok_or_else(|| BgpError::local("short length"))?;
        if !(BGP_HEADER_LEN..=BGP_MAX_MESSAGE_LEN).contains(&length) {
            return Err(BgpError::notify(
                error::error_code::MESSAGE_HEADER,
                error::header_subcode::BAD_MESSAGE_LENGTH,
                format!("message length {length} outside 19..=4096 (§4.1)"),
            ));
        }
        if length as usize != buf.len() {
            return Err(BgpError::local(format!(
                "frame is {} octets, header says {length}",
                buf.len()
            )));
        }
        let msg_type = r.u8().ok_or_else(|| BgpError::local("short type"))?;
        let body = r.rest();
        // Per-type minimum sizes (§4.2/§4.3/§4.4/§4.5; RFC 2918 §3).
        let min = match msg_type {
            message_type::OPEN => 29,
            message_type::UPDATE => 23,
            message_type::NOTIFICATION => 21,
            message_type::KEEPALIVE => 19,
            message_type::ROUTE_REFRESH => 23,
            other => {
                return Err(BgpError::notify(
                    error::error_code::MESSAGE_HEADER,
                    error::header_subcode::BAD_MESSAGE_TYPE,
                    format!("unknown message type {other} (§6.1)"),
                ))
            }
        };
        if length < min {
            return Err(BgpError::notify(
                error::error_code::MESSAGE_HEADER,
                error::header_subcode::BAD_MESSAGE_LENGTH,
                format!("type {msg_type} length {length} below minimum {min}"),
            ));
        }
        Ok(match msg_type {
            message_type::OPEN => Self::Open(BgpOpen::decode(body)?),
            message_type::UPDATE => Self::Update(BgpUpdate::decode(body, asn4)?),
            message_type::NOTIFICATION => Self::Notification(BgpNotification::decode(body)?),
            // §4.4: a KEEPALIVE is exactly the 19-octet header (the
            // type-minimum check above rejected any data octets).
            message_type::KEEPALIVE => Self::Keepalive,
            _ => Self::RouteRefresh(BgpRouteRefresh::decode(body)?),
        })
    }
}

/// An OPEN message (RFC 4271 §4.2).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BgpOpen {
    pub version: u8,
    /// The 2-octet My Autonomous System field: the real AS when it
    /// maps, AS_TRANS (23456) otherwise (RFC 6793 §4.1); the real
    /// 4-octet value rides capability 65.
    pub my_as: u16,
    pub hold_time: u16,
    pub bgp_id: Ipv4Addr,
    pub capabilities: Vec<Capability>,
}

impl BgpOpen {
    pub fn new(asn: u32, hold_time: u16, bgp_id: Ipv4Addr, capabilities: Vec<Capability>) -> Self {
        let mut caps = capabilities;
        if !caps
            .iter()
            .any(|c| matches!(c, Capability::FourOctetAsNumber { .. }))
        {
            caps.push(Capability::FourOctetAsNumber { asn });
        }
        Self {
            version: 4,
            my_as: if asn > u16::MAX as u32 {
                crate::AS_TRANS
            } else {
                asn as u16
            },
            hold_time,
            bgp_id,
            capabilities: caps,
        }
    }

    /// The 4-octet AS the peer claimed (capability 65 when present,
    /// else the widened 2-octet field).
    pub fn peer_as4(&self) -> u32 {
        for cap in &self.capabilities {
            if let Capability::FourOctetAsNumber { asn } = cap {
                return *asn;
            }
        }
        self.my_as as u32
    }

    /// True when the peer advertised the 4-octet AS capability.
    pub fn four_octet_capable(&self) -> bool {
        self.capabilities
            .iter()
            .any(|c| matches!(c, Capability::FourOctetAsNumber { .. }))
    }

    pub fn supports_route_refresh(&self) -> bool {
        self.capabilities
            .iter()
            .any(|c| matches!(c, Capability::RouteRefresh))
    }

    /// True when the peer offered the given (AFI, SAFI) multiprotocol
    /// capability.
    pub fn supports_af(&self, afi: u16, safi: u8) -> bool {
        self.capabilities.iter().any(|c| {
            matches!(c, Capability::Multiprotocol { afi: a, safi: s } if *a == afi && *s == safi)
        })
    }

    fn encode(&self, out: &mut Vec<u8>) {
        out.push(self.version);
        put_u16(out, self.my_as);
        put_u16(out, self.hold_time);
        out.extend_from_slice(&self.bgp_id.octets());
        let mut params = Vec::new();
        if !self.capabilities.is_empty() {
            params.push(2); // Capability Optional Parameter (RFC 5492 §4)
            let mut value = Vec::new();
            encode_capabilities(&self.capabilities, &mut value);
            params.push(value.len() as u8);
            params.extend_from_slice(&value);
        }
        out.push(params.len() as u8);
        out.extend_from_slice(&params);
    }

    fn decode(buf: &[u8]) -> BgpResult<Self> {
        let mut r = Reader::new(buf);
        let open_err =
            |sub: u8, what: &str| BgpError::notify(error::error_code::OPEN_MESSAGE, sub, what);
        let version = r
            .u8()
            .ok_or_else(|| BgpError::local("truncated OPEN version"))?;
        if version != 4 {
            return Err(open_err(
                error::open_subcode::UNSUPPORTED_VERSION_NUMBER,
                &format!("peer speaks BGP-{version}, we speak BGP-4 (§6.2)"),
            ));
        }
        let my_as = r
            .u16()
            .ok_or_else(|| BgpError::local("truncated OPEN My AS"))?;
        let hold_time = r
            .u16()
            .ok_or_else(|| BgpError::local("truncated OPEN Hold Time"))?;
        if (1..=2).contains(&hold_time) {
            return Err(open_err(
                error::open_subcode::UNACCEPTABLE_HOLD_TIME,
                &format!("hold time {hold_time}s rejected (§4.2: zero or at least three)"),
            ));
        }
        let id_bytes = r
            .take(4)
            .ok_or_else(|| BgpError::local("truncated OPEN BGP Identifier"))?;
        let bgp_id = Ipv4Addr::new(id_bytes[0], id_bytes[1], id_bytes[2], id_bytes[3]);
        if !valid_bgp_id(bgp_id) {
            return Err(open_err(
                error::open_subcode::BAD_BGP_IDENTIFIER,
                &format!("{bgp_id} is not a valid unicast host address (§6.2)"),
            ));
        }
        let opt_len = r
            .u8()
            .ok_or_else(|| BgpError::local("truncated OPEN optional-parameters length"))?;
        // The optional-parameters field runs to the end of the OPEN:
        // detect the RFC 9072 extended encoding from the would-be first
        // parameter type octet BEFORE trusting the (bogus) non-extended
        // length — when extended, that length MUST be ignored and the
        // 2-octet extended length governs (RFC 9072 §2).
        let raw = r.rest();
        let capabilities = if opt_len != 0 && raw.first() == Some(&255) {
            if raw.len() < 3 {
                return Err(BgpError::local(
                    "truncated RFC 9072 extended OPEN parameters",
                ));
            }
            let total = u16::from_be_bytes([raw[1], raw[2]]) as usize;
            if raw.len() < 3 + total {
                return Err(BgpError::local(
                    "RFC 9072 extended optional parameters overrun OPEN",
                ));
            }
            decode_open_params(&raw[..3 + total], true)?
        } else {
            if raw.len() != opt_len as usize {
                return Err(BgpError::local("OPEN optional parameters overrun message"));
            }
            decode_open_params(raw, false)?
        };

        Ok(Self {
            version,
            my_as,
            hold_time,
            bgp_id,
            capabilities,
        })
    }
}

/// RFC 4271 §6.2: the BGP Identifier must be "a valid unicast IP host
/// address" — not unspecified, not multicast/class-D, not class E
/// (which also excludes the all-ones broadcast).
fn valid_bgp_id(addr: Ipv4Addr) -> bool {
    let [a, _, _, _] = addr.octets();
    !(addr.is_unspecified() || a >= 224)
}

/// Walks the OPEN optional parameters (either §4.2 encoding or the
/// RFC 9072 extended one). Every parameter must be the capability
/// parameter (type 2) — v1 supports nothing else, so anything else is
/// an Unsupported Optional Parameter (§6.2).
fn decode_open_params(params: &[u8], extended: bool) -> BgpResult<Vec<Capability>> {
    let mut caps = Vec::new();
    let mut r = Reader::new(params);
    if extended {
        // Re-read detection octets: type 255 then the 2-octet total.
        let t = r.u8().unwrap_or(255);
        debug_assert_eq!(t, 255, "caller verified the 255 marker");
        let total = r.u16().unwrap_or(0) as usize;
        let field = r
            .take(total)
            .ok_or_else(|| BgpError::local("RFC 9072 extended optional-parameters overrun OPEN"))?;
        let mut fr = Reader::new(field);
        while !fr.is_empty() {
            let param_type = fr
                .u8()
                .ok_or_else(|| BgpError::local("truncated extended parameter type"))?;
            let len = fr
                .u16()
                .ok_or_else(|| BgpError::local("truncated extended parameter length"))?
                as usize;
            let value = fr
                .take(len)
                .ok_or_else(|| BgpError::local("extended parameter overruns field"))?;
            append_param(&mut caps, param_type, value)?;
        }
        return Ok(caps);
    }
    while !r.is_empty() {
        let param_type = r
            .u8()
            .ok_or_else(|| BgpError::local("truncated parameter type"))?;
        let len =
            r.u8()
                .ok_or_else(|| BgpError::local("truncated parameter length"))? as usize;
        let value = r
            .take(len)
            .ok_or_else(|| BgpError::local("parameter overruns optional-parameters field"))?;
        append_param(&mut caps, param_type, value)?;
    }
    Ok(caps)
}

fn append_param(caps: &mut Vec<Capability>, param_type: u8, value: &[u8]) -> BgpResult<()> {
    match param_type {
        2 => caps.extend(decode_capabilities(value)?),
        _ => {
            return Err(BgpError::notify(
                error::error_code::OPEN_MESSAGE,
                error::open_subcode::UNSUPPORTED_OPTIONAL_PARAMETER,
                format!("unsupported OPEN optional parameter type {param_type} (§6.2)"),
            ))
        }
    }
    Ok(())
}

/// An UPDATE message (RFC 4271 §4.3): withdrawn routes, path
/// attributes, and NLRI. Multiprotocol routes ride MP_REACH/MP_UNREACH
/// attributes instead of the top-level fields (RFC 4760).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct BgpUpdate {
    pub withdrawn: Vec<IpPrefix>,
    pub attrs: Vec<PathAttribute>,
    pub nlri: Vec<IpPrefix>,
}

impl BgpUpdate {
    /// Convenience accessors over the attribute list.
    pub fn attr(&self, attr_type: u8) -> Option<&PathAttribute> {
        self.attrs.iter().find(|a| a.attr_type() == attr_type)
    }

    pub fn origin(&self) -> Option<Origin> {
        match self.attr(crate::attr::attr_type::ORIGIN) {
            Some(PathAttribute::Origin(o)) => Some(*o),
            _ => None,
        }
    }

    pub fn as_path(&self) -> Option<&AsPath> {
        match self.attr(crate::attr::attr_type::AS_PATH) {
            Some(PathAttribute::AsPath(p)) => Some(p),
            _ => None,
        }
    }

    /// The prefixes this UPDATE announces, family-merged: top-level
    /// NLRI (v4) plus any MP_REACH NLRI.
    pub fn announced(&self) -> Vec<IpPrefix> {
        let mut out = self.nlri.clone();
        for attr in &self.attrs {
            if let PathAttribute::MpReach(mp) = attr {
                out.extend(mp.nlri.iter().copied());
            }
        }
        out
    }

    /// The prefixes this UPDATE withdraws: top-level (v4) plus
    /// MP_UNREACH.
    pub fn withdrawn_all(&self) -> Vec<IpPrefix> {
        let mut out = self.withdrawn.clone();
        for attr in &self.attrs {
            if let PathAttribute::MpUnreach(mp) = attr {
                out.extend(mp.withdrawn.iter().copied());
            }
        }
        out
    }

    /// Well-known presence check per §6.3: any route (NLRI present)
    /// must carry ORIGIN, AS_PATH and NEXT_HOP. Missing ones are a
    /// Missing Well-known Attribute with the absent type in the data.
    pub fn validate_well_known(&self) -> BgpResult<()> {
        if self.nlri.is_empty() && self.announced().is_empty() {
            return Ok(());
        }
        if self.nlri.is_empty() {
            return Ok(()); // MP routes carry their own rules (RFC 4760 §3.2)
        }
        for want in [
            crate::attr::attr_type::ORIGIN,
            crate::attr::attr_type::AS_PATH,
            crate::attr::attr_type::NEXT_HOP,
        ] {
            if self.attr(want).is_none() {
                return Err(BgpError::notify(
                    error::error_code::UPDATE_MESSAGE,
                    error::update_subcode::MISSING_WELL_KNOWN_ATTRIBUTE,
                    format!("UPDATE with NLRI missing well-known attribute {want} (§6.3)"),
                ));
            }
        }
        Ok(())
    }

    fn encode(&self, out: &mut Vec<u8>, asn4: bool) -> BgpResult<()> {
        let mut withdrawn = Vec::new();
        for prefix in &self.withdrawn {
            encode_prefix(&mut withdrawn, *prefix);
        }
        if withdrawn.len() > u16::MAX as usize {
            return Err(BgpError::local("withdrawn routes exceed 65535 octets"));
        }
        put_u16(out, withdrawn.len() as u16);
        out.extend_from_slice(&withdrawn);

        let mut attrs = Vec::new();
        encode_attributes(&self.attrs, &mut attrs, asn4)?;
        if attrs.len() > u16::MAX as usize {
            return Err(BgpError::local("path attributes exceed 65535 octets"));
        }
        put_u16(out, attrs.len() as u16);
        out.extend_from_slice(&attrs);

        for prefix in &self.nlri {
            encode_prefix(out, *prefix);
        }
        Ok(())
    }

    fn decode(buf: &[u8], asn4: bool) -> BgpResult<Self> {
        let mut r = Reader::new(buf);
        let withdrawn_len = r
            .u16()
            .ok_or_else(|| BgpError::local("truncated UPDATE withdrawn length"))?
            as usize;
        let withdrawn_bytes = r.take(withdrawn_len).ok_or_else(|| {
            // §6.3: lengths too large for the message = Malformed
            // Attribute List.
            BgpError::notify(
                error::error_code::UPDATE_MESSAGE,
                error::update_subcode::MALFORMED_ATTRIBUTE_LIST,
                "withdrawn routes length overruns UPDATE",
            )
        })?;
        let mut wr = Reader::new(withdrawn_bytes);
        let mut withdrawn = Vec::new();
        while !wr.is_empty() {
            withdrawn.push(decode_prefix(&mut wr, false)?);
        }

        let attr_len = r
            .u16()
            .ok_or_else(|| BgpError::local("truncated UPDATE total path attribute length"))?
            as usize;
        let attr_bytes = r.take(attr_len).ok_or_else(|| {
            BgpError::notify(
                error::error_code::UPDATE_MESSAGE,
                error::update_subcode::MALFORMED_ATTRIBUTE_LIST,
                "total path attribute length overruns UPDATE (§6.3)",
            )
        })?;
        let attrs = decode_attributes(attr_bytes, asn4)?;

        let mut nlri = Vec::new();
        while !r.is_empty() {
            nlri.push(decode_prefix(&mut r, false)?);
        }

        Ok(Self {
            withdrawn,
            attrs,
            nlri,
        })
    }
}

/// A NOTIFICATION message (RFC 4271 §4.5).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BgpNotification {
    pub code: u8,
    pub subcode: u8,
    pub data: Vec<u8>,
}

impl BgpNotification {
    pub fn cease(subcode: u8) -> Self {
        Self {
            code: error::error_code::CEASE,
            subcode,
            data: Vec::new(),
        }
    }

    fn encode(&self, out: &mut Vec<u8>) {
        out.push(self.code);
        out.push(self.subcode);
        out.extend_from_slice(&self.data);
    }

    fn decode(buf: &[u8]) -> BgpResult<Self> {
        let mut r = Reader::new(buf);
        let code = r
            .u8()
            .ok_or_else(|| BgpError::local("truncated NOTIFICATION code"))?;
        let subcode = r
            .u8()
            .ok_or_else(|| BgpError::local("truncated NOTIFICATION subcode"))?;
        Ok(Self {
            code,
            subcode,
            data: r.rest().to_vec(),
        })
    }
}

/// A ROUTE-REFRESH message (RFC 2918 §3): AFI + reserved + SAFI.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BgpRouteRefresh {
    pub afi: u16,
    pub safi: u8,
}

impl BgpRouteRefresh {
    fn encode(&self, out: &mut Vec<u8>) {
        put_u16(out, self.afi);
        out.push(0); // Reserved: SHOULD be 0 (RFC 2918 §3)
        out.push(self.safi);
    }

    fn decode(buf: &[u8]) -> BgpResult<Self> {
        let mut r = Reader::new(buf);
        let afi = r
            .u16()
            .ok_or_else(|| BgpError::local("truncated ROUTE-REFRESH AFI"))?;
        let _reserved = r
            .u8()
            .ok_or_else(|| BgpError::local("truncated ROUTE-REFRESH reserved"))?;
        let safi = r
            .u8()
            .ok_or_else(|| BgpError::local("truncated ROUTE-REFRESH SAFI"))?;
        if !r.is_empty() {
            return Err(BgpError::local("trailing bytes after ROUTE-REFRESH body"));
        }
        Ok(Self { afi, safi })
    }
}

/// Reusable builders for the messages the session layer sends.
pub fn keepalive() -> BgpMessage {
    BgpMessage::Keepalive
}

pub fn route_refresh(afi: u16, safi: u8) -> BgpMessage {
    BgpMessage::RouteRefresh(BgpRouteRefresh { afi, safi })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::attr::{MpReach, MpUnreach};
    use crate::wire::unhex;

    fn id(a: u8) -> Ipv4Addr {
        Ipv4Addr::new(10, 0, 0, a)
    }

    #[test]
    fn header_minima_enforced_per_type() {
        for (ty, min) in [(1u8, 29u16), (2, 23), (3, 21), (4, 19), (5, 23)] {
            let mut frame = vec![0xff; 16];
            put_u16(&mut frame, 19);
            frame.push(ty);
            if min > 19 {
                let err = BgpMessage::decode(&frame, false).unwrap_err();
                assert_eq!(
                    err.notification,
                    Some((1, error::header_subcode::BAD_MESSAGE_LENGTH)),
                    "type {ty} below minimum {min}"
                );
            } else {
                assert!(
                    BgpMessage::decode(&frame, false).is_ok(),
                    "type {ty} at {min}"
                );
            }
        }
    }

    #[test]
    fn bad_marker_is_not_synchronized() {
        let mut frame = vec![0x00; 16];
        put_u16(&mut frame, 19);
        frame.push(4);
        let err = BgpMessage::decode(&frame, false).unwrap_err();
        assert_eq!(
            err.notification,
            Some((1, error::header_subcode::CONNECTION_NOT_SYNCHRONIZED))
        );
    }

    #[test]
    fn out_of_range_length_rejected() {
        for bad in [0u16, 18, 4097, 65535] {
            let mut frame = vec![0xff; 16];
            put_u16(&mut frame, bad);
            frame.push(4);
            let err = BgpMessage::decode(&frame, false).unwrap_err();
            assert_eq!(
                err.notification,
                Some((1, error::header_subcode::BAD_MESSAGE_LENGTH)),
                "length {bad}"
            );
        }
    }

    #[test]
    fn unknown_message_type_rejected() {
        let mut frame = vec![0xff; 16];
        put_u16(&mut frame, 19);
        frame.push(9);
        let err = BgpMessage::decode(&frame, false).unwrap_err();
        assert_eq!(
            err.notification,
            Some((1, error::header_subcode::BAD_MESSAGE_TYPE))
        );
    }

    #[test]
    fn keepalive_is_bare_header() {
        let frame = BgpMessage::Keepalive.encode(false).unwrap();
        assert_eq!(frame.len(), 19);
        assert_eq!(frame[16..19], [0, 19, 4]);
        assert_eq!(
            BgpMessage::decode(&frame, false).unwrap(),
            BgpMessage::Keepalive
        );
    }

    /// Golden OPEN, every byte derived by hand: version 4, AS 65001,
    /// hold 90, id 10.0.0.1, one capability parameter holding
    /// MP(v4-unicast) + route-refresh + AS4(65001).
    #[test]
    fn open_golden_bytes() {
        let open = BgpOpen::new(
            65001,
            90,
            id(1),
            vec![
                Capability::Multiprotocol { afi: 1, safi: 1 },
                Capability::RouteRefresh,
            ],
        );
        let frame = BgpMessage::Open(open.clone()).encode(false).unwrap();
        // length 19+26=45 (0x2d); opt-params field 0x10 octets =
        // type(1)+len(1)+14 capability octets (MP 6 + refresh 2 +
        // AS4 6), so the parameter's own length byte is 0x0e.
        let expected = unhex(
            "ffffffffffffffffffffffffffffffff 002d 01 \
             04 fd e9 005a 0a000001 \
             10 \
             02 0e 01 04 0001 0001 02 00 41 04 0000fde9",
        );
        assert_eq!(frame, expected);
        assert_eq!(
            BgpMessage::decode(&frame, false).unwrap(),
            BgpMessage::Open(open)
        );
    }

    #[test]
    fn open_four_octet_as_uses_as_trans_in_two_octet_field() {
        let open = BgpOpen::new(4200000000, 90, id(1), vec![]);
        assert_eq!(open.my_as, crate::AS_TRANS);
        assert_eq!(open.peer_as4(), 4200000000);
        let frame = BgpMessage::Open(open).encode(false).unwrap();
        let back = match BgpMessage::decode(&frame, false).unwrap() {
            BgpMessage::Open(o) => o,
            other => panic!("{other:?}"),
        };
        assert_eq!(back.peer_as4(), 4200000000);
        assert!(back.four_octet_capable());
    }

    #[test]
    fn open_bad_version_rejected() {
        let mut buf = vec![4, 0xfd, 0xe9, 0, 90];
        buf.extend_from_slice(&id(1).octets());
        buf.push(0);
        buf[0] = 3; // BGP-3
        let err = BgpOpen::decode(&buf).unwrap_err();
        assert_eq!(
            err.notification,
            Some((2, error::open_subcode::UNSUPPORTED_VERSION_NUMBER))
        );
    }

    #[test]
    fn open_hold_time_one_and_two_rejected() {
        for bad in [1u16, 2] {
            let mut buf = vec![4, 0xfd, 0xe9];
            put_u16(&mut buf, bad);
            buf.extend_from_slice(&id(1).octets());
            buf.push(0);
            let err = BgpOpen::decode(&buf).unwrap_err();
            assert_eq!(
                err.notification,
                Some((2, error::open_subcode::UNACCEPTABLE_HOLD_TIME)),
                "hold {bad}"
            );
        }
        // Zero and three are fine.
        for good in [0u16, 3] {
            let mut buf = vec![4, 0xfd, 0xe9];
            put_u16(&mut buf, good);
            buf.extend_from_slice(&id(1).octets());
            buf.push(0);
            assert!(BgpOpen::decode(&buf).is_ok(), "hold {good}");
        }
    }

    #[test]
    fn open_bad_bgp_identifier_rejected() {
        for bad in ["0.0.0.0", "224.0.0.5", "240.1.2.3", "255.255.255.255"] {
            let mut buf = vec![4, 0xfd, 0xe9, 0, 90];
            buf.extend_from_slice(&bad.parse::<Ipv4Addr>().unwrap().octets());
            buf.push(0);
            let err = BgpOpen::decode(&buf).unwrap_err();
            assert_eq!(
                err.notification,
                Some((2, error::open_subcode::BAD_BGP_IDENTIFIER)),
                "{bad}"
            );
        }
    }

    #[test]
    fn open_optional_params_overrun_rejected() {
        let mut buf = vec![4, 0xfd, 0xe9, 0, 90];
        buf.extend_from_slice(&id(1).octets());
        buf.push(20); // claims 20 octets
        buf.extend_from_slice(&[2, 6, 1, 4, 0, 1, 0, 1]); // 8 present
        assert!(BgpOpen::decode(&buf).is_err());
    }

    #[test]
    fn open_unsupported_parameter_type_rejected() {
        let mut buf = vec![4, 0xfd, 0xe9, 0, 90];
        buf.extend_from_slice(&id(1).octets());
        buf.push(4);
        buf.extend_from_slice(&[1, 2, 0xAA, 0xBB]); // auth (deprecated)
        let err = BgpOpen::decode(&buf).unwrap_err();
        assert_eq!(
            err.notification,
            Some((2, error::open_subcode::UNSUPPORTED_OPTIONAL_PARAMETER))
        );
    }

    #[test]
    fn open_rfc9072_extended_params_decoded() {
        // Extended encoding: non-ext len 255, marker type 255, ext
        // length 10, then one parameter (type 2, len 8) holding
        // MP(v4) + AS4. Built per RFC 9072 Figure 1/2.
        let mut params = vec![2u8];
        let mut value = Vec::new();
        encode_capabilities(
            &[
                Capability::Multiprotocol { afi: 1, safi: 1 },
                Capability::FourOctetAsNumber { asn: 65001 },
            ],
            &mut value,
        );
        put_u16(&mut params, value.len() as u16); // 2-octet length (Figure 2)
        params.extend_from_slice(&value);
        let mut buf = vec![4, 0xfd, 0xe9, 0, 90];
        buf.extend_from_slice(&id(1).octets());
        buf.push(255); // Non-Ext OP Len: 255 per RFC 9072
        buf.push(255); // Non-Ext OP Type: 255 signals extended
        put_u16(&mut buf, params.len() as u16);
        buf.extend_from_slice(&params);
        let open = BgpOpen::decode(&buf).unwrap();
        assert!(open.supports_af(1, 1));
        assert_eq!(open.peer_as4(), 65001);
    }

    #[test]
    fn open_capability_length_overrun_rejected() {
        let mut buf = vec![4, 0xfd, 0xe9, 0, 90];
        buf.extend_from_slice(&id(1).octets());
        buf.push(6);
        // parameter type 2, claims 4, holds 2
        buf.extend_from_slice(&[2, 4, 0x41, 0x02]);
        assert!(BgpOpen::decode(&buf).is_err());
    }

    /// Golden UPDATE announcing 203.0.113.0/24: withdrawn 0, ORIGIN
    /// IGP, AS_PATH (65002), NEXT_HOP 10.0.0.2, then the /24 NLRI.
    #[test]
    fn update_golden_bytes() {
        let update = BgpUpdate {
            withdrawn: vec![],
            attrs: vec![
                PathAttribute::Origin(Origin::Igp),
                PathAttribute::AsPath(AsPath::sequence([65002])),
                PathAttribute::NextHop(id(2)),
            ],
            nlri: vec!["203.0.113.0/24".parse().unwrap()],
        };
        let frame = BgpMessage::Update(update.clone()).encode(false).unwrap();
        // attrs = ORIGIN(4) + AS_PATH(7) + NEXT_HOP(7: header 3 +
        // 4 octets) = 18 (0x12); NLRI = length octet 24 + 3 address
        // octets; frame = 19 + 2+2+18+4 = 45 (0x2d).
        let expected = unhex(
            "ffffffffffffffffffffffffffffffff 002d 02 \
             0000 \
             0012 \
             40 01 01 00 \
             40 02 04 02 01 fdea \
             40 03 04 0a000002 \
             18 cb0071",
        );
        assert_eq!(frame, expected);
        assert_eq!(
            BgpMessage::decode(&frame, false).unwrap(),
            BgpMessage::Update(update)
        );
    }

    #[test]
    fn update_withdrawn_overrun_rejected() {
        let body = unhex("0005 cb0071"); // 5 bytes claimed, 3 present
        let err = BgpUpdate::decode(&body, false).unwrap_err();
        assert_eq!(
            err.notification,
            Some((3, error::update_subcode::MALFORMED_ATTRIBUTE_LIST))
        );
    }

    #[test]
    fn update_attr_len_overrun_rejected() {
        let body = unhex("0000 0009 400100"); // 9 claimed, 3 present
        let err = BgpUpdate::decode(&body, false).unwrap_err();
        assert_eq!(
            err.notification,
            Some((3, error::update_subcode::MALFORMED_ATTRIBUTE_LIST))
        );
    }

    #[test]
    fn update_trailing_partial_prefix_rejected() {
        // withdrawn 0, no attrs, NLRI /24 but only 3 octets of address
        let body = unhex("0000 0000 cb0071");
        let err = BgpUpdate::decode(&body, false).unwrap_err();
        assert_eq!(
            err.notification,
            Some((3, error::update_subcode::INVALID_NETWORK_FIELD))
        );
    }

    #[test]
    fn update_missing_well_known_flagged() {
        let update = BgpUpdate {
            withdrawn: vec![],
            attrs: vec![PathAttribute::Origin(Origin::Igp)],
            nlri: vec!["203.0.113.0/24".parse().unwrap()],
        };
        let err = update.validate_well_known().unwrap_err();
        assert_eq!(
            err.notification,
            Some((3, error::update_subcode::MISSING_WELL_KNOWN_ATTRIBUTE))
        );
    }

    #[test]
    fn update_mp_and_v4_fields_merge() {
        let update = BgpUpdate {
            withdrawn: vec!["198.51.100.0/24".parse().unwrap()],
            attrs: vec![
                PathAttribute::Origin(Origin::Igp),
                PathAttribute::AsPath(AsPath::default()),
                PathAttribute::MpUnreach(MpUnreach {
                    afi: 2,
                    safi: 1,
                    withdrawn: vec!["2001:db8::/32".parse().unwrap()],
                }),
                PathAttribute::MpReach(MpReach {
                    afi: 2,
                    safi: 1,
                    next_hop: crate::attr::MpNextHop::V6 {
                        global: "2001:db8::1".parse().unwrap(),
                        link_local: None,
                    },
                    nlri: vec!["2001:db8:aa::/48".parse().unwrap()],
                }),
            ],
            nlri: vec!["203.0.113.0/24".parse().unwrap()],
        };
        let frame = BgpMessage::Update(update.clone()).encode(true).unwrap();
        assert!(frame.len() <= 4096);
        assert_eq!(
            BgpMessage::decode(&frame, true).unwrap(),
            BgpMessage::Update(update.clone())
        );
        assert_eq!(update.announced().len(), 2);
        assert_eq!(update.withdrawn_all().len(), 2);
    }

    #[test]
    fn notification_round_trip() {
        let n = BgpNotification {
            code: 6,
            subcode: error::cease_subcode::ADMIN_SHUTDOWN,
            data: vec![],
        };
        let frame = BgpMessage::Notification(n.clone()).encode(false).unwrap();
        assert_eq!(frame.len(), 21);
        assert_eq!(&frame[16..], &[0, 21, 3, 6, 2]);
        assert_eq!(
            BgpMessage::decode(&frame, false).unwrap(),
            BgpMessage::Notification(n)
        );
    }

    #[test]
    fn route_refresh_golden_bytes() {
        let frame = route_refresh(1, 1).encode(false).unwrap();
        assert_eq!(frame.len(), 23);
        assert_eq!(&frame[16..], &[0, 23, 5, 0, 1, 0, 1]);
        assert_eq!(
            BgpMessage::decode(&frame, false).unwrap(),
            route_refresh(1, 1)
        );
        // Reserved octet is ignored on receipt (RFC 2918 §3): it sits
        // at frame offset 21 (marker 16 + length 2 + type 1 + AFI 2).
        let mut odd = frame.clone();
        odd[21] = 0xFF;
        assert_eq!(
            BgpMessage::decode(&odd, false).unwrap(),
            route_refresh(1, 1)
        );
    }

    #[test]
    fn route_refresh_trailing_bytes_rejected() {
        let mut frame = route_refresh(1, 1).encode(false).unwrap();
        frame.extend_from_slice(&[0]);
        assert!(BgpMessage::decode(&frame, false).is_err());
    }

    /// Property-style fuzz substitute: random frames of garbage never
    /// panic the decoder (checked reads only) and random valid
    /// OPEN/UPDATE/KEEPALIVE/REFRESH messages round-trip. 512 rounds.
    #[test]
    fn random_inputs_never_panic_and_valid_round_trip() {
        let mut rng = 0xda3e39cb94b95bdbu64;
        let mut next = move || {
            rng ^= rng << 13;
            rng ^= rng >> 7;
            rng ^= rng << 17;
            rng
        };
        for round in 0..512u32 {
            let garbage_len = (next() % 64) as usize;
            let garbage: Vec<u8> = (0..garbage_len).map(|_| (next() >> 24) as u8).collect();
            if garbage.len() >= 19 {
                let _ = BgpMessage::decode(&garbage, round % 2 == 0);
            }
            let _ = BgpOpen::decode(&garbage);
            let _ = BgpUpdate::decode(&garbage, round % 2 == 0);
            let _ = BgpRouteRefresh::decode(&garbage);

            let msg = match round % 4 {
                0 => BgpMessage::Keepalive,
                1 => BgpMessage::Open(BgpOpen::new(
                    (next() % 4_300_000_000) as u32,
                    90,
                    Ipv4Addr::new(10, 0, (round % 250) as u8, 1),
                    vec![],
                )),
                2 => BgpMessage::Notification(BgpNotification {
                    code: 6,
                    subcode: 2,
                    data: vec![],
                }),
                _ => route_refresh(1, 1),
            };
            let asn4 = round % 2 == 0;
            if let Ok(frame) = msg.encode(asn4) {
                assert_eq!(
                    BgpMessage::decode(&frame, asn4).unwrap(),
                    msg,
                    "round {round}"
                );
            }
        }
    }
}
