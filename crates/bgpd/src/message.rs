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

use crate::attr::{
    decode_attributes_with, decode_nlri, encode_attributes, encode_nlri, AddPathCtx, AsPath, Nlri,
    Origin, PathAttribute, UpdateHandling, UpdateOutcome,
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
    /// Classic NLRI encoding; `encode_with` carries the ADD-PATH
    /// direction (RFC 7911 §3).
    pub fn encode(&self, asn4: bool) -> BgpResult<Vec<u8>> {
        self.encode_with(asn4, AddPathCtx::default())
    }

    /// [`Self::encode`] with the negotiated ADD-PATH direction: an
    /// UPDATE's NLRI uses the extended encoding only where directed —
    /// a nonzero Path Identifier outside it is refused by the codec
    /// (RFC 7911 §5's send-side MUST), never silently flattened.
    pub fn encode_with(&self, asn4: bool, addpath: AddPathCtx) -> BgpResult<Vec<u8>> {
        let mut body = Vec::new();
        match self {
            Self::Open(open) => open.encode(&mut body),
            Self::Update(update) => update.encode(&mut body, asn4, addpath)?,
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
    /// message — the session layer frames first). Classic NLRI
    /// encoding; `decode_with_handling` carries the ADD-PATH
    /// direction (RFC 7911 §3).
    pub fn decode(buf: &[u8], asn4: bool) -> BgpResult<Self> {
        Self::decode_with_handling(
            buf,
            asn4,
            UpdateHandling::StrictRfc4271,
            AddPathCtx::default(),
        )
        .map(|(m, _)| m)
    }

    /// [`Self::decode`] with RFC 7606 UPDATE error handling and the
    /// negotiated ADD-PATH direction: extended NLRI (the 4-octet Path
    /// Identifier per prefix, RFC 7911 §3) decodes only for the
    /// families that negotiated it. A malformed-but-salvageable UPDATE
    /// decodes to itself plus the structured handling outcome
    /// (attribute discard / treat-as-withdraw carrying the routes);
    /// errors that keep the session reset still return `Err`.
    pub fn decode_with_handling(
        buf: &[u8],
        asn4: bool,
        handling: UpdateHandling,
        addpath: AddPathCtx,
    ) -> BgpResult<(Self, UpdateOutcome)> {
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
            message_type::OPEN => (Self::Open(BgpOpen::decode(body)?), UpdateOutcome::Clean),
            message_type::UPDATE => {
                let (update, report) =
                    BgpUpdate::decode_with_handling(body, asn4, handling, addpath)?;
                (Self::Update(update), report)
            }
            message_type::NOTIFICATION => (
                Self::Notification(BgpNotification::decode(body)?),
                UpdateOutcome::Clean,
            ),
            // §4.4: a KEEPALIVE is exactly the 19-octet header (the
            // type-minimum check above rejected any data octets).
            message_type::KEEPALIVE => (Self::Keepalive, UpdateOutcome::Clean),
            _ => (
                Self::RouteRefresh(BgpRouteRefresh::decode(body)?),
                UpdateOutcome::Clean,
            ),
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

    /// The peer's Graceful Restart capability (RFC 4724 §3),
    /// flattened to the receiving-speaker facts: the Restart State
    /// (R) bit, the 12-bit Restart Time, and RFC 8538 §2's Graceful
    /// Notification (N) bit.
    pub fn graceful_restart(&self) -> Option<crate::fsm::GracefulRestartInfo> {
        self.capabilities.iter().find_map(|c| match c {
            Capability::GracefulRestart {
                restart_state,
                graceful_notification,
                restart_time,
                ..
            } => Some(crate::fsm::GracefulRestartInfo {
                restart_state: *restart_state,
                graceful_notification: *graceful_notification,
                restart_time: *restart_time,
            }),
            _ => None,
        })
    }

    /// The peer's ADD-PATH (RFC 7911 §4) Send/Receive value for one
    /// family — 0 when the family is absent or the capability is not
    /// offered. (1 = receive, 2 = send, 3 = both.) Per §4, a Send/
    /// Receive value outside 1..=3 makes the *whole capability*
    /// "treated as not understood and ignored": every family then
    /// reads 0, not just the offending tuple.
    pub fn add_path(&self, afi: u16, safi: u8) -> u8 {
        let Some(tuples) = self.capabilities.iter().find_map(|c| match c {
            Capability::AddPath(tuples) => Some(tuples),
            _ => None,
        }) else {
            return 0;
        };
        // The §4 ignore rule keys on the capability as a unit: any
        // invalid tuple voids the whole offer.
        if tuples.iter().any(|t| !t.send_receive_valid()) {
            return 0;
        }
        tuples
            .iter()
            .find(|t| t.afi == afi && t.safi == safi)
            .map(|t| t.send_receive)
            .unwrap_or(0)
    }

    /// True when the peer offered the given (AFI, SAFI) multiprotocol
    /// capability.
    pub fn supports_af(&self, afi: u16, safi: u8) -> bool {
        self.capabilities.iter().any(|c| {
            matches!(c, Capability::Multiprotocol { afi: a, safi: s } if *a == afi && *s == safi)
        })
    }

    pub(crate) fn encode(&self, out: &mut Vec<u8>) {
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

    pub(crate) fn decode(buf: &[u8]) -> BgpResult<Self> {
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
/// attributes instead of the top-level fields (RFC 4760). Each NLRI
/// entry carries its ADD-PATH Path Identifier when the family
/// negotiated one (RFC 7911 §3) — 0 for the classic encoding.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct BgpUpdate {
    pub withdrawn: Vec<Nlri>,
    pub attrs: Vec<PathAttribute>,
    pub nlri: Vec<Nlri>,
}

impl BgpUpdate {
    /// Full encoded frame for this UPDATE alone (header + body),
    /// classic NLRI encoding.
    pub fn encode_frame(&self, asn4: bool) -> BgpResult<Vec<u8>> {
        BgpMessage::Update(self.clone()).encode(asn4)
    }

    /// [`Self::encode_frame`] with the ADD-PATH direction negotiated
    /// for the send (RFC 7911 §3/§5): toward a peer that agreed to
    /// receive extended NLRI for a family, that family's fields encode
    /// `Path Identifier (4) | Length (1) | Prefix`. The ids themselves
    /// are the caller's per-neighbor allocation (§2 — "MUST generate
    /// its own Path Identifier"); the codec only refuses a nonzero id
    /// under the classic gate.
    pub fn encode_frame_with(&self, asn4: bool, addpath: AddPathCtx) -> BgpResult<Vec<u8>> {
        BgpMessage::Update(self.clone()).encode_with(asn4, addpath)
    }

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
    /// NLRI (v4) plus any MP_REACH NLRI. Path IDs ride along
    /// (RFC 7911): a withdrawal's key is the (prefix, path-id) pair.
    pub fn announced(&self) -> Vec<Nlri> {
        let mut out = self.nlri.clone();
        for attr in &self.attrs {
            if let PathAttribute::MpReach(mp) = attr {
                out.extend(mp.nlri.iter().copied());
            }
        }
        out
    }

    /// The prefixes this UPDATE withdraws: top-level (v4) plus
    /// MP_UNREACH, with their path IDs.
    pub fn withdrawn_all(&self) -> Vec<Nlri> {
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

    /// RFC 7606 §5.1's sender-side MUST NOT, verified wording: "An
    /// UPDATE message MUST NOT contain more than one of the following:
    /// non-empty Withdrawn Routes field, non-empty Network Layer
    /// Reachability Information field, MP_REACH_NLRI attribute, and
    /// MP_UNREACH_NLRI attribute." bgpd never emits a mixed UPDATE
    /// (B-4: the encode hard-reject — "we must not send what §5.1
    /// forbids"); the receive side stays tolerant per the same
    /// section ("an implementation MUST still be prepared to receive
    /// these fields in any position or combination"), pinned by the
    /// merge-decode test. The End-of-RIB shapes pass: the v4 marker
    /// carries none of the four; a family's MP marker exactly one.
    pub fn validate_single_route_container(&self) -> BgpResult<()> {
        let containers = [
            !self.withdrawn.is_empty(),
            !self.nlri.is_empty(),
            self.attrs
                .iter()
                .any(|a| matches!(a, PathAttribute::MpReach(_))),
            self.attrs
                .iter()
                .any(|a| matches!(a, PathAttribute::MpUnreach(_))),
        ];
        if containers.iter().filter(|c| **c).count() > 1 {
            return Err(BgpError::local(
                "mixed UPDATE: more than one of withdrawn routes / NLRI / \
                 MP_REACH_NLRI / MP_UNREACH_NLRI (RFC 7606 §5.1 MUST NOT)",
            ));
        }
        Ok(())
    }

    pub(crate) fn encode(
        &self,
        out: &mut Vec<u8>,
        asn4: bool,
        addpath: AddPathCtx,
    ) -> BgpResult<()> {
        self.validate_single_route_container()?;
        let mut withdrawn = Vec::new();
        for nlri in &self.withdrawn {
            encode_nlri(&mut withdrawn, nlri, addpath.v4)?;
        }
        if withdrawn.len() > u16::MAX as usize {
            return Err(BgpError::local("withdrawn routes exceed 65535 octets"));
        }
        put_u16(out, withdrawn.len() as u16);
        out.extend_from_slice(&withdrawn);

        let mut attrs = Vec::new();
        encode_attributes(&self.attrs, &mut attrs, asn4, addpath)?;
        if attrs.len() > u16::MAX as usize {
            return Err(BgpError::local("path attributes exceed 65535 octets"));
        }
        put_u16(out, attrs.len() as u16);
        out.extend_from_slice(&attrs);

        for nlri in &self.nlri {
            encode_nlri(out, nlri, addpath.v4)?;
        }
        Ok(())
    }

    /// Strict [`Self::decode_with_handling`] under the classic
    /// encoding (the tests' RFC 4271 expectations keep the
    /// session-reset shape).
    #[cfg(test)]
    fn decode(buf: &[u8], asn4: bool) -> BgpResult<Self> {
        Self::decode_with_handling(
            buf,
            asn4,
            UpdateHandling::StrictRfc4271,
            AddPathCtx::default(),
        )
        .map(|(u, _)| u)
    }

    /// [`Self::decode`] with RFC 7606 handling for the attribute
    /// block and the negotiated ADD-PATH direction for the v4
    /// top-level fields (the withdrawn/NLRI framing rules are
    /// un-revised: a message-level overrun stays Malformed Attribute
    /// List and NLRI errors stay Invalid Network Field, both session
    /// resets). The structured [`UpdateOutcome`] (B-1) is finalized
    /// here: §3(j) routes only what parsed, §3(d)'s missing
    /// well-known mandatory attributes fold into treat-as-withdraw,
    /// and §5.2's no-reachable-NLRI shape escalates to the session
    /// reset.
    pub(crate) fn decode_with_handling(
        buf: &[u8],
        asn4: bool,
        handling: UpdateHandling,
        addpath: AddPathCtx,
    ) -> BgpResult<(Self, UpdateOutcome)> {
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
            withdrawn.push(decode_nlri(&mut wr, false, addpath.v4)?);
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
        let decoded = decode_attributes_with(attr_bytes, asn4, handling, addpath)?;

        let mut nlri = Vec::new();
        while !r.is_empty() {
            nlri.push(decode_nlri(&mut r, false, addpath.v4)?);
        }

        let update = Self {
            withdrawn,
            attrs: decoded.attrs,
            nlri,
        };
        let mut ledger = decoded.handling;

        // §3(d): "If any of the well-known mandatory attributes are
        // not present in an UPDATE message, then 'treat-as-withdraw'
        // MUST be used" — folded into the outcome for v4-NLRI
        // announcements (validate_well_known's scope; RFC 4760 §3.2
        // governs MP routes), the strict mode keeping the RFC 4271
        // session reset via `validate_well_known` below. A mandatory
        // attribute that was malformed names itself already; its
        // post-discard absence is not double-reported.
        if handling.is_rfc7606() && !update.nlri.is_empty() {
            for want in [
                crate::attr::attr_type::ORIGIN,
                crate::attr::attr_type::AS_PATH,
                crate::attr::attr_type::NEXT_HOP,
            ] {
                if update.attr(want).is_none() && !ledger.causes.iter().any(|(t, _)| *t == want) {
                    ledger.treat_as_withdraw(
                        want,
                        format!("UPDATE with NLRI missing well-known attribute {want} (§6.3)"),
                        Some((
                            error::error_code::UPDATE_MESSAGE,
                            error::update_subcode::MISSING_WELL_KNOWN_ATTRIBUTE,
                        )),
                    );
                }
            }
        } else {
            update.validate_well_known()?;
        }

        let outcome = if !ledger.withdraw {
            if ledger.causes.is_empty() {
                UpdateOutcome::Clean
            } else {
                UpdateOutcome::Discarded(ledger.causes)
            }
        } else {
            // §5.2: an UPDATE "that does contain path attributes other
            // than MP_UNREACH_NLRI and doesn't encode any reachable
            // NLRI" leaves us unable "to be confident that the NLRI
            // have been successfully parsed as Section 3 (j) requires"
            // — any non-discard error there escalates to the session
            // reset. (A well-formed lone MP_UNREACH — the EOR shape —
            // never carries a trigger; a malformed attribute is
            // itself a "path attribute other than MP_UNREACH_NLRI".)
            let has_reachable = !update.nlri.is_empty()
                || update
                    .attrs
                    .iter()
                    .any(|a| matches!(a, PathAttribute::MpReach(mp) if !mp.nlri.is_empty()));
            if !has_reachable {
                let (code, sub) = ledger.notify.unwrap_or((
                    error::error_code::UPDATE_MESSAGE,
                    error::update_subcode::MALFORMED_ATTRIBUTE_LIST,
                ));
                return Err(BgpError::notify(
                    code,
                    sub,
                    "no reachable NLRI with a treat-as-withdraw-class error: \
                     session reset (RFC 7606 §5.2)",
                ));
            }
            // §2: "as though all contained routes had been withdrawn" —
            // the announced set leaves and the explicit withdrawals
            // still apply; every route named only as parsed (§3(j)).
            let mut routes = update.announced();
            routes.extend(update.withdrawn_all());
            UpdateOutcome::Withdrawn {
                routes,
                causes: ledger.causes,
            }
        };
        Ok((update, outcome))
    }

    /// True when this UPDATE is an End-of-RIB marker (RFC 4724 §3): no
    /// reachable NLRI and no withdrawn routes — the bare minimum
    /// UPDATE for IPv4 unicast, or an MP_UNREACH carrying no routes
    /// for a multiprotocol family (returns that family).
    pub fn end_of_rib(&self) -> Option<Option<(u16, u8)>> {
        if !self.withdrawn.is_empty() || !self.announced().is_empty() {
            return None;
        }
        match self.attrs.as_slice() {
            [] => Some(None), // the v4-unicast marker
            [PathAttribute::MpUnreach(mp)] if mp.withdrawn.is_empty() => {
                Some(Some((mp.afi, mp.safi)))
            }
            _ => None,
        }
    }

    /// Builds the End-of-RIB marker for one family (RFC 4724 §3): the
    /// minimum-length UPDATE for v4 unicast; an UPDATE carrying only
    /// an empty MP_UNREACH for multiprotocol families.
    pub fn end_of_rib_marker(afi: u16, safi: u8) -> Self {
        if afi == 1 && safi == 1 {
            Self::default()
        } else {
            Self {
                attrs: vec![PathAttribute::MpUnreach(crate::attr::MpUnreach {
                    afi,
                    safi,
                    withdrawn: Vec::new(),
                })],
                ..Default::default()
            }
        }
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

    /// A Hard Reset (RFC 8538 §3): a Cease NOTIFICATION with the Hard
    /// Reset subcode (9) whose data portion "carries an encapsulated
    /// NOTIFICATION" — the reason for the reset. §3.1's wire form:
    /// `ErrCode(1) | Subcode(1) | Data(variable)` — the encapsulated
    /// notification's code, subcode, and data in that order.
    pub fn hard_reset(reason: &Self) -> Self {
        let mut data = Vec::with_capacity(2 + reason.data.len());
        data.push(reason.code);
        data.push(reason.subcode);
        data.extend_from_slice(&reason.data);
        Self {
            code: error::error_code::CEASE,
            subcode: error::cease_subcode::HARD_RESET,
            data,
        }
    }

    /// Whether this is a Hard Reset (RFC 8538 §3: Cease with subcode
    /// 9) — the one NOTIFICATION class a receiving speaker must
    /// answer with the plain RFC 4271 session termination (§3.2:
    /// "Whenever a BGP speaker receives a Hard Reset, the speaker
    /// MUST terminate the BGP session following the standard
    /// procedures in [RFC4271]").
    pub fn is_hard_reset(&self) -> bool {
        self.code == error::error_code::CEASE && self.subcode == error::cease_subcode::HARD_RESET
    }

    /// The encapsulated reason of a Hard Reset (RFC 8538 §3.1), when
    /// the data portion actually carries one — a Hard Reset with a
    /// truncated body (no two leading octets) logs as reason-less
    /// rather than failing the session.
    pub fn hard_reset_reason(&self) -> Option<Self> {
        if !self.is_hard_reset() || self.data.len() < 2 {
            return None;
        }
        Some(Self {
            code: self.data[0],
            subcode: self.data[1],
            data: self.data[2..].to_vec(),
        })
    }

    /// RFC 8538 §5.1's suggested send-side classification, row by
    /// row (the table's own caveat: "These suggestions are only
    /// that -- suggestions, not requirements"): toward a peer whose
    /// Graceful Restart capability carried the N bit, the permanent
    /// Cease reasons — Maximum Number of Prefixes Reached (1),
    /// Administrative Shutdown (2), Peer De-configured (3), and a
    /// Hard Reset reason itself (9) — are sent AS a Hard Reset
    /// wrapping the reason; the transient Cease subcodes 5-8 are a
    /// "Graceful Cease" (the notification rides plain, letting the
    /// peer retain); Administrative Reset (4) is listed as "user
    /// control" — v1 sends it plain (graceful; a knob can come with
    /// the first user who wants the hard shape). Non-Cease error
    /// codes are never wrapped: §5.1 notes "use of Hard Reset does
    /// not appear to be indicated" for them. Toward a peer that did
    /// not offer the N bit, every notification rides plain — an
    /// RFC 4486-only speaker has no Hard Reset semantics.
    pub fn wrapped_for_n_peer(&self, n_exchanged: bool) -> Self {
        if !n_exchanged || self.code != error::error_code::CEASE {
            return self.clone();
        }
        match self.subcode {
            error::cease_subcode::MAX_PREFIXES
            | error::cease_subcode::ADMIN_SHUTDOWN
            | error::cease_subcode::PEER_DECONFIGURED
            | error::cease_subcode::HARD_RESET => Self::hard_reset(self),
            _ => self.clone(),
        }
    }

    pub(crate) fn encode(&self, out: &mut Vec<u8>) {
        out.push(self.code);
        out.push(self.subcode);
        out.extend_from_slice(&self.data);
    }

    pub(crate) fn decode(buf: &[u8]) -> BgpResult<Self> {
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
    pub(crate) fn encode(&self, out: &mut Vec<u8>) {
        put_u16(out, self.afi);
        out.push(0); // Reserved: SHOULD be 0 (RFC 2918 §3)
        out.push(self.safi);
    }

    pub(crate) fn decode(buf: &[u8]) -> BgpResult<Self> {
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

/// One frame the session read: the decoded message, its RFC 7606
/// outcome (UPDATEs; [`UpdateOutcome::Clean`] otherwise), and the raw
/// frame bytes — RFC 7606 §6's debugging facility "must include
/// logging an error listing the NLRI involved and containing the
/// entire malformed UPDATE message", so the bytes ride along for
/// exactly that log line.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecodedFrame {
    pub message: BgpMessage,
    pub outcome: UpdateOutcome,
    pub frame: Vec<u8>,
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

    /// B-4's receive-side pin: RFC 7606 §5.1's sender-side MUST NOT
    /// ("An UPDATE message MUST NOT contain more than one of the
    /// following: non-empty Withdrawn Routes field, non-empty ...
    /// NLRI field, MP_REACH_NLRI attribute, and MP_UNREACH_NLRI
    /// attribute") makes this a frame bgpd refuses to SEND — but the
    /// same section's receiver duty ("an implementation MUST still be
    /// prepared to receive these fields in any position or
    /// combination") keeps the decode tolerant. The mixed frame is
    /// built by hand (the codec will not produce it).
    #[test]
    fn update_mp_and_v4_fields_merge() {
        let update = BgpUpdate {
            withdrawn: vec!["198.51.100.0/24".parse().unwrap()],
            attrs: vec![
                PathAttribute::Origin(Origin::Igp),
                PathAttribute::AsPath(AsPath::default()),
                // The v4 NLRI needs the mandatory triple (§6.3; the
                // §3(d) fold makes strict decode check it here).
                PathAttribute::NextHop(id(2)),
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
        // B-4: the encode hard-reject — we must not send what §5.1
        // forbids (four route containers in one UPDATE here).
        let err = BgpMessage::Update(update.clone()).encode(true).unwrap_err();
        assert!(err.message.contains("§5.1"));

        // The receiver still merges every family: hand-built frame.
        let mut attr_bytes = Vec::new();
        crate::attr::encode_attributes(&update.attrs, &mut attr_bytes, true, AddPathCtx::default())
            .unwrap();
        let mut body = vec![0x00, 0x04, 24, 198, 51, 100]; // withdrawn
        body.extend_from_slice(&(attr_bytes.len() as u16).to_be_bytes());
        body.extend_from_slice(&attr_bytes);
        body.extend_from_slice(&[24, 203, 0, 113]); // NLRI
        let (decoded, _) = BgpUpdate::decode_with_handling(
            &body,
            true,
            UpdateHandling::StrictRfc4271,
            AddPathCtx::default(),
        )
        .unwrap();
        assert_eq!(decoded, update);
        assert_eq!(decoded.announced().len(), 2);
        assert_eq!(decoded.withdrawn_all().len(), 2);
    }

    /// RFC 7911 §3 golden: the extended encoding — the 4-octet Path
    /// Identifier before each prefix — in one announce frame and one
    /// withdrawal frame (RFC 7606 §5.1 forbids sending both fields in
    /// one UPDATE). Path ID 1, 203.0.113.0/24 is
    /// `00000001 18 cb0071` on the wire, the RFC's own example shape.
    #[test]
    fn update_add_path_golden_bytes() {
        let ctx = AddPathCtx {
            v4: true,
            v6: false,
        };
        let attrs = vec![
            PathAttribute::Origin(Origin::Igp),
            PathAttribute::AsPath(AsPath::sequence([65002])),
            PathAttribute::NextHop(id(2)),
        ];
        let announce = BgpUpdate {
            withdrawn: vec![],
            attrs: attrs.clone(),
            nlri: vec![Nlri {
                prefix: "203.0.113.0/24".parse().unwrap(),
                path_id: 1,
            }],
        };
        // frame = 19 header + 2+0 withdrawn + 2+18 attrs + 8 NLRI
        // (4 id + 1 length + 3 address octets) = 49 (0x31).
        let frame = BgpMessage::Update(announce.clone())
            .encode_with(false, ctx)
            .unwrap();
        let expected = unhex(
            "ffffffffffffffffffffffffffffffff 0031 02 \
             0000 \
             0012 \
             40 01 01 00 \
             40 02 04 02 01 fdea \
             40 03 04 0a000002 \
             00000001 18 cb0071",
        );
        assert_eq!(frame, expected);
        let (back, _) =
            BgpMessage::decode_with_handling(&frame, false, UpdateHandling::StrictRfc4271, ctx)
                .unwrap();
        assert_eq!(back, BgpMessage::Update(announce));

        let withdraw = BgpUpdate {
            withdrawn: vec![Nlri {
                prefix: "198.51.100.0/24".parse().unwrap(),
                path_id: 0x0102_0304,
            }],
            attrs,
            nlri: vec![],
        };
        // frame = 19 header + 2+8 withdrawn + 2+18 attrs = 49 (0x31).
        let frame = BgpMessage::Update(withdraw.clone())
            .encode_with(false, ctx)
            .unwrap();
        let expected = unhex(
            "ffffffffffffffffffffffffffffffff 0031 02 \
             0008 01020304 18 c63364 \
             0012 \
             40 01 01 00 \
             40 02 04 02 01 fdea \
             40 03 04 0a000002",
        );
        assert_eq!(frame, expected);
        let (back, _) =
            BgpMessage::decode_with_handling(&frame, false, UpdateHandling::StrictRfc4271, ctx)
                .unwrap();
        assert_eq!(back, BgpMessage::Update(withdraw));
        // Mixed path IDs on one prefix coexist as separate entries —
        // the §5 replacement key.
        let update = BgpUpdate {
            withdrawn: vec![],
            attrs: vec![
                PathAttribute::Origin(Origin::Igp),
                PathAttribute::AsPath(AsPath::sequence([65002])),
                PathAttribute::NextHop(id(2)),
            ],
            nlri: vec![
                Nlri {
                    prefix: "203.0.113.0/24".parse().unwrap(),
                    path_id: 1,
                },
                Nlri {
                    prefix: "203.0.113.0/24".parse().unwrap(),
                    path_id: 2,
                },
            ],
        };
        let frame = BgpMessage::Update(update.clone())
            .encode_with(false, ctx)
            .unwrap();
        let (back, _) =
            BgpMessage::decode_with_handling(&frame, false, UpdateHandling::StrictRfc4271, ctx)
                .unwrap();
        assert_eq!(back, BgpMessage::Update(update));
    }

    /// RFC 7911 §3 applies wherever the session's NLRI encoding is
    /// used: MP_REACH and MP_UNREACH prefix lists for v6 under the
    /// negotiated (2,1) direction.
    #[test]
    fn update_add_path_mp_v6_round_trip() {
        let ctx = AddPathCtx {
            v4: false,
            v6: true,
        };
        // One container each (RFC 7606 §5.1): the MP_UNREACH
        // withdrawal and the MP_REACH announce ride separate frames.
        let unreach = BgpUpdate {
            withdrawn: vec![],
            attrs: vec![PathAttribute::MpUnreach(MpUnreach {
                afi: 2,
                safi: 1,
                withdrawn: vec![Nlri {
                    prefix: "2001:db8::/32".parse().unwrap(),
                    path_id: 9,
                }],
            })],
            nlri: vec![],
        };
        let frame = BgpMessage::Update(unreach.clone())
            .encode_with(true, ctx)
            .unwrap();
        let (back, _) =
            BgpMessage::decode_with_handling(&frame, true, UpdateHandling::StrictRfc4271, ctx)
                .unwrap();
        assert_eq!(back, BgpMessage::Update(unreach));

        let reach = BgpUpdate {
            withdrawn: vec![],
            attrs: vec![PathAttribute::MpReach(MpReach {
                afi: 2,
                safi: 1,
                next_hop: crate::attr::MpNextHop::V6 {
                    global: "2001:db8::1".parse().unwrap(),
                    link_local: None,
                },
                nlri: vec![
                    Nlri {
                        prefix: "2001:db8:aa::/48".parse().unwrap(),
                        path_id: 1,
                    },
                    Nlri {
                        prefix: "2001:db8:aa::/48".parse().unwrap(),
                        path_id: 0xdead_beef,
                    },
                ],
            })],
            nlri: vec![],
        };
        let frame = BgpMessage::Update(reach.clone())
            .encode_with(true, ctx)
            .unwrap();
        let (back, _) =
            BgpMessage::decode_with_handling(&frame, true, UpdateHandling::StrictRfc4271, ctx)
                .unwrap();
        assert_eq!(back, BgpMessage::Update(reach.clone()));

        // The v4 top-level fields stay classic under a v6-only
        // negotiation: family-scoped, not session-global.
        assert!(!ctx.for_family(1, 1));
        // And a v4 classic NLRI in the SAME message decodes with
        // path_id 0 (classic key) even under this ctx — a receive-side
        // frame built by hand (§5.1 forbids SENDING the mix; receivers
        // "MUST still be prepared to receive these fields in any
        // position or combination").
        let mut attrs = reach.attrs.clone();
        // The v4 NLRI's mandatory triple (§6.3): the MP-only attrs of
        // the v6 update above do not cover it.
        attrs.extend([
            PathAttribute::Origin(Origin::Igp),
            PathAttribute::AsPath(AsPath::default()),
            PathAttribute::NextHop(id(3)),
        ]);
        let mut attr_bytes = Vec::new();
        crate::attr::encode_attributes(&attrs, &mut attr_bytes, true, ctx).unwrap();
        let mut body = vec![0x00, 0x00];
        body.extend_from_slice(&(attr_bytes.len() as u16).to_be_bytes());
        body.extend_from_slice(&attr_bytes);
        body.extend_from_slice(&[24, 203, 0, 113]);
        let (decoded, _) =
            BgpUpdate::decode_with_handling(&body, true, UpdateHandling::StrictRfc4271, ctx)
                .unwrap();
        assert_eq!(decoded.nlri.len(), 1);
        assert_eq!(decoded.nlri[0].path_id, 0, "classic key");
        assert_eq!(decoded.announced().len(), 3, "2 v6 + 1 v4");
    }

    /// The /0 hazard, pinned (RFC 7911's only defense is the
    /// capability gate): extended NLRI decoded under a CLASSIC
    /// context reads the path ID's top octet as the prefix length —
    /// path IDs 1..255 read as 0, i.e. 0.0.0.0/0 — and the decode
    /// must NOT silently succeed with a poisoned default route. These
    /// exact bytes error (the trailing garbage trips the length
    /// validation); the gate itself (never decoding extended without
    /// the negotiation) is what makes the aligned-poison case
    /// unreachable in operation — capability trust, no heuristic.
    #[test]
    fn add_path_zero_hazard_classic_context_is_loud() {
        // Extended encoding of (path 1, 203.0.113.0/24):
        // 00 00 00 01 | 18 | cb 00 71 — classic eyes see length 0,
        // 0, 0, then 1 (a /1 needing 1 octet = 0x18), then 0xcb = 203
        // > 32 → INVALID_NETWORK_FIELD.
        let body = unhex("0000 0000 00000001 18 cb0071");
        let err = BgpUpdate::decode(&body, false).unwrap_err();
        assert_eq!(
            err.notification,
            Some((3, error::update_subcode::INVALID_NETWORK_FIELD))
        );
    }

    /// The mirror mis-gate: CLASSIC bytes under an extended context
    /// read the first 4 prefix octets as the path ID — loud here too
    /// (the /24 runs out of octets for its length byte).
    #[test]
    fn classic_nlri_under_add_path_ctx_is_loud() {
        let ctx = AddPathCtx { v4: true, v6: true };
        let body = unhex("0000 0000 18 cb0071");
        let err = BgpUpdate::decode_with_handling(&body, false, UpdateHandling::StrictRfc4271, ctx)
            .unwrap_err();
        assert_eq!(
            err.notification,
            Some((3, error::update_subcode::INVALID_NETWORK_FIELD))
        );
    }

    /// RFC 7911 §5's send-side MUST, enforced at the codec: a nonzero
    /// Path Identifier is never emitted under the classic encoding —
    /// refused loudly, not silently flattened to a corrupt frame.
    #[test]
    fn path_id_refused_without_negotiated_ctx() {
        let update = BgpUpdate {
            withdrawn: vec![],
            attrs: vec![
                PathAttribute::Origin(Origin::Igp),
                PathAttribute::AsPath(AsPath::sequence([65002])),
                PathAttribute::NextHop(id(2)),
            ],
            nlri: vec![Nlri {
                prefix: "203.0.113.0/24".parse().unwrap(),
                path_id: 7,
            }],
        };
        assert!(BgpMessage::Update(update.clone()).encode(false).is_err());
        // With the direction negotiated, the same message encodes.
        let ctx = AddPathCtx {
            v4: true,
            v6: false,
        };
        assert!(BgpMessage::Update(update).encode_with(false, ctx).is_ok());
    }

    /// RFC 4724 §3 End-of-RIB markers: the v4-unicast one is the bare
    /// minimum UPDATE; a multiprotocol family's is an empty
    /// MP_UNREACH. Neither an ordinary UPDATE nor a withdrawn-only
    /// UPDATE counts.
    #[test]
    fn end_of_rib_marker_shapes() {
        let v4 = BgpUpdate::end_of_rib_marker(1, 1);
        assert_eq!(v4.end_of_rib(), Some(None));
        let frame = v4.encode_frame(false).unwrap();
        assert_eq!(frame.len(), 23, "the minimum UPDATE length");
        match BgpMessage::decode(&frame, false).unwrap() {
            BgpMessage::Update(back) => assert_eq!(back, v4),
            other => panic!("{other:?}"),
        }

        let v6 = BgpUpdate::end_of_rib_marker(2, 1);
        assert_eq!(v6.end_of_rib(), Some(Some((2, 1))));
        let frame = v6.encode_frame(true).unwrap();
        match BgpMessage::decode(&frame, true).unwrap() {
            BgpMessage::Update(back) => assert_eq!(back, v6),
            other => panic!("{other:?}"),
        }

        // A route-bearing UPDATE is not an EOR; neither is a
        // withdrawal.
        let announce = BgpUpdate {
            attrs: vec![PathAttribute::Origin(Origin::Igp)],
            nlri: vec!["203.0.113.0/24".parse().unwrap()],
            ..Default::default()
        };
        assert_eq!(announce.end_of_rib(), None);
        let withdraw = BgpUpdate {
            withdrawn: vec!["203.0.113.0/24".parse().unwrap()],
            ..Default::default()
        };
        assert_eq!(withdraw.end_of_rib(), None);
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

    /// RFC 8538 §3.1's Hard Reset wire form: Cease (6) with subcode 9
    /// and "an encapsulated NOTIFICATION" in the data portion —
    /// `ErrCode(1) | Subcode(1) | Data` of the reason. A reason
    /// carrying its own data (RFC 4486 subcode 1's prefix limit)
    /// keeps it after the two leading octets.
    #[test]
    fn hard_reset_wire_format_and_round_trip() {
        let reason = BgpNotification {
            code: 6,
            subcode: error::cease_subcode::ADMIN_SHUTDOWN,
            data: vec![],
        };
        let hr = BgpNotification::hard_reset(&reason);
        assert!(hr.is_hard_reset());
        assert_eq!(hr.code, 6);
        assert_eq!(hr.subcode, error::cease_subcode::HARD_RESET);
        assert_eq!(hr.data, vec![6, 2]);
        // frame tail: length 23, type 3, 6, 9, 6, 2.
        let frame = BgpMessage::Notification(hr.clone()).encode(false).unwrap();
        assert_eq!(&frame[16..], &[0, 23, 3, 6, 9, 6, 2]);
        let back = match BgpMessage::decode(&frame, false).unwrap() {
            BgpMessage::Notification(n) => n,
            other => panic!("{other:?}"),
        };
        assert!(back.is_hard_reset());
        let unwrapped = back.hard_reset_reason().unwrap();
        assert_eq!((unwrapped.code, unwrapped.subcode), (6, 2));

        // A reason with data: RFC 4486 subcode 1 carries the limit.
        let maxpfx = BgpNotification {
            code: 6,
            subcode: error::cease_subcode::MAX_PREFIXES,
            data: vec![0x00, 0x0c, 0x00, 0x00],
        };
        let hr = BgpNotification::hard_reset(&maxpfx);
        assert_eq!(hr.data, vec![6, 1, 0x00, 0x0c, 0x00, 0x00]);
        let unwrapped = hr.hard_reset_reason().unwrap();
        assert_eq!((unwrapped.code, unwrapped.subcode), (6, 1));
        assert_eq!(unwrapped.data, vec![0x00, 0x0c, 0x00, 0x00]);

        // A truncated reason body logs as reason-less, never panics.
        let bare = BgpNotification {
            code: 6,
            subcode: error::cease_subcode::HARD_RESET,
            data: vec![6],
        };
        assert!(bare.is_hard_reset());
        assert!(bare.hard_reset_reason().is_none());
        // And a plain Cease is not a Hard Reset.
        assert!(!reason.is_hard_reset());
        assert!(reason.hard_reset_reason().is_none());
    }

    /// RFC 8538 §5.1's table, row by row, plus the two global rules:
    /// toward a peer that did not offer the N bit nothing is wrapped,
    /// and non-Cease error codes are never wrapped ("use of Hard
    /// Reset does not appear to be indicated"). Subcode 4
    /// (Administrative Reset) is the table's "user control" row — v1
    /// sends it plain (graceful).
    #[test]
    fn rfc8538_send_classification_table() {
        let table = [
            (1u8, true), // Maximum Number of Prefixes Reached
            (2, true),   // Administrative Shutdown
            (3, true),   // Peer De-configured
            (4, false),  // Administrative Reset — user control (v1: plain)
            (5, false),  // Connection Rejected
            (6, false),  // Other Configuration Change
            (7, false),  // Connection Collision Resolution
            (8, false),  // Out of Resources
        ];
        for (subcode, expect_hard) in table {
            let plain = BgpNotification::cease(subcode);
            let sent = plain.wrapped_for_n_peer(true);
            assert_eq!(
                sent.is_hard_reset(),
                expect_hard,
                "Cease/{subcode} wrapped={} expected={expect_hard}",
                sent.is_hard_reset()
            );
            if expect_hard {
                let reason = sent.hard_reset_reason().unwrap();
                assert_eq!((reason.code, reason.subcode), (6, subcode));
            } else {
                assert_eq!(sent, plain);
            }
            // Without the N bit: everything rides plain.
            assert_eq!(plain.wrapped_for_n_peer(false), plain);
        }
        // Non-Cease codes are never wrapped, N bit or not.
        for (code, subcode) in [
            (1u8, 3u8), // Message Header / Bad Message Type
            (2, 2),     // OPEN / Bad Peer AS
            (3, 11),    // UPDATE / Malformed AS_PATH
            (4, 0),     // Hold Timer Expired
            (5, 0),     // Finite State Machine
        ] {
            let plain = BgpNotification {
                code,
                subcode,
                data: vec![],
            };
            assert_eq!(plain.wrapped_for_n_peer(true), plain);
            assert!(!plain.is_hard_reset());
        }
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

    /// B-4's table: every pair of route containers is a hard encode
    /// reject (RFC 7606 §5.1's MUST NOT), while each legitimate
    /// single-container shape — announce, withdrawal, both EOR
    /// markers — still encodes.
    #[test]
    fn encode_rejects_mixed_route_containers() {
        fn attrs(extra: Vec<PathAttribute>) -> Vec<PathAttribute> {
            [
                PathAttribute::Origin(Origin::Igp),
                PathAttribute::AsPath(AsPath::default()),
                PathAttribute::NextHop(id(2)),
            ]
            .into_iter()
            .chain(extra)
            .collect()
        }
        let p4 = "203.0.113.0/24".parse().unwrap();
        let mp_reach = PathAttribute::MpReach(MpReach {
            afi: 2,
            safi: 1,
            next_hop: crate::attr::MpNextHop::V6 {
                global: "2001:db8::1".parse().unwrap(),
                link_local: None,
            },
            nlri: vec!["2001:db8:aa::/48".parse().unwrap()],
        });
        let mp_unreach = PathAttribute::MpUnreach(MpUnreach {
            afi: 2,
            safi: 1,
            withdrawn: vec!["2001:db8::/32".parse().unwrap()],
        });
        // Each row names two of the four containers.
        let mixed = [
            // withdrawn + NLRI
            BgpUpdate {
                withdrawn: vec![p4],
                attrs: attrs(vec![]),
                nlri: vec![p4],
            },
            // NLRI + MP_REACH
            BgpUpdate {
                withdrawn: vec![],
                attrs: attrs(vec![mp_reach.clone()]),
                nlri: vec![p4],
            },
            // withdrawn + MP_UNREACH
            BgpUpdate {
                withdrawn: vec![p4],
                attrs: attrs(vec![mp_unreach.clone()]),
                nlri: vec![],
            },
            // MP_REACH + MP_UNREACH
            BgpUpdate {
                withdrawn: vec![],
                attrs: attrs(vec![mp_reach.clone(), mp_unreach.clone()]),
                nlri: vec![],
            },
        ];
        for (i, update) in mixed.iter().enumerate() {
            let err = update.encode_frame(true).unwrap_err();
            assert!(err.message.contains("§5.1"), "row {i}: {}", err.message);
        }
        // The legitimate shapes pass.
        for ok in [
            BgpUpdate::default(),               // v4 EOR
            BgpUpdate::end_of_rib_marker(2, 1), // v6 EOR
            BgpUpdate {
                attrs: attrs(vec![]),
                nlri: vec![p4],
                ..Default::default()
            },
            BgpUpdate {
                withdrawn: vec![p4],
                attrs: attrs(vec![]),
                ..Default::default()
            },
        ] {
            assert!(ok.encode_frame(true).is_ok());
        }
    }

    // ---- RFC 7606 structured outcome (B-1/B-2, S8-a) ----------------

    use crate::attr::UpdateOutcome;

    fn decode_7606(body: &[u8]) -> BgpResult<(BgpUpdate, UpdateOutcome)> {
        BgpUpdate::decode_with_handling(
            body,
            false,
            UpdateHandling::Rfc7606 { internal: false },
            AddPathCtx::default(),
        )
    }

    /// B-1's enum end to end (UPDATE level): Clean / Discarded /
    /// Withdrawn, the withdrawal set built from the parseable NLRI
    /// (§3(j)) and naming both directions of "contained" (§2).
    #[test]
    fn update_outcome_enum_three_dispositions() {
        // Clean: the golden announce shape.
        let clean = unhex("0000 0012 40010100 400204 0201fdea 400304 0a000002 18cb0071");
        let (_, outcome) = decode_7606(&clean).unwrap();
        assert_eq!(outcome, UpdateOutcome::Clean);

        // Withdrawn (§2): malformed ORIGIN (length 2) with NLRI — the
        // routes are exactly what parsed (AS_PATH + NEXT_HOP are good,
        // so ORIGIN is the sole cause).
        let taw = unhex("0000 0013 400102 0000 400204 0201fdea 400304 0a000002 18cb0071");
        let (update, outcome) = decode_7606(&taw).unwrap();
        assert_eq!(
            outcome,
            UpdateOutcome::Withdrawn {
                routes: vec!["203.0.113.0/24".parse().unwrap()],
                causes: vec![(1, "attribute 1 length 2, expected 1 (§4.3)".into())],
            },
            "the announced prefix is the withdrawal set"
        );
        assert!(
            !update.nlri.is_empty(),
            "the NLRI parsed — §3(j)'s prerequisite for treat-as-withdraw"
        );

        // Withdrawn names the explicit withdrawals too (§2 "all
        // contained routes") — a mixed frame (receiver tolerance,
        // §5.1's "MUST still be prepared to receive ... any ...
        // combination") carries both directions.
        let taw = unhex("0004 18c63364 0013 400102 0000 400204 0201fdea 400304 0a000002 18cb0071");
        let (_, outcome) = decode_7606(&taw).unwrap();
        match outcome {
            UpdateOutcome::Withdrawn { routes, .. } => assert_eq!(
                routes,
                vec![
                    "203.0.113.0/24".parse().unwrap(),
                    "198.51.100.0/24".parse().unwrap(),
                ]
            ),
            other => panic!("{other:?}"),
        }

        // Discarded (§2's third disposition): a wrong-length
        // AGGREGATOR rides with a processable route.
        let disc =
            unhex("0000 0018 40010100 400204 0201fdea 400304 0a000002 c00703 010203 18cb0071");
        let (update, outcome) = decode_7606(&disc).unwrap();
        assert_eq!(update.nlri.len(), 1, "the route processes");
        match outcome {
            UpdateOutcome::Discarded(causes) => assert_eq!(causes[0].0, 7),
            other => panic!("{other:?}"),
        }
    }

    /// §3(d): "If any of the well-known mandatory attributes are not
    /// present in an UPDATE message, then 'treat-as-withdraw' MUST be
    /// used" — folded into the outcome (the strict mode keeps the
    /// §6.3 session reset with subcode 3 and the absent type in the
    /// data field shape).
    #[test]
    fn missing_well_known_folds_into_the_outcome() {
        // ORIGIN + AS_PATH but no NEXT_HOP, with NLRI.
        let body = unhex("0000 0007 40010100 400200 18cb0071");
        let (update, outcome) = decode_7606(&body).unwrap();
        assert!(!update.nlri.is_empty());
        match outcome {
            UpdateOutcome::Withdrawn { routes, causes } => {
                assert_eq!(routes, vec!["203.0.113.0/24".parse().unwrap()]);
                assert!(causes[0].1.contains("missing well-known"));
            }
            other => panic!("{other:?}"),
        }
        let err = BgpUpdate::decode(&body, false).unwrap_err();
        assert_eq!(
            err.notification,
            Some((3, error::update_subcode::MISSING_WELL_KNOWN_ATTRIBUTE)),
            "strict mode: the RFC 4271 session reset"
        );
    }

    /// §5.2, verbatim shape: "if an UPDATE message ... does contain
    /// path attributes other than MP_UNREACH_NLRI and doesn't encode
    /// any reachable NLRI ... if any ... error specifies an approach
    /// other than 'attribute discard', then the 'session reset'
    /// approach MUST be used" — treat-as-withdraw is voided for the
    /// no-NLRI shapes, kept when NLRI parsed, and attribute discard
    /// never escalates.
    #[test]
    fn rfc7606_5_2_no_reachable_nlri_escalates_to_reset() {
        // Bad ORIGIN, no NLRI at all: cannot be confident the NLRI
        // parsed (§3(j)) → session reset with the triggering subcode.
        let body = unhex("0000 0005 400102 0000");
        let err = decode_7606(&body).unwrap_err();
        assert_eq!(
            err.notification,
            Some((3, error::update_subcode::ATTRIBUTE_LENGTH_ERROR))
        );
        assert!(err.message.contains("§5.2"));

        // Withdrawal-only UPDATE with a bad MED: same escalation.
        let body = unhex("0004 18c63364 000a 40010100 800403 000001");
        let err = decode_7606(&body).unwrap_err();
        assert_eq!(
            err.notification,
            Some((3, error::update_subcode::ATTRIBUTE_LENGTH_ERROR)),
            "no reachable NLRI: treat-as-withdraw voided (§5.2)"
        );

        // The contrast: the same bad ORIGIN WITH NLRI stays
        // treat-as-withdraw (§2/§3(j) satisfied).
        let body = unhex("0000 0005 400102 0000 18cb0071");
        assert!(matches!(
            decode_7606(&body).unwrap().1,
            UpdateOutcome::Withdrawn { .. }
        ));

        // Attribute-discard errors never escalate (§5.2's "other than
        // 'attribute discard'"): bad AGGREGATOR, no NLRI → Discarded.
        let body = unhex("0000 000a 40010100 c00703 010203");
        assert!(matches!(
            decode_7606(&body).unwrap().1,
            UpdateOutcome::Discarded(_)
        ));
    }

    /// The strict escape hatch (B-2's knob,
    /// `neighbor X update-error-handling strict-rfc4271`): the same
    /// frames under RFC 4271 handling are session resets, never
    /// salvageable outcomes.
    #[test]
    fn strict_rfc4271_keeps_the_session_resets() {
        let strict = |body: &[u8]| {
            BgpUpdate::decode_with_handling(
                body,
                false,
                UpdateHandling::StrictRfc4271,
                AddPathCtx::default(),
            )
        };
        for body in [
            // treat-as-withdraw class: malformed ORIGIN with NLRI.
            unhex("0000 0005 400102 0000 18cb0071"),
            // attribute-discard class: bad AGGREGATOR.
            unhex("0000 0007 40010100 c00703 010203"),
        ] {
            let err = strict(&body).unwrap_err();
            assert_eq!(
                err.notification.map(|(c, _)| c),
                Some(3),
                "UPDATE Message Error, the §6.3 reset"
            );
        }
    }
}
