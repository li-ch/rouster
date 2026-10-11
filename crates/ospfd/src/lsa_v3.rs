//! The OSPFv3 LSA codec (RFC 5340 Appendix A.4: the 20-byte header
//! §A.4.2 with the 16-bit LS type of §A.4.2.1, and the IPv6 bodies —
//! router §A.4.3, network §A.4.4, inter-area-prefix §A.4.5,
//! inter-area-router §A.4.6, AS-external §A.4.7 (shared by the
//! NSSA-LSA §A.4.8), link §A.4.9, intra-area-prefix §A.4.10, plus
//! the shared IPv6 prefix representation §A.4.1).
//!
//! This is the N2B ladder slice: **codecs only, no v6 runtime**. The
//! v2 codec in [`crate::lsa`] is untouched (only-add); the two
//! families meet on the shared seams documented there — the u16
//! [`LsaType`](crate::lsa::LsaType), the u32 [`RouterId`] /
//! [`LinkStateId`], the signed sequence space of §12.1.6 (RFC 2328
//! lineage via RFC 5340 §4.4.1), and the Fletcher-16 placement
//! (checksum over everything except the 2-byte age, field at LSA
//! bytes 16-17 — relative offset 14 from byte 2, identical to v2).
//!
//! Strictness policy (the curated v3 list — deliberately different
//! from v2 in exactly two places, both RFC-mandated):
//!
//! - **Unknown LS function codes decode, they do not error** — the
//!   U-bit contract (§3.4/A.4.2.1): unrecognized types are stored
//!   and flooded via [`LsaBodyV3::Unknown`]. v2's header codec
//!   rejects them; v3 *requires* tolerance. The S2/S1 = `0b11`
//!   reserved scope is still rejected (A.4.2.1's table).
//! - **Unknown Options and PrefixOptions bits are carried and
//!   ignored** (§A.2: "ignore the unrecognized bits and process the
//!   packet or LSA normally") — the deliberate exception to the
//!   house reserved-bit-rejection rule, as is the deprecated x-bit
//!   (set 0, ignore on receipt) in both the Options field and the
//!   router-LSA flags.
//! - Everything else follows the house rule: structural reserved
//!   fields (the prefix triple's 16-bit zero, the router-link
//!   reserved octet, the five bits above E/F/T, the DBD preamble's
//!   reserved octet) are rejected when nonzero — the capture-corpus
//!   experience is that real senders zero them, and leniency here
//!   is a fingerprinting hazard.
//! - Framing exactness everywhere (the A19 lesson): declared
//!   lengths and count fields (`# prefixes` in link- and
//!   intra-area-prefix-LSAs) must consume the body exactly.

use std::net::Ipv6Addr;

use crate::checksum::{fletcher_verify, lsa_fletcher_checksum};
use crate::error::OspfError;
use crate::lsa::{LinkStateId, LsaType, RouterId, INITIAL_SEQUENCE_NUMBER, MAX_SEQUENCE_NUMBER};
use crate::wire::{put_u16, put_u24, put_u32, put_u8, Reader};

/// The 24-bit OSPFv3 Options field (RFC 5340 A.2), present in
/// Hello/DBD packets and in the router-, network-, inter-area-router-
/// and link-LSA bodies. Layout of the low octet (bit 0 = V6):
/// `| *16 reserved* | DC | R | N | x | E | V6 |`. Unrecognized bits
/// are ignored on receipt and cleared when sending (A.2); the raw
/// value is kept so re-flooding an LSA stays byte-faithful.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Options24(pub u32);

impl Options24 {
    pub const V6: u32 = 0x01;
    pub const E: u32 = 0x02;
    /// Deprecated MOSPF bit (A.2): set 0, ignore on receipt.
    pub const X: u32 = 0x04;
    pub const N: u32 = 0x08;
    pub const R: u32 = 0x10;
    pub const DC: u32 = 0x20;

    pub fn v6_bit(self) -> bool {
        self.0 & Self::V6 != 0
    }

    pub fn e_bit(self) -> bool {
        self.0 & Self::E != 0
    }

    pub fn n_bit(self) -> bool {
        self.0 & Self::N != 0
    }

    pub fn r_bit(self) -> bool {
        self.0 & Self::R != 0
    }

    pub fn dc_bit(self) -> bool {
        self.0 & Self::DC != 0
    }

    pub(crate) fn read(r: &mut Reader<'_>, field: &'static str) -> Result<Self, OspfError> {
        let raw = r.u24().ok_or(OspfError::Truncated {
            field,
            need: 3,
            have: 0,
        })?;
        Ok(Self(raw))
    }

    pub(crate) fn put(&self, buf: &mut Vec<u8>) {
        put_u24(buf, self.0);
    }
}

/// The 8-bit PrefixOptions field of every advertised prefix (RFC
/// 5340 A.4.1.1): `| *3 | DN | P | x | LA | NU |` (bit 0 = NU). The
/// x-bit is deprecated (set 0 / ignore); unassigned high bits are
/// carried and ignored, like the Options field.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct PrefixOptions(pub u8);

impl PrefixOptions {
    /// NU: exclude the prefix from IPv6 unicast calculations.
    pub const NU: u8 = 0x01;
    /// LA: the prefix is an IPv6 interface address of the advertiser.
    pub const LA: u8 = 0x02;
    /// Deprecated (was multicast): set 0, ignore on receipt.
    pub const X: u8 = 0x04;
    /// P: NSSA propagate (RFC 3101).
    pub const P: u8 = 0x08;
    /// DN: VPN re-advertisement control ([DN-BIT]).
    pub const DN: u8 = 0x10;

    pub fn nu_bit(self) -> bool {
        self.0 & Self::NU != 0
    }

    pub fn la_bit(self) -> bool {
        self.0 & Self::LA != 0
    }

    pub fn p_bit(self) -> bool {
        self.0 & Self::P != 0
    }

    pub fn dn_bit(self) -> bool {
        self.0 & Self::DN != 0
    }
}

/// The OSPFv3 prefix triple (RFC 5340 A.4.1): PrefixLength (0-128),
/// PrefixOptions, a 16-bit zero field, then the address prefix as
/// `((PrefixLength + 31) / 32)` zero-padded 32-bit words. Length 0
/// is the default route (A.4.5/A.4.7).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Prefix {
    /// Bits, 0..=128.
    pub len: u8,
    pub options: PrefixOptions,
    /// Exactly [`Prefix::words`] bytes, zero-padded per the RFC.
    pub addr: Vec<u8>,
}

impl Prefix {
    /// The address-prefix size in bytes: `(len + 31) / 32` words of
    /// 4 bytes (A.4.1) — a 17-bit prefix occupies 8 bytes, /32
    /// occupies 4, the default route occupies none.
    pub fn words(len: u8) -> usize {
        (len as usize).div_ceil(32) * 4
    }

    /// The default route (length 0, A.4.1: "The default route is
    /// represented by a prefix of length 0").
    pub fn default_route() -> Self {
        Self {
            len: 0,
            options: PrefixOptions(0),
            addr: Vec::new(),
        }
    }

    fn encode(&self, buf: &mut Vec<u8>) {
        debug_assert_eq!(self.addr.len(), Self::words(self.len));
        put_u8(buf, self.len);
        put_u8(buf, self.options.0);
        put_u16(buf, 0);
        buf.extend_from_slice(&self.addr);
    }

    fn decode(r: &mut Reader<'_>, field: &'static str) -> Result<Self, OspfError> {
        let len = r.u8().ok_or(OspfError::Truncated {
            field,
            need: 1,
            have: 0,
        })?;
        if len > 128 {
            return Err(OspfError::BadLength {
                field: "prefix length",
                declared: len as usize,
                actual: 128,
            });
        }
        let options = PrefixOptions(r.u8().ok_or(OspfError::Truncated {
            field,
            need: 1,
            have: 0,
        })?);
        let zero = r.u16().ok_or(OspfError::Truncated {
            field,
            need: 2,
            have: 0,
        })?;
        if zero != 0 {
            return Err(OspfError::ReservedBits16 {
                field: "prefix reserved",
                value: zero,
            });
        }
        let want = Self::words(len);
        let addr = r
            .take(want)
            .ok_or(OspfError::Truncated {
                field,
                need: want,
                have: r.remaining(),
            })?
            .to_vec();
        Ok(Self { len, options, addr })
    }
}

/// Router link types (RFC 5340 A.4.3 "Router Link Types" table) —
/// v2's stub link (type 3) is gone: it is *reserved* in v3, its
/// addressing work moved to the intra-area-prefix-LSA.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LinkTypeV3 {
    /// 1: point-to-point connection to another router.
    PointToPoint,
    /// 2: connection to a transit network (the neighbor described is
    /// the link's DR).
    Transit,
    /// 4: virtual link.
    Virtual,
}

impl LinkTypeV3 {
    fn from_u8(v: u8) -> Result<Self, OspfError> {
        match v {
            1 => Ok(Self::PointToPoint),
            2 => Ok(Self::Transit),
            4 => Ok(Self::Virtual),
            other => Err(OspfError::BadLinkType(other)),
        }
    }

    fn to_u8(self) -> u8 {
        match self {
            Self::PointToPoint => 1,
            Self::Transit => 2,
            Self::Virtual => 4,
        }
    }
}

/// One v3 router-link record (A.4.3): 16 bytes — Type, a reserved
/// zero octet, Metric, Interface ID, Neighbor Interface ID,
/// Neighbor Router ID. No TOS tails, no addresses.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RouterLinkV3 {
    pub link_type: LinkTypeV3,
    pub metric: u16,
    /// The Interface ID assigned to the interface being described.
    pub interface_id: u32,
    /// The neighbor's Interface ID for the link (the DR's, for type-2
    /// links) — together with the neighbor Router ID it locates the
    /// attached network-LSA.
    pub neighbor_interface_id: u32,
    pub neighbor_router_id: RouterId,
}

/// The v3 router-LSA body (A.4.3): `| 0(3) | Nt | x | V | E | B |`
/// plus the 24-bit Options, then 16-byte link records to Length
/// exhaustion (there is no link count field in v3).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RouterLsaV3 {
    /// Nt: NSSA border router translating unconditionally (RFC 3101
    /// §3.1) — decode-carry only; translation semantics are not
    /// tonight's scope.
    pub nt_bit: bool,
    pub v_bit: bool,
    pub e_bit: bool,
    pub b_bit: bool,
    pub options: Options24,
    pub links: Vec<RouterLinkV3>,
}

/// The v3 network-LSA body (A.4.4): one `| 0 | Options |` word then
/// the attached Router IDs (count deduced from the LSA header's
/// Length). No mask — subnets ceased to exist as an LSA concept
/// (§2.2). The LS ID is the DR's Interface ID on the link.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NetworkLsaV3 {
    /// Logical OR of all fully adjacent neighbors' link-LSA Options
    /// (§4.4.3.3 — the DR computes it from received link-LSAs).
    pub options: Options24,
    pub attached: Vec<RouterId>,
}

/// The inter-area-prefix-LSA body (A.4.5, the v2 type-3): a 24-bit
/// metric and the prefix triple. The stub-area default route is
/// PrefixLength 0.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InterAreaPrefixLsaV3 {
    pub metric: u32,
    pub prefix: Prefix,
}

/// The inter-area-router-LSA body (A.4.6, the v2 type-4): the
/// destination ASBR's capabilities, a 24-bit metric, and the
/// Destination Router ID *in the body* (v2 carried it in the Link
/// State ID; v3's LS ID is a pure de-multiplexer).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InterAreaRouterLsaV3 {
    /// The destination router's router-LSA Options.
    pub options: Options24,
    pub metric: u32,
    pub destination_router_id: RouterId,
}

/// The AS-external-LSA body (A.4.7) — also the NSSA-LSA body
/// (A.4.8: "other than the LS type, their format is exactly the
/// same"). E/F/T live in the top three bits of the flags octet,
/// making the v2 always-present forwarding address and tag
/// *optional* (present iff F / T set), with the Referenced Link
/// State ID present iff the Referenced LS Type is non-zero.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AsExternalLsaV3 {
    pub e_bit: bool,
    pub f_bit: bool,
    pub t_bit: bool,
    /// 24-bit metric.
    pub metric: u32,
    pub prefix: Prefix,
    /// Zero "until its use is defined" (§4.4.3.6); non-zero values
    /// are ignored on receipt, not rejected (§4.4.3.7).
    pub referenced_ls_type: u16,
    /// Present iff F. MUST be a global IPv6 address when present —
    /// never `::` and never `fe80::/10` (A.4.7).
    pub forwarding_address: Option<Ipv6Addr>,
    /// Present iff T.
    pub external_route_tag: Option<u32>,
    /// Present iff `referenced_ls_type != 0`.
    pub referenced_link_state_id: Option<u32>,
}

/// The link-LSA body (A.4.9, link-local flooding scope, no v2
/// counterpart): the router's priority, its Options contribution to
/// the DR's network-LSA, its link-local address on the link, and the
/// link's prefixes. Link-local addresses appear in link-LSAs and
/// nowhere else (§2.5).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LinkLsaV3 {
    pub router_priority: u8,
    pub options: Options24,
    /// The originator's link-local interface address (128 bits).
    pub link_local_address: Ipv6Addr,
    pub prefixes: Vec<Prefix>,
}

/// One intra-area-prefix-LSA prefix record (A.4.10): the prefix
/// triple plus a per-prefix 16-bit Metric (the v2 stub-link metric
/// analogue).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PrefixMetric {
    pub metric: u16,
    pub prefix: Prefix,
}

/// The intra-area-prefix-LSA body (A.4.10): prefixes + metrics plus
/// the (Referenced LS Type, Link State ID, Advertising Router)
/// triple pointing at the router-LSA (0x2001) or network-LSA
/// (0x2002) the prefixes belong to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IntraAreaPrefixLsaV3 {
    pub prefixes: Vec<PrefixMetric>,
    pub referenced_ls_type: LsaType,
    pub referenced_link_state_id: LinkStateId,
    pub referenced_adv_router: RouterId,
}

/// A decoded OSPFv3 LSA: header + typed body.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LsaV3 {
    pub header: LsaHeaderV3,
    pub body: LsaBodyV3,
}

/// The eight OSPFv3 body shapes plus the U-bit escape hatch. The
/// [`Unknown`](LsaBodyV3::Unknown) variant is load-bearing: v3's
/// U-bit contract (§3.4) means a codec that errors on unknown
/// function codes is non-conformant — such LSAs are stored and
/// flooded opaque, which requires carrying the raw body bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LsaBodyV3 {
    Router(RouterLsaV3),
    Network(NetworkLsaV3),
    InterAreaPrefix(InterAreaPrefixLsaV3),
    InterAreaRouter(InterAreaRouterLsaV3),
    /// The AS-external shape; the header's LS type decides 0x4005
    /// vs 0x2007 (NSSA) — the body is identical (A.4.8).
    AsExternal(AsExternalLsaV3),
    Link(LinkLsaV3),
    IntraAreaPrefix(IntraAreaPrefixLsaV3),
    /// An unrecognized (or deprecated 0x2006) function code: the
    /// raw body travels along so flooding is byte-faithful.
    Unknown {
        ls_type: u16,
        raw: Vec<u8>,
    },
}

/// The 20-byte OSPFv3 LSA header (A.4.2) — same size as v2, but the
/// two octets v2 spent on Options + the type octet become the single
/// 16-bit LS type (whose high three bits are the U/S2/S1 properties,
/// A.4.2.1). Router ID, Area ID and Link State ID stay 32-bit (§2.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LsaHeaderV3 {
    pub ls_age: u16,
    pub ls_type: LsaType,
    pub link_state_id: LinkStateId,
    pub adv_router: RouterId,
    pub seq: u32,
    pub checksum: u16,
    /// In bytes, including this 20-byte header.
    pub length: u16,
}

impl LsaHeaderV3 {
    pub const WIRE_SIZE: usize = 20;

    pub fn seq_signed(&self) -> i32 {
        self.seq as i32
    }

    pub fn effective_age(&self) -> u16 {
        self.ls_age & !crate::lsa::DO_NOT_AGE
    }

    pub fn is_max_age(&self) -> bool {
        self.effective_age() >= crate::MAX_AGE
    }

    /// Decode the 20-byte header. Field constraints mirror the v2
    /// codec where RFC 5340 inherits them: signed sequence range
    /// (§12.1.6 via §4.4.1), nonzero checksum, age <= MaxAge,
    /// length >= 20. The v3 differences: the full 16-bit LS type is
    /// read (no options octet), the reserved S2/S1 scope is
    /// rejected, and *unknown function codes are accepted* — the
    /// body decode routes them to [`LsaBodyV3::Unknown`].
    pub fn decode(r: &mut Reader<'_>) -> Result<Self, OspfError> {
        let field = "OSPFv3 LSA header";
        let age = r.u16().ok_or(OspfError::Truncated {
            field,
            need: 2,
            have: r.remaining(),
        })?;
        let ls_type = LsaType(r.u16().ok_or(OspfError::Truncated {
            field,
            need: 2,
            have: r.remaining(),
        })?);
        if ls_type.scope() == crate::lsa::Scope::Reserved {
            return Err(OspfError::ReservedScope(ls_type.0));
        }
        let link_state_id = LinkStateId(r.u32().ok_or(OspfError::Truncated {
            field,
            need: 4,
            have: r.remaining(),
        })?);
        let adv_router = RouterId(r.u32().ok_or(OspfError::Truncated {
            field,
            need: 4,
            have: r.remaining(),
        })?);
        let seq = r.u32().ok_or(OspfError::Truncated {
            field,
            need: 4,
            have: r.remaining(),
        })?;
        // §12.1.6 (RFC 2328 lineage, referenced by §4.4.1): 0x80000000
        // is reserved; the rest of the signed space is legal.
        if !(INITIAL_SEQUENCE_NUMBER as i32..=MAX_SEQUENCE_NUMBER as i32).contains(&(seq as i32)) {
            return Err(OspfError::BadSequence(seq));
        }
        let checksum = r.u16().ok_or(OspfError::Truncated {
            field,
            need: 2,
            have: r.remaining(),
        })?;
        if checksum == 0 {
            return Err(OspfError::ZeroChecksum);
        }
        let length = r.u16().ok_or(OspfError::Truncated {
            field,
            need: 2,
            have: r.remaining(),
        })?;
        if age & !crate::lsa::DO_NOT_AGE > crate::MAX_AGE {
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
            ls_type,
            link_state_id,
            adv_router,
            seq,
            checksum,
            length,
        })
    }

    /// Encode the header (20 bytes). The checksum field is written
    /// as stored — [`LsaV3::encode`] computes it over the full LSA.
    pub fn encode(&self, buf: &mut Vec<u8>) {
        put_u16(buf, self.ls_age);
        put_u16(buf, self.ls_type.0);
        put_u32(buf, self.link_state_id.0);
        put_u32(buf, self.adv_router.0);
        put_u32(buf, self.seq);
        put_u16(buf, self.checksum);
        put_u16(buf, self.length);
    }
}

impl LsaV3 {
    /// Encode header + body into wire bytes, computing the length
    /// and the Fletcher checksum. The checksum arithmetic and
    /// placement are *identical to v2* (§4.4.1 defers to RFC 2328
    /// §12.1.7): over everything except the 2-byte age, stored at
    /// LSA bytes 16-17 — relative offset 14 from byte 2.
    pub fn encode(&self) -> Vec<u8> {
        let mut buf = Vec::new();
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
            LsaBodyV3::Router(r) => {
                // | 0(3) | Nt | x | V | E | B | — cell-counting per the
                // A.4.3 diagram: Nt = 0x10, x = 0x08 (deprecated,
                // written 0), V = 0x04, E = 0x02, B = 0x01.
                let mut flags = 0u8;
                flags |= u8::from(r.nt_bit) << 4;
                flags |= u8::from(r.v_bit) << 2;
                flags |= u8::from(r.e_bit) << 1;
                flags |= u8::from(r.b_bit);
                put_u8(buf, flags);
                r.options.put(buf);
                for link in &r.links {
                    put_u8(buf, link.link_type.to_u8());
                    put_u8(buf, 0);
                    put_u16(buf, link.metric);
                    put_u32(buf, link.interface_id);
                    put_u32(buf, link.neighbor_interface_id);
                    put_u32(buf, link.neighbor_router_id.0);
                }
            }
            LsaBodyV3::Network(n) => {
                put_u8(buf, 0);
                n.options.put(buf);
                for rtr in &n.attached {
                    put_u32(buf, rtr.0);
                }
            }
            LsaBodyV3::InterAreaPrefix(p) => {
                put_u8(buf, 0);
                put_u24(buf, p.metric);
                p.prefix.encode(buf);
            }
            LsaBodyV3::InterAreaRouter(iar) => {
                put_u8(buf, 0);
                iar.options.put(buf);
                put_u8(buf, 0);
                put_u24(buf, iar.metric);
                put_u32(buf, iar.destination_router_id.0);
            }
            LsaBodyV3::AsExternal(e) => {
                // | *5 | E | F | T | then the 24-bit metric (A.4.7):
                // E = 0x04, F = 0x02, T = 0x01.
                let mut flags = 0u8;
                flags |= u8::from(e.e_bit) << 2;
                flags |= u8::from(e.f_bit) << 1;
                flags |= u8::from(e.t_bit);
                put_u8(buf, flags);
                put_u24(buf, e.metric);
                e.prefix.encode(buf);
                put_u16(buf, e.referenced_ls_type);
                if let Some(fa) = e.forwarding_address {
                    buf.extend_from_slice(&fa.octets());
                }
                if let Some(tag) = e.external_route_tag {
                    put_u32(buf, tag);
                }
                if let Some(rid) = e.referenced_link_state_id {
                    put_u32(buf, rid);
                }
            }
            LsaBodyV3::Link(l) => {
                put_u8(buf, l.router_priority);
                l.options.put(buf);
                buf.extend_from_slice(&l.link_local_address.octets());
                put_u32(buf, l.prefixes.len() as u32);
                for p in &l.prefixes {
                    p.encode(buf);
                }
            }
            LsaBodyV3::IntraAreaPrefix(iapr) => {
                put_u16(buf, iapr.prefixes.len() as u16);
                put_u16(buf, iapr.referenced_ls_type.0);
                put_u32(buf, iapr.referenced_link_state_id.0);
                put_u32(buf, iapr.referenced_adv_router.0);
                for pm in &iapr.prefixes {
                    put_u8(buf, pm.prefix.len);
                    put_u8(buf, pm.prefix.options.0);
                    put_u16(buf, pm.metric);
                    buf.extend_from_slice(&pm.prefix.addr);
                }
            }
            LsaBodyV3::Unknown { raw, .. } => buf.extend_from_slice(raw),
        }
    }

    /// Decode a whole OSPFv3 LSA: header, framing exactness (the
    /// declared length equals the buffer), Fletcher verification,
    /// then the body — which for an unrecognized function code is
    /// the opaque [`LsaBodyV3::Unknown`], not an error.
    pub fn decode(buf: &[u8]) -> Result<Self, OspfError> {
        let mut r = Reader::new(buf);
        let header = LsaHeaderV3::decode(&mut r)?;
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
                field: "OSPFv3 LSA body",
                count: r.remaining(),
            });
        }
        Ok(Self { header, body })
    }

    /// Decode a bare 20-byte header (the DBD/LSAck representation,
    /// A.3.3/A.3.6).
    pub fn decode_header(buf: &[u8]) -> Result<LsaHeaderV3, OspfError> {
        let mut r = Reader::new(buf);
        let h = LsaHeaderV3::decode(&mut r)?;
        if !r.is_empty() {
            return Err(OspfError::Trailing {
                field: "OSPFv3 LSA header",
                count: r.remaining(),
            });
        }
        Ok(h)
    }

    fn decode_body(r: &mut Reader<'_>, header: &LsaHeaderV3) -> Result<LsaBodyV3, OspfError> {
        match header.ls_type {
            LsaType::V3_ROUTER => Self::decode_router(r),
            LsaType::V3_NETWORK => Self::decode_network(r),
            LsaType::V3_INTER_AREA_PREFIX => Self::decode_inter_area_prefix(r),
            LsaType::V3_INTER_AREA_ROUTER => Self::decode_inter_area_router(r),
            // A.4.8: "other than the LS type, their format is exactly
            // the same as AS-external LSAs" (the v3 analogue of the
            // v2 codec's type-7 share).
            LsaType::V3_AS_EXTERNAL | LsaType::V3_NSSA => Self::decode_external(r),
            LsaType::V3_LINK => Self::decode_link(r),
            LsaType::V3_INTRA_AREA_PREFIX => Self::decode_intra_area_prefix(r),
            // Unknown or deprecated (0x2006) function codes: opaque
            // bytes, header-only handling (§3.4's U-bit contract).
            other => Ok(LsaBodyV3::Unknown {
                ls_type: other.0,
                raw: r.rest().to_vec(),
            }),
        }
    }

    fn decode_router(r: &mut Reader<'_>) -> Result<LsaBodyV3, OspfError> {
        let field = "router-LSA(v3) body";
        let flags = r.u8().ok_or(OspfError::Truncated {
            field,
            need: 1,
            have: 0,
        })?;
        // Bits 5-7 above Nt are reserved and rejected; the x-bit
        // (0x08) is deprecated — "set 0, ignore on receipt" — so it
        // is neither rejected nor stored (A.4.3).
        if flags & 0xe0 != 0 {
            return Err(OspfError::ReservedBits {
                field: "router-LSA(v3) flags",
                value: flags,
            });
        }
        let nt_bit = flags & 0x10 != 0;
        let v_bit = flags & 0x04 != 0;
        let e_bit = flags & 0x02 != 0;
        let b_bit = flags & 0x01 != 0;
        let options = Options24::read(r, field)?;
        let mut links = Vec::new();
        // No count field in v3: links run to Length exhaustion
        // (A.4.3 — the header's Length is the only bound).
        while !r.is_empty() {
            if r.remaining() < 16 {
                return Err(OspfError::Truncated {
                    field: "router link(v3)",
                    need: 16,
                    have: r.remaining(),
                });
            }
            let link_type = LinkTypeV3::from_u8(r.u8().expect("bounds checked"))?;
            let reserved = r.u8().expect("bounds checked");
            if reserved != 0 {
                return Err(OspfError::ReservedBits {
                    field: "router link(v3)",
                    value: reserved,
                });
            }
            let metric = r.u16().expect("bounds checked");
            let interface_id = r.u32().expect("bounds checked");
            let neighbor_interface_id = r.u32().expect("bounds checked");
            let neighbor_router_id = RouterId(r.u32().expect("bounds checked"));
            links.push(RouterLinkV3 {
                link_type,
                metric,
                interface_id,
                neighbor_interface_id,
                neighbor_router_id,
            });
        }
        Ok(LsaBodyV3::Router(RouterLsaV3 {
            nt_bit,
            v_bit,
            e_bit,
            b_bit,
            options,
            links,
        }))
    }

    fn decode_network(r: &mut Reader<'_>) -> Result<LsaBodyV3, OspfError> {
        let field = "network-LSA(v3) body";
        let reserved = r.u8().ok_or(OspfError::Truncated {
            field,
            need: 1,
            have: 0,
        })?;
        if reserved != 0 {
            return Err(OspfError::ReservedBits {
                field: "network-LSA(v3)",
                value: reserved,
            });
        }
        let options = Options24::read(r, field)?;
        let mut attached = Vec::new();
        while !r.is_empty() {
            let id = r.u32().ok_or(OspfError::Truncated {
                field,
                need: 4,
                have: r.remaining(),
            })?;
            attached.push(RouterId(id));
        }
        Ok(LsaBodyV3::Network(NetworkLsaV3 { options, attached }))
    }

    fn decode_inter_area_prefix(r: &mut Reader<'_>) -> Result<LsaBodyV3, OspfError> {
        let field = "inter-area-prefix-LSA body";
        let reserved = r.u8().ok_or(OspfError::Truncated {
            field,
            need: 1,
            have: 0,
        })?;
        if reserved != 0 {
            return Err(OspfError::ReservedBits {
                field: "inter-area-prefix metric",
                value: reserved,
            });
        }
        let metric = r.u24().ok_or(OspfError::Truncated {
            field,
            need: 3,
            have: 0,
        })?;
        let prefix = Prefix::decode(r, field)?;
        Ok(LsaBodyV3::InterAreaPrefix(InterAreaPrefixLsaV3 {
            metric,
            prefix,
        }))
    }

    fn decode_inter_area_router(r: &mut Reader<'_>) -> Result<LsaBodyV3, OspfError> {
        let field = "inter-area-router-LSA body";
        let reserved = r.u8().ok_or(OspfError::Truncated {
            field,
            need: 1,
            have: 0,
        })?;
        if reserved != 0 {
            return Err(OspfError::ReservedBits {
                field: "inter-area-router options",
                value: reserved,
            });
        }
        let options = Options24::read(r, field)?;
        let reserved = r.u8().ok_or(OspfError::Truncated {
            field,
            need: 1,
            have: 0,
        })?;
        if reserved != 0 {
            return Err(OspfError::ReservedBits {
                field: "inter-area-router metric",
                value: reserved,
            });
        }
        let metric = r.u24().ok_or(OspfError::Truncated {
            field,
            need: 3,
            have: 0,
        })?;
        let destination_router_id = RouterId(r.u32().ok_or(OspfError::Truncated {
            field,
            need: 4,
            have: 0,
        })?);
        Ok(LsaBodyV3::InterAreaRouter(InterAreaRouterLsaV3 {
            options,
            metric,
            destination_router_id,
        }))
    }

    fn decode_external(r: &mut Reader<'_>) -> Result<LsaBodyV3, OspfError> {
        let field = "AS-external-LSA(v3) body";
        let flags = r.u8().ok_or(OspfError::Truncated {
            field,
            need: 1,
            have: 0,
        })?;
        if flags & 0xf8 != 0 {
            return Err(OspfError::ReservedBits {
                field: "external(v3) E|F|T",
                value: flags,
            });
        }
        let e_bit = flags & 0x04 != 0;
        let f_bit = flags & 0x02 != 0;
        let t_bit = flags & 0x01 != 0;
        let metric = r.u24().ok_or(OspfError::Truncated {
            field,
            need: 3,
            have: 0,
        })?;
        let prefix = Prefix::decode(r, field)?;
        let referenced_ls_type = r.u16().ok_or(OspfError::Truncated {
            field,
            need: 2,
            have: 0,
        })?;
        // Fixed option order: forwarding address, then tag, then the
        // referenced LS ID (A.4.7) — each present iff its gate is set.
        let forwarding_address = if f_bit {
            let octets: [u8; 16] = r
                .take(16)
                .ok_or(OspfError::Truncated {
                    field,
                    need: 16,
                    have: r.remaining(),
                })?
                .try_into()
                .expect("16 bytes");
            let addr = Ipv6Addr::from(octets);
            // A.4.7 MUST NOT: never the unspecified address, never a
            // link-local (fe80::/10) one — a global address is
            // required when a forwarding address is advertised.
            if addr.is_unspecified() || (addr.segments()[0] & 0xffc0) == 0xfe80 {
                return Err(OspfError::BadForwardingAddress(addr));
            }
            Some(addr)
        } else {
            None
        };
        let external_route_tag = if t_bit {
            Some(r.u32().ok_or(OspfError::Truncated {
                field,
                need: 4,
                have: 0,
            })?)
        } else {
            None
        };
        let referenced_link_state_id = if referenced_ls_type != 0 {
            Some(r.u32().ok_or(OspfError::Truncated {
                field,
                need: 4,
                have: 0,
            })?)
        } else {
            None
        };
        Ok(LsaBodyV3::AsExternal(AsExternalLsaV3 {
            e_bit,
            f_bit,
            t_bit,
            metric,
            prefix,
            referenced_ls_type,
            forwarding_address,
            external_route_tag,
            referenced_link_state_id,
        }))
    }

    fn decode_link(r: &mut Reader<'_>) -> Result<LsaBodyV3, OspfError> {
        let field = "link-LSA body";
        let router_priority = r.u8().ok_or(OspfError::Truncated {
            field,
            need: 1,
            have: 0,
        })?;
        let options = Options24::read(r, field)?;
        let octets: [u8; 16] = r
            .take(16)
            .ok_or(OspfError::Truncated {
                field,
                need: 16,
                have: r.remaining(),
            })?
            .try_into()
            .expect("16 bytes");
        let link_local_address = Ipv6Addr::from(octets);
        let n_prefixes = r.u32().ok_or(OspfError::Truncated {
            field,
            need: 4,
            have: 0,
        })? as usize;
        let mut prefixes = Vec::with_capacity(n_prefixes.min(1024));
        for _ in 0..n_prefixes {
            prefixes.push(Prefix::decode(r, field)?);
        }
        Ok(LsaBodyV3::Link(LinkLsaV3 {
            router_priority,
            options,
            link_local_address,
            prefixes,
        }))
    }

    fn decode_intra_area_prefix(r: &mut Reader<'_>) -> Result<LsaBodyV3, OspfError> {
        let field = "intra-area-prefix-LSA body";
        let n_prefixes = r.u16().ok_or(OspfError::Truncated {
            field,
            need: 2,
            have: 0,
        })? as usize;
        let referenced_ls_type = LsaType(r.u16().ok_or(OspfError::Truncated {
            field,
            need: 2,
            have: 0,
        })?);
        let referenced_link_state_id = LinkStateId(r.u32().ok_or(OspfError::Truncated {
            field,
            need: 4,
            have: 0,
        })?);
        let referenced_adv_router = RouterId(r.u32().ok_or(OspfError::Truncated {
            field,
            need: 4,
            have: 0,
        })?);
        let mut prefixes = Vec::with_capacity(n_prefixes.min(1024));
        for _ in 0..n_prefixes {
            let len = r.u8().ok_or(OspfError::Truncated {
                field,
                need: 1,
                have: 0,
            })?;
            let options = PrefixOptions(r.u8().ok_or(OspfError::Truncated {
                field,
                need: 1,
                have: 0,
            })?);
            let metric = r.u16().ok_or(OspfError::Truncated {
                field,
                need: 2,
                have: 0,
            })?;
            if len > 128 {
                return Err(OspfError::BadLength {
                    field: "prefix length",
                    declared: len as usize,
                    actual: 128,
                });
            }
            let want = Prefix::words(len);
            let addr = r
                .take(want)
                .ok_or(OspfError::Truncated {
                    field,
                    need: want,
                    have: r.remaining(),
                })?
                .to_vec();
            prefixes.push(PrefixMetric {
                metric,
                prefix: Prefix { len, options, addr },
            });
        }
        Ok(LsaBodyV3::IntraAreaPrefix(IntraAreaPrefixLsaV3 {
            prefixes,
            referenced_ls_type,
            referenced_link_state_id,
            referenced_adv_router,
        }))
    }

    /// The (LS type, LS ID, adv router) lookup key (§12.2 lineage —
    /// the LS ID de-multiplexes multiple router- and intra-area-
    /// prefix-LSAs per router, A.4.3/A.4.10).
    pub fn key(&self) -> crate::lsa::LsaKey {
        crate::lsa::LsaKey {
            ls_type: self.header.ls_type,
            link_state_id: self.header.link_state_id,
            adv_router: self.header.adv_router,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::checksum::fletcher_verify;
    use crate::lsa::{LsaKey, DO_NOT_AGE};

    // Test-oracle disclosure: unlike the v2 codec (truthed against a
    // 31-packet real capture), these goldens are hand-derived from
    // the RFC 5340 A.4 diagrams and pinned byte-by-byte in comments;
    // the wire-truth leg (a live FRR ospf6d interop) is the recorded
    // follow-up (see docs/protocols/ospf.md §Deferred).

    fn header(ls_type: LsaType, ls_id: u32, adv: u32) -> LsaHeaderV3 {
        LsaHeaderV3 {
            ls_age: 1,
            ls_type,
            link_state_id: LinkStateId(ls_id),
            adv_router: RouterId(adv),
            seq: INITIAL_SEQUENCE_NUMBER,
            checksum: 0,
            length: 0,
        }
    }

    fn rid(s: &str) -> RouterId {
        RouterId::from_ipv4(s.parse().unwrap())
    }

    fn prefix(len: u8, options: u8, addr: &[u8]) -> Prefix {
        Prefix {
            len,
            options: PrefixOptions(options),
            addr: addr.to_vec(),
        }
    }

    /// Fill in the computed checksum/length so round trips compare.
    fn computed(mut lsa: LsaV3) -> LsaV3 {
        let bytes = lsa.encode();
        lsa.header.checksum = u16::from_be_bytes([bytes[16], bytes[17]]);
        lsa.header.length = bytes.len() as u16;
        lsa
    }

    #[test]
    fn prefix_word_arithmetic() {
        // A.4.1: the address prefix consumes ((len+31)/32) 32-bit
        // words, zero-padded — the classic ceil(len/32): a /17
        // prefix fits one word (4 bytes), /33 needs two (8 bytes).
        assert_eq!(Prefix::words(0), 0, "default route carries no bytes");
        assert_eq!(Prefix::words(1), 4);
        assert_eq!(Prefix::words(17), 4);
        assert_eq!(Prefix::words(32), 4);
        assert_eq!(Prefix::words(33), 8);
        assert_eq!(Prefix::words(64), 8);
        assert_eq!(Prefix::words(128), 16);
        // On the wire: 4 header bytes + the words.
        let mut buf = Vec::new();
        prefix(17, 0x08, &[0x20, 0x01, 0x0d, 0xb8]).encode(&mut buf);
        assert_eq!(buf, vec![17, 0x08, 0, 0, 0x20, 0x01, 0x0d, 0xb8]);
        let mut r = Reader::new(&buf);
        let p = Prefix::decode(&mut r, "test").unwrap();
        assert_eq!(p, prefix(17, 0x08, &[0x20, 0x01, 0x0d, 0xb8]));
        assert!(r.is_empty());
        // The default route (A.4.5/A.4.7: PrefixLength 0).
        let mut buf = Vec::new();
        Prefix::default_route().encode(&mut buf);
        assert_eq!(buf, vec![0, 0, 0, 0]);
    }

    #[test]
    fn prefix_length_and_reserved_rejected() {
        // A.4.1: prefixes are bit strings of length 0..=128 (the
        // buffer is hand-assembled — an inconsistent struct cannot
        // pass encode's own arity check).
        let buf = vec![129, 0, 0, 0];
        let mut r = Reader::new(&buf);
        assert!(matches!(
            Prefix::decode(&mut r, "test").unwrap_err(),
            OspfError::BadLength {
                field: "prefix length",
                declared: 129,
                actual: 128
            }
        ));
        // The 16-bit zero field is structural reserved (house rule:
        // reject; real senders zero it).
        let buf = vec![64, 0, 0x12, 0x34, 1, 2, 3, 4, 5, 6, 7, 8];
        let mut r = Reader::new(&buf);
        assert!(matches!(
            Prefix::decode(&mut r, "test").unwrap_err(),
            OspfError::ReservedBits16 {
                field: "prefix reserved",
                value: 0x1234
            }
        ));
        // Declared words longer than the buffer (A19).
        let buf = vec![64, 0, 0, 0, 1, 2, 3];
        let mut r = Reader::new(&buf);
        assert!(matches!(
            Prefix::decode(&mut r, "test").unwrap_err(),
            OspfError::Truncated { need: 8, .. }
        ));
        // PrefixOptions unknown high bits are carried, not rejected
        // (A.4.1.1 leaves bits 5-7 unassigned; capability field).
        let buf = vec![64, 0xe3, 0, 0, 1, 2, 3, 4, 5, 6, 7, 8];
        let mut r = Reader::new(&buf);
        let p = Prefix::decode(&mut r, "test").unwrap();
        assert_eq!(p.options.0, 0xe3);
        assert!(
            p.options.nu_bit() && p.options.la_bit(),
            "the assigned low bits read"
        );
        assert!(!p.options.p_bit() && !p.options.dn_bit());
    }

    #[test]
    fn router_lsa_v3_layout() {
        // Hand-derived from the A.4.3 diagram: Nt|V router, two
        // links (one p2p, one transit pointing at the DR).
        let lsa = LsaV3 {
            header: header(LsaType::V3_ROUTER, 0, 0x0a00_0001),
            body: LsaBodyV3::Router(RouterLsaV3 {
                nt_bit: true,
                v_bit: true,
                e_bit: false,
                b_bit: true,
                options: Options24(Options24::V6 | Options24::E | Options24::R),
                links: vec![
                    RouterLinkV3 {
                        link_type: LinkTypeV3::PointToPoint,
                        metric: 10,
                        interface_id: 7,
                        neighbor_interface_id: 9,
                        neighbor_router_id: rid("10.0.0.2"),
                    },
                    RouterLinkV3 {
                        link_type: LinkTypeV3::Transit,
                        metric: 20,
                        interface_id: 7,
                        neighbor_interface_id: 3, // the DR's ifid
                        neighbor_router_id: rid("10.0.0.9"),
                    },
                ],
            }),
        };
        let bytes = lsa.encode();
        // 20 header + 4 flags/options + 2 x 16-byte links.
        assert_eq!(bytes.len(), 56);
        assert_eq!(u16::from_be_bytes([bytes[2], bytes[3]]), 0x2001, "LS type");
        // Flags octet: Nt(0x10) | V(0x04) | B(0x01) = 0x15.
        assert_eq!(bytes[20], 0x15);
        // Options word: 24-bit big-endian 0x000013.
        assert_eq!(&bytes[21..24], &[0x00, 0x00, 0x13]);
        // Link 1: type 1, reserved 0, metric 10, ifid 7, nbr ifid 9.
        assert_eq!(&bytes[24..28], &[1, 0, 0, 10]);
        assert_eq!(&bytes[28..32], &7u32.to_be_bytes());
        assert_eq!(&bytes[32..36], &9u32.to_be_bytes());
        assert_eq!(&bytes[36..40], &0x0a00_0002u32.to_be_bytes());
        // Link 2: type 2 at offset 40.
        assert_eq!(bytes[40], 2);
        assert_eq!(&bytes[48..52], &3u32.to_be_bytes(), "DR interface ID");
        assert_eq!(
            &bytes[52..56],
            &0x0a00_0009u32.to_be_bytes(),
            "DR router ID"
        );
        // Length and checksum filled, verifies, round trips.
        assert_eq!(u16::from_be_bytes([bytes[18], bytes[19]]), 56);
        assert!(u16::from_be_bytes([bytes[16], bytes[17]]) != 0);
        assert!(fletcher_verify(&bytes[2..]));
        assert_eq!(LsaV3::decode(&bytes).unwrap(), computed(lsa));
    }

    #[test]
    fn router_lsa_v3_strictness() {
        let sample = LsaV3 {
            header: header(LsaType::V3_ROUTER, 0, 1),
            body: LsaBodyV3::Router(RouterLsaV3 {
                nt_bit: false,
                v_bit: false,
                e_bit: true,
                b_bit: false,
                options: Options24(Options24::V6 | Options24::E),
                links: vec![RouterLinkV3 {
                    link_type: LinkTypeV3::PointToPoint,
                    metric: 1,
                    interface_id: 1,
                    neighbor_interface_id: 2,
                    neighbor_router_id: rid("10.0.0.2"),
                }],
            }),
        };
        let base = sample.encode();
        let repair = |bytes: &mut Vec<u8>| {
            let len = bytes.len() as u16;
            bytes[18..20].copy_from_slice(&len.to_be_bytes());
            let csum = lsa_fletcher_checksum(&mut bytes[2..], 14);
            bytes[16..18].copy_from_slice(&csum.to_be_bytes());
        };
        // Reserved bits above Nt rejected (bits 5-7).
        let mut b = base.clone();
        b[20] |= 0x20;
        repair(&mut b);
        assert!(matches!(
            LsaV3::decode(&b).unwrap_err(),
            OspfError::ReservedBits {
                field: "router-LSA(v3) flags",
                ..
            }
        ));
        // The deprecated x-bit (0x08) is IGNORED (A.4.3: set 0,
        // ignore on receipt) — decode succeeds.
        let mut b = base.clone();
        b[20] |= 0x08;
        repair(&mut b);
        assert!(
            LsaV3::decode(&b).is_ok(),
            "deprecated x-bit must be ignored"
        );
        // Link type 3 is reserved in v3 (the v2 stub link is gone).
        let mut b = base.clone();
        b[24] = 3;
        repair(&mut b);
        assert_eq!(LsaV3::decode(&b).unwrap_err(), OspfError::BadLinkType(3));
        // The link record's reserved octet is structural.
        let mut b = base.clone();
        b[25] = 0xff;
        repair(&mut b);
        assert!(matches!(
            LsaV3::decode(&b).unwrap_err(),
            OspfError::ReservedBits {
                field: "router link(v3)",
                ..
            }
        ));
        // A partial link record (fewer than 16 bytes left) truncates.
        let mut b = base.clone();
        b.truncate(40 - 4);
        repair(&mut b);
        assert!(matches!(
            LsaV3::decode(&b).unwrap_err(),
            OspfError::Truncated {
                field: "router link(v3)",
                need: 16,
                ..
            }
        ));
        // Unknown Options bits are ignored (A.2 — the RFC-mandated
        // exception to the reserved-bit house rule) and preserved
        // raw for faithful re-flood.
        let mut b = base.clone();
        b[21] |= 0x80; // bit 23, a *-bit reserved for v2 migration
        repair(&mut b);
        let back = LsaV3::decode(&b).unwrap();
        let LsaBodyV3::Router(r) = back.body else {
            panic!()
        };
        assert_eq!(r.options.0 & 0x80_0000, 0x80_0000);
    }

    #[test]
    fn network_lsa_v3_layout() {
        // A.4.4: one 0|Options word plus the attached Router IDs
        // (count deduced from the header Length); no mask anywhere.
        let lsa = LsaV3 {
            header: header(LsaType::V3_NETWORK, 3, 0x0a00_0009), // LS ID = DR's ifid
            body: LsaBodyV3::Network(NetworkLsaV3 {
                options: Options24(Options24::V6 | Options24::E | Options24::R),
                attached: vec![rid("10.0.0.1"), rid("10.0.0.9")],
            }),
        };
        let bytes = lsa.encode();
        assert_eq!(bytes.len(), 20 + 4 + 8);
        assert_eq!(bytes[20], 0, "the leading zero octet");
        assert_eq!(&bytes[21..24], &[0x00, 0x00, 0x13]);
        assert_eq!(&bytes[24..28], &0x0a00_0001u32.to_be_bytes());
        assert_eq!(&bytes[28..32], &0x0a00_0009u32.to_be_bytes());
        assert_eq!(LsaV3::decode(&bytes).unwrap(), computed(lsa));
        // Truncation mid-attached-router is rejected (the count is
        // deduced from Length, so the length repair is enough).
        let mut cut = bytes[..30].to_vec();
        let len = cut.len() as u16;
        cut[18..20].copy_from_slice(&len.to_be_bytes());
        let csum = lsa_fletcher_checksum(&mut cut[2..], 14);
        cut[16..18].copy_from_slice(&csum.to_be_bytes());
        assert!(matches!(
            LsaV3::decode(&cut).unwrap_err(),
            OspfError::Truncated { .. }
        ));
        // The leading octet is structural reserved.
        let mut b = bytes.clone();
        b[20] = 1;
        b[18..20].copy_from_slice(&32u16.to_be_bytes());
        let csum = lsa_fletcher_checksum(&mut b[2..], 14);
        b[16..18].copy_from_slice(&csum.to_be_bytes());
        assert!(matches!(
            LsaV3::decode(&b).unwrap_err(),
            OspfError::ReservedBits {
                field: "network-LSA(v3)",
                ..
            }
        ));
    }

    #[test]
    fn inter_area_prefix_lsa_v3_layout() {
        // A.4.5: 0|metric(3) then the prefix triple; the stub-area
        // default route is PrefixLength 0.
        let lsa = LsaV3 {
            header: header(LsaType::V3_INTER_AREA_PREFIX, 42, 0x0a00_0005),
            body: LsaBodyV3::InterAreaPrefix(InterAreaPrefixLsaV3 {
                metric: 0x00ff_ffff, // LSInfinity-scale metric fits 24 bits
                prefix: prefix(64, 0x01, &[0x20, 0x01, 0x0d, 0xb8, 0, 1, 0, 2]),
            }),
        };
        let bytes = lsa.encode();
        assert_eq!(bytes.len(), 20 + 4 + 12);
        assert_eq!(&bytes[20..24], &[0x00, 0xff, 0xff, 0xff], "0|metric");
        assert_eq!(bytes[24], 64);
        assert_eq!(&bytes[28..36], &[0x20, 0x01, 0x0d, 0xb8, 0, 1, 0, 2]);
        assert_eq!(LsaV3::decode(&bytes).unwrap(), computed(lsa));
        // The default summary form (A.4.5).
        let def = LsaV3 {
            header: header(LsaType::V3_INTER_AREA_PREFIX, 0, 0x0a00_0005),
            body: LsaBodyV3::InterAreaPrefix(InterAreaPrefixLsaV3 {
                metric: 1,
                prefix: Prefix::default_route(),
            }),
        };
        assert_eq!(def.encode().len(), 20 + 4 + 4);
        assert_eq!(LsaV3::decode(&def.encode()).unwrap(), computed(def));
    }

    #[test]
    fn inter_area_router_lsa_v3_layout() {
        // A.4.6: options word, metric word, and the destination ASBR
        // Router ID IN THE BODY (the v2 LS-ID trick is dropped).
        let lsa = LsaV3 {
            header: header(LsaType::V3_INTER_AREA_ROUTER, 7, 0x0a00_0005),
            body: LsaBodyV3::InterAreaRouter(InterAreaRouterLsaV3 {
                options: Options24(Options24::V6 | Options24::E),
                metric: 30,
                destination_router_id: rid("10.0.0.7"),
            }),
        };
        let bytes = lsa.encode();
        assert_eq!(bytes.len(), 20 + 4 + 4 + 4);
        assert_eq!(bytes[20], 0);
        assert_eq!(&bytes[21..24], &[0x00, 0x00, 0x03]);
        assert_eq!(&bytes[24..28], &[0, 0, 0, 30]);
        assert_eq!(&bytes[28..32], &0x0a00_0007u32.to_be_bytes());
        assert_eq!(LsaV3::decode(&bytes).unwrap(), computed(lsa));
    }

    #[test]
    fn external_lsa_v3_eft_optionality() {
        // A.4.7: E/F/T in the top three bits (0x04/0x02/0x01); FA,
        // tag and Referenced LS ID are optional in fixed order, each
        // present iff its gate is set; the Referenced LS ID rides on
        // the Referenced LS Type being non-zero.
        let global_fa: Ipv6Addr = "2001:db8:1::1".parse().unwrap();
        for (f, t, ref_ty) in [
            (false, false, 0u16),
            (true, false, 0),
            (false, true, 0),
            (true, true, 0),
            (false, false, 0x2009),
            (true, true, 0x2009),
        ] {
            let body = AsExternalLsaV3 {
                e_bit: true,
                f_bit: f,
                t_bit: t,
                metric: 20,
                prefix: prefix(48, 0, &[0x20, 0x01, 0x0d, 0xb8, 0xaa, 0xbb, 0, 0]),
                referenced_ls_type: ref_ty,
                forwarding_address: f.then_some(global_fa),
                external_route_tag: t.then_some(0xdead_beef),
                referenced_link_state_id: (ref_ty != 0).then_some(99),
            };
            let lsa = LsaV3 {
                header: header(LsaType::V3_AS_EXTERNAL, 5, 3),
                body: LsaBodyV3::AsExternal(body),
            };
            let bytes = lsa.encode();
            // 20 header + 4 flags/metric + 12 prefix + 2 ref type
            // + 16 FA? + 4 tag? + 4 ref LS ID?
            let expect = 20
                + 4
                + 12
                + 2
                + if f { 16 } else { 0 }
                + if t { 4 } else { 0 }
                + if ref_ty != 0 { 4 } else { 0 };
            assert_eq!(bytes.len(), expect, "f={f} t={t} ref={ref_ty}");
            // Flags octet: E only (0x04) + F/T as set.
            assert_eq!(bytes[20], 0x04 | u8::from(f) << 1 | u8::from(t));
            // The option order on the wire: FA, tag, ref LS ID.
            let mut off = 38; // after the 2-byte Referenced LS Type
            if f {
                assert_eq!(&bytes[off..off + 16], &global_fa.octets());
                off += 16;
            }
            if t {
                assert_eq!(&bytes[off..off + 4], &0xdead_beefu32.to_be_bytes());
                off += 4;
            }
            if ref_ty != 0 {
                assert_eq!(&bytes[off..off + 4], &99u32.to_be_bytes());
                off += 4;
            }
            assert_eq!(off, bytes.len());
            assert_eq!(LsaV3::decode(&bytes).unwrap(), computed(lsa));
        }
        // NSSA-LSA (0x2007) shares the decode (A.4.8).
        let nssa = LsaV3 {
            header: header(LsaType::V3_NSSA, 5, 3),
            body: LsaBodyV3::AsExternal(AsExternalLsaV3 {
                e_bit: false,
                f_bit: true,
                t_bit: false,
                metric: 1,
                prefix: prefix(64, 0x08, &[0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 5]),
                referenced_ls_type: 0,
                forwarding_address: Some(global_fa),
                external_route_tag: None,
                referenced_link_state_id: None,
            }),
        };
        let bytes = nssa.encode();
        assert_eq!(u16::from_be_bytes([bytes[2], bytes[3]]), 0x2007);
        assert_eq!(bytes[20], 0x02, "F only");
        assert_eq!(LsaV3::decode(&bytes).unwrap(), computed(nssa));
    }

    #[test]
    fn external_lsa_v3_forwarding_address_must_be_global() {
        // A.4.7 MUST NOT: the forwarding address is never the
        // unspecified address and never fe80::/10.
        for bad in ["::", "fe80::1", "febf::ffff:1"] {
            let lsa = LsaV3 {
                header: header(LsaType::V3_AS_EXTERNAL, 0, 3),
                body: LsaBodyV3::AsExternal(AsExternalLsaV3 {
                    e_bit: false,
                    f_bit: true,
                    t_bit: false,
                    metric: 1,
                    prefix: Prefix::default_route(),
                    referenced_ls_type: 0,
                    forwarding_address: Some(bad.parse().unwrap()),
                    external_route_tag: None,
                    referenced_link_state_id: None,
                }),
            };
            let err = LsaV3::decode(&lsa.encode()).unwrap_err();
            assert!(
                matches!(err, OspfError::BadForwardingAddress(_)),
                "{bad}: {err}"
            );
        }
        // fec0::/10 (site-local) is NOT link-local — accepted here as
        // a decode matter (its routing deprecation is not ours).
        let ok = LsaV3 {
            header: header(LsaType::V3_AS_EXTERNAL, 0, 3),
            body: LsaBodyV3::AsExternal(AsExternalLsaV3 {
                e_bit: false,
                f_bit: true,
                t_bit: false,
                metric: 1,
                prefix: Prefix::default_route(),
                referenced_ls_type: 0,
                forwarding_address: Some("fec0::1".parse().unwrap()),
                external_route_tag: None,
                referenced_link_state_id: None,
            }),
        };
        assert!(LsaV3::decode(&ok.encode()).is_ok());
        // Reserved bits above E/F/T rejected.
        let mut b = LsaV3 {
            header: header(LsaType::V3_AS_EXTERNAL, 0, 3),
            body: LsaBodyV3::AsExternal(AsExternalLsaV3 {
                e_bit: false,
                f_bit: false,
                t_bit: false,
                metric: 1,
                prefix: Prefix::default_route(),
                referenced_ls_type: 0,
                forwarding_address: None,
                external_route_tag: None,
                referenced_link_state_id: None,
            }),
        }
        .encode();
        b[20] |= 0x08;
        let n = b.len() as u16;
        b[18..20].copy_from_slice(&n.to_be_bytes());
        let csum = lsa_fletcher_checksum(&mut b[2..], 14);
        b[16..18].copy_from_slice(&csum.to_be_bytes());
        assert!(matches!(
            LsaV3::decode(&b).unwrap_err(),
            OspfError::ReservedBits {
                field: "external(v3) E|F|T",
                ..
            }
        ));
    }

    #[test]
    fn link_lsa_v3_layout() {
        // A.4.9: priority, Options, the link-local address, a real
        // count field (# prefixes), then prefix triples.
        let lsa = LsaV3 {
            header: header(LsaType::V3_LINK, 1, 0x0a00_0003), // LS ID = our ifid
            body: LsaBodyV3::Link(LinkLsaV3 {
                router_priority: 40,
                options: Options24(Options24::V6 | Options24::E | Options24::R),
                link_local_address: "fe80::1".parse().unwrap(),
                prefixes: vec![
                    prefix(56, 0, &[0x20, 0x01, 0x0d, 0xb8, 0xc0, 0x01, 0x01, 0x00]),
                    Prefix::default_route(),
                ],
            }),
        };
        let bytes = lsa.encode();
        // 20 + 4 (prio+options) + 16 (lladdr) + 4 (count) + 12 + 4.
        assert_eq!(bytes.len(), 60);
        assert_eq!(bytes[20], 40);
        assert_eq!(&bytes[21..24], &[0x00, 0x00, 0x13]);
        assert_eq!(
            &bytes[24..40],
            &"fe80::1".parse::<Ipv6Addr>().unwrap().octets()
        );
        assert_eq!(&bytes[40..44], &2u32.to_be_bytes(), "# prefixes");
        assert_eq!(bytes[44], 56);
        assert_eq!(
            &bytes[48..56],
            &[0x20, 0x01, 0x0d, 0xb8, 0xc0, 0x01, 0x01, 0x00]
        );
        assert_eq!(bytes[56], 0, "second prefix: default route");
        assert_eq!(LsaV3::decode(&bytes).unwrap(), computed(lsa));
        // Count strictness: claim 3, provide 2 (A19).
        let mut b = bytes.clone();
        b[40..44].copy_from_slice(&3u32.to_be_bytes());
        let csum = lsa_fletcher_checksum(&mut b[2..], 14);
        b[16..18].copy_from_slice(&csum.to_be_bytes());
        assert!(matches!(
            LsaV3::decode(&b).unwrap_err(),
            OspfError::Truncated {
                field: "link-LSA body",
                ..
            }
        ));
    }

    #[test]
    fn intra_area_prefix_lsa_v3_layout() {
        // A.4.10: # prefixes, the referenced-LSA triple, then
        // per-prefix (len, options, metric, words).
        let lsa = LsaV3 {
            header: header(LsaType::V3_INTRA_AREA_PREFIX, 0, 0x0a00_0001),
            body: LsaBodyV3::IntraAreaPrefix(IntraAreaPrefixLsaV3 {
                prefixes: vec![PrefixMetric {
                    metric: 10,
                    prefix: prefix(64, 0x02, &[0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 1]),
                }],
                referenced_ls_type: LsaType::V3_ROUTER,
                referenced_link_state_id: LinkStateId(0),
                referenced_adv_router: rid("10.0.0.1"),
            }),
        };
        let bytes = lsa.encode();
        // 20 + 2 count + 2 ref type + 4 ref ls id + 4 ref adv + 12.
        assert_eq!(bytes.len(), 44);
        assert_eq!(&bytes[20..22], &1u16.to_be_bytes());
        assert_eq!(
            &bytes[22..24],
            &0x2001u16.to_be_bytes(),
            "referenced: router-LSA"
        );
        assert_eq!(&bytes[24..28], &0u32.to_be_bytes());
        assert_eq!(&bytes[28..32], &0x0a00_0001u32.to_be_bytes());
        assert_eq!(&bytes[32..36], &[64, 0x02, 0, 10], "len|opts|metric");
        assert_eq!(&bytes[36..44], &[0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 1]);
        assert_eq!(LsaV3::decode(&bytes).unwrap(), computed(lsa.clone()));
        // The network-referenced form (0x2002 + the DR's ifid).
        let net_ref = LsaV3 {
            header: header(LsaType::V3_INTRA_AREA_PREFIX, 2, 0x0a00_0009),
            body: LsaBodyV3::IntraAreaPrefix(IntraAreaPrefixLsaV3 {
                prefixes: vec![],
                referenced_ls_type: LsaType::V3_NETWORK,
                referenced_link_state_id: LinkStateId(3),
                referenced_adv_router: rid("10.0.0.9"),
            }),
        };
        assert_eq!(net_ref.encode().len(), 32);
        assert_eq!(LsaV3::decode(&net_ref.encode()).unwrap(), computed(net_ref));
        // Count overrun rejected.
        let mut b = lsa.encode();
        b[20..22].copy_from_slice(&2u16.to_be_bytes());
        let csum = lsa_fletcher_checksum(&mut b[2..], 14);
        b[16..18].copy_from_slice(&csum.to_be_bytes());
        assert!(matches!(
            LsaV3::decode(&b).unwrap_err(),
            OspfError::Truncated { .. }
        ));
    }

    #[test]
    fn unknown_ls_type_stored_and_reflooded() {
        // §3.4/A.4.2.1 U-bit contract: unrecognized function codes are
        // stored and flooded, not rejected. 0x800A = U=1, link scope;
        // 0x2006 is the deprecated MOSPF code ("may be reassigned").
        for ty in [0x800Au16, 0x2006] {
            let raw = vec![0xde, 0xad, 0xbe, 0xef];
            let lsa = LsaV3 {
                header: header(LsaType(ty), 77, 5),
                body: LsaBodyV3::Unknown {
                    ls_type: ty,
                    raw: raw.clone(),
                },
            };
            let bytes = lsa.encode();
            assert_eq!(bytes.len(), 24);
            assert_eq!(u16::from_be_bytes([bytes[2], bytes[3]]), ty);
            assert_eq!(&bytes[20..24], &raw[..]);
            assert!(fletcher_verify(&bytes[2..]));
            // Decodes to the opaque Unknown and re-encodes byte-exact
            // (flooding must be faithful).
            let back = LsaV3::decode(&bytes).unwrap();
            assert_eq!(back.body, LsaBodyV3::Unknown { ls_type: ty, raw });
            assert_eq!(back.encode(), bytes);
            assert_eq!(
                back.key(),
                LsaKey {
                    ls_type: LsaType(ty),
                    link_state_id: LinkStateId(77),
                    adv_router: RouterId(5)
                }
            );
        }
        // The reserved flooding scope (S2/S1 = 0b11) IS rejected —
        // nothing can legally carry it.
        let err = LsaHeaderV3::decode(&mut Reader::new(
            &LsaV3 {
                header: header(LsaType(0x6009), 0, 1),
                body: LsaBodyV3::Unknown {
                    ls_type: 0x6009,
                    raw: vec![],
                },
            }
            .encode(),
        ))
        .unwrap_err();
        assert_eq!(err, OspfError::ReservedScope(0x6009));
    }

    #[test]
    fn v3_header_layout_and_validations() {
        // A.4.2: 16-bit LS type at bytes 2-3, no options octet, the
        // rest field-identical to v2.
        let lsa = LsaV3 {
            header: LsaHeaderV3 {
                ls_age: 0x0001,
                ls_type: LsaType::V3_ROUTER,
                link_state_id: LinkStateId(0x1122_3344),
                adv_router: RouterId(0x5566_7788),
                seq: INITIAL_SEQUENCE_NUMBER,
                checksum: 0, // encode fills it
                length: 0,
            },
            body: LsaBodyV3::Router(RouterLsaV3 {
                nt_bit: false,
                v_bit: false,
                e_bit: false,
                b_bit: false,
                options: Options24(0),
                links: vec![],
            }),
        };
        let bytes = lsa.encode();
        assert_eq!(bytes.len(), 24, "header + empty body prefix");
        assert_eq!(&bytes[0..2], &1u16.to_be_bytes());
        assert_eq!(&bytes[2..4], &0x2001u16.to_be_bytes());
        assert_eq!(&bytes[4..8], &0x1122_3344u32.to_be_bytes());
        assert_eq!(&bytes[8..12], &0x5566_7788u32.to_be_bytes());
        // The standalone header decode (DBD/LSAck shape).
        let h = LsaV3::decode_header(&bytes[..20]).unwrap();
        assert_eq!(h.ls_type, LsaType::V3_ROUTER);
        assert_eq!(h.length as usize, bytes.len());
        assert!(LsaV3::decode_header(&bytes[..19]).is_err());
        // Sequence and age validations mirror v2 (§12.1.6, §14).
        let mut b = bytes.clone();
        b[12..16].copy_from_slice(&0x8000_0000u32.to_be_bytes());
        b[18..20].copy_from_slice(&24u16.to_be_bytes());
        let csum = lsa_fletcher_checksum(&mut b[2..], 14);
        b[16..18].copy_from_slice(&csum.to_be_bytes());
        assert_eq!(
            LsaV3::decode(&b).unwrap_err(),
            OspfError::BadSequence(0x8000_0000)
        );
        let mut b = bytes.clone();
        b[0..2].copy_from_slice(&3601u16.to_be_bytes());
        b[18..20].copy_from_slice(&24u16.to_be_bytes());
        let csum = lsa_fletcher_checksum(&mut b[2..], 14);
        b[16..18].copy_from_slice(&csum.to_be_bytes());
        assert!(matches!(
            LsaV3::decode(&b).unwrap_err(),
            OspfError::AgeTooLarge(3601)
        ));
        // DoNotAge carries (bit 15 of the age masked for aging).
        let mut b = bytes;
        b[0..2].copy_from_slice(&(DO_NOT_AGE | 100).to_be_bytes());
        b[18..20].copy_from_slice(&24u16.to_be_bytes());
        let csum = lsa_fletcher_checksum(&mut b[2..], 14);
        b[16..18].copy_from_slice(&csum.to_be_bytes());
        let back = LsaV3::decode(&b).unwrap();
        assert_eq!(back.header.effective_age(), 100);
        assert!(!back.header.is_max_age());
        // Length field mismatch rejected (framing exactness).
        let mut b = back.encode();
        b[18..20].copy_from_slice(&25u16.to_be_bytes());
        let csum = lsa_fletcher_checksum(&mut b[2..], 14);
        b[16..18].copy_from_slice(&csum.to_be_bytes());
        assert!(matches!(
            LsaV3::decode(&b).unwrap_err(),
            OspfError::BadLength { .. }
        ));
        let _ = &lsa;
    }

    #[test]
    fn every_truncation_of_a_valid_v3_lsa_rejected() {
        let full = LsaV3 {
            header: header(LsaType::V3_ROUTER, 0, 1),
            body: LsaBodyV3::Router(RouterLsaV3 {
                nt_bit: false,
                v_bit: false,
                e_bit: true,
                b_bit: false,
                options: Options24(Options24::V6 | Options24::E),
                links: vec![RouterLinkV3 {
                    link_type: LinkTypeV3::Transit,
                    metric: 10,
                    interface_id: 1,
                    neighbor_interface_id: 2,
                    neighbor_router_id: rid("10.0.0.2"),
                }],
            }),
        }
        .encode();
        for cut in 0..full.len() {
            assert!(
                LsaV3::decode(&full[..cut]).is_err(),
                "truncation at {cut} must not decode"
            );
        }
        // Checksum corruption detected (single body bit).
        let mut corrupt = full.clone();
        corrupt[25] ^= 0x40;
        assert!(matches!(
            LsaV3::decode(&corrupt).unwrap_err(),
            OspfError::ChecksumMismatch { .. }
        ));
    }

    /// The fixed-seed xorshift property convention (the W5B/M3 note).
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

    fn random_prefix(rng: &mut XorShift) -> Prefix {
        let len = rng.below(129) as u8;
        let words = Prefix::words(len);
        let addr: Vec<u8> = (0..words).map(|_| (rng.next() >> 32) as u8).collect();
        Prefix {
            len,
            options: PrefixOptions((rng.next() & 0xff) as u8),
            addr,
        }
    }

    fn random_lsa(rng: &mut XorShift) -> LsaV3 {
        use LinkTypeV3::*;
        let adv = RouterId((rng.next() >> 32) as u32);
        // The header's LS type must match the body family (the
        // encode path dispatches on the body, decode on the header).
        let ls_type = [
            LsaType::V3_ROUTER,
            LsaType::V3_LINK,
            LsaType::V3_INTRA_AREA_PREFIX,
        ][(rng.below(3)) as usize];
        let header = LsaHeaderV3 {
            ls_age: (rng.below(crate::MAX_AGE as u64)) as u16,
            ls_type,
            link_state_id: LinkStateId((rng.next() >> 32) as u32),
            adv_router: adv,
            seq: INITIAL_SEQUENCE_NUMBER + rng.below(0x0000_ffff) as u32,
            checksum: 0,
            length: 0,
        };
        let body = match ls_type {
            LsaType::V3_ROUTER => {
                let n = rng.below(4) as usize;
                LsaBodyV3::Router(RouterLsaV3 {
                    nt_bit: rng.next() & 1 == 1,
                    v_bit: rng.next() & 1 == 1,
                    e_bit: rng.next() & 1 == 1,
                    b_bit: rng.next() & 1 == 1,
                    options: Options24((rng.next() & 0xff_ffff) as u32),
                    links: (0..n)
                        .map(|_| RouterLinkV3 {
                            link_type: [PointToPoint, Transit, Virtual][(rng.below(3)) as usize],
                            metric: (rng.next() >> 48) as u16,
                            interface_id: (rng.next() >> 32) as u32,
                            neighbor_interface_id: (rng.next() >> 32) as u32,
                            neighbor_router_id: RouterId((rng.next() >> 32) as u32),
                        })
                        .collect(),
                })
            }
            LsaType::V3_LINK => {
                let n = rng.below(4) as usize;
                LsaBodyV3::Link(LinkLsaV3 {
                    router_priority: (rng.next() >> 56) as u8,
                    options: Options24((rng.next() & 0xff_ffff) as u32),
                    link_local_address: Ipv6Addr::from(
                        ((rng.next() as u128) << 64) | rng.next() as u128,
                    ),
                    prefixes: (0..n).map(|_| random_prefix(rng)).collect(),
                })
            }
            _ => {
                let n = rng.below(4) as usize;
                LsaBodyV3::IntraAreaPrefix(IntraAreaPrefixLsaV3 {
                    prefixes: (0..n)
                        .map(|_| PrefixMetric {
                            metric: (rng.next() >> 48) as u16,
                            prefix: random_prefix(rng),
                        })
                        .collect(),
                    referenced_ls_type: LsaType::V3_ROUTER,
                    referenced_link_state_id: LinkStateId((rng.next() >> 32) as u32),
                    referenced_adv_router: RouterId((rng.next() >> 32) as u32),
                })
            }
        };
        LsaV3 { header, body }
    }

    #[test]
    fn property_round_trip_and_checksum_invariants() {
        let mut rng = XorShift(0x5eed_0f5a_0bad_0003_u64);
        for _ in 0..512 {
            let lsa = random_lsa(&mut rng);
            let bytes = lsa.encode();
            let mut expect = lsa.clone();
            expect.header.checksum = u16::from_be_bytes([bytes[16], bytes[17]]);
            expect.header.length = bytes.len() as u16;
            assert_eq!(LsaV3::decode(&bytes).unwrap(), expect);
            assert_eq!(
                u16::from_be_bytes([bytes[18], bytes[19]]) as usize,
                bytes.len()
            );
            assert!(fletcher_verify(&bytes[2..]));
            assert!(u16::from_be_bytes([bytes[16], bytes[17]]) != 0);
        }
    }

    #[test]
    fn property_single_bit_corruption_detected() {
        let mut rng = XorShift(0x1234_5678_9abc_def1_u64);
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
}
