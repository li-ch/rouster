//! The IS-IS TLV set — the protocol's whole data model (ISO 10589
//! §9.8's "variable length fields", RFC 1195 §5.2's IP additions,
//! RFC 5305's wide-metric pair, RFC 5301's hostname, RFC 5303's
//! three-way handshake).
//!
//! Encoding rule (ISO 10589 §9.8/§9.7): every field is `CODE (1) |
//! LENGTH (1) | VALUE (LENGTH)`. The house strictness applies at each
//! nesting level: the value length is checked against the buffer
//! (`Reader::take` — the A19 never-trust-counts rule) and against the
//! entry arithmetic of the specific TLV (a multiple of 11 for TLV 2,
//! of 16 for TLV 9, of 12 for TLV 128/130...).
//!
//! Tolerances pinned to the specs, nothing more:
//!
//! - **Unknown TLV codes are ignored, not errors** — ISO 10589 §9.7:
//!   "Any codes in a received PDU that are not recognised shall be
//!   ignored." They are carried as [`Tlv::Unknown`] so re-flooding is
//!   byte-preserving.
//! - **Repeatable TLVs stay repeatable**: RFC 1195 §5.2 — the IP
//!   reachability/interface-address fields "may occur multiple times
//!   in an LSP"; TLV 22 likewise (RFC 5305 §3: the structure repeats
//!   within the TLV and the TLV itself repeats across fragments).
//!   The codec preserves instance order; the semantic layer merges.
//! - **Padding (8) is opaque**: "LENGTH octets of arbitrary value"
//!   (§9.7); content is neither zeroed nor validated.
//! - **Reserved bits**: §9.1 — "transmitted as zero, and ignored on
//!   receipt". Metric octet flag positions consumed by the spec
//!   (I/E, up/down, S) are decoded; unknown high bits inside metric
//!   octets are likewise ignored-per-§9.1, not rejected.
//!
//! The narrow IS-reachability entry (TLV 2) follows the deployed
//! 11-octet form RFC 5305 §3 describes — "the default metric, the
//! delay, the monetary cost, the reliability, and the 7-octet ID of
//! the adjacent neighbor", metrics first, no virtual flag (the
//! partition-repair virtual flag of DP 10589/RFC 1142 was dropped by
//! the final ISO 10589:1992). Verified against FRR 10.2.2's
//! `pack_item_oldstyle_reach` (metric, 0x80, 0x80, 0x80, id) — the
//! interop oracle byte-for-byte.

use std::net::Ipv4Addr;

use crate::error::IsisError;
use crate::system::{LspId, NeighborId, SystemId};
use crate::wire::{put_u16, put_u24, put_u32, put_u8, Reader};

/// TLV codepoints (ISO 10589 §9.8 unless noted).
pub const TLV_AREA_ADDRESSES: u8 = 1;
pub const TLV_IS_REACHABILITY: u8 = 2;
pub const TLV_PADDING: u8 = 8;
pub const TLV_LSP_ENTRIES: u8 = 9;
pub const TLV_AUTHENTICATION: u8 = 10;
pub const TLV_EXTENDED_IS_REACHABILITY: u8 = 22; // RFC 5305 §3
pub const TLV_IP_INTERNAL_REACHABILITY: u8 = 128; // RFC 1195 §5.2
pub const TLV_NLPID: u8 = 129; // RFC 1195 §5.2 "Protocols Supported"
pub const TLV_IP_EXTERNAL_REACHABILITY: u8 = 130; // RFC 1195 §5.2
pub const TLV_IP_INTERFACE_ADDRESS: u8 = 132; // RFC 1195 §5.2
pub const TLV_EXTENDED_IP_REACHABILITY: u8 = 135; // RFC 5305 §4
pub const TLV_HOSTNAME: u8 = 137; // RFC 5301
pub const TLV_THREEWAY_ADJACENCY: u8 = 240; // RFC 5303 §3

/// NLPID values (RFC 1195 §5.2.2: 0xCC IPv4; RFC 1195/Knowledge: 0x8E
/// IPv6 — "IP version 6" per the IANA NLPID registry).
pub const NLPID_IPV4: u8 = 0xCC;
pub const NLPID_IPV6: u8 = 0x8E;

/// Authentication types (ISO 10589 §9.7; RFC 5304 §2 adds 54).
pub const AUTH_RESERVED: u8 = 0;
pub const AUTH_CLEARTEXT: u8 = 1;
pub const AUTH_HMAC_MD5: u8 = 54;
pub const AUTH_PRIVATE: u8 = 255;

/// One metric octet of the narrow metric family (ISO 10589 §9.8's
/// metric fields; RFC 5302 §2 redefined bit 7 as the up/down bit).
///
/// Layout of the *default metric* octet: `I/E | U/D | metric(6)`;
/// the delay/expense/error octets replace I/E with S (1 = metric
/// unsupported). Six usable bits → metric 0..=63 (RFC 5305 §3's
/// "possible metric range of 0-63").
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct NarrowMetric {
    /// Bit 8 of the default-metric octet: true = external metric
    /// (I/E). On the S-octets: true = "this metric is unsupported".
    pub flag: bool,
    /// RFC 5302's up/down bit (bit 7): true = the prefix travelled
    /// down the hierarchy (L2→L1) and must not be re-advertised back
    /// up.
    pub up_down: bool,
    /// The six metric bits, 0..=63.
    pub value: u16,
}

impl NarrowMetric {
    fn from_octet(b: u8) -> Self {
        Self {
            flag: b & 0x80 != 0,
            up_down: b & 0x40 != 0,
            value: (b & 0x3f) as u16,
        }
    }

    fn to_octet(self) -> u8 {
        (u8::from(self.flag) << 7) | (u8::from(self.up_down) << 6) | (self.value as u8 & 0x3f)
    }

    /// The metric an SPF uses: `None` when this is an S-octet of an
    /// unsupported metric (S = 1) — the caller passes which family it
    /// is decoding.
    pub fn metric(self) -> u32 {
        self.value as u32
    }
}

/// One neighbour entry of the narrow IS-reachability TLV 2 (the
/// deployed 11-octet form RFC 5305 §3 describes and FRR 10.2.2
/// writes: default/delay/expense/error metric octets, then the
/// 7-octet neighbour id).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OldIsNeighbor {
    pub id: NeighborId,
    pub default_metric: NarrowMetric,
    pub delay_metric: NarrowMetric,
    pub expense_metric: NarrowMetric,
    pub error_metric: NarrowMetric,
}

/// One neighbour entry of the extended IS-reachability TLV 22 (RFC
/// 5305 §3): 7-octet system ID + pseudonode, 3-octet default metric,
/// sub-TLV length, sub-TLVs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExtIsNeighbor {
    pub id: NeighborId,
    /// 24-bit metric (RFC 5305: "encoded as a 24-bit unsigned
    /// integer"; a link at 2^24-1 MUST NOT be used by normal SPF).
    pub metric: u32,
    pub sub_tlvs: Vec<SubTlv>,
}

/// A Traffic-Engineering sub-TLV (RFC 5305 §3: 1-octet type, 1-octet
/// length, value). v1 carries them opaquely (the SPF consumes none;
/// the established ones are listed for documentation).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SubTlv {
    pub kind: u8,
    pub value: Vec<u8>,
}

/// Established sub-TLV types under TLV 22 (RFC 5305 §3's table).
pub const SUBTLV_ADMIN_GROUP: u8 = 3;
pub const SUBTLV_MAX_LINK_BW: u8 = 4;
pub const SUBTLV_MAX_RES_BW: u8 = 5;
pub const SUBTLV_UNRESERVED_BW: u8 = 6;
pub const SUBTLV_TE_DEFAULT_METRIC: u8 = 7;

impl SubTlv {
    pub fn new(kind: u8, value: Vec<u8>) -> Self {
        Self { kind, value }
    }
}

/// One entry of the narrow IP reachability TLVs 128/130 (RFC 1195
/// §5.3.3): four metric octets, IPv4 address, IPv4 mask — 12 octets
/// per entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NarrowIpReach {
    pub default_metric: NarrowMetric,
    pub delay_metric: NarrowMetric,
    pub expense_metric: NarrowMetric,
    pub error_metric: NarrowMetric,
    /// RFC 1195 transmits address and mask as separate 4-octet
    /// fields (not prefix/length).
    pub address: Ipv4Addr,
    pub mask: Ipv4Addr,
    /// True when from TLV 130 (external reachability).
    pub external: bool,
}

impl NarrowIpReach {
    /// The prefix this entry names (address masked by mask).
    pub fn prefix(&self) -> (Ipv4Addr, u8) {
        let m = u32::from(self.mask);
        let plen = (!m).leading_zeros().min(32) as u8;
        let a = u32::from(self.address) & m;
        (Ipv4Addr::from(a), plen)
    }
}

/// One entry of the extended IP reachability TLV 135 (RFC 5305 §4):
/// 4-octet metric, control octet (up/down bit, sub-TLV-present bit,
/// 6-bit prefix length), the minimal prefix octets, optional
/// sub-TLVs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WideIpReach {
    /// 32-bit metric (RFC 5305 §4: "4 octets of metric information";
    /// ≥ MAX_PATH_METRIC prefixes are excluded from normal SPF).
    pub metric: u32,
    /// RFC 5302's up/down bit.
    pub up_down: bool,
    pub prefix: (Ipv4Addr, u8),
    pub sub_tlvs: Vec<SubTlv>,
}

impl WideIpReach {
    /// The minimal prefix octet count for a prefix length (RFC 5305
    /// §4's table: 0 bits → 0 octets; 1-8 → 1; 9-16 → 2; 17-24 → 3;
    /// 25-32 → 4; "The remaining bits of prefix are transmitted as
    /// zero and ignored upon receipt").
    pub fn prefix_octets(plen: u8) -> usize {
        (plen as usize).div_ceil(8)
    }
}

/// One LSP entry of TLV 9 (ISO 10589 §9.10/§9.12 — CSNP and PSNP
/// bodies): remaining lifetime, LSP id, sequence number, checksum —
/// 16 octets per entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LspEntry {
    pub remaining_lifetime: u16,
    pub lsp_id: LspId,
    pub sequence_number: u32,
    pub checksum: u16,
}

/// The three-way handshake state (RFC 5303 §3).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ThreewayState {
    /// "The system has not received any IIH packet containing the
    /// three-way handshake option on this point-to-point circuit."
    /// Wire value **2**.
    #[default]
    Down,
    /// "...does not know whether the neighbor is receiving its IIH
    /// packet." Wire value **1**.
    Initializing,
    /// "The system knows that the neighbor is receiving its IIH
    /// packets." Wire value **0**.
    Up,
}

impl ThreewayState {
    /// RFC 5303 §3.1: "0 - Up, 1 - Initializing, 2 - Down" (note the
    /// ordering — 0 is Up, not Down; FRR 10.2.2's
    /// `enum isis_threeway_state` carries the same values).
    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            0 => Some(Self::Up),
            1 => Some(Self::Initializing),
            2 => Some(Self::Down),
            _ => None,
        }
    }

    pub fn to_u8(self) -> u8 {
        match self {
            Self::Up => 0,
            Self::Initializing => 1,
            Self::Down => 2,
        }
    }
}

/// The P2P three-way adjacency TLV 240 (RFC 5303 §3): adjacency
/// state, extended local circuit ID, neighbor system ID, and — only
/// in the Up state — the neighbor's extended circuit ID (11 or 15
/// octets).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ThreewayAdjacency {
    pub state: ThreewayState,
    pub extended_local_circuit_id: u32,
    pub neighbor_system_id: SystemId,
    /// Present (and on the wire) only when `state == Up` (RFC 5303
    /// §3: "the Neighbor Extended Local Circuit ID is not included"
    /// otherwise).
    pub neighbor_extended_circuit_id: Option<u32>,
}

/// The typed TLV model. One PDU carries a `Vec<Tlv>` in wire order.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Tlv {
    /// CODE 1: area addresses, each length-prefixed (1..=13 octets).
    AreaAddresses(Vec<Vec<u8>>),
    /// CODE 2: the narrow IS-reachability set (ISO layout — see the
    /// module note for the FRR divergence).
    IsReachability(Vec<OldIsNeighbor>),
    /// CODE 8: padding, opaque value.
    Padding(Vec<u8>),
    /// CODE 9: LSP entries (CSNP/PSNP bodies).
    LspEntries(Vec<LspEntry>),
    /// CODE 10: authentication (type octet + value; ISO §9.7, RFC
    /// 5304 §2 for type 54).
    Authentication { auth_type: u8, value: Vec<u8> },
    /// CODE 22 (RFC 5305 §3): extended IS reachability.
    ExtIsReachability(Vec<ExtIsNeighbor>),
    /// CODE 128 (RFC 1195 §5.3.3): internal IP reachability.
    IpInternalReachability(Vec<NarrowIpReach>),
    /// CODE 129 (RFC 1195 §5.2.1): protocols supported (NLPIDs).
    ProtocolsSupported(Vec<u8>),
    /// CODE 130 (RFC 1195 §5.3.3): external IP reachability.
    IpExternalReachability(Vec<NarrowIpReach>),
    /// CODE 132 (RFC 1195 §5.2.1): IP interface addresses.
    IpInterfaceAddress(Vec<Ipv4Addr>),
    /// CODE 135 (RFC 5305 §4): extended IP reachability.
    ExtIpReachability(Vec<WideIpReach>),
    /// CODE 137 (RFC 5301): the dynamic hostname.
    Hostname(String),
    /// CODE 240 (RFC 5303 §3): the three-way handshake option.
    ThreewayAdjacency(ThreewayAdjacency),
    /// Anything else: carried opaquely so flooding is byte-preserving
    /// (ISO §9.7: "codes in a received PDU that are not recognised
    /// shall be ignored").
    Unknown { kind: u8, value: Vec<u8> },
}

impl Tlv {
    pub fn kind(&self) -> u8 {
        match self {
            Self::AreaAddresses(_) => TLV_AREA_ADDRESSES,
            Self::IsReachability(_) => TLV_IS_REACHABILITY,
            Self::Padding(_) => TLV_PADDING,
            Self::LspEntries(_) => TLV_LSP_ENTRIES,
            Self::Authentication { .. } => TLV_AUTHENTICATION,
            Self::ExtIsReachability(_) => TLV_EXTENDED_IS_REACHABILITY,
            Self::IpInternalReachability(_) => TLV_IP_INTERNAL_REACHABILITY,
            Self::ProtocolsSupported(_) => TLV_NLPID,
            Self::IpExternalReachability(_) => TLV_IP_EXTERNAL_REACHABILITY,
            Self::IpInterfaceAddress(_) => TLV_IP_INTERFACE_ADDRESS,
            Self::ExtIpReachability(_) => TLV_EXTENDED_IP_REACHABILITY,
            Self::Hostname(_) => TLV_HOSTNAME,
            Self::ThreewayAdjacency(_) => TLV_THREEWAY_ADJACENCY,
            Self::Unknown { kind, .. } => *kind,
        }
    }
}

/// Decode a full TLV block (everything after a PDU's fixed header).
/// The whole block must be consumed exactly — trailing bytes mean
/// the outer framing lied about its length.
pub fn decode_tlvs(bytes: &[u8]) -> Result<Vec<Tlv>, IsisError> {
    let mut r = Reader::new(bytes);
    let mut out = Vec::new();
    while !r.is_empty() {
        let kind = r.u8().ok_or(IsisError::Truncated {
            field: "TLV code",
            need: 1,
            have: 0,
        })?;
        let len = r.u8().ok_or(IsisError::Truncated {
            field: "TLV length",
            need: 1,
            have: 0,
        })? as usize;
        let value = r.take(len).ok_or(IsisError::BadTlvLength {
            kind,
            declared: len,
            actual: r.remaining(),
        })?;
        out.push(decode_one(kind, value)?);
    }
    Ok(out)
}

/// Decode one TLV value of known length. Entry-structured TLVs
/// enforce the modulo rule; string and address TLVs enforce their own
/// arithmetic.
fn decode_one(kind: u8, value: &[u8]) -> Result<Tlv, IsisError> {
    let entry_err = |entry: usize| IsisError::BadTlvEntrySize {
        kind,
        len: value.len(),
        entry,
    };
    Ok(match kind {
        TLV_AREA_ADDRESSES => {
            let mut r = Reader::new(value);
            let mut areas = Vec::new();
            while !r.is_empty() {
                let alen = r.u8().ok_or(IsisError::Truncated {
                    field: "area address length",
                    need: 1,
                    have: 0,
                })? as usize;
                if !(1..=13).contains(&alen) {
                    return Err(IsisError::BadAreaLength(alen));
                }
                let area = r.take(alen).ok_or(IsisError::Truncated {
                    field: "area address",
                    need: alen,
                    have: r.remaining(),
                })?;
                areas.push(area.to_vec());
            }
            Tlv::AreaAddresses(areas)
        }
        TLV_IS_REACHABILITY => {
            if !value.len().is_multiple_of(11) {
                return Err(entry_err(11));
            }
            let mut neighbors = Vec::new();
            for chunk in value.as_chunks::<11>().0 {
                neighbors.push(OldIsNeighbor {
                    default_metric: NarrowMetric::from_octet(chunk[0]),
                    delay_metric: NarrowMetric::from_octet(chunk[1]),
                    expense_metric: NarrowMetric::from_octet(chunk[2]),
                    error_metric: NarrowMetric::from_octet(chunk[3]),
                    id: NeighborId::new(
                        SystemId::from_bytes([
                            chunk[4], chunk[5], chunk[6], chunk[7], chunk[8], chunk[9],
                        ]),
                        chunk[10],
                    ),
                });
            }
            Tlv::IsReachability(neighbors)
        }
        TLV_PADDING => Tlv::Padding(value.to_vec()),
        TLV_LSP_ENTRIES => {
            if !value.len().is_multiple_of(16) {
                return Err(entry_err(16));
            }
            let mut entries = Vec::new();
            for chunk in value.as_chunks::<16>().0 {
                entries.push(LspEntry {
                    remaining_lifetime: u16::from_be_bytes([chunk[0], chunk[1]]),
                    lsp_id: LspId::new(
                        SystemId::from_bytes([
                            chunk[2], chunk[3], chunk[4], chunk[5], chunk[6], chunk[7],
                        ]),
                        chunk[8],
                        chunk[9],
                    ),
                    sequence_number: u32::from_be_bytes([
                        chunk[10], chunk[11], chunk[12], chunk[13],
                    ]),
                    checksum: u16::from_be_bytes([chunk[14], chunk[15]]),
                });
            }
            Tlv::LspEntries(entries)
        }
        TLV_AUTHENTICATION => {
            let (auth_type, rest) = value.split_first().ok_or(IsisError::BadAuthShape)?;
            Tlv::Authentication {
                auth_type: *auth_type,
                value: rest.to_vec(),
            }
        }
        TLV_EXTENDED_IS_REACHABILITY => {
            let mut r = Reader::new(value);
            let mut neighbors = Vec::new();
            while !r.is_empty() {
                let id = r.take(7).ok_or(IsisError::Truncated {
                    field: "TLV 22 neighbour id",
                    need: 7,
                    have: r.remaining(),
                })?;
                let metric = r.u24().ok_or(IsisError::Truncated {
                    field: "TLV 22 metric",
                    need: 3,
                    have: r.remaining(),
                })?;
                let sub_len = r.u8().ok_or(IsisError::Truncated {
                    field: "TLV 22 sub-TLV length",
                    need: 1,
                    have: 0,
                })? as usize;
                let sub = r.take(sub_len).ok_or(IsisError::BadTlvLength {
                    kind: TLV_EXTENDED_IS_REACHABILITY,
                    declared: sub_len,
                    actual: r.remaining(),
                })?;
                neighbors.push(ExtIsNeighbor {
                    id: NeighborId::new(
                        SystemId::from_bytes([id[0], id[1], id[2], id[3], id[4], id[5]]),
                        id[6],
                    ),
                    metric,
                    sub_tlvs: decode_sub_tlvs(TLV_EXTENDED_IS_REACHABILITY, sub)?,
                });
            }
            Tlv::ExtIsReachability(neighbors)
        }
        TLV_IP_INTERNAL_REACHABILITY => {
            if !value.len().is_multiple_of(12) {
                return Err(entry_err(12));
            }
            Tlv::IpInternalReachability(
                value
                    .as_chunks::<12>()
                    .0
                    .iter()
                    .map(|c| decode_narrow_ip(c, false))
                    .collect(),
            )
        }
        TLV_NLPID => Tlv::ProtocolsSupported(value.to_vec()),
        TLV_IP_EXTERNAL_REACHABILITY => {
            if !value.len().is_multiple_of(12) {
                return Err(entry_err(12));
            }
            Tlv::IpExternalReachability(
                value
                    .as_chunks::<12>()
                    .0
                    .iter()
                    .map(|c| decode_narrow_ip(c, true))
                    .collect(),
            )
        }
        TLV_IP_INTERFACE_ADDRESS => {
            if !value.len().is_multiple_of(4) {
                return Err(entry_err(4));
            }
            Tlv::IpInterfaceAddress(
                value
                    .as_chunks::<4>()
                    .0
                    .iter()
                    .map(|c| Ipv4Addr::new(c[0], c[1], c[2], c[3]))
                    .collect(),
            )
        }
        TLV_EXTENDED_IP_REACHABILITY => {
            let mut r = Reader::new(value);
            let mut prefixes = Vec::new();
            while !r.is_empty() {
                let metric = r.u32().ok_or(IsisError::Truncated {
                    field: "TLV 135 metric",
                    need: 4,
                    have: r.remaining(),
                })?;
                let control = r.u8().ok_or(IsisError::Truncated {
                    field: "TLV 135 control",
                    need: 1,
                    have: 0,
                })?;
                let plen = control & 0x3f;
                if plen > 32 {
                    return Err(IsisError::BadLength {
                        field: "TLV 135 prefix length",
                        declared: plen as usize,
                        actual: 32,
                    });
                }
                let up_down = control & 0x80 != 0;
                let has_sub = control & 0x40 != 0;
                let poctets = WideIpReach::prefix_octets(plen);
                let pfx = r.take(poctets).ok_or(IsisError::Truncated {
                    field: "TLV 135 prefix",
                    need: poctets,
                    have: r.remaining(),
                })?;
                let mut bytes = [0u8; 4];
                bytes[..poctets].copy_from_slice(pfx);
                let sub_tlvs = if has_sub {
                    let sub_len = r.u8().ok_or(IsisError::Truncated {
                        field: "TLV 135 sub-TLV length",
                        need: 1,
                        have: 0,
                    })? as usize;
                    let sub = r.take(sub_len).ok_or(IsisError::BadTlvLength {
                        kind: TLV_EXTENDED_IP_REACHABILITY,
                        declared: sub_len,
                        actual: r.remaining(),
                    })?;
                    decode_sub_tlvs(TLV_EXTENDED_IP_REACHABILITY, sub)?
                } else {
                    Vec::new()
                };
                prefixes.push(WideIpReach {
                    metric,
                    up_down,
                    prefix: (Ipv4Addr::from(bytes), plen),
                    sub_tlvs,
                });
            }
            Tlv::ExtIpReachability(prefixes)
        }
        TLV_HOSTNAME => {
            // RFC 5301 §2: "printable ASCII string". Reject control
            // octets (the strict reading — deployments carry hostnames,
            // not binary).
            for &b in value {
                if !(0x20..=0x7e).contains(&b) {
                    return Err(IsisError::BadHostnameByte(b));
                }
            }
            let name =
                String::from_utf8(value.to_vec()).map_err(|_| IsisError::BadHostnameByte(0))?;
            Tlv::Hostname(name)
        }
        TLV_THREEWAY_ADJACENCY => {
            // RFC 5303 §3: state (1), extended local circuit ID (4),
            // neighbor system ID (6), neighbor extended circuit ID (4,
            // only in Up) — lengths 11 or 15.
            if value.len() != 11 && value.len() != 15 {
                return Err(IsisError::BadLength {
                    field: "TLV 240",
                    declared: value.len(),
                    actual: 11,
                });
            }
            let state =
                ThreewayState::from_u8(value[0]).ok_or(IsisError::BadThreewayState(value[0]))?;
            let neighbor_extended_circuit_id = if value.len() == 15 {
                if state != ThreewayState::Up {
                    // The 15-octet form is only meaningful Up; a
                    // non-Up state carrying it is malformed.
                    return Err(IsisError::BadLength {
                        field: "TLV 240 (neighbor circuit id present but state is not Up)",
                        declared: 15,
                        actual: 11,
                    });
                }
                Some(u32::from_be_bytes([
                    value[11], value[12], value[13], value[14],
                ]))
            } else {
                None
            };
            Tlv::ThreewayAdjacency(ThreewayAdjacency {
                state,
                extended_local_circuit_id: u32::from_be_bytes([
                    value[1], value[2], value[3], value[4],
                ]),
                neighbor_system_id: SystemId::from_bytes([
                    value[5], value[6], value[7], value[8], value[9], value[10],
                ]),
                neighbor_extended_circuit_id,
            })
        }
        other => Tlv::Unknown {
            kind: other,
            value: value.to_vec(),
        },
    })
}

/// Sub-TLV framing (RFC 5305 §3): `type (1) | length (1) | value`.
fn decode_sub_tlvs(parent: u8, mut bytes: &[u8]) -> Result<Vec<SubTlv>, IsisError> {
    let mut out = Vec::new();
    while !bytes.is_empty() {
        if bytes.len() < 2 {
            return Err(IsisError::BadSubTlv {
                parent,
                kind: bytes[0],
                available: bytes.len(),
            });
        }
        let kind = bytes[0];
        let len = bytes[1] as usize;
        if bytes.len() - 2 < len {
            return Err(IsisError::BadSubTlv {
                parent,
                kind,
                available: bytes.len() - 2,
            });
        }
        out.push(SubTlv::new(kind, bytes[2..2 + len].to_vec()));
        bytes = &bytes[2 + len..];
    }
    Ok(out)
}

fn decode_narrow_ip(chunk: &[u8], external: bool) -> NarrowIpReach {
    NarrowIpReach {
        default_metric: NarrowMetric::from_octet(chunk[0]),
        delay_metric: NarrowMetric::from_octet(chunk[1]),
        expense_metric: NarrowMetric::from_octet(chunk[2]),
        error_metric: NarrowMetric::from_octet(chunk[3]),
        address: Ipv4Addr::new(chunk[4], chunk[5], chunk[6], chunk[7]),
        mask: Ipv4Addr::new(chunk[8], chunk[9], chunk[10], chunk[11]),
        external,
    }
}

/// Encode one TLV (code, length, value) into `buf`.
pub fn encode_tlv(buf: &mut Vec<u8>, tlv: &Tlv) {
    let mut value = Vec::new();
    match tlv {
        Tlv::AreaAddresses(areas) => {
            for area in areas {
                put_u8(&mut value, area.len() as u8);
                value.extend_from_slice(area);
            }
        }
        Tlv::IsReachability(neighbors) => {
            for n in neighbors {
                put_u8(&mut value, n.default_metric.to_octet());
                put_u8(&mut value, n.delay_metric.to_octet());
                put_u8(&mut value, n.expense_metric.to_octet());
                put_u8(&mut value, n.error_metric.to_octet());
                value.extend_from_slice(&n.id.system.0);
                put_u8(&mut value, n.id.pseudonode);
            }
        }
        Tlv::Padding(v) => value.extend_from_slice(v),
        Tlv::LspEntries(entries) => {
            for e in entries {
                put_u16(&mut value, e.remaining_lifetime);
                value.extend_from_slice(&e.lsp_id.system.0);
                put_u8(&mut value, e.lsp_id.pseudonode);
                put_u8(&mut value, e.lsp_id.fragment);
                put_u32(&mut value, e.sequence_number);
                put_u16(&mut value, e.checksum);
            }
        }
        Tlv::Authentication {
            auth_type,
            value: v,
        } => {
            put_u8(&mut value, *auth_type);
            value.extend_from_slice(v);
        }
        Tlv::ExtIsReachability(neighbors) => {
            for n in neighbors {
                value.extend_from_slice(&n.id.system.0);
                put_u8(&mut value, n.id.pseudonode);
                put_u24(&mut value, n.metric);
                let mut subs = Vec::new();
                for s in &n.sub_tlvs {
                    put_u8(&mut subs, s.kind);
                    put_u8(&mut subs, s.value.len() as u8);
                    subs.extend_from_slice(&s.value);
                }
                put_u8(&mut value, subs.len() as u8);
                value.extend_from_slice(&subs);
            }
        }
        Tlv::IpInternalReachability(entries) | Tlv::IpExternalReachability(entries) => {
            for e in entries {
                put_u8(&mut value, e.default_metric.to_octet());
                put_u8(&mut value, e.delay_metric.to_octet());
                put_u8(&mut value, e.expense_metric.to_octet());
                put_u8(&mut value, e.error_metric.to_octet());
                value.extend_from_slice(&e.address.octets());
                value.extend_from_slice(&e.mask.octets());
            }
        }
        Tlv::ProtocolsSupported(nlpids) => value.extend_from_slice(nlpids),
        Tlv::IpInterfaceAddress(addrs) => {
            for a in addrs {
                value.extend_from_slice(&a.octets());
            }
        }
        Tlv::ExtIpReachability(prefixes) => {
            for p in prefixes {
                put_u32(&mut value, p.metric);
                let poctets = WideIpReach::prefix_octets(p.prefix.1);
                let mut control = p.prefix.1 & 0x3f;
                if p.up_down {
                    control |= 0x80;
                }
                if !p.sub_tlvs.is_empty() {
                    control |= 0x40;
                }
                put_u8(&mut value, control);
                value.extend_from_slice(&p.prefix.0.octets()[..poctets]);
                if !p.sub_tlvs.is_empty() {
                    let mut subs = Vec::new();
                    for s in &p.sub_tlvs {
                        put_u8(&mut subs, s.kind);
                        put_u8(&mut subs, s.value.len() as u8);
                        subs.extend_from_slice(&s.value);
                    }
                    put_u8(&mut value, subs.len() as u8);
                    value.extend_from_slice(&subs);
                }
            }
        }
        Tlv::Hostname(name) => value.extend_from_slice(name.as_bytes()),
        Tlv::ThreewayAdjacency(tw) => {
            put_u8(&mut value, tw.state.to_u8());
            put_u32(&mut value, tw.extended_local_circuit_id);
            value.extend_from_slice(&tw.neighbor_system_id.0);
            if let Some(ncid) = tw.neighbor_extended_circuit_id {
                put_u32(&mut value, ncid);
            }
        }
        Tlv::Unknown { kind: _, value: v } => value.extend_from_slice(v),
    }
    debug_assert!(
        value.len() <= 255,
        "TLV values are length-byte bounded; fragment instead"
    );
    put_u8(buf, tlv.kind());
    put_u8(buf, value.len() as u8);
    buf.extend_from_slice(&value);
}

/// Encode a whole TLV block.
pub fn encode_tlvs(buf: &mut Vec<u8>, tlvs: &[Tlv]) {
    for tlv in tlvs {
        encode_tlv(buf, tlv);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SYS: SystemId = SystemId::from_bytes([0x19, 0x21, 0x68, 0x00, 0x10, 0x01]);

    fn roundtrip(tlvs: &[Tlv]) -> Vec<Tlv> {
        let mut buf = Vec::new();
        encode_tlvs(&mut buf, tlvs);
        decode_tlvs(&buf).expect("roundtrip decodes")
    }

    #[test]
    fn area_addresses_roundtrip_and_split() {
        let tlv = Tlv::AreaAddresses(vec![vec![0x49, 0x00, 0x01], vec![0x49]]);
        let back = roundtrip(std::slice::from_ref(&tlv));
        assert_eq!(back, vec![tlv]);
        // Wire: 49.0001 is 3 bytes -> 03 49 00 01; 49 is 1 -> 01 49.
        let mut buf = Vec::new();
        encode_tlv(&mut buf, &back[0]);
        assert_eq!(buf, vec![1, 6, 3, 0x49, 0x00, 0x01, 1, 0x49]);
    }

    #[test]
    fn area_address_length_bounds_enforced() {
        // A 14-byte area address is rejected (1..=13).
        let bad = {
            let mut v = vec![14u8];
            v.extend_from_slice(&[0u8; 14]);
            v
        };
        let mut buf = vec![TLV_AREA_ADDRESSES, bad.len() as u8];
        buf.extend_from_slice(&bad);
        assert!(matches!(
            decode_tlvs(&buf),
            Err(IsisError::BadAreaLength(14))
        ));
        // A length prefix that overruns the TLV value is a bad
        // length (the area itself never gets read).
        let bad2 = [TLV_AREA_ADDRESSES, 4, 9, 0x49];
        assert!(matches!(
            decode_tlvs(&bad2),
            Err(IsisError::BadTlvLength {
                kind: 1,
                declared: 4,
                actual: 2
            })
        ));
    }

    /// The deployed 11-octet form (RFC 5305 §3's description, FRR
    /// 10.2.2's byte order): four metric octets, then the 7-octet id.
    #[test]
    fn old_is_reachability_deployed_layout() {
        let n = OldIsNeighbor {
            id: NeighborId::new(SYS, 0),
            default_metric: NarrowMetric {
                flag: false,
                up_down: false,
                value: 10,
            },
            delay_metric: NarrowMetric {
                flag: true,
                up_down: false,
                value: 0,
            },
            expense_metric: NarrowMetric {
                flag: true,
                up_down: false,
                value: 0,
            },
            error_metric: NarrowMetric {
                flag: true,
                up_down: false,
                value: 0,
            },
        };
        let tlv = Tlv::IsReachability(vec![n]);
        let mut buf = Vec::new();
        encode_tlv(&mut buf, &tlv);
        assert_eq!(
            buf,
            vec![
                TLV_IS_REACHABILITY,
                11,
                10,
                0x80,
                0x80,
                0x80,
                0x19,
                0x21,
                0x68,
                0x00,
                0x10,
                0x01,
                0x00
            ]
        );
        assert_eq!(roundtrip(std::slice::from_ref(&tlv)), vec![tlv]);
        // Modulo rule: 10 bytes is not an entry set.
        let bad = {
            let mut v = vec![TLV_IS_REACHABILITY, 10];
            v.extend_from_slice(&[0u8; 10]);
            v
        };
        assert!(matches!(
            decode_tlvs(&bad),
            Err(IsisError::BadTlvEntrySize {
                kind: 2,
                entry: 11,
                ..
            })
        ));
    }

    #[test]
    fn ext_is_reachability_with_subtlvs() {
        let n = ExtIsNeighbor {
            id: NeighborId::new(SYS, 0),
            metric: 0x010203,
            sub_tlvs: vec![
                SubTlv::new(SUBTLV_ADMIN_GROUP, vec![0xff; 4]),
                SubTlv::new(SUBTLV_TE_DEFAULT_METRIC, vec![0, 0, 0, 5]),
            ],
        };
        let tlv = Tlv::ExtIsReachability(vec![n]);
        let back = roundtrip(std::slice::from_ref(&tlv));
        assert_eq!(back, vec![tlv]);
        // Sub-TLV overrun is caught: declared 40 bytes, only 3 there.
        let mut v = vec![TLV_EXTENDED_IS_REACHABILITY, 14];
        v.extend_from_slice(&SYS.0);
        v.push(0); // pseudonode
        v.extend_from_slice(&[0, 0, 1]); // metric
        v.push(40); // sub-TLV length
        v.extend_from_slice(&[3, 4, 1]); // only 3 bytes of sub-TLVs
        assert!(matches!(
            decode_tlvs(&v),
            Err(IsisError::BadTlvLength {
                kind: 22,
                declared: 40,
                actual: 3
            })
        ));
    }

    /// RFC 5305 §4: the control octet is up/down (0x80), sub-TLV
    /// present (0x40), 6-bit prefix length; the prefix octets are
    /// minimal; the sub-TLV length byte exists only when the bit is
    /// set.
    #[test]
    fn wide_ip_reach_control_octet_semantics() {
        let entries = vec![
            WideIpReach {
                metric: 10,
                up_down: false,
                prefix: (Ipv4Addr::new(10, 1, 0, 0), 16),
                sub_tlvs: vec![],
            },
            WideIpReach {
                metric: 0xffff_ffff,
                up_down: true,
                prefix: (Ipv4Addr::new(192, 168, 0, 0), 24),
                sub_tlvs: vec![SubTlv::new(1, vec![7])],
            },
        ];
        let tlv = Tlv::ExtIpReachability(entries);
        let mut buf = Vec::new();
        encode_tlv(&mut buf, &tlv);
        // metric(4) control(1) pfx(2) | metric(4) control(1) pfx(3) sublen(1) subtlv(3)
        assert_eq!(buf[0], TLV_EXTENDED_IP_REACHABILITY);
        assert_eq!(buf[1], 19);
        assert_eq!(&buf[2..6], &[0, 0, 0, 10]);
        assert_eq!(buf[6], 16, "no up/down, no sub-TLVs, plen 16");
        assert_eq!(&buf[7..9], &[10, 1]);
        assert_eq!(&buf[9..13], &[0xff, 0xff, 0xff, 0xff]);
        assert_eq!(
            buf[13],
            0x80 | 0x40 | 24,
            "up/down + sub-TLV present + plen 24"
        );
        assert_eq!(&buf[14..17], &[192, 168, 0]);
        assert_eq!(buf[17], 3);
        assert_eq!(&buf[18..21], &[1, 1, 7]);
        assert_eq!(roundtrip(std::slice::from_ref(&tlv)), vec![tlv]);
    }

    #[test]
    fn wide_ip_reach_prefix_length_bounds() {
        // plen 33 in the 6-bit field is impossible; only reachable via
        // a raw control octet since the encoder masks to 6 bits.
        let bad = {
            let mut v = vec![TLV_EXTENDED_IP_REACHABILITY, 7];
            v.extend_from_slice(&[0, 0, 0, 1]); // metric
            v.push(33); // control: plen 33
            v.extend_from_slice(&[10, 0]); // prefix octets
            v
        };
        assert!(matches!(
            decode_tlvs(&bad),
            Err(IsisError::BadLength {
                field: "TLV 135 prefix length",
                ..
            })
        ));
    }

    #[test]
    fn narrow_ip_reachability_entry_shape() {
        let e = NarrowIpReach {
            default_metric: NarrowMetric {
                flag: false,
                up_down: false,
                value: 63,
            },
            delay_metric: NarrowMetric {
                flag: true,
                up_down: false,
                value: 0,
            },
            expense_metric: NarrowMetric {
                flag: true,
                up_down: false,
                value: 0,
            },
            error_metric: NarrowMetric {
                flag: true,
                up_down: false,
                value: 0,
            },
            address: Ipv4Addr::new(10, 0, 0, 0),
            mask: Ipv4Addr::new(255, 255, 255, 0),
            external: false,
        };
        let tlv = Tlv::IpInternalReachability(vec![e]);
        let back = roundtrip(std::slice::from_ref(&tlv));
        assert_eq!(back, vec![tlv]);
        let Tlv::IpInternalReachability(entries) = &back[0] else {
            unreachable!()
        };
        let (addr, plen) = entries[0].prefix();
        assert_eq!((addr, plen), (Ipv4Addr::new(10, 0, 0, 0), 24));
        // 12-byte modulo rule.
        let bad = vec![
            TLV_IP_INTERNAL_REACHABILITY,
            11,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
        ];
        assert!(matches!(
            decode_tlvs(&bad),
            Err(IsisError::BadTlvEntrySize {
                kind: 128,
                entry: 12,
                ..
            })
        ));
    }

    #[test]
    fn lsp_entries_sixteen_byte_shape() {
        let entry = LspEntry {
            remaining_lifetime: 1200,
            lsp_id: LspId::zero(SYS),
            sequence_number: 2,
            checksum: 0xabcd,
        };
        let tlv = Tlv::LspEntries(vec![entry]);
        let mut buf = Vec::new();
        encode_tlv(&mut buf, &tlv);
        assert_eq!(buf.len(), 2 + 16);
        assert_eq!(&buf[2..4], &[0x04, 0xb0]);
        assert_eq!(&buf[12..16], &[0, 0, 0, 2]);
        assert_eq!(&buf[16..18], &[0xab, 0xcd]);
        assert_eq!(roundtrip(std::slice::from_ref(&tlv)), vec![tlv]);
        let bad = vec![
            TLV_LSP_ENTRIES,
            15,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
        ];
        assert!(matches!(
            decode_tlvs(&bad),
            Err(IsisError::BadTlvEntrySize {
                kind: 9,
                entry: 16,
                ..
            })
        ));
    }

    #[test]
    fn authentication_shapes() {
        let tlv = Tlv::Authentication {
            auth_type: AUTH_CLEARTEXT,
            value: b"secret".to_vec(),
        };
        let mut buf = Vec::new();
        encode_tlv(&mut buf, &tlv);
        assert_eq!(buf, vec![10, 7, 1, b's', b'e', b'c', b'r', b'e', b't']);
        assert_eq!(roundtrip(std::slice::from_ref(&tlv)), vec![tlv]);
        // RFC 5304 shape: type 54 + 16 digest octets.
        let md5 = Tlv::Authentication {
            auth_type: AUTH_HMAC_MD5,
            value: vec![0x5a; 16],
        };
        assert_eq!(roundtrip(std::slice::from_ref(&md5)), vec![md5]);
        // A type-less authentication TLV is malformed.
        assert!(matches!(
            decode_tlvs(&[TLV_AUTHENTICATION, 0]),
            Err(IsisError::BadAuthShape)
        ));
    }

    #[test]
    fn hostname_ascii_rule() {
        assert_eq!(
            roundtrip(&[Tlv::Hostname("r2.rouster".into())]),
            vec![Tlv::Hostname("r2.rouster".into())]
        );
        // Non-printable octet rejected (RFC 5301 §2 printable ASCII).
        assert!(matches!(
            decode_tlvs(&[TLV_HOSTNAME, 2, b'r', 0x01]),
            Err(IsisError::BadHostnameByte(0x01))
        ));
    }

    /// RFC 5303 §3: 11 octets Down/Initializing, 15 Up; states 0-2
    /// only; the neighbor circuit id exists only Up.
    #[test]
    fn threeway_adjacency_lengths_and_states() {
        let down = Tlv::ThreewayAdjacency(ThreewayAdjacency {
            state: ThreewayState::Down,
            extended_local_circuit_id: 7,
            neighbor_system_id: SYS,
            neighbor_extended_circuit_id: None,
        });
        let up = Tlv::ThreewayAdjacency(ThreewayAdjacency {
            state: ThreewayState::Up,
            extended_local_circuit_id: 7,
            neighbor_system_id: SYS,
            neighbor_extended_circuit_id: Some(9),
        });
        let mut buf = Vec::new();
        encode_tlv(&mut buf, &down);
        assert_eq!(buf.len(), 2 + 11);
        let mut buf = Vec::new();
        encode_tlv(&mut buf, &up);
        assert_eq!(buf.len(), 2 + 15);
        assert_eq!(roundtrip(&[down.clone(), up.clone()]), vec![down, up]);
        // Bad state value.
        assert!(matches!(
            decode_tlvs(&{
                let mut v = vec![TLV_THREEWAY_ADJACENCY, 11, 3];
                v.extend_from_slice(&[0; 10]);
                v
            }),
            Err(IsisError::BadThreewayState(3))
        ));
        // Neighbor circuit id present while not Up.
        let mut v = vec![TLV_THREEWAY_ADJACENCY, 15, 1];
        v.extend_from_slice(&[0; 14]);
        assert!(matches!(decode_tlvs(&v), Err(IsisError::BadLength { .. })));
    }

    /// ISO §9.7: "Any codes in a received PDU that are not recognised
    /// shall be ignored" — carried opaquely, byte-preserving.
    #[test]
    fn unknown_tlvs_pass_through() {
        let unknown = Tlv::Unknown {
            kind: 234,
            value: vec![1, 2, 3],
        };
        assert_eq!(roundtrip(std::slice::from_ref(&unknown)), vec![unknown]);
    }

    #[test]
    fn padding_is_opaque() {
        let pad = Tlv::Padding(vec![0xff; 20]);
        assert_eq!(roundtrip(std::slice::from_ref(&pad)), vec![pad]);
        // RFC-cited: may occur multiple times, length may be zero.
        assert_eq!(
            roundtrip(&[Tlv::Padding(vec![])]),
            vec![Tlv::Padding(vec![])]
        );
    }

    #[test]
    fn value_length_never_lies() {
        // Declared 30, only 10 present.
        let mut bad = vec![TLV_NLPID, 30];
        bad.extend_from_slice(&[0xCC; 10]);
        assert!(matches!(
            decode_tlvs(&bad),
            Err(IsisError::BadTlvLength {
                kind: 129,
                declared: 30,
                actual: 10
            })
        ));
        // Truncated header itself.
        assert!(matches!(
            decode_tlvs(&[TLV_NLPID]),
            Err(IsisError::Truncated { .. })
        ));
        assert!(matches!(
            decode_tlvs(&[7]),
            Err(IsisError::Truncated { .. })
        ));
    }

    #[test]
    fn interface_addresses_four_byte_multiples() {
        let tlv =
            Tlv::IpInterfaceAddress(vec![Ipv4Addr::new(10, 0, 0, 2), Ipv4Addr::new(10, 0, 1, 2)]);
        assert_eq!(roundtrip(std::slice::from_ref(&tlv)), vec![tlv]);
        let bad = vec![TLV_IP_INTERFACE_ADDRESS, 3, 10, 0, 0];
        assert!(matches!(
            decode_tlvs(&bad),
            Err(IsisError::BadTlvEntrySize {
                kind: 132,
                entry: 4,
                ..
            })
        ));
    }

    /// Repeatable TLVs stay separate instances in order (RFC 1195
    /// §5.2 "may occur multiple times" — merge is the semantic
    /// layer's job, not the codec's).
    #[test]
    fn repeatable_tlvs_keep_order() {
        let tlvs = vec![
            Tlv::IpInterfaceAddress(vec![Ipv4Addr::new(10, 0, 0, 1)]),
            Tlv::ProtocolsSupported(vec![NLPID_IPV4]),
            Tlv::IpInterfaceAddress(vec![Ipv4Addr::new(10, 0, 1, 1)]),
        ];
        assert_eq!(roundtrip(&tlvs), tlvs);
    }
}
