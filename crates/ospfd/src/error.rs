//! Error types for the OSPF codec, database and state machines
//! (`thiserror`, the workspace convention).

/// Every malformed-input rejection in the codec funnels into this enum.
/// Variants name the exact field that failed and carry the offending
/// value so logs can pinpoint wire breakage (the A19 post-mortem shape).
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum OspfError {
    #[error("buffer truncated reading {field} ({need} bytes, {have} left)")]
    Truncated {
        field: &'static str,
        need: usize,
        have: usize,
    },

    #[error("length field for {field}: declared {declared}, actual {actual}")]
    BadLength {
        field: &'static str,
        declared: usize,
        actual: usize,
    },

    #[error("unknown LS type {0}")]
    BadLsType(u16),

    #[error("unknown router link type {0}")]
    BadLinkType(u8),

    #[error("reserved bits set in {field}: {value:#04x}")]
    ReservedBits { field: &'static str, value: u8 },

    #[error("reserved bits set in {field}: {value:#06x}")]
    ReservedBits16 { field: &'static str, value: u16 },

    #[error(
        "LSA flooding scope bits S2/S1 = 0b11 are reserved (LS type {0:#06x}, RFC 5340 A.4.2.1)"
    )]
    ReservedScope(u16),

    #[error("OSPFv3 forwarding address must be a global IPv6 address (RFC 5340 A.4.7 MUST NOT), got {0}")]
    BadForwardingAddress(std::net::Ipv6Addr),

    #[error("LS checksum mismatch: header says {header:#06x}, computed {computed:#06x}")]
    ChecksumMismatch { header: u16, computed: u16 },

    #[error("LS checksum field is zero (RFC 2328 §12.1.7: cannot be zero)")]
    ZeroChecksum,

    #[error("LS age {0} exceeds MaxAge 3600")]
    AgeTooLarge(u16),

    #[error("LS sequence number {0:#010x} outside the legal range 0x80000001..=0x7fffffff (RFC 2328 §12.1.6)")]
    BadSequence(u32),

    #[error("network mask must be zero for type-4 summary-LSAs, got {0}")]
    Type4MaskNonZero(std::net::Ipv4Addr),

    #[error("unknown OSPF packet type {0}")]
    BadPacketType(u8),

    #[error("unknown OSPF version {0}")]
    BadVersion(u8),

    #[error("trailing {count} bytes after {field}")]
    Trailing { field: &'static str, count: usize },

    #[error("neighbor state error: {0}")]
    Neighbor(String),

    #[error("configuration error: {0}")]
    Config(String),
}
