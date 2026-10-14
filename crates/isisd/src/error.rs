//! Error types for the IS-IS codec, database and state machines
//! (`thiserror`, the workspace convention — the ospfd shape).

/// Every malformed-input rejection in the codec funnels into this
/// enum. Variants name the exact field that failed and carry the
/// offending value so logs can pinpoint wire breakage (the A19
/// post-mortem shape).
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum IsisError {
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

    /// ISO 10589 §9.5.2: the intra-domain routeing protocol
    /// discriminator is 0x83.
    #[error("protocol discriminator is {0:#04x}, not 0x83 (ISO 10589 §9.5.2)")]
    BadDiscriminator(u8),

    #[error("version {0} is neither 1 (common header) nor 1 (PDU-specific)")]
    BadVersion(u8),

    #[error("unknown PDU type {0}")]
    BadPduType(u8),

    /// ISO 10589 §9.5.2: the length indicator gives the fixed header
    /// size and must equal the PDU type's fixed part.
    #[error("length indicator {found}, expected {expected} for this PDU type")]
    BadLengthIndicator { expected: u8, found: u8 },

    /// ID length 0 (meaning 6) is the only deployed encoding; ISO
    /// 10589 permits 1..=8 and 0 (the fixed 6). Others are rejected
    /// strictly (divergence disclosed: no deployment carries them).
    #[error("ID length {0} unsupported (0 = the 6-octet system ID is the only form accepted)")]
    BadIdLength(u8),

    #[error("reserved bits set in {field}: {value:#04x}")]
    ReservedBits { field: &'static str, value: u8 },

    #[error("TLV {kind} length {declared} leaves {actual} bytes in the value")]
    BadTlvLength {
        kind: u8,
        declared: usize,
        actual: usize,
    },

    #[error("TLV {kind} value length {len} is not a multiple of its {entry} byte entries")]
    BadTlvEntrySize { kind: u8, len: usize, entry: usize },

    #[error("sub-TLV {kind} under TLV {parent} overruns the {available} bytes available")]
    BadSubTlv {
        parent: u8,
        kind: u8,
        available: usize,
    },

    #[error("IS-IS level {0} is not 1 or 2")]
    BadLevel(u8),

    /// The LSP type block's IS type field (ISO 10589 §9.8): 1 = an
    /// L1 IS, 3 = an L2 IS (0 and 2 are unused on the wire).
    #[error("IS type {0} in the LSP type block is not 1 (L1) or 3 (L2)")]
    BadIsType(u8),

    /// RFC 5303 §3: the adjacency three-way state is 0, 1 or 2.
    #[error("three-way adjacency state {0} is not 0 (Up), 1 (Initializing) or 2 (Down)")]
    BadThreewayState(u8),

    #[error("LSP checksum mismatch: header says {header:#06x}, computed {computed:#06x}")]
    ChecksumMismatch { header: u16, computed: u16 },

    #[error("LSP checksum field is zero (the Fletcher octets are always nonzero)")]
    ZeroChecksum,

    /// ISO 10589 §7.3.16.3: a Remaining Lifetime above MaxAge is
    /// processed as a checksum error.
    #[error("remaining lifetime {0} exceeds MaxAge {1}")]
    AgeTooLarge(u16, u16),

    /// RFC 5301 §2: the hostname is a printable ASCII string.
    #[error("hostname TLV carries non-printable byte {0:#04x}")]
    BadHostnameByte(u8),

    /// An area address is 1..=13 bytes (an NSAP tops out at 20 bytes
    /// — FRR's `ISO_ADDR_SIZE` — and the system ID + NSEL occupy 7 of
    /// them); the TLV carries each one length-prefixed.
    #[error("area address length {0} outside 1..=13")]
    BadAreaLength(usize),

    #[error("authentication TLV carries no type octet")]
    BadAuthShape,

    #[error("trailing {count} bytes after {field}")]
    Trailing { field: &'static str, count: usize },

    #[error("adjacency state error: {0}")]
    Adjacency(String),

    #[error("configuration error: {0}")]
    Config(String),
}
