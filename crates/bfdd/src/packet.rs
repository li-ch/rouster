//! BFD Control packet codec — RFC 5880 §4.1 (header), §5 (protocol
//! specifics), §6.7 (authentication sections), and the packet-level
//! front half of the §6.8.6 receive procedure.
//!
//! [`BfdPacket::decode`] implements exactly §6.8.6 steps 1–6, in the
//! specified order (version, length, detect multiplier, reserved M
//! bit, My Discriminator); the session-level remainder of the
//! procedure (steps 7–25: demultiplexing, authentication decisions,
//! state transitions, poll/final) lives in [`crate::session`]. The
//! split is the RFC's own: steps 1–6 validate the packet in isolation,
//! steps 7+ need session context.
//!
//! Version handling: RFC 5880 §4.1 defines version 1; §6.8.6 step 1
//! discards any other version. Version 0 (the draft protocol) is
//! accepted for decode only because Appendix A's optional (non-
//! normative) automatic version negotiation switches a system to v0
//! upon receiving a v0 packet — the v0 header layout is identical, so
//! the same decoder serves both; a v0 packet is still rejected unless
//! the caller opted in ([`VersionPolicy`]).
//!
//! No fuzzing (no-nightly fence): the malformed-input table below is
//! the substitute and covers every structural error the decoder can
//! produce, per repo convention.

use std::time::Duration;

/// BFD control UDP ports: RFC 5881 §4 (single hop) and RFC 5883 §3
/// (multihop). Echo uses RFC 5881 §4's port 3785.
pub const PORT_SINGLEHOP: u16 = 3784;
pub const PORT_MULTIHOP: u16 = 4784;
pub const PORT_ECHO: u16 = 3785;

/// UDP source port range every BFD implementation must draw from so
/// the receiver can demultiplex (RFC 5881 §4: source port MUST be in
/// 49152–65535; the intentional gap from 3784 is what keeps an
/// ephemeral collision from being mistaken for a session).
pub const SOURCE_PORT_MIN: u16 = 49152;
pub const SOURCE_PORT_MAX: u16 = 65535;

/// Fixed header size before any authentication section (RFC 5880 §4.1).
pub const HEADER_LEN: u16 = 24;

/// Minimum length of a packet carrying an authentication section
/// (RFC 5880 §6.8.6 step 2: "26 if it is one" — type + length byte
/// ride ahead of every auth body).
pub const MIN_AUTH_LEN: u16 = 26;

/// Simple Password password bounds (RFC 5880 §6.7.2: "between 1 and
/// 16 bytes").
pub const PASSWORD_MAX: usize = 16;

/// Keyed MD5 digest size (RFC 5880 §6.7.3/§6.7.4: 16 bytes).
pub const MD5_DIGEST_LEN: usize = 16;

/// Keyed SHA1 digest size (RFC 5880 §6.7.5/§6.7.6: 20 bytes).
pub const SHA1_DIGEST_LEN: usize = 20;

/// BFD session state (RFC 5880 §4.1 Sta field, values per §3.3/
/// §6.8.1; the two-bit encoding is §4.1's).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum BfdState {
    AdminDown,
    Down,
    Init,
    Up,
}

impl BfdState {
    /// The two-bit Sta encoding (RFC 5880 §4.1).
    pub fn to_bits(self) -> u8 {
        match self {
            BfdState::AdminDown => 0,
            BfdState::Down => 1,
            BfdState::Init => 2,
            BfdState::Up => 3,
        }
    }

    /// Decodes the two-bit Sta field; values above 3 cannot occur in
    /// two bits, so decoding is total.
    pub fn from_bits(bits: u8) -> Self {
        match bits & 0b11 {
            0 => BfdState::AdminDown,
            1 => BfdState::Down,
            2 => BfdState::Init,
            _ => BfdState::Up,
        }
    }
}

impl std::fmt::Display for BfdState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            BfdState::AdminDown => "AdminDown",
            BfdState::Down => "Down",
            BfdState::Init => "Init",
            BfdState::Up => "Up",
        })
    }
}

/// Local diagnostic codes (RFC 5880 §4.1 Diag field, values per §6.8.1
/// and the transitions in §6.8.6–§6.8.8). Values 9–31 are unassigned;
/// they round-trip through [`Diagnostic::Unknown`] so a peer's future
/// code still logs faithfully (unknown ≠ invalid).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Diagnostic {
    None,
    /// Control Detection Time Expired (RFC 5880 §6.8.8).
    TimeExpired,
    /// Echo Function Failed (RFC 5880 §6.8.9).
    EchoFailed,
    /// Neighbor Signaled Session Down — received AdminDown/Down
    /// (RFC 5880 §6.8.6 steps 22–23).
    NeighborSignaledSessionDown,
    ForwardingPlaneReset,
    PathDown,
    ConcatenatedPathDown,
    AdminDown,
    ReverseConcatenatedPathDown,
    /// An unassigned diagnostic code (9–31).
    Unknown(u8),
}

impl Diagnostic {
    /// The five-bit Diag encoding (RFC 5880 §4.1).
    pub fn to_bits(self) -> u8 {
        match self {
            Diagnostic::None => 0,
            Diagnostic::TimeExpired => 1,
            Diagnostic::EchoFailed => 2,
            Diagnostic::NeighborSignaledSessionDown => 3,
            Diagnostic::ForwardingPlaneReset => 4,
            Diagnostic::PathDown => 5,
            Diagnostic::ConcatenatedPathDown => 6,
            Diagnostic::AdminDown => 7,
            Diagnostic::ReverseConcatenatedPathDown => 8,
            Diagnostic::Unknown(code) => code & 0x1f,
        }
    }

    /// Decodes the five-bit Diag field; codes 9–31 map to
    /// [`Diagnostic::Unknown`].
    pub fn from_bits(bits: u8) -> Self {
        match bits & 0x1f {
            0 => Diagnostic::None,
            1 => Diagnostic::TimeExpired,
            2 => Diagnostic::EchoFailed,
            3 => Diagnostic::NeighborSignaledSessionDown,
            4 => Diagnostic::ForwardingPlaneReset,
            5 => Diagnostic::PathDown,
            6 => Diagnostic::ConcatenatedPathDown,
            7 => Diagnostic::AdminDown,
            8 => Diagnostic::ReverseConcatenatedPathDown,
            other => Diagnostic::Unknown(other),
        }
    }
}

impl std::fmt::Display for Diagnostic {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let name = match self {
            Diagnostic::None => "No Diagnostic",
            Diagnostic::TimeExpired => "Control Detection Time Expired",
            Diagnostic::EchoFailed => "Echo Function Failed",
            Diagnostic::NeighborSignaledSessionDown => "Neighbor Signaled Session Down",
            Diagnostic::ForwardingPlaneReset => "Forwarding Plane Reset",
            Diagnostic::PathDown => "Path Down",
            Diagnostic::ConcatenatedPathDown => "Concatenated Path Down",
            Diagnostic::AdminDown => "Administratively Down",
            Diagnostic::ReverseConcatenatedPathDown => "Reverse Concatenated Path Down",
            Diagnostic::Unknown(_) => "Unknown Diagnostic",
        };
        write!(f, "{name} ({})", self.to_bits())
    }
}

/// Authentication section types (RFC 5880 §6.7.1). Types 2–5 need
/// MD5/SHA1 primitives this workspace deliberately does not carry (no
/// new dependencies, P2-a fence); the daemon negotiates none of them,
/// and a received section of those types parses structurally but never
/// verifies — the caller discards per §6.8.6 step 12 semantics
/// (unknown authentication type ⇒ discard).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AuthType {
    SimplePassword,
    KeyedMd5,
    MeticulousKeyedMd5,
    KeyedSha1,
    MeticulousKeyedSha1,
}

impl AuthType {
    /// The one-byte Auth Type encoding (RFC 5880 §6.7.1).
    pub fn to_bits(self) -> u8 {
        match self {
            AuthType::SimplePassword => 1,
            AuthType::KeyedMd5 => 2,
            AuthType::MeticulousKeyedMd5 => 3,
            AuthType::KeyedSha1 => 4,
            AuthType::MeticulousKeyedSha1 => 5,
        }
    }

    /// Decodes the Auth Type byte; 0 (reserved, RFC 5880 §6.7.1) and
    /// 6+ (unassigned) yield `None` — §6.8.6 step 12's "unknown
    /// authentication type" discard.
    pub fn from_bits(bits: u8) -> Option<Self> {
        match bits {
            1 => Some(AuthType::SimplePassword),
            2 => Some(AuthType::KeyedMd5),
            3 => Some(AuthType::MeticulousKeyedMd5),
            4 => Some(AuthType::KeyedSha1),
            5 => Some(AuthType::MeticulousKeyedSha1),
            _ => None,
        }
    }
}

impl std::fmt::Display for AuthType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            AuthType::SimplePassword => "Simple Password",
            AuthType::KeyedMd5 => "Keyed MD5",
            AuthType::MeticulousKeyedMd5 => "Meticulous Keyed MD5",
            AuthType::KeyedSha1 => "Keyed SHA1",
            AuthType::MeticulousKeyedSha1 => "Meticulous Keyed SHA1",
        })
    }
}

/// One authentication section (RFC 5880 §6.7). The digest-carrying
/// variants hold the peer's digest bytes opaquely: verification of
/// types 2–5 requires MD5/SHA1, which the no-new-dependencies fence
/// excludes — structural parsing and length accounting are exact, the
/// cryptographic comparison is out of scope and disclosed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuthSection {
    /// §6.7.2: Auth Len = 3 + password length, Auth Key ID + password
    /// follow the two lead bytes.
    SimplePassword { key_id: u8, password: Vec<u8> },
    /// §6.7.3/§6.7.4 (MD5) and §6.7.5/§6.7.6 (SHA1): Auth Len = 8 +
    /// digest length, Auth Key ID + one reserved byte + 32-bit
    /// sequence number + the digest.
    Keyed {
        auth_type: AuthType,
        key_id: u8,
        sequence: u32,
        digest: Vec<u8>,
    },
}

impl AuthSection {
    /// Auth Len, the length of the whole section including the type
    /// and length bytes (RFC 5880 §6.7: each subsection specifies its
    /// own Auth Len; these are the four cryptographic layouts' 24/28
    /// and Simple Password's variable form).
    pub fn auth_len(&self) -> usize {
        match self {
            AuthSection::SimplePassword { password, .. } => 3 + password.len(),
            AuthSection::Keyed { digest, .. } => 8 + digest.len(),
        }
    }

    /// The section's type.
    pub fn auth_type(&self) -> AuthType {
        match self {
            AuthSection::SimplePassword { .. } => AuthType::SimplePassword,
            AuthSection::Keyed { auth_type, .. } => *auth_type,
        }
    }
}

/// A BFD Control packet (RFC 5880 §4.1) with the fixed fields decoded
/// to names and intervals to [`Duration`] (wire microseconds).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BfdPacket {
    /// Version; 1 per RFC 5880 §4.1. 0 is carried only under
    /// Appendix A's non-normative automatic version negotiation.
    pub version: u8,
    pub diag: Diagnostic,
    pub state: BfdState,
    /// Poll bit (RFC 5880 §4.1; poll sequences per §6.5).
    pub poll: bool,
    /// Final bit (RFC 5880 §4.1).
    pub final_bit: bool,
    /// Control Plane Independent bit (RFC 5880 §4.1).
    pub control_plane_independent: bool,
    /// Authentication Present bit (RFC 5880 §4.1) — encoded from
    /// `auth` being `Some`; kept explicit so round-trips are exact.
    pub auth_present: bool,
    /// Demand Mode bit (RFC 5880 §4.1; demand mode per §6.6).
    pub demand: bool,
    /// Detection multiplier (RFC 5880 §4.1).
    pub detect_mult: u8,
    /// My Discriminator (RFC 5880 §4.1; nonzero, unique per system —
    /// §6.8.1).
    pub my_discr: u32,
    /// Your Discriminator (RFC 5880 §4.1; zero until learned).
    pub your_discr: u32,
    /// Desired Min Tx Interval (RFC 5880 §4.1, microseconds).
    pub desired_min_tx: Duration,
    /// Required Min Rx Interval (RFC 5880 §4.1, microseconds).
    pub required_min_rx: Duration,
    /// Min Echo Rx Interval (RFC 5880 §4.1, microseconds; zero
    /// disables the echo function — §6.8.9).
    pub min_echo_rx: Duration,
    /// The authentication section, when present (RFC 5880 §6.7).
    pub auth: Option<AuthSection>,
}

/// Which protocol versions [`BfdPacket::decode`] accepts — RFC 5880
/// §6.8.6 step 1 discards anything that is not the negotiated
/// version, and Appendix A (non-normative) adds the v0 compatibility
/// switch for systems that opt into automatic version negotiation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum VersionPolicy {
    /// Exactly version 1 (the RFC 5880 §6.8.6 step 1 rule).
    #[default]
    Version1Only,
    /// Version 1, or version 0 accepted as its structurally identical
    /// draft form (Appendix A compatibility).
    AcceptDraft0,
}

/// Codec errors — one variant per structural rejection the decoder's
/// slice of the receive procedure (RFC 5880 §6.8.6 steps 1–6) and the
/// auth-section rules (§6.7) can produce.
#[derive(Debug, thiserror::Error, PartialEq, Eq, Clone)]
pub enum DecodeError {
    /// §6.8.6 step 1: version other than the negotiated one.
    #[error("unsupported version {0} (expected 1; 0 needs VersionPolicy::AcceptDraft0 per RFC 5880 Appendix A)")]
    UnsupportedVersion(u8),
    /// §6.8.6 step 2: shorter than the 24-byte fixed header (or 26
    /// when the A bit promises an auth section).
    #[error("length {length} below the {minimum}-byte minimum (RFC 5880 §6.8.6 step 2)")]
    TooShort { length: u16, minimum: u16 },
    /// §6.8.6 step 3: Length field exceeds the received payload.
    #[error(
        "length {length} exceeds the {payload}-byte payload (truncated; RFC 5880 §6.8.6 step 3)"
    )]
    Truncated { length: u16, payload: usize },
    /// §6.8.6 step 4: zero detect multiplier.
    #[error("detect multiplier is zero (RFC 5880 §6.8.6 step 4)")]
    ZeroDetectMult,
    /// §6.8.6 step 5: the reserved (multipoint) flag bit is set.
    #[error("reserved M bit set (RFC 5880 §6.8.6 step 5)")]
    MultipointBit,
    /// §6.8.6 step 6: zero My Discriminator.
    #[error("my discriminator is zero (RFC 5880 §6.8.6 step 6)")]
    ZeroMyDiscriminator,
    /// §6.7.2: an Auth Len that cannot hold even its own lead bytes.
    #[error("auth length {0} below the 3-byte section minimum (RFC 5880 §6.7)")]
    AuthLenTooSmall(u16),
    /// §6.7: the section claims more bytes than the packet carries.
    #[error("auth section length {auth_len} overruns the payload (RFC 5880 §6.7)")]
    AuthOverrun { auth_len: u16, available: usize },
    /// §6.7.2: passwords are 1–16 bytes.
    #[error("simple password length {0} outside 1..=16 (RFC 5880 §6.7.2)")]
    BadPasswordLength(usize),
    /// §6.7.3–§6.7.6: digest size for the auth type.
    #[error("auth digest length {len} wrong for {auth_type} (RFC 5880 §6.7)")]
    BadDigestLength { len: usize, auth_type: AuthType },
    /// §6.8.6 step 12: reserved/unassigned auth type.
    #[error("unknown auth type {0} (RFC 5880 §6.8.6 step 12)")]
    UnknownAuthType(u8),
}

impl BfdPacket {
    /// A packet with all flags clear, zero intervals, and the given
    /// state/discriminators — the base every caller dresses before
    /// encoding.
    pub fn new(state: BfdState, my_discr: u32, your_discr: u32) -> Self {
        Self {
            version: 1,
            diag: Diagnostic::None,
            state,
            poll: false,
            final_bit: false,
            control_plane_independent: false,
            auth_present: false,
            demand: false,
            detect_mult: 3,
            my_discr,
            your_discr,
            desired_min_tx: Duration::from_secs(1),
            required_min_rx: Duration::from_secs(1),
            min_echo_rx: Duration::ZERO,
            auth: None,
        }
    }

    /// Total on-wire length (RFC 5880 §4.1 Length field): the fixed
    /// header plus the auth section when present.
    pub fn wire_len(&self) -> u16 {
        HEADER_LEN + self.auth.as_ref().map_or(0, |a| a.auth_len()) as u16
    }

    /// Serialises the packet. The M bit is always encoded zero
    /// (RFC 5880 §4.1: "MUST be zero on transmit"); the A bit mirrors
    /// `auth`. Intervals are truncated to their 32-bit wire form.
    pub fn encode(&self) -> Vec<u8> {
        let auth_len = self.auth.as_ref().map_or(0, |a| a.auth_len());
        let mut buf = Vec::with_capacity(HEADER_LEN as usize + auth_len);
        buf.push(((self.version & 0x07) << 5) | self.diag.to_bits());
        let mut flags = self.state.to_bits() << 6;
        flags |= u8::from(self.poll) << 5;
        flags |= u8::from(self.final_bit) << 4;
        flags |= u8::from(self.control_plane_independent) << 3;
        flags |= u8::from(self.auth_present || self.auth.is_some()) << 2;
        flags |= u8::from(self.demand) << 1;
        // M bit: reserved, always zero on transmit (RFC 5880 §4.1).
        buf.push(flags);
        buf.push(self.detect_mult);
        buf.push(self.wire_len() as u8);
        buf.extend_from_slice(&self.my_discr.to_be_bytes());
        buf.extend_from_slice(&self.your_discr.to_be_bytes());
        buf.extend_from_slice(&micros_u32(self.desired_min_tx).to_be_bytes());
        buf.extend_from_slice(&micros_u32(self.required_min_rx).to_be_bytes());
        buf.extend_from_slice(&micros_u32(self.min_echo_rx).to_be_bytes());
        if let Some(auth) = &self.auth {
            buf.push(auth.auth_type().to_bits());
            buf.push(auth.auth_len() as u8);
            match auth {
                AuthSection::SimplePassword { key_id, password } => {
                    buf.push(*key_id);
                    buf.extend_from_slice(password);
                }
                AuthSection::Keyed {
                    key_id,
                    sequence,
                    digest,
                    ..
                } => {
                    buf.push(*key_id);
                    buf.push(0); // reserved (RFC 5880 §6.7.3)
                    buf.extend_from_slice(&sequence.to_be_bytes());
                    buf.extend_from_slice(digest);
                }
            }
        }
        buf
    }

    /// Parses and validates a received BFD Control packet — RFC 5880
    /// §6.8.6 steps 1–6 in the specified order, then the auth section
    /// (§6.7). Bytes beyond the Length field are ignored (the Length
    /// field is authoritative per §4.1); the session-level steps 7–25
    /// are [`crate::session`]'s.
    pub fn decode(payload: &[u8], policy: VersionPolicy) -> Result<Self, DecodeError> {
        // §6.8.6 step 2 needs the header to exist before anything can
        // be read; a one-byte-short packet cannot carry a Length
        // field at all.
        if payload.len() < HEADER_LEN as usize {
            // Still surface the version first when readable, to keep
            // the diagnostic order helpful without changing which
            // packets are accepted.
            let version = payload.first().map_or(0, |b| b >> 5);
            check_version(version, policy)?;
            return Err(DecodeError::TooShort {
                length: payload.len() as u16,
                minimum: HEADER_LEN,
            });
        }
        let version = payload[0] >> 5;
        check_version(version, policy)?;

        let state_bits = (payload[1] >> 6) & 0b11;
        let auth_present = payload[1] & 0x04 != 0;
        let length = u16::from(payload[3]);

        // Step 2: below the A-bit-dependent minimum.
        let minimum = if auth_present {
            MIN_AUTH_LEN
        } else {
            HEADER_LEN
        };
        if length < minimum {
            return Err(DecodeError::TooShort { length, minimum });
        }
        // Step 3: the packet was truncated.
        if length as usize > payload.len() {
            return Err(DecodeError::Truncated {
                length,
                payload: payload.len(),
            });
        }
        let detect_mult = payload[2];
        // Step 4.
        if detect_mult == 0 {
            return Err(DecodeError::ZeroDetectMult);
        }
        // Step 5: reserved bit.
        if payload[1] & 0x01 != 0 {
            return Err(DecodeError::MultipointBit);
        }
        let my_discr = u32::from_be_bytes(payload[4..8].try_into().expect("length checked"));
        // Step 6.
        if my_discr == 0 {
            return Err(DecodeError::ZeroMyDiscriminator);
        }

        let auth = if auth_present {
            // Step 2 already guarantees length >= 26 here, so at least
            // the type and length bytes of a section exist.
            Some(decode_auth(&payload[HEADER_LEN as usize..length as usize])?)
        } else {
            if length > HEADER_LEN {
                // §4.1: the auth section is present iff A is set; a
                // length accounting for one without the bit is not a
                // packet this protocol defines.
                return Err(DecodeError::TooShort { length, minimum });
            }
            None
        };

        Ok(Self {
            version,
            diag: Diagnostic::from_bits(payload[0] & 0x1f),
            state: BfdState::from_bits(state_bits),
            poll: payload[1] & 0x20 != 0,
            final_bit: payload[1] & 0x10 != 0,
            control_plane_independent: payload[1] & 0x08 != 0,
            auth_present,
            demand: payload[1] & 0x02 != 0,
            detect_mult,
            my_discr,
            your_discr: u32::from_be_bytes(payload[8..12].try_into().expect("length checked")),
            desired_min_tx: Duration::from_micros(interval_u64(payload, 12)),
            required_min_rx: Duration::from_micros(interval_u64(payload, 16)),
            min_echo_rx: Duration::from_micros(interval_u64(payload, 20)),
            auth,
        })
    }
}

/// RFC 5880 §6.8.6 step 1's version check, parameterised by Appendix
/// A's optional v0 compatibility.
fn check_version(version: u8, policy: VersionPolicy) -> Result<(), DecodeError> {
    match (version, policy) {
        (1, _) | (0, VersionPolicy::AcceptDraft0) => Ok(()),
        (0, VersionPolicy::Version1Only) => Err(DecodeError::UnsupportedVersion(0)),
        (v, _) => Err(DecodeError::UnsupportedVersion(v)),
    }
}

/// Reads one big-endian µs interval field at `off`.
fn interval_u64(payload: &[u8], off: usize) -> u64 {
    u32::from_be_bytes(payload[off..off + 4].try_into().expect("length checked")) as u64
}

/// A Duration back to its 32-bit wire µs form (saturating; real
/// configurations are milliseconds, far under the 4294 s ceiling).
fn micros_u32(d: Duration) -> u32 {
    d.as_micros().min(u32::MAX as u128) as u32
}

/// Parses the authentication section (RFC 5880 §6.7) from the bytes
/// between the fixed header and the packet's Length boundary.
fn decode_auth(section: &[u8]) -> Result<AuthSection, DecodeError> {
    // §6.7: Auth Len covers the type and length bytes themselves.
    if section.len() < 2 {
        return Err(DecodeError::AuthLenTooSmall(section.len() as u16));
    }
    let auth_type =
        AuthType::from_bits(section[0]).ok_or(DecodeError::UnknownAuthType(section[0]))?;
    let auth_len = section[1] as u16;
    if auth_len < 3 {
        return Err(DecodeError::AuthLenTooSmall(auth_len));
    }
    if auth_len as usize > section.len() {
        return Err(DecodeError::AuthOverrun {
            auth_len,
            available: section.len(),
        });
    }
    match auth_type {
        AuthType::SimplePassword => {
            // §6.7.2: type, len, key id, password.
            let password_len = auth_len as usize - 3;
            if password_len == 0 || password_len > PASSWORD_MAX {
                return Err(DecodeError::BadPasswordLength(password_len));
            }
            Ok(AuthSection::SimplePassword {
                key_id: section[2],
                password: section[3..3 + password_len].to_vec(),
            })
        }
        AuthType::KeyedMd5 | AuthType::MeticulousKeyedMd5 => {
            // §6.7.3/§6.7.4: type, len, key id, reserved, sequence,
            // 16-byte digest.
            if section.len() < 24 || auth_len != 24 {
                return Err(DecodeError::BadDigestLength {
                    len: auth_len.saturating_sub(8) as usize,
                    auth_type,
                });
            }
            Ok(AuthSection::Keyed {
                auth_type,
                key_id: section[2],
                sequence: u32::from_be_bytes(section[4..8].try_into().expect("length checked")),
                digest: section[8..24].to_vec(),
            })
        }
        AuthType::KeyedSha1 | AuthType::MeticulousKeyedSha1 => {
            // §6.7.5/§6.7.6: same layout, 20-byte digest.
            if section.len() < 28 || auth_len != 28 {
                return Err(DecodeError::BadDigestLength {
                    len: auth_len.saturating_sub(8) as usize,
                    auth_type,
                });
            }
            Ok(AuthSection::Keyed {
                auth_type,
                key_id: section[2],
                sequence: u32::from_be_bytes(section[4..8].try_into().expect("length checked")),
                digest: section[8..28].to_vec(),
            })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Golden bytes for a plain Down packet (RFC 5880 §4.1 field
    /// order: vers|diag, sta|flags, mult, length, my, your, three
    /// intervals), every field hand-packed.
    #[test]
    fn golden_plain_down_packet() {
        let bytes = [
            0x20, // v1, diag 0
            0x40, // Sta=Down(01), all flags clear
            0x03, // detect mult 3
            0x18, // length 24
            0x11, 0x22, 0x33, 0x44, // my discr 0x11223344
            0x00, 0x00, 0x00, 0x00, // your discr 0 (not yet learned)
            0x00, 0x0f, 0x42, 0x40, // desired min tx = 1_000_000 µs
            0x00, 0x07, 0xa1, 0x20, // required min rx = 500_000 µs
            0x00, 0x00, 0x00, 0x00, // min echo rx 0 (echo off)
        ];
        let pkt = BfdPacket::decode(&bytes, VersionPolicy::Version1Only).unwrap();
        assert_eq!(pkt.version, 1);
        assert_eq!(pkt.diag, Diagnostic::None);
        assert_eq!(pkt.state, BfdState::Down);
        assert!(!pkt.poll && !pkt.final_bit && !pkt.demand);
        assert!(!pkt.control_plane_independent && !pkt.auth_present);
        assert_eq!(pkt.detect_mult, 3);
        assert_eq!(pkt.my_discr, 0x1122_3344);
        assert_eq!(pkt.your_discr, 0);
        assert_eq!(pkt.desired_min_tx, Duration::from_millis(1000));
        assert_eq!(pkt.required_min_rx, Duration::from_millis(500));
        assert_eq!(pkt.min_echo_rx, Duration::ZERO);
        assert!(pkt.auth.is_none());
        // And back: the encode of the decode is the same bytes.
        assert_eq!(pkt.encode(), bytes);
    }

    /// Golden bytes for an Up packet with every flag set that a real
    /// exchange carries (P/F excluded), plus interval round-trips.
    #[test]
    fn golden_up_packet_all_flags() {
        let bytes = [
            0x23, // v1, diag 3 (neighbor signaled down)
            0xda, // Sta=Up(11), P=0, F=1, C=1, A=0, D=1, M=0
            0x05, // detect mult 5
            0x18, // length 24
            0xde, 0xad, 0xbe, 0xef, // my
            0xca, 0xfe, 0xba, 0xbe, // your
            0x00, 0x00, 0x27, 0x10, // 10_000 µs tx
            0x00, 0x00, 0x13, 0x88, // 5_000 µs rx
            0x00, 0x00, 0x03, 0xe8, // 1_000 µs echo
        ];
        let pkt = BfdPacket::decode(&bytes, VersionPolicy::Version1Only).unwrap();
        assert_eq!(pkt.diag, Diagnostic::NeighborSignaledSessionDown);
        assert_eq!(pkt.state, BfdState::Up);
        assert!(pkt.final_bit && pkt.control_plane_independent && pkt.demand);
        assert!(!pkt.poll && !pkt.auth_present);
        assert_eq!(pkt.my_discr, 0xdead_beef);
        assert_eq!(pkt.your_discr, 0xcafe_babe);
        assert_eq!(pkt.desired_min_tx, Duration::from_micros(10_000));
        assert_eq!(pkt.required_min_rx, Duration::from_micros(5_000));
        assert_eq!(pkt.min_echo_rx, Duration::from_micros(1_000));
        assert_eq!(pkt.encode(), bytes);
    }

    /// RFC 5880 §6.7.2 Simple Password golden: Auth Len = 3 + 9, key
    /// id 7, password "rouster!" — header Length must account for it.
    #[test]
    fn golden_simple_password_auth() {
        let password = b"rouster!"; // 8 bytes
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&[0x20, 0x44, 0x03, 24 + 3 + 8]); // Down, A set
        bytes.extend_from_slice(&0x0102_0304u32.to_be_bytes());
        bytes.extend_from_slice(&0x0a0b_0c0du32.to_be_bytes());
        bytes.extend_from_slice(&1_000_000u32.to_be_bytes());
        bytes.extend_from_slice(&1_000_000u32.to_be_bytes());
        bytes.extend_from_slice(&0u32.to_be_bytes());
        bytes.extend_from_slice(&[0x01, 3 + 8, 0x07]); // type, auth len, key id
        bytes.extend_from_slice(password);
        assert_eq!(bytes.len(), 35);

        let pkt = BfdPacket::decode(&bytes, VersionPolicy::Version1Only).unwrap();
        let AuthSection::SimplePassword {
            key_id,
            password: got,
        } = pkt.auth.as_ref().expect("auth present")
        else {
            panic!("simple password expected");
        };
        assert_eq!((*key_id, got.as_slice()), (7, &password[..]));
        assert!(pkt.auth_present);
        assert_eq!(pkt.wire_len(), 35);
        assert_eq!(pkt.encode(), bytes);
    }

    /// RFC 5880 §6.7.3 Keyed MD5 golden: 24-byte auth section (Auth
    /// Len 24), reserved byte zero, sequence 42, digest bytes opaque.
    #[test]
    fn golden_keyed_md5_structure() {
        let digest: Vec<u8> = (0..16).collect();
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&[0x20, 0x44, 0x03, 24 + 24]); // A set
        bytes.extend_from_slice(&1u32.to_be_bytes());
        bytes.extend_from_slice(&2u32.to_be_bytes());
        bytes.extend_from_slice(&300_000u32.to_be_bytes());
        bytes.extend_from_slice(&300_000u32.to_be_bytes());
        bytes.extend_from_slice(&0u32.to_be_bytes());
        bytes.extend_from_slice(&[0x02, 24, 0x09, 0x00]); // type 2, len 24, key 9, reserved
        bytes.extend_from_slice(&42u32.to_be_bytes());
        bytes.extend_from_slice(&digest);

        let pkt = BfdPacket::decode(&bytes, VersionPolicy::Version1Only).unwrap();
        let AuthSection::Keyed {
            auth_type,
            key_id,
            sequence,
            digest: got,
        } = pkt.auth.as_ref().expect("auth present")
        else {
            panic!("keyed expected");
        };
        assert_eq!(*auth_type, AuthType::KeyedMd5);
        assert_eq!(*key_id, 9);
        assert_eq!(*sequence, 42);
        assert_eq!(got, &digest);
        assert_eq!(pkt.encode(), bytes);
    }

    /// Round-trip across the full state × diag × flags × auth-shape
    /// matrix — every decodable field survives encode→decode.
    #[test]
    fn round_trip_field_matrix() {
        let states = [
            BfdState::AdminDown,
            BfdState::Down,
            BfdState::Init,
            BfdState::Up,
        ];
        let diags = [
            Diagnostic::None,
            Diagnostic::TimeExpired,
            Diagnostic::EchoFailed,
            Diagnostic::NeighborSignaledSessionDown,
            Diagnostic::ForwardingPlaneReset,
            Diagnostic::PathDown,
            Diagnostic::ConcatenatedPathDown,
            Diagnostic::AdminDown,
            Diagnostic::ReverseConcatenatedPathDown,
            Diagnostic::Unknown(17),
        ];
        let auths = [
            None,
            Some(AuthSection::SimplePassword {
                key_id: 1,
                password: b"k".to_vec(),
            }),
            Some(AuthSection::SimplePassword {
                key_id: 255,
                password: vec![0xab; 16],
            }),
            Some(AuthSection::Keyed {
                auth_type: AuthType::MeticulousKeyedMd5,
                key_id: 4,
                sequence: u32::MAX,
                digest: vec![0x55; MD5_DIGEST_LEN],
            }),
            Some(AuthSection::Keyed {
                auth_type: AuthType::KeyedSha1,
                key_id: 4,
                sequence: 0,
                digest: vec![0x77; SHA1_DIGEST_LEN],
            }),
        ];
        for &state in &states {
            for &diag in &diags {
                for &poll in &[false, true] {
                    for &final_bit in &[false, true] {
                        for &cpi in &[false, true] {
                            for &demand in &[false, true] {
                                for auth in &auths {
                                    let pkt = BfdPacket {
                                        version: 1,
                                        diag,
                                        state,
                                        poll,
                                        final_bit,
                                        control_plane_independent: cpi,
                                        auth_present: auth.is_some(),
                                        demand,
                                        detect_mult: 7,
                                        my_discr: 0x0102_0304,
                                        your_discr: 0x0506_0708,
                                        desired_min_tx: Duration::from_micros(123_456),
                                        required_min_rx: Duration::from_micros(654_321),
                                        min_echo_rx: Duration::from_micros(50_000),
                                        auth: auth.clone(),
                                    };
                                    let bytes = pkt.encode();
                                    assert_eq!(bytes.len(), pkt.wire_len() as usize);
                                    let back =
                                        BfdPacket::decode(&bytes, VersionPolicy::Version1Only)
                                            .expect("round trip decodes");
                                    assert_eq!(back, pkt);
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    /// Malformed-input table, one rejection per decoder error: the
    /// no-nightly fuzz substitute (every structural error the decoder
    /// can produce is pinned).
    #[test]
    fn malformed_input_table() {
        let base = BfdPacket::new(BfdState::Down, 1, 0);
        let good = base.encode();

        // §6.8.6 step 1: wrong version.
        let mut b = good.clone();
        b[0] = 0x40; // version 2
        assert_eq!(
            BfdPacket::decode(&b, VersionPolicy::Version1Only),
            Err(DecodeError::UnsupportedVersion(2))
        );
        // Appendix A: version 0 needs the opt-in policy.
        b[0] = 0x00;
        assert_eq!(
            BfdPacket::decode(&b, VersionPolicy::Version1Only),
            Err(DecodeError::UnsupportedVersion(0))
        );
        assert!(BfdPacket::decode(&b, VersionPolicy::AcceptDraft0).is_ok());

        // Step 2: below-minimum Length fields.
        let mut b = good.clone();
        b[3] = 23;
        assert_eq!(
            BfdPacket::decode(&b, VersionPolicy::Version1Only),
            Err(DecodeError::TooShort {
                length: 23,
                minimum: 24
            })
        );
        b[1] |= 0x04; // A set
        b[3] = 25;
        assert_eq!(
            BfdPacket::decode(&b, VersionPolicy::Version1Only),
            Err(DecodeError::TooShort {
                length: 25,
                minimum: 26
            })
        );

        // Step 3: Length beyond the payload (truncation).
        let mut b = good.clone();
        b[3] = 30;
        assert_eq!(
            BfdPacket::decode(&b, VersionPolicy::Version1Only),
            Err(DecodeError::Truncated {
                length: 30,
                payload: 24
            })
        );

        // Step 4: zero multiplier.
        let mut b = good.clone();
        b[2] = 0;
        assert_eq!(
            BfdPacket::decode(&b, VersionPolicy::Version1Only),
            Err(DecodeError::ZeroDetectMult)
        );

        // Step 5: reserved M bit set.
        let mut b = good.clone();
        b[1] |= 0x01;
        assert_eq!(
            BfdPacket::decode(&b, VersionPolicy::Version1Only),
            Err(DecodeError::MultipointBit)
        );

        // Step 6: zero My Discriminator.
        let mut b = good.clone();
        b[4] = 0;
        b[5] = 0;
        b[6] = 0;
        b[7] = 0;
        assert_eq!(
            BfdPacket::decode(&b, VersionPolicy::Version1Only),
            Err(DecodeError::ZeroMyDiscriminator)
        );

        // Physically short payloads, with and without a readable
        // version byte.
        assert_eq!(
            BfdPacket::decode(&[], VersionPolicy::Version1Only),
            Err(DecodeError::UnsupportedVersion(0)) // version of an empty payload reads 0
        );
        let mut b = good.clone();
        b.truncate(20);
        assert_eq!(
            BfdPacket::decode(&b, VersionPolicy::Version1Only),
            Err(DecodeError::TooShort {
                length: 20,
                minimum: 24
            })
        );

        // §4.1: Length accounting for an auth section with A clear is
        // not a defined packet (the trailing bytes exist, so this is
        // the A-bit rule, not truncation).
        let mut b = good.clone();
        b.extend_from_slice(&[0, 0, 0]);
        b[3] = 27;
        assert!(matches!(
            BfdPacket::decode(&b, VersionPolicy::Version1Only),
            Err(DecodeError::TooShort { .. })
        ));

        // §4.1: A set with exactly the bare header length is caught
        // by step 2 (24 < 26 with A set) — the A bit always has at
        // least the section's lead bytes to chew on.
        let mut b = good.clone();
        b[1] |= 0x04;
        assert_eq!(
            BfdPacket::decode(&b, VersionPolicy::Version1Only),
            Err(DecodeError::TooShort {
                length: 24,
                minimum: 26
            })
        );
    }

    /// §6.7's own malformed table: auth lengths, password bounds,
    /// digest sizes, unknown types.
    #[test]
    fn malformed_auth_table() {
        let authed = BfdPacket {
            auth: Some(AuthSection::SimplePassword {
                key_id: 1,
                password: b"secret-key".to_vec(),
            }),
            auth_present: true,
            ..BfdPacket::new(BfdState::Up, 9, 8)
        };
        let bytes = authed.encode();
        assert_eq!(bytes.len(), 24 + 3 + 10);

        // §6.7: Auth Len below its own 3-byte minimum.
        let mut b = bytes.clone();
        let at = 24; // auth section offset
        b[at + 1] = 2;
        assert_eq!(
            BfdPacket::decode(&b, VersionPolicy::Version1Only),
            Err(DecodeError::AuthLenTooSmall(2))
        );

        // §6.7: section overruns the packet.
        let mut b = bytes.clone();
        b[at + 1] = 40;
        assert!(matches!(
            BfdPacket::decode(&b, VersionPolicy::Version1Only),
            Err(DecodeError::AuthOverrun { auth_len: 40, .. })
        ));

        // §6.7.2: password lengths 0 and 17 are both out of bounds
        // (the payload is padded so the Length field is honest and
        // the rejection is the password rule, not truncation).
        let bad_lengths = [
            (3usize, DecodeError::BadPasswordLength(0)),
            (20, DecodeError::BadPasswordLength(17)),
        ];
        for (total, err) in bad_lengths {
            let mut b = bytes.clone();
            b[at + 1] = total as u8;
            b[3] = (24 + total) as u8;
            b.resize(24 + total, 0);
            assert_eq!(BfdPacket::decode(&b, VersionPolicy::Version1Only), Err(err));
        }

        // §6.7.1: reserved (0) and unassigned (6) auth types.
        for &ty in &[0u8, 6, 255] {
            let mut b = bytes.clone();
            b[at] = ty;
            assert_eq!(
                BfdPacket::decode(&b, VersionPolicy::Version1Only),
                Err(DecodeError::UnknownAuthType(ty))
            );
        }

        // §6.7.3: Keyed MD5 with a digest-sized hole (Auth Len 20).
        let mut md5 = BfdPacket::new(BfdState::Up, 9, 8);
        md5.auth = Some(AuthSection::Keyed {
            auth_type: AuthType::KeyedMd5,
            key_id: 1,
            sequence: 1,
            digest: vec![0; MD5_DIGEST_LEN],
        });
        md5.auth_present = true;
        let mut b = md5.encode();
        b[24] = 0x02; // type
        b[25] = 20; // wrong Auth Len (must be 24)
        b[3] = 24 + 24;
        assert!(matches!(
            BfdPacket::decode(&b, VersionPolicy::Version1Only),
            Err(DecodeError::BadDigestLength {
                auth_type: AuthType::KeyedMd5,
                ..
            })
        ));

        // §6.7.5: Keyed SHA1 needs 28; 24 is the MD5 size.
        let mut b = md5.encode();
        b[24] = 0x04; // KeyedSha1
                      // Auth Len stays 24 — wrong for SHA1's 20-byte digest.
        assert!(matches!(
            BfdPacket::decode(&b, VersionPolicy::Version1Only),
            Err(DecodeError::BadDigestLength {
                auth_type: AuthType::KeyedSha1,
                ..
            })
        ));
    }

    /// Bytes past the Length field are ignored — the Length field is
    /// authoritative (RFC 5880 §4.1); receivers must not treat
    /// trailing padding as structure.
    #[test]
    fn trailing_bytes_beyond_length_are_ignored() {
        let base = BfdPacket::new(BfdState::Init, 5, 6);
        let mut padded = base.encode();
        padded.extend_from_slice(&[0xff, 0xff, 0xff, 0xff]);
        let pkt = BfdPacket::decode(&padded, VersionPolicy::Version1Only).unwrap();
        assert_eq!(pkt, base);
    }

    /// Every Sta and Diag encoding round-trips through its bit width
    /// (§4.1), including the unknown-diagnostic passthrough.
    #[test]
    fn state_and_diag_bit_encoding_is_total() {
        for bits in 0..4u8 {
            assert_eq!(BfdState::from_bits(bits).to_bits(), bits);
        }
        for bits in 0..32u8 {
            assert_eq!(Diagnostic::from_bits(bits).to_bits(), bits);
        }
        assert_eq!(Diagnostic::from_bits(17), Diagnostic::Unknown(17));
        assert_eq!(Diagnostic::Unknown(0x1d).to_bits(), 0x1d);
        // The five-bit mask drops high garbage rather than panicking.
        assert_eq!(Diagnostic::Unknown(0x3f).to_bits(), 0x1f);
    }

    /// Ports named for the RFCs that define them (RFC 5881 §4;
    /// RFC 5883 §3) — the constants the transports bind.
    #[test]
    fn ports_match_the_rfcs() {
        assert_eq!(PORT_SINGLEHOP, 3784);
        assert_eq!(PORT_MULTIHOP, 4784);
        assert_eq!(PORT_ECHO, 3785);
        assert_eq!((SOURCE_PORT_MIN, SOURCE_PORT_MAX), (49152, 65535));
    }
}
