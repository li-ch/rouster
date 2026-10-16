//! RTR (RPKI-to-Router) protocol PDU codec.
//!
//! Wire formats per RFC 8210 §5 (protocol version 1) and
//! draft-ietf-sidrops-8210bis-27 §5 (version 2: adds the ASPA PDU, the
//! 64 KiB PDU size cap, and error codes 9–12). Version 0 (RFC 6810)
//! PDUs decode for downgrade support; the only v0 shape difference the
//! codec sees is the 12-byte End-of-Data (no timing parameters).
//!
//! Strictness policy (the A19 lesson, applied here):
//! - fixed-size PDUs must declare exactly their canonical length;
//! - variable-size PDUs must account for every byte (no trailing slack);
//! - value ranges are checked (`max_len >= prefix_len`, prefix length
//!   within the family limit, ASPA provider list strictly increasing);
//! - reserved "zero" fields are ignored on receipt (RFC 8210 §5.1 says
//!   MUST be ignored) and sent as zero;
//! - reserved flag bits are ignored on receipt, sent as zero.
//!
//! ASPA semantic violations that RFC 8210bis-27 §5.12 says the router
//! answers with Error Code 9 — announcement with no providers, AS 0 in
//! a multi-provider list, withdrawal carrying providers — decode fine
//! structurally; call [`Pdu::aspa_provider_list_error`] to detect them
//! so the session layer can emit the mandated Error Report.

use std::net::{Ipv4Addr, Ipv6Addr};

use common::{Ipv4Prefix, Ipv6Prefix, PrefixError};

/// Protocol version 0 (RFC 6810).
pub const VERSION_0: u8 = 0;
/// Protocol version 1 (RFC 8210).
pub const VERSION_1: u8 = 1;
/// Protocol version 2 (draft-ietf-sidrops-8210bis-27).
pub const VERSION_2: u8 = 2;

/// Highest protocol version this codec implements (8210bis-27 §7: the
/// router starts at its highest version and downgrades on demand).
pub const HIGHEST_VERSION: u8 = VERSION_2;

/// 8210bis-27 §5: "Limits the maximum size of a PDU to 64KB".
pub const MAX_PDU_LEN: u32 = 65_536;

/// RTR TCP service port (RFC 8210 §9, "rpki-rtr").
pub const RTR_PORT: u16 = 323;

/// PDU type codes (RFC 8210 §5; 8210bis-27 §5.12 adds type 11).
pub mod pdu_type {
    pub const SERIAL_NOTIFY: u8 = 0;
    pub const SERIAL_QUERY: u8 = 1;
    pub const RESET_QUERY: u8 = 2;
    pub const CACHE_RESPONSE: u8 = 3;
    pub const IPV4_PREFIX: u8 = 4;
    // Type 5 is reserved.
    pub const IPV6_PREFIX: u8 = 6;
    pub const END_OF_DATA: u8 = 7;
    pub const CACHE_RESET: u8 = 8;
    pub const ROUTER_KEY: u8 = 9;
    pub const ERROR_REPORT: u8 = 10;
    pub const ASPA: u8 = 11;
}

/// Error Report codes (RFC 8210 §12; 8210bis-27 §12 adds 9–12).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ErrorCode {
    CorruptData,
    InternalError,
    NoDataAvailable,
    InvalidRequest,
    UnsupportedProtocolVersion,
    UnsupportedPduType,
    WithdrawalOfUnknownRecord,
    DuplicateAnnouncementReceived,
    UnexpectedProtocolVersion,
    AspaProviderListError,
    TransportError,
    OrderingError,
    CacheRestart,
    CacheShutdown,
    /// Code point not known to this codec (the registry may have grown).
    Unknown(u16),
}

impl ErrorCode {
    pub fn from_u16(v: u16) -> Self {
        match v {
            0 => ErrorCode::CorruptData,
            1 => ErrorCode::InternalError,
            2 => ErrorCode::NoDataAvailable,
            3 => ErrorCode::InvalidRequest,
            4 => ErrorCode::UnsupportedProtocolVersion,
            5 => ErrorCode::UnsupportedPduType,
            6 => ErrorCode::WithdrawalOfUnknownRecord,
            7 => ErrorCode::DuplicateAnnouncementReceived,
            8 => ErrorCode::UnexpectedProtocolVersion,
            9 => ErrorCode::AspaProviderListError,
            10 => ErrorCode::TransportError,
            11 => ErrorCode::OrderingError,
            12 => ErrorCode::CacheRestart,
            13 => ErrorCode::CacheShutdown,
            other => ErrorCode::Unknown(other),
        }
    }

    pub fn to_u16(self) -> u16 {
        match self {
            ErrorCode::CorruptData => 0,
            ErrorCode::InternalError => 1,
            ErrorCode::NoDataAvailable => 2,
            ErrorCode::InvalidRequest => 3,
            ErrorCode::UnsupportedProtocolVersion => 4,
            ErrorCode::UnsupportedPduType => 5,
            ErrorCode::WithdrawalOfUnknownRecord => 6,
            ErrorCode::DuplicateAnnouncementReceived => 7,
            ErrorCode::UnexpectedProtocolVersion => 8,
            ErrorCode::AspaProviderListError => 9,
            ErrorCode::TransportError => 10,
            ErrorCode::OrderingError => 11,
            ErrorCode::CacheRestart => 12,
            ErrorCode::CacheShutdown => 13,
            ErrorCode::Unknown(v) => v,
        }
    }

    /// Fatal errors drop the session and flush all data learned from
    /// the cache (RFC 8210 §12; 8210bis-27 §12 marks 2, 4, 12, 13
    /// non-fatal).
    pub fn is_fatal(self) -> bool {
        !matches!(
            self,
            ErrorCode::NoDataAvailable
                | ErrorCode::UnsupportedProtocolVersion
                | ErrorCode::CacheRestart
                | ErrorCode::CacheShutdown
        )
    }
}

/// Cache timing parameters, carried by the End-of-Data PDU
/// (RFC 8210 §5.8/§6). Absent in protocol version 0.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Timing {
    pub refresh_interval: u32,
    pub retry_interval: u32,
    pub expire_interval: u32,
}

impl Timing {
    /// RFC 8210 §6 recommended defaults: refresh 3600 s, retry 600 s,
    /// expire 7200 s.
    pub const DEFAULT: Timing = Timing {
        refresh_interval: 3600,
        retry_interval: 600,
        expire_interval: 7200,
    };
}

/// Announce/withdraw flag shared by all payload PDUs (RFC 8210 §5.1:
/// lowest-order bit is 1 for announcement, 0 for withdrawal; the
/// remaining bits are reserved and ignored on receipt).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PayloadFlags {
    pub announce: bool,
}

impl PayloadFlags {
    pub const ANNOUNCE: PayloadFlags = PayloadFlags { announce: true };
    pub const WITHDRAW: PayloadFlags = PayloadFlags { announce: false };

    fn from_byte(b: u8) -> Self {
        PayloadFlags {
            announce: b & 0x01 != 0,
        }
    }

    fn to_byte(self) -> u8 {
        u8::from(self.announce)
    }
}

/// One RTR PDU, decoded version-agnostically. The wire version is
/// carried on the PDU so the session layer can enforce version
/// stability (RFC 8210 §7) after negotiation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Pdu {
    /// §5.2 — cache hints that new data is available.
    SerialNotify {
        version: u8,
        session_id: u16,
        serial: u32,
    },
    /// §5.3 — router asks for changes since `serial`.
    SerialQuery {
        version: u8,
        session_id: u16,
        serial: u32,
    },
    /// §5.4 — router asks for the whole current database.
    ResetQuery { version: u8 },
    /// §5.5 — cache confirms a query and starts a data sequence.
    CacheResponse { version: u8, session_id: u16 },
    /// §5.6 — IPv4 ROA payload (a VRP when announced).
    Ipv4Prefix {
        version: u8,
        flags: PayloadFlags,
        prefix: Ipv4Prefix,
        max_len: u8,
        asn: u32,
    },
    /// §5.7 — IPv6 ROA payload.
    Ipv6Prefix {
        version: u8,
        flags: PayloadFlags,
        prefix: Ipv6Prefix,
        max_len: u8,
        asn: u32,
    },
    /// §5.8 (8210bis-27 §5.7) — ends a data sequence. `timing` is
    /// `None` exactly when the wire version is 0 (RFC 6810 carried no
    /// intervals).
    EndOfData {
        version: u8,
        session_id: u16,
        serial: u32,
        timing: Option<Timing>,
    },
    /// §5.9 — cache cannot serve the requested incremental update.
    CacheReset { version: u8 },
    /// §5.10 — BGPsec router key, pass-through (we store but do not
    /// parse the subjectPublicKeyInfo).
    RouterKey {
        version: u8,
        flags: PayloadFlags,
        ski: [u8; 20],
        asn: u32,
        spki: Vec<u8>,
    },
    /// §5.11 — error report; either party may send.
    ErrorReport {
        version: u8,
        error_code: ErrorCode,
        erroneous_pdu: Vec<u8>,
        text: Option<String>,
    },
    /// 8210bis-27 §5.12 — ASPA object (customer AS → provider set).
    /// Version-2 only.
    Aspa {
        version: u8,
        flags: PayloadFlags,
        customer_asn: u32,
        providers: Vec<u32>,
    },
}

impl Pdu {
    /// The wire protocol version carried by this PDU.
    pub fn version(&self) -> u8 {
        match self {
            Pdu::SerialNotify { version, .. }
            | Pdu::SerialQuery { version, .. }
            | Pdu::ResetQuery { version }
            | Pdu::CacheResponse { version, .. }
            | Pdu::Ipv4Prefix { version, .. }
            | Pdu::Ipv6Prefix { version, .. }
            | Pdu::EndOfData { version, .. }
            | Pdu::CacheReset { version }
            | Pdu::RouterKey { version, .. }
            | Pdu::ErrorReport { version, .. }
            | Pdu::Aspa { version, .. } => *version,
        }
    }

    /// 8210bis-27 §5.12 ASPA provider-list violations that the router
    /// MUST answer with Error Code 9, detected after a successful
    /// structural decode.
    pub fn aspa_provider_list_error(&self) -> Option<ErrorCode> {
        let Pdu::Aspa {
            flags, providers, ..
        } = self
        else {
            return None;
        };
        if flags.announce {
            // "For an announcement, the PDU MUST contain at least one
            // Provider Autonomous System Number."
            if providers.is_empty() {
                return Some(ErrorCode::AspaProviderListError);
            }
            // "an ASPA announcement PDU containing multiple Provider
            // Autonomous System Numbers MUST NOT contain AS 0"
            if providers.len() > 1 && providers.contains(&0) {
                return Some(ErrorCode::AspaProviderListError);
            }
        } else if !providers.is_empty() {
            // "there MUST be no Provider list" on a withdrawal.
            return Some(ErrorCode::AspaProviderListError);
        }
        None
    }

    /// Encode at wire version `version`. [`Pdu::version`] must agree
    /// with it (the session never rewrites versions after negotiation,
    /// RFC 8210 §7).
    pub fn encode(&self, version: u8) -> Result<Vec<u8>, EncodeError> {
        if self.version() != version {
            return Err(EncodeError::VersionMismatch {
                pdu: self.version(),
                requested: version,
            });
        }
        let mut out = Vec::new();
        match self {
            Pdu::SerialNotify {
                session_id, serial, ..
            } => {
                out.extend_from_slice(&[version, pdu_type::SERIAL_NOTIFY]);
                out.extend_from_slice(&session_id.to_be_bytes());
                out.extend_from_slice(&12u32.to_be_bytes());
                out.extend_from_slice(&serial.to_be_bytes());
            }
            Pdu::SerialQuery {
                session_id, serial, ..
            } => {
                out.extend_from_slice(&[version, pdu_type::SERIAL_QUERY]);
                out.extend_from_slice(&session_id.to_be_bytes());
                out.extend_from_slice(&12u32.to_be_bytes());
                out.extend_from_slice(&serial.to_be_bytes());
            }
            Pdu::ResetQuery { .. } => {
                out.extend_from_slice(&[version, pdu_type::RESET_QUERY, 0, 0]);
                out.extend_from_slice(&8u32.to_be_bytes());
            }
            Pdu::CacheResponse { session_id, .. } => {
                out.extend_from_slice(&[version, pdu_type::CACHE_RESPONSE]);
                out.extend_from_slice(&session_id.to_be_bytes());
                out.extend_from_slice(&8u32.to_be_bytes());
            }
            Pdu::Ipv4Prefix {
                flags,
                prefix,
                max_len,
                asn,
                ..
            } => {
                out.extend_from_slice(&[version, pdu_type::IPV4_PREFIX, 0, 0]);
                out.extend_from_slice(&20u32.to_be_bytes());
                out.push(flags.to_byte());
                out.push(prefix.prefix_len());
                out.push(*max_len);
                out.push(0);
                out.extend_from_slice(&prefix.addr().octets());
                out.extend_from_slice(&asn.to_be_bytes());
            }
            Pdu::Ipv6Prefix {
                flags,
                prefix,
                max_len,
                asn,
                ..
            } => {
                out.extend_from_slice(&[version, pdu_type::IPV6_PREFIX, 0, 0]);
                out.extend_from_slice(&32u32.to_be_bytes());
                out.push(flags.to_byte());
                out.push(prefix.prefix_len());
                out.push(*max_len);
                out.push(0);
                out.extend_from_slice(&prefix.addr().octets());
                out.extend_from_slice(&asn.to_be_bytes());
            }
            Pdu::EndOfData {
                session_id,
                serial,
                timing,
                ..
            } => match timing {
                None if version == VERSION_0 => {
                    out.extend_from_slice(&[version, pdu_type::END_OF_DATA]);
                    out.extend_from_slice(&session_id.to_be_bytes());
                    out.extend_from_slice(&12u32.to_be_bytes());
                    out.extend_from_slice(&serial.to_be_bytes());
                }
                Some(t) if version >= VERSION_1 => {
                    out.extend_from_slice(&[version, pdu_type::END_OF_DATA]);
                    out.extend_from_slice(&session_id.to_be_bytes());
                    out.extend_from_slice(&24u32.to_be_bytes());
                    out.extend_from_slice(&serial.to_be_bytes());
                    out.extend_from_slice(&t.refresh_interval.to_be_bytes());
                    out.extend_from_slice(&t.retry_interval.to_be_bytes());
                    out.extend_from_slice(&t.expire_interval.to_be_bytes());
                }
                _ => {
                    return Err(EncodeError::VersionTiming {
                        version,
                        has_timing: timing.is_some(),
                    })
                }
            },
            Pdu::CacheReset { .. } => {
                out.extend_from_slice(&[version, pdu_type::CACHE_RESET, 0, 0]);
                out.extend_from_slice(&8u32.to_be_bytes());
            }
            Pdu::RouterKey {
                flags,
                ski,
                asn,
                spki,
                ..
            } => {
                let len = 32u32 + spki.len() as u32;
                out.extend_from_slice(&[version, pdu_type::ROUTER_KEY]);
                out.push(flags.to_byte());
                out.push(0);
                out.extend_from_slice(&len.to_be_bytes());
                out.extend_from_slice(ski);
                out.extend_from_slice(&asn.to_be_bytes());
                out.extend_from_slice(spki);
            }
            Pdu::ErrorReport {
                error_code,
                erroneous_pdu,
                text,
                ..
            } => {
                let text_bytes = text.as_deref().map(str::as_bytes).unwrap_or(&[]);
                let len = 16u32 + erroneous_pdu.len() as u32 + text_bytes.len() as u32;
                out.extend_from_slice(&[version, pdu_type::ERROR_REPORT]);
                out.extend_from_slice(&error_code.to_u16().to_be_bytes());
                out.extend_from_slice(&len.to_be_bytes());
                out.extend_from_slice(&(erroneous_pdu.len() as u32).to_be_bytes());
                out.extend_from_slice(erroneous_pdu);
                out.extend_from_slice(&(text_bytes.len() as u32).to_be_bytes());
                out.extend_from_slice(text_bytes);
            }
            Pdu::Aspa {
                flags,
                customer_asn,
                providers,
                ..
            } => {
                if version < VERSION_2 {
                    return Err(EncodeError::TypeRequiresVersion {
                        pdu_type: pdu_type::ASPA,
                        needs: VERSION_2,
                        got: version,
                    });
                }
                let len = 12u32 + 4 * providers.len() as u32;
                out.extend_from_slice(&[version, pdu_type::ASPA]);
                out.push(flags.to_byte());
                out.push(0);
                out.extend_from_slice(&len.to_be_bytes());
                out.extend_from_slice(&customer_asn.to_be_bytes());
                for p in providers {
                    out.extend_from_slice(&p.to_be_bytes());
                }
            }
        }
        debug_assert_eq!(out.len() as u32, be_u32_len(&out).unwrap_or(0));
        Ok(out)
    }

    /// Decode the PDU at the front of `buf`. Returns the PDU and the
    /// number of bytes consumed; trailing bytes are left for the next
    /// PDU. [`DecodeError::Truncated`] means `buf` holds fewer bytes
    /// than the declared length — the caller should read more.
    pub fn decode(buf: &[u8]) -> Result<(Pdu, usize), DecodeError> {
        if buf.len() < 8 {
            return Err(DecodeError::Truncated {
                have: buf.len(),
                need: 8,
            });
        }
        let version = buf[0];
        let ptype = buf[1];
        let field16 = u16::from_be_bytes([buf[2], buf[3]]);
        let declared = u32::from_be_bytes([buf[4], buf[5], buf[6], buf[7]]);
        if declared > MAX_PDU_LEN {
            return Err(DecodeError::Oversized {
                declared,
                max: MAX_PDU_LEN,
            });
        }
        if (buf.len() as u64) < u64::from(declared) {
            return Err(DecodeError::Truncated {
                have: buf.len(),
                need: declared as usize,
            });
        }
        if declared < 8 {
            return Err(DecodeError::LengthTooShort { declared, ptype });
        }
        let body = &buf[8..declared as usize];
        // Error Reports decode at any version so the session layer can
        // act on (e.g. log) even a version-mangled one; every other PDU
        // must carry a version we speak (RFC 8210 §7 / bis §7: unknown
        // version → terminate with Error Code 4 unless it was itself an
        // Error Report).
        if ptype != pdu_type::ERROR_REPORT && version > VERSION_2 {
            return Err(DecodeError::UnsupportedVersion(version));
        }

        let expect_len = |want: u32| -> Result<(), DecodeError> {
            if declared != want {
                return Err(DecodeError::BadLength {
                    ptype,
                    declared,
                    want,
                });
            }
            Ok(())
        };

        let pdu = match ptype {
            pdu_type::SERIAL_NOTIFY => {
                expect_len(12)?;
                Pdu::SerialNotify {
                    version,
                    session_id: field16,
                    serial: be_u32(body)?,
                }
            }
            pdu_type::SERIAL_QUERY => {
                expect_len(12)?;
                Pdu::SerialQuery {
                    version,
                    session_id: field16,
                    serial: be_u32(body)?,
                }
            }
            pdu_type::RESET_QUERY => {
                expect_len(8)?;
                Pdu::ResetQuery { version }
            }
            pdu_type::CACHE_RESPONSE => {
                expect_len(8)?;
                Pdu::CacheResponse {
                    version,
                    session_id: field16,
                }
            }
            pdu_type::IPV4_PREFIX => {
                expect_len(20)?;
                Pdu::Ipv4Prefix {
                    version,
                    flags: PayloadFlags::from_byte(body[0]),
                    prefix: Ipv4Prefix::new(
                        Ipv4Addr::new(body[4], body[5], body[6], body[7]),
                        check_prefix_len(body[1], 32, pdu_type::IPV4_PREFIX)?,
                    )?,
                    max_len: check_max_len(body[1], body[2], 32, pdu_type::IPV4_PREFIX)?,
                    asn: u32::from_be_bytes([body[8], body[9], body[10], body[11]]),
                }
            }
            pdu_type::IPV6_PREFIX => {
                expect_len(32)?;
                let mut addr = [0u8; 16];
                addr.copy_from_slice(&body[4..20]);
                Pdu::Ipv6Prefix {
                    version,
                    flags: PayloadFlags::from_byte(body[0]),
                    prefix: Ipv6Prefix::new(
                        Ipv6Addr::from(addr),
                        check_prefix_len(body[1], 128, pdu_type::IPV6_PREFIX)?,
                    )?,
                    max_len: check_max_len(body[1], body[2], 128, pdu_type::IPV6_PREFIX)?,
                    asn: u32::from_be_bytes([body[20], body[21], body[22], body[23]]),
                }
            }
            pdu_type::END_OF_DATA => match version {
                VERSION_0 => {
                    expect_len(12)?;
                    Pdu::EndOfData {
                        version,
                        session_id: field16,
                        serial: be_u32(body)?,
                        timing: None,
                    }
                }
                _ => {
                    expect_len(24)?;
                    Pdu::EndOfData {
                        version,
                        session_id: field16,
                        serial: be_u32(&body[0..4])?,
                        timing: Some(Timing {
                            refresh_interval: be_u32(&body[4..8])?,
                            retry_interval: be_u32(&body[8..12])?,
                            expire_interval: be_u32(&body[12..16])?,
                        }),
                    }
                }
            },
            pdu_type::CACHE_RESET => {
                expect_len(8)?;
                Pdu::CacheReset { version }
            }
            pdu_type::ROUTER_KEY => {
                if version < VERSION_1 {
                    return Err(DecodeError::TypeRequiresVersion {
                        pdu_type: ptype,
                        needs: VERSION_1,
                        got: version,
                    });
                }
                if declared < 32 {
                    return Err(DecodeError::BadLength {
                        ptype,
                        declared,
                        want: 32,
                    });
                }
                let mut ski = [0u8; 20];
                ski.copy_from_slice(&body[0..20]);
                Pdu::RouterKey {
                    version,
                    flags: PayloadFlags::from_byte(buf[2]),
                    ski,
                    asn: u32::from_be_bytes([body[20], body[21], body[22], body[23]]),
                    spki: body[24..].to_vec(),
                }
            }
            pdu_type::ERROR_REPORT => {
                if declared < 16 {
                    return Err(DecodeError::BadLength {
                        ptype,
                        declared,
                        want: 16,
                    });
                }
                // The encap/text lens bound-check BEFORE any slice:
                // the fuzzers' first catch (errreport-encap-len-oob)
                // — a u32 encap_len far past the body panicked the
                // text_len read. Both fields must fit the declared
                // body before the accounting check runs.
                let encap_len = be_u32(&body[0..4])? as usize;
                if 8 + encap_len > body.len() {
                    return Err(DecodeError::UnaccountedLength {
                        ptype,
                        declared,
                        accounted: (16 + encap_len.min(body.len())) as u32,
                    });
                }
                let text_len = be_u32(&body[4 + encap_len..8 + encap_len])? as usize;
                if 16 + encap_len + text_len != declared as usize {
                    return Err(DecodeError::UnaccountedLength {
                        ptype,
                        declared,
                        accounted: (16 + encap_len + text_len) as u32,
                    });
                }
                // Body layout: encap-len (4) | erroneous PDU | text-len (4) | text.
                let erroneous_pdu = body[4..4 + encap_len].to_vec();
                let text = if text_len > 0 {
                    Some(
                        String::from_utf8(body[8 + encap_len..8 + encap_len + text_len].to_vec())
                            .map_err(|_| DecodeError::InvalidUtf8)?,
                    )
                } else {
                    None
                };
                Pdu::ErrorReport {
                    version,
                    error_code: ErrorCode::from_u16(field16),
                    erroneous_pdu,
                    text,
                }
            }
            pdu_type::ASPA => {
                if version < VERSION_2 {
                    return Err(DecodeError::TypeRequiresVersion {
                        pdu_type: ptype,
                        needs: VERSION_2,
                        got: version,
                    });
                }
                if declared < 12 || !(declared - 12).is_multiple_of(4) {
                    return Err(DecodeError::AspaShape { declared });
                }
                let customer_asn = be_u32(&body[0..4])?;
                let mut providers = Vec::with_capacity((declared as usize - 12) / 4);
                for &quad in body[4..].as_chunks::<4>().0 {
                    providers.push(u32::from_be_bytes(quad));
                }
                // §5.12: providers are "in increasing numeric order" and
                // "MUST be unique" — a wire-format constraint.
                if providers.windows(2).any(|w| w[0] >= w[1]) {
                    return Err(DecodeError::AspaProvidersNotIncreasing);
                }
                Pdu::Aspa {
                    version,
                    flags: PayloadFlags::from_byte(buf[2]),
                    customer_asn,
                    providers,
                }
            }
            other => {
                return Err(DecodeError::UnsupportedPduType(other));
            }
        };
        Ok((pdu, declared as usize))
    }
}

// All RTR integers are network byte order (RFC 8210 §5).
fn be_u32(b: &[u8]) -> Result<u32, DecodeError> {
    let bytes: [u8; 4] = b.try_into().map_err(|_| DecodeError::Truncated {
        have: b.len(),
        need: 4,
    })?;
    Ok(u32::from_be_bytes(bytes))
}

/// Peek the declared length of the PDU at the front of `buf`; `None`
/// when the 8-byte header is not yet fully buffered. The session
/// reader uses this to frame before decoding.
pub fn be_u32_len(buf: &[u8]) -> Option<u32> {
    if buf.len() < 8 {
        return None;
    }
    Some(u32::from_be_bytes([buf[4], buf[5], buf[6], buf[7]]))
}

fn check_prefix_len(len: u8, max: u8, ptype: u8) -> Result<u8, DecodeError> {
    if len > max {
        return Err(DecodeError::PrefixLengthTooLong { ptype, len, max });
    }
    Ok(len)
}

fn check_max_len(
    prefix_len: u8,
    max_len: u8,
    family_max: u8,
    ptype: u8,
) -> Result<u8, DecodeError> {
    // RFC 8210 §5.1: Max Length "MUST NOT be less than the Prefix
    // Length element"; and it cannot exceed the family maximum.
    if max_len < prefix_len || max_len > family_max {
        return Err(DecodeError::MaxLengthInvalid {
            ptype,
            prefix_len,
            max_len,
        });
    }
    Ok(max_len)
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum EncodeError {
    #[error("pdu version {pdu} does not match session version {requested}")]
    VersionMismatch { pdu: u8, requested: u8 },
    #[error("end-of-data timing presence ({has_timing}) wrong for version {version}")]
    VersionTiming { version: u8, has_timing: bool },
    #[error("pdu type {pdu_type} requires version >= {needs}, got {got}")]
    TypeRequiresVersion { pdu_type: u8, needs: u8, got: u8 },
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum DecodeError {
    #[error("buffer holds {have} bytes but the PDU needs {need}")]
    Truncated { have: usize, need: usize },
    #[error("declared length {declared} exceeds the 64 KiB cap (8210bis-27 §5)")]
    Oversized { declared: u32, max: u32 },
    #[error("pdu type {ptype} declares length {declared}, want {want}")]
    BadLength { ptype: u8, declared: u32, want: u32 },
    #[error("pdu type {ptype} declares length {declared} < minimum header+body")]
    LengthTooShort { declared: u32, ptype: u8 },
    #[error(
        "pdu type {ptype} declares {declared} bytes but header fields account for {accounted}"
    )]
    UnaccountedLength {
        ptype: u8,
        declared: u32,
        accounted: u32,
    },
    #[error("pdu type {ptype} prefix length {len} exceeds family maximum {max}")]
    PrefixLengthTooLong { ptype: u8, len: u8, max: u8 },
    #[error("pdu type {ptype} max length {max_len} invalid for prefix length {prefix_len}")]
    MaxLengthInvalid {
        ptype: u8,
        prefix_len: u8,
        max_len: u8,
    },
    #[error("pdu type {pdu_type} requires version >= {needs}, got {got}")]
    TypeRequiresVersion { pdu_type: u8, needs: u8, got: u8 },
    #[error("protocol version {0} is not 0, 1, or 2")]
    UnsupportedVersion(u8),
    #[error("pdu type {0} is not assigned by RFC 8210 / 8210bis-27")]
    UnsupportedPduType(u8),
    #[error("aspa PDU length {declared} is not 12 + 4n")]
    AspaShape { declared: u32 },
    #[error("aspa provider list is not strictly increasing")]
    AspaProvidersNotIncreasing,
    #[error("error report text is not valid UTF-8 (RFC 8210 §5.11)")]
    InvalidUtf8,
    #[error("prefix malformed: {0}")]
    Prefix(#[from] PrefixError),
}

#[cfg(test)]
mod tests {
    use super::*;

    // ---- Golden bytes: hand-computed per the RFC diagrams. ---------

    #[test]
    fn golden_serial_notify_v1() {
        // RFC 8210 §5.2: ver 1, type 0, session 0x1234, len 12, serial 425.
        let bytes = [
            0x01, 0x00, 0x12, 0x34, 0x00, 0x00, 0x00, 0x0c, 0x00, 0x00, 0x01, 0xa9,
        ];
        let (pdu, used) = Pdu::decode(&bytes).unwrap();
        assert_eq!(used, 12);
        assert_eq!(
            pdu,
            Pdu::SerialNotify {
                version: 1,
                session_id: 0x1234,
                serial: 425
            }
        );
        assert_eq!(pdu.encode(1).unwrap(), bytes);
    }

    #[test]
    fn golden_serial_query_v1() {
        let bytes = [
            0x01, 0x01, 0xab, 0xcd, 0x00, 0x00, 0x00, 0x0c, 0xff, 0xff, 0xff, 0xf5,
        ];
        let (pdu, _) = Pdu::decode(&bytes).unwrap();
        assert_eq!(
            pdu,
            Pdu::SerialQuery {
                version: 1,
                session_id: 0xabcd,
                serial: 0xffff_fff5
            }
        );
        assert_eq!(pdu.encode(1).unwrap(), bytes);
    }

    #[test]
    fn golden_reset_query_v2() {
        let bytes = [0x02, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x08];
        let (pdu, _) = Pdu::decode(&bytes).unwrap();
        assert_eq!(pdu, Pdu::ResetQuery { version: 2 });
        assert_eq!(pdu.encode(2).unwrap(), bytes);
    }

    #[test]
    fn golden_cache_response_v1() {
        let bytes = [0x01, 0x03, 0x00, 0x42, 0x00, 0x00, 0x00, 0x08];
        let (pdu, _) = Pdu::decode(&bytes).unwrap();
        assert_eq!(
            pdu,
            Pdu::CacheResponse {
                version: 1,
                session_id: 0x42
            }
        );
    }

    #[test]
    fn golden_ipv4_prefix_roa() {
        // RFC 8210 §5.6 shape: announce 192.0.2.0/24 max 24 AS 64512.
        let bytes = [
            0x01, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x14, // header, len 20
            0x01, 0x18, 0x18, 0x00, // flags=announce, plen 24, maxlen 24, zero
            0xc0, 0x00, 0x02, 0x00, // 192.0.2.0
            0x00, 0x00, 0xfc, 0x00, // ASN 64512
        ];
        let (pdu, _) = Pdu::decode(&bytes).unwrap();
        let Pdu::Ipv4Prefix {
            flags,
            prefix,
            max_len,
            asn,
            ..
        } = &pdu
        else {
            panic!("wrong variant")
        };
        assert!(flags.announce);
        assert_eq!(prefix.to_string(), "192.0.2.0/24");
        assert_eq!(*max_len, 24);
        assert_eq!(*asn, 64512);
        assert_eq!(pdu.encode(1).unwrap(), bytes);
    }

    #[test]
    fn golden_ipv6_prefix_roa() {
        // RFC 8210 §5.7: announce 2001:db8::/32 max 48 AS 4200000000,
        // len 32. Built explicitly so each field's offset is visible.
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&[0x02, 0x06, 0x00, 0x00]);
        bytes.extend_from_slice(&32u32.to_be_bytes());
        bytes.extend_from_slice(&[0x01, 0x20, 0x30, 0x00]); // announce, /32, max 48
        bytes.extend_from_slice(&[0x20, 0x01, 0x0d, 0xb8]);
        bytes.extend_from_slice(&[0u8; 12]);
        bytes.extend_from_slice(&4_200_000_000u32.to_be_bytes());
        assert_eq!(bytes.len(), 32);
        let (pdu, _) = Pdu::decode(&bytes).unwrap();
        let Pdu::Ipv6Prefix {
            prefix,
            max_len,
            asn,
            ..
        } = &pdu
        else {
            panic!("wrong variant")
        };
        assert_eq!(prefix.to_string(), "2001:db8::/32");
        assert_eq!(*max_len, 48);
        assert_eq!(*asn, 4_200_000_000);
        assert_eq!(pdu.encode(2).unwrap(), bytes);
    }

    #[test]
    fn golden_end_of_data_v1_with_timing() {
        // RFC 8210 §5.8: len 24, serial 1, refresh 3600, retry 600,
        // expire 7200.
        let bytes = [
            0x01, 0x07, 0x12, 0x34, 0x00, 0x00, 0x00, 0x18, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00,
            0x0e, 0x10, 0x00, 0x00, 0x02, 0x58, 0x00, 0x00, 0x1c, 0x20,
        ];
        let (pdu, _) = Pdu::decode(&bytes).unwrap();
        assert_eq!(
            pdu,
            Pdu::EndOfData {
                version: 1,
                session_id: 0x1234,
                serial: 1,
                timing: Some(Timing {
                    refresh_interval: 3600,
                    retry_interval: 600,
                    expire_interval: 7200
                })
            }
        );
        assert_eq!(pdu.encode(1).unwrap(), bytes);
    }

    #[test]
    fn golden_end_of_data_v0_has_no_timing() {
        // RFC 6810 epoch: length 12, serial only. "Both flag epochs"
        // for the session-id/serial handling.
        let bytes = [
            0x00, 0x07, 0x12, 0x34, 0x00, 0x00, 0x00, 0x0c, 0x00, 0x00, 0x00, 0x2a,
        ];
        let (pdu, _) = Pdu::decode(&bytes).unwrap();
        assert_eq!(
            pdu,
            Pdu::EndOfData {
                version: 0,
                session_id: 0x1234,
                serial: 42,
                timing: None
            }
        );
        assert_eq!(pdu.encode(0).unwrap(), bytes);
        // A v1 session must not emit the v0 shape, and vice versa.
        let mut v1_on_v0_shape = bytes.to_vec();
        v1_on_v0_shape[0] = 0x01; // v1 version byte on a 12-byte EoD
        assert!(matches!(
            Pdu::decode(&v1_on_v0_shape),
            Err(DecodeError::BadLength { .. })
        ));
        let v0 = Pdu::EndOfData {
            version: 0,
            session_id: 1,
            serial: 1,
            timing: None,
        };
        assert!(matches!(
            v0.encode(1),
            Err(EncodeError::VersionMismatch { .. })
        ));
    }

    #[test]
    fn golden_cache_reset_v1() {
        let bytes = [0x01, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x08];
        assert_eq!(
            Pdu::decode(&bytes).unwrap().0,
            Pdu::CacheReset { version: 1 }
        );
    }

    #[test]
    fn golden_router_key_v1() {
        // len = 32 + spki; ski 20 octets; asn; spki DER passthrough.
        let ski = [0x11u8; 20];
        let spki = vec![0x30, 0x59, 0x30, 0x13, 0x06, 0x07];
        let pdu = Pdu::RouterKey {
            version: 1,
            flags: PayloadFlags::ANNOUNCE,
            ski,
            asn: 64512,
            spki: spki.clone(),
        };
        let bytes = pdu.encode(1).unwrap();
        assert_eq!(bytes.len(), 38);
        assert_eq!(&bytes[..2], &[0x01, 0x09]);
        assert_eq!(bytes[2], 0x01); // flags at offset 2 per §5.10
        assert_eq!(&bytes[4..8], &38u32.to_be_bytes());
        assert_eq!(&bytes[8..28], &ski);
        assert_eq!(&bytes[28..32], &64512u32.to_be_bytes());
        assert_eq!(&bytes[32..], &spki);
        let (back, used) = Pdu::decode(&bytes).unwrap();
        assert_eq!(used, 38);
        assert_eq!(back, pdu);
    }

    #[test]
    fn golden_error_report_with_text_and_encap() {
        let erroneous = [0x01, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff];
        let text = "length mismatch".to_string();
        let pdu = Pdu::ErrorReport {
            version: 1,
            error_code: ErrorCode::CorruptData,
            erroneous_pdu: erroneous.to_vec(),
            text: Some(text.clone()),
        };
        let bytes = pdu.encode(1).unwrap();
        // 16 fixed + 8 encap + 15 text ("length mismatch")
        assert_eq!(bytes.len(), 39);
        assert_eq!(&bytes[..2], &[0x01, 0x0a]);
        assert_eq!(&bytes[2..4], &0u16.to_be_bytes()); // error code 0
        assert_eq!(&bytes[8..12], &8u32.to_be_bytes());
        assert_eq!(&bytes[12..20], &erroneous);
        assert_eq!(&bytes[20..24], &15u32.to_be_bytes());
        assert_eq!(&bytes[24..], text.as_bytes());
        let (back, _) = Pdu::decode(&bytes).unwrap();
        assert_eq!(back, pdu);
    }

    #[test]
    fn golden_error_report_minimal() {
        // RFC 8210 §5.11: generic error → empty encapsulated PDU,
        // zero lengths.
        let bytes = [
            0x01, 0x0a, 0x00, 0x01, 0x00, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00,
        ];
        let (pdu, _) = Pdu::decode(&bytes).unwrap();
        assert_eq!(
            pdu,
            Pdu::ErrorReport {
                version: 1,
                error_code: ErrorCode::InternalError,
                erroneous_pdu: vec![],
                text: None,
            }
        );
        assert_eq!(pdu.encode(1).unwrap(), bytes);
    }

    #[test]
    fn golden_aspa_v2() {
        // 8210bis-27 §5.12: announce CAS 64512, providers [64500, 64501].
        let bytes = [
            0x02, 0x0b, 0x01, 0x00, 0x00, 0x00, 0x00, 0x14, 0x00, 0x00, 0xfc, 0x00, 0x00, 0x00,
            0xfb, 0xf4, 0x00, 0x00, 0xfb, 0xf5,
        ];
        let (pdu, used) = Pdu::decode(&bytes).unwrap();
        assert_eq!(used, 20);
        assert_eq!(
            pdu,
            Pdu::Aspa {
                version: 2,
                flags: PayloadFlags::ANNOUNCE,
                customer_asn: 64512,
                providers: vec![64500, 64501]
            }
        );
        assert_eq!(pdu.encode(2).unwrap(), bytes);
        // Zero-provider withdrawal: length exactly 12.
        let wdr = [
            0x02, 0x0b, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0c, 0x00, 0x00, 0xfc, 0x00,
        ];
        assert_eq!(
            Pdu::decode(&wdr).unwrap().0,
            Pdu::Aspa {
                version: 2,
                flags: PayloadFlags::WITHDRAW,
                customer_asn: 64512,
                providers: vec![]
            }
        );
    }

    // ---- Round-trips over constructed PDUs. ------------------------

    #[test]
    fn roundtrip_all_types_v2() {
        let pdus = vec![
            Pdu::SerialNotify {
                version: 2,
                session_id: 7,
                serial: 99,
            },
            Pdu::SerialQuery {
                version: 2,
                session_id: 7,
                serial: 98,
            },
            Pdu::ResetQuery { version: 2 },
            Pdu::CacheResponse {
                version: 2,
                session_id: 7,
            },
            Pdu::Ipv4Prefix {
                version: 2,
                flags: PayloadFlags::WITHDRAW,
                prefix: "10.0.0.0/8".parse().unwrap(),
                max_len: 24,
                asn: 0,
            },
            Pdu::Ipv6Prefix {
                version: 2,
                flags: PayloadFlags::ANNOUNCE,
                prefix: "2001:db8:1::/48".parse().unwrap(),
                max_len: 64,
                asn: 64512,
            },
            Pdu::EndOfData {
                version: 2,
                session_id: 7,
                serial: 100,
                timing: Some(Timing::DEFAULT),
            },
            Pdu::CacheReset { version: 2 },
            Pdu::RouterKey {
                version: 2,
                flags: PayloadFlags::ANNOUNCE,
                ski: [9u8; 20],
                asn: 1,
                spki: vec![0xde, 0xad],
            },
            Pdu::ErrorReport {
                version: 2,
                error_code: ErrorCode::NoDataAvailable,
                erroneous_pdu: vec![],
                text: Some("cache rebuilding".into()),
            },
            Pdu::Aspa {
                version: 2,
                flags: PayloadFlags::ANNOUNCE,
                customer_asn: 64512,
                providers: vec![1, 2, 3],
            },
        ];
        for pdu in pdus {
            let bytes = pdu.encode(2).unwrap();
            let (back, used) = Pdu::decode(&bytes).unwrap();
            assert_eq!(used, bytes.len());
            assert_eq!(back, pdu, "roundtrip failed for {pdu:?}");
        }
    }

    #[test]
    fn decode_multiple_pdus_from_one_buffer() {
        let a = Pdu::ResetQuery { version: 1 };
        let b = Pdu::CacheResponse {
            version: 1,
            session_id: 5,
        };
        let mut buf = a.encode(1).unwrap();
        buf.extend(b.encode(1).unwrap());
        let (first, used) = Pdu::decode(&buf).unwrap();
        assert_eq!(first, a);
        let (second, used2) = Pdu::decode(&buf[used..]).unwrap();
        assert_eq!(second, b);
        assert_eq!(used + used2, buf.len());
    }

    #[test]
    fn reserved_bits_and_zero_fields_ignored_on_receipt() {
        // RFC 8210 §5.1: reserved fields MUST be ignored on receipt.
        let mut bytes = Pdu::ResetQuery { version: 1 }.encode(1).unwrap();
        bytes[2] = 0xff; // "zero" session field
        assert_eq!(
            Pdu::decode(&bytes).unwrap().0,
            Pdu::ResetQuery { version: 1 }
        );

        let mut v4 = Pdu::Ipv4Prefix {
            version: 1,
            flags: PayloadFlags::ANNOUNCE,
            prefix: "192.0.2.0/24".parse().unwrap(),
            max_len: 24,
            asn: 64512,
        }
        .encode(1)
        .unwrap();
        v4[8] = 0xfd; // announce bit + reserved junk
        v4[11] = 0xee; // reserved zero byte after max length
        assert_eq!(
            Pdu::decode(&v4).unwrap().0,
            Pdu::Ipv4Prefix {
                version: 1,
                flags: PayloadFlags::ANNOUNCE,
                prefix: "192.0.2.0/24".parse().unwrap(),
                max_len: 24,
                asn: 64512
            }
        );
    }

    // ---- Malformed inputs (the A19 battery). -----------------------

    #[test]
    fn malformed_header_too_short() {
        assert!(matches!(
            Pdu::decode(&[0x01, 0x00]),
            Err(DecodeError::Truncated { have: 2, need: 8 })
        ));
    }

    #[test]
    fn malformed_declared_length_larger_than_buffer() {
        let mut bytes = Pdu::ResetQuery { version: 1 }.encode(1).unwrap();
        bytes[7] = 0x10; // declared 16, only 8 present
        assert!(matches!(
            Pdu::decode(&bytes),
            Err(DecodeError::Truncated { have: 8, need: 16 })
        ));
    }

    #[test]
    fn malformed_oversized_pdu_rejected() {
        let mut bytes = Pdu::ResetQuery { version: 1 }.encode(1).unwrap();
        bytes.extend_from_slice(&[0u8; 100]); // pad so declared fits in buffer
        bytes[4..8].copy_from_slice(&(MAX_PDU_LEN + 1).to_be_bytes());
        assert!(matches!(
            Pdu::decode(&bytes),
            Err(DecodeError::Oversized { .. })
        ));
    }

    #[test]
    fn malformed_wrong_fixed_lengths() {
        for (ty, len, want) in [
            (0u8, 13u32, 12u32), // Serial Notify
            (2, 9, 8),           // Reset Query
            (3, 16, 8),          // Cache Response
            (4, 21, 20),         // IPv4 Prefix
            (6, 24, 32),         // IPv6 Prefix
            (8, 12, 8),          // Cache Reset
        ] {
            let mut bytes = vec![0x01, ty, 0, 0];
            bytes.extend_from_slice(&len.to_be_bytes());
            bytes.extend_from_slice(&[0u8; 40]); // buffer large enough
            assert_eq!(
                Pdu::decode(&bytes),
                Err(DecodeError::BadLength {
                    ptype: ty,
                    declared: len,
                    want
                }),
                "type {ty}"
            );
        }
    }

    #[test]
    fn malformed_v1_end_of_data_at_v0_length() {
        let mut bytes = vec![0x01, 0x07, 0x12, 0x34];
        bytes.extend_from_slice(&12u32.to_be_bytes());
        bytes.extend_from_slice(&[0; 8]);
        assert!(matches!(
            Pdu::decode(&bytes),
            Err(DecodeError::BadLength { want: 24, .. })
        ));
    }

    #[test]
    fn malformed_prefix_value_ranges() {
        let mk = |plen: u8, maxlen: u8| -> Vec<u8> {
            let mut b = vec![0x01, 0x04, 0, 0];
            b.extend_from_slice(&20u32.to_be_bytes());
            b.extend_from_slice(&[0x01, plen, maxlen, 0x00]);
            b.extend_from_slice(&[0xc0, 0x00, 0x02, 0x00]);
            b.extend_from_slice(&64512u32.to_be_bytes());
            b
        };
        assert!(matches!(
            Pdu::decode(&mk(33, 33)),
            Err(DecodeError::PrefixLengthTooLong { .. })
        ));
        assert!(matches!(
            Pdu::decode(&mk(24, 23)),
            Err(DecodeError::MaxLengthInvalid { .. })
        ));
        assert!(matches!(
            Pdu::decode(&mk(24, 33)),
            Err(DecodeError::MaxLengthInvalid { .. })
        ));
        assert!(Pdu::decode(&mk(24, 24)).is_ok());
        let mk6 = |plen: u8, maxlen: u8| -> Vec<u8> {
            let mut b = vec![0x01, 0x06, 0, 0];
            b.extend_from_slice(&32u32.to_be_bytes());
            b.extend_from_slice(&[0x01, plen, maxlen, 0x00]);
            b.extend_from_slice(&[0u8; 16]);
            b.extend_from_slice(&64512u32.to_be_bytes());
            b
        };
        assert!(matches!(
            Pdu::decode(&mk6(129, 129)),
            Err(DecodeError::PrefixLengthTooLong { .. })
        ));
        assert!(matches!(
            Pdu::decode(&mk6(32, 130)),
            Err(DecodeError::MaxLengthInvalid { .. })
        ));
        assert!(Pdu::decode(&mk6(32, 48)).is_ok());
    }

    #[test]
    fn malformed_aspa_shapes() {
        // Not 12 + 4n.
        let bad = [
            0x02, 0x0b, 0x01, 0x00, 0x00, 0x00, 0x00, 0x0d, 0x00, 0x00, 0x00, 0x01, 0xaa,
        ];
        assert!(matches!(
            Pdu::decode(&bad),
            Err(DecodeError::AspaShape { declared: 13 })
        ));
        // Providers not strictly increasing.
        let mut dup = vec![0x02, 0x0b, 0x01, 0x00];
        dup.extend_from_slice(&20u32.to_be_bytes());
        dup.extend_from_slice(&64512u32.to_be_bytes());
        dup.extend_from_slice(&64500u32.to_be_bytes());
        dup.extend_from_slice(&64500u32.to_be_bytes());
        assert_eq!(
            Pdu::decode(&dup),
            Err(DecodeError::AspaProvidersNotIncreasing)
        );
        // Decreasing.
        let mut dec = vec![0x02, 0x0b, 0x01, 0x00];
        dec.extend_from_slice(&20u32.to_be_bytes());
        dec.extend_from_slice(&64512u32.to_be_bytes());
        dec.extend_from_slice(&64502u32.to_be_bytes());
        dec.extend_from_slice(&64501u32.to_be_bytes());
        assert_eq!(
            Pdu::decode(&dec),
            Err(DecodeError::AspaProvidersNotIncreasing)
        );
    }

    #[test]
    fn aspa_semantic_violations_decode_but_flag_code9() {
        // Announcement with no providers (bis §5.12: Error Code 9).
        let mut b = vec![0x02, 0x0b, 0x01, 0x00];
        b.extend_from_slice(&12u32.to_be_bytes());
        b.extend_from_slice(&64512u32.to_be_bytes());
        let (pdu, _) = Pdu::decode(&b).unwrap();
        assert_eq!(
            pdu.aspa_provider_list_error(),
            Some(ErrorCode::AspaProviderListError)
        );
        // AS 0 alongside a real provider.
        let mut b = vec![0x02, 0x0b, 0x01, 0x00];
        b.extend_from_slice(&20u32.to_be_bytes());
        b.extend_from_slice(&64512u32.to_be_bytes());
        b.extend_from_slice(&0u32.to_be_bytes());
        b.extend_from_slice(&64500u32.to_be_bytes());
        let (pdu, _) = Pdu::decode(&b).unwrap();
        assert_eq!(
            pdu.aspa_provider_list_error(),
            Some(ErrorCode::AspaProviderListError)
        );
        // Lone AS 0 provider is a legal announcement (an AS0 ASPA).
        let mut solo = vec![0x02, 0x0b, 0x01, 0x00];
        solo.extend_from_slice(&16u32.to_be_bytes());
        solo.extend_from_slice(&64512u32.to_be_bytes());
        solo.extend_from_slice(&0u32.to_be_bytes());
        let (pdu, _) = Pdu::decode(&solo).unwrap();
        assert_eq!(pdu.aspa_provider_list_error(), None);
        // Withdrawal carrying providers (must be length 12).
        let mut w = vec![0x02, 0x0b, 0x00, 0x00];
        w.extend_from_slice(&16u32.to_be_bytes());
        w.extend_from_slice(&64512u32.to_be_bytes());
        w.extend_from_slice(&64500u32.to_be_bytes());
        let (pdu, _) = Pdu::decode(&w).unwrap();
        assert_eq!(
            pdu.aspa_provider_list_error(),
            Some(ErrorCode::AspaProviderListError)
        );
    }

    #[test]
    fn malformed_error_report_accounting() {
        // Text length overruns the PDU.
        let mut b = vec![0x01, 0x0a, 0x00, 0x00];
        b.extend_from_slice(&20u32.to_be_bytes());
        b.extend_from_slice(&0u32.to_be_bytes()); // encapsulated length 0
        b.extend_from_slice(&8u32.to_be_bytes()); // claims 8 bytes of text
        b.extend_from_slice(b"short"); // only 5 present inside the PDU
        assert!(matches!(
            Pdu::decode(&b),
            Err(DecodeError::UnaccountedLength { .. })
        ));
    }

    #[test]
    fn malformed_error_report_invalid_utf8() {
        let mut b = vec![0x01, 0x0a, 0x00, 0x00];
        b.extend_from_slice(&19u32.to_be_bytes());
        b.extend_from_slice(&0u32.to_be_bytes());
        b.extend_from_slice(&3u32.to_be_bytes());
        b.extend_from_slice(&[0xff, 0xfe, 0xfd]);
        assert_eq!(Pdu::decode(&b), Err(DecodeError::InvalidUtf8));
    }

    #[test]
    fn malformed_unsupported_pdu_type_and_versions() {
        let mut b = vec![0x01, 0x05, 0, 0]; // type 5 reserved
        b.extend_from_slice(&8u32.to_be_bytes());
        assert_eq!(Pdu::decode(&b), Err(DecodeError::UnsupportedPduType(5)));
        // Version 7 Serial Notify.
        let mut b = vec![0x07, 0x00, 0, 0];
        b.extend_from_slice(&12u32.to_be_bytes());
        b.extend_from_slice(&[0; 4]);
        assert_eq!(Pdu::decode(&b), Err(DecodeError::UnsupportedVersion(7)));
        // ASPA at v1 is not a legal PDU for that version.
        let mut b = vec![0x01, 0x0b, 0x01, 0x00];
        b.extend_from_slice(&12u32.to_be_bytes());
        b.extend_from_slice(&64512u32.to_be_bytes());
        assert!(matches!(
            Pdu::decode(&b),
            Err(DecodeError::TypeRequiresVersion {
                needs: 2,
                got: 1,
                ..
            })
        ));
        // Router Key at v0 likewise.
        let mut b = vec![0x00, 0x09, 0x01, 0x00];
        b.extend_from_slice(&32u32.to_be_bytes());
        b.extend_from_slice(&[0u8; 24]);
        assert!(matches!(
            Pdu::decode(&b),
            Err(DecodeError::TypeRequiresVersion {
                needs: 1,
                got: 0,
                ..
            })
        ));
    }

    #[test]
    fn error_report_decodes_at_any_version() {
        // RFC 8210 §7: an unrecognized version must still let the
        // Error Report itself be read (so it can be acted on/logged).
        let mut b = vec![0x07, 0x0a, 0x00, 0x04];
        b.extend_from_slice(&16u32.to_be_bytes());
        b.extend_from_slice(&0u32.to_be_bytes());
        b.extend_from_slice(&0u32.to_be_bytes());
        let (pdu, _) = Pdu::decode(&b).unwrap();
        assert!(matches!(
            pdu,
            Pdu::ErrorReport {
                error_code: ErrorCode::UnsupportedProtocolVersion,
                ..
            }
        ));
    }

    #[test]
    fn error_code_table_roundtrip() {
        for code in 0..=13u16 {
            assert_eq!(ErrorCode::from_u16(code).to_u16(), code);
        }
        assert_eq!(ErrorCode::from_u16(999), ErrorCode::Unknown(999));
        // Fatality per bis-27 §12: 2, 4, 12, 13 non-fatal.
        for code in [0u16, 1, 3, 5, 6, 7, 8, 9, 10, 11] {
            assert!(ErrorCode::from_u16(code).is_fatal(), "code {code}");
        }
        for code in [2u16, 4, 12, 13] {
            assert!(!ErrorCode::from_u16(code).is_fatal(), "code {code}");
        }
    }

    #[test]
    fn encode_version_mismatch_rejected() {
        let pdu = Pdu::ResetQuery { version: 2 };
        assert!(matches!(
            pdu.encode(1),
            Err(EncodeError::VersionMismatch {
                pdu: 2,
                requested: 1
            })
        ));
    }
}

#[cfg(test)]
mod fuzz_catch_tests {
    use super::*;

    /// The fuzzers' first catch (2026-10-16): a u32 encap_len far
    /// past the body panicked the text_len read in ERROR_REPORT
    /// decode. Repro: crates/rpki/fuzz/crashes/errreport-encap-len-oob.bin.
    #[test]
    fn errreport_encap_len_oob_is_rejected_not_panicked() {
        let bytes = [
            0x02u8, 0x0a, 0x00, 0x02, 0x00, 0x00, 0x00, 0x10, 0x63, 0x61, 0x63, 0x68, 0x65, 0x20,
            0x72, 0x65,
        ];
        assert!(matches!(
            Pdu::decode(&bytes[..]),
            Err(DecodeError::UnaccountedLength { .. })
        ));
    }
}
