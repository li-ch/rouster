//! BGP capabilities (RFC 5492): the `<Capability Code, Capability
//! Length, Capability Value>` triples carried inside the OPEN message's
//! Capability Optional Parameter (Parameter Type 2).
//!
//! Understood v1: Multiprotocol Extensions (code 1, RFC 4760), Route
//! Refresh (code 2, RFC 2918), Four-octet AS Number (code 65, RFC
//! 6793). Anything else decodes as [`Capability::Unknown`] — preserved
//! on the session's capability record, never acted on (unknown
//! capabilities MUST be ignored per RFC 5492 §2).

use crate::error::{BgpError, BgpResult};
use crate::wire::Reader;

pub mod capability_code {
    pub const MULTIPROTOCOL_EXTENSIONS: u8 = 1;
    pub const ROUTE_REFRESH: u8 = 2;
    pub const FOUR_OCTET_AS_NUMBER: u8 = 65;
}

/// One advertised capability.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Capability {
    /// Code 1: `<AFI(2), Reserved(1), SAFI(1)>` (RFC 4760 §7).
    Multiprotocol { afi: u16, safi: u8 },
    /// Code 2: empty value (RFC 2918 §3).
    RouteRefresh,
    /// Code 65: the 4-octet AS number (RFC 6793 §2).
    FourOctetAsNumber { asn: u32 },
    /// Unrecognized code: value kept verbatim for logging.
    Unknown { code: u8, value: Vec<u8> },
}

impl Capability {
    pub fn code(&self) -> u8 {
        match self {
            Self::Multiprotocol { .. } => capability_code::MULTIPROTOCOL_EXTENSIONS,
            Self::RouteRefresh => capability_code::ROUTE_REFRESH,
            Self::FourOctetAsNumber { .. } => capability_code::FOUR_OCTET_AS_NUMBER,
            Self::Unknown { code, .. } => *code,
        }
    }

    pub fn encode_value(&self, out: &mut Vec<u8>) {
        match self {
            Self::Multiprotocol { afi, safi } => {
                out.extend_from_slice(&afi.to_be_bytes());
                out.push(0); // reserved
                out.push(*safi);
            }
            Self::RouteRefresh => {}
            Self::FourOctetAsNumber { asn } => out.extend_from_slice(&asn.to_be_bytes()),
            Self::Unknown { value, .. } => out.extend_from_slice(value),
        }
    }
}

/// Decodes a run of capability triples (the body of one Capability
/// Optional Parameter). The slice is the *declared* parameter value —
/// any trailing garbage is a malformed parameter, not silence.
pub fn decode_capabilities(buf: &[u8]) -> BgpResult<Vec<Capability>> {
    let mut r = Reader::new(buf);
    let mut caps = Vec::new();
    while !r.is_empty() {
        let code = r
            .u8()
            .ok_or_else(|| BgpError::local("truncated capability header"))?;
        let len = r
            .u8()
            .ok_or_else(|| BgpError::local("truncated capability length"))?;
        let value = r
            .take(len as usize)
            .ok_or_else(|| BgpError::local(format!("capability {code} overruns parameter")))?;
        caps.push(match code {
            capability_code::MULTIPROTOCOL_EXTENSIONS => {
                let mut vr = Reader::new(value);
                let afi = vr.u16();
                let reserved = vr.u8();
                let safi = vr.u8();
                match (afi, reserved, safi, vr.is_empty()) {
                    // AFI(2) + Reserved(1) + SAFI(1), nothing more.
                    (Some(afi), Some(_), Some(safi), true) => {
                        Capability::Multiprotocol { afi, safi }
                    }
                    _ => return Err(BgpError::local("malformed multiprotocol capability value")),
                }
            }
            capability_code::ROUTE_REFRESH => {
                if value.is_empty() {
                    Capability::RouteRefresh
                } else {
                    return Err(BgpError::local("route refresh capability with data"));
                }
            }
            capability_code::FOUR_OCTET_AS_NUMBER => {
                if value.len() == 4 {
                    Capability::FourOctetAsNumber {
                        asn: u32::from_be_bytes([value[0], value[1], value[2], value[3]]),
                    }
                } else {
                    return Err(BgpError::local("four-octet AS capability not 4 bytes"));
                }
            }
            code => Capability::Unknown {
                code,
                value: value.to_vec(),
            },
        });
    }
    Ok(caps)
}

/// Encodes capabilities into one parameter value (no parameter header).
pub fn encode_capabilities(caps: &[Capability], out: &mut Vec<u8>) {
    for cap in caps {
        let mut value = Vec::new();
        cap.encode_value(&mut value);
        out.push(cap.code());
        out.push(value.len() as u8);
        out.extend_from_slice(&value);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// FRR-style IPv4/IPv6 unicast + 4-byte AS + route refresh run.
    fn caps() -> Vec<Capability> {
        vec![
            Capability::Multiprotocol { afi: 1, safi: 1 },
            Capability::Multiprotocol { afi: 2, safi: 1 },
            Capability::RouteRefresh,
            Capability::FourOctetAsNumber { asn: 4200000000u32 },
        ]
    }

    #[test]
    fn round_trips() {
        let mut buf = Vec::new();
        encode_capabilities(&caps(), &mut buf);
        assert_eq!(decode_capabilities(&buf).unwrap(), caps());
    }

    #[test]
    fn four_octet_as_value_is_be_u32() {
        let mut buf = Vec::new();
        encode_capabilities(&[Capability::FourOctetAsNumber { asn: 65000 }], &mut buf);
        assert_eq!(buf, vec![65, 4, 0x00, 0x00, 0xfd, 0xe8]);
    }

    #[test]
    fn multiprotocol_value_carries_reserved_byte() {
        let mut buf = Vec::new();
        encode_capabilities(&[Capability::Multiprotocol { afi: 2, safi: 1 }], &mut buf);
        // code 1, len 4, AFI 0002, reserved 00, SAFI 01 (RFC 4760 §7)
        assert_eq!(buf, vec![1, 4, 0x00, 0x02, 0x00, 0x01]);
    }

    #[test]
    fn unknown_capability_is_preserved_and_ignored() {
        let mut buf = Vec::new();
        encode_capabilities(
            &[
                Capability::Unknown {
                    code: 69,
                    value: vec![1, 2, 3],
                },
                Capability::RouteRefresh,
            ],
            &mut buf,
        );
        assert_eq!(
            decode_capabilities(&buf).unwrap(),
            vec![
                Capability::Unknown {
                    code: 69,
                    value: vec![1, 2, 3]
                },
                Capability::RouteRefresh
            ]
        );
    }

    #[test]
    fn capability_length_overrun_rejected() {
        // Declares 3 bytes of value, holds 1.
        assert!(decode_capabilities(&[2, 3, 0x00]).is_err());
    }

    #[test]
    fn truncated_header_rejected() {
        assert!(decode_capabilities(&[1]).is_err());
        assert!(decode_capabilities(&[1, 4, 0x00]).is_err());
    }

    #[test]
    fn bad_multiprotropic_length_rejected() {
        assert!(decode_capabilities(&[1, 3, 0x00, 0x01, 0x01]).is_err());
    }
}
