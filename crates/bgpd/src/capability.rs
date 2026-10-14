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
    /// Graceful Restart (RFC 4724 §3).
    pub const GRACEFUL_RESTART: u8 = 64;
    /// Multiple Paths / ADD-PATH (RFC 7911 §2).
    pub const ADD_PATH: u8 = 69;
}

/// One `<AFI, SAFI, Send/Receive>` tuple of the ADD-PATH capability
/// (RFC 7911 §4). Send/Receive: 1 = receive, 2 = send, 3 = both.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AddPathFamily {
    pub afi: u16,
    pub safi: u8,
    pub send_receive: u8,
}

impl AddPathFamily {
    /// The §4-valid Send/Receive values (1 receive, 2 send, 3 both).
    pub fn send_receive_valid(self) -> bool {
        matches!(self.send_receive, 1..=3)
    }
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
    /// Code 64 (RFC 4724 §3): 2 restart octets — the Restart State
    /// (R) bit in the top bit, a 12-bit Restart Time in seconds —
    /// followed by up to 63 `<AFI(2), SAFI(1), Flags(1)>` triples
    /// whose top flag bit is the per-family Forwarding State (F)
    /// bit. An empty family list = receiving-side support only.
    /// RFC 8538 §2 defines the second-most-significant Restart Flags
    /// bit as the Graceful Notification ("N") bit — "used to indicate
    /// Graceful Restart support for BGP NOTIFICATION messages".
    GracefulRestart {
        restart_state: bool,
        graceful_notification: bool,
        restart_time: u16,
        families: Vec<(u16, u8, bool)>,
    },
    /// Code 69 (RFC 7911 §4): one or more `<AFI(2), SAFI(1),
    /// Send/Receive(1)>` tuples in a **single instance** (the RFC's
    /// MUST: multi-family speakers merge into one capability).
    /// Send/Receive: 1 = willing to receive, 2 = willing to send,
    /// 3 = both. A value outside 1..=3 makes the *whole capability*
    /// "treated as not understood and ignored" (§4, a SHOULD) — the
    /// codec keeps it; consumers ([`crate::message::BgpOpen::add_path`])
    /// ignore it.
    AddPath(Vec<AddPathFamily>),
    /// Unrecognized code: value kept verbatim for logging.
    Unknown { code: u8, value: Vec<u8> },
}

impl Capability {
    pub fn code(&self) -> u8 {
        match self {
            Self::Multiprotocol { .. } => capability_code::MULTIPROTOCOL_EXTENSIONS,
            Self::RouteRefresh => capability_code::ROUTE_REFRESH,
            Self::FourOctetAsNumber { .. } => capability_code::FOUR_OCTET_AS_NUMBER,
            Self::GracefulRestart { .. } => capability_code::GRACEFUL_RESTART,
            Self::AddPath { .. } => capability_code::ADD_PATH,
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
            Self::GracefulRestart {
                restart_state,
                graceful_notification,
                restart_time,
                families,
            } => {
                let restart = (*restart_state as u16) << 15
                    | (*graceful_notification as u16) << 14
                    | (restart_time & 0x0fff);
                out.extend_from_slice(&restart.to_be_bytes());
                for (afi, safi, forwarding) in families {
                    out.extend_from_slice(&afi.to_be_bytes());
                    out.push(*safi);
                    out.push((*forwarding as u8) << 7);
                }
            }
            Self::AddPath(tuples) => {
                // One instance, every tuple inline (RFC 7911 §4 MUST:
                // multi-family support rides a single capability).
                for t in tuples {
                    out.extend_from_slice(&t.afi.to_be_bytes());
                    out.push(t.safi);
                    out.push(t.send_receive);
                }
            }
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
            capability_code::ADD_PATH => {
                // RFC 7911 §4: "one or more tuples", each 4 octets —
                // any other length is malformed (module precedent for
                // known codes: error, not ignore). An invalid
                // Send/Receive *value* is NOT malformed: §4 says the
                // capability is then treated as not understood and
                // ignored — a consumer-side decision, so the codec
                // keeps the tuple and [`AddPathFamily::send_receive_valid`]
                // answers it.
                if value.is_empty() || !value.len().is_multiple_of(4) {
                    return Err(BgpError::local(
                        "add-path capability length not 4n (RFC 7911 §4)",
                    ));
                }
                Capability::AddPath(
                    value
                        .as_chunks::<4>()
                        .0
                        .iter()
                        .map(|c| AddPathFamily {
                            afi: u16::from_be_bytes([c[0], c[1]]),
                            safi: c[2],
                            send_receive: c[3],
                        })
                        .collect(),
                )
            }
            capability_code::GRACEFUL_RESTART => {
                // 2 restart octets + 4-octet family triples (RFC 4724
                // §3; at most 63 triples, so the value caps at 254).
                if value.len() < 2 || (value.len() - 2) % 4 != 0 || value.len() > 2 + 63 * 4 {
                    return Err(BgpError::local(
                        "graceful restart capability length not 2+4n",
                    ));
                }
                let restart = u16::from_be_bytes([value[0], value[1]]);
                let mut families = Vec::new();
                for chunk in value[2..].as_chunks::<4>().0 {
                    families.push((
                        u16::from_be_bytes([chunk[0], chunk[1]]),
                        chunk[2],
                        chunk[3] & 0x80 != 0,
                    ));
                }
                Capability::GracefulRestart {
                    restart_state: restart & 0x8000 != 0,
                    graceful_notification: restart & 0x4000 != 0,
                    restart_time: restart & 0x0fff,
                    families,
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
                    code: 80,
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
                    code: 80,
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

    // ---- RFC 4724 Graceful Restart (N5 M3) -------------------------

    /// The capability's wire shape (RFC 4724 §3): the R bit in the
    /// top bit of the 2-octet field, the 12-bit Restart Time below
    /// it, then 4-octet family triples with the F bit on top of the
    /// flags octet.
    #[test]
    fn graceful_restart_capability_wire_format() {
        let cap = Capability::GracefulRestart {
            restart_state: true,
            graceful_notification: false,
            restart_time: 120,
            families: vec![(1, 1, true), (2, 1, false)],
        };
        let mut buf = Vec::new();
        encode_capabilities(std::slice::from_ref(&cap), &mut buf);
        // code 64, len 10, restart 0x8000|120 = 0x8078, then
        // 0001 01 80, 0002 01 00.
        assert_eq!(
            buf,
            vec![64, 10, 0x80, 0x78, 0x00, 0x01, 0x01, 0x80, 0x00, 0x02, 0x01, 0x00]
        );
        assert_eq!(decode_capabilities(&buf).unwrap(), vec![cap]);

        // No restart bit, no families (receive-only speaker).
        let bare = Capability::GracefulRestart {
            restart_state: false,
            graceful_notification: false,
            restart_time: 90,
            families: vec![],
        };
        let mut buf = Vec::new();
        encode_capabilities(std::slice::from_ref(&bare), &mut buf);
        assert_eq!(buf, vec![64, 2, 0x00, 0x5a]);
        assert_eq!(decode_capabilities(&buf).unwrap(), vec![bare]);
    }

    /// RFC 8538 §2: "The second most significant bit is defined in
    /// this document as the Graceful Notification ('N') bit" of the
    /// Restart Flags — bit 14 of the 2-octet field, between the R bit
    /// (15) and the 12-bit Restart Time. The golden bytes pin its
    /// position on the wire both alone and under the R bit.
    #[test]
    fn graceful_restart_n_bit_wire_format() {
        // N set, R clear: 0x4000 | 120 = 0x4078.
        let n = Capability::GracefulRestart {
            restart_state: false,
            graceful_notification: true,
            restart_time: 120,
            families: vec![],
        };
        let mut buf = Vec::new();
        encode_capabilities(std::slice::from_ref(&n), &mut buf);
        assert_eq!(buf, vec![64, 2, 0x40, 0x78]);
        assert_eq!(decode_capabilities(&buf).unwrap(), vec![n]);

        // R and N both set: 0xC000 | 90 = 0xC05A.
        let rn = Capability::GracefulRestart {
            restart_state: true,
            graceful_notification: true,
            restart_time: 90,
            families: vec![],
        };
        let mut buf = Vec::new();
        encode_capabilities(std::slice::from_ref(&rn), &mut buf);
        assert_eq!(buf, vec![64, 2, 0xc0, 0x5a]);
        assert_eq!(decode_capabilities(&buf).unwrap(), vec![rn]);
    }

    /// RFC 7911 §4: the ADD-PATH capability tuples. One family rides
    /// one 4-octet tuple; the Send/Receive values are 1/2/3.
    #[test]
    fn add_path_capability_round_trips() {
        let cap = Capability::AddPath(vec![AddPathFamily {
            afi: 1,
            safi: 1,
            send_receive: 3, // send+receive
        }]);
        let mut buf = Vec::new();
        encode_capabilities(std::slice::from_ref(&cap), &mut buf);
        assert_eq!(buf, vec![69, 4, 0x00, 0x01, 0x01, 0x03]);
        assert_eq!(decode_capabilities(&buf).unwrap(), vec![cap]);
        assert!(decode_capabilities(&[69, 3, 0x00, 0x01, 0x01]).is_err());
    }

    /// RFC 7911 §4's single-instance MUST: multiple families merge
    /// into ONE capability of 4n octets (not repeated instances).
    /// The codec round-trips the merged shape; repeated instances also
    /// decode (both are legal wire input for a decoder — the MUST
    /// binds the sender).
    #[test]
    fn add_path_capability_multi_family_single_instance() {
        let cap = Capability::AddPath(vec![
            AddPathFamily {
                afi: 1,
                safi: 1,
                send_receive: 1,
            },
            AddPathFamily {
                afi: 2,
                safi: 1,
                send_receive: 3,
            },
        ]);
        let mut buf = Vec::new();
        encode_capabilities(std::slice::from_ref(&cap), &mut buf);
        assert_eq!(
            buf,
            vec![69, 8, 0x00, 0x01, 0x01, 0x01, 0x00, 0x02, 0x01, 0x03]
        );
        assert_eq!(decode_capabilities(&buf).unwrap(), vec![cap]);
    }

    /// §4: a value length that is not 4n (or empty) is malformed;
    /// an invalid Send/Receive value is NOT — the tuples decode and
    /// the ignore-the-capability rule is a consumer concern.
    #[test]
    fn add_path_capability_lengths_and_invalid_sr() {
        // Not 4n.
        assert!(decode_capabilities(&[69, 5, 0, 1, 1, 1, 2]).is_err());
        // Empty.
        assert!(decode_capabilities(&[69, 0]).is_err());
        // S/R 0 and 4: decodes (kept for the consumer to ignore).
        let caps = decode_capabilities(&[69, 8, 0, 1, 1, 0, 0, 1, 1, 4]).unwrap();
        match &caps[0] {
            Capability::AddPath(tuples) => {
                assert_eq!(tuples.len(), 2);
                assert!(!tuples[0].send_receive_valid());
                assert!(!tuples[1].send_receive_valid());
            }
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn graceful_restart_bad_lengths_rejected() {
        // value not 2+4n.
        assert!(decode_capabilities(&[64, 3, 0x00, 0x78, 0x01]).is_err());
        assert!(decode_capabilities(&[64, 0]).is_err());
        // 64 triples would exceed the capability's length octet.
        let mut buf = vec![64, 255];
        buf.extend(std::iter::repeat_n(0u8, 255));
        assert!(decode_capabilities(&buf).is_err());
    }
}
