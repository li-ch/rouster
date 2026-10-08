//! ZAPI message header (FRR wire format).
//!
//! ```text
//!  0                   1                   2                   3
//!  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |         Length (incl. header) |    Marker     |    Version    |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |                           VRF ID                              |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |            Command            |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! ```
//!
//! Version 0 is implicitly versioned (no version field); it is distinguished
//! by the marker byte position holding a command value instead of the marker
//! (255 for FRR). Rouster targets FRR-style versioned headers only.

/// ZAPI header length in bytes.
pub const ZAPI_HEADER_LEN: usize = 10;

/// FRR ZAPI marker byte (Quagga used 255; FRR uses 254 on the wire for
/// versioned headers — see FRR `lib/zclient.h`). We accept both on decode.
pub const ZAPI_MARKER: u8 = 254;

/// Highest ZAPI version this crate understands (FRR 10.x speaks version 6).
pub const ZAPI_VERSION: u8 = 6;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ZapiHeader {
    /// Total message length including this header.
    pub length: u16,
    pub marker: u8,
    pub version: u8,
    pub vrf_id: u32,
    pub command: u16,
}

impl ZapiHeader {
    pub fn new(command: u16, vrf_id: u32, body_len: usize) -> Self {
        Self {
            length: (ZAPI_HEADER_LEN + body_len) as u16,
            marker: ZAPI_MARKER,
            version: ZAPI_VERSION,
            vrf_id,
            command,
        }
    }

    pub fn encode(&self, buf: &mut [u8]) {
        assert!(buf.len() >= ZAPI_HEADER_LEN);
        buf[0..2].copy_from_slice(&self.length.to_be_bytes());
        buf[2] = self.marker;
        buf[3] = self.version;
        buf[4..8].copy_from_slice(&self.vrf_id.to_be_bytes());
        buf[8..10].copy_from_slice(&self.command.to_be_bytes());
    }

    pub fn decode(buf: &[u8]) -> Result<Self, ZapiHeaderError> {
        if buf.len() < ZAPI_HEADER_LEN {
            return Err(ZapiHeaderError::Truncated);
        }
        let length = u16::from_be_bytes([buf[0], buf[1]]);
        if (length as usize) < ZAPI_HEADER_LEN {
            return Err(ZapiHeaderError::BadLength(length));
        }
        let marker = buf[2];
        let version = buf[3];
        if version == 0 {
            return Err(ZapiHeaderError::UnsupportedVersion(0));
        }
        Ok(Self {
            length,
            marker,
            version,
            vrf_id: u32::from_be_bytes([buf[4], buf[5], buf[6], buf[7]]),
            command: u16::from_be_bytes([buf[8], buf[9]]),
        })
    }
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum ZapiHeaderError {
    #[error("buffer too short for ZAPI header")]
    Truncated,
    #[error("invalid ZAPI message length field: {0}")]
    BadLength(u16),
    #[error("unsupported ZAPI version: {0}")]
    UnsupportedVersion(u8),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn header_roundtrip() {
        let h = ZapiHeader::new(23, 42, 100);
        let mut buf = [0u8; ZAPI_HEADER_LEN];
        h.encode(&mut buf);
        let decoded = ZapiHeader::decode(&buf).unwrap();
        assert_eq!(h, decoded);
        assert_eq!(decoded.length as usize, ZAPI_HEADER_LEN + 100);
    }

    #[test]
    fn rejects_truncated() {
        assert_eq!(
            ZapiHeader::decode(&[0u8; 4]),
            Err(ZapiHeaderError::Truncated)
        );
    }
}
