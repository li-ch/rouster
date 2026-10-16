//! The IS-IS PDU codecs: the 8-octet common header (ISO 10589
//! §9.5-§9.13; RFC 1142 carries the same text) and the five PDU
//! families the daemon speaks — LAN IIH (15/16), P2P IIH (17), LSP
//! (18/20), CSNP (24/25), PSNP (26/27).
//!
//! Fixed-part sizes (length indicator values — the common header plus
//! the PDU-specific fixed part; pinned to FRR 10.2.2 `pdu_size()` +
//! `ISIS_FIXED_HDR_LEN` and to ISO §9.5-§9.13 figures):
//!
//! | PDU            | types | fixed part | length indicator |
//! |----------------|-------|------------|------------------|
//! | LAN IIH        | 15/16 | 19         | 27               |
//! | P2P IIH        | 17    | 12         | 20               |
//! | LSP            | 18/20 | 19         | 27               |
//! | CSNP           | 24/25 | 25         | 33               |
//! | PSNP           | 26/27 | 9          | 17               |
//!
//! Field order note: the IIHs and SNPs put **PDU Length** after the
//! holding time / source id, while the LSP puts it first — each
//! family follows its ISO figure exactly (§9.7 vs §9.8), and the
//! tests pin the asymmetry.
//!
//! Validation strictness (the house rule, pinned to the specs):
//! discriminator 0x83, versions 1, length indicator exactly the
//! family's, ID length 0 (= 6), PDU length ≥ the fixed part and ≤
//! the buffer, trailing bytes rejected (the framing is exact). The
//! ECO/User ECO bytes (§9.1: "transmitted as zero, ignored on
//! receipt") and the PDU type's reserved high bits are ignored on
//! receipt per the same clause.

use crate::error::IsisError;
use crate::system::{Level, LspId, NeighborId, SystemId};
use crate::tlv::{decode_tlvs, encode_tlvs, Tlv};
use crate::wire::{put_u16, put_u32, put_u8, Reader};

/// The architectural constant (ISO 10589 §9.5: "intra-domain
/// routeing protocol discriminator").
pub const PROTOCOL_DISCRIMINATOR: u8 = 0x83;

/// PDU type codes (ISO 10589 §9.4).
pub const PDU_L1_LAN_HELLO: u8 = 15;
pub const PDU_L2_LAN_HELLO: u8 = 16;
pub const PDU_P2P_HELLO: u8 = 17;
pub const PDU_L1_LSP: u8 = 18;
pub const PDU_L2_LSP: u8 = 20;
pub const PDU_L1_CSNP: u8 = 24;
pub const PDU_L2_CSNP: u8 = 25;
pub const PDU_L1_PSNP: u8 = 26;
pub const PDU_L2_PSNP: u8 = 27;

/// The 8-octet common header every PDU carries.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CommonHeader {
    /// Length of the fixed header (the family's length indicator).
    pub length_indicator: u8,
    /// 0 = the 6-octet system ID (the only deployed value).
    pub id_length: u8,
    pub pdu_type: u8,
    /// The ECO/User ECO pair (§9.1: transmitted as zero, ignored on
    /// receipt — kept so re-encode is byte-faithful).
    pub reserved: u8,
    pub max_area_addresses: u8,
}

impl CommonHeader {
    pub const WIRE_SIZE: usize = 8;

    /// The expected length indicator for a PDU type (FRR `pdu_size`
    /// parity).
    pub fn expected_length_indicator(pdu_type: u8) -> Option<u8> {
        Some(match pdu_type {
            PDU_L1_LAN_HELLO | PDU_L2_LAN_HELLO => 27,
            PDU_P2P_HELLO => 20,
            PDU_L1_LSP | PDU_L2_LSP => 27,
            PDU_L1_CSNP | PDU_L2_CSNP => 33,
            PDU_L1_PSNP | PDU_L2_PSNP => 17,
            _ => return None,
        })
    }

    pub fn encode(&self, buf: &mut Vec<u8>) {
        put_u8(buf, PROTOCOL_DISCRIMINATOR);
        put_u8(buf, self.length_indicator);
        put_u8(buf, 1); // version/protocol ID extension
        put_u8(buf, self.id_length);
        put_u8(buf, self.pdu_type);
        put_u8(buf, 1); // version (subversion)
        put_u8(buf, self.reserved);
        put_u8(buf, self.max_area_addresses);
    }

    pub fn decode(r: &mut Reader<'_>) -> Result<Self, IsisError> {
        let field = "common header";
        let discriminator = r.u8().ok_or(err_trunc(field, 1, r.remaining()))?;
        if discriminator != PROTOCOL_DISCRIMINATOR {
            return Err(IsisError::BadDiscriminator(discriminator));
        }
        let length_indicator = r.u8().ok_or(err_trunc(field, 1, r.remaining()))?;
        let version = r.u8().ok_or(err_trunc(field, 1, r.remaining()))?;
        if version != 1 {
            return Err(IsisError::BadVersion(version));
        }
        let id_length = r.u8().ok_or(err_trunc(field, 1, r.remaining()))?;
        // §9.8's ID Length rule: 1..=8, 0 (= 6) or 255 (null). Only
        // the 6-octet form is deployed; others are rejected
        // (disclosed strictness — nothing real carries them).
        if id_length != 0 {
            return Err(IsisError::BadIdLength(id_length));
        }
        let pdu_type_raw = r.u8().ok_or(err_trunc(field, 1, r.remaining()))?;
        // §9.4: bits 6-8 reserved, ignored on receipt.
        let pdu_type = pdu_type_raw & 0x1f;
        let version2 = r.u8().ok_or(err_trunc(field, 1, r.remaining()))?;
        if version2 != 1 {
            return Err(IsisError::BadVersion(version2));
        }
        let reserved = r.u8().ok_or(err_trunc(field, 1, r.remaining()))?;
        let max_area_addresses = r.u8().ok_or(err_trunc(field, 1, r.remaining()))?;
        if Self::expected_length_indicator(pdu_type).is_none() {
            return Err(IsisError::BadPduType(pdu_type));
        }
        if length_indicator != Self::expected_length_indicator(pdu_type).expect("just checked") {
            return Err(IsisError::BadLengthIndicator {
                expected: Self::expected_length_indicator(pdu_type).expect("just checked"),
                found: length_indicator,
            });
        }
        Ok(Self {
            length_indicator,
            id_length,
            pdu_type,
            reserved,
            max_area_addresses,
        })
    }
}

fn err_trunc(field: &'static str, need: usize, have: usize) -> IsisError {
    IsisError::Truncated { field, need, have }
}

/// A decoded PDU: header plus typed body.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Pdu {
    pub header: CommonHeader,
    pub body: PduBody,
}

impl Pdu {
    /// Full encode, including the PDU length backpatch (the length
    /// field sits mid-PDU, so `encode_into` writes a placeholder and
    /// patches it — every family's figure puts PDU Length in the fixed
    /// part).
    pub fn encode(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        self.header.encode(&mut buf);
        let len_at = match self.body {
            PduBody::LanHello(_) | PduBody::P2pHello(_) => 8 + 1 + 6 + 2,
            PduBody::Lsp(_) => 8,
            PduBody::Csnp(_) => 8,
            PduBody::Psnp(_) => 8,
        };
        self.body.encode(&mut buf);
        let total = buf.len() as u16;
        buf[len_at] = (total >> 8) as u8;
        buf[len_at + 1] = (total & 0xff) as u8;
        buf
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, IsisError> {
        let mut r = Reader::new(bytes);
        let header = CommonHeader::decode(&mut r)?;
        let body = match header.pdu_type {
            PDU_L1_LAN_HELLO | PDU_L2_LAN_HELLO => PduBody::LanHello(LanHello::decode(
                &mut r,
                header.pdu_type == PDU_L2_LAN_HELLO,
            )?),
            PDU_P2P_HELLO => PduBody::P2pHello(P2pHello::decode(&mut r)?),
            PDU_L1_LSP | PDU_L2_LSP => {
                PduBody::Lsp(Lsp::decode(&mut r, header.pdu_type == PDU_L2_LSP)?)
            }
            PDU_L1_CSNP | PDU_L2_CSNP => {
                PduBody::Csnp(Csnp::decode(&mut r, header.pdu_type == PDU_L2_CSNP)?)
            }
            PDU_L1_PSNP | PDU_L2_PSNP => {
                PduBody::Psnp(Psnp::decode(&mut r, header.pdu_type == PDU_L2_PSNP)?)
            }
            other => return Err(IsisError::BadPduType(other)),
        };
        // The framing is exact: nothing may trail the TLV block, and
        // PDU Length ("Entire length of this PDU, in octets,
        // including header", §9.5-§9.13) must equal the buffer.
        if !r.is_empty() {
            return Err(IsisError::Trailing {
                field: "PDU",
                count: r.remaining(),
            });
        }
        // §7.3.11: the LSP checksum is verified over the received
        // bytes exactly (zeroing the field for the recomputation —
        // `lsp_checksum` does that in place on the copy).
        if let PduBody::Lsp(lsp) = &body {
            let mut copy = bytes.to_vec();
            let computed = crate::checksum::lsp_checksum(&mut copy);
            if lsp.checksum == 0 {
                return Err(IsisError::ZeroChecksum);
            }
            if computed != lsp.checksum {
                return Err(IsisError::ChecksumMismatch {
                    header: lsp.checksum,
                    computed,
                });
            }
        }
        let declared = body.pdu_length() as usize;
        if declared != bytes.len() {
            return Err(IsisError::BadLength {
                field: "PDU length",
                declared,
                actual: bytes.len(),
            });
        }
        Ok(Self { header, body })
    }

    /// The level(s) this PDU belongs to (from its type).
    pub fn level(&self) -> Level {
        match self.header.pdu_type {
            PDU_L1_LAN_HELLO | PDU_L1_LSP | PDU_L1_CSNP | PDU_L1_PSNP => Level::Level1,
            _ => Level::Level2,
        }
    }

    /// The TLV block (shared accessor for the FSM layers).
    pub fn tlvs(&self) -> &[Tlv] {
        match &self.body {
            PduBody::LanHello(p) => &p.tlvs,
            PduBody::P2pHello(p) => &p.tlvs,
            PduBody::Lsp(p) => &p.tlvs,
            PduBody::Csnp(p) => &p.tlvs,
            PduBody::Psnp(p) => &p.tlvs,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PduBody {
    LanHello(LanHello),
    P2pHello(P2pHello),
    Lsp(Lsp),
    Csnp(Csnp),
    Psnp(Psnp),
}

impl PduBody {
    /// The family's declared PDU length (the exact-framing check in
    /// [`Pdu::decode`]).
    pub fn pdu_length(&self) -> u16 {
        match self {
            Self::LanHello(p) => p.pdu_length,
            Self::P2pHello(p) => p.pdu_length,
            Self::Lsp(p) => p.pdu_length,
            Self::Csnp(p) => p.pdu_length,
            Self::Psnp(p) => p.pdu_length,
        }
    }

    /// Set the declared PDU length (encode patches the wire field;
    /// this mirrors it into the struct so constructed PDUs compare
    /// equal to their decoded selves).
    pub fn set_pdu_length(&mut self, len: u16) {
        match self {
            Self::LanHello(p) => p.pdu_length = len,
            Self::P2pHello(p) => p.pdu_length = len,
            Self::Lsp(p) => p.pdu_length = len,
            Self::Csnp(p) => p.pdu_length = len,
            Self::Psnp(p) => p.pdu_length = len,
        }
    }

    fn encode(&self, buf: &mut Vec<u8>) {
        match self {
            Self::LanHello(p) => p.encode(buf),
            Self::P2pHello(p) => p.encode(buf),
            Self::Lsp(p) => p.encode(buf),
            Self::Csnp(p) => p.encode(buf),
            Self::Psnp(p) => p.encode(buf),
        }
    }
}

/// The LAN IIH fixed part (ISO §9.5/§9.6): circuit type, source id,
/// holding time, PDU length, priority, LAN id (the DIS's id).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LanHello {
    pub circuit_type: Level,
    pub source_id: SystemId,
    pub holding_time: u16,
    pub pdu_length: u16,
    /// 7-bit LAN priority (the DIS election input).
    pub priority: u8,
    /// The designated intermediate system's id (system + pseudonode).
    pub lan_id: NeighborId,
    pub tlvs: Vec<Tlv>,
}

impl LanHello {
    fn encode(&self, buf: &mut Vec<u8>) {
        put_u8(buf, self.circuit_type.circuit_bits());
        buf.extend_from_slice(&self.source_id.0);
        put_u16(buf, self.holding_time);
        put_u16(buf, self.pdu_length);
        put_u8(buf, self.priority & 0x7f);
        buf.extend_from_slice(&self.lan_id.system.0);
        put_u8(buf, self.lan_id.pseudonode);
        encode_tlvs(buf, &self.tlvs);
    }

    fn decode(r: &mut Reader<'_>, _level2: bool) -> Result<Self, IsisError> {
        let field = "LAN IIH fixed part";
        let ct = r.u8().ok_or(err_trunc(field, 1, r.remaining()))?;
        let circuit_type =
            Level::from_circuit_bits(ct & 0x03).ok_or(IsisError::BadLevel(ct & 0x03))?;
        let source = r.take(6).ok_or(err_trunc(field, 6, r.remaining()))?;
        let holding_time = r.u16().ok_or(err_trunc(field, 2, r.remaining()))?;
        let pdu_length = r.u16().ok_or(err_trunc(field, 2, r.remaining()))?;
        let priority = r.u8().ok_or(err_trunc(field, 1, r.remaining()))?;
        let lan = r.take(7).ok_or(err_trunc(field, 7, r.remaining()))?;
        let tlvs = decode_tlvs(r.rest())?;
        Ok(Self {
            circuit_type,
            source_id: SystemId::from_bytes([
                source[0], source[1], source[2], source[3], source[4], source[5],
            ]),
            holding_time,
            pdu_length,
            priority: priority & 0x7f,
            lan_id: NeighborId::new(
                SystemId::from_bytes([lan[0], lan[1], lan[2], lan[3], lan[4], lan[5]]),
                lan[6],
            ),
            tlvs,
        })
    }
}

/// The P2P IIH fixed part (ISO §9.7): circuit type, source id,
/// holding time, PDU length, local circuit id.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct P2pHello {
    pub circuit_type: Level,
    pub source_id: SystemId,
    pub holding_time: u16,
    pub pdu_length: u16,
    /// The 1-octet local circuit id (ISO §9.7: unique per circuit at
    /// this IS).
    pub local_circuit_id: u8,
    pub tlvs: Vec<Tlv>,
}

impl P2pHello {
    fn encode(&self, buf: &mut Vec<u8>) {
        put_u8(buf, self.circuit_type.circuit_bits());
        buf.extend_from_slice(&self.source_id.0);
        put_u16(buf, self.holding_time);
        put_u16(buf, self.pdu_length);
        put_u8(buf, self.local_circuit_id);
        encode_tlvs(buf, &self.tlvs);
    }

    fn decode(r: &mut Reader<'_>) -> Result<Self, IsisError> {
        let field = "P2P IIH fixed part";
        let ct = r.u8().ok_or(err_trunc(field, 1, r.remaining()))?;
        let circuit_type =
            Level::from_circuit_bits(ct & 0x03).ok_or(IsisError::BadLevel(ct & 0x03))?;
        let source = r.take(6).ok_or(err_trunc(field, 6, r.remaining()))?;
        let holding_time = r.u16().ok_or(err_trunc(field, 2, r.remaining()))?;
        let pdu_length = r.u16().ok_or(err_trunc(field, 2, r.remaining()))?;
        let local_circuit_id = r.u8().ok_or(err_trunc(field, 1, r.remaining()))?;
        let tlvs = decode_tlvs(r.rest())?;
        Ok(Self {
            circuit_type,
            source_id: SystemId::from_bytes([
                source[0], source[1], source[2], source[3], source[4], source[5],
            ]),
            holding_time,
            pdu_length,
            local_circuit_id,
            tlvs,
        })
    }
}

/// The LSP type block (ISO §9.8): P (partition repair), four ATT
/// bits (per metric), LSPDBOL, IS type.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct LspBits {
    /// Partition repair supported.
    pub partition: bool,
    /// ATT bits: (default, delay, expense, error) — bit 4 through
    /// bit 7. The default-metric ATT bit (0x08) is the one modern
    /// L1-only routers follow for the default route.
    pub attached: [bool; 4],
    /// LSP database overload (ISO §9.8: "An LSP with this bit set
    /// will not be used by any decision process to calculate routes
    /// to another IS through the originating system").
    pub overload: bool,
    pub is_type: Level,
}

impl LspBits {
    pub fn encode(self) -> u8 {
        let mut b = 0u8;
        b |= u8::from(self.partition) << 7;
        let mut att = 0u8;
        for (i, &set) in self.attached.iter().enumerate() {
            att |= u8::from(set) << (i + 3);
        }
        b |= att;
        b |= u8::from(self.overload) << 2;
        b |= self.is_type.is_type_bits() & 0x03;
        b
    }

    pub fn decode(b: u8) -> Result<Self, IsisError> {
        Ok(Self {
            partition: b & 0x80 != 0,
            attached: [
                b & 0x08 != 0, // bit 4: default metric
                b & 0x10 != 0, // bit 5: delay
                b & 0x20 != 0, // bit 6: expense
                b & 0x40 != 0, // bit 7: error
            ],
            overload: b & 0x04 != 0,
            is_type: Level::from_is_type_bits(b & 0x03).ok_or(IsisError::BadIsType(b & 0x03))?,
        })
    }

    /// Whether any ATT bit is set (the L1→L2 default-route hook,
    /// ISO §9.8 + RFC 1195: an L1 router routes unknown destinations
    /// to the nearest attached L2 IS).
    pub fn is_attached(self) -> bool {
        self.attached.iter().any(|&b| b)
    }
}

/// The LSP fixed part (ISO §9.8) plus its TLV block. The checksum
/// covers bytes from the LSP id (offset 12) on — see `checksum.rs`;
/// `encode` computes it fresh (deterministic for identical content,
/// so re-flooding a decoded LSP reproduces its wire bytes).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Lsp {
    pub pdu_length: u16,
    pub remaining_lifetime: u16,
    pub id: LspId,
    pub sequence_number: u32,
    pub checksum: u16,
    pub bits: LspBits,
    pub tlvs: Vec<Tlv>,
}

impl Lsp {
    /// Whether this is a purge (zero remaining lifetime — ISO
    /// §7.3.16.4's "retain only the LSP header" tombstone).
    pub fn is_purge(&self) -> bool {
        self.remaining_lifetime == 0
    }

    fn encode(&self, buf: &mut Vec<u8>) {
        put_u16(buf, self.pdu_length);
        put_u16(buf, self.remaining_lifetime);
        buf.extend_from_slice(&self.id.system.0);
        put_u8(buf, self.id.pseudonode);
        put_u8(buf, self.id.fragment);
        put_u32(buf, self.sequence_number);
        put_u16(buf, 0); // checksum placeholder
        put_u8(buf, self.bits.encode());
        encode_tlvs(buf, &self.tlvs);
        let sum = crate::checksum::lsp_checksum(buf);
        buf[24] = (sum >> 8) as u8;
        buf[25] = (sum & 0xff) as u8;
    }

    fn decode(r: &mut Reader<'_>, _level2: bool) -> Result<Self, IsisError> {
        let field = "LSP fixed part";
        let pdu_length = r.u16().ok_or(err_trunc(field, 2, r.remaining()))?;
        let remaining_lifetime = r.u16().ok_or(err_trunc(field, 2, r.remaining()))?;
        let id = r.take(8).ok_or(err_trunc(field, 8, r.remaining()))?;
        let sequence_number = r.u32().ok_or(err_trunc(field, 4, r.remaining()))?;
        let checksum = r.u16().ok_or(err_trunc(field, 2, r.remaining()))?;
        let bits_raw = r.u8().ok_or(err_trunc(field, 1, r.remaining()))?;
        let bits = LspBits::decode(bits_raw)?;
        // ISO §7.3.16.3: remaining lifetime above MaxAge is a
        // checksum error.
        if remaining_lifetime > crate::MAX_AGE {
            return Err(IsisError::AgeTooLarge(remaining_lifetime, crate::MAX_AGE));
        }
        let tlvs = decode_tlvs(r.rest())?;
        Ok(Self {
            pdu_length,
            remaining_lifetime,
            id: LspId::new(
                SystemId::from_bytes([id[0], id[1], id[2], id[3], id[4], id[5]]),
                id[6],
                id[7],
            ),
            sequence_number,
            checksum,
            bits,
            tlvs,
        })
    }
}

/// The CSNP fixed part (ISO §9.10/§9.11): PDU length, source id,
/// start LSP id, end LSP id — the database range this CSNP describes
/// (the LSP entries ride TLV 9).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Csnp {
    pub pdu_length: u16,
    pub source_id: SystemId,
    pub start_lsp_id: LspId,
    pub end_lsp_id: LspId,
    pub tlvs: Vec<Tlv>,
}

impl Csnp {
    fn encode(&self, buf: &mut Vec<u8>) {
        put_u16(buf, self.pdu_length);
        buf.extend_from_slice(&self.source_id.0);
        put_u8(buf, 0); // source id's trailing octet (§9.10: ID Length + 1)
        put_lsp_id(buf, self.start_lsp_id);
        put_lsp_id(buf, self.end_lsp_id);
        encode_tlvs(buf, &self.tlvs);
    }

    fn decode(r: &mut Reader<'_>, _level2: bool) -> Result<Self, IsisError> {
        let field = "CSNP fixed part";
        let pdu_length = r.u16().ok_or(err_trunc(field, 2, r.remaining()))?;
        let source = r.take(7).ok_or(err_trunc(field, 7, r.remaining()))?;
        let start = read_lsp_id(r, field)?;
        let end = read_lsp_id(r, field)?;
        let tlvs = decode_tlvs(r.rest())?;
        Ok(Self {
            pdu_length,
            source_id: SystemId::from_bytes([
                source[0], source[1], source[2], source[3], source[4], source[5],
            ]),
            start_lsp_id: start,
            end_lsp_id: end,
            tlvs,
        })
    }
}

/// The PSNP fixed part (ISO §9.12/§9.13): PDU length, source id —
/// the requested/acknowledged entries ride TLV 9.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Psnp {
    pub pdu_length: u16,
    pub source_id: SystemId,
    pub tlvs: Vec<Tlv>,
}

impl Psnp {
    fn encode(&self, buf: &mut Vec<u8>) {
        put_u16(buf, self.pdu_length);
        buf.extend_from_slice(&self.source_id.0);
        put_u8(buf, 0);
        encode_tlvs(buf, &self.tlvs);
    }

    fn decode(r: &mut Reader<'_>, _level2: bool) -> Result<Self, IsisError> {
        let field = "PSNP fixed part";
        let pdu_length = r.u16().ok_or(err_trunc(field, 2, r.remaining()))?;
        let source = r.take(7).ok_or(err_trunc(field, 7, r.remaining()))?;
        let tlvs = decode_tlvs(r.rest())?;
        Ok(Self {
            pdu_length,
            source_id: SystemId::from_bytes([
                source[0], source[1], source[2], source[3], source[4], source[5],
            ]),
            tlvs,
        })
    }
}

fn put_lsp_id(buf: &mut Vec<u8>, id: LspId) {
    buf.extend_from_slice(&id.system.0);
    put_u8(buf, id.pseudonode);
    put_u8(buf, id.fragment);
}

fn read_lsp_id(r: &mut Reader<'_>, field: &'static str) -> Result<LspId, IsisError> {
    let raw = r.take(8).ok_or(err_trunc(field, 8, r.remaining()))?;
    Ok(LspId::new(
        SystemId::from_bytes([raw[0], raw[1], raw[2], raw[3], raw[4], raw[5]]),
        raw[6],
        raw[7],
    ))
}

/// The all-purpose L1/L2 P2P IIH constructor (the daemon's TX shape).
pub fn p2p_hello(
    circuit_type: Level,
    source: SystemId,
    holding_time: u16,
    local_circuit_id: u8,
    tlvs: Vec<Tlv>,
) -> Pdu {
    Pdu {
        header: CommonHeader {
            length_indicator: 20,
            id_length: 0,
            pdu_type: PDU_P2P_HELLO,
            reserved: 0,
            max_area_addresses: 0,
        },
        body: PduBody::P2pHello(P2pHello {
            circuit_type,
            source_id: source,
            holding_time,
            pdu_length: 0, // patched by encode
            local_circuit_id,
            tlvs,
        }),
    }
}

/// The L1/L2 LAN IIH constructor (the broadcast circuit's TX shape —
/// ISO §9.5/§9.6: priority and the LAN ID ride the fixed part).
pub fn lan_hello(
    level2: bool,
    circuit_type: Level,
    source: SystemId,
    holding_time: u16,
    priority: u8,
    lan_id: NeighborId,
    tlvs: Vec<Tlv>,
) -> Pdu {
    Pdu {
        header: CommonHeader {
            length_indicator: 27,
            id_length: 0,
            pdu_type: if level2 {
                PDU_L2_LAN_HELLO
            } else {
                PDU_L1_LAN_HELLO
            },
            reserved: 0,
            max_area_addresses: 0,
        },
        body: PduBody::LanHello(LanHello {
            circuit_type,
            source_id: source,
            holding_time,
            pdu_length: 0,
            priority: priority & 0x7f,
            lan_id,
            tlvs,
        }),
    }
}

/// The L1/L2 LSP constructor (the daemon's origination shape — the
/// checksum is computed on encode).
pub fn lsp(
    level2: bool,
    id: LspId,
    sequence_number: u32,
    remaining_lifetime: u16,
    bits: LspBits,
    tlvs: Vec<Tlv>,
) -> Pdu {
    Pdu {
        header: CommonHeader {
            length_indicator: 27,
            id_length: 0,
            pdu_type: if level2 { PDU_L2_LSP } else { PDU_L1_LSP },
            reserved: 0,
            max_area_addresses: 0,
        },
        body: PduBody::Lsp(Lsp {
            pdu_length: 0,
            remaining_lifetime,
            id,
            sequence_number,
            checksum: 0,
            bits,
            tlvs,
        }),
    }
}

/// The L1/L2 PSNP constructor.
pub fn psnp(level2: bool, source: SystemId, tlvs: Vec<Tlv>) -> Pdu {
    Pdu {
        header: CommonHeader {
            length_indicator: 17,
            id_length: 0,
            pdu_type: if level2 { PDU_L2_PSNP } else { PDU_L1_PSNP },
            reserved: 0,
            max_area_addresses: 0,
        },
        body: PduBody::Psnp(Psnp {
            pdu_length: 0,
            source_id: source,
            tlvs,
        }),
    }
}

/// The L1/L2 CSNP constructor (full range by default —
/// `0000.0000.0000.00-00` through `ffff.ffff.ffff.ff-ff`).
pub fn csnp(level2: bool, source: SystemId, tlvs: Vec<Tlv>) -> Pdu {
    Pdu {
        header: CommonHeader {
            length_indicator: 33,
            id_length: 0,
            pdu_type: if level2 { PDU_L2_CSNP } else { PDU_L1_CSNP },
            reserved: 0,
            max_area_addresses: 0,
        },
        body: PduBody::Csnp(Csnp {
            pdu_length: 0,
            source_id: source,
            start_lsp_id: LspId::new(SystemId::from_bytes([0; 6]), 0, 0),
            end_lsp_id: LspId::new(SystemId::from_bytes([0xff; 6]), 0xff, 0xff),
            tlvs,
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tlv::{ThreewayAdjacency, ThreewayState, WideIpReach, NLPID_IPV4};

    const SYS: SystemId = SystemId::from_bytes([0x19, 0x21, 0x68, 0x00, 0x10, 0x01]);
    const PEER: SystemId = SystemId::from_bytes([0x19, 0x21, 0x68, 0x00, 0x10, 0x02]);

    fn roundtrip(pdu: Pdu) -> Pdu {
        let bytes = pdu.encode();
        Pdu::decode(&bytes).expect("roundtrip decodes")
    }

    /// Encode, decode, and compare — with the constructed original's
    /// placeholder PDU length normalized to the wire value first.
    fn assert_roundtrip(pdu: Pdu) {
        let bytes = pdu.encode();
        let mut want = pdu;
        want.body.set_pdu_length(bytes.len() as u16);
        if let PduBody::Lsp(l) = &mut want.body {
            l.checksum = u16::from_be_bytes([bytes[24], bytes[25]]);
        }
        assert_eq!(Pdu::decode(&bytes).expect("decodes"), want);
    }

    /// A golden P2P IIH, hand-assembled byte for byte: the exact
    /// frame our daemon emits on a p2p circuit with three-way
    /// enabled (and what FRR 10.2.2's `fill_fixed_hdr` + `put_hello_
    /// hdr` shape mirrors).
    #[test]
    fn golden_p2p_hello() {
        let pdu = p2p_hello(
            Level::Level1And2,
            SYS,
            30,
            1,
            vec![
                Tlv::AreaAddresses(vec![vec![0x49, 0x00, 0x01]]),
                Tlv::ProtocolsSupported(vec![NLPID_IPV4]),
                Tlv::IpInterfaceAddress(vec!["10.0.0.2".parse().unwrap()]),
                Tlv::ThreewayAdjacency(ThreewayAdjacency {
                    state: ThreewayState::Initializing,
                    extended_local_circuit_id: 1,
                    neighbor: Some((PEER, 0)),
                }),
            ],
        );
        let bytes = pdu.encode();
        // Header (8): 83 14 01 00 11 01 00 00
        assert_eq!(
            &bytes[..8],
            &[0x83, 0x14, 0x01, 0x00, 0x11, 0x01, 0x00, 0x00]
        );
        // Fixed part (12): circuit 3, source, holding 30, len, circuit id 1
        assert_eq!(bytes[8], 3);
        assert_eq!(&bytes[9..15], &SYS.0);
        assert_eq!(&bytes[15..17], &[0, 30]);
        assert_eq!(&bytes[17..19], &(bytes.len() as u16).to_be_bytes());
        assert_eq!(bytes[19], 1);
        // TLV 1: [code 1][len 4][alen 3][49 00 01]
        assert_eq!(&bytes[20..26], &[1, 4, 3, 0x49, 0x00, 0x01]);
        assert_eq!(
            bytes.len(),
            20 + 6 + 3 + 6 + 17,
            "TLV 240 is now the 15-octet form"
        );
        // Level from the type byte: P2P IIH (17) belongs to the
        // L2 family block in `level()`; the levels themselves ride
        // the circuit-type byte.
        assert_eq!(
            roundtrip(p2p_hello(Level::Level1, SYS, 30, 1, vec![])).level(),
            Level::Level2
        );
    }

    #[test]
    fn golden_lsp_with_checksum() {
        let pdu = lsp(
            false,
            LspId::zero(SYS),
            1,
            1200,
            LspBits {
                partition: false,
                attached: [false; 4],
                overload: false,
                // The wire carries 3 = "an L2 IS"; an L1L2 router is
                // indistinguishable here (system.rs's note) — the
                // roundtrip must use the wire-visible value.
                is_type: Level::Level2,
            },
            vec![
                Tlv::AreaAddresses(vec![vec![0x49, 0x00, 0x01]]),
                Tlv::ProtocolsSupported(vec![NLPID_IPV4]),
                Tlv::Hostname("rouster-r2".into()),
                Tlv::ExtIsReachability(vec![crate::tlv::ExtIsNeighbor {
                    id: NeighborId::new(PEER, 0),
                    metric: 10,
                    sub_tlvs: vec![],
                }]),
                Tlv::ExtIpReachability(vec![WideIpReach {
                    metric: 10,
                    up_down: false,
                    prefix: ("10.255.2.1".parse().unwrap(), 32),
                    sub_tlvs: vec![],
                }]),
                Tlv::IpInterfaceAddress(vec!["10.0.0.2".parse().unwrap()]),
            ],
        );
        let bytes = pdu.encode();
        // Header: L1 LSP = 18, length indicator 27.
        assert_eq!(
            &bytes[..8],
            &[0x83, 0x1b, 0x01, 0x00, 0x12, 0x01, 0x00, 0x00]
        );
        // Fixed part: pdu length first, then remaining lifetime 1200.
        assert_eq!(&bytes[8..10], &(bytes.len() as u16).to_be_bytes());
        assert_eq!(&bytes[10..12], &[0x04, 0xb0]);
        // The type block: IS type 3.
        assert_eq!(bytes[26], 3);
        // The checksum verifies and roundtrips.
        assert_roundtrip(pdu);
        // A flip in the TLV block breaks decode (checksum rejection).
        let mut corrupt = bytes.clone();
        corrupt[40] ^= 0x01;
        assert!(matches!(
            Pdu::decode(&corrupt),
            Err(IsisError::ChecksumMismatch { .. })
        ));
    }

    /// ISO §7.3.16.3: a remaining lifetime above MaxAge is processed
    /// as a checksum error — decode rejects it as `AgeTooLarge`.
    #[test]
    fn lifetime_above_max_age_rejected() {
        let mut pdu = lsp(
            false,
            LspId::zero(SYS),
            1,
            crate::MAX_AGE + 1,
            LspBits::default(),
            vec![],
        );
        // Encode leaves the checksum over the too-large lifetime —
        // decode must reject the lifetime before anything else.
        let bytes = pdu.encode();
        assert!(matches!(
            Pdu::decode(&bytes),
            Err(IsisError::AgeTooLarge(v, _)) if v == crate::MAX_AGE + 1
        ));
        let PduBody::Lsp(l) = &mut pdu.body else {
            unreachable!()
        };
        l.remaining_lifetime = crate::MAX_AGE;
        assert_roundtrip(pdu);
    }

    #[test]
    fn golden_csnp_range() {
        let pdu = csnp(
            false,
            SYS,
            vec![Tlv::LspEntries(vec![crate::tlv::LspEntry {
                remaining_lifetime: 1199,
                lsp_id: LspId::zero(SYS),
                sequence_number: 1,
                checksum: 0x1234,
            }])],
        );
        let bytes = pdu.encode();
        assert_eq!(
            &bytes[..8],
            &[0x83, 0x21, 0x01, 0x00, 0x18, 0x01, 0x00, 0x00]
        );
        // PDU length first, then source id + 0.
        assert_eq!(&bytes[8..10], &(bytes.len() as u16).to_be_bytes());
        assert_eq!(&bytes[10..17], &[SYS.0.as_slice(), &[0]].concat());
        // Start id all-zero, end id all-ff.
        assert_eq!(&bytes[17..25], &[0u8; 8]);
        assert_eq!(&bytes[25..33], &[0xffu8; 8]);
        assert_roundtrip(pdu);
    }

    #[test]
    fn psnp_roundtrip() {
        let pdu = psnp(
            true,
            SYS,
            vec![Tlv::LspEntries(vec![crate::tlv::LspEntry {
                remaining_lifetime: 1000,
                lsp_id: LspId::zero(PEER),
                sequence_number: 9,
                checksum: 0xbeef,
            }])],
        );
        assert_roundtrip(pdu);
    }

    /// Malformed-header sweep: every field the house rule pins is
    /// enforced.
    #[test]
    fn malformed_common_header() {
        let good = p2p_hello(Level::Level1, SYS, 30, 1, vec![]);
        let bytes = good.encode();
        // Wrong discriminator.
        let mut bad = bytes.clone();
        bad[0] = 0x84;
        assert!(matches!(
            Pdu::decode(&bad),
            Err(IsisError::BadDiscriminator(0x84))
        ));
        // Wrong version.
        let mut bad = bytes.clone();
        bad[2] = 2;
        assert!(matches!(Pdu::decode(&bad), Err(IsisError::BadVersion(2))));
        // Nonzero ID length.
        let mut bad = bytes.clone();
        bad[3] = 6;
        assert!(matches!(Pdu::decode(&bad), Err(IsisError::BadIdLength(6))));
        // Unknown PDU type (reserved bits masked first).
        let mut bad = bytes.clone();
        bad[4] = 28;
        assert!(matches!(Pdu::decode(&bad), Err(IsisError::BadPduType(28))));
        // Reserved high bits of the type byte are IGNORED (§9.4).
        let mut tolerant = bytes.clone();
        tolerant[4] |= 0x80;
        assert_eq!(
            Pdu::decode(&tolerant).unwrap().header.pdu_type,
            PDU_P2P_HELLO
        );
        // Wrong length indicator for the family.
        let mut bad = bytes.clone();
        bad[1] = 27;
        assert!(matches!(
            Pdu::decode(&bad),
            Err(IsisError::BadLengthIndicator {
                expected: 20,
                found: 27
            })
        ));
        // Circuit type 0: the whole PDU shall be ignored (§9.7).
        let mut bad = bytes.clone();
        bad[8] = 0;
        assert!(matches!(Pdu::decode(&bad), Err(IsisError::BadLevel(0))));
    }

    /// Truncations at every fixed-part boundary of every family.
    #[test]
    fn truncation_sweep() {
        let cases: Vec<Pdu> = vec![
            p2p_hello(Level::Level1, SYS, 30, 1, vec![]),
            Pdu {
                header: CommonHeader {
                    length_indicator: 27,
                    id_length: 0,
                    pdu_type: PDU_L1_LAN_HELLO,
                    reserved: 0,
                    max_area_addresses: 0,
                },
                body: PduBody::LanHello(LanHello {
                    circuit_type: Level::Level1,
                    source_id: SYS,
                    holding_time: 30,
                    pdu_length: 0,
                    priority: 64,
                    lan_id: NeighborId::new(SYS, 1),
                    tlvs: vec![],
                }),
            },
            lsp(false, LspId::zero(SYS), 1, 1200, LspBits::default(), vec![]),
            csnp(false, SYS, vec![]),
            psnp(false, SYS, vec![]),
        ];
        for pdu in cases {
            let bytes = pdu.encode();
            for cut in 1..bytes.len() {
                let result = Pdu::decode(&bytes[..cut]);
                assert!(
                    result.is_err(),
                    "{} truncated to {} decoded — house rule violated",
                    match pdu.body {
                        PduBody::LanHello(_) => "LAN IIH",
                        PduBody::P2pHello(_) => "P2P IIH",
                        PduBody::Lsp(_) => "LSP",
                        PduBody::Csnp(_) => "CSNP",
                        PduBody::Psnp(_) => "PSNP",
                    },
                    cut
                );
            }
        }
    }

    /// Trailing bytes after the TLV block are rejected (exact
    /// framing).
    #[test]
    fn trailing_bytes_rejected() {
        let good = p2p_hello(Level::Level1, SYS, 30, 1, vec![]);
        let mut bad = good.encode();
        bad.extend_from_slice(&[9, 0, 0, 0]); // a whole extra TLV 9 entry block
        assert!(matches!(
            Pdu::decode(&bad),
            Err(IsisError::BadLength {
                field: "PDU length",
                ..
            })
        ));
    }

    /// The L1/L2 type pairs decode to their levels.
    #[test]
    fn level_from_type() {
        for (pdu, level) in [
            (
                lsp(false, LspId::zero(SYS), 1, 100, LspBits::default(), vec![]),
                Level::Level1,
            ),
            (
                lsp(true, LspId::zero(SYS), 1, 100, LspBits::default(), vec![]),
                Level::Level2,
            ),
            (csnp(false, SYS, vec![]), Level::Level1),
            (psnp(true, SYS, vec![]), Level::Level2),
        ] {
            assert_eq!(roundtrip(pdu.clone()).level(), level);
        }
    }

    /// LSP bits: every flag position of the type block (§9.8: P
    /// bit 8, ATT bits 7-4, LSPDBOL bit 3, IS type bits 2-1).
    #[test]
    fn lsp_type_block_bits() {
        let bits = LspBits {
            partition: true,
            attached: [true, false, true, false],
            overload: true,
            is_type: Level::Level2,
        };
        let b = bits.encode();
        assert_eq!(b, 0x80 | 0x08 | 0x20 | 0x04 | 0x03);
        assert_eq!(LspBits::decode(b).unwrap(), bits);
        assert!(bits.is_attached());
        assert!(!LspBits::default().is_attached());
        // IS type 2 is unused on the LSP block.
        assert!(matches!(
            LspBits::decode(0x02),
            Err(IsisError::BadIsType(2))
        ));
        // Wire: the type block lands at byte 26 of an LSP.
        let pdu = lsp(false, LspId::zero(SYS), 1, 100, bits, vec![]);
        let bytes = pdu.encode();
        assert_eq!(bytes[26], b);
    }

    /// Purge shape: zero remaining lifetime, header-only body.
    #[test]
    fn purge_shape() {
        let purge = lsp(false, LspId::zero(PEER), 7, 0, LspBits::default(), vec![]);
        let back = roundtrip(purge);
        let PduBody::Lsp(l) = &back.body else {
            unreachable!()
        };
        assert!(l.is_purge());
    }

    /// The unhex round trip through a real wire shape: a LAN IIH
    /// (type 15) decoded from raw octets — the smoke's captured FRR
    /// frames land here unchanged.
    #[test]
    fn lan_hello_from_wire_bytes() {
        // Assembled by hand: header + fixed + one area TLV.
        let mut bytes = vec![
            0x83, 27, 1, 0, 15, 1, 0, 0, // common (L1 LAN IIH)
            1, // circuit type L1
        ];
        bytes.extend_from_slice(&SYS.0);
        bytes.extend_from_slice(&[0, 30]); // holding time
        bytes.extend_from_slice(&[0, 21 + 6]); // pdu length (patched below)
        bytes.push(64); // priority
        bytes.extend_from_slice(&SYS.0);
        bytes.push(1); // lan id pseudonode
        bytes.extend_from_slice(&[1, 4, 3, 0x49, 0x00, 0x01]); // TLV 1: 49.0001
        let total = bytes.len() as u16;
        bytes[17] = (total >> 8) as u8;
        bytes[18] = (total & 0xff) as u8;
        let pdu = Pdu::decode(&bytes).expect("LAN IIH decodes");
        let PduBody::LanHello(h) = &pdu.body else {
            unreachable!()
        };
        assert_eq!(h.circuit_type, Level::Level1);
        assert_eq!(h.priority, 64);
        assert_eq!(h.lan_id, NeighborId::new(SYS, 1));
        assert_eq!(pdu.level(), Level::Level1);
    }
}
