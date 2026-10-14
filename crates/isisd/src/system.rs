//! IS-IS identifiers: the 6-octet system ID, the 8-octet LSP id and
//! the 7-octet neighbour/destination IDs (ISO 10589 §9.1's framing:
//! IDs are `ID Length` octets, `ID Length` = 0 means 6 — the only
//! deployed encoding, enforced by the common header decode).

use std::fmt;

/// A 6-octet system identifier, displayed in the house style
/// `1921.6800.1001`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct SystemId(pub [u8; 6]);

impl SystemId {
    pub const fn from_bytes(bytes: [u8; 6]) -> Self {
        Self(bytes)
    }

    /// Parse the dotted hex form `xxxx.xxxx.xxxx` (12 hex digits).
    pub fn parse_dotted(s: &str) -> Option<Self> {
        let parts: Vec<&str> = s.split('.').collect();
        if parts.len() != 3 {
            return None;
        }
        let mut bytes = [0u8; 6];
        for (i, part) in parts.iter().enumerate() {
            if part.len() != 4 {
                return None;
            }
            bytes[i * 2] = u8::from_str_radix(&part[..2], 16).ok()?;
            bytes[i * 2 + 1] = u8::from_str_radix(&part[2..], 16).ok()?;
        }
        Some(Self(bytes))
    }
}

impl fmt::Display for SystemId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let b = self.0;
        write!(
            f,
            "{:02x}{:02x}.{:02x}{:02x}.{:02x}{:02x}",
            b[0], b[1], b[2], b[3], b[4], b[5]
        )
    }
}

/// A 7-octet "system ID + pseudonode" destination ID — the neighbour
/// identifier inside reachability TLVs (ISO 10589 §9.8's LSP-id
/// structure; RFC 5305 §3 calls it "7 octets of system ID and
/// pseudonode number") and the LAN ID / DIS id of LAN IIHs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct NeighborId {
    pub system: SystemId,
    pub pseudonode: u8,
}

impl NeighborId {
    pub const fn new(system: SystemId, pseudonode: u8) -> Self {
        Self { system, pseudonode }
    }

    /// True when this names a pseudonode (a LAN's DIS), not a router.
    pub fn is_pseudonode(&self) -> bool {
        self.pseudonode != 0
    }
}

impl fmt::Display for NeighborId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}.{:02x}", self.system, self.pseudonode)
    }
}

/// The 8-octet LSP identifier (ISO 10589 §9.8): source system ID,
/// pseudonode ID, LSP fragment number. Displayed
/// `1921.6800.1001.00-00` (FRR's `%pLS` shape).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct LspId {
    pub system: SystemId,
    pub pseudonode: u8,
    pub fragment: u8,
}

impl LspId {
    pub const fn new(system: SystemId, pseudonode: u8, fragment: u8) -> Self {
        Self {
            system,
            pseudonode,
            fragment,
        }
    }

    /// The zero fragment of a real (non-pseudonode) system — the LSP
    /// that carries the per-router TLVs.
    pub const fn zero(system: SystemId) -> Self {
        Self::new(system, 0, 0)
    }

    /// The 7-octet neighbour view of this LSP's origin (TLV 2/22
    /// entries point at `system + pseudonode`).
    pub fn as_neighbor(&self) -> NeighborId {
        NeighborId::new(self.system, self.pseudonode)
    }
}

impl fmt::Display for LspId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}.{:02x}-{:02x}",
            self.system, self.pseudonode, self.fragment
        )
    }
}

/// The IS type of a circuit or router (the two low bits of the IIH
/// circuit-type byte and the LSP type block; ISO 10589 §9.7/§9.8 —
/// note §9.8's wire values for the LSP type block are 1 = L1 and
/// 3 = L2, with 2 unused there; the circuit-type byte uses 2 for
/// L2-only).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Level {
    #[default]
    Level1,
    /// Both levels ("level 1 and level 2", the L1L2 router).
    Level1And2,
    /// Level 2 only (circuit type byte 2 / LSP IS type 3).
    Level2,
}

impl Level {
    /// Decode the two low bits of the circuit-type byte (§9.7:
    /// 0 = reserved — the whole PDU shall be ignored; callers reject
    /// 0 before reaching here).
    pub fn from_circuit_bits(bits: u8) -> Option<Self> {
        match bits {
            1 => Some(Self::Level1),
            2 => Some(Self::Level2),
            3 => Some(Self::Level1And2),
            _ => None,
        }
    }

    pub fn circuit_bits(self) -> u8 {
        match self {
            Self::Level1 => 1,
            Self::Level2 => 2,
            Self::Level1And2 => 3,
        }
    }

    /// Decode the IS type field of the LSP type block (§9.8: 1 = L1
    /// IS, 3 = L2 IS, 0 and 2 unused).
    pub fn from_is_type_bits(bits: u8) -> Option<Self> {
        match bits {
            1 => Some(Self::Level1),
            3 => Some(Self::Level2),
            _ => None,
        }
    }

    /// The wire IS type of this router's LSPs: an L1L2 router emits
    /// IS type 3 like a pure L2 router (§9.8's two values).
    pub fn is_type_bits(self) -> u8 {
        match self {
            Self::Level1 => 1,
            Self::Level2 | Self::Level1And2 => 3,
        }
    }

    /// Whether this router/circuit participates in level 1.
    pub fn has_level1(self) -> bool {
        !matches!(self, Self::Level2)
    }

    /// Whether this router/circuit participates in level 2.
    pub fn has_level2(self) -> bool {
        !matches!(self, Self::Level1)
    }
}

impl fmt::Display for Level {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::Level1 => "L1",
            Self::Level1And2 => "L1L2",
            Self::Level2 => "L2",
        };
        f.write_str(s)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn system_id_roundtrip_and_ordering() {
        let id = SystemId::parse_dotted("1921.6800.1001").unwrap();
        assert_eq!(id.0, [0x19, 0x21, 0x68, 0x00, 0x10, 0x01]);
        assert_eq!(id.to_string(), "1921.6800.1001");
        assert_eq!(SystemId::parse_dotted("1921.6800.10"), None);
        assert_eq!(SystemId::parse_dotted("1921.6800.100Z"), None);
        // Ordering is byte-wise (the LSPDB key order).
        let smaller = SystemId::parse_dotted("0000.0000.0001").unwrap();
        assert!(smaller < id);
    }

    #[test]
    fn lsp_id_display_and_neighbor_view() {
        let sys = SystemId::parse_dotted("1921.6800.1001").unwrap();
        let id = LspId::new(sys, 0, 0);
        assert_eq!(id.to_string(), "1921.6800.1001.00-00");
        assert!(!id.as_neighbor().is_pseudonode());
        let lan = LspId::new(sys, 0x02, 0x01);
        assert_eq!(lan.to_string(), "1921.6800.1001.02-01");
        assert!(lan.as_neighbor().is_pseudonode());
    }

    /// §9.7 vs §9.8 encoding asymmetry: the circuit-type byte carries
    /// 2 for L2-only, the LSP type block carries 3 for an L2 (or
    /// L1L2) router — 2 is unused there.
    #[test]
    fn level_bits_are_per_field() {
        assert_eq!(Level::from_circuit_bits(1), Some(Level::Level1));
        assert_eq!(Level::from_circuit_bits(2), Some(Level::Level2));
        assert_eq!(Level::from_circuit_bits(3), Some(Level::Level1And2));
        assert_eq!(Level::from_circuit_bits(0), None, "reserved: PDU ignored");

        assert_eq!(Level::from_is_type_bits(1), Some(Level::Level1));
        assert_eq!(Level::from_is_type_bits(3), Some(Level::Level2));
        assert_eq!(Level::from_is_type_bits(2), None, "unused on the LSP block");
        assert_eq!(Level::from_is_type_bits(0), None);

        assert_eq!(Level::Level1.is_type_bits(), 1);
        assert_eq!(Level::Level1And2.is_type_bits(), 3);
        assert_eq!(Level::Level2.is_type_bits(), 3);

        assert!(Level::Level1And2.has_level1() && Level::Level1And2.has_level2());
        assert!(!Level::Level2.has_level1());
        assert!(!Level::Level1.has_level2());
    }
}
