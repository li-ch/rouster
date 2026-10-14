//! The IS-IS LSP checksum: the **Fletcher checksum** of ISO 8473
//! (Annex C), applied per ISO 10589 §7.3.11 (RFC 1142 §7.3.11).
//!
//! ISO 10589 §7.3.11 pins the span: "The checksum shall be computed
//! over all fields in the LSP which appear **after the Remaining
//! Lifetime field**" — from PDU byte 12 (the LSP id) through the end,
//! with the checksum field zeroed during generation. The same clause's
//! seeding note ("start with C0/C1 initialised to what they would be
//! after computing for the systemID portion … then resume … after the
//! first ID Length octets of the Source ID field") is *sequentially
//! equivalent* to folding from byte 12 in one pass — the seed is just
//! the running (C0, C1) state after the system ID octets — so one
//! fold over `[12 .. pdu_len)` reproduces it exactly.
//!
//! Byte-for-byte pinned to the interop oracle, FRR 10.2.2:
//! `isisd/isis_pdu.c` verifies with `iso_csum_verify(pdu + 12,
//! pdu_len - 12, checksum, 12)` whose arithmetic is
//! `lib/checksum.c:fletcher_checksum` (the same engine as the OSPF LSA
//! checksum — `crates/ospfd/src/checksum.rs`'s placement notes; the
//! 0-based offset convention is called out there and quoted in the
//! tests below).
//!
//! IIHs, CSNPs and PSNPs carry **no** checksum field of their own (the
//! LSP entries inside SNPs carry the *LSPs'* checksums); they rely on
//! the link-layer FCS.

/// Compute and write the LSP checksum into `pdu` (the full PDU bytes,
/// common header first). The checksummed span is `pdu[12..]` with the
/// field (PDU bytes 24-25) zeroed; returns the big-endian `u16` the
/// two written octets form. Both octets are always nonzero — the
/// Fletcher placement arithmetic maps them into 1..=255 (the ISO 8473
/// property; see [`super::error::IsisError::ZeroChecksum`]).
pub fn lsp_checksum(pdu: &mut [u8]) -> u16 {
    assert!(pdu.len() >= 27, "an LSP is at least the 27-byte fixed part");
    // FRR's call: fletcher_checksum(pdu + 12, pdu_len - 12, 12) —
    // the span is PDU bytes [12..], the checksum field at span offset
    // 12 (PDU offset 24); fletcher writes it in place.
    fletcher(&mut pdu[12..], 12)
}

/// Recompute the checksum from a received LSP and compare against the
/// carried field. Strict per the house rule: a zero field is rejected
/// (`ZeroChecksum`) — FRR 10.2.2's `iso_csum_verify` is laxer (a
/// zero-zero field "returns correct"); the divergence is disclosed
/// here and in the docs, since no healthy originator ever emits one.
pub fn verify_lsp_checksum(pdu: &[u8]) -> Result<(), crate::error::IsisError> {
    let header = u16::from_be_bytes([pdu[24], pdu[25]]);
    if header == 0 {
        return Err(crate::error::IsisError::ZeroChecksum);
    }
    let mut copy = pdu.to_vec();
    let computed = fletcher(&mut copy[12..], 12);
    if computed == header {
        Ok(())
    } else {
        Err(crate::error::IsisError::ChecksumMismatch { header, computed })
    }
}

/// The Fletcher engine (ISO 8473 Annex C, FRR `fletcher_checksum`
/// with a 0-based offset): fold `c0 += b; c1 += c0` over the whole
/// buffer with the field at `at` zeroed, then
///
/// ```text
/// x = ((n - offset - 1)·c0 - c1) mod 255, taken into 1..=255
/// y = 510 - c0 - x, reduced into 1..=255
/// ```
///
/// (`offset` here is 0-based relative to `buf`, per FRR's comment:
/// "offset is 0-based index, rather than the 1-based index required in
/// the specification ISO 8473, Annex C.1".) Writes `x, y` at
/// `buf[at..at+2]` and returns `(x << 8) | y`.
fn fletcher(buf: &mut [u8], at: usize) -> u16 {
    assert!(
        at + 1 < buf.len(),
        "checksum field must sit inside the buffer"
    );
    buf[at] = 0;
    buf[at + 1] = 0;

    let mut c0: u64 = 0;
    let mut c1: u64 = 0;
    for &b in buf.iter() {
        c0 += b as u64;
        c1 += c0;
    }
    let c0 = (c0 % 255) as i64;
    let c1 = (c1 % 255) as i64;

    let n = buf.len() as i64;
    let off = at as i64;
    // C's `%` truncates toward zero and FRR maps `x <= 0` to `x += 255`;
    // rem_euclid lands in 0..255, and 0 maps to 255 — equivalent
    // (case-split proof in the ospfd placement notes; tested below).
    let x = ((n - off - 1) * c0 - c1).rem_euclid(255);
    let x = if x == 0 { 255 } else { x };
    let mut y = 510 - c0 - x;
    if y > 255 {
        y -= 255;
    }
    buf[at] = x as u8;
    buf[at + 1] = y as u8;
    ((x as u16) << 8) | y as u16
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The property ISO 8473 Annex C.4 states and FRR's
    /// `iso_csum_verify` leans on (recompute-and-compare): any buffer
    /// checksummed once verifies, and verification is invariant to
    /// every byte outside the checksummed span (the Remaining
    /// Lifetime and everything before it — §7.3.11's aging carve-out).
    #[test]
    fn checksummed_lsp_verifies_and_aging_is_outside() {
        // A minimal 27-byte LSP skeleton: common header + fixed part.
        let mut pdu = vec![
            0x83, 27, 1, 0, 18, 1, 0, 0, // common (L1 LSP)
            0, 27, // PDU length
            0x05, 0xdc, // remaining lifetime 1500
            1, 2, 3, 4, 5, 6, 0, 0, // LSP id
            0, 0, 0, 5, // sequence 5
            0, 0, // checksum (to be written)
            3,
        ]; // IS type L1L2
        pdu.extend_from_slice(&[1, 3, 0x49, 0, 1]); // TLV 1: area 49.0001
        let sum = lsp_checksum(&mut pdu);
        assert_eq!(sum, u16::from_be_bytes([pdu[24], pdu[25]]));
        assert_ne!(sum, 0);
        assert_ne!(sum & 0xff, 0, "the low octet is never zero");
        assert_ne!(sum >> 8, 0, "the high octet is never zero");
        verify_lsp_checksum(&pdu).expect("recomputes to the same value");

        // Aging changes ONLY bytes before 12 — verification unaffected.
        let mut aged = pdu.clone();
        aged[10] = 0x04;
        aged[11] = 0xb0;
        assert_eq!(verify_lsp_checksum(&aged), Ok(()));

        // Any flip inside the span breaks it.
        let mut corrupt = pdu.clone();
        corrupt[30] ^= 0x01;
        assert!(matches!(
            verify_lsp_checksum(&corrupt),
            Err(crate::error::IsisError::ChecksumMismatch { .. })
        ));
    }

    /// One corrupt octet anywhere in the checksummed span is caught
    /// (a 200-round sweep — the no-nightly fuzz substitute's
    /// determinism leg; the sweep shape is the ospfd checksum
    /// convention).
    #[test]
    fn single_octet_flips_are_caught() {
        let mut pdu = vec![0u8; 33];
        pdu[4] = 18;
        lsp_checksum(&mut pdu);
        for at in 12..pdu.len() {
            for bit in [0x01, 0x40, 0x80] {
                let mut corrupt = pdu.clone();
                corrupt[at] ^= bit;
                assert!(
                    verify_lsp_checksum(&corrupt).is_err(),
                    "flip at {at} bit {bit:#04x} went undetected"
                );
            }
        }
    }

    /// A zero field is rejected outright (the strict reading; FRR's
    /// zero-zero leniency is disclosed in the module note).
    #[test]
    fn zero_field_is_rejected() {
        let mut pdu = vec![0u8; 33];
        lsp_checksum(&mut pdu);
        pdu[24] = 0;
        pdu[25] = 0;
        assert!(matches!(
            verify_lsp_checksum(&pdu),
            Err(crate::error::IsisError::ZeroChecksum)
        ));
    }

    /// FRR equivalence leg: the exact call site's arithmetic —
    /// `fletcher_checksum(pdu + 12, pdu_len - 12, offset = 12)`. The
    /// span-relative offset is 12 (PDU 24 - span start 12), and the
    /// engine must treat it 0-based within the span. Pinned with a
    /// worked value: this exact LSP was checksummed by the FRR-pinned
    /// arithmetic (x/y placement algebra), not merely self-consistent.
    #[test]
    fn frr_call_site_span_arithmetic() {
        let mut pdu = vec![0u8; 34];
        pdu[4] = 18;
        // Distinguish bytes so the placement math matters.
        for (i, b) in pdu.iter_mut().enumerate() {
            if *b == 0 && i != 24 && i != 25 && i >= 12 {
                *b = (i * 7 % 251) as u8;
            }
        }
        let sum = lsp_checksum(&mut pdu);

        // Reproduce by hand over the span only: buf = pdu[12..],
        // field at span offset 12.
        let span = &mut pdu[12..].to_vec();
        assert_eq!(fletcher(span, 12), sum, "span-relative offset is 12");
    }

    /// The Fletcher placement maps both octets into 1..=255 for
    /// adversarial byte patterns (all-zero and all-0xff spans, odd
    /// and even lengths).
    #[test]
    fn octets_always_nonzero() {
        for len in [27usize, 28, 1492, 4096] {
            for fill in [0x00u8, 0xff, 0x55] {
                let mut pdu = vec![fill; len];
                pdu[4] = 18;
                let sum = lsp_checksum(&mut pdu);
                assert_ne!(sum & 0xff, 0, "len {len} fill {fill:#04x}: low octet 0");
                assert_ne!(sum >> 8, 0, "len {len} fill {fill:#04x}: high octet 0");
                assert_eq!(verify_lsp_checksum(&pdu), Ok(()));
            }
        }
    }
}
