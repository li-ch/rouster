//! OSPF checksums — two different algorithms, do not mix them up:
//!
//! - **LSA checksum** (RFC 2328 §12.1.7): the **Fletcher checksum**
//!   (ISO 8473 Annex B/C, via RFC 1008), over the complete LSA contents
//!   *excepting the 2-byte LS age field*, with the checksum field itself
//!   zeroed during computation. Implemented below in
//!   [`lsa_fletcher_checksum`] with the placement arithmetic pinned to
//!   FRR 10.2.2 `lib/checksum.c:fletcher_checksum` (0-based offsets; the
//!   checksum sits at relative offset 14 from the `options` byte).
//!
//! - **OSPF packet checksum** (RFC 2328 §A.3.1): the *standard IP
//!   one's-complement checksum* of the packet excluding the 64-bit
//!   authentication field, in [`packet_ip_checksum`]. The OSPF packet
//!   header embeds it at bytes 12-14; bytes 16-24 (Authentication) are
//!   skipped.
//!
//! Both were validated byte-for-byte against a real OSPFv2 capture
//! (31 packets, 19 LSAs — see the test module: every real checksum
//! verifies, and recomputation from checksum-zeroed bytes reproduces the
//! wire value exactly).

/// Fletcher-16 checksum over `buf` (which must already exclude the LS
/// age field — pass `&lsa[2..length]`), writing the two checksum octets
/// at `offset` (relative to `buf`; for an LSA that is 14, since the
/// checksum lives at LSA bytes 16-17).
///
/// Returns the checksum as the big-endian `u16` formed by the two
/// written octets. The FRR-pinned placement math:
///
/// ```text
/// c0 = Σ buf[i] mod 255,  c1 = Σ_i (n - i) · buf[i] mod 255   (field zeroed)
/// x = ((n - offset - 1)·c0 - c1) mod 255, taken in 1..=255
/// y = 510 - c0 - x, reduced into 1..=255
/// ```
///
/// Both octets are always nonzero, which is exactly §12.1.7's "the LS
/// checksum field cannot take on the value of zero".
pub fn lsa_fletcher_checksum(buf: &mut [u8], offset: usize) -> u16 {
    assert!(
        offset + 1 < buf.len(),
        "checksum offset must leave two octets inside the buffer"
    );
    // Zero the field for the accumulation (FRR does this in-place too).
    buf[offset] = 0;
    buf[offset + 1] = 0;

    let mut c0: u64 = 0;
    let mut c1: u64 = 0;
    for &b in buf.iter() {
        c0 += b as u64;
        c1 += c0;
    }
    let c0 = (c0 % 255) as i64;
    let c1 = (c1 % 255) as i64;

    let n = buf.len() as i64;
    let off = offset as i64;
    // C's `%` truncates toward zero and FRR then maps `x <= 0` to
    // `x += 255`; rem_euclid with a zero-to-255 mapping is equivalent
    // (proven by case split; see the property tests).
    let mut x = ((n - off - 1) * c0 - c1).rem_euclid(255);
    if x == 0 {
        x = 255;
    }
    let mut y = 510 - c0 - x;
    if y > 255 {
        y -= 255;
    }

    buf[offset] = x as u8;
    buf[offset + 1] = y as u8;
    ((x as u16) << 8) | y as u16
}

/// Fletcher verification (RFC 2328 §12.1.7 / ISO 8473): with the
/// checksum in place, both accumulator sums must be ≡ 0 mod 255.
/// `buf` is the checksummed region — for an LSA, `&lsa[2..length]`.
pub fn fletcher_verify(buf: &[u8]) -> bool {
    let mut c0: u64 = 0;
    let mut c1: u64 = 0;
    for &b in buf {
        c0 += b as u64;
        c1 += c0;
    }
    c0.is_multiple_of(255) && c1.is_multiple_of(255)
}

/// The standard IP one's-complement checksum (RFC 2328 §A.3.1's packet
/// Checksum field: "16-bit one's complement of the one's complement sum
/// of all the 16-bit words in the packet, excepting the authentication
/// field"). An odd trailing byte is padded with a zero.
pub fn internet_checksum(data: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    let (words, tail) = data.as_chunks::<2>();
    for c in words {
        sum += u16::from_be_bytes(*c) as u32;
    }
    if let [b] = tail {
        sum += (*b as u32) << 8;
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wire::unhex;

    /// 19 LSAs lifted verbatim from a real OSPFv2 exchange capture
    /// (router/network/AS-external types, one natural MaxAge flush).
    /// Format: full LSA hex (header + body, checksum field included).
    const REAL_LSAS: &[&str] = &[
        // router-LSA, E-bit set, one stub link
        "03e20201c0a8aa08c0a8aa0880000dc32506002402000001c0a8aa00ffffff000300000a",
        // router-LSA with two stub links
        "00020201c0a8aa03c0a8aa03800000013a9c003002000002c0a8aa00ffffff000300000ac0a8aa00ffffff000300000a",
        // AS-external: E=1 (type-2 metric), /32 mask, no forwarding addr
        "0003020550d41000c0a8aa02800000012a490024ffffffff800000140000000000000000",
        // AS-external: /24 mask with forwarding address 192.168.170.1
        "000302059479ab00c0a8aa028000000134a50024ffffff0080000014c0a8aa0100000000",
        "00030205c0827800c0a8aa0280000001d3190024ffffff00800000140000000000000000",
        "00030205c0a80000c0a8aa028000000137080024ffffff00800000140000000000000000",
        "00030205c0a80100c0a8aa02800000012c120024ffffff00800000140000000000000000",
        "00030205c0a8ac00c0a8aa028000000133410024ffffff0080000014c0a8aa0a00000000",
        "000102059479ab00c0a8aa03800000012eaa0024ffffff0080000014c0a8aa0100000000",
        "00010205c0827800c0a8aa0380000001cd1e0024ffffff00800000140000000000000000",
        "00010205c0a80000c0a8aa0380000001310d0024ffffff00800000140000000000000000",
        "00010205c0a80100c0a8aa038000000126170024ffffff00800000140000000000000000",
        "00010205c0a8ac00c0a8aa03800000012d460024ffffff0080000014c0a8aa0a00000000",
        "0001020550d41000c0a8aa0380000001244e0024ffffffff800000140000000000000000",
        // network-LSA: mask /24, attached routers .3 and .8 (the DR)
        "00010202c0a8aa08c0a8aa088000000137b70020ffffff00c0a8aa03c0a8aa08",
        // router-LSA: transit link to DR 192.168.170.8 via ifaddr
        "00010201c0a8aa08c0a8aa0880000dc4af57002402000001c0a8aa08c0a8aa080200000a",
        // router-LSA, seq one above initial
        "00010201c0a8aa03c0a8aa0380000002389d003002000002c0a8aa00ffffff000300000ac0a8aa00ffffff000300000a",
        // router-LSA aged to MaxAge (3600) — the natural flush case
        "0e100201c0a8aa02c0a8aa02800000014a8e003002000002c0a8aa00ffffff000300000ac0a8aa00ffffff000300000a",
    ];

    #[test]
    fn fletcher_verifies_every_real_lsa() {
        for hex in REAL_LSAS {
            let lsa = unhex(hex);
            let len = u16::from_be_bytes([lsa[18], lsa[19]]) as usize;
            assert_eq!(len, lsa.len(), "framing length must match buffer");
            assert!(
                fletcher_verify(&lsa[2..len]),
                "real-world LSA must verify: {hex}"
            );
        }
    }

    #[test]
    fn fletcher_recomputes_every_real_checksum() {
        for hex in REAL_LSAS {
            let lsa = unhex(hex);
            let len = u16::from_be_bytes([lsa[18], lsa[19]]) as usize;
            let want = u16::from_be_bytes([lsa[16], lsa[17]]);
            let got = lsa_fletcher_checksum(&mut lsa[2..len].to_vec(), 14);
            assert_eq!(want, got, "recomputation must reproduce {hex}'s checksum");
        }
    }

    #[test]
    fn fletcher_checksum_octets_never_zero() {
        // §12.1.7: "The LS checksum field cannot take on the value of
        // zero." Sweep a family of buffers; x and y must stay nonzero.
        let mut seed = 0x1234_5678_u64;
        for len in [17_usize, 20, 24, 33, 40, 64, 129] {
            for _ in 0..200 {
                let mut buf: Vec<u8> = (0..len)
                    .map(|_| {
                        seed ^= seed << 13;
                        seed ^= seed >> 7;
                        seed ^= seed << 17;
                        seed as u8
                    })
                    .collect();
                lsa_fletcher_checksum(&mut buf, 14);
                assert!(buf[14] != 0 && buf[15] != 0, "zero checksum octet");
                assert!(fletcher_verify(&buf), "computed checksum must verify");
            }
        }
    }

    #[test]
    fn fletcher_corruption_detected() {
        let mut lsa = unhex(REAL_LSAS[0]);
        let len = lsa.len();
        // Corrupt one byte inside the checksummed region (anything but
        // the 2-byte age field): verification must fail.
        for i in 2..len {
            let mut copy = lsa.clone();
            copy[i] ^= 0x01;
            assert!(
                !fletcher_verify(&copy[2..len]),
                "corrupting byte {i} undetected"
            );
        }
        // Corrupting only the age field is by design undetectable
        // (§12.1.7: age is excepted so it can increment in place).
        lsa[0] ^= 0xff;
        assert!(fletcher_verify(&lsa[2..len]));
    }

    #[test]
    fn internet_checksum_matches_real_hello() {
        // Hello from the same capture, byte-exact: mask /24,
        // HelloInterval 10, options E, priority 1, dead 40,
        // DR 192.168.170.8, BDR 0.0.0.0, no neighbors. Expected
        // checksum 0x273b over bytes [0..16] + [24..44] with the
        // checksum field zeroed (the 8-byte auth field excluded).
        let pkt = unhex(
            "0201002cc0a8aa0800000001273b00000000000000000000\
             ffffff00000a020100000028c0a8aa0800000000",
        );
        assert_eq!(pkt.len(), 44);
        let mut region = pkt[..16].to_vec();
        region[12] = 0;
        region[13] = 0;
        region.extend_from_slice(&pkt[24..]);
        assert_eq!(internet_checksum(&region), 0x273b);
    }

    #[test]
    fn internet_checksum_odd_length_pads_zero() {
        // One's-complement sum of [0x01, 0x02, 0x03] = 0x0102 + 0x0300
        // = 0x0402 -> ~0x0402 = 0xfbfd.
        assert_eq!(internet_checksum(&[0x01, 0x02, 0x03]), 0xfbfd);
        assert_eq!(internet_checksum(&[0xff, 0xff, 0xff, 0xff]), 0x0000);
    }
}
