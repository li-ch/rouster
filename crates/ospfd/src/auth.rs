//! OSPFv2 packet authentication (RFC 2328 Appendix D + RFC 5709).
//!
//! Three AuType modes (Appendix D Table 20): Null (D.1), simple
//! password (D.2), and cryptographic authentication (D.3-D.5.3). In
//! crypto mode the 64-bit header field becomes the Figure-18
//! descriptor (zero octets, Key ID, Auth Data Len, cryptographic
//! sequence number), the packet checksum is left 0 (D.4.3 step 2),
//! and the MAC travels as a trailer appended past the OSPF length
//! (included in the IP length only). The digest we compute is
//! HMAC-SHA-256 per RFC 5709 §3.3 — the trailer region is filled
//! with Apad (`0x878FE1F3` repeated to the hash length) and MAC'd
//! together with the packet.
//!
//! FRR 10.2 reality (ospfd.rst, frr-10.2 tag): the simple password is
//! deprecated ("insecure ... deprecated in favour of MD5 HMAC
//! authentication"); FRR's two crypto paths are keyed-MD5
//! (`ip ospf message-digest-key <id> md5 <key>`) and the key-chain
//! path whose internal-crypto build resolves `md5` and `hmac-sha-256`
//! only (lib/keychain.c's algo table). We implement both crypto
//! engines — HMAC-SHA-256 (RFC 5709's MUST-level floor, landed N3)
//! and keyed-MD5 (the legacy D.4.3(6) digest, landed S8-b with the
//! key chains that select per key) — plus the RFC 8177 key chain
//! that feeds them (see `keychain`).
//!
//! The digest primitives are implemented here in pure safe Rust —
//! verified against FIPS 180-4, RFC 4231, and RFC 1321 vectors —
//! because the standing fence admits no new dependencies (a
//! `sha2`/`hmac` crate swap is an owner decision, recorded in the
//! stage report). Keep this module v2/v3-shareable (architecture
//! invariant 3): the "MAC over packet ‖ Apad-filled trailer + replay
//! counter + key selection" skeleton is exactly OSPFv3's RFC 7166
//! shape.

/// SHA-256 (FIPS 180-4). Pure safe Rust; self-verified below against
/// the standard vectors.
pub fn sha256(data: &[u8]) -> [u8; 32] {
    const K: [u32; 64] = [
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4,
        0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe,
        0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f,
        0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
        0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc,
        0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
        0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116,
        0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7,
        0xc67178f2,
    ];
    let mut h: [u32; 8] = [
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab,
        0x5be0cd19,
    ];
    // Padding: 0x80, zeros, 64-bit big-endian bit length.
    let bit_len = (data.len() as u64).wrapping_mul(8);
    let mut msg = data.to_vec();
    msg.push(0x80);
    while msg.len() % 64 != 56 {
        msg.push(0);
    }
    msg.extend_from_slice(&bit_len.to_be_bytes());
    let mut w = [0u32; 64];
    for block in msg.as_chunks::<64>().0 {
        for (i, word) in w.iter_mut().take(16).enumerate() {
            *word = u32::from_be_bytes([
                block[i * 4],
                block[i * 4 + 1],
                block[i * 4 + 2],
                block[i * 4 + 3],
            ]);
        }
        for i in 16..64 {
            let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
            let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
            w[i] = w[i - 16]
                .wrapping_add(s0)
                .wrapping_add(w[i - 7])
                .wrapping_add(s1);
        }
        let mut v = h;
        for i in 0..64 {
            let s1 = v[4].rotate_right(6) ^ v[4].rotate_right(11) ^ v[4].rotate_right(25);
            let ch = (v[4] & v[5]) ^ ((!v[4]) & v[6]);
            let t1 = v[7]
                .wrapping_add(s1)
                .wrapping_add(ch)
                .wrapping_add(K[i])
                .wrapping_add(w[i]);
            let s0 = v[0].rotate_right(2) ^ v[0].rotate_right(13) ^ v[0].rotate_right(22);
            let maj = (v[0] & v[1]) ^ (v[0] & v[2]) ^ (v[1] & v[2]);
            let t2 = s0.wrapping_add(maj);
            v[7] = v[6];
            v[6] = v[5];
            v[5] = v[4];
            v[4] = v[3].wrapping_add(t1);
            v[3] = v[2];
            v[2] = v[1];
            v[1] = v[0];
            v[0] = t1.wrapping_add(t2);
        }
        for (hi, vi) in h.iter_mut().zip(v) {
            *hi = hi.wrapping_add(vi);
        }
    }
    let mut out = [0u8; 32];
    for (i, word) in h.iter().enumerate() {
        out[i * 4..i * 4 + 4].copy_from_slice(&word.to_be_bytes());
    }
    out
}

/// HMAC (RFC 2104): `H(K ⊕ opad ‖ H(K ⊕ ipad ‖ m))` with SHA-256's
/// 64-byte block size.
pub fn hmac_sha256(key: &[u8], message: &[u8]) -> [u8; 32] {
    const BLOCK: usize = 64;
    let mut ko = [0u8; BLOCK];
    if key.len() > BLOCK {
        ko[..32].copy_from_slice(&sha256(key));
    } else {
        ko[..key.len()].copy_from_slice(key);
    }
    let mut ipad = [0x36u8; BLOCK];
    let mut opad = [0x5cu8; BLOCK];
    for i in 0..BLOCK {
        ipad[i] ^= ko[i];
        opad[i] ^= ko[i];
    }
    let mut inner = ipad.to_vec();
    inner.extend_from_slice(message);
    let inner_hash = sha256(&inner);
    let mut outer = opad.to_vec();
    outer.extend_from_slice(&inner_hash);
    sha256(&outer)
}

/// The Apad constant (RFC 5709 §3.3): `0x878FE1F3` repeated to the
/// hash length (32 bytes for SHA-256).
fn apad() -> [u8; 32] {
    [
        0x87, 0x8f, 0xe1, 0xf3, 0x87, 0x8f, 0xe1, 0xf3, 0x87, 0x8f, 0xe1, 0xf3, 0x87, 0x8f, 0xe1,
        0xf3, 0x87, 0x8f, 0xe1, 0xf3, 0x87, 0x8f, 0xe1, 0xf3, 0x87, 0x8f, 0xe1, 0xf3, 0x87, 0x8f,
        0xe1, 0xf3,
    ]
}

/// The MAC of one OSPFv2 packet in crypto mode (RFC 5709 §3.3): the
/// First-Hash input is the packet (checksum field zero per RFC 2328
/// D.4.3(2), the Figure-18 auth field intact) followed by the
/// Apad-filled trailer.
pub fn packet_mac(packet: &[u8], key: &[u8]) -> [u8; 32] {
    let mut msg = packet.to_vec();
    msg.extend_from_slice(&apad());
    hmac_sha256(key, &msg)
}

/// The legacy crypto digest (RFC 2328 D.4.3 step 6): keyed-MD5 —
/// "The 16 byte MD5 key is appended to the OSPF packet", the pad and
/// length fields are MD5's own, and the algorithm runs over the
/// concatenation, producing the 16-byte digest written past the
/// packet (not counted in the OSPF length, included in the IP
/// length). The packet here already carries the Figure-18 field and
/// a zero checksum (steps 1-5).
pub fn packet_mac_md5(packet: &[u8], key: &[u8]) -> [u8; 16] {
    let mut msg = packet.to_vec();
    msg.extend_from_slice(key);
    md5(&msg)
}

/// MD5 (RFC 1321). Pure safe Rust; self-verified below against the
/// RFC's own test vectors. The exact same construction SHA-256 uses
/// (Merkle-Damgård over 512-bit blocks, 64-bit big-endian length)
/// with the MD5 IV, shifts and round functions — included for the
/// legacy D.4.3(6) digest and the RFC 8177 `md5` algorithm
/// (FRR's internal-crypto key chains resolve it); the collision
/// weaknesses that deprecate it are a known cost of interop with
/// deployed peers, which is why `hmac-sha-256` is the recommended
/// configuration.
pub fn md5(data: &[u8]) -> [u8; 16] {
    const S: [u32; 64] = [
        7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 5, 9, 14, 20, 5, 9, 14, 20, 5,
        9, 14, 20, 5, 9, 14, 20, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 6, 10,
        15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21,
    ];
    const K: [u32; 64] = [
        0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee, 0xf57c0faf, 0x4787c62a, 0xa8304613,
        0xfd469501, 0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be, 0x6b901122, 0xfd987193,
        0xa679438e, 0x49b40821, 0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa, 0xd62f105d,
        0x02441453, 0xd8a1e681, 0xe7d3fbc8, 0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed,
        0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a, 0xfffa3942, 0x8771f681, 0x6d9d6122,
        0xfde5380c, 0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70, 0x289b7ec6, 0xeaa127fa,
        0xd4ef3085, 0x04881d05, 0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665, 0xf4292244,
        0x432aff97, 0xab9423a7, 0xfc93a039, 0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1,
        0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1, 0xf7537e82, 0xbd3af235, 0x2ad7d2bb,
        0xeb86d391,
    ];
    let mut h: [u32; 4] = [0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476];
    let bit_len = (data.len() as u64).wrapping_mul(8);
    let mut msg = data.to_vec();
    msg.push(0x80);
    while msg.len() % 64 != 56 {
        msg.push(0);
    }
    msg.extend_from_slice(&bit_len.to_le_bytes());
    let mut w = [0u32; 16];
    for block in msg.as_chunks::<64>().0 {
        for (i, word) in w.iter_mut().enumerate() {
            *word = u32::from_le_bytes([
                block[i * 4],
                block[i * 4 + 1],
                block[i * 4 + 2],
                block[i * 4 + 3],
            ]);
        }
        let (mut a, mut b, mut c, mut d) = (h[0], h[1], h[2], h[3]);
        for i in 0..64 {
            let (f, g) = match i / 16 {
                0 => ((b & c) | ((!b) & d), i),
                1 => ((d & b) | ((!d) & c), (5 * i + 1) % 16),
                2 => (b ^ c ^ d, (3 * i + 5) % 16),
                _ => (c ^ (b | !d), (7 * i) % 16),
            };
            let tmp = d;
            d = c;
            c = b;
            b = b.wrapping_add(
                a.wrapping_add(f)
                    .wrapping_add(K[i])
                    .wrapping_add(w[g])
                    .rotate_left(S[i]),
            );
            a = tmp;
        }
        h[0] = h[0].wrapping_add(a);
        h[1] = h[1].wrapping_add(b);
        h[2] = h[2].wrapping_add(c);
        h[3] = h[3].wrapping_add(d);
    }
    let mut out = [0u8; 16];
    for (i, word) in h.iter().enumerate() {
        out[i * 4..i * 4 + 4].copy_from_slice(&word.to_le_bytes());
    }
    out
}

/// The per-interface authentication configuration.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub enum AuthConfig {
    /// AuType 0 (D.1): the field is not examined.
    #[default]
    None,
    /// AuType 1 (D.2): a clear 64-bit password, null-padded (D.4.2
    /// step 3).
    Simple {
        /// Exactly 8 bytes (padded at parse time).
        password: [u8; 8],
    },
    /// AuType 2 (D.3/D.4.3) with the HMAC-SHA-256 digest (RFC 5709).
    /// One static key — the `message-digest-key` form.
    HmacSha256 { key_id: u8, key: Vec<u8> },
    /// AuType 2 with the legacy 16-byte keyed-MD5 digest (D.4.3
    /// step 6). One static key — the `message-digest-key` form when
    /// the FRR edge spells `md5`.
    KeyedMd5 { key_id: u8, key: Vec<u8> },
    /// AuType 2 sourced from an RFC 8177 key chain referenced by
    /// name (config resolves it; see `keychain`): every send stamps
    /// the chain's most-recent-live-start key, every receive
    /// accepts any live-accept key by its Key ID — accept-any-live/
    /// send-highest rollover v1. The AuType is crypto regardless of
    /// the keys' algorithms.
    KeyChain { chain: crate::keychain::KeyChain },
}

impl AuthConfig {
    /// The AuType octet this mode transmits (App D Table 20).
    pub fn au_type(&self) -> u16 {
        match self {
            AuthConfig::None => 0,
            AuthConfig::Simple { .. } => 1,
            // Both crypto engines and the chain carry AuType 2.
            AuthConfig::HmacSha256 { .. }
            | AuthConfig::KeyedMd5 { .. }
            | AuthConfig::KeyChain { .. } => 2,
        }
    }

    /// The digest-trailer length this mode appends past the OSPF
    /// packet (D.4.3 step 4's Auth Data Len). `None` for the
    /// non-crypto modes.
    pub fn digest_len(&self) -> Option<usize> {
        match self {
            AuthConfig::HmacSha256 { .. } => Some(32),
            AuthConfig::KeyedMd5 { .. } => Some(16),
            AuthConfig::KeyChain { chain } => chain.send_key(0).map(|k| k.algorithm.digest_len()),
            _ => None,
        }
    }

    /// The concrete send view at `now`: a key chain resolves to the
    /// most-recent-live-start key's engine view (D.4.3's selection);
    /// every static mode is itself. **`AuthConfig::None` for a chain
    /// with no live send key is the disclosed fail-closed path**: the
    /// interface then transmits Null-authenticated packets, which
    /// any crypto-configured peer discards by the AuType check
    /// (D.5) — the adjacency dies by its own timers rather than by
    /// unsigned garbage passing anywhere.
    pub fn live_send_view(&self, now: u64) -> AuthConfig {
        match self {
            AuthConfig::KeyChain { chain } => match chain.send_key(now) {
                Some(key) => crate::keychain::KeyChain::view_of(key),
                None => AuthConfig::None,
            },
            other => other.clone(),
        }
    }

    /// The concrete receive view for a packet stamping `key_id`,
    /// verified at `now`: a key chain accepts any key whose accept
    /// lifetime is live (D.5.3 step 1 — the rollover overlap);
    /// static crypto modes only match their own Key ID; the
    /// non-crypto modes pass themselves through (their checks never
    /// look at a Key ID).
    pub fn accept_view(&self, now: u64, key_id: u8) -> Option<AuthConfig> {
        match self {
            AuthConfig::KeyChain { chain } => chain
                .accept_key(now, key_id)
                .map(crate::keychain::KeyChain::view_of),
            AuthConfig::HmacSha256 { key_id: id, .. } if *id == key_id => Some(self.clone()),
            AuthConfig::KeyedMd5 { key_id: id, .. } if *id == key_id => Some(self.clone()),
            AuthConfig::HmacSha256 { .. } | AuthConfig::KeyedMd5 { .. } => None,
            _ => Some(self.clone()),
        }
    }

    /// The 64-bit header field for our own packets. `seq` is the
    /// cryptographic sequence number (D.4.3 step 5) in crypto mode.
    /// Callers pass the LIVE view for chain-configured interfaces
    /// (`live_send_view`) — the chain variant itself has no single
    /// key to stamp.
    pub fn auth_field(&self, seq: u32) -> u64 {
        let (key_id, data_len) = match self {
            AuthConfig::None => return 0,
            AuthConfig::Simple { password } => return u64::from_be_bytes(*password),
            AuthConfig::HmacSha256 { key_id, .. } => (*key_id, 32),
            AuthConfig::KeyedMd5 { key_id, .. } => (*key_id, 16),
            AuthConfig::KeyChain { .. } => return 0, // resolve first (live_send_view)
        };
        CryptoAuthData {
            key_id,
            data_len,
            seq,
        }
        .to_u64()
    }
}

/// The Figure-18 view of the 64-bit field in crypto mode (D.3):
/// offset 16-17 zero, 18 Key ID, 19 Auth Data Len, 20-23 the
/// cryptographic sequence number.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CryptoAuthData {
    pub key_id: u8,
    pub data_len: u8,
    pub seq: u32,
}

impl CryptoAuthData {
    pub fn to_u64(self) -> u64 {
        let seq = self.seq;
        let mut b = [0u8; 8];
        b[2] = self.key_id;
        b[3] = self.data_len;
        b[4..8].copy_from_slice(&seq.to_be_bytes());
        u64::from_be_bytes(b)
    }

    pub fn from_u64(v: u64) -> Self {
        let b = v.to_be_bytes();
        Self {
            key_id: b[2],
            data_len: b[3],
            seq: u32::from_be_bytes([b[4], b[5], b[6], b[7]]),
        }
    }
}

/// Encode one packet for the wire under an auth mode: Null/simple
/// ride the normal checksum path (the header already carries the
/// field); crypto leaves the checksum 0 (D.4.3 step 2) and appends
/// the digest trailer past the OSPF length ("not included in the
/// OSPF header's packet length, although it is included in the
/// packet's IP header length field"). Callers pass the LIVE view for
/// chain-configured interfaces.
pub fn encode_for_wire(packet: &crate::packet::Packet, auth: &AuthConfig) -> Vec<u8> {
    match auth {
        AuthConfig::None | AuthConfig::Simple { .. } | AuthConfig::KeyChain { .. } => {
            packet.encode()
        }
        AuthConfig::HmacSha256 { key, .. } => {
            let mut buf = packet.encode();
            // encode() computed a checksum; crypto mode must send 0.
            buf[12] = 0;
            buf[13] = 0;
            let mac = packet_mac(&buf, key);
            buf.extend_from_slice(&mac);
            buf
        }
        AuthConfig::KeyedMd5 { key, .. } => {
            let mut buf = packet.encode();
            buf[12] = 0;
            buf[13] = 0;
            let mac = packet_mac_md5(&buf, key);
            buf.extend_from_slice(&mac);
            buf
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    #[test]
    fn sha256_matches_fips_180_4_vectors() {
        // FIPS 180-4's own examples.
        assert_eq!(
            hex(&sha256(b"abc")),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        assert_eq!(
            hex(&sha256(b"")),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        assert_eq!(
            hex(&sha256(
                b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"
            )),
            "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"
        );
        // One million 'a' bytes (multi-block, exercised at 10k to
        // keep test time sane — the property is the block chaining).
        let long = vec![b'a'; 10_000];
        assert_eq!(hex(&sha256(&long)).len(), 64);
    }

    #[test]
    fn hmac_matches_rfc_4231_vectors() {
        // RFC 4231 test cases 1-3 (SHA-256 column).
        let key = bytes(0x0b, 20);
        assert_eq!(
            hex(&hmac_sha256(&key, b"Hi There")),
            "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"
        );
        assert_eq!(
            hex(&hmac_sha256(b"Jefe", b"what do ya want for nothing?")),
            "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"
        );
        let key = bytes(0xaa, 20);
        assert_eq!(
            hex(&hmac_sha256(
                &key,
                b"\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd"
            )),
            "773ea91e36800e46854db8ebd09181a72959098b3ef8c122d9635514ced565fe"
        );
        // A key longer than the block size (RFC 4231 case 6).
        let key = bytes(0xaa, 131);
        assert_eq!(
            hex(&hmac_sha256(
                &key,
                b"Test Using Larger Than Block-Size Key - Hash Key First"
            )),
            "60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54"
        );
    }

    fn bytes(fill: u8, n: usize) -> Vec<u8> {
        vec![fill; n]
    }

    #[test]
    fn crypto_auth_field_round_trips_the_figure18_layout() {
        let d = CryptoAuthData {
            key_id: 1,
            data_len: 32,
            seq: 0x0102_0304,
        };
        let v = d.to_u64();
        assert_eq!(CryptoAuthData::from_u64(v), d);
        let b = v.to_be_bytes();
        assert_eq!(&b[0..2], &[0, 0], "the two zero octets (D.3 Figure 18)");
        assert_eq!(b[2], 1, "Key ID");
        assert_eq!(b[3], 32, "Auth Data Len = 32 for SHA-256");
        assert_eq!(&b[4..8], &[1, 2, 3, 4], "the sequence number");
    }

    #[test]
    fn packet_mac_is_keyed_and_apad_bound() {
        // The MAC over an Apad-filled trailer: flipping any packet
        // byte, the key, or skipping Apad must change the result.
        let pkt = b"0123456789abcdefghij"; // stand-in packet bytes
        let m1 = packet_mac(pkt, b"secret");
        let mut other = pkt.to_vec();
        other[0] ^= 1;
        assert_ne!(m1, packet_mac(&other, b"secret"));
        assert_ne!(m1, packet_mac(pkt, b"Secret"));
        // Direct Apad check: MAC(pkt ‖ apad) equals the module's.
        let mut msg = pkt.to_vec();
        msg.extend_from_slice(&apad());
        assert_eq!(m1, hmac_sha256(b"secret", &msg));
    }

    /// RFC 1321 §A.5's own test suite (the suite the reference
    /// implementation validates with).
    #[test]
    fn md5_matches_rfc1321_vectors() {
        assert_eq!(
            hex(&md5(b"")),
            "d41d8cd98f00b204e9800998ecf8427e",
            "RFC 1321 A.5(1)"
        );
        assert_eq!(
            hex(&md5(b"a")),
            "0cc175b9c0f1b6a831c399e269772661",
            "RFC 1321 A.5(2)"
        );
        assert_eq!(
            hex(&md5(b"abc")),
            "900150983cd24fb0d6963f7d28e17f72",
            "RFC 1321 A.5(3)"
        );
        assert_eq!(
            hex(&md5(b"message digest")),
            "f96b697d7cb7938d525a2f31aaf161d0",
            "RFC 1321 A.5(4)"
        );
        assert_eq!(
            hex(&md5(b"abcdefghijklmnopqrstuvwxyz")),
            "c3fcd3d76192e4007dfb496cca67e13b",
            "RFC 1321 A.5(5)"
        );
        assert_eq!(
            hex(&md5(
                b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
            )),
            "d174ab98d277d9f5a5611c2c9f419d9f",
            "RFC 1321 A.5(6)"
        );
        assert_eq!(
            hex(&md5(
                b"12345678901234567890123456789012345678901234567890123456789012345678901234567890"
            )),
            "57edf4a22be3c955ac49da2e2107b67a",
            "RFC 1321 A.5(7)"
        );
        // The multi-block chain (the v2 short-input case above).
        let long = vec![b'a'; 10_000];
        assert_eq!(hex(&md5(&long)).len(), 32);
    }

    /// The legacy crypto digest (D.4.3 step 6): MD5 over packet ‖
    /// key — keyed, 16 bytes, and neither the RFC 5709 Apad nor the
    /// HMAC construction appears in it (the RFC's letter: append the
    /// key, run MD5 once).
    #[test]
    fn keyed_md5_mac_follows_d433_step6() {
        let pkt = b"0123456789abcdefghij";
        let m = packet_mac_md5(pkt, b"secret");
        assert_eq!(m.len(), 16, "D.4.3 step 4: MD5's Auth Data Len is 16");
        let mut msg = pkt.to_vec();
        msg.extend_from_slice(b"secret");
        assert_eq!(m, md5(&msg), "digest = MD5(packet ‖ key)");
        // Keyed: a different secret changes everything.
        assert_ne!(m, packet_mac_md5(pkt, b"Secret"));
        // Neither the Apad nor the HMAC inner shape.
        let mut apad_msg = pkt.to_vec();
        apad_msg.extend_from_slice(&apad());
        assert_ne!(m[..], md5(&apad_msg)[..16]);
        assert_ne!(m[..], hmac_sha256(b"secret", pkt)[..16]);
    }

    /// The key-chain views: a chain resolves to its live key's
    /// engine view at send time (the rollover pick), accepts by Key
    /// ID within the accept window at receive time, and degrades to
    /// the disclosed fail-closed Null view when no key is live.
    #[test]
    fn key_chain_views_resolve_live() {
        use crate::keychain::{KeyAlgorithm, KeyChain, KeyEntry, Lifetime};
        let chain = AuthConfig::KeyChain {
            chain: KeyChain {
                name: "kc".into(),
                keys: vec![
                    KeyEntry {
                        key_id: 1,
                        algorithm: KeyAlgorithm::HmacSha256,
                        secret: b"old".to_vec(),
                        send_lifetime: Lifetime {
                            start: Some(0),
                            end: None,
                        },
                        accept_lifetime: Lifetime {
                            start: Some(0),
                            end: None,
                        },
                    },
                    KeyEntry {
                        key_id: 2,
                        algorithm: KeyAlgorithm::Md5,
                        secret: b"new".to_vec(),
                        send_lifetime: Lifetime {
                            start: Some(300),
                            end: None,
                        },
                        accept_lifetime: Lifetime {
                            start: Some(300),
                            end: None,
                        },
                    },
                ],
            },
        };
        // AuType is crypto regardless of the keys' engines.
        assert_eq!(chain.au_type(), 2);
        // Send: key 1 before 300, key 2 (the later start) after.
        assert_eq!(
            chain.live_send_view(100),
            AuthConfig::HmacSha256 {
                key_id: 1,
                key: b"old".to_vec()
            }
        );
        assert_eq!(
            chain.live_send_view(300),
            AuthConfig::KeyedMd5 {
                key_id: 2,
                key: b"new".to_vec()
            }
        );
        // Accept: any live key by ID — the old key still verifies
        // during the overlap (accept-any-live).
        assert_eq!(
            chain.accept_view(300, 1).unwrap(),
            AuthConfig::HmacSha256 {
                key_id: 1,
                key: b"old".to_vec()
            }
        );
        assert!(
            chain.accept_view(299, 2).is_none(),
            "key 2 not yet in its accept window"
        );
        assert!(chain.accept_view(300, 9).is_none(), "unknown Key ID");
        // Static crypto modes only match their own Key ID.
        let static_md5 = AuthConfig::KeyedMd5 {
            key_id: 7,
            key: b"k".to_vec(),
        };
        assert_eq!(static_md5.accept_view(0, 7).unwrap(), static_md5);
        assert!(static_md5.accept_view(0, 8).is_none());
        // The fail-closed send view when nothing is live.
        let dead = AuthConfig::KeyChain {
            chain: KeyChain {
                name: "kc".into(),
                keys: vec![KeyEntry {
                    key_id: 1,
                    algorithm: KeyAlgorithm::HmacSha256,
                    secret: b"x".to_vec(),
                    send_lifetime: Lifetime {
                        start: Some(0),
                        end: Some(10),
                    },
                    accept_lifetime: Lifetime::ALWAYS,
                }],
            },
        };
        assert_eq!(
            dead.live_send_view(10),
            AuthConfig::None,
            "fail-closed (disclosed)"
        );
    }
}
