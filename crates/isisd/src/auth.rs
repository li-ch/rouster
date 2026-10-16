//! IS-IS authentication: TLV 10 cleartext (ISO 10589 §9.7) and
//! HMAC-MD5 (RFC 5304), with key chains in the ospfd `keychain.rs`
//! pattern (RFC 8177's rollover model).
//!
//! **The engines** follow the ospfd precedent (`crates/ospfd/src/
//! auth.rs`): MD5 (RFC 1321) and HMAC (RFC 2104) in pure safe Rust,
//! self-verified against the RFCs' own test vectors — no new
//! dependencies. MD5's collision weaknesses are a known cost of
//! interop with deployed peers (RFC 5304 has no stronger successor
//! on the IS-IS wire besides RFC 5310's SHA family, §Deferred).
//!
//! **RFC 5304's wire shape**: authentication type 54, "the length of
//! the Authentication Value for HMAC-MD5 is 16, and the length field
//! in the TLV is 17" — one key-id-free octet-prefixed digest (§3.4
//! considered and rejected a Key ID field; rollover instead rides
//! RFC 5304 §2's permission that a receiver "MAY" check multiple
//! passwords). The digest text is "the IS-IS PDU to be authenticated
//! with the Authentication Value field ... set to zero" and, for
//! LSPs, "the Checksum and Remaining Lifetime fields are set to zero
//! (0) before authentication is computed" — the lifetime exclusion is
//! what lets a re-flooding IS decrement it without breaking the
//! digest. Verification failure: "MUST discard the PDU if the
//! Authentication Value is incorrect."
//!
//! **Key chains** (RFC 8177, the ospfd shape): keys with send and
//! accept lifetimes on the injected clock; the sender uses the live
//! key with the most recent start (§2.3), the receiver accepts any
//! key inside its accept window — on IS-IS that means trying every
//! live accept key against the digest, since nothing on the wire
//! names the key.
//!
//! **SNP authentication modes** (the per-PDU family ISO §7.3.15.1.3
//! gates on the receive-password set): `Off` (never include, never
//! require), `SendOnly` (include on transmit, tolerate absence on
//! receipt — RFC 5304 §2's transition mode), `Validate` (include and
//! require).

use crate::tlv::{Tlv, AUTH_CLEARTEXT, AUTH_HMAC_MD5, TLV_AUTHENTICATION};

/// MD5 (RFC 1321). Pure safe Rust, verified below against the RFC's
/// own test vectors — the exact ospfd `auth.rs` construction
/// (Merkle-Damgård over 512-bit blocks, 64-bit little-endian length,
/// MD5's IV, shifts and round functions).
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

/// HMAC-MD5 (RFC 2104): `H(K ⊕ opad ‖ H(K ⊕ ipad ‖ m))` with MD5's
/// 64-byte block size.
pub fn hmac_md5(key: &[u8], message: &[u8]) -> [u8; 16] {
    const BLOCK: usize = 64;
    let mut ko = [0u8; BLOCK];
    if key.len() > BLOCK {
        ko[..16].copy_from_slice(&md5(key));
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
    let inner_hash = md5(&inner);
    let mut outer = opad.to_vec();
    outer.extend_from_slice(&inner_hash);
    md5(&outer)
}

/// A send or accept lifetime: `start` inclusive, `end` exclusive;
/// `None` bounds are unbounded (RFC 8177's "always"/"no-end-time" —
/// the ospfd `keychain.rs` shape).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Lifetime {
    pub start: Option<u64>,
    pub end: Option<u64>,
}

impl Lifetime {
    pub const ALWAYS: Lifetime = Lifetime {
        start: None,
        end: None,
    };

    /// The window test: `start <= now < end`.
    pub fn live(&self, now: u64) -> bool {
        self.start.is_none_or(|s| s <= now) && self.end.is_none_or(|e| now < e)
    }
}

/// The per-key crypto algorithm (RFC 5304's two wire forms).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthAlgorithm {
    Cleartext,
    HmacMd5,
}

/// One key in the chain (RFC 8177 §2.2's parameters minus the Key ID
/// — RFC 5304 §3.4 rejected one for IS-IS, so nothing on the wire
/// names the key).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthKey {
    pub algorithm: AuthAlgorithm,
    pub secret: Vec<u8>,
    pub send_lifetime: Lifetime,
    pub accept_lifetime: Lifetime,
}

/// A key chain (RFC 8177): the rollover machinery. The sender uses
/// the live key with the most recent start (§2.3 + the ospfd
/// send-highest rule); the receiver accepts any key whose accept
/// lifetime is live (RFC 5304 §2's multiple-password permission —
/// the digest is tried against each).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct KeyChain {
    pub keys: Vec<AuthKey>,
}

impl KeyChain {
    /// The send-side selection: among live send keys, the latest
    /// start (deterministic last-wins on equal starts).
    pub fn send_key(&self, now: u64) -> Option<&AuthKey> {
        self.keys
            .iter()
            .filter(|k| k.send_lifetime.live(now))
            .max_by_key(|k| k.send_lifetime.start.unwrap_or(0))
    }

    /// The receive-side candidates at `now` (accept-any-live).
    pub fn accept_keys(&self, now: u64) -> impl Iterator<Item = &AuthKey> {
        self.keys
            .iter()
            .filter(move |k| k.accept_lifetime.live(now))
    }

    pub fn is_empty(&self) -> bool {
        self.keys.is_empty()
    }
}

/// How CSNPs/PSNPs treat authentication (ISO §7.3.15's receive-
/// password gating; FRR's `authenticate snp` modes).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum SnpAuth {
    /// Never include the TLV, never require it.
    #[default]
    Off,
    /// Include on transmit, tolerate absence on receipt (RFC 5304
    /// §2's transition mode).
    SendOnly,
    /// Include and require.
    Validate,
}

impl SnpAuth {
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "off" => Some(Self::Off),
            "send-only" => Some(Self::SendOnly),
            "validate" => Some(Self::Validate),
            _ => None,
        }
    }
}

/// One level's authentication configuration (area password at L1,
/// domain password at L2 — ISO §7.3.7/§7.3.9's per-level transmit
/// passwords).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct LevelAuth {
    pub chain: KeyChain,
    pub snp: SnpAuth,
}

impl LevelAuth {
    pub fn enabled(&self) -> bool {
        !self.chain.is_empty()
    }
}

/// Where a TLV 10's value sits inside the encoded PDU (found by
/// walking the TLV block from the fixed part).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AuthValueAt {
    pub auth_type: u8,
    pub offset: usize,
    pub len: usize,
}

/// Find the authentication TLV in an encoded PDU. `fixed` is the
/// common-header-pinned fixed-part size (the length indicator —
/// TLV blocks start there).
pub fn find_auth_tlv(pdu: &[u8], fixed: usize) -> Option<AuthValueAt> {
    let mut pos = fixed;
    while pos + 2 <= pdu.len() {
        let kind = pdu[pos];
        let len = pdu[pos + 1] as usize;
        let value_at = pos + 2;
        if value_at + len > pdu.len() {
            return None; // malformed; the codec rejects elsewhere
        }
        if kind == TLV_AUTHENTICATION {
            if len == 0 {
                return None;
            }
            return Some(AuthValueAt {
                auth_type: pdu[value_at],
                offset: value_at + 1,
                len: len - 1,
            });
        }
        pos = value_at + len;
    }
    None
}

/// The HMAC-MD5 digest of one PDU per RFC 5304 §2: the encoded bytes
/// with the Authentication Value zeroed, and — for LSPs — the
/// Checksum (bytes 24..26) and Remaining Lifetime (bytes 10..12)
/// zeroed as well. The input is copied; the caller's bytes are not
/// modified.
pub fn hmac_md5_digest(pdu: &[u8], auth: AuthValueAt, is_lsp: bool, key: &[u8]) -> [u8; 16] {
    let mut text = pdu.to_vec();
    for b in &mut text[auth.offset..auth.offset + auth.len.min(16)] {
        *b = 0;
    }
    if is_lsp {
        for b in &mut text[10..12] {
            *b = 0; // Remaining Lifetime
        }
        for b in &mut text[24..26] {
            *b = 0; // Checksum
        }
    }
    hmac_md5(key, &text)
}

/// Verify one encoded PDU against a key chain. ISO/IS-IS rules:
/// an absent TLV 10 fails when authentication is configured; a
/// cleartext value must byte-equal the password; an HMAC-MD5 value
/// must be 16 octets matching one of the live accept keys (RFC 5304
/// §2's multiple-password permission).
pub fn verify(
    pdu: &[u8],
    fixed: usize,
    is_lsp: bool,
    chain: &KeyChain,
    now: u64,
) -> Result<(), &'static str> {
    let Some(auth) = find_auth_tlv(pdu, fixed) else {
        return Err("no authentication TLV (required by the configured password)");
    };
    let value = &pdu[auth.offset..auth.offset + auth.len];
    match auth.auth_type {
        AUTH_CLEARTEXT => {
            if chain
                .accept_keys(now)
                .any(|key| key.algorithm == AuthAlgorithm::Cleartext && key.secret == value)
            {
                Ok(())
            } else {
                Err("cleartext password mismatch")
            }
        }
        AUTH_HMAC_MD5 => {
            if value.len() != 16 {
                return Err("HMAC-MD5 value is not 16 octets (RFC 5304 s2)");
            }
            if chain.accept_keys(now).any(|key| {
                key.algorithm == AuthAlgorithm::HmacMd5
                    && hmac_md5_digest(pdu, auth, is_lsp, &key.secret).as_slice() == value
            }) {
                Ok(())
            } else {
                Err("HMAC-MD5 digest mismatch")
            }
        }
        _ => Err("unknown authentication type"),
    }
}

/// The TLV 10 a transmitter appends for one key: the cleartext
/// password, or HMAC-MD5's 17-octet value (type octet + 16 zero
/// digest octets — the digest is patched into the encoded bytes
/// afterwards; see [`hmac_md5_digest`]).
pub fn auth_tlv(key: &AuthKey) -> Tlv {
    match key.algorithm {
        AuthAlgorithm::Cleartext => Tlv::Authentication {
            auth_type: AUTH_CLEARTEXT,
            value: key.secret.clone(),
        },
        AuthAlgorithm::HmacMd5 => Tlv::Authentication {
            auth_type: AUTH_HMAC_MD5,
            value: vec![0u8; 16],
        },
    }
}

/// Patch a computed digest into encoded bytes at the auth value.
pub fn patch_digest(pdu: &mut [u8], auth: AuthValueAt, digest: &[u8; 16]) {
    pdu[auth.offset..auth.offset + 16].copy_from_slice(digest);
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    /// RFC 1321's own test suite (A.5).
    #[test]
    fn md5_matches_rfc1321_vectors() {
        assert_eq!(hex(&md5(b"")), "d41d8cd98f00b204e9800998ecf8427e");
        assert_eq!(hex(&md5(b"abc")), "900150983cd24fb0d6963f7d28e17f72");
        assert_eq!(
            hex(&md5(
                b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
            )),
            "d174ab98d277d9f5a5611c2c9f419d9f"
        );
    }

    /// RFC 2202's HMAC-MD5 test cases 1 and 2.
    #[test]
    fn hmac_md5_matches_rfc2202_vectors() {
        assert_eq!(
            hex(&hmac_md5(&[0x0b; 16], b"Hi There")),
            "9294727a3638bb1c13f48ef8158bfc9d"
        );
        assert_eq!(
            hex(&hmac_md5(b"Jefe", b"what do ya want for nothing?")),
            "750c783e6ab0b503eaa86e310a5db738"
        );
    }

    /// The chain pattern (ospfd keychain parity): send picks the
    /// latest live start; accept admits any live accept key; a dead
    /// chain sends nothing and accepts nothing.
    #[test]
    fn key_chain_send_and_accept_selection() {
        let chain = KeyChain {
            keys: vec![
                AuthKey {
                    algorithm: AuthAlgorithm::HmacMd5,
                    secret: b"old".to_vec(),
                    send_lifetime: Lifetime {
                        start: Some(0),
                        end: Some(100),
                    },
                    accept_lifetime: Lifetime {
                        start: Some(0),
                        end: Some(200),
                    },
                },
                AuthKey {
                    algorithm: AuthAlgorithm::HmacMd5,
                    secret: b"new".to_vec(),
                    send_lifetime: Lifetime {
                        start: Some(50),
                        end: None,
                    },
                    accept_lifetime: Lifetime {
                        start: Some(50),
                        end: None,
                    },
                },
            ],
        };
        assert_eq!(chain.send_key(50).unwrap().secret, b"new");
        assert_eq!(chain.send_key(49).unwrap().secret, b"old");
        // The rollover overlap: key 1's accept window still open at
        // 150 (its SEND window closed at 100) — both accepted, one
        // sent. Past 200 only key 2 remains.
        assert_eq!(chain.accept_keys(150).count(), 2);
        assert_eq!(chain.send_key(150).unwrap().secret, b"new");
        assert_eq!(chain.accept_keys(200).count(), 1);
        // A fully dead chain: fail-closed.
        let dead = KeyChain {
            keys: vec![AuthKey {
                algorithm: AuthAlgorithm::HmacMd5,
                secret: b"x".to_vec(),
                send_lifetime: Lifetime {
                    start: None,
                    end: Some(10),
                },
                accept_lifetime: Lifetime::ALWAYS,
            }],
        };
        assert!(dead.send_key(10).is_none());
        assert_eq!(dead.accept_keys(10).count(), 1);
    }

    /// The half-open lifetime window (start inclusive, end
    /// exclusive — the ospfd rule).
    #[test]
    fn lifetime_windows_are_half_open() {
        let w = Lifetime {
            start: Some(10),
            end: Some(20),
        };
        assert!(!w.live(9));
        assert!(w.live(10));
        assert!(w.live(19));
        assert!(!w.live(20));
        assert!(Lifetime::ALWAYS.live(u64::MAX));
    }

    /// RFC 5304's zeroing rules exercised over a real PDU shape: an
    /// LSP whose TLV block carries TLV 10 — flipping any byte of the
    /// covered text breaks the digest; mutating the (excluded)
    /// Remaining Lifetime or Checksum does not.
    #[test]
    fn hmac_md5_covers_the_pdu_and_excludes_lifetime_and_checksum() {
        let key = b"secret-key";
        let mut bytes = vec![0x83u8, 27, 1, 0, 20, 1, 0, 0];
        bytes.extend_from_slice(&[0, 60]); // pdu length (patched below)
        bytes.extend_from_slice(&[4, 0xb0]); // remaining lifetime 1200
        bytes.extend_from_slice(&[0x19, 0x21, 0x68, 0, 0x10, 2, 0, 0]); // lsp id
        bytes.extend_from_slice(&[0, 0, 0, 1]); // sequence
        bytes.extend_from_slice(&[0xab, 0xcd]); // checksum (placeholder)
        bytes.push(0x03); // type block: L2
        bytes.extend_from_slice(&[137, 2, b'r', b'2']); // TLV 137: "r2"
        bytes.extend_from_slice(&[10, 17, 54]); // TLV 10: type 54 + 16 zero octets
        bytes.extend_from_slice(&[0u8; 16]);
        let total = bytes.len() as u16;
        bytes[8..10].copy_from_slice(&total.to_be_bytes());
        let auth = find_auth_tlv(&bytes, 27).expect("TLV 10 found");
        assert_eq!(auth.auth_type, AUTH_HMAC_MD5);
        assert_eq!(auth.len, 16);
        let digest = hmac_md5_digest(&bytes, auth, true, key);
        patch_digest(&mut bytes.clone(), auth, &digest);
        let mut signed = bytes.clone();
        patch_digest(&mut signed, auth, &digest);
        // Verify clean, then each corruption class.
        let chain = |secret: &[u8]| KeyChain {
            keys: vec![AuthKey {
                algorithm: AuthAlgorithm::HmacMd5,
                secret: secret.to_vec(),
                send_lifetime: Lifetime::ALWAYS,
                accept_lifetime: Lifetime::ALWAYS,
            }],
        };
        assert!(verify(&signed, 27, true, &chain(key), 0).is_ok());
        assert!(verify(&signed, 27, true, &chain(b"wrong"), 0).is_err());
        // A hostname flip breaks it (covered text).
        let mut tampered = signed.clone();
        tampered[29] = b'X';
        assert!(verify(&tampered, 27, true, &chain(key), 0).is_err());
        // A lifetime change does NOT (RFC 5304 zeroes it) — the
        // re-flooding decrement case.
        let mut aged = signed.clone();
        aged[10..12].copy_from_slice(&3u16.to_be_bytes());
        assert!(verify(&aged, 27, true, &chain(key), 0).is_ok());
        // Neither does a checksum change (also zeroed).
        let mut resummed = signed.clone();
        resummed[24..26].copy_from_slice(&0x1234u16.to_be_bytes());
        assert!(verify(&resummed, 27, true, &chain(key), 0).is_ok());
        // A 15-octet digest fails the 16-octet rule (the TLV rebuilt
        // consistently short so the walker still finds it).
        // Cut at the digest (the type octet stays), shorten the TLV
        // length byte, close with 15 zero value octets.
        let mut short = signed[..auth.offset].to_vec();
        short[auth.offset - 2] = 16; // TLV length: type octet + 15
        short.extend(std::iter::repeat_n(0u8, 15));
        let total = short.len() as u16;
        short[8..10].copy_from_slice(&total.to_be_bytes());
        assert_eq!(
            verify(&short, 27, true, &chain(key), 0),
            Err("HMAC-MD5 value is not 16 octets (RFC 5304 s2)")
        );
    }

    /// Cleartext: byte-equality against the live accept keys.
    #[test]
    fn cleartext_verify() {
        let chain = |secret: &str| KeyChain {
            keys: vec![AuthKey {
                algorithm: AuthAlgorithm::Cleartext,
                secret: secret.as_bytes().to_vec(),
                send_lifetime: Lifetime::ALWAYS,
                accept_lifetime: Lifetime::ALWAYS,
            }],
        };
        let mut bytes = vec![0x83u8, 20, 1, 0, 17, 1, 0, 0];
        bytes.push(2); // circuit type L2
        bytes.extend_from_slice(&[0x19, 0x21, 0x68, 0, 0x10, 2]);
        bytes.extend_from_slice(&[0, 30]); // holding time
        bytes.extend_from_slice(&[0, 39]); // pdu length (patched below)
        bytes.push(1); // local circuit id
                       // TLV 1: two areas (49.0001 and 49), length-prefixed — value 6.
        bytes.extend_from_slice(&[1, 6, 3, 0x49, 0x00, 0x01, 1, 0x49]);
        bytes.extend_from_slice(&[10, 7, 1]); // TLV 10: type 1 + "secret"
        bytes.extend_from_slice(b"secret");
        bytes.extend_from_slice(&[129, 1, 0xCC]); // TLV 129
        let total = bytes.len() as u16;
        bytes[17..19].copy_from_slice(&total.to_be_bytes());
        assert!(verify(&bytes, 20, false, &chain("secret"), 0).is_ok());
        assert!(verify(&bytes, 20, false, &chain("Secret"), 0).is_err());
        // No TLV 10 at all.
        let mut unsigned = bytes.clone();
        unsigned.truncate(23);
        let total = unsigned.len() as u16;
        unsigned[15..17].copy_from_slice(&total.to_be_bytes());
        assert!(verify(&unsigned, 20, false, &chain("secret"), 0).is_err());
    }
}
