//! Key chains (RFC 8177) — the rollover machinery the Appendix D
//! crypto engines feed on.
//!
//! RFC 8177's model, minimal v1: a key CHAIN is identified by name
//! and holds a list of KEYs, each with a numeric Key ID (OSPF's
//! Figure-18 field is 8 bits — 1..=255 here, an OSPF-specific
//! narrowing of 8177's uint64 `key-id`), a crypto algorithm
//! (`md5` = the legacy RFC 2328 D.4.3(6) digest, `hmac-sha-256` =
//! RFC 5709), a `key-string` secret, and send/accept lifetimes.
//! A lifetime defaults to "always" (8177's default: "if
//! unspecified, the key is always considered valid") and may be
//! bounded (`start` inclusive, `end` exclusive — RFC 2328 D.4.3's
//! `KeyStartGenerate <= current time < KeyStopGenerate` and D.5.3's
//! accept window in the same shape).
//!
//! The rollover semantics v1 implements are 8177 §2.3's permission:
//! the receiver "MAY accept all the keys that have a valid accept
//! lifetime" while the sender "MAY send the key with the most recent
//! send lifetime" — accept-any-live / send-highest(latest start),
//! RFC 2328 D.4.3's own selection ("among the keys that are valid
//! for message generation ... choose the one with the most recent
//! KeyStartGenerate time"). Overlapping accept windows across two
//! keys are what makes the rollover graceful (8177's Appendix A
//! procedure; NTP alignment rides §Deferred with wall-clock time).
//!
//! Time is the daemon's injected clock (u64 seconds, t=0 at
//! construction) — the lifetime seconds in the config are expressed
//! on that clock. v1, disclosed: wall-clock/NTP-anchored lifetimes
//! (what cross-router rollover actually needs — 8177 §2.4: "It is
//! RECOMMENDED that these devices be time-synchronized") swap in at
//! the `now` seam without touching this model.

use crate::auth::AuthConfig;

/// One key chain (RFC 8177's `key-chain` list entry): a name and its
/// keys, ordered by configuration (selection never depends on it).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct KeyChain {
    pub name: String,
    pub keys: Vec<KeyEntry>,
}

/// The per-key crypto algorithm (RFC 8177's `crypto-algorithm`,
/// narrowed to the two engines ospfd ships: the RFC 5709
/// HMAC-SHA-256 and the legacy RFC 2328 D.4.3(6) keyed-MD5).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyAlgorithm {
    HmacSha256,
    Md5,
}

impl KeyAlgorithm {
    /// The digest length this algorithm appends (D.4.3 step 4's
    /// Auth Data Len).
    pub fn digest_len(self) -> usize {
        match self {
            KeyAlgorithm::HmacSha256 => 32,
            KeyAlgorithm::Md5 => 16,
        }
    }
}

/// A send or accept lifetime: `start` inclusive, `end` exclusive;
/// `None` bounds are unbounded (RFC 8177's "always"/"no-end-time").
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Lifetime {
    pub start: Option<u64>,
    pub end: Option<u64>,
}

impl Lifetime {
    /// The always-open lifetime (both bounds `None`) — 8177's
    /// default when no lifetime is configured.
    pub const ALWAYS: Lifetime = Lifetime {
        start: None,
        end: None,
    };

    /// RFC 2328 D.4.3/D.5.3's window test: `start <= now < end`
    /// (unbounded bounds always pass).
    pub fn live(&self, now: u64) -> bool {
        self.start.is_none_or(|s| s <= now) && self.end.is_none_or(|e| now < e)
    }
}

/// One key in a chain (RFC 8177 §2.2's key parameters + RFC 2328
/// D.3's Key ID semantics).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyEntry {
    /// The Figure-18 Key ID the packets stamp (1..=255).
    pub key_id: u8,
    pub algorithm: KeyAlgorithm,
    /// The secret (`key-string` — a string in transit and config,
    /// bytes to the MAC engines; no hex-string support v1).
    pub secret: Vec<u8>,
    pub send_lifetime: Lifetime,
    pub accept_lifetime: Lifetime,
}

impl KeyChain {
    /// The send-side selection (RFC 8177 §2.3 + RFC 2328 D.4.3):
    /// among the keys whose send lifetime is live, the one with the
    /// LATEST start time ("the most recent KeyStartGenerate"); a
    /// later-configured key with the same start wins on last-wins
    /// (8177 leaves equal starts unspecified — deterministic here).
    /// `None` when no key is live for sending (the interface's
    /// fail-closed case: see `AuthConfig::live_send_view`).
    pub fn send_key(&self, now: u64) -> Option<&KeyEntry> {
        self.keys
            .iter()
            .filter(|k| k.send_lifetime.live(now))
            .max_by_key(|k| (k.send_lifetime.start.unwrap_or(0), k.key_id))
    }

    /// The receive-side selection (RFC 2328 D.5.3 step 1): the key
    /// with the packet's Key ID whose ACCEPT lifetime is live —
    /// accept-any-live. `None` discards the packet ("If the key is
    /// not found, or if the key is not valid for reception ..., the
    /// OSPF packet is discarded").
    pub fn accept_key(&self, now: u64, key_id: u8) -> Option<&KeyEntry> {
        self.keys
            .iter()
            .find(|k| k.key_id == key_id && k.accept_lifetime.live(now))
    }

    /// The concrete Appendix-D view of one key (what the send/verify
    /// paths consume).
    pub fn view_of(key: &KeyEntry) -> AuthConfig {
        match key.algorithm {
            KeyAlgorithm::HmacSha256 => AuthConfig::HmacSha256 {
                key_id: key.key_id,
                key: key.secret.clone(),
            },
            KeyAlgorithm::Md5 => AuthConfig::KeyedMd5 {
                key_id: key.key_id,
                key: key.secret.clone(),
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(id: u8, send: Lifetime, accept: Lifetime) -> KeyEntry {
        KeyEntry {
            key_id: id,
            algorithm: KeyAlgorithm::HmacSha256,
            secret: format!("secret-{id}").into_bytes(),
            send_lifetime: send,
            accept_lifetime: accept,
        }
    }

    fn lifetime(start: Option<u64>, end: Option<u64>) -> Lifetime {
        Lifetime { start, end }
    }

    /// RFC 8177's default: an unspecified lifetime is "always" —
    /// live at every clock the daemon can inject.
    #[test]
    fn unspecified_lifetimes_are_always_live() {
        let always = Lifetime::ALWAYS;
        assert!(always.live(0));
        assert!(always.live(1_700_000_000));
        assert_eq!(always, Lifetime::default());
    }

    /// The window arithmetic (RFC 2328 D.4.3's
    /// `KeyStartGenerate <= now < KeyStopGenerate`): start
    /// inclusive, end exclusive.
    #[test]
    fn lifetime_windows_are_half_open() {
        let w = lifetime(Some(100), Some(200));
        assert!(!w.live(99), "before start");
        assert!(w.live(100), "start inclusive");
        assert!(w.live(199));
        assert!(!w.live(200), "end exclusive");
        // Unbounded ends only.
        let open_end = lifetime(Some(50), None);
        assert!(!open_end.live(49));
        assert!(open_end.live(50));
        assert!(open_end.live(u64::MAX / 2));
        // Unbounded starts only.
        let open_start = lifetime(None, Some(10));
        assert!(open_start.live(0));
        assert!(open_start.live(9));
        assert!(!open_start.live(10));
    }

    /// The send-side selection: latest live start wins (RFC 8177
    /// §2.3's "the most recent send lifetime ... latest start-time";
    /// RFC 2328 D.4.3's "most recent KeyStartGenerate"), and a fully
    /// expired chain sends nothing.
    #[test]
    fn send_key_picks_the_most_recent_live_start() {
        let chain = KeyChain {
            name: "kc".into(),
            keys: vec![
                entry(1, lifetime(Some(0), None), lifetime(Some(0), None)),
                entry(2, lifetime(Some(300), None), lifetime(Some(300), None)),
            ],
        };
        assert_eq!(chain.send_key(100).unwrap().key_id, 1, "only key 1 live");
        assert_eq!(
            chain.send_key(300).unwrap().key_id,
            2,
            "key 2's later start wins once live"
        );
        // Key 2 send-expiring falls back to key 1 (still live).
        let chain = KeyChain {
            name: "kc".into(),
            keys: vec![
                entry(1, lifetime(Some(0), None), lifetime(Some(0), None)),
                entry(2, lifetime(Some(300), Some(400)), Lifetime::ALWAYS),
            ],
        };
        assert_eq!(chain.send_key(399).unwrap().key_id, 2);
        assert_eq!(chain.send_key(400).unwrap().key_id, 1);
        // Nothing live at all.
        let dead = KeyChain {
            name: "kc".into(),
            keys: vec![entry(1, lifetime(Some(0), Some(10)), Lifetime::ALWAYS)],
        };
        assert!(dead.send_key(10).is_none(), "fail-closed: no live send key");
        // Equal starts: the higher Key ID is the deterministic pick
        // (8177 leaves equal starts unspecified).
        let tie = KeyChain {
            name: "kc".into(),
            keys: vec![
                entry(3, lifetime(Some(0), None), Lifetime::ALWAYS),
                entry(1, lifetime(Some(0), None), Lifetime::ALWAYS),
            ],
        };
        assert_eq!(tie.send_key(0).unwrap().key_id, 3);
    }

    /// The receive-side selection (D.5.3 step 1): any key with the
    /// packet's Key ID whose ACCEPT window is live — including a key
    /// the sender stopped using (the rollover overlap), excluding an
    /// expired one even when the ID matches.
    #[test]
    fn accept_key_matches_id_within_the_accept_window() {
        let chain = KeyChain {
            name: "kc".into(),
            keys: vec![
                entry(1, Lifetime::ALWAYS, lifetime(Some(0), Some(500))),
                entry(2, lifetime(Some(300), None), lifetime(Some(300), None)),
            ],
        };
        assert_eq!(chain.accept_key(100, 1).unwrap().key_id, 1);
        assert!(chain.accept_key(100, 2).is_none(), "key 2 not yet accepted");
        assert_eq!(chain.accept_key(400, 2).unwrap().key_id, 2);
        assert!(
            chain.accept_key(500, 1).is_none(),
            "key 1's accept window closed"
        );
        assert!(chain.accept_key(100, 9).is_none(), "unknown Key ID");
    }

    /// The view mapping: an entry renders to the concrete Appendix-D
    /// auth config its algorithm names, secret and Key ID carried.
    #[test]
    fn entries_map_to_their_auth_views() {
        let mut k = entry(5, Lifetime::ALWAYS, Lifetime::ALWAYS);
        k.algorithm = KeyAlgorithm::HmacSha256;
        assert_eq!(
            KeyChain::view_of(&k),
            AuthConfig::HmacSha256 {
                key_id: 5,
                key: b"secret-5".to_vec()
            }
        );
        k.algorithm = KeyAlgorithm::Md5;
        assert_eq!(
            KeyChain::view_of(&k),
            AuthConfig::KeyedMd5 {
                key_id: 5,
                key: b"secret-5".to_vec()
            }
        );
        assert_eq!(
            KeyAlgorithm::Md5.digest_len(),
            16,
            "D.4.3 step 4: MD5's Auth Data Len"
        );
        assert_eq!(KeyAlgorithm::HmacSha256.digest_len(), 32);
    }
}
