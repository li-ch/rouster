//! The Validated ROA Payload (VRP) table.
//!
//! A VRP is RFC 6811 §2's "(IP address, prefix length, maximum length,
//! origin AS number)" tuple as loaded from the cache. The table stores
//! the currently-announced set for one cache session and applies RTR
//! payload PDUs:
//!
//! - announce = insert; the tuple must not already be active (RFC 8210
//!   §5.6: the cache guarantees one and only one PDU per
//!   {Prefix, Len, Max-Len, ASN} — a repeat is error code 7 territory);
//! - withdraw = remove; the exact tuple must exist (§5.1: "a withdraw
//!   effectively deletes one previously announced Prefix PDU with the
//!   exact same Prefix, Length, Max-Len, and ASN" — otherwise error
//!   code 6);
//! - a Cache Response to a Reset Query replaces the whole table
//!   (RFC 8210 §5.5: the cache "sends the set of all data records it
//!   has"), so the session layer calls [`VrpTable::clear`] when that
//!   sequence begins, on session-id change (§5.1), and on expiry of
//!   the End-of-Data expire interval (§6: data "MUST NOT" be retained
//!   past it).

use std::collections::BTreeSet;

use common::IpPrefix;

use crate::pdu::{PayloadFlags, Pdu};

/// One validated ROA payload: prefix, max length, origin ASN.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Vrp {
    pub prefix: IpPrefix,
    pub max_len: u8,
    pub asn: u32,
}

impl Vrp {
    /// RFC 6811 §2, "Covered": a Route Prefix is Covered by a VRP when
    /// the VRP prefix length is ≤ the Route prefix length and the two
    /// addresses agree on every bit the VRP prefix names (the route
    /// prefix is the VRP prefix or more specific than it).
    pub fn covers(&self, route: &IpPrefix) -> bool {
        match (&self.prefix, route) {
            (IpPrefix::V4(v), IpPrefix::V4(r)) => {
                v.prefix_len() <= r.prefix_len() && v.contains(r.addr())
            }
            (IpPrefix::V6(v), IpPrefix::V6(r)) => {
                v.prefix_len() <= r.prefix_len() && v.contains(r.addr())
            }
            _ => false,
        }
    }

    /// Build a VRP from a decoded IPv4/IPv6 Prefix PDU.
    pub fn from_prefix_pdu(pdu: &Pdu) -> Option<Vrp> {
        match pdu {
            Pdu::Ipv4Prefix {
                prefix,
                max_len,
                asn,
                ..
            } => Some(Vrp {
                prefix: IpPrefix::V4(*prefix),
                max_len: *max_len,
                asn: *asn,
            }),
            Pdu::Ipv6Prefix {
                prefix,
                max_len,
                asn,
                ..
            } => Some(Vrp {
                prefix: IpPrefix::V6(*prefix),
                max_len: *max_len,
                asn: *asn,
            }),
            _ => None,
        }
    }
}

impl std::fmt::Display for Vrp {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // IpPrefix's Display already carries the /len.
        write!(f, "{} max {} as {}", self.prefix, self.max_len, self.asn)
    }
}

/// The announce/withdraw outcome the table reports to the session
/// layer, which turns it into RTR error codes 7/6 (RFC 8210 §12).
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum VrpTableError {
    #[error("duplicate announcement of {0} (RFC 8210 §5.6, error code 7)")]
    DuplicateAnnouncement(Vrp),
    #[error("withdrawal of unknown record {0} (RFC 8210 §5.1, error code 6)")]
    UnknownWithdrawal(Vrp),
}

/// The set of VRPs one cache session currently holds. Deterministically
/// iterable (BTreeSet) so snapshots and golden tests are stable.
#[derive(Debug, Default, Clone)]
pub struct VrpTable {
    vrps: BTreeSet<Vrp>,
}

impl VrpTable {
    pub fn new() -> Self {
        VrpTable {
            vrps: BTreeSet::new(),
        }
    }

    /// Apply one payload PDU's announce/withdraw flag (RFC 8210 §5.1).
    pub fn apply(&mut self, vrp: Vrp, flags: PayloadFlags) -> Result<(), VrpTableError> {
        if flags.announce {
            if !self.vrps.insert(vrp) {
                return Err(VrpTableError::DuplicateAnnouncement(vrp));
            }
        } else if !self.vrps.remove(&vrp) {
            return Err(VrpTableError::UnknownWithdrawal(vrp));
        }
        Ok(())
    }

    /// Drop everything learned from the cache: reset-response start,
    /// session-id change, cache-shutdown error, or expire-interval
    /// expiry (RFC 8210 §5.1/§6; 8210bis-27 §12).
    pub fn clear(&mut self) {
        self.vrps.clear();
    }

    pub fn len(&self) -> usize {
        self.vrps.len()
    }

    pub fn is_empty(&self) -> bool {
        self.vrps.is_empty()
    }

    pub fn contains(&self, vrp: &Vrp) -> bool {
        self.vrps.contains(vrp)
    }

    pub fn iter(&self) -> impl Iterator<Item = &Vrp> {
        self.vrps.iter()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn v4(s: &str, max_len: u8, asn: u32) -> Vrp {
        Vrp {
            prefix: s.parse().unwrap(),
            max_len,
            asn,
        }
    }

    fn v6(s: &str, max_len: u8, asn: u32) -> Vrp {
        Vrp {
            prefix: s.parse().unwrap(),
            max_len,
            asn,
        }
    }

    fn r(s: &str) -> IpPrefix {
        s.parse().unwrap()
    }

    // ---- RFC 6811 §2 "Covered", exercised as a table of cases. -----

    #[test]
    fn covered_exact_and_more_specific() {
        // VRP 192.0.2.0/24 covers itself and its more specifics only.
        let vrp = v4("192.0.2.0/24", 24, 64512);
        assert!(vrp.covers(&r("192.0.2.0/24"))); // equal
        assert!(vrp.covers(&r("192.0.2.128/25"))); // more specific
        assert!(!vrp.covers(&r("192.0.2.0/23"))); // less specific (aggregate)
        assert!(!vrp.covers(&r("192.0.3.0/24"))); // sibling
        assert!(!vrp.covers(&r("198.51.100.0/24"))); // non-intersecting
    }

    #[test]
    fn covered_bit_identity_not_octet() {
        // "identical for all bits specified by the VRP prefix length" —
        // a /31 VRP covers the sibling /32 that shares its 31 bits.
        let vrp = v4("10.1.2.2/31", 32, 64512);
        assert!(vrp.covers(&r("10.1.2.2/32")));
        assert!(vrp.covers(&r("10.1.2.3/32")));
        assert!(!vrp.covers(&r("10.1.2.0/32")));
        // Host bits beyond the VRP length are irrelevant to Covering.
        let loose = v4("10.1.2.99/24", 24, 1);
        assert!(loose.covers(&r("10.1.2.7/32")));
    }

    #[test]
    fn covered_v6() {
        let vrp = v6("2001:db8::/32", 48, 64512);
        assert!(vrp.covers(&r("2001:db8:1::/48")));
        assert!(vrp.covers(&r("2001:db8:ffff::/64")));
        assert!(!vrp.covers(&r("2001:db9::/32")));
        assert!(!vrp.covers(&r("2001:db8::/31")));
    }

    #[test]
    fn covered_never_crosses_family() {
        let v4vrp = v4("192.0.2.0/24", 32, 64512);
        let v6vrp = v6("::ffff:192.0.2.0/120", 128, 64512);
        // v4-mapped v6 is still v6 on the wire and in the table.
        assert!(!v4vrp.covers(&r("::ffff:192.0.2.0/120")));
        assert!(!v6vrp.covers(&r("192.0.2.0/24")));
    }

    // ---- announce/withdraw/flush semantics -------------------------

    #[test]
    fn apply_announce_withdraw_roundtrip() {
        let mut t = VrpTable::new();
        let vrp = v4("192.0.2.0/24", 24, 64512);
        t.apply(vrp, PayloadFlags::ANNOUNCE).unwrap();
        assert_eq!(t.len(), 1);
        assert!(t.contains(&vrp));
        // Withdrawing the exact tuple removes it.
        t.apply(vrp, PayloadFlags::WITHDRAW).unwrap();
        assert!(t.is_empty());
    }

    #[test]
    fn apply_duplicate_announcement_rejected() {
        // RFC 8210 §5.6: one and only one PDU per unique tuple; a
        // repeat is the error-code-7 condition.
        let mut t = VrpTable::new();
        let vrp = v4("192.0.2.0/24", 24, 64512);
        t.apply(vrp, PayloadFlags::ANNOUNCE).unwrap();
        assert_eq!(
            t.apply(vrp, PayloadFlags::ANNOUNCE),
            Err(VrpTableError::DuplicateAnnouncement(vrp))
        );
        // A differing tuple (here: different maxlen) is not a duplicate.
        t.apply(v4("192.0.2.0/24", 25, 64512), PayloadFlags::ANNOUNCE)
            .unwrap();
    }

    #[test]
    fn apply_withdrawal_of_unknown_rejected() {
        // RFC 8210 §5.1: a withdraw deletes the exact same tuple; there
        // is none here, so the error-code-6 condition.
        let mut t = VrpTable::new();
        let stored = v4("192.0.2.0/24", 24, 64512);
        t.apply(stored, PayloadFlags::ANNOUNCE).unwrap();
        let off_by_maxlen = v4("192.0.2.0/24", 25, 64512);
        assert_eq!(
            t.apply(off_by_maxlen, PayloadFlags::WITHDRAW),
            Err(VrpTableError::UnknownWithdrawal(off_by_maxlen))
        );
        let off_by_asn = v4("192.0.2.0/24", 24, 64513);
        assert_eq!(
            t.apply(off_by_asn, PayloadFlags::WITHDRAW),
            Err(VrpTableError::UnknownWithdrawal(off_by_asn))
        );
        // The exact tuple still withdraws cleanly.
        t.apply(stored, PayloadFlags::WITHDRAW).unwrap();
    }

    #[test]
    fn clear_flushes_everything() {
        let mut t = VrpTable::new();
        t.apply(v4("192.0.2.0/24", 24, 64512), PayloadFlags::ANNOUNCE)
            .unwrap();
        t.apply(v6("2001:db8::/32", 48, 64512), PayloadFlags::ANNOUNCE)
            .unwrap();
        t.clear();
        assert!(t.is_empty());
        // Post-clear announces are fresh, not duplicates (session
        // restart = fresh cache).
        t.apply(v4("192.0.2.0/24", 24, 64512), PayloadFlags::ANNOUNCE)
            .unwrap();
    }

    #[test]
    fn iteration_is_deterministic() {
        // BTreeSet<Vrp> orders by (prefix, max_len, asn).
        let mut t = VrpTable::new();
        for (p, m, a) in [
            ("198.51.100.0/24", 24u8, 64513u32),
            ("192.0.2.0/24", 24, 64512),
            ("192.0.2.0/24", 25, 64511),
        ] {
            t.apply(v4(p, m, a), PayloadFlags::ANNOUNCE).unwrap();
        }
        let displayed: Vec<String> = t.iter().map(|v| v.to_string()).collect();
        assert_eq!(
            displayed,
            vec![
                "192.0.2.0/24 max 24 as 64512",
                "192.0.2.0/24 max 25 as 64511",
                "198.51.100.0/24 max 24 as 64513",
            ]
        );
    }

    #[test]
    fn from_prefix_pdu_maps_both_families() {
        let p4 = Pdu::Ipv4Prefix {
            version: 1,
            flags: PayloadFlags::ANNOUNCE,
            prefix: "192.0.2.0/24".parse().unwrap(),
            max_len: 24,
            asn: 64512,
        };
        assert_eq!(
            Vrp::from_prefix_pdu(&p4),
            Some(v4("192.0.2.0/24", 24, 64512))
        );
        let p6 = Pdu::Ipv6Prefix {
            version: 1,
            flags: PayloadFlags::ANNOUNCE,
            prefix: "2001:db8::/32".parse().unwrap(),
            max_len: 48,
            asn: 64512,
        };
        assert_eq!(
            Vrp::from_prefix_pdu(&p6),
            Some(v6("2001:db8::/32", 48, 64512))
        );
        assert_eq!(Vrp::from_prefix_pdu(&Pdu::CacheReset { version: 1 }), None);
    }
}
