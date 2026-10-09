//! Applied-SAV state persistence (pure encode/decode; the Linux impl
//! owns the file I/O).
//!
//! The Linux backend records what it wrote (interface, pre-SAV value,
//! applied value) so [`clear`](crate::Dataplane::sav_clear) and the
//! replace semantics of [`install`](crate::Dataplane::sav_install) can
//! restore pre-SAV state — not just within one process lifetime, but
//! across them: a restarted daemon (and tonight's one-command-per-
//! process smoke binary) would otherwise have forgotten the prior
//! values. The file lives at `/run/rouster/sav-applied` (the run dir
//! AGENTS.md sanctions for daemon state), one `ifindex name prior
//! value` line per interface.
//!
//! Decoding is deliberately lenient: a malformed line is skipped, not
//! fatal — a corrupt line must not brick the restoration of every
//! other interface.

use std::collections::BTreeMap;

/// ifindex → (interface name at write time, pre-SAV rp_filter, applied
/// rp_filter value).
pub type AppliedMap = BTreeMap<u32, (String, u8, u8)>;

/// Serialize the applied map (deterministic: BTreeMap order).
pub fn encode(map: &AppliedMap) -> String {
    let mut out = String::new();
    for (&ifindex, (name, prior, value)) in map {
        out.push_str(&format!("{ifindex} {name} {prior} {value}\n"));
    }
    out
}

/// Parse an applied-state file. Malformed lines are skipped (see
/// module docs); there is no error case.
pub fn decode(text: &str) -> AppliedMap {
    let mut map = AppliedMap::new();
    for line in text.lines() {
        let mut parts = line.split_whitespace();
        let (
            Some(ifindex),
            Some(name),
            Some(prior),
            Some(value),
            None, // exactly four fields
        ) = (
            parts.next(),
            parts.next(),
            parts.next(),
            parts.next(),
            parts.next(),
        )
        else {
            continue;
        };
        let (Ok(ifindex), Ok(prior), Ok(value)) = (
            ifindex.parse::<u32>(),
            prior.parse::<u8>(),
            value.parse::<u8>(),
        ) else {
            continue;
        };
        map.insert(ifindex, (name.to_string(), prior, value));
    }
    map
}

#[cfg(test)]
mod tests {
    use super::*;

    fn map() -> AppliedMap {
        [
            (6u32, ("vethspoof".to_string(), 0u8, 1u8)),
            (4, ("vethlegit".to_string(), 0, 2)),
        ]
        .into_iter()
        .collect()
    }

    /// Round-trip: encode → decode returns the identical map.
    #[test]
    fn applied_state_round_trips() {
        assert_eq!(decode(&encode(&map())), map());
        assert!(encode(&AppliedMap::new()).is_empty());
        assert!(decode("").is_empty());
    }

    /// The encoding is the documented line format, BTreeMap order.
    #[test]
    fn applied_state_format_is_documented_lines() {
        assert_eq!(encode(&map()), "4 vethlegit 0 2\n6 vethspoof 0 1\n");
    }

    /// Malformed lines are skipped without affecting the healthy ones.
    #[test]
    fn malformed_lines_are_skipped_leniently() {
        let text = "6 vethspoof 0 1\n\
                    garbage\n\
                    4 vethlegit 0 2 extra\n\
                    5 nonnumeric prior value\n";
        let decoded = decode(text);
        assert_eq!(decoded.len(), 1);
        assert_eq!(decoded.get(&6), Some(&("vethspoof".to_string(), 0, 1)));
    }
}
