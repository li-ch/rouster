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
//! AGENTS.md sanctions for daemon state), a `boot-id <id>` stamp line
//! followed by one `ifindex name prior value` line per interface.
//!
//! Boot safety: the file keys by ifindex, and ifindexes are per-boot —
//! a reboot may create interfaces in a different order, so restoring
//! a stale file by ifindex could write onto the wrong interface. The
//! first line therefore stamps the writing boot's id (from
//! `/proc/sys/kernel/random/boot_id`, supplied by the Linux impl), and
//! decoding against a different boot yields [`ForeignBoot`]: the
//! caller must treat the persisted state as absent — a fresh install
//! surface, as if nothing had ever been applied. A stamp-less
//! non-empty file (the pre-stamp format) is also `ForeignBoot`: its
//! boot is unknowable, so it is never trusted. An empty applied map
//! persists as an empty file (nothing restorable, nothing to guard).
//!
//! Decoding of the body is deliberately lenient: a malformed line is
//! skipped, not fatal — a corrupt line must not brick the restoration
//! of every other interface.

use std::collections::BTreeMap;

/// ifindex → (interface name at write time, pre-SAV rp_filter, applied
/// rp_filter value).
pub type AppliedMap = BTreeMap<u32, (String, u8, u8)>;

/// Whether a decoded applied-state file belongs to the boot reading it.
#[derive(Debug, PartialEq, Eq)]
pub enum DecodeOutcome {
    /// The boot-id stamp matches the reading boot: the ifindex → name
    /// mapping is still the one the writer saw, so the entries are
    /// safe to restore.
    Current(AppliedMap),
    /// The stamp names another boot (or is absent/malformed): the
    /// persisted state must be treated as absent, never restored — a
    /// reboot may have reordered ifindexes onto other interfaces.
    ForeignBoot,
}

/// Serialize the applied map (deterministic: BTreeMap order) under the
/// current boot's stamp. An empty map encodes as an empty file: no
/// entries to restore, so no stamp to guard them.
pub fn encode(boot_id: &str, map: &AppliedMap) -> String {
    if map.is_empty() {
        return String::new();
    }
    let mut out = format!("boot-id {boot_id}\n");
    for (&ifindex, (name, prior, value)) in map {
        out.push_str(&format!("{ifindex} {name} {prior} {value}\n"));
    }
    out
}

/// Parse an applied-state file against the boot that is reading it.
///
/// A stamp mismatch — different boot, missing stamp (legacy or foreign
/// format), malformed stamp, or stamp not on the first line — is
/// [`DecodeOutcome::ForeignBoot`], not an error: the caller treats the
/// state as absent. Body decoding stays lenient (see module docs);
/// there is no error case.
pub fn decode(text: &str, boot_id: &str) -> DecodeOutcome {
    // The stamp must be the first line, exactly `boot-id <id>`.
    let (first, rest) = match text.split_once('\n') {
        Some((first, rest)) => (first, rest),
        None => (text, ""),
    };
    let mut header = first.split_whitespace();
    let stamp_matches = match (header.next(), header.next(), header.next()) {
        (Some("boot-id"), Some(id), None) => id == boot_id,
        _ => false,
    };
    if !stamp_matches {
        return DecodeOutcome::ForeignBoot;
    }

    let mut map = AppliedMap::new();
    for line in rest.lines() {
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
    DecodeOutcome::Current(map)
}

#[cfg(test)]
mod tests {
    use super::*;
    use DecodeOutcome::Current;

    const BOOT: &str = "1b06d3ad-1f3e-4e6f-9a2a-3b8c7d5e9f01";
    const OTHER_BOOT: &str = "9f8e7d6c-5b4a-4c3d-2e1f-0a9b8c7d6e5f";

    fn map() -> AppliedMap {
        [
            (6u32, ("vethspoof".to_string(), 0u8, 1u8)),
            (4, ("vethlegit".to_string(), 0, 2)),
        ]
        .into_iter()
        .collect()
    }

    /// Round-trip within one boot: encode → decode returns the
    /// identical map. An empty map is an empty file (nothing applied
    /// leaves nothing on disk), which decodes as foreign — equivalent
    /// to absent for the caller.
    #[test]
    fn applied_state_round_trips_within_one_boot() {
        assert_eq!(decode(&encode(BOOT, &map()), BOOT), Current(map()));
        assert!(encode(BOOT, &AppliedMap::new()).is_empty());
        assert_eq!(decode("", BOOT), DecodeOutcome::ForeignBoot);
    }

    /// The encoding is the documented format: stamp line first, then
    /// `ifindex name prior value` lines in BTreeMap order.
    #[test]
    fn applied_state_format_is_stamp_then_documented_lines() {
        assert_eq!(
            encode(BOOT, &map()),
            format!("boot-id {BOOT}\n4 vethlegit 0 2\n6 vethspoof 0 1\n")
        );
    }

    /// A file stamped by a different boot is ignored wholesale — the
    /// exact reboot-reordered-ifindexes hazard this guard exists for.
    /// Stamp-less legacy files and malformed/missplaced stamps are
    /// equally foreign: the boot is unknowable, so never trusted.
    #[test]
    fn foreign_boot_state_is_treated_as_absent() {
        let text = encode(BOOT, &map());
        assert_eq!(
            decode(&text, OTHER_BOOT),
            DecodeOutcome::ForeignBoot,
            "different boot: state must be ignored"
        );
        // Pre-stamp legacy format: entries but no way to date them.
        assert_eq!(
            decode("4 vethlegit 0 2\n6 vethspoof 0 1\n", BOOT),
            DecodeOutcome::ForeignBoot
        );
        // Malformed stamps: wrong keyword, missing id, extra field,
        // stamp not on the first line.
        assert_eq!(
            decode("bootid 1\n4 vethlegit 0 2\n", BOOT),
            DecodeOutcome::ForeignBoot
        );
        assert_eq!(
            decode("boot-id\n4 vethlegit 0 2\n", BOOT),
            DecodeOutcome::ForeignBoot
        );
        assert_eq!(
            decode("boot-id a b\n4 vethlegit 0 2\n", BOOT),
            DecodeOutcome::ForeignBoot
        );
        assert_eq!(
            decode(&format!("4 vethlegit 0 2\nboot-id {BOOT}\n"), BOOT),
            DecodeOutcome::ForeignBoot
        );
    }

    /// Malformed body lines are skipped without affecting the healthy
    /// ones — but only once the stamp has vouched for the boot.
    #[test]
    fn malformed_lines_are_skipped_leniently() {
        let text = format!(
            "boot-id {BOOT}\n\
             6 vethspoof 0 1\n\
             garbage\n\
             4 vethlegit 0 2 extra\n\
             5 nonnumeric prior value\n"
        );
        let decoded = decode(&text, BOOT);
        assert_eq!(
            decoded,
            Current(
                [(6u32, ("vethspoof".to_string(), 0u8, 1u8))]
                    .into_iter()
                    .collect()
            )
        );
    }
}
