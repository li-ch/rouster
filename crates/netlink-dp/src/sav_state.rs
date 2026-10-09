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
//!
//! Beyond persistence, this module owns the replay math the backend's
//! churn guard runs: [`replay_delta`] splits a resolved install into
//! the writes and reverts still owed against the applied map, so an
//! identical replay writes nothing at all — neither sysctls nor the
//! state file.

use std::collections::{BTreeMap, BTreeSet};

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

/// The churn-guard verdict for replaying a resolved install against
/// the applied map: which writes the replay still owes the kernel,
/// and which applied entries it must revert. Both empty is an
/// identical replay — the caller touches nothing, neither the sysctl
/// files nor the state file. Load-bearing since savd re-evaluates on
/// every dirtying event (identical replays are the common case), and
/// for a fresh process whose in-memory map only the disk merge fills.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct ReplayDelta {
    /// `(ifindex, name, planned value)` targets whose applied entry
    /// does not already match on all three fields — the only procfs
    /// writes the replay still needs.
    pub writes: Vec<(u32, String, u8)>,
    /// `(ifindex, name, prior)` applied entries the plan no longer
    /// covers; their pre-SAV value must be restored.
    pub reverts: Vec<(u32, String, u8)>,
}

/// Split a resolved plan — one `(ifindex, interface name, value)`
/// tuple per target, as the backend resolves it from the sysctl plan
/// — into the writes and reverts still owed against `applied`.
///
/// A target is already in force only when the applied entry under the
/// same ifindex carries the *same name* (ifindexes are recycled; an
/// equal value recorded under a different name was written to a
/// different sysctl file) and the *same value*. `writes` keeps the
/// planned order; `reverts` follows the applied map's BTreeMap order.
pub fn replay_delta(planned: &[(u32, String, u8)], applied: &AppliedMap) -> ReplayDelta {
    let mut delta = ReplayDelta::default();
    for (ifindex, name, value) in planned {
        let already = applied
            .get(ifindex)
            .is_some_and(|(applied_name, _, applied_value)| {
                applied_name == name && applied_value == value
            });
        if !already {
            delta.writes.push((*ifindex, name.clone(), *value));
        }
    }
    let planned_indexes: BTreeSet<u32> = planned.iter().map(|&(ix, _, _)| ix).collect();
    for (&ifindex, (name, prior, _)) in applied {
        if !planned_indexes.contains(&ifindex) {
            delta.reverts.push((ifindex, name.clone(), *prior));
        }
    }
    delta
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

    /// The churn guard's core claim (W7 §Deferred 5): a replay whose
    /// resolved plan matches the applied map on (ifindex, name,
    /// value) — every interface, both directions — owes the kernel
    /// nothing: no procfs writes, no reverts, no state-file rewrite.
    /// An empty delta is what `sav_install` short-circuits on, so
    /// this is the host-side proof an identical replay is a no-op.
    #[test]
    fn identical_replay_is_a_noop() {
        let applied: AppliedMap = [
            (2u32, ("vethspoof".to_string(), 0u8, 1u8)),
            (3, ("vethlegit".to_string(), 0, 2)),
        ]
        .into_iter()
        .collect();
        // Order-invariant: identity holds however the caller ordered
        // the resolved targets.
        for planned in [
            vec![
                (2u32, "vethspoof".to_string(), 1u8),
                (3, "vethlegit".to_string(), 2),
            ],
            vec![
                (3, "vethlegit".to_string(), 2),
                (2, "vethspoof".to_string(), 1),
            ],
        ] {
            assert_eq!(replay_delta(&planned, &applied), ReplayDelta::default());
        }
    }

    /// A genuinely different plan still converges: a changed value
    /// and a new interface produce exactly those writes, a dropped
    /// interface exactly that revert — never more, never fewer.
    #[test]
    fn changed_plan_writes_and_reverts_the_difference() {
        let applied: AppliedMap = [
            (2u32, ("vethspoof".to_string(), 0u8, 1u8)),
            (4, ("vethgone".to_string(), 0, 2)),
        ]
        .into_iter()
        .collect();
        // 2 changes 1→2; 3 is new; 4 left the program.
        let planned = vec![
            (2u32, "vethspoof".to_string(), 2u8),
            (3, "vethnew".to_string(), 1),
        ];
        assert_eq!(
            replay_delta(&planned, &applied),
            ReplayDelta {
                writes: vec![
                    (2, "vethspoof".to_string(), 2),
                    (3, "vethnew".to_string(), 1),
                ],
                reverts: vec![(4, "vethgone".to_string(), 0)],
            }
        );
    }

    /// An equal value under a different name is NOT identical:
    /// ifindexes are recycled and the sysctl file is keyed by name,
    /// so the replay must rewrite onto the new interface (and the
    /// executor re-reads its prior instead of trusting the stale
    /// entry's).
    #[test]
    fn same_value_under_a_recycled_ifindex_name_still_writes() {
        let applied: AppliedMap = [(2u32, ("eth-old".to_string(), 0u8, 1u8))]
            .into_iter()
            .collect();
        let planned = vec![(2, "eth-new".to_string(), 1)];
        assert_eq!(
            replay_delta(&planned, &applied),
            ReplayDelta {
                writes: vec![(2, "eth-new".to_string(), 1)],
                reverts: Vec::new(),
            }
        );
    }

    /// Nothing applied yet (fresh boot, absent/empty state file): the
    /// whole plan is owed — the guard must never suppress a first
    /// install.
    #[test]
    fn fresh_surface_writes_everything() {
        let planned = vec![(2u32, "vethspoof".to_string(), 1u8)];
        let delta = replay_delta(&planned, &AppliedMap::new());
        assert_eq!(delta.writes, planned);
        assert!(delta.reverts.is_empty());
    }
}
