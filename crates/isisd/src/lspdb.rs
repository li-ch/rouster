//! The LSP database: the per-level keyed store, the ISO 10589
//! "determining the latest information" ordering lattice (§7.3.16,
//! via RFC 1142's clause numbering), remaining-lifetime aging with an
//! injected clock, the sequence-number rules for own LSPs (§7.3.16.1
//! — the "first LSP is numbered 1 / next number greater / lollipop"
//! rules), CSNP/PSNP-driven synchronisation (§7.3.15.2, §7.3.17,
//! §7.3.18) and purge tombstones (§7.3.16.4).
//!
//! Pure and clock-injected (the ospfd LSDB convention): every method
//! takes `now` in seconds; nothing reads a wall clock. The ordering
//! lattice itself is exposed as [`newer_than`] for the property
//! suite.
//!
//! The bit-numbering note from RFC 1142 §9.1 matters when reading the
//! cited clauses against modern diagrams: ISO bits are numbered from
//! the LEAST significant, so "bit 8" of the type block is 0x80.

use std::collections::BTreeMap;

use crate::pdu::{Lsp, Pdu};
use crate::system::LspId;
use crate::tlv::{LspEntry, Tlv};

/// Which LSP of two represents the latest information (ISO §7.3.16's
/// ordering lattice). `Equal` includes the "same instance" case;
/// same-sequence-different-checksum is the §7.3.16.2 confusion case,
/// reported separately so the caller runs the purge path.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Ordering {
    ReceivedNewer,
    StoredNewer,
    Equal,
    /// §7.3.16.2: same sequence number, different checksums, and not
    /// our own current LSP — "the system that notices the mismatch
    /// shall treat the LSP as if its Remaining Lifetime had expired"
    /// (purge + flood one copy).
    Confusion,
}

/// §7.3.16.3's lattice, verbatim:
///
/// - "If the Remaining Lifetime of the received LSP is zero it shall
///   be processed as described in 7.3.16.4" — a zero-lifetime
///   (purged) instance beats a live stored one at the same sequence
///   number.
/// - "If the Remaining Lifetime of the received LSP is non-zero, but
///   there is an LSP in the database with the same sequence number
///   and zero Remaining Lifetime, the LSP in the database shall be
///   considered most recent."
/// - "Otherwise, the PDU with the larger sequence number shall be
///   considered the most recent."
pub fn newer_than(received: &Lsp, stored: &Lsp) -> Ordering {
    use Ordering::*;
    if received.sequence_number == stored.sequence_number {
        if received.is_purge() && !stored.is_purge() {
            return ReceivedNewer;
        }
        if !received.is_purge() && stored.is_purge() {
            return StoredNewer;
        }
        if received.checksum != stored.checksum {
            return Confusion;
        }
        return Equal;
    }
    if received.sequence_number > stored.sequence_number {
        ReceivedNewer
    } else {
        StoredNewer
    }
}

/// One stored LSP plus its arrival clock (the aging input).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredLsp {
    pub lsp: Lsp,
    /// `now` when this instance was installed.
    pub received_at: u64,
    /// `now` when the remaining lifetime reached zero (None while
    /// live).
    pub zeroed_at: Option<u64>,
}

impl StoredLsp {
    /// The remaining lifetime at `now` (ISO §7.3.16.3: a system
    /// holding an LSP decrements its lifetime according to the
    /// holding time).
    pub fn remaining_lifetime(&self, now: u64) -> u16 {
        if self.zeroed_at.is_some() || self.lsp.is_purge() {
            return 0;
        }
        self.lsp
            .remaining_lifetime
            .saturating_sub((now - self.received_at).min(u32::MAX as u64) as u16)
    }
}

/// The outcome of offering a received LSP to the database (the
/// §7.3.15.1 actions the caller must take).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InstallOutcome {
    /// Newer: installed — flood it (all SRM flags set).
    Installed,
    /// Equal instance: no database change (ack the receipt).
    Duplicate,
    /// Older than what we hold: flood OUR copy back (§7.3.15.1's
    /// "a copy of the LSP in the local database is sent" rule for
    /// old instances).
    OlderThanStored,
    /// §7.3.16.2 confusion: a tombstone was installed — flood it.
    ConfusionPurged,
}

/// The LSP database for one level (the daemon holds one per level it
/// runs).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Lspdb {
    entries: BTreeMap<LspId, StoredLsp>,
}

/// The actions a received CSNP asks for (ISO §7.3.15.2 a: compare
/// each entry against the database — ours missing or theirs newer →
/// request via PSNP; ours newer → send ours; equal → the entry is
/// synchronised).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CsnpActions {
    /// Entries to request with a PSNP (missing or theirs newer).
    pub requests: Vec<LspEntry>,
    /// Our LSPs to send (ours newer than described).
    pub to_send: Vec<LspId>,
}

impl Lspdb {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    pub fn get(&self, id: &LspId) -> Option<&StoredLsp> {
        self.entries.get(id)
    }

    pub fn ids(&self) -> impl Iterator<Item = LspId> + '_ {
        self.entries.keys().copied()
    }

    pub fn lsps(&self) -> impl Iterator<Item = &Lsp> {
        self.entries.values().map(|s| &s.lsp)
    }

    /// The stored records (LSP + arrival clock) — the SPF's aging
    /// view.
    pub fn stored_lsps(&self) -> impl Iterator<Item = &StoredLsp> {
        self.entries.values()
    }

    /// Install (or reject) a received LSP at clock `now` — the
    /// §7.3.15.1 receive path restricted to the database actions.
    /// Purges (zero remaining lifetime) install as header-only
    /// tombstones: §7.3.16.4 "retain only the LSP header".
    pub fn install(&mut self, received: Lsp, now: u64) -> InstallOutcome {
        match self
            .entries
            .get(&received.id)
            .map(|s| newer_than(&received, &s.lsp))
        {
            None => {
                self.put(received, now);
                InstallOutcome::Installed
            }
            Some(Ordering::ReceivedNewer) => {
                self.put(received, now);
                InstallOutcome::Installed
            }
            Some(Ordering::StoredNewer) => InstallOutcome::OlderThanStored,
            Some(Ordering::Equal) => InstallOutcome::Duplicate,
            Some(Ordering::Confusion) => {
                // §7.3.16.2: treat the LSP as if its Remaining
                // Lifetime had expired — store one copy with zero
                // written as the Remaining Lifetime, and flood it.
                let mut tombstone = received.clone();
                tombstone.remaining_lifetime = 0;
                tombstone.tlvs.clear();
                self.put(tombstone, now);
                InstallOutcome::ConfusionPurged
            }
        }
    }

    fn put(&mut self, mut lsp: Lsp, now: u64) {
        let purged = lsp.is_purge();
        if purged {
            // The tombstone is header-only (§7.3.16.4.b).
            lsp.tlvs.clear();
        }
        self.entries.insert(
            lsp.id,
            StoredLsp {
                lsp,
                received_at: now,
                zeroed_at: if purged { Some(now) } else { None },
            },
        );
    }

    /// Age the database to `now`: live LSPs whose remaining lifetime
    /// reaches zero are purged in place (§7.3.16.4: SRM flags set —
    /// the returned PDUs are the synchronized-purge flood) and
    /// tombstones older than `ZERO_AGE_LIFETIME` are dropped
    /// (§7.3.16.4.c).
    pub fn tick(&mut self, now: u64) -> Vec<Pdu> {
        let mut purges = Vec::new();
        let mut expired = Vec::new();
        for (id, stored) in self.entries.iter_mut() {
            match stored.zeroed_at {
                None => {
                    if stored.remaining_lifetime(now) == 0 && !stored.lsp.is_purge() {
                        stored.zeroed_at = Some(now);
                        stored.lsp.remaining_lifetime = 0;
                        stored.lsp.tlvs.clear();
                        purges.push(crate::pdu::lsp(
                            false,
                            *id,
                            stored.lsp.sequence_number,
                            0,
                            stored.lsp.bits,
                            vec![],
                        ));
                    }
                }
                Some(zeroed) => {
                    if now.saturating_sub(zeroed) >= crate::ZERO_AGE_LIFETIME as u64 {
                        expired.push(*id);
                    }
                }
            }
        }
        for id in expired {
            self.entries.remove(&id);
        }
        purges
    }

    /// The TLV 9 blocks describing the whole database (a CSNP body;
    /// §9.10: entries of 16 octets, so 15 per 255-byte TLV — chunked
    /// here exactly).
    pub fn csnp_entries(&self, now: u64) -> Vec<Tlv> {
        self.entries_in_range(
            LspId::new(crate::system::SystemId::from_bytes([0; 6]), 0, 0),
            LspId::new(crate::system::SystemId::from_bytes([0xff; 6]), 0xff, 0xff),
            now,
        )
    }

    /// The TLV 9 blocks for a CSNP range (start..=end inclusive —
    /// §9.10's "start LSP id / end LSP id").
    pub fn entries_in_range(&self, start: LspId, end: LspId, now: u64) -> Vec<Tlv> {
        let mut entries: Vec<LspEntry> = self
            .entries
            .range(start..=end)
            .map(|(id, stored)| LspEntry {
                remaining_lifetime: stored.remaining_lifetime(now),
                lsp_id: *id,
                sequence_number: stored.lsp.sequence_number,
                checksum: stored.lsp.checksum,
            })
            .collect();
        let mut tlvs = Vec::new();
        while !entries.is_empty() {
            let take = entries.len().min(15);
            let chunk: Vec<LspEntry> = entries.drain(..take).collect();
            tlvs.push(Tlv::LspEntries(chunk));
        }
        tlvs
    }

    /// Compare a received CSNP's entries against the database and
    /// produce the synchronisation actions (ISO §7.3.15.2.a).
    pub fn process_csnp(&self, entries: &[LspEntry]) -> CsnpActions {
        let mut actions = CsnpActions::default();
        for entry in entries {
            match self.entries.get(&entry.lsp_id) {
                None => actions.requests.push(*entry),
                Some(stored) => {
                    let fake = Lsp {
                        pdu_length: 0,
                        remaining_lifetime: entry.remaining_lifetime,
                        id: entry.lsp_id,
                        sequence_number: entry.sequence_number,
                        checksum: entry.checksum,
                        bits: stored.lsp.bits,
                        tlvs: vec![],
                    };
                    match newer_than(&fake, &stored.lsp) {
                        Ordering::ReceivedNewer => actions.requests.push(*entry),
                        Ordering::StoredNewer => actions.to_send.push(entry.lsp_id),
                        Ordering::Confusion | Ordering::Equal => {}
                    }
                }
            }
        }
        actions
    }

    /// A received PSNP's entries are acknowledgements for the LSPs we
    /// sent (§7.3.15.2.b: "a partial sequence number packet … may act
    /// as an acknowledgement" — clear the SRM flag for matching
    /// entries) and requests for the ones where we hold something
    /// newer; returns the LSPs to (re)send. Aging is unaffected.
    pub fn process_psnp(&mut self, entries: &[LspEntry]) -> Vec<LspId> {
        let mut to_send = Vec::new();
        for entry in entries {
            if let Some(stored) = self.entries.get(&entry.lsp_id) {
                let fake = Lsp {
                    pdu_length: 0,
                    remaining_lifetime: entry.remaining_lifetime,
                    id: entry.lsp_id,
                    sequence_number: entry.sequence_number,
                    checksum: entry.checksum,
                    bits: stored.lsp.bits,
                    tlvs: vec![],
                };
                if matches!(newer_than(&fake, &stored.lsp), Ordering::StoredNewer) {
                    to_send.push(entry.lsp_id);
                }
            }
        }
        to_send
    }

    /// Build a PSNP body (TLV 9 entries) for the LSPs we want.
    pub fn psnp_for(&self, requests: &[LspEntry]) -> Vec<Tlv> {
        vec![Tlv::LspEntries(requests.to_vec())]
    }

    /// Remove an LSP (the daemon's own reorigination path replaces it
    /// via `install`).
    pub fn remove(&mut self, id: &LspId) -> Option<StoredLsp> {
        self.entries.remove(id)
    }
}

/// The own-LSP sequence counter (ISO §7.3.16.1): first LSP numbered
/// 1; reoriginations take "the next number greater"; a received copy
/// of our own LSP with a higher number rebinds us to one past it
/// (§7.3.16.1: "S shall change its sequence number to be the next
/// number greater than the new one received, and shall generate a
/// link state PDU"). The space is a lollipop: 1..=MAX_SEQUENCE_NUMBER
/// then shutdown for MaxAge + ZeroAgeLifetime (the wrap is modelled
/// as exhaustion — restarting at 1 after the wait is §Deferred, it
/// needs daemon-level timer machinery).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SequenceCounter {
    next: u32,
}

impl Default for SequenceCounter {
    fn default() -> Self {
        Self { next: 1 }
    }
}

impl SequenceCounter {
    pub fn new() -> Self {
        Self::default()
    }

    /// The sequence number for the next origination (§7.3.16.1: start
    /// at 1 — 0 is reserved to compare less than any generated LSP).
    pub fn take_next(&mut self) -> Option<u32> {
        if self.next > crate::MAX_SEQUENCE_NUMBER {
            return None; // §7.3.16.1: disable until expiry (see type note)
        }
        let value = self.next;
        self.next = self.next.saturating_add(1);
        Some(value)
    }

    /// Rebind on receiving our own LSP with a higher sequence number.
    pub fn rebound(&mut self, received: u32) -> Option<u32> {
        if received >= self.next {
            self.next = received.saturating_add(1);
        }
        self.take_next()
    }

    /// The number the next origination would use (peek, no consume).
    pub fn peek(&self) -> u32 {
        self.next
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pdu::{lsp as lsp_pdu, LspBits, PduBody};
    use crate::system::SystemId;
    use crate::tlv::Tlv;

    const A: SystemId = SystemId::from_bytes([0, 0, 0, 0, 0, 1]);
    const B: SystemId = SystemId::from_bytes([0, 0, 0, 0, 0, 2]);
    const C: SystemId = SystemId::from_bytes([0, 0, 0, 0, 0, 3]);

    fn make_lsp(id: LspId, seq: u32, lifetime: u16, checksum: u16, tlvs: Vec<Tlv>) -> Lsp {
        let pdu = lsp_pdu(false, id, seq, lifetime, LspBits::default(), tlvs);
        let bytes = pdu.encode();
        let mut decoded = match Pdu::decode(&bytes).unwrap().body {
            PduBody::Lsp(l) => l,
            _ => unreachable!(),
        };
        decoded.checksum = checksum;
        decoded
    }

    fn entry(id: LspId, seq: u32, lifetime: u16, checksum: u16) -> LspEntry {
        LspEntry {
            remaining_lifetime: lifetime,
            lsp_id: id,
            sequence_number: seq,
            checksum,
        }
    }

    #[test]
    fn install_and_ordering_basics() {
        let mut db = Lspdb::new();
        let id = LspId::zero(A);
        assert_eq!(
            db.install(
                make_lsp(id, 1, 1200, 0x1234, vec![Tlv::Hostname("a".into())]),
                0
            ),
            InstallOutcome::Installed
        );
        assert_eq!(db.len(), 1);
        // Same instance.
        assert_eq!(
            db.install(make_lsp(id, 1, 1200, 0x1234, vec![]), 10),
            InstallOutcome::Duplicate
        );
        // Older.
        assert_eq!(
            db.install(make_lsp(id, 0, 1200, 0x4321, vec![]), 20),
            InstallOutcome::OlderThanStored
        );
        // Newer.
        assert_eq!(
            db.install(make_lsp(id, 2, 1200, 0x5678, vec![]), 30),
            InstallOutcome::Installed
        );
        assert_eq!(db.get(&id).unwrap().lsp.sequence_number, 2);
    }

    /// §7.3.16.3's zero-age rules: a purge at the same sequence wins;
    /// a live LSP does not beat a stored tombstone.
    #[test]
    fn zero_age_wins_at_same_sequence() {
        let id = LspId::zero(B);
        let live = make_lsp(id, 5, 1200, 0x1111, vec![]);
        let purged = make_lsp(id, 5, 0, 0x1111, vec![]);
        assert_eq!(newer_than(&purged, &live), Ordering::ReceivedNewer);
        assert_eq!(newer_than(&live, &purged), Ordering::StoredNewer);

        let mut db = Lspdb::new();
        db.install(live.clone(), 0);
        assert_eq!(db.install(purged, 100), InstallOutcome::Installed);
        let stored = db.get(&id).unwrap();
        assert!(stored.lsp.is_purge());
        assert!(stored.lsp.tlvs.is_empty(), "tombstone is header-only");
    }

    /// §7.3.16.2: same sequence, different checksums, someone else's
    /// LSP → purge one copy and flood.
    #[test]
    fn confusion_purges() {
        let id = LspId::zero(B);
        let first = make_lsp(id, 5, 1200, 0x1111, vec![Tlv::Hostname("one".into())]);
        let second = make_lsp(id, 5, 1200, 0x2222, vec![Tlv::Hostname("two".into())]);
        assert_eq!(newer_than(&second, &first), Ordering::Confusion);

        let mut db = Lspdb::new();
        db.install(first, 0);
        assert_eq!(db.install(second, 5), InstallOutcome::ConfusionPurged);
        let stored = db.get(&id).unwrap();
        assert_eq!(stored.lsp.remaining_lifetime, 0);
        assert!(stored.lsp.tlvs.is_empty());
    }

    /// §7.3.16.3: aging decrements with the injected clock and the
    /// expiry purge floods a header-only tombstone (§7.3.16.4.a/b),
    /// which the tombstone expiry later drops (§7.3.16.4.c).
    #[test]
    fn aging_purges_and_tombstones_expire() {
        let mut db = Lspdb::new();
        let id = LspId::zero(A);
        db.install(
            make_lsp(id, 1, 100, 0x1234, vec![Tlv::Hostname("a".into())]),
            0,
        );
        assert_eq!(db.get(&id).unwrap().remaining_lifetime(50), 50);
        assert_eq!(db.get(&id).unwrap().remaining_lifetime(150), 0);
        // Not yet expired at 99 (100 seconds of holding remain 1).
        assert!(db.tick(99).is_empty());
        // Expired at 100: one synchronized purge PDU.
        let purges = db.tick(100);
        assert_eq!(purges.len(), 1);
        let PduBody::Lsp(p) = &purges[0].body else {
            unreachable!()
        };
        assert_eq!(p.id, id);
        assert_eq!(p.remaining_lifetime, 0);
        assert!(p.tlvs.is_empty());
        // The tombstone lingers ZeroAgeLifetime, then drops.
        assert!(db.get(&id).is_some());
        let _ = db.tick(100 + crate::ZERO_AGE_LIFETIME as u64 - 1);
        assert!(db.get(&id).is_some());
        let _ = db.tick(100 + crate::ZERO_AGE_LIFETIME as u64);
        assert!(db.get(&id).is_none());
    }

    /// §7.3.16.1: first LSP numbered 1; successive originations
    /// increment; 0 compares less than everything generated.
    #[test]
    fn sequence_counter_lollipop() {
        let mut seq = SequenceCounter::new();
        assert_eq!(seq.take_next(), Some(1));
        assert_eq!(seq.take_next(), Some(2));
        // A received own-LSP with a higher number rebinds.
        assert_eq!(seq.rebound(9), Some(10));
        assert_eq!(seq.take_next(), Some(11));
        // A lower number does not disturb the counter.
        assert_eq!(seq.rebound(3), Some(12));
        // Exhaustion at the top of the space (§7.3.16.1's disable).
        let mut top = SequenceCounter::new();
        top.next = crate::MAX_SEQUENCE_NUMBER;
        assert_eq!(top.take_next(), Some(crate::MAX_SEQUENCE_NUMBER));
        assert_eq!(top.take_next(), None);
    }

    /// CSNP synchronisation (§7.3.15.2.a): missing → request; theirs
    /// newer → request; ours newer → send; equal → nothing.
    #[test]
    fn csnp_sync_actions() {
        let mut db = Lspdb::new();
        let ida = LspId::zero(A);
        let idb = LspId::zero(B);
        let idc = LspId::zero(C);
        db.install(make_lsp(ida, 4, 1200, 0x0101, vec![]), 0);
        db.install(make_lsp(idb, 7, 1200, 0x0202, vec![]), 0);

        let actions = db.process_csnp(&[
            entry(ida, 4, 1200, 0x0101), // equal: synchronised
            entry(idb, 5, 1200, 0x0202), // ours newer: send ours
            entry(idc, 1, 1200, 0x0303), // missing: request
        ]);
        assert_eq!(actions.to_send, vec![idb]);
        assert_eq!(actions.requests, vec![entry(idc, 1, 1200, 0x0303)]);

        // Ours missing there / theirs newer → request.
        let actions = db.process_csnp(&[entry(idb, 9, 1200, 0x0404)]);
        assert_eq!(actions.requests, vec![entry(idb, 9, 1200, 0x0404)]);
        assert!(actions.to_send.is_empty());
    }

    /// PSNP entries: matching = acknowledgement (nothing to do here —
    /// SRM clearing is the daemon's flag bookkeeping); ours-newer =
    /// resend.
    #[test]
    fn psnp_ack_and_request() {
        let mut db = Lspdb::new();
        let ida = LspId::zero(A);
        db.install(make_lsp(ida, 4, 1200, 0x0101, vec![]), 0);
        // Ack: their entry equals ours.
        assert!(db.process_psnp(&[entry(ida, 4, 1200, 0x0101)]).is_empty());
        // Request: their entry is older.
        assert_eq!(db.process_psnp(&[entry(ida, 2, 1200, 0x0101)]), vec![ida]);
        // Unknown id: nothing (we cannot send what we lack).
        assert!(db
            .process_psnp(&[entry(LspId::zero(C), 2, 1200, 0x77)])
            .is_empty());
    }

    /// The CSNP body chunks at 15 entries per TLV (16 octets each,
    /// 255-octet values).
    #[test]
    fn csnp_chunking() {
        let mut db = Lspdb::new();
        let ids: Vec<LspId> = (0..32)
            .map(|i| LspId::new(SystemId::from_bytes([0, 0, 0, 0, 0, i as u8]), 0, 0))
            .collect();
        for (seq, id) in ids.iter().enumerate() {
            db.install(make_lsp(*id, seq as u32 + 1, 1200, 0x0a0a, vec![]), 0);
        }
        let tlvs = db.csnp_entries(0);
        assert_eq!(tlvs.len(), 3);
        let counts: Vec<usize> = tlvs
            .iter()
            .map(|t| match t {
                Tlv::LspEntries(es) => es.len(),
                _ => 0,
            })
            .collect();
        assert_eq!(counts, vec![15, 15, 2]);
        // BTreeMap order: ids ascending in the entries.
        let Tlv::LspEntries(first) = &tlvs[0] else {
            unreachable!()
        };
        assert_eq!(first[0].lsp_id, ids[0]);
        assert_eq!(first[14].lsp_id, ids[14]);
        let Tlv::LspEntries(last) = &tlvs[2] else {
            unreachable!()
        };
        assert_eq!(last[1].lsp_id, ids[31]);
    }

    /// The ordering lattice as a property: within one LSP id, the
    /// relation is a strict weak ordering except the documented
    /// confusion case, and the zero-age override composes with the
    /// sequence ordering the way §7.3.16.3 says (sequence first, then
    /// the tiebreaks).
    #[test]
    fn lattice_properties() {
        use proptest::prelude::*;

        fn arb_lsp(seq: u32, lifetime: u16, checksum: u16) -> Lsp {
            make_lsp(LspId::zero(B), seq, lifetime, checksum, vec![])
        }

        proptest!(
            ProptestConfig::with_cases(512),
            |(s1 in 1u32..100, s2 in 1u32..100,
              l1 in proptest::bool::ANY, l2 in proptest::bool::ANY,
              same_sum in proptest::bool::ANY) | {
                let a = arb_lsp(s1, if l1 { 0 } else { 1200 }, 0x1111);
                let b = arb_lsp(s2, if l2 { 0 } else { 1200 }, if same_sum && s1 == s2 { 0x1111 } else { 0x2222 });
                let ord = newer_than(&a, &b);
                let inv = newer_than(&b, &a);
                // Antisymmetry on the comparable cases.
                if s1 != s2 {
                    prop_assert_ne!(ord, Ordering::Equal);
                    prop_assert!(matches!(
                        (ord, inv),
                        (Ordering::ReceivedNewer, Ordering::StoredNewer)
                            | (Ordering::StoredNewer, Ordering::ReceivedNewer)
                    ));
                } else {
                    // Same sequence: equal, confusion, or the
                    // zero-age tiebreaks (which invert each other).
                    match (l1, l2, same_sum) {
                        (true, false, _) => {
                            prop_assert_eq!(ord, Ordering::ReceivedNewer);
                            prop_assert_eq!(inv, Ordering::StoredNewer);
                        }
                        (false, true, _) => {
                            prop_assert_eq!(ord, Ordering::StoredNewer);
                            prop_assert_eq!(inv, Ordering::ReceivedNewer);
                        }
                        (_, _, true) => {
                            prop_assert_eq!(ord, Ordering::Equal);
                            prop_assert_eq!(inv, Ordering::Equal);
                        }
                        _ => {
                            prop_assert_eq!(ord, Ordering::Confusion);
                        }
                    }
                }
            }
        );
    }

    /// Transitivity of the sequence-number arm across three
    /// instances (the property the "lollipop" claim rests on).
    #[test]
    fn lattice_transitivity() {
        use proptest::prelude::*;
        proptest!(
            ProptestConfig::with_cases(256),
            |(s1 in 1u32..1000, s2 in 1u32..1000, s3 in 1u32..1000) | {
                let a = make_lsp(LspId::zero(B), s1, 1200, 0x01, vec![]);
                let b = make_lsp(LspId::zero(B), s2, 1200, 0x01, vec![]);
                let c = make_lsp(LspId::zero(B), s3, 1200, 0x01, vec![]);
                if s1 < s2 && s2 < s3 {
                    prop_assert_eq!(newer_than(&a, &b), Ordering::StoredNewer);
                    prop_assert_eq!(newer_than(&b, &c), Ordering::StoredNewer);
                    prop_assert_eq!(newer_than(&a, &c), Ordering::StoredNewer);
                    prop_assert_eq!(newer_than(&c, &a), Ordering::ReceivedNewer);
                }
            }
        );
    }

    /// The database converges under interleaved installs from two
    /// sources: whatever the arrival order, the final stored instance
    /// for each id is the maximal one (the lattice's purpose).
    #[test]
    fn install_convergence_property() {
        use proptest::prelude::*;
        proptest!(
            ProptestConfig::with_cases(128),
            |(order in proptest::collection::vec(0u8..4, 0..16)) | {
                let instances: Vec<Lsp> = (0u32..4)
                    .map(|i| make_lsp(LspId::zero(B), i + 1, 1200, 0x0100 + i as u16, vec![]))
                    .collect();
                let mut db = Lspdb::new();
                let mut max_installed = 0u32;
                for &i in &order {
                    let _ = db.install(instances[i as usize].clone(), 0);
                    max_installed = max_installed.max(i as u32 + 1);
                }
                if order.is_empty() {
                    prop_assert!(db.get(&LspId::zero(B)).is_none());
                } else {
                    let stored_b = db.get(&LspId::zero(B)).unwrap();
                    prop_assert_eq!(stored_b.lsp.sequence_number, max_installed);
                    prop_assert_eq!(stored_b.lsp.checksum, 0x0100 + (max_installed - 1) as u16);
                }
            }
        );
    }
}
