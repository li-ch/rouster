//! The link state database (RFC 2328 §12.2) and its lifecycle rules.
//!
//! - **Keyed store**: (LS type, Link State ID, Advertising Router) —
//!   §12.2's lookup function; a single (most recent) instance per key.
//! - **"Newer than"** (§13.1): the exact four-step comparison —
//!   signed LS sequence number, then LS checksum (u16), then the
//!   MaxAge-only rule, then the MaxAgeDiff age rule — as a total
//!   [`std::cmp::Ordering` (plus an `Identical` outcome)] over
//!   headers. Property-tested as a strict weak ordering.
//! - **Install** (§13.2): replacement plus the contents-difference
//!   detection that decides whether SPF must rerun (options / MaxAge
//!   / length / body — explicitly *not* seq or checksum), and the
//!   MinLSArrival guard of §13 step 5(a) (flood-installed instances
//!   cannot be overwritten within `MIN_LS_ARRIVAL`).
//! - **Aging** (§14): clock-injected ticks advance the age (never past
//!   `MAX_AGE`), self-originated LSAs crossing `LS_REFRESH_TIME` are
//!   reported for refresh (§12.4's re-origination with seq+1), and
//!   entries reaching MaxAge are reported for the flush reflood.
//!   A MaxAge LSA leaves the table only when it is off every
//!   retransmission list and no adjacency is syncing (Exchange or
//!   Loading) — §14's removal condition, polled via [`Lsdb::flush_ready`].
//! - **Sequence rollover** (§12.1.6): originating past
//!   `MAX_SEQUENCE_NUMBER` is refused until the instance has been
//!   prematurely aged (§14.1) and flushed; the next origination then
//!   restarts at `INITIAL_SEQUENCE_NUMBER`.
//!
//! The clock is injected throughout (`now` in seconds); nothing in
//! here starts timers or reads wall time — the bgpd FSM convention.
//! §12.2's "an LSA deleted from the database must also be removed
//! from all neighbors' Link state retransmission lists" lives with
//! the neighbor structures (M4); `remove` returns the key so callers
//! can cascade.

use std::cmp::Ordering;

use crate::lsa::{Lsa, LsaHeader, LsaKey, INITIAL_SEQUENCE_NUMBER, MAX_SEQUENCE_NUMBER};
use crate::{LS_REFRESH_TIME, MAX_AGE, MAX_AGE_DIFF, MIN_LS_ARRIVAL, MIN_LS_INTERVAL};

/// The family-neutral LSA-header surface the LSDB semantics run on
/// (§13.1/§13.2/§14): the fields both wire families' 20-byte headers
/// share — v2 (`LsaHeader`) and v3 (`LsaHeaderV3`) implement it, and
/// one generic [`Lsdb`] serves OSPFv2 and OSPFv3 unchanged. This is
/// architecture invariant 3's "the LSDB is address-family
/// independent" cashed as code.
pub trait LsaHeaderInfo {
    fn ls_age(&self) -> u16;
    fn set_ls_age(&mut self, age: u16);
    fn seq(&self) -> u32;
    fn set_seq(&mut self, seq: u32);
    fn checksum(&self) -> u16;
    /// In bytes, including the 20-byte header.
    fn length(&self) -> u16;
    /// §12.1.6: the sequence compares as signed i32.
    fn seq_signed(&self) -> i32;
    /// Age with the DoNotAge bit masked off.
    fn effective_age(&self) -> u16;
    /// §14: MaxAge instances are not used in the routing calculation.
    fn is_max_age(&self) -> bool;
    /// §14.1: force MaxAge, preserving the DoNotAge bit.
    fn force_max_age(&mut self);
}

/// One LSA family's codec surface for the LSDB: identity, the header
/// view, the §13.2 contents-difference body half, and the
/// locally-built normalization (re-encode to fill checksum/length).
pub trait LsaInstance: Clone {
    type Header: LsaHeaderInfo;

    fn key(&self) -> LsaKey;
    fn header(&self) -> &Self::Header;
    fn header_mut(&mut self) -> &mut Self::Header;
    /// §13.2's body-side difference (everything except length and
    /// MaxAge, which the generic comparison covers): v2's Options
    /// octet + body; v3's body (Options live in bodies there).
    fn body_differs(&self, other: &Self) -> bool;
    /// A locally built instance (zero checksum/length) normalized to
    /// its encoded form; already-normalized instances pass through.
    fn normalized(&self) -> Self;
}

impl LsaHeaderInfo for LsaHeader {
    fn ls_age(&self) -> u16 {
        self.ls_age
    }
    fn set_ls_age(&mut self, age: u16) {
        self.ls_age = age;
    }
    fn seq(&self) -> u32 {
        self.seq
    }
    fn set_seq(&mut self, seq: u32) {
        self.seq = seq;
    }
    fn checksum(&self) -> u16 {
        self.checksum
    }
    fn length(&self) -> u16 {
        self.length
    }
    fn seq_signed(&self) -> i32 {
        LsaHeader::seq_signed(self)
    }
    fn effective_age(&self) -> u16 {
        LsaHeader::effective_age(self)
    }
    fn is_max_age(&self) -> bool {
        LsaHeader::is_max_age(self)
    }
    fn force_max_age(&mut self) {
        self.ls_age = (self.ls_age & crate::lsa::DO_NOT_AGE) | MAX_AGE;
    }
}

impl LsaInstance for Lsa {
    type Header = LsaHeader;

    fn key(&self) -> LsaKey {
        Lsa::key(self)
    }
    fn header(&self) -> &LsaHeader {
        &self.header
    }
    fn header_mut(&mut self) -> &mut LsaHeader {
        &mut self.header
    }
    fn body_differs(&self, other: &Self) -> bool {
        // §13.2's Options + body list (the header Options octet is
        // the v2 half of the family difference).
        self.header.options != other.header.options || self.body != other.body
    }
    fn normalized(&self) -> Self {
        if self.header.checksum == 0 || self.header.length == 0 {
            Lsa::decode(&self.encode()).unwrap_or_else(|_| self.clone())
        } else {
            self.clone()
        }
    }
}

/// The §13.1 comparison outcome. `Identical` is distinct from `Equal`
/// only in naming intent (§13.1's final bullet: "the two instances
/// are considered to be identical").
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Which {
    FirstNewer,
    SecondNewer,
    Identical,
}

/// §13.1: which of two instances of the same LSA is more recent.
/// Both headers must be of the same LSA (same type/ID/adv-router);
/// callers guarantee that (the LSDB only ever compares store hits).
pub fn newer_than<H: LsaHeaderInfo>(a: &H, b: &H) -> Which {
    // 1. The LSA having the newer LS sequence number is more recent
    //    (§12.1.6: signed 32-bit space).
    match a.seq_signed().cmp(&b.seq_signed()) {
        Ordering::Greater => return Which::FirstNewer,
        Ordering::Less => return Which::SecondNewer,
        Ordering::Equal => {}
    }
    // 2. Same sequence: larger LS checksum (16-bit unsigned) wins.
    match a.checksum().cmp(&b.checksum()) {
        Ordering::Greater => return Which::FirstNewer,
        Ordering::Less => return Which::SecondNewer,
        Ordering::Equal => {}
    }
    // 3. Same seq + checksum: if only one instance is MaxAge, it is
    //    the more recent.
    match (a.is_max_age(), b.is_max_age()) {
        (true, false) => return Which::FirstNewer,
        (false, true) => return Which::SecondNewer,
        _ => {}
    }
    // 4. Ages differing by more than MaxAgeDiff: the younger wins.
    let (aa, ba) = (a.effective_age(), b.effective_age());
    if aa.abs_diff(ba) > MAX_AGE_DIFF {
        return if aa < ba {
            Which::FirstNewer
        } else {
            Which::SecondNewer
        };
    }
    Which::Identical
}

/// One stored instance plus its bookkeeping.
#[derive(Debug, Clone)]
pub struct LsaEntry<T: LsaInstance = Lsa> {
    pub lsa: T,
    /// Injection-time seconds when this instance was installed.
    pub installed_at: u64,
    /// True when the instance arrived via flooding (subject to the
    /// MinLSArrival overwrite guard, §13 step 5(a)).
    pub via_flooding: bool,
    /// True while the instance sits on some neighbor's link state
    /// retransmission list (§14's removal condition a).
    pub on_retransmission: bool,
}

/// What an [`Lsdb::install`] did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InstallOutcome {
    /// Replaced the store copy (or created it). `changed` is §13.2's
    /// contents-difference verdict — false means "no need to rerun
    /// the routing calculation".
    Installed { changed: bool },
    /// Same instance as the store copy (§13 step 7: acknowledge /
    /// implied-ack territory, nothing to store).
    SameInstance,
    /// The store copy is more recent (§13 step 8: send the database
    /// copy back; nothing stored).
    Stale,
    /// Refused: the current copy was flood-installed less than
    /// `MIN_LS_ARRIVAL` seconds ago (§13 step 5(a): discard without
    /// acknowledging).
    RejectedMinLsArrival,
}

/// What an aging tick observed.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AgingReport {
    /// Self-originated LSAs whose age crossed `LS_REFRESH_TIME`:
    /// re-originate with seq+1 (§12.4).
    pub refresh_due: Vec<LsaKey>,
    /// LSAs whose age reached MaxAge: reflood them as the flush
    /// (§14).
    pub max_age: Vec<LsaKey>,
}

/// Sequence-number bookkeeping for a self-originated LSA.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SeqState {
    /// Free to originate with `next`.
    Ready { next: u32 },
    /// At MaxSequenceNumber: the §12.1.6 rollover path — prematurely
    /// age, flush, then restart at InitialSequenceNumber.
    NeedsFlush { pending: u32 },
}

/// §13.4's outcome for one received self-originated LSA.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Readopt {
    /// The received instance is newer than anything we originated:
    /// tracking advanced one past it — re-originate.
    Advanced,
    /// At/below our own tracking (§13's steps 7/8 territory).
    Stale,
    /// The received instance sits at MaxSequenceNumber: flush before
    /// the sequence restarts (§12.1.6) — prematurely age the stored
    /// copy (§14.1).
    NeedsFlush,
    /// Not an LSA we originate (anymore) — the caller's §13.4 flush
    /// policy decides (no route / no longer DR / Router ID changed).
    NotOurs,
}

/// The typed link state database for one area (plus the global
/// AS-external scope — v1 keeps one store; areas are §Deferred).
///
/// Generic over the LSA family ([`LsaInstance`]): OSPFv2 (`Lsa`) is
/// the default — every existing use compiles unchanged — and
/// OSPFv3 instantiates `Lsdb<LsaV3>` (the S7-a seam fix: ONE
/// implementation of §12.2/§13.1/§13.2/§14 for both families, per
/// architecture invariant 3).
#[derive(Debug)]
pub struct Lsdb<T: LsaInstance = Lsa> {
    map: std::collections::HashMap<LsaKey, LsaEntry<T>>,
    self_seq: std::collections::HashMap<LsaKey, SeqState>,
    self_originated_at: std::collections::HashMap<LsaKey, u64>,
    last_tick: Option<u64>,
}

impl<T: LsaInstance> Default for Lsdb<T> {
    fn default() -> Self {
        Self {
            map: Default::default(),
            self_seq: Default::default(),
            self_originated_at: Default::default(),
            last_tick: None,
        }
    }
}

impl<T: LsaInstance> Lsdb<T> {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn len(&self) -> usize {
        self.map.len()
    }

    pub fn is_empty(&self) -> bool {
        self.map.is_empty()
    }

    pub fn get(&self, key: &LsaKey) -> Option<&LsaEntry<T>> {
        self.map.get(key)
    }

    pub fn get_mut(&mut self, key: &LsaKey) -> Option<&mut LsaEntry<T>> {
        self.map.get_mut(key)
    }

    /// All stored instances (the database summary list of §10.3
    /// ExStart/Exchange — MaxAge entries included; the DD layer moves
    /// them to the retransmission list per §14).
    pub fn all(&self) -> impl Iterator<Item = &LsaEntry<T>> {
        self.map.values()
    }

    pub fn contains(&self, key: &LsaKey) -> bool {
        self.map.contains_key(key)
    }

    /// §13.2 install path. `now` is the injected clock (seconds).
    pub fn install(&mut self, lsa: T, via_flooding: bool, now: u64) -> InstallOutcome {
        // Locally built LSAs carry a zero header checksum/length (the
        // codec fills them at encode); normalize once so the stored
        // header — what DD summaries and LSAcks describe — is the
        // wire truth (§A.4.1: the checksum "cannot be zero").
        let lsa = lsa.normalized();
        let key = lsa.key();
        match self.map.get_mut(&key) {
            None => {
                self.map.insert(
                    key,
                    LsaEntry {
                        lsa,
                        installed_at: now,
                        via_flooding,
                        on_retransmission: false,
                    },
                );
                InstallOutcome::Installed { changed: true }
            }
            Some(current) => {
                match newer_than(lsa.header(), current.lsa.header()) {
                    Which::SecondNewer => return InstallOutcome::Stale,
                    Which::Identical => {
                        if lsa.header().seq() == current.lsa.header().seq() {
                            // §13 step 7: neither more recent — the
                            // same instance as far as the protocol is
                            // concerned (implied-ack territory).
                            return InstallOutcome::SameInstance;
                        }
                        // Identical by the age-difference tiebreak but
                        // a different raw instance: nothing in §13
                        // tells us to replace the incumbent.
                        return InstallOutcome::Stale;
                    }
                    Which::FirstNewer => {}
                }
                if via_flooding
                    && current.via_flooding
                    && now.saturating_sub(current.installed_at) < MIN_LS_ARRIVAL as u64
                {
                    return InstallOutcome::RejectedMinLsArrival;
                }
                let changed = contents_differ(&lsa, &current.lsa);
                let was_retrans = current.on_retransmission;
                let installed_at = if changed { now } else { current.installed_at };
                *current = LsaEntry {
                    lsa,
                    installed_at,
                    via_flooding,
                    on_retransmission: was_retrans,
                };
                InstallOutcome::Installed { changed }
            }
        }
    }

    /// §13.2's contents-difference list: Options changed, one instance
    /// MaxAge and the other not, length changed, or the body changed
    /// (seq/checksum excluded).
    pub fn contents_differ_with(&self, candidate: &T) -> bool {
        // Normalize the candidate the same way install does (a
        // locally built LSA carries a zero length until encoded), so
        // the §13.2 length comparison sees the wire truth.
        let candidate = candidate.normalized();
        match self.map.get(&candidate.key()) {
            None => true,
            Some(entry) => contents_differ(&candidate, &entry.lsa),
        }
    }

    /// Advance every stored LSA's age by the elapsed time and report
    /// the §14 / §12.4 events (§14: never increment past MaxAge).
    pub fn tick_aging(&mut self, now: u64) -> AgingReport {
        let mut report = AgingReport::default();
        let delta = match self.last_tick {
            None => {
                self.last_tick = Some(now);
                return report;
            }
            Some(prev) => now.saturating_sub(prev),
        };
        self.last_tick = Some(now);
        if delta == 0 {
            return report;
        }
        for (key, entry) in &mut self.map {
            if entry.lsa.header().is_max_age() {
                // Already MaxAge: awaiting the flush removal condition.
                continue;
            }
            let age = entry.lsa.header().ls_age();
            let dna = age & crate::lsa::DO_NOT_AGE;
            let eff = (age & !crate::lsa::DO_NOT_AGE).saturating_add(delta as u16);
            let new_eff = eff.min(MAX_AGE);
            entry.lsa.header_mut().set_ls_age(dna | new_eff);
            if new_eff >= MAX_AGE {
                report.max_age.push(*key);
            }
        }
        // Refresh bookkeeping (§12.4): self-originated LSAs crossing
        // LS_REFRESH_TIME are re-originated. The self-originated set
        // is exactly the keys sequence state is tracked for.
        for key in self.self_seq.keys() {
            if let Some(entry) = self.map.get(key) {
                let eff = entry.lsa.header().effective_age();
                if eff >= LS_REFRESH_TIME && !entry.lsa.header().is_max_age() {
                    report.refresh_due.push(*key);
                }
            }
        }
        report
    }

    /// §14's removal condition: MaxAge LSAs come out once they are on
    /// no retransmission list and no adjacency is in Exchange/Loading
    /// (`adjacency_syncing` carries that router-wide fact).
    pub fn flush_ready(&self, adjacency_syncing: bool) -> Vec<LsaKey> {
        self.map
            .iter()
            .filter(|(_, e)| e.lsa.header().is_max_age())
            .filter(|(_, e)| !e.on_retransmission)
            .filter(|_| !adjacency_syncing)
            .map(|(k, _)| *k)
            .collect()
    }

    /// Remove an LSA (the §14 removal, or §12.2's deletion paths).
    /// Returns the removed instance so callers can cascade it off
    /// neighbor retransmission lists.
    pub fn remove(&mut self, key: &LsaKey) -> Option<T> {
        self.self_seq.remove(key);
        self.self_originated_at.remove(key);
        self.map.remove(key).map(|e| e.lsa)
    }

    /// Originate (or re-originate) a self-originated LSA: enforces
    /// MinLSInterval (§Appendix B) and the §12.1.6 rollover guard,
    /// bumps the tracked sequence, and installs it. The caller supplies
    /// the full LSA with any sequence number — it is overwritten.
    pub fn originate(
        &mut self,
        mut lsa: T,
        now: u64,
    ) -> Result<InstallOutcome, crate::error::OspfError> {
        let key = lsa.key();
        if let Some(&last) = self.self_originated_at.get(&key) {
            if now.saturating_sub(last) < MIN_LS_INTERVAL as u64 {
                return Err(crate::error::OspfError::Config(format!(
                    "MinLSInterval ({MIN_LS_INTERVAL}s) not elapsed for {key:?}"
                )));
            }
        }
        let next = match self.self_seq.get(&key) {
            None => INITIAL_SEQUENCE_NUMBER,
            Some(SeqState::Ready { next }) => *next,
            Some(SeqState::NeedsFlush { .. }) => {
                // §12.1.6: the MaxSequenceNumber instance must be
                // completely flushed before a new instance is
                // introduced.
                if self.map.contains_key(&key) {
                    return Err(crate::error::OspfError::Config(format!(
                        "sequence rollover for {key:?}: flush the MaxSequenceNumber instance first"
                    )));
                }
                INITIAL_SEQUENCE_NUMBER
            }
        };
        let new_seq = if next == MAX_SEQUENCE_NUMBER {
            // Originate AT MaxSequenceNumber once, then require flush.
            self.self_seq.insert(
                key,
                SeqState::NeedsFlush {
                    pending: MAX_SEQUENCE_NUMBER,
                },
            );
            MAX_SEQUENCE_NUMBER
        } else {
            self.self_seq
                .insert(key, SeqState::Ready { next: next + 1 });
            next
        };
        lsa.header_mut().set_seq(new_seq);
        self.self_originated_at.insert(key, now);
        Ok(self.install(lsa, false, now))
    }

    /// §14.1 premature aging: set MaxAge, keep the sequence number,
    /// and report it for the flush reflood.
    pub fn premature_age(&mut self, key: &LsaKey) -> Option<T> {
        let entry = self.map.get_mut(key)?;
        entry.lsa.header_mut().force_max_age();
        Some(entry.lsa.clone())
    }

    /// §13.4's re-adoption: a received instance of a self-originated
    /// LSA is "newer than the last instance that the router actually
    /// originated" (a pre-restart instance a peer still holds) — the
    /// router must then advance its sequence tracking "one past the
    /// received LS sequence number" so the next origination is the
    /// newest in the domain.
    ///
    /// Returns `true` when the tracking advanced (the caller then
    /// re-originates). Older/equal instances return `false` (§13's
    /// steps 7/8 already answer them). A received instance at
    /// MaxSequenceNumber cannot be advanced past (§12.1.6): the
    /// tracking moves to the flush-before-restart state instead, and
    /// the caller should prematurely age its stored copy (§14.1).
    pub fn readopt_self_originated(&mut self, received: &T) -> Readopt {
        let key = received.key();
        let Some(SeqState::Ready { next }) = self.self_seq.get(&key) else {
            // Not ours to originate (anymore): nothing to adopt —
            // the flush decision is the caller's policy.
            return Readopt::NotOurs;
        };
        let recv = received.header().seq() as i32;
        let ours = *next as i32;
        if recv < ours {
            return Readopt::Stale;
        }
        if received.header().seq() == crate::lsa::MAX_SEQUENCE_NUMBER {
            // §12.1.6: nothing exists past MaxSequenceNumber — the
            // old instance must be flushed before the sequence
            // restarts at InitialSequenceNumber.
            self.self_seq.insert(
                key,
                SeqState::NeedsFlush {
                    pending: crate::lsa::MAX_SEQUENCE_NUMBER,
                },
            );
            return Readopt::NeedsFlush;
        }
        self.self_seq.insert(
            key,
            SeqState::Ready {
                next: received.header().seq() + 1,
            },
        );
        Readopt::Advanced
    }

    /// Install an already-originated instance into this database
    /// and track its sequence — the AS-scope mirroring path (§7: the
    /// AS-external list is part of every area's database; one
    /// origination, identical instances everywhere).
    pub fn mirror_originated(&mut self, lsa: &T, now: u64) {
        let key = lsa.key();
        let next = lsa
            .header()
            .seq()
            .wrapping_add(1)
            .max(crate::lsa::INITIAL_SEQUENCE_NUMBER);
        let _ = self.install(lsa.clone(), false, now);
        self.self_seq.insert(key, SeqState::Ready { next });
        self.self_originated_at.insert(key, now);
    }

    /// The next sequence number the LSDB would stamp for `key`
    /// (operator surface / tests; `None` when never originated).
    pub fn next_seq_for(&self, key: &LsaKey) -> Option<i32> {
        match self.self_seq.get(key) {
            Some(SeqState::Ready { next }) => Some(*next as i32),
            _ => None,
        }
    }

    /// Mark/unmark an LSA as sitting on a retransmission list (§14
    /// removal condition a).
    pub fn set_on_retransmission(&mut self, key: &LsaKey, on: bool) {
        if let Some(e) = self.map.get_mut(key) {
            e.on_retransmission = on;
        }
    }
}

/// §13.2's difference list as a predicate over the family-neutral
/// surface: MaxAge and length from the header, the body/options
/// family half from [`LsaInstance::body_differs`].
fn contents_differ<T: LsaInstance>(new: &T, old: &T) -> bool {
    new.header().is_max_age() != old.header().is_max_age()
        || new.header().length() != old.header().length()
        || new.body_differs(old)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::lsa::{
        LinkStateId, LinkType, LsaBody, LsaHeader, LsaType, Options, RouterId, RouterLink,
        RouterLsa,
    };

    fn hdr(seq: u32, checksum: u16, age: u16) -> LsaHeader {
        LsaHeader {
            ls_age: age,
            options: Options(0x02),
            ls_type: LsaType::ROUTER,
            link_state_id: LinkStateId::new(1),
            adv_router: RouterId::new(2),
            seq,
            checksum,
            length: 36,
        }
    }

    fn router_lsa(seq: u32, age: u16, metric: u16) -> Lsa {
        Lsa {
            header: LsaHeader {
                ls_age: age,
                options: Options(0x02),
                ls_type: LsaType::ROUTER,
                link_state_id: LinkStateId::new(1),
                adv_router: RouterId::new(2),
                seq,
                checksum: 0x1234,
                length: 0,
            },
            body: LsaBody::Router(RouterLsa {
                v_bit: false,
                e_bit: false,
                b_bit: false,
                nt_bit: false,
                links: vec![RouterLink {
                    link_id: LinkStateId::new(9),
                    link_data: 0xffff_ff00,
                    link_type: LinkType::Stub,
                    metric,
                    tos: vec![],
                }],
            }),
        }
    }

    // ---- §13.1 table tests, one per bullet ----------------------

    #[test]
    fn newer_by_sequence() {
        // Bullet 1: newer sequence wins — including across the
        // signed wrap (0x7fffffff is the max, 0x80000001 the min).
        assert_eq!(
            newer_than(&hdr(5, 0x1111, 0), &hdr(4, 0xffff, 0)),
            Which::FirstNewer
        );
        assert_eq!(
            newer_than(&hdr(4, 0x1111, 0), &hdr(5, 0xffff, 0)),
            Which::SecondNewer
        );
        assert_eq!(
            newer_than(
                &hdr(MAX_SEQUENCE_NUMBER, 1, 0),
                &hdr(INITIAL_SEQUENCE_NUMBER, 2, 0)
            ),
            Which::FirstNewer
        );
        // seq 0 (signed 0) beats every 0x8... value.
        assert_eq!(
            newer_than(&hdr(0, 1, 0), &hdr(0xffff_ffff, 2, 0)),
            Which::FirstNewer
        );
    }

    #[test]
    fn newer_by_checksum() {
        // Bullet 2: same sequence, larger 16-bit checksum wins.
        assert_eq!(
            newer_than(&hdr(5, 0x2000, 0), &hdr(5, 0x1fff, 0)),
            Which::FirstNewer
        );
        assert_eq!(
            newer_than(&hdr(5, 0x2000, 0), &hdr(5, 0x2000, 0)),
            Which::Identical
        );
    }

    #[test]
    fn newer_by_max_age_only() {
        // Bullet 3: same seq+checksum, exactly one MaxAge — the
        // MaxAge instance is "more recent" (it is the flush).
        assert_eq!(
            newer_than(&hdr(5, 7, MAX_AGE), &hdr(5, 7, 100)),
            Which::FirstNewer
        );
        assert_eq!(
            newer_than(&hdr(5, 7, 100), &hdr(5, 7, MAX_AGE)),
            Which::SecondNewer
        );
    }

    #[test]
    fn newer_by_max_age_diff() {
        // Bullet 4: ages differing by MORE than MaxAgeDiff (900):
        // the younger instance is more recent.
        assert_eq!(
            newer_than(&hdr(5, 7, 100), &hdr(5, 7, 100 + 901)),
            Which::FirstNewer
        );
        // Exactly MaxAgeDiff apart: identical.
        assert_eq!(
            newer_than(&hdr(5, 7, 100), &hdr(5, 7, 100 + MAX_AGE_DIFF)),
            Which::Identical
        );
        assert_eq!(
            newer_than(&hdr(5, 7, 100 + MAX_AGE_DIFF), &hdr(5, 7, 100)),
            Which::Identical
        );
    }

    // ---- install paths ------------------------------------------

    #[test]
    fn install_new_identical_stale() {
        let mut db = Lsdb::new();
        let a = router_lsa(10, 1, 5);
        let key = a.key();
        assert_eq!(
            db.install(a.clone(), true, 100),
            InstallOutcome::Installed { changed: true }
        );
        // Same instance again: §13 step 7.
        assert_eq!(
            db.install(a.clone(), true, 200),
            InstallOutcome::SameInstance
        );
        // Older: stale.
        let older = router_lsa(9, 1, 5);
        assert_eq!(db.install(older, true, 300), InstallOutcome::Stale);
        // Newer, same body: installed, contents unchanged → no SPF.
        let newer = router_lsa(11, 1, 5);
        assert_eq!(
            db.install(newer, true, 400),
            InstallOutcome::Installed { changed: false }
        );
        // Newer, changed body: contents changed → SPF.
        let changed = router_lsa(12, 1, 6);
        assert_eq!(
            db.install(changed, true, 500),
            InstallOutcome::Installed { changed: true }
        );
        assert!(db.contains(&key));
    }

    #[test]
    fn install_min_ls_arrival_guard() {
        // §13 step 5(a): flood-installed instances cannot be replaced
        // within MinLSArrival (1s) — discarded WITHOUT acknowledging.
        let mut db = Lsdb::new();
        db.install(router_lsa(10, 1, 5), true, 1000);
        let newer = router_lsa(11, 1, 5);
        assert_eq!(
            db.install(newer.clone(), true, 1000),
            InstallOutcome::RejectedMinLsArrival
        );
        // At +1s (== MinLSArrival) the window has passed and it goes
        // through; a dt strictly inside the window is the rejection.
        let mut db2 = Lsdb::new();
        db2.install(router_lsa(10, 1, 5), true, 1000);
        assert_eq!(
            db2.install(router_lsa(11, 1, 5), true, 1001 + MIN_LS_ARRIVAL as u64),
            InstallOutcome::Installed { changed: false }
        );
        // A sub-second later arrival is still inside the window.
        let mut db4 = Lsdb::new();
        db4.install(router_lsa(10, 1, 5), true, 1000);
        assert_eq!(
            db4.install(router_lsa(11, 1, 5), true, 1000),
            InstallOutcome::RejectedMinLsArrival
        );
        // Self-originated replacements are not guarded.
        let mut db3 = Lsdb::new();
        db3.install(router_lsa(10, 1, 5), false, 1000);
        assert_eq!(
            db3.install(router_lsa(11, 1, 5), false, 1000),
            InstallOutcome::Installed { changed: false }
        );
    }

    #[test]
    fn contents_differ_list() {
        // §13.2: options, MaxAge-vs-not, length, body. Sequence-only
        // changes do NOT count.
        let mut db = Lsdb::new();
        db.install(router_lsa(10, 1, 5), true, 0);
        assert!(!db.contents_differ_with(&router_lsa(11, 1, 5)), "seq-only");
        assert!(
            db.contents_differ_with(&router_lsa(11, 1, 6)),
            "body metric"
        );
        let mut aged = router_lsa(11, 1, 5);
        aged.header.ls_age = MAX_AGE;
        assert!(db.contents_differ_with(&aged), "MaxAge vs not");
        let mut opts = router_lsa(11, 1, 5);
        opts.header.options = Options(0x06);
        assert!(db.contents_differ_with(&opts), "options");
        let mut longer = router_lsa(11, 1, 5);
        longer.body = LsaBody::Router(RouterLsa {
            v_bit: false,
            e_bit: false,
            b_bit: false,
            nt_bit: false,
            links: vec![
                RouterLink {
                    link_id: LinkStateId::new(9),
                    link_data: 0xffff_ff00,
                    link_type: LinkType::Stub,
                    metric: 5,
                    tos: vec![],
                },
                RouterLink {
                    link_id: LinkStateId::new(10),
                    link_data: 0xffff_ff00,
                    link_type: LinkType::Stub,
                    metric: 5,
                    tos: vec![],
                },
            ],
        });
        assert!(db.contents_differ_with(&longer), "length via body");
    }

    // ---- aging ---------------------------------------------------

    #[test]
    fn aging_increments_clamps_and_reports() {
        let mut db = Lsdb::new();
        db.install(router_lsa(10, 1, 5), true, 0);
        let key = router_lsa(10, 1, 5).key();
        db.tick_aging(0); // establishes the epoch
        let report = db.tick_aging(10);
        assert!(report.refresh_due.is_empty() && report.max_age.is_empty());
        assert_eq!(db.get(&key).unwrap().lsa.header.ls_age, 11);
        // A big jump clamps at MaxAge and reports the flush.
        let report = db.tick_aging(4000);
        assert_eq!(db.get(&key).unwrap().lsa.header.ls_age, MAX_AGE);
        assert!(report.max_age.contains(&key));
        assert!(db.get(&key).unwrap().lsa.header.is_max_age());
    }

    #[test]
    fn refresh_due_at_ls_refresh_time() {
        // §12.4: self-originated LSAs are refreshed when their age
        // crosses LS_REFRESH_TIME (the originate() path tracks them).
        let mut db = Lsdb::new();
        db.originate(router_lsa(1, 0, 5), 0).unwrap();
        let key = router_lsa(1, 0, 5).key();
        db.tick_aging(0);
        // Age 0 + 1799 = 1799 < LS_REFRESH_TIME: not yet due.
        let report = db.tick_aging(LS_REFRESH_TIME as u64 - 1);
        assert!(!report.refresh_due.contains(&key));
        // One more second: age 1800 == LS_REFRESH_TIME: due (§12.4).
        let report = db.tick_aging(LS_REFRESH_TIME as u64);
        assert!(report.refresh_due.contains(&key));
    }

    #[test]
    fn max_age_removal_condition() {
        // §14: out of the database only when off all retransmission
        // lists AND no adjacency is Exchange/Loading.
        let mut db = Lsdb::new();
        db.install(router_lsa(10, MAX_AGE, 5), true, 0);
        let key = router_lsa(10, 1, 5).key();
        assert_eq!(db.get(&key).unwrap().lsa.header.ls_age, MAX_AGE);
        db.set_on_retransmission(&key, true);
        assert!(db.flush_ready(true).is_empty());
        assert!(
            db.flush_ready(false).is_empty(),
            "still on a retransmission list"
        );
        db.set_on_retransmission(&key, false);
        assert!(db.flush_ready(true).is_empty(), "an adjacency is syncing");
        assert_eq!(db.flush_ready(false), vec![key]);
        assert!(db.remove(&key).is_some());
        assert!(db.flush_ready(false).is_empty());
    }

    // ---- origination + rollover ----------------------------------

    #[test]
    fn originate_tracks_sequence_and_min_ls_interval() {
        let mut db = Lsdb::new();
        let key = router_lsa(0, 1, 5).key();
        db.originate(router_lsa(0, 1, 5), 0).unwrap();
        assert_eq!(
            db.get(&key).unwrap().lsa.header.seq,
            INITIAL_SEQUENCE_NUMBER
        );
        // Too soon: MinLSInterval (5s).
        assert!(db.originate(router_lsa(0, 1, 6), 2).is_err());
        db.originate(router_lsa(0, 1, 6), 5).unwrap();
        assert_eq!(
            db.get(&key).unwrap().lsa.header.seq,
            INITIAL_SEQUENCE_NUMBER + 1
        );
    }

    #[test]
    fn sequence_rollover_requires_flush() {
        // §12.1.6: at MaxSequenceNumber the instance must be flushed
        // (premature aging, §14.1) before a fresh InitialSequenceNumber
        // instance may be originated.
        let mut db = Lsdb::new();
        let key = router_lsa(0, 1, 5).key();
        // Force the tracked sequence to the boundary.
        db.self_seq.insert(
            key,
            SeqState::Ready {
                next: MAX_SEQUENCE_NUMBER,
            },
        );
        db.install(router_lsa(1, 1, 5), false, 0);
        db.originate(router_lsa(0, 1, 5), 10).unwrap();
        assert_eq!(db.get(&key).unwrap().lsa.header.seq, MAX_SEQUENCE_NUMBER);
        // Further origination is refused while the instance exists.
        assert!(db.originate(router_lsa(0, 1, 5), 100).is_err());
        // Premature-age it (age -> MaxAge, seq kept), flush it out.
        let aged = db.premature_age(&key).unwrap();
        assert_eq!(aged.header.ls_age, MAX_AGE);
        assert_eq!(
            aged.header.seq, MAX_SEQUENCE_NUMBER,
            "§14.1 keeps the sequence"
        );
        db.set_on_retransmission(&key, true);
        assert!(db.flush_ready(false).is_empty());
        db.set_on_retransmission(&key, false);
        db.remove(&key);
        // Now the restart at InitialSequenceNumber is allowed.
        db.originate(router_lsa(0, 1, 5), 200).unwrap();
        assert_eq!(
            db.get(&key).unwrap().lsa.header.seq,
            INITIAL_SEQUENCE_NUMBER
        );
    }

    // ---- ordering property tests ---------------------------------

    struct XorShift(u64);
    impl XorShift {
        fn next(&mut self) -> u64 {
            self.0 ^= self.0 << 13;
            self.0 ^= self.0 >> 7;
            self.0 ^= self.0 << 17;
            self.0
        }
    }

    fn rand_header(rng: &mut XorShift) -> LsaHeader {
        let pick = rng.next() % 4;
        let seq = match pick {
            0 => INITIAL_SEQUENCE_NUMBER + (rng.next() % 0xffff) as u32,
            1 => MAX_SEQUENCE_NUMBER - (rng.next() % 0xffff) as u32,
            2 => (rng.next() >> 40) as u32,
            _ => 0xffff_ffff - (rng.next() % 0xffff) as u32,
        };
        let age = (rng.next() % (MAX_AGE as u64 + 1)) as u16;
        hdr(
            seq,
            (rng.next() >> 48) as u16,
            if rng.next().is_multiple_of(8) {
                MAX_AGE
            } else {
                age
            },
        )
    }

    #[test]
    fn property_ordering_is_strict_weak() {
        // §13.1's comparison is total and antisymmetric, and — because
        // sequence/checksum/MaxAge form a lexicographic prefix and the
        // age-difference rule cannot cycle within the remaining class
        // (a cycle needs ages differing by more than 3·MaxAgeDiff
        // inside a 0..=MaxAge window) — transitive. 4096 triples.
        let mut rng = XorShift(0x015b_0001_2026_1007);
        for _ in 0..4096 {
            let a = rand_header(&mut rng);
            let b = rand_header(&mut rng);
            let c = rand_header(&mut rng);
            let ab = newer_than(&a, &b);
            let ba = newer_than(&b, &a);
            // Antisymmetry / totality.
            match (ab, ba) {
                // ab=FirstNewer says "a newer"; ba=SecondNewer also
                // says "a newer" (b's view: the second arg wins).
                (Which::FirstNewer, Which::SecondNewer)
                | (Which::SecondNewer, Which::FirstNewer)
                | (Which::Identical, Which::Identical) => {}
                (Which::FirstNewer, x) => panic!("asymmetric: {ab:?} vs {x:?}"),
                (Which::SecondNewer, x) => panic!("asymmetric: {ab:?} vs {x:?}"),
                (Which::Identical, x) => panic!("asymmetric: {ab:?} vs {x:?}"),
            }
            // Transitivity of the "newer" relation.
            let bc = newer_than(&b, &c);
            let ac = newer_than(&a, &c);
            if ab == Which::FirstNewer && bc == Which::FirstNewer {
                assert_eq!(ac, Which::FirstNewer);
            }
            if ab == Which::SecondNewer && bc == Which::SecondNewer {
                assert_eq!(ac, Which::SecondNewer);
            }
        }
    }

    #[test]
    fn property_install_keeps_most_recent() {
        // Whatever order instances arrive in, the store holds one of
        // the instances not older than any it has seen.
        let mut rng = XorShift(0x2233_4455_6677_8899);
        for _ in 0..256 {
            let mut db = Lsdb::new();
            let mut best: Option<LsaHeader> = None;
            for i in 0..16 {
                let lsa = router_lsa(
                    (rng.next() % 100) as u32,
                    (rng.next() % 6) as u16,
                    (rng.next() % 2) as u16 * 5,
                );
                // Day-2: install normalizes the header (checksum/
                // length filled) — model the same truth here.
                let lsa = lsa.normalized();
                let hdr = lsa.header;
                let _ = i;
                db.install(lsa, true, 1000 + 10 * i); // spacing > MinLSArrival
                best = match best {
                    None => Some(hdr),
                    Some(b) => match newer_than(&hdr, &b) {
                        Which::FirstNewer => Some(hdr),
                        _ => Some(b),
                    },
                };
            }
            let stored = db.get(&router_lsa(0, 0, 0).key()).unwrap().lsa.header;
            let best = best.unwrap();
            assert_eq!(newer_than(&stored, &best), Which::Identical);
        }
    }

    // ---- §13.4 re-adoption ----------------------------------------

    fn originated_db(seq: u32) -> Lsdb {
        // One self-originated instance at `seq` (as Lsdb::originate
        // would have stamped it), tracking `seq + 1` next.
        let mut db = Lsdb::new();
        let mut lsa = router_lsa(seq, 0, 10).normalized();
        lsa.header.seq = seq;
        let _ = db.install(lsa, false, 0);
        // The self-seq tracking originate() maintains.
        db.self_seq
            .insert(router_lsa(0, 0, 0).key(), SeqState::Ready { next: seq + 1 });
        db
    }

    #[test]
    fn readopt_advances_one_past_a_newer_received_instance() {
        // §13.4: "the router must then advance the LSA's LS sequence
        // number one past the received LS sequence number" — a peer
        // still holding our pre-restart instance (seq 0x80000005)
        // while we restarted at InitialSequenceNumber.
        let mut db = originated_db(INITIAL_SEQUENCE_NUMBER);
        let received = router_lsa(0x8000_0005, 0, 10).normalized();
        assert_eq!(db.readopt_self_originated(&received), Readopt::Advanced);
        assert_eq!(
            db.next_seq_for(&received.key()),
            Some(0x8000_0006u32 as i32),
            "the next origination is one past the received instance"
        );
        // The re-origination that follows is accepted (MinLSInterval
        // aside — inject time past it).
        let mut fresh = router_lsa(0, 0, 10);
        fresh.header.seq = 0xdead_beef; // overwritten by originate
        let outcome = db.originate(fresh.normalized(), 10).unwrap();
        assert!(matches!(outcome, InstallOutcome::Installed { .. }));
        assert_eq!(
            db.get(&received.key()).unwrap().lsa.header.seq,
            0x8000_0006,
            "the re-originated instance carries the advanced sequence"
        );
    }

    #[test]
    fn readopt_is_a_noop_on_stale_or_equal_instances() {
        // Our tracking is at 0x80000006: the peer echoing our current
        // instance (0x80000005) or an older one changes nothing.
        let mut db = originated_db(0x8000_0005);
        for seq in [0x8000_0001, 0x8000_0004, 0x8000_0005] {
            let received = router_lsa(seq, 0, 10).normalized();
            assert_eq!(db.readopt_self_originated(&received), Readopt::Stale);
            assert_eq!(
                db.next_seq_for(&received.key()),
                Some(0x8000_0006u32 as i32)
            );
        }
    }

    #[test]
    fn readopt_at_max_sequence_number_takes_the_flush_path() {
        // §13.4 meets §12.1.6: nothing exists past MaxSequenceNumber,
        // so the tracking moves to flush-before-restart.
        let mut db = originated_db(0x7fff_fffd);
        let received = router_lsa(MAX_SEQUENCE_NUMBER, 0, 10).normalized();
        assert_eq!(db.readopt_self_originated(&received), Readopt::NeedsFlush);
        // Originating is refused while the old instance is stored
        // (the rollover guard); premature aging plus the §14 removal
        // (the daemon's flush_ready loop) unlock the restart.
        let mut fresh = router_lsa(0, 0, 10);
        fresh.header.seq = 0;
        assert!(db.originate(fresh.normalized(), 10).is_err());
        assert!(db.premature_age(&received.key()).is_some());
        db.remove(&received.key());
        let outcome = db.originate(fresh.normalized(), 10).unwrap();
        assert!(matches!(outcome, InstallOutcome::Installed { .. }));
        assert_eq!(
            db.get(&received.key()).unwrap().lsa.header.seq,
            INITIAL_SEQUENCE_NUMBER,
            "the sequence restarted at InitialSequenceNumber"
        );
    }

    #[test]
    fn mirror_originated_installs_and_tracks() {
        // §7's AS-scope mirroring: the identical type-5 instance
        // lands in another area's database with the sequence
        // tracking aligned (one origination, consistent instances).
        let mut db = Lsdb::new();
        let lsa = router_lsa(0x8000_0007, 0, 10)
            .normalized()
            .with_computed_header();
        db.mirror_originated(&lsa, 42);
        let key = lsa.key();
        assert_eq!(db.get(&key).unwrap().lsa.header.seq, 0x8000_0007);
        assert_eq!(db.next_seq_for(&key), Some(0x8000_0008u32 as i32));
        // The same instance mirrored again: no seq churn.
        db.mirror_originated(&lsa, 43);
        assert_eq!(db.get(&key).unwrap().lsa.header.seq, 0x8000_0007);
    }

    #[test]
    fn readopt_reports_not_ours_for_foreign_lsas() {
        // An LSA we do not originate (e.g. a summary we no longer
        // advertise, or a network-LSA after losing DR) — the §13.4
        // flush decision belongs to the caller's policy.
        let mut db = Lsdb::new();
        let foreign = router_lsa(0x8000_0009, 0, 10).normalized();
        assert_eq!(db.readopt_self_originated(&foreign), Readopt::NotOurs);
    }

    /// The AF-generic seam proof (S7-a): the SAME `Lsdb`
    /// implementation runs the v3 family — install with the §13.2
    /// contents-difference gate, newer-instance replacement with the
    /// MinLSArrival guard, §14 aging/refresh reporting — over
    /// `LsaV3` untouched.
    #[test]
    fn the_generic_lsdb_serves_the_v3_family() {
        use crate::lsa_v3::{
            LinkTypeV3, LsaBodyV3, LsaHeaderV3, LsaV3, Options24, RouterLinkV3, RouterLsaV3,
        };
        fn v3_router_lsa(seq: u32, metric: u16) -> LsaV3 {
            LsaV3 {
                header: LsaHeaderV3 {
                    ls_age: 0,
                    ls_type: LsaType::V3_ROUTER,
                    link_state_id: LinkStateId(0),
                    adv_router: RouterId(0x0a00_0009),
                    seq,
                    checksum: 0,
                    length: 0,
                },
                body: LsaBodyV3::Router(RouterLsaV3 {
                    nt_bit: false,
                    v_bit: false,
                    e_bit: true,
                    b_bit: false,
                    options: Options24(Options24::V6 | Options24::E),
                    links: vec![RouterLinkV3 {
                        link_type: LinkTypeV3::PointToPoint,
                        metric,
                        interface_id: 2,
                        neighbor_interface_id: 7,
                        neighbor_router_id: RouterId(0x0a00_0001),
                    }],
                }),
            }
        }
        let mut db: Lsdb<LsaV3> = Lsdb::new();
        // Origination stamps the sequence and normalizes the header.
        let outcome = db.originate(v3_router_lsa(0, 5), 0).unwrap();
        assert!(matches!(
            outcome,
            InstallOutcome::Installed { changed: true }
        ));
        let key = LsaKey {
            ls_type: LsaType::V3_ROUTER,
            link_state_id: LinkStateId(0),
            adv_router: RouterId(0x0a00_0009),
        };
        let stored = db.get(&key).unwrap();
        assert_eq!(stored.lsa.header.seq, INITIAL_SEQUENCE_NUMBER);
        assert_ne!(stored.lsa.header.checksum, 0, "normalized to wire form");
        assert_eq!(stored.lsa.header.length as usize, stored.lsa.encode().len());
        // A flood-installed instance one sequence up with a different
        // body: replaced, changed=true (§13.2's body difference).
        let outcome = db.install(v3_router_lsa(INITIAL_SEQUENCE_NUMBER + 1, 6), true, 10);
        assert!(matches!(
            outcome,
            InstallOutcome::Installed { changed: true }
        ));
        // The MinLSArrival guard (§13 step 5a): another flood
        // instance within the window is refused.
        let outcome = db.install(v3_router_lsa(INITIAL_SEQUENCE_NUMBER + 2, 7), true, 10);
        assert_eq!(outcome, InstallOutcome::RejectedMinLsArrival);
        // §12.4 refresh reporting + §14.1's DoNotAge-preserving
        // premature age. (The first aging tick only anchors the
        // clock — §14's injected-time convention.)
        db.tick_aging(10);
        let report = db.tick_aging(10 + LS_REFRESH_TIME as u64 + 5);
        assert!(report.refresh_due.contains(&key), "self-originated refresh");
        let aged = db.premature_age(&key).unwrap();
        assert!(aged.header.is_max_age());
        assert_eq!(aged.header.seq, INITIAL_SEQUENCE_NUMBER + 1, "seq kept");
    }
}
