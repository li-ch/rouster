//! ASPA object model and AS_PATH verification.
//!
//! Model per draft-ietf-sidrops-aspa-verification-28 (the
//! RFC 8416/9234-era SIDROPS work; version fetched 2026-10-10, still a
//! draft — everything here cites the section that pins it):
//!
//! - an ASPA maps a customer AS (CAS) to its union of provider ASes
//!   (U-SPAS, §5.3). Over RTR v2 the wire carries the whole provider
//!   set in one ASPA PDU per CAS and a new announcement replaces the
//!   previous one (8210bis-27 §5.12); an empty provider set ("this AS
//!   has no providers", expressible in the object model, e.g. an AS0
//!   ASPA arrives as `{0}`) means *Not Provider+* for every peer.
//! - `authorized(x, y)` (§5.3) returns **No Attestation** when x has
//!   no U-SPAS entry, **Provider+** when y is in it, else
//!   **Not Provider+**.
//! - Verification (§5.2–§5.6) walks the COMPRESSED_AS_PATH (§5.2:
//!   consecutive duplicates removed; AS(1) is the origin, AS(N) the
//!   most recently added AS) in terms of an up-ramp from AS(1) and a
//!   down-ramp from AS(N); §5.4 bounds each ramp from the authorization
//!   outcomes, and §5.5/§5.6 turn the bounds into Valid/Invalid/Unknown
//!   for routes from customers/peers/RS (upstream) vs providers
//!   (downstream).

use std::collections::{BTreeMap, BTreeSet};

use crate::pdu::PayloadFlags;

/// One CAS → provider-set mapping (the U-SPAS view, §5.3).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Aspa {
    pub customer_asn: u32,
    pub providers: BTreeSet<u32>,
}

/// Session-layer outcomes of applying an ASPA PDU; the caller turns
/// these into RTR error codes 7/6 (8210bis-27 §12).
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum AspaTableError {
    #[error("duplicate ASPA announcement for AS {0} (error code 7)")]
    DuplicateAnnouncement(u32),
    #[error("withdrawal of unknown ASPA for AS {0} (error code 6)")]
    UnknownWithdrawal(u32),
}

/// The ASPA table: customer ASN → U-SPAS. A plain map is the whole
/// state — §5.3's U-SPAS union is already folded by the cache (one
/// PDU per CAS, 8210bis-27 §5.12).
#[derive(Debug, Default, Clone)]
pub struct AspaTable {
    map: BTreeMap<u32, BTreeSet<u32>>,
}

impl AspaTable {
    pub fn new() -> Self {
        AspaTable {
            map: BTreeMap::new(),
        }
    }

    /// Apply an ASPA PDU (8210bis-27 §5.12): an announcement replaces
    /// the previous record for the CAS — unless it is byte-for-byte
    /// the same provider set, which is the duplicate-announcement
    /// error; a withdrawal removes the whole record.
    pub fn apply(
        &mut self,
        customer_asn: u32,
        flags: PayloadFlags,
        providers: BTreeSet<u32>,
    ) -> Result<Option<BTreeSet<u32>>, AspaTableError> {
        if flags.announce {
            match self.map.insert(customer_asn, providers.clone()) {
                Some(old) if old == providers => {
                    // Restore: the insert above was a no-op value-wise.
                    self.map.insert(customer_asn, old.clone());
                    Err(AspaTableError::DuplicateAnnouncement(customer_asn))
                }
                old => Ok(old),
            }
        } else {
            match self.map.remove(&customer_asn) {
                Some(old) => Ok(Some(old)),
                None => Err(AspaTableError::UnknownWithdrawal(customer_asn)),
            }
        }
    }

    /// Drop everything (session restart / fatal error / expiry).
    pub fn clear(&mut self) {
        self.map.clear();
    }

    /// The U-SPAS entry for a customer AS, if any (None ⇒ No
    /// Attestation).
    pub fn get(&self, customer_asn: u32) -> Option<&BTreeSet<u32>> {
        self.map.get(&customer_asn)
    }

    pub fn len(&self) -> usize {
        self.map.len()
    }

    pub fn is_empty(&self) -> bool {
        self.map.len() == 0
    }

    pub fn iter(&self) -> impl Iterator<Item = Aspa> + '_ {
        self.map.iter().map(|(cas, set)| Aspa {
            customer_asn: *cas,
            providers: set.clone(),
        })
    }
}

/// §5.3's provider authorization function.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Authorization {
    /// No U-SPAS entry for the customer AS (or none cryptographically
    /// valid — over RTR that distinction lives in the cache).
    NoAttestation,
    /// AS y is an attested Provider (or non-transparent RS) of AS x.
    ProviderPlus,
    /// x has an attestation and y is not in it.
    NotProviderPlus,
}

/// `authorized(AS x, AS y)` per §5.3 Figure 2.
pub fn authorized(table: &AspaTable, x: u32, y: u32) -> Authorization {
    match table.get(x) {
        None => Authorization::NoAttestation,
        Some(spas) => {
            if spas.contains(&y) {
                Authorization::ProviderPlus
            } else {
                Authorization::NotProviderPlus
            }
        }
    }
}

/// One AS_PATH segment (RFC 4271 §4.3). Only AS_SEQUENCE carries
/// verifiable hop structure; any AS_SET makes the path Invalid per
/// verification-28 §5.5 step 3 (and RFC 9774's treat-as-withdraw
/// prerequisite).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PathSegment {
    AsSequence(Vec<u32>),
    AsSet(Vec<u32>),
}

/// An AS_PATH as received. `segments[0]` is the leftmost (most
/// recently added) segment; the origin is the rightmost AS of the
/// final segment when that segment is an AS_SEQUENCE.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct AsPath {
    pub segments: Vec<PathSegment>,
}

impl AsPath {
    /// A plain AS_SEQUENCE path, leftmost-first (e.g. `[64500, 64501]`
    /// = learned from 64500, originated by 64501).
    pub fn sequence(asns: Vec<u32>) -> Self {
        AsPath {
            segments: vec![PathSegment::AsSequence(asns)],
        }
    }

    /// §5.2's COMPRESSED_AS_PATH: consecutive duplicate ASNs removed,
    /// left-to-right order preserved (index 0 = AS(N), last = AS(1) the
    /// origin). `None` when any segment is an AS_SET (§5.5 step 3).
    pub fn compressed(&self) -> Option<Vec<u32>> {
        let mut out: Vec<u32> = Vec::new();
        for seg in &self.segments {
            match seg {
                PathSegment::AsSequence(asns) => {
                    for &asn in asns {
                        if out.last() != Some(&asn) {
                            out.push(asn);
                        }
                    }
                }
                PathSegment::AsSet(_) => return None,
            }
        }
        Some(out)
    }

    /// The origin ASN per RFC 6811 §2 ("rightmost AS in the final
    /// segment ... if that segment is of type AS_SEQUENCE"); `None`
    /// stands for that document's "NONE".
    pub fn origin(&self) -> Option<u32> {
        match self.segments.last() {
            Some(PathSegment::AsSequence(asns)) => asns.last().copied(),
            _ => None,
        }
    }
}

/// How the route was received, selecting the §5.5 or §5.6 procedure
/// (§6.3: RFC 9234 BGP roles map onto this).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PeerRelation {
    /// Use the upstream procedure, strict neighbor-AS check (§5.5).
    Customer,
    /// Use the upstream procedure, strict neighbor-AS check (§5.5).
    Peer,
    /// Use the downstream procedure (§5.6).
    Provider,
    /// RS-client receiving from an RS: upstream procedure with the
    /// §5.5 step-2 neighbor-check exception (a transparent RS does not
    /// prepend its AS).
    RsClient,
}

/// §5.5/§5.6 outcomes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AspaValidity {
    Valid,
    Invalid,
    Unknown,
}

impl AspaValidity {
    pub fn as_str(self) -> &'static str {
        match self {
            AspaValidity::Valid => "Valid",
            AspaValidity::Invalid => "Invalid",
            AspaValidity::Unknown => "Unknown",
        }
    }
}

/// Ramp bounds per §5.4, computed over `path` given origin-first (A(1)
/// ..= A(N)); `path` is the COMPRESSED_AS_PATH reversed so that
/// `path[i-1] == A(i)`.
struct RampBounds {
    max_up: usize,
    min_up: usize,
    max_down: usize,
    min_down: usize,
}

fn ramp_bounds(table: &AspaTable, a: &[u32]) -> RampBounds {
    let n = a.len();
    // Up-ramp hops: A(i) -> A(i+1), i in 1..=N-1 (customer to
    // provider). max_up_ramp: minimum I with "Not Provider+";
    // min_up_ramp: minimum I with "No Attestation" or "Not Provider+".
    let mut max_up = n;
    let mut min_up = n;
    for i in 1..n {
        match authorized(table, a[i - 1], a[i]) {
            // authorized(A(i), A(i+1))
            Authorization::NotProviderPlus => {
                max_up = i;
                min_up = i;
                break;
            }
            Authorization::NoAttestation => min_up = min_up.min(i),
            Authorization::ProviderPlus => {}
        }
    }
    // Down-ramp hops: A(j) -> A(j-1), j in 2..=N. Both bounds use "J
    // the maximum index", i.e. scan from the top of the path
    // downward: max_down_ramp takes the topmost "Not Provider+",
    // min_down_ramp the topmost non-"Provider+" (of either class).
    let mut max_down = n;
    for j in (2..=n).rev() {
        if authorized(table, a[j - 1], a[j - 2]) == Authorization::NotProviderPlus {
            max_down = n - j + 1;
            break;
        }
    }
    let mut min_down = n;
    for j in (2..=n).rev() {
        if authorized(table, a[j - 1], a[j - 2]) != Authorization::ProviderPlus {
            min_down = n - j + 1;
            break;
        }
    }
    RampBounds {
        max_up,
        min_up,
        max_down,
        min_down,
    }
}

/// §5.5, upstream paths (received from a Customer or Peer, or by an RS
/// from an RS-client, or by an RS-client from an RS). `neighbor_asn`
/// is `None` exactly in the RS-client-from-transparent-RS case that
/// §5.5 step 2 exempts from the neighbor check.
pub fn verify_upstream(
    table: &AspaTable,
    path: &AsPath,
    neighbor_asn: Option<u32>,
) -> AspaValidity {
    // Step 3 first, so a set-carrying path is Invalid even when it
    // would also fail step 2 (both halt Invalid; order is unobservable,
    // but the compressed path is needed for every later step).
    let Some(flat) = path.compressed() else {
        return AspaValidity::Invalid;
    };
    // Step 1: empty AS_PATH.
    if flat.is_empty() {
        return AspaValidity::Invalid;
    }
    // Step 2: most recently added AS must be the neighbor (unless the
    // receiver is an RS-client behind a transparent RS).
    if let Some(neighbor) = neighbor_asn {
        if flat[0] != neighbor {
            return AspaValidity::Invalid;
        }
    }
    let n = flat.len();
    let mut a: Vec<u32> = flat.into_iter().rev().collect(); // A(1)..A(N)
    let bounds = ramp_bounds(table, &a);
    a.clear();
    // Steps 4-6 with max/min_down_ramp pinned to 0 (the path must be
    // a pure up-ramp).
    if bounds.max_up < n {
        AspaValidity::Invalid
    } else if bounds.min_up < n {
        AspaValidity::Unknown
    } else {
        AspaValidity::Valid
    }
}

/// §5.6, downstream paths (received from a Provider). The neighbor
/// check is always strict here.
pub fn verify_downstream(table: &AspaTable, path: &AsPath, neighbor_asn: u32) -> AspaValidity {
    let Some(flat) = path.compressed() else {
        return AspaValidity::Invalid;
    };
    if flat.is_empty() {
        return AspaValidity::Invalid;
    }
    if flat[0] != neighbor_asn {
        return AspaValidity::Invalid;
    }
    let n = flat.len();
    let a: Vec<u32> = flat.into_iter().rev().collect();
    let bounds = ramp_bounds(table, &a);
    if bounds.max_up + bounds.max_down < n {
        AspaValidity::Invalid
    } else if bounds.min_up + bounds.min_down < n {
        AspaValidity::Unknown
    } else {
        AspaValidity::Valid
    }
}

/// Select the procedure by peering relationship (§6.3: map RFC 9234
/// roles onto this). `neighbor_asn` follows the upstream rule above.
pub fn verify(
    table: &AspaTable,
    path: &AsPath,
    neighbor_asn: Option<u32>,
    relation: PeerRelation,
) -> AspaValidity {
    match relation {
        PeerRelation::Provider => {
            match neighbor_asn {
                Some(n) => verify_downstream(table, path, n),
                None => AspaValidity::Invalid, // no neighbor to check against
            }
        }
        PeerRelation::RsClient => verify_upstream(table, path, None),
        PeerRelation::Customer | PeerRelation::Peer => match neighbor_asn {
            Some(n) => verify_upstream(table, path, Some(n)),
            None => AspaValidity::Invalid,
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn table(entries: &[(u32, &[u32])]) -> AspaTable {
        let mut t = AspaTable::new();
        for (cas, providers) in entries {
            t.apply(
                *cas,
                PayloadFlags::ANNOUNCE,
                providers.iter().copied().collect(),
            )
            .unwrap();
        }
        t
    }

    // ---- The §6.1-style lattice (hand-built shapes, §-cited). ------

    #[test]
    fn single_as_origin_from_customer_is_valid() {
        // §5.5 with N=1: no hops, max_up_ramp = min_up_ramp = 1 = N.
        let t = table(&[]);
        let path = AsPath::sequence(vec![64501]);
        assert_eq!(
            verify_upstream(&t, &path, Some(64501)),
            AspaValidity::Valid
        );
        assert_eq!(
            verify(&t, &path, Some(64501), PeerRelation::Customer),
            AspaValidity::Valid
        );
    }

    #[test]
    fn clean_customer_chain_from_customer_is_valid() {
        // 64501's provider is 64502; received from customer 64502.
        let t = table(&[(64501, &[64502])]);
        let path = AsPath::sequence(vec![64502, 64501]);
        assert_eq!(
            verify_upstream(&t, &path, Some(64502)),
            AspaValidity::Valid
        );
    }

    #[test]
    fn customer_route_via_unattested_provider_is_unknown() {
        // Same path but 64501 has no ASPA: hop 1 is No Attestation ⇒
        // min_up_ramp 1 < N ⇒ Unknown (§5.5 step 5).
        let t = table(&[]);
        let path = AsPath::sequence(vec![64502, 64501]);
        assert_eq!(
            verify_upstream(&t, &path, Some(64502)),
            AspaValidity::Unknown
        );
    }

    #[test]
    fn upstream_leak_is_invalid() {
        // 64503 learned from a peer (not its provider) and passed the
        // route downstream; the customer sees [64503, 64502, 64501]
        // where 64502 ∈ SPAS(64501) but 64503 ∉ SPAS(64502) (its
        // attested provider is 64500). max_up_ramp 2 < 3 ⇒ Invalid
        // (§5.5 step 4).
        let t = table(&[(64501, &[64502]), (64502, &[64500])]);
        let path = AsPath::sequence(vec![64503, 64502, 64501]);
        assert_eq!(
            verify_upstream(&t, &path, Some(64503)),
            AspaValidity::Invalid
        );
    }

    #[test]
    fn leak_beyond_no_attestation_is_still_invalid() {
        // The Not Provider+ hop outranks later unknowns: max_up_ramp
        // is pinned by the first attested mismatch even when hops
        // further up are No Attestation (§5.4).
        let t = table(&[(64501, &[64502])]); // 64502, 64503 unattested
        let path = AsPath::sequence(vec![64504, 64503, 64502, 64501]);
        // hops: 1→2 Provider+, 2→3 No Attestation, 3→4 No Attestation:
        // max_up = 4 (nothing is Not Provider+) — Unknown, not Invalid.
        assert_eq!(
            verify_upstream(&t, &path, Some(64504)),
            AspaValidity::Unknown
        );
        // Now 64503 attests 64505 as provider: hop 3→4 becomes Not
        // Provider+ ⇒ max_up = 3 < 4 ⇒ Invalid.
        let t = table(&[(64501, &[64502]), (64502, &[64503]), (64503, &[64505])]);
        assert_eq!(
            verify_upstream(&t, &path, Some(64504)),
            AspaValidity::Invalid
        );
    }

    #[test]
    fn downstream_clean_path_is_valid() {
        // Verifier 64505 buys transit from 64504; 64504 from 64503;
        // 64503 from 64502; route originated by 64501 whose provider
        // is 64502. Received from provider 64504: the up-ramp runs
        // 64501→64502→64503→64504 (all attested), so N=4 equals
        // max_up_ramp ⇒ Valid (§5.6 step 6; the down-ramp is moot).
        let t = table(&[
            (64501, &[64502]),
            (64502, &[64503]),
            (64503, &[64504]),
            (64504, &[64505]),
        ]);
        let path = AsPath::sequence(vec![64504, 64503, 64502, 64501]);
        assert_eq!(
            verify_downstream(&t, &path, 64504),
            AspaValidity::Valid
        );
    }

    #[test]
    fn downstream_leak_is_invalid() {
        // Provider 64504 hands us [64504, 64505, 64501]: 64505 is
        // provably not 64504's provider (its attested provider is
        // 64599), not 64501's either (64502 is). Up-ramp: hop 1→2 Not
        // Provider+ ⇒ max_up_ramp 1. Down-ramp from AS(3): hop (3→2)
        // is Not Provider+ ⇒ max_down_ramp 1. 1 + 1 < 3 ⇒ Invalid
        // (§5.6 step 4) — no tiling of the path into ramps exists.
        let t = table(&[(64501, &[64502]), (64504, &[64599]), (64505, &[64506])]);
        let path = AsPath::sequence(vec![64504, 64505, 64501]);
        assert_eq!(
            verify_downstream(&t, &path, 64504),
            AspaValidity::Invalid
        );
        // The same path seen upstream (from peer 64504) is also
        // Invalid — max_up_ramp 1 < 3.
        assert_eq!(
            verify_upstream(&t, &path, Some(64504)),
            AspaValidity::Invalid
        );
    }

    #[test]
    fn downstream_ambiguous_lean_is_unknown() {
        // Path [64504, 64503, 64501] from provider 64504: hop 1→2 (is
        // 64503 a provider of 64501?) has no attestation; hop 2→3 (is
        // 64504 a provider of 64503?) has none either. max ramps = N
        // (no Not Provider+), min ramps = 1 + 2 < 3 ⇒ Unknown (§5.6
        // step 5).
        let t = table(&[]);
        let path = AsPath::sequence(vec![64504, 64503, 64501]);
        assert_eq!(
            verify_downstream(&t, &path, 64504),
            AspaValidity::Unknown
        );
    }

    #[test]
    fn downstream_dual_provider_path_resolves_valid() {
        // 64501 lists both 64502 and 64503 as providers (dual-homed);
        // the verifier buys transit from 64503. Path [64503, 64502,
        // 64501]: up-ramp hop 1→2 is Provider+ (64502 ∈ SPAS(64501)),
        // hop 2→3 (64503 a provider of 64502?) No Attestation ⇒
        // min_up 2. Down-ramp hop (3→2): authorized(64503, 64502) —
        // no attestation ⇒ min_down 1. 2 + 1 ≥ 3 and max_up + max_down
        // = 6 ≥ 3 ⇒ Valid.
        let t = table(&[(64501, &[64502, 64503])]);
        let path = AsPath::sequence(vec![64503, 64502, 64501]);
        assert_eq!(
            verify_downstream(&t, &path, 64503),
            AspaValidity::Valid
        );
        // The mirrored path [64502, 64503, 64501] from the other
        // provider is Valid by the same derivation — dual-homed
        // origination is reachable through either provider.
        let path = AsPath::sequence(vec![64502, 64503, 64501]);
        assert_eq!(
            verify_downstream(&t, &path, 64502),
            AspaValidity::Valid
        );
    }

    // ---- §5.5 prerequisite steps. ----------------------------------

    #[test]
    fn empty_path_is_invalid_both_directions() {
        let t = table(&[]);
        let empty = AsPath::default();
        assert_eq!(
            verify_upstream(&t, &empty, Some(1)),
            AspaValidity::Invalid
        );
        assert_eq!(
            verify_downstream(&t, &empty, 1),
            AspaValidity::Invalid
        );
        // An AS_SEQUENCE([]) segment is still an empty path.
        let hollow = AsPath::sequence(vec![]);
        assert_eq!(
            verify_upstream(&t, &hollow, Some(1)),
            AspaValidity::Invalid
        );
    }

    #[test]
    fn neighbor_mismatch_is_invalid() {
        // §5.5 step 2 / §5.6 step 2.
        let t = table(&[(64501, &[64502])]);
        let path = AsPath::sequence(vec![64502, 64501]);
        assert_eq!(
            verify_upstream(&t, &path, Some(64599)),
            AspaValidity::Invalid
        );
        assert_eq!(
            verify_downstream(&t, &path, 64599),
            AspaValidity::Invalid
        );
        // RS-client exemption (§5.5 step 2's "not an RS-client"): the
        // transparent RS did not prepend, so no neighbor is checkable.
        assert_eq!(
            verify(&t, &path, None, PeerRelation::RsClient),
            AspaValidity::Valid
        );
    }

    #[test]
    fn as_set_path_is_invalid() {
        // §5.5/§5.6 step 3 (and RFC 9774's prerequisite).
        let t = table(&[(64501, &[64502])]);
        let path = AsPath {
            segments: vec![PathSegment::AsSequence(vec![64502]), PathSegment::AsSet(vec![64501])],
        };
        assert_eq!(
            verify_upstream(&t, &path, Some(64502)),
            AspaValidity::Invalid
        );
        assert_eq!(
            verify_downstream(&t, &path, 64502),
            AspaValidity::Invalid
        );
    }

    #[test]
    fn consecutive_duplicates_are_compressed() {
        // §5.2: prepends collapse before ramp math. Without
        // compression the neighbor check would see [64502, 64502,
        // 64501] and ... it would still pass; the ramp bound is the
        // observable: with 64502 ∉ SPAS(64501) but the duplicate hop
        // 64502→64502 being Provider+-irrelevant, compression decides
        // Valid vs Unknown.
        let t = table(&[(64502, &[64503])]);
        let path = AsPath::sequence(vec![64502, 64502, 64502, 64501]);
        // Compressed: [64502, 64501]; hop 1→2: no attestation for
        // 64501 ⇒ Unknown.
        assert_eq!(
            verify_upstream(&t, &path, Some(64502)),
            AspaValidity::Unknown
        );
        // With the attestation present it is Valid — N=2 either way.
        let t = table(&[(64501, &[64502]), (64502, &[64503])]);
        assert_eq!(
            verify_upstream(&t, &path, Some(64502)),
            AspaValidity::Valid
        );
        assert_eq!(path.compressed().unwrap(), vec![64502, 64501]);
        // RFC 6811 origin extraction: rightmost AS of final segment.
        assert_eq!(path.origin(), Some(64501));
    }

    #[test]
    fn as0_aspa_blocks_every_hop_out() {
        // §4: an AS0 ASPA says "no transit providers, not an
        // RS-client" — authorized(x, y) is Not Provider+ for every y.
        let t = table(&[(64501, &[0])]);
        let path = AsPath::sequence(vec![64502, 64501]);
        assert_eq!(
            authorized(&t, 64501, 64502),
            Authorization::NotProviderPlus
        );
        assert_eq!(
            verify_upstream(&t, &path, Some(64502)),
            AspaValidity::Invalid
        );
        // ...but an AS0 entry mixed into a real provider list has "no
        // influence" (§4): the real provider still attests.
        let t = table(&[(64501, &[0, 64502])]);
        assert_eq!(
            authorized(&t, 64501, 64502),
            Authorization::ProviderPlus
        );
        assert_eq!(
            verify_upstream(&t, &path, Some(64502)),
            AspaValidity::Valid
        );
    }

    #[test]
    fn relation_selects_the_procedure() {
        let t = table(&[(64501, &[64502])]);
        let path = AsPath::sequence(vec![64502, 64501]);
        for rel in [PeerRelation::Customer, PeerRelation::Peer] {
            assert_eq!(
                verify(&t, &path, Some(64502), rel),
                AspaValidity::Valid,
                "{rel:?}"
            );
        }
        // From a provider the same clean path is Valid too (pure
        // up-ramp, §5.6).
        assert_eq!(
            verify(&t, &path, Some(64502), PeerRelation::Provider),
            AspaValidity::Valid
        );
    }

    // ---- Table mechanics. ------------------------------------------

    #[test]
    fn aspa_announcement_replaces_previous() {
        // 8210bis-27 §5.12: a new announcement for the same CAS
        // replaces the previous record.
        let mut t = AspaTable::new();
        t.apply(64501, PayloadFlags::ANNOUNCE, BTreeSet::from([64502]))
            .unwrap();
        let old = t.apply(64501, PayloadFlags::ANNOUNCE, BTreeSet::from([64503, 64504]));
        assert_eq!(old.unwrap(), Some(BTreeSet::from([64502])));
        assert_eq!(t.get(64501), Some(&BTreeSet::from([64503, 64504])));
        // Byte-identical repeat is the error-code-7 duplicate.
        assert_eq!(
            t.apply(64501, PayloadFlags::ANNOUNCE, BTreeSet::from([64503, 64504])),
            Err(AspaTableError::DuplicateAnnouncement(64501))
        );
        // Withdrawal removes the record; repeating it is error 6.
        assert_eq!(
            t.apply(64501, PayloadFlags::WITHDRAW, BTreeSet::new())
                .unwrap(),
            Some(BTreeSet::from([64503, 64504]))
        );
        assert_eq!(
            t.apply(64501, PayloadFlags::WITHDRAW, BTreeSet::new()),
            Err(AspaTableError::UnknownWithdrawal(64501))
        );
        assert!(t.is_empty());
    }

    #[test]
    fn empty_provider_set_means_no_providers() {
        // The object model can say "no providers at all" (the RTR wire
        // cannot: announcements need ≥1 provider — pdu tests pin
        // that); every authorized() is then Not Provider+.
        let mut t = AspaTable::new();
        t.apply(64501, PayloadFlags::ANNOUNCE, BTreeSet::new())
            .unwrap();
        assert_eq!(
            authorized(&t, 64501, 64502),
            Authorization::NotProviderPlus
        );
        assert_eq!(
            authorized(&t, 64599, 64502),
            Authorization::NoAttestation
        );
    }

    #[test]
    fn iteration_is_deterministic() {
        let t = table(&[(64502, &[64503]), (64501, &[64502, 64503])]);
        let cas: Vec<u32> = t.iter().map(|a| a.customer_asn).collect();
        assert_eq!(cas, vec![64501, 64502]);
        let providers: Vec<Vec<u32>> = t.iter().map(|a| a.providers.iter().copied().collect()).collect();
        assert_eq!(providers, vec![vec![64502, 64503], vec![64503]]);
    }
}
