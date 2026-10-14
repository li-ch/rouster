//! BAR-SAV: per-interface permissible source-prefix allowlists from
//! BGP UPDATE AS_PATHs + ASPA + ROA.
//!
//! Implemented against **draft-ietf-sidrops-bar-sav-10** (Sriram,
//! Lubashev, Montgomery; published 2026-07-19, expires 2027-01-20 —
//! the pinned revision; a local copy lives at
//! `away/2026-10-14/quarantine/barsav/bar-sav-10.txt`). All step
//! citations below ("§4 Step 5", "§8 Step 3") point at that revision.
//!
//! What this module implements, exactly:
//!
//! - **§4 (BAR-SAV)** — the customer/lateral-peer interface
//!   procedure: the iterative customer-cone expansion over ASPA data
//!   (Steps 5-6) AND unique AS_PATHs from Adj-RIBs-In of all
//!   interfaces (Step 7 — the draft's preamble is explicit that the
//!   two sources must interleave, not merge), then the prefix sets
//!   Q1 (ROA-authorized, Step 11) and Q2 (BGP-originated, Step 12)
//!   whose union with the interface's Prefix ACL is the permissible
//!   list (Step 13). §2: the SAME procedure serves customer and
//!   lateral-peer interfaces ("the CC includes the AS belonging to
//!   the customer or lateral peer").
//! - **§8 (BAR-SAV-PI)** — the provider-interface procedure: S (the
//!   cone-exclusive prefix set, Steps 1-5) subtracted from the
//!   loose-uRPF allowed set (Step 6), then the local-AS exemptions
//!   (Step 7) — G is the provider allowlist (Step 8).
//! - **§4's security preamble** — only paths that are NOT
//!   RPKI-ROV Invalid (RFC 6811 §2) and NOT AS_PATH-verification
//!   Invalid (draft-ietf-sidrops-aspa-verification §5.5/§5.6, the
//!   procedure selected by the receiving interface's role) feed
//!   Steps 7 and 12.
//!
//! What feeds it (the M3 edge): bgpd's read-only Adj-RIB-In snapshot
//! (the `barsav feed` file — see [`parse_barsav_feed`]) plus an RPKI
//! snapshot in bgpd's `vrp-file` format (see
//! [`parse_rpki_snapshot`]; format-identical to bgpd's
//! `parse_vrp_file` so one file serves both daemons).
//!
//! House rules honored here (repo AGENTS.md SAVNET rules, binding):
//! **monitor before drop** (the derivation only produces typed
//! [`SavRule`]s; the action they compile with is data elsewhere,
//! Monitor by default) and **unknown ≠ invalid** (an interface with
//! no derivation result produces no rule, so its traffic is
//! *unjudged* — never spoof-flagged). BAR-SAV sits BELOW SAVNET in
//! priority and never behind `experimental-savnet`: it derives from
//! chartered-RFC data (ROA/ASPA) plus the local BGP speaker's own
//! Adj-RIBs-In — there is no draft-dependent wire protocol in it.
//!
//! Pure: no I/O, no clock, no dataplane. Everything is plain data in,
//! [`BarsavDerivation`] out; determinism is a property (BTree-backed
//! sets throughout, same input ⇒ byte-identical output).

use std::collections::BTreeSet;
use std::fmt;
use std::net::IpAddr;

use common::IpPrefix;
use rpki::{
    AspaTable, AspaValidity, OriginAsn, PayloadFlags, PeerRelation, Validity, Vrp, VrpTable,
};

use crate::gen::{RuleOrigin, RuleSet, SavRule};
use crate::InterfaceRef;

// ---- Input types ------------------------------------------------------

/// The role of one BAR-SAV-configured interface's neighbor. §2 runs
/// the same §4 procedure for [`Customer`] and [`LateralPeer`]; §8 is
/// the provider-interface procedure. The names follow §1.1 of RFC
/// 8704 (which BAR-SAV builds on) and RFC 9234 §4's BGP roles — the
/// same triple bgpd's `neighbor <ip> role` knob carries.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum BarRole {
    /// Provider-to-customer link: the neighbor buys transit from us.
    Customer,
    /// Lateral (non-transit) peer: P2P, §2's second subject.
    LateralPeer,
    /// Transit provider: §8's subject (BAR-SAV-PI).
    Provider,
}

impl BarRole {
    /// Parse the config token (`role <customer|peer|provider>`).
    pub fn parse(token: &str) -> Option<Self> {
        match token {
            "customer" => Some(BarRole::Customer),
            "peer" => Some(BarRole::LateralPeer),
            "provider" => Some(BarRole::Provider),
            _ => None,
        }
    }
}

impl fmt::Display for BarRole {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            BarRole::Customer => "customer",
            BarRole::LateralPeer => "peer",
            BarRole::Provider => "provider",
        })
    }
}

/// One BAR-SAV-configured neighbor: the interface (`ifindex`), its
/// AS-k (§4 Step 1: "the Customer or Lateral Peer ASN"), the role,
/// and the two per-interface ACLs the draft names (§4 Steps 3 and 13
/// — the operator's manual additions to the discovered sets).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BarNeighbor {
    /// The interface the neighbor connects through.
    pub ifindex: u32,
    /// AS-k, the neighbor's own ASN.
    pub asn: u32,
    /// The neighbor's role.
    pub role: BarRole,
    /// §4 Step 3: "Extend AS-set Z(1) to include ASNs from any ASN
    /// ACL configured for the interface."
    pub asn_acl: Vec<u32>,
    /// §4 Step 13: "… and any Prefix ACL configured for this
    /// interface" joins the permissible set.
    pub prefix_acl: Vec<IpPrefix>,
}

impl BarNeighbor {
    /// A neighbor with no ACLs (the common shape).
    pub fn new(ifindex: u32, asn: u32, role: BarRole) -> Self {
        Self {
            ifindex,
            asn,
            role,
            asn_acl: Vec::new(),
            prefix_acl: Vec::new(),
        }
    }
}

/// One BGP-learned path as the derivation consumes it: §4 Step 7/12's
/// "unique AS_PATHs in Adj-RIBs-In of all interfaces". `as_path` is
/// wire order — element 0 is the most recently added AS (the
/// neighbor side), the last element the origin (RFC 4271 §4.3; the
/// same order `rpki::AsPath::sequence` carries). A path containing
/// any AS_SET is carried with [`BarPath::has_as_set`] set — the
/// ASPA-verification §5.5 step 3 verdict for such a path is Invalid,
/// so the derivation excludes it (the flag keeps the feed honest
/// without flattening a set into fake sequence data).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BarPath {
    /// The announced prefix.
    pub prefix: IpPrefix,
    /// The path, wire order (neighbor side first).
    pub as_path: Vec<u32>,
    /// True when the original AS_PATH contained an AS_SET anywhere.
    pub has_as_set: bool,
    /// The receiving interface (kernel ifindex).
    pub ingress: u32,
}

impl BarPath {
    /// A clean AS_SEQUENCE path.
    pub fn sequence(prefix: &str, ingress: u32, asns: &[u32]) -> Self {
        Self {
            prefix: prefix.parse().expect("static prefix parses"),
            as_path: asns.to_vec(),
            has_as_set: false,
            ingress,
        }
    }

    /// The origin ASN per RFC 6811 §2 (rightmost element of a pure
    /// sequence; `None` mirrors that document's NONE for sets).
    fn origin(&self) -> OriginAsn {
        if self.has_as_set {
            OriginAsn::None
        } else {
            self.as_path
                .last()
                .map(|&asn| OriginAsn::As(asn))
                .unwrap_or(OriginAsn::None)
        }
    }
}

/// Everything one derivation run consumes. Borrowed throughout — the
/// caller (a test, or savd's evaluate) owns the mirrors.
#[derive(Debug)]
pub struct BarsavInput<'a> {
    /// The local AS (loop-rejected paths never reach the Adj-RIBs-In,
    /// §9.5 — and the derivation additionally refuses to place the
    /// local AS in any cone: a safety addendum beyond the draft text,
    /// disclosed).
    pub local_as: u32,
    /// The BAR-SAV-configured neighbors (one per interface; the
    /// derivation runs per entry).
    pub neighbors: &'a [BarNeighbor],
    /// The BGP speaker's Adj-RIBs-In, all interfaces (§4 Steps 7/12;
    /// §8 Steps 3/5).
    pub paths: &'a [BarPath],
    /// The ROA view (§4 Step 11's Q1; the ROV gate of §4's preamble;
    /// §8 Step 4).
    pub vrps: &'a VrpTable,
    /// The ASPA view (§4 Step 5's A(i); the AS_PATH gate of §4's
    /// preamble; §8 Step 5).
    pub aspas: &'a AspaTable,
    /// §8 Step 7's exemptions: "(a) any prefixes originated by the
    /// local AS that are single-homed, (b) any internal-use-only
    /// prefixes of the local AS, and (c) any prefixes known to the
    /// local AS to be single-homed to its customer cone" — operator
    /// knowledge, carried as config.
    pub provider_exempt: &'a [IpPrefix],
}

impl<'a> BarsavInput<'a> {
    /// An input over borrowed views with no exemptions.
    pub fn new(
        local_as: u32,
        neighbors: &'a [BarNeighbor],
        paths: &'a [BarPath],
        vrps: &'a VrpTable,
        aspas: &'a AspaTable,
    ) -> Self {
        Self {
            local_as,
            neighbors,
            paths,
            vrps,
            aspas,
            provider_exempt: &[],
        }
    }

    fn neighbor_on(&self, ifindex: u32) -> Option<&BarNeighbor> {
        self.neighbors.iter().find(|n| n.ifindex == ifindex)
    }
}

// ---- Result types -----------------------------------------------------

/// §4's outcome for one customer/lateral-peer interface.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CustomerResult {
    /// The interface the allowlist gates.
    pub ifindex: u32,
    /// AS-k.
    pub asn: u32,
    /// Customer or lateral peer (§2: same procedure).
    pub role: BarRole,
    /// AS-set D (Step 10): the neighbor's customer cone, sorted.
    pub cone: Vec<u32>,
    /// Pfx-set Q1 (Step 11): prefixes ROA-authorized for cone ASes.
    pub q_roa: Vec<IpPrefix>,
    /// Pfx-set Q2 (Step 12): prefixes the Adj-RIBs-In show cone ASes
    /// originating.
    pub q_bgp: Vec<IpPrefix>,
    /// Pfx-set Q (Step 13) — the permissible prefix list for SAV on
    /// this interface.
    pub allowlist: Vec<IpPrefix>,
}

/// §8's outcome for one provider interface.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProviderResult {
    /// The interface the allowlist gates.
    pub ifindex: u32,
    /// AS-set Du (Step 2): the union of the customer cones.
    pub du: Vec<u32>,
    /// Pfx-set S (Step 5): prefixes originating exclusively within
    /// the customer cone with all feasible paths inside it.
    pub s: Vec<IpPrefix>,
    /// Pfx-set G (Step 7): the provider-interface allowlist — the
    /// loose-uRPF allowed set minus S minus the local exemptions.
    pub allowlist: Vec<IpPrefix>,
}

/// One interface's derivation outcome (the per-interface procedures
/// of §4 and §8 are disjoint by role).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IfaceResult {
    /// §4: customer or lateral peer.
    Customer(CustomerResult),
    /// §8: provider (BAR-SAV-PI).
    Provider(ProviderResult),
}

impl IfaceResult {
    /// The interface this result gates.
    pub fn ifindex(&self) -> u32 {
        match self {
            IfaceResult::Customer(r) => r.ifindex,
            IfaceResult::Provider(r) => r.ifindex,
        }
    }

    /// The derived permissible prefix list (Q or G).
    pub fn allowlist(&self) -> &[IpPrefix] {
        match self {
            IfaceResult::Customer(r) => &r.allowlist,
            IfaceResult::Provider(r) => &r.allowlist,
        }
    }
}

/// The whole derivation: one result per configured neighbor, in the
/// input's neighbor order. Deterministic (every set BTree-backed).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct BarsavDerivation {
    /// One entry per BAR-SAV-configured interface.
    pub results: Vec<IfaceResult>,
    /// How many feed paths the §4 preamble excluded (ROV Invalid /
    /// ASPA Invalid / AS_SET), for the evaluate log.
    pub paths_excluded: usize,
}

impl BarsavDerivation {
    /// The derivation as typed IBA rules (GSC -03 §2.1: an interface
    /// allowlist; BAR-SAV -10 is one of the mechanisms GSC names as
    /// needing exactly this shape): one [`SavRule::Iba`] per
    /// (interface, prefix), provenance [`RuleOrigin::BarSav`]. An
    /// interface whose derivation produced nothing contributes no
    /// rule — unknown ≠ invalid.
    pub fn rules(&self) -> RuleSet {
        RuleSet::from_rules(self.results.iter().flat_map(|result| {
            result.allowlist().iter().map(|&prefix| SavRule::Iba {
                prefix,
                interfaces: vec![InterfaceRef::If {
                    ifindex: result.ifindex(),
                    name: None,
                }],
                origin: Some(RuleOrigin::BarSav),
            })
        }))
    }
}

// ---- §4: the customer/lateral-peer procedure --------------------------

/// §4's customer cone for one neighbor: Steps 2-10.
///
/// The interleaved expansion the draft's preamble mandates ("both
/// ASPAs and AS_PATHs should be used to iteratively expand the
/// discovered customer cone"): each round grows the frontier with
/// A(i) (ASPA customers of the frontier, Steps 5-6) ∪ B(i) (AS_PATH
/// customers of the frontier, Step 7), minus everything already seen
/// (Step 8), until a round adds nothing (Step 9); D is the union
/// (Step 10).
fn customer_cone(input: &BarsavInput, neighbor: &BarNeighbor) -> BTreeSet<u32> {
    // Steps 2-3: Z(1) = {AS-k} ∪ ASN ACL.
    let mut cone: BTreeSet<u32> = std::iter::once(neighbor.asn)
        .chain(neighbor.asn_acl.iter().copied())
        .filter(|&asn| asn != input.local_as)
        .collect();
    // The whole AS universe the two sources can name — the frontier
    // can never outgrow it, which bounds the loop (defensive: the
    // strictly-growing-seen argument already terminates it).
    let universe: BTreeSet<u32> = input
        .paths
        .iter()
        .flat_map(|p| p.as_path.iter().copied())
        .chain(input.aspas.iter().flat_map(|a| {
            let mut v = vec![a.customer_asn];
            v.extend(a.providers.iter().copied());
            v
        }))
        .collect();
    let usable = usable_paths(input);
    let mut frontier: BTreeSet<u32> = cone.clone();
    let mut rounds = 0usize;
    while !frontier.is_empty() && rounds <= universe.len() {
        rounds += 1;
        let mut next: BTreeSet<u32> = BTreeSet::new();
        // Step 5: A(i) — ASNs whose ASPA declares a frontier member
        // as Provider ("all ASNs whose ASPA data declares at least one
        // ASN in AS-set Z(i-1) as a Provider").
        for aspa in input.aspas.iter() {
            if aspa.providers.intersection(&frontier).next().is_some()
                && aspa.customer_asn != input.local_as
            {
                next.insert(aspa.customer_asn);
            }
        }
        // Step 6: "If AS-set A(i) contains AS 0 or any ASes with IANA
        // special purpose AS numbers, remove such ASes from the set
        // and proceed."
        next.retain(|&asn| !is_special_purpose_asn(asn));
        // Step 7: B(i) — customer ASNs of frontier members "according
        // to unique AS_PATHs in Adj-RIBs-In of all interfaces": in
        // wire order the AS at position j+1 (toward the origin) is a
        // customer of the AS at position j (the draft's preamble:
        // "each AS is a customer of the AS added next in AS_PATHs").
        for path in &usable {
            for pair in path.as_path.windows(2) {
                if frontier.contains(&pair[0]) && pair[1] != input.local_as {
                    next.insert(pair[1]);
                }
            }
        }
        // Step 8: Z(i) = (A(i) ∪ B(i)) − everything seen.
        next.retain(|asn| !cone.contains(asn));
        cone.extend(next.iter().copied());
        frontier = next;
    }
    cone
}

/// The paths that survive §4's security preamble: not AS_SET-carrying
/// (verification §5.5 step 3 ⇒ Invalid), not RPKI-ROV Invalid
/// (RFC 6811 §2), and not AS_PATH-verification Invalid (§5.5/§5.6 —
/// the procedure selected by the receiving interface's role per
/// verification §6.3; a path from an interface with no configured
/// role keeps the benefit of the doubt: no role, no procedure, no
/// Invalid verdict to exclude on — disclosed).
fn usable_paths<'a>(input: &'a BarsavInput<'_>) -> Vec<&'a BarPath> {
    input
        .paths
        .iter()
        .filter(|path| {
            if path.has_as_set {
                return false;
            }
            // ROV (RFC 6811 §2): Invalid routes are excluded.
            if input.vrps.validate(&path.prefix, path.origin()) == Validity::Invalid {
                return false;
            }
            // AS_PATH verification: only where the receiving
            // interface's role selects a procedure.
            if let Some(neighbor) = input.neighbor_on(path.ingress) {
                let relation = match neighbor.role {
                    BarRole::Customer | BarRole::LateralPeer => PeerRelation::Customer,
                    BarRole::Provider => PeerRelation::Provider,
                };
                let rpki_path = rpki::AsPath::sequence(path.as_path.clone());
                let verdict = rpki::verify(input.aspas, &rpki_path, Some(neighbor.asn), relation);
                if verdict == AspaValidity::Invalid {
                    return false;
                }
            }
            true
        })
        .collect()
}

/// §4 Steps 11-13 for one neighbor's cone: Q1 ∪ Q2 ∪ Prefix ACL.
fn permissible_prefixes(
    input: &BarsavInput,
    neighbor: &BarNeighbor,
    cone: &BTreeSet<u32>,
    usable: &[&BarPath],
) -> (Vec<IpPrefix>, Vec<IpPrefix>, Vec<IpPrefix>) {
    // Step 11: Q1 — "Select all ROAs in which the authorized origin
    // ASN is in AS-set D. Form the union of the sets of prefixes
    // listed in the selected ROAs."
    let q_roa: BTreeSet<IpPrefix> = input
        .vrps
        .iter()
        .filter(|vrp| cone.contains(&vrp.asn))
        .map(|vrp| vrp.prefix)
        .collect();
    // Step 12: Q2 — "Using the routes in Adj-RIBs-In of all
    // interfaces, create a list of all prefixes originated by any ASN
    // in AS-set D."
    let q_bgp: BTreeSet<IpPrefix> = usable
        .iter()
        .filter_map(|path| match path.origin() {
            OriginAsn::As(asn) if cone.contains(&asn) => Some(path.prefix),
            _ => None,
        })
        .collect();
    // Step 13: Q = Q1 ∪ Q2 ∪ Prefix ACL.
    let q: BTreeSet<IpPrefix> = q_roa
        .union(&q_bgp)
        .copied()
        .chain(neighbor.prefix_acl.iter().copied())
        .collect();
    (
        q_roa.into_iter().collect(),
        q_bgp.into_iter().collect(),
        q.into_iter().collect(),
    )
}

// ---- §8: BAR-SAV-PI ---------------------------------------------------

/// §8 Steps 1-7: the provider-interface derivation.
///
/// Steps 1-2 run §4 per CUSTOMER interface (the draft's wording —
/// "for each customer interface of the AS in consideration"; whether
/// lateral peers join Du is one of the draft's open edges, §Deferred
/// in savnet.md) and union the cones (Du) and permissible sets (Qu).
/// Steps 3-5 shrink Qu to S; Step 6 subtracts S from the loose-uRPF
/// allowed set (here: the prefixes with any usable Adj-RIBs-In route
/// — the route-existence reading of RFC 3704 §2.4/§8704 §2.4 over the
/// BAR-SAV feed itself, since the pure core has no FIB; disclosed);
/// Step 7 removes the local exemptions.
fn provider_allowlist(
    input: &BarsavInput,
    customer_cones: &[(u32, BTreeSet<u32>)],
    customer_qs: &[BTreeSet<IpPrefix>],
    usable: &[&BarPath],
) -> (Vec<u32>, Vec<IpPrefix>, Vec<IpPrefix>) {
    // Step 2: Du and Qu (the unions over the customer interfaces).
    let du: BTreeSet<u32> = customer_cones
        .iter()
        .flat_map(|(_, cone)| cone.iter().copied())
        .collect();
    let qu: BTreeSet<IpPrefix> = customer_qs.iter().flatten().copied().collect();

    // Step 3: keep prefixes whose customer-interface routes are ALL
    // RPKI-ROV Valid and ASPA-Valid. Vacuous truth does NOT apply
    // here: a prefix with no customer-interface route has nothing
    // attesting cone exclusivity (it entered Qu only via ROA or a
    // non-customer route), so it drops — disclosed reading of "the
    // prefixes whose routes in the RIBs-In (of the customer
    // interfaces in consideration) are all RPKI-ROV Valid and have
    // Valid AS path per ASPA verification".
    let customer_ifindexes: BTreeSet<u32> =
        customer_cones.iter().map(|(ifindex, _)| *ifindex).collect();
    let mut s: BTreeSet<IpPrefix> = BTreeSet::new();
    'prefix: for &prefix in &qu {
        let mut saw_customer_route = false;
        for path in usable.iter().filter(|p| p.prefix == prefix) {
            if !customer_ifindexes.contains(&path.ingress) {
                continue;
            }
            let Some(neighbor) = input.neighbor_on(path.ingress) else {
                continue 'prefix;
            };
            saw_customer_route = true;
            if input.vrps.validate(&prefix, path.origin()) != Validity::Valid {
                continue 'prefix;
            }
            let rpki_path = rpki::AsPath::sequence(path.as_path.clone());
            let verdict = rpki::verify(
                input.aspas,
                &rpki_path,
                Some(neighbor.asn),
                PeerRelation::Customer,
            );
            if verdict != AspaValidity::Valid {
                continue 'prefix;
            }
        }
        if !saw_customer_route {
            continue;
        }
        // Step 4: "keep only the prefixes that have all their allowed
        // origin ASes (per ROAs) contained within AS-set Du" — every
        // VRP covering the prefix (its ROA-authorized origins) must
        // name a cone AS.
        for vrp in input.vrps.iter() {
            if vrp.covers(&prefix) && !du.contains(&vrp.asn) {
                continue 'prefix;
            }
        }
        // Step 5: "keep only the prefixes with all feasible routes
        // from their respective origin ASes to the local AS ...
        // such that each AS in the AS path of each route has all its
        // Provider ASes (per ASPAs) contained within AS-set Du." The
        // feasible routes the speaker knows are its usable
        // Adj-RIBs-In paths for the prefix; an AS with no ASPA has no
        // (per-ASPA) providers — vacuously contained, the literal
        // reading (one of the draft's open edges: §Deferred).
        for path in usable.iter().filter(|p| p.prefix == prefix) {
            for &asn in &path.as_path {
                if let Some(providers) = input.aspas.get(asn) {
                    if providers.iter().any(|p| !du.contains(p)) {
                        continue 'prefix;
                    }
                }
            }
        }
        s.insert(prefix);
    }

    // Step 6: Ga = (loose uRPF allowed set) − S. The loose set over
    // the feed: every prefix with a usable route (route existence,
    // RFC 8704 §2.4's "one or more prefixes that encompass the
    // source address" — at prefix granularity here).
    let loose: BTreeSet<IpPrefix> = usable.iter().map(|path| path.prefix).collect();
    let ga: BTreeSet<IpPrefix> = loose.difference(&s).copied().collect();
    // Step 7: G = Ga − the local exemptions.
    let g: BTreeSet<IpPrefix> = ga
        .iter()
        .copied()
        .filter(|prefix| !input.provider_exempt.contains(prefix))
        .collect();
    (
        du.into_iter().collect(),
        s.into_iter().collect(),
        g.into_iter().collect(),
    )
}

// ---- The generator ----------------------------------------------------

/// Run the whole derivation: §4 per customer/lateral-peer interface,
/// §8 per provider interface (its Steps 1-2 ride the §4 results).
///
/// Deterministic: results follow the input's neighbor order; every
/// set is BTree-backed, so the same input yields byte-identical
/// output.
pub fn generate_barsav(input: &BarsavInput) -> BarsavDerivation {
    let usable = usable_paths(input);
    let excluded = input.paths.len() - usable.len();
    let mut results = Vec::new();
    // §8's Step 1 needs the per-customer-interface D and Q first;
    // compute them in one pass and remember the customer ones.
    let mut customer_cones: Vec<(u32, BTreeSet<u32>)> = Vec::new();
    let mut customer_qs: Vec<BTreeSet<IpPrefix>> = Vec::new();
    for neighbor in input.neighbors {
        match neighbor.role {
            BarRole::Customer | BarRole::LateralPeer => {
                // §4 Steps 2-10.
                let cone = customer_cone(input, neighbor);
                // §4 Steps 11-13.
                let (q_roa, q_bgp, q) = permissible_prefixes(input, neighbor, &cone, &usable);
                if neighbor.role == BarRole::Customer {
                    customer_cones.push((neighbor.ifindex, cone.clone()));
                    customer_qs.push(q.iter().copied().collect());
                }
                results.push(IfaceResult::Customer(CustomerResult {
                    ifindex: neighbor.ifindex,
                    asn: neighbor.asn,
                    role: neighbor.role,
                    cone: cone.into_iter().collect(),
                    q_roa,
                    q_bgp,
                    allowlist: q,
                }));
            }
            BarRole::Provider => { /* handled after the customer pass */ }
        }
    }
    // §8 Steps 1-7 — the same G applies at every provider interface
    // (Step 8: "Apply Pfx-set G as the allowlist for ingress SAV at
    // each provider interface"; the optional per-interface extension
    // of Step 8 is §Deferred with the neighbor prefix ACLs).
    let (du, s, g) = if input.neighbors.iter().any(|n| n.role == BarRole::Provider) {
        provider_allowlist(input, &customer_cones, &customer_qs, &usable)
    } else {
        (Vec::new(), Vec::new(), Vec::new())
    };
    for neighbor in input
        .neighbors
        .iter()
        .filter(|n| n.role == BarRole::Provider)
    {
        results.push(IfaceResult::Provider(ProviderResult {
            ifindex: neighbor.ifindex,
            du: du.clone(),
            s: s.clone(),
            allowlist: g.clone(),
        }));
    }
    BarsavDerivation {
        results,
        paths_excluded: excluded,
    }
}

/// Step 6's "AS 0 or any ASes with IANA special purpose AS numbers":
/// the IANA Special-Purpose AS Number registry (0, 65535,
/// 4294967295 reserved; 64496-64511 / 65536-65551 documentation;
/// 64512-65534 / 4200000000-4294967294 private use; 23456 AS_TRANS).
fn is_special_purpose_asn(asn: u32) -> bool {
    asn == 0
        || asn == 65535
        || asn == 23456
        || asn == 4294967295
        || (64496..=64511).contains(&asn)
        || (64512..=65534).contains(&asn)
        || (65536..=65551).contains(&asn)
        || (4200000000..=4294967294).contains(&asn)
}

// ---- The M3 feed edge: file formats ------------------------------------

/// One parsed `barsav feed` line: the Adj-RIB-In snapshot's unit.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FeedPath {
    /// The announced prefix.
    pub prefix: IpPrefix,
    /// The BGP peer the path was learned from (bgpd's per-peer
    /// Adj-RIB-In key; the consumer resolves it to an interface).
    pub peer: IpAddr,
    /// The path, wire order (neighbor side first), flattened from its
    /// AS_SEQUENCE segments.
    pub as_path: Vec<u32>,
    /// The original path contained an AS_SET (excluded from the
    /// derivation, §5.5 step 3).
    pub has_as_set: bool,
}

/// Parse bgpd's BAR-SAV feed snapshot:
///
/// ```text
/// # bgpd BAR-SAV Adj-RIB-In feed v1
/// # one line per (prefix, unique path, peer); as-set marks an
/// # AS_SET-carrying path (excluded from the derivation)
/// 198.51.100.0/24 peer 192.0.2.9 path 201
/// 203.0.113.0/24 peer 192.0.2.9 path 201 202
/// 192.0.2.128/25 peer 198.51.100.2 path 401 as-set
/// ```
///
/// `#` comments and blank lines skipped; anything else is a
/// line-numbered error (the suite's config convention). This is the
/// sav-side half of the M3 read-only feed: bgpd's
/// [`bgpd::rib::LocRib::barsav_feed_text`] renders, this parses — one
/// format, two small codecs, no wire protocol.
pub fn parse_barsav_feed(text: &str) -> Result<Vec<FeedPath>, String> {
    let mut out = Vec::new();
    for (idx, raw) in text.lines().enumerate() {
        let line_no = idx + 1;
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let tokens: Vec<&str> = line.split_whitespace().collect();
        let (prefix, peer, rest): (&str, &str, &[&str]) = match tokens.as_slice() {
            [prefix, "peer", peer, "path", rest @ ..] => (prefix, peer, rest),
            _ => {
                return Err(format!(
                    "line {line_no}: expected `<prefix> peer <addr> path <asn>... [as-set]`, \
                     got `{line}`"
                ))
            }
        };
        let prefix: IpPrefix = prefix
            .parse()
            .map_err(|e| format!("line {line_no}: bad prefix `{prefix}`: {e}"))?;
        let peer: IpAddr = peer
            .parse()
            .map_err(|e| format!("line {line_no}: bad peer address `{peer}`: {e}"))?;
        let has_as_set = matches!(rest, [.., "as-set"]);
        let asns = rest.iter().take_while(|&&t| t != "as-set");
        let mut as_path = Vec::new();
        for token in asns {
            let asn: u32 = token
                .parse()
                .map_err(|_| format!("line {line_no}: bad AS number `{token}`"))?;
            as_path.push(asn);
        }
        out.push(FeedPath {
            prefix,
            peer,
            as_path,
            has_as_set,
        });
    }
    Ok(out)
}

/// Parse an RPKI snapshot in bgpd's `vrp-file` format —
/// format-identical to `bgpd::rov::parse_vrp_file` (one format across
/// the suite; the duplicate is deliberate: sav must not depend on
/// bgpd, and the format is pinned by that parser's tests there and
/// these here):
///
/// ```text
/// vrp 192.0.2.0/24 max 24 as 64512
/// aspa 64501 provider 64502 64503
/// ```
pub fn parse_rpki_snapshot(text: &str) -> Result<(VrpTable, AspaTable), String> {
    let mut vrps = VrpTable::new();
    let mut aspas = AspaTable::new();
    for (idx, raw) in text.lines().enumerate() {
        let line_no = idx + 1;
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let tokens: Vec<&str> = line.split_whitespace().collect();
        match tokens.as_slice() {
            ["vrp", prefix, "max", max_len, "as", asn] => {
                let prefix: IpPrefix = prefix
                    .parse()
                    .map_err(|e| format!("line {line_no}: bad prefix `{prefix}`: {e}"))?;
                let max_len: u8 = max_len
                    .parse()
                    .map_err(|_| format!("line {line_no}: max expects 0..=128, got `{max_len}`"))?;
                let asn: u32 = asn
                    .parse()
                    .map_err(|_| format!("line {line_no}: as expects an AS number, got `{asn}`"))?;
                vrps.apply(
                    Vrp {
                        prefix,
                        max_len,
                        asn,
                    },
                    PayloadFlags::ANNOUNCE,
                )
                .map_err(|e| format!("line {line_no}: {e}"))?;
            }
            ["aspa", customer, "provider", providers @ ..] if !providers.is_empty() => {
                let customer: u32 = customer.parse().map_err(|_| {
                    format!("line {line_no}: aspa expects an AS number, got `{customer}`")
                })?;
                let mut set = BTreeSet::new();
                for p in providers {
                    let asn: u32 = p.parse().map_err(|_| {
                        format!("line {line_no}: provider expects an AS number, got `{p}`")
                    })?;
                    set.insert(asn);
                }
                aspas
                    .apply(customer, PayloadFlags::ANNOUNCE, set)
                    .map_err(|e| format!("line {line_no}: {e}"))?;
            }
            _ => {
                return Err(format!(
                    "line {line_no}: expected `vrp <prefix> max <len> as <asn>` or \
                     `aspa <asn> provider <asn>...`, got `{line}`"
                ))
            }
        }
    }
    Ok((vrps, aspas))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn vrp_table(entries: &[(&str, u8, u32)]) -> VrpTable {
        let mut t = VrpTable::new();
        for &(prefix, max_len, asn) in entries {
            t.apply(
                Vrp {
                    prefix: prefix.parse().unwrap(),
                    max_len,
                    asn,
                },
                PayloadFlags::ANNOUNCE,
            )
            .unwrap();
        }
        t
    }

    fn aspa_table(entries: &[(u32, &[u32])]) -> AspaTable {
        let mut t = AspaTable::new();
        for &(cas, providers) in entries {
            t.apply(
                cas,
                PayloadFlags::ANNOUNCE,
                providers.iter().copied().collect(),
            )
            .unwrap();
        }
        t
    }

    fn p(s: &str) -> IpPrefix {
        s.parse().unwrap()
    }

    /// The doc-range worked topology (RFC 5737 prefixes; global-range
    /// AS numbers chosen OUTSIDE the IANA special-purpose registry —
    /// the private and documentation ranges are §4 Step 6's removal
    /// set, so cone members must not live in them): local AS 100;
    /// customer AS 201 (originates
    /// 198.51.100.0/24) whose own customer is AS 202 (originates
    /// 203.0.113.0/24); lateral peer AS 401 (originates
    /// 192.0.2.0/24) on ifindex 3; provider AS 501 (originates
    /// 198.18.0.0/15 via 502) on ifindex 4.
    fn doc_topology_paths() -> Vec<BarPath> {
        vec![
            // From the customer interface (ifindex 2): the customer's
            // own prefix, and its customer's deeper-originated prefix.
            BarPath::sequence("198.51.100.0/24", 2, &[201]),
            BarPath::sequence("203.0.113.0/24", 2, &[201, 202]),
            // From the lateral peer (ifindex 3).
            BarPath::sequence("192.0.2.0/24", 3, &[401]),
            // From the provider (ifindex 4): something far away.
            BarPath::sequence("198.18.0.0/15", 4, &[501, 502]),
        ]
    }

    fn doc_neighbors() -> Vec<BarNeighbor> {
        vec![
            BarNeighbor::new(2, 201, BarRole::Customer),
            BarNeighbor::new(3, 401, BarRole::LateralPeer),
            BarNeighbor::new(4, 501, BarRole::Provider),
        ]
    }

    fn doc_input<'a>(
        neighbors: &'a [BarNeighbor],
        paths: &'a [BarPath],
        vrps: &'a VrpTable,
        aspas: &'a AspaTable,
    ) -> BarsavInput<'a> {
        BarsavInput::new(100, neighbors, paths, vrps, aspas)
    }

    /// Empty RPKI views, bound (a temporary would not live long
    /// enough to feed `doc_input`'s borrow).
    fn empty_tables() -> (VrpTable, AspaTable) {
        (vrp_table(&[]), aspa_table(&[]))
    }

    fn allowlist_of(results: &[IfaceResult], ifindex: u32) -> &[IpPrefix] {
        results
            .iter()
            .find(|r| r.ifindex() == ifindex)
            .expect("result for ifindex")
            .allowlist()
    }

    fn customer_of(derivation: &BarsavDerivation) -> &CustomerResult {
        match &derivation.results[0] {
            IfaceResult::Customer(c) => c,
            _ => panic!("first result is the customer interface"),
        }
    }

    fn provider_of(derivation: &BarsavDerivation) -> &ProviderResult {
        for result in &derivation.results {
            if let IfaceResult::Provider(p) = result {
                return p;
            }
        }
        panic!("no provider result");
    }

    /// §4 Steps 2/7/10 via the doc topology: the customer interface's
    /// cone is {201, 202} — AS-k plus the AS_PATH-discovered
    /// customer-of-customer (Step 7's wire-order pairs: in
    /// [201, 202], 202 is a customer of 201).
    #[test]
    fn customer_cone_walks_the_as_paths() {
        let (vrps, aspas) = empty_tables();
        let paths = doc_topology_paths();
        let neighbors = doc_neighbors();
        let input = doc_input(&neighbors, &paths, &vrps, &aspas);
        assert_eq!(customer_of(&generate_barsav(&input)).cone, vec![201, 202]);
    }

    /// §4 Step 5: the ASPA side of the expansion — 301 has an ASPA
    /// declaring 202 a provider, so it joins the cone even though
    /// NO AS_PATH mentions it (the partial-deployment case BAR-SAV
    /// exists for; the preamble's "iteratively expand" mandate is why
    /// the two sources must interleave round by round, 302 riding
    /// 301 in round 3).
    #[test]
    fn aspa_extends_the_cone_beyond_the_paths() {
        let aspas = aspa_table(&[(301, &[202]), (302, &[301])]);
        let (vrps, aspas) = (vrp_table(&[]), aspas);
        let paths = doc_topology_paths();
        let neighbors = doc_neighbors();
        let input = doc_input(&neighbors, &paths, &vrps, &aspas);
        let derivation = generate_barsav(&input);
        let cone = &customer_of(&derivation).cone;
        assert!(cone.contains(&301), "cone: {cone:?}");
        assert!(cone.contains(&302), "the discovery iterates (preamble)");
    }

    /// §4 Step 6: special-purpose ASNs are removed from A(i) — an
    /// ASPA whose customer ASN is private (64512) never joins the
    /// cone, and nothing behind it is discovered through it.
    #[test]
    fn special_purpose_asns_leave_the_aspa_expansion() {
        // 64512 (private) declares 202 a provider; 301 declares
        // the private ASN a provider.
        let aspas = aspa_table(&[(64512, &[202]), (301, &[64512])]);
        let (vrps, aspas) = (vrp_table(&[]), aspas);
        let paths = doc_topology_paths();
        let neighbors = doc_neighbors();
        let input = doc_input(&neighbors, &paths, &vrps, &aspas);
        let derivation = generate_barsav(&input);
        let cone = &customer_of(&derivation).cone;
        assert!(!cone.contains(&64512));
        assert!(!cone.contains(&301), "nothing behind the removed ASN");
        // The registry list itself.
        for &asn in &[
            0u32, 65535, 23456, 64496, 64511, 64512, 65534, 65536, 65551, 4200000000, 4294967294,
            4294967295,
        ] {
            assert!(is_special_purpose_asn(asn), "{asn}");
        }
        for &asn in &[1u32, 100, 201, 202, 65552, 4199999999] {
            assert!(!is_special_purpose_asn(asn), "{asn}");
        }
    }

    /// §4 Steps 11-13: Q for the customer interface is Q1 (ROAs for
    /// cone ASes — including a prefix NO path announced, the
    /// NO_EXPORT-hidden multi-homed case) ∪ Q2 (paths cone ASes
    /// originate) ∪ the Prefix ACL. A non-cone AS's ROA never lands.
    #[test]
    fn customer_allowlist_unions_roa_bgp_and_acl() {
        let vrps = vrp_table(&[
            ("198.51.100.0/24", 24, 201),
            ("203.0.113.128/25", 25, 202), // Q1-only: never on the wire
            ("192.0.2.0/24", 24, 401),     // peer AS: not in this cone
        ]);
        let neighbors = vec![
            {
                let mut n = BarNeighbor::new(2, 201, BarRole::Customer);
                n.prefix_acl = vec![p("198.18.10.0/24")];
                n
            },
            BarNeighbor::new(3, 401, BarRole::LateralPeer),
            BarNeighbor::new(4, 501, BarRole::Provider),
        ];
        let paths = doc_topology_paths();
        let aspas = aspa_table(&[]);
        let input = doc_input(&neighbors, &paths, &vrps, &aspas);
        let derivation = generate_barsav(&input);
        assert_eq!(
            allowlist_of(&derivation.results, 2),
            &[
                p("198.18.10.0/24"),
                p("198.51.100.0/24"),
                p("203.0.113.0/24"),
                p("203.0.113.128/25"),
            ],
            "Q = Q1 (hidden ROA) ∪ Q2 (both originated) ∪ ACL, sorted"
        );
        // The component sets stay exposed for the evaluate log.
        let customer = customer_of(&derivation);
        assert_eq!(
            customer.q_roa,
            vec![p("198.51.100.0/24"), p("203.0.113.128/25")]
        );
        assert_eq!(
            customer.q_bgp,
            vec![p("198.51.100.0/24"), p("203.0.113.0/24")]
        );
    }

    /// §2: the lateral peer interface runs the SAME procedure — its
    /// cone is the peer's own ("the CC includes the AS belonging to
    /// the customer or lateral peer"), its allowlist the peer's
    /// prefixes; the customer's prefixes do not leak onto it.
    #[test]
    fn lateral_peer_interface_runs_the_same_procedure() {
        let (vrps, aspas) = empty_tables();
        let paths = doc_topology_paths();
        let neighbors = doc_neighbors();
        let input = doc_input(&neighbors, &paths, &vrps, &aspas);
        let derivation = generate_barsav(&input);
        let peer = match &derivation.results[1] {
            IfaceResult::Customer(c) => c,
            _ => panic!("second result is the peer interface"),
        };
        assert_eq!(peer.role, BarRole::LateralPeer);
        assert_eq!(peer.cone, vec![401]);
        assert_eq!(peer.allowlist, vec![p("192.0.2.0/24")]);
        assert!(!peer.allowlist.contains(&p("198.51.100.0/24")));
    }

    /// §4's preamble, ROV side: an RPKI-ROV Invalid path (a ROA
    /// authorizes the prefix for a DIFFERENT origin) feeds nothing —
    /// neither the cone walk nor Q2.
    #[test]
    fn rov_invalid_paths_are_excluded() {
        // 203.0.113.0/24 is ROA-authorized for 901, not 202.
        let vrps = vrp_table(&[("198.51.100.0/24", 24, 201), ("203.0.113.0/24", 24, 901)]);
        let aspas = aspa_table(&[]);
        let paths = doc_topology_paths();
        let neighbors = doc_neighbors();
        let input = doc_input(&neighbors, &paths, &vrps, &aspas);
        let derivation = generate_barsav(&input);
        let customer = customer_of(&derivation);
        assert!(
            !customer.cone.contains(&202),
            "the Invalid path's Step-7 pairs are gone"
        );
        assert!(!customer.allowlist.contains(&p("203.0.113.0/24")));
        assert_eq!(derivation.paths_excluded, 1);
    }

    /// §4's preamble, AS_PATH side: a path whose ASPA verification is
    /// Invalid (route-leak shape — an AS0 attestation makes every hop
    /// above the origin Not Provider+) is excluded.
    #[test]
    fn aspa_invalid_paths_are_excluded() {
        let aspas = aspa_table(&[(202, &[0])]);
        let (vrps, aspas) = (vrp_table(&[]), aspas);
        let paths = doc_topology_paths();
        let neighbors = doc_neighbors();
        let input = doc_input(&neighbors, &paths, &vrps, &aspas);
        let derivation = generate_barsav(&input);
        let customer = customer_of(&derivation);
        assert!(!customer.cone.contains(&202));
        assert!(!customer.allowlist.contains(&p("203.0.113.0/24")));
        assert_eq!(derivation.paths_excluded, 1);
    }

    /// §4's preamble, the AS_SET case (aspa-verification §5.5 step 3):
    /// has_as_set paths are excluded wholesale.
    #[test]
    fn as_set_paths_are_excluded() {
        let mut paths = doc_topology_paths();
        paths.push(BarPath {
            prefix: p("198.19.0.0/15"),
            as_path: vec![201, 701],
            has_as_set: true,
            ingress: 2,
        });
        let (vrps, aspas) = empty_tables();
        let neighbors = doc_neighbors();
        let input = doc_input(&neighbors, &paths, &vrps, &aspas);
        let derivation = generate_barsav(&input);
        assert_eq!(derivation.paths_excluded, 1);
        assert!(!customer_of(&derivation)
            .allowlist
            .contains(&p("198.19.0.0/15")));
    }

    /// §8 Steps 1-6: S holds prefixes that originate exclusively in
    /// the cone — all their covering ROAs name cone ASes and every
    /// path AS's providers stay in Du (no attestation reading as the
    /// vacuous containment, the draft's literal text) — and G (the
    /// provider allowlist) is the loose-uRPF set minus S.
    #[test]
    fn provider_subtraction_derives_s_from_the_cone() {
        let vrps = vrp_table(&[("198.51.100.0/24", 24, 201), ("203.0.113.0/24", 24, 202)]);
        let aspas = aspa_table(&[(202, &[201])]);
        let paths = doc_topology_paths();
        let neighbors = doc_neighbors();
        let input = doc_input(&neighbors, &paths, &vrps, &aspas);
        let derivation = generate_barsav(&input);
        let provider = provider_of(&derivation);
        assert_eq!(provider.du, vec![201, 202], "the customer cone union");
        assert_eq!(
            provider.s,
            vec![p("198.51.100.0/24"), p("203.0.113.0/24")],
            "both cone prefixes are cone-exclusive here"
        );
        // Step 6: G = loose − S — the peer's and provider's own
        // prefixes stay allowed (route existence), S leaves.
        assert_eq!(
            provider.allowlist,
            vec![p("192.0.2.0/24"), p("198.18.0.0/15")]
        );
    }

    /// §8 Step 5's exclusion: a cone AS with a provider OUTSIDE the
    /// cone (a dual-homed deep AS) kills its prefixes' S membership —
    /// traffic could legitimately arrive via that other provider, so
    /// the prefix stays permitted on the provider interface.
    #[test]
    fn out_of_cone_provider_kills_s_membership() {
        let vrps = vrp_table(&[("203.0.113.0/24", 24, 202)]);
        // 202 is dual-homed: providers 201 (cone) AND 701.
        let aspas = aspa_table(&[(202, &[201, 701])]);
        let paths = doc_topology_paths();
        let neighbors = doc_neighbors();
        let input = doc_input(&neighbors, &paths, &vrps, &aspas);
        let derivation = generate_barsav(&input);
        let provider = provider_of(&derivation);
        assert!(!provider.s.contains(&p("203.0.113.0/24")));
        assert!(provider.allowlist.contains(&p("203.0.113.0/24")));
    }

    /// §8 Step 7: the local exemptions (single-homed / internal-use
    /// prefixes) leave G even when S missed them.
    #[test]
    fn provider_exemptions_leave_the_allowlist() {
        let paths = doc_topology_paths();
        let neighbors = doc_neighbors();
        let exempt = [p("192.0.2.0/24")];
        let (vrps, aspas) = empty_tables();
        let input = BarsavInput {
            local_as: 100,
            neighbors: &neighbors,
            paths: &paths,
            vrps: &vrps,
            aspas: &aspas,
            provider_exempt: &exempt,
        };
        let derivation = generate_barsav(&input);
        let provider = provider_of(&derivation);
        assert!(!provider.allowlist.contains(&p("192.0.2.0/24")));
        assert!(provider.allowlist.contains(&p("198.18.0.0/15")));
    }

    /// §8 Step 3's reading: a Qu prefix with no customer-interface
    /// route at all (it entered via ROA Q1 only) never reaches S —
    /// nothing attests its exclusivity.
    #[test]
    fn roa_only_prefixes_never_reach_s() {
        // A ROA for a cone AS whose prefix no path announced.
        let vrps = vrp_table(&[("203.0.113.128/25", 25, 202)]);
        let aspas = aspa_table(&[]);
        let paths = doc_topology_paths();
        let neighbors = doc_neighbors();
        let input = doc_input(&neighbors, &paths, &vrps, &aspas);
        let derivation = generate_barsav(&input);
        assert!(
            customer_of(&derivation)
                .allowlist
                .contains(&p("203.0.113.128/25")),
            "the customer interface's Q carries it (Step 11)"
        );
        assert!(!provider_of(&derivation).s.contains(&p("203.0.113.128/25")));
    }

    /// The safety addendum beyond the draft text (disclosed): the
    /// local AS never lands in a cone — a bogus ASPA claiming to be
    /// the local AS's customer must not leak us into the discovery.
    #[test]
    fn the_local_as_never_joins_a_cone() {
        let aspas = aspa_table(&[(100, &[201])]);
        let (vrps, aspas) = (vrp_table(&[]), aspas);
        let paths = doc_topology_paths();
        let neighbors = doc_neighbors();
        let input = doc_input(&neighbors, &paths, &vrps, &aspas);
        let derivation = generate_barsav(&input);
        assert!(!customer_of(&derivation).cone.contains(&100));
    }

    /// The ACLs: §4 Step 3 seeds Z(1) with the ASN ACL (an
    /// AS_PATH-invisible AS still expands its cone through ASPA), and
    /// the prefix ACL rides Q (Step 13).
    #[test]
    fn asn_acl_seeds_the_cone_and_prefix_acl_rides_q() {
        let aspas = aspa_table(&[(310, &[210])]);
        let neighbors = vec![
            {
                let mut n = BarNeighbor::new(2, 201, BarRole::Customer);
                n.asn_acl = vec![210];
                n.prefix_acl = vec![p("198.18.20.0/24")];
                n
            },
            BarNeighbor::new(3, 401, BarRole::LateralPeer),
            BarNeighbor::new(4, 501, BarRole::Provider),
        ];
        let paths = doc_topology_paths();
        let vrps = vrp_table(&[]);
        let input = BarsavInput::new(100, &neighbors, &paths, &vrps, &aspas);
        let derivation = generate_barsav(&input);
        let customer = customer_of(&derivation);
        // Z(1) = {201, 210}; 310 attests 210 as provider, so
        // A(2) ∋ 310 — the ACL-seeded ASPA discovery.
        assert!(customer.cone.contains(&210));
        assert!(customer.cone.contains(&310));
        assert!(customer.allowlist.contains(&p("198.18.20.0/24")));
    }

    /// DETERMINISM: the same input yields byte-identical output, and
    /// a path-order permutation changes nothing (BTree-backed sets,
    /// not sequences, carry the state).
    #[test]
    fn derivation_is_deterministic_and_order_independent() {
        let vrps = vrp_table(&[("198.51.100.0/24", 24, 201), ("203.0.113.0/24", 24, 202)]);
        let aspas = aspa_table(&[(202, &[201]), (301, &[202])]);
        let paths = doc_topology_paths();
        let neighbors = doc_neighbors();
        let input = doc_input(&neighbors, &paths, &vrps, &aspas);
        let first = generate_barsav(&input);
        assert_eq!(
            format!("{first:?}"),
            format!("{:?}", generate_barsav(&input))
        );
        let mut shuffled = paths.clone();
        shuffled.reverse();
        let input2 = doc_input(&neighbors, &shuffled, &vrps, &aspas);
        assert_eq!(
            generate_barsav(&input2).results,
            first.results,
            "path order must not leak"
        );
    }

    /// The house rules at the output edge: every rule the derivation
    /// emits is an IBA allowlist entry provenance-tagged bar-sav, and
    /// an empty feed yields no rule anywhere (unknown ≠ invalid —
    /// never a spoof verdict from missing data).
    #[test]
    fn rules_are_iba_allowlists_with_bar_sav_provenance() {
        let (vrps, aspas) = empty_tables();
        let paths = doc_topology_paths();
        let neighbors = doc_neighbors();
        let input = doc_input(&neighbors, &paths, &vrps, &aspas);
        let derivation = generate_barsav(&input);
        let rules = derivation.rules();
        for rule in rules.rules() {
            assert_eq!(rule.mode(), crate::mode::ValidationMode::Iba);
            assert_eq!(rule.origin(), Some(RuleOrigin::BarSav));
        }
        // The customer interface carries exactly its two prefixes.
        let cust: Vec<IpPrefix> = rules
            .rules()
            .iter()
            .filter(|r| r.interfaces().first().and_then(|i| i.ifindex()) == Some(2))
            .map(|r| r.prefix())
            .collect();
        assert_eq!(cust, vec![p("198.51.100.0/24"), p("203.0.113.0/24")]);
        // An empty feed: nothing derived, no rules at all.
        let (vrps, aspas) = empty_tables();
        let empty = doc_input(&neighbors, &[], &vrps, &aspas);
        assert!(generate_barsav(&empty).rules().is_empty());
    }

    // ---- The M3 feed codecs -------------------------------------------

    /// The feed parser: the documented shapes parse (v4 and v6, the
    /// as-set marker), and malformed lines carry line numbers.
    #[test]
    fn feed_parses_the_documented_shapes() {
        let feed = "# bgpd BAR-SAV Adj-RIB-In feed v1\n\
                    198.51.100.0/24 peer 192.0.2.9 path 201\n\
                    203.0.113.0/24 peer 192.0.2.9 path 201 202\n\
                    192.0.2.128/25 peer 198.51.100.2 path 401 as-set\n\
                    2001:db8::/48 peer 2001:db8::2 path 201\n";
        let paths = parse_barsav_feed(feed).unwrap();
        assert_eq!(paths.len(), 4);
        assert_eq!(paths[1].as_path, vec![201, 202]);
        assert!(paths[2].has_as_set);
        assert_eq!(paths[2].as_path, vec![401]);
        assert_eq!(paths[3].prefix, p("2001:db8::/48"));
        assert_eq!(paths[3].peer, "2001:db8::2".parse::<IpAddr>().unwrap());

        assert!(parse_barsav_feed("junk\n").unwrap_err().contains("line 1"));
        assert!(parse_barsav_feed("10.0.0.0/8 peer not-an-addr path 1\n")
            .unwrap_err()
            .contains("bad peer address"));
        assert!(parse_barsav_feed("10.0.0.0/8 peer 1.2.3.4 path x\n")
            .unwrap_err()
            .contains("bad AS number"));
        // An as-set-only path (empty sequence) is still a line.
        let only = parse_barsav_feed("10.0.0.0/8 peer 1.2.3.4 path as-set\n").unwrap();
        assert!(only[0].has_as_set && only[0].as_path.is_empty());
    }

    /// The RPKI snapshot parser: format-compatible with bgpd's
    /// vrp-file (same shapes, same strictness, line-numbered errors).
    #[test]
    fn rpki_snapshot_parses_the_vrp_file_format() {
        let text = "# snapshot\n\
                    vrp 192.0.2.0/24 max 24 as 64512\n\
                    vrp 2001:db8:1::/48 max 64 as 64512\n\
                    aspa 64501 provider 64502 64503\n";
        let (vrps, aspas) = parse_rpki_snapshot(text).unwrap();
        assert_eq!(vrps.len(), 2);
        assert_eq!(aspas.get(64501).map(|s| s.len()), Some(2));
        assert!(parse_rpki_snapshot("nope\n")
            .unwrap_err()
            .contains("line 1"));
        assert!(parse_rpki_snapshot("aspa 64501 provider\n")
            .unwrap_err()
            .contains("line 1"));
    }

    /// End to end over the feed edge: parse the feed + snapshot files
    /// exactly as savd will, then run the derivation — the M1/M3 seam
    /// in one test.
    #[test]
    fn feed_files_drive_the_derivation_end_to_end() {
        let feed = "198.51.100.0/24 peer 192.0.2.9 path 201\n\
                    203.0.113.0/24 peer 192.0.2.9 path 201 202\n\
                    192.0.2.0/24 peer 198.51.100.2 path 401\n";
        let snapshot = "vrp 198.51.100.0/24 max 24 as 201\n\
                        vrp 203.0.113.0/24 max 24 as 202\n\
                        aspa 202 provider 201\n";
        let (vrps, aspas) = parse_rpki_snapshot(snapshot).unwrap();
        // savd's join: peer address -> ifindex (on-link resolution);
        // here the hand-mapped ifindexes of the doc topology.
        let paths: Vec<BarPath> = parse_barsav_feed(feed)
            .unwrap()
            .into_iter()
            .map(|line| BarPath {
                prefix: line.prefix,
                as_path: line.as_path,
                has_as_set: line.has_as_set,
                ingress: if line.peer.to_string().starts_with("192.0.2.") {
                    2
                } else {
                    3
                },
            })
            .collect();
        let neighbors = doc_neighbors();
        let input = doc_input(&neighbors, &paths, &vrps, &aspas);
        let derivation = generate_barsav(&input);
        assert_eq!(
            allowlist_of(&derivation.results, 2),
            &[p("198.51.100.0/24"), p("203.0.113.0/24")]
        );
        assert_eq!(allowlist_of(&derivation.results, 3), &[p("192.0.2.0/24")]);
    }
}
