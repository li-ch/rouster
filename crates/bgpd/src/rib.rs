//! The BGP RIB (RFC 4271 §9): per-peer Adj-RIBs-In, the Loc-RIB, and
//! the decision process as pure functions.
//!
//! The §9.1.2.2 tiebreak ladder, exactly as the RFC orders it (the
//! criteria MUST be applied in order; a criterion only removes
//! candidates while more than one remains):
//!
//! 0. degree of preference — v1 materializes it as LOCAL_PREF
//!    (§9.1.1 lets local policy set it; the default of 100 for
//!    missing LOCAL_PREF is the operator-visible convention, FRR
//!    parity);
//! 1. a) smallest AS_PATH count (an AS_SET counts as 1);
//! 2. b) lowest ORIGIN number (IGP < EGP < INCOMPLETE);
//! 3. c) lowest MULTI_EXIT_DISC, comparable only between routes
//!    learned from the same neighboring AS; absent MED reads as 0;
//! 4. d) eBGP-learned beats iBGP-learned when both remain;
//! 5. e) lowest interior cost to NEXT_HOP — SKIPPED in v1: no IGP
//!    exists yet, and §9.1.2.2 e) explicitly allows skipping when no
//!    cost can be determined;
//! 6. f) lowest BGP Identifier;
//! 7. g) lowest peer address from which the route was received.
//!
//! Import/export are trait seams (W2-d: the BIRD-inspired typed policy
//! engine plus RPKI/OTC validation implement them; the defaults stay
//! accept-all, so an unconfigured daemon is behavior-identical).

use std::collections::{BTreeMap, BTreeSet, HashSet};
use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;

use common::{IpPrefix, Nexthop, NexthopGroup, RouteEntry, RouteProtocol};
use tracing::info;

use crate::attr::{attr_type, AsPath, AsSegment, Nlri, Origin, PathAttribute};
use crate::message::BgpUpdate;
use crate::peer::{PeerInfo, RouteSink};

/// One stored route: the prefix, its path attributes, the peer it
/// came from, and the RPKI-derived validation state W2-d records at
/// import (RFC 6811 §2 / RFC 9234 §5 visibility for show output).
///
/// [`PartialEq`] deliberately ignores [`Route::stale`]: marking a
/// route stale (RFC 4724 §4.2 retention) is bookkeeping, not a route
/// change — `recompute` must not report a best-path flip for it.
#[derive(Debug, Clone, Eq)]
pub struct Route {
    pub prefix: IpPrefix,
    /// The route's path attributes, interned and shared (PERF-M1 M2):
    /// identical tuples across prefixes — 6.02× of the table at the
    /// 100k census — share one allocation (FRR's `bgp_attr` intern
    /// hash is the known art). Clones are refcount bumps; the import
    /// policy's mutations copy-on-write via `Arc::make_mut`.
    pub attrs: Arc<Vec<PathAttribute>>,
    /// The learning peer, shared per-peer (PERF-M1 M3): every route
    /// of one session points at the same `PeerInfo` — 8 B in the map
    /// slot instead of 28 — and every reader (`route.source.address`)
    /// derefs unchanged.
    pub source: Arc<PeerInfo>,
    /// Learned over an internal (iBGP) session (§9.1.2.2 d).
    pub internal: bool,
    /// RFC 6811 §2 prefix-origin validity; `None` = RPKI not in use
    /// for this route (no tables). Recorded at import for eBGP AND
    /// iBGP paths — the state is a pure prefix/origin function
    /// (S13-b); enforcement (reject-invalid) stays the eBGP edge
    /// posture.
    pub rov: Option<rpki::Validity>,
    /// ASPA verification outcome (draft-ietf-sidrops-aspa-verification
    /// §5.5/§5.6); `None` = not computed (no tables, no neighbor
    /// role, or iBGP — the procedure keys on the eBGP edge role).
    pub aspa: Option<rpki::AspaValidity>,
    /// Learned over a route-server-client session (N5): the route
    /// reflects to other clients transparently (no local-AS prepend,
    /// NEXT_HOP/MED preserved) and never installs into the kernel —
    /// the RS RIB stays separate from the kernel RIB.
    pub rs_client: bool,
    /// Learned from a configured route-reflector CLIENT (RFC 4456):
    /// §9.2's no-iBGP-redistribution prohibition lifts for it — a
    /// route from a client may be re-advertised to all iBGP peers
    /// (RFC 4456 §4's reflection table).
    pub rr_client: bool,
    /// RFC 4724 §4.2: retained across a GR peer's session loss. Stale
    /// routes keep feeding forwarding/best-path until flushed (EOR,
    /// re-establishment without the R bit, or the restart timer); a
    /// re-advertised prefix simply replaces its stale entry.
    pub stale: bool,
    /// RFC 7911 §2/§5: the Path Identifier this path arrived under
    /// (ADD-PATH receive). 0 = the classic no-ADD-PATH key. Sibling
    /// paths of one prefix from one peer differ here and only here;
    /// the value is the peer's local matter — opaque, never assumed
    /// stable across its restart (§5's GR caution).
    pub path_id: u32,
}

impl Route {
    /// The plain-route constructor (no RPKI state, classic path id 0).
    pub fn new(
        prefix: IpPrefix,
        attrs: Vec<PathAttribute>,
        source: PeerInfo,
        internal: bool,
    ) -> Self {
        Self::from_shared_attrs(prefix, Arc::new(attrs), Arc::new(source), internal)
    }

    /// [`Self::new`] for an already-interned, shared attribute tuple
    /// (the `LocRib::announce` path — one intern per UPDATE, shared
    /// by every prefix it carries).
    pub fn from_shared_attrs(
        prefix: IpPrefix,
        attrs: Arc<Vec<PathAttribute>>,
        source: Arc<PeerInfo>,
        internal: bool,
    ) -> Self {
        Self {
            prefix,
            attrs,
            source,
            internal,
            rov: None,
            aspa: None,
            rs_client: false,
            rr_client: false,
            stale: false,
            path_id: 0,
        }
    }
}

impl PartialEq for Route {
    fn eq(&self, other: &Self) -> bool {
        // Every field except `stale` (see the type doc).
        self.prefix == other.prefix
            && self.attrs == other.attrs
            && self.source == other.source
            && self.internal == other.internal
            && self.rov == other.rov
            && self.aspa == other.aspa
            && self.rs_client == other.rs_client
            && self.rr_client == other.rr_client
            && self.path_id == other.path_id
    }
}

impl Route {
    pub fn attr(&self, want: u8) -> Option<&PathAttribute> {
        self.attrs.iter().find(|a| a.attr_type() == want)
    }

    pub fn origin(&self) -> Origin {
        match self.attr(attr_type::ORIGIN) {
            Some(PathAttribute::Origin(o)) => *o,
            _ => Origin::Incomplete,
        }
    }

    pub fn as_path_len(&self) -> usize {
        match self.attr(attr_type::AS_PATH) {
            Some(PathAttribute::AsPath(p)) => p.path_length(),
            _ => 0,
        }
    }

    /// LOCAL_PREF with the 100 default for the missing attribute.
    pub fn local_pref(&self) -> u32 {
        match self.attr(attr_type::LOCAL_PREF) {
            Some(PathAttribute::LocalPref(v)) => *v,
            _ => 100,
        }
    }

    /// MED; absent reads as the lowest possible value (§9.1.2.2 c).
    pub fn med(&self) -> u32 {
        match self.attr(attr_type::MULTI_EXIT_DISC) {
            Some(PathAttribute::Med(v)) => *v,
            _ => 0,
        }
    }

    /// The neighbor AS the route was received from (the §9.1.2.2 c
    /// comparability key): the rightmost AS_SEQUENCE element, or for
    /// iBGP-learned routes whatever the path says (locally-originated
    /// iBGP routes compare under the local AS, per the RFC's
    /// neighborAS() rules).
    pub fn neighbor_as(&self) -> Option<u32> {
        match self.attr(attr_type::AS_PATH) {
            Some(PathAttribute::AsPath(p)) => p.neighbor_as(),
            _ => None,
        }
    }

    pub fn next_hop_v4(&self) -> Option<Ipv4Addr> {
        match self.attr(attr_type::NEXT_HOP) {
            Some(PathAttribute::NextHop(a)) => Some(*a),
            _ => None,
        }
    }

    /// OTC / Only To Customer (RFC 9234 §5) when the route carries it.
    pub fn otc(&self) -> Option<u32> {
        match self.attr(attr_type::OTC) {
            Some(PathAttribute::Otc(v)) => Some(*v),
            _ => None,
        }
    }

    /// Route Origin ASN per RFC 6811 §2 (rightmost AS of a final
    /// AS_SEQUENCE; None = that document's NONE).
    pub fn origin_as(&self) -> Option<u32> {
        match self.attr(attr_type::AS_PATH) {
            Some(PathAttribute::AsPath(p)) => p.origin_as(),
            _ => None,
        }
    }
}

/// Import policy seam: Phase 1 of §9.1.1 / §9.2.1 — everything an
/// Adj-RIB-In route passes through before it becomes a decision-process
/// candidate. Returns the (possibly mutated) route, or `None` to
/// reject. W2-d widened this from a bool: a set-action filter mutates
/// attributes before best-path (§9.1.1: local policy may raise the
/// degree of preference).
pub trait ImportPolicy: Send + Sync {
    fn import(&self, route: Route) -> Option<Route>;
}

/// Export policy seam: the §9.2.1 Phase 3 dissemination filter (plus
/// W2-d's RFC 9234 OTC synthesis on eBGP export). Returns the
/// advertisement-shaped route, or `None` to suppress. `internal` is
/// whether the target session is iBGP (RFC 9234 applies to eBGP only).
pub trait ExportPolicy: Send + Sync {
    fn export(&self, route: &Route, to_peer: &PeerInfo, internal: bool) -> Option<Route>;
}

/// The accept-all pair (the unconfigured default — behavior-identical
/// to the v1 seams: import passes routes through unchanged; export
/// keeps §9.2.2's loop-prevention floor of never reflecting a route to
/// the peer it was learned from).
#[derive(Default)]
pub struct AcceptAll;
impl ImportPolicy for AcceptAll {
    fn import(&self, route: Route) -> Option<Route> {
        Some(route)
    }
}
impl ExportPolicy for AcceptAll {
    fn export(&self, route: &Route, to_peer: &PeerInfo, _internal: bool) -> Option<Route> {
        if route.source.address == to_peer.address {
            None
        } else {
            Some(route.clone())
        }
    }
}

/// The §9.1 decision process: pick the best route among candidates.
/// Pure — callers feed Adj-RIB-In candidates for one prefix.
///
/// F10 lever 2: every candidate's §9.1 scalars (LOCAL_PREF, path
/// length, ORIGIN, MED, neighbor AS, session type, BGP Identifier,
/// peer address) are derived ONCE up front — the previous form
/// re-derived them per step by scanning the candidate's attribute
/// list, and the MED step compares candidates pairwise, so one
/// recompute over same-feed peers cost O(candidates² × attributes)
/// attribute walks. Semantics are unchanged step for step (the pure
/// decision table tests below pin them).
pub fn best_path<'a>(candidates: &[&'a Route]) -> Option<&'a Route> {
    if candidates.is_empty() {
        return None;
    }
    struct Score {
        pref: u32,
        path_len: usize,
        origin: Origin,
        med: u32,
        neighbor_as: Option<u32>,
        internal: bool,
        bgp_id: Option<Ipv4Addr>,
        addr: IpAddr,
    }
    let scores: Vec<Score> = candidates
        .iter()
        .map(|&r| Score {
            pref: r.local_pref(),
            path_len: r.as_path_len(),
            origin: r.origin(),
            med: r.med(),
            neighbor_as: r.neighbor_as(),
            internal: r.internal,
            bgp_id: r.source.bgp_id,
            addr: r.source.address,
        })
        .collect();
    let mut alive: Vec<usize> = (0..scores.len()).collect();

    // Degree of preference (LOCAL_PREF, higher wins).
    let top_pref = alive.iter().map(|&i| scores[i].pref).max().unwrap();
    alive.retain(|&i| scores[i].pref == top_pref);
    if alive.len() == 1 {
        return Some(candidates[alive[0]]);
    }

    // a) smallest AS_PATH count (AS_SET = 1).
    let shortest = alive.iter().map(|&i| scores[i].path_len).min().unwrap();
    alive.retain(|&i| scores[i].path_len == shortest);
    if alive.len() == 1 {
        return Some(candidates[alive[0]]);
    }

    // b) lowest ORIGIN number.
    let best_origin = alive.iter().map(|&i| scores[i].origin).min().unwrap();
    alive.retain(|&i| scores[i].origin == best_origin);
    if alive.len() == 1 {
        return Some(candidates[alive[0]]);
    }

    // c) lowest MED among routes from the same neighboring AS
    // (RFC pseudocode: remove m when a same-neighbor-AS n has a
    // strictly smaller MED; missing reads as 0).
    let mut med_alive: Vec<usize> = Vec::new();
    'outer: for &m in &alive {
        if let Some(m_as) = scores[m].neighbor_as {
            for &n in &alive {
                if n != m && scores[n].neighbor_as == Some(m_as) && scores[n].med < scores[m].med {
                    continue 'outer; // dominated, remove m
                }
            }
        }
        med_alive.push(m);
    }
    alive = med_alive;
    if alive.len() == 1 {
        return Some(candidates[alive[0]]);
    }

    // d) eBGP over iBGP.
    if alive.iter().any(|&i| !scores[i].internal) {
        alive.retain(|&i| !scores[i].internal);
        if alive.len() == 1 {
            return Some(candidates[alive[0]]);
        }
    }

    // e) interior cost to NEXT_HOP — skipped (no IGP yet; §9.1.2.2 e
    // allows skipping when no cost can be determined).

    // f) lowest BGP Identifier.
    if alive.iter().all(|&i| scores[i].bgp_id.is_some()) {
        let lowest = alive
            .iter()
            .map(|&i| scores[i].bgp_id.unwrap())
            .min()
            .unwrap();
        alive.retain(|&i| scores[i].bgp_id == Some(lowest));
        if alive.len() == 1 {
            return Some(candidates[alive[0]]);
        }
    }

    // g) lowest peer address.
    let lowest_addr = alive.iter().map(|&i| scores[i].addr).min().unwrap();
    alive.retain(|&i| scores[i].addr == lowest_addr);
    Some(candidates[alive[0]])
}

/// A Loc-RIB change produced by a recompute: the prefix, its new best
/// route, and (for withdrawals) the route it replaces.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BestChange {
    pub prefix: IpPrefix,
    pub best: Option<Route>,
    pub old: Option<Route>,
}

/// The attribute intern table (PERF-M1 M2, the census-named 6.02×
/// duplication): one shared `Arc<Vec<PathAttribute>>` per distinct
/// tuple — FRR's `bgp_attr` hash is the known art, and this is its
/// Rust-shape translation: the refcount IS the pin count.
///
/// - `intern` returns the canonical instance for a value (found by
///   hash+eq on the tuple itself — `Arc`'s `Hash`/`Eq` delegate to
///   the inner `Vec`, so an owned `Vec` probes the set directly).
/// - `sweep` drops entries nothing outside the set references
///   (`strong_count == 1` = only the set's own pin) — the GC pass,
///   run after the bulk Adj-RIB-In removals (peer clear, soft reset,
///   stale flush) and every [`Self::SWEEP_EVERY`] interns, so a
///   churning table does not accumulate dead tuples.
#[derive(Default)]
pub struct AttrInterner {
    set: HashSet<Arc<Vec<PathAttribute>>>,
    interns_since_sweep: usize,
}

impl AttrInterner {
    const SWEEP_EVERY: usize = 65_536;

    pub fn intern(&mut self, attrs: Vec<PathAttribute>) -> Arc<Vec<PathAttribute>> {
        if let Some(hit) = self.set.get(&attrs) {
            return Arc::clone(hit);
        }
        let arc = Arc::new(attrs);
        self.set.insert(Arc::clone(&arc));
        self.interns_since_sweep += 1;
        if self.interns_since_sweep >= Self::SWEEP_EVERY {
            self.interns_since_sweep = 0;
            self.sweep();
        }
        arc
    }

    /// Drop entries no live route references (the set's own pin is
    /// the only one left). O(distinct tuples).
    pub fn sweep(&mut self) {
        self.set.retain(|a| Arc::strong_count(a) > 1);
    }

    /// Distinct tuples currently pinned (the census surface).
    pub fn len(&self) -> usize {
        self.set.len()
    }

    /// Whether the table holds nothing (tests).
    pub fn is_empty(&self) -> bool {
        self.set.is_empty()
    }
}

/// Adj-RIBs-In + Loc-RIB (§9.1's three RIBs minus Adj-RIB-Out, which
/// the session's OutRib plays).
pub struct LocRib {
    local_as: u32,
    /// peer address → ((prefix, path-id) → route). The key widens the
    /// RFC 4271 implicit-replacement key by the ADD-PATH Path
    /// Identifier (RFC 7911 §5: a new advertisement replaces only the
    /// same (prefix, path-id); a *different* id from the same peer
    /// coexists as a sibling path). Classic sessions live under id 0.
    adj_in: BTreeMap<IpAddr, BTreeMap<Nlri, Route>>,
    best: BTreeMap<IpPrefix, Route>,
    /// The interned attribute tuples every stored route shares
    /// (PERF-M1 M2).
    pub attrs: AttrInterner,
    /// The per-peer shared PeerInfo handles (PERF-M1 M3): bounded by
    /// the peer count, so every stored route's `source` is an 8-byte
    /// pointer to one instance instead of a 28-byte inline copy.
    peer_infos: BTreeMap<IpAddr, Arc<PeerInfo>>,
    /// The Phase 1 import policy (§9.2.1): typed filter + RPKI/OTC
    /// validation in W2-d; accept-all by default.
    import: Arc<dyn ImportPolicy>,
    /// Route-server client addresses (N5): their routes carry the
    /// transparent-reflection and never-install semantics.
    rs_clients: BTreeSet<IpAddr>,
    /// Route-reflector client addresses (RFC 4456, S7-b): routes from
    /// these iBGP peers re-advertise to all iBGP peers; routes from
    /// other iBGP peers re-advertise to clients only.
    rr_clients: BTreeSet<IpAddr>,
}

impl LocRib {
    pub fn new(local_as: u32) -> Self {
        Self::with_policy(local_as, Arc::new(AcceptAll))
    }

    pub fn with_policy(local_as: u32, import: Arc<dyn ImportPolicy>) -> Self {
        Self {
            local_as,
            adj_in: BTreeMap::new(),
            best: BTreeMap::new(),
            attrs: AttrInterner::default(),
            peer_infos: BTreeMap::new(),
            import,
            rs_clients: BTreeSet::new(),
            rr_clients: BTreeSet::new(),
        }
    }

    /// Configure the route-server client set (N5).
    pub fn set_route_server_clients(&mut self, clients: impl IntoIterator<Item = IpAddr>) {
        self.rs_clients = clients.into_iter().collect();
    }

    pub fn is_route_server_client(&self, addr: &IpAddr) -> bool {
        self.rs_clients.contains(addr)
    }

    /// Configure the route-reflector client set (RFC 4456; the
    /// `neighbor X route-reflector-client` knob).
    pub fn set_route_reflector_clients(&mut self, clients: impl IntoIterator<Item = IpAddr>) {
        self.rr_clients = clients.into_iter().collect();
    }

    pub fn is_route_reflector_client(&self, addr: &IpAddr) -> bool {
        self.rr_clients.contains(addr)
    }

    pub fn local_as(&self) -> u32 {
        self.local_as
    }

    /// Adj-RIB-In update from one peer's UPDATE (announce side). Each
    /// carried path (prefix + its ADD-PATH identifier, RFC 7911 §3)
    /// runs the import policy (§9.2.1 Phase 1) before entering the
    /// Adj-RIB-In: rejected paths never become decision candidates;
    /// accepted ones may carry mutated attributes.
    pub fn announce(&mut self, peer: &PeerInfo, update: &BgpUpdate) {
        let rib = self.adj_in.entry(peer.address).or_default();
        let internal = peer.remote_as == self.local_as;
        let rs_client = self.rs_clients.contains(&peer.address);
        let rr_client = internal && self.rr_clients.contains(&peer.address);
        // One interned tuple per UPDATE (PERF-M1 M2): the B-3
        // LOCAL_PREF reset is per-UPDATE-identical (a session fact),
        // so it runs once here; every prefix the UPDATE carries
        // shares the canonical instance, and equal tuples across
        // UPDATEs collapse to it as well.
        let mut base = update.attrs.clone();
        reset_external_local_pref(&mut base, internal);
        let base = self.attrs.intern(base);
        // Re-pin when the session's facts changed (a re-established
        // peer may carry a new BGP Identifier); otherwise share.
        let peer_info = match self.peer_infos.get(&peer.address) {
            Some(cached) if **cached == *peer => Arc::clone(cached),
            _ => {
                let arc = Arc::new(*peer);
                self.peer_infos.insert(peer.address, Arc::clone(&arc));
                arc
            }
        };
        for nlri in update.announced() {
            let mut route = Route::from_shared_attrs(
                nlri.prefix,
                Arc::clone(&base),
                Arc::clone(&peer_info),
                internal,
            );
            route.rs_client = rs_client;
            route.rr_client = rr_client;
            route.path_id = nlri.path_id;
            match self.import.import(route) {
                Some(route) => {
                    rib.insert(nlri, route);
                }
                None => {
                    info!(peer = %peer.address, prefix = %nlri.prefix,
                        path_id = nlri.path_id, "bgpd: route rejected by import policy");
                }
            }
        }
    }

    /// Adj-RIB-In withdrawals, keyed (prefix, path-id): RFC 7911 §5 —
    /// removing one path of a prefix leaves its siblings; a key never
    /// seen is "silently ignore" (the §5 SHOULD — a `BTreeMap::remove`
    /// on an absent key is exactly that).
    pub fn withdraw(&mut self, peer: &PeerInfo, nlris: &[Nlri]) {
        if let Some(rib) = self.adj_in.get_mut(&peer.address) {
            for nlri in nlris {
                rib.remove(nlri);
            }
        }
    }

    /// RFC 4724 §4.2: mark every route of a lost GR session stale —
    /// retained (still a best-path candidate) until flushed.
    pub fn mark_peer_stale(&mut self, peer: &PeerInfo) {
        if let Some(rib) = self.adj_in.get_mut(&peer.address) {
            for route in rib.values_mut() {
                route.stale = true;
            }
            if !rib.is_empty() {
                info!(peer = %peer.address, routes = rib.len(),
                    "bgpd: routes marked stale (RFC 4724)");
            }
        }
    }

    /// Delete the peer's routes still marked stale (re-advertised
    /// prefixes replaced theirs). Returns how many left.
    pub fn flush_stale(&mut self, peer: &PeerInfo) -> usize {
        self.flush_stale_family(peer, None).len()
    }

    /// [`Self::flush_stale`] for one family (`Some(true)` = v6,
    /// `Some(false)` = v4, `None` = both) — the per-family EOR
    /// trigger (RFC 4724 §3/§4.2). Returns the flushed prefixes (F10:
    /// the caller recomputes exactly these — a full-table recompute
    /// per EOR made establishment-window CPU grow O(peers × prefixes);
    /// a prefix whose every candidate was flushed still yields its
    /// withdrawal change through the per-prefix recompute).
    pub fn flush_stale_family(&mut self, peer: &PeerInfo, v6: Option<bool>) -> Vec<IpPrefix> {
        let Some(rib) = self.adj_in.get_mut(&peer.address) else {
            return Vec::new();
        };
        let mut flushed = Vec::new();
        rib.retain(|_, route| {
            let in_family = v6.is_none_or(|want| {
                matches!(
                    (want, route.prefix),
                    (true, IpPrefix::V6(_)) | (false, IpPrefix::V4(_))
                )
            });
            let keep = !(route.stale && in_family);
            if !keep {
                flushed.push(route.prefix);
            }
            keep
        });
        if !flushed.is_empty() {
            info!(peer = %peer.address, routes = flushed.len(),
                "bgpd: stale routes flushed (RFC 4724)");
        }
        flushed
    }

    /// How many of the peer's routes are currently stale (tests,
    /// show surface).
    pub fn stale_count(&self, peer: &PeerInfo) -> usize {
        self.adj_in
            .get(&peer.address)
            .map(|rib| rib.values().filter(|r| r.stale).count())
            .unwrap_or(0)
    }

    /// "Deletes all routes associated with this connection".
    pub fn clear_peer(&mut self, peer: &PeerInfo) {
        if let Some(rib) = self.adj_in.remove(&peer.address) {
            if !rib.is_empty() {
                info!(peer = %peer.address, routes = rib.len(), "bgpd: peer routes withdrawn");
            }
        }
        // PERF-M1 M2: bulk removal — drop interned tuples nothing
        // references anymore.
        self.attrs.sweep();
    }

    /// The soft inbound reset (W2-d, RFC 2918 §3): drop the peer's
    /// Adj-RIB-In entries ahead of the re-advertisement so the
    /// rebuilt set reflects the *current* import policy — prefixes
    /// the new policy rejects (or the peer no longer sends) vanish
    /// instead of lingering.
    pub fn soft_reset_peer(&mut self, peer: &PeerInfo) {
        if let Some(rib) = self.adj_in.remove(&peer.address) {
            info!(peer = %peer.address, routes = rib.len(), "bgpd: soft inbound reset, Adj-RIB-In cleared");
        }
        self.attrs.sweep();
    }

    /// Re-run the decision process over every known prefix; returns
    /// the best-path changes (for export and re-advertisement).
    /// ADD-PATH (RFC 7911 §5): every sibling path of a prefix is a
    /// candidate — "the procedures for adding, deleting, and
    /// advertising routes are unchanged" apart from the widened key —
    /// and the Loc-RIB still elects exactly one best per prefix.
    /// Session-level events (peer clear, stale flush, soft reset);
    /// the per-UPDATE hot path is [`Self::recompute_prefix`].
    pub fn recompute(&mut self) -> Vec<BestChange> {
        // Union of the candidates' prefixes and the current best
        // table: a prefix whose every candidate vanished must still
        // produce its withdrawal change.
        let mut prefixes: Vec<IpPrefix> = self
            .adj_in
            .values()
            .flat_map(|rib| rib.values().map(|r| r.prefix))
            .chain(self.best.keys().copied())
            .collect();
        prefixes.sort();
        prefixes.dedup();
        let mut changes = Vec::new();
        for prefix in prefixes {
            changes.extend(self.recompute_prefix(prefix));
        }
        changes
    }

    /// The one-prefix half of [`Self::recompute`]: elect the best
    /// path for exactly one prefix and return its change, if any.
    /// The §9.1 decision process is per-prefix, so this is
    /// semantically identical to the bulk walk restricted to that
    /// prefix — and costs O(log n) candidate lookup (the Nlri key
    /// orders by prefix first, so each peer's Adj-RIB-In is range-
    /// scanned, never flattened). The UPDATE hot path calls this for
    /// exactly the prefixes a message touched (bench F1: the old
    /// full-table recompute per UPDATE made ingestion O(n²)); F10
    /// lever 3: candidates stay borrowed (one clone of the winner
    /// beats N clones for the election).
    ///
    /// speaker-opt lever 2 (`BGPD_FAST_ELECTION=1`, default OFF): a
    /// single-candidate fast path. `best_path` over one candidate
    /// returns it by construction (the ladder only removes
    /// candidates while more than one remains), so the generic arm's
    /// score/alive vectors and unconditional winner clone are pure
    /// overhead there — and the unchanged-destination check (the
    /// stale-ignoring [`Route::eq`], Arc pointer-shortcut) runs
    /// BEFORE any clone, making a re-announcement of the identical
    /// path allocation-free. The bulk-ingest shape (one peer, fresh
    /// prefixes) is exactly this arm; the 2026-10-28 decomposition
    /// put the sink at 1.56 s of the 4.91 s EOR window. Semantics
    /// are the generic arm's, pinned by
    /// `single_candidate_fast_path_agrees_with_bulk_recompute`.
    pub fn recompute_prefix(&mut self, prefix: IpPrefix) -> Vec<BestChange> {
        self.recompute_prefix_mode(prefix, crate::fast_election())
    }

    /// [`Self::recompute_prefix`]'s mode-switchable core (the
    /// speaker-opt lever-2 gate's testability seam: the equivalence
    /// tests drive both arms without env mutation). The fast arms
    /// early-return; every other shape falls through to the generic
    /// tail below (the F10-lever-3 body, unchanged).
    fn recompute_prefix_mode(&mut self, prefix: IpPrefix, fast: bool) -> Vec<BestChange> {
        let lo = Nlri {
            prefix,
            path_id: u32::MIN,
        };
        let hi = Nlri {
            prefix,
            path_id: u32::MAX,
        };
        let candidates: Vec<&Route> = if fast {
            let mut candidates = self
                .adj_in
                .values()
                .flat_map(|rib| rib.range(lo..=hi).map(|(_, r)| r));
            let first = candidates.next();
            let second = candidates.next();
            match (first, second) {
                // Zero candidates: the generic tail's withdrawal
                // change, reached identically.
                (None, _) => Vec::new(),
                (Some(only), None) => {
                    // Unchanged destination: no change event, no clone.
                    if self.best.get(&prefix).is_some_and(|b| *b == *only) {
                        return Vec::new();
                    }
                    let new_best = only.clone();
                    let old_best = self.best.insert(prefix, new_best.clone());
                    return vec![BestChange {
                        prefix,
                        best: Some(new_best),
                        old: old_best,
                    }];
                }
                (Some(a), Some(b)) => {
                    let mut all = vec![a, b];
                    all.extend(candidates);
                    all
                }
            }
        } else {
            self.adj_in
                .values()
                .flat_map(|rib| rib.range(lo..=hi).map(|(_, r)| r))
                .collect()
        };
        let new_best = best_path(&candidates).map(|r| (*r).clone());
        let old_best = self.best.get(&prefix).cloned();
        if new_best.as_ref() == old_best.as_ref() {
            return Vec::new();
        }
        if let Some(route) = &new_best {
            self.best.insert(prefix, route.clone());
        } else {
            self.best.remove(&prefix);
        }
        vec![BestChange {
            prefix,
            best: new_best,
            old: old_best,
        }]
    }

    pub fn best_routes(&self) -> impl Iterator<Item = &Route> {
        self.best.values()
    }

    /// PERF-M1's census view (feature `mem-census`): every Adj-RIB-In
    /// route, read-only. Feature-gated so the ungated public surface
    /// is unchanged; the census module is the only caller.
    #[cfg(feature = "mem-census")]
    pub fn census_adj_routes(&self) -> impl Iterator<Item = &Route> {
        self.adj_in.values().flat_map(|rib| rib.values())
    }

    /// PERF-M1's census view: the peer count (the adj_in fan-out).
    #[cfg(feature = "mem-census")]
    pub fn census_peer_count(&self) -> usize {
        self.adj_in.len()
    }

    pub fn route_count(&self) -> usize {
        self.adj_in.values().map(|rib| rib.len()).sum()
    }

    /// The BAR-SAV Adj-RIB-In feed snapshot (S9-a M3, the read-only
    /// edge): every stored per-peer path rendered as one feed line —
    /// `<prefix> peer <addr> path <asn>... [as-set]` — behind a
    /// header naming the format. READ-ONLY: takes the RIB lock for
    /// reading through the caller (`&self`), touches no decision
    /// state, and changes nothing on the wire; the daemon's feed
    /// writer task snapshots this on change and swaps the file
    /// atomically, and savd's `sav::barsav::parse_barsav_feed` is the
    /// consuming half (draft-ietf-sidrops-bar-sav-10 §4 Step 7/12's
    /// "unique AS_PATHs in Adj-RIBs-In of all interfaces").
    ///
    /// Deterministic by construction (the BTreeMap iteration order),
    /// so the writer's change detection is a plain string compare.
    /// AS_SEQUENCE segments flatten in wire order (leftmost = the
    /// neighbor's AS); a path carrying any AS_SET keeps its flattened
    /// sequence but gains the `as-set` marker — the consumer excludes
    /// such paths (aspa-verification §5.5 step 3), and flattening
    /// only ever happens to a path that will not be used.
    pub fn barsav_feed_text(&self) -> String {
        let mut out = String::from(
            "# bgpd BAR-SAV Adj-RIB-In feed v1\n\
             # one line per (prefix, path, peer); `as-set` marks an AS_SET path\n",
        );
        for (peer, rib) in &self.adj_in {
            for route in rib.values() {
                let mut has_set = false;
                let mut asns: Vec<u32> = Vec::new();
                if let Some(PathAttribute::AsPath(path)) = route.attr(attr_type::AS_PATH) {
                    for segment in &path.segments {
                        match segment {
                            AsSegment::Sequence(v) => asns.extend(v.iter().copied()),
                            AsSegment::Set(v) => {
                                has_set = true;
                                asns.extend(v.iter().copied());
                            }
                        }
                    }
                }
                let rendered: Vec<String> = asns.iter().map(|asn| asn.to_string()).collect();
                out.push_str(&format!(
                    "{} peer {} path {}{}\n",
                    route.prefix,
                    peer,
                    rendered.join(" "),
                    if has_set { " as-set" } else { "" }
                ));
            }
        }
        out
    }
}

/// The [`RouteSink`] that feeds the Loc-RIB: sessions call into this;
/// best-path changes flow out through the callback channel (ZAPI
/// export + Adj-RIB-Out rebuild).
pub struct RibSink {
    rib: std::sync::Arc<std::sync::Mutex<LocRib>>,
    pub changes: Vec<BestChange>,
}

impl RibSink {
    pub fn new(rib: std::sync::Arc<std::sync::Mutex<LocRib>>) -> Self {
        Self {
            rib,
            changes: Vec::new(),
        }
    }

    /// Take the accumulated best-path changes (the daemon drains this
    /// into its export paths; v1 drains after each session action via
    /// its own lock — the polling shape the savd daemon also uses).
    pub fn take_changes(&mut self) -> Vec<BestChange> {
        std::mem::take(&mut self.changes)
    }
}

impl RouteSink for RibSink {
    fn announce(&mut self, peer: &PeerInfo, update: &BgpUpdate) {
        let mut rib = self.rib.lock().unwrap();
        // Per-prefix recompute for exactly the touched prefixes (F1):
        // a rejected-by-policy prefix simply elects its unchanged
        // best and yields no change.
        let touched: Vec<IpPrefix> = update.announced().into_iter().map(|n| n.prefix).collect();
        rib.announce(peer, update);
        for prefix in touched {
            self.changes.extend(rib.recompute_prefix(prefix));
        }
    }

    fn withdraw(&mut self, peer: &PeerInfo, nlris: &[Nlri]) {
        let mut rib = self.rib.lock().unwrap();
        rib.withdraw(peer, nlris);
        for nlri in nlris {
            self.changes.extend(rib.recompute_prefix(nlri.prefix));
        }
    }

    fn clear_peer(&mut self, peer: &PeerInfo) {
        let mut rib = self.rib.lock().unwrap();
        rib.clear_peer(peer);
        self.changes.extend(rib.recompute());
    }

    fn retain_stale(&mut self, peer: &PeerInfo) {
        let mut rib = self.rib.lock().unwrap();
        rib.mark_peer_stale(peer);
        // No recompute: stale routes stay best-path candidates until
        // flushed (RFC 4724 §4.2 retention).
    }

    fn flush_stale(&mut self, peer: &PeerInfo) {
        let mut rib = self.rib.lock().unwrap();
        rib.flush_stale(peer);
        self.changes.extend(rib.recompute());
    }

    fn eor_received(&mut self, peer: &PeerInfo, afi: u16, safi: u8) {
        let _ = safi;
        let mut rib = self.rib.lock().unwrap();
        // F10: recompute exactly the flushed prefixes — nothing else
        // in the Adj-RIB-In changed, so the full-table walk per EOR
        // was pure O(peers × prefixes) burn at session-establishment
        // time (a full-table `recompute()` here was measured at
        // ~3.5 ms per EOR at N=100 peers × 100 prefixes).
        let flushed = rib.flush_stale_family(peer, Some(afi == 2));
        for prefix in flushed {
            self.changes.extend(rib.recompute_prefix(prefix));
        }
    }

    fn refresh_sent(&mut self, peer: &PeerInfo) {
        let mut rib = self.rib.lock().unwrap();
        rib.soft_reset_peer(peer);
        self.changes.extend(rib.recompute());
    }
}

/// RFC 4271 §9.2's iBGP dissemination rule with the RFC 4456 §4
/// exception — the export gate for learned routes toward one peer:
///
/// §9.2: "When a BGP speaker receives an UPDATE message from an
/// internal peer, the receiving BGP speaker SHALL NOT re-distribute
/// the routing information contained in that UPDATE message to other
/// internal peers (unless the speaker acts as a BGP Route
/// Reflector [RFC2796])."
///
/// The reflection table (RFC 4456 §4): a route learned from a
/// non-client iBGP peer reflects to CLIENTS only; a route learned
/// from a client reflects to all iBGP peers (clients and
/// non-clients). Locally-originated and eBGP-learned routes are
/// untouched by the prohibition.
pub fn ibgp_readvertisement_allowed(
    route_internal: bool,
    from_rr_client: bool,
    to_internal: bool,
    to_rr_client: bool,
) -> bool {
    if !route_internal || !to_internal {
        return true; // the prohibition covers internal → internal only
    }
    to_rr_client || from_rr_client
}

/// RFC 4271 §9.1.3's Adj-RIB-Out installation floor: "A route SHALL
/// NOT be installed in the Adj-Rib-Out unless the destination, and
/// NEXT_HOP described by this route, may be forwarded appropriately
/// by the Routing Table." The v1 shape of "forwarded appropriately":
/// the route must name a next hop its family can carry (v4 NEXT_HOP /
/// v6 MP_REACH). Full §9.1.2.1 resolvability (resolution through the
/// kernel Routing Table) is §Deferred with route next-hop resolution
/// (v1: single-hop peers only).
pub fn forwardable(route: &Route) -> bool {
    if route.attr(attr_type::NEXT_HOP).is_some() {
        return true;
    }
    // Any decoded MP_REACH carries a well-formed next hop by
    // construction (B-23: the codec rejects inconsistent lengths
    // instead of guessing a Raw shape).
    route
        .attrs
        .iter()
        .any(|attr| matches!(attr, PathAttribute::MpReach(_)))
}

/// RFC 4271 §5.1.5 (LOCAL_PREF), verified wording: "If it is contained
/// in an UPDATE message that is received from an external peer, then
/// this attribute MUST be ignored by the receiving speaker, except in
/// the case of BGP Confederations". Materialized as the FRR convention
/// (the adjudicated B-3 "reset-at-import"): the received value never
/// reaches the stored route — external imports carry the local default
/// degree of preference (100, §9.1.1: the local speaker computes it
/// from local policy, not from the peer). Applied BEFORE the import
/// policy so a route-map `set local-preference` still overrides.
/// (Sheet citation note: the LOCAL_PREF eBGP wording lives in §5.1.5;
/// §5.1.4 is MULTI_EXIT_DISC — its "MUST NOT be propagated to other
/// neighboring ASes" rule is the B-10 MED strip's citation.)
pub fn reset_external_local_pref(attrs: &mut Vec<PathAttribute>, internal: bool) {
    if internal {
        return;
    }
    attrs.retain(|a| a.attr_type() != attr_type::LOCAL_PREF);
    attrs.push(PathAttribute::LocalPref(100));
}

/// RFC 4271 §5.1.5's LOCAL_PREF shape for one exported UPDATE:
/// "SHALL be included in all UPDATE messages that a given BGP speaker
/// sends to other internal peers" and "MUST NOT include this
/// attribute in UPDATE messages it sends to external peers" — an
/// eBGP-learned route synthesizes the local degree of preference
/// (materialized as LOCAL_PREF) toward internal peers, and an
/// iBGP-learned route's LOCAL_PREF never leaks externally.
pub fn shape_local_pref(attrs: &mut Vec<PathAttribute>, internal: bool) {
    let has = attrs.iter().any(|a| a.attr_type() == attr_type::LOCAL_PREF);
    if internal && !has {
        // The §9.1.1 degree of preference this daemon materializes as
        // LOCAL_PREF (100 = the FRR-parity default).
        attrs.push(PathAttribute::LocalPref(100));
    } else if !internal && has {
        attrs.retain(|a| a.attr_type() != attr_type::LOCAL_PREF);
    }
}

/// The RS export attribute set (B-10): what a client→client
/// reflection never carries.
///
/// - **MED** — RFC 4271 §5.1.4: "The MULTI_EXIT_DISC attribute
///   received from a neighboring AS MUST NOT be propagated to other
///   neighboring ASes." Client A and client B are different ASes;
///   the origin client's MED dies at the route server.
/// - **LOCAL_PREF** — §5.1.5: "A BGP speaker MUST NOT include this
///   attribute in UPDATE messages it sends to external peers" — an
///   RS client is another AS. (The eBGP arm of
///   [`shape_local_pref`] already strips it; this is the RS-path
///   belt regardless of session-type plumbing.)
/// - **OTC** — RFC 9234: a client's OTC never re-attributes to
///   another client. The §5 ingress rule ("If a route with the OTC
///   Attribute is received from a Customer or an RS-Client, then it
///   is a route leak and MUST be considered ineligible") already
///   kills OTC-bearing client routes when roles are configured —
///   this is the export-side enforcement for role-less clients.
///   The §5 egress synthesis (OTC := local AS toward RS-Clients)
///   stays with the role machinery (§Deferred).
///
/// AS_PATH, NEXT_HOP, COMMUNITIES and the rest ride through — the
/// reflection stays transparent for everything the RFCs do not
/// forbid.
pub fn strip_rs_export_attrs(attrs: &mut Vec<PathAttribute>) {
    attrs.retain(|a| {
        !matches!(
            a.attr_type(),
            attr_type::MULTI_EXIT_DISC | attr_type::LOCAL_PREF | attr_type::OTC
        )
    });
}

/// A withdrawal as a zebra ROUTE_DELETE entry (the fixture shape: no
/// nexthops in the delete).
pub fn route_delete_entry(prefix: IpPrefix) -> RouteEntry {
    RouteEntry::new(prefix, RouteProtocol::Bgp, NexthopGroup::new(), 0)
}

/// A Loc-RIB best route as a zebra ROUTE_ADD entry (the ZAPI export
/// shape: BGP protocol, the route's next hop, main table).
pub fn route_entry(route: &Route) -> Option<RouteEntry> {
    let nh = route.next_hop_v4().map(Nexthop::Ipv4)?;
    Some(RouteEntry::new(
        route.prefix,
        RouteProtocol::Bgp,
        NexthopGroup::single(nh),
        0,
    ))
}

/// The M4 Adj-RIB-Out source: the Loc-RIB's best paths (filtered by
/// the export policy) plus the locally-originated networks.
pub struct LocRibOut {
    rib: std::sync::Arc<std::sync::Mutex<LocRib>>,
    networks: crate::peer::ConfiguredNetworks,
    policy: std::sync::Arc<dyn ExportPolicy>,
}

impl LocRibOut {
    pub fn new(
        rib: std::sync::Arc<std::sync::Mutex<LocRib>>,
        networks: crate::peer::ConfiguredNetworks,
        policy: std::sync::Arc<dyn ExportPolicy>,
    ) -> Self {
        Self {
            rib,
            networks,
            policy,
        }
    }
}

impl crate::peer::OutRib for LocRibOut {
    fn advertisements(
        &self,
        afi: u16,
        safi: u8,
        next_hop: IpAddr,
        to_peer: IpAddr,
        internal: bool,
    ) -> Vec<BgpUpdate> {
        // Locally-originated networks, gated by the export policy like
        // every other advertisement (FRR's neighbor route-map OUT
        // applies to `network` announcements too).
        let to_peer_info = PeerInfo {
            address: to_peer,
            remote_as: 0,
            bgp_id: None,
        };
        let local_as = self.rib.lock().unwrap().local_as();
        let mut updates = Vec::new();
        for update in self
            .networks
            .advertisements(afi, safi, next_hop, to_peer, internal)
        {
            let Some(prefix) = update.announced().first().map(|n| n.prefix) else {
                updates.push(update);
                continue;
            };
            // A synthetic local route: the export gate's §9.2.2 floor
            // (never reflect to the origin peer) can never trip for it
            // (unspecified source), but the typed filter applies in
            // full.
            let local = Route::new(
                prefix,
                update.attrs.clone(),
                PeerInfo {
                    address: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
                    remote_as: local_as,
                    bgp_id: None,
                },
                false,
            );
            match self.policy.export(&local, &to_peer_info, internal) {
                Some(exported) => {
                    let mut update = update;
                    // Splice the policy's edits in, keeping the
                    // NEXT_HOP/MP_REACH encoding the session layer
                    // produced (the typed model has no next-hop
                    // representation to edit).
                    let mut attrs = (*exported.attrs).clone();
                    for attr in &update.attrs {
                        if matches!(attr, PathAttribute::NextHop(_) | PathAttribute::MpReach(_)) {
                            attrs.retain(|a| a.attr_type() != attr.attr_type());
                            attrs.push(attr.clone());
                        }
                    }
                    // §5.1.5: locally-originated routes carry
                    // LOCAL_PREF toward internal peers too.
                    shape_local_pref(&mut attrs, internal);
                    update.attrs = attrs;
                    updates.push(update);
                }
                None => {
                    info!(%prefix, %to_peer, "bgpd: network not advertised (export policy)")
                }
            }
        }
        // Learned best paths: advertise to OTHER peers per policy.
        // v1 single-family guard: only v4-unicast re-advertisement is
        // wired (the smoke's shape); v6 learned paths ride their
        // MP_REACH attributes through unchanged.
        if afi == 1 && safi == 1 {
            let rib = self.rib.lock().unwrap();
            // N5 route-server mode: an RS-client target receives only
            // other clients' routes, transparently — no local-AS
            // prepend, NEXT_HOP and MED exactly as received (FRR
            // doc/user/routeserver.rst: `route-server-client`
            // "enables the transparent mode ... some BGP attributes
            // (as-path, next-hop and MED) of the routes announced to
            // that peer are not modified"; bgp_route.c's transparency
            // check requires BOTH ends to be RS clients).
            let to_is_client = rib.is_route_server_client(&to_peer);
            // RFC 4456: is the target one of OUR route-reflector
            // clients (§9.2's exception)?
            let to_is_rr_client = rib.is_route_reflector_client(&to_peer);
            for route in rib.best_routes() {
                if to_is_client && !route.rs_client {
                    continue; // "RS-clients do not receive any announce from the Main Loc-RIB"
                }
                // RFC 4271 §9.2: an iBGP-learned route is not
                // re-distributed to other internal peers — unless the
                // RFC 4456 §4 reflection table lifts it (target is a
                // client, or the route came from one).
                if !ibgp_readvertisement_allowed(
                    route.internal,
                    route.rr_client,
                    internal,
                    to_is_rr_client,
                ) {
                    continue;
                }
                // The export-policy seam (Phase 3); the default blocks
                // reflection to the origin peer.
                let Some(exported) = self.policy.export(route, &to_peer_info, internal) else {
                    continue;
                };
                // §9.1.3's floor: no Adj-RIB-Out installation without a
                // forwardable NEXT_HOP.
                if !forwardable(&exported) {
                    continue;
                }
                let mut attrs = (*exported.attrs).clone();
                // §5.1.5's LOCAL_PREF shape for the session type.
                shape_local_pref(&mut attrs, internal);
                // B-10: the RS export attribute set — a client→client
                // reflection never carries the origin client's MED,
                // LOCAL_PREF, or OTC (§5.1.4 / §5.1.5 / RFC 9234).
                if to_is_client {
                    strip_rs_export_attrs(&mut attrs);
                }
                // Phase 3 (§5.1.2): prepend the local AS on eBGP
                // re-advertisement; keep AS_PATH on iBGP. RS-client
                // targets are the exception: the reflection is
                // transparent (the client's own AS_PATH, unchanged).
                if !internal && !to_is_client {
                    if let Some(PathAttribute::AsPath(p)) = attrs
                        .iter_mut()
                        .find(|a| a.attr_type() == attr_type::AS_PATH)
                    {
                        let mut segments = p.segments.clone();
                        match segments.first_mut() {
                            Some(AsSegment::Sequence(v)) => v.insert(0, rib.local_as()),
                            _ => segments.insert(0, AsSegment::Sequence(vec![rib.local_as()])),
                        }
                        let replaced = attrs
                            .iter()
                            .position(|a| a.attr_type() == attr_type::AS_PATH);
                        if let Some(i) = replaced {
                            attrs[i] = PathAttribute::AsPath(AsPath { segments });
                        }
                    }
                }
                updates.push(BgpUpdate {
                    withdrawn: vec![],
                    attrs,
                    // Classic path id 0 at this seam: re-advertised
                    // routes get OUR encoding (RFC 7911 §2 — a
                    // re-advertiser "MUST generate its own Path
                    // Identifier"), so the per-peer allocation happens
                    // at the session send path (`PeerSession::
                    // assign_tx_path_ids`), never by leaking the id
                    // the route arrived under.
                    nlri: vec![Nlri::from(exported.prefix)],
                });
            }
        }
        updates
    }
}

/// The ZAPI egress decision for one best-path change, honoring the
/// route-server RIB separation (N5): a best path learned from an
/// RS-client never installs into the kernel — FRR's route-server
/// flavor of a view ("Routes selected by the view are not installed
/// into the kernel routing table", doc/user/bgp.rst) — while a
/// transition that replaces an installed route with an RS-only one
/// still withdraws it.
pub fn zebra_commands(change: &BestChange) -> Vec<crate::zedge::ZedgeCommand> {
    match change.best.as_ref() {
        Some(route) if route.rs_client => {
            if change.old.as_ref().is_some_and(|old| !old.rs_client) {
                vec![crate::zedge::ZedgeCommand::RouteDel(route_delete_entry(
                    change.prefix,
                ))]
            } else {
                Vec::new()
            }
        }
        Some(route) => match route_entry(route) {
            Some(entry) => vec![crate::zedge::ZedgeCommand::RouteAdd(entry)],
            None => Vec::new(),
        },
        None => {
            if change.old.as_ref().is_some_and(|old| old.rs_client) {
                Vec::new()
            } else {
                vec![crate::zedge::ZedgeCommand::RouteDel(route_delete_entry(
                    change.prefix,
                ))]
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    fn peer(addr: &str, as_: u32, id: u8) -> PeerInfo {
        PeerInfo {
            address: addr.parse().unwrap(),
            remote_as: as_,
            bgp_id: Some(Ipv4Addr::new(10, 1, 1, id)),
        }
    }

    fn route(
        prefix: &str,
        peer_info: &PeerInfo,
        internal: bool,
        attrs: Vec<PathAttribute>,
    ) -> Route {
        Route::new(prefix.parse().unwrap(), attrs, *peer_info, internal)
    }

    fn base_attrs(path: Vec<u32>, med: Option<u32>) -> Vec<PathAttribute> {
        let mut attrs = vec![
            PathAttribute::Origin(Origin::Igp),
            PathAttribute::AsPath(AsPath::sequence(path)),
            PathAttribute::NextHop("192.0.2.1".parse().unwrap()),
        ];
        if let Some(med) = med {
            attrs.push(PathAttribute::Med(med));
        }
        attrs
    }

    /// Table tests over the full §9.1.2.2 ladder. Each row: the
    /// candidates, the index that must win, and the criterion that
    /// decides it.
    #[test]
    fn ladder_local_pref_first() {
        let p = peer("192.0.2.1", 65001, 1);
        let mut a = route("203.0.113.0/24", &p, false, base_attrs(vec![65001], None));
        Arc::make_mut(&mut a.attrs).push(PathAttribute::LocalPref(50));
        let mut b = route(
            "203.0.113.0/24",
            &p,
            false,
            base_attrs(vec![65001, 65002], None),
        );
        Arc::make_mut(&mut b.attrs).push(PathAttribute::LocalPref(200));
        // Higher LOCAL_PREF wins even with a longer AS_PATH.
        assert_eq!(best_path(&[&a, &b]).unwrap().local_pref(), 200);
    }

    #[test]
    fn ladder_as_path_length_then_origin() {
        let p = peer("192.0.2.1", 65001, 1);
        let short = route("203.0.113.0/24", &p, false, base_attrs(vec![65001], None));
        let long = route(
            "203.0.113.0/24",
            &p,
            false,
            base_attrs(vec![65001, 65002], None),
        );
        assert_eq!(
            best_path(&[&long.clone(), &short.clone()])
                .unwrap()
                .as_path_len(),
            1
        );

        // Tie on length: lower ORIGIN wins (IGP=0 < EGP=1).
        let mut egp = long;
        Arc::make_mut(&mut egp.attrs)[0] = PathAttribute::Origin(Origin::Egp);
        assert_eq!(best_path(&[&egp, &short]).unwrap().origin(), Origin::Igp);
    }

    #[test]
    fn ladder_as_set_counts_one() {
        let p = peer("192.0.2.1", 65001, 1);
        let set = Route::new(
            "203.0.113.0/24".parse().unwrap(),
            vec![
                PathAttribute::Origin(Origin::Igp),
                PathAttribute::AsPath(AsPath {
                    segments: vec![
                        AsSegment::Sequence(vec![65001]),
                        AsSegment::Set(vec![1, 2, 3, 4, 5]),
                    ],
                }),
                PathAttribute::NextHop("192.0.2.1".parse().unwrap()),
            ],
            p,
            false,
        );
        let longer = route("203.0.113.0/24", &p, false, base_attrs(vec![1, 2, 3], None));
        // set path = 1 + 1 = 2 beats sequence of 3.
        assert_eq!(best_path(&[&set, &longer]).unwrap().as_path_len(), 2);
    }

    #[test]
    fn ladder_med_only_within_neighbor_as() {
        let p1 = peer("192.0.2.1", 65001, 1);
        let p2 = peer("192.0.2.2", 65002, 2);
        // Same neighbor AS 65001: lower MED wins.
        let hi = route(
            "203.0.113.0/24",
            &p1,
            false,
            base_attrs(vec![65001], Some(200)),
        );
        let lo = route(
            "203.0.113.0/24",
            &p1,
            false,
            base_attrs(vec![65001], Some(50)),
        );
        assert_eq!(best_path(&[&hi, &lo]).unwrap().med(), 50);

        // Different neighbor ASes: MED incomparable — falls through to
        // eBGP-tie (both eBGP) → BGP Identifier (10.1.1.2 > 10.1.1.1).
        let a = route(
            "203.0.113.0/24",
            &p1,
            false,
            base_attrs(vec![65001], Some(999)),
        );
        let b = route(
            "203.0.113.0/24",
            &p2,
            false,
            base_attrs(vec![65002], Some(1)),
        );
        assert_eq!(
            best_path(&[&a, &b]).unwrap().source.bgp_id,
            Some(Ipv4Addr::new(10, 1, 1, 1)),
            "MED not compared across neighbor ASes (§9.1.2.2 c)"
        );
    }

    #[test]
    fn ladder_missing_med_reads_zero() {
        let p = peer("192.0.2.1", 65001, 1);
        let with_med = route(
            "203.0.113.0/24",
            &p,
            false,
            base_attrs(vec![65001], Some(100)),
        );
        let without = route("203.0.113.0/24", &p, false, base_attrs(vec![65001], None));
        assert_eq!(
            best_path(&[&with_med, &without]).unwrap().med(),
            0,
            "absent MED is the lowest possible value"
        );
    }

    #[test]
    fn ladder_ebgp_beats_ibgp() {
        let external = peer("192.0.2.1", 65001, 1);
        let internal = peer("192.0.2.9", 65000, 9);
        // Equal AS_PATH/origin/MED so the ladder reaches step d).
        let e = route(
            "203.0.113.0/24",
            &external,
            false,
            base_attrs(vec![65001], None),
        );
        let i = route(
            "203.0.113.0/24",
            &internal,
            true,
            base_attrs(vec![65001], None),
        );
        assert!(!best_path(&[&e, &i]).unwrap().internal);
    }

    #[test]
    fn ladder_bgp_identifier_then_peer_address() {
        let p1 = peer("192.0.2.1", 65001, 9);
        let p2 = peer("192.0.2.2", 65002, 2);
        let a = route("203.0.113.0/24", &p1, false, base_attrs(vec![65001], None));
        let b = route("203.0.113.0/24", &p2, false, base_attrs(vec![65002], None));
        // Different neighbor ASes (MED skipped) → both eBGP → lowest
        // BGP Identifier (10.1.1.2) wins regardless of peer address.
        assert_eq!(
            best_path(&[&a.clone(), &b.clone()]).unwrap().source.bgp_id,
            Some(Ipv4Addr::new(10, 1, 1, 2))
        );

        // Identical IDs (different ASes, equal paths): lowest peer
        // address (§9.1.2.2 g).
        let same_id_a = Route {
            source: Arc::new(PeerInfo {
                bgp_id: Some(Ipv4Addr::new(10, 1, 1, 5)),
                ..*a.source
            }),
            ..a
        };
        let same_id_b = Route {
            source: Arc::new(PeerInfo {
                bgp_id: Some(Ipv4Addr::new(10, 1, 1, 5)),
                ..*b.source
            }),
            ..b
        };
        assert_eq!(
            best_path(&[&same_id_a, &same_id_b]).unwrap().source.address,
            "192.0.2.1".parse::<IpAddr>().unwrap()
        );
    }

    #[test]
    fn best_path_empty_is_none() {
        assert!(best_path(&[]).is_none());
    }

    #[test]
    fn incremental_recompute_matches_bulk() {
        // F1's equivalence bar: driving the UPDATE hot path through
        // recompute_prefix (per touched prefix) lands the same best
        // table and the same change stream as the bulk recompute.
        let mut bulk = LocRib::new(65000);
        let mut incr = LocRib::new(65000);
        let p1 = peer("192.0.2.1", 65001, 1);
        let p2 = peer("192.0.2.2", 65002, 2);
        let px: Vec<IpPrefix> = ["203.0.113.0/24", "198.51.100.0/24", "192.0.2.128/25"]
            .iter()
            .map(|s| s.parse().unwrap())
            .collect();

        let mut bulk_changes = Vec::new();
        let mut incr_changes = Vec::new();

        // Step 1: p1 announces all three.
        let u1 = BgpUpdate {
            attrs: base_attrs(vec![65001], None),
            nlri: px.iter().map(|p| Nlri::from(*p)).collect(),
            ..Default::default()
        };
        bulk.announce(&p1, &u1);
        bulk_changes.extend(bulk.recompute());
        incr.announce(&p1, &u1);
        for p in &px {
            incr_changes.extend(incr.recompute_prefix(*p));
        }

        // Step 2: p2 announces a shorter path for the middle prefix.
        let u2 = BgpUpdate {
            attrs: base_attrs(vec![], None),
            nlri: vec![Nlri::from(px[1])],
            ..Default::default()
        };
        bulk.announce(&p2, &u2);
        bulk_changes.extend(bulk.recompute());
        incr.announce(&p2, &u2);
        incr_changes.extend(incr.recompute_prefix(px[1]));

        // Step 3: p2 withdraws → the best falls back to p1.
        let nlri2 = Nlri::from(px[1]);
        bulk.withdraw(&p2, &[nlri2]);
        bulk_changes.extend(bulk.recompute());
        incr.withdraw(&p2, &[nlri2]);
        incr_changes.extend(incr.recompute_prefix(px[1]));

        // Step 4: p1 withdraws everything → all prefixes vanish.
        let nlris: Vec<Nlri> = px.iter().map(|p| Nlri::from(*p)).collect();
        bulk.withdraw(&p1, &nlris);
        bulk_changes.extend(bulk.recompute());
        incr.withdraw(&p1, &nlris);
        for p in &px {
            incr_changes.extend(incr.recompute_prefix(*p));
        }

        assert_eq!(bulk.best, incr.best, "same best table");
        // The streams carry the same changes; within one batch the
        // bulk walk yields them in sorted-prefix order while the
        // incremental path follows message order — no consumer
        // observes within-batch ordering, so compare canonically.
        let mut bulk_sorted = bulk_changes;
        let mut incr_sorted = incr_changes;
        bulk_sorted.sort_by_key(|c| c.prefix);
        incr_sorted.sort_by_key(|c| c.prefix);
        assert_eq!(bulk_sorted, incr_sorted, "same change stream");
        assert!(bulk.best.is_empty(), "everything withdrawn");
    }

    #[test]
    fn single_candidate_fast_path_agrees_with_bulk_recompute() {
        // speaker-opt lever 2's equivalence bar (the F1
        // incremental_recompute_matches_bulk shape): the
        // BGPD_FAST_ELECTION single-candidate arm lands the same best
        // table and the same change stream as the bulk recompute —
        // across fresh insert, identical re-announcement (the
        // unchanged-destination arm: no change, no clone), contested
        // prefixes (two candidates → the generic arm), replacement,
        // and withdrawal.
        let mut bulk = LocRib::new(65000);
        let mut fast = LocRib::new(65000);
        let p1 = peer("192.0.2.1", 65001, 1);
        let p2 = peer("192.0.2.2", 65002, 2);
        let px: Vec<IpPrefix> = ["203.0.113.0/24", "198.51.100.0/24", "192.0.2.128/25"]
            .iter()
            .map(|s| s.parse().unwrap())
            .collect();

        let mut bulk_changes = Vec::new();
        let mut fast_changes = Vec::new();

        // Step 1: p1 announces all three — the single-candidate bulk
        // shape (fresh prefixes).
        let u1 = BgpUpdate {
            attrs: base_attrs(vec![65001], None),
            nlri: px.iter().map(|p| Nlri::from(*p)).collect(),
            ..Default::default()
        };
        bulk.announce(&p1, &u1);
        bulk_changes.extend(bulk.recompute());
        fast.announce(&p1, &u1);
        for p in &px {
            fast_changes.extend(fast.recompute_prefix_mode(*p, true));
        }

        // Step 2: p1 re-announces one prefix IDENTICALLY — the
        // unchanged-destination arm must yield no change at all.
        let u1b = BgpUpdate {
            attrs: base_attrs(vec![65001], None),
            nlri: vec![Nlri::from(px[0])],
            ..Default::default()
        };
        bulk.announce(&p1, &u1b);
        bulk_changes.extend(bulk.recompute());
        fast.announce(&p1, &u1b);
        let before = fast_changes.len();
        fast_changes.extend(fast.recompute_prefix_mode(px[0], true));
        assert_eq!(fast_changes.len(), before, "identical re-announce is quiet");

        // Step 3: p2 announces a shorter path for the middle prefix —
        // two candidates, the generic arm under the flag.
        let u2 = BgpUpdate {
            attrs: base_attrs(vec![], None),
            nlri: vec![Nlri::from(px[1])],
            ..Default::default()
        };
        bulk.announce(&p2, &u2);
        bulk_changes.extend(bulk.recompute());
        fast.announce(&p2, &u2);
        fast_changes.extend(fast.recompute_prefix_mode(px[1], true));

        // Step 4: p2 withdraws → the best falls back to p1.
        let nlri2 = Nlri::from(px[1]);
        bulk.withdraw(&p2, &[nlri2]);
        bulk_changes.extend(bulk.recompute());
        fast.withdraw(&p2, &[nlri2]);
        fast_changes.extend(fast.recompute_prefix_mode(px[1], true));

        // Step 5: p1 withdraws everything → all prefixes vanish (the
        // zero-candidate withdrawal arm).
        let nlris: Vec<Nlri> = px.iter().map(|p| Nlri::from(*p)).collect();
        bulk.withdraw(&p1, &nlris);
        bulk_changes.extend(bulk.recompute());
        fast.withdraw(&p1, &nlris);
        for p in &px {
            fast_changes.extend(fast.recompute_prefix_mode(*p, true));
        }

        assert_eq!(bulk.best, fast.best, "same best table");
        let mut bulk_sorted = bulk_changes;
        let mut fast_sorted = fast_changes;
        bulk_sorted.sort_by_key(|c| c.prefix);
        fast_sorted.sort_by_key(|c| c.prefix);
        assert_eq!(bulk_sorted, fast_sorted, "same change stream");
        assert!(bulk.best.is_empty(), "everything withdrawn");
    }

    #[test]
    fn loc_rib_recompute_tracks_best_changes() {
        let mut rib = LocRib::new(65000);
        let p1 = peer("192.0.2.1", 65001, 1);
        let p2 = peer("192.0.2.2", 65002, 2);

        let u1 = BgpUpdate {
            attrs: base_attrs(vec![65001], None),
            nlri: vec!["203.0.113.0/24".parse().unwrap()],
            ..Default::default()
        };
        rib.announce(&p1, &u1);
        let changes = rib.recompute();
        assert_eq!(changes.len(), 1);
        assert_eq!(changes[0].best.as_ref().unwrap().source.address, p1.address);

        // A better path (shorter) from p2 flips the best.
        let u2 = BgpUpdate {
            attrs: base_attrs(vec![], None),
            nlri: vec!["203.0.113.0/24".parse().unwrap()],
            ..Default::default()
        };
        rib.announce(&p2, &u2);
        let changes = rib.recompute();
        assert_eq!(changes.len(), 1, "best flipped");
        assert_eq!(changes[0].best.as_ref().unwrap().source.address, p2.address);

        // Peer teardown withdraws.
        rib.clear_peer(&p2);
        let changes = rib.recompute();
        assert_eq!(changes.len(), 1);
        assert_eq!(changes[0].best.as_ref().unwrap().source.address, p1.address);
        rib.clear_peer(&p1);
        let changes = rib.recompute();
        assert_eq!(changes.len(), 1);
        assert!(changes[0].best.is_none(), "fully withdrawn");
    }

    #[test]
    fn loc_rib_recompute_is_quiet_without_changes() {
        let mut rib = LocRib::new(65000);
        let p = peer("192.0.2.1", 65001, 1);
        let u = BgpUpdate {
            attrs: base_attrs(vec![65001], None),
            nlri: vec!["203.0.113.0/24".parse().unwrap()],
            ..Default::default()
        };
        rib.announce(&p, &u);
        rib.recompute();
        assert!(rib.recompute().is_empty(), "no change, no event");
    }

    // ---- PERF-M1 M2: attribute interning -----------------------------

    /// Identical tuples intern to one shared allocation (the census's
    /// 6.02× duplication collapses), and the elected best shares the
    /// same instance — the best table's deep copy is gone.
    #[test]
    fn interned_attrs_share_one_allocation() {
        let mut rib = LocRib::new(65000);
        let p = peer("192.0.2.1", 65001, 1);
        let u1 = BgpUpdate {
            attrs: base_attrs(vec![65001, 65002], Some(50)),
            nlri: vec!["203.0.113.0/24".parse::<IpPrefix>().unwrap().into()],
            ..Default::default()
        };
        let mut u2 = u1.clone();
        u2.nlri = vec!["198.51.100.0/24".parse::<IpPrefix>().unwrap().into()];
        rib.announce(&p, &u1);
        rib.announce(&p, &u2);
        rib.recompute();
        let r1 = rib.adj_in[&p.address]
            .get(&path_nlri("203.0.113.0/24", 0))
            .unwrap();
        let r2 = rib.adj_in[&p.address]
            .get(&path_nlri("198.51.100.0/24", 0))
            .unwrap();
        assert!(
            Arc::ptr_eq(&r1.attrs, &r2.attrs),
            "equal tuples across UPDATEs share the interned instance"
        );
        let best = rib.best_routes().next().unwrap();
        assert!(
            r1.attrs.iter().any(|a| a.attr_type() == attr_type::AS_PATH)
                && r2
                    .attrs
                    .iter()
                    .any(|a| a.attr_type() == attr_type::LOCAL_PREF),
            "B-3's LOCAL_PREF 100 reset is part of the interned tuple"
        );
        assert_eq!(best.med(), 50, "shared attrs still read per-route");
        assert_eq!(rib.attrs.len(), 1, "one distinct tuple in the table");
    }

    /// The sweep drops tuples no stored route references (bulk peer
    /// clear) and keeps the ones still live.
    #[test]
    fn interner_sweep_drops_dead_tuples() {
        let mut rib = LocRib::new(65000);
        let p1 = peer("192.0.2.1", 65001, 1);
        let p2 = peer("192.0.2.2", 65002, 2);
        rib.announce(
            &p1,
            &BgpUpdate {
                attrs: base_attrs(vec![65001], Some(10)),
                nlri: vec!["203.0.113.0/24".parse::<IpPrefix>().unwrap().into()],
                ..Default::default()
            },
        );
        rib.announce(
            &p2,
            &BgpUpdate {
                attrs: base_attrs(vec![65002], Some(20)),
                nlri: vec!["198.51.100.0/24".parse::<IpPrefix>().unwrap().into()],
                ..Default::default()
            },
        );
        assert_eq!(rib.attrs.len(), 2);
        rib.clear_peer(&p1);
        assert_eq!(rib.attrs.len(), 1, "p1's tuple swept with its routes");
        assert_eq!(rib.route_count(), 1);
    }

    /// Copy-on-write: mutating a stored route's attributes (the policy
    /// engine's set-actions) forks the tuple instead of corrupting
    /// every sharer.
    #[test]
    fn attr_mutation_forks_the_shared_tuple() {
        let mut rib = LocRib::new(65000);
        let p = peer("192.0.2.1", 65001, 1);
        let shared = Arc::new(base_attrs(vec![65001], None));
        let mk = |prefix: &str| BgpUpdate {
            attrs: (*shared).clone(),
            nlri: vec![prefix.parse::<IpPrefix>().unwrap().into()],
            ..Default::default()
        };
        rib.announce(&p, &mk("203.0.113.0/24"));
        rib.announce(&p, &mk("198.51.100.0/24"));
        let r1 = rib.adj_in[&p.address]
            .get(&path_nlri("203.0.113.0/24", 0))
            .unwrap();
        let r2 = rib.adj_in[&p.address]
            .get(&path_nlri("198.51.100.0/24", 0))
            .unwrap();
        assert!(Arc::ptr_eq(&r1.attrs, &r2.attrs));
        let mut forked = r1.clone();
        Arc::make_mut(&mut forked.attrs).push(PathAttribute::Med(42));
        assert_ne!(forked.med(), r2.med(), "the fork does not leak to r2");
        assert!(Arc::ptr_eq(&r1.attrs, &r2.attrs), "originals still shared");
    }

    /// PERF-M1 M3: one shared PeerInfo per peer — every stored route
    /// of a session points at the same instance.
    #[test]
    fn peer_info_is_shared_per_peer() {
        let mut rib = LocRib::new(65000);
        let p = peer("192.0.2.1", 65001, 1);
        let u1 = BgpUpdate {
            attrs: base_attrs(vec![65001], Some(10)),
            nlri: vec!["203.0.113.0/24".parse::<IpPrefix>().unwrap().into()],
            ..Default::default()
        };
        let mut u2 = u1.clone();
        u2.attrs = base_attrs(vec![65001, 65002], None);
        u2.nlri = vec!["198.51.100.0/24".parse::<IpPrefix>().unwrap().into()];
        rib.announce(&p, &u1);
        rib.announce(&p, &u2);
        let r1 = rib.adj_in[&p.address]
            .get(&path_nlri("203.0.113.0/24", 0))
            .unwrap();
        let r2 = rib.adj_in[&p.address]
            .get(&path_nlri("198.51.100.0/24", 0))
            .unwrap();
        assert!(
            Arc::ptr_eq(&r1.source, &r2.source),
            "routes of one peer share the PeerInfo instance"
        );
        assert_eq!(r1.source.address, p.address, "readers deref unchanged");
        // A re-announcement with changed session facts (new BGP
        // Identifier) re-pins the shared instance for new routes.
        let renewed = PeerInfo {
            bgp_id: Some(Ipv4Addr::new(10, 9, 9, 9)),
            ..p
        };
        rib.announce(&renewed, &u1);
        let r1b = rib.adj_in[&p.address]
            .get(&path_nlri("203.0.113.0/24", 0))
            .unwrap();
        assert_eq!(r1b.source.bgp_id, Some(Ipv4Addr::new(10, 9, 9, 9)));
    }

    // ---- RFC 7911 ADD-PATH receive semantics (N5B) ------------------

    fn path_update(prefix: &str, path_id: u32, med: Option<u32>) -> BgpUpdate {
        BgpUpdate {
            attrs: base_attrs(vec![65001], med),
            nlri: vec![Nlri {
                prefix: prefix.parse().unwrap(),
                path_id,
            }],
            ..Default::default()
        }
    }

    fn path_nlri(prefix: &str, path_id: u32) -> Nlri {
        Nlri {
            prefix: prefix.parse().unwrap(),
            path_id,
        }
    }

    /// RFC 7911 §5: the replacement key widens to (prefix, path-id) —
    /// sibling paths from ONE peer coexist (no implicit replacement),
    /// a re-advertisement of the same key replaces, and a per-path
    /// withdrawal leaves the sibling alone.
    #[test]
    fn add_path_siblings_coexist_and_replace_by_key() {
        let mut rib = LocRib::new(65000);
        // Internal peer: the raise below rides LOCAL_PREF 200, which
        // B-3 (§5.1.5) now ignores from external peers.
        let p = peer("192.0.2.1", 65000, 1);
        rib.announce(&p, &path_update("203.0.113.0/24", 1, None));
        rib.announce(&p, &path_update("203.0.113.0/24", 2, None));
        assert_eq!(rib.route_count(), 2, "two sibling paths coexist");
        rib.recompute();
        assert_eq!(rib.best_routes().count(), 1, "one best per prefix");

        // Same (prefix, path-id): replaces, not a third entry — and
        // the replacement's new attributes surface as a best-path
        // event (the winner is still path 1, raised by LOCAL_PREF).
        let mut better = path_update("203.0.113.0/24", 1, None);
        better.attrs.push(PathAttribute::LocalPref(200));
        rib.announce(&p, &better);
        assert_eq!(rib.route_count(), 2);
        let changes = rib.recompute();
        assert_eq!(changes.len(), 1, "the best route's attrs changed");
        assert_eq!(changes[0].best.as_ref().unwrap().path_id, 1);

        // Withdrawing path 1 leaves path 2.
        rib.withdraw(&p, &[path_nlri("203.0.113.0/24", 1)]);
        assert_eq!(rib.route_count(), 1);
        let changes = rib.recompute();
        assert_eq!(changes.len(), 1, "the best may flip to the sibling");
        assert_eq!(changes[0].best.as_ref().unwrap().path_id, 2);
    }

    /// §5's SHOULD: "withdraw a prefix with a Path Identifier not seen
    /// before → silently ignore" — an unseen key is a no-op (and a
    /// CLASSIC withdrawal of a prefix stored only under path ids hits
    /// the same rule: key (prefix, 0) was never announced).
    #[test]
    fn add_path_withdraw_unseen_key_silently_ignored() {
        let mut rib = LocRib::new(65000);
        let p = peer("192.0.2.1", 65001, 1);
        rib.announce(&p, &path_update("203.0.113.0/24", 5, None));
        rib.recompute();
        rib.withdraw(&p, &[path_nlri("203.0.113.0/24", 99)]);
        assert_eq!(rib.route_count(), 1, "unseen path id ignored");
        rib.withdraw(&p, &[path_nlri("203.0.113.0/24", 0)]);
        assert_eq!(rib.route_count(), 1, "classic key never announced");
        assert!(rib.recompute().is_empty(), "no best-path effect");
        // The real key still withdraws cleanly.
        rib.withdraw(&p, &[path_nlri("203.0.113.0/24", 5)]);
        assert_eq!(rib.route_count(), 0);
        assert!(rib.recompute()[0].best.is_none());
    }

    /// §5: "the procedures ... are otherwise unchanged" — sibling
    /// paths are ordinary decision candidates; best_path picks by the
    /// §9.1.2.2 ladder (MED here), the Loc-RIB keeps exactly one best
    /// per prefix, and per-path withdrawal can flip it.
    #[test]
    fn add_path_siblings_are_decision_candidates() {
        let mut rib = LocRib::new(65000);
        let p = peer("192.0.2.1", 65001, 1);
        rib.announce(&p, &path_update("203.0.113.0/24", 1, Some(200)));
        rib.announce(&p, &path_update("203.0.113.0/24", 2, Some(10)));
        let changes = rib.recompute();
        assert_eq!(changes.len(), 1);
        assert_eq!(changes[0].best.as_ref().unwrap().path_id, 2, "lower MED");
        // Losing the winner flips the best to the sibling.
        rib.withdraw(&p, &[path_nlri("203.0.113.0/24", 2)]);
        let changes = rib.recompute();
        assert_eq!(changes.len(), 1);
        assert_eq!(changes[0].best.as_ref().unwrap().path_id, 1);
        // Sibling paths from two peers mix into one candidate set.
        let q = peer("192.0.2.2", 65002, 2);
        rib.announce(&q, &path_update("203.0.113.0/24", 7, Some(500)));
        let changes = rib.recompute();
        assert_eq!(changes.len(), 0, "existing best (MED 200) still wins");
        assert_eq!(rib.route_count(), 2);
    }

    #[test]
    fn withdrawal_removes_the_prefix() {
        let mut rib = LocRib::new(65000);
        let p = peer("192.0.2.1", 65001, 1);
        rib.announce(
            &p,
            &BgpUpdate {
                attrs: base_attrs(vec![65001], None),
                nlri: vec!["203.0.113.0/24".parse().unwrap()],
                ..Default::default()
            },
        );
        rib.recompute();
        rib.withdraw(&p, &["203.0.113.0/24".parse().unwrap()]);
        let changes = rib.recompute();
        assert_eq!(changes.len(), 1);
        assert!(changes[0].best.is_none());
        assert_eq!(rib.route_count(), 0);
    }

    #[test]
    fn route_entry_exports_bgp_nexthop() {
        let p = peer("192.0.2.1", 65001, 1);
        let r = route("203.0.113.0/24", &p, false, base_attrs(vec![65001], None));
        let entry = route_entry(&r).unwrap();
        assert_eq!(entry.prefix.to_string(), "203.0.113.0/24");
        assert_eq!(entry.protocol, RouteProtocol::Bgp);
    }

    /// The W2-d soft inbound reset (RFC 2918 §3): refreshing clears
    /// the peer's Adj-RIB-In so a re-advertisement the (new) import
    /// policy still rejects cannot linger from the old one.
    #[test]
    fn soft_reset_drops_stale_adj_rib_in_entries() {
        let mut rib = LocRib::new(65000);
        let p = peer("192.0.2.1", 65001, 1);
        rib.announce(
            &p,
            &BgpUpdate {
                attrs: base_attrs(vec![65001], None),
                nlri: vec!["203.0.113.0/24".parse().unwrap()],
                ..Default::default()
            },
        );
        rib.recompute();
        assert_eq!(rib.route_count(), 1);
        rib.soft_reset_peer(&p);
        assert_eq!(rib.route_count(), 0, "Adj-RIB-In cleared");
        let changes = rib.recompute();
        assert_eq!(changes.len(), 1);
        assert!(
            changes[0].best.is_none(),
            "best withdrawn until re-advertised"
        );
        // The re-advertisement re-populates (the RFC 2918 round trip).
        rib.announce(
            &p,
            &BgpUpdate {
                attrs: base_attrs(vec![65001], None),
                nlri: vec!["203.0.113.0/24".parse().unwrap()],
                ..Default::default()
            },
        );
        assert!(rib.recompute()[0].best.is_some());
    }

    #[test]
    fn export_policy_default_blocks_reflection() {
        let p = peer("192.0.2.1", 65001, 1);
        let r = route("203.0.113.0/24", &p, false, base_attrs(vec![65001], None));
        assert!(
            AcceptAll.export(&r, &p, false).is_none(),
            "never reflect to origin"
        );
        let other = peer("192.0.2.2", 65002, 2);
        assert!(AcceptAll.export(&r, &other, false).is_some());
    }

    // ---- N5: route-server mode --------------------------------------

    /// An RS-client's routes carry the rs_client flag; the reflection
    /// toward another client is transparent — the client's own
    /// AS_PATH and NEXT_HOP unchanged, no local-AS prepend — and the
    /// B-10 RS export set (MED / LOCAL_PREF / OTC) is stripped.
    #[test]
    fn route_server_reflection_is_transparent() {
        let mut rib = LocRib::new(65000);
        let client_a = peer("192.0.2.101", 65001, 1);
        let client_b_addr: IpAddr = "192.0.2.102".parse().unwrap();
        rib.set_route_server_clients(vec![client_a.address, client_b_addr]);
        let mut attrs = base_attrs(vec![65001], Some(42));
        attrs.push(PathAttribute::LocalPref(200));
        attrs.push(PathAttribute::Otc(65001));
        rib.announce(
            &client_a,
            &BgpUpdate {
                attrs,
                nlri: vec!["203.0.113.0/24".parse().unwrap()],
                ..Default::default()
            },
        );
        assert!(rib.recompute()[0].best.as_ref().unwrap().rs_client);

        let out = LocRibOut::new(
            Arc::new(Mutex::new(rib)),
            crate::peer::ConfiguredNetworks::new(65000, vec![]),
            Arc::new(AcceptAll),
        );
        let updates = crate::peer::OutRib::advertisements(
            &out,
            1,
            1,
            "10.0.0.1".parse().unwrap(), // the RS's own address — must NOT be used
            client_b_addr,
            false, // eBGP session
        );
        assert_eq!(updates.len(), 1);
        let update = &updates[0];
        let path = update.as_path().unwrap();
        assert_eq!(path.path_length(), 1, "no RS AS prepended");
        assert!(
            !path
                .segments
                .iter()
                .any(|s| matches!(s, AsSegment::Sequence(v) if v.contains(&65000))),
            "the RS's own AS never enters the reflected path"
        );
        assert_eq!(
            update.attr(attr_type::NEXT_HOP),
            Some(&PathAttribute::NextHop("192.0.2.1".parse().unwrap())),
            "the origin client's next hop preserved"
        );
        // B-10: §5.1.4 ("MUST NOT be propagated to other neighboring
        // ASes"), §5.1.5 ("MUST NOT include this attribute ... to
        // external peers"), RFC 9234 (never re-attribute a client's
        // OTC to another client).
        assert_eq!(
            update.attr(attr_type::MULTI_EXIT_DISC),
            None,
            "MED stripped"
        );
        assert_eq!(
            update.attr(attr_type::LOCAL_PREF),
            None,
            "LOCAL_PREF stripped"
        );
        assert_eq!(update.attr(attr_type::OTC), None, "OTC stripped");
    }

    /// The strip itself, purely: the three RS export attributes go,
    /// everything else stays.
    #[test]
    fn rs_export_strip_set() {
        let mut attrs = base_attrs(vec![65001], Some(42));
        attrs.push(PathAttribute::LocalPref(200));
        attrs.push(PathAttribute::Otc(65001));
        attrs.push(PathAttribute::Communities(vec![0x00_02_00_01]));
        strip_rs_export_attrs(&mut attrs);
        assert!(attrs.iter().any(|a| matches!(a, PathAttribute::Origin(_))));
        assert!(attrs.iter().any(|a| matches!(a, PathAttribute::AsPath(_))));
        assert!(attrs.iter().any(|a| matches!(a, PathAttribute::NextHop(_))));
        assert!(attrs
            .iter()
            .any(|a| matches!(a, PathAttribute::Communities(_))));
        assert!(!attrs
            .iter()
            .any(|a| a.attr_type() == attr_type::MULTI_EXIT_DISC));
        assert!(!attrs.iter().any(|a| a.attr_type() == attr_type::LOCAL_PREF));
        assert!(!attrs.iter().any(|a| a.attr_type() == attr_type::OTC));
    }

    /// The origin-peer floor survives RS mode (no reflect back), an
    /// RS-client target does not receive non-client routes (v1: no
    /// per-client RIBs — FRR's route-server-maps stay §Deferred), and
    /// a normal peer still gets the client's route with the local AS
    /// prepended (the Main Loc-RIB path).
    #[test]
    fn route_server_scoping_floors_and_normal_peers() {
        let mut rib = LocRib::new(65000);
        let client_a = peer("192.0.2.101", 65001, 1);
        let client_b_addr: IpAddr = "192.0.2.102".parse().unwrap();
        let third_addr: IpAddr = "192.0.2.10".parse().unwrap();
        rib.set_route_server_clients(vec![client_a.address, client_b_addr]);
        rib.announce(
            &client_a,
            &BgpUpdate {
                attrs: base_attrs(vec![65001], None),
                nlri: vec!["203.0.113.0/24".parse().unwrap()],
                ..Default::default()
            },
        );
        // A normal-peer route in the table too.
        let normal_peer = peer("192.0.2.9", 65009, 9);
        rib.announce(
            &normal_peer,
            &BgpUpdate {
                attrs: base_attrs(vec![65009], None),
                nlri: vec!["198.51.100.0/24".parse().unwrap()],
                ..Default::default()
            },
        );
        rib.recompute();

        let out = LocRibOut::new(
            Arc::new(Mutex::new(rib)),
            crate::peer::ConfiguredNetworks::new(65000, vec![]),
            Arc::new(AcceptAll),
        );
        // Back to the origin client: nothing.
        assert!(
            crate::peer::OutRib::advertisements(
                &out,
                1,
                1,
                "10.0.0.1".parse().unwrap(),
                client_a.address,
                false
            )
            .is_empty(),
            "never reflect to the origin peer"
        );
        // To the other client: only the client route, not the normal
        // peer's.
        let to_client = crate::peer::OutRib::advertisements(
            &out,
            1,
            1,
            "10.0.0.1".parse().unwrap(),
            client_b_addr,
            false,
        );
        assert_eq!(to_client.len(), 1);
        assert_eq!(to_client[0].nlri, vec!["203.0.113.0/24".parse().unwrap()]);
        // To a third (normal, non-client) peer: both routes, the
        // client's path prepended with the RS AS (the Main Loc-RIB
        // path — the normal peer's own route is reflected there too).
        let to_normal = crate::peer::OutRib::advertisements(
            &out,
            1,
            1,
            "10.0.0.1".parse().unwrap(),
            third_addr,
            false,
        );
        assert_eq!(to_normal.len(), 2);
        let reflected = to_normal
            .iter()
            .find(|u| u.nlri == vec!["203.0.113.0/24".parse().unwrap()])
            .unwrap();
        assert_eq!(reflected.as_path().unwrap().path_length(), 2);
        assert!(reflected
            .as_path()
            .unwrap()
            .neighbor_as()
            .is_some_and(|a| a == 65001));
    }

    /// RFC 4724 §4.2 stale lifecycle: a lost GR session retains the
    /// routes marked stale (still best-path candidates); a
    /// re-advertised prefix replaces its stale entry; the per-family
    /// EOR flush removes only that family's leftovers; a full flush
    /// removes the rest.
    #[test]
    fn graceful_restart_stale_lifecycle() {
        let mut rib = LocRib::new(65000);
        let p = peer("192.0.2.1", 65001, 1);
        let u4 = |pfx: &str| BgpUpdate {
            attrs: base_attrs(vec![65001], None),
            nlri: vec![pfx.parse().unwrap()],
            ..Default::default()
        };
        let u6 = |pfx: &str| BgpUpdate {
            attrs: vec![
                PathAttribute::Origin(Origin::Igp),
                PathAttribute::AsPath(AsPath::sequence([65001])),
                PathAttribute::MpReach(crate::attr::MpReach {
                    afi: 2,
                    safi: 1,
                    next_hop: crate::attr::MpNextHop::V6 {
                        global: "2001:db8::1".parse().unwrap(),
                        link_local: None,
                    },
                    nlri: vec![pfx.parse().unwrap()],
                }),
            ],
            ..Default::default()
        };
        rib.announce(&p, &u4("203.0.113.0/24"));
        rib.announce(&p, &u4("198.51.100.0/24"));
        rib.announce(&p, &u6("2001:db8:1::/48"));
        rib.recompute();

        // Session lost: everything goes stale, nothing deleted.
        rib.mark_peer_stale(&p);
        assert_eq!(rib.stale_count(&p), 3);
        assert_eq!(rib.route_count(), 3, "retained, not deleted");
        assert!(rib.recompute().is_empty(), "best paths unchanged");

        // The peer returns: one prefix re-advertised (its stale entry
        // is replaced wholesale), then the v4 EOR flushes the rest of
        // v4 — the v6 route stays until its own EOR.
        rib.announce(&p, &u4("203.0.113.0/24"));
        assert_eq!(rib.stale_count(&p), 2, "re-advertised prefix is fresh");
        rib.flush_stale_family(&p, Some(false));
        assert_eq!(rib.route_count(), 2, "stale v4 flushed, v6 retained");
        assert_eq!(rib.stale_count(&p), 1);

        // The v6 EOR (or the restart timer) takes the rest.
        let changes = {
            rib.flush_stale_family(&p, Some(true));
            rib.recompute()
        };
        assert_eq!(rib.route_count(), 1, "only the re-advertised route left");
        assert_eq!(
            changes.iter().filter(|c| c.best.is_none()).count(),
            2,
            "the flushed stale bests withdrew"
        );

        // Re-establishment without the R bit: flush_stale sweeps all.
        rib.mark_peer_stale(&p);
        assert_eq!(rib.stale_count(&p), 1);
        rib.flush_stale(&p);
        assert_eq!(rib.route_count(), 0);
    }

    /// RibSink drives the same lifecycle through the RouteSink hooks
    /// the session calls.
    #[test]
    fn rib_sink_graceful_restart_hooks() {
        let rib = Arc::new(std::sync::Mutex::new(LocRib::new(65000)));
        let mut sink = RibSink::new(Arc::clone(&rib));
        let p = peer("192.0.2.1", 65001, 1);
        sink.announce(
            &p,
            &BgpUpdate {
                attrs: base_attrs(vec![65001], None),
                nlri: vec!["203.0.113.0/24".parse().unwrap()],
                ..Default::default()
            },
        );
        // Session lost with GR: retained stale, not cleared.
        sink.retain_stale(&p);
        assert_eq!(rib.lock().unwrap().route_count(), 1);
        assert_eq!(rib.lock().unwrap().stale_count(&p), 1);
        // Re-established without the R bit: flushed, best withdrawn.
        sink.flush_stale(&p);
        assert_eq!(rib.lock().unwrap().route_count(), 0);
        assert!(!sink.take_changes().is_empty());
        // The EOR hook routes per-family flushes.
        sink.announce(
            &p,
            &BgpUpdate {
                attrs: base_attrs(vec![65001], None),
                nlri: vec!["198.51.100.0/24".parse().unwrap()],
                ..Default::default()
            },
        );
        sink.retain_stale(&p);
        sink.eor_received(&p, 1, 1);
        assert_eq!(rib.lock().unwrap().route_count(), 0, "v4 EOR flushed it");
    }

    /// RFC 4724 §4.1's forwarding window: routes retained stale at a
    /// GR session loss stay best-path candidates ("MUST NOT
    /// differentiate between stale and other information during
    /// forwarding") — recompute produces NO withdrawal, so nothing
    /// reaches `zebra_commands` and the kernel keeps forwarding
    /// through the grace window.
    #[test]
    fn restart_window_preserves_forwarding() {
        let mut rib = LocRib::new(65000);
        let p = peer("192.0.2.1", 65001, 1);
        rib.announce(
            &p,
            &BgpUpdate {
                attrs: base_attrs(vec![65001], None),
                nlri: vec!["203.0.113.0/24".parse().unwrap()],
                ..Default::default()
            },
        );
        let changes = rib.recompute();
        assert_eq!(changes.len(), 1);
        assert!(changes[0].best.as_ref().is_some());

        // The session is lost and the routes retained stale: no
        // withdrawal — the best survives untouched (§4.1).
        rib.mark_peer_stale(&p);
        assert_eq!(rib.stale_count(&p), 1);
        let changes = rib.recompute();
        assert!(
            changes.is_empty(),
            "stale retention produces no best-path change (RFC 4724 §4.1)"
        );
        // The best table itself is untouched — the snapshot from
        // before the loss keeps exporting (that non-differentiation
        // IS §4.1's rule).
        let best = rib.best_routes().next().unwrap();
        assert_eq!(best.source.address, p.address);
        assert!(
            route_entry(best).is_some(),
            "still exportable — forwarding continues"
        );
    }

    // ---- RFC 4271 §9.2 / RFC 4456: iBGP dissemination (S7-b) -----

    /// §9.2's prohibition: "When a BGP speaker receives an UPDATE
    /// message from an internal peer, the receiving BGP speaker SHALL
    /// NOT re-distribute the routing information ... to other
    /// internal peers" — the iBGP-learned best is absent from the
    /// Adj-RIB-Out toward another internal peer, present toward an
    /// external one (with §5.1.5's synthesized LOCAL_PREF).
    #[test]
    fn ibgp_learned_route_not_readvertised_to_ibgp() {
        let mut rib = LocRib::new(65000);
        let internal_peer = peer("10.0.0.9", 65000, 9); // same AS: iBGP
        rib.announce(
            &internal_peer,
            &BgpUpdate {
                attrs: base_attrs(vec![65042, 65043], None),
                nlri: vec!["203.0.113.0/24".parse().unwrap()],
                ..Default::default()
            },
        );
        rib.recompute();
        let out = LocRibOut::new(
            Arc::new(Mutex::new(rib)),
            crate::peer::ConfiguredNetworks::new(65000, vec![]),
            Arc::new(AcceptAll),
        );
        // Toward another INTERNAL peer: nothing (§9.2).
        let to_internal = crate::peer::OutRib::advertisements(
            &out,
            1,
            1,
            "10.0.0.1".parse().unwrap(),
            "10.0.0.10".parse().unwrap(),
            true,
        );
        assert!(
            to_internal.is_empty(),
            "iBGP-learned route suppressed toward another internal peer (§9.2)"
        );
        // Toward an EXTERNAL peer: advertised, AS_PATH prepended, and
        // without LOCAL_PREF (§5.1.5 MUST NOT externally).
        let to_external = crate::peer::OutRib::advertisements(
            &out,
            1,
            1,
            "192.0.2.1".parse().unwrap(),
            "192.0.2.10".parse().unwrap(),
            false,
        );
        assert_eq!(to_external.len(), 1);
        let update = &to_external[0];
        assert_eq!(
            update.as_path().unwrap().path_length(),
            3,
            "local AS prepended"
        );
        assert!(
            update.attr(attr_type::LOCAL_PREF).is_none(),
            "§5.1.5 external"
        );
    }

    /// The RFC 4456 §4 reflection table, driven through the export
    /// path: a route from a CLIENT reflects to every internal peer;
    /// a route from a NON-client reflects to clients only — never to
    /// another non-client.
    #[test]
    fn rr_client_reflection_table() {
        let mut rib = LocRib::new(65000);
        let client_a = peer("10.0.0.21", 65000, 21);
        let client_b_addr: IpAddr = "10.0.0.22".parse().unwrap();
        let non_client_c = peer("10.0.0.31", 65000, 31);
        let non_client_d_addr: IpAddr = "10.0.0.32".parse().unwrap();
        rib.set_route_reflector_clients(vec![client_a.address, client_b_addr]);
        // A route from client A ...
        rib.announce(
            &client_a,
            &BgpUpdate {
                attrs: base_attrs(vec![65042], None),
                nlri: vec!["203.0.113.0/24".parse().unwrap()],
                ..Default::default()
            },
        );
        // ... and one from non-client C.
        rib.announce(
            &non_client_c,
            &BgpUpdate {
                attrs: base_attrs(vec![65043], None),
                nlri: vec!["198.51.100.0/24".parse().unwrap()],
                ..Default::default()
            },
        );
        rib.recompute();
        let out = LocRibOut::new(
            Arc::new(Mutex::new(rib)),
            crate::peer::ConfiguredNetworks::new(65000, vec![]),
            Arc::new(AcceptAll),
        );
        let holds = |to: IpAddr, prefix: &str| {
            crate::peer::OutRib::advertisements(&out, 1, 1, "10.0.0.1".parse().unwrap(), to, true)
                .iter()
                .any(|u| u.nlri.iter().any(|n| n.prefix.to_string() == prefix))
        };
        // From a client: to the other client AND to non-clients.
        assert!(holds(client_b_addr, "203.0.113.0/24"), "client → client");
        assert!(
            holds(non_client_d_addr, "203.0.113.0/24"),
            "client → non-client (RFC 4456 §4)"
        );
        // From a non-client: to clients, never to another non-client.
        assert!(
            holds(client_b_addr, "198.51.100.0/24"),
            "non-client → client"
        );
        assert!(
            !holds(non_client_d_addr, "198.51.100.0/24"),
            "§9.2: non-client → non-client stays suppressed"
        );
    }

    /// Reflection keeps the peer's own LOCAL_PREF (§5.1.5 shape only
    /// synthesizes when missing): a client's 200 rides to the other
    /// client, never flattened to 100.
    #[test]
    fn rr_reflection_keeps_the_peer_local_pref() {
        let mut rib = LocRib::new(65000);
        let client_a = peer("10.0.0.21", 65000, 21);
        let client_b_addr: IpAddr = "10.0.0.22".parse().unwrap();
        rib.set_route_reflector_clients(vec![client_a.address, client_b_addr]);
        let mut attrs = base_attrs(vec![65042], None);
        attrs.push(PathAttribute::LocalPref(200));
        rib.announce(
            &client_a,
            &BgpUpdate {
                attrs,
                nlri: vec!["203.0.113.0/24".parse().unwrap()],
                ..Default::default()
            },
        );
        rib.recompute();
        let out = LocRibOut::new(
            Arc::new(Mutex::new(rib)),
            crate::peer::ConfiguredNetworks::new(65000, vec![]),
            Arc::new(AcceptAll),
        );
        let updates = crate::peer::OutRib::advertisements(
            &out,
            1,
            1,
            "10.0.0.1".parse().unwrap(),
            client_b_addr,
            true,
        );
        assert_eq!(updates.len(), 1);
        assert_eq!(
            updates[0].attr(attr_type::LOCAL_PREF),
            Some(&PathAttribute::LocalPref(200)),
            "the client's own LOCAL_PREF rides the reflection"
        );
    }

    /// §9.1.3's floor: "A route SHALL NOT be installed in the
    /// Adj-Rib-Out unless the destination, and NEXT_HOP described by
    /// this route, may be forwarded appropriately" — a candidate with
    /// no next hop its family can carry never reaches the Adj-RIB-Out.
    #[test]
    fn export_requires_forwardable_next_hop() {
        let mut rib = LocRib::new(65000);
        let p = peer("192.0.2.1", 65001, 1);
        // ORIGIN + AS_PATH but no NEXT_HOP (and no MP_REACH): not
        // forwardable in any family.
        rib.announce(
            &p,
            &BgpUpdate {
                attrs: vec![
                    PathAttribute::Origin(Origin::Igp),
                    PathAttribute::AsPath(AsPath::sequence([65001])),
                ],
                nlri: vec!["203.0.113.0/24".parse().unwrap()],
                ..Default::default()
            },
        );
        rib.recompute();
        let out = LocRibOut::new(
            Arc::new(Mutex::new(rib)),
            crate::peer::ConfiguredNetworks::new(65000, vec![]),
            Arc::new(AcceptAll),
        );
        assert!(
            crate::peer::OutRib::advertisements(
                &out,
                1,
                1,
                "192.0.2.1".parse().unwrap(),
                "192.0.2.9".parse().unwrap(),
                false
            )
            .is_empty(),
            "no forwardable NEXT_HOP, no Adj-RIB-Out entry (§9.1.3)"
        );
    }

    /// §5.1.5's LOCAL_PREF shape as the pure table: synthesized toward
    /// internal peers when missing, kept when present, never sent
    /// externally.
    #[test]
    fn local_pref_shape_table() {
        let mut attrs = vec![
            PathAttribute::Origin(Origin::Igp),
            PathAttribute::AsPath(AsPath::sequence([65001])),
        ];
        shape_local_pref(&mut attrs, true);
        assert_eq!(
            attrs
                .iter()
                .find(|a| a.attr_type() == attr_type::LOCAL_PREF),
            Some(&PathAttribute::LocalPref(100)),
            "synthesized toward internal peers"
        );
        shape_local_pref(&mut attrs, true);
        assert_eq!(
            attrs
                .iter()
                .filter(|a| a.attr_type() == attr_type::LOCAL_PREF)
                .count(),
            1,
            "no duplicate when already present"
        );
        shape_local_pref(&mut attrs, false);
        assert!(
            attrs.iter().all(|a| a.attr_type() != attr_type::LOCAL_PREF),
            "stripped toward external peers (MUST NOT)"
        );
    }

    /// B-3 (RFC 4271 §5.1.5, verified): a LOCAL_PREF received from an
    /// external peer "MUST be ignored by the receiving speaker" —
    /// reset-to-100 at import (FRR convention), never stored, never
    /// compared. Internal peers keep theirs; a later route-map
    /// `set local-preference` (the import policy) still overrides.
    #[test]
    fn external_local_pref_reset_at_import() {
        let mut attrs = vec![
            PathAttribute::Origin(Origin::Igp),
            PathAttribute::AsPath(AsPath::sequence([65001])),
            PathAttribute::LocalPref(999),
        ];
        reset_external_local_pref(&mut attrs, false);
        assert_eq!(
            attrs
                .iter()
                .find(|a| a.attr_type() == attr_type::LOCAL_PREF),
            Some(&PathAttribute::LocalPref(100)),
            "external value replaced by the local default"
        );

        // Internal: untouched.
        let mut attrs = vec![PathAttribute::LocalPref(200)];
        reset_external_local_pref(&mut attrs, true);
        assert_eq!(
            attrs
                .iter()
                .find(|a| a.attr_type() == attr_type::LOCAL_PREF),
            Some(&PathAttribute::LocalPref(200))
        );
    }

    /// B-3 end to end at the Adj-RIB-In: an eBGP UPDATE carrying
    /// LOCAL_PREF 999 stores 100 — the peer cannot manipulate the
    /// §9.1.2.2 a) ladder (degree of preference is local policy,
    /// §9.1.1); the same UPDATE over iBGP keeps 200.
    #[test]
    fn announce_resets_external_local_pref_in_adj_rib_in() {
        let update = |pref: u32| BgpUpdate {
            attrs: vec![
                PathAttribute::Origin(Origin::Igp),
                PathAttribute::AsPath(AsPath::sequence([65001])),
                PathAttribute::NextHop("192.0.2.1".parse().unwrap()),
                PathAttribute::LocalPref(pref),
            ],
            nlri: vec![Nlri::from("203.0.113.0/24".parse::<IpPrefix>().unwrap())],
            ..Default::default()
        };
        let mut rib = LocRib::new(65000);
        let external = peer("192.0.2.1", 65001, 1);
        rib.announce(&external, &update(999));
        let stored = rib
            .adj_in
            .get(&external.address)
            .unwrap()
            .values()
            .next()
            .unwrap();
        assert_eq!(stored.local_pref(), 100, "external 999 ignored");

        let internal = peer("10.0.0.1", 65000, 2);
        rib.announce(&internal, &update(200));
        let stored = rib
            .adj_in
            .get(&internal.address)
            .unwrap()
            .values()
            .next()
            .unwrap();
        assert_eq!(stored.local_pref(), 200, "internal kept");
    }

    /// The BAR-SAV feed snapshot (S9-a M3): the Adj-RIB-In rendered
    /// read-only — wire-order AS_PATHs per (prefix, peer), the
    /// `as-set` marker for set-carrying paths, deterministic
    /// (peer-address, prefix) order — and pure (nothing changes in
    /// the RIB). The sav-side parser (`sav::barsav::parse_barsav_feed`)
    /// is the consuming half; the format is pinned by both tests.
    #[test]
    fn barsav_feed_renders_the_adj_rib_in_read_only() {
        let update = |path: AsPath, prefix: &str| BgpUpdate {
            attrs: vec![
                PathAttribute::Origin(Origin::Igp),
                PathAttribute::AsPath(path),
                PathAttribute::NextHop("192.0.2.1".parse().unwrap()),
            ],
            nlri: vec![Nlri::from(prefix.parse::<IpPrefix>().unwrap())],
            ..Default::default()
        };
        let mut rib = LocRib::new(65000);
        let customer = peer("192.0.2.9", 65001, 1);
        rib.announce(
            &customer,
            &update(AsPath::sequence([65001]), "198.51.100.0/24"),
        );
        rib.announce(
            &customer,
            &update(AsPath::sequence([65001, 65002]), "203.0.113.0/24"),
        );
        // A set-carrying path: flattened sequence + the marker.
        let mixed = AsPath {
            segments: vec![
                AsSegment::Sequence(vec![65001]),
                AsSegment::Set(vec![65003, 65004]),
            ],
        };
        rib.announce(&customer, &update(mixed, "198.19.0.0/15"));
        let other = peer("198.51.100.2", 65010, 2);
        rib.announce(&other, &update(AsPath::sequence([65010]), "192.0.2.0/24"));

        let before = rib.route_count();
        let text = rib.barsav_feed_text();
        assert_eq!(
            before,
            rib.route_count(),
            "read-only: nothing stored or dropped"
        );

        let lines: Vec<&str> = text.lines().collect();
        assert!(lines[0].starts_with("# bgpd BAR-SAV Adj-RIB-In feed v1"));
        assert_eq!(
            lines[2..],
            [
                "198.19.0.0/15 peer 192.0.2.9 path 65001 65003 65004 as-set",
                "198.51.100.0/24 peer 192.0.2.9 path 65001",
                "203.0.113.0/24 peer 192.0.2.9 path 65001 65002",
                "192.0.2.0/24 peer 198.51.100.2 path 65010",
            ],
            "deterministic (peer, prefix) order; wire-order paths; as-set marked"
        );
    }

    /// The ladder consequence: two eBGP peers fighting with inflated
    /// LOCAL_PREFs cannot outrank each other (both read 100); the
    /// AS_PATH tiebreak decides — the B-3 posture pinned.
    #[test]
    fn external_local_pref_cannot_rig_the_ladder() {
        let p1 = peer("192.0.2.1", 65001, 1);
        let p2 = peer("192.0.2.2", 65002, 2);
        let mut rigging = route(
            "203.0.113.0/24",
            &p1,
            false,
            base_attrs(vec![65001, 65002], None),
        );
        Arc::make_mut(&mut rigging.attrs).push(PathAttribute::LocalPref(999));
        let honest = route("203.0.113.0/24", &p2, false, base_attrs(vec![65001], None));
        // Route::new bypasses announce (no reset) — apply the import
        // rule the way announce does, then compare.
        let mut attrs = (*rigging.attrs).clone();
        reset_external_local_pref(&mut attrs, false);
        let rigging = Route {
            attrs: Arc::new(attrs),
            ..rigging.clone()
        };
        assert_eq!(best_path(&[&rigging, &honest]).unwrap().as_path_len(), 1);
    }

    /// The RS RIB stays out of the kernel (FRR's view semantics): an
    /// RS-client best never produces a ZAPI add; replacing an
    /// installed route with an RS-client one withdraws it.
    #[test]
    fn route_server_bests_never_install_to_zebra() {
        let client = peer("192.0.2.101", 65001, 1);
        let mut rs_route = route(
            "203.0.113.0/24",
            &client,
            false,
            base_attrs(vec![65001], None),
        );
        rs_route.rs_client = true;
        // RS best with no installed predecessor: nothing to say.
        assert!(zebra_commands(&BestChange {
            prefix: rs_route.prefix,
            best: Some(rs_route.clone()),
            old: None,
        })
        .is_empty());
        // Normal best installs; transition to an RS best withdraws.
        let normal = route(
            "203.0.113.0/24",
            &peer("192.0.2.9", 65009, 9),
            false,
            base_attrs(vec![65009], None),
        );
        assert!(matches!(
            zebra_commands(&BestChange {
                prefix: normal.prefix,
                best: Some(normal.clone()),
                old: None,
            })
            .as_slice(),
            [crate::zedge::ZedgeCommand::RouteAdd(_)]
        ));
        assert!(matches!(
            zebra_commands(&BestChange {
                prefix: normal.prefix,
                best: Some(rs_route.clone()),
                old: Some(normal),
            })
            .as_slice(),
            [crate::zedge::ZedgeCommand::RouteDel(_)]
        ));
        // Losing the last RS best: nothing was installed, nothing to
        // delete.
        assert!(zebra_commands(&BestChange {
            prefix: rs_route.prefix,
            best: None,
            old: Some(rs_route),
        })
        .is_empty());
    }
}
