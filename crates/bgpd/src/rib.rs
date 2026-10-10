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

use std::collections::BTreeMap;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;

use common::{IpPrefix, Nexthop, NexthopGroup, RouteEntry, RouteProtocol};
use tracing::info;

use crate::attr::{attr_type, AsPath, AsSegment, Origin, PathAttribute};
use crate::message::BgpUpdate;
use crate::peer::{PeerInfo, RouteSink};

/// One stored route: the prefix, its path attributes, and the peer it
/// came from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Route {
    pub prefix: IpPrefix,
    pub attrs: Vec<PathAttribute>,
    pub source: PeerInfo,
    /// Learned over an internal (iBGP) session (§9.1.2.2 d).
    pub internal: bool,
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
pub fn best_path(candidates: &[Route]) -> Option<&Route> {
    let mut alive: Vec<usize> = (0..candidates.len()).collect();
    if alive.is_empty() {
        return None;
    }

    // Degree of preference (LOCAL_PREF, higher wins).
    let top_pref = alive
        .iter()
        .map(|&i| candidates[i].local_pref())
        .max()
        .unwrap();
    alive.retain(|&i| candidates[i].local_pref() == top_pref);
    if alive.len() == 1 {
        return Some(&candidates[alive[0]]);
    }

    // a) smallest AS_PATH count (AS_SET = 1).
    let shortest = alive
        .iter()
        .map(|&i| candidates[i].as_path_len())
        .min()
        .unwrap();
    alive.retain(|&i| candidates[i].as_path_len() == shortest);
    if alive.len() == 1 {
        return Some(&candidates[alive[0]]);
    }

    // b) lowest ORIGIN number.
    let best_origin = alive.iter().map(|&i| candidates[i].origin()).min().unwrap();
    alive.retain(|&i| candidates[i].origin() == best_origin);
    if alive.len() == 1 {
        return Some(&candidates[alive[0]]);
    }

    // c) lowest MED among routes from the same neighboring AS
    // (RFC pseudocode: remove m when a same-neighbor-AS n has a
    // strictly smaller MED; missing reads as 0).
    let mut med_alive: Vec<usize> = Vec::new();
    'outer: for &m in &alive {
        if let Some(m_as) = candidates[m].neighbor_as() {
            for &n in &alive {
                if n != m {
                    if let Some(n_as) = candidates[n].neighbor_as() {
                        if n_as == m_as && candidates[n].med() < candidates[m].med() {
                            continue 'outer; // dominated, remove m
                        }
                    }
                }
            }
        }
        med_alive.push(m);
    }
    alive = med_alive;
    if alive.len() == 1 {
        return Some(&candidates[alive[0]]);
    }

    // d) eBGP over iBGP.
    if alive.iter().any(|&i| !candidates[i].internal) {
        alive.retain(|&i| !candidates[i].internal);
        if alive.len() == 1 {
            return Some(&candidates[alive[0]]);
        }
    }

    // e) interior cost to NEXT_HOP — skipped (no IGP yet; §9.1.2.2 e
    // allows skipping when no cost can be determined).

    // f) lowest BGP Identifier.
    let ids: Vec<Option<Ipv4Addr>> = alive.iter().map(|&i| candidates[i].source.bgp_id).collect();
    if ids.iter().all(Option::is_some) {
        let lowest = ids.iter().flatten().copied().min().unwrap();
        alive.retain(|&i| candidates[i].source.bgp_id == Some(lowest));
        if alive.len() == 1 {
            return Some(&candidates[alive[0]]);
        }
    }

    // g) lowest peer address.
    let lowest_addr = alive
        .iter()
        .map(|&i| candidates[i].source.address)
        .min()
        .unwrap();
    alive.retain(|&i| candidates[i].source.address == lowest_addr);
    Some(&candidates[alive[0]])
}

/// A Loc-RIB change produced by a recompute: the prefix, its new best
/// route, and (for withdrawals) the route it replaces.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BestChange {
    pub prefix: IpPrefix,
    pub best: Option<Route>,
    pub old: Option<Route>,
}

/// Adj-RIBs-In + Loc-RIB (§9.1's three RIBs minus Adj-RIB-Out, which
/// the session's OutRib plays).
pub struct LocRib {
    local_as: u32,
    /// peer address → (prefix → route)
    adj_in: BTreeMap<IpAddr, BTreeMap<IpPrefix, Route>>,
    best: BTreeMap<IpPrefix, Route>,
    /// The Phase 1 import policy (§9.2.1): typed filter + RPKI/OTC
    /// validation in W2-d; accept-all by default.
    import: Arc<dyn ImportPolicy>,
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
            import,
        }
    }

    pub fn local_as(&self) -> u32 {
        self.local_as
    }

    /// Adj-RIB-In update from one peer's UPDATE (announce side). Each
    /// carried prefix runs the import policy (§9.2.1 Phase 1) before
    /// entering the Adj-RIB-In: rejected prefixes never become
    /// decision candidates; accepted ones may carry mutated
    /// attributes.
    pub fn announce(&mut self, peer: &PeerInfo, update: &BgpUpdate) {
        let rib = self.adj_in.entry(peer.address).or_default();
        let internal = peer.remote_as == self.local_as;
        for prefix in update.announced() {
            let route = Route {
                prefix,
                attrs: update.attrs.clone(),
                source: *peer,
                internal,
            };
            match self.import.import(route) {
                Some(route) => {
                    rib.insert(prefix, route);
                }
                None => {
                    info!(peer = %peer.address, %prefix, "bgpd: route rejected by import policy");
                }
            }
        }
    }

    /// Adj-RIB-In withdrawals.
    pub fn withdraw(&mut self, peer: &PeerInfo, prefixes: &[IpPrefix]) {
        if let Some(rib) = self.adj_in.get_mut(&peer.address) {
            for prefix in prefixes {
                rib.remove(prefix);
            }
        }
    }

    /// "Deletes all routes associated with this connection".
    pub fn clear_peer(&mut self, peer: &PeerInfo) {
        if let Some(rib) = self.adj_in.remove(&peer.address) {
            if !rib.is_empty() {
                info!(peer = %peer.address, routes = rib.len(), "bgpd: peer routes withdrawn");
            }
        }
    }

    /// Re-run the decision process over every known prefix; returns
    /// the best-path changes (for export and re-advertisement).
    pub fn recompute(&mut self) -> Vec<BestChange> {
        // Union of the candidates' prefixes and the current best
        // table: a prefix whose every candidate vanished must still
        // produce its withdrawal change.
        let mut prefixes: Vec<IpPrefix> = self
            .adj_in
            .values()
            .flat_map(|rib| rib.keys())
            .chain(self.best.keys())
            .copied()
            .collect();
        prefixes.sort();
        prefixes.dedup();
        let mut changes = Vec::new();
        for prefix in prefixes {
            let candidates: Vec<Route> = self
                .adj_in
                .values()
                .filter_map(|rib| rib.get(&prefix).cloned())
                .collect();
            let new_best = best_path(&candidates).cloned();
            let old_best = self.best.get(&prefix).cloned();
            if new_best.as_ref() != old_best.as_ref() {
                if let Some(route) = &new_best {
                    self.best.insert(prefix, route.clone());
                } else {
                    self.best.remove(&prefix);
                }
                changes.push(BestChange {
                    prefix,
                    best: new_best,
                    old: old_best,
                });
            }
        }
        changes
    }

    pub fn best_routes(&self) -> impl Iterator<Item = &Route> {
        self.best.values()
    }

    pub fn route_count(&self) -> usize {
        self.adj_in.values().map(|rib| rib.len()).sum()
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
        rib.announce(peer, update);
        self.changes.extend(rib.recompute());
    }

    fn withdraw(&mut self, peer: &PeerInfo, prefixes: &[IpPrefix]) {
        let mut rib = self.rib.lock().unwrap();
        rib.withdraw(peer, prefixes);
        self.changes.extend(rib.recompute());
    }

    fn clear_peer(&mut self, peer: &PeerInfo) {
        let mut rib = self.rib.lock().unwrap();
        rib.clear_peer(peer);
        self.changes.extend(rib.recompute());
    }
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
            let Some(prefix) = update.announced().first().copied() else {
                updates.push(update);
                continue;
            };
            // A synthetic local route: the export gate's §9.2.2 floor
            // (never reflect to the origin peer) can never trip for it
            // (unspecified source), but the typed filter applies in
            // full.
            let local = Route {
                prefix,
                attrs: update.attrs.clone(),
                source: PeerInfo {
                    address: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
                    remote_as: local_as,
                    bgp_id: None,
                },
                internal: false,
            };
            match self.policy.export(&local, &to_peer_info, internal) {
                Some(exported) => {
                    let mut update = update;
                    // Splice the policy's edits in, keeping the
                    // NEXT_HOP/MP_REACH encoding the session layer
                    // produced (the typed model has no next-hop
                    // representation to edit).
                    let mut attrs = exported.attrs;
                    for attr in &update.attrs {
                        if matches!(attr, PathAttribute::NextHop(_) | PathAttribute::MpReach(_)) {
                            attrs.retain(|a| a.attr_type() != attr.attr_type());
                            attrs.push(attr.clone());
                        }
                    }
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
            for route in rib.best_routes() {
                // The export-policy seam (Phase 3); the default blocks
                // reflection to the origin peer.
                let Some(exported) = self.policy.export(route, &to_peer_info, internal) else {
                    continue;
                };
                let Some(&PathAttribute::NextHop(_)) = exported.attr(attr_type::NEXT_HOP) else {
                    continue;
                };
                let mut attrs = exported.attrs;
                // Phase 3 (§5.1.2): prepend the local AS on eBGP
                // re-advertisement; keep AS_PATH on iBGP.
                if !internal {
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
                    nlri: vec![exported.prefix],
                });
            }
        }
        updates
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
        Route {
            prefix: prefix.parse().unwrap(),
            attrs,
            source: *peer_info,
            internal,
        }
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
        a.attrs.push(PathAttribute::LocalPref(50));
        let mut b = route(
            "203.0.113.0/24",
            &p,
            false,
            base_attrs(vec![65001, 65002], None),
        );
        b.attrs.push(PathAttribute::LocalPref(200));
        // Higher LOCAL_PREF wins even with a longer AS_PATH.
        assert_eq!(best_path(&[a, b]).unwrap().local_pref(), 200);
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
            best_path(&[long.clone(), short.clone()])
                .unwrap()
                .as_path_len(),
            1
        );

        // Tie on length: lower ORIGIN wins (IGP=0 < EGP=1).
        let mut egp = long;
        egp.attrs[0] = PathAttribute::Origin(Origin::Egp);
        assert_eq!(best_path(&[egp, short]).unwrap().origin(), Origin::Igp);
    }

    #[test]
    fn ladder_as_set_counts_one() {
        let p = peer("192.0.2.1", 65001, 1);
        let set = Route {
            prefix: "203.0.113.0/24".parse().unwrap(),
            attrs: vec![
                PathAttribute::Origin(Origin::Igp),
                PathAttribute::AsPath(AsPath {
                    segments: vec![
                        AsSegment::Sequence(vec![65001]),
                        AsSegment::Set(vec![1, 2, 3, 4, 5]),
                    ],
                }),
                PathAttribute::NextHop("192.0.2.1".parse().unwrap()),
            ],
            source: p,
            internal: false,
        };
        let longer = route("203.0.113.0/24", &p, false, base_attrs(vec![1, 2, 3], None));
        // set path = 1 + 1 = 2 beats sequence of 3.
        assert_eq!(best_path(&[set, longer]).unwrap().as_path_len(), 2);
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
        assert_eq!(best_path(&[hi, lo]).unwrap().med(), 50);

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
            best_path(&[a, b]).unwrap().source.bgp_id,
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
            best_path(&[with_med, without]).unwrap().med(),
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
        assert!(!best_path(&[e, i]).unwrap().internal);
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
            best_path(&[a.clone(), b.clone()]).unwrap().source.bgp_id,
            Some(Ipv4Addr::new(10, 1, 1, 2))
        );

        // Identical IDs (different ASes, equal paths): lowest peer
        // address (§9.1.2.2 g).
        let same_id_a = Route {
            source: PeerInfo {
                bgp_id: Some(Ipv4Addr::new(10, 1, 1, 5)),
                ..a.source
            },
            ..a
        };
        let same_id_b = Route {
            source: PeerInfo {
                bgp_id: Some(Ipv4Addr::new(10, 1, 1, 5)),
                ..b.source
            },
            ..b
        };
        assert_eq!(
            best_path(&[same_id_a, same_id_b]).unwrap().source.address,
            "192.0.2.1".parse::<IpAddr>().unwrap()
        );
    }

    #[test]
    fn best_path_empty_is_none() {
        assert!(best_path(&[]).is_none());
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
}
