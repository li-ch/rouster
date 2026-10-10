//! bgpd's bridge onto the typed policy engine (W2-d M1): the
//! [`policy::RouteView`] implementation for bgpd paths, the
//! wire-attribute ↔ policy-model conversion, and the import/export
//! engines that run compiled [`policy::Filter`]s in the §9.2.1 Phase 1
//! / Phase 3 seams.
//!
//! The conversion is one snapshot per evaluation: bgpd's `Route` holds
//! the wire model (`Vec<PathAttribute>`), the engine owns its own
//! attribute model ([`policy::BgpAttrs`]) — [`PolicyView`] converts
//! once, `policy::RouteData::from_view` snapshots it, the filter
//! mutates the snapshot, and [`write_back`] splices the edited
//! attributes into the wire model (replace-or-insert per attribute).
//! Attributes the typed model cannot represent (NEXT_HOP, MP_REACH,
//! AGGREGATOR, unknown-transitive passthrough) survive untouched.

use std::sync::Arc;

use common::{IpPrefix, Nexthop, NexthopGroup, RouteProtocol};
use policy::{RouteData, RouteView};
use tracing::info;

use crate::attr::{attr_type, AsPath, Origin, PathAttribute};
use crate::peer::PeerInfo;
use crate::rib::{ExportPolicy, ImportPolicy, Route};

// ---------------------------------------------------------------------------
// Wire model → policy model
// ---------------------------------------------------------------------------

/// The policy engine's window onto one bgpd route (the W1-a §Deferred
/// anchor "bgpd implements RouteView", resolved here).
///
/// Converts the wire attributes once at construction; implements the
/// read-only view the engine snapshot needs. `metric` maps to MED
/// (BIRD's `bgp_metric`; `set metric` on a BGP route is MED in FRR's
/// documented wording — policy.md §6.5).
pub struct PolicyView {
    prefix: IpPrefix,
    metric: u32,
    nexthops: NexthopGroup,
    attrs: policy::BgpAttrs,
}

impl PolicyView {
    pub fn new(route: &Route) -> Self {
        let nexthops = match route.attr(attr_type::NEXT_HOP) {
            Some(PathAttribute::NextHop(v4)) => NexthopGroup::single(Nexthop::Ipv4(*v4)),
            _ => match route.attr(attr_type::MP_REACH_NLRI) {
                Some(PathAttribute::MpReach(mp)) => match mp.next_hop {
                    crate::attr::MpNextHop::V4(v4) => NexthopGroup::single(Nexthop::Ipv4(v4)),
                    crate::attr::MpNextHop::V6 { global, .. } => {
                        NexthopGroup::single(Nexthop::Ipv6(global))
                    }
                    crate::attr::MpNextHop::Raw(_) => NexthopGroup::new(),
                },
                _ => NexthopGroup::new(),
            },
        };
        Self {
            prefix: route.prefix,
            metric: route.med(),
            nexthops,
            attrs: to_policy_attrs(&route.attrs),
        }
    }
}

impl RouteView for PolicyView {
    fn prefix(&self) -> IpPrefix {
        self.prefix
    }

    fn protocol(&self) -> RouteProtocol {
        RouteProtocol::Bgp
    }

    fn metric(&self) -> u32 {
        self.metric
    }

    fn nexthop_group(&self) -> &NexthopGroup {
        &self.nexthops
    }

    fn bgp_attrs(&self) -> Option<&policy::BgpAttrs> {
        Some(&self.attrs)
    }
}

/// Convert the wire attribute list into the engine's owned model.
pub fn to_policy_attrs(attrs: &[PathAttribute]) -> policy::BgpAttrs {
    let mut out = policy::BgpAttrs::default();
    for attr in attrs {
        match attr {
            PathAttribute::AsPath(p) => out.as_path = to_policy_path(p),
            PathAttribute::LocalPref(v) => out.local_pref = Some(*v),
            PathAttribute::Med(v) => out.med = Some(*v),
            PathAttribute::Origin(o) => out.origin = Some(to_policy_origin(*o)),
            PathAttribute::Communities(cs) => {
                out.communities = cs.iter().map(|c| community_from_wire(*c)).collect();
            }
            PathAttribute::Otc(v) => out.otc = Some(*v),
            _ => {}
        }
    }
    out
}

fn to_policy_path(p: &AsPath) -> policy::AsPath {
    policy::AsPath::from_segments(
        p.segments
            .iter()
            .map(|seg| match seg {
                crate::attr::AsSegment::Set(v) => policy::AsSegment::Set(v.clone()),
                crate::attr::AsSegment::Sequence(v) => policy::AsSegment::Sequence(v.clone()),
            })
            .collect(),
    )
}

fn to_policy_origin(o: Origin) -> policy::BgpOrigin {
    match o {
        Origin::Igp => policy::BgpOrigin::Igp,
        Origin::Egp => policy::BgpOrigin::Egp,
        Origin::Incomplete => policy::BgpOrigin::Incomplete,
    }
}

fn from_policy_origin(o: policy::BgpOrigin) -> Origin {
    match o {
        policy::BgpOrigin::Igp => Origin::Igp,
        policy::BgpOrigin::Egp => Origin::Egp,
        policy::BgpOrigin::Incomplete => Origin::Incomplete,
    }
}

fn community_from_wire(v: u32) -> policy::Community {
    use policy::{Community, WellKnownCommunity};
    let hi = (v >> 16) as u16;
    let lo = (v & 0xffff) as u16;
    let well_known = match (hi, lo) {
        (0xffff, 1) => Some(WellKnownCommunity::NoExport),
        (0xffff, 2) => Some(WellKnownCommunity::NoAdvertise),
        (0xffff, 3) => Some(WellKnownCommunity::LocalAs),
        (0xffff, 4) => Some(WellKnownCommunity::Gshut),
        _ => None,
    };
    match well_known {
        Some(w) => Community::WellKnown(w),
        None => Community::Pair(hi, lo),
    }
}

fn community_to_wire(c: policy::Community) -> u32 {
    let (hi, lo) = match c {
        policy::Community::Pair(a, b) => (a, b),
        policy::Community::WellKnown(w) => w.as_pair(),
    };
    (u32::from(hi) << 16) | u32::from(lo)
}

// ---------------------------------------------------------------------------
// Policy model → wire model (write-back)
// ---------------------------------------------------------------------------

/// Replace-or-insert one path attribute.
pub(crate) fn upsert_attr(attrs: &mut Vec<PathAttribute>, attr: PathAttribute) {
    match attrs.iter().position(|a| a.attr_type() == attr.attr_type()) {
        Some(i) => attrs[i] = attr,
        None => attrs.push(attr),
    }
}

fn drop_attr(attrs: &mut Vec<PathAttribute>, ty: u8) {
    attrs.retain(|a| a.attr_type() != ty);
}

/// Splice the filter's edits back into the wire model. Only attributes
/// the engine actually represents are touched; the original `Route`
/// attrs are the base so passthrough attributes survive.
pub fn write_back(data: &RouteData, route: &mut Route) {
    let original_med = route.med();
    if data.metric != original_med {
        upsert_attr(&mut route.attrs, PathAttribute::Med(data.metric));
    }
    let Some(bgp) = &data.bgp else {
        return;
    };
    if let Some(v) = bgp.local_pref {
        upsert_attr(&mut route.attrs, PathAttribute::LocalPref(v));
    }
    if let Some(v) = bgp.med {
        upsert_attr(&mut route.attrs, PathAttribute::Med(v));
    }
    if let Some(o) = bgp.origin {
        upsert_attr(
            &mut route.attrs,
            PathAttribute::Origin(from_policy_origin(o)),
        );
    }
    // Communities: replace wholesale (an engine `set community none`
    // removes the attribute entirely).
    if bgp.communities.is_empty() {
        drop_attr(&mut route.attrs, attr_type::COMMUNITIES);
    } else {
        let wire: Vec<u32> = bgp
            .communities
            .iter()
            .map(|c| community_to_wire(*c))
            .collect();
        upsert_attr(&mut route.attrs, PathAttribute::Communities(wire));
    }
    if let Some(v) = bgp.otc {
        upsert_attr(&mut route.attrs, PathAttribute::Otc(v));
    }
    // AS_PATH: rewrite from the model when the route carries one (a
    // prepend is the only structural edit the engine makes).
    if route.attr(attr_type::AS_PATH).is_some() {
        let mut segments = Vec::new();
        for seg in bgp.as_path.segments() {
            match seg {
                policy::AsSegment::Set(v) => segments.push(crate::attr::AsSegment::Set(v.clone())),
                policy::AsSegment::Sequence(v) => {
                    segments.push(crate::attr::AsSegment::Sequence(v.clone()))
                }
            }
        }
        upsert_attr(&mut route.attrs, PathAttribute::AsPath(AsPath { segments }));
    }
}

/// Run one compiled filter over a route: `None` = reject, `Some` =
/// accepted (with mutated attributes spliced in).
pub fn run_filter(filter: &policy::Filter, route: Route) -> Option<Route> {
    let mut data = RouteData::from_view(&PolicyView::new(&route));
    let verdict = filter.apply(&mut data);
    if !verdict.is_accept() {
        return None;
    }
    let mut route = route;
    write_back(&data, &mut route);
    Some(route)
}

// ---------------------------------------------------------------------------
// The engines
// ---------------------------------------------------------------------------

/// The import engine (§9.2.1 Phase 1): Adj-RIB-In routes pass the
/// compiled filter before entering the decision process. `None` filter
/// = accept-all (behavior-identical to v1).
#[derive(Default)]
pub struct TypedImport {
    filter: Option<Arc<policy::Filter>>,
}

impl TypedImport {
    pub fn new(filter: Option<Arc<policy::Filter>>) -> Self {
        Self { filter }
    }
}

impl ImportPolicy for TypedImport {
    fn import(&self, route: Route) -> Option<Route> {
        let prefix = route.prefix;
        let peer = route.source.address;
        let Some(filter) = &self.filter else {
            return Some(route);
        };
        match run_filter(filter, route) {
            Some(route) => Some(route),
            None => {
                info!(%prefix, %peer, "bgpd: route rejected by import filter");
                None
            }
        }
    }
}

/// The export engine (§9.2.1 Phase 3 + RFC 9234 OTC egress): gates
/// Adj-RIB-Out. Keeps the §9.2.2 floor (never reflect to the origin
/// peer), then runs the compiled filter.
#[derive(Default)]
pub struct TypedExport {
    filter: Option<Arc<policy::Filter>>,
}

impl TypedExport {
    pub fn new(filter: Option<Arc<policy::Filter>>) -> Self {
        Self { filter }
    }
}

impl ExportPolicy for TypedExport {
    fn export(&self, route: &Route, to_peer: &PeerInfo, _internal: bool) -> Option<Route> {
        // §9.2.2 loop-prevention floor.
        if route.source.address == to_peer.address {
            return None;
        }
        let Some(filter) = &self.filter else {
            return Some(route.clone());
        };
        match run_filter(filter, route.clone()) {
            Some(route) => Some(route),
            None => {
                info!(prefix = %route.prefix, peer = %to_peer.address,
                    "bgpd: route not advertised (export filter)");
                None
            }
        }
    }
}

/// The named import/export filters compiled from `bgpd.conf`'s
/// route-map stanzas (the W1-a compatibility grammar).
#[derive(Debug, Default)]
pub struct NamedPolicy {
    pub import: Option<Arc<policy::Filter>>,
    pub export: Option<Arc<policy::Filter>>,
}

/// The full import pipeline (W2-d): RPKI/OTC validation first (RFC
/// 6811 §2 validity is a property of the received announcement; the
/// typed filter sees the post-validation route), then the compiled
/// filter.
pub struct ImportPipeline {
    pub validation: Arc<crate::rov::ValidationGate>,
    pub filter: Option<Arc<policy::Filter>>,
}

impl ImportPipeline {
    pub fn new(
        validation: Arc<crate::rov::ValidationGate>,
        filter: Option<Arc<policy::Filter>>,
    ) -> Self {
        Self { validation, filter }
    }
}

impl ImportPolicy for ImportPipeline {
    fn import(&self, route: Route) -> Option<Route> {
        let route = self.validation.apply(route)?;
        match &self.filter {
            None => Some(route),
            Some(filter) => run_filter(filter, route),
        }
    }
}

/// The full export pipeline (W2-d): §9.2.2 reflection floor, RFC 9234
/// egress (eBGP only — roles are eBGP constructs), then the compiled
/// filter.
pub struct ExportPipeline {
    pub validation: Arc<crate::rov::ValidationGate>,
    pub filter: Option<Arc<policy::Filter>>,
    pub local_as: u32,
}

impl ExportPipeline {
    pub fn new(
        validation: Arc<crate::rov::ValidationGate>,
        filter: Option<Arc<policy::Filter>>,
        local_as: u32,
    ) -> Self {
        Self {
            validation,
            filter,
            local_as,
        }
    }
}

impl ExportPolicy for ExportPipeline {
    fn export(&self, route: &Route, to_peer: &PeerInfo, internal: bool) -> Option<Route> {
        // §9.2.2 loop-prevention floor.
        if route.source.address == to_peer.address {
            return None;
        }
        // RFC 9234 §5 egress (eBGP only — roles are eBGP constructs).
        let route = if internal {
            route.clone()
        } else {
            self.validation
                .otc_egress(route, to_peer.address, self.local_as)?
        };
        match &self.filter {
            None => Some(route),
            Some(filter) => run_filter(filter, route),
        }
    }
}

/// Compile the config's policy stanzas and resolve the `import` /
/// `export` names. Unknown names and grammar errors carry the line
/// number policy's parser reported (offsets preserved by the
/// blank-padded fragment config.rs builds).
pub fn compile_named_policy(config: &crate::config::BgpdConfig) -> Result<NamedPolicy, String> {
    let doc = policy::parse_policy_config(&config.policy_text)
        .map_err(|e| format!("policy stanzas: {e}"))?;
    let resolve = |name: &Option<String>| -> Result<Option<Arc<policy::Filter>>, String> {
        match name {
            None => Ok(None),
            Some(n) => policy::compile_route_map(&doc, n)
                .map(|out| Some(Arc::new(out.filter)))
                .map_err(|e| format!("filter `{n}`: {e}")),
        }
    };
    Ok(NamedPolicy {
        import: resolve(&config.import_filter)?,
        export: resolve(&config.export_filter)?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rib::AcceptAll;
    use std::net::Ipv4Addr;

    fn peer_info(addr: &str, as_: u32) -> PeerInfo {
        PeerInfo {
            address: addr.parse().unwrap(),
            remote_as: as_,
            bgp_id: Some(Ipv4Addr::new(10, 1, 1, 1)),
        }
    }

    fn route(prefix: &str, path: Vec<u32>) -> Route {
        let source = peer_info("192.0.2.9", 65001);
        Route::new(
            prefix.parse().unwrap(),
            vec![
                PathAttribute::Origin(Origin::Igp),
                PathAttribute::AsPath(AsPath::sequence(path)),
                PathAttribute::NextHop("192.0.2.9".parse().unwrap()),
            ],
            source,
            false,
        )
    }

    fn prefix_set_filter(match_prefix: &str, actions: Vec<policy::Action>) -> policy::Filter {
        let mut b = policy::FilterBuilder::new().default_verdict(policy::Verdict::Accept);
        let set = policy::PrefixSet::from_patterns(vec![policy::PrefixPattern::exact(
            match_prefix.parse().unwrap(),
        )]);
        let idx = b.add_prefix_set(set);
        b.add_rule(policy::Term::PrefixIn(idx), actions);
        b.build().unwrap()
    }

    // ---- M1: the RouteView bridge --------------------------------

    #[test]
    fn policy_view_exposes_the_wire_attributes() {
        let mut r = route("203.0.113.0/24", vec![65001, 65002]);
        r.attrs.push(PathAttribute::LocalPref(200));
        r.attrs.push(PathAttribute::Med(50));
        r.attrs.push(PathAttribute::Communities(vec![
            (65000u32 << 16) | 1,
            0xffff_0002,
        ]));
        let view = PolicyView::new(&r);
        assert_eq!(view.prefix().to_string(), "203.0.113.0/24");
        assert_eq!(view.metric(), 50, "metric = MED (BIRD bgp_metric)");
        let bgp = view.bgp_attrs().unwrap();
        assert_eq!(bgp.as_path.render(), "65001 65002");
        assert_eq!(bgp.local_pref, Some(200));
        assert_eq!(bgp.med, Some(50));
        assert_eq!(bgp.origin, Some(policy::BgpOrigin::Igp));
        assert_eq!(bgp.communities.len(), 2);
        assert_eq!(bgp.communities[0].to_string(), "65000:1");
        assert_eq!(bgp.communities[1].to_string(), "no-advertise");
        assert_eq!(
            view.nexthop_group().hops(),
            &[(common::Nexthop::Ipv4("192.0.2.9".parse().unwrap()), 1)],
            "NEXT_HOP becomes the group"
        );
    }

    #[test]
    fn policy_view_v6_nexthop_from_mp_reach() {
        let mut r = route("2001:db8:1::/48", vec![65001]);
        r.attrs.retain(|a| !matches!(a, PathAttribute::NextHop(_)));
        r.attrs.push(PathAttribute::MpReach(crate::attr::MpReach {
            afi: 2,
            safi: 1,
            next_hop: crate::attr::MpNextHop::V6 {
                global: "2001:db8::1".parse().unwrap(),
                link_local: None,
            },
            nlri: vec!["2001:db8:1::/48".parse().unwrap()],
        }));
        let view = PolicyView::new(&r);
        assert_eq!(
            view.nexthop_group().hops(),
            &[(common::Nexthop::Ipv6("2001:db8::1".parse().unwrap()), 1)]
        );
    }

    // ---- M1: filter execution + write-back -----------------------

    #[test]
    fn reject_filter_drops_the_route() {
        let filter = prefix_set_filter("203.0.113.0/24", vec![policy::Action::Reject]);
        let engine = TypedImport::new(Some(Arc::new(filter)));
        let dropped = engine
            .import(route("203.0.113.0/24", vec![65001]))
            .is_none();
        assert!(dropped, "the matched route is rejected");
        let other = engine.import(route("198.51.100.0/24", vec![65001]));
        assert!(
            other.is_some(),
            "unmatched routes fall to the accept default"
        );
    }

    #[test]
    fn set_filter_mutates_attributes_before_best_path() {
        // §9.1.1: local policy may raise the degree of preference —
        // here LOCAL_PREF 200 replaces the 100 default before the
        // stored route reaches the decision process.
        let filter = prefix_set_filter(
            "203.0.113.0/24",
            vec![policy::Action::SetLocalPref(200), policy::Action::Accept],
        );
        let engine = TypedImport::new(Some(Arc::new(filter)));
        let out = engine.import(route("203.0.113.0/24", vec![65001])).unwrap();
        assert_eq!(out.local_pref(), 200);
        // A prepend is a structural write-back the wire codec must see.
        let prepend = prefix_set_filter(
            "203.0.113.0/24",
            vec![
                policy::Action::PrependAsPath {
                    asn: 65000,
                    times: 2,
                },
                policy::Action::Accept,
            ],
        );
        let out = TypedImport::new(Some(Arc::new(prepend)))
            .import(route("203.0.113.0/24", vec![65001]))
            .unwrap();
        assert_eq!(out.as_path_len(), 3, "65000 65000 65001");
        assert_eq!(
            out.attr(attr_type::AS_PATH).map(|_| ()),
            Some(()),
            "AS_PATH stays a wire attribute"
        );
    }

    #[test]
    fn write_back_keeps_passthrough_attributes() {
        // Unknown-transitive passthrough and AGGREGATOR survive an
        // engine pass untouched (§4.3/§5).
        let mut r = route("203.0.113.0/24", vec![65001]);
        r.attrs.push(PathAttribute::Aggregator {
            asn: 65001,
            addr: "10.0.0.1".parse().unwrap(),
        });
        r.attrs.push(PathAttribute::Unknown {
            attr_type: 99,
            flags: 0xc0,
            value: vec![1, 2, 3],
        });
        let filter = prefix_set_filter("203.0.113.0/24", vec![policy::Action::Accept]);
        let out = run_filter(&filter, r).unwrap();
        assert!(out.attr(7).is_some(), "AGGREGATOR preserved");
        assert!(out.attr(99).is_some(), "unknown passthrough preserved");
    }

    #[test]
    fn write_back_community_none_removes_the_attribute() {
        let mut r = route("203.0.113.0/24", vec![65001]);
        r.attrs
            .push(PathAttribute::Communities(vec![65000 << 16 | 1]));
        let filter = prefix_set_filter(
            "203.0.113.0/24",
            vec![
                policy::Action::SetCommunities {
                    list: vec![],
                    mode: policy::CommMode::Replace,
                },
                policy::Action::Accept,
            ],
        );
        let out = run_filter(&filter, r).unwrap();
        assert!(out.attr(attr_type::COMMUNITIES).is_none(), "none = removed");
    }

    #[test]
    fn typed_export_gates_adj_rib_out() {
        let filter = prefix_set_filter("198.51.100.0/24", vec![policy::Action::Reject]);
        let engine = TypedExport::new(Some(Arc::new(filter)));
        let to = peer_info("192.0.2.10", 65002);
        assert!(engine
            .export(&route("198.51.100.0/24", vec![65001]), &to, false)
            .is_none());
        assert!(engine
            .export(&route("203.0.113.0/24", vec![65001]), &to, false)
            .is_some());
    }

    #[test]
    fn typed_export_mutates_the_advertisement() {
        let filter = prefix_set_filter(
            "203.0.113.0/24",
            vec![policy::Action::SetMed(42), policy::Action::Accept],
        );
        let engine = TypedExport::new(Some(Arc::new(filter)));
        let to = peer_info("192.0.2.10", 65002);
        let out = engine
            .export(&route("203.0.113.0/24", vec![65001]), &to, false)
            .unwrap();
        assert_eq!(out.med(), 42);
    }

    #[test]
    fn accept_all_import_is_identity_and_export_blocks_reflection() {
        let r = route("203.0.113.0/24", vec![65001]);
        let out = AcceptAll.import(r.clone()).unwrap();
        assert_eq!(out, r);
        let origin = r.source;
        assert!(AcceptAll.export(&r, &origin, false).is_none());
        let other = peer_info("192.0.2.10", 65002);
        assert_eq!(AcceptAll.export(&r, &other, false).unwrap(), r);
    }

    #[test]
    fn empty_filter_options_are_behavior_identical() {
        // No config = no filter = v1 behavior (the w-smoke invariant).
        let import = TypedImport::new(None);
        let r = route("203.0.113.0/24", vec![65001]);
        assert_eq!(import.import(r.clone()).unwrap(), r);
        let export = TypedExport::new(None);
        let to = peer_info("192.0.2.10", 65002);
        assert_eq!(export.export(&r, &to, false).unwrap(), r);
    }

    // ---- M1: the config → compiled filter path -------------------

    fn config_with(text: &str) -> crate::config::BgpdConfig {
        crate::config::parse_config(text).unwrap()
    }

    const POLICY_CONF: &str = "\
router bgp 65000
 bgp router-id 10.0.0.1
 import IN
 export OUT
route-map IN permit 10
 match ip address prefix-list CUST
 set local-preference 200
route-map OUT permit 10
 match community TAGGED
route-map OUT deny 99
ip prefix-list CUST seq 5 permit 203.0.113.0/24
bgp community-list standard TAGGED permit 65000:99
";

    #[test]
    fn route_map_compat_compiles_into_the_engines() {
        let config = config_with(POLICY_CONF);
        let named = compile_named_policy(&config).unwrap();
        let (import, export) = (named.import.unwrap(), named.export.unwrap());
        // IN: only CUST-space passes, with LOCAL_PREF 200 set.
        let ok = run_filter(&import, route("203.0.113.0/24", vec![65001])).unwrap();
        assert_eq!(ok.local_pref(), 200);
        assert!(run_filter(&import, route("198.51.100.0/24", vec![65001])).is_none());
        // OUT: only community 65000:99 passes (implicit deny-all tail).
        let mut tagged = route("203.0.113.0/24", vec![65001]);
        tagged
            .attrs
            .push(PathAttribute::Communities(vec![65000 << 16 | 99]));
        assert!(run_filter(&export, tagged).is_some());
        assert!(run_filter(&export, route("203.0.113.0/24", vec![65001])).is_none());
    }

    #[test]
    fn unknown_filter_name_is_a_startup_error() {
        let config = config_with("router bgp 65000\n bgp router-id 10.0.0.1\n import MISSING\n");
        let err = compile_named_policy(&config).unwrap_err();
        assert!(err.contains("not found"), "{err}");
    }

    #[test]
    fn policy_grammar_error_carries_the_file_line_number() {
        // The undefined prefix-list is cited at the route-map entry's
        // head line — file line 4 through the blank-padded fragment.
        let config = config_with(
            "router bgp 65000\n bgp router-id 10.0.0.1\n import IN\nroute-map IN permit 10\n match ip address prefix-list NOPE\n",
        );
        let err = compile_named_policy(&config).unwrap_err();
        assert!(err.contains("undefined prefix-list"), "{err}");
        assert!(err.contains("line 4"), "{err}");
    }

    #[test]
    fn no_policy_stanzas_compiles_empty() {
        let config = config_with("router bgp 65000\n bgp router-id 10.0.0.1\n");
        let named = compile_named_policy(&config).unwrap();
        assert!(named.import.is_none());
        assert!(named.export.is_none());
    }
}
