//! RPKI-derived validation in the decision path (W2-d M2/M3):
//!
//! - **ROV** (RFC 6811 §2): prefix-origin validity computed at import
//!   from the VRP table, recorded on the route (show-output
//!   visibility), with `reject-invalid` enforcement (the RFC's
//!   recommended local policy for Invalid; Valid/NotFound pass).
//! - **OTC / roles** (RFC 9234 §4/§5): per-neighbor Customer/Peer/
//!   Provider roles; the §5 ingress rules (reject leaked
//!   OTC-bearing routes from customers; reject OTC≠peer-AS from
//!   peers; synthesize OTC from providers/peers when absent) and the
//!   egress rules (synthesize OTC toward customers/peers; never
//!   propagate OTC-bearing routes to peers/providers).
//! - **ASPA** (draft-ietf-sidrops-aspa-verification-28 §5): the
//!   up/down-ramp verification at import, advisory (record-only, the
//!   default) or enforce (reject Invalid).
//!
//! Table sources: an RTR cache session (rpki::RtrClient filling a
//! SharedTables handle) or a static `vrp-file` fixture (tests and
//! offline operation). Validation only runs on eBGP-learned routes —
//! validity is an edge property; iBGP-carried validity is §Deferred
//! with iBGP policy propagation.

use std::collections::BTreeMap;
use std::net::IpAddr;
use std::sync::Arc;

use rpki::{AspaTable, AspaValidity, OriginAsn, PeerRelation, Validity, VrpTable};
use tracing::info;

use crate::attr::{attr_type, PathAttribute};
use crate::config::{AspaMode, Role};
use crate::policy_engine::upsert_attr;
use crate::rib::Route;

/// Where the VRP/ASPA tables come from.
pub enum RpkiTables {
    /// A `vrp-file` snapshot loaded at startup (static fixture mode).
    Static(Arc<VrpTable>, Arc<AspaTable>),
    /// A live RTR session (RFC 8210) — the client's shared handle.
    Rtr(rpki::client::SharedTables),
}

impl RpkiTables {
    /// Run `f` against a consistent (vrps, aspa) view.
    pub fn with<R>(&self, f: impl FnOnce(&VrpTable, &AspaTable) -> R) -> R {
        match self {
            Self::Static(vrps, aspa) => f(vrps, aspa),
            Self::Rtr(shared) => {
                let tables = shared.lock().unwrap();
                f(&tables.vrps, &tables.aspa)
            }
        }
    }
}

/// Parse a `vrp-file`: one record per line, `#` comments, blank lines
/// skipped.
///
/// ```text
/// vrp 192.0.2.0/24 max 24 as 64512
/// vrp 2001:db8:1::/48 max 64 as 64512
/// aspa 64501 provider 64502 64503
/// ```
///
/// ASPA lines carry the whole U-SPAS in one record (8210bis-27 §5.12
/// shape: one announcement per customer AS). Unknown lines are errors
/// carrying the line number — strict, the bgpd.conf convention.
pub fn parse_vrp_file(text: &str) -> Result<(VrpTable, AspaTable), String> {
    let mut vrps = VrpTable::new();
    let mut aspa = AspaTable::new();
    for (idx, raw) in text.lines().enumerate() {
        let line_no = idx + 1;
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let tokens: Vec<&str> = line.split_whitespace().collect();
        match tokens.as_slice() {
            ["vrp", prefix, "max", max_len, "as", asn] => {
                let prefix = prefix
                    .parse()
                    .map_err(|e| format!("line {line_no}: bad prefix `{prefix}`: {e}"))?;
                let max_len: u8 = max_len
                    .parse()
                    .map_err(|_| format!("line {line_no}: max expects 0..=128, got `{max_len}`"))?;
                let asn: u32 = asn
                    .parse()
                    .map_err(|_| format!("line {line_no}: as expects an AS number, got `{asn}`"))?;
                vrps.apply(
                    rpki::Vrp {
                        prefix,
                        max_len,
                        asn,
                    },
                    rpki::pdu::PayloadFlags::ANNOUNCE,
                )
                .map_err(|e| format!("line {line_no}: {e}"))?;
            }
            ["aspa", customer, "provider", providers @ ..] if !providers.is_empty() => {
                let customer: u32 = customer.parse().map_err(|_| {
                    format!("line {line_no}: aspa expects an AS number, got `{customer}`")
                })?;
                let mut set = std::collections::BTreeSet::new();
                for p in providers {
                    let asn: u32 = p.parse().map_err(|_| {
                        format!("line {line_no}: provider expects an AS number, got `{p}`")
                    })?;
                    set.insert(asn);
                }
                aspa.apply(customer, rpki::pdu::PayloadFlags::ANNOUNCE, set)
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
    Ok((vrps, aspa))
}

/// The import-side validation gate: ROV, OTC ingress, ASPA — in that
/// order (RFC 6811 §2 validity is a property of the received
/// announcement, computed before any local filter runs; the typed
/// filter sees the final state).
pub struct ValidationGate {
    pub tables: Option<RpkiTables>,
    pub reject_invalid: bool,
    pub aspa: AspaMode,
    /// RFC 9234 §4 roles by neighbor address.
    pub roles: BTreeMap<IpAddr, Role>,
}

impl ValidationGate {
    /// Apply validation to one imported route: `None` = ineligible
    /// (rejected), `Some` = accepted (validity recorded, OTC possibly
    /// synthesized). iBGP-learned routes pass untouched.
    pub fn apply(&self, mut route: Route) -> Option<Route> {
        if route.internal {
            return Some(route);
        }
        let Some(tables) = &self.tables else {
            // No RPKI: only the OTC rules can still apply (roles are
            // configured independently of the rpki stanza).
            return self.otc_ingress(route);
        };
        // ---- ROV (RFC 6811 §2) -----------------------------------
        let validity = tables.with(|vrps, _| {
            let origin = match route.origin_as() {
                Some(asn) => OriginAsn::As(asn),
                None => OriginAsn::None,
            };
            vrps.validate(&route.prefix, origin)
        });
        route.rov = Some(validity);
        if validity == Validity::Invalid && self.reject_invalid {
            info!(peer = %route.source.address, prefix = %route.prefix,
                "bgpd: route rejected, RPKI Invalid (RFC 6811 §2)");
            return None;
        }
        // ---- ASPA (verification-28 §5.5/§5.6) ---------------------
        if let Some(role) = self.roles.get(&route.source.address) {
            let path = rpki_path(route.attr(attr_type::AS_PATH));
            let relation = peer_relation(*role);
            let verdict = tables
                .with(|_, aspa| rpki::verify(aspa, &path, Some(route.source.remote_as), relation));
            route.aspa = Some(verdict);
            if verdict == AspaValidity::Invalid && self.aspa == AspaMode::Enforce {
                info!(peer = %route.source.address, prefix = %route.prefix,
                    "bgpd: route rejected, ASPA Invalid (aspa enforce)");
                return None;
            }
        }
        // ---- OTC ingress (RFC 9234 §5) ----------------------------
        self.otc_ingress(route)
    }

    /// RFC 9234 §5 ingress rules 1-3, by role:
    ///
    /// 1. "If a route with the OTC Attribute is received from a
    ///    Customer or an RS-Client, then it is a route leak and MUST
    ///    be considered ineligible."
    /// 2. OTC from a Peer is ineligible unless the value equals the
    ///    peer's AS number.
    /// 3. "If a route is received from a Provider, a Peer, or an RS
    ///    and the OTC Attribute is not present, then it MUST be added
    ///    with a value equal to the AS number of the remote AS."
    fn otc_ingress(&self, mut route: Route) -> Option<Route> {
        let Some(role) = self.roles.get(&route.source.address) else {
            return Some(route);
        };
        let remote_as = route.source.remote_as;
        let otc = route.otc();
        match (*role, otc) {
            (Role::Customer, Some(_)) => {
                info!(peer = %route.source.address, prefix = %route.prefix,
                    "bgpd: route rejected, OTC from a customer is a route leak (RFC 9234 §5)");
                None
            }
            (Role::Peer, Some(v)) if v != remote_as => {
                info!(peer = %route.source.address, prefix = %route.prefix, otc = v,
                    "bgpd: route rejected, OTC != peer AS is a route leak (RFC 9234 §5)");
                None
            }
            (Role::Provider, None) | (Role::Peer, None) => {
                upsert_attr(&mut route.attrs, PathAttribute::Otc(remote_as));
                Some(route)
            }
            _ => Some(route),
        }
    }

    /// RFC 9234 §5 egress rules 1-2:
    ///
    /// 1. "If a route is to be advertised to a Customer, a Peer, or
    ///    an RS-Client (when the sender is an RS), and the OTC
    ///    Attribute is not present, then ... an OTC Attribute MUST be
    ///    added" with the local AS's number.
    /// 2. "If a route already contains the OTC Attribute, it MUST NOT
    ///    be propagated to Providers, Peers, or RSes."
    ///
    /// Returns the egress decision: `None` = suppressed, `Some(route)`
    /// = advertise (OTC synthesized when rule 1 fires). Unconfigured
    /// roles: no OTC behavior.
    pub fn otc_egress(&self, route: &Route, to_peer: IpAddr, local_as: u32) -> Option<Route> {
        let Some(role) = self.roles.get(&to_peer) else {
            return Some(route.clone());
        };
        match (*role, route.otc()) {
            (Role::Peer, Some(_)) | (Role::Provider, Some(_)) => None, // rule 2
            (Role::Customer, None) | (Role::Peer, None) => {
                let mut out = route.clone();
                upsert_attr(&mut out.attrs, PathAttribute::Otc(local_as)); // rule 1
                Some(out)
            }
            _ => Some(route.clone()),
        }
    }
}

impl crate::rib::ImportPolicy for ValidationGate {
    fn import(&self, route: Route) -> Option<Route> {
        self.apply(route)
    }
}

/// The bgpd wire AS_PATH shape the rpki verifier consumes.
fn rpki_path(attr: Option<&PathAttribute>) -> rpki::AsPath {
    match attr {
        Some(PathAttribute::AsPath(p)) => rpki::AsPath {
            segments: p
                .segments
                .iter()
                .map(|seg| match seg {
                    crate::attr::AsSegment::Set(v) => rpki::PathSegment::AsSet(v.clone()),
                    crate::attr::AsSegment::Sequence(v) => rpki::PathSegment::AsSequence(v.clone()),
                })
                .collect(),
        },
        _ => rpki::AsPath::default(),
    }
}

/// RFC 9234 §4 role → the ASPA verify procedure (verification-28 §6.3
/// maps BGP roles onto PeerRelation).
fn peer_relation(role: Role) -> PeerRelation {
    match role {
        Role::Customer => PeerRelation::Customer,
        Role::Peer => PeerRelation::Peer,
        Role::Provider => PeerRelation::Provider,
    }
}

/// Build the table source the config names: spawn the RTR client for
/// `cache` (the client fills its `SharedTables` and keeps them fresh —
/// tokio TCP only, no new dependencies) or load the `vrp-file`
/// fixture. `None` when the rpki stanza is absent.
pub fn tables_from_config(
    rpki: &crate::config::RpkiConfig,
    shutdown: tokio::sync::watch::Receiver<bool>,
) -> Result<Option<RpkiTables>, String> {
    if let Some((host, port)) = &rpki.cache {
        let addr = std::net::SocketAddr::new(
            host.parse()
                .map_err(|e| format!("rpki cache `{host}` is not an address: {e}"))?,
            *port,
        );
        let (client, tables) = rpki::RtrClient::new(rpki::ClientConfig::new(addr));
        client.spawn(shutdown);
        Ok(Some(RpkiTables::Rtr(tables)))
    } else if let Some(path) = &rpki.vrp_file {
        let text = std::fs::read_to_string(path)
            .map_err(|e| format!("cannot read vrp-file {}: {e}", path.display()))?;
        let (vrps, aspa) = parse_vrp_file(&text)?;
        info!(path = %path.display(), vrps = vrps.len(), aspas = aspa.len(),
            "bgpd: rpki static tables loaded");
        Ok(Some(RpkiTables::Static(Arc::new(vrps), Arc::new(aspa))))
    } else {
        Ok(None)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::attr::AsPath;
    use crate::message::BgpUpdate;
    use crate::peer::PeerInfo;
    use crate::rib::{AcceptAll, ImportPolicy, LocRib};
    use std::net::Ipv4Addr;

    fn tables(vrps: &[(&str, u8, u32)], aspas: &[(u32, &[u32])]) -> RpkiTables {
        let mut v = VrpTable::new();
        for (prefix, max_len, asn) in vrps {
            v.apply(
                rpki::Vrp {
                    prefix: prefix.parse().unwrap(),
                    max_len: *max_len,
                    asn: *asn,
                },
                rpki::pdu::PayloadFlags::ANNOUNCE,
            )
            .unwrap();
        }
        let mut a = AspaTable::new();
        for (cas, providers) in aspas {
            a.apply(
                *cas,
                rpki::pdu::PayloadFlags::ANNOUNCE,
                providers.iter().copied().collect(),
            )
            .unwrap();
        }
        RpkiTables::Static(Arc::new(v), Arc::new(a))
    }

    fn gate_with(tables: RpkiTables, roles: &[(&str, u32, Role)]) -> ValidationGate {
        ValidationGate {
            tables: Some(tables),
            reject_invalid: true,
            aspa: AspaMode::Advisory,
            roles: roles
                .iter()
                .map(|(addr, _asn, role)| (addr.parse().unwrap(), *role))
                .collect(),
        }
    }

    fn route_from(prefix: &str, peer_addr: &str, remote_as: u32, path: Vec<u32>) -> Route {
        Route::new(
            prefix.parse().unwrap(),
            vec![
                PathAttribute::Origin(crate::attr::Origin::Igp),
                PathAttribute::AsPath(AsPath::sequence(path)),
                PathAttribute::NextHop(Ipv4Addr::new(192, 0, 2, 1)),
            ],
            PeerInfo {
                address: peer_addr.parse().unwrap(),
                remote_as,
                bgp_id: Some(Ipv4Addr::new(10, 1, 1, 1)),
            },
            false,
        )
    }

    // ---- RFC 6811 §2 / RFC 6483 §2 matrix through the gate --------

    /// The single-ROA matrix (ROA 192.0.2.0/24-24 AS 64512) plus the
    /// NotFound column, driven through the import gate as a table.
    #[test]
    fn rov_matrix_through_the_import_gate() {
        let gate = gate_with(
            tables(&[("192.0.2.0/24", 24, 64512)], &[]),
            &[("192.0.2.9", 65001, Role::Peer)],
        );
        let cases: &[(&str, u32, Validity, bool)] = &[
            // (route, origin, expected validity, accepted)
            ("198.51.100.0/24", 64512, Validity::NotFound, true), // non-intersecting
            ("192.0.2.0/24", 64512, Validity::Valid, true),       // exact + matching AS
            ("192.0.2.0/24", 64513, Validity::Invalid, false),    // exact + wrong AS
            ("192.0.2.128/25", 64512, Validity::Invalid, false),  // beyond maxLength
        ];
        for (prefix, origin, validity, accepted) in cases {
            let route = route_from(prefix, "192.0.2.9", 65001, vec![65001, *origin]);
            let out = gate.apply(route);
            assert_eq!(out.is_some(), *accepted, "{prefix} from AS {origin}");
            if *accepted {
                // Validity stays visible on the stored path.
                assert_eq!(
                    out.unwrap().rov,
                    Some(*validity),
                    "{prefix} from AS {origin}"
                );
            }
        }
    }

    #[test]
    fn rov_validity_recorded_when_not_enforced() {
        // reject-invalid false: Invalid is recorded but kept —
        // Valid/NotFound pass either way (RFC 6811 §2's reject is a
        // local-policy choice).
        let mut gate = gate_with(
            tables(&[("192.0.2.0/24", 24, 64512)], &[]),
            &[("192.0.2.9", 65001, Role::Peer)],
        );
        gate.reject_invalid = false;
        let out = gate
            .apply(route_from(
                "192.0.2.0/24",
                "192.0.2.9",
                65001,
                vec![65001, 64513],
            ))
            .unwrap();
        assert_eq!(out.rov, Some(Validity::Invalid), "recorded, not dropped");
    }

    #[test]
    fn rov_origin_none_from_trailing_as_set_is_invalid() {
        // RFC 6811 §2: an origin of NONE never Matches — Covered but
        // unmatched is Invalid, so the default gate rejects it.
        let mut gate = gate_with(
            tables(&[("192.0.2.0/24", 24, 64512)], &[]),
            &[("192.0.2.9", 65001, Role::Peer)],
        );
        let mut route = route_from("192.0.2.0/24", "192.0.2.9", 65001, vec![]);
        route.attrs[1] = PathAttribute::AsPath(AsPath {
            segments: vec![
                crate::attr::AsSegment::Sequence(vec![65001]),
                crate::attr::AsSegment::Set(vec![64512]),
            ],
        });
        assert!(
            gate.apply(route.clone()).is_none(),
            "Invalid by origin NONE, rejected"
        );
        gate.reject_invalid = false;
        let out = gate.apply(route).unwrap();
        assert_eq!(out.rov, Some(Validity::Invalid));
    }

    #[test]
    fn no_rpki_tables_leaves_routes_untouched() {
        let gate = ValidationGate {
            tables: None,
            reject_invalid: true,
            aspa: AspaMode::Enforce,
            roles: BTreeMap::new(),
        };
        let route = route_from("203.0.113.0/24", "192.0.2.9", 65001, vec![65001]);
        let out = gate.apply(route.clone()).unwrap();
        assert_eq!(out, route);
        assert_eq!(out.rov, None);
        assert_eq!(out.aspa, None);
    }

    #[test]
    fn ibgp_routes_skip_validation() {
        let gate = gate_with(
            tables(&[("192.0.2.0/24", 24, 64512)], &[]),
            &[("192.0.2.9", 65000, Role::Peer)],
        );
        let mut route = route_from("192.0.2.0/24", "192.0.2.9", 65000, vec![64513]);
        route.internal = true;
        let out = gate.apply(route).unwrap();
        assert_eq!(out.rov, None, "validity is an eBGP edge property (v1)");
    }

    // ---- RFC 9234 §5 OTC, table-driven from the rules ------------

    #[test]
    fn otc_from_customer_is_a_leak() {
        // §5 ingress rule 1 verbatim.
        let gate = gate_with(tables(&[], &[]), &[("192.0.2.9", 65010, Role::Customer)]);
        let mut route = route_from("203.0.113.0/24", "192.0.2.9", 65010, vec![65010]);
        route.attrs.push(PathAttribute::Otc(65099));
        assert!(gate.apply(route).is_none());
    }

    #[test]
    fn otc_from_peer_value_rules() {
        let gate = gate_with(tables(&[], &[]), &[("192.0.2.9", 65010, Role::Peer)]);
        // OTC == peer AS: legitimate (ingress rule 2's allowed case).
        let mut ok = route_from("203.0.113.0/24", "192.0.2.9", 65010, vec![65010]);
        ok.attrs.push(PathAttribute::Otc(65010));
        assert!(gate.apply(ok).is_some());
        // OTC != peer AS: a route leak, ineligible.
        let mut bad = route_from("203.0.113.0/24", "192.0.2.9", 65010, vec![65010]);
        bad.attrs.push(PathAttribute::Otc(65099));
        assert!(gate.apply(bad).is_none());
    }

    #[test]
    fn otc_synthesized_from_provider_and_peer_when_absent() {
        // §5 ingress rule 3: OTC := the remote AS.
        for role in [Role::Provider, Role::Peer] {
            let gate = gate_with(tables(&[], &[]), &[("192.0.2.9", 65010, role)]);
            let out = gate
                .apply(route_from(
                    "203.0.113.0/24",
                    "192.0.2.9",
                    65010,
                    vec![65010, 64500],
                ))
                .unwrap();
            assert_eq!(out.otc(), Some(65010), "{role:?}");
        }
    }

    #[test]
    fn otc_from_provider_preserved_unchanged() {
        // "Once the OTC Attribute has been set, it MUST be preserved
        // unchanged."
        let gate = gate_with(tables(&[], &[]), &[("192.0.2.9", 65010, Role::Provider)]);
        let mut route = route_from("203.0.113.0/24", "192.0.2.9", 65010, vec![65010]);
        route.attrs.push(PathAttribute::Otc(65042));
        let out = gate.apply(route).unwrap();
        assert_eq!(out.otc(), Some(65042));
    }

    #[test]
    fn otc_egress_rules() {
        let gate = gate_with(tables(&[], &[]), &[]);
        let roles = |r: Role| ValidationGate {
            tables: None,
            reject_invalid: true,
            aspa: AspaMode::Advisory,
            roles: BTreeMap::from([("192.0.2.9".parse().unwrap(), r)]),
        };
        let plain = route_from("203.0.113.0/24", "198.51.100.9", 65020, vec![65020]);
        let mut marked = plain.clone();
        marked.attrs.push(PathAttribute::Otc(65010));
        let to: IpAddr = "192.0.2.9".parse().unwrap();

        // Egress rule 1: to a Customer without OTC -> add local AS.
        let out = roles(Role::Customer).otc_egress(&plain, to, 65000).unwrap();
        assert_eq!(out.otc(), Some(65000));
        // Egress rule 1 (Peer reading): to a Peer without OTC -> add
        // local AS as well ("to a Customer, a Peer, or an RS-Client").
        let out = roles(Role::Peer).otc_egress(&plain, to, 65000).unwrap();
        assert_eq!(out.otc(), Some(65000));
        // Egress rule 2: OTC-bearing must not reach Providers or Peers.
        assert!(roles(Role::Provider)
            .otc_egress(&marked, to, 65000)
            .is_none());
        assert!(roles(Role::Peer).otc_egress(&marked, to, 65000).is_none());
        // ...but flows down to Customers unchanged.
        let out = roles(Role::Customer)
            .otc_egress(&marked, to, 65000)
            .unwrap();
        assert_eq!(out.otc(), Some(65010), "preserved unchanged");
        // Unconfigured role: no OTC behavior at all.
        assert_eq!(
            gate.otc_egress(&plain, to, 65000).unwrap().otc(),
            None,
            "no role, no synthesis"
        );
    }

    #[test]
    fn otc_unconfigured_roles_leave_import_untouched() {
        // Tables present but no role for the peer: ROV still runs (the
        // empty table says NotFound); OTC is neither rejected nor
        // synthesized.
        let gate = gate_with(tables(&[], &[]), &[]);
        let mut route = route_from("203.0.113.0/24", "192.0.2.9", 65010, vec![65010]);
        route.attrs.push(PathAttribute::Otc(65099));
        let out = gate.apply(route).unwrap();
        assert_eq!(out.otc(), Some(65099), "unconfigured role: untouched");
        assert_eq!(out.rov, Some(Validity::NotFound), "ROV still computed");
    }

    // ---- the LocRib pipeline (ROV + policy in one announce) -------

    #[test]
    fn loc_rib_import_rejects_rpki_invalid() {
        // The M4 smoke's unit-level shape: an Invalid prefix never
        // reaches Adj-RIB-In, a Valid one does.
        let gate = Arc::new(gate_with(
            tables(&[("192.0.2.0/24", 24, 64512)], &[]),
            &[("192.0.2.9", 65001, Role::Peer)],
        ));
        let mut rib = LocRib::with_policy(65000, gate);
        let peer = PeerInfo {
            address: "192.0.2.9".parse().unwrap(),
            remote_as: 65001,
            bgp_id: Some(Ipv4Addr::new(10, 1, 1, 1)),
        };
        let update = BgpUpdate {
            attrs: vec![
                PathAttribute::Origin(crate::attr::Origin::Igp),
                PathAttribute::AsPath(AsPath::sequence([65001, 64513])),
                PathAttribute::NextHop("192.0.2.9".parse().unwrap()),
            ],
            nlri: vec!["192.0.2.0/24".parse().unwrap()],
            ..Default::default()
        };
        rib.announce(&peer, &update);
        assert_eq!(rib.route_count(), 0, "Invalid never enters Adj-RIB-In");
        let update = BgpUpdate {
            attrs: vec![
                PathAttribute::Origin(crate::attr::Origin::Igp),
                PathAttribute::AsPath(AsPath::sequence([65001, 64512])),
                PathAttribute::NextHop("192.0.2.9".parse().unwrap()),
            ],
            nlri: vec!["192.0.2.0/24".parse().unwrap()],
            ..Default::default()
        };
        rib.announce(&peer, &update);
        assert_eq!(rib.route_count(), 1, "Valid passes");
        // And the recorded validity is visible on the stored path.
        let changes = rib.recompute();
        assert_eq!(changes[0].best.as_ref().unwrap().rov, Some(Validity::Valid));
    }

    #[test]
    fn accept_all_still_identity_with_new_fields() {
        let route = route_from("203.0.113.0/24", "192.0.2.9", 65001, vec![65001]);
        assert_eq!(AcceptAll.import(route.clone()).unwrap(), route);
    }

    // ---- vrp-file parser ------------------------------------------

    #[test]
    fn vrp_file_parses_vrps_and_aspas() {
        let (vrps, aspa) = parse_vrp_file(
            "# fixture\nvrp 192.0.2.0/24 max 24 as 64512\nvrp 2001:db8:1::/48 max 64 as 64512\n\naspa 64501 provider 64502 64503\n",
        )
        .unwrap();
        assert_eq!(vrps.len(), 2);
        assert_eq!(aspa.len(), 1);
        assert_eq!(aspa.get(64501).unwrap().len(), 2);
        // And it drives validation.
        let gate = gate_with(
            RpkiTables::Static(Arc::new(vrps), Arc::new(aspa)),
            &[("192.0.2.9", 65001, Role::Peer)],
        );
        let out = gate
            .apply(route_from(
                "192.0.2.0/24",
                "192.0.2.9",
                65001,
                vec![65001, 64512],
            ))
            .unwrap();
        assert_eq!(out.rov, Some(Validity::Valid));
    }

    #[test]
    fn vrp_file_errors_carry_line_numbers() {
        let err = parse_vrp_file("vrp 192.0.2.0/24 max 24 as 64512\njunk line here\n").unwrap_err();
        assert!(err.contains("line 2"), "{err}");
        let err = parse_vrp_file("vrp nope max 24 as 64512\n").unwrap_err();
        assert!(err.contains("line 1"), "{err}");
        let err = parse_vrp_file("aspa 64501 provider\n").unwrap_err();
        assert!(err.contains("line 1"), "{err}");
    }

    // ---- M3: ASPA in the decision path ----------------------------
    // The P2-c lattice shapes (rpki/src/aspa.rs tests) driven through
    // the bgpd gate: the verdict a rouster bgpd would record/reject
    // with, per neighbor role and aspa mode.

    fn aspa_gate(aspas: &[(u32, &[u32])], role: Role, mode: AspaMode) -> ValidationGate {
        ValidationGate {
            tables: Some(tables(&[], aspas)),
            reject_invalid: true,
            aspa: mode,
            roles: BTreeMap::from([("192.0.2.9".parse().unwrap(), role)]),
        }
    }

    #[test]
    fn aspa_clean_customer_chain_is_valid_advisory_and_enforce() {
        // 64501's provider is 64502; we receive [64502, 64501] from our
        // customer 64502: §5.5 with a pure up-ramp ⇒ Valid, accepted
        // under either mode with the verdict recorded.
        for mode in [AspaMode::Advisory, AspaMode::Enforce] {
            let gate = aspa_gate(&[(64501, &[64502])], Role::Customer, mode);
            let out = gate
                .apply(route_from(
                    "203.0.113.0/24",
                    "192.0.2.9",
                    64502,
                    vec![64502, 64501],
                ))
                .unwrap_or_else(|| panic!("{mode:?}"));
            assert_eq!(out.aspa, Some(AspaValidity::Valid), "{mode:?}");
        }
    }

    #[test]
    fn aspa_unattested_hop_is_unknown_not_rejected_even_enforcing() {
        // Same path but no attestation: Unknown — enforce rejects only
        // Invalid (verification-28 §5: Unknown means unverifiable, not
        // bogus).
        let gate = aspa_gate(&[], Role::Customer, AspaMode::Enforce);
        let out = gate
            .apply(route_from(
                "203.0.113.0/24",
                "192.0.2.9",
                64502,
                vec![64502, 64501],
            ))
            .unwrap();
        assert_eq!(out.aspa, Some(AspaValidity::Unknown));
    }

    #[test]
    fn aspa_upstream_leak_invalid_advisory_records_enforce_rejects() {
        // 64503 learned from a peer and leaked downstream; we (the
        // customer) see [64503, 64502, 64501] where 64503 ∉ SPAS(64502):
        // max_up_ramp 2 < 3 ⇒ Invalid (§5.5 step 4).
        let path = vec![64503, 64502, 64501];
        let aspas = [(64501, &[64502][..]), (64502, &[64500][..])];
        let advisory = aspa_gate(&aspas, Role::Customer, AspaMode::Advisory);
        let out = advisory
            .apply(route_from(
                "203.0.113.0/24",
                "192.0.2.9",
                64503,
                path.clone(),
            ))
            .unwrap();
        assert_eq!(out.aspa, Some(AspaValidity::Invalid), "recorded only");
        let enforce = aspa_gate(&aspas, Role::Customer, AspaMode::Enforce);
        assert!(
            enforce
                .apply(route_from("203.0.113.0/24", "192.0.2.9", 64503, path))
                .is_none(),
            "enforce rejects the leak"
        );
    }

    #[test]
    fn aspa_downstream_leak_from_provider_rejected_when_enforcing() {
        // §5.6: provider 64504 hands us [64504, 64505, 64501] — no ramp
        // tiling exists ⇒ Invalid; from a provider the downstream
        // procedure applies (role → PeerRelation::Provider).
        let aspas = [
            (64501, &[64502][..]),
            (64504, &[64599][..]),
            (64505, &[64506][..]),
        ];
        let path = vec![64504, 64505, 64501];
        let enforce = aspa_gate(&aspas, Role::Provider, AspaMode::Enforce);
        assert!(enforce
            .apply(route_from(
                "203.0.113.0/24",
                "192.0.2.9",
                64504,
                path.clone()
            ))
            .is_none());
        let advisory = aspa_gate(&aspas, Role::Provider, AspaMode::Advisory);
        assert_eq!(
            advisory
                .apply(route_from("203.0.113.0/24", "192.0.2.9", 64504, path))
                .unwrap()
                .aspa,
            Some(AspaValidity::Invalid)
        );
    }

    #[test]
    fn aspa_neighbor_mismatch_from_peer_is_invalid() {
        // §5.5 step 2: the most recently added AS must be the neighbor.
        // The gate feeds the session's remote AS, so a forged first hop
        // is caught even with clean attestations elsewhere.
        let gate = aspa_gate(&[(64501, &[64502])], Role::Peer, AspaMode::Enforce);
        assert!(
            gate.apply(route_from(
                "203.0.113.0/24",
                "192.0.2.9",
                64599,
                vec![64502, 64501]
            ))
            .is_none(),
            "neighbor 64599 != first hop 64502"
        );
    }

    #[test]
    fn aspa_as_set_path_is_invalid_per_rfc_9774_prerequisite() {
        // §5.5 step 3: an AS_SET anywhere makes the path Invalid (the
        // RFC 9774 treat-as-withdraw prerequisite; enforce drops it).
        let gate = aspa_gate(&[(64501, &[64502])], Role::Customer, AspaMode::Enforce);
        let mut route = route_from("203.0.113.0/24", "192.0.2.9", 64502, vec![]);
        route.attrs[1] = PathAttribute::AsPath(AsPath {
            segments: vec![
                crate::attr::AsSegment::Sequence(vec![64502]),
                crate::attr::AsSegment::Set(vec![64501]),
            ],
        });
        assert!(gate.apply(route).is_none());
    }

    #[test]
    fn aspa_dual_provider_path_resolves_valid_from_provider() {
        // §5.6 dual-homed origin: [64503, 64502, 64501] from provider
        // 64503 where SPAS(64501) = {64502, 64503} ⇒ Valid.
        let gate = aspa_gate(
            &[(64501, &[64502, 64503])],
            Role::Provider,
            AspaMode::Enforce,
        );
        let out = gate
            .apply(route_from(
                "203.0.113.0/24",
                "192.0.2.9",
                64503,
                vec![64503, 64502, 64501],
            ))
            .unwrap();
        assert_eq!(out.aspa, Some(AspaValidity::Valid));
    }

    #[test]
    fn aspa_requires_a_role_to_run() {
        // No role configured: no procedure selection is possible —
        // nothing recorded, nothing rejected (honest Unknown-by-
        // omission; verification-28 §6.3 keys off the RFC 9234 role).
        let gate = ValidationGate {
            tables: Some(tables(&[], &[(64501, &[64502])])),
            reject_invalid: true,
            aspa: AspaMode::Enforce,
            roles: BTreeMap::new(),
        };
        let out = gate
            .apply(route_from(
                "203.0.113.0/24",
                "192.0.2.9",
                64503,
                vec![64503, 64502, 64501],
            ))
            .unwrap();
        assert_eq!(out.aspa, None);
        assert_eq!(out.rov, Some(Validity::NotFound), "ROV still runs");
    }

    #[test]
    fn aspa_advisory_is_the_v1_default_through_config() {
        let config = crate::config::parse_config(
            "router bgp 65000\nbgp router-id 10.0.0.1\nneighbor 192.0.2.9 remote-as 64503\nneighbor 192.0.2.9 role customer\n",
        )
        .unwrap();
        assert_eq!(config.aspa, AspaMode::Advisory);
        assert!(
            config.neighbors.values().all(|n| n.role.is_some()),
            "roles parse independently of the rpki stanza"
        );
    }
}
