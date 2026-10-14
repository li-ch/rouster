//! LSA origination builders (RFC 2328 §12.4): the router-LSA
//! (§12.4.1), the network-LSA a DR originates (§12.4.2), and the
//! AS-external-LSA for redistributed routes (§12.4.4).
//!
//! Pure builders: they take a snapshot of what the daemon knows
//! (interface states, adjacencies, the LSDB's sequence state) and
//! produce an [`Lsa`] whose sequence number the LSDB's
//! [`crate::lsdb::Lsdb::originate`] then stamps (§12.1's bookkeeping
//! stays in one place). Age 0, options per the area (§12.1's E-bit —
//! the v1 single area is external-capable), checksum/length filled
//! by encode.
//!
//! v1 shape disclosures:
//! - Router-LSA links: numbered p2p (type-1 + the type-3 stub for
//!   the subnet, §12.4.1.1), transit (type-2, broadcast DR case),
//!   and interface stubs (type-3). Virtual links (type-4) are
//!   §Deferred with §15.
//! - The E-bit of the router-LSA (ASBR status) turns on exactly
//!   when an AS-external LSA is being originated — §12.4.4's "the
//!   router then becomes an AS boundary router" sequencing, wired at
//!   the daemon.
//! - §12.4.4's Link State ID allocation handles the no-conflict
//!   case (the prefix's own network number); the collision path
//!   (ID already used by a different prefix → +1 walk) is v1
//!   omitted, disclosed.

use std::net::Ipv4Addr;

use crate::iface::InterfaceState;
use crate::lsa::{
    AsExternalLsa, LinkStateId, LinkType, Lsa, LsaBody, LsaHeader, LsaType, NetworkLsa, Options,
    RouterId, RouterLink, RouterLsa, SummaryLsa,
};

/// The daemon's per-interface snapshot the router-LSA builder needs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InterfaceAdv {
    /// §9's interface state — only ≥ PointToPoint contributes links.
    pub state: InterfaceState,
    /// The network type as configured (§C.3).
    pub p2p: bool,
    /// Our address on the interface.
    pub address: Ipv4Addr,
    /// The subnet mask (broadcast/numbered-p2p networks).
    pub mask: Ipv4Addr,
    /// The interface cost (§C.3).
    pub cost: u16,
    /// On p2p: the fully-adjacent neighbor's Router ID (type-1
    /// links appear only at Full, §12.4.1.1).
    pub p2p_neighbors_full: Vec<RouterId>,
    /// On broadcast, when we are DR: the fully-adjacent routers'
    /// IDs for the network-LSA (§12.4.2).
    pub attached_routers: Vec<RouterId>,
    /// On broadcast, when a DR has been elected (state DR/Backup/
    /// DROther, not Waiting): the DR's interface address (§12.4.1.2).
    pub dr_address: Option<Ipv4Addr>,
    /// §12.4.1.2's adjacency gate for the type-2 transit link: we
    /// are fully adjacent to the DR, or we are the DR and fully
    /// adjacent to at least one other router. Without it the
    /// interface is described in the Waiting form (a type-3 stub of
    /// the subnet).
    pub transit_adjacent: bool,
    /// A virtual link endpoint (§15/§D.3): the adjacency rides the
    /// transit area but the LSA is the BACKBONE's — one unnumbered
    /// type-4 link per fully adjacent endpoint. v1 Link Data: our
    /// own address on the transit network (RFC 2328 §12.4.1 names
    /// the MIB-II ifIndex for the unnumbered form — disclosed).
    pub virtual_link: bool,
}

/// Build the router-LSA (§12.4.1). `e_bit` mirrors §12.4.4: set when
/// redistributing external routes (an ASBR); `b_bit` when the router
/// is an area border router (§A.4.2); `nt_bit` when this NSSA border
/// router's translator state is enabled (RFC 3101 §3.1 — set only in
/// the router-LSA originated INTO the NSSA). The Link State ID of a
/// router-LSA is the router's own ID (§12.4.1).
pub fn build_router_lsa(
    own: RouterId,
    e_bit: bool,
    b_bit: bool,
    v_bit: bool,
    nt_bit: bool,
    interfaces: &[InterfaceAdv],
) -> Lsa {
    let mut links = Vec::new();
    for iface in interfaces {
        if iface.state < InterfaceState::PointToPoint {
            continue;
        }
        if iface.virtual_link {
            // §D.3: the virtual link is an unnumbered point-to-point
            // link (type 4) in the backbone's router-LSA — Link ID =
            // the other endpoint's Router ID, one per Full endpoint.
            for nbr in &iface.p2p_neighbors_full {
                links.push(RouterLink {
                    link_id: LinkStateId(nbr.0),
                    link_data: u32::from(iface.address),
                    link_type: LinkType::Virtual,
                    metric: iface.cost,
                    tos: vec![],
                });
            }
            continue;
        }
        if iface.p2p {
            // §12.4.1.1: a type-1 link per fully adjacent neighbor —
            // Link ID = neighbor's Router ID, Link Data = our own
            // interface address (numbered p2p).
            for nbr in &iface.p2p_neighbors_full {
                links.push(RouterLink {
                    link_id: LinkStateId(nbr.0),
                    link_data: u32::from(iface.address),
                    link_type: LinkType::PointToPoint,
                    metric: iface.cost,
                    tos: vec![],
                });
            }
            // ... and the numbered p2p subnet as a type-3 stub:
            // Link ID = the subnet number, Link Data = the mask.
            let subnet = u32::from(iface.address) & u32::from(iface.mask);
            links.push(RouterLink {
                link_id: LinkStateId(subnet),
                link_data: u32::from(iface.mask),
                link_type: LinkType::Stub,
                metric: iface.cost,
                tos: vec![],
            });
        } else {
            // §12.4.1.2 broadcast/NBMA: with a DR elected AND the
            // adjacency gate satisfied, a single type-2 transit link
            // (Link ID = the DR's interface address — possibly our
            // own — Link Data = our own address). Otherwise the
            // Waiting form: the subnet as a type-3 stub.
            let subnet = u32::from(iface.address) & u32::from(iface.mask);
            match (iface.dr_address, iface.transit_adjacent) {
                (Some(dr), true) => links.push(RouterLink {
                    link_id: LinkStateId(u32::from(dr)),
                    link_data: u32::from(iface.address),
                    link_type: LinkType::Transit,
                    metric: iface.cost,
                    tos: vec![],
                }),
                _ => links.push(RouterLink {
                    link_id: LinkStateId(subnet),
                    link_data: u32::from(iface.mask),
                    link_type: LinkType::Stub,
                    metric: iface.cost,
                    tos: vec![],
                }),
            }
        }
    }
    Lsa {
        header: LsaHeader {
            ls_age: 0,
            options: Options(Options::E),
            ls_type: LsaType::ROUTER,
            link_state_id: LinkStateId(own.0),
            adv_router: own,
            seq: 0, // stamped by Lsdb::originate
            checksum: 0,
            length: 0,
        },
        body: LsaBody::Router(RouterLsa {
            v_bit,
            e_bit,
            b_bit,
            nt_bit,
            links,
        }),
    }
}

/// Build the network-LSA the DR originates (§12.4.2): Link State ID
/// = the DR's own interface address, mask + the fully adjacent
/// routers (itself included). Called only in state DR.
pub fn build_network_lsa(own: RouterId, iface: &InterfaceAdv, dr_address: Ipv4Addr) -> Lsa {
    let mut attached = vec![own];
    attached.extend(iface.attached_routers.iter().copied());
    attached.sort_unstable();
    attached.dedup();
    Lsa {
        header: LsaHeader {
            ls_age: 0,
            options: Options(Options::E),
            ls_type: LsaType::NETWORK,
            link_state_id: LinkStateId(u32::from(dr_address)),
            adv_router: own,
            seq: 0,
            checksum: 0,
            length: 0,
        },
        body: LsaBody::Network(NetworkLsa {
            mask: iface.mask,
            attached,
        }),
    }
}

/// Build a summary-LSA (§12.4.3 / §A.4.4). Type 3 (network): Link
/// State ID = the network's address, mask + the routing-table cost.
/// Type 4 (ASBR): Link State ID = the ASBR's Router ID, mask 0 (the
/// §A.4.4 type-4 rule).
pub fn build_summary_lsa(
    own: RouterId,
    type4: bool,
    link_state_id: Ipv4Addr,
    mask: Ipv4Addr,
    metric: u32,
) -> Lsa {
    Lsa {
        header: LsaHeader {
            ls_age: 0,
            options: Options(Options::E),
            ls_type: if type4 {
                LsaType::SUMMARY_ASBR
            } else {
                LsaType::SUMMARY_NETWORK
            },
            link_state_id: LinkStateId(u32::from(link_state_id)),
            adv_router: own,
            seq: 0,
            checksum: 0,
            length: 0,
        },
        body: LsaBody::Summary(SummaryLsa {
            mask: if type4 { Ipv4Addr::UNSPECIFIED } else { mask },
            metric,
            tos: vec![],
        }),
    }
}

/// Build the type-7 NSSA-external-LSA for one external route
/// imported into an NSSA (RFC 3101 §2.3/§2.4): the type-5 body shape
/// with the header type 7, the P-bit in the header Options' N/P
/// position, and the forwarding address the caller selected
/// (§2.4's FA rules: a P-set LSA must carry a non-zero FA).
pub fn build_nssa_lsa(
    own: RouterId,
    network: Ipv4Addr,
    mask: Ipv4Addr,
    metric: u32,
    type2: bool,
    forwarding_address: Ipv4Addr,
    p_bit: bool,
) -> Lsa {
    let mut options = Options(0);
    if p_bit {
        options.0 |= Options::NP;
    }
    Lsa {
        header: LsaHeader {
            ls_age: 0,
            options,
            ls_type: LsaType::NSSA,
            link_state_id: LinkStateId(u32::from(network)),
            adv_router: own,
            seq: 0,
            checksum: 0,
            length: 0,
        },
        body: LsaBody::AsExternal(AsExternalLsa {
            mask,
            e_bit: type2,
            metric,
            forwarding_address,
            external_route_tag: 0,
            tos: vec![],
        }),
    }
}

/// Build the AS-external-LSA for one redistributed route (§12.4.4).
/// Type-2 (E-bit) with FRR's default metric 20; forwarding address
/// 0.0.0.0 (the ASBR itself — §12.4.4's default when no dedicated
/// forwarding address is configured).
pub fn build_external_lsa(
    own: RouterId,
    network: Ipv4Addr,
    mask: Ipv4Addr,
    metric: u32,
    type2: bool,
) -> Lsa {
    Lsa {
        header: LsaHeader {
            ls_age: 0,
            options: Options(Options::E),
            ls_type: LsaType::AS_EXTERNAL,
            // §12.4.4: the Link State ID is the external network
            // number (the no-conflict allocation; see module note).
            link_state_id: LinkStateId(u32::from(network)),
            adv_router: own,
            seq: 0,
            checksum: 0,
            length: 0,
        },
        body: LsaBody::AsExternal(AsExternalLsa {
            mask,
            e_bit: type2,
            metric,
            forwarding_address: Ipv4Addr::UNSPECIFIED,
            external_route_tag: 0,
            tos: vec![],
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::iface::InterfaceState::*;

    fn rid(s: &str) -> RouterId {
        RouterId::from_ipv4(s.parse().unwrap())
    }

    fn ip(s: &str) -> Ipv4Addr {
        s.parse().unwrap()
    }

    fn iface(p2p: bool, addr: &str, mask: &str, cost: u16) -> InterfaceAdv {
        InterfaceAdv {
            state: PointToPoint,
            p2p,
            address: ip(addr),
            mask: ip(mask),
            cost,
            p2p_neighbors_full: vec![],
            attached_routers: vec![],
            dr_address: None,
            transit_adjacent: false,
            virtual_link: false,
        }
    }

    #[test]
    fn router_lsa_numbers_a_p2p_adjacency() {
        // §12.4.1.1: one type-1 link to the Full neighbor plus the
        // numbered-subnet type-3 stub.
        let mut adv = iface(true, "10.77.0.1", "255.255.255.252", 10);
        adv.p2p_neighbors_full = vec![rid("10.255.2.1")];
        let lsa = build_router_lsa(rid("10.255.1.1"), false, false, false, false, &[adv]);
        assert_eq!(lsa.header.ls_type, LsaType::ROUTER);
        assert_eq!(lsa.header.link_state_id.0, u32::from(ip("10.255.1.1")));
        let LsaBody::Router(body) = &lsa.body else {
            panic!("router body");
        };
        assert!(!body.e_bit && !body.v_bit && !body.b_bit);
        assert_eq!(body.links.len(), 2);
        assert_eq!(body.links[0].link_type, LinkType::PointToPoint);
        assert_eq!(body.links[0].link_id.0, u32::from(ip("10.255.2.1")));
        assert_eq!(body.links[0].link_data, u32::from(ip("10.77.0.1")));
        assert_eq!(body.links[1].link_type, LinkType::Stub);
        assert_eq!(body.links[1].link_id.0, u32::from(ip("10.77.0.0")));
        assert_eq!(body.links[1].link_data, u32::from(ip("255.255.255.252")));
        // Round-trips through the codec (header checksum/length
        // filled by encode — compare against the computed form).
        let back = Lsa::decode(&lsa.encode()).unwrap();
        assert_eq!(back, lsa.with_computed_header());
    }

    #[test]
    fn down_interfaces_contribute_nothing() {
        let mut adv = iface(true, "10.77.0.1", "255.255.255.252", 10);
        adv.state = Down;
        adv.p2p_neighbors_full = vec![rid("10.255.2.1")];
        let lsa = build_router_lsa(rid("1.1.1.1"), false, false, false, false, &[adv]);
        let LsaBody::Router(body) = &lsa.body else {
            panic!()
        };
        assert!(body.links.is_empty());
    }

    #[test]
    fn type_seven_round_trips_with_p_bit_and_fa() {
        // RFC 3101 Appendix C: the type-7 body is the type-5 shape;
        // the P-bit rides the header Options' N/P position.
        let lsa = crate::origination::build_nssa_lsa(
            rid("1.1.1.1"),
            ip("192.0.2.0"),
            ip("255.255.255.0"),
            20,
            true,
            ip("10.0.0.1"),
            true,
        );
        assert_eq!(lsa.header.ls_type, crate::lsa::LsaType::NSSA);
        assert!(lsa.header.options.np_bit(), "P-bit set");
        let back = Lsa::decode(&lsa.encode()).unwrap();
        assert_eq!(back.header.ls_type, crate::lsa::LsaType::NSSA);
        assert!(back.header.options.np_bit(), "P-bit survives the codec");
        let crate::lsa::LsaBody::AsExternal(ext) = &back.body else {
            panic!("type-7 body decodes to the external shape")
        };
        assert_eq!(ext.forwarding_address, ip("10.0.0.1"));
        assert_eq!(ext.mask, ip("255.255.255.0"));
        assert!(ext.e_bit);
        assert_eq!(ext.metric, 20);
        // P clear form.
        let lsa = crate::origination::build_nssa_lsa(
            rid("1.1.1.1"),
            ip("192.0.2.0"),
            ip("255.255.255.0"),
            20,
            true,
            ip("0.0.0.0"),
            false,
        );
        assert!(!lsa.header.options.np_bit());
    }

    #[test]
    fn asbr_bit_is_carried() {
        // §12.4.4: originating type-5s makes the router an ASBR —
        // the E-bit lands in the router-LSA.
        let lsa = build_router_lsa(rid("1.1.1.1"), true, false, false, false, &[]);
        let LsaBody::Router(body) = &lsa.body else {
            panic!()
        };
        assert!(body.e_bit);
    }

    #[test]
    fn broadcast_transit_and_waiting_forms() {
        // §12.4.1.2's three shapes for a broadcast interface:
        // 1. DR elected + adjacent to it (or DR with a Full other):
        //    the type-2 transit link, Link ID = the DR's address.
        let mut adv = iface(false, "10.0.0.5", "255.255.255.0", 10);
        adv.dr_address = Some(ip("10.0.0.9"));
        adv.transit_adjacent = true;
        let lsa = build_router_lsa(rid("1.1.1.1"), false, false, false, false, &[adv]);
        let LsaBody::Router(body) = &lsa.body else {
            panic!()
        };
        assert_eq!(body.links.len(), 1);
        assert_eq!(body.links[0].link_type, LinkType::Transit);
        assert_eq!(body.links[0].link_id.0, u32::from(ip("10.0.0.9")));
        assert_eq!(body.links[0].link_data, u32::from(ip("10.0.0.5")));
        // 2. DR elected but not yet adjacent to it: the Waiting form
        //    (type-3 stub of the subnet).
        let mut adv = iface(false, "10.0.0.5", "255.255.255.0", 10);
        adv.dr_address = Some(ip("10.0.0.9"));
        adv.transit_adjacent = false;
        let lsa = build_router_lsa(rid("1.1.1.1"), false, false, false, false, &[adv]);
        let LsaBody::Router(body) = &lsa.body else {
            panic!()
        };
        assert_eq!(body.links.len(), 1);
        assert_eq!(body.links[0].link_type, LinkType::Stub);
        assert_eq!(body.links[0].link_id.0, u32::from(ip("10.0.0.0")));
        assert_eq!(body.links[0].link_data, u32::from(ip("255.255.255.0")));
        // 3. Still Waiting (no DR): the same stub form.
        let adv = iface(false, "10.0.0.5", "255.255.255.0", 10);
        let lsa = build_router_lsa(rid("1.1.1.1"), false, false, false, false, &[adv]);
        let LsaBody::Router(body) = &lsa.body else {
            panic!()
        };
        assert_eq!(body.links.len(), 1);
        assert_eq!(body.links[0].link_type, LinkType::Stub);
    }

    #[test]
    fn network_lsa_lists_attached_routers_deduped() {
        // §12.4.2: mask + all fully adjacent routers including the
        // DR itself; Link State ID = the DR's interface address.
        let mut adv = iface(false, "10.0.0.5", "255.255.255.0", 10);
        adv.attached_routers = vec![rid("2.2.2.2"), rid("1.1.1.1")];
        let lsa = build_network_lsa(rid("3.3.3.3"), &adv, ip("10.0.0.5"));
        assert_eq!(lsa.header.ls_type, LsaType::NETWORK);
        assert_eq!(lsa.header.link_state_id.0, u32::from(ip("10.0.0.5")));
        let LsaBody::Network(body) = &lsa.body else {
            panic!()
        };
        assert_eq!(
            body.attached,
            vec![rid("1.1.1.1"), rid("2.2.2.2"), rid("3.3.3.3")],
            "sorted, deduped, DR included"
        );
        assert_eq!(body.mask, ip("255.255.255.0"));
        let back = Lsa::decode(&lsa.encode()).unwrap();
        assert_eq!(back, lsa.with_computed_header());
    }

    #[test]
    fn summary_lsa_shapes() {
        // §12.4.3/§A.4.4: type 3 carries the network's mask and the
        // routing-table cost; type 4 names the ASBR (Link State ID =
        // its Router ID) with mask 0.
        let net = build_summary_lsa(
            rid("1.1.1.1"),
            false,
            ip("10.20.0.0"),
            ip("255.255.255.0"),
            27,
        );
        assert_eq!(net.header.ls_type, LsaType::SUMMARY_NETWORK);
        assert_eq!(net.header.link_state_id.0, u32::from(ip("10.20.0.0")));
        let LsaBody::Summary(body) = &net.body else {
            panic!()
        };
        assert_eq!(body.mask, ip("255.255.255.0"));
        assert_eq!(body.metric, 27);
        let back = Lsa::decode(&net.encode()).unwrap();
        assert_eq!(back, net.with_computed_header());
        let asbr = build_summary_lsa(rid("1.1.1.1"), true, ip("9.9.9.9"), ip("0.0.0.0"), 41);
        assert_eq!(asbr.header.ls_type, LsaType::SUMMARY_ASBR);
        assert_eq!(asbr.header.link_state_id.0, u32::from(ip("9.9.9.9")));
        let LsaBody::Summary(body) = &asbr.body else {
            panic!()
        };
        assert_eq!(body.mask, Ipv4Addr::UNSPECIFIED, "type-4 mask 0 (§A.4.4)");
        assert_eq!(body.metric, 41);
        let back = Lsa::decode(&asbr.encode()).unwrap();
        assert_eq!(back, asbr.with_computed_header());
    }

    #[test]
    fn external_lsa_shape() {
        // §A.4.5/§12.4.4: ID = network number, mask, E-bit for
        // type-2, forwarding 0.0.0.0.
        let lsa = build_external_lsa(
            rid("1.1.1.1"),
            ip("198.51.100.0"),
            ip("255.255.255.0"),
            20,
            true,
        );
        assert_eq!(lsa.header.ls_type, LsaType::AS_EXTERNAL);
        assert_eq!(lsa.header.link_state_id.0, u32::from(ip("198.51.100.0")));
        let LsaBody::AsExternal(body) = &lsa.body else {
            panic!()
        };
        assert!(body.e_bit);
        assert_eq!(body.metric, 20);
        assert_eq!(body.forwarding_address, Ipv4Addr::UNSPECIFIED);
        let back = Lsa::decode(&lsa.encode()).unwrap();
        assert_eq!(back, lsa.with_computed_header());
    }
}
