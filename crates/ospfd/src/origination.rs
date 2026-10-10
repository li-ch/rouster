//! LSA origination builders (RFC 2328 §12.4): the router-LSA
//! (§12.4.1), the network-LSA a DR originates (§12.4.2), and the
//! AS-external-LSA for redistributed routes (§12.4.3).
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
//!   when an AS-external LSA is being originated — §12.4.3's "the
//!   router then becomes an AS boundary router" sequencing, wired at
//!   the daemon.
//! - §12.4.3's Link State ID allocation handles the no-conflict
//!   case (the prefix's own network number); the collision path
//!   (ID already used by a different prefix → +1 walk) is v1
//!   omitted, disclosed.

use std::net::Ipv4Addr;

use crate::iface::InterfaceState;
use crate::lsa::{
    AsExternalLsa, LinkStateId, LinkType, Lsa, LsaBody, LsaHeader, LsaType, NetworkLsa, Options,
    RouterId, RouterLink, RouterLsa,
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
    /// DROther): the DR's interface address for the type-2 transit
    /// link (§12.4.1.2).
    pub dr_address: Option<Ipv4Addr>,
}

/// Build the router-LSA (§12.4.1). `e_bit` mirrors §12.4.3: set when
/// redistributing external routes. The Link State ID of a router-LSA
/// is the router's own ID (§12.4.1).
pub fn build_router_lsa(own: RouterId, e_bit: bool, interfaces: &[InterfaceAdv]) -> Lsa {
    let mut links = Vec::new();
    for iface in interfaces {
        if iface.state < InterfaceState::PointToPoint {
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
        } else if let Some(dr) = iface.dr_address {
            // §12.4.1.2: broadcast/NBMA networks — a type-2 transit
            // link to the DR: Link ID = the DR's interface address,
            // Link Data = our own address.
            links.push(RouterLink {
                link_id: LinkStateId(u32::from(dr)),
                link_data: u32::from(iface.address),
                link_type: LinkType::Transit,
                metric: iface.cost,
                tos: vec![],
            });
        } else {
            // Waiting: §12.4.1.2's wait — the interface's links
            // appear once a DR is elected.
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
            v_bit: false,
            e_bit,
            b_bit: false,
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

/// Build the AS-external-LSA for one redistributed route (§12.4.3).
/// Type-2 (E-bit) with FRR's default metric 20; forwarding address
/// 0.0.0.0 (the ASBR itself — §12.4.3's default when no dedicated
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
            // §12.4.3: the Link State ID is the external network
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
        }
    }

    #[test]
    fn router_lsa_numbers_a_p2p_adjacency() {
        // §12.4.1.1: one type-1 link to the Full neighbor plus the
        // numbered-subnet type-3 stub.
        let mut adv = iface(true, "10.77.0.1", "255.255.255.252", 10);
        adv.p2p_neighbors_full = vec![rid("10.255.2.1")];
        let lsa = build_router_lsa(rid("10.255.1.1"), false, &[adv]);
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
        let lsa = build_router_lsa(rid("1.1.1.1"), false, &[adv]);
        let LsaBody::Router(body) = &lsa.body else {
            panic!()
        };
        assert!(body.links.is_empty());
    }

    #[test]
    fn asbr_bit_is_carried() {
        // §12.4.3: originating type-5s makes the router an ASBR —
        // the E-bit lands in the router-LSA.
        let lsa = build_router_lsa(rid("1.1.1.1"), true, &[]);
        let LsaBody::Router(body) = &lsa.body else {
            panic!()
        };
        assert!(body.e_bit);
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
    fn external_lsa_shape() {
        // §A.4.5/§12.4.3: ID = network number, mask, E-bit for
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
