//! The OSPFv3 daemon runtime (RFC 5340) — S7-a: the AF-generic
//! proof run live over the v6 transport.
//!
//! What is SHARED with the v2 daemon (the invariant-3 scorecard's
//! left column — no fork, the same modules):
//!
//! - [`crate::neighbor::NeighborFsm`] — the whole §10.3 state table
//!   and the §10.6 master/slave core via [`crate::neighbor::DdView`]
//!   (the S7-a seam fix: both families' DBDs map onto one view).
//! - [`crate::lsdb::Lsdb`]`<LsaV3>` — the ONE §12.2/§13.1/§13.2/§14
//!   implementation through the [`crate::lsdb::LsaInstance`] seam
//!   (v2 is the default type parameter; v3 instantiates the same
//!   struct).
//! - The codecs (`packet_v3`/`lsa_v3`), the checksums, the §12.4
//!   constants, and the `zedge`/`exchange`-shaped run-loop skeleton
//!   (per-interface sockets → one mpsc → the core → obligations).
//!
//! What is v3-specific (the right column — where RFC 5340 genuinely
//! diverges from RFC 2328):
//!
//! - Neighbors keyed by **Router ID** (§4.2.2.1), the peer's
//!   link-local learned as the Hello source; no subnet model (§2.1).
//! - The **Instance ID**: carried in every header, discarded on
//!   mismatch (§A.3.1/§4.2 — "Instance ID solely affects the
//!   reception of packets").
//! - **Flooding scope** (§3.2/§4.5.2): link-local-scope LSAs
//!   (link-LSAs, 0x0008) live in a per-interface database and never
//!   leave the link; area- and AS-scope LSAs live in the area
//!   database.
//! - Origination: the v3 **router-LSA** (0x2001, interface-ID links)
//!   and **link-LSA** (0x0008, the link-local address + prefixes —
//!   "link-local addresses appear in link-LSAs and nowhere else",
//!   §2.5) plus **AS-external** (0x4005) for the redistributed.
//! - Route calculation is the §16.4-lite single-hop-ASBR form v2
//!   shipped Day 2 (the full v3 SPF — link-LSA next hops, IAPR
//!   prefix attachment — is §Deferred as recorded in ospf.md): an
//!   external LSA whose advertising router is a directly-attached
//!   Full neighbor installs via that adjacency's link-local.
//!
//! Disclosed v1 fences (honest scorecard): point-to-point networks
//! only (the §9.4 broadcast election over v3 Router-ID claims and
//! the DR/BDR-driven ff02::6 receive gate ride with it); single
//! area; the conversation bookkeeping below is exchange.rs's shape
//! mirrored over v3 types (the v2 `Conversation` is `Packet`-typed
//! end to end — generifying it means a multi-day rewrite of the v2
//! daemon in the same breath; the FSM TABLE and LSDB it drives are
//! the shared cores).

use std::collections::{BTreeMap, HashMap};
use std::net::Ipv6Addr;
use std::sync::Arc;

use common::{IpPrefix, Ipv6Prefix, Nexthop, NexthopGroup, RouteEntry, RouteProtocol};
use tokio::sync::mpsc;
use tracing::{debug, info, warn};

use crate::config::{InterfaceConfig, NetworkType, OspfdConfig};
use crate::lsa::{LinkStateId, LsaKey, LsaType, RouterId};
use crate::lsa_v3::{
    AsExternalLsaV3, LinkTypeV3, LsaBodyV3, LsaHeaderV3, LsaV3, Options24, Prefix, RouterLinkV3,
    RouterLsaV3,
};
use crate::lsdb::{InstallOutcome, LsaInstance, Lsdb, Readopt, Which};
use crate::neighbor::{
    process_hello_v3, DdView, HelloParamsV3, NeighborAction, NeighborEvent, NeighborFsm,
    NeighborState,
};
use crate::packet_v3::{
    DbDescriptionV3, HelloV3, LsAckV3, LsRequestV3, LsRequestV3Entry, LsUpdateV3, PacketBodyV3,
    PacketHeaderV3, PacketV3,
};
use crate::transport::{OspfV6RawSocket, ReceivedV6};
use crate::zedge::{RedistributedRoute, ZedgeCommand};

/// The v3 AS-external LSA's U/S2/S1 shape (0x4005).
const V3_AS_EXTERNAL: LsaType = LsaType::V3_AS_EXTERNAL;
/// The v3 link-LSA (0x0008, link-local flooding scope).
const V3_LINK: LsaType = LsaType::V3_LINK;
/// The v3 router-LSA (0x2001).
const V3_ROUTER: LsaType = LsaType::V3_ROUTER;

/// The Options24 we advertise on a normal-area interface: V6 | E | R
/// (§A.2 — R is the "router" bit every OSPFv3 router sets).
fn our_options() -> Options24 {
    Options24(Options24::V6 | Options24::E | Options24::R)
}

/// What the core wants put on the wire after one input.
#[derive(Clone)]
pub struct WireOutV3 {
    pub iface: usize,
    pub to: WireToV3,
    pub packet: PacketV3,
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum WireToV3 {
    /// AllSPFRouters, ff02::5 (§A.1) — Hellos and floods.
    Multicast,
    /// AllDRouters, ff02::6 (§A.1) — the broadcast-network arm.
    AllDRouters,
    Unicast(Ipv6Addr),
}

impl WireToV3 {
    fn addr(self) -> Ipv6Addr {
        match self {
            Self::Multicast => crate::transport::ALL_SPF_ROUTERS_V6,
            Self::AllDRouters => crate::transport::ALL_D_ROUTERS_V6,
            Self::Unicast(a) => a,
        }
    }
}

/// One outbound conversation obligation (unicast to the neighbor).
#[derive(Debug, Clone)]
struct SendV3 {
    to: Ipv6Addr,
    packet: PacketV3,
}

/// The conversation timing parameters (§C.3 lineage).
#[derive(Clone)]
struct ConversationParamsV3 {
    rxmt_interval: u64,
    mtu: u16,
    options: Options24,
    instance_id: u8,
}

/// The per-neighbor conversation: exchange.rs's §10.6-§10.9/§13.3-
/// §13.7 bookkeeping mirrored over v3 types, driving the SHARED
/// [`NeighborFsm`]. Disclosed as the mirrored piece (module note).
pub struct ConversationV3 {
    pub fsm: NeighborFsm,
    /// The neighbor's link-local address (the Hello source, §2.5 —
    /// unicast sends and the route-export gateway).
    pub ip: Ipv6Addr,
    /// The peer's Interface ID (its Hello's — the router-LSA p2p
    /// link's neighbor-side value, §4.4.3.1).
    pub peer_interface_id: Option<u32>,
    pub inactivity_deadline: u64,
    summary: std::collections::VecDeque<LsaHeaderV3>,
    peer_dd_done: bool,
    pub requests: Vec<(LsaType, LinkStateId, RouterId)>,
    pub rxmt: Vec<(LsaKey, Vec<u8>)>,
    rxmt_deadline: Option<u64>,
    dd_deadline: Option<u64>,
    last_dd_sent: Option<DbDescriptionV3>,
    own_router_id: RouterId,
    area_id: u32,
    params: ConversationParamsV3,
}

impl ConversationV3 {
    fn new(
        own_router_id: RouterId,
        area_id: u32,
        peer_ip: Ipv6Addr,
        now: u64,
        dead_interval: u64,
        params: ConversationParamsV3,
    ) -> Self {
        Self {
            fsm: NeighborFsm::new(own_router_id),
            ip: peer_ip,
            peer_interface_id: None,
            inactivity_deadline: now + dead_interval,
            summary: Default::default(),
            peer_dd_done: false,
            requests: Vec::new(),
            rxmt: Vec::new(),
            rxmt_deadline: None,
            dd_deadline: None,
            last_dd_sent: None,
            own_router_id,
            area_id,
            params,
        }
    }

    fn state(&self) -> NeighborState {
        self.fsm.state
    }

    fn packet(&self, body: PacketBodyV3) -> PacketV3 {
        PacketV3 {
            header: PacketHeaderV3 {
                version: 3,
                packet_type: body.packet_type(),
                length: 0,
                router_id: self.own_router_id,
                area_id: self.area_id,
                checksum: 0,
                instance_id: self.params.instance_id,
            },
            body,
        }
    }

    fn send(&self, body: PacketBodyV3) -> SendV3 {
        SendV3 {
            to: self.ip,
            packet: self.packet(body),
        }
    }

    /// Fire one neighbor event and map its §10.3 actions to
    /// obligations. `area` + `link` are the two databases the
    /// summary list describes (§3.2: the area/AS store plus THIS
    /// link's link-local-scope store).
    fn fire_and_map(
        &mut self,
        event: NeighborEvent,
        area: &Lsdb<LsaV3>,
        link: &Lsdb<LsaV3>,
        now: u64,
    ) -> (Vec<SendV3>, ConversationReportV3) {
        let mut sends = Vec::new();
        let mut report = ConversationReportV3::default();
        let (_, actions) = self.fsm.fire(event);
        for action in actions {
            match action {
                NeighborAction::RestartInactivityTimer | NeighborAction::StopInactivityTimer => {}
                NeighborAction::ClearLists => {
                    self.summary.clear();
                    self.requests.clear();
                    self.rxmt.clear();
                    self.rxmt_deadline = None;
                    self.dd_deadline = None;
                    self.last_dd_sent = None;
                    self.peer_dd_done = false;
                    self.fsm.summary_pending = false;
                }
                NeighborAction::BumpDdSequence => {
                    self.fsm.dd_sequence = self.fsm.dd_sequence.wrapping_add(1);
                }
                NeighborAction::SendEmptyDd { init, more, master } => {
                    let dd = DbDescriptionV3 {
                        interface_mtu: self.params.mtu,
                        options: self.params.options,
                        init,
                        more,
                        master,
                        dd_sequence: self.fsm.dd_sequence,
                        lsa_headers: vec![],
                    };
                    self.last_dd_sent = Some(dd.clone());
                    self.dd_deadline = Some(now + self.params.rxmt_interval);
                    sends.push(self.send(PacketBodyV3::DbDescription(dd)));
                }
                NeighborAction::BuildSummaryList => {
                    // §10.3 + §3.2: every LSA in the area database
                    // plus the attached link's link-local-scope ones.
                    self.summary.clear();
                    self.summary.extend(area.all().map(|e| e.lsa.header));
                    self.summary.extend(link.all().map(|e| e.lsa.header));
                    self.fsm.summary_pending = !self.summary.is_empty();
                }
                NeighborAction::SendLsRequests => {
                    sends.extend(self.build_lsr(now));
                }
                NeighborAction::InterfaceNeighborChange => {}
                NeighborAction::AdjacencyUp => report.adjacency_up = true,
                NeighborAction::AdjacencyDown => {
                    report.adjacency_down = true;
                    self.rxmt.clear();
                    self.rxmt_deadline = None;
                }
            }
        }
        if matches!(self.fsm.state, NeighborState::Loading) && !self.requests.is_empty() {
            sends.extend(self.build_lsr(now));
        }
        (sends, report)
    }

    /// §10.8: the next DD chunk — up to the MTU budget of headers,
    /// M=0 exactly when the summary drains with it. The v3 budget:
    /// 16-byte packet header + 12-byte DBD preamble (A.3.3).
    fn build_dd_chunk(&mut self, now: u64) -> SendV3 {
        let budget = (self.params.mtu as usize).saturating_sub(16 + 12) / 20;
        let take = budget.min(self.summary.len());
        let mut headers = Vec::with_capacity(take);
        for _ in 0..take {
            headers.push(self.summary.pop_front().expect("len checked"));
        }
        self.fsm.summary_pending = !self.summary.is_empty();
        let more = !self.summary.is_empty();
        let dd = DbDescriptionV3 {
            interface_mtu: self.params.mtu,
            options: self.params.options,
            init: false,
            more,
            master: self.fsm.master,
            dd_sequence: self.fsm.dd_sequence,
            lsa_headers: headers,
        };
        self.last_dd_sent = Some(dd.clone());
        self.dd_deadline = Some(now + self.params.rxmt_interval);
        self.send(PacketBodyV3::DbDescription(dd))
    }

    /// §10.9: one LSR packet (16-byte header + 12-byte entries).
    fn build_lsr(&mut self, now: u64) -> Vec<SendV3> {
        if self.requests.is_empty() {
            return vec![];
        }
        let budget = (self.params.mtu as usize).saturating_sub(16) / 12;
        let take = budget.min(self.requests.len());
        let requests: Vec<LsRequestV3Entry> = self.requests[..take]
            .iter()
            .map(|(t, id, r)| LsRequestV3Entry {
                ls_type: *t,
                link_state_id: *id,
                adv_router: *r,
            })
            .collect();
        self.dd_deadline = Some(now + self.params.rxmt_interval);
        vec![self.send(PacketBodyV3::LsRequest(LsRequestV3 { requests }))]
    }

    fn request_matches(r: &(LsaType, LinkStateId, RouterId), h: &LsaHeaderV3) -> bool {
        r.0 == h.ls_type && r.1 == h.link_state_id && r.2 == h.adv_router
    }

    /// §10.6 (via the shared `process_dbd_view` core).
    fn handle_dbd(
        &mut self,
        pkt: &DbDescriptionV3,
        packet_router_id: RouterId,
        our_mtu: u16,
        area: &mut Lsdb<LsaV3>,
        link: &mut Lsdb<LsaV3>,
        now: u64,
    ) -> (Vec<SendV3>, ConversationReportV3) {
        let mut sends = Vec::new();
        let mut report = ConversationReportV3::default();
        if pkt.interface_mtu > our_mtu {
            return (sends, report);
        }
        self.fsm.peer_id_larger_value = Some(packet_router_id.larger_than(self.own_router_id));
        self.fsm.summary_pending = !self.summary.is_empty();
        let state_before = self.state();

        let view = DdView {
            init: pkt.init,
            more: pkt.more,
            master: pkt.master,
            options: pkt.options.0,
            dd_sequence: pkt.dd_sequence,
            has_headers: !pkt.lsa_headers.is_empty(),
        };
        let result = self.fsm.process_dbd_view(&view);
        if result.accepted {
            for hdr in &pkt.lsa_headers {
                let key = LsaKey {
                    ls_type: hdr.ls_type,
                    link_state_id: hdr.link_state_id,
                    adv_router: hdr.adv_router,
                };
                // The described LSA lives in the database its
                // flooding scope names (§3.2).
                let store = if hdr.ls_type.scope() == crate::lsa::Scope::Link {
                    &mut *link
                } else {
                    &mut *area
                };
                let need = match store.get(&key) {
                    None => true,
                    Some(entry) => matches!(
                        crate::lsdb::newer_than(hdr, entry.lsa.header()),
                        Which::FirstNewer
                    ),
                };
                if need && !self.requests.iter().any(|r| Self::request_matches(r, hdr)) {
                    self.requests
                        .push((hdr.ls_type, hdr.link_state_id, hdr.adv_router));
                }
            }
            if !pkt.more {
                self.peer_dd_done = true;
            }
        }
        for event in result.events {
            let (mut ev_sends, ev_report) = self.fire_and_map(event, area, link, now);
            sends.append(&mut ev_sends);
            report.merge(&ev_report);
        }
        if result.send_reply {
            let master_round_complete = self.fsm.master
                && !pkt.more
                && self.summary.is_empty()
                && self.last_dd_sent.as_ref().is_some_and(|d| !d.more);
            let duplicate_echo = !result.accepted && self.last_dd_sent.is_some();
            if !master_round_complete {
                if duplicate_echo {
                    if let Some(dd) = &self.last_dd_sent {
                        let mut dd = dd.clone();
                        dd.dd_sequence = self.fsm.dd_sequence;
                        sends.push(self.send(PacketBodyV3::DbDescription(dd)));
                    }
                } else if matches!(
                    state_before,
                    NeighborState::Exchange | NeighborState::ExStart
                ) {
                    sends.push(self.build_dd_chunk(now));
                }
            }
        }
        if !self.fsm.master
            && matches!(self.state(), NeighborState::Exchange)
            && self.peer_dd_done
            && self.summary.is_empty()
        {
            let (mut ev_sends, ev_report) =
                self.fire_and_map(NeighborEvent::ExchangeDone, area, link, now);
            sends.append(&mut ev_sends);
            report.merge(&ev_report);
        }
        if matches!(self.state(), NeighborState::Loading) && self.requests.is_empty() {
            let (mut ev_sends, ev_report) =
                self.fire_and_map(NeighborEvent::LoadingDone, area, link, now);
            sends.append(&mut ev_sends);
            report.merge(&ev_report);
        }
        (sends, report)
    }

    /// §10.9: one received Link State Request — answers from the
    /// scope-correct database.
    fn handle_lsr(
        &mut self,
        pkt: &LsRequestV3,
        area: &mut Lsdb<LsaV3>,
        link: &mut Lsdb<LsaV3>,
        now: u64,
    ) -> (Vec<SendV3>, ConversationReportV3) {
        let mut lsas = Vec::new();
        let mut report = ConversationReportV3::default();
        let mut sends = Vec::new();
        for req in &pkt.requests {
            let key = LsaKey {
                ls_type: req.ls_type,
                link_state_id: req.link_state_id,
                adv_router: req.adv_router,
            };
            let store = if req.ls_type.scope() == crate::lsa::Scope::Link {
                &mut *link
            } else {
                &mut *area
            };
            match store.get(&key) {
                Some(entry) => lsas.push(entry.lsa.clone()),
                None => {
                    let (mut ev_sends, ev_report) =
                        self.fire_and_map(NeighborEvent::BadLSReq, area, link, now);
                    sends.append(&mut ev_sends);
                    report.merge(&ev_report);
                    return (sends, report);
                }
            }
        }
        // LSU batches by the interface MTU (16-byte header + 4-byte
        // count + each LSA's own length).
        let mut batch: Vec<LsaV3> = Vec::new();
        let mut batch_len = 16 + 4;
        for lsa in lsas {
            let lsa_len = lsa.header.length as usize;
            if !batch.is_empty() && batch_len + lsa_len > self.params.mtu as usize {
                sends.push(self.send(PacketBodyV3::LsUpdate(LsUpdateV3 {
                    lsas: std::mem::take(&mut batch),
                })));
                batch_len = 16 + 4;
            }
            batch_len += lsa_len;
            batch.push(lsa);
        }
        if !batch.is_empty() {
            sends.push(self.send(PacketBodyV3::LsUpdate(LsUpdateV3 { lsas: batch })));
        }
        (sends, report)
    }

    /// §13 (§4.5.1's scope rules): one received LSA against the
    /// scope-correct database.
    fn flood_one(
        &mut self,
        lsa: &LsaV3,
        area: &mut Lsdb<LsaV3>,
        link: &mut Lsdb<LsaV3>,
        now: u64,
        neighbor_syncing: bool,
    ) -> (FloodActionV3, bool) {
        let key = lsa.key();
        let had_request = self
            .requests
            .iter()
            .any(|r| Self::request_matches(r, &lsa.header));
        if had_request {
            self.requests
                .retain(|r| !Self::request_matches(r, &lsa.header));
        }
        let on_rxmt = self.rxmt.iter().any(|(k, _)| *k == key);
        // Step 4: MaxAge, no instance, nobody syncing.
        if lsa.header.is_max_age()
            && !area.contains(&key)
            && !link.contains(&key)
            && !neighbor_syncing
        {
            return (FloodActionV3::AckAndDiscard, had_request);
        }
        let store = if lsa.header.ls_type.scope() == crate::lsa::Scope::Link {
            &mut *link
        } else {
            &mut *area
        };
        let db = store.get(&key).map(|e| e.lsa.clone());
        match db {
            None => match store.install(lsa.clone(), true, now) {
                InstallOutcome::RejectedMinLsArrival => (FloodActionV3::Discard, false),
                _ => (
                    FloodActionV3::InstallAndFlood { changed: true },
                    had_request,
                ),
            },
            Some(db_lsa) => match crate::lsdb::newer_than(lsa.header(), db_lsa.header()) {
                Which::FirstNewer => match store.install(lsa.clone(), true, now) {
                    InstallOutcome::RejectedMinLsArrival => (FloodActionV3::Discard, false),
                    outcome => (
                        FloodActionV3::InstallAndFlood {
                            changed: matches!(outcome, InstallOutcome::Installed { changed: true }),
                        },
                        had_request,
                    ),
                },
                _ if had_request => (FloodActionV3::BadLSReq, had_request),
                Which::Identical => {
                    if lsa.header.seq == db_lsa.header.seq {
                        (
                            FloodActionV3::SameInstance {
                                on_rxmt_list: on_rxmt,
                            },
                            false,
                        )
                    } else {
                        (
                            FloodActionV3::SameInstance {
                                on_rxmt_list: false,
                            },
                            false,
                        )
                    }
                }
                Which::SecondNewer => {
                    if db_lsa.header.is_max_age() && db_lsa.header.seq == crate::MAX_SEQUENCE_NUMBER
                    {
                        return (FloodActionV3::Discard, false);
                    }
                    (FloodActionV3::SendDatabaseCopy(db_lsa), false)
                }
            },
        }
    }

    fn handle_lsu(
        &mut self,
        lsas: &[LsaV3],
        area: &mut Lsdb<LsaV3>,
        link: &mut Lsdb<LsaV3>,
        now: u64,
        other_adjacencies_syncing: bool,
    ) -> (Vec<SendV3>, ConversationReportV3) {
        let mut sends = Vec::new();
        let mut report = ConversationReportV3::default();
        for lsa in lsas {
            let (action, _) = self.flood_one(lsa, area, link, now, other_adjacencies_syncing);
            match action {
                FloodActionV3::InstallAndFlood { changed } => {
                    if changed {
                        report.changed.push(lsa.key());
                        report.changed_lsa(lsa);
                    }
                    sends.push(self.send(PacketBodyV3::LsAck(LsAckV3 {
                        headers: vec![lsa.header],
                    })));
                }
                FloodActionV3::AckAndDiscard => {
                    sends.push(self.send(PacketBodyV3::LsAck(LsAckV3 {
                        headers: vec![lsa.header],
                    })));
                }
                FloodActionV3::SameInstance { on_rxmt_list } => {
                    if on_rxmt_list {
                        self.implied_ack(&lsa.header);
                    } else {
                        sends.push(self.send(PacketBodyV3::LsAck(LsAckV3 {
                            headers: vec![lsa.header],
                        })));
                    }
                }
                FloodActionV3::SendDatabaseCopy(db) => {
                    sends.push(self.send(PacketBodyV3::LsUpdate(LsUpdateV3 { lsas: vec![db] })));
                }
                FloodActionV3::BadLSReq => {
                    let (mut ev_sends, ev_report) =
                        self.fire_and_map(NeighborEvent::BadLSReq, area, link, now);
                    sends.append(&mut ev_sends);
                    report.merge(&ev_report);
                    return (sends, report);
                }
                FloodActionV3::Discard => {}
            }
        }
        if matches!(self.state(), NeighborState::Loading) {
            if self.requests.is_empty() {
                let (mut ev_sends, ev_report) =
                    self.fire_and_map(NeighborEvent::LoadingDone, area, link, now);
                sends.append(&mut ev_sends);
                report.merge(&ev_report);
            } else {
                sends.extend(self.build_lsr(now));
            }
        }
        (sends, report)
    }

    /// §13.5/§13.6: direct acks clear the retransmission list.
    fn handle_lsack(&mut self, headers: &[LsaHeaderV3]) {
        let keys: Vec<LsaKey> = headers
            .iter()
            .map(|h| LsaKey {
                ls_type: h.ls_type,
                link_state_id: h.link_state_id,
                adv_router: h.adv_router,
            })
            .collect();
        self.rxmt.retain(|(k, _)| !keys.contains(k));
        if self.rxmt.is_empty() {
            self.rxmt_deadline = None;
        }
    }

    fn implied_ack(&mut self, header: &LsaHeaderV3) {
        let key = LsaKey {
            ls_type: header.ls_type,
            link_state_id: header.link_state_id,
            adv_router: header.adv_router,
        };
        self.rxmt.retain(|(k, _)| *k != key);
        if self.rxmt.is_empty() {
            self.rxmt_deadline = None;
        }
    }

    fn queue_retransmit(&mut self, lsa: &LsaV3, now: u64) {
        let key = lsa.key();
        if !self.rxmt.iter().any(|(k, _)| *k == key) {
            self.rxmt.push((key, lsa.encode()));
        }
        self.rxmt_deadline = Some(now + self.params.rxmt_interval);
    }

    /// The periodic tick (§10.2/§10.8/§13.5).
    fn tick(&mut self, now: u64) -> (Vec<SendV3>, ConversationReportV3) {
        let mut sends = Vec::new();
        let mut report = ConversationReportV3::default();
        if matches!(self.state(), NeighborState::Down) {
            return (sends, report);
        }
        if now >= self.inactivity_deadline {
            let (_, actions) = self.fsm.fire(NeighborEvent::InactivityTimer);
            for action in actions {
                if action == NeighborAction::AdjacencyDown {
                    report.adjacency_down = true;
                }
                if action == NeighborAction::ClearLists {
                    self.summary.clear();
                    self.requests.clear();
                    self.rxmt.clear();
                    self.rxmt_deadline = None;
                    self.dd_deadline = None;
                    self.last_dd_sent = None;
                    self.peer_dd_done = false;
                    self.fsm.summary_pending = false;
                }
            }
            return (sends, report);
        }
        if let Some(deadline) = self.dd_deadline {
            if now >= deadline {
                match self.state() {
                    NeighborState::ExStart | NeighborState::Exchange => {
                        if let Some(dd) = &self.last_dd_sent {
                            let mut dd = dd.clone();
                            dd.dd_sequence = self.fsm.dd_sequence;
                            sends.push(self.send(PacketBodyV3::DbDescription(dd)));
                        }
                    }
                    NeighborState::Loading if !self.requests.is_empty() => {
                        sends.extend(self.build_lsr(now));
                    }
                    _ => {}
                }
                self.dd_deadline = Some(now + self.params.rxmt_interval);
            }
        }
        if let Some(deadline) = self.rxmt_deadline {
            if now >= deadline && !self.rxmt.is_empty() {
                let lsas: Vec<LsaV3> = self
                    .rxmt
                    .iter()
                    .filter_map(|(_, bytes)| LsaV3::decode(bytes).ok())
                    .collect();
                if !lsas.is_empty() {
                    sends.push(self.send(PacketBodyV3::LsUpdate(LsUpdateV3 { lsas })));
                }
                self.rxmt_deadline = Some(now + self.params.rxmt_interval);
            }
        }
        (sends, report)
    }

    fn touch_inactivity(&mut self, now: u64, dead_interval: u64) {
        self.inactivity_deadline = now + dead_interval;
    }

    fn in_hello(&self) -> bool {
        self.state().at_least(NeighborState::Init)
    }
}

/// §13's actions for one received LSA (the v3 policy: unknown types
/// are NOT rejected — the U-bit contract, §3.4 — they install and
/// flood opaque; only the decoding itself can reject).
#[derive(Debug, Clone)]
enum FloodActionV3 {
    InstallAndFlood { changed: bool },
    AckAndDiscard,
    SameInstance { on_rxmt_list: bool },
    SendDatabaseCopy(LsaV3),
    BadLSReq,
    Discard,
}

#[derive(Default)]
struct ConversationReportV3 {
    changed: Vec<LsaKey>,
    changed_lsas: Vec<LsaV3>,
    adjacency_up: bool,
    adjacency_down: bool,
}

impl ConversationReportV3 {
    fn changed_lsa(&mut self, lsa: &LsaV3) {
        self.changed_lsas.push(lsa.clone());
    }
    fn merge(&mut self, other: &Self) {
        self.changed.extend_from_slice(&other.changed);
        self.changed_lsas.extend_from_slice(&other.changed_lsas);
        self.adjacency_up |= other.adjacency_up;
        self.adjacency_down |= other.adjacency_down;
    }
}

/// One OSPFv3 interface under the daemon.
pub struct InterfaceV3 {
    pub name: String,
    pub area: u32,
    pub cfg: InterfaceConfig,
    /// The kernel ifindex: the multicast join/egress argument AND
    /// the Interface ID (§C.1's MIB-II ifIndex convention).
    pub ifindex: u32,
    /// Our link-local source address (§2.5).
    pub link_local: Ipv6Addr,
    /// §A.3.1: received packets whose Instance ID differs are
    /// discarded.
    pub instance_id: u8,
    pub neighbors: HashMap<RouterId, ConversationV3>,
    hello_deadline: u64,
    /// §3.2: the link-local-scope database (the link's link-LSAs).
    pub link_lsdb: Lsdb<LsaV3>,
    /// Whether the self-originated link-LSA needs (re-)origination.
    link_lsa_dirty: bool,
}

impl InterfaceV3 {
    fn params(&self) -> ConversationParamsV3 {
        ConversationParamsV3 {
            rxmt_interval: 5,
            mtu: self.cfg.mtu,
            options: our_options(),
            instance_id: self.instance_id,
        }
    }
}

/// The OSPFv3 daemon core. Clock-injected (`now` in seconds); `run`
/// owns the real clock.
pub struct OspfdV3 {
    pub router_id: RouterId,
    /// v1: single area (multi-area v3 is §Deferred).
    pub area: u32,
    pub interfaces: Vec<InterfaceV3>,
    /// The area/AS-scope database (§3.2's area + AS scopes in one
    /// store, v1).
    pub lsdb: Lsdb<LsaV3>,
    routes: BTreeMap<String, RouteEntry>,
    /// Self-originated externals (prefix string -> (key, LS ID)).
    externals: BTreeMap<String, (LsaKey, u32)>,
    /// The next AS-external LS ID allocator (v3's LS ID is a pure
    /// de-multiplexer, A.4.7).
    next_external_lsid: u32,
    router_lsa_dirty: bool,
    asbr: bool,
    zapi: Option<mpsc::UnboundedSender<ZedgeCommand>>,
    redistribute_static: bool,
    /// §A.3.1's discard counter (Instance ID mismatches).
    pub dropped_instance_mismatch: u64,
    /// Receive-side hop-limit enforcement counter (S8-b, the v6
    /// mirror of the v2 N1 rule): UNICAST v3 packets (DD/LSR/LSU/
    /// LSAck — not ff02::5/6) dropped because their received hop
    /// limit is not 1, read back through the audited cmsg path
    /// (`transport::recvmsg_v6_ctl`). Keyed on our own documented
    /// unicast hops-1 parity (RFC 5340 §A.1 mandates the multicast
    /// arm only; v3 virtual links are §Deferred). Multicast packets
    /// are not checked (the kernel's rule).
    pub dropped_degraded_hop_limit: u64,
}

impl OspfdV3 {
    pub fn new(cfg: &OspfdConfig) -> Result<Self, String> {
        let Some(rid) = cfg.router_id else {
            return Err("router-id is required (v1: no zapi router-id request)".into());
        };
        let router_id = RouterId::from_ipv4(rid);
        let Some(area_cfg) = cfg.areas.first() else {
            return Err("address-family ipv6-unicast requires one area stanza".into());
        };
        let mut interfaces = Vec::new();
        for (name, icfg) in &area_cfg.interfaces {
            let Some(link_local) = icfg.link_local else {
                return Err(format!(
                    "interface {name}: link-local <fe80::...> is required for OSPFv3"
                ));
            };
            if !link_local.is_unicast_link_local() {
                return Err(format!(
                    "interface {name}: link-local must be a fe80::/10 address (RFC 5340 2.5)"
                ));
            }
            if icfg.network_type != NetworkType::PointToPoint {
                return Err(format!(
                    "interface {name}: OSPFv3 v1 supports network-type point-to-point only"
                ));
            }
            let ifindex = match icfg.ifindex {
                Some(idx) => idx,
                // Linux hosts resolve the name; tests pin the index.
                None => crate::transport::ifindex_of(name)
                    .map_err(|e| format!("interface {name}: no ifindex ({e})"))?,
            };
            interfaces.push(InterfaceV3 {
                name: name.clone(),
                area: area_cfg.id,
                cfg: icfg.clone(),
                ifindex,
                link_local,
                instance_id: icfg.instance_id,
                neighbors: HashMap::new(),
                hello_deadline: 0,
                link_lsdb: Lsdb::new(),
                link_lsa_dirty: true,
            });
        }
        if interfaces.is_empty() {
            return Err("address-family ipv6-unicast requires at least one interface".into());
        }
        Ok(Self {
            router_id,
            area: area_cfg.id,
            interfaces,
            lsdb: Lsdb::new(),
            routes: BTreeMap::new(),
            externals: BTreeMap::new(),
            next_external_lsid: 0,
            router_lsa_dirty: true,
            asbr: false,
            zapi: None,
            redistribute_static: cfg.redistribute_static,
            dropped_instance_mismatch: 0,
            dropped_degraded_hop_limit: 0,
        })
    }

    pub fn attach_zapi(&mut self, tx: mpsc::UnboundedSender<ZedgeCommand>) {
        self.zapi = Some(tx);
    }

    fn packet(&self, iface: usize, body: PacketBodyV3) -> PacketV3 {
        PacketV3 {
            header: PacketHeaderV3 {
                version: 3,
                packet_type: body.packet_type(),
                length: 0,
                router_id: self.router_id,
                area_id: self.area,
                checksum: 0,
                instance_id: self.interfaces[iface].instance_id,
            },
            body,
        }
    }

    /// §A.3.2 + §C.3: the interface's Hello — multicast to ff02::5,
    /// source the link-local, the seen-neighbor list carrying every
    /// Router ID heard from within RouterDeadInterval.
    fn make_hello(&self, iface: usize) -> PacketV3 {
        let i = &self.interfaces[iface];
        let neighbors: Vec<RouterId> = i
            .neighbors
            .iter()
            .filter(|(_, c)| c.in_hello())
            .map(|(rid, _)| *rid)
            .collect();
        self.packet(
            iface,
            PacketBodyV3::Hello(HelloV3 {
                interface_id: i.ifindex,
                router_priority: i.cfg.priority,
                options: our_options(),
                hello_interval: i.cfg.hello_interval,
                router_dead_interval: i.cfg.dead_interval.min(u32::from(u16::MAX)) as u16,
                // p2p: no DR election (§C.3); the claim fields are
                // Router IDs and stay 0 (4.2.2.1 ignores them on p2p).
                designated_router: RouterId(0),
                backup_designated_router: RouterId(0),
                neighbors,
            }),
        )
    }

    fn sends_into(&mut self, iface: usize, sends: Vec<SendV3>) -> Vec<WireOutV3> {
        sends
            .into_iter()
            .map(|s| WireOutV3 {
                iface,
                to: WireToV3::Unicast(s.to),
                packet: s.packet,
            })
            .collect()
    }

    /// Process one inbound datagram (already attributed its verified
    /// destination by the run loop / the test pump; `hop_limit` is
    /// the cmsg read-back's value when the kernel attached one).
    pub fn on_packet(
        &mut self,
        iface_idx: usize,
        received: &ReceivedV6,
        dst: Ipv6Addr,
        hop_limit: Option<u32>,
        now: u64,
    ) -> Vec<WireOutV3> {
        let out = Vec::new();
        // §4.2: locally originated packets are not processed (the
        // source equals one of our own link-locals).
        if self.interfaces.iter().any(|i| i.link_local == received.src) {
            return out;
        }
        // The receive-side hop-limit check (S8-b): a UNICAST packet
        // with a degraded hop limit cannot have come from an on-link
        // peer (our own unicast arm carries hop 1 — the documented
        // local parity; RFC 5340 §A.1 mandates the multicast arm
        // only). Dropped and counted before any §4.2 processing —
        // the v2 daemon's N1 rule, mirrored. `None` (no cmsg) is
        // fail-open, disclosed at the transport's audited block.
        if !crate::transport::is_multicast_dst_v6(dst)
            && !hop_limit
                .map(crate::transport::unicast_hop_limit_ok)
                .unwrap_or(true)
        {
            self.dropped_degraded_hop_limit += 1;
            info!(
                src = %received.src,
                dst = %dst,
                hop_limit = ?hop_limit,
                "ospfv3: unicast packet dropped: hop limit != 1 (our unicast parity; see transport.rs)"
            );
            return out;
        }
        // The pseudo-header checksum verifies against the REAL
        // destination when the run loop resolved it from the
        // `in6_pktinfo` cmsg; the destination-trial decode remains
        // as the fallback for the no-cmsg path (S7-a's interim,
        // now the secondary).
        let decoded = crate::packet_v3::PacketV3::decode(&received.payload, received.src, dst)
            .ok()
            .or_else(|| {
                crate::transport::decode_v3_dst(&received.payload, received.src, dst)
                    .map(|(packet, _)| packet)
            });
        let packet = match decoded {
            Some(p) => p,
            None => {
                debug!(
                    src = %received.src,
                    "ospfv3: packet failed the pseudo-header checksum"
                );
                return out;
            }
        };
        if std::env::var_os("ROUSTER_OSPFV3_TRACE").is_some() {
            info!(
                src = %received.src,
                dst = %dst,
                rid = %packet.header.router_id,
                packet_type = packet.header.packet_type,
                instance = packet.header.instance_id,
                "ospfv3: packet received"
            );
        }
        // §4.2's header verification ladder.
        if packet.header.router_id == self.router_id {
            return out;
        }
        if packet.header.area_id != self.area {
            debug!(
                area = packet.header.area_id,
                src = %received.src,
                "ospfv3: foreign area drop"
            );
            return out;
        }
        if packet.header.instance_id != self.interfaces[iface_idx].instance_id {
            self.dropped_instance_mismatch += 1;
            debug!(
                instance = packet.header.instance_id,
                src = %received.src,
                "ospfv3: Instance ID mismatch discard (A.3.1)"
            );
            return out;
        }
        // §4.2: AllDRouters destinations are DR/BDR-only.
        if dst == crate::transport::ALL_D_ROUTERS_V6 {
            debug!(src = %received.src, "ospfv3: AllDRouters packet on a p2p interface — drop");
            return out;
        }
        self.on_packet_on(iface_idx, packet, received.src, now)
    }

    fn on_packet_on(
        &mut self,
        iface_idx: usize,
        packet: PacketV3,
        src: Ipv6Addr,
        now: u64,
    ) -> Vec<WireOutV3> {
        let mut out = Vec::new();
        let peer = packet.header.router_id;
        match &packet.body {
            PacketBodyV3::Hello(hello) => {
                let iface = &self.interfaces[iface_idx];
                let params = HelloParamsV3 {
                    hello_interval: iface.cfg.hello_interval,
                    router_dead_interval: iface.cfg.dead_interval,
                    e_capable: true,
                };
                let events = match process_hello_v3(hello, &params, self.router_id) {
                    Ok(events) => events,
                    Err(e) => {
                        debug!(error = %e, src = %src, "ospfv3: hello rejected");
                        return out;
                    }
                };
                let dead = self.interfaces[iface_idx].cfg.dead_interval as u64;
                let conv_params = self.interfaces[iface_idx].params();
                let iface = &mut self.interfaces[iface_idx];
                let conv = iface.neighbors.entry(peer).or_insert_with(|| {
                    ConversationV3::new(self.router_id, self.area, src, now, dead, conv_params)
                });
                conv.ip = src;
                conv.peer_interface_id = Some(hello.interface_id);
                // The databases ride as taken values (the conversation
                // mutably borrows the interface while the link store
                // lives in the same vector).
                let link = std::mem::take(&mut self.interfaces[iface_idx].link_lsdb);
                for event in events {
                    let area = &self.lsdb;
                    let conv = self.interfaces[iface_idx].neighbors.get_mut(&peer).unwrap();
                    let (mut ev_sends, mut report) = conv.fire_and_map(event, area, &link, now);
                    if event == NeighborEvent::TwoWayReceived {
                        // p2p: §10.4's answer is always yes.
                        let conv = self.interfaces[iface_idx].neighbors.get_mut(&peer).unwrap();
                        let (s, r) =
                            conv.fire_and_map(NeighborEvent::AdjOk(true), area, &link, now);
                        ev_sends.extend(s);
                        report.merge(&r);
                    }
                    out.extend(self.sends_into(iface_idx, ev_sends));
                    let conv = self.interfaces[iface_idx].neighbors.get_mut(&peer).unwrap();
                    conv.touch_inactivity(now, dead);
                    self.after_report_v3(iface_idx, Some(peer), &report, now, &mut out);
                }
                self.interfaces[iface_idx].link_lsdb = link;
            }
            PacketBodyV3::DbDescription(_)
            | PacketBodyV3::LsRequest(_)
            | PacketBodyV3::LsUpdate(_)
            | PacketBodyV3::LsAck(_) => {
                // §4.2: conversation packets must come from an
                // active neighbor (identified by Router ID).
                if !self.interfaces[iface_idx].neighbors.contains_key(&peer) {
                    debug!(src = %src, "ospfv3: conversation packet from unknown neighbor");
                    return out;
                }
                let syncing = self.any_syncing();
                let mtu = self.interfaces[iface_idx].cfg.mtu;
                // The databases: area + this link's link-scope store.
                let mut area = std::mem::take(&mut self.lsdb);
                let mut link = std::mem::take(&mut self.interfaces[iface_idx].link_lsdb);
                let (sends, report) = {
                    let conv = self.interfaces[iface_idx].neighbors.get_mut(&peer).unwrap();
                    match &packet.body {
                        PacketBodyV3::DbDescription(dd) => {
                            conv.handle_dbd(dd, peer, mtu, &mut area, &mut link, now)
                        }
                        PacketBodyV3::LsRequest(lsr) => {
                            conv.handle_lsr(lsr, &mut area, &mut link, now)
                        }
                        PacketBodyV3::LsUpdate(lsu) => {
                            let (sends, report) =
                                conv.handle_lsu(&lsu.lsas, &mut area, &mut link, now, syncing);
                            out.extend(self.sends_into(iface_idx, sends));
                            // §4.5.2: newly installed area/AS-scope
                            // LSAs flood the OTHER interfaces too.
                            self.reflood_installed(&report, iface_idx, now, &mut out);
                            (Vec::new(), report)
                        }
                        PacketBodyV3::LsAck(ack) => {
                            let conv = self.interfaces[iface_idx].neighbors.get_mut(&peer).unwrap();
                            conv.handle_lsack(&ack.headers);
                            (Vec::new(), ConversationReportV3::default())
                        }
                        PacketBodyV3::Hello(_) => unreachable!(),
                    }
                };
                self.lsdb = area;
                self.interfaces[iface_idx].link_lsdb = link;
                out.extend(self.sends_into(iface_idx, sends));
                // §13.4: a newer self-originated instance (the
                // restart case) re-adopts + re-originates — after
                // the databases are back in place.
                if let PacketBodyV3::LsUpdate(lsu) = &packet.body {
                    self.readopt_self_originated(&lsu.lsas, now, &mut out);
                }
                self.after_report_v3(iface_idx, Some(peer), &report, now, &mut out);
            }
        }
        out
    }

    /// Whether any adjacency is in Exchange/Loading (§13 step 4 /
    /// §14's flush condition).
    fn any_syncing(&self) -> bool {
        self.interfaces.iter().any(|i| {
            i.neighbors
                .values()
                .any(|c| matches!(c.state(), NeighborState::Exchange | NeighborState::Loading))
        })
    }

    /// §4.5.2: newly installed area/AS-scope LSAs (from the peer's
    /// LSU) flood out every other interface — LSU to each Full
    /// neighbor, queued for retransmission (§13.3, the v2 p2p shape).
    fn reflood_installed(
        &mut self,
        report: &ConversationReportV3,
        from_iface: usize,
        now: u64,
        out: &mut Vec<WireOutV3>,
    ) {
        for lsa in &report.changed_lsas {
            if lsa.header.ls_type.scope() == crate::lsa::Scope::Link {
                // Link-local scope never leaves the link (§3.2).
                continue;
            }
            for idx in 0..self.interfaces.len() {
                if idx == from_iface {
                    continue;
                }
                let ips: Vec<Ipv6Addr> = {
                    let iface = &mut self.interfaces[idx];
                    iface
                        .neighbors
                        .iter_mut()
                        .filter(|(_, c)| c.state() == NeighborState::Full)
                        .map(|(_, c)| {
                            c.queue_retransmit(lsa, now);
                            c.ip
                        })
                        .collect()
                };
                for ip in ips {
                    let packet = self.packet(
                        idx,
                        PacketBodyV3::LsUpdate(LsUpdateV3 {
                            lsas: vec![lsa.clone()],
                        }),
                    );
                    out.push(WireOutV3 {
                        iface: idx,
                        to: WireToV3::Unicast(ip),
                        packet,
                    });
                }
            }
        }
    }

    /// The post-input bookkeeping: adjacency transitions dirty the
    /// router-LSA; changed LSAs rerun the route table.
    fn after_report_v3(
        &mut self,
        iface_idx: usize,
        peer: Option<RouterId>,
        report: &ConversationReportV3,
        now: u64,
        out: &mut Vec<WireOutV3>,
    ) {
        let mut table_dirty = false;
        if report.adjacency_up {
            info!(
                iface = %self.interfaces[iface_idx].name,
                neighbor = ?peer,
                "ospfv3: adjacency FULL"
            );
            // §4.4.3.1: the router-LSA gains the link at once (the
            // peer's SPF needs it before it can route via us).
            self.router_lsa_dirty = true;
            self.originate_router_lsa(now, out);
            table_dirty = true;
        }
        if report.adjacency_down {
            info!(
                iface = %self.interfaces[iface_idx].name,
                neighbor = ?peer,
                "ospfv3: adjacency down"
            );
            self.router_lsa_dirty = true;
            self.originate_router_lsa(now, out);
            table_dirty = true;
        }
        // The interop machine-check surface: a FOREIGN router- or
        // link-LSA landed (the LSDB-convergence proof).
        for lsa in &report.changed_lsas {
            if lsa.header.adv_router != self.router_id
                && matches!(lsa.header.ls_type, V3_ROUTER | V3_LINK)
            {
                info!(
                    lsa = lsa.header.ls_type.name(),
                    adv = %lsa.header.adv_router,
                    seq = lsa.header.seq,
                    "ospfv3: peer LSA installed"
                );
            }
        }
        if report.changed.iter().any(|k| k.ls_type == V3_AS_EXTERNAL) {
            table_dirty = true;
        }
        // Refresh-due self-originated LSAs re-originate now (the
        // aging tick reports them through here on the periodic path).
        let _ = now;
        if table_dirty {
            self.recompute_table(now);
        }
        let _ = out;
    }

    // ---- LSA origination (§4.4.3) --------------------------------

    /// §4.4.3.1: the router-LSA — one p2p link per fully-adjacent
    /// neighbor, carrying Interface IDs (v3's replacement for Link
    /// Data, §2.2).
    fn build_router_lsa(&self) -> LsaV3 {
        let mut links = Vec::new();
        for iface in &self.interfaces {
            for (rid, conv) in &iface.neighbors {
                if conv.state() == NeighborState::Full {
                    links.push(RouterLinkV3 {
                        link_type: LinkTypeV3::PointToPoint,
                        metric: iface.cfg.cost,
                        interface_id: iface.ifindex,
                        neighbor_interface_id: conv.peer_interface_id.unwrap_or(0),
                        neighbor_router_id: *rid,
                    });
                }
            }
        }
        LsaV3 {
            header: LsaHeaderV3 {
                ls_age: 0,
                ls_type: V3_ROUTER,
                // v1: one router-LSA (LS ID 0; the multiple-router-
                // LSA concatenation of A.4.3 is §Deferred).
                link_state_id: LinkStateId(0),
                adv_router: self.router_id,
                seq: 0,
                checksum: 0,
                length: 0,
            },
            body: LsaBodyV3::Router(RouterLsaV3 {
                nt_bit: false,
                v_bit: false,
                e_bit: self.asbr,
                b_bit: false,
                options: our_options(),
                links,
            }),
        }
    }

    /// §4.4.3.8: the link-LSA — our link-local address and the
    /// link's prefixes, link-local flooding scope. "Link-local
    /// addresses appear in OSPF link-LSAs and nowhere else" (§2.5) —
    /// this is how a neighbor learns the next-hop address.
    fn build_link_lsa(&self, iface: usize) -> LsaV3 {
        let iface = &self.interfaces[iface];
        LsaV3 {
            header: LsaHeaderV3 {
                ls_age: 0,
                ls_type: V3_LINK,
                // §A.4.9: the LS ID is the router's Interface ID.
                link_state_id: LinkStateId(iface.ifindex),
                adv_router: self.router_id,
                seq: 0,
                checksum: 0,
                length: 0,
            },
            body: LsaBodyV3::Link(crate::lsa_v3::LinkLsaV3 {
                router_priority: iface.cfg.priority,
                options: our_options(),
                link_local_address: iface.link_local,
                // v1: no configured link prefixes (§4.4.3.8's
                // configured-prefix advertisement rides with prefix
                // config).
                prefixes: vec![],
            }),
        }
    }

    /// §4.4.3.6: the AS-external-LSA for one redistributed prefix.
    fn build_external_lsa(&self, prefix: &Ipv6Prefix, metric: u32, lsid: u32) -> LsaV3 {
        LsaV3 {
            header: LsaHeaderV3 {
                ls_age: 0,
                ls_type: V3_AS_EXTERNAL,
                // v3's LS ID is a pure de-multiplexer (A.4.7) — our
                // per-prefix allocator.
                link_state_id: LinkStateId(lsid),
                adv_router: self.router_id,
                seq: 0,
                checksum: 0,
                length: 0,
            },
            body: LsaBodyV3::AsExternal(AsExternalLsaV3 {
                // Type-2 (the v2 daemon's redistribute parity).
                e_bit: true,
                f_bit: false,
                t_bit: false,
                metric,
                prefix: Prefix {
                    len: prefix.prefix_len(),
                    options: Default::default(),
                    addr: prefix_bytes(prefix),
                },
                referenced_ls_type: 0,
                forwarding_address: None,
                external_route_tag: None,
                referenced_link_state_id: None,
            }),
        }
    }

    /// Originate (or refresh) the router-LSA and flood it.
    fn originate_router_lsa(&mut self, now: u64, out: &mut Vec<WireOutV3>) {
        let lsa = self.build_router_lsa();
        let key = lsa.key();
        if self.lsdb.originate(lsa, now).is_ok() {
            self.router_lsa_dirty = false;
            let stored = self.lsdb.get(&key).map(|e| e.lsa.clone());
            if let Some(lsa) = stored {
                self.flood_own(&lsa, now, out);
            }
        }
    }

    fn originate_link_lsa(&mut self, iface: usize, now: u64, out: &mut Vec<WireOutV3>) {
        let lsa = self.build_link_lsa(iface);
        let key = lsa.key();
        if self.interfaces[iface].link_lsdb.originate(lsa, now).is_ok() {
            self.interfaces[iface].link_lsa_dirty = false;
            let stored = self.interfaces[iface]
                .link_lsdb
                .get(&key)
                .map(|e| e.lsa.clone());
            if let Some(lsa) = stored {
                self.flood_own(&lsa, now, out);
            }
        }
    }

    /// §4.5.2: flood a self-originated LSA — LSU unicast to every
    /// Full neighbor (the v2 p2p shape), queued for retransmission;
    /// link-scope LSAs only on their own interface.
    fn flood_own(&mut self, lsa: &LsaV3, now: u64, out: &mut Vec<WireOutV3>) {
        let link_scope = lsa.header.ls_type.scope() == crate::lsa::Scope::Link;
        for idx in 0..self.interfaces.len() {
            if link_scope {
                // Find OUR link-LSA's interface: the LS ID is the
                // interface ID (A.4.9).
                let ours = lsa.header.adv_router == self.router_id
                    && lsa.header.link_state_id.0 == self.interfaces[idx].ifindex;
                if !ours {
                    continue;
                }
            }
            let ips: Vec<Ipv6Addr> = {
                let iface = &mut self.interfaces[idx];
                iface
                    .neighbors
                    .iter_mut()
                    .filter(|(_, c)| c.state() == NeighborState::Full)
                    .map(|(_, c)| {
                        c.queue_retransmit(lsa, now);
                        c.ip
                    })
                    .collect()
            };
            let packet = self.packet(
                idx,
                PacketBodyV3::LsUpdate(LsUpdateV3 {
                    lsas: vec![lsa.clone()],
                }),
            );
            for ip in ips {
                out.push(WireOutV3 {
                    iface: idx,
                    to: WireToV3::Unicast(ip),
                    packet: packet.clone(),
                });
            }
        }
    }

    fn originate_external(
        &mut self,
        prefix: &Ipv6Prefix,
        metric: u32,
        now: u64,
        out: &mut Vec<WireOutV3>,
    ) {
        let lsid = self.next_external_lsid;
        let lsa = self.build_external_lsa(prefix, metric, lsid);
        let key = lsa.key();
        if self.lsdb.originate(lsa, now).is_ok() {
            self.next_external_lsid += 1;
            self.externals.insert(prefix.to_string(), (key, lsid));
            self.asbr = true;
            self.router_lsa_dirty = true;
            let stored = self.lsdb.get(&key).map(|e| e.lsa.clone());
            if let Some(lsa) = stored {
                info!(prefix = %prefix, "ospfv3: external LSA originated");
                self.flood_own(&lsa, now, out);
            }
        }
    }

    fn withdraw_external(&mut self, prefix_str: &str, now: u64, out: &mut Vec<WireOutV3>) {
        if let Some((key, _)) = self.externals.remove(prefix_str) {
            if let Some(aged) = self.lsdb.premature_age(&key) {
                info!(
                    prefix = prefix_str,
                    "ospfv3: external LSA withdrawn (premature age)"
                );
                self.flood_own(&aged, now, out);
                self.asbr = !self.externals.is_empty();
                self.router_lsa_dirty = true;
                self.recompute_table(now);
            }
        }
    }

    pub fn on_redistribute_add(
        &mut self,
        route: &RedistributedRoute,
        now: u64,
        out: &mut Vec<WireOutV3>,
    ) {
        let IpPrefix::V6(prefix) = &route.prefix else {
            return; // v3 runtime consumes v6 pushes only
        };
        self.originate_external(prefix, route.metric.max(1), now, out);
    }

    pub fn on_redistribute_del(
        &mut self,
        route: &RedistributedRoute,
        now: u64,
        out: &mut Vec<WireOutV3>,
    ) {
        self.withdraw_external(&route.prefix.to_string(), now, out);
    }

    // ---- Route calculation (§16.4-lite, direct ASBR) --------------

    /// The v1 OSPFv3 route table: every AS-external-LSA whose
    /// advertising router is a directly-attached Full neighbor
    /// installs through that adjacency (the p2p seam: the gateway is
    /// the adjacency's link-local, the v2 daemon's shape). Full v3
    /// SPF (link-LSA next hops, IAPR attachment) is §Deferred.
    fn recompute_table(&mut self, now: u64) {
        let mut want: BTreeMap<String, RouteEntry> = BTreeMap::new();
        let mut gateways: HashMap<RouterId, (Ipv6Addr, u32, u16)> = HashMap::new();
        for iface in &self.interfaces {
            for (rid, conv) in &iface.neighbors {
                if conv.state() == NeighborState::Full {
                    gateways.insert(*rid, (conv.ip, iface.ifindex, iface.cfg.cost));
                }
            }
        }
        for entry in self.lsdb.all() {
            if entry.lsa.header.ls_type != V3_AS_EXTERNAL || entry.lsa.header.is_max_age() {
                continue;
            }
            let LsaBodyV3::AsExternal(body) = &entry.lsa.body else {
                continue;
            };
            if body.metric >= crate::LS_INFINITY {
                continue; // §16.4 step (5): unreachable
            }
            let Some((gw, ifindex, cost)) = gateways.get(&entry.lsa.header.adv_router) else {
                continue;
            };
            let prefix = match ipv6_prefix_of(&body.prefix) {
                Some(p) => p,
                None => continue,
            };
            let metric = if body.e_bit {
                body.metric // type-2: the external metric as-is
            } else {
                body.metric.saturating_add(u32::from(*cost))
            };
            let route = RouteEntry::new(
                IpPrefix::V6(prefix),
                RouteProtocol::Ospf,
                NexthopGroup::single(Nexthop::Ipv6If(*gw, *ifindex)),
                metric,
            );
            want.insert(prefix.to_string(), route);
        }
        // Diff against the installed table (the v2 export shape).
        let mut commands = Vec::new();
        for (prefix, route) in &want {
            match self.routes.get(prefix) {
                None => {
                    info!(prefix = %prefix, "ospfv3: route installed");
                    commands.push(ZedgeCommand::RouteAdd(route.clone()));
                }
                Some(old) if old != route => {
                    commands.push(ZedgeCommand::RouteDel(old.clone()));
                    commands.push(ZedgeCommand::RouteAdd(route.clone()));
                }
                _ => {}
            }
        }
        for (prefix, route) in &self.routes {
            if !want.contains_key(prefix) {
                info!(prefix = %prefix, "ospfv3: route withdrawn");
                commands.push(ZedgeCommand::RouteDel(route.clone()));
            }
        }
        self.routes = want;
        if let Some(zapi) = &self.zapi {
            for command in commands {
                let _ = zapi.send(command);
            }
        }
        let _ = now;
    }

    // ---- The periodic tick ---------------------------------------

    pub fn tick(&mut self, now: u64, out: &mut Vec<WireOutV3>) {
        // §C.3 Hellos.
        for idx in 0..self.interfaces.len() {
            if now >= self.interfaces[idx].hello_deadline {
                let hello = self.make_hello(idx);
                out.push(WireOutV3 {
                    iface: idx,
                    to: WireToV3::Multicast,
                    packet: hello,
                });
                self.interfaces[idx].hello_deadline =
                    now + u64::from(self.interfaces[idx].cfg.hello_interval);
            }
        }
        // Conversation ticks.
        for idx in 0..self.interfaces.len() {
            let area = std::mem::take(&mut self.lsdb);
            let link = std::mem::take(&mut self.interfaces[idx].link_lsdb);
            let iface = &mut self.interfaces[idx];
            let mut reports = Vec::new();
            for conv in iface.neighbors.values_mut() {
                let (sends, report) = conv.tick(now);
                reports.push(report);
                for s in sends {
                    out.push(WireOutV3 {
                        iface: idx,
                        to: WireToV3::Unicast(s.to),
                        packet: s.packet,
                    });
                }
            }
            self.interfaces[idx].link_lsdb = link;
            self.lsdb = area;
            let mut merged = ConversationReportV3::default();
            for report in &reports {
                merged.merge(report);
            }
            if merged.adjacency_up || merged.adjacency_down {
                self.after_report_v3(idx, None, &merged, now, out);
            }
        }
        // §12.4 re-origination: the adjacency-driven LSAs.
        if self.router_lsa_dirty {
            self.originate_router_lsa(now, out);
        }
        for idx in 0..self.interfaces.len() {
            if self.interfaces[idx].link_lsa_dirty {
                self.originate_link_lsa(idx, now, out);
            }
        }
        // §14 aging: the area/AS database and every link store.
        let syncing = self.any_syncing();
        let mut area = std::mem::take(&mut self.lsdb);
        let mut aged = area.tick_aging(now);
        // Refresh-due self-originated LSAs re-originate.
        for key in std::mem::take(&mut aged.refresh_due) {
            let rebuild = match key.ls_type {
                V3_ROUTER => Some(self.build_router_lsa()),
                _ => self.lsdb.get(&key).map(|e| e.lsa.clone()),
            };
            if let Some(lsa) = rebuild {
                if self.lsdb.originate(lsa, now).is_ok() {
                    let stored = self.lsdb.get(&key).map(|e| e.lsa.clone());
                    if let Some(lsa) = stored {
                        self.flood_own(&lsa, now, out);
                    }
                }
            }
        }
        // MaxAge reflood + removal (§14).
        for key in std::mem::take(&mut aged.max_age) {
            if let Some(lsa) = area.get(&key).map(|e| e.lsa.clone()) {
                self.flood_own(&lsa, now, out);
            }
        }
        for key in area.flush_ready(syncing) {
            area.remove(&key);
        }
        self.lsdb = area;
        for idx in 0..self.interfaces.len() {
            let mut link = std::mem::take(&mut self.interfaces[idx].link_lsdb);
            let report = link.tick_aging(now);
            for key in report.refresh_due {
                if key.ls_type == V3_LINK {
                    let lsa = self.build_link_lsa(idx);
                    if link.originate(lsa, now).is_ok() {
                        let stored = link.get(&key).map(|e| e.lsa.clone());
                        if let Some(lsa) = stored {
                            self.flood_own(&lsa, now, out);
                        }
                    }
                }
            }
            for key in report.max_age {
                if let Some(lsa) = link.get(&key).map(|e| e.lsa.clone()) {
                    self.flood_own(&lsa, now, out);
                }
            }
            for key in link.flush_ready(syncing) {
                link.remove(&key);
            }
            self.interfaces[idx].link_lsdb = link;
        }
    }

    /// §13.4's v1 arm: a received newer self-originated LSA advances
    /// the tracking and re-originates (the restart case).
    fn readopt_self_originated(&mut self, lsas: &[LsaV3], now: u64, out: &mut Vec<WireOutV3>) {
        for lsa in lsas {
            if lsa.header.adv_router != self.router_id {
                continue;
            }
            let key = lsa.key();
            let store_is_link = lsa.header.ls_type.scope() == crate::lsa::Scope::Link;
            let readopt = if store_is_link {
                let iface = self
                    .interfaces
                    .iter_mut()
                    .find(|i| i.link_lsdb.contains(&key));
                match iface {
                    Some(i) => i.link_lsdb.readopt_self_originated(lsa),
                    None => continue,
                }
            } else {
                self.lsdb.readopt_self_originated(lsa)
            };
            match readopt {
                Readopt::Advanced => {
                    let rebuild = match key.ls_type {
                        V3_ROUTER => self.build_router_lsa(),
                        V3_LINK => {
                            let idx = self
                                .interfaces
                                .iter()
                                .position(|i| i.link_lsdb.contains(&key))
                                .unwrap_or(0);
                            self.build_link_lsa(idx)
                        }
                        _ => continue,
                    };
                    let originated;
                    if store_is_link {
                        let idx = self
                            .interfaces
                            .iter()
                            .position(|i| i.link_lsdb.contains(&key))
                            .unwrap_or(0);
                        originated = self.interfaces[idx]
                            .link_lsdb
                            .originate(rebuild, now)
                            .is_ok();
                        if originated {
                            let stored = self.interfaces[idx]
                                .link_lsdb
                                .get(&key)
                                .map(|e| e.lsa.clone());
                            if let Some(lsa) = stored {
                                self.flood_own(&lsa, now, out);
                            }
                        }
                    } else {
                        originated = self.lsdb.originate(rebuild, now).is_ok();
                        if originated {
                            let stored = self.lsdb.get(&key).map(|e| e.lsa.clone());
                            if let Some(lsa) = stored {
                                self.flood_own(&lsa, now, out);
                            }
                        }
                    }
                }
                Readopt::NeedsFlush => {
                    let aged = if store_is_link {
                        self.interfaces
                            .iter_mut()
                            .find(|i| i.link_lsdb.contains(&key))
                            .and_then(|i| i.link_lsdb.premature_age(&key))
                    } else {
                        self.lsdb.premature_age(&key)
                    };
                    if let Some(aged) = aged {
                        self.flood_own(&aged, now, out);
                    }
                }
                _ => {}
            }
        }
    }

    /// The neighbor/conversation state surface (tests + operators).
    pub fn neighbor_states(&self) -> Vec<(String, RouterId, NeighborState)> {
        self.interfaces
            .iter()
            .flat_map(|i| {
                i.neighbors
                    .iter()
                    .map(|(rid, c)| (i.name.clone(), *rid, c.state()))
            })
            .collect()
    }

    pub fn installed_routes(&self) -> Vec<&RouteEntry> {
        self.routes.values().collect()
    }
}

/// The A.4.1 prefix triple's address bytes: exactly
/// `((len + 31) / 32)` words, truncated from the address.
fn prefix_bytes(prefix: &Ipv6Prefix) -> Vec<u8> {
    let take = Prefix::words(prefix.prefix_len()).min(16);
    prefix.addr().octets()[..take].to_vec()
}

/// The inverse: an LSA prefix triple back to a route prefix.
fn ipv6_prefix_of(prefix: &Prefix) -> Option<Ipv6Prefix> {
    let mut bytes = [0u8; 16];
    let take = Prefix::words(prefix.len).min(16);
    if prefix.addr.len() != take {
        return None;
    }
    bytes[..take].copy_from_slice(&prefix.addr);
    Ipv6Prefix::new(std::net::Ipv6Addr::from(bytes), prefix.len).ok()
}

/// The inbound event type: (interface index, datagram, the resolved
/// destination, the cmsg hop limit when the kernel attached one).
pub type InboundV3 = (usize, ReceivedV6, Ipv6Addr, Option<u32>);

/// The run loop (the v2 daemon's shape, sockets → mpsc → core).
pub async fn run(
    mut core: OspfdV3,
    sockets: Vec<Arc<OspfV6RawSocket>>,
    mut pushed: mpsc::UnboundedReceiver<RedistributedRoute>,
    mut withdrawn: mpsc::UnboundedReceiver<RedistributedRoute>,
    mut shutdown: tokio::sync::watch::Receiver<bool>,
) -> std::io::Result<()> {
    let (tx, mut rx) = mpsc::channel::<InboundV3>(1024);
    // The receive pumps: the AUDITED recvmsg read-back per socket
    // (`transport::recvmsg_v6_ctl`) — the true destination and the
    // received hop limit come off the kernel's cmsgs, replacing
    // S7-a's destination-trial interim at the loop's edge (the trial
    // remains the fallback when the kernel attaches no cmsg).
    // bfdd's discipline: nonblocking recvmsg on its own blocking
    // thread with a 10 ms poll rhythm (a parked BLOCKING recvmsg
    // cannot be woken portably, which would wedge the runtime's
    // blocking-task join), the pump holding only a WEAK socket
    // reference so the daemon's Drop (the last strong Arc) closes
    // the socket and ends the pump at the next poll.
    for (idx, sock) in sockets.iter().enumerate() {
        let sock = Arc::downgrade(sock);
        let tx = tx.clone();
        tokio::task::spawn_blocking(move || {
            let mut payload = [std::mem::MaybeUninit::<u8>::uninit(); 65535];
            let mut ctrl = [std::mem::MaybeUninit::<u8>::uninit(); crate::transport::CTL_BUFSZ_V6];
            loop {
                let Some(sock) = sock.upgrade() else { return };
                match sock.recv_ctl(&mut payload, &mut ctrl) {
                    Ok(read) => {
                        // The REAL verdict when the cmsg attached the
                        // destination; the §4.2 candidate trial as the
                        // no-cmsg fallback (disclosed at the transport).
                        let own = sock.link_local;
                        let dst = read.dst.unwrap_or(own);
                        if read.dst.is_none()
                            && crate::transport::decode_v3_dst(read.payload, read.src, own)
                                .is_none()
                        {
                            continue; // verifies against no candidate — drop
                        }
                        let datagram = ReceivedV6 {
                            src: read.src,
                            payload: read.payload.to_vec(),
                        };
                        if tx
                            .blocking_send((idx, datagram, dst, read.hop_limit))
                            .is_err()
                        {
                            return; // run loop gone
                        }
                    }
                    Err(e)
                        if e.kind() == std::io::ErrorKind::WouldBlock
                            || e.kind() == std::io::ErrorKind::Interrupted =>
                    {
                        std::thread::sleep(std::time::Duration::from_millis(10));
                    }
                    Err(e) => {
                        warn!(error = %e, "ospfv3: read-back pump failed; stopping");
                        return;
                    }
                }
            }
        });
    }
    drop(tx);

    let start = tokio::time::Instant::now();
    let mut tick_interval = tokio::time::interval(std::time::Duration::from_secs(1));
    info!(
        router_id = %core.router_id,
        area = core.area,
        interfaces = core.interfaces.len(),
        redistribute_static = core.redistribute_static,
        "ospfv3: running"
    );
    let mut out = Vec::new();
    core.tick(0, &mut out);
    flush_wire_v3(&sockets, &core, out).await;

    loop {
        tokio::select! {
            inbound = rx.recv() => {
                let Some((idx, received, dst, hop)) = inbound else { break };
                let now = start.elapsed().as_secs();
                let out = core.on_packet(idx, &received, dst, hop, now);
                flush_wire_v3(&sockets, &core, out).await;
            }
            _ = tick_interval.tick() => {
                let now = start.elapsed().as_secs();
                let mut out = Vec::new();
                core.tick(now, &mut out);
                flush_wire_v3(&sockets, &core, out).await;
            }
            route = pushed.recv() => {
                if let Some(route) = route {
                    let now = start.elapsed().as_secs();
                    let mut out = Vec::new();
                    core.on_redistribute_add(&route, now, &mut out);
                    flush_wire_v3(&sockets, &core, out).await;
                }
            }
            route = withdrawn.recv() => {
                if let Some(route) = route {
                    let now = start.elapsed().as_secs();
                    let mut out = Vec::new();
                    core.on_redistribute_del(&route, now, &mut out);
                    flush_wire_v3(&sockets, &core, out).await;
                }
            }
            _ = shutdown.changed() => {
                info!("ospfv3: shutdown");
                return Ok(());
            }
        }
    }
    Ok(())
}

async fn flush_wire_v3(sockets: &[Arc<OspfV6RawSocket>], core: &OspfdV3, out: Vec<WireOutV3>) {
    for wire in out {
        let Some(sock) = sockets.get(wire.iface) else {
            continue;
        };
        let src = core.interfaces[wire.iface].link_local;
        let dst = wire.to.addr();
        let bytes = wire.packet.encode(src, dst);
        let result = match wire.to {
            WireToV3::Multicast => sock.send_multicast(&bytes).await,
            WireToV3::AllDRouters => sock.send_multicast_drouters(&bytes).await,
            WireToV3::Unicast(ip) => sock.send_unicast(&bytes, ip).await,
        };
        if let Err(e) = result {
            warn!(error = %e, iface = %core.interfaces[wire.iface].name, "ospfv3: send failed");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::parse as parse_config;

    fn v3_conf(rid: &str, ll: &str, ifindex: u32, instance: u8) -> OspfdConfig {
        let text = format!(
            "router ospf\n address-family ipv6-unicast\n router-id {rid}\n area 0.0.0.0\n  interface eth0\n   link-local {ll}\n   ifindex {ifindex}\n   instance-id {instance}\n   network-type point-to-point\n   hello-interval 2\n   dead-interval 8\n"
        );
        parse_config(&text).unwrap()
    }

    fn core_v3(rid: u32, ll: Ipv6Addr, ifindex: u32, instance: u8) -> OspfdV3 {
        OspfdV3::new(&v3_conf(
            &RouterId(rid).to_ipv4().to_string(),
            &ll.to_string(),
            ifindex,
            instance,
        ))
        .unwrap()
    }

    /// Deliver one core's obligations to the other (the v2 pump
    /// convention): encode with the sender's link-local and the
    /// obligation's destination, feed the receiver, return the
    /// receiver's new obligations.
    fn deliver(
        from: &mut OspfdV3,
        to: &mut OspfdV3,
        out: Vec<WireOutV3>,
        now: u64,
    ) -> Vec<WireOutV3> {
        let src_ll = from.interfaces[0].link_local;
        let mut next = Vec::new();
        for wire in out {
            let bytes = wire.packet.encode(src_ll, wire.to.addr());
            let received = ReceivedV6 {
                src: src_ll,
                payload: bytes,
            };
            // Every obligation destination is one of ff02::5/6 or
            // the peer's link-local — the trial's candidate set.
            let dst = wire.to.addr();
            next.extend(to.on_packet(0, &received, dst, None, now));
        }
        next
    }

    /// Run two pure v3 cores against each other until both report a
    /// Full neighbor — the v2 `run_to_full` convention: each round,
    /// both cores tick and every obligation is ping-ponged between
    /// them until the queues drain.
    fn run_to_full(a: &mut OspfdV3, b: &mut OspfdV3, mut now: u64, rounds: usize) -> u64 {
        let is_full = |c: &OspfdV3| {
            c.neighbor_states()
                .iter()
                .any(|(_, _, s)| *s == NeighborState::Full)
        };
        for _ in 0..rounds {
            let mut out_a = Vec::new();
            let mut out_b = Vec::new();
            a.tick(now, &mut out_a);
            b.tick(now, &mut out_b);
            // (to_b, packets): deliver toward the named core.
            let mut queue: Vec<(bool, Vec<WireOutV3>)> = vec![(true, out_a), (false, out_b)];
            for _ in 0..128 {
                match queue.pop() {
                    Some((_, drained)) if drained.is_empty() => continue,
                    Some((to_b, drained)) => {
                        let replies = if to_b {
                            deliver(a, b, drained, now)
                        } else {
                            deliver(b, a, drained, now)
                        };
                        // The replies target the OTHER core.
                        queue.push((!to_b, replies));
                    }
                    None => break,
                }
            }
            if is_full(a) && is_full(b) {
                // Let the adjacency-driven re-origination land too
                // (MinLSInterval 5 s: the link-bearing router-LSA
                // supersedes the empty one built at construction —
                // the same seconds a real bring-up takes).
                for _ in 0..8 {
                    now += 1;
                    let mut out_a = Vec::new();
                    let mut out_b = Vec::new();
                    a.tick(now, &mut out_a);
                    b.tick(now, &mut out_b);
                    let mut queue: Vec<(bool, Vec<WireOutV3>)> =
                        vec![(true, out_a), (false, out_b)];
                    for _ in 0..128 {
                        match queue.pop() {
                            Some((_, drained)) if drained.is_empty() => continue,
                            Some((to_b, drained)) => {
                                let replies = if to_b {
                                    deliver(a, b, drained, now)
                                } else {
                                    deliver(b, a, drained, now)
                                };
                                queue.push((!to_b, replies));
                            }
                            None => break,
                        }
                    }
                }
                return now;
            }
            now += 1;
        }
        now
    }

    #[test]
    fn two_v3_cores_reach_full_and_exchange_lsas() {
        let ll_a: Ipv6Addr = "fe80::aa".parse().unwrap();
        let ll_b: Ipv6Addr = "fe80::bb".parse().unwrap();
        let mut a = core_v3(0x0a00_0001, ll_a, 11, 0);
        let mut b = core_v3(0x0a00_0002, ll_b, 22, 0);
        let end = run_to_full(&mut a, &mut b, 0, 30);
        let states_a: Vec<NeighborState> =
            a.neighbor_states().into_iter().map(|(_, _, s)| s).collect();
        let states_b: Vec<NeighborState> =
            b.neighbor_states().into_iter().map(|(_, _, s)| s).collect();
        assert!(
            states_a.contains(&NeighborState::Full),
            "core A reached Full (states: {states_a:?}, t={end})"
        );
        assert!(
            states_b.contains(&NeighborState::Full),
            "core B reached Full (states: {states_b:?}, t={end})"
        );
        // LSDB convergence: each holds the peer's router-LSA AND the
        // peer's link-LSA (link-scope exchange over the SAME link).
        let key_router_b = LsaKey {
            ls_type: V3_ROUTER,
            link_state_id: LinkStateId(0),
            adv_router: RouterId(0x0a00_0002),
        };
        let key_link_b = LsaKey {
            ls_type: V3_LINK,
            link_state_id: LinkStateId(22),
            adv_router: RouterId(0x0a00_0002),
        };
        assert!(a.lsdb.contains(&key_router_b), "A holds B's router-LSA");
        assert!(
            a.interfaces[0].link_lsdb.contains(&key_link_b),
            "A holds B's link-LSA in the LINK-scope store (3.2)"
        );
        assert!(!a.lsdb.contains(&key_link_b), "never in the area store");
        // The router-LSA's p2p link carries Interface IDs both ways.
        let router_b = a.lsdb.get(&key_router_b).unwrap().lsa.clone();
        let LsaBodyV3::Router(body) = router_b.body else {
            panic!("router-LSA body")
        };
        assert_eq!(body.links.len(), 1);
        assert_eq!(body.links[0].interface_id, 22, "B's interface ID");
        assert_eq!(
            body.links[0].neighbor_interface_id, 11,
            "OUR interface ID, learned from our Hello"
        );
        assert_eq!(body.links[0].neighbor_router_id, RouterId(0x0a00_0001));
    }

    #[test]
    fn instance_id_mismatch_discards() {
        let ll_a: Ipv6Addr = "fe80::aa".parse().unwrap();
        let ll_b: Ipv6Addr = "fe80::bb".parse().unwrap();
        let mut a = core_v3(0x0a00_0001, ll_a, 11, 0);
        let mut b = core_v3(0x0a00_0002, ll_b, 22, 7); // instance 7
        let mut out_b = Vec::new();
        b.tick(0, &mut out_b);
        let before = a.dropped_instance_mismatch;
        let drained = deliver(&mut b, &mut a, out_b, 0);
        assert!(drained.is_empty(), "nothing processed");
        assert_eq!(a.dropped_instance_mismatch, before + 1, "counted discard");
        assert!(a.interfaces[0].neighbors.is_empty(), "no neighbor formed");
    }

    #[test]
    fn redistributed_static_originates_type5_and_installs_theirs() {
        let ll_a: Ipv6Addr = "fe80::aa".parse().unwrap();
        let ll_b: Ipv6Addr = "fe80::bb".parse().unwrap();
        let mut a = core_v3(0x0a00_0001, ll_a, 11, 0);
        let mut b = core_v3(0x0a00_0002, ll_b, 22, 0);
        run_to_full(&mut a, &mut b, 0, 30);
        // Our redistribution: a v6 static push originates 0x4005.
        let prefix: Ipv6Prefix = "2001:db8:99::/64".parse().unwrap();
        let route = RedistributedRoute {
            prefix: IpPrefix::V6(prefix),
            metric: 5,
        };
        let mut out = Vec::new();
        a.on_redistribute_add(&route, 100, &mut out);
        // Flood to B and let the exchange settle.
        let mut queue = vec![(true, out)];
        for _ in 0..64 {
            match queue.pop() {
                Some((_, drained)) if drained.is_empty() => continue,
                Some((to_b, drained)) => {
                    let replies = if to_b {
                        deliver(&mut a, &mut b, drained, 100)
                    } else {
                        deliver(&mut b, &mut a, drained, 100)
                    };
                    queue.push((!to_b, replies));
                }
                None => break,
            }
        }
        let ext_keys: Vec<LsaKey> = b
            .lsdb
            .all()
            .map(|e| e.lsa.key())
            .filter(|k| k.ls_type == V3_AS_EXTERNAL)
            .collect();
        assert_eq!(ext_keys.len(), 1, "B holds our type-5");
        assert_eq!(ext_keys[0].adv_router, RouterId(0x0a00_0001));
        // And B installs the route (no zapi attached: the table only).
        let routes = b.installed_routes();
        assert_eq!(routes.len(), 1, "B installed the external route");
        assert_eq!(routes[0].prefix, IpPrefix::V6(prefix));
        assert_eq!(routes[0].metric, 5, "type-2 metric as-is");
        match routes[0].nexthops.hops()[0].0 {
            Nexthop::Ipv6If(gw, ifindex) => {
                assert_eq!(gw, ll_a, "gateway is A's link-local (2.5)");
                assert_eq!(ifindex, 22, "B's interface");
            }
            other => panic!("wrong nexthop shape: {other:?}"),
        }
        // Withdrawal: premature age.
        let mut out = Vec::new();
        a.on_redistribute_del(&route, 110, &mut out);
        assert!(a.externals.is_empty());
        assert!(!a.asbr, "no longer an ASBR");
    }

    #[test]
    fn link_lsa_carries_the_link_local_and_lsid_is_the_interface_id() {
        let ll: Ipv6Addr = "fe80::42".parse().unwrap();
        let mut core = core_v3(0x0a00_0001, ll, 9, 0);
        let mut out = Vec::new();
        core.tick(0, &mut out);
        let key = LsaKey {
            ls_type: V3_LINK,
            link_state_id: LinkStateId(9),
            adv_router: RouterId(0x0a00_0001),
        };
        let entry = core.interfaces[0].link_lsdb.get(&key).expect("link-LSA");
        let LsaBodyV3::Link(body) = &entry.lsa.body else {
            panic!("link body");
        };
        assert_eq!(
            body.link_local_address, ll,
            "2.5: the address neighbors need"
        );
        assert_ne!(entry.lsa.header.checksum, 0, "normalized");
        // Wire round-trip: encode/decode agrees byte-for-byte.
        let bytes = entry.lsa.encode();
        assert_eq!(LsaV3::decode(&bytes).unwrap(), entry.lsa);
    }
}
