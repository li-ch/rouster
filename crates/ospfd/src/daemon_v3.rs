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
use crate::spf::SpfScheduler;
use crate::spf_v3::{NextHopV3, SpfLinkV3, SpfResultV3};
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
    /// The §9 interface state machine (broadcast networks; the p2p
    /// rows only ever use the PointToPoint state).
    pub fsm: crate::iface::InterfaceFsm,
    /// The elected DR/BDR on a broadcast link (§9.4's result, also
    /// our Hello's claim fields — Router IDs in v3, §A.3.2; 0 = none).
    pub dr: RouterId,
    pub bdr: RouterId,
    /// §9.3's WaitTimer deadline (monotonic seconds), broadcast only.
    pub wait_deadline: Option<u64>,
    /// Per-neighbor Hello claims on a broadcast link (§9.2/§9.4's
    /// election inputs) — the v3 shape: DR/BDR claims are Router IDs,
    /// mapped into the shared election's identity slot.
    pub claims: HashMap<RouterId, crate::iface::ElectionNeighbor>,
    /// The self-originated network-LSA (while DR), §4.4.3.3.
    network_lsa: Option<LsaKey>,
    /// Whether the network-LSA needs (re-)origination (DR only).
    network_lsa_dirty: bool,
    /// The DR's network-referenced IAPR (§4.4.3.9 part 1) + dirty.
    network_iapr: Option<LsaKey>,
    network_iapr_dirty: bool,
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

    fn broadcast(&self) -> bool {
        self.cfg.network_type == NetworkType::Broadcast
    }

    /// §10.4's adjacency answer: p2p always adjacent ("all router
    /// pairs directly connected by a physical point-to-point link
    /// become adjacent"); broadcast with/toward the DR and BDR only.
    fn adjacency_ok(&self, rid: RouterId) -> bool {
        if !self.broadcast() {
            return true;
        }
        matches!(
            self.fsm.state,
            crate::iface::InterfaceState::Dr | crate::iface::InterfaceState::Backup
        ) || rid == self.dr
            || rid == self.bdr
    }
}

/// The §9.4 identity mapping: v3's DR/BDR claims are ROUTER IDs
/// (§A.3.2), the shared election's slots are address-typed — the
/// election compares identities only, so Router IDs ride the u32
/// identity slot unchanged (the AF-generic seam; documented, never
/// interpreted as an address).
fn rid_identity(rid: RouterId) -> std::net::Ipv4Addr {
    std::net::Ipv4Addr::from(rid.0)
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
    /// The §4.8.1 throttle (the v2 area's FRR-parity 0/50/5000 ms
    /// shape): topology changes (router-/network-LSAs) recompute the
    /// SPT on their own schedule; the table-only classes
    /// (IAPR/external installs) rerun the walk on the cached result
    /// (§16.5's discipline).
    spf_sched: SpfScheduler,
    spf_dirty: bool,
    last_spf: Option<SpfResultV3>,
    table_dirty: bool,
    routes: BTreeMap<String, RouteEntry>,
    /// Self-originated externals (prefix string -> (key, LS ID)).
    externals: BTreeMap<String, (LsaKey, u32)>,
    /// The next AS-external LS ID allocator (v3's LS ID is a pure
    /// de-multiplexer, A.4.7).
    next_external_lsid: u32,
    router_lsa_dirty: bool,
    /// The router-referenced IAPR (§4.4.3.9 part 2: this router's
    /// own prefixes, referenced LS type 0x2001) + dirty.
    iapr_key: Option<LsaKey>,
    iapr_dirty: bool,
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
            if icfg.network_type != NetworkType::PointToPoint
                && icfg.network_type != NetworkType::Broadcast
            {
                return Err(format!(
                    "interface {name}: OSPFv3 v1 supports network-type point-to-point|broadcast"
                ));
            }
            let ifindex = match icfg.ifindex {
                Some(idx) => idx,
                // Linux hosts resolve the name; tests pin the index.
                None => crate::transport::ifindex_of(name)
                    .map_err(|e| format!("interface {name}: no ifindex ({e})"))?,
            };
            let p2p = icfg.network_type == NetworkType::PointToPoint;
            let mut fsm = crate::iface::InterfaceFsm::new_with_priority(p2p, icfg.priority);
            // §9.3 InterfaceUp fires at construction; broadcast arms
            // the WaitTimer (the RouterDeadInterval startup form).
            let (_, actions) = fsm.fire(crate::iface::InterfaceEvent::InterfaceUp);
            let wait_deadline = if actions.contains(&crate::iface::InterfaceAction::StartWaitTimer)
            {
                Some(icfg.dead_interval as u64)
            } else {
                None
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
                fsm,
                dr: RouterId(0),
                bdr: RouterId(0),
                wait_deadline,
                claims: HashMap::new(),
                network_lsa: None,
                network_lsa_dirty: false,
                network_iapr: None,
                network_iapr_dirty: false,
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
            spf_sched: SpfScheduler::new(0, 50, 5000),
            spf_dirty: true,
            last_spf: None,
            table_dirty: true,
            routes: BTreeMap::new(),
            externals: BTreeMap::new(),
            next_external_lsid: 0,
            router_lsa_dirty: true,
            iapr_key: None,
            iapr_dirty: true,
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
        // §A.3.2: the DR/BDR claims (Router IDs on a broadcast link —
        // "ignored on point-to-point links", 4.2.2.1).
        let (dr, bdr) = if i.broadcast() {
            (i.dr, i.bdr)
        } else {
            (RouterId(0), RouterId(0))
        };
        self.packet(
            iface,
            PacketBodyV3::Hello(HelloV3 {
                interface_id: i.ifindex,
                router_priority: i.cfg.priority,
                options: our_options(),
                hello_interval: i.cfg.hello_interval,
                router_dead_interval: i.cfg.dead_interval.min(u32::from(u16::MAX)) as u16,
                designated_router: dr,
                backup_designated_router: bdr,
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
        // §4.2/§A.1: AllDRouters (ff02::6) destinations are processed
        // only by the link's DR and BDR ("routers not belonging to
        // the Designated Router's network should drop").
        if dst == crate::transport::ALL_D_ROUTERS_V6 {
            let role = self.interfaces[iface_idx].fsm.state;
            if !matches!(
                role,
                crate::iface::InterfaceState::Dr | crate::iface::InterfaceState::Backup
            ) {
                debug!(src = %received.src, "ospfv3: AllDRouters packet while not DR/BDR — drop");
                return out;
            }
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
                let was_2way = self.interfaces[iface_idx]
                    .neighbors
                    .get(&peer)
                    .is_some_and(|c| c.state().at_least(NeighborState::TwoWay));
                // The databases ride as taken values (the conversation
                // mutably borrows the interface while the link store
                // lives in the same vector).
                let link = std::mem::take(&mut self.interfaces[iface_idx].link_lsdb);
                for event in events {
                    let area = &self.lsdb;
                    let conv = self.interfaces[iface_idx].neighbors.get_mut(&peer).unwrap();
                    let (mut ev_sends, mut report) = conv.fire_and_map(event, area, &link, now);
                    if event == NeighborEvent::TwoWayReceived {
                        // §10.4's answer: p2p always adjacent;
                        // broadcast only with/toward the DR/BDR.
                        let answer = self.interfaces[iface_idx].adjacency_ok(peer);
                        let conv = self.interfaces[iface_idx].neighbors.get_mut(&peer).unwrap();
                        let (s, r) =
                            conv.fire_and_map(NeighborEvent::AdjOk(answer), area, &link, now);
                        ev_sends.extend(s);
                        report.merge(&r);
                        if !answer {
                            info!(
                                iface = %self.interfaces[iface_idx].name,
                                neighbor = %peer,
                                "ospfv3: neighbor stays 2-Way (§10.4: neither side is DR/BDR)"
                            );
                        }
                    }
                    out.extend(self.sends_into(iface_idx, ev_sends));
                    let conv = self.interfaces[iface_idx].neighbors.get_mut(&peer).unwrap();
                    conv.touch_inactivity(now, dead);
                    self.after_report_v3(iface_idx, Some(peer), &report, now, &mut out);
                }
                self.interfaces[iface_idx].link_lsdb = link;
                // ---- §9.2/§9.4 (broadcast): claims + election ----
                if self.interfaces[iface_idx].broadcast() {
                    let is_2way = self.interfaces[iface_idx]
                        .neighbors
                        .get(&peer)
                        .is_some_and(|c| c.state().at_least(NeighborState::TwoWay));
                    // The claim snapshot: v3's DR/BDR claims are
                    // Router IDs, riding the shared election's
                    // identity slot (`rid_identity`).
                    let new_claims = crate::iface::ElectionNeighbor {
                        router_id: peer,
                        address: rid_identity(peer),
                        priority: hello.router_priority,
                        dr: rid_identity(hello.designated_router),
                        bdr: rid_identity(hello.backup_designated_router),
                    };
                    let iface_state = self.interfaces[iface_idx].fsm.state;
                    let prev_claims = self.interfaces[iface_idx].claims.get(&peer).copied();
                    let ism_events = crate::iface::hello_interface_events(
                        iface_state,
                        prev_claims,
                        new_claims,
                        was_2way,
                        is_2way,
                    );
                    self.interfaces[iface_idx].claims.insert(peer, new_claims);
                    for ev in ism_events {
                        let (_, actions) = self.interfaces[iface_idx].fsm.fire(ev);
                        if actions.contains(&crate::iface::InterfaceAction::ElectDr) {
                            self.run_election_v3(iface_idx, now, &mut out);
                        }
                    }
                }
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
                if ips.is_empty() {
                    continue;
                }
                let packet = self.packet(
                    idx,
                    PacketBodyV3::LsUpdate(LsUpdateV3 {
                        lsas: vec![lsa.clone()],
                    }),
                );
                if self.interfaces[idx].broadcast() {
                    // §13.3's broadcast rule (the flood_own shape).
                    let to = if self.drouters_member(idx) {
                        WireToV3::Multicast
                    } else {
                        WireToV3::AllDRouters
                    };
                    out.push(WireOutV3 {
                        iface: idx,
                        to,
                        packet,
                    });
                    continue;
                }
                for ip in ips {
                    out.push(WireOutV3 {
                        iface: idx,
                        to: WireToV3::Unicast(ip),
                        packet: packet.clone(),
                    });
                }
            }
        }
    }

    /// The post-input bookkeeping: adjacency transitions dirty the
    /// router-LSA; changed LSAs mark their §16.5 class and rerun the
    /// walk when due.
    fn after_report_v3(
        &mut self,
        iface_idx: usize,
        peer: Option<RouterId>,
        report: &ConversationReportV3,
        now: u64,
        out: &mut Vec<WireOutV3>,
    ) {
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
            self.mark_spf_dirty(now);
        }
        if report.adjacency_down {
            info!(
                iface = %self.interfaces[iface_idx].name,
                neighbor = ?peer,
                "ospfv3: adjacency down"
            );
            self.router_lsa_dirty = true;
            self.originate_router_lsa(now, out);
            self.mark_spf_dirty(now);
        }
        // The interop machine-check surface: a FOREIGN router- or
        // link-LSA landed (the LSDB-convergence proof). The trace
        // widens to every foreign LSA.
        for lsa in &report.changed_lsas {
            if lsa.header.adv_router != self.router_id
                && (matches!(lsa.header.ls_type, V3_ROUTER | V3_LINK)
                    || std::env::var_os("ROUSTER_OSPFV3_TRACE").is_some())
            {
                info!(
                    lsa = lsa.header.ls_type.name(),
                    adv = %lsa.header.adv_router,
                    seq = lsa.header.seq,
                    "ospfv3: peer LSA installed"
                );
            }
        }
        // §16.5's classes (the v3 mapping): router-/network-LSAs are
        // area-topology changes (§16.1 recompute); the IAPR and
        // external classes touch only the routing table walk.
        for key in &report.changed {
            match key.ls_type {
                V3_ROUTER | LsaType::V3_NETWORK => self.mark_spf_dirty(now),
                _ => self.table_dirty = true,
            }
        }
        // The DR's §4.4.3.3/§4.4.3.9 duties: the attached set (and
        // with it the network IAPR's prefix source) changed with any
        // adjacency transition; a link-LSA change while DR re-offers
        // the IAPR's inputs.
        if self.interfaces[iface_idx].broadcast()
            && self.interfaces[iface_idx].fsm.state == crate::iface::InterfaceState::Dr
        {
            if report.adjacency_up || report.adjacency_down {
                self.interfaces[iface_idx].network_lsa_dirty = true;
                self.interfaces[iface_idx].network_iapr_dirty = true;
            }
            if report
                .changed_lsas
                .iter()
                .any(|l| l.header.ls_type == V3_LINK && l.header.adv_router != self.router_id)
            {
                self.interfaces[iface_idx].network_iapr_dirty = true;
            }
        }
        self.maybe_spf(now);
    }

    /// A topology change: the SPT recomputes on the throttle schedule
    /// (§16.5's incremental classes at the v3 seam).
    fn mark_spf_dirty(&mut self, now: u64) {
        self.spf_dirty = true;
        self.spf_sched.on_change(now * 1000);
    }

    /// Run the §9.4 election on one broadcast interface and apply the
    /// outcome — the v2 daemon's `run_election` shape over v3
    /// identities: the claims are Router IDs (`rid_identity`), the
    /// role drives the type-2 link, the network-LSA and the DR's IAPR
    /// duties, and step (7)'s AdjOK? re-evaluation.
    fn run_election_v3(&mut self, idx: usize, now: u64, out: &mut Vec<WireOutV3>) {
        let (neighbors, prev) = {
            let iface = &self.interfaces[idx];
            // §9.4's inputs: the bidirectional neighbors' claims.
            let neighbors: Vec<crate::iface::ElectionNeighbor> = iface
                .neighbors
                .iter()
                .filter(|(_, c)| c.state().at_least(NeighborState::TwoWay))
                .filter_map(|(rid, _)| iface.claims.get(rid).copied())
                .collect();
            (neighbors, (iface.dr, iface.bdr))
        };
        let own = crate::iface::ElectionNeighbor {
            router_id: self.router_id,
            address: rid_identity(self.router_id),
            priority: self.interfaces[idx].cfg.priority,
            // Our claims = what our Hellos carry (§9.4's repeat reads
            // them back).
            dr: rid_identity(prev.0),
            bdr: rid_identity(prev.1),
        };
        let outcome = crate::iface::elect_dr(
            own,
            &neighbors,
            (rid_identity(prev.0), rid_identity(prev.1)),
        );
        let was_role = self.interfaces[idx].fsm.state;
        {
            let iface = &mut self.interfaces[idx];
            iface.dr = RouterId(u32::from(outcome.dr));
            iface.bdr = RouterId(u32::from(outcome.bdr));
            // §9.3's "New state: Depends upon action routine" — the
            // election IS the action routine for the Waiting rows.
            iface.fsm.state = outcome.role;
            if outcome.role != crate::iface::InterfaceState::Waiting {
                iface.wait_deadline = None;
            }
        }
        if was_role != outcome.role || outcome.dr_changed || outcome.bdr_changed {
            info!(
                iface = %self.interfaces[idx].name,
                dr = %self.interfaces[idx].dr,
                bdr = %self.interfaces[idx].bdr,
                role = outcome.role.name(),
                "ospfv3: DR election (§9.4 over Router-ID claims)"
            );
        }
        if was_role != outcome.role {
            // The type-2 link description changed with the role.
            self.router_lsa_dirty = true;
            if was_role == crate::iface::InterfaceState::Dr
                && outcome.role != crate::iface::InterfaceState::Dr
            {
                // §4.4.3.3: a former DR flushes its network-LSA and
                // the DR's network-referenced IAPR.
                let aged_net = self.interfaces[idx]
                    .network_lsa
                    .take()
                    .and_then(|key| self.lsdb.premature_age(&key));
                if let Some(maxage) = aged_net {
                    self.flood_own(&maxage, now, out);
                }
                let aged_iapr = self.interfaces[idx]
                    .network_iapr
                    .take()
                    .and_then(|key| self.lsdb.premature_age(&key));
                if let Some(maxage) = aged_iapr {
                    self.flood_own(&maxage, now, out);
                }
                info!(iface = %self.interfaces[idx].name, "ospfv3: DR duties flushed (no longer DR)");
            }
            if outcome.role == crate::iface::InterfaceState::Dr {
                self.interfaces[idx].network_lsa_dirty = true;
                self.interfaces[idx].network_iapr_dirty = true;
            }
        }
        if outcome.dr_changed {
            // The transit-link key follows the DR (its Interface ID +
            // Router ID, §4.4.3.2).
            self.router_lsa_dirty = true;
        }
        if outcome.dr_changed || outcome.bdr_changed {
            // §9.4 step (7): AdjOK? on every neighbor ≥ 2-Way.
            let keys: Vec<RouterId> = self.interfaces[idx]
                .neighbors
                .iter()
                .filter(|(_, c)| c.state().at_least(NeighborState::TwoWay))
                .map(|(rid, _)| *rid)
                .collect();
            for key in keys {
                self.reevaluate_adjacency_v3(idx, key, now, out);
            }
        }
    }

    /// Fire AdjOK? with §10.4's broadcast answer for one neighbor.
    fn reevaluate_adjacency_v3(
        &mut self,
        idx: usize,
        peer: RouterId,
        now: u64,
        out: &mut Vec<WireOutV3>,
    ) {
        let answer = self.interfaces[idx].adjacency_ok(peer);
        let link = std::mem::take(&mut self.interfaces[idx].link_lsdb);
        let area = &self.lsdb;
        let Some(conv) = self.interfaces[idx].neighbors.get_mut(&peer) else {
            self.interfaces[idx].link_lsdb = link;
            return;
        };
        let (sends, report) = conv.fire_and_map(NeighborEvent::AdjOk(answer), area, &link, now);
        self.interfaces[idx].link_lsdb = link;
        out.extend(self.sends_into(idx, sends));
        self.after_report_v3(idx, Some(peer), &report, now, out);
    }

    /// Whether the run loop should hold the ff02::6 (AllDRouters)
    /// membership on this interface (§A.1: joined while DR/BDR).
    pub fn drouters_member(&self, idx: usize) -> bool {
        let iface = &self.interfaces[idx];
        iface.broadcast()
            && matches!(
                iface.fsm.state,
                crate::iface::InterfaceState::Dr | crate::iface::InterfaceState::Backup
            )
    }

    /// The §4.8 walk gate: topology-due areas recompute §16.1; the
    /// table-only classes rerun on the cached result.
    fn maybe_spf(&mut self, now: u64) {
        let recompute =
            self.last_spf.is_none() || (self.spf_dirty && self.spf_sched.is_due(now * 1000));
        if recompute {
            self.spf_sched.mark_run(now * 1000);
            self.spf_dirty = false;
            let links: Vec<SpfLinkV3> = self
                .interfaces
                .iter()
                .map(|i| SpfLinkV3 {
                    interface_id: i.ifindex,
                    lsdb: &i.link_lsdb,
                })
                .collect();
            self.last_spf = Some(crate::spf_v3::calculate_v3(
                self.router_id,
                &self.lsdb,
                &links,
            ));
            if std::env::var_os("ROUSTER_OSPFV3_TRACE").is_some() {
                info!(
                    routers = ?self
                        .last_spf
                        .as_ref()
                        .map(|s| s.routers.iter().map(|r| r.router).collect::<Vec<_>>())
                        .unwrap_or_default(),
                    "ospfv3: SPF ran"
                );
            }
        }
        if recompute || self.table_dirty {
            self.table_dirty = false;
            self.recompute_table(now);
        }
    }

    // ---- LSA origination (§4.4.3) --------------------------------

    /// §4.4.3.2: the router-LSA. p2p: one Type 1 link per fully
    /// adjacent neighbor; broadcast: ONE Type 2 (transit) link — "If
    /// the router is fully adjacent to the link's Designated Router
    /// or if the router itself is the Designated Router and is fully
    /// adjacent to at least one other router" — keyed by the DR's
    /// (Interface ID, Router ID). Interface IDs replace v2's Link
    /// Data (§2.2).
    fn build_router_lsa(&self) -> LsaV3 {
        let mut links = Vec::new();
        for iface in &self.interfaces {
            if iface.broadcast() {
                let we_are_dr = iface.dr == self.router_id;
                let full_with_dr = iface
                    .neighbors
                    .get(&iface.dr)
                    .is_some_and(|c| c.state() == NeighborState::Full);
                let any_full = iface
                    .neighbors
                    .values()
                    .any(|c| c.state() == NeighborState::Full);
                let describe = full_with_dr || (we_are_dr && any_full);
                if !describe {
                    continue; // §4.4.3.2: not described without a Full DR adjacency
                }
                // The DR's Interface ID as advertised in its Hellos;
                // ourselves as DR -> our own Interface ID.
                let dr_iface = if we_are_dr {
                    iface.ifindex
                } else {
                    iface
                        .neighbors
                        .get(&iface.dr)
                        .and_then(|c| c.peer_interface_id)
                        .unwrap_or(0)
                };
                links.push(RouterLinkV3 {
                    link_type: LinkTypeV3::Transit,
                    metric: iface.cfg.cost,
                    interface_id: iface.ifindex,
                    neighbor_interface_id: dr_iface,
                    neighbor_router_id: iface.dr,
                });
                continue;
            }
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
                // LSA concatenation of A.4.3 is the SPF consumer's
                // duty — done, spf_v3 — origination stays single-
                // fragment while links fit, disclosed).
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
    /// this is how a neighbor learns the next-hop address. The
    /// configured prefixes (§C.3's `prefix` lines) ride here for the
    /// DR's IAPR (§4.4.3.9).
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
                prefixes: iface
                    .cfg
                    .prefixes_v6
                    .iter()
                    .map(|p| Prefix {
                        len: p.prefix_len(),
                        options: Default::default(),
                        addr: prefix_bytes(p),
                    })
                    .collect(),
            }),
        }
    }

    /// §4.4.3.3: the network-LSA while DR — "originated for every
    /// broadcast or NBMA link with an elected Designated Router that
    /// is fully adjacent with at least one other router on the link.
    /// ... lists all routers on the link with which it is fully
    /// adjacent." The LS ID is the DR's (our) Interface ID; the
    /// Options field is the logical OR of the attached routers'
    /// link-LSA Options.
    fn build_network_lsa(&self, iface: usize) -> Option<LsaV3> {
        let iface = &self.interfaces[iface];
        if iface.dr != self.router_id {
            return None;
        }
        let mut attached = vec![self.router_id];
        let mut options = our_options();
        for (rid, conv) in &iface.neighbors {
            if conv.state() != NeighborState::Full {
                continue;
            }
            attached.push(*rid);
            // The OR contribution from this router's link-LSA.
            if let Some(entry) = iface.link_lsdb.all().find(|e| {
                e.lsa.header.adv_router == *rid
                    && e.lsa.header.link_state_id.0 == conv.peer_interface_id.unwrap_or(0)
            }) {
                if let LsaBodyV3::Link(body) = &entry.lsa.body {
                    options = Options24(options.0 | body.options.0);
                }
            }
        }
        if attached.len() < 2 {
            return None; // not fully adjacent with anyone: no network-LSA
        }
        attached.sort();
        Some(LsaV3 {
            header: LsaHeaderV3 {
                ls_age: 0,
                ls_type: LsaType::V3_NETWORK,
                link_state_id: LinkStateId(iface.ifindex),
                adv_router: self.router_id,
                seq: 0,
                checksum: 0,
                length: 0,
            },
            body: LsaBodyV3::Network(crate::lsa_v3::NetworkLsaV3 { options, attached }),
        })
    }

    /// §4.4.3.9 part 1: the DR's network-referenced IAPR — "Each
    /// link-LSA associated with Link L is examined ... If the
    /// link-LSA's Advertising Router is fully adjacent to the
    /// Designated Router and the Link State ID matches the neighbor's
    /// interface ID, the list of prefixes in the link-LSA is copied
    /// into the intra-area-prefix-LSA" (our own link-LSA included);
    /// NU/LA-bit prefixes are not copied; duplicates OR their
    /// PrefixOptions; the Metric is 0. The referenced triple names
    /// the link's network-LSA (0x2002, the DR's Interface ID, the
    /// DR's Router ID).
    fn build_network_iapr(&self, idx: usize) -> Option<LsaV3> {
        let iface = &self.interfaces[idx];
        if iface.dr != self.router_id {
            return None;
        }
        // The fully-adjacent routers' Interface IDs (ours = ifindex).
        let mut eligible: Vec<(RouterId, u32)> = vec![(self.router_id, iface.ifindex)];
        for (rid, conv) in &iface.neighbors {
            if conv.state() == NeighborState::Full {
                if let Some(id) = conv.peer_interface_id {
                    eligible.push((*rid, id));
                }
            }
        }
        let mut prefixes: Vec<crate::lsa_v3::PrefixMetric> = Vec::new();
        for entry in iface.link_lsdb.all() {
            let ok = eligible.iter().any(|(rid, iface_id)| {
                entry.lsa.header.adv_router == *rid && entry.lsa.header.link_state_id.0 == *iface_id
            });
            if !ok {
                continue;
            }
            let LsaBodyV3::Link(body) = &entry.lsa.body else {
                continue;
            };
            for p in &body.prefixes {
                if p.options.nu_bit() || p.options.la_bit() {
                    continue; // "SHOULD NOT be copied"
                }
                match prefixes
                    .iter_mut()
                    .find(|pm| pm.prefix.len == p.len && pm.prefix.addr == p.addr)
                {
                    // Duplicates: OR the PrefixOptions together.
                    Some(pm) => {
                        pm.prefix.options =
                            crate::lsa_v3::PrefixOptions(pm.prefix.options.0 | p.options.0)
                    }
                    None => prefixes.push(crate::lsa_v3::PrefixMetric {
                        metric: 0,
                        prefix: p.clone(),
                    }),
                }
            }
        }
        if prefixes.is_empty() {
            return None;
        }
        Some(LsaV3 {
            header: LsaHeaderV3 {
                ls_age: 0,
                ls_type: LsaType::V3_INTRA_AREA_PREFIX,
                // The LS ID is a pure de-multiplexer — one per DR
                // interface, allocated deterministically (1 + idx;
                // 0 is the router-referenced IAPR's).
                link_state_id: LinkStateId(1 + idx as u32),
                adv_router: self.router_id,
                seq: 0,
                checksum: 0,
                length: 0,
            },
            body: LsaBodyV3::IntraAreaPrefix(crate::lsa_v3::IntraAreaPrefixLsaV3 {
                prefixes,
                referenced_ls_type: LsaType::V3_NETWORK,
                referenced_link_state_id: LinkStateId(iface.ifindex),
                referenced_adv_router: self.router_id,
            }),
        })
    }

    /// §4.4.3.9 part 2: the router-referenced IAPR — this router's
    /// own prefixes: the p2p interfaces' configured global prefixes
    /// at the interface output cost (broadcast interfaces' prefixes
    /// are skipped — they ride the DR's network-referenced IAPR once
    /// the interface is a Type 2 link). Referenced (0x2001, 0, us).
    fn build_router_iapr(&self) -> Option<LsaV3> {
        let mut prefixes: Vec<crate::lsa_v3::PrefixMetric> = Vec::new();
        for iface in &self.interfaces {
            if iface.broadcast() {
                continue; // the DR's IAPR carries the transit link's prefixes
            }
            for p in &iface.cfg.prefixes_v6 {
                match prefixes
                    .iter_mut()
                    .find(|pm| pm.prefix.len == p.prefix_len() && pm.prefix.addr == prefix_bytes(p))
                {
                    Some(pm) => pm.metric = pm.metric.min(iface.cfg.cost),
                    None => prefixes.push(crate::lsa_v3::PrefixMetric {
                        metric: iface.cfg.cost,
                        prefix: Prefix {
                            len: p.prefix_len(),
                            options: Default::default(),
                            addr: prefix_bytes(p),
                        },
                    }),
                }
            }
        }
        if prefixes.is_empty() {
            return None;
        }
        Some(LsaV3 {
            header: LsaHeaderV3 {
                ls_age: 0,
                ls_type: LsaType::V3_INTRA_AREA_PREFIX,
                link_state_id: LinkStateId(0),
                adv_router: self.router_id,
                seq: 0,
                checksum: 0,
                length: 0,
            },
            body: LsaBodyV3::IntraAreaPrefix(crate::lsa_v3::IntraAreaPrefixLsaV3 {
                prefixes,
                referenced_ls_type: V3_ROUTER,
                referenced_link_state_id: LinkStateId(0),
                referenced_adv_router: self.router_id,
            }),
        })
    }

    /// Originate (or refresh) the network-LSA and DR's IAPR on one
    /// interface, and flush the pair when the justification left
    /// (no longer DR, or the LSA would be empty).
    fn originate_network_duties(&mut self, iface: usize, now: u64, out: &mut Vec<WireOutV3>) {
        // The network-LSA. A MinLSInterval-rejected origination
        // KEEPS the dirty flag (the content update must land at the
        // next opportunity — clearing on rejection would strand a
        // stale LSA forever).
        match self.build_network_lsa(iface) {
            Some(lsa) => {
                let key = lsa.key();
                if self.lsdb.originate(lsa, now).is_ok() {
                    self.interfaces[iface].network_lsa = Some(key);
                    self.interfaces[iface].network_lsa_dirty = false;
                    if let Some(stored) = self.lsdb.get(&key).map(|e| e.lsa.clone()) {
                        info!(
                            iface = %self.interfaces[iface].name,
                            "ospfv3: network-LSA originated (§4.4.3.3)"
                        );
                        self.flood_own(&stored, now, out);
                        self.mark_spf_dirty(now);
                    }
                }
            }
            None => {
                if let Some(key) = self.interfaces[iface].network_lsa.take() {
                    self.interfaces[iface].network_lsa_dirty = false;
                    if let Some(aged) = self.lsdb.premature_age(&key) {
                        self.flood_own(&aged, now, out);
                        self.mark_spf_dirty(now);
                    }
                }
            }
        }
        // The DR's network-referenced IAPR (same keep-dirty rule).
        match self.build_network_iapr(iface) {
            Some(lsa) => {
                let key = lsa.key();
                if self.lsdb.originate(lsa, now).is_ok() {
                    self.interfaces[iface].network_iapr = Some(key);
                    self.interfaces[iface].network_iapr_dirty = false;
                    if let Some(stored) = self.lsdb.get(&key).map(|e| e.lsa.clone()) {
                        info!(
                            iface = %self.interfaces[iface].name,
                            "ospfv3: network IAPR originated (§4.4.3.9)"
                        );
                        self.flood_own(&stored, now, out);
                        self.table_dirty = true;
                    }
                }
            }
            None => {
                if let Some(key) = self.interfaces[iface].network_iapr.take() {
                    self.interfaces[iface].network_iapr_dirty = false;
                    if let Some(aged) = self.lsdb.premature_age(&key) {
                        self.flood_own(&aged, now, out);
                        self.table_dirty = true;
                    }
                }
            }
        }
    }

    /// Originate (or flush) the router-referenced IAPR.
    fn originate_router_iapr(&mut self, now: u64, out: &mut Vec<WireOutV3>) {
        // The same keep-dirty-on-rejection rule as the DR duties.
        match self.build_router_iapr() {
            Some(lsa) => {
                let key = lsa.key();
                if self.lsdb.originate(lsa, now).is_ok() {
                    self.iapr_key = Some(key);
                    self.iapr_dirty = false;
                    if let Some(stored) = self.lsdb.get(&key).map(|e| e.lsa.clone()) {
                        info!("ospfv3: router IAPR originated (§4.4.3.9)");
                        self.flood_own(&stored, now, out);
                        self.table_dirty = true;
                    }
                }
            }
            None => {
                if let Some(key) = self.iapr_key.take() {
                    self.iapr_dirty = false;
                    if let Some(aged) = self.lsdb.premature_age(&key) {
                        self.flood_own(&aged, now, out);
                        self.table_dirty = true;
                    }
                }
            }
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
        match self.lsdb.originate(lsa, now) {
            Ok(outcome) => {
                self.router_lsa_dirty = false;
                let stored = self.lsdb.get(&key).map(|e| e.lsa.clone());
                if let Some(lsa) = stored {
                    self.flood_own(&lsa, now, out);
                }
                // §16.5 (the v2 seam's parity — daemon.rs marks the
                // area dirty on every landed own router-LSA): a landed
                // instance with changed contents is an area-topology
                // change. The MinLSInterval deferral makes this
                // load-bearing — adjacency FULL inside 5 s of the
                // startup origination is rejected here and retried
                // from tick, and THAT landing must rerun the §4.8
                // walk or the cached result keeps the pre-adjacency
                // graph forever (every later §16.4 external then
                // resolves its ASBR against an empty routers set).
                if matches!(outcome, InstallOutcome::Installed { changed: true }) {
                    self.mark_spf_dirty(now);
                }
            }
            Err(_) => {
                // MinLSInterval not elapsed — keep the dirty flag;
                // tick retries until the instance lands.
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

    /// §4.5.2: flood a self-originated LSA. Broadcast links: ONE
    /// multicast LSU — "to AllSPFRouters if the router is the DR or
    /// Backup, AllDRouters otherwise" (§13.3's v2 rule, v3's
    /// ff02::5/6 form) — queued for unicast retransmission per Full
    /// neighbor. p2p links: LSU unicast to every Full neighbor (the
    /// v2 p2p shape). Link-scope LSAs never leave their own link.
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
            if self.interfaces[idx].broadcast() && !ips.is_empty() {
                // §13.3's broadcast rule: DR/BDR flood on AllSPFRouters,
                // DR Others on AllDRouters (the DR/BDR relay).
                let to = if self.drouters_member(idx) {
                    WireToV3::Multicast
                } else {
                    WireToV3::AllDRouters
                };
                out.push(WireOutV3 {
                    iface: idx,
                    to,
                    packet,
                });
                continue;
            }
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
                self.mark_spf_dirty(now);
                self.maybe_spf(now);
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

    // ---- Route calculation (§4.8 over the cached §4.8.1 SPF) -------

    /// Decorate one §4.8.2 hop into a kernel nexthop: the SPF's
    /// link-local when the link-LSA provided it; else the adjacency's
    /// Hello source (§4.8.2's "next-hop address may be determined via
    /// the IPv6 source address in the neighbor's Hello packet"); the
    /// directly-connected form (no address, no via) is the interface
    /// alone.
    fn decorate_hop(&self, hop: &NextHopV3) -> Option<Nexthop> {
        match (hop.address, hop.via) {
            (Some(ll), _) => Some(Nexthop::Ipv6If(ll, hop.interface_id)),
            (None, Some(via)) => {
                // The Hello-source fallback: the adjacency on the
                // outgoing interface.
                let iface = self
                    .interfaces
                    .iter()
                    .find(|i| i.ifindex == hop.interface_id)?;
                let conv = iface.neighbors.get(&via)?;
                if conv.state() == NeighborState::Full {
                    Some(Nexthop::Ipv6If(conv.ip, hop.interface_id))
                } else {
                    None
                }
            }
            (None, None) => Some(Nexthop::IfIndex(hop.interface_id)),
        }
    }

    fn hops_to_group(&self, hops: &[NextHopV3]) -> NexthopGroup {
        let mut group = NexthopGroup::new();
        for hop in hops {
            if let Some(nexthop) = self.decorate_hop(hop) {
                group.add(nexthop, 1);
            }
        }
        group
    }

    /// The route-table walk over the cached SPF result: the §4.8.1
    /// stage-two prefix routes (IAPR) plus the §4.8.5 external
    /// calculation (the §16.4 shape: the ASBR distance from the SPF's
    /// router entries, the F-bit forwarding-address resolution, type-1
    /// = X + Y / type-2 = Y). The §16.4-lite direct-ASBR form (S7-a's
    /// interim) is gone — a multi-hop ASBR resolves through the tree.
    fn recompute_table(&mut self, now: u64) {
        let Some(spf) = self.last_spf.clone() else {
            return;
        };
        let mut want: BTreeMap<String, RouteEntry> = BTreeMap::new();
        // ---- the intra-area prefix routes (4.8.1 stage two) ----
        for route in &spf.routes {
            let group = self.hops_to_group(&route.next_hops);
            if group.is_empty() {
                continue;
            }
            let entry = RouteEntry::new(
                IpPrefix::V6(route.prefix),
                RouteProtocol::Ospf,
                group,
                route.cost,
            );
            want.insert(route.prefix.to_string(), entry);
        }
        // ---- the external routes (4.8.5 = 16.4) ----
        let trace = std::env::var_os("ROUSTER_OSPFV3_TRACE").is_some();
        for entry in self.lsdb.all() {
            if entry.lsa.header.ls_type != V3_AS_EXTERNAL || entry.lsa.header.is_max_age() {
                continue;
            }
            // §16.4 (1)/(2): MaxAge above; self-originated skipped.
            if entry.lsa.header.adv_router == self.router_id {
                continue;
            }
            let LsaBodyV3::AsExternal(body) = &entry.lsa.body else {
                continue;
            };
            if body.metric >= crate::LS_INFINITY {
                if trace {
                    info!(
                        adv = %entry.lsa.header.adv_router,
                        metric = body.metric,
                        "ospfv3: external skipped: metric infinity"
                    );
                }
                continue; // §16.4 step (5): unreachable
            }
            // (3) the ASBR distance from the SPF's router entries.
            // §4.8.5: "AS Boundary Router and forwarding address
            // selection will proceed the same as if RFC1583Compatibility
            // is disabled" — single-area v1, so the plain least-cost
            // pick is exact here.
            let Some(asbr) = spf
                .routers
                .iter()
                .find(|r| r.router == entry.lsa.header.adv_router)
            else {
                if trace {
                    info!(
                        adv = %entry.lsa.header.adv_router,
                        routers = ?spf.routers.iter().map(|r| r.router).collect::<Vec<_>>(),
                        "ospfv3: external skipped: ASBR not in SPF routers"
                    );
                }
                continue; // ASBR unreachable
            };
            // (3b) the forwarding address: the F bit (4.8.5's rule —
            // "A forwarding address is in use if and only if bit F is
            // set"), resolved by a longest-prefix match in the intra
            // table.
            let (x, hops) = if let Some(fa) = body.forwarding_address {
                let fa_path = spf
                    .routes
                    .iter()
                    .filter(|r| r.prefix.prefix_len() > 0 && r.prefix.contains(fa))
                    .max_by_key(|r| r.prefix.prefix_len());
                let Some(fa_path) = fa_path else {
                    if trace {
                        info!(fa = %fa, "ospfv3: external skipped: FA without intra path");
                    }
                    continue; // FA must have an intra-area path
                };
                (fa_path.cost, fa_path.next_hops.clone())
            } else {
                (asbr.cost, asbr.next_hops.clone())
            };
            // (4)/(5): X (the intra-AS distance) + Y (the LSA metric).
            let cost = if body.e_bit {
                body.metric.min(crate::LS_INFINITY)
            } else {
                x.saturating_add(body.metric)
            };
            let prefix = match ipv6_prefix_of(&body.prefix) {
                Some(p) => p,
                None => continue,
            };
            if body.prefix.options.nu_bit() {
                continue; // 4.8.5: NU prefixes are ignored
            }
            let group = self.hops_to_group(&hops);
            if group.is_empty() {
                if trace {
                    info!(
                        adv = %entry.lsa.header.adv_router,
                        hops = ?hops,
                        "ospfv3: external skipped: no decorated nexthop"
                    );
                }
                continue;
            }
            let route = RouteEntry::new(IpPrefix::V6(prefix), RouteProtocol::Ospf, group, cost);
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
        // §9.3's WaitTimer (broadcast): the deferral before the first
        // election ends — fire it once and elect.
        for idx in 0..self.interfaces.len() {
            if self.interfaces[idx].wait_deadline.is_some_and(|d| now >= d) {
                self.interfaces[idx].wait_deadline = None;
                let (_, actions) = self.interfaces[idx]
                    .fsm
                    .fire(crate::iface::InterfaceEvent::WaitTimer);
                if actions.contains(&crate::iface::InterfaceAction::ElectDr) {
                    self.run_election_v3(idx, now, out);
                }
            }
        }
        // Conversation ticks.
        for idx in 0..self.interfaces.len() {
            let area = std::mem::take(&mut self.lsdb);
            let link = std::mem::take(&mut self.interfaces[idx].link_lsdb);
            let iface = &mut self.interfaces[idx];
            let mut reports = Vec::new();
            let mut dead: Vec<RouterId> = Vec::new();
            for (rid, conv) in iface.neighbors.iter_mut() {
                let (sends, report) = conv.tick(now);
                if report.adjacency_down {
                    dead.push(*rid);
                }
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
            if !dead.is_empty() && self.interfaces[idx].broadcast() {
                // §9.2's NeighborChange (a neighbor left the
                // bidirectional set): drop its claims and re-elect.
                for rid in dead {
                    self.interfaces[idx].claims.remove(&rid);
                }
                self.run_election_v3(idx, now, out);
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
        // §4.4.3.3/§4.4.3.9: the DR duties and the router IAPR.
        for idx in 0..self.interfaces.len() {
            if self.interfaces[idx].network_lsa_dirty || self.interfaces[idx].network_iapr_dirty {
                self.originate_network_duties(idx, now, out);
            }
        }
        if self.iapr_dirty {
            self.originate_router_iapr(now, out);
        }
        // The §4.8 walk gate (topology-due recompute / table-only
        // rerun on the cached result).
        self.maybe_spf(now);
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

/// The inverse: an LSA prefix triple back to a route prefix (the
/// spf_v3 helper, shared).
use crate::spf_v3::ipv6_prefix_of;

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
    // §A.1: the AllDRouters (ff02::6) membership follows the §9.4
    // role — joined while DR/BDR, left otherwise. Reconciled after
    // every core batch (the core's wanted state vs the sockets').
    let mut drouters_joined: Vec<bool> = vec![false; sockets.len()];
    reconcile_drouters(&sockets, &core, &mut drouters_joined);

    loop {
        tokio::select! {
            inbound = rx.recv() => {
                let Some((idx, received, dst, hop)) = inbound else { break };
                let now = start.elapsed().as_secs();
                let out = core.on_packet(idx, &received, dst, hop, now);
                flush_wire_v3(&sockets, &core, out).await;
                reconcile_drouters(&sockets, &core, &mut drouters_joined);
            }
            _ = tick_interval.tick() => {
                let now = start.elapsed().as_secs();
                let mut out = Vec::new();
                core.tick(now, &mut out);
                flush_wire_v3(&sockets, &core, out).await;
                reconcile_drouters(&sockets, &core, &mut drouters_joined);
            }
            route = pushed.recv() => {
                if let Some(route) = route {
                    let now = start.elapsed().as_secs();
                    let mut out = Vec::new();
                    core.on_redistribute_add(&route, now, &mut out);
                    flush_wire_v3(&sockets, &core, out).await;
                    reconcile_drouters(&sockets, &core, &mut drouters_joined);
                }
            }
            route = withdrawn.recv() => {
                if let Some(route) = route {
                    let now = start.elapsed().as_secs();
                    let mut out = Vec::new();
                    core.on_redistribute_del(&route, now, &mut out);
                    flush_wire_v3(&sockets, &core, out).await;
                    reconcile_drouters(&sockets, &core, &mut drouters_joined);
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

/// §A.1's ff02::6 membership reconcile: join when the core wants the
/// DR/BDR role's AllDRouters feed, leave when it does not.
fn reconcile_drouters(sockets: &[Arc<OspfV6RawSocket>], core: &OspfdV3, joined: &mut [bool]) {
    for (idx, sock) in sockets.iter().enumerate() {
        let want = core.drouters_member(idx);
        if want && !joined[idx] {
            if sock.join_all_drouters().is_ok() {
                joined[idx] = true;
                info!(
                    iface = %core.interfaces[idx].name,
                    "ospfv3: joined AllDRouters (ff02::6, DR/BDR role)"
                );
            }
        } else if !want && joined[idx] && sock.leave_all_drouters().is_ok() {
            joined[idx] = false;
        }
    }
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

    /// S10-e regression (the interop REDIST-IN flake): the
    /// MinLSInterval-deferred own router-LSA re-origination must
    /// re-dirty the SPF when it lands from the tick retry. The field
    /// shape: adjacency FULL arrives <5 s after the t=0 startup
    /// origination, so the with-link instance is rejected here and
    /// retried later; the peer's exchange-time router-LSA already
    /// carried the back-link, and the peer sends NO post-Full refresh
    /// (the FRR runs that fail). Without the landing-side re-dirty the
    /// cached SPF keeps the pre-adjacency graph (routers=[]) forever
    /// and every §16.4 external resolves its ASBR against nothing —
    /// the "route installed" that never came.
    #[test]
    fn deferred_own_router_lsa_landing_reruns_spf_and_installs_external() {
        let ll_a: Ipv6Addr = "fe80::aa".parse().unwrap();
        let ll_b: Ipv6Addr = "fe80::bb".parse().unwrap();
        let mut a = core_v3(0x0a00_0001, ll_a, 11, 0);
        let mut b = core_v3(0x0a00_0002, ll_b, 22, 0);
        // Bring-up to Full WITHOUT run_to_full's settle drain: stop at
        // the first Full (inside MinLSInterval of the t=0 startup
        // origination), and never tick the peer again afterward — the
        // silent-peer shape that unmasks the deferral.
        let is_full = |c: &OspfdV3| {
            c.neighbor_states()
                .iter()
                .any(|(_, _, s)| *s == NeighborState::Full)
        };
        let mut now = 0;
        for _ in 0..10 {
            let mut out_a = Vec::new();
            let mut out_b = Vec::new();
            a.tick(now, &mut out_a);
            b.tick(now, &mut out_b);
            let mut queue: Vec<(bool, Vec<WireOutV3>)> = vec![(true, out_a), (false, out_b)];
            for _ in 0..128 {
                match queue.pop() {
                    Some((_, drained)) if drained.is_empty() => continue,
                    Some((to_b, drained)) => {
                        let replies = if to_b {
                            deliver(&mut a, &mut b, drained, now)
                        } else {
                            deliver(&mut b, &mut a, drained, now)
                        };
                        queue.push((!to_b, replies));
                    }
                    None => break,
                }
            }
            now += 1;
            assert!(now < 10, "no Full within 10 s");
            if is_full(&a) && is_full(&b) {
                break;
            }
        }
        assert!(now < 5, "Full inside MinLSInterval (was t={now})");
        assert!(
            a.router_lsa_dirty,
            "the with-link re-origination is deferred (MinLSInterval)"
        );
        // B's post-Full router-LSA lands straight in A's database (the
        // exchange-carried-with-link shape) and dirties the SPF — as
        // the LSU arrival did in the field.
        let b_rtr = LsaV3 {
            header: LsaHeaderV3 {
                ls_age: 1,
                ls_type: V3_ROUTER,
                link_state_id: LinkStateId(0),
                adv_router: RouterId(0x0a00_0002),
                seq: 0x8000_0002,
                checksum: 0,
                length: 0,
            },
            body: LsaBodyV3::Router(RouterLsaV3 {
                nt_bit: false,
                v_bit: false,
                e_bit: true,
                b_bit: false,
                options: our_options(),
                links: vec![RouterLinkV3 {
                    link_type: LinkTypeV3::PointToPoint,
                    metric: 1,
                    interface_id: 22,
                    neighbor_interface_id: 11,
                    neighbor_router_id: RouterId(0x0a00_0001),
                }],
            }),
        };
        a.lsdb.install(b_rtr, false, now);
        a.mark_spf_dirty(now);
        a.maybe_spf(now + 1);
        assert!(
            a.last_spf.as_ref().is_some_and(|s| s.routers.is_empty()),
            "the cached SPF is still the pre-adjacency graph (A's own \
             router-LSA has no links yet)"
        );
        // The deferred instance lands at t=5 (tick retry). From there
        // the SPF must rerun within a bounded wait — the landing itself
        // re-dirties it.
        let mut healed = false;
        for t in 5..12u64 {
            let mut out = Vec::new();
            a.tick(t, &mut out);
            if a.last_spf.as_ref().is_some_and(|s| !s.routers.is_empty()) {
                assert_eq!(
                    a.last_spf.as_ref().unwrap().routers[0].router,
                    RouterId(0x0a00_0002),
                    "the peer became reachable once our own link landed"
                );
                healed = true;
                break;
            }
        }
        assert!(healed, "the landed router-LSA never reran the SPF");
        // The §16.4 leg: B's external arrives (table-only class) and
        // now resolves its ASBR through the healthy cached SPF.
        let ext = LsaV3 {
            header: LsaHeaderV3 {
                ls_age: 1,
                ls_type: V3_AS_EXTERNAL,
                link_state_id: LinkStateId(0),
                adv_router: RouterId(0x0a00_0002),
                seq: 0x8000_0001,
                checksum: 0,
                length: 0,
            },
            body: LsaBodyV3::AsExternal(AsExternalLsaV3 {
                e_bit: true,
                f_bit: false,
                t_bit: false,
                metric: 20,
                prefix: Prefix {
                    len: 64,
                    options: Default::default(),
                    addr: prefix_bytes(&"2001:db8:88::/64".parse().unwrap()),
                },
                referenced_ls_type: 0,
                forwarding_address: None,
                external_route_tag: None,
                referenced_link_state_id: None,
            }),
        };
        a.lsdb.install(ext, false, 12);
        a.table_dirty = true;
        a.maybe_spf(12);
        let routes = a.installed_routes();
        assert_eq!(routes.len(), 1, "the external installed: {:?}", routes);
        assert_eq!(
            routes[0].prefix,
            IpPrefix::V6("2001:db8:88::/64".parse().unwrap())
        );
        assert_eq!(routes[0].metric, 20, "type-2 metric as-is");
        match routes[0].nexthops.hops()[0].0 {
            Nexthop::Ipv6If(gw, ifindex) => {
                assert_eq!(gw, ll_b, "gateway is B's link-local (2.5)");
                assert_eq!(ifindex, 11, "A's interface");
            }
            other => panic!("wrong nexthop shape: {other:?}"),
        }
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

    // ---- the full §4.8 walk (S10-b M1) ------------------------------

    /// A two-interface chain core: eth0/eth1 p2p with pinned ifindexes.
    fn chain_core(rid: u32, ll0: Ipv6Addr, if0: u32, ll1: Ipv6Addr, if1: u32) -> OspfdV3 {
        let rid_s = RouterId(rid).to_ipv4().to_string();
        let text = format!(
            "router ospf\n address-family ipv6-unicast\n router-id {rid_s}\n area 0.0.0.0\n  \
             interface eth0\n   link-local {ll0}\n   ifindex {if0}\n   network-type \
             point-to-point\n   hello-interval 2\n   dead-interval 8\n  interface eth1\n   \
             link-local {ll1}\n   ifindex {if1}\n   network-type point-to-point\n   \
             hello-interval 2\n   dead-interval 8\n"
        );
        OspfdV3::new(&parse_config(&text).unwrap()).unwrap()
    }

    /// The chain mesh pump: wires from (core, iface) deliver to the
    /// wired peer's matching interface. `links` maps (core, iface) ->
    /// (peer core, peer iface).
    fn pump_chain(
        cores: &mut [OspfdV3],
        links: &HashMap<(usize, usize), (usize, usize)>,
        out: (usize, Vec<WireOutV3>),
        now: u64,
    ) -> Vec<((usize, usize), Vec<WireOutV3>)> {
        let (from, wires) = out;
        let mut replies = Vec::new();
        for wire in wires {
            let Some((to, to_iface)) = links.get(&(from, wire.iface)).copied() else {
                continue;
            };
            let src_ll = cores[from].interfaces[wire.iface].link_local;
            let bytes = wire.packet.encode(src_ll, wire.to.addr());
            let received = ReceivedV6 {
                src: src_ll,
                payload: bytes,
            };
            let back = cores[to].on_packet(to_iface, &received, wire.to.addr(), None, now);
            if !back.is_empty() {
                replies.push(((to, to_iface), back));
            }
        }
        replies
    }

    /// Run the chain until every wired pair reaches Full, then settle
    /// (the run_to_full discipline, three-core form).
    fn chain_to_full(
        cores: &mut [OspfdV3],
        links: &HashMap<(usize, usize), (usize, usize)>,
        mut now: u64,
    ) -> u64 {
        let all_full = |cores: &[OspfdV3]| {
            cores.iter().all(|c| {
                let n_full = c
                    .neighbor_states()
                    .iter()
                    .filter(|(_, _, s)| *s == NeighborState::Full)
                    .count();
                let wired = c.interfaces.len();
                n_full >= wired
            })
        };
        for _ in 0..40 {
            let mut queue: Vec<(usize, Vec<WireOutV3>)> = Vec::new();
            for (i, core) in cores.iter_mut().enumerate() {
                let mut out = Vec::new();
                core.tick(now, &mut out);
                if !out.is_empty() {
                    queue.push((i, out));
                }
            }
            for _ in 0..256 {
                match queue.pop() {
                    Some((_, drained)) if drained.is_empty() => continue,
                    Some((from, drained)) => {
                        for ((to, _), back) in pump_chain(cores, links, (from, drained), now) {
                            queue.push((to, back));
                        }
                    }
                    None => break,
                }
            }
            if all_full(cores) {
                // Settle: re-originations land (MinLSInterval).
                for _ in 0..10 {
                    now += 1;
                    let mut queue: Vec<(usize, Vec<WireOutV3>)> = Vec::new();
                    for (i, core) in cores.iter_mut().enumerate() {
                        let mut out = Vec::new();
                        core.tick(now, &mut out);
                        if !out.is_empty() {
                            queue.push((i, out));
                        }
                    }
                    for _ in 0..256 {
                        match queue.pop() {
                            Some((_, drained)) if drained.is_empty() => continue,
                            Some((from, drained)) => {
                                for ((to, _), back) in
                                    pump_chain(cores, links, (from, drained), now)
                                {
                                    queue.push((to, back));
                                }
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
    fn spf_resolves_a_multihop_asbr_through_the_tree() {
        // A -- B -- C (two p2p links). C redistributes a v6 static.
        // A's §4.8.5 calculation must resolve the ASBR C THROUGH the
        // tree (cost 2 hops) and forward via B's link-local — the
        // §16.4-lite direct-ASBR form could not do this.
        let ll_a: Ipv6Addr = "fe80::1".parse().unwrap();
        let ll_b0: Ipv6Addr = "fe80::2".parse().unwrap();
        let ll_b1: Ipv6Addr = "fe80::3".parse().unwrap();
        let ll_c: Ipv6Addr = "fe80::4".parse().unwrap();
        let mut cores = [
            chain_core(0x0a00_0001, ll_a, 11, ll_a, 99), // A: iface 11 (99 unwired)
            chain_core(0x0a00_0002, ll_b0, 22, ll_b1, 33), // B: 22 to A, 33 to C
            chain_core(0x0a00_0003, ll_c, 44, ll_c, 99), // C: iface 44
        ];
        // A.eth0 - B.eth0; B.eth1 - C.eth0.
        let links: HashMap<(usize, usize), (usize, usize)> = HashMap::from([
            ((0, 0), (1, 0)),
            ((1, 0), (0, 0)),
            ((1, 1), (2, 0)),
            ((2, 0), (1, 1)),
        ]);
        chain_to_full(&mut cores, &links, 0);
        for (i, core) in cores.iter().enumerate() {
            let states: Vec<NeighborState> = core
                .neighbor_states()
                .into_iter()
                .map(|(_, _, s)| s)
                .collect();
            assert!(
                states.contains(&NeighborState::Full),
                "core {i} reached Full (states: {states:?})"
            );
        }
        // C redistributes.
        let prefix: Ipv6Prefix = "2001:db8:99::/64".parse().unwrap();
        let route = RedistributedRoute {
            prefix: IpPrefix::V6(prefix),
            metric: 5,
        };
        let mut out = Vec::new();
        cores[2].on_redistribute_add(&route, 100, &mut out);
        let mut queue = vec![((2usize, 0usize), out)];
        for _ in 0..64 {
            match queue.pop() {
                Some((_, drained)) if drained.is_empty() => continue,
                Some(((from, _), drained)) => {
                    // Re-pump with the chain helper shape.
                    for ((to, _), back) in pump_chain(&mut cores, &links, (from, drained), 100) {
                        queue.push(((to, 0), back));
                    }
                }
                None => break,
            }
        }
        // A installs the external via B's link-local (the SPF's
        // inherited first hop), NOT C's.
        let routes = cores[0].installed_routes();
        let entry = routes
            .iter()
            .find(|r| r.prefix == IpPrefix::V6(prefix))
            .unwrap_or_else(|| panic!("A installs the multihop external: {routes:?}"));
        assert_eq!(entry.metric, 5, "type-2 metric as-is (16.4 (4))");
        match entry.nexthops.hops()[0].0 {
            Nexthop::Ipv6If(gw, ifindex) => {
                assert_eq!(
                    gw, ll_b0,
                    "the gateway is B's link-local (the inherited hop)"
                );
                assert_eq!(ifindex, 11, "A's own interface");
            }
            other => panic!("wrong nexthop shape: {other:?}"),
        }
    }

    #[test]
    fn iapr_prefix_routes_install_with_spf_next_hops() {
        // After A-B Full, inject into A's LSDB an intra-area-prefix-LSA
        // referencing B's router-LSA (what B would originate): A's
        // stage-two walk installs the prefix via B's link-local at
        // dist(B) + metric (4.8.1's second stage / 4.8.2's hops).
        let ll_a: Ipv6Addr = "fe80::aa".parse().unwrap();
        let ll_b: Ipv6Addr = "fe80::bb".parse().unwrap();
        let mut a = core_v3(0x0a00_0001, ll_a, 11, 0);
        let mut b = core_v3(0x0a00_0002, ll_b, 22, 0);
        run_to_full(&mut a, &mut b, 0, 30);
        let prefix: Ipv6Prefix = "2001:db8:42::/64".parse().unwrap();
        let lsa = LsaV3 {
            header: LsaHeaderV3 {
                ls_age: 1,
                ls_type: LsaType::V3_INTRA_AREA_PREFIX,
                link_state_id: LinkStateId(0),
                adv_router: RouterId(0x0a00_0002),
                seq: 0x8000_0001,
                checksum: 0x9999,
                length: 0,
            },
            body: LsaBodyV3::IntraAreaPrefix(crate::lsa_v3::IntraAreaPrefixLsaV3 {
                prefixes: vec![crate::lsa_v3::PrefixMetric {
                    metric: 3,
                    prefix: crate::lsa_v3::Prefix {
                        len: 64,
                        options: Default::default(),
                        addr: prefix.addr().octets()[..8].to_vec(),
                    },
                }],
                referenced_ls_type: V3_ROUTER,
                referenced_link_state_id: LinkStateId(0),
                referenced_adv_router: RouterId(0x0a00_0002),
            }),
        };
        let _ = a.lsdb.install(lsa, true, 40);
        a.mark_spf_dirty(40);
        a.maybe_spf(40);
        let routes = a.installed_routes();
        let entry = routes
            .iter()
            .find(|r| r.prefix == IpPrefix::V6(prefix))
            .unwrap_or_else(|| panic!("the IAPR prefix installs: {routes:?}"));
        assert_eq!(entry.metric, 13, "dist(B)=10 + prefix metric 3");
        match entry.nexthops.hops()[0].0 {
            Nexthop::Ipv6If(gw, ifindex) => {
                assert_eq!(gw, ll_b, "B's link-local (4.8.2)");
                assert_eq!(ifindex, 11, "A's interface");
            }
            other => panic!("wrong nexthop shape: {other:?}"),
        }
    }

    // ---- the broadcast arm + the IAPRs (S10-b M2) -------------------

    fn bcast_core(rid: u32, ll: Ipv6Addr, ifindex: u32, priority: u8, prefix: &str) -> OspfdV3 {
        let rid_s = RouterId(rid).to_ipv4().to_string();
        let text = format!(
            "router ospf\n address-family ipv6-unicast\n router-id {rid_s}\n area 0.0.0.0\n  \
             interface eth0\n   link-local {ll}\n   ifindex {ifindex}\n   priority {priority}\n   \
             network-type broadcast\n   hello-interval 2\n   dead-interval 8\n   prefix {prefix}\n"
        );
        OspfdV3::new(&parse_config(&text).unwrap()).unwrap()
    }

    /// The broadcast pump: multicast wires reach EVERY other core on
    /// the shared link; unicast wires only the addressed peer.
    fn bcast_pump(
        cores: &mut [OspfdV3],
        from: usize,
        out: Vec<WireOutV3>,
        now: u64,
    ) -> Vec<(usize, Vec<WireOutV3>)> {
        let mut replies = Vec::new();
        for wire in out {
            let src_ll = cores[from].interfaces[0].link_local;
            let bytes = wire.packet.encode(src_ll, wire.to.addr());
            let received = ReceivedV6 {
                src: src_ll,
                payload: bytes,
            };
            for (to, core) in cores.iter_mut().enumerate() {
                if to == from {
                    continue;
                }
                let dst = wire.to.addr();
                let unicast_ours =
                    matches!(wire.to, WireToV3::Unicast(ip) if ip == core.interfaces[0].link_local);
                if matches!(wire.to, WireToV3::Unicast(_)) && !unicast_ours {
                    continue;
                }
                let back = core.on_packet(0, &received, dst, None, now);
                if !back.is_empty() {
                    replies.push((to, back));
                }
            }
        }
        replies
    }

    /// Run the broadcast mesh to a quiescent state (election held,
    /// all DR/BDR adjacencies Full, LSDBs converged).
    fn bcast_mesh_run(cores: &mut [OspfdV3], mut now: u64, rounds: usize) -> u64 {
        for _ in 0..rounds {
            let mut queue: Vec<(usize, Vec<WireOutV3>)> = Vec::new();
            for (i, core) in cores.iter_mut().enumerate() {
                let mut out = Vec::new();
                core.tick(now, &mut out);
                if !out.is_empty() {
                    queue.push((i, out));
                }
            }
            // The v2 run_mesh wave discipline: drain the whole queue
            // per generation (FIFO), so no stale obligation is
            // processed after the replies it provoked.
            for _ in 0..64 {
                if queue.is_empty() {
                    break;
                }
                let batch = std::mem::take(&mut queue);
                for (from, drained) in batch {
                    for (to, back) in bcast_pump(cores, from, drained, now) {
                        queue.push((to, back));
                    }
                }
            }
            now += 1;
        }
        now
    }

    #[test]
    fn broadcast_elects_originate_network_lsa_and_iapr_and_route() {
        // Three routers on one broadcast link: R1 (pri 3) DR, R2
        // (pri 2) BDR, R3 (pri 1) DR Other — the §10.4 matrix holds
        // (all pairs adjacent through DR/BDR), the DR originates the
        // network-LSA (all three attached, LS ID = its Interface ID)
        // and the network-referenced IAPR (every attached router's
        // link-LSA prefixes at metric 0), and the DROther's SPF
        // installs the other routers' prefixes as directly connected
        // (4.8.2's no-address hop).
        let ll1: Ipv6Addr = "fe80::1".parse().unwrap();
        let ll2: Ipv6Addr = "fe80::2".parse().unwrap();
        let ll3: Ipv6Addr = "fe80::3".parse().unwrap();
        let rid1 = RouterId(0x0a00_0001);
        let rid2 = RouterId(0x0a00_0002);
        let rid3 = RouterId(0x0a00_0003);
        let mut cores = [
            bcast_core(0x0a00_0001, ll1, 11, 3, "2001:db8:1::/64"),
            bcast_core(0x0a00_0002, ll2, 22, 2, "2001:db8:2::/64"),
            bcast_core(0x0a00_0003, ll3, 33, 1, "2001:db8:3::/64"),
        ];
        bcast_mesh_run(&mut cores, 0, 40);
        // The election: all agree on R1 DR / R2 BDR.
        for (i, core) in cores.iter().enumerate() {
            assert_eq!(
                core.interfaces[0].dr, rid1,
                "core {i}: R1 is DR (highest priority)"
            );
            assert_eq!(core.interfaces[0].bdr, rid2, "core {i}: R2 is BDR");
        }
        // §10.4's matrix: R1 Full with both; R2 Full with R1 and R3;
        // R3 Full with R1 and R2 (DROther pairs with DR AND BDR).
        let full_with = |core: &OspfdV3, peer: RouterId| {
            core.interfaces[0]
                .neighbors
                .get(&peer)
                .is_some_and(|c| c.state() == NeighborState::Full)
        };
        assert!(full_with(&cores[0], rid2) && full_with(&cores[0], rid3));
        assert!(full_with(&cores[1], rid1) && full_with(&cores[1], rid3));
        assert!(full_with(&cores[2], rid1) && full_with(&cores[2], rid2));
        // The DR's network-LSA (LS ID = R1's Interface ID 11, adv R1)
        // lists all three attached routers — in EVERY core's LSDB.
        for (i, core) in cores.iter().enumerate() {
            let key = LsaKey {
                ls_type: LsaType::V3_NETWORK,
                link_state_id: LinkStateId(11),
                adv_router: rid1,
            };
            let entry = core
                .lsdb
                .get(&key)
                .unwrap_or_else(|| panic!("core {i} holds the network-LSA"));
            let LsaBodyV3::Network(body) = &entry.lsa.body else {
                panic!("network body");
            };
            let mut attached = body.attached.clone();
            attached.sort();
            assert_eq!(attached, vec![rid1, rid2, rid3], "all three attached");
        }
        // The DROther's router-LSA: ONE type-2 link keyed by the DR
        // pair (11, R1).
        let r3_router = cores[2]
            .lsdb
            .get(&LsaKey {
                ls_type: V3_ROUTER,
                link_state_id: LinkStateId(0),
                adv_router: rid3,
            })
            .map(|e| e.lsa.clone())
            .expect("R3's own router-LSA");
        let LsaBodyV3::Router(body) = r3_router.body else {
            panic!("router body");
        };
        assert_eq!(body.links.len(), 1, "one transit link");
        assert_eq!(body.links[0].link_type, LinkTypeV3::Transit);
        assert_eq!(body.links[0].interface_id, 33, "R3's Interface ID");
        assert_eq!(body.links[0].neighbor_interface_id, 11, "the DR's");
        assert_eq!(body.links[0].neighbor_router_id, rid1);
        // The DR's network-referenced IAPR: all three prefixes at
        // metric 0, referenced (0x2002, 11, R1) — and it ROUTES: R3
        // installs R2's prefix as directly connected (the root sits
        // on the referenced transit link).
        let iapr_key = LsaKey {
            ls_type: LsaType::V3_INTRA_AREA_PREFIX,
            link_state_id: LinkStateId(1),
            adv_router: rid1,
        };
        let iapr = cores[2]
            .lsdb
            .get(&iapr_key)
            .map(|e| e.lsa.clone())
            .expect("the DR's network IAPR in R3's LSDB");
        let LsaBodyV3::IntraAreaPrefix(body) = &iapr.body else {
            panic!("iapr body");
        };
        assert_eq!(
            body.referenced_ls_type,
            LsaType::V3_NETWORK,
            "network-referenced"
        );
        assert_eq!(body.referenced_link_state_id, LinkStateId(11));
        assert_eq!(body.referenced_adv_router, rid1);
        let mut prefixes: Vec<String> = body
            .prefixes
            .iter()
            .filter_map(|pm| ipv6_prefix_of(&pm.prefix).map(|p| p.to_string()))
            .collect();
        prefixes.sort();
        assert_eq!(
            prefixes,
            vec![
                "2001:db8:1::/64".to_string(),
                "2001:db8:2::/64".to_string(),
                "2001:db8:3::/64".to_string()
            ],
            "every attached router's link-LSA prefixes, metric 0"
        );
        assert!(body.prefixes.iter().all(|pm| pm.metric == 0));
        // R3's table: R2's prefix reachable through the network at
        // R3's link cost (10) — the directly-connected no-address hop.
        let want: Ipv6Prefix = "2001:db8:2::/64".parse().unwrap();
        let routes: Vec<RouteEntry> = cores[2].installed_routes().into_iter().cloned().collect();
        let entry = routes
            .iter()
            .find(|r| r.prefix == IpPrefix::V6(want))
            .unwrap_or_else(|| panic!("R3 routes R2's prefix: {routes:?}"));
        assert_eq!(entry.metric, 10, "link cost + metric 0");
        match entry.nexthops.hops()[0].0 {
            Nexthop::IfIndex(ifindex) => assert_eq!(ifindex, 33, "solely the outgoing link"),
            other => panic!("wrong nexthop shape: {other:?}"),
        }
    }

    #[test]
    fn ff02_6_receive_gate_is_dr_bdr_only() {
        // §4.2: an AllDRouters-destined LSU is processed by the DR/BDR
        // only — the DROther drops it (no install, no ack).
        let ll1: Ipv6Addr = "fe80::1".parse().unwrap();
        let ll2: Ipv6Addr = "fe80::2".parse().unwrap();
        let ll3: Ipv6Addr = "fe80::3".parse().unwrap();
        let mut cores = [
            bcast_core(0x0a00_0001, ll1, 11, 3, "2001:db8:1::/64"),
            bcast_core(0x0a00_0002, ll2, 22, 2, "2001:db8:2::/64"),
            bcast_core(0x0a00_0003, ll3, 33, 1, "2001:db8:3::/64"),
        ];
        bcast_mesh_run(&mut cores, 0, 40);
        // An external originated on R2 floods; capture R2's LSU wire.
        let route = RedistributedRoute {
            prefix: IpPrefix::V6("2001:db8:99::/64".parse().unwrap()),
            metric: 5,
        };
        let mut out = Vec::new();
        cores[1].on_redistribute_add(&route, 100, &mut out);
        let lsu_wire = out
            .iter()
            .find(|w| matches!(w.packet.body, PacketBodyV3::LsUpdate(_)))
            .expect("an LSU obligation")
            .clone();
        let ext_key = LsaKey {
            ls_type: V3_AS_EXTERNAL,
            link_state_id: LinkStateId(0),
            adv_router: RouterId(0x0a00_0002),
        };
        // Re-encode the same LSU for the ff02::6 destination (the
        // pseudo-header checksum covers dst; encode() recomputes it).
        let src_ll = cores[1].interfaces[0].link_local;
        let bytes = lsu_wire
            .packet
            .encode(src_ll, crate::transport::ALL_D_ROUTERS_V6);
        let received = ReceivedV6 {
            src: src_ll,
            payload: bytes,
        };
        // The DROther (R3) drops it.
        let back = cores[2].on_packet(0, &received, crate::transport::ALL_D_ROUTERS_V6, None, 100);
        assert!(back.is_empty(), "no ack from the DROther");
        assert!(
            !cores[2].lsdb.contains(&ext_key),
            "the DROther did not process the AllDRouters LSU"
        );
        // The DR (R1) processes it (installs + acks).
        let back = cores[0].on_packet(0, &received, crate::transport::ALL_D_ROUTERS_V6, None, 100);
        assert!(
            cores[0].lsdb.contains(&ext_key),
            "the DR installed the AllDRouters LSU"
        );
        assert!(
            back.iter()
                .any(|w| matches!(w.packet.body, PacketBodyV3::LsAck(_))),
            "the DR acknowledged"
        );
    }

    #[test]
    fn p2p_prefixes_advertise_via_the_router_iapr() {
        // §4.4.3.9 part 2: p2p configured prefixes ride the
        // router-referenced IAPR (0x2001) at the interface output
        // cost — "the list of global prefixes configured in RTX for
        // the link are copied ... The Metric field for each of these
        // prefixes is set to the interface's output cost."
        let ll_a: Ipv6Addr = "fe80::aa".parse().unwrap();
        let ll_b: Ipv6Addr = "fe80::bb".parse().unwrap();
        let mut cores = [
            bcast_core(0x0a00_0001, ll_a, 11, 1, "2001:db8:a::/64"),
            bcast_core(0x0a00_0002, ll_b, 22, 1, "2001:db8:b::/64"),
        ];
        // Reconfigure to p2p (the helper's shape is broadcast; p2p is
        // the default v3 lab shape).
        for core in cores.iter_mut() {
            core.interfaces[0].cfg.network_type = NetworkType::PointToPoint;
        }
        // The helper already constructed broadcast FSMs; rebuild the
        // FSMs the p2p way (InterfaceUp lands directly in
        // PointToPoint).
        for core in cores.iter_mut() {
            core.interfaces[0].fsm = crate::iface::InterfaceFsm::new_with_priority(true, 1);
            let _ = core.interfaces[0]
                .fsm
                .fire(crate::iface::InterfaceEvent::InterfaceUp);
            core.interfaces[0].wait_deadline = None;
        }
        let mut now = bcast_mesh_run(&mut cores, 0, 40);
        // Both Full.
        for (i, core) in cores.iter().enumerate() {
            assert!(
                core.neighbor_states()
                    .iter()
                    .any(|(_, _, s)| *s == NeighborState::Full),
                "core {i} Full"
            );
        }
        // A's router IAPR: referenced (0x2001, 0, A), prefix at
        // metric = the interface cost (10), in B's LSDB.
        let key = LsaKey {
            ls_type: LsaType::V3_INTRA_AREA_PREFIX,
            link_state_id: LinkStateId(0),
            adv_router: RouterId(0x0a00_0001),
        };
        let iapr = cores[1]
            .lsdb
            .get(&key)
            .map(|e| e.lsa.clone())
            .expect("A's router IAPR in B's LSDB");
        let LsaBodyV3::IntraAreaPrefix(body) = &iapr.body else {
            panic!("iapr body");
        };
        assert_eq!(body.referenced_ls_type, V3_ROUTER);
        assert_eq!(body.referenced_link_state_id, LinkStateId(0));
        assert_eq!(body.referenced_adv_router, RouterId(0x0a00_0001));
        assert_eq!(body.prefixes.len(), 1);
        assert_eq!(
            ipv6_prefix_of(&body.prefixes[0].prefix)
                .unwrap()
                .to_string(),
            "2001:db8:a::/64"
        );
        assert_eq!(body.prefixes[0].metric, 10, "the interface output cost");
        // B installs A's prefix at 10 (to A) + 10 (A's cost) via A's
        // link-local.
        let want: Ipv6Prefix = "2001:db8:a::/64".parse().unwrap();
        let routes: Vec<RouteEntry> = cores[1].installed_routes().into_iter().cloned().collect();
        let entry = routes
            .iter()
            .find(|r| r.prefix == IpPrefix::V6(want))
            .unwrap_or_else(|| panic!("B routes A's prefix: {routes:?}"));
        assert_eq!(entry.metric, 20);
        match entry.nexthops.hops()[0].0 {
            Nexthop::Ipv6If(gw, ifindex) => {
                assert_eq!(gw, ll_a);
                assert_eq!(ifindex, 22, "B's interface");
            }
            other => panic!("wrong nexthop shape: {other:?}"),
        }
        let _ = &mut now;
    }
}
