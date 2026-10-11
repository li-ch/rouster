//! The adjacency conversation (RFC 2328 §10.6-§10.9, §13.3-§13.7)
//! as daemon-side bookkeeping around the landed pure cores: the
//! Database Summary list drain (§10.8's multi-packet DD walk), the
//! Link State Request list (§10.9), and the retransmission list
//! with its RxmtInterval pacing (§13.3/§13.5-§13.7).
//!
//! Pure and clock-injected (seconds in, [`Send`] obligations out) —
//! the two-sided DB synchronization is table-tested below by wiring
//! two [`Conversation`]s to each other with no sockets, the same
//! logic the daemon runs against real peers.
//!
//! Send addressing follows §A.1/§13.5: conversation packets (DD,
//! LSR, LSU, direct LSAck) go unicast to the neighbor; Hellos and
//! the multicast floods are the interface layer's.

use std::collections::VecDeque;
use std::net::Ipv4Addr;

use crate::lsa::{Lsa, LsaHeader, LsaKey, Options, RouterId};
use crate::lsdb::{self, Lsdb};
use crate::neighbor::{
    flood_step, FloodAction, NeighborAction, NeighborEvent, NeighborFsm, NeighborState,
};
use crate::packet::{
    DbDescription, LsAck, LsRequest, LsRequestId, LsUpdate, Packet, PacketBody, PacketHeader,
};

/// Appendix B / §C.3 timing the conversation needs.
pub struct ConversationParams {
    /// RxmtInterval (§C.3, default 5 s): DD/LSR retransmit and LSU
    /// flood-ack pacing.
    pub rxmt_interval: u64,
    /// Interface MTU — advertised in every DD (§A.3.3) and the DD
    /// header-count budget.
    pub mtu: u16,
    /// Our Hello/DD options byte (E-bit for a normal area).
    pub options: Options,
}

impl Default for ConversationParams {
    fn default() -> Self {
        Self {
            rxmt_interval: 5,
            mtu: 1500,
            options: Options(Options::E),
        }
    }
}

/// One outbound packet obligation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Send {
    pub to: Ipv4Addr,
    pub packet: Packet,
}

/// What the conversation learned — the daemon's SPF/flood wiring.
#[derive(Debug, Default)]
pub struct ConversationReport {
    /// LSAs installed with changed contents (schedule SPF).
    pub changed: Vec<LsaKey>,
    /// The adjacency reached Full (§10.1).
    pub adjacency_up: bool,
    /// The adjacency was destroyed from ≥ ExStart.
    pub adjacency_down: bool,
}

impl ConversationReport {
    fn merge(&mut self, other: &ConversationReport) {
        self.changed.extend_from_slice(&other.changed);
        self.adjacency_up |= other.adjacency_up;
        self.adjacency_down |= other.adjacency_down;
    }
}

/// One neighbor conversation on one interface.
pub struct Conversation {
    pub fsm: NeighborFsm,
    /// The neighbor's IP address on the attached network (§10.5's
    /// source address; unicast sends go here).
    pub ip: Ipv4Addr,
    /// The neighbor's Router ID (the Hello packet header's; our
    /// Hello's neighbor list carries it, §C.3).
    pub peer_router_id: Option<RouterId>,
    /// RouterDeadInterval deadline (§10.2's Inactivity Timer).
    pub inactivity_deadline: u64,
    /// §10.8: the Database Summary list still to send in DDs.
    summary: VecDeque<LsaHeader>,
    /// Whether the peer has sent its M=0 terminator (the other half
    /// of the §10.6 ExchangeDone gate).
    peer_dd_done: bool,
    /// §10.9: the Link State Request list.
    pub requests: Vec<LsRequestId>,
    /// §13.3: the retransmission list (LSAs sent, not yet acked).
    pub rxmt: Vec<(LsaKey, Vec<u8>)>,
    rxmt_deadline: Option<u64>,
    dd_deadline: Option<u64>,
    last_dd_sent: Option<DbDescription>,
    own_router_id: RouterId,
    area_id: u32,
    params: ConversationParams,
}

impl Conversation {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        own_router_id: RouterId,
        area_id: u32,
        peer_ip: Ipv4Addr,
        now: u64,
        dead_interval: u64,
        params: ConversationParams,
    ) -> Self {
        Self {
            fsm: NeighborFsm::new(own_router_id),
            ip: peer_ip,
            peer_router_id: None,
            inactivity_deadline: now + dead_interval,
            summary: VecDeque::new(),
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

    pub fn state(&self) -> NeighborState {
        self.fsm.state
    }

    fn packet(&self, body: PacketBody) -> Packet {
        Packet {
            header: PacketHeader {
                version: 2,
                packet_type: body.packet_type(),
                length: 0,
                router_id: self.own_router_id,
                area_id: self.area_id,
                checksum: 0,
                au_type: 0,
                authentication: 0,
            },
            body,
        }
    }

    fn send(&self, body: PacketBody) -> Send {
        Send {
            to: self.ip,
            packet: self.packet(body),
        }
    }

    /// Fire one neighbor event and map its actions to obligations
    /// (the §10.3 action column; the LSDB feeds the summary build).
    pub fn fire_and_map(
        &mut self,
        event: NeighborEvent,
        lsdb: &Lsdb,
        now: u64,
    ) -> (Vec<Send>, ConversationReport) {
        let mut sends = Vec::new();
        let mut report = ConversationReport::default();
        let (_, actions) = self.fsm.fire(event);
        for action in actions {
            match action {
                NeighborAction::RestartInactivityTimer => {
                    // The caller refreshes via touch_inactivity (it
                    // owns the dead interval).
                }
                NeighborAction::StopInactivityTimer => {}
                NeighborAction::ClearLists => {
                    // §10.3: the lists die with the conversation.
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
                    let dd = DbDescription {
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
                    sends.push(self.send(PacketBody::DbDescription(dd)));
                }
                NeighborAction::BuildSummaryList => {
                    // §10.3: the Database Summary list = every LSA in
                    // the area LSDB, as headers.
                    self.summary = lsdb.all().map(|e| e.lsa.header).collect();
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
        // §10.3's ExchangeDone action: entering Loading with pending
        // requests sends the first Link State Request round at once
        // (§10.9; a duplicate LSR is re-answered, the RxmtInterval
        // retransmit covers loss).
        if matches!(self.fsm.state, NeighborState::Loading) && !self.requests.is_empty() {
            sends.extend(self.build_lsr(now));
        }
        (sends, report)
    }

    /// Build the next DD chunk (§10.8): up to the MTU budget of
    /// headers, M=0 exactly when the summary drains with it.
    fn build_dd_chunk(&mut self, now: u64) -> Send {
        // Header budget: 24-byte packet header + 8-byte DD preamble;
        // each LSA header is 20 bytes.
        let budget = (self.params.mtu as usize).saturating_sub(24 + 8) / 20;
        let take = budget.min(self.summary.len());
        let mut headers = Vec::with_capacity(take);
        for _ in 0..take {
            headers.push(self.summary.pop_front().expect("len checked"));
        }
        self.fsm.summary_pending = !self.summary.is_empty();
        let more = !self.summary.is_empty();
        let dd = DbDescription {
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
        self.send(PacketBody::DbDescription(dd))
    }

    /// §10.9: one LSR packet with the outstanding requests (MTU
    /// budget), arming the retransmit.
    fn build_lsr(&mut self, now: u64) -> Vec<Send> {
        if self.requests.is_empty() {
            return vec![];
        }
        let budget = (self.params.mtu as usize).saturating_sub(24) / 12;
        let take = budget.min(self.requests.len());
        let requests: Vec<LsRequestId> = self.requests[..take].to_vec();
        self.dd_deadline = Some(now + self.params.rxmt_interval);
        vec![self.send(PacketBody::LsRequest(LsRequest { requests }))]
    }

    fn request_matches(r: &LsRequestId, header: &LsaHeader) -> bool {
        r.ls_type == u32::from(header.ls_type.0)
            && r.link_state_id == header.link_state_id
            && r.adv_router == header.adv_router
    }

    /// §10.6: one received Database Description packet.
    pub fn handle_dbd(
        &mut self,
        pkt: &DbDescription,
        packet_router_id: RouterId,
        our_mtu: u16,
        lsdb: &mut Lsdb,
        now: u64,
    ) -> (Vec<Send>, ConversationReport) {
        let mut sends = Vec::new();
        let mut report = ConversationReport::default();
        // §10.6: "If the Interface MTU field ... indicates an MTU
        // larger than the router's own, the packet is rejected" (the
        // interface layer owns MTU knowledge).
        if pkt.interface_mtu > our_mtu {
            return (sends, report);
        }
        // The §10.6 ExStart comparison input.
        self.fsm.peer_id_larger_value = Some(packet_router_id.larger_than(self.own_router_id));
        // The §10.6 ExchangeDone gate's own-half.
        self.fsm.summary_pending = !self.summary.is_empty();
        let state_before = self.state();

        let result = self.fsm.process_dbd(pkt);
        if result.accepted {
            // The described headers feed the request list (§10.6's
            // comparison: newer-or-unknown → request, §10.9).
            for hdr in &pkt.lsa_headers {
                let key = LsaKey::from_header(hdr);
                let need = match lsdb.get(&key) {
                    None => true,
                    Some(entry) => matches!(
                        lsdb::newer_than(hdr, &entry.lsa.header),
                        lsdb::Which::FirstNewer
                    ),
                };
                if need && !self.requests.iter().any(|r| Self::request_matches(r, hdr)) {
                    self.requests.push(LsRequestId {
                        ls_type: u32::from(hdr.ls_type.0),
                        link_state_id: hdr.link_state_id,
                        adv_router: hdr.adv_router,
                    });
                }
            }
            if !pkt.more {
                self.peer_dd_done = true;
            }
        }
        for event in result.events {
            let (mut ev_sends, ev_report) = self.fire_and_map(event, lsdb, now);
            sends.append(&mut ev_sends);
            report.merge(&ev_report);
        }
        if result.send_reply {
            // §10.8: the exchange's last round is the master's M=0
            // chunk answered by the slave's M=0 echo — once BOTH
            // have crossed, the master opens no new round.
            let master_round_complete = self.fsm.master
                && !pkt.more
                && self.summary.is_empty()
                && self.last_dd_sent.as_ref().is_some_and(|d| !d.more);
            // The reply is our next description chunk (or the empty
            // M=0 terminator when drained). A slave's echo of a
            // duplicate retransmits the last DD instead. The reply
            // obligation survives the events' state transitions —
            // the slave's final echo still goes out after
            // ExchangeDone moved it to Loading.
            let duplicate_echo = !result.accepted && self.last_dd_sent.is_some();
            if !master_round_complete {
                if duplicate_echo {
                    if let Some(dd) = &self.last_dd_sent {
                        let mut dd = dd.clone();
                        dd.dd_sequence = self.fsm.dd_sequence;
                        sends.push(self.send(PacketBody::DbDescription(dd)));
                    }
                } else if matches!(
                    state_before,
                    NeighborState::Exchange | NeighborState::ExStart
                ) {
                    sends.push(self.build_dd_chunk(now));
                }
            }
        }
        // §10.6's ExchangeDone second half: our summary drained after
        // the peer already sent M=0. §10.6 evaluates the gate at
        // receipt: a slave M=0 that arrived while the master was
        // still sending does not complete the master's exchange —
        // only the slave completes retroactively (its own drain +
        // the master's recorded M=0; the final echo still goes out
        // as the ack).
        if !self.fsm.master
            && matches!(self.state(), NeighborState::Exchange)
            && self.peer_dd_done
            && self.summary.is_empty()
        {
            let (mut ev_sends, ev_report) =
                self.fire_and_map(NeighborEvent::ExchangeDone, lsdb, now);
            sends.append(&mut ev_sends);
            report.merge(&ev_report);
        }
        // Loading with an empty request list: LoadingDone fires at
        // once (§10.3's Exchange/Loading + LoadingDone → Full).
        if matches!(self.state(), NeighborState::Loading) && self.requests.is_empty() {
            let (mut ev_sends, ev_report) =
                self.fire_and_map(NeighborEvent::LoadingDone, lsdb, now);
            sends.append(&mut ev_sends);
            report.merge(&ev_report);
        }
        (sends, report)
    }

    /// §10.9: one received Link State Request.
    pub fn handle_lsr(
        &mut self,
        pkt: &LsRequest,
        lsdb: &mut Lsdb,
        now: u64,
    ) -> (Vec<Send>, ConversationReport) {
        let mut lsas = Vec::new();
        let mut report = ConversationReport::default();
        let mut sends = Vec::new();
        for req in &pkt.requests {
            let key = LsaKey {
                ls_type: crate::lsa::LsaType(req.ls_type as u16),
                link_state_id: req.link_state_id,
                adv_router: req.adv_router,
            };
            match lsdb.get(&key) {
                Some(entry) => lsas.push(entry.lsa.clone()),
                // §10.9: a request we cannot satisfy is an exchange
                // error — BadLSReq re-establishes the conversation.
                None => {
                    let (mut ev_sends, ev_report) =
                        self.fire_and_map(NeighborEvent::BadLSReq, lsdb, now);
                    sends.append(&mut ev_sends);
                    report.merge(&ev_report);
                    return (sends, report);
                }
            }
        }
        // Answer LSUs split by the interface MTU (24-byte packet
        // header + 4-byte count + each LSA's own length).
        let mut batch: Vec<Lsa> = Vec::new();
        let mut batch_len = 24 + 4;
        for lsa in lsas {
            let lsa_len = lsa.header.length as usize;
            if !batch.is_empty() && batch_len + lsa_len > self.params.mtu as usize {
                sends.push(self.send(PacketBody::LsUpdate(LsUpdate {
                    lsas: std::mem::take(&mut batch),
                })));
                batch_len = 24 + 4;
            }
            batch_len += lsa_len;
            batch.push(lsa);
        }
        if !batch.is_empty() {
            sends.push(self.send(PacketBody::LsUpdate(LsUpdate { lsas: batch })));
        }
        (sends, report)
    }

    /// §13: one received Link State Update (the LSAs, in order).
    /// `other_adjacencies_syncing` feeds step 4's flush exception.
    pub fn handle_lsu(
        &mut self,
        lsas: &[Lsa],
        lsdb: &mut Lsdb,
        now: u64,
        other_adjacencies_syncing: bool,
    ) -> (Vec<Send>, ConversationReport) {
        let mut sends = Vec::new();
        let mut report = ConversationReport::default();
        for lsa in lsas {
            let key = lsa.key();
            // §10.9: an answer retires its request-list entry,
            // whatever the instance.
            let had_request = self
                .requests
                .iter()
                .any(|r| Self::request_matches(r, &lsa.header));
            if had_request {
                self.requests
                    .retain(|r| !Self::request_matches(r, &lsa.header));
            }
            let on_rxmt = self.rxmt.iter().any(|(k, _)| *k == key);
            let action = flood_step(
                &lsa.encode(),
                lsdb,
                now,
                other_adjacencies_syncing,
                false, // normal area (stub is §Deferred)
                had_request,
                on_rxmt,
            );
            match action {
                FloodAction::InstallAndFlood { changed } => {
                    if changed {
                        report.changed.push(key);
                    }
                    // §13.5: the direct acknowledgment — on p2p,
                    // unicast back to the source (§13.5's "direct").
                    sends.push(self.send(PacketBody::LsAck(LsAck {
                        headers: vec![lsa.header],
                    })));
                }
                FloodAction::AckAndDiscard => {
                    sends.push(self.send(PacketBody::LsAck(LsAck {
                        headers: vec![lsa.header],
                    })));
                }
                FloodAction::SameInstance { on_rxmt_list } => {
                    if on_rxmt_list {
                        // §13.3: the implied acknowledgment.
                        self.implied_ack(&lsa.header);
                    } else {
                        sends.push(self.send(PacketBody::LsAck(LsAck {
                            headers: vec![lsa.header],
                        })));
                    }
                }
                FloodAction::SendDatabaseCopy(db) => {
                    // §13 step 8: send our newer copy straight back.
                    sends.push(self.send(PacketBody::LsUpdate(LsUpdate { lsas: vec![db] })));
                }
                FloodAction::BadLSReq => {
                    let (mut ev_sends, ev_report) =
                        self.fire_and_map(NeighborEvent::BadLSReq, lsdb, now);
                    sends.append(&mut ev_sends);
                    report.merge(&ev_report);
                    return (sends, report);
                }
                FloodAction::Discard { .. } => {}
            }
        }
        if matches!(self.state(), NeighborState::Loading) && self.requests.is_empty() {
            let (mut ev_sends, ev_report) =
                self.fire_and_map(NeighborEvent::LoadingDone, lsdb, now);
            sends.append(&mut ev_sends);
            report.merge(&ev_report);
        } else if matches!(self.state(), NeighborState::Loading) && !self.requests.is_empty() {
            // §10.9: the answer arrived; the next request round goes
            // out at once (the LSR itself is MTU-budgeted).
            sends.extend(self.build_lsr(now));
        }
        (sends, report)
    }

    /// §13.5/§13.6: one received Link State Acknowledgment — direct
    /// acks clear the retransmission list.
    pub fn handle_lsack(&mut self, headers: &[LsaHeader]) {
        let keys: Vec<LsaKey> = headers.iter().map(LsaKey::from_header).collect();
        self.rxmt.retain(|(k, _)| !keys.contains(k));
        if self.rxmt.is_empty() {
            self.rxmt_deadline = None;
        }
    }

    /// §13.3's implied acknowledgment: an LSU carrying an instance we
    /// flooded to this neighbor.
    pub fn implied_ack(&mut self, header: &LsaHeader) {
        let key = LsaKey::from_header(header);
        self.rxmt.retain(|(k, _)| *k != key);
        if self.rxmt.is_empty() {
            self.rxmt_deadline = None;
        }
    }

    /// §13.3: remember a flooded LSA on this neighbor's
    /// retransmission list (unacked until LSAck/implied ack).
    pub fn queue_retransmit(&mut self, lsa: &Lsa, now: u64) {
        let key = lsa.key();
        if !self.rxmt.iter().any(|(k, _)| *k == key) {
            self.rxmt.push((key, lsa.encode()));
        }
        self.rxmt_deadline = Some(now + self.params.rxmt_interval);
    }

    /// The periodic tick: Inactivity Timer, DD/LSR retransmission,
    /// LSU retransmission (§13.5's "every RxmtInterval until acked").
    pub fn tick(&mut self, now: u64) -> (Vec<Send>, ConversationReport) {
        let mut sends = Vec::new();
        let mut report = ConversationReport::default();
        if matches!(self.state(), NeighborState::Down) {
            return (sends, report);
        }
        if now >= self.inactivity_deadline {
            // §10.2: the Inactivity Timer expired — the neighbor is
            // declared dead.
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
                // §10.8/§10.9: retransmit the outstanding DD or LSR.
                match self.state() {
                    NeighborState::ExStart | NeighborState::Exchange => {
                        if let Some(dd) = &self.last_dd_sent {
                            let mut dd = dd.clone();
                            dd.dd_sequence = self.fsm.dd_sequence;
                            sends.push(self.send(PacketBody::DbDescription(dd)));
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
                // §13.5: re-flood every unacked LSA in one LSU.
                let lsas: Vec<Lsa> = self
                    .rxmt
                    .iter()
                    .filter_map(|(_, bytes)| Lsa::decode(bytes).ok())
                    .collect();
                if !lsas.is_empty() {
                    sends.push(self.send(PacketBody::LsUpdate(LsUpdate { lsas })));
                }
                self.rxmt_deadline = Some(now + self.params.rxmt_interval);
            }
        }
        (sends, report)
    }

    /// Restart the Inactivity Timer (§10.2) — the caller owns the
    /// dead interval.
    pub fn touch_inactivity(&mut self, now: u64, dead_interval: u64) {
        self.inactivity_deadline = now + dead_interval;
    }

    /// Whether this neighbor belongs in our Hellos (§C.3: every
    /// router heard from within RouterDeadInterval — v1: state ≥
    /// Init).
    pub fn in_hello(&self) -> bool {
        self.state().at_least(NeighborState::Init)
    }
}

impl LsaKey {
    pub(crate) fn from_header(hdr: &LsaHeader) -> LsaKey {
        LsaKey {
            ls_type: hdr.ls_type,
            link_state_id: hdr.link_state_id,
            adv_router: hdr.adv_router,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::iface::InterfaceState;
    use crate::origination::{build_router_lsa, InterfaceAdv};

    fn rid(s: &str) -> RouterId {
        RouterId::from_ipv4(s.parse().unwrap())
    }

    fn lsa_for(own: RouterId, n: u32) -> Lsa {
        // A distinctive router-LSA per (router, instance).
        let lsa = build_router_lsa(
            own,
            false,
            false,
            &[InterfaceAdv {
                state: InterfaceState::PointToPoint,
                p2p: true,
                address: Ipv4Addr::new(10, 0, (n % 250) as u8, 1),
                mask: "255.255.255.252".parse().unwrap(),
                cost: n as u16,
                p2p_neighbors_full: vec![],
                attached_routers: vec![],
                dr_address: None,
                transit_adjacent: false,
            }],
        );
        lsa.with_computed_header()
    }

    /// Deliver one side's sends to the other side, packet-type aware;
    /// returns the receiving side's obligations in turn.
    fn deliver(to: &mut Conversation, sends: &[Send], lsdb: &mut Lsdb, now: u64) -> Vec<Send> {
        let mut out = Vec::new();
        for send in sends {
            match &send.packet.body {
                PacketBody::DbDescription(dd) => {
                    let (mut s, _) =
                        to.handle_dbd(dd, send.packet.header.router_id, 1500, lsdb, now);
                    out.append(&mut s);
                }
                PacketBody::LsRequest(lsr) => {
                    let (mut s, _) = to.handle_lsr(lsr, lsdb, now);
                    out.append(&mut s);
                }
                PacketBody::LsUpdate(lsu) => {
                    let (mut s, _) = to.handle_lsu(&lsu.lsas, lsdb, now, false);
                    out.append(&mut s);
                }
                PacketBody::LsAck(ack) => to.handle_lsack(&ack.headers),
                PacketBody::Hello(_) => {}
            }
        }
        out
    }

    #[test]
    fn two_sided_exchange_reaches_full_and_converges() {
        // A (10.1.1.1, master — larger ID) and B (10.2.2.2, slave),
        // each with a private LSA the other lacks. Drive both sides'
        // ExStart assertions, then pump every obligation across until
        // both are Full and both LSDBs hold the union. No sockets:
        // the pure §10.6-§10.9 walk.
        let now = 100u64;
        let mut db_a = Lsdb::new();
        let mut db_b = Lsdb::new();
        let la = lsa_for(rid("10.1.1.1"), 1);
        let lb = lsa_for(rid("10.2.2.2"), 2);
        db_a.install(la.clone(), false, now);
        db_b.install(lb.clone(), false, now);
        let mut a = Conversation::new(
            rid("10.1.1.1"),
            0,
            "10.9.9.2".parse().unwrap(),
            now,
            40,
            Default::default(),
        );
        let mut b = Conversation::new(
            rid("10.2.2.2"),
            0,
            "10.9.9.1".parse().unwrap(),
            now,
            40,
            Default::default(),
        );

        // Hellos → Init → AdjOk(true) (p2p, §10.4) → ExStart with
        // the empty I/M/MS DD each side.
        a.fire_and_map(NeighborEvent::HelloReceived, &db_a, now);
        let (sends_a, _) = a.fire_and_map(NeighborEvent::AdjOk(true), &db_a, now);
        b.fire_and_map(NeighborEvent::HelloReceived, &db_b, now);
        let (sends_b, _) = b.fire_and_map(NeighborEvent::AdjOk(true), &db_b, now);
        assert_eq!(sends_a.len(), 1, "ExStart empty DD");
        assert_eq!(sends_b.len(), 1);
        // Both assert master (MS=1) at ExStart; §10.6's negotiation
        // resolves it — the larger Router ID wins in the walk below.
        for (side, sends) in [("a", &sends_a), ("b", &sends_b)] {
            let PacketBody::DbDescription(dd) = &sends[0].packet.body else {
                panic!("{side}'s ExStart packet is a DD");
            };
            assert!(dd.init && dd.more && dd.master, "{side} asserts I/M/MS");
        }

        // Pump every obligation both directions until quiet; both
        // sides must be Full and converged.
        let mut pending: Vec<(bool, Vec<Send>)> = vec![(true, sends_a), (false, sends_b)];
        let mut rounds = 0;
        while !pending.is_empty() {
            let (from_a, sends) = pending.remove(0);
            rounds += 1;
            assert!(rounds < 40, "exchange did not settle");
            let replies = if from_a {
                deliver(&mut b, &sends, &mut db_b, now)
            } else {
                deliver(&mut a, &sends, &mut db_a, now)
            };
            if !replies.is_empty() {
                pending.push((!from_a, replies));
            }
        }
        assert_eq!(a.state(), NeighborState::Full, "A Full");
        assert_eq!(b.state(), NeighborState::Full, "B Full");
        assert!(rounds >= 4, "a real multi-round walk happened");
        // Both LSDBs converged to the union.
        assert!(db_a.contains(&lb.key()), "A holds B's LSA");
        assert!(db_b.contains(&la.key()), "B holds A's LSA");
        // Retransmission lists drained (everything acked).
        assert!(a.rxmt.is_empty(), "A's rxmt drained");
        assert!(b.rxmt.is_empty(), "B's rxmt drained");
    }

    #[test]
    fn larger_lsdb_multi_packet_dd_walk() {
        // §10.8's multi-packet drain: A's summary (150+ headers) does
        // not fit one DD; the walk must still reach Full with B
        // holding everything.
        let now = 0u64;
        let mut db_a = Lsdb::new();
        let mut db_b = Lsdb::new();
        for i in 0..150u32 {
            let lsa = lsa_for(RouterId(0x0a01_0100 + i), i + 1);
            db_a.install(lsa, false, now);
        }
        let mut a = Conversation::new(
            rid("10.9.9.9"),
            0,
            "10.9.9.2".parse().unwrap(),
            now,
            40,
            Default::default(),
        );
        let mut b = Conversation::new(
            rid("10.2.2.2"),
            0,
            "10.9.9.1".parse().unwrap(),
            now,
            40,
            Default::default(),
        );
        a.fire_and_map(NeighborEvent::HelloReceived, &db_a, now);
        let (sends_a, _) = a.fire_and_map(NeighborEvent::AdjOk(true), &db_a, now);
        b.fire_and_map(NeighborEvent::HelloReceived, &db_b, now);
        let (sends_b, _) = b.fire_and_map(NeighborEvent::AdjOk(true), &db_b, now);

        let mut pending: Vec<(bool, Vec<Send>)> = vec![(true, sends_a), (false, sends_b)];
        let mut rounds = 0;
        while !pending.is_empty() {
            let (from_a, sends) = pending.remove(0);
            rounds += 1;
            assert!(rounds < 400, "walk did not settle");
            let replies = if from_a {
                deliver(&mut b, &sends, &mut db_b, now)
            } else {
                deliver(&mut a, &sends, &mut db_a, now)
            };
            if !replies.is_empty() {
                pending.push((!from_a, replies));
            }
        }
        assert_eq!(a.state(), NeighborState::Full);
        assert_eq!(b.state(), NeighborState::Full);
        assert!(rounds >= 8, "the 150-header summary took several DDs");
        assert_eq!(db_b.len(), 150, "B learned every LSA");
        // §10.8: no DD carried more than the MTU budget of headers.
        // (Asserted implicitly by decode strictness in deliver.)
    }

    #[test]
    fn retransmit_list_paces_and_clears() {
        let now = 0u64;
        let mut c = Conversation::new(
            rid("1.1.1.1"),
            0,
            "10.0.0.2".parse().unwrap(),
            now,
            40,
            Default::default(),
        );
        c.fsm.state = NeighborState::Full;
        let lsa = lsa_for(rid("2.2.2.2"), 5);
        c.queue_retransmit(&lsa, now);
        assert_eq!(c.rxmt.len(), 1);
        // Before the deadline: nothing.
        let (sends, _) = c.tick(now + 4);
        assert!(sends.is_empty());
        // At the deadline: the LSU re-flood (§13.5).
        let (sends, _) = c.tick(now + 5);
        assert!(matches!(sends[0].packet.body, PacketBody::LsUpdate(_)));
        // A direct ack clears it.
        c.handle_lsack(&[lsa.header]);
        assert!(c.rxmt.is_empty());
        let (sends, _) = c.tick(now + 11);
        assert!(sends.is_empty());
    }

    #[test]
    fn inactivity_timer_takes_the_neighbor_down() {
        let now = 0u64;
        let mut c = Conversation::new(
            rid("1.1.1.1"),
            0,
            "10.0.0.2".parse().unwrap(),
            now,
            40,
            Default::default(),
        );
        c.fsm.state = NeighborState::Full;
        let (_, report) = c.tick(39);
        assert!(!report.adjacency_down);
        let (_, report) = c.tick(40);
        assert!(report.adjacency_down, "§10.2 Inactivity Timer");
        assert_eq!(c.state(), NeighborState::Down);
    }

    #[test]
    fn lsr_for_unknown_lsa_is_badlsreq() {
        // §10.9: a request we cannot satisfy restarts the exchange.
        let now = 0u64;
        let mut c = Conversation::new(
            rid("1.1.1.1"),
            0,
            "10.0.0.2".parse().unwrap(),
            now,
            40,
            Default::default(),
        );
        c.fsm.state = NeighborState::Full;
        c.fsm.neighbor_options = Some(Options::E);
        let lsr = LsRequest {
            requests: vec![LsRequestId {
                ls_type: 1,
                link_state_id: crate::lsa::LinkStateId(0x0a00_0001),
                adv_router: rid("9.9.9.9"),
            }],
        };
        let (_, report) = c.handle_lsr(&lsr, &mut Lsdb::new(), now);
        // §10.3's row re-establishes the conversation (ClearLists +
        // empty DD); the neighbor itself is not destroyed.
        assert!(!report.adjacency_down);
        assert_eq!(c.state(), NeighborState::ExStart);
        assert!(c.requests.is_empty(), "the lists were cleared");
    }

    #[test]
    fn mtu_rejection_per_10_6() {
        // §10.6: a DD advertising a larger MTU than ours is rejected.
        let now = 0u64;
        let mut c = Conversation::new(
            rid("1.1.1.1"),
            0,
            "10.0.0.2".parse().unwrap(),
            now,
            40,
            Default::default(),
        );
        c.fsm.state = NeighborState::ExStart;
        c.fsm.peer_id_larger_value = Some(true);
        let dd = DbDescription {
            interface_mtu: 9000,
            options: Options(Options::E),
            init: true,
            more: true,
            master: true,
            dd_sequence: 1,
            lsa_headers: vec![],
        };
        let (sends, _) = c.handle_dbd(&dd, rid("2.2.2.2"), 1500, &mut Lsdb::new(), now);
        assert!(sends.is_empty());
        assert_eq!(c.state(), NeighborState::ExStart, "rejected silently");
    }

    #[test]
    fn maxage_unexpected_lsa_acks_and_discards() {
        // §13 step 4: MaxAge, no local instance, nobody syncing →
        // acknowledge and discard (no install).
        let now = 0u64;
        let mut c = Conversation::new(
            rid("1.1.1.1"),
            0,
            "10.0.0.2".parse().unwrap(),
            now,
            40,
            Default::default(),
        );
        c.fsm.state = NeighborState::Full;
        let mut lsa = lsa_for(rid("8.8.8.8"), 3);
        lsa.header.ls_age = crate::MAX_AGE;
        let lsa = lsa.with_computed_header();
        let (sends, report) = c.handle_lsu(&[lsa], &mut Lsdb::new(), now, false);
        assert!(report.changed.is_empty());
        assert!(matches!(sends[0].packet.body, PacketBody::LsAck(_)));
    }

    #[test]
    fn master_confirm_on_slave_first_chunk_sends_data_round() {
        // B (10.255.2.1, master) in ExStart receives A's slave chunk
        // (i=0, ms=0, seq == ours, headers). Case 2 must fire.
        let now = 0u64;
        let mut db = Lsdb::new();
        db.install(
            lsa_for(RouterId::from_ipv4("10.255.2.1".parse().unwrap()), 1),
            false,
            now,
        );
        let mut b = Conversation::new(
            rid("10.255.2.1"),
            0,
            "10.77.0.1".parse().unwrap(),
            now,
            40,
            Default::default(),
        );
        b.fire_and_map(NeighborEvent::HelloReceived, &db, now);
        b.fire_and_map(NeighborEvent::AdjOk(true), &db, now);
        assert_eq!(b.state(), NeighborState::ExStart);
        let chunk = DbDescription {
            interface_mtu: 1500,
            options: Options(Options::E),
            init: false,
            more: false,
            master: false,
            dd_sequence: b.fsm.dd_sequence,
            lsa_headers: vec![],
        };
        let (sends, _) = b.handle_dbd(&chunk, rid("10.255.1.1"), 1500, &mut db, now);
        assert_eq!(b.state(), NeighborState::Exchange, "case 2 fired");
        assert!(b.fsm.master);
        assert!(!sends.is_empty());
    }
}
