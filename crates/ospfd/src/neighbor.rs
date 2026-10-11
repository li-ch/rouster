//! The neighbor conversation state machine (RFC 2328 §10) and the
//! Database Exchange / flooding cores.
//!
//! Pure and clock-injected, the bgpd FSM convention: [`NeighborFsm`]
//! holds the §10.3 table; `fire(event)` returns the actions the RFC's
//! "New state / Action" entries prescribe. Packet-level processing:
//!
//! - [`process_hello`] (§10.5): parameter agreement checks, then the
//!   HelloReceived / 2-WayReceived / 1-WayReceived event ladder and
//!   the RouterDeadInterval restart.
//! - [`NeighborFsm::process_dbd`] (§10.6): state-dependent acceptance
//!   (Down/Attempt reject, Init → 2-WayReceived fall-through, 2-Way
//!   ignores, ExStart master/slave negotiation, Exchange
//!   duplicate/seq/options handling, Loading/Full duplicates only),
//!   emitting NegotiationDone / SeqNumberMismatch / ExchangeDone and
//!   the master/slave send obligations of §10.8.
//! - [`flood_step`] (§13): one received LSA against the LSDB —
//!   checksum/type/stub-area/MaxAge-absent gates (steps 1-4),
//!   newer-instance handling (step 5, incl. the MinLSArrival guard
//!   inside the LSDB), the request-list error (step 6 → BadLSReq),
//!   implied acknowledgment (step 7a), and the send-the-database-copy
//!   back (step 8).
//!
//! The §10.4 adjacency decision is injected as a bool by the caller
//! (network type + DR/BDR knowledge live at the interface layer).

use crate::lsa::Lsa;
use crate::lsdb::{self, InstallOutcome, Lsdb};
use crate::packet::{DbDescription, Hello};

/// §10.1 neighbor states.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum NeighborState {
    Down,
    /// NBMA-only: concerted effort to contact the neighbor.
    Attempt,
    Init,
    TwoWay,
    ExStart,
    Exchange,
    Loading,
    Full,
}

impl NeighborState {
    pub fn name(self) -> &'static str {
        match self {
            Self::Down => "Down",
            Self::Attempt => "Attempt",
            Self::Init => "Init",
            Self::TwoWay => "2-Way",
            Self::ExStart => "ExStart",
            Self::Exchange => "Exchange",
            Self::Loading => "Loading",
            Self::Full => "Full",
        }
    }

    /// "state greater than X" comparisons the spec makes (§10.1).
    pub fn at_least(self, other: NeighborState) -> bool {
        self >= other
    }
}

/// §10.2 events (plus the injected AdjOK? answer).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NeighborEvent {
    /// NBMA start of Hellos.
    Start,
    HelloReceived,
    OneWayReceived,
    TwoWayReceived,
    NegotiationDone,
    ExchangeDone,
    BadLSReq,
    LoadingDone,
    /// The §10.4 adjacency decision, with its answer.
    AdjOk(bool),
    SeqNumberMismatch,
    KillNbr,
    InactivityTimer,
    LLDown,
}

/// Actions the §10.3 entries prescribe.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NeighborAction {
    /// Start (or restart) the Inactivity Timer (RouterDeadInterval).
    RestartInactivityTimer,
    /// Disable the Inactivity Timer.
    StopInactivityTimer,
    /// Clear the retransmission + database-summary + request lists.
    ClearLists,
    /// Bump the DD sequence number.
    BumpDdSequence,
    /// Send an otherwise-empty DD with the given I/M/MS bits (the
    /// ExStart assertion and the re-establishment after
    /// SeqNumberMismatch/BadLSReq).
    SendEmptyDd {
        init: bool,
        more: bool,
        master: bool,
    },
    /// Build the Database summary list from the area LSDB (§10.3
    /// NegotiationDone action).
    BuildSummaryList,
    /// Start (or continue) sending Link State Requests (§10.9).
    SendLsRequests,
    /// The interface FSM's NeighborChange event (DR re-election).
    InterfaceNeighborChange,
    /// An adjacency reached Full.
    AdjacencyUp,
    /// An adjacency was destroyed (from ≥ ExStart).
    AdjacencyDown,
}

/// Per-neighbor conversation state.
#[derive(Debug, Clone)]
pub struct NeighborFsm {
    pub state: NeighborState,
    /// Our Router ID (for master/slave comparison, §10.6).
    pub own_router_id: crate::lsa::RouterId,
    /// True once negotiated: we are the master.
    pub master: bool,
    /// The DD sequence number in the neighbor data structure.
    pub dd_sequence: u32,
    /// The last received DD packet's summary (duplicate detection,
    /// §10.6) — I/M/MS, options, DD sequence.
    pub last_dd: Option<(bool, bool, bool, u8, u32)>,
    /// Neighbor Options recorded at NegotiationDone (§10.6).
    pub neighbor_options: Option<u8>,
    /// The peer's Router ID is larger than ours (the §10.6 ExStart
    /// comparison input — the daemon layer sets it from the packet
    /// header; tests set it directly).
    pub peer_id_larger_value: Option<bool>,
    /// Whether our Database Summary list still has unsent DD
    /// headers — the §10.6 ExchangeDone gate's "we have sent our
    /// whole description" half. The daemon keeps it current;
    /// `false` (the default) models the summary-fits-one-packet
    /// assumption of the pure tests.
    pub summary_pending: bool,
}

impl NeighborFsm {
    pub fn new(own_router_id: crate::lsa::RouterId) -> Self {
        Self {
            state: NeighborState::Down,
            own_router_id,
            master: false,
            dd_sequence: 0,
            last_dd: None,
            neighbor_options: None,
            peer_id_larger_value: None,
            summary_pending: false,
        }
    }

    /// Fire one §10.3 event. Returns the resulting state (unchanged
    /// when the table says so) and the prescribed actions.
    pub fn fire(&mut self, event: NeighborEvent) -> (NeighborState, Vec<NeighborAction>) {
        use NeighborAction as A;
        use NeighborEvent as E;
        use NeighborState as S;
        let mut actions = Vec::new();
        let from = self.state;
        let next = match (&self.state, event) {
            // Down + Start -> Attempt: send a Hello, start timer.
            (S::Down, E::Start) => {
                actions.push(A::RestartInactivityTimer);
                S::Attempt
            }
            // Attempt + HelloReceived -> Init: restart the timer.
            (S::Attempt, E::HelloReceived) => {
                actions.push(A::RestartInactivityTimer);
                S::Init
            }
            // Down + HelloReceived -> Init: start the timer.
            (S::Down, E::HelloReceived) => {
                actions.push(A::RestartInactivityTimer);
                S::Init
            }
            // Init or greater + HelloReceived: no change, restart timer.
            (s, E::HelloReceived) if s.at_least(S::Init) => {
                actions.push(A::RestartInactivityTimer);
                *s
            }
            // Init + 2-WayReceived: the §10.4 decision.
            (S::Init, E::TwoWayReceived) => {
                // caller supplies AdjOk separately for the decision;
                // a bare TwoWayReceived without the answer parks at
                // the decision point via AdjOk below.
                S::Init
            }
            (S::Init, E::AdjOk(false)) | (S::TwoWay, E::AdjOk(false)) => S::TwoWay,
            (S::Init, E::AdjOk(true)) | (S::TwoWay, E::AdjOk(true)) => {
                // Enter ExStart: bump DD seq, declare master, send
                // the empty I/M/MS DD (§10.3 Init+2-Way action).
                self.dd_sequence = self.dd_sequence.wrapping_add(1);
                actions.push(A::SendEmptyDd {
                    init: true,
                    more: true,
                    master: true,
                });
                S::ExStart
            }
            // ExStart + NegotiationDone -> Exchange: build the
            // Database summary list.
            (S::ExStart, E::NegotiationDone) => {
                actions.push(A::BuildSummaryList);
                S::Exchange
            }
            // Exchange + ExchangeDone: Full when the request list is
            // empty, else Loading (caller resolves via LoadingDone).
            (S::Exchange, E::ExchangeDone) => {
                // The caller fires AdjOK-style knowledge separately;
                // here we model "request list empty" as an immediate
                // LoadingDone in the same breath when it arrives.
                S::Loading
            }
            (S::Loading, E::LoadingDone) => {
                actions.push(A::AdjacencyUp);
                S::Full
            }
            (S::Exchange, E::LoadingDone) => {
                actions.push(A::AdjacencyUp);
                S::Full
            }
            // 2-Way or greater + AdjOK(yes): stay; the §10.3 entry
            // performs the Init+2-Way actions only when coming from
            // 2-Way, which AdjOk(true) above covers.
            (s, E::AdjOk(true)) if s.at_least(S::ExStart) => *s,
            // ExStart or greater + AdjOK(no): destroy the adjacency.
            (s, E::AdjOk(false)) if s.at_least(S::ExStart) => {
                actions.push(A::ClearLists);
                actions.push(A::AdjacencyDown);
                S::TwoWay
            }
            // Exchange or greater + SeqNumberMismatch/BadLSReq:
            // re-establish.
            (s, E::SeqNumberMismatch) | (s, E::BadLSReq) if s.at_least(S::Exchange) => {
                actions.push(A::ClearLists);
                self.dd_sequence = self.dd_sequence.wrapping_add(1);
                actions.push(A::SendEmptyDd {
                    init: true,
                    more: true,
                    master: true,
                });
                S::ExStart
            }
            // Any state + KillNbr/LLDown/InactivityTimer -> Down.
            (_, E::KillNbr) | (_, E::LLDown) | (_, E::InactivityTimer) => {
                if self.state.at_least(S::ExStart) {
                    actions.push(A::AdjacencyDown);
                }
                actions.push(A::ClearLists);
                actions.push(A::StopInactivityTimer);
                S::Down
            }
            // 2-Way or greater + 1-Way -> Init: clear the lists.
            (s, E::OneWayReceived) if s.at_least(S::TwoWay) => {
                if s.at_least(S::ExStart) {
                    actions.push(A::AdjacencyDown);
                }
                actions.push(A::ClearLists);
                S::Init
            }
            // Init + 1-Way: no change.
            (S::Init, E::OneWayReceived) => S::Init,
            // 2-Way or greater + 2-Way: no change, no action.
            (s, E::TwoWayReceived) if s.at_least(S::TwoWay) => *s,
            // DD/LSU-driven progress events out of place: ignored.
            (S::Down | S::Attempt, E::NegotiationDone)
            | (S::Down | S::Attempt, E::ExchangeDone)
            | (S::Down | S::Attempt, E::LoadingDone)
            | (S::TwoWay, E::NegotiationDone)
            | (S::TwoWay, E::ExchangeDone) => self.state,
            (S::Loading, E::ExchangeDone) => S::Loading,
            (S::Full, E::ExchangeDone) => S::Full,
            (s, e) => {
                // Fallthrough: unmatched combinations are no-ops
                // (the spec's tables only define the listed rows).
                let _ = (s, e);
                *s
            }
        };
        self.state = next;
        let _ = from;
        (next, actions)
    }

    /// §10.6: process one received Database Description packet.
    /// Returns the internal events to feed back through `fire` and
    /// whether a reply DD should be sent (the §10.8 obligations).
    pub fn process_dbd(&mut self, pkt: &DbDescription) -> DdResult {
        use NeighborEvent as E;
        let mut events = Vec::new();
        let mut send_reply = false;
        let duplicate = self.last_dd.is_some_and(|(i, m, ms, opt, seq)| {
            i == pkt.init
                && m == pkt.more
                && ms == pkt.master
                && opt == pkt.options.0
                && seq == pkt.dd_sequence
        });

        match self.state {
            NeighborState::Down | NeighborState::Attempt => {
                // §10.6: reject.
                return DdResult::rejected();
            }
            NeighborState::Init => {
                // Fire 2-WayReceived; the caller then re-dispatches
                // in the new state (ExStart here falls through).
                events.push(E::TwoWayReceived);
                return DdResult {
                    events,
                    send_reply: false,
                    accepted: false,
                };
            }
            NeighborState::TwoWay => {
                // §10.6: ignore (DD packets only bring up adjacencies).
                return DdResult::rejected();
            }
            NeighborState::ExStart => {
                let neighbor_id_larger =
                    pkt.lsa_headers.is_empty() && pkt.init && pkt.more && pkt.master;
                // Case 1: I/M/MS set, empty, neighbor's Router ID
                // larger -> we are slave, adopt its DD sequence.
                if neighbor_id_larger && self.peer_id_larger(pkt) {
                    self.master = false;
                    self.dd_sequence = pkt.dd_sequence;
                    self.neighbor_options = Some(pkt.options.0);
                    events.push(E::NegotiationDone);
                    // Slave must reply.
                    send_reply = true;
                } else if !pkt.init && !pkt.master && pkt.dd_sequence == self.dd_sequence {
                    // The slave's acknowledgment of our ExStart DD:
                    // we are master, negotiation done. The master's
                    // next DD (its first description chunk) goes out
                    // one sequence ahead (§10.8: the master
                    // increments; Figure 14's x+1 first full DD).
                    self.master = true;
                    self.dd_sequence = self.dd_sequence.wrapping_add(1);
                    self.neighbor_options = Some(pkt.options.0);
                    events.push(E::NegotiationDone);
                    send_reply = true;
                } else if pkt.init && pkt.more && pkt.master && !self.peer_id_larger(pkt) {
                    // Both claim master; the smaller-ID router
                    // defers: stay in ExStart (our next empty DD
                    // goes out on the RxmtInterval; the peer will
                    // see ours and defer if we are larger).
                    return DdResult::rejected();
                } else {
                    return DdResult::rejected();
                }
            }
            NeighborState::Exchange => {
                if duplicate {
                    // Master discards; slave retransmits its last DD.
                    if !self.master {
                        send_reply = true;
                    }
                    return DdResult {
                        events,
                        send_reply,
                        accepted: false,
                    };
                }
                // MS-bit consistency.
                if pkt.master == self.master {
                    // Both claim the same role: mismatch.
                    if pkt.master {
                        events.push(E::SeqNumberMismatch);
                        return DdResult {
                            events,
                            send_reply: false,
                            accepted: false,
                        };
                    }
                }
                if pkt.init {
                    events.push(E::SeqNumberMismatch);
                    return DdResult {
                        events,
                        send_reply: false,
                        accepted: false,
                    };
                }
                if Some(pkt.options.0) != self.neighbor_options {
                    events.push(E::SeqNumberMismatch);
                    return DdResult {
                        events,
                        send_reply: false,
                        accepted: false,
                    };
                }
                let expected = if self.master {
                    self.dd_sequence
                } else {
                    self.dd_sequence.wrapping_add(1)
                };
                if pkt.dd_sequence != expected {
                    events.push(E::SeqNumberMismatch);
                    return DdResult {
                        events,
                        send_reply: false,
                        accepted: false,
                    };
                }
                // Accept: record and act per master/slave.
                if self.master {
                    self.dd_sequence = self.dd_sequence.wrapping_add(1);
                    send_reply = true;
                    if !pkt.more && self.exchange_send_complete() {
                        events.push(E::ExchangeDone);
                    }
                } else {
                    self.dd_sequence = pkt.dd_sequence;
                    send_reply = true;
                    if !pkt.more && self.exchange_send_complete() {
                        events.push(E::ExchangeDone);
                    }
                }
            }
            NeighborState::Loading | NeighborState::Full => {
                // Only duplicates are legal (§10.6).
                if pkt.options.0 != self.neighbor_options.unwrap_or(pkt.options.0) || pkt.init {
                    events.push(E::SeqNumberMismatch);
                    return DdResult {
                        events,
                        send_reply: false,
                        accepted: false,
                    };
                }
                if duplicate {
                    if !self.master {
                        send_reply = true;
                    }
                } else {
                    events.push(E::SeqNumberMismatch);
                }
                return DdResult {
                    events,
                    send_reply,
                    accepted: false,
                };
            }
        }
        self.last_dd = Some((
            pkt.init,
            pkt.more,
            pkt.master,
            pkt.options.0,
            pkt.dd_sequence,
        ));
        DdResult {
            events,
            send_reply,
            accepted: true,
        }
    }

    /// Whether our own DD sequence has been fully sent — the caller
    /// tracks the summary-list drain; v1 models the "we have sent our
    /// whole description" bookkeeping via this hook (always true when
    /// the DBD summary fits one packet; multi-packet DBDs are the
    /// daemon layer's §10.8 loop).
    fn exchange_send_complete(&self) -> bool {
        !self.summary_pending
    }

    fn peer_id_larger(&self, _pkt: &DbDescription) -> bool {
        // The peer's Router ID comes from the packet header at the
        // daemon layer; threaded here as the comparison closure by
        // process_dbd_with_peer below.
        self.peer_id_larger_value.unwrap_or(false)
    }
}

/// Result of DD processing: internal neighbor events to fire, whether
/// a reply DD is owed, and whether the packet was accepted as the
/// next in sequence.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DdResult {
    pub events: Vec<NeighborEvent>,
    pub send_reply: bool,
    pub accepted: bool,
}

impl DdResult {
    fn rejected() -> Self {
        Self {
            events: vec![],
            send_reply: false,
            accepted: false,
        }
    }
}

/// §10.5: Hello receive processing. Returns the events to fire (in
/// order), or an error naming the parameter mismatch that drops the
/// packet.
pub fn process_hello(
    hello: &Hello,
    own: &HelloParams,
    own_router_id: crate::lsa::RouterId,
    packet_router_id: crate::lsa::RouterId,
    p2p: bool,
) -> Result<Vec<NeighborEvent>, crate::error::OspfError> {
    use crate::error::OspfError;
    // §10.5: Network Mask, HelloInterval and RouterDeadInterval must
    // match the interface config (mask ignored on p2p/virtual links).
    if !p2p && hello.network_mask != own.network_mask {
        return Err(OspfError::Neighbor(format!(
            "network mask mismatch: got {} want {}",
            hello.network_mask, own.network_mask
        )));
    }
    if hello.hello_interval != own.hello_interval {
        return Err(OspfError::Neighbor(format!(
            "HelloInterval mismatch: got {} want {}",
            hello.hello_interval, own.hello_interval
        )));
    }
    if hello.router_dead_interval != own.router_dead_interval {
        return Err(OspfError::Neighbor(format!(
            "RouterDeadInterval mismatch: got {} want {}",
            hello.router_dead_interval, own.router_dead_interval
        )));
    }
    // E-bit must match the area's ExternalRoutingCapability.
    if hello.options.e_bit() != own.e_capable {
        return Err(OspfError::Neighbor(
            "E-bit mismatch with area external routing capability".into(),
        ));
    }
    let _ = packet_router_id;
    // Every Hello fires HelloReceived; then the 2-way check.
    let mut events = vec![NeighborEvent::HelloReceived];
    if hello.neighbors.contains(&own_router_id) {
        events.push(NeighborEvent::TwoWayReceived);
    } else {
        events.push(NeighborEvent::OneWayReceived);
    }
    Ok(events)
}

/// The receiving interface's Hello parameters (§10.5's checks) plus
/// the area's external capability.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HelloParams {
    pub network_mask: std::net::Ipv4Addr,
    pub hello_interval: u16,
    pub router_dead_interval: u32,
    /// Area ExternalRoutingCapability (E-bit).
    pub e_capable: bool,
    /// Point-to-point / virtual link: mask ignored on receive.
    pub p2p: bool,
}

/// §13 steps 1-3 receive-side admission, derived from the area type:
/// what LSA classes this area accepts. Stub areas discard
/// AS-external-LSAs (§13 step 3); FRR's totally-stubby
/// (`no-summary`) discards the summary LSAs too.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum AreaAdmission {
    #[default]
    Normal,
    /// `area <id> stub`: no type-5s (§3.6/§13 step 3).
    Stub,
    /// `area <id> stub no-summary`: no type-5s and no type-3/4s (FRR's
    /// totally stubby extension).
    StubNoSummary,
}

impl AreaAdmission {
    /// §13 step 3: "If the area is a stub area and the LSA is an
    /// AS-external-LSA, then the LSA is not flooded further" — the
    /// receiver-side form discards it on arrival.
    pub fn admits(self, ls_type: crate::lsa::LsaType) -> bool {
        match self {
            AreaAdmission::Normal => true,
            AreaAdmission::Stub => ls_type != crate::lsa::LsaType::AS_EXTERNAL,
            AreaAdmission::StubNoSummary => !matches!(
                ls_type,
                crate::lsa::LsaType::AS_EXTERNAL
                    | crate::lsa::LsaType::SUMMARY_NETWORK
                    | crate::lsa::LsaType::SUMMARY_ASBR
            ),
        }
    }
}

/// §13 flooding: what to do with one received LSA.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FloodAction {
    /// Step 5(b)/(d): flood the new LSA out other interfaces and
    /// install it; a schedule SPF may follow (contents changed).
    InstallAndFlood { changed: bool },
    /// Step 4: MaxAge and no instance and nobody syncing —
    /// acknowledge and discard.
    AckAndDiscard,
    /// Step 7: same instance — acknowledge (or treat as implied ack
    /// when it was on our retransmission list).
    SameInstance { on_rxmt_list: bool },
    /// Step 8: our copy is more recent — send the database copy
    /// straight back to the neighbor.
    SendDatabaseCopy(Lsa),
    /// Step 6: the LSA is on the sending neighbor's request list —
    /// BadLSReq (restart the exchange).
    BadLSReq,
    /// Steps 1-3: discard (bad checksum / unknown type / type 5 into
    /// a stub area) or step 5(a) MinLSArrival rejection (no ack).
    Discard { silent: bool },
}

/// §13 steps for a single received LSA. `neighbor_syncing` carries
/// whether any adjacency is in Exchange/Loading; `admission` the
/// area-type admission rules; `on_request_list`/`on_rxmt_list`
/// mirror the neighbor lists (the caller owns them).
pub fn flood_step(
    lsa_bytes: &[u8],
    lsdb: &mut Lsdb,
    now: u64,
    neighbor_syncing: bool,
    admission: AreaAdmission,
    on_request_list: bool,
    on_rxmt_list: bool,
) -> FloodAction {
    // (1) Validate the LS checksum.
    let lsa = match Lsa::decode(lsa_bytes) {
        Ok(l) => l,
        Err(_) => return FloodAction::Discard { silent: true },
    };
    // (2) Unknown LS type.
    if !lsa.header.ls_type.is_known_v2() {
        return FloodAction::Discard { silent: true };
    }
    // (3) Area-type admission: AS-external into a stub area (§3.6);
    // summaries into a totally-stubby area (FRR's no-summary).
    if !admission.admits(lsa.header.ls_type) {
        return FloodAction::Discard { silent: true };
    }
    // (4) MaxAge with no instance and nobody syncing: ack + discard.
    if lsa.header.is_max_age() && !lsdb.contains(&lsa.key()) && !neighbor_syncing {
        return FloodAction::AckAndDiscard;
    }
    // (5)-(8) against the database copy.
    let key = lsa.key();
    let db = lsdb.get(&key).map(|e| e.lsa.clone());
    match db {
        None => match lsdb.install(lsa.clone(), true, now) {
            InstallOutcome::RejectedMinLsArrival => FloodAction::Discard { silent: true },
            _ => FloodAction::InstallAndFlood { changed: true },
        },
        Some(db_lsa) => match lsdb::newer_than(&lsa.header, &db_lsa.header) {
            lsdb::Which::FirstNewer => match lsdb.install(lsa.clone(), true, now) {
                InstallOutcome::RejectedMinLsArrival => FloodAction::Discard { silent: true },
                outcome => FloodAction::InstallAndFlood {
                    changed: matches!(outcome, InstallOutcome::Installed { changed: true }),
                },
            },
            // (6) an instance on the sender's request list is an
            // exchange error — checked before the same-instance
            // acknowledgment (§13's step order).
            _ if on_request_list => FloodAction::BadLSReq,
            lsdb::Which::Identical => {
                if lsa.header.seq == db_lsa.header.seq {
                    // (7) same instance: implied ack if awaited.
                    FloodAction::SameInstance { on_rxmt_list }
                } else {
                    // Identical by age dispersion but a different
                    // instance: nothing in §13 replaces the copy.
                    FloodAction::SameInstance {
                        on_rxmt_list: false,
                    }
                }
            }
            lsdb::Which::SecondNewer => {
                // (8) send the database copy back (unless it is the
                // MaxSequenceNumber wrap flush-in-progress).
                if db_lsa.header.is_max_age() && db_lsa.header.seq == crate::MAX_SEQUENCE_NUMBER {
                    return FloodAction::Discard { silent: true };
                }
                FloodAction::SendDatabaseCopy(db_lsa)
            }
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::lsa::{
        LinkStateId, LsaBody, LsaHeader, LsaType, Options, RouterId, RouterLink, RouterLsa,
        INITIAL_SEQUENCE_NUMBER,
    };
    use crate::packet::LsAck;
    use std::net::Ipv4Addr;

    fn ip(s: &str) -> Ipv4Addr {
        s.parse().unwrap()
    }

    fn rid(s: &str) -> RouterId {
        RouterId::from_ipv4(ip(s))
    }

    fn params() -> HelloParams {
        HelloParams {
            network_mask: ip("255.255.255.0"),
            hello_interval: 10,
            router_dead_interval: 40,
            e_capable: true,
            p2p: true,
        }
    }

    fn hello_for(seen: &[&str]) -> Hello {
        Hello {
            network_mask: ip("255.255.255.0"),
            hello_interval: 10,
            options: Options(0x02),
            router_priority: 1,
            router_dead_interval: 40,
            designated_router: Ipv4Addr::UNSPECIFIED,
            backup_designated_router: Ipv4Addr::UNSPECIFIED,
            neighbors: seen.iter().map(|s| rid(s)).collect(),
        }
    }

    // ---- §10.5 hello processing ----------------------------------

    #[test]
    fn hello_two_way_and_one_way() {
        // Seeing ourselves in the list: 2-WayReceived.
        let ev = process_hello(
            &hello_for(&["1.1.1.1"]),
            &params(),
            rid("1.1.1.1"),
            rid("2.2.2.2"),
            true,
        )
        .unwrap();
        assert_eq!(
            ev,
            vec![NeighborEvent::HelloReceived, NeighborEvent::TwoWayReceived]
        );
        // Not listed: 1-WayReceived.
        let ev = process_hello(
            &hello_for(&["9.9.9.9"]),
            &params(),
            rid("1.1.1.1"),
            rid("2.2.2.2"),
            true,
        )
        .unwrap();
        assert_eq!(
            ev,
            vec![NeighborEvent::HelloReceived, NeighborEvent::OneWayReceived]
        );
    }

    #[test]
    fn hello_parameter_mismatches_drop() {
        let mut h = hello_for(&[]);
        h.hello_interval = 9;
        assert!(process_hello(&h, &params(), rid("1.1.1.1"), rid("2.2.2.2"), true).is_err());
        let mut h = hello_for(&[]);
        h.router_dead_interval = 39;
        assert!(process_hello(&h, &params(), rid("1.1.1.1"), rid("2.2.2.2"), true).is_err());
        // Mask mismatch matters on broadcast, ignored on p2p (§10.5).
        let mut h = hello_for(&[]);
        h.network_mask = ip("255.255.0.0");
        let mut bcast = params();
        bcast.p2p = false;
        assert!(process_hello(&h, &bcast, rid("1.1.1.1"), rid("2.2.2.2"), false).is_err());
        assert!(process_hello(&h, &params(), rid("1.1.1.1"), rid("2.2.2.2"), true).is_ok());
        // E-bit mismatch with the area.
        let mut h = hello_for(&[]);
        h.options = Options(0x00);
        assert!(process_hello(&h, &params(), rid("1.1.1.1"), rid("2.2.2.2"), true).is_err());
    }

    // ---- §10.3 table rows ------------------------------------------

    fn fsm() -> NeighborFsm {
        NeighborFsm::new(rid("1.1.1.1"))
    }

    #[test]
    fn down_hello_init_and_timer() {
        let mut n = fsm();
        let (s, a) = n.fire(NeighborEvent::HelloReceived);
        assert_eq!(s, NeighborState::Init);
        assert_eq!(a, vec![NeighborAction::RestartInactivityTimer]);
        // Init or greater: same, restart only.
        let (s, a) = n.fire(NeighborEvent::HelloReceived);
        assert_eq!(s, NeighborState::Init);
        assert_eq!(a, vec![NeighborAction::RestartInactivityTimer]);
    }

    #[test]
    fn start_on_nbma_reaches_attempt() {
        let mut n = fsm();
        let (s, a) = n.fire(NeighborEvent::Start);
        assert_eq!(s, NeighborState::Attempt);
        assert_eq!(a, vec![NeighborAction::RestartInactivityTimer]);
        let (s, _) = n.fire(NeighborEvent::HelloReceived);
        assert_eq!(s, NeighborState::Init);
    }

    #[test]
    fn init_two_way_adjacency_decision() {
        // §10.3 Init + 2-WayReceived with AdjOk(no): 2-Way.
        let mut n = fsm();
        n.fire(NeighborEvent::HelloReceived);
        let (s, _) = n.fire(NeighborEvent::TwoWayReceived);
        assert_eq!(s, NeighborState::Init, "the decision event is AdjOk");
        let (s, a) = n.fire(NeighborEvent::AdjOk(false));
        assert_eq!(s, NeighborState::TwoWay);
        assert!(a.is_empty());
        // 2-Way + AdjOk(yes): ExStart, DD bumped, empty I/M/MS DD.
        let (s, a) = n.fire(NeighborEvent::AdjOk(true));
        assert_eq!(s, NeighborState::ExStart);
        assert_eq!(
            a,
            vec![NeighborAction::SendEmptyDd {
                init: true,
                more: true,
                master: true
            }]
        );
    }

    #[test]
    fn killnbr_initytimer_lldown_force_down() {
        for ev in [
            NeighborEvent::KillNbr,
            NeighborEvent::InactivityTimer,
            NeighborEvent::LLDown,
        ] {
            let mut n = fsm();
            n.fire(NeighborEvent::HelloReceived);
            n.fire(NeighborEvent::AdjOk(true)); // ExStart
            let (s, a) = n.fire(ev);
            assert_eq!(s, NeighborState::Down);
            assert!(a.contains(&NeighborAction::ClearLists));
            assert!(a.contains(&NeighborAction::StopInactivityTimer));
            assert!(a.contains(&NeighborAction::AdjacencyDown));
        }
    }

    #[test]
    fn one_way_from_two_way_clears_lists() {
        let mut n = fsm();
        n.fire(NeighborEvent::HelloReceived);
        n.fire(NeighborEvent::AdjOk(false));
        n.fire(NeighborEvent::AdjOk(true)); // ExStart
        let (s, a) = n.fire(NeighborEvent::OneWayReceived);
        assert_eq!(s, NeighborState::Init);
        assert!(a.contains(&NeighborAction::ClearLists));
        // From Init: 1-Way is a no-op.
        let (s, a) = n.fire(NeighborEvent::OneWayReceived);
        assert_eq!(s, NeighborState::Init);
        assert!(a.is_empty());
    }

    #[test]
    fn seq_mismatch_and_badlsreq_re_establish() {
        for ev in [NeighborEvent::SeqNumberMismatch, NeighborEvent::BadLSReq] {
            let mut n = fsm();
            n.fire(NeighborEvent::HelloReceived);
            n.fire(NeighborEvent::AdjOk(true));
            n.fire(NeighborEvent::NegotiationDone); // Exchange
            let seq = n.dd_sequence;
            let (s, a) = n.fire(ev);
            assert_eq!(s, NeighborState::ExStart, "tear down and re-establish");
            assert!(a.contains(&NeighborAction::ClearLists));
            assert_eq!(n.dd_sequence, seq + 1);
            assert!(a.contains(&NeighborAction::SendEmptyDd {
                init: true,
                more: true,
                master: true
            }));
        }
    }

    #[test]
    fn adjacency_lifecycle_to_full() {
        let mut n = fsm();
        n.fire(NeighborEvent::HelloReceived);
        n.fire(NeighborEvent::AdjOk(true));
        let (s, a) = n.fire(NeighborEvent::NegotiationDone);
        assert_eq!(s, NeighborState::Exchange);
        assert_eq!(a, vec![NeighborAction::BuildSummaryList]);
        let (s2, _) = n.fire(NeighborEvent::ExchangeDone);
        assert_eq!(s2, NeighborState::Loading);
        let (s3, a3) = n.fire(NeighborEvent::LoadingDone);
        assert_eq!(s3, NeighborState::Full);
        assert_eq!(a3, vec![NeighborAction::AdjacencyUp]);
    }

    #[test]
    fn adjok_no_destroys_partial_adjacency() {
        let mut n = fsm();
        n.fire(NeighborEvent::HelloReceived);
        n.fire(NeighborEvent::AdjOk(true));
        n.fire(NeighborEvent::NegotiationDone);
        let (s, a) = n.fire(NeighborEvent::AdjOk(false));
        assert_eq!(s, NeighborState::TwoWay);
        assert!(a.contains(&NeighborAction::ClearLists));
        assert!(a.contains(&NeighborAction::AdjacencyDown));
    }

    // ---- §10.6/§10.8: the Figure 14 exchange ----------------------

    fn dd(seq: u32, init: bool, more: bool, master: bool) -> DbDescription {
        DbDescription {
            interface_mtu: 1500,
            options: Options(0x02),
            init,
            more,
            master,
            dd_sequence: seq,
            lsa_headers: vec![],
        }
    }

    #[test]
    fn figure14_master_slave_exchange() {
        // §10.10: RT1 (us, smaller ID) and RT2 (peer, larger ID).
        // RT1 goes ExStart asserting master; RT2's larger ID wins.
        let mut rt1 = NeighborFsm::new(rid("1.1.1.1"));
        rt1.peer_id_larger_value = Some(true);
        rt1.fire(NeighborEvent::HelloReceived);
        rt1.fire(NeighborEvent::TwoWayReceived);
        rt1.fire(NeighborEvent::AdjOk(true)); // ExStart, sends empty DD I/M/MS

        // RT2's ExStart DD (seq=y, I/M/MS): we become slave, adopt y.
        let r = rt1.process_dbd(&dd(500, true, true, true));
        assert!(r.accepted);
        assert!(!rt1.master, "the larger Router ID is master");
        assert_eq!(rt1.dd_sequence, 500);
        assert!(r.send_reply, "the slave must reply");
        let (s, _) = rt1.fire(NeighborEvent::NegotiationDone);
        assert_eq!(s, NeighborState::Exchange);

        // Master polls: seq=501, M=1, MS=1 (the slave expects seq+1).
        let r = rt1.process_dbd(&dd(501, false, true, true));
        assert!(r.accepted);
        assert_eq!(rt1.dd_sequence, 501, "slave takes the master's seq");
        assert!(r.send_reply);
        // ... eventually the master's final DD has M=0; the slave's
        // reply also M=0 -> ExchangeDone (slave generates it first).
        let r = rt1.process_dbd(&dd(502, false, false, true));
        assert!(r.accepted);
        assert_eq!(r.events, vec![NeighborEvent::ExchangeDone]);
        rt1.fire(NeighborEvent::ExchangeDone);
        let (s, _) = rt1.fire(NeighborEvent::LoadingDone);
        assert_eq!(s, NeighborState::Full);
    }

    #[test]
    fn master_side_sequencing_and_duplicates() {
        // The master's view: the slave's DD must echo our sequence.
        let mut m = NeighborFsm::new(rid("9.9.9.9"));
        m.peer_id_larger_value = Some(false);
        m.fire(NeighborEvent::HelloReceived);
        m.fire(NeighborEvent::AdjOk(true));
        // Slave (smaller ID) sends its ExStart empty DD first; we are
        // larger, so we wait for the slave to defer — model the
        // slave's acknowledgment of our empty DD instead.
        let r = m.process_dbd(&dd(1, false, false, false));
        assert!(r.accepted);
        assert!(m.master);
        // The master's first description DD goes one ahead (§10.8 /
        // Figure 14: negotiation at x, first full DD at x+1) — the
        // Day-2 correction to the ExStart case-2 bump.
        assert_eq!(m.dd_sequence, 2);
        m.fire(NeighborEvent::NegotiationDone);
        // Exchange: master expects its own seq echoed; wrong seq is a
        // SeqNumberMismatch.
        let bad = m.process_dbd(&dd(99, false, true, false));
        assert!(!bad.accepted);
        assert_eq!(bad.events, vec![NeighborEvent::SeqNumberMismatch]);
        // The correct echo (at the bumped sequence) is accepted and
        // the master bumps again for its next round.
        let ok = m.process_dbd(&dd(2, false, true, false));
        assert!(ok.accepted);
        assert_eq!(m.dd_sequence, 3);
        // A duplicate of the last accepted: master discards silently.
        let dup = m.process_dbd(&dd(2, false, true, false));
        assert!(!dup.accepted);
        assert!(!dup.send_reply);
        assert!(dup.events.is_empty());
    }

    #[test]
    fn dbd_rejected_in_wrong_states() {
        let mut n = fsm();
        // Down and Attempt: reject (§10.6).
        assert!(!n.process_dbd(&dd(1, true, true, true)).accepted);
        n.fire(NeighborEvent::HelloReceived);
        n.fire(NeighborEvent::AdjOk(false));
        // 2-Way: ignore.
        assert!(!n.process_dbd(&dd(1, true, true, true)).accepted);
        // Init: the 2-WayReceived event fires, packet re-processed.
        let mut n2 = fsm();
        n2.fire(NeighborEvent::HelloReceived);
        let r = n2.process_dbd(&dd(1, true, true, true));
        assert_eq!(r.events, vec![NeighborEvent::TwoWayReceived]);
    }

    #[test]
    fn exchange_options_change_is_mismatch() {
        // §10.6: a changed Options field -> SeqNumberMismatch.
        let mut n = fsm();
        n.peer_id_larger_value = Some(true);
        n.fire(NeighborEvent::HelloReceived);
        n.fire(NeighborEvent::AdjOk(true));
        n.process_dbd(&dd(500, true, true, true));
        n.fire(NeighborEvent::NegotiationDone);
        let mut pkt = dd(501, false, true, true);
        pkt.options = Options(0x06); // E + MC suddenly
        let r = n.process_dbd(&pkt);
        assert!(!r.accepted);
        assert_eq!(r.events, vec![NeighborEvent::SeqNumberMismatch]);
        // The I bit mid-exchange likewise.
        let mut pkt = dd(502, true, true, true);
        pkt.options = Options(0x02);
        let r = n.process_dbd(&pkt);
        assert!(!r.accepted);
        assert_eq!(r.events, vec![NeighborEvent::SeqNumberMismatch]);
    }

    // ---- §13 flooding ----------------------------------------------

    fn lsa(seq: u32, age: u16) -> Lsa {
        Lsa {
            header: LsaHeader {
                ls_age: age,
                options: Options(0x02),
                ls_type: LsaType::ROUTER,
                link_state_id: LinkStateId::from_ipv4(ip("2.2.2.2")),
                adv_router: rid("2.2.2.2"),
                seq,
                checksum: 0x1234,
                length: 0,
            },
            body: LsaBody::Router(RouterLsa {
                v_bit: false,
                e_bit: false,
                b_bit: false,
                links: vec![RouterLink {
                    link_id: LinkStateId::from_ipv4(ip("10.0.0.0")),
                    link_data: 0xffff_ff00,
                    link_type: crate::lsa::LinkType::Stub,
                    metric: 1,
                    tos: vec![],
                }],
            }),
        }
    }

    fn db() -> Lsdb {
        Lsdb::new()
    }

    #[test]
    fn flood_steps_1_to_4() {
        // (1) bad checksum: silent discard.
        let mut bytes = lsa(INITIAL_SEQUENCE_NUMBER, 1).encode();
        bytes[25] ^= 0x80;
        assert_eq!(
            flood_step(
                &bytes,
                &mut db(),
                0,
                false,
                AreaAdmission::Normal,
                false,
                false
            ),
            FloodAction::Discard { silent: true }
        );
        // (2) unknown LS type — encode a valid router LSA then swap
        // the type octet and repair length/checksum is not possible
        // without body revalidation; the decode rejects it via the
        // header's known-type check.
        let mut bytes = lsa(INITIAL_SEQUENCE_NUMBER, 1).encode();
        bytes[3] = 7;
        // (checksum now invalid -> still a silent discard, same bucket)
        assert_eq!(
            flood_step(
                &bytes,
                &mut db(),
                0,
                false,
                AreaAdmission::Normal,
                false,
                false
            ),
            FloodAction::Discard { silent: true }
        );
        // (3) type-5 into a stub area: discard.
        let ext = Lsa {
            header: LsaHeader {
                ls_age: 1,
                options: Options(0x02),
                ls_type: LsaType::AS_EXTERNAL,
                link_state_id: LinkStateId::from_ipv4(ip("198.51.100.0")),
                adv_router: rid("3.3.3.3"),
                seq: INITIAL_SEQUENCE_NUMBER,
                checksum: 0,
                length: 0,
            },
            body: LsaBody::AsExternal(crate::lsa::AsExternalLsa {
                mask: ip("255.255.255.0"),
                e_bit: true,
                metric: 20,
                forwarding_address: Ipv4Addr::UNSPECIFIED,
                external_route_tag: 0,
                tos: vec![],
            }),
        }
        .encode();
        assert_eq!(
            flood_step(&ext, &mut db(), 0, false, AreaAdmission::Stub, false, false),
            FloodAction::Discard { silent: true }
        );
        // (4) MaxAge, no instance, nobody syncing: ack and discard.
        let bytes = lsa(INITIAL_SEQUENCE_NUMBER, crate::MAX_AGE).encode();
        assert_eq!(
            flood_step(
                &bytes,
                &mut db(),
                0,
                false,
                AreaAdmission::Normal,
                false,
                false
            ),
            FloodAction::AckAndDiscard
        );
    }

    #[test]
    fn flood_step5_install_flood_and_min_ls_arrival() {
        let mut d = db();
        let bytes = lsa(INITIAL_SEQUENCE_NUMBER, 1).encode();
        assert_eq!(
            flood_step(
                &bytes,
                &mut d,
                100,
                false,
                AreaAdmission::Normal,
                false,
                false
            ),
            FloodAction::InstallAndFlood { changed: true }
        );
        // A newer instance within MinLSArrival: silent discard (5a).
        let newer = lsa(INITIAL_SEQUENCE_NUMBER + 1, 1).encode();
        assert_eq!(
            flood_step(
                &newer,
                &mut d,
                100,
                false,
                AreaAdmission::Normal,
                false,
                false
            ),
            FloodAction::Discard { silent: true }
        );
        // After the window: installed; same body => not "changed".
        assert_eq!(
            flood_step(
                &newer,
                &mut d,
                200,
                false,
                AreaAdmission::Normal,
                false,
                false
            ),
            FloodAction::InstallAndFlood { changed: false }
        );
    }

    #[test]
    fn flood_step6_7_8() {
        let mut d = db();
        // Seed the database with seq N+1.
        let newer = lsa(INITIAL_SEQUENCE_NUMBER + 1, 1).encode();
        flood_step(
            &newer,
            &mut d,
            0,
            false,
            AreaAdmission::Normal,
            false,
            false,
        );
        // The same instance (seq N+1) again: step 7 — implied ack
        // when it sits on our retransmission list.
        assert_eq!(
            flood_step(
                &newer,
                &mut d,
                10,
                false,
                AreaAdmission::Normal,
                false,
                true
            ),
            FloodAction::SameInstance { on_rxmt_list: true }
        );
        // Step 6 fires FIRST for a request-listed LSA (§13 order):
        // even the same instance is a BadLSReq when the sender had
        // it on its request list.
        assert_eq!(
            flood_step(
                &newer,
                &mut d,
                10,
                false,
                AreaAdmission::Normal,
                true,
                false
            ),
            FloodAction::BadLSReq
        );
        // (8) older instance (seq N): send the database copy back.
        let older = lsa(INITIAL_SEQUENCE_NUMBER, 1).encode();
        match flood_step(
            &older,
            &mut d,
            10,
            false,
            AreaAdmission::Normal,
            false,
            false,
        ) {
            FloodAction::SendDatabaseCopy(l) => {
                assert_eq!(l.header.seq, INITIAL_SEQUENCE_NUMBER + 1)
            }
            other => panic!("expected SendDatabaseCopy, got {other:?}"),
        }
    }

    #[test]
    fn lsack_headers_acknowledge() {
        // §A.3.6: an LSAck echoes LSA headers.
        let l = lsa(INITIAL_SEQUENCE_NUMBER, 1);
        let bytes = l.encode();
        let h = Lsa::decode_header(&bytes[..20]).unwrap();
        let ack = LsAck { headers: vec![h] };
        assert_eq!(ack.headers[0].adv_router, rid("2.2.2.2"));
    }
}
