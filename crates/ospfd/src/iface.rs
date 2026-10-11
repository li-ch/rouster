//! The interface-level state machine (RFC 2328 §9) and the
//! Designated Router election (§9.4).
//!
//! Pure and clock-injected, the neighbor FSM's conventions: the
//! §9.3 table as `fire(event) -> actions`, and §9.4's election as a
//! pure function over the neighbor snapshot. The AF-generic seam:
//! nothing in §9 touches address length — the v6 differences
//! (all-routers addresses, no network mask in hellos) live at the
//! transport/hello layer.
//!
//! The election implements §9.4's steps (1)-(5) verbatim, including
//! step (4)'s repeat with our own claims updated to the first
//! round's result (the RFC's "X will no longer be eligible for
//! Backup Designated Router election"). The resulting lone-router
//! outcome — DR self, BDR 0.0.0.0 — was probed against the FRR
//! 10.2.2 oracle (`ospf_ism.c:ospf_dr_election`, one repeat, self
//! excluded from BDR election once it declares DR): "State DR ...
//! No backup designated router on this network".
//!
//! v1 scope disclosure: the daemon drives PointToPoint and
//! broadcast interfaces; NBMA (§C.3) is §Deferred with the
//! unicast-hello machinery it requires.

use crate::lsa::RouterId;
use std::net::Ipv4Addr;

/// §9.1 interface states.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum InterfaceState {
    Down,
    /// The interface is a loopback or has no address.
    Loopback,
    /// Broadcast network, waiting for the WaitTimer to expire
    /// (§9.3's DR election deferral).
    Waiting,
    /// Point-to-point or virtual link — no DR election runs.
    PointToPoint,
    /// The designated router on a broadcast network.
    Dr,
    /// The backup designated router.
    Backup,
    /// Neither DR nor BDR.
    DrOther,
}

impl InterfaceState {
    pub fn name(self) -> &'static str {
        match self {
            Self::Down => "Down",
            Self::Loopback => "Loopback",
            Self::Waiting => "Waiting",
            Self::PointToPoint => "PointToPoint",
            Self::Dr => "DR",
            Self::Backup => "Backup",
            Self::DrOther => "DR Other",
        }
    }
}

/// §9.2 interface events.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InterfaceEvent {
    /// Lower layer says the interface is usable.
    InterfaceUp,
    /// The WaitTimer (RouterDeadInterval) expired.
    WaitTimer,
    /// A hello claiming a BDR other than 0.0.0.0 was seen.
    BackupSeen,
    /// A change in the set of bidirectional neighbors (state change
    /// to/from Full, priority change, or a new DR claim) — the
    /// §9.5/§12.4.2 re-election trigger.
    NeighborChange,
    /// Loop detected on the interface.
    LoopInd,
    /// The loop went away.
    UnloopInd,
    /// Lower layer says the interface is unusable.
    InterfaceDown,
}

/// Actions the §9.3 entries prescribe.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InterfaceAction {
    /// Start (or restart) the Hello timer and emit the first Hello.
    StartHello,
    /// Start the WaitTimer.
    StartWaitTimer,
    /// Elect DR/BDR (§9.4) — the resulting role changes drive
    /// adjacency re-evaluation (§10.4 AdjOk) and network-LSA
    /// origination (§12.4.2).
    ElectDr,
    /// Interface left the usable set: neighbors down, timers off.
    KillNeighbors,
}

/// The per-interface machine. `p2p` pins the network type
/// (§C.3): InterfaceUp lands directly in PointToPoint, skipping the
/// WaitTimer/election arm entirely (§9.3's "otherwise" branch).
/// `priority` is our §C.3 Router Priority: a broadcast interface
/// with priority 0 enters DR Other at InterfaceUp (§9.3: "if the
/// router is not eligible to become Designated Router the interface
/// state transitions to DR Other").
#[derive(Debug, Clone)]
pub struct InterfaceFsm {
    pub state: InterfaceState,
    pub p2p: bool,
    pub priority: u8,
}

impl InterfaceFsm {
    pub fn new(p2p: bool) -> Self {
        Self {
            state: InterfaceState::Down,
            p2p,
            priority: 1,
        }
    }

    pub fn new_with_priority(p2p: bool, priority: u8) -> Self {
        Self {
            state: InterfaceState::Down,
            p2p,
            priority,
        }
    }

    /// Fire one §9.3 event; returns the resulting state (unchanged
    /// where the table says so) and the prescribed actions. The
    /// Waiting rows' `ElectDr` actions leave the state Waiting —
    /// §9.4 steps (5)/(7) then set DR/Backup/DR Other (the caller
    /// applies [`crate::iface::elect_dr`]'s outcome).
    pub fn fire(&mut self, event: InterfaceEvent) -> (InterfaceState, Vec<InterfaceAction>) {
        use InterfaceAction as A;
        use InterfaceEvent as E;
        use InterfaceState as S;
        let mut actions = Vec::new();
        let next = match (&self.state, event) {
            // §9.3, InterfaceUp row: Down -> hello starts; p2p ->
            // PointToPoint; broadcast-eligible -> Waiting (WaitTimer);
            // broadcast-ineligible (priority 0) -> DR Other.
            (S::Down, E::InterfaceUp) => {
                actions.push(A::StartHello);
                if self.p2p {
                    S::PointToPoint
                } else if self.priority == 0 {
                    S::DrOther
                } else {
                    actions.push(A::StartWaitTimer);
                    S::Waiting
                }
            }
            // §9.3, WaitTimer row: Waiting -> elect, per the
            // network type.
            (S::Waiting, E::WaitTimer) => {
                actions.push(A::ElectDr);
                S::Waiting // resolved by the election (§9.4.4)
            }
            // §9.3, BackupSeen row: Waiting -> elect early.
            (S::Waiting, E::BackupSeen) => {
                actions.push(A::ElectDr);
                S::Waiting
            }
            // §9.3, NeighborChange row: must be evaluated by the
            // DR/BDR/DR Other (not Waiting).
            (S::Dr | S::Backup | S::DrOther, E::NeighborChange) => {
                actions.push(A::ElectDr);
                self.state
            }
            // §9.3, LoopInd row: any non-Down/Loopback -> Loopback,
            // hello suppressed.
            (S::Waiting | S::PointToPoint | S::Dr | S::Backup | S::DrOther, E::LoopInd) => {
                S::Loopback
            }
            // §9.3, UnloopInd row: Loopback -> the network-type
            // state again, hello resumes.
            (S::Loopback, E::UnloopInd) => {
                actions.push(A::StartHello);
                if self.p2p {
                    S::PointToPoint
                } else if self.priority == 0 {
                    S::DrOther
                } else {
                    actions.push(A::StartWaitTimer);
                    S::Waiting
                }
            }
            // §9.3, InterfaceDown row: any non-Down -> Down.
            (
                S::Waiting | S::PointToPoint | S::Dr | S::Backup | S::DrOther | S::Loopback,
                E::InterfaceDown,
            ) => {
                actions.push(A::KillNeighbors);
                S::Down
            }
            // No-ops the table leaves undefined: Waiting receiving
            // NeighborChange (§9.3: "the event should be disregarded
            // if the state is Waiting").
            (S::Waiting, E::NeighborChange) => self.state,
            // Loopback absorbs everything but UnloopInd/InterfaceDown.
            (S::Loopback, _) => self.state,
            // Down absorbs everything but InterfaceUp.
            (S::Down, _) => self.state,
            // The DR/Backup/DROther rows for WaitTimer/BackupSeen are
            // not defined (the wait phase is over); PointToPoint has
            // no election events.
            (_, _) => self.state,
        };
        self.state = next;
        (next, actions)
    }
}

impl Default for InterfaceFsm {
    fn default() -> Self {
        Self::new(true)
    }
}

/// One neighbor's contribution to the §9.4 election inputs — the
/// fields Hello packets carry (§A.3.2) plus the §10.1 state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ElectionNeighbor {
    pub router_id: RouterId,
    /// The neighbor's address on this network (its DR/BDR claims
    /// name addresses, not Router IDs, §A.3.2).
    pub address: Ipv4Addr,
    /// 0 = ineligible (§9.4: only priority > 0 routers are
    /// eligible).
    pub priority: u8,
    /// The DR this neighbor claims.
    pub dr: Ipv4Addr,
    /// The BDR this neighbor claims.
    pub bdr: Ipv4Addr,
}

/// The §9.4 election outcome.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ElectionOutcome {
    pub dr: Ipv4Addr,
    pub bdr: Ipv4Addr,
    /// Our resulting role (§9.4 step 5).
    pub role: InterfaceState,
    /// Step (7)'s signal: the DR identity changed → adjacencies on
    /// this interface must be re-evaluated (AdjOK? on every
    /// neighbor ≥ 2-Way).
    pub dr_changed: bool,
    /// Step (7)'s signal: the BDR identity changed.
    pub bdr_changed: bool,
}

/// Whether a router is currently declaring itself DR/BDR in its
/// hellos (§9.4's "listing themselves ... in their Hello Packets"):
/// the claim names its own interface address, and 0.0.0.0 is "no
/// claim" (§9.4's initialization).
fn declares_dr(n: &ElectionNeighbor) -> bool {
    n.dr != Ipv4Addr::UNSPECIFIED && n.dr == n.address
}

fn declares_bdr(n: &ElectionNeighbor) -> bool {
    n.bdr != Ipv4Addr::UNSPECIFIED && n.bdr == n.address
}

/// §9.4's electing function, steps (1)-(5).
///
/// Inputs: `own` is ourselves (address, priority, and the DR/BDR we
/// are currently claiming in our hellos); `neighbors` is every
/// bidirectional (state ≥ 2-Way, §9.4's opening) neighbor's claim
/// snapshot; `prev` is the interface's current (DR, BDR) — the
/// values this election may replace (§9.4 step 1 notes them for
/// the step-7 comparison; before the first election they are
/// 0.0.0.0, §9.4's initialization).
///
/// `own` is the caller's live claim state, so the step-(4) repeat
/// runs with our claims updated to the first round's result ("if
/// Router X is now the Designated Router, when step 2 is repeated X
/// will no longer be eligible for Backup Designated Router
/// election") — one repeat, exactly FRR 10.2.2's
/// `ospf_dr_election` shape.
pub fn elect_dr(
    own: ElectionNeighbor,
    neighbors: &[ElectionNeighbor],
    prev: (Ipv4Addr, Ipv4Addr),
) -> ElectionOutcome {
    /// §9.4.1/§9.4.2's comparison: highest Router Priority first,
    /// the largest Router ID breaking ties.
    fn rank(n: &ElectionNeighbor) -> (u8, RouterId) {
        (n.priority, n.router_id)
    }
    /// Steps (2)+(3) over one claim snapshot. The eligible set is
    /// ourselves plus the priority > 0 neighbors (§9.4's "Discard
    /// all routers ... having Router Priority of 0"); the ≥ 2-Way
    /// filter is the caller's (the snapshot IS the bidirectional
    /// set).
    fn elect_once(own: &ElectionNeighbor, neighbors: &[ElectionNeighbor]) -> (Ipv4Addr, Ipv4Addr) {
        let mut eligible: Vec<&ElectionNeighbor> =
            neighbors.iter().filter(|n| n.priority > 0).collect();
        if own.priority > 0 {
            eligible.push(own);
        }
        // Step (2): the BDR. "Only those routers ... that have not
        // declared themselves to be Designated Router are eligible
        // to become Backup Designated Router"; among them, the
        // self-declared BDRs win, else the highest rank of the
        // remaining.
        let non_dr: Vec<&ElectionNeighbor> = eligible
            .iter()
            .copied()
            .filter(|n| !declares_dr(n))
            .collect();
        let bdr = non_dr
            .iter()
            .copied()
            .filter(|n| declares_bdr(n))
            .max_by_key(|n| rank(n))
            .or_else(|| non_dr.iter().copied().max_by_key(|n| rank(n)))
            .map(|n| n.address)
            .unwrap_or(Ipv4Addr::UNSPECIFIED);
        // Step (3): the DR. The self-declared DRs first; "if no
        // routers have declared themselves Designated Router, assign
        // the Designated Router to be the same as the newly elected
        // Backup Designated Router" (the promotion).
        let dr = eligible
            .iter()
            .copied()
            .filter(|n| declares_dr(n))
            .max_by_key(|n| rank(n))
            .map(|n| n.address)
            .unwrap_or(bdr);
        (dr, bdr)
    }

    let role_of = |dr: Ipv4Addr, bdr: Ipv4Addr| {
        if dr == own.address {
            InterfaceState::Dr
        } else if bdr == own.address {
            InterfaceState::Backup
        } else {
            InterfaceState::DrOther
        }
    };

    let mut round = own;
    let (mut dr, mut bdr) = elect_once(&round, neighbors);
    // Step (4): "If Router X is now newly the Designated Router or
    // newly the Backup Designated Router, or is now no longer ...,
    // repeat steps 2 and 3" — the DROther-from-below transition
    // (e.g. Waiting → DR Other) is not a role change (FRR's
    // `new_state == ISM_DROther && old_state < ISM_DROther` guard).
    let prev_role = role_of(prev.0, prev.1);
    let new_role = role_of(dr, bdr);
    let was_dr_or_bdr = matches!(prev_role, InterfaceState::Dr | InterfaceState::Backup);
    if new_role != prev_role && !(new_role == InterfaceState::DrOther && !was_dr_or_bdr) {
        // Our claims become the first round's result; the repeat
        // then excludes a now-DR self from BDR election.
        round.dr = dr;
        round.bdr = bdr;
        let (dr2, bdr2) = elect_once(&round, neighbors);
        dr = dr2;
        bdr = bdr2;
    }
    ElectionOutcome {
        dr,
        bdr,
        role: role_of(dr, bdr),
        dr_changed: dr != prev.0,
        bdr_changed: bdr != prev.1,
    }
}

/// §9.2's interface events derived from one received Hello — the
/// pure half of the hello-processing integration (the daemon owns
/// the neighbor/claims bookkeeping and feeds this the deltas).
///
/// `prev` is the neighbor's previous claim snapshot (`None` on the
/// first hello); `new` the just-received claims;
/// `was_bidirectional`/`is_bidirectional` carry the neighbor FSM's
/// ≥ 2-Way status before/after this hello. FRR 10.2.2 parity
/// (`ospf_packet.c:ospf_hello`):
///
/// - **BackupSeen** (§9.2, both forms, Waiting only, and only when
///   bidirectional — "the router must also appear in the neighbor's
///   Hello Packet"): the neighbor claims itself BDR; or claims
///   itself DR while indicating no BDR.
/// - **NeighborChange** (§9.2's five causes): bidirectionality
///   established or lost; the neighbor newly/no-longer declares
///   itself DR or BDR; its priority changed.
///
/// The Waiting gate on NeighborChange is the §9.3 table's (the
/// event is disregarded there); the function reports it regardless
/// and `InterfaceFsm::fire` absorbs it.
pub fn hello_interface_events(
    state: InterfaceState,
    prev: Option<ElectionNeighbor>,
    new: ElectionNeighbor,
    was_bidirectional: bool,
    is_bidirectional: bool,
) -> Vec<InterfaceEvent> {
    let mut events = Vec::new();
    if !is_bidirectional {
        // §9.2: every NeighborChange cause requires the neighbor to
        // be (or have just been) bidirectional.
        if was_bidirectional {
            events.push(InterfaceEvent::NeighborChange);
        }
        return events;
    }
    // §9.2's BackupSeen, Waiting only.
    if state == InterfaceState::Waiting {
        let claims_bdr = declares_bdr(&new);
        let claims_dr_without_bdr = declares_dr(&new) && new.bdr == Ipv4Addr::UNSPECIFIED;
        if claims_bdr || claims_dr_without_bdr {
            events.push(InterfaceEvent::BackupSeen);
        }
    }
    // §9.2's NeighborChange causes.
    if !was_bidirectional {
        events.push(InterfaceEvent::NeighborChange);
    }
    if let Some(prev) = prev {
        if declares_dr(&prev) != declares_dr(&new)
            || declares_bdr(&prev) != declares_bdr(&new)
            || prev.priority != new.priority
        {
            events.push(InterfaceEvent::NeighborChange);
        }
    }
    events
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rid(s: &str) -> RouterId {
        RouterId::from_ipv4(s.parse().unwrap())
    }

    fn ip(s: &str) -> Ipv4Addr {
        s.parse().unwrap()
    }

    fn nb(s: &str, addr: &str, pri: u8, dr: &str, bdr: &str) -> ElectionNeighbor {
        ElectionNeighbor {
            router_id: rid(s),
            address: ip(addr),
            priority: pri,
            dr: ip(dr),
            bdr: ip(bdr),
        }
    }

    // ---- §9.3 table -------------------------------------------------

    #[test]
    fn interface_up_starts_hello_and_wait_on_broadcast() {
        let mut f = InterfaceFsm::new(false);
        let (s, a) = f.fire(InterfaceEvent::InterfaceUp);
        assert_eq!(s, InterfaceState::Waiting);
        assert!(a.contains(&InterfaceAction::StartHello));
        assert!(a.contains(&InterfaceAction::StartWaitTimer));
    }

    #[test]
    fn interface_up_lands_directly_in_point_to_point() {
        // §C.3: p2p networks run no election; §9.3's InterfaceUp row
        // names PointToPoint for them.
        let mut f = InterfaceFsm::new(true);
        let (s, a) = f.fire(InterfaceEvent::InterfaceUp);
        assert_eq!(s, InterfaceState::PointToPoint);
        assert_eq!(a, vec![InterfaceAction::StartHello]);
        // Election events are meaningless there and absorbed.
        let (s, a) = f.fire(InterfaceEvent::WaitTimer);
        assert_eq!(s, InterfaceState::PointToPoint);
        assert!(a.is_empty());
    }

    #[test]
    fn wait_timer_and_backup_seen_elect() {
        for ev in [InterfaceEvent::WaitTimer, InterfaceEvent::BackupSeen] {
            let mut f = InterfaceFsm::new(false);
            f.fire(InterfaceEvent::InterfaceUp);
            let (_, a) = f.fire(ev);
            assert!(a.contains(&InterfaceAction::ElectDr), "{ev:?}");
        }
    }

    #[test]
    fn loop_goes_to_loopback_and_back() {
        let mut f = InterfaceFsm::new(false);
        f.fire(InterfaceEvent::InterfaceUp);
        let (s, _) = f.fire(InterfaceEvent::LoopInd);
        assert_eq!(s, InterfaceState::Loopback);
        // Loopback absorbs election events until UnloopInd.
        let (s, _) = f.fire(InterfaceEvent::NeighborChange);
        assert_eq!(s, InterfaceState::Loopback);
        let (s, a) = f.fire(InterfaceEvent::UnloopInd);
        assert_eq!(s, InterfaceState::Waiting);
        assert!(a.contains(&InterfaceAction::StartHello));
    }

    #[test]
    fn interface_down_kills_neighbors_from_any_state() {
        for start in [
            InterfaceState::Waiting,
            InterfaceState::PointToPoint,
            InterfaceState::Dr,
            InterfaceState::Backup,
            InterfaceState::DrOther,
            InterfaceState::Loopback,
        ] {
            let mut f = InterfaceFsm {
                state: start,
                p2p: false,
                priority: 1,
            };
            let (s, a) = f.fire(InterfaceEvent::InterfaceDown);
            assert_eq!(s, InterfaceState::Down);
            assert!(a.contains(&InterfaceAction::KillNeighbors), "{start:?}");
        }
    }

    #[test]
    fn waiting_disregards_neighbor_change() {
        // §9.3's NeighborChange row: "disregarded if the state is
        // Waiting".
        let mut f = InterfaceFsm {
            state: InterfaceState::Waiting,
            p2p: false,
            priority: 1,
        };
        let (s, a) = f.fire(InterfaceEvent::NeighborChange);
        assert_eq!(s, InterfaceState::Waiting);
        assert!(a.is_empty());
    }

    // ---- §9.4 election ----------------------------------------------

    fn no_prev() -> (Ipv4Addr, Ipv4Addr) {
        // §9.4's initialization: the first election sees 0.0.0.0 for
        // both (the lack of a DR/BDR).
        (Ipv4Addr::UNSPECIFIED, Ipv4Addr::UNSPECIFIED)
    }

    /// One election-table row: (name, own, neighbors, prev, expected
    /// (dr, bdr, role)).
    type ElectionRow = (
        &'static str,
        ElectionNeighbor,
        Vec<ElectionNeighbor>,
        (Ipv4Addr, Ipv4Addr),
        (Ipv4Addr, Ipv4Addr, InterfaceState),
    );

    /// One hello-event-table row: (name, state, prev claims, new
    /// claims, was 2-Way, is 2-Way, expected events).
    type HelloEventRow = (
        &'static str,
        InterfaceState,
        Option<ElectionNeighbor>,
        ElectionNeighbor,
        bool,
        bool,
        Vec<InterfaceEvent>,
    );

    /// The §9.4 tiebreak-order table: every row cites the step that
    /// decides it.
    #[test]
    fn election_table() {
        let cases: &[ElectionRow] = &[
            // §9.4 step (3)+(4) + the FRR 10.2.2 probe: sole router
            // elects itself BDR then DR; the step-(4) repeat removes
            // the now-DR-declaring self from BDR election, leaving
            // BDR 0.0.0.0 ("No backup designated router on this
            // network").
            (
                "sole router: DR self, BDR none",
                nb("1.1.1.1", "10.0.0.1", 1, "0.0.0.0", "0.0.0.0"),
                vec![],
                no_prev(),
                (ip("10.0.0.1"), ip("0.0.0.0"), InterfaceState::Dr),
            ),
            // Step (2): "the one having highest Router Priority";
            // priority wins outright.
            (
                "higher priority is DR",
                nb("1.1.1.1", "10.0.0.1", 5, "0.0.0.0", "0.0.0.0"),
                vec![nb("9.9.9.9", "10.0.0.9", 2, "0.0.0.0", "0.0.0.0")],
                no_prev(),
                (ip("10.0.0.1"), ip("10.0.0.9"), InterfaceState::Dr),
            ),
            // Step (2): "In case of a tie, the one having the highest
            // Router ID is chosen" — same for step (3).
            (
                "router-id tiebreak at equal priority",
                nb("1.1.1.1", "10.0.0.1", 1, "0.0.0.0", "0.0.0.0"),
                vec![nb("2.2.2.2", "10.0.0.2", 1, "0.0.0.0", "0.0.0.0")],
                no_prev(),
                (ip("10.0.0.2"), ip("10.0.0.2"), InterfaceState::DrOther),
            ),
            // §9.4's eligibility: "Routers having Router Priority of
            // 0 are ineligible" — the eligible set is the other
            // router alone; it declares DR (and BDR, the transient
            // both-claim), so step (2)'s non-DR-declarer set is
            // empty and the BDR stays 0.0.0.0 on our side.
            (
                "priority 0 is ineligible",
                nb("1.1.1.1", "10.0.0.1", 0, "10.0.0.1", "10.0.0.1"),
                vec![nb("2.2.2.2", "10.0.0.2", 1, "10.0.0.2", "10.0.0.2")],
                no_prev(),
                (ip("10.0.0.2"), ip("0.0.0.0"), InterfaceState::DrOther),
            ),
            // Step (2)'s claimant restriction: a router declaring
            // itself DR is excluded from BDR election even when it
            // also declares itself BDR (the transient both-claim
            // shape).
            (
                "DR declarer excluded from BDR election",
                nb("1.1.1.1", "10.0.0.1", 1, "0.0.0.0", "10.0.0.1"),
                vec![nb("2.2.2.2", "10.0.0.2", 9, "10.0.0.2", "10.0.0.2")],
                no_prev(),
                (ip("10.0.0.2"), ip("10.0.0.1"), InterfaceState::Backup),
            ),
            // Step (3): "If no routers have declared themselves
            // Designated Router, assign the Designated Router to be
            // the same as the newly elected Backup Designated Router".
            (
                "BDR claimant promotes to DR",
                nb("1.1.1.1", "10.0.0.1", 1, "0.0.0.0", "10.0.0.1"),
                vec![nb("2.2.2.2", "10.0.0.2", 1, "0.0.0.0", "10.0.0.2")],
                no_prev(),
                (ip("10.0.0.2"), ip("10.0.0.2"), InterfaceState::DrOther),
            ),
            // §7.3/§9.4.2's stability: DR selection happens among DR
            // CLAIMANTS only — a higher-priority router that does not
            // claim DR cannot displace the incumbent.
            (
                "incumbent DR claimant stays DR",
                nb("1.1.1.1", "10.0.0.1", 5, "0.0.0.0", "10.0.0.1"),
                vec![nb("9.9.9.9", "10.0.0.9", 1, "10.0.0.9", "0.0.0.0")],
                (ip("10.0.0.9"), Ipv4Addr::UNSPECIFIED),
                (ip("10.0.0.9"), ip("10.0.0.1"), InterfaceState::Backup),
            ),
            // Three routers, the incumbent DR and BDR both claiming:
            // nobody's role changes → no repeat, claims win.
            (
                "established DR/BDR pair re-elected",
                nb("1.1.1.1", "10.0.0.1", 1, "0.0.0.0", "0.0.0.0"),
                vec![
                    nb("8.8.8.8", "10.0.0.8", 5, "10.0.0.8", "0.0.0.0"),
                    nb("9.9.9.9", "10.0.0.9", 3, "0.0.0.0", "10.0.0.9"),
                ],
                (ip("10.0.0.8"), ip("10.0.0.9")),
                (ip("10.0.0.8"), ip("10.0.0.9"), InterfaceState::DrOther),
            ),
        ];
        for (name, own, neighbors, prev, (dr, bdr, role)) in cases {
            let out = elect_dr(*own, neighbors, *prev);
            assert_eq!((out.dr, out.bdr, out.role), (*dr, *bdr, *role), "{name}");
            // Step (7)'s comparison flags are exactly the identity
            // changes against `prev`.
            assert_eq!(out.dr_changed, out.dr != prev.0, "{name} dr_changed");
            assert_eq!(out.bdr_changed, out.bdr != prev.1, "{name} bdr_changed");
        }
    }

    #[test]
    fn dr_loss_promotes_bdr_and_repeats() {
        // Footnote [5]'s scenario: the DR (10.0.0.9) vanishes; the
        // BDR (ours, 10.0.0.1, priority 1) and one other (10.0.0.2,
        // priority 1, no claims) remain. We were Backup → newly DR:
        // step (4) repeats, and the repeat elects the highest other
        // non-DR-declarer as the new BDR.
        let own = nb("1.1.1.1", "10.0.0.1", 1, "0.0.0.0", "10.0.0.1");
        let other = nb("2.2.2.2", "10.0.0.2", 1, "0.0.0.0", "0.0.0.0");
        let out = elect_dr(own, &[other], (ip("10.0.0.9"), ip("10.0.0.1")));
        assert_eq!(out.dr, ip("10.0.0.1"), "the BDR promotes to DR");
        assert_eq!(out.bdr, ip("10.0.0.2"), "the remaining router takes BDR");
        assert_eq!(out.role, InterfaceState::Dr);
        // Footnote [5]: both identities change — the BDR (us)
        // becomes DR, and "the remaining router having highest
        // Router Priority will be selected as Backup Designated
        // Router" (§9.4 step 7 fires on either change).
        assert!(out.dr_changed && out.bdr_changed);
    }

    #[test]
    fn simultaneous_boot_pair_converges() {
        // Two routers boot at once (both Waiting, no claims); the
        // WaitTimer fires on both. The higher Router ID (B)
        // elects itself DR and — via the step-(4) repeat — A as BDR;
        // A's single pass yields the transient DR=B/BDR=B of
        // footnote [5]'s flavor, and A's re-election after seeing
        // B's claims converges to the same pair.
        let a = nb("1.1.1.1", "10.0.0.1", 1, "0.0.0.0", "0.0.0.0");
        let b = nb("2.2.2.2", "10.0.0.2", 1, "0.0.0.0", "0.0.0.0");
        // B's first election: DR=B (BDR promotes, step 3), then the
        // repeat with B claiming DR leaves A the BDR.
        let out_b = elect_dr(b, &[a], no_prev());
        assert_eq!((out_b.dr, out_b.bdr), (ip("10.0.0.2"), ip("10.0.0.1")));
        assert_eq!(out_b.role, InterfaceState::Dr);
        // A's first election: A is neither newly DR nor BDR → no
        // repeat; the BDR elected (B) also becomes DR.
        let out_a = elect_dr(a, &[b], no_prev());
        assert_eq!((out_a.dr, out_a.bdr), (ip("10.0.0.2"), ip("10.0.0.2")));
        assert_eq!(out_a.role, InterfaceState::DrOther);
        // B's hellos now claim DR=B, BDR=A (its post-election
        // values); A re-elects (§9.2's NeighborChange: B newly
        // declares itself DR) and converges.
        let b_claiming = nb("2.2.2.2", "10.0.0.2", 1, "10.0.0.2", "10.0.0.1");
        let out_a2 = elect_dr(a, &[b_claiming], (out_a.dr, out_a.bdr));
        assert_eq!((out_a2.dr, out_a2.bdr), (ip("10.0.0.2"), ip("10.0.0.1")));
        assert_eq!(out_a2.role, InterfaceState::Backup);
    }

    #[test]
    fn waiting_to_dr_other_needs_no_repeat() {
        // §9.4 step (4) read with FRR's guard: a router that was
        // neither DR nor BDR (e.g. Waiting, prev 0.0.0.0/0.0.0.0)
        // and still elects DR Other does not repeat — the result
        // already names others both roles.
        let own = nb("1.1.1.1", "10.0.0.1", 1, "0.0.0.0", "0.0.0.0");
        let dr = nb("8.8.8.8", "10.0.0.8", 5, "10.0.0.8", "0.0.0.0");
        let bdr = nb("9.9.9.9", "10.0.0.9", 3, "0.0.0.0", "10.0.0.9");
        let out = elect_dr(own, &[dr, bdr], no_prev());
        assert_eq!(
            (out.dr, out.bdr, out.role),
            (ip("10.0.0.8"), ip("10.0.0.9"), InterfaceState::DrOther)
        );
    }

    #[test]
    fn no_eligible_routers_leaves_both_unset() {
        // Everyone priority 0 (or nobody bidirectional): §9.4's
        // eligible set is empty; both stay 0.0.0.0 and the role is
        // DR Other.
        let own = nb("1.1.1.1", "10.0.0.1", 0, "0.0.0.0", "0.0.0.0");
        let out = elect_dr(own, &[], no_prev());
        assert_eq!(out.dr, Ipv4Addr::UNSPECIFIED);
        assert_eq!(out.bdr, Ipv4Addr::UNSPECIFIED);
        assert_eq!(out.role, InterfaceState::DrOther);
    }

    #[test]
    fn priority_zero_interface_enters_dr_other_directly() {
        // §9.3 InterfaceUp: broadcast + priority 0 skips Waiting —
        // "if the router is not eligible ... the interface state
        // transitions to DR Other"; no WaitTimer.
        let mut f = InterfaceFsm::new_with_priority(false, 0);
        let (s, a) = f.fire(InterfaceEvent::InterfaceUp);
        assert_eq!(s, InterfaceState::DrOther);
        assert_eq!(a, vec![InterfaceAction::StartHello]);
    }

    // ---- §9.2 hello-driven events -----------------------------------

    #[test]
    fn hello_event_table() {
        use InterfaceEvent as E;
        let cases: &[HelloEventRow] = &[
            // §9.2 form one: neighbor claims itself BDR while we
            // wait → BackupSeen.
            (
                "bdr claim during waiting",
                InterfaceState::Waiting,
                None,
                nb("2.2.2.2", "10.0.0.2", 1, "0.0.0.0", "10.0.0.2"),
                false,
                true,
                vec![E::BackupSeen, E::NeighborChange],
            ),
            // §9.2 form two: neighbor claims itself DR and indicates
            // no BDR.
            (
                "dr claim without bdr during waiting",
                InterfaceState::Waiting,
                None,
                nb("2.2.2.2", "10.0.0.2", 1, "10.0.0.2", "0.0.0.0"),
                false,
                true,
                vec![E::BackupSeen, E::NeighborChange],
            ),
            // The DR-claim form requires "there is no Backup
            // Designated Router" — a named BDR does not fire.
            (
                "dr claim with bdr named: no backup seen",
                InterfaceState::Waiting,
                None,
                nb("2.2.2.2", "10.0.0.2", 1, "10.0.0.2", "10.0.0.3"),
                false,
                true,
                vec![E::NeighborChange],
            ),
            // BackupSeen is Waiting-only (§9.2: "signals an end to
            // the Waiting state" — no meaning elsewhere); the first
            // bidirectional hello still reports NeighborChange.
            (
                "bdr claim outside waiting",
                InterfaceState::DrOther,
                None,
                nb("2.2.2.2", "10.0.0.2", 1, "0.0.0.0", "10.0.0.2"),
                false,
                true,
                vec![E::NeighborChange],
            ),
            // §9.2: "In either case there must be bidirectional
            // communication" — one-way hellos fire nothing.
            (
                "one-way first hello: nothing",
                InterfaceState::Waiting,
                None,
                nb("2.2.2.2", "10.0.0.2", 1, "10.0.0.2", "0.0.0.0"),
                false,
                false,
                vec![],
            ),
            // Priority change (§9.2's fifth cause).
            (
                "priority change",
                InterfaceState::Dr,
                Some(nb("2.2.2.2", "10.0.0.2", 1, "0.0.0.0", "0.0.0.0")),
                nb("2.2.2.2", "10.0.0.2", 3, "0.0.0.0", "0.0.0.0"),
                true,
                true,
                vec![E::NeighborChange],
            ),
            // New self-DR declaration (§9.2's third cause).
            (
                "neighbor newly declares dr",
                InterfaceState::DrOther,
                Some(nb("2.2.2.2", "10.0.0.2", 1, "0.0.0.0", "0.0.0.0")),
                nb("2.2.2.2", "10.0.0.2", 1, "10.0.0.2", "0.0.0.0"),
                true,
                true,
                vec![E::NeighborChange],
            ),
            // Lost bidirectionality (§9.2's second cause) — claims
            // not examined on a one-way hello.
            (
                "bidirectionality lost",
                InterfaceState::DrOther,
                Some(nb("2.2.2.2", "10.0.0.2", 1, "10.0.0.2", "0.0.0.0")),
                nb("2.2.2.2", "10.0.0.2", 5, "10.0.0.2", "0.0.0.0"),
                true,
                false,
                vec![E::NeighborChange],
            ),
            // Steady state: same claims, same priority, still
            // bidirectional → nothing.
            (
                "steady state",
                InterfaceState::Backup,
                Some(nb("2.2.2.2", "10.0.0.2", 1, "10.0.0.2", "10.0.0.1")),
                nb("2.2.2.2", "10.0.0.2", 1, "10.0.0.2", "10.0.0.1"),
                true,
                true,
                vec![],
            ),
        ];
        for (name, state, prev, new, was, is, expected) in cases {
            assert_eq!(
                hello_interface_events(*state, *prev, *new, *was, *is),
                *expected,
                "{name}"
            );
        }
    }
}
