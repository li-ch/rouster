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
//! v1 scope disclosure: the daemon drives interfaces as
//! PointToPoint only (the interop topology); the broadcast arm
//! (Waiting, DR/Backup/DR Other, network-LSA origination by the DR,
//! §12.4.2) is landed and table-tested here but not yet driven by
//! the binary — the §9.4 role changes' socket effects
//! (join/leave 224.0.0.6) are wired in `transport`.

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
#[derive(Debug, Clone)]
pub struct InterfaceFsm {
    pub state: InterfaceState,
    pub p2p: bool,
}

impl InterfaceFsm {
    pub fn new(p2p: bool) -> Self {
        Self {
            state: InterfaceState::Down,
            p2p,
        }
    }

    /// Fire one §9.3 event; returns the resulting state (unchanged
    /// where the table says so) and the prescribed actions.
    pub fn fire(&mut self, event: InterfaceEvent) -> (InterfaceState, Vec<InterfaceAction>) {
        use InterfaceAction as A;
        use InterfaceEvent as E;
        use InterfaceState as S;
        let mut actions = Vec::new();
        let next = match (&self.state, event) {
            // §9.3, InterfaceUp row: Down -> hello starts; broadcast
            // networks further wait (the WaitTimer) before electing.
            (S::Down, E::InterfaceUp) => {
                actions.push(A::StartHello);
                if self.p2p {
                    S::PointToPoint
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
pub struct ElectionResult {
    pub dr: Ipv4Addr,
    pub bdr: Ipv4Addr,
    /// Our resulting role.
    pub role: InterfaceState,
}

/// §9.4's electing function, steps 1-4, verbatim order:
///
/// 1. Calculate the BDR: among eligible routers (priority > 0,
///    state ≥ 2-Way — the caller filters), prefer those that claim
///    themselves BDR ("BackupSeen"), highest (priority, Router ID)
///    wins; if none claims, the highest eligible.
/// 2. Calculate the DR: among those claiming themselves DR, highest
///    (priority, Router ID); if none, the BDR just elected (§9.4.3).
/// 3. If we are the DR (the elected DR is our own interface
///    address), we are DR; else BDR; else DR Other.
/// 4. The caller fires NeighborChange-equivalent re-evaluation when
///    the result differs from the previous election.
pub fn elect_dr(own: ElectionNeighbor, neighbors: &[ElectionNeighbor]) -> ElectionResult {
    /// §9.4.1/§9.4.2's comparison: highest priority first, Router ID
    /// breaking ties ("largest ... Router ID").
    fn rank(n: &ElectionNeighbor) -> (u8, RouterId) {
        (n.priority, n.router_id)
    }
    // Eligible set: ourselves plus priority > 0 neighbors.
    let mut eligible: Vec<&ElectionNeighbor> =
        neighbors.iter().filter(|n| n.priority > 0).collect();
    if own.priority > 0 {
        eligible.push(&own);
    }
    // §9.4.1 step 1: the BDR claimants first, then every eligible.
    let bdr = eligible
        .iter()
        .filter(|n| n.bdr != Ipv4Addr::UNSPECIFIED && n.bdr == n.address)
        .copied()
        .max_by_key(|n| rank(n))
        .or_else(|| eligible.iter().copied().max_by_key(|n| rank(n)))
        .map(|n| n.address)
        .unwrap_or(Ipv4Addr::UNSPECIFIED);
    // §9.4.2 step 2: the DR claimants, else the BDR promotes
    // (§9.4.3).
    let dr = eligible
        .iter()
        .filter(|n| n.dr != Ipv4Addr::UNSPECIFIED && n.dr == n.address)
        .copied()
        .max_by_key(|n| rank(n))
        .map(|n| n.address)
        .unwrap_or(bdr);
    // §9.4.4 step 3: our role.
    let role = if dr == own.address {
        InterfaceState::Dr
    } else if bdr == own.address {
        InterfaceState::Backup
    } else {
        InterfaceState::DrOther
    };
    ElectionResult { dr, bdr, role }
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
        };
        let (s, a) = f.fire(InterfaceEvent::NeighborChange);
        assert_eq!(s, InterfaceState::Waiting);
        assert!(a.is_empty());
    }

    // ---- §9.4 election ----------------------------------------------

    #[test]
    fn sole_router_becomes_dr() {
        // §9.4.3: with no other claimants the router elects itself
        // BDR then DR.
        let own = nb("1.1.1.1", "10.0.0.1", 1, "0.0.0.0", "0.0.0.0");
        let r = elect_dr(own, &[]);
        assert_eq!(r.dr, ip("10.0.0.1"));
        assert_eq!(r.bdr, ip("10.0.0.1"));
        assert_eq!(r.role, InterfaceState::Dr);
    }

    #[test]
    fn priority_then_router_id_breaks_ties() {
        // Higher priority wins regardless of ID.
        let own = nb("1.1.1.1", "10.0.0.1", 5, "10.0.0.1", "10.0.0.1");
        let other = nb("9.9.9.9", "10.0.0.9", 2, "10.0.0.9", "10.0.0.9");
        let r = elect_dr(own, &[other]);
        assert_eq!(r.dr, ip("10.0.0.1"), "priority 5 beats 2");
        assert_eq!(r.role, InterfaceState::Dr);
        // Equal priority: higher Router ID wins both claimant sets.
        let own = nb("1.1.1.1", "10.0.0.1", 1, "10.0.0.1", "10.0.0.1");
        let other = nb("2.2.2.2", "10.0.0.2", 1, "10.0.0.2", "10.0.0.2");
        let r = elect_dr(own, &[other]);
        assert_eq!(r.dr, ip("10.0.0.2"), "Router ID tiebreak");
        assert_eq!(r.bdr, ip("10.0.0.2"));
        assert_eq!(r.role, InterfaceState::DrOther);
    }

    #[test]
    fn priority_zero_is_ineligible() {
        // §9.4: priority 0 routers never become DR/BDR.
        let own = nb("1.1.1.1", "10.0.0.1", 0, "10.0.0.1", "10.0.0.1");
        let other = nb("2.2.2.2", "10.0.0.2", 1, "10.0.0.2", "10.0.0.2");
        let r = elect_dr(own, &[other]);
        assert_eq!(r.dr, ip("10.0.0.2"));
        assert_eq!(r.role, InterfaceState::DrOther);
    }

    #[test]
    fn bdr_promotes_to_dr_when_no_claimants() {
        // §9.4.3: "If no routers claim to be the DR, the router just
        // elected BDR becomes the DR" — nobody claims DR; both claim
        // BDR; the higher Router ID wins BDR and promotes.
        let own = nb("1.1.1.1", "10.0.0.1", 1, "0.0.0.0", "10.0.0.1");
        let other = nb("2.2.2.2", "10.0.0.2", 1, "0.0.0.0", "10.0.0.2");
        let r = elect_dr(own, &[other]);
        assert_eq!(r.bdr, ip("10.0.0.2"));
        assert_eq!(r.dr, ip("10.0.0.2"), "the BDR promotes to DR");
        assert_eq!(r.role, InterfaceState::DrOther);
    }

    #[test]
    fn established_dr_stays_dr_without_claims() {
        // The classic stability case: DR selection happens among DR
        // CLAIMANTS only (§9.4.2) — a higher-priority router that
        // does not claim DR cannot displace the incumbent.
        let own = nb("1.1.1.1", "10.0.0.1", 5, "0.0.0.0", "10.0.0.1");
        let incumbent_dr = nb("9.9.9.9", "10.0.0.9", 1, "10.0.0.9", "0.0.0.0");
        let r = elect_dr(own, &[incumbent_dr]);
        assert_eq!(r.dr, ip("10.0.0.9"), "the DR claimant stays DR");
        assert_eq!(r.bdr, ip("10.0.0.1"), "we claim and win BDR");
        assert_eq!(r.role, InterfaceState::Backup);
    }
}
