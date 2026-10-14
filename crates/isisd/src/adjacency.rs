//! The point-to-point IIH adjacency state machine (ISO 10589
//! §8.2.4/§8.2.5 via RFC 1142, with RFC 5303 §3.2's three-way
//! handshake grafted in as §8.2.4.1.1) — pure, message-driven and
//! clock-injected, the ospfd `neighbor.rs` shape.
//!
//! What FRR 10.2.2 actually does (the cited oracle, verified in its
//! source): `process_p2p_hello` (`isisd/isis_pdu.c`) runs the
//! acceptance tests — own-sysid discard ("Received IIH with our own
//! sysid"), the area/level `calculated_type` rules of ISO §8.2.4.2's
//! tables, the NLPID usability check — then hands the TLV 240 option
//! to `isis_adj_process_threeway` (`isisd/isis_adjacency.c`), which
//! implements RFC 5303's state table verbatim:
//!
//! ```text
//!                  Received:  Down    Initializing    Up
//!   Our state Down:          Initialize      Up        Down
//!       Initializing:        Initialize      Up        Up
//!       Up:                  Initialize      Accept    Accept
//! ```
//!
//! (The three-way state is separate from the ISO adjacency state —
//! RFC 5303 §2.1: "an adjacency may have two states … its state as
//! defined in ISO 10589, and its three-way state". A system without
//! the option is the legacy assumption: the link is trusted both
//! ways and the adjacency goes Up on the first accepted IIH — the
//! `threeway: None` arm.)
//!
//! The area rule (ISO §8.2.4.2): a shared area address validates any
//! level combination; **no shared area validates only L2** ("the IS
//! shall mark the adjacency as Level 2 Only"). The NLPID rule (RFC
//! 1195 §5.2): a IIH without Protocols Supported is an OSI-only
//! router — for the v4-only v1 daemon that is a rejection (an
//! IP-capable peer must announce NLPID 0xCC).
//!
//! MTU matching: our transmit side pads IIHs to the circuit MTU
//! (ISO §8.2.3: "trailing pad options are inserted to make PDU Length
//! equal to at least maxsize - 1" — `crate::pdu`'s builder pads via
//! TLV 8), which proves OUR MTU to the peer; the receive side takes
//! FRR's `pdu_len_validate` bounds (declared length ≤ our MTU and ≤
//! the received frame). The stricter lower-bound receive check the
//! ISO padding rule implies is NOT enforced — FRR does not enforce
//! it either (disclosed divergence: an undersized peer IIH is
//! accepted).

use crate::system::{Level, SystemId};
use crate::tlv::{ThreewayAdjacency, ThreewayState, NLPID_IPV4};

/// The ISO adjacency state (§8.2.5's Down/Initializing/Up — FRR's
/// `enum isis_adj_state`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum AdjacencyState {
    #[default]
    Down,
    Initializing,
    Up,
}

/// One received IIH, already codec-decoded, distilled to what the
/// FSM consumes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HelloInfo {
    pub source: SystemId,
    pub circuit_type: Level,
    pub holding_time: u16,
    /// TLV 1's area addresses.
    pub areas: Vec<Vec<u8>>,
    /// TLV 129's NLPIDs.
    pub nlpids: Vec<u8>,
    /// TLV 240, when present.
    pub threeway: Option<ThreewayAdjacency>,
    /// The received PDU length (the MTU bound).
    pub pdu_length: u16,
}

/// The circuit's view the FSM needs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CircuitContext {
    pub our_system_id: SystemId,
    /// Our manual area addresses (the area-match input).
    pub our_areas: Vec<Vec<u8>>,
    /// The circuit's is-type.
    pub our_level: Level,
    /// Our MTU — the receive upper bound and the transmit pad target.
    pub mtu: u16,
    /// Our extended circuit ID (TLV 240's local field).
    pub extended_circuit_id: u32,
}

/// What the FSM wants the daemon to do.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Action {
    /// The adjacency reached Up (the LSP regen + CSNP trigger).
    AdjacencyUp(Level),
    /// The adjacency left Up ("Neighbor restarted" is RFC 5303's
    /// wording; hold expiry is ISO §8.2.5's monitoring).
    AdjacencyDown(&'static str),
    /// State changed in a way that should re-send our hello soon
    /// (FRR's `send_hello_sched` on a three-way transition).
    ResendHello,
    None,
}

/// The adjacency record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Adjacency {
    pub state: AdjacencyState,
    pub threeway: ThreewayState,
    pub neighbor: SystemId,
    /// The level this adjacency actually runs at (ISO §8.2.4.2's
    /// calculated type: the area/level combination).
    pub level: Level,
    pub neighbor_areas: Vec<Vec<u8>>,
    pub holding_time: u16,
    pub neighbor_extended_circuit_id: Option<u32>,
    /// Last accepted hello (the hold-timer anchor).
    pub last_hello_at: u64,
}

impl Adjacency {
    pub fn new(neighbor: SystemId) -> Self {
        Self {
            state: AdjacencyState::Down,
            threeway: ThreewayState::Down,
            neighbor,
            level: Level::Level2,
            neighbor_areas: vec![],
            holding_time: 0,
            neighbor_extended_circuit_id: None,
            last_hello_at: 0,
        }
    }

    /// The TLV 240 option our next IIH carries (RFC 5303 §3.2's
    /// clause e: the current state; the neighbour fields when known —
    /// Initializing or Up).
    pub fn threeway_option(&self, ctx: &CircuitContext) -> ThreewayAdjacency {
        ThreewayAdjacency {
            state: self.threeway,
            extended_local_circuit_id: ctx.extended_circuit_id,
            neighbor_system_id: self.neighbor,
            neighbor_extended_circuit_id: if self.threeway == ThreewayState::Down {
                None
            } else {
                self.neighbor_extended_circuit_id
            },
        }
    }

    /// ISO §8.2.5's hold monitoring: true when `now` passed the last
    /// accepted hello by more than the neighbour's holding time (the
    /// caller then takes the adjacency Down).
    pub fn hold_expired(&self, now: u64) -> bool {
        self.state != AdjacencyState::Down
            && now.saturating_sub(self.last_hello_at) > self.holding_time as u64
    }
}

/// RFC 5303 §3.2's Adjacency Three-Way State Table as a pure
/// function: (our state, received state) → the action.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ThreewayAction {
    Initialize,
    Up,
    Accept,
    /// The "Neighbor restarted" arm: adjacencyStateChange(Down), the
    /// adjacency is deleted.
    DownRestart,
}

pub fn threeway_table(ours: ThreewayState, received: ThreewayState) -> ThreewayAction {
    use ThreewayState::{Down, Initializing, Up};
    match (ours, received) {
        (Down, Initializing) | (Initializing, Initializing) => ThreewayAction::Up,
        (Down, Up) => ThreewayAction::DownRestart,
        (Initializing, Up) => ThreewayAction::Up,
        (Up, Up) | (Up, Initializing) => ThreewayAction::Accept,
        (_, Down) => ThreewayAction::Initialize,
    }
}

/// ISO §8.2.4.2's area/level combination, in FRR's `calculated_type`
/// shape: a shared area address admits any matching level; none
/// admits only L2 (marked level 2 only). `None` = no valid
/// combination (rejected).
fn calculated_level(
    our: Level,
    their: Level,
    our_areas: &[Vec<u8>],
    their_areas: &[Vec<u8>],
) -> Option<Level> {
    let shared = our_areas.iter().any(|a| their_areas.contains(a));
    if shared {
        match (our, their) {
            (Level::Level1, _) => Some(Level::Level1),
            (_, Level::Level1) => Some(Level::Level1),
            (Level::Level1And2, Level::Level1And2) => Some(Level::Level1And2),
            _ => Some(Level::Level2),
        }
    } else {
        // §8.2.4.2: "if they have no area address in common, the
        // adjacency is only valid if both Intermediate systems are
        // Level 2, and the IS shall mark the adjacency as Level 2
        // Only."
        match (our, their) {
            (Level::Level2, _) | (_, Level::Level2) => Some(Level::Level2),
            (Level::Level1And2, Level::Level1And2) => Some(Level::Level2),
            _ => None,
        }
    }
}

/// The PDU acceptance tests (ISO §8.2.4.1's p2p subset + RFC 5303
/// §3.2's option checks), run before any state transition. `Err`
/// carries the discard reason.
pub fn accept_hello(
    ctx: &CircuitContext,
    hello: &HelloInfo,
) -> Result<Option<ThreewayAdjacency>, &'static str> {
    if hello.source == ctx.our_system_id {
        return Err("own system id (ISO 10589: discard; FRR: 'Received IIH with our own sysid')");
    }
    if hello.pdu_length > ctx.mtu {
        return Err("PDU length above our MTU (FRR pdu_len_validate)");
    }
    // RFC 5303 §3.2: "If they are present, and the Neighbor System ID
    // contained therein does not match the local system's ID, or the
    // Neighbor Extended Local Circuit ID does not match the local
    // system's extended circuit ID, the PDU SHALL be discarded".
    if let Some(tw) = &hello.threeway {
        if tw.state != ThreewayState::Down {
            if tw.neighbor_system_id != ctx.our_system_id {
                return Err("three-way neighbor system id is not us");
            }
            if let Some(ncid) = tw.neighbor_extended_circuit_id {
                if ncid != ctx.extended_circuit_id {
                    return Err("three-way neighbor circuit id is not ours");
                }
            }
        }
    }
    // RFC 1195 §5.2: no Protocols Supported = OSI-only router; the
    // v4-only v1 daemon declines (an IP adjacency needs NLPID 0xCC).
    if !hello.nlpids.contains(&NLPID_IPV4) {
        return Err("no IPv4 NLPID (OSI-only or non-IP peer)");
    }
    Ok(hello.threeway.clone())
}

/// Process one accepted IIH: the ISO §8.2.4.2 level calculation, the
/// adjacency bookkeeping, and the RFC 5303 table. Returns the action
/// (or the rejection reason before any state change).
pub fn process_hello(
    adj: &mut Adjacency,
    ctx: &CircuitContext,
    hello: &HelloInfo,
    now: u64,
) -> Result<Action, &'static str> {
    let tw = accept_hello(ctx, hello)?;
    let level = calculated_level(
        ctx.our_level,
        hello.circuit_type,
        &ctx.our_areas,
        &hello.areas,
    )
    .ok_or("no valid area/level combination (ISO 8.2.4.2)")?;

    // §8.2.5's hold bookkeeping.
    adj.holding_time = hello.holding_time;
    adj.last_hello_at = now;
    adj.neighbor_areas = hello.areas.clone();
    adj.neighbor = hello.source;
    if let Some(tw) = &tw {
        adj.neighbor_extended_circuit_id = Some(tw.extended_local_circuit_id);
    }
    if adj.state == AdjacencyState::Down {
        adj.state = AdjacencyState::Initializing;
        adj.level = level;
    } else {
        adj.level = level;
    }

    match tw {
        None => {
            // Legacy peer (no TLV 240): the link is assumed
            // functional both ways (RFC 5303 §3.2's fallback; FRR's
            // disable_threeway_adj arm).
            adj.threeway = ThreewayState::Up;
            if adj.state != AdjacencyState::Up {
                adj.state = AdjacencyState::Up;
                return Ok(Action::AdjacencyUp(level));
            }
            Ok(Action::None)
        }
        Some(tw) => {
            let action = threeway_table(adj.threeway, tw.state);
            match action {
                ThreewayAction::Initialize => {
                    adj.threeway = ThreewayState::Initializing;
                    Ok(Action::ResendHello)
                }
                ThreewayAction::Up => {
                    let was_up = adj.state == AdjacencyState::Up;
                    adj.threeway = ThreewayState::Up;
                    adj.state = AdjacencyState::Up;
                    if was_up {
                        Ok(Action::ResendHello)
                    } else {
                        Ok(Action::AdjacencyUp(level))
                    }
                }
                ThreewayAction::Accept => {
                    adj.threeway = ThreewayState::Up;
                    Ok(Action::None)
                }
                ThreewayAction::DownRestart => {
                    // RFC 5303: adjacencyStateChange(Down) with the
                    // reason "Neighbor restarted"; the adjacency is
                    // deleted (the daemon re-creates it on the next
                    // hello).
                    *adj = Adjacency::new(hello.source);
                    adj.state = AdjacencyState::Initializing;
                    adj.threeway = ThreewayState::Initializing;
                    adj.holding_time = hello.holding_time;
                    adj.last_hello_at = now;
                    Ok(Action::AdjacencyDown("Neighbor restarted"))
                }
            }
        }
    }
}

/// The hold-expiry event (ISO §8.2.5's "Monitoring point-to-point
/// adjacencies": expiry takes the adjacency Down).
pub fn process_hold_expired(adj: &mut Adjacency) -> Action {
    if adj.state == AdjacencyState::Down {
        return Action::None;
    }
    *adj = Adjacency::new(adj.neighbor);
    Action::AdjacencyDown("hold time expired")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::system::{Level, SystemId};
    use crate::tlv::{ThreewayAdjacency, ThreewayState};

    const US: SystemId = SystemId::from_bytes([0, 0, 0, 0, 0, 1]);
    const THEM: SystemId = SystemId::from_bytes([0, 0, 0, 0, 0, 2]);

    fn ctx() -> CircuitContext {
        CircuitContext {
            our_system_id: US,
            our_areas: vec![vec![0x49, 0x00, 0x01]],
            our_level: Level::Level1And2,
            mtu: 1500,
            extended_circuit_id: 7,
        }
    }

    fn hello(
        threeway: Option<ThreewayState>,
        areas: Vec<Vec<u8>>,
        circuit_type: Level,
        holding: u16,
    ) -> HelloInfo {
        let neighbor_extended_circuit_id = if threeway == Some(ThreewayState::Up) {
            Some(7)
        } else {
            None
        };
        HelloInfo {
            source: THEM,
            circuit_type,
            holding_time: holding,
            areas,
            nlpids: vec![crate::tlv::NLPID_IPV4],
            threeway: threeway.map(|state| ThreewayAdjacency {
                state,
                extended_local_circuit_id: 9,
                neighbor_system_id: US,
                neighbor_extended_circuit_id,
            }),
            pdu_length: 50,
        }
    }

    /// The RFC 5303 table, every cell (the 3×3 lattice).
    #[test]
    fn threeway_table_cells() {
        use ThreewayState::{Down, Initializing, Up};
        assert_eq!(threeway_table(Down, Down), ThreewayAction::Initialize);
        assert_eq!(threeway_table(Down, Initializing), ThreewayAction::Up);
        assert_eq!(threeway_table(Down, Up), ThreewayAction::DownRestart);
        assert_eq!(
            threeway_table(Initializing, Down),
            ThreewayAction::Initialize
        );
        assert_eq!(
            threeway_table(Initializing, Initializing),
            ThreewayAction::Up
        );
        assert_eq!(threeway_table(Initializing, Up), ThreewayAction::Up);
        assert_eq!(threeway_table(Up, Down), ThreewayAction::Initialize);
        assert_eq!(threeway_table(Up, Initializing), ThreewayAction::Accept);
        assert_eq!(threeway_table(Up, Up), ThreewayAction::Accept);
    }

    /// The full three-way dance: both sides start Down, exchange
    /// Initializing, reach Up — exactly the interop choreography with
    /// an FRR peer.
    #[test]
    fn three_way_dance_to_up() {
        let ctx = ctx();
        let mut adj = Adjacency::new(THEM);
        let areas = vec![vec![0x49, 0x00, 0x01]];

        // Their first IIH: state Down (they know nothing of us yet),
        // neighbor fields per RFC (they are Down: none).
        let action = process_hello(
            &mut adj,
            &ctx,
            &hello(
                Some(ThreewayState::Down),
                areas.clone(),
                Level::Level1And2,
                30,
            ),
            0,
        )
        .unwrap();
        assert_eq!(adj.state, AdjacencyState::Initializing);
        assert_eq!(adj.threeway, ThreewayState::Initializing);
        assert!(matches!(action, Action::ResendHello));
        // The option we now advertise carries them as neighbor with
        // their circuit id.
        let opt = adj.threeway_option(&ctx);
        assert_eq!(opt.state, ThreewayState::Initializing);
        assert_eq!(opt.neighbor_system_id, THEM);
        assert_eq!(opt.neighbor_extended_circuit_id, Some(9));

        // Their second IIH: Initializing, listing US — we go Up.
        let action = process_hello(
            &mut adj,
            &ctx,
            &hello(
                Some(ThreewayState::Initializing),
                areas.clone(),
                Level::Level1And2,
                30,
            ),
            1,
        )
        .unwrap();
        assert_eq!(adj.state, AdjacencyState::Up);
        assert_eq!(adj.threeway, ThreewayState::Up);
        assert_eq!(action, Action::AdjacencyUp(Level::Level1And2));

        // Their steady-state: Up listing US with our circuit id —
        // Accept, nothing changes.
        let action = process_hello(
            &mut adj,
            &ctx,
            &hello(Some(ThreewayState::Up), areas, Level::Level1And2, 30),
            2,
        )
        .unwrap();
        assert_eq!(action, Action::None);
        assert_eq!(adj.state, AdjacencyState::Up);
    }

    /// The neighbor-restarted arm: recv Up while we are Down.
    #[test]
    fn neighbor_restarted_arm() {
        let ctx = ctx();
        let mut adj = Adjacency::new(THEM);
        let areas = vec![vec![0x49, 0x00, 0x01]];
        // We never got past Down; they claim Up (stale state).
        let action = process_hello(
            &mut adj,
            &ctx,
            &hello(Some(ThreewayState::Up), areas, Level::Level1And2, 30),
            0,
        )
        .unwrap();
        assert_eq!(action, Action::AdjacencyDown("Neighbor restarted"));
        assert_eq!(adj.state, AdjacencyState::Initializing, "re-created");
        assert_eq!(adj.threeway, ThreewayState::Initializing);
    }

    /// A live adjacency that hears Down: re-initialize (neighbor
    /// restarted), then Up again.
    #[test]
    fn restart_then_up() {
        let ctx = ctx();
        let mut adj = Adjacency::new(THEM);
        let areas = vec![vec![0x49, 0x00, 0x01]];
        process_hello(
            &mut adj,
            &ctx,
            &hello(
                Some(ThreewayState::Initializing),
                areas.clone(),
                Level::Level1And2,
                30,
            ),
            0,
        )
        .unwrap();
        assert_eq!(adj.state, AdjacencyState::Up);
        // They restart: their IIH says Down.
        let action = process_hello(
            &mut adj,
            &ctx,
            &hello(
                Some(ThreewayState::Down),
                areas.clone(),
                Level::Level1And2,
                30,
            ),
            5,
        )
        .unwrap();
        assert!(matches!(action, Action::ResendHello));
        assert_eq!(
            adj.state,
            AdjacencyState::Up,
            "ISO state untouched by Initialize"
        );
        assert_eq!(adj.threeway, ThreewayState::Initializing);
        // Then they initialize us again.
        let action = process_hello(
            &mut adj,
            &ctx,
            &hello(
                Some(ThreewayState::Initializing),
                areas,
                Level::Level1And2,
                30,
            ),
            6,
        )
        .unwrap();
        assert_eq!(action, Action::ResendHello);
        assert_eq!(adj.threeway, ThreewayState::Up);
    }

    /// A legacy peer (no TLV 240): Up on the first accepted hello.
    #[test]
    fn legacy_peer_goes_up_immediately() {
        let ctx = ctx();
        let mut adj = Adjacency::new(THEM);
        let action = process_hello(
            &mut adj,
            &ctx,
            &hello(None, vec![vec![0x49, 0x00, 0x01]], Level::Level1And2, 30),
            0,
        )
        .unwrap();
        assert_eq!(action, Action::AdjacencyUp(Level::Level1And2));
        assert_eq!(adj.threeway, ThreewayState::Up);
    }

    /// ISO §8.2.4.2: shared area → the level combination; disjoint
    /// areas → L2 only (or rejection when neither side can do L2).
    #[test]
    fn area_level_combinations() {
        let base = ctx();
        let shared = vec![vec![0x49, 0x00, 0x01]];
        let disjoint = vec![vec![0x49, 0x00, 0x02]];

        // Shared area, L1L2 both: adjacency at L1L2.
        let mut adj = Adjacency::new(THEM);
        process_hello(
            &mut adj,
            &base,
            &hello(None, shared.clone(), Level::Level1And2, 30),
            0,
        )
        .unwrap();
        assert_eq!(adj.level, Level::Level1And2);

        // Shared area, peer L1-only: the adjacency is L1.
        let mut adj = Adjacency::new(THEM);
        process_hello(
            &mut adj,
            &base,
            &hello(None, shared.clone(), Level::Level1, 30),
            0,
        )
        .unwrap();
        assert_eq!(adj.level, Level::Level1);

        // Disjoint areas, both L1L2: valid as L2 only.
        let mut adj = Adjacency::new(THEM);
        process_hello(
            &mut adj,
            &base,
            &hello(None, disjoint.clone(), Level::Level1And2, 30),
            0,
        )
        .unwrap();
        assert_eq!(adj.level, Level::Level2, "marked Level 2 Only");

        // Disjoint areas and we are L1-only: rejected.
        let mut l1_ctx = ctx();
        l1_ctx.our_level = Level::Level1;
        let mut adj = Adjacency::new(THEM);
        assert!(process_hello(
            &mut adj,
            &l1_ctx,
            &hello(None, disjoint, Level::Level1, 30),
            0
        )
        .is_err());
    }

    /// The acceptance rejections: own sysid, oversized PDU, wrong
    /// three-way neighbor, OSI-only peer.
    #[test]
    fn acceptance_rejections() {
        let ctx = ctx();
        let mut adj = Adjacency::new(THEM);

        // Own system id.
        let mut own = hello(None, vec![ctx.our_areas[0].clone()], Level::Level1And2, 30);
        own.source = US;
        assert_eq!(
            process_hello(&mut adj, &ctx, &own, 0),
            Err("own system id (ISO 10589: discard; FRR: 'Received IIH with our own sysid')")
        );

        // PDU above our MTU.
        let mut big = hello(None, vec![ctx.our_areas[0].clone()], Level::Level1And2, 30);
        big.pdu_length = 1501;
        assert_eq!(
            process_hello(&mut adj, &ctx, &big, 0),
            Err("PDU length above our MTU (FRR pdu_len_validate)")
        );

        // Three-way neighbor is not us.
        let mut wrong = hello(
            Some(ThreewayState::Initializing),
            vec![ctx.our_areas[0].clone()],
            Level::Level1And2,
            30,
        );
        wrong.threeway = wrong.threeway.map(|mut tw| {
            tw.neighbor_system_id = SystemId::from_bytes([9, 9, 9, 9, 9, 9]);
            tw
        });
        assert_eq!(
            process_hello(&mut adj, &ctx, &wrong, 0),
            Err("three-way neighbor system id is not us")
        );

        // Three-way neighbor circuit id not ours (present only in Up).
        let mut wrong_cid = hello(
            Some(ThreewayState::Up),
            vec![ctx.our_areas[0].clone()],
            Level::Level1And2,
            30,
        );
        wrong_cid.threeway = wrong_cid.threeway.map(|mut tw| {
            tw.neighbor_extended_circuit_id = Some(999);
            tw
        });
        assert_eq!(
            process_hello(&mut adj, &ctx, &wrong_cid, 0),
            Err("three-way neighbor circuit id is not ours")
        );

        // OSI-only peer (no NLPID 0xCC).
        let mut osi = hello(None, vec![ctx.our_areas[0].clone()], Level::Level1And2, 30);
        osi.nlpids = vec![];
        assert_eq!(
            process_hello(&mut adj, &ctx, &osi, 0),
            Err("no IPv4 NLPID (OSI-only or non-IP peer)")
        );
    }

    /// ISO §8.2.5's hold monitoring: expiry inside the window keeps
    /// the adjacency; past it, Down.
    #[test]
    fn hold_expiry() {
        let ctx = ctx();
        let mut adj = Adjacency::new(THEM);
        process_hello(
            &mut adj,
            &ctx,
            &hello(None, vec![vec![0x49, 0x00, 0x01]], Level::Level1And2, 30),
            100,
        )
        .unwrap();
        assert!(!adj.hold_expired(129));
        assert!(adj.hold_expired(131));
        assert_eq!(
            process_hold_expired(&mut adj),
            Action::AdjacencyDown("hold time expired")
        );
        assert_eq!(adj.state, AdjacencyState::Down);
        // Idempotent.
        assert_eq!(process_hold_expired(&mut adj), Action::None);
    }

    /// The neighbor's areas and circuit id are captured for the LSP
    /// (the IIH view).
    #[test]
    fn neighbor_bookkeeping() {
        let ctx = ctx();
        let mut adj = Adjacency::new(THEM);
        let areas = vec![vec![0x49, 0x00, 0x01], vec![0x49]];
        process_hello(
            &mut adj,
            &ctx,
            &hello(
                Some(ThreewayState::Initializing),
                areas.clone(),
                Level::Level1And2,
                45,
            ),
            10,
        )
        .unwrap();
        assert_eq!(adj.neighbor_areas, areas);
        assert_eq!(adj.neighbor_extended_circuit_id, Some(9));
        assert_eq!(adj.holding_time, 45);
        assert_eq!(adj.last_hello_at, 10);
    }
}
