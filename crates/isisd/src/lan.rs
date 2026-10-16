//! The broadcast/LAN circuit engine: LAN IIH acceptance (ISO 10589
//! §8.4.1's LAN tables via RFC 1142), neighbour tracking with CODE 6's
//! Up condition (§8.4.1.5), and DIS election (§8.4.4).
//!
//! **DIS election, §8.4.4 verbatim**: "A LAN Designated Intermediate
//! System is the highest priority Intermediate system in a particular
//! set on the LAN, with numerically highest MAC source lANAddress
//! breaking ties. The set consists of: the local Intermediate system,
//! together with those Intermediate systems from which LAN Level n IIH
//! PDUs have been received and to which Level n adjacencies exist in
//! state Up" — plus the standing condition that "An Intermediate
//! system shall not declare itself to be a LAN Designated Intermediate
//! system of any type until it has at least one Up Intermediate system
//! adjacency on the circuit". Election is preemptive (§7.2.3: an IS
//! "shall resign" when "some other Intermediate system of higher
//! priority has taken over that function" — the opposite of OSPF's
//! non-preemptive DR), and it runs separately per level (§7.2.3:
//! "There shall be a LAN Level 1 Designated Intermediate system and a
//! LAN Level 2 Designated Intermediate system").
//!
//! **The LAN ID** (§8.4.4): our own systemID followed by a one-octet
//! nonzero Local Circuit ID when we are the DIS; otherwise the LAN ID
//! received in the DIS's IIHs.
//!
//! **Adjacency states on a LAN** (§8.4.1.5): a neighbour is Up once
//! "R reports this circuit's lANAddress in its Level n LAN IIH PDUs"
//! — the CODE 6 SNPA list — and stays Up while IIHs keep arriving
//! within the holding time. There is no three-way handshake on LANs
//! (RFC 5303's TLV 240 is p2p-only).
//!
//! **Acceptance** differs from the p2p tables by level: a Level 1 LAN
//! IIH from a disjoint area is an initializationFailure (§8.4.1.2:
//! "shall take no further action"); a Level 2 LAN IIH is always
//! acceptable (§8.4.1.3: "shall accept the adjacency") — the area
//! match is an L1-only rule on LANs. The NLPID rule (RFC 1195 §5.2)
//! and the own-sysid discard apply at both levels, as on p2p.

use std::collections::HashMap;

use crate::system::{Level, NeighborId, SystemId};
use crate::tlv::{Tlv, NLPID_IPV4};

/// The default LAN priority (ISO §9.5's 7-bit field; FRR's
/// `ISIS_DEFAULT_PRIORITY` — 64).
pub const DEFAULT_LAN_PRIORITY: u8 = 64;

/// One LAN neighbour (the IIH view).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LanNeighbor {
    pub system: SystemId,
    /// The SNPA (MAC) their IIHs come from — CODE 6's entry shape
    /// and the election tie-break input.
    pub snpa: [u8; 6],
    pub priority: u8,
    pub holding_time: u16,
    /// §8.4.1.5: they list our MAC in their CODE 6.
    pub up: bool,
    /// The LAN ID they report (the DIS as they see it).
    pub lan_id: NeighborId,
    pub last_hello_at: u64,
}

/// One candidate in a DIS election (§8.4.4's set).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DisCandidate {
    pub system: SystemId,
    pub priority: u8,
    pub snpa: [u8; 6],
    /// The LAN ID this candidate reports when it is the DIS (self:
    /// systemID + local circuit id; a neighbour: the LAN ID from its
    /// IIHs).
    pub lan_id: NeighborId,
}

/// §8.4.4's election over a candidate set: highest priority, ties
/// broken by the numerically highest MAC SNPA. `None` only for an
/// empty set (the caller keeps "no DIS" until a candidate exists).
pub fn elect_dis(candidates: &[DisCandidate]) -> Option<DisCandidate> {
    candidates
        .iter()
        .copied()
        .max_by(|a, b| (a.priority, a.snpa).cmp(&(b.priority, b.snpa)))
}

/// One received LAN IIH, already codec-decoded, distilled to what
/// the engine consumes (the p2p `HelloInfo` shape).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LanHelloInfo {
    pub level2: bool,
    pub source: SystemId,
    pub priority: u8,
    pub holding_time: u16,
    /// The LAN id the sender reports (the DIS as they see it).
    pub lan_id: NeighborId,
    /// TLV 1's area addresses.
    pub areas: Vec<Vec<u8>>,
    /// TLV 129's NLPIDs.
    pub nlpids: Vec<u8>,
    /// TLV 6's SNPA list — §8.4.1.5's Up condition reads our own MAC
    /// out of it.
    pub code6: Vec<[u8; 6]>,
    pub now: u64,
}

/// What a LAN IIH did to the circuit state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LanAction {
    /// The neighbour reached Up (§8.4.1.5's CODE 6 condition) — the
    /// LSP regen + sync trigger.
    NeighborUp(SystemId),
    /// A neighbour left Up (their CODE 6 dropped us).
    NeighborDown(SystemId),
    /// The DIS changed; the fields are the new LAN ID and whether
    /// WE are now the DIS (§7.2.3's takeover/resignation: originate
    /// pseudonode LSPs / purge ours).
    DisChanged { lan_id: NeighborId, us: bool },
    /// The DIS record was refreshed with no change.
    None,
}

/// The LAN circuit engine, pure and clock-injected (the p2p FSM's
/// conventions). One instance per level the daemon runs on a
/// broadcast circuit.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LanCircuit {
    pub our_system_id: SystemId,
    pub our_snpa: [u8; 6],
    pub our_priority: u8,
    pub our_areas: Vec<Vec<u8>>,
    /// The circuit's is-type (the IIH circuit type we transmit).
    pub our_level: Level,
    /// Our nonzero Local Circuit ID — the pseudonode octet of OUR
    /// LAN ID when we are the DIS (§8.4.4).
    pub local_circuit_id: u8,
    neighbors: HashMap<SystemId, LanNeighbor>,
    /// The current DIS LAN ID (None until elected).
    dis: Option<NeighborId>,
}

impl LanCircuit {
    pub fn new(
        our_system_id: SystemId,
        our_snpa: [u8; 6],
        our_priority: u8,
        our_areas: Vec<Vec<u8>>,
        our_level: Level,
        local_circuit_id: u8,
    ) -> Self {
        Self {
            our_system_id,
            our_snpa,
            our_priority,
            our_areas,
            our_level,
            local_circuit_id,
            neighbors: HashMap::new(),
            dis: None,
        }
    }

    pub fn neighbors(&self) -> impl Iterator<Item = &LanNeighbor> {
        self.neighbors.values()
    }

    /// The Up neighbours (§8.4.1.5).
    pub fn up_neighbors(&self) -> impl Iterator<Item = &LanNeighbor> + '_ {
        self.neighbors.values().filter(|n| n.up)
    }

    /// Our candidate record (§8.4.4's "local Intermediate system").
    fn self_candidate(&self) -> DisCandidate {
        DisCandidate {
            system: self.our_system_id,
            priority: self.our_priority,
            snpa: self.our_snpa,
            lan_id: NeighborId::new(self.our_system_id, self.local_circuit_id),
        }
    }

    /// §8.4.4's set: the best Up-or-Initializing neighbour versus
    /// ourselves — highest priority, numerically highest MAC
    /// breaking ties — but "an Intermediate system shall not declare
    /// itself to be a LAN Designated Intermediate system ... until it
    /// has at least one Up Intermediate system adjacency on the
    /// circuit": we only WIN with an Up neighbour to serve (a set
    /// with no Up adjacency still elects the best neighbour).
    /// Callers re-run this after every IIH and every state change
    /// (the election is preemptive, §7.2.3).
    pub fn elect(&self) -> Option<DisCandidate> {
        let best = self
            .neighbors
            .values()
            .map(|n| DisCandidate {
                system: n.system,
                priority: n.priority,
                snpa: n.snpa,
                lan_id: n.lan_id,
            })
            .max_by(|a, b| (a.priority, a.snpa).cmp(&(b.priority, b.snpa)))?;
        let we_win = self.our_priority > best.priority
            || (self.our_priority == best.priority && self.our_snpa > best.snpa);
        if we_win && self.up_neighbors().next().is_some() {
            Some(self.self_candidate())
        } else {
            Some(best)
        }
    }

    /// The LAN ID to stamp in our IIHs (§8.4.4): ours when we are
    /// the DIS, the elected neighbour's when not, `None` before any
    /// election produces a DIS.
    pub fn lan_id(&self) -> Option<NeighborId> {
        self.elect().map(|w| w.lan_id)
    }

    /// Whether WE hold the DIS role right now.
    pub fn is_dis(&self) -> bool {
        self.elect().is_some_and(|w| w.system == self.our_system_id)
    }

    /// The CODE 6 list for our IIHs: the SNPA of every known
    /// neighbour, Up or Initializing (§9.5 "IS Neighbours" — the MACs
    /// whose IIHs we have been receiving; FRR 10.2.2's
    /// `isis_adj_build_neigh_list` includes both states, and the
    /// bootstrap dance needs it: neither side reaches Up until it
    /// sees its own MAC listed, so the first-heard neighbour must
    /// appear while still Initializing).
    pub fn code6_list(&self) -> Vec<[u8; 6]> {
        let mut macs: Vec<[u8; 6]> = self.neighbors.values().map(|n| n.snpa).collect();
        macs.sort();
        macs.dedup();
        macs
    }

    /// Re-run the election and report a DIS change as an action
    /// (§7.2.3's takeover/resignation).
    fn refresh_dis(&mut self) -> LanAction {
        let new = self.elect().map(|w| w.lan_id);
        match (self.dis, new) {
            (old, Some(new)) if old != Some(new) => {
                let us = new.system == self.our_system_id;
                self.dis = Some(new);
                LanAction::DisChanged { lan_id: new, us }
            }
            (Some(_), None) => {
                // The set emptied: the DIS record lapses.
                self.dis = None;
                LanAction::DisChanged {
                    lan_id: NeighborId::new(self.our_system_id, 0),
                    us: false,
                }
            }
            _ => LanAction::None,
        }
    }

    /// Process one accepted LAN IIH (already codec-decoded). Pure
    /// aside from the injected clock. Returns the action, or the
    /// rejection reason before any state change.
    pub fn process_hello(&mut self, hello: &LanHelloInfo) -> Result<LanAction, &'static str> {
        let LanHelloInfo {
            level2,
            source,
            priority,
            holding_time,
            lan_id,
            areas,
            nlpids,
            code6,
            now,
        } = hello;
        if *source == self.our_system_id {
            return Err("own system id (ISO 10589: discard)");
        }
        if !nlpids.contains(&NLPID_IPV4) {
            return Err("no IPv4 NLPID (OSI-only or non-IP peer)");
        }
        // §8.4.1.2 vs §8.4.1.3: the area match is an L1-only rule on
        // LANs — an L2 LAN IIH "shall" be accepted regardless of
        // area (L2 carries between areas).
        if !*level2 && !self.our_areas.iter().any(|a| areas.contains(a)) {
            return Err("L1 LAN IIH with no shared area (ISO 8.4.1.2)");
        }
        let us_listed = code6.contains(&self.our_snpa);
        let entry = self.neighbors.entry(*source).or_insert(LanNeighbor {
            system: *source,
            // Placeholder until the frame's source MAC lands via
            // `note_snpa` (the IIH body does not carry the sender's
            // own SNPA — CODE 6 names the MACs the SENDER heard).
            snpa: self.our_snpa,
            priority: 0,
            holding_time: *holding_time,
            up: false,
            lan_id: *lan_id,
            last_hello_at: *now,
        });
        let was_up = entry.up;
        entry.priority = priority & 0x7f;
        entry.holding_time = *holding_time;
        entry.up = us_listed;
        entry.lan_id = *lan_id;
        entry.last_hello_at = *now;
        let state_change = match (was_up, us_listed) {
            (false, true) => Some(LanAction::NeighborUp(*source)),
            (true, false) => Some(LanAction::NeighborDown(*source)),
            _ => None,
        };
        let dis_change = self.refresh_dis();
        // The Up transition outranks the DIS bookkeeping in the
        // return value; callers handle both by re-originating, and
        // `refresh_dis` already recorded the DIS change internally.
        Ok(state_change.unwrap_or(dis_change))
    }

    /// Attach the frame's source MAC as the neighbour's SNPA (the
    /// transport knows it; the IIH body does not carry it). Called
    /// by the daemon with the parsed frame before `process_hello`
    /// state is consulted — a direct setter for the first-heard
    /// neighbour.
    pub fn note_snpa(&mut self, source: SystemId, snpa: [u8; 6], now: u64) {
        let entry = self.neighbors.entry(source).or_insert(LanNeighbor {
            system: source,
            snpa,
            priority: 0,
            holding_time: 0,
            up: false,
            lan_id: NeighborId::new(source, 0),
            last_hello_at: now,
        });
        entry.snpa = snpa;
    }

    /// Hold expiry (ISO §8.4.1.5's "Holdtimer expired" — the
    /// neighbour record is deleted). Returns the actions, DIS
    /// refresh included.
    pub fn tick(&mut self, now: u64) -> Vec<LanAction> {
        let mut actions = Vec::new();
        let expired: Vec<SystemId> = self
            .neighbors
            .iter()
            .filter(|(_, n)| {
                n.holding_time > 0 && now.saturating_sub(n.last_hello_at) > n.holding_time as u64
            })
            .map(|(&s, _)| s)
            .collect();
        for system in expired {
            if let Some(n) = self.neighbors.remove(&system) {
                if n.up {
                    actions.push(LanAction::NeighborDown(system));
                }
            }
        }
        if let LanAction::DisChanged { .. } = self.refresh_dis() {
            actions.push(self.dis_change_action());
        }
        actions
    }

    fn dis_change_action(&self) -> LanAction {
        match self.dis {
            Some(lan_id) => LanAction::DisChanged {
                lan_id,
                us: lan_id.system == self.our_system_id,
            },
            None => LanAction::DisChanged {
                lan_id: NeighborId::new(self.our_system_id, 0),
                us: false,
            },
        }
    }
}

/// Pull the CODE 6 entries out of an IIH's TLV list.
pub fn code6_of(tlvs: &[Tlv]) -> Vec<[u8; 6]> {
    tlvs.iter()
        .filter_map(|t| match t {
            Tlv::LanNeighbors(m) => Some(m.clone()),
            _ => None,
        })
        .flatten()
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    const US: SystemId = SystemId::from_bytes([0, 0, 0, 0, 0, 1]);
    const A: SystemId = SystemId::from_bytes([0, 0, 0, 0, 0, 2]);
    const B: SystemId = SystemId::from_bytes([0, 0, 0, 0, 0, 3]);
    const OUR_MAC: [u8; 6] = [0x02, 0, 0, 0, 0, 1];
    const A_MAC: [u8; 6] = [0x02, 0, 0, 0, 0, 2];
    const B_MAC: [u8; 6] = [0x01, 0, 0, 0, 0, 3];
    fn areas() -> Vec<Vec<u8>> {
        vec![vec![0x49, 0x00, 0x01]]
    }

    fn circuit() -> LanCircuit {
        LanCircuit::new(
            US,
            OUR_MAC,
            DEFAULT_LAN_PRIORITY,
            areas(),
            Level::Level1And2,
            1,
        )
    }

    /// §8.4.4's two axes over the bare candidate set: priority first,
    /// numerically-highest-MAC ties.
    #[test]
    fn election_priority_then_snpa() {
        let mk = |system, priority, snpa: u8| DisCandidate {
            system,
            priority,
            snpa: [0x02, 0, 0, 0, 0, snpa],
            lan_id: NeighborId::new(system, 1),
        };
        // Priority dominates.
        let set = [mk(A, 64, 0x09), mk(B, 65, 0x01)];
        assert_eq!(elect_dis(&set).unwrap().system, B);
        // Tie -> numerically highest MAC (byte-wise).
        let set = [mk(A, 64, 0x09), mk(B, 64, 0x10)];
        assert_eq!(elect_dis(&set).unwrap().system, B);
        let set = [mk(A, 64, 0x2a), mk(B, 64, 0x10)];
        assert_eq!(elect_dis(&set).unwrap().system, A);
        // Empty set: no DIS.
        assert!(elect_dis(&[]).is_none());
    }

    /// The dance: both sides hear each other (CODE 6 grows), the
    /// neighbour reaches Up, the higher-priority peer becomes DIS —
    /// and §8.4.4's standing condition: we only declare ourselves DIS
    /// with an Up adjacency.
    #[test]
    fn lan_adjacency_and_dis_takeover() {
        let mut lan = circuit();
        // Their first IIH: they do not list us yet — Initializing.
        let action = lan
            .process_hello(&LanHelloInfo {
                level2: true,
                source: A,
                priority: 70,
                holding_time: 30,
                lan_id: NeighborId::new(A, 1),
                areas: areas(),
                nlpids: [0xCC].to_vec(),
                code6: [].to_vec(),
                now: 0,
            })
            .unwrap();
        assert_eq!(
            action,
            LanAction::DisChanged {
                lan_id: NeighborId::new(A, 1),
                us: false
            }
        );
        assert!(!lan.neighbors().next().unwrap().up);
        assert!(!lan.is_dis());

        // They now list our MAC: Up (§8.4.1.5), and at priority 70
        // they stay DIS.
        lan.note_snpa(A, A_MAC, 1);
        let action = lan
            .process_hello(&LanHelloInfo {
                level2: true,
                source: A,
                priority: 70,
                holding_time: 30,
                lan_id: NeighborId::new(A, 1),
                areas: areas(),
                nlpids: [0xCC].to_vec(),
                code6: [OUR_MAC].to_vec(),
                now: 2,
            })
            .unwrap();
        assert_eq!(action, LanAction::NeighborUp(A));
        assert!(lan.up_neighbors().next().is_some());
        assert_eq!(lan.lan_id(), Some(NeighborId::new(A, 1)));

        // A second neighbour joins the set at our priority: with an
        // Up adjacency we would beat B on the MAC tie-break (ours is
        // numerically higher), but A stays DIS at priority 70.
        lan.note_snpa(B, B_MAC, 3);
        lan.process_hello(&LanHelloInfo {
            level2: true,
            source: B,
            priority: 64,
            holding_time: 30,
            lan_id: NeighborId::new(A, 1),
            areas: areas(),
            nlpids: vec![0xCC],
            code6: vec![OUR_MAC],
            now: 3,
        })
        .unwrap();
        assert_eq!(lan.lan_id(), Some(NeighborId::new(A, 1)));

        // A restarts at lower priority than us: preemption (§7.2.3's
        // resignation) — WE take over with our Local Circuit ID as
        // the pseudonode octet.
        let action = lan
            .process_hello(&LanHelloInfo {
                level2: true,
                source: A,
                priority: 10,
                holding_time: 30,
                lan_id: NeighborId::new(A, 1),
                areas: areas(),
                nlpids: vec![0xCC],
                code6: vec![OUR_MAC],
                now: 4,
            })
            .unwrap();
        assert_eq!(
            action,
            LanAction::DisChanged {
                lan_id: NeighborId::new(US, 1),
                us: true
            }
        );
        assert!(lan.is_dis());
        assert_eq!(
            lan.code6_list(),
            vec![B_MAC, A_MAC],
            "CODE 6 lists the neighbours' MACs, sorted"
        );
    }

    /// We never win the election without an Up adjacency (§8.4.4's
    /// standing condition) — a lone Initializing neighbour keeps the
    /// DIS role even when our priority is higher.
    #[test]
    fn no_dis_without_an_up_adjacency() {
        let mut lan = circuit();
        lan.note_snpa(A, A_MAC, 0);
        lan.process_hello(&LanHelloInfo {
            level2: true,
            source: A,
            priority: 10,
            holding_time: 30,
            lan_id: NeighborId::new(A, 1),
            areas: areas(),
            nlpids: [0xCC].to_vec(),
            code6: [].to_vec(),
            now: 0,
        })
        .unwrap();
        assert!(!lan.is_dis(), "no Up adjacency: we do not take over");
        assert_eq!(lan.lan_id(), Some(NeighborId::new(A, 1)));
    }

    /// §8.4.1.2 vs §8.4.1.3: a disjoint-area L1 LAN IIH is rejected;
    /// the same peer at L2 is accepted.
    #[test]
    fn area_rule_is_level_gated() {
        let mut lan = circuit();
        let disjoint = vec![vec![0x49, 0x00, 0x09]];
        assert_eq!(
            lan.process_hello(&LanHelloInfo {
                level2: false,
                source: A,
                priority: 64,
                holding_time: 30,
                lan_id: NeighborId::new(A, 1),
                areas: disjoint.clone(),
                nlpids: [0xCC].to_vec(),
                code6: [].to_vec(),
                now: 0,
            }),
            Err("L1 LAN IIH with no shared area (ISO 8.4.1.2)")
        );
        assert!(lan.neighbors().next().is_none(), "rejected: no record");
        assert!(
            lan.process_hello(&LanHelloInfo {
                level2: true,
                source: A,
                priority: 64,
                holding_time: 30,
                lan_id: NeighborId::new(A, 1),
                areas: disjoint.clone(),
                nlpids: [0xCC].to_vec(),
                code6: [].to_vec(),
                now: 0,
            })
            .is_ok(),
            "L2 accepts across areas (8.4.1.3)"
        );
        // OSI-only peer rejected at both levels (RFC 1195 §5.2).
        assert!(lan
            .process_hello(&LanHelloInfo {
                level2: true,
                source: A,
                priority: 64,
                holding_time: 30,
                lan_id: NeighborId::new(A, 1),
                areas: areas(),
                nlpids: [].to_vec(),
                code6: [].to_vec(),
                now: 1,
            })
            .is_err());
    }

    /// Hold expiry removes the record and refreshes the DIS (§8.4.1.5
    /// "Holdtimer expired").
    #[test]
    fn hold_expiry_drops_neighbors() {
        let mut lan = circuit();
        lan.note_snpa(A, A_MAC, 0);
        lan.process_hello(&LanHelloInfo {
            level2: true,
            source: A,
            priority: 70,
            holding_time: 30,
            lan_id: NeighborId::new(A, 1),
            areas: areas(),
            nlpids: vec![0xCC],
            code6: vec![OUR_MAC],
            now: 0,
        })
        .unwrap();
        assert!(lan.up_neighbors().next().is_some());
        assert!(lan.tick(30).is_empty(), "not yet");
        let actions = lan.tick(31);
        assert!(matches!(
            actions.as_slice(),
            [
                LanAction::NeighborDown(A),
                LanAction::DisChanged { us: false, .. }
            ]
        ));
        assert!(lan.neighbors().next().is_none());
    }
}
