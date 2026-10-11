//! The ospfd daemon: sockets, timers, and the SPF/flood loop that
//! drives the landed cores (W2-e Day 2).
//!
//! Event loop shape (the bfdd session-loop convention — no sockets'
//! lifecycles inside the protocol logic): per-interface raw sockets
//! ([`crate::transport`]) each run a recv task feeding one mpsc; the
//! main loop selects over packets, the 1-second tick (§14 aging,
//! §C.3 hellos, RxmtInterval retransmits), zapi redistribute pushes,
//! and shutdown. The demultiplex rule (no SO_BINDTODEVICE — the
//! transport module's fence): each raw socket receives EVERY proto-89
//! datagram, so a packet is processed only when its on-link source
//! matches the socket's own interface.
//!
//! v1 scope, disclosed: interfaces run the §9 PointToPoint arm
//! (`network-type point-to-point`); the broadcast arm (Waiting, DR/
//! BDR election, network-LSA origination) is landed and tested in
//! `iface`/`origination` but not yet driven here. Router ID and
//! interface addresses come from config (see `zedge` for the
//! ROUTER_ID_ADD/INTERFACE_ADD_REQUEST omissions). One area.
//!
//! Route export: every SPF run diffs the intra-area routes (§16.1)
//! plus the §16.4-lite external routes against the installed table
//! and emits ZEBRA_ROUTE_ADD/_DELETE (protocol OSPF) through the
//! zapi edge.

use std::collections::{BTreeMap, HashMap};
use std::net::Ipv4Addr;
use std::sync::Arc;

use common::{Ipv4Prefix, Nexthop, NexthopGroup, RouteEntry, RouteProtocol};
use tokio::sync::mpsc;
use tracing::{debug, info, warn};

use crate::config::{InterfaceConfig, NetworkType, OspfdConfig};
use crate::exchange::{Conversation, ConversationParams, ConversationReport, Send};
use crate::iface::InterfaceFsm;
use crate::lsa::{Lsa, LsaKey, LsaType, Options, RouterId};
use crate::lsdb::{Lsdb, Readopt};
use crate::neighbor::process_hello;
use crate::neighbor::{HelloParams, NeighborEvent, NeighborState};
use crate::origination::{build_external_lsa, build_router_lsa, InterfaceAdv};
use crate::packet::{Hello, LsUpdate, Packet, PacketBody};
use crate::spf::{self, Destination, SpfScheduler};
use crate::transport::{OspfRawSocket, Received};
use crate::zedge::{RedistributedRoute, ZedgeCommand};

/// An inbound packet event: (interface index, datagram).
pub type Inbound = (usize, Received);

/// One OSPF interface under the daemon.
pub struct Interface {
    pub name: String,
    pub cfg: InterfaceConfig,
    pub addr: Ipv4Addr,
    pub mask: Ipv4Addr,
    pub p2p: bool,
    pub fsm: InterfaceFsm,
    /// The elected DR/BDR addresses on a broadcast network (§9.4's
    /// result; also our Hello's DR/BDR claim fields, §A.3.2 —
    /// 0.0.0.0 while Waiting).
    pub dr: Ipv4Addr,
    pub bdr: Ipv4Addr,
    /// §9.3's WaitTimer deadline (monotonic seconds), broadcast only.
    pub wait_deadline: Option<u64>,
    /// Per-neighbor Hello claims on a broadcast network (§9.2/§9.4's
    /// election inputs: priority + the DR/BDR each neighbor claims).
    pub claims: HashMap<RouterId, crate::iface::ElectionNeighbor>,
    /// Neighbors keyed by Router ID.
    pub neighbors: HashMap<RouterId, Conversation>,
    /// Next hello deadline (monotonic seconds).
    hello_deadline: u64,
}

impl Interface {
    fn conversation_params(&self) -> ConversationParams {
        ConversationParams {
            rxmt_interval: 5,
            mtu: self.cfg.mtu,
            options: Options(Options::E),
        }
    }

    /// §10.4's adjacency decision on a broadcast network: only the
    /// DR and BDR pairs — "all routers become adjacent to both the
    /// Designated Router and the Backup Designated Router". The
    /// neighbor is identified by its interface address matching the
    /// elected DR/BDR (§A.3.2: the claim fields name addresses).
    fn adjacency_ok(&self, nbr_addr: Ipv4Addr) -> bool {
        matches!(
            self.fsm.state,
            crate::iface::InterfaceState::Dr | crate::iface::InterfaceState::Backup
        ) || nbr_addr == self.dr
            || nbr_addr == self.bdr
    }
}

/// The daemon state machine core. `now` is monotonic seconds since
/// start (clock-injected throughout; `run` owns the real clock).
pub struct Ospfd {
    pub router_id: RouterId,
    pub area_id: u32,
    pub interfaces: Vec<Interface>,
    pub lsdb: Lsdb,
    spf_sched: SpfScheduler,
    /// The exported route table (prefix string -> entry).
    routes: BTreeMap<String, RouteEntry>,
    /// Self-originated external LSAs (prefix string -> key).
    externals: BTreeMap<String, LsaKey>,
    /// Router-LSA re-origination pending (adjacency change or refresh).
    router_lsa_dirty: bool,
    /// Self-originated network-LSAs per interface (§12.4.2) — the
    /// flush handles on losing DR.
    network_lsas: HashMap<usize, LsaKey>,
    /// Network-LSA re-origination pending per interface.
    network_lsa_dirty: Vec<usize>,
    /// Whether any external LSA exists (the router-LSA E-bit, §12.4.3).
    asbr: bool,
    /// SPF pending (an LSA changed contents; §16 runs on the
    /// throttle window).
    spf_dirty: bool,
    zapi: Option<mpsc::UnboundedSender<ZedgeCommand>>,
    redistribute_static: bool,
}

/// What the core wants put on the wire after one input.
#[derive(Clone)]
pub struct WireOut {
    pub iface: usize,
    pub to: WireTo,
    pub packet: Packet,
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum WireTo {
    /// AllSPFRouters, 224.0.0.5 (§A.1) — Hellos and the DR/BDR
    /// floods on broadcast networks.
    Multicast,
    /// AllDRouters, 224.0.0.6 (§A.1) — a DR Other's flood on a
    /// broadcast network (§13.3: only the DR/BDR process it).
    AllDRouters,
    Unicast(Ipv4Addr),
}

impl Ospfd {
    pub fn new(cfg: &OspfdConfig) -> Result<Self, String> {
        let Some(router_id) = cfg.router_id else {
            return Err("router-id is required (v1: no zapi router-id request)".into());
        };
        let mut interfaces = Vec::new();
        for (name, icfg) in &cfg.interfaces {
            let Some((addr, mask)) = icfg.address else {
                return Err(format!(
                    "interface {name}: address <a.b.c.d/m> is required (v1)"
                ));
            };
            if addr.is_unspecified() || addr.is_loopback() {
                return Err(format!(
                    "interface {name}: address must be a real interface address"
                ));
            }
            let p2p = icfg.network_type == NetworkType::PointToPoint;
            let mut fsm = InterfaceFsm::new_with_priority(p2p, icfg.priority);
            // §9.3 InterfaceUp: the config's address IS the lower
            // layer's usable-interface signal (v1: no link-state
            // tracking) — the interface enters PointToPoint/Waiting
            // (or DR Other at priority 0) at construction.
            let (_, actions) = fsm.fire(crate::iface::InterfaceEvent::InterfaceUp);
            let wait_deadline = if actions.contains(&crate::iface::InterfaceAction::StartWaitTimer)
            {
                // The WaitTimer is the RouterDeadInterval (§9.5.1's
                // startup form), clocked from the daemon's t=0.
                Some(icfg.dead_interval as u64)
            } else {
                None
            };
            interfaces.push(Interface {
                name: name.clone(),
                cfg: icfg.clone(),
                addr,
                mask,
                p2p,
                fsm,
                dr: Ipv4Addr::UNSPECIFIED,
                bdr: Ipv4Addr::UNSPECIFIED,
                wait_deadline,
                claims: HashMap::new(),
                neighbors: HashMap::new(),
                hello_deadline: 0,
            });
        }
        if interfaces.is_empty() {
            return Err("no interfaces configured".into());
        }
        Ok(Self {
            router_id: RouterId::from_ipv4(router_id),
            area_id: cfg.area_id,
            interfaces,
            lsdb: Lsdb::new(),
            spf_sched: SpfScheduler::new(0, 50, 5000),
            routes: BTreeMap::new(),
            externals: BTreeMap::new(),
            router_lsa_dirty: true,
            network_lsas: HashMap::new(),
            network_lsa_dirty: Vec::new(),
            asbr: false,
            spf_dirty: false,
            zapi: None,
            redistribute_static: cfg.redistribute_static,
        })
    }

    pub fn attach_zapi(&mut self, tx: mpsc::UnboundedSender<ZedgeCommand>) {
        self.zapi = Some(tx);
    }

    /// The p2p neighbor's IP address on the interface whose own
    /// address is `interface_addr` — §16.1.1's p2p next hop ("the
    /// neighboring router"), which no LSA carries (Link Data is the
    /// ADVERTISER's address); the adjacency (the Hello source) does.
    fn p2p_peer_address(&self, interface_addr: Ipv4Addr) -> Option<Ipv4Addr> {
        self.interfaces
            .iter()
            .filter(|i| i.addr == interface_addr)
            .flat_map(|i| i.neighbors.values())
            .filter(|c| c.state() == NeighborState::Full)
            .map(|c| c.ip)
            .next()
    }

    /// Mark the routing calculation dirty (§16 runs on the throttle
    /// window — FRR-parity backoff). EVERY dirtying site must go
    /// through here: the scheduler's due deadline dies with
    /// `mark_run`, so a bare `spf_dirty` flag without `on_change`
    /// would never fire again.
    fn mark_spf_dirty(&mut self, now: u64) {
        self.spf_sched.on_change(now * 1000);
        self.spf_dirty = true;
    }

    fn packet(&self, body: PacketBody) -> Packet {
        make_packet(self.router_id, self.area_id, body)
    }

    fn hello_now(router_id: RouterId, area_id: u32, iface: &Interface) -> Packet {
        make_hello(router_id, area_id, iface)
    }

    /// Interface advertisement snapshot (§12.4.1's builder input).
    fn interface_advs(&self) -> Vec<InterfaceAdv> {
        self.interfaces
            .iter()
            .map(|i| {
                let full: Vec<RouterId> = i
                    .neighbors
                    .values()
                    .filter(|c| c.state() == NeighborState::Full)
                    .filter_map(|c| c.peer_router_id)
                    .collect();
                let elected = !i.p2p
                    && i.fsm.state != crate::iface::InterfaceState::Waiting
                    && i.dr != Ipv4Addr::UNSPECIFIED;
                // §12.4.1.2's adjacency gate: fully adjacent to the
                // DR (its conversation sits at Full), or we ARE the
                // DR with at least one Full other router.
                let transit_adjacent = if !i.p2p {
                    if i.fsm.state == crate::iface::InterfaceState::Dr {
                        !full.is_empty()
                    } else {
                        i.neighbors
                            .values()
                            .any(|c| c.ip == i.dr && c.state() == NeighborState::Full)
                    }
                } else {
                    false
                };
                InterfaceAdv {
                    state: i.fsm.state,
                    p2p: i.p2p,
                    address: i.addr,
                    mask: i.mask,
                    cost: i.cfg.cost,
                    p2p_neighbors_full: full.clone(),
                    attached_routers: full,
                    dr_address: if elected { Some(i.dr) } else { None },
                    transit_adjacent,
                }
            })
            .collect()
    }

    /// Run the §9.4 election on one interface (the ElectDr action of
    /// the §9.3 rows: WaitTimer, BackupSeen, NeighborChange) and
    /// apply the outcome: the interface's DR/BDR and state (§9.4
    /// steps 5), the AdjOK? re-evaluation on identity changes (step
    /// 7), and the §12.4.2 network-LSA duties on role changes.
    fn run_election(&mut self, idx: usize, now: u64, out: &mut Vec<WireOut>) {
        let (neighbors, own_addr, own_pri, prev) = {
            let iface = &self.interfaces[idx];
            // §9.4's inputs: the bidirectional neighbors' claims
            // (state ≥ 2-Way).
            let neighbors: Vec<crate::iface::ElectionNeighbor> = iface
                .neighbors
                .iter()
                .filter(|(_, c)| c.state().at_least(NeighborState::TwoWay))
                .filter_map(|(rid, _)| iface.claims.get(rid).copied())
                .collect();
            (
                neighbors,
                iface.addr,
                iface.cfg.priority,
                (iface.dr, iface.bdr),
            )
        };
        let own = crate::iface::ElectionNeighbor {
            router_id: self.router_id,
            address: own_addr,
            priority: own_pri,
            // Our claims = what our Hellos carry: the interface's
            // current DR/BDR (§9.4's repeat reads them back).
            dr: prev.0,
            bdr: prev.1,
        };
        let outcome = crate::iface::elect_dr(own, &neighbors, prev);
        let was_role = self.interfaces[idx].fsm.state;
        {
            let iface = &mut self.interfaces[idx];
            iface.dr = outcome.dr;
            iface.bdr = outcome.bdr;
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
                dr = %outcome.dr,
                bdr = %outcome.bdr,
                role = outcome.role.name(),
                "ospfd: DR election (§9.4)"
            );
        }
        if was_role != outcome.role {
            // The transit-link description changed with the role.
            self.router_lsa_dirty = true;
            // §12.4.2: a former DR flushes its network-LSA.
            if was_role == crate::iface::InterfaceState::Dr
                && outcome.role != crate::iface::InterfaceState::Dr
            {
                if let Some(key) = self.network_lsas.remove(&idx) {
                    if let Some(maxage) = self.lsdb.premature_age(&key) {
                        self.flood_own(&maxage, now, out);
                        info!(iface = %self.interfaces[idx].name, "ospfd: network-LSA flushed (no longer DR)");
                    }
                }
            }
            if outcome.role == crate::iface::InterfaceState::Dr {
                self.network_lsa_dirty.push(idx);
            }
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
                self.reevaluate_adjacency(idx, key, now, out);
            }
        }
    }

    /// Fire AdjOK? with §10.4's answer for one neighbor on a
    /// broadcast interface (also the TwoWayReceived decision point).
    fn reevaluate_adjacency(
        &mut self,
        idx: usize,
        peer: RouterId,
        now: u64,
        out: &mut Vec<WireOut>,
    ) {
        let answer = {
            let iface = &self.interfaces[idx];
            match iface.neighbors.get(&peer) {
                Some(c) => iface.adjacency_ok(c.ip),
                None => return,
            }
        };
        let iface = &mut self.interfaces[idx];
        if let Some(conv) = iface.neighbors.get_mut(&peer) {
            let (sends, report) = conv.fire_and_map(NeighborEvent::AdjOk(answer), &self.lsdb, now);
            out.extend(sends_into(idx, sends));
            if report.adjacency_up || report.adjacency_down {
                let _ = iface;
                self.router_lsa_dirty = true;
                if self.interfaces[idx].fsm.state == crate::iface::InterfaceState::Dr {
                    self.network_lsa_dirty.push(idx);
                }
            }
        }
    }

    /// §12.4.2: the DR's network-LSA — originated only while DR and
    /// fully adjacent to at least one other router; flushed on
    /// losing either condition (§12.4.2's premature-aging rule).
    fn originate_network_lsa(&mut self, idx: usize, now: u64, out: &mut Vec<WireOut>) {
        let (state, addr, mask, attached) = {
            let iface = &self.interfaces[idx];
            (
                iface.fsm.state,
                iface.addr,
                iface.mask,
                iface
                    .neighbors
                    .values()
                    .filter(|c| c.state() == NeighborState::Full)
                    .filter_map(|c| c.peer_router_id)
                    .collect::<Vec<_>>(),
            )
        };
        let warranted = state == crate::iface::InterfaceState::Dr && !attached.is_empty();
        if !warranted {
            // §12.4.2: "A router that has formerly been the
            // Designated Router ... should flush the network-LSA".
            if let Some(key) = self.network_lsas.remove(&idx) {
                if let Some(maxage) = self.lsdb.premature_age(&key) {
                    self.flood_own(&maxage, now, out);
                    info!(iface = %self.interfaces[idx].name, "ospfd: network-LSA flushed (§12.4.2)");
                }
            }
            return;
        }
        let adv = InterfaceAdv {
            state,
            p2p: false,
            address: addr,
            mask,
            cost: 10, // unused by the network-LSA body
            p2p_neighbors_full: vec![],
            attached_routers: attached,
            dr_address: Some(addr),
            transit_adjacent: true,
        };
        let lsa = crate::origination::build_network_lsa(self.router_id, &adv, addr);
        let key = lsa.key();
        match self.lsdb.originate(lsa, now) {
            Ok(_) => {
                self.network_lsas.insert(idx, key);
                if let Some(entry) = self.lsdb.get(&key) {
                    let stored = entry.lsa.clone();
                    self.flood_own(&stored, now, out);
                }
                self.mark_spf_dirty(now);
            }
            Err(e) => {
                // MinLSInterval — retry on a later tick.
                debug!(error = %e, "ospfd: network-LSA origination deferred");
            }
        }
    }

    /// (Re-)originate the router-LSA (§12.4.1) and flood it to Full
    /// neighbors (§13.3 retransmission lists armed).
    fn originate_router_lsa(&mut self, now: u64, out: &mut Vec<WireOut>) {
        let lsa = build_router_lsa(self.router_id, self.asbr, &self.interface_advs());
        match self.lsdb.originate(lsa, now) {
            Ok(_) => {
                self.router_lsa_dirty = false;
                // Flood the STORED instance — Lsdb::originate stamped
                // the sequence (§12.1.6); the builder's copy carries
                // the raw 0.
                let key = LsaKey {
                    ls_type: crate::lsa::LsaType::ROUTER,
                    link_state_id: crate::lsa::LinkStateId(self.router_id.0),
                    adv_router: self.router_id,
                };
                if let Some(entry) = self.lsdb.get(&key) {
                    let stored = entry.lsa.clone();
                    self.flood_own(&stored, now, out);
                    // The area graph changed: §16 runs.
                    self.mark_spf_dirty(now);
                }
                info!("ospfd: router-LSA originated");
            }
            Err(e) => {
                // MinLSInterval not elapsed — retry on the next tick.
                debug!(error = %e, "ospfd: router-LSA origination deferred (MinLSInterval)");
            }
        }
    }

    /// §12.4.3: originate the AS-external-LSA for a redistributed
    /// route and flood it; the router-LSA turns on its E-bit (the
    /// router is now an ASBR).
    fn originate_external(
        &mut self,
        prefix: Ipv4Prefix,
        metric: u32,
        now: u64,
        out: &mut Vec<WireOut>,
    ) {
        let lsa = build_external_lsa(
            self.router_id,
            prefix.addr(),
            Ipv4Addr::from(u32::MAX << (32 - prefix.prefix_len())),
            metric,
            true, // type-2 external (FRR's default)
        );
        let key = lsa.key();
        match self.lsdb.originate(lsa, now) {
            Ok(_) => {
                self.externals.insert(prefix.to_string(), key);
                let first = !self.asbr;
                self.asbr = true;
                if let Some(entry) = self.lsdb.get(&key) {
                    let stored = entry.lsa.clone();
                    self.flood_own(&stored, now, out);
                }
                self.mark_spf_dirty(now);
                info!(prefix = %prefix, "ospfd: external LSA originated");
                if first {
                    // The E-bit change re-originates the router-LSA.
                    self.router_lsa_dirty = true;
                }
            }
            Err(e) => debug!(error = %e, "ospfd: external origination deferred"),
        }
    }

    /// §12.4.3's withdrawal: premature-age the LSA (§14.1) and flood
    /// the MaxAge instance.
    fn withdraw_external(&mut self, prefix_str: &str, now: u64, out: &mut Vec<WireOut>) {
        if let Some(key) = self.externals.remove(prefix_str) {
            if let Some(lsa) = self.lsdb.premature_age(&key) {
                self.flood_own(&lsa, now, out);
                info!(
                    prefix = prefix_str,
                    "ospfd: external LSA withdrawn (MaxAge)"
                );
            }
            let _ = now;
        }
    }

    /// §13.4: whether the router currently wishes to originate the
    /// LSA named by `key`. The "no longer wishes" cases drive the
    /// flush: no advertisable route (externals), no longer DR for
    /// the network (network-LSAs), and the Router-ID-changed shape
    /// is handled by `is_our_network` below.
    fn wants_to_originate(&self, key: &LsaKey) -> bool {
        match key.ls_type {
            // Our router-LSA: always (the router exists).
            LsaType::ROUTER => true,
            // §13.4 case 2: the network-LSA only while we are its DR.
            LsaType::NETWORK => self.interfaces.iter().any(|i| {
                u32::from(i.addr) == key.link_state_id.0
                    && i.fsm.state == crate::iface::InterfaceState::Dr
            }),
            // §13.4 case 1: only while the redistributed route exists.
            LsaType::AS_EXTERNAL => self.externals.values().any(|k| k == key),
            // Summary-LSAs: the §12.4.3 set (inter-area, M4); none
            // are originated yet, so any received self-summary is
            // flushed.
            _ => false,
        }
    }

    /// §13.4's reception of self-originated LSAs, run after the LSU's
    /// flooding install: by then the store holds the received
    /// instance whenever it won §13.1, so this sees exactly the
    /// adopted state. Two detections (§13.4): Advertising Router ==
    /// our ID, or a network-LSA whose Link State ID is one of our
    /// interface addresses.
    fn after_self_originated(&mut self, lsas: &[Lsa], now: u64, out: &mut Vec<WireOut>) {
        for lsa in lsas {
            let is_self = lsa.header.adv_router == self.router_id;
            let is_our_network = lsa.header.ls_type == LsaType::NETWORK
                && self
                    .interfaces
                    .iter()
                    .any(|i| u32::from(i.addr) == lsa.header.link_state_id.0);
            if !is_self && !is_our_network {
                continue;
            }
            let key = lsa.key();
            // Only an instance that actually became our stored copy
            // (won §13.1) triggers the special action; older echoes
            // were answered by §13's steps 7/8, MaxAge ones are
            // already flushing.
            let Some(stored) = self.lsdb.get(&key) else {
                continue;
            };
            if stored.lsa.header.seq != lsa.header.seq || stored.lsa.header.is_max_age() {
                continue;
            }
            let stored = stored.lsa.clone();
            if self.wants_to_originate(&key) {
                match self.lsdb.readopt_self_originated(lsa) {
                    Readopt::Advanced => {
                        info!(key = ?key, "ospfd: adopting newer self-originated LSA (§13.4)");
                        // Re-originate past it on the next tick
                        // (MinLSInterval retries included).
                        match key.ls_type {
                            LsaType::ROUTER => self.router_lsa_dirty = true,
                            LsaType::AS_EXTERNAL => {
                                if let crate::lsa::LsaBody::AsExternal(ext) = &stored.body {
                                    let prefix = Ipv4Prefix::new(
                                        stored.header.link_state_id.to_ipv4(),
                                        u32::from(ext.mask).count_ones() as u8,
                                    )
                                    .expect("external mask");
                                    self.originate_external(prefix, ext.metric, now, out);
                                }
                            }
                            // §13.4 case 2 while still DR: re-originate
                            // the network-LSA past the adopted instance.
                            LsaType::NETWORK => {
                                if let Some(idx) = self
                                    .interfaces
                                    .iter()
                                    .position(|i| u32::from(i.addr) == key.link_state_id.0)
                                {
                                    self.network_lsa_dirty.push(idx);
                                }
                            }
                            _ => {}
                        }
                    }
                    Readopt::NeedsFlush => {
                        // §12.1.6 met §13.4: prematurely age our copy
                        // (§14.1) so the sequence can restart.
                        if let Some(maxage) = self.lsdb.premature_age(&key) {
                            self.flood_own(&maxage, now, out);
                        }
                    }
                    Readopt::Stale | Readopt::NotOurs => {}
                }
            } else {
                // §13.4's flush list: increment the received LSA's
                // age to MaxAge and reflood (§14.1).
                if let Some(maxage) = self.lsdb.premature_age(&key) {
                    info!(key = ?key, "ospfd: flushing unwanted self-originated LSA (§13.4)");
                    self.flood_own(&maxage, now, out);
                }
            }
        }
    }

    /// Flood one self-originated LSA to every Full neighbor, arming
    /// §13.3's retransmission lists. The wire shape: p2p unicast per
    /// neighbor; broadcast networks multicast per §13.3/§A.1 — the
    /// DR and BDR send to AllSPFRouters (224.0.0.5), DR Others to
    /// AllDRouters (224.0.0.6) so only the DR/BDR process the flood.
    /// (Retransmissions stay unicast per neighbor — the RxmtInterval
    /// paths in `exchange`.)
    fn flood_own(&mut self, lsa: &Lsa, now: u64, out: &mut Vec<WireOut>) {
        // Collect (interface, neighbor ips, broadcast role) first,
        // then build packets (packet() borrows self immutably).
        let mut targets: Vec<(usize, Vec<Ipv4Addr>, Option<bool>)> = Vec::new();
        for (idx, iface) in self.interfaces.iter_mut().enumerate() {
            let bcast_role = if iface.p2p {
                None
            } else {
                Some(matches!(
                    iface.fsm.state,
                    crate::iface::InterfaceState::Dr | crate::iface::InterfaceState::Backup
                ))
            };
            let ips: Vec<Ipv4Addr> = iface
                .neighbors
                .iter_mut()
                .filter(|(_, c)| c.state() == NeighborState::Full)
                .map(|(_, c)| {
                    c.queue_retransmit(lsa, now);
                    c.ip
                })
                .collect();
            targets.push((idx, ips, bcast_role));
        }
        for (idx, ips, bcast_role) in targets {
            match bcast_role {
                Some(dr_or_bdr) if !ips.is_empty() => {
                    // §13.3: one multicast LSU on the broadcast
                    // network; every Full neighbor is on the
                    // retransmission list.
                    let packet = self.packet(PacketBody::LsUpdate(LsUpdate {
                        lsas: vec![lsa.clone()],
                    }));
                    out.push(WireOut {
                        iface: idx,
                        to: if dr_or_bdr {
                            WireTo::Multicast
                        } else {
                            WireTo::AllDRouters
                        },
                        packet,
                    });
                }
                _ => {
                    for ip in ips {
                        let packet = self.packet(PacketBody::LsUpdate(LsUpdate {
                            lsas: vec![lsa.clone()],
                        }));
                        out.push(WireOut {
                            iface: idx,
                            to: WireTo::Unicast(ip),
                            packet,
                        });
                    }
                }
            }
        }
    }

    /// Process one inbound datagram (already demultiplexed to its
    /// interface by the run loop's on-link test).
    pub fn on_packet(&mut self, iface_idx: usize, received: &Received, now: u64) -> Vec<WireOut> {
        let mut out = Vec::new();
        let packet = match Packet::decode(&received.payload) {
            Ok(p) => p,
            Err(e) => {
                debug!(error = %e, src = %received.src, "ospfd: packet decode failed");
                return out;
            }
        };
        // §A.3.1 checks: version handled by decode; our own Router ID
        // (§A.3: "packets originating from itself"); the area.
        if packet.header.router_id == self.router_id {
            return out;
        }
        if packet.header.area_id != self.area_id {
            debug!(area = packet.header.area_id, src = %received.src, "ospfd: foreign area drop");
            return out;
        }
        // §A.1/§13: packets addressed to AllDRouters (224.0.0.6) are
        // processed only by the DR and BDR on a broadcast network.
        if received.dst == crate::packet::ALL_D_ROUTERS && !self.interfaces[iface_idx].p2p {
            let role = self.interfaces[iface_idx].fsm.state;
            if !matches!(
                role,
                crate::iface::InterfaceState::Dr | crate::iface::InterfaceState::Backup
            ) {
                debug!(src = %received.src, "ospfd: AllDRouters packet while DR Other — drop");
                return out;
            }
        }
        let peer = packet.header.router_id;
        let hello_params = {
            let iface = &self.interfaces[iface_idx];
            HelloParams {
                network_mask: iface.mask,
                hello_interval: iface.cfg.hello_interval,
                router_dead_interval: iface.cfg.dead_interval,
                e_capable: true,
                p2p: iface.p2p,
            }
        };
        match &packet.body {
            PacketBody::Hello(hello) => {
                let events = match process_hello(
                    hello,
                    &hello_params,
                    self.router_id,
                    peer,
                    self.interfaces[iface_idx].p2p,
                ) {
                    Ok(events) => events,
                    Err(e) => {
                        debug!(error = %e, src = %received.src, "ospfd: hello rejected");
                        return out;
                    }
                };
                let dead = self.interfaces[iface_idx].cfg.dead_interval as u64;
                let p2p = self.interfaces[iface_idx].p2p;
                let params = self.interfaces[iface_idx].conversation_params();
                // §9.2's bidirectionality before this hello (the
                // neighbor FSM state prior to the events below).
                let was_2way = self.interfaces[iface_idx]
                    .neighbors
                    .get(&peer)
                    .is_some_and(|c| c.state().at_least(NeighborState::TwoWay));
                // §10.4's answer for the 2-Way decision point,
                // evaluated against the currently elected DR/BDR (the
                // election below runs after the events).
                let adj_answer = p2p || self.interfaces[iface_idx].adjacency_ok(received.src);
                let iface_name = self.interfaces[iface_idx].name.clone();
                let conv = self.interfaces[iface_idx]
                    .neighbors
                    .entry(peer)
                    .or_insert_with(|| {
                        Conversation::new(
                            self.router_id,
                            self.area_id,
                            received.src,
                            now,
                            dead,
                            params,
                        )
                    });
                conv.peer_router_id = Some(peer);
                conv.ip = received.src;
                let mut adj_change = false;
                for event in events {
                    let (event_sends, report) = conv.fire_and_map(event, &self.lsdb, now);
                    out.extend(sends_into(iface_idx, event_sends));
                    conv.touch_inactivity(now, dead);
                    match event {
                        NeighborEvent::TwoWayReceived => {
                            // §10.3's decision point: AdjOK? with
                            // §10.4's answer — p2p always adjacent;
                            // broadcast only with/toward the DR/BDR.
                            let (sends, report) = conv.fire_and_map(
                                NeighborEvent::AdjOk(adj_answer),
                                &self.lsdb,
                                now,
                            );
                            out.extend(sends_into(iface_idx, sends));
                            if report.adjacency_up || report.adjacency_down {
                                adj_change = true;
                            } else if !p2p && !adj_answer {
                                // §10.4: "If the decision is made to
                                // not attempt an adjacency, the state
                                // of the neighbor communication stops
                                // at 2-Way."
                                info!(
                                    iface = %iface_name,
                                    neighbor = %peer,
                                    "ospfd: neighbor stays 2-Way (§10.4: neither side is DR/BDR)"
                                );
                            }
                        }
                        NeighborEvent::OneWayReceived => {
                            adj_change = true;
                        }
                        _ => {}
                    }
                    if report.adjacency_up || report.adjacency_down {
                        adj_change = true;
                    }
                }
                let is_2way = self.interfaces[iface_idx]
                    .neighbors
                    .get(&peer)
                    .is_some_and(|c| c.state().at_least(NeighborState::TwoWay));
                if !p2p {
                    // §9.2/§9.4: the claim snapshot feeds the
                    // interface events (BackupSeen / NeighborChange)
                    // and the election inputs.
                    let new_claims = crate::iface::ElectionNeighbor {
                        router_id: peer,
                        address: received.src,
                        priority: hello.router_priority,
                        dr: hello.designated_router,
                        bdr: hello.backup_designated_router,
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
                    if is_2way && !was_2way && adj_change {
                        // A new bidirectional neighbor extends the
                        // election set (§9.2's first cause).
                        self.network_lsa_dirty.push(iface_idx);
                    }
                    for ev in ism_events {
                        let (_, actions) = self.interfaces[iface_idx].fsm.fire(ev);
                        if actions.contains(&crate::iface::InterfaceAction::ElectDr) {
                            self.run_election(iface_idx, now, &mut out);
                        }
                    }
                }
                if adj_change {
                    self.router_lsa_dirty = true;
                    if !p2p
                        && self.interfaces[iface_idx].fsm.state == crate::iface::InterfaceState::Dr
                    {
                        // §12.4.2: the attached-router list changed.
                        self.network_lsa_dirty.push(iface_idx);
                    }
                }
            }
            PacketBody::DbDescription(_)
            | PacketBody::LsRequest(_)
            | PacketBody::LsUpdate(_)
            | PacketBody::LsAck(_) => {
                // Conversation packets from unknown neighbors are
                // dropped (§10.6 rejects in Down; we have no record).
                let syncing = self.any_syncing();
                let iface = &mut self.interfaces[iface_idx];
                let Some(conv) = iface.neighbors.get_mut(&peer) else {
                    debug!(src = %received.src, "ospfd: conversation packet from unknown neighbor");
                    return out;
                };
                let mut received_lsas: Option<Vec<Lsa>> = None;
                let (sends, report) = match &packet.body {
                    PacketBody::DbDescription(dd) => {
                        conv.handle_dbd(dd, peer, iface.cfg.mtu, &mut self.lsdb, now)
                    }
                    PacketBody::LsRequest(lsr) => conv.handle_lsr(lsr, &mut self.lsdb, now),
                    PacketBody::LsUpdate(lsu) => {
                        let (sends, report) =
                            conv.handle_lsu(&lsu.lsas, &mut self.lsdb, now, syncing);
                        received_lsas = Some(lsu.lsas.clone());
                        (sends, report)
                    }
                    PacketBody::LsAck(ack) => {
                        conv.handle_lsack(&ack.headers);
                        (Vec::new(), ConversationReport::default())
                    }
                    PacketBody::Hello(_) => unreachable!(),
                };
                out.extend(sends_into(iface_idx, sends));
                // §13.4's self-originated reception, after the
                // flooding install (see the method note).
                if let Some(lsas) = received_lsas {
                    self.after_self_originated(&lsas, now, &mut out);
                }
                self.after_report(iface_idx, Some(peer), &report, now);
            }
        }
        out
    }

    /// §13 step 4 / §14's removal condition b: any adjacency in
    /// Exchange or Loading.
    fn any_syncing(&self) -> bool {
        self.interfaces.iter().any(|iface| {
            iface
                .neighbors
                .values()
                .any(|c| matches!(c.state(), NeighborState::Exchange | NeighborState::Loading))
        })
    }

    fn after_report(
        &mut self,
        iface_idx: usize,
        peer: Option<RouterId>,
        report: &ConversationReport,
        now: u64,
    ) {
        if report.adjacency_up {
            info!(
                iface = %self.interfaces[iface_idx].name,
                neighbor = peer.map(|p| p.to_string()).unwrap_or_default(),
                "ospfd: adjacency FULL"
            );
            self.router_lsa_dirty = true;
            // §12.4.2: the attached-router list grew — the DR's
            // network-LSA re-originates (the not-yet-warranted first
            // attempt retries here).
            if !self.interfaces[iface_idx].p2p
                && self.interfaces[iface_idx].fsm.state == crate::iface::InterfaceState::Dr
            {
                self.network_lsa_dirty.push(iface_idx);
            }
        }
        if report.adjacency_down {
            self.router_lsa_dirty = true;
            if !self.interfaces[iface_idx].p2p
                && self.interfaces[iface_idx].fsm.state == crate::iface::InterfaceState::Dr
            {
                self.network_lsa_dirty.push(iface_idx);
            }
        }
        if !report.changed.is_empty() {
            // The SPF throttle (FRR-parity 0/50/5000 ms backoff).
            self.mark_spf_dirty(now);
        }
    }

    /// Fire pending SPF when the throttle window opens, diff the
    /// route table, and emit zapi adds/deletes.
    pub fn maybe_spf(&mut self, now: u64, zapi_out: &mut Vec<ZedgeCommand>) {
        if !self.spf_dirty || !self.spf_sched.is_due(now * 1000) {
            return;
        }
        self.spf_sched.mark_run(now * 1000);
        self.spf_dirty = false;
        let result = spf::calculate(self.router_id, &self.lsdb);
        let mut fresh: BTreeMap<String, RouteEntry> = BTreeMap::new();
        for route in &result.routes {
            let Destination::Network { addr, mask } = route.destination else {
                continue; // Router destinations feed §16.4 below
            };
            let prefix = Ipv4Prefix::new(addr, mask_prefix(mask)).expect("valid mask from SPF");
            let mut nexthops = NexthopGroup::new();
            for nh in &route.next_hops {
                nexthops.add(
                    match nh.router {
                        Some(r) => Nexthop::Ipv4(r),
                        // p2p first hop: the adjacency's address (the
                        // interface-form hop is not a valid gateway).
                        None => match self.p2p_peer_address(nh.interface) {
                            Some(peer) => Nexthop::Ipv4(peer),
                            None => continue,
                        },
                    },
                    1,
                );
            }
            let entry = RouteEntry::new(
                common::IpPrefix::V4(prefix),
                RouteProtocol::Ospf,
                nexthops,
                route.cost,
            );
            fresh.insert(prefix.to_string(), entry);
        }
        // §16.4-lite: external routes from type-5 LSAs. §16.4.1 steps
        // 1-5, single-area form: the "distance to the ASBR" is the
        // intra-area route to the advertising router (§16.4.1 step
        // 5c); the type-4 summary lookup of a multi-area ASBR is
        // §Deferred with inter-area routing.
        let router_routes: HashMap<RouterId, &spf::Route> = result
            .routes
            .iter()
            .filter_map(|r| match r.destination {
                Destination::Router(id) => Some((id, r)),
                _ => None,
            })
            .collect();
        for entry in self.lsdb.all() {
            if entry.lsa.header.ls_type != LsaType::AS_EXTERNAL
                || entry.lsa.header.is_max_age()
                || entry.lsa.header.adv_router == self.router_id
            {
                continue;
            }
            let crate::lsa::LsaBody::AsExternal(ext) = &entry.lsa.body else {
                continue;
            };
            let Some(asbr_route) = router_routes.get(&entry.lsa.header.adv_router) else {
                continue; // ASBR unreachable — §16.4.1 step 5
            };
            let cost = if ext.e_bit {
                ext.metric.min(crate::LS_INFINITY)
            } else {
                asbr_route.cost.saturating_add(ext.metric)
            };
            let prefix = Ipv4Prefix::new(
                entry.lsa.header.link_state_id.to_ipv4(),
                u32::from(ext.mask).count_ones() as u8,
            )
            .expect("external mask");
            let hops: Vec<Nexthop> = if ext.forwarding_address != Ipv4Addr::UNSPECIFIED {
                vec![Nexthop::Ipv4(ext.forwarding_address)]
            } else {
                asbr_route
                    .next_hops
                    .iter()
                    .filter_map(|nh| match nh.router {
                        Some(r) => Some(Nexthop::Ipv4(r)),
                        None => self.p2p_peer_address(nh.interface).map(Nexthop::Ipv4),
                    })
                    .collect()
            };
            let mut group = NexthopGroup::new();
            for hop in hops {
                group.add(hop, 1);
            }
            let entry_out = RouteEntry::new(
                common::IpPrefix::V4(prefix),
                RouteProtocol::Ospf,
                group,
                cost,
            );
            fresh.insert(prefix.to_string(), entry_out);
        }
        // Diff against the installed table.
        let old_keys: Vec<String> = self.routes.keys().cloned().collect();
        for key in old_keys {
            if !fresh.contains_key(&key) {
                if let Some(entry) = self.routes.remove(&key) {
                    info!(prefix = %key, "ospfd: OSPF route withdrawn");
                    zapi_out.push(ZedgeCommand::RouteDel(entry));
                }
            }
        }
        for (key, entry) in fresh {
            let changed = self
                .routes
                .get(&key)
                .map(|old| *old != entry)
                .unwrap_or(true);
            if changed {
                info!(prefix = %key, metric = entry.metric, "ospfd: OSPF route installed");
                self.routes.insert(key, entry.clone());
                zapi_out.push(ZedgeCommand::RouteAdd(entry));
            } else {
                self.routes.insert(key, entry);
            }
        }
    }

    /// The 1-second tick: hellos, the WaitTimer, neighbor timers,
    /// aging, deferred originations, SPF.
    pub fn tick(&mut self, now: u64, out: &mut Vec<WireOut>, zapi_out: &mut Vec<ZedgeCommand>) {
        // §C.3 Hellos.
        let (router_id, area_id) = (self.router_id, self.area_id);
        for (idx, iface) in self.interfaces.iter_mut().enumerate() {
            if now >= iface.hello_deadline {
                iface.hello_deadline = now + iface.cfg.hello_interval as u64;
                let packet = Self::hello_now(router_id, area_id, iface);
                out.push(WireOut {
                    iface: idx,
                    to: WireTo::Multicast,
                    packet,
                });
            }
        }
        // §9.3's WaitTimer (broadcast): the deferral before the
        // first election ends — fire it once and elect.
        let mut wait_fired: Vec<usize> = Vec::new();
        for (idx, iface) in self.interfaces.iter().enumerate() {
            if iface.wait_deadline.is_some_and(|d| now >= d) {
                wait_fired.push(idx);
            }
        }
        for idx in wait_fired {
            self.interfaces[idx].wait_deadline = None;
            let (_, actions) = self.interfaces[idx]
                .fsm
                .fire(crate::iface::InterfaceEvent::WaitTimer);
            if actions.contains(&crate::iface::InterfaceAction::ElectDr) {
                self.run_election(idx, now, out);
            }
        }
        // Neighbor timers (inactivity, DD/LSR/LSU retransmits).
        let mut down_events: Vec<(usize, RouterId)> = Vec::new();
        for (idx, iface) in self.interfaces.iter_mut().enumerate() {
            let keys: Vec<RouterId> = iface.neighbors.keys().copied().collect();
            for key in keys {
                let Some(conv) = iface.neighbors.get_mut(&key) else {
                    continue;
                };
                let (sends, report) = conv.tick(now);
                out.extend(sends_into(idx, sends));
                if report.adjacency_down {
                    down_events.push((idx, key));
                }
            }
        }
        if !down_events.is_empty() {
            self.router_lsa_dirty = true;
            for (idx, key) in &down_events {
                info!(neighbor = %key, "ospfd: neighbor timed out (Inactivity Timer)");
                // §9.2's second NeighborChange cause: a neighbor left
                // the bidirectional set — re-elect on broadcast, and
                // the network-LSA's attached list lost a router.
                if !self.interfaces[*idx].p2p {
                    self.run_election(*idx, now, out);
                    self.network_lsa_dirty.push(*idx);
                }
            }
        }
        // §14 aging.
        let report = self.lsdb.tick_aging(now);
        for key in report.refresh_due {
            let _ = key;
            self.router_lsa_dirty = true;
            // §12.4.2 refresh: the network-LSA rides the same
            // refresh cadence.
            let matches: Vec<usize> = self
                .network_lsas
                .iter()
                .filter(|(_, v)| **v == key)
                .map(|(idx, _)| *idx)
                .collect();
            for idx in matches {
                self.network_lsa_dirty.push(idx);
            }
        }
        if !report.max_age.is_empty() {
            // §14: reflood the MaxAge instances (the flush); removal
            // follows flush_ready below once acked.
            let lsas: Vec<Lsa> = report
                .max_age
                .iter()
                .filter_map(|k| self.lsdb.get(k).map(|e| e.lsa.clone()))
                .collect();
            if !lsas.is_empty() {
                let packet = self.packet(PacketBody::LsUpdate(LsUpdate { lsas }));
                for idx in 0..self.interfaces.len() {
                    out.push(WireOut {
                        iface: idx,
                        to: WireTo::Multicast,
                        packet: packet.clone(),
                    });
                }
            }
        }
        for key in self.lsdb.flush_ready(self.any_syncing()) {
            if let Some(removed) = self.lsdb.remove(&key) {
                debug!(key = ?key, len = removed.header.length, "ospfd: LSA flushed (MaxAge)");
                self.mark_spf_dirty(now);
            }
        }
        // Deferred originations (MinLSInterval retries).
        if self.router_lsa_dirty {
            self.originate_router_lsa(now, out);
        }
        let dirty_networks: Vec<usize> = std::mem::take(&mut self.network_lsa_dirty);
        for idx in dirty_networks {
            self.originate_network_lsa(idx, now, out);
        }
        // SPF when due.
        self.maybe_spf(now, zapi_out);
    }

    /// A redistributed static route from zebra (§12.4.3).
    pub fn on_redistribute_add(
        &mut self,
        route: RedistributedRoute,
        now: u64,
        out: &mut Vec<WireOut>,
    ) {
        let common::IpPrefix::V4(prefix) = route.prefix else {
            return;
        };
        info!(prefix = %prefix, "ospfd: redistribute static -> external LSA");
        self.originate_external(prefix, route.metric, now, out);
    }

    pub fn on_redistribute_del(
        &mut self,
        route: RedistributedRoute,
        now: u64,
        out: &mut Vec<WireOut>,
    ) {
        let common::IpPrefix::V4(prefix) = route.prefix else {
            return;
        };
        self.withdraw_external(&prefix.to_string(), now, out);
    }

    /// Current neighbor states (operator surface / tests).
    pub fn neighbor_states(&self) -> Vec<(String, RouterId, NeighborState)> {
        let mut v = Vec::new();
        for iface in &self.interfaces {
            for (rid, conv) in &iface.neighbors {
                v.push((iface.name.clone(), *rid, conv.state()));
            }
        }
        v
    }
}

fn make_packet(router_id: RouterId, area_id: u32, body: PacketBody) -> Packet {
    Packet {
        header: crate::packet::PacketHeader {
            version: 2,
            packet_type: body.packet_type(),
            length: 0,
            router_id,
            area_id,
            checksum: 0,
            au_type: 0,
            authentication: 0,
        },
        body,
    }
}

fn make_hello(router_id: RouterId, area_id: u32, iface: &Interface) -> Packet {
    let body = PacketBody::Hello(Hello {
        // §C.3: the mask of the attached network; 0.0.0.0 is the
        // convention on p2p (ignored by receivers anyway).
        network_mask: if iface.p2p {
            Ipv4Addr::UNSPECIFIED
        } else {
            iface.mask
        },
        hello_interval: iface.cfg.hello_interval,
        options: Options(Options::E),
        router_priority: iface.cfg.priority,
        router_dead_interval: iface.cfg.dead_interval,
        // §A.3.2: our DR/BDR claims — the interface's elected values
        // on broadcast (0.0.0.0 while Waiting), 0.0.0.0 on p2p (no
        // election runs there).
        designated_router: if iface.p2p {
            Ipv4Addr::UNSPECIFIED
        } else {
            iface.dr
        },
        backup_designated_router: if iface.p2p {
            Ipv4Addr::UNSPECIFIED
        } else {
            iface.bdr
        },
        neighbors: iface
            .neighbors
            .values()
            .filter(|c| c.in_hello())
            .filter_map(|c| c.peer_router_id)
            .collect(),
    });
    make_packet(router_id, area_id, body)
}

fn sends_into(iface_idx: usize, sends: Vec<Send>) -> Vec<WireOut> {
    sends
        .into_iter()
        .map(|s| WireOut {
            iface: iface_idx,
            to: WireTo::Unicast(s.to),
            packet: s.packet,
        })
        .collect()
}

fn mask_prefix(mask: Ipv4Addr) -> u8 {
    u32::from(mask).count_ones() as u8
}

/// The resident async loop: sockets, recv tasks, timers, zapi.
pub async fn run(
    mut core: Ospfd,
    sockets: Vec<Arc<OspfRawSocket>>,
    mut pushed: mpsc::UnboundedReceiver<RedistributedRoute>,
    mut withdrawn: mpsc::UnboundedReceiver<RedistributedRoute>,
    mut shutdown: tokio::sync::watch::Receiver<bool>,
) -> std::io::Result<()> {
    let (tx, mut rx) = mpsc::channel::<Inbound>(1024);
    for (idx, sock) in sockets.iter().enumerate() {
        let sock = Arc::clone(sock);
        let tx = tx.clone();
        tokio::spawn(async move {
            let mut buf = vec![0u8; 65535];
            loop {
                match sock.recv(&mut buf).await {
                    Ok(Some(received)) => {
                        if tx.send((idx, received)).await.is_err() {
                            return;
                        }
                    }
                    Ok(None) => unreachable!("async recv blocks until ready"),
                    Err(e) => {
                        warn!(error = %e, "ospfd: recv error");
                        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
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
        interfaces = core.interfaces.len(),
        redistribute_static = core.redistribute_static,
        "ospfd: running"
    );
    // §A.1's membership duty: interfaces electing themselves DR/BDR
    // join AllDRouters (224.0.0.6); the sync runs after every core
    // step so §9.4 role changes take effect immediately.
    let mut dr_joined: Vec<bool> = vec![false; sockets.len()];
    macro_rules! sync_dr_membership {
        () => {
            for (idx, sock) in sockets.iter().enumerate() {
                let need = core
                    .interfaces
                    .get(idx)
                    .is_some_and(|i| {
                        matches!(
                            i.fsm.state,
                            crate::iface::InterfaceState::Dr | crate::iface::InterfaceState::Backup
                        )
                    });
                if need != dr_joined[idx] {
                    let result = if need {
                        sock.join_all_drouters()
                    } else {
                        sock.leave_all_drouters()
                    };
                    match result {
                        Ok(()) => {
                            dr_joined[idx] = need;
                            info!(
                                iface = %core.interfaces[idx].name,
                                joined = need,
                                "ospfd: AllDRouters membership (§9.4/§A.1)"
                            );
                        }
                        Err(e) => warn!(error = %e, "ospfd: AllDRouters membership change failed"),
                    }
                }
            }
        };
    }
    // The first hello and the router-LSA go out at once.
    let mut out = Vec::new();
    let mut zapi_out = Vec::new();
    core.tick(0, &mut out, &mut zapi_out);
    flush_wire(&sockets, &core, out).await;
    flush_zapi(&core, zapi_out).await;
    sync_dr_membership!();

    loop {
        tokio::select! {
            inbound = rx.recv() => {
                let Some((idx, received)) = inbound else { break };
                // The demultiplex fence: process only on the interface
                // whose subnet contains the source (each raw socket
                // delivers every proto-89 datagram).
                let iface = &core.interfaces[idx];
                let src = u32::from(received.src);
                let mask = u32::from(iface.mask);
                if src & mask != u32::from(iface.addr) & mask {
                    continue;
                }
                let now = start.elapsed().as_secs();
                let out = core.on_packet(idx, &received, now);
                flush_wire(&sockets, &core, out).await;
                sync_dr_membership!();
            }
            _ = tick_interval.tick() => {
                let now = start.elapsed().as_secs();
                let mut out = Vec::new();
                let mut zapi_out = Vec::new();
                core.tick(now, &mut out, &mut zapi_out);
                flush_wire(&sockets, &core, out).await;
                flush_zapi(&core, zapi_out).await;
                sync_dr_membership!();
            }
            route = pushed.recv() => {
                if let Some(route) = route {
                    let now = start.elapsed().as_secs();
                    let mut out = Vec::new();
                    core.on_redistribute_add(route, now, &mut out);
                    flush_wire(&sockets, &core, out).await;
                }
            }
            route = withdrawn.recv() => {
                if let Some(route) = route {
                    let now = start.elapsed().as_secs();
                    let mut out = Vec::new();
                    core.on_redistribute_del(route, now, &mut out);
                    flush_wire(&sockets, &core, out).await;
                }
            }
            _ = shutdown.changed() => {
                info!("ospfd: shutdown");
                return Ok(());
            }
        }
    }
    Ok(())
}

async fn flush_wire(sockets: &[Arc<OspfRawSocket>], core: &Ospfd, out: Vec<WireOut>) {
    for wire in out {
        let Some(sock) = sockets.get(wire.iface) else {
            continue;
        };
        let bytes = wire.packet.encode();
        let result = match wire.to {
            WireTo::Multicast => sock.send_multicast(&bytes).await,
            WireTo::AllDRouters => sock.send_multicast_drouters(&bytes).await,
            WireTo::Unicast(dst) => sock.send_unicast(&bytes, dst).await,
        };
        if let Err(e) = result {
            warn!(error = %e, iface = %core.interfaces[wire.iface].name, "ospfd: send failed");
        }
    }
}

async fn flush_zapi(core: &Ospfd, out: Vec<ZedgeCommand>) {
    if let Some(tx) = &core.zapi {
        for command in out {
            let _ = tx.send(command);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::parse as parse_config;
    use crate::packet::PacketBody;
    use std::net::Ipv4Addr;

    fn ip(s: &str) -> Ipv4Addr {
        s.parse().unwrap()
    }

    fn core_for(router_id: &str, ifname: &str, addr: &str) -> Ospfd {
        let text = format!(
            "router ospf\n router-id {router_id}\n area 0.0.0.0\n  interface {ifname}\n   address {addr}/30\n   network-type point-to-point\n redistribute static\n"
        );
        Ospfd::new(&parse_config(&text).unwrap()).unwrap()
    }

    /// A broadcast-network core (§C.3 defaults + fast timers).
    fn bcast_core(router_id: &str, addr: &str, priority: u8) -> Ospfd {
        let text = format!(
            "router ospf\n router-id {router_id}\n area 0.0.0.0\n  interface eth0\n   address {addr}/24\n   network-type broadcast\n   priority {priority}\n   hello-interval 1\n   dead-interval 4\n"
        );
        Ospfd::new(&parse_config(&text).unwrap()).unwrap()
    }

    /// Extract the packet bodies from one core's wire output.
    fn bodies(out: &[WireOut]) -> Vec<(Option<Ipv4Addr>, Packet)> {
        out.iter()
            .map(|w| {
                let to = match w.to {
                    WireTo::Multicast | WireTo::AllDRouters => None,
                    WireTo::Unicast(dst) => Some(dst),
                };
                (to, w.packet.clone())
            })
            .collect()
    }

    /// Deliver one core's wire output into the other core (the
    /// transport's on-link demux and encode/decode are exercised
    /// implicitly by Packet::decode in on_packet).
    fn pump(from: &mut Ospfd, to: &mut Ospfd, out: Vec<WireOut>, now: u64) -> Vec<WireOut> {
        let mut replies = Vec::new();
        for (_, packet) in bodies(&out) {
            let payload = packet.encode();
            let idx = 0;
            replies.extend(to.on_packet(
                idx,
                &crate::transport::Received {
                    src: {
                        // Pretend the packet arrived from the sender's
                        // interface address (the on-link source).
                        from.interfaces[0].addr
                    },
                    dst: crate::packet::ALL_SPF_ROUTERS,
                    payload,
                },
                now,
            ));
        }
        let _ = from;
        replies
    }

    #[test]
    fn two_daemons_reach_full_and_install_routes() {
        let mut a = core_for("10.255.1.1", "eth0", "10.77.0.1");
        let mut b = core_for("10.255.2.1", "eth0", "10.77.0.2");

        // Bring the interfaces up (§9 InterfaceUp) and run ticks until
        // both report Full neighbors and both have the other's stub
        // network route installed (SPF export).
        for core in [&mut a, &mut b] {
            core.interfaces[0]
                .fsm
                .fire(crate::iface::InterfaceEvent::InterfaceUp);
        }
        let mut now = 0u64;
        // Direction-tagged queue: true = the sends originated on A.
        let mut queue: Vec<(bool, Vec<WireOut>)> = Vec::new();
        let mut out_a = Vec::new();
        let mut out_b = Vec::new();
        let mut zap_a: Vec<crate::zedge::ZedgeCommand> = Vec::new();
        let mut zap_b: Vec<crate::zedge::ZedgeCommand> = Vec::new();
        a.tick(now, &mut out_a, &mut zap_a);
        b.tick(now, &mut out_b, &mut zap_b);
        if !out_a.is_empty() {
            queue.push((true, out_a));
        }
        if !out_b.is_empty() {
            queue.push((false, out_b));
        }

        let full = |c: &Ospfd| {
            c.neighbor_states()
                .iter()
                .any(|(_, _, s)| *s == NeighborState::Full)
        };
        let mut iterations = 0;
        while !(full(&a) && full(&b)) && iterations < 200 {
            iterations += 1;
            // Drain every pending exchange obligation first.
            while !queue.is_empty() {
                let (from_a, out) = queue.remove(0);
                let replies = if from_a {
                    pump(&mut a, &mut b, out, now)
                } else {
                    pump(&mut b, &mut a, out, now)
                };
                if !replies.is_empty() {
                    queue.push((!from_a, replies));
                }
            }
            // Quiet: advance the clock 1 s and tick both sides
            // (hellos at HelloInterval, retransmits at RxmtInterval).
            now += 1;
            let mut oa = Vec::new();
            let mut ob = Vec::new();
            a.tick(now, &mut oa, &mut zap_a);
            b.tick(now, &mut ob, &mut zap_b);
            if !oa.is_empty() {
                queue.push((true, oa));
            }
            if !ob.is_empty() {
                queue.push((false, ob));
            }
        }
        assert!(iterations < 200, "adjacency never settled");
        assert!(
            a.neighbor_states()
                .iter()
                .any(|(_, _, s)| *s == NeighborState::Full),
            "A reached Full"
        );
        assert!(
            b.neighbor_states()
                .iter()
                .any(|(_, _, s)| *s == NeighborState::Full),
            "B reached Full"
        );

        // SPF ran on both sides: each holds the other's router-LSA
        // and an intra-area route to the shared /30's stub network.
        for (me, other) in [(&a, "10.255.2.1"), (&b, "10.255.1.1")] {
            let key = crate::lsa::LsaKey {
                ls_type: crate::lsa::LsaType::ROUTER,
                link_state_id: crate::lsa::LinkStateId(ip(other).into()),
                adv_router: RouterId::from_ipv4(ip(other)),
            };
            assert!(me.lsdb.contains(&key), "{other}'s router-LSA installed");
        }

        // Route export: the walk's ticks ran SPF through its
        // throttle and emitted the zapi obligations as they arose.
        assert!(
            zap_b
                .iter()
                .any(|c| matches!(c, crate::zedge::ZedgeCommand::RouteAdd(_))),
            "B exported OSPF routes to zebra"
        );
        let prefixes: Vec<String> = zap_b
            .iter()
            .filter_map(|c| match c {
                crate::zedge::ZedgeCommand::RouteAdd(entry) => Some(entry.prefix.to_string()),
                _ => None,
            })
            .collect();
        assert!(
            prefixes.iter().any(|p| p.starts_with("10.77.0.")),
            "the shared stub network is a route: {prefixes:?}"
        );
        assert!(
            b.routes.keys().any(|k| k.starts_with("10.77.0.")),
            "B's installed table holds the stub route"
        );

        // Redistribute: a static push becomes an external LSA on A,
        // floods to B, and B's §16.4-lite installs it as an OSPF
        // route (type-2 external).
        let mut out = Vec::new();
        a.on_redistribute_add(
            crate::zedge::RedistributedRoute {
                prefix: common::IpPrefix::V4(Ipv4Prefix::new(ip("198.51.100.0"), 24).unwrap()),
                metric: 20,
            },
            now + 6,
            &mut out,
        );
        assert!(
            out.iter()
                .any(|w| matches!(w.packet.body, PacketBody::LsUpdate(_))),
            "the external LSA flooded to the Full neighbor"
        );
        // A is now an ASBR (the router-LSA E-bit): re-originate.
        a.router_lsa_dirty = true;
        let mut out2 = Vec::new();
        a.tick(now + 11, &mut out2, &mut Vec::new());
        let mut staged: Vec<(bool, Vec<WireOut>)> = vec![(true, out)];
        if !out2.is_empty() {
            staged.push((true, out2));
        }
        // One quiet tick each side lets the SPF throttle open.
        let mut oa3 = Vec::new();
        let mut ob3 = Vec::new();
        a.tick(now + 11, &mut oa3, &mut zap_a);
        b.tick(now + 11, &mut ob3, &mut zap_b);
        if !oa3.is_empty() {
            staged.push((true, oa3));
        }
        if !ob3.is_empty() {
            staged.push((false, ob3));
        }
        let mut rounds = 0;
        while !staged.is_empty() {
            let (from_a, sends) = staged.remove(0);
            rounds += 1;
            assert!(rounds < 50);
            let replies = if from_a {
                pump(&mut a, &mut b, sends, now + 11)
            } else {
                pump(&mut b, &mut a, sends, now + 11)
            };
            if !replies.is_empty() {
                staged.push((!from_a, replies));
            }
        }
        // Flush B's SPF after the external arrived (the throttle
        // opens on the next quiet tick).
        let mut ob4 = Vec::new();
        b.tick(now + 12, &mut ob4, &mut zap_b);
        if !ob4.is_empty() {
            let _ = pump(&mut b, &mut a, ob4, now + 12);
        }
        // B installed the external route through §16.4-lite.
        let ext_routes: Vec<String> = zap_b
            .iter()
            .filter_map(|c| match c {
                crate::zedge::ZedgeCommand::RouteAdd(entry) => Some(entry.prefix.to_string()),
                _ => None,
            })
            .collect();
        assert!(
            ext_routes.iter().any(|p| p == "198.51.100.0/24"),
            "B installed the redistributed external route: {ext_routes:?}"
        );
    }

    /// Run two cores (already constructed) to mutual Full adjacency.
    /// Returns the clock at settlement.
    fn run_to_full(a: &mut Ospfd, b: &mut Ospfd, mut now: u64) -> u64 {
        let mut queue: Vec<(bool, Vec<WireOut>)> = Vec::new();
        let mut zap: Vec<crate::zedge::ZedgeCommand> = Vec::new();
        let mut oa = Vec::new();
        let mut ob = Vec::new();
        a.tick(now, &mut oa, &mut zap);
        b.tick(now, &mut ob, &mut zap);
        if !oa.is_empty() {
            queue.push((true, oa));
        }
        if !ob.is_empty() {
            queue.push((false, ob));
        }
        let full = |c: &Ospfd| {
            c.neighbor_states()
                .iter()
                .any(|(_, _, s)| *s == NeighborState::Full)
        };
        let mut iterations = 0;
        while !(full(a) && full(b)) && iterations < 300 {
            iterations += 1;
            while !queue.is_empty() {
                let (from_a, sends) = queue.remove(0);
                let replies = if from_a {
                    pump(a, b, sends, now)
                } else {
                    pump(b, a, sends, now)
                };
                if !replies.is_empty() {
                    queue.push((!from_a, replies));
                }
            }
            now += 1;
            let mut oa = Vec::new();
            let mut ob = Vec::new();
            a.tick(now, &mut oa, &mut zap);
            b.tick(now, &mut ob, &mut zap);
            if !oa.is_empty() {
                queue.push((true, oa));
            }
            if !ob.is_empty() {
                queue.push((false, ob));
            }
        }
        assert!(iterations < 300, "adjacency never settled");
        assert!(full(a) && full(b));
        // Drain any residual exchange traffic.
        while !queue.is_empty() {
            let (from_a, sends) = queue.remove(0);
            let replies = if from_a {
                pump(a, b, sends, now)
            } else {
                pump(b, a, sends, now)
            };
            if !replies.is_empty() {
                queue.push((!from_a, replies));
            }
        }
        now
    }

    #[test]
    fn restart_adopts_a_newer_self_originated_router_lsa_back() {
        // §13.4's restart case (the W2-e §Deferred repro): B holds
        // A's router-LSA at seq S when A restarts. A's fresh instance
        // (InitialSequenceNumber) is OLDER; without the re-adoption A
        // sticks at the stale instance forever. With it, A adopts the
        // received instance, re-originates at S+1, and B accepts.
        let mut a = core_for("10.255.1.1", "eth0", "10.77.0.1");
        let mut b = core_for("10.255.2.1", "eth0", "10.77.0.2");
        let now = run_to_full(&mut a, &mut b, 0);

        // B's stored copy of A's router-LSA — the pre-restart
        // instance A will be handed back.
        let key = crate::lsa::LsaKey {
            ls_type: crate::lsa::LsaType::ROUTER,
            link_state_id: crate::lsa::LinkStateId(ip("10.255.1.1").into()),
            adv_router: RouterId::from_ipv4(ip("10.255.1.1")),
        };
        let pre_restart = b.lsdb.get(&key).unwrap().lsa.clone();
        let seq = pre_restart.header.seq;
        assert!(
            seq > crate::lsa::INITIAL_SEQUENCE_NUMBER,
            "multiple originations happened"
        );

        // A restarts: a fresh core with the same Router ID. Its first
        // router-LSA is at InitialSequenceNumber — older than the
        // instance B holds.
        let mut a2 = core_for("10.255.1.1", "eth0", "10.77.0.1");
        let mut zap = Vec::new();
        let mut oa = Vec::new();
        a2.tick(now, &mut oa, &mut zap);
        assert_eq!(
            a2.lsdb.get(&key).unwrap().lsa.header.seq,
            crate::lsa::INITIAL_SEQUENCE_NUMBER
        );
        // The re-established adjacency delivers B's copy through the
        // normal DBD/LSR exchange (B's is newer than a2's).
        let now2 = run_to_full(&mut a2, &mut b, now);

        // §13.4 fired: the tracking advanced one past the received
        // instance, and the re-origination (MinLSInterval past a2's
        // first, hence the quiet ticks) consumed it — the stored
        // instance carries S+1 (asserted below, after the drain).
        assert!(
            a2.lsdb.next_seq_for(&key).unwrap() > seq as i32,
            "tracking advanced past the received instance"
        );
        let mut a2_seq = a2.lsdb.get(&key).unwrap().lsa.header.seq;
        let mut settled = now2;
        for _ in 0..12 {
            if a2_seq == seq + 1 {
                break;
            }
            settled += 1;
            let mut oa = Vec::new();
            let mut ob = Vec::new();
            a2.tick(settled, &mut oa, &mut zap);
            b.tick(settled, &mut ob, &mut zap);
            for (from_a, sends) in [(true, oa), (false, ob)] {
                let replies = if from_a {
                    pump(&mut a2, &mut b, sends, settled)
                } else {
                    pump(&mut b, &mut a2, sends, settled)
                };
                if !replies.is_empty() {
                    let _ = pump(&mut a2, &mut b, replies, settled);
                }
            }
            a2_seq = a2.lsdb.get(&key).unwrap().lsa.header.seq;
        }
        assert_eq!(
            a2.lsdb.get(&key).unwrap().lsa.header.seq,
            seq + 1,
            "the re-originated instance is one past the adopted one (§13.4)"
        );
        // B accepted it (§13.1: S+1 beats S).
        assert_eq!(b.lsdb.get(&key).unwrap().lsa.header.seq, seq + 1);
    }

    #[test]
    fn unwanted_self_originated_external_is_flushed() {
        // §13.4's "no longer wishes to originate" flush: a peer echoes
        // an AS-external LSA under our Router ID that is not in our
        // redistributed set — it must be prematurely aged (§14.1) and
        // the MaxAge instance reflooded, not adopted.
        let mut a = core_for("10.255.1.1", "eth0", "10.77.0.1");
        let mut b = core_for("10.255.2.1", "eth0", "10.77.0.2");
        let now = run_to_full(&mut a, &mut b, 0);

        // Hand A an LSU from B carrying "our" external LSA at a
        // sequence well past anything A originated.
        let foreign = crate::origination::build_external_lsa(
            a.router_id,
            ip("198.51.100.0"),
            ip("255.255.255.0"),
            20,
            true,
        );
        let key = foreign.key();
        let mut foreign = foreign.with_computed_header();
        foreign.header.seq = crate::lsa::INITIAL_SEQUENCE_NUMBER + 40;
        foreign = foreign.with_computed_header();
        // The packet must carry B's Router ID (A drops packets it
        // originates, §A.3.1's self-check).
        let payload = b
            .packet(PacketBody::LsUpdate(LsUpdate {
                lsas: vec![foreign.clone()],
            }))
            .encode();
        let out = a.on_packet(
            0,
            &crate::transport::Received {
                src: b.interfaces[0].addr,
                dst: crate::packet::ALL_SPF_ROUTERS,
                payload,
            },
            now + 1,
        );
        // The flush reflood went out and the stored copy is MaxAge.
        assert!(
            out.iter()
                .any(|w| matches!(w.packet.body, PacketBody::LsUpdate(_))),
            "the MaxAge instance is reflooded (§14.1)"
        );
        let stored = a.lsdb.get(&key).unwrap();
        assert!(stored.lsa.header.is_max_age(), "flushed, not adopted");
        // The re-adoption did NOT advance any tracking (no want).
        assert!(!a.externals.values().any(|k| *k == key));
    }

    // ---- broadcast networks (§7.3/§9.4/§10.4/§12.4.2) -----------

    /// Deliver one core's wire output to every other core on the
    /// shared broadcast network — multicast to all, unicast to the
    /// addressed neighbor only (§A.1's two addresses). Cores in
    /// `dead` neither send nor receive (the silent-wire model of a
    /// crashed router).
    fn deliver_mesh(
        cores: &mut [Ospfd],
        from: usize,
        outs: &[WireOut],
        now: u64,
        dead: &[usize],
        queue: &mut Vec<(usize, Vec<WireOut>)>,
    ) {
        if dead.contains(&from) {
            return;
        }
        let from_addr = cores[from].interfaces[0].addr;
        // The on-link destinations: multicast reaches every core,
        // unicast only the addressed neighbor (§A.1).
        let targets: Vec<usize> = (0..cores.len())
            .filter(|i| *i != from && !dead.contains(i))
            .collect();
        for (dst, packet) in bodies(outs) {
            let payload = packet.encode();
            for i in &targets {
                let i = *i;
                {
                    if let Some(d) = dst {
                        // Unicast: only the addressed neighbor processes.
                        if cores[i].interfaces[0].addr != d {
                            continue;
                        }
                    }
                    let replies = cores[i].on_packet(
                        0,
                        &crate::transport::Received {
                            src: from_addr,
                            dst: crate::packet::ALL_SPF_ROUTERS,
                            payload: payload.clone(),
                        },
                        now,
                    );
                    if !replies.is_empty() {
                        queue.push((i, replies));
                    }
                }
            }
        }
    }

    /// Run a mesh of broadcast cores (dead ones stay silent) until
    /// the collective state — neighbor states, DR/BDR, LSDB
    /// (key,seq,age), routes — holds still for `stable_for`
    /// consecutive seconds. (Hello traffic is steady-state noise at
    /// HelloInterval 1; a quiet-wire criterion would never fire.)
    fn run_mesh(cores: &mut [Ospfd], start: u64, stable_for: u64, dead: &[usize]) -> u64 {
        fn digest(cores: &[Ospfd], dead: &[usize]) -> u64 {
            let mut h: u64 = 0x9e37_79b9;
            for (i, core) in cores.iter().enumerate() {
                if dead.contains(&i) {
                    continue;
                }
                for iface in &core.interfaces {
                    h = h.wrapping_mul(31).wrapping_add(u32::from(iface.dr) as u64);
                    h = h.wrapping_mul(31).wrapping_add(u32::from(iface.bdr) as u64);
                    h = h.wrapping_mul(31).wrapping_add(iface.fsm.state as u64);
                    for (rid, c) in &iface.neighbors {
                        h = h.wrapping_mul(31).wrapping_add(rid.0 as u64);
                        h = h.wrapping_mul(31).wrapping_add(c.state() as u64);
                    }
                }
                for entry in core.lsdb.all() {
                    // Ages advance every second (§14 steady state) —
                    // seq alone captures instance churn.
                    h = h.wrapping_mul(31).wrapping_add(entry.lsa.header.seq as u64);
                }
                h = h.wrapping_mul(31).wrapping_add(core.routes.len() as u64);
            }
            h
        }
        let mut now = start;
        let mut queue: Vec<(usize, Vec<WireOut>)> = Vec::new();
        let mut zap: Vec<crate::zedge::ZedgeCommand> = Vec::new();
        let mut outs: Vec<Vec<WireOut>> = cores.iter_mut().map(|_| Vec::new()).collect();
        for i in 0..cores.len() {
            if !dead.contains(&i) {
                cores[i].tick(now, &mut outs[i], &mut zap);
            }
        }
        for (i, o) in outs.iter().enumerate() {
            if !o.is_empty() {
                deliver_mesh(cores, i, o, now, dead, &mut queue);
            }
        }
        let mut last = digest(cores, dead);
        let mut quiet = 0u64;
        for _ in 0..400 {
            // Drain all pending traffic first.
            while !queue.is_empty() {
                let batch = std::mem::take(&mut queue);
                for (from, outs) in batch {
                    deliver_mesh(cores, from, &outs, now, dead, &mut queue);
                }
            }
            let d = digest(cores, dead);
            if d == last {
                quiet += 1;
                if quiet >= stable_for {
                    return now;
                }
            } else {
                quiet = 0;
                last = d;
            }
            now += 1;
            let mut outs: Vec<Vec<WireOut>> = cores.iter_mut().map(|_| Vec::new()).collect();
            for i in 0..cores.len() {
                if !dead.contains(&i) {
                    cores[i].tick(now, &mut outs[i], &mut zap);
                }
            }
            for (i, o) in outs.iter().enumerate() {
                if !o.is_empty() {
                    deliver_mesh(cores, i, o, now, dead, &mut queue);
                }
            }
        }
        panic!("broadcast mesh never settled");
    }

    #[test]
    fn broadcast_network_elects_and_builds_adjacencies_per_10_4() {
        // Four routers on one broadcast network: A (pri 4) DR,
        // B (pri 3) BDR, C and D DR Others. §10.4: adjacencies exist
        // only between {DR,BDR} and everyone — the C-D pair stays at
        // 2-Way. The DR originates the network-LSA listing all four
        // (§12.4.2), and everyone's SPF routes the transit network.
        let mut cores = vec![
            bcast_core("10.255.1.1", "10.78.0.1", 4),
            bcast_core("10.255.2.1", "10.78.0.2", 3),
            bcast_core("10.255.3.1", "10.78.0.3", 2),
            bcast_core("10.255.4.1", "10.78.0.4", 1),
        ];
        let [a, b, c, d] = [0, 1, 2, 3];
        // WaitTimer = RouterDeadInterval = 4 s; run to stability.
        run_mesh(&mut cores, 0, 8, &[]);

        // §9.4's outcome, identical on all four: DR = A, BDR = B.
        for (i, core) in cores.iter().enumerate() {
            assert_eq!(
                core.interfaces[0].dr,
                ip("10.78.0.1"),
                "core {i} agrees on the DR"
            );
            assert_eq!(
                core.interfaces[0].bdr,
                ip("10.78.0.2"),
                "core {i} agrees on the BDR"
            );
        }
        use crate::iface::InterfaceState;
        assert_eq!(cores[a].interfaces[0].fsm.state, InterfaceState::Dr);
        assert_eq!(cores[b].interfaces[0].fsm.state, InterfaceState::Backup);
        assert_eq!(cores[c].interfaces[0].fsm.state, InterfaceState::DrOther);
        assert_eq!(cores[d].interfaces[0].fsm.state, InterfaceState::DrOther);

        // The adjacency matrix (§10.4): Full with/toward DR and BDR;
        // the two DR Others stay 2-Way with each other.
        let state_between = |x: usize, y: usize| -> Option<NeighborState> {
            let peer = cores[y].router_id;
            cores[x].interfaces[0]
                .neighbors
                .get(&peer)
                .map(|conv| conv.state())
        };
        for (x, y) in [(a, b), (a, c), (a, d), (b, c), (b, d)] {
            assert_eq!(
                state_between(x, y),
                Some(NeighborState::Full),
                "adjacency {x}-{y} (§10.4: DR/BDR pairs)"
            );
        }
        for (x, y) in [(c, d), (d, c)] {
            assert_eq!(
                state_between(x, y),
                Some(NeighborState::TwoWay),
                "the DR Other pair {x}-{y} stops at 2-Way (§10.4)"
            );
        }

        // §12.4.2: the DR's network-LSA — Link State ID = A's
        // address, all four routers attached, present in every LSDB.
        let net_key = crate::lsa::LsaKey {
            ls_type: LsaType::NETWORK,
            link_state_id: crate::lsa::LinkStateId(ip("10.78.0.1").into()),
            adv_router: cores[a].router_id,
        };
        for (i, core) in cores.iter().enumerate() {
            let entry = core
                .lsdb
                .get(&net_key)
                .unwrap_or_else(|| panic!("core {i} holds the DR's network-LSA"));
            let crate::lsa::LsaBody::Network(body) = &entry.lsa.body else {
                panic!("network body");
            };
            let mut attached: Vec<u32> = body.attached.iter().map(|r| r.0).collect();
            attached.sort_unstable();
            let mut want: Vec<u32> = cores.iter().map(|c| c.router_id.0).collect();
            want.sort_unstable();
            assert_eq!(attached, want, "all four routers attached (§12.4.2)");
            assert_eq!(body.mask, ip("255.255.255.0"));
        }

        // §12.4.1.2: every router-LSA carries the type-2 transit link
        // to the DR's address (Link ID = 10.78.0.1).
        for (i, core) in cores.iter().enumerate() {
            let key = crate::lsa::LsaKey {
                ls_type: LsaType::ROUTER,
                link_state_id: crate::lsa::LinkStateId(core.router_id.0),
                adv_router: core.router_id,
            };
            let entry = core.lsdb.get(&key).unwrap();
            let crate::lsa::LsaBody::Router(body) = &entry.lsa.body else {
                panic!()
            };
            assert!(
                body.links.iter().any(|l| {
                    l.link_type == crate::lsa::LinkType::Transit
                        && l.link_id.0 == u32::from(ip("10.78.0.1"))
                }),
                "core {i}'s router-LSA numbers the transit link"
            );
        }

        // SPF: the transit network itself is a route on the DR
        // Others (the network-LSA vertex with its mask).
        let d_routes: Vec<String> = cores[d].routes.keys().cloned().collect();
        assert!(
            d_routes.iter().any(|r| r == "10.78.0.0/24"),
            "D routes the transit network: {d_routes:?}"
        );
    }

    #[test]
    fn broadcast_dr_loss_promotes_bdr_and_re_originate_network_lsa() {
        // Footnote [5]/§12.4.2: the DR dies (its packets stop);
        // within RouterDeadInterval the BDR promotes, a new DR/BDR is
        // elected, adjacencies re-form, and the new DR originates its
        // own network-LSA (the dead DR's copy ages out on the
        // normal §14 lifetime — the flush duty died with it).
        let mut cores = vec![
            bcast_core("10.255.1.1", "10.79.0.1", 4),
            bcast_core("10.255.2.1", "10.79.0.2", 3),
            bcast_core("10.255.3.1", "10.79.0.3", 2),
        ];
        let (a, b, c) = (0, 1, 2);
        let now = run_mesh(&mut cores, 0, 8, &[]);
        assert_eq!(
            cores[a].interfaces[0].fsm.state,
            crate::iface::InterfaceState::Dr
        );
        assert_eq!(
            cores[b].interfaces[0].fsm.state,
            crate::iface::InterfaceState::Backup
        );

        // A goes silent: neither ticks nor delivers. Its neighbors'
        // Inactivity Timers fire within RouterDeadInterval (4 s) and
        // §9.2's second NeighborChange cause re-runs the election.
        run_mesh(&mut cores, now + 1, 12, &[a]);

        // B (was BDR) is the new DR; C the new BDR — on both living
        // cores.
        for core in [&cores[b], &cores[c]] {
            assert_eq!(core.interfaces[0].dr, ip("10.79.0.2"), "B is the new DR");
            assert_eq!(core.interfaces[0].bdr, ip("10.79.0.3"), "C is the new BDR");
        }
        assert_eq!(
            cores[b].interfaces[0].fsm.state,
            crate::iface::InterfaceState::Dr
        );
        assert_eq!(
            cores[c].interfaces[0].fsm.state,
            crate::iface::InterfaceState::Backup
        );
        // §12.4.2: the new DR's network-LSA — Link State ID = B's
        // address, attached = B and C (A's adjacency died with it).
        let new_net_key = crate::lsa::LsaKey {
            ls_type: LsaType::NETWORK,
            link_state_id: crate::lsa::LinkStateId(ip("10.79.0.2").into()),
            adv_router: cores[b].router_id,
        };
        for (i, core) in cores.iter().enumerate().skip(1) {
            let entry = core
                .lsdb
                .get(&new_net_key)
                .unwrap_or_else(|| panic!("living core {i} holds the new DR's network-LSA"));
            let crate::lsa::LsaBody::Network(body) = &entry.lsa.body else {
                panic!("network body")
            };
            let mut attached: Vec<u32> = body.attached.iter().map(|r| r.0).collect();
            attached.sort_unstable();
            assert_eq!(
                attached,
                vec![cores[b].router_id.0, cores[c].router_id.0],
                "the attached list is the living Full set plus the DR"
            );
        }
        // The adjacency re-formed: B-C Full.
        let peer = cores[c].router_id;
        assert_eq!(
            cores[b].interfaces[0]
                .neighbors
                .get(&peer)
                .map(|c| c.state()),
            Some(NeighborState::Full),
            "B-C adjacency re-formed after the DR loss"
        );
    }
}
