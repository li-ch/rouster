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
use crate::lsdb::Lsdb;
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
    /// Whether any external LSA exists (the router-LSA E-bit, §12.4.3).
    asbr: bool,
    /// SPF pending (an LSA changed contents; §16 runs on the
    /// throttle window).
    spf_dirty: bool,
    zapi: Option<mpsc::UnboundedSender<ZedgeCommand>>,
    redistribute_static: bool,
}

/// What the core wants put on the wire after one input.
pub struct WireOut {
    pub iface: usize,
    pub to: WireTo,
    pub packet: Packet,
}

#[derive(Clone, Copy)]
pub enum WireTo {
    Multicast,
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
            let mut fsm = InterfaceFsm::new(icfg.network_type == NetworkType::PointToPoint);
            // §9.3 InterfaceUp: the config's address IS the lower
            // layer's usable-interface signal (v1: no link-state
            // tracking) — the interface enters PointToPoint/Waiting
            // at construction.
            fsm.fire(crate::iface::InterfaceEvent::InterfaceUp);
            interfaces.push(Interface {
                name: name.clone(),
                cfg: icfg.clone(),
                addr,
                mask,
                p2p: icfg.network_type == NetworkType::PointToPoint,
                fsm,
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
            .map(|i| InterfaceAdv {
                state: i.fsm.state,
                p2p: i.p2p,
                address: i.addr,
                mask: i.mask,
                cost: i.cfg.cost,
                p2p_neighbors_full: i
                    .neighbors
                    .values()
                    .filter(|c| c.state() == NeighborState::Full)
                    .filter_map(|c| c.peer_router_id)
                    .collect(),
                attached_routers: i
                    .neighbors
                    .values()
                    .filter(|c| c.state() == NeighborState::Full)
                    .filter_map(|c| c.peer_router_id)
                    .collect(),
                dr_address: None,
            })
            .collect()
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

    /// Flood one self-originated LSA to every Full neighbor (v1: the
    /// p2p unicast shape; §13.3's retransmission lists armed).
    fn flood_own(&mut self, lsa: &Lsa, now: u64, out: &mut Vec<WireOut>) {
        // Collect (interface, neighbor ip) targets first, then build
        // packets (packet() borrows self immutably).
        let mut targets: Vec<(usize, Vec<Ipv4Addr>)> = Vec::new();
        for (idx, iface) in self.interfaces.iter_mut().enumerate() {
            let ips: Vec<Ipv4Addr> = iface
                .neighbors
                .iter_mut()
                .filter(|(_, c)| c.state() == NeighborState::Full)
                .map(|(_, c)| {
                    c.queue_retransmit(lsa, now);
                    c.ip
                })
                .collect();
            targets.push((idx, ips));
        }
        for (idx, ips) in targets {
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
                        NeighborEvent::TwoWayReceived if p2p => {
                            // §10.4: on p2p every neighbor becomes
                            // adjacent; broadcast's DR/BDR decision is
                            // the landed-but-not-driven arm.
                            let (sends, report) =
                                conv.fire_and_map(NeighborEvent::AdjOk(true), &self.lsdb, now);
                            out.extend(sends_into(iface_idx, sends));
                            if report.adjacency_up || report.adjacency_down {
                                adj_change = true;
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
                if adj_change {
                    self.router_lsa_dirty = true;
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
                let (sends, report) = match &packet.body {
                    PacketBody::DbDescription(dd) => {
                        conv.handle_dbd(dd, peer, iface.cfg.mtu, &mut self.lsdb, now)
                    }
                    PacketBody::LsRequest(lsr) => conv.handle_lsr(lsr, &mut self.lsdb, now),
                    PacketBody::LsUpdate(lsu) => {
                        conv.handle_lsu(&lsu.lsas, &mut self.lsdb, now, syncing)
                    }
                    PacketBody::LsAck(ack) => {
                        conv.handle_lsack(&ack.headers);
                        (Vec::new(), ConversationReport::default())
                    }
                    PacketBody::Hello(_) => unreachable!(),
                };
                out.extend(sends_into(iface_idx, sends));
                self.after_report(iface_idx, &report, now);
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

    fn after_report(&mut self, iface_idx: usize, report: &ConversationReport, now: u64) {
        if report.adjacency_up {
            info!(
                iface = %self.interfaces[iface_idx].name,
                "ospfd: adjacency FULL"
            );
            self.router_lsa_dirty = true;
        }
        if report.adjacency_down {
            self.router_lsa_dirty = true;
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

    /// The 1-second tick: hellos, neighbor timers, aging, deferred
    /// originations, SPF.
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
        // Neighbor timers (inactivity, DD/LSR/LSU retransmits).
        let mut down_events = Vec::new();
        for (idx, iface) in self.interfaces.iter_mut().enumerate() {
            let keys: Vec<RouterId> = iface.neighbors.keys().copied().collect();
            for key in keys {
                let Some(conv) = iface.neighbors.get_mut(&key) else {
                    continue;
                };
                let (sends, report) = conv.tick(now);
                out.extend(sends_into(idx, sends));
                if report.adjacency_down {
                    down_events.push(key);
                }
            }
        }
        if !down_events.is_empty() {
            self.router_lsa_dirty = true;
            for key in down_events {
                info!(neighbor = %key, "ospfd: neighbor timed out (Inactivity Timer)");
            }
        }
        // §14 aging.
        let report = self.lsdb.tick_aging(now);
        for key in report.refresh_due {
            let _ = key;
            self.router_lsa_dirty = true;
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
        designated_router: Ipv4Addr::UNSPECIFIED,
        backup_designated_router: Ipv4Addr::UNSPECIFIED,
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
    // The first hello and the router-LSA go out at once.
    let mut out = Vec::new();
    let mut zapi_out = Vec::new();
    core.tick(0, &mut out, &mut zapi_out);
    flush_wire(&sockets, &core, out).await;
    flush_zapi(&core, zapi_out).await;

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
            }
            _ = tick_interval.tick() => {
                let now = start.elapsed().as_secs();
                let mut out = Vec::new();
                let mut zapi_out = Vec::new();
                core.tick(now, &mut out, &mut zapi_out);
                flush_wire(&sockets, &core, out).await;
                flush_zapi(&core, zapi_out).await;
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

    /// Extract the packet bodies from one core's wire output.
    fn bodies(out: &[WireOut]) -> Vec<(Option<Ipv4Addr>, Packet)> {
        out.iter()
            .map(|w| {
                let to = match w.to {
                    WireTo::Multicast => None,
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
}
