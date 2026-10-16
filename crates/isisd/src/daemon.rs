//! The isisd run loop: one p2p circuit, the IIH engine, per-level
//! LSPDBs with origination/refresh/purge, CSNP/PSNP synchronisation,
//! SPF-driven route export through the zapi edge — the ospfd daemon
//! shape (message-driven core, timers as intervals, zapi optional).
//!
//! Pure helpers ([`build_hello`], [`build_own_lsp`],
//! [`collect_routes`]) are table-tested; the loop itself is the
//! container smoke's subject.
//!
//! v1 scope (disclosed): **one p2p circuit per daemon** (the
//! transport's no-bind fence); `is-type level-1-2` runs both levels'
//! databases on the one circuit (the IIH carries circuit type 3; LSP
//! exchange and SPF run per level, L1 routes preferred over L2 — RFC
//! 1195 §3.10.1); broadcast/DIS election, pseudonode LSPs, LSP
//! fragmenting beyond the first, and synonymous NETs are §Deferred.

use std::collections::{HashMap, HashSet};
use std::net::Ipv4Addr;
use std::time::{Duration, Instant};

use common::{IpPrefix, Nexthop, NexthopGroup, RouteEntry, RouteProtocol};
use tokio::sync::mpsc;
use tracing::{info, warn};

use crate::adjacency::{
    process_hello, process_hold_expired, Action as AdjAction, Adjacency, CircuitContext, HelloInfo,
};
use crate::config::{IsisdConfig, NetworkType};
use crate::lan::{code6_of, LanAction, LanCircuit, LanHelloInfo};
use crate::lspdb::{InstallOutcome, Lspdb, SequenceCounter};
use crate::pdu::{
    csnp as csnp_pdu, lan_hello, lsp as lsp_pdu, p2p_hello, psnp as psnp_pdu, Lsp, LspBits, Pdu,
    PduBody,
};
use crate::spf::{self, Route, SpfResult};
use crate::system::{Level, LspId, NeighborId, SystemId};
use crate::tlv::{ExtIsNeighbor, LspEntry, Tlv, WideIpReach, NLPID_IPV4};
use crate::zedge::ZedgeCommand;

/// The interface metric we advertise on adjacency TLV 22 entries (the
/// FRR default `isis metric`).
pub const DEFAULT_CIRCUIT_METRIC: u32 = 10;

/// Refresh own LSPs when the remaining lifetime drops below this
/// (ISO §7.3.14's periodic regeneration; FRR refreshes at MaxAge-300).
const REFRESH_BELOW: u16 = 300;

/// The DIS's periodic CSNP interval (ISO §7.3.12's
/// CompleteSNPInterval-Default, 10 s — FRR's default).
const COMPLETE_SNP_INTERVAL: u16 = 10;

/// Our Local Circuit ID on the one broadcast circuit (§8.4.4's LAN
/// id octet when we are the DIS; one circuit per daemon, v1).
const LOCAL_CIRCUIT_ID: u8 = 1;

/// One inter-level advertised prefix: the prefix, its carried metric
/// and the up/down bit it rides with (RFC 5302).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LeakedPrefix {
    pub prefix: (Ipv4Addr, u8),
    pub metric: u32,
    pub up_down: bool,
}

/// Per-level state.
struct LevelState {
    db: Lspdb,
    /// The router LSP's sequence counter.
    seq: SequenceCounter,
    /// The pseudonode LSP's counter (§7.3.16.1: "The sequence numbers
    /// the Intermediate system generates for its Link State PDUs with
    /// different values of LSP number are independent").
    pseudo_seq: SequenceCounter,
}

/// Events into the daemon.
pub enum Event {
    /// A received PDU (already frame-parsed and codec-decoded) with
    /// the frame's source MAC — the LAN SNPA (CODE 6's companion and
    /// the DIS tie-break input; unused on p2p circuits).
    Pdu(Pdu, [u8; 6]),
    /// A redistributed route push from zebra (add/remove).
    Redistributed { prefix: (Ipv4Addr, u8), add: bool },
}

pub struct Daemon {
    config: IsisdConfig,
    system_id: SystemId,
    areas: Vec<Vec<u8>>,
    circuit: CircuitContext,
    adjacency: Adjacency,
    /// The per-level databases (index 0 = L1, 1 = L2), present per
    /// is-type.
    levels: [Option<LevelState>; 2],
    /// Redistributed statics (TLV 135 content).
    redistributed: Vec<(Ipv4Addr, u8)>,
    /// Inter-area prefixes currently advertised INTO our L1 LSP —
    /// the L2→L1 leak, up/down set (RFC 5302).
    leaked_down: Vec<LeakedPrefix>,
    /// Inter-area prefixes currently advertised INTO our L2 LSP —
    /// the L1-area reachability a border re-advertises up (RFC 1195
    /// §3.10.2's L1→L2 movement), up/down clear.
    moved_up: Vec<LeakedPrefix>,
    /// The zapi export edge (absent = standalone).
    zapi: Option<mpsc::UnboundedSender<ZedgeCommand>>,
    /// What we last told zebra (the route diff baseline).
    installed: HashMap<(Ipv4Addr, u8), RouteEntry>,
    /// The broadcast circuit engines, per level (None on p2p).
    lan: [Option<LanCircuit>; 2],
    /// The clock of the last periodic CSNP (the DIS duty).
    last_csnp_at: Option<u64>,
    start: Instant,
}

fn level_index(level2: bool) -> usize {
    usize::from(level2)
}

impl Daemon {
    pub fn new(config: IsisdConfig) -> Result<Self, crate::error::IsisError> {
        let system_id = config.system_id().ok_or_else(|| {
            crate::error::IsisError::Config("NET too short for a system id".into())
        })?;
        let areas = vec![config.area_address()];
        let circuit = CircuitContext {
            our_system_id: system_id,
            our_areas: areas.clone(),
            our_level: config.interface.circuit_type,
            mtu: config.interface.mtu,
            extended_circuit_id: 1,
        };
        let mut levels = [None, None];
        if config.is_type.has_level1() {
            levels[0] = Some(LevelState {
                db: Lspdb::new(),
                seq: SequenceCounter::new(),
                pseudo_seq: SequenceCounter::new(),
            });
        }
        if config.is_type.has_level2() {
            levels[1] = Some(LevelState {
                db: Lspdb::new(),
                seq: SequenceCounter::new(),
                pseudo_seq: SequenceCounter::new(),
            });
        }
        if levels[0].is_none() && levels[1].is_none() {
            return Err(crate::error::IsisError::Config(
                "is-type leaves no level".into(),
            ));
        }
        let broadcast = config.interface.network == NetworkType::Broadcast;
        let mut lan = [None, None];
        if broadcast {
            let level = config.interface.circuit_type;
            let build = || {
                Some(LanCircuit::new(
                    system_id,
                    [0; 6], // until set_lan_mac, after the socket opens
                    config.interface.priority,
                    areas.clone(),
                    level,
                    LOCAL_CIRCUIT_ID,
                ))
            };
            if config.is_type.has_level1() {
                lan[0] = build();
            }
            if config.is_type.has_level2() {
                lan[1] = build();
            }
        }
        Ok(Self {
            system_id,
            areas,
            circuit,
            adjacency: Adjacency::new(SystemId::from_bytes([0; 6])),
            levels,
            redistributed: Vec::new(),
            leaked_down: Vec::new(),
            moved_up: Vec::new(),
            zapi: None,
            installed: HashMap::new(),
            lan,
            last_csnp_at: None,
            config,
            start: Instant::now(),
        })
    }

    /// Record our SNPA on the broadcast circuits (the bin calls this
    /// once the raw socket names the interface's MAC; election
    /// tie-breaks and CODE 6 need it).
    pub fn set_lan_mac(&mut self, mac: [u8; 6]) {
        for circuit in self.lan.iter_mut().flatten() {
            circuit.our_snpa = mac;
        }
    }

    pub fn attach_zapi(&mut self, tx: mpsc::UnboundedSender<ZedgeCommand>) {
        self.zapi = Some(tx);
    }

    /// Read-only config view (the bin's plumbing).
    pub fn config_ref(&self) -> &IsisdConfig {
        &self.config
    }

    /// Test hook: move the injected clock forward (the daemon's `now`
    /// is elapsed-since-start; travelling back in `start` travels
    /// forward in `now`).
    #[cfg(test)]
    pub fn time_travel(&mut self, secs: u64) {
        self.start -= Duration::from_secs(secs);
    }

    fn now(&self) -> u64 {
        self.start.elapsed().as_secs()
    }

    /// The levels this daemon runs, as `level2` flags (`false` = the
    /// L1 slot, `true` = the L2 slot). S13-a fix: the iterator
    /// previously yielded the slot's `is_some()` — an L1L2 daemon
    /// iterated "level2 = true" twice and never ran its L1 database
    /// (invisible while every config and smoke was L2-only; the M1
    /// inter-area tests exposed it).
    fn active_levels(&self) -> impl Iterator<Item = bool> + '_ {
        [
            (self.levels[0].is_some(), false),
            (self.levels[1].is_some(), true),
        ]
        .into_iter()
        .filter(|(active, _)| *active)
        .map(|(_, level2)| level2)
    }

    // ---- origination ---------------------------------------------

    /// The TLV set of our own LSP at `level` (pure — the test target).
    /// Own prefixes (interface + redistributed) ride every level we
    /// run; the inter-area sets are level-specific: leaked-down
    /// prefixes (up/down set, RFC 5302) only in the L1 LSP,
    /// moved-up area prefixes (up/down clear) only in the L2 LSP.
    fn own_tlvs(&self, level2: bool) -> Vec<Tlv> {
        let mut tlvs = vec![
            Tlv::AreaAddresses(self.areas.clone()),
            Tlv::ProtocolsSupported(vec![NLPID_IPV4]),
            Tlv::Hostname(self.config.hostname.clone()),
        ];
        match self.config.interface.network {
            NetworkType::PointToPoint => {
                if self.adjacency.state == crate::adjacency::AdjacencyState::Up {
                    tlvs.push(Tlv::ExtIsReachability(vec![ExtIsNeighbor {
                        id: NeighborId::new(self.adjacency.neighbor, 0),
                        metric: DEFAULT_CIRCUIT_METRIC,
                        sub_tlvs: vec![],
                    }]));
                }
            }
            // Broadcast: the adjacency entry names the LAN — the DIS's
            // pseudonode (§7.3.9: the set of "Intermediate system
            // adjacency, threeWayPermit FALSE, LAN designated" ones).
            NetworkType::Broadcast => {
                if let Some(lan_id) = self
                    .lan
                    .get(usize::from(level2))
                    .and_then(|l| l.as_ref())
                    .and_then(|l| l.lan_id())
                {
                    if self
                        .lan
                        .get(usize::from(level2))
                        .and_then(|l| l.as_ref())
                        .is_some_and(|l| l.up_neighbors().next().is_some())
                    {
                        tlvs.push(Tlv::ExtIsReachability(vec![ExtIsNeighbor {
                            id: lan_id,
                            metric: DEFAULT_CIRCUIT_METRIC,
                            sub_tlvs: vec![],
                        }]));
                    }
                }
            }
        }
        if let Some((addr, plen)) = self.config.interface.address {
            tlvs.push(Tlv::IpInterfaceAddress(vec![addr]));
            tlvs.push(Tlv::ExtIpReachability(vec![WideIpReach {
                metric: DEFAULT_CIRCUIT_METRIC,
                up_down: false,
                prefix: (addr, plen),
                sub_tlvs: vec![],
            }]));
        }
        for &(addr, plen) in &self.redistributed {
            tlvs.push(Tlv::ExtIpReachability(vec![WideIpReach {
                metric: DEFAULT_CIRCUIT_METRIC,
                up_down: false,
                prefix: (addr, plen),
                sub_tlvs: vec![],
            }]));
        }
        let inter_level: &[LeakedPrefix] = if level2 {
            &self.moved_up
        } else {
            &self.leaked_down
        };
        for &LeakedPrefix {
            prefix: (addr, plen),
            metric,
            up_down,
        } in inter_level
        {
            tlvs.push(Tlv::ExtIpReachability(vec![WideIpReach {
                metric,
                up_down,
                prefix: (addr, plen),
                sub_tlvs: vec![],
            }]));
        }
        tlvs
    }

    /// (Re)originate our LSP for `level`: bump the sequence counter,
    /// install into our own DB, return the PDU to flood.
    fn originate(&mut self, level2: bool) -> Option<Pdu> {
        // Compute the immutable inputs first so the level-state borrow
        // below is exclusive.
        let bits = LspBits {
            partition: false,
            attached: [false; 4],
            overload: false,
            is_type: self.config.is_type,
        };
        let tlvs = self.own_tlvs(level2);
        let now = self.now();
        let state = self.levels[level_index(level2)].as_mut()?;
        let seq = state.seq.take_next()?;
        let pdu = lsp_pdu(
            level2,
            LspId::zero(self.system_id),
            seq,
            crate::MAX_AGE,
            bits,
            tlvs,
        );
        let bytes = pdu.encode();
        let decoded = match Pdu::decode(&bytes).ok()?.body {
            PduBody::Lsp(l) => l,
            _ => return None,
        };
        match state.db.install_self(decoded, now) {
            Ok(()) => Some(pdu),
            Err(e) => {
                warn!("isisd: own LSP install failed: {e:?}");
                None
            }
        }
    }

    /// The own-LSP refresh check (ISO §7.3.14): reoriginate when the
    /// stored copy's remaining lifetime drops below the window.
    fn refresh_check(&mut self, out: &mut Vec<Pdu>) {
        for level2 in self.active_levels().collect::<Vec<_>>() {
            let needs = {
                let state = self.levels[level_index(level2)].as_ref().unwrap();
                match state.db.get(&LspId::zero(self.system_id)) {
                    Some(stored) => stored.remaining_lifetime(self.now()) < REFRESH_BELOW,
                    None => true,
                }
            };
            if needs {
                if let Some(pdu) = self.originate(level2) {
                    out.push(pdu);
                }
            }
        }
    }

    // ---- PDU handling --------------------------------------------

    pub fn handle_pdu(&mut self, pdu: Pdu, src_mac: [u8; 6], out: &mut Vec<Pdu>) {
        match pdu.body {
            PduBody::P2pHello(hello) => self.handle_hello(hello, out),
            PduBody::LanHello(hello) => {
                self.handle_lan_hello(pdu.header.pdu_type, hello, src_mac, out)
            }
            PduBody::Lsp(lsp) => self.handle_lsp(pdu.header.pdu_type, lsp, out),
            PduBody::Csnp(c) => self.handle_csnp(pdu.header.pdu_type, c, out),
            PduBody::Psnp(p) => {
                self.handle_psnp(pdu.header.pdu_type == crate::pdu::PDU_L2_PSNP, p, out)
            }
        }
    }

    /// One received LAN IIH (ISO §8.4.1's LAN acceptance + §8.4.4's
    /// election bookkeeping). `src_mac` is the frame's source MAC —
    /// the neighbour's SNPA.
    fn handle_lan_hello(
        &mut self,
        pdu_type: u8,
        hello: crate::pdu::LanHello,
        src_mac: [u8; 6],
        out: &mut Vec<Pdu>,
    ) {
        let level2 = pdu_type == crate::pdu::PDU_L2_LAN_HELLO;
        let now = self.now();
        let areas: Vec<Vec<u8>> = hello
            .tlvs
            .iter()
            .filter_map(|t| match t {
                Tlv::AreaAddresses(a) => Some(a.clone()),
                _ => None,
            })
            .flatten()
            .collect();
        let nlpids: Vec<u8> = hello
            .tlvs
            .iter()
            .filter_map(|t| match t {
                Tlv::ProtocolsSupported(n) => Some(n.clone()),
                _ => None,
            })
            .flatten()
            .collect();
        let code6 = code6_of(&hello.tlvs);
        let Some(lan) = self.lan[level_index(level2)].as_mut() else {
            return;
        };
        lan.note_snpa(hello.source_id, src_mac, now);
        let info = LanHelloInfo {
            level2,
            source: hello.source_id,
            priority: hello.priority,
            holding_time: hello.holding_time,
            lan_id: hello.lan_id,
            areas,
            nlpids,
            code6,
            now,
        };
        let result = lan.process_hello(&info);
        match result {
            Ok(action) => self.on_lan_action(level2, action, out),
            Err(reason) => {
                info!(source = %hello.source_id, reason, "LAN IIH rejected");
            }
        }
    }

    /// The LAN engine's verdicts: adjacency changes re-originate the
    /// router LSP (its TLV 22 names the LAN), DIS takeovers originate
    /// our pseudonode LSP (§7.2.3), resignations purge it.
    fn on_lan_action(&mut self, level2: bool, action: LanAction, out: &mut Vec<Pdu>) {
        match action {
            LanAction::NeighborUp(system) => {
                info!(neighbor = %system, level = if level2 { "L2" } else { "L1" }, "LAN adjacency UP");
                if let Some(pdu) = self.originate(level2) {
                    out.push(pdu);
                }
                if let Some(pdu) = self.originate_pseudonode(level2) {
                    out.push(pdu);
                }
                out.push(self.build_csnp(level2));
                self.recompute_routes(out);
            }
            LanAction::NeighborDown(system) => {
                info!(neighbor = %system, "LAN adjacency DOWN");
                if let Some(pdu) = self.originate(level2) {
                    out.push(pdu);
                }
                if let Some(pdu) = self.originate_pseudonode(level2) {
                    out.push(pdu);
                }
                self.recompute_routes(out);
            }
            LanAction::DisChanged { us: true, .. } => {
                info!("DIS takeover: originating the pseudonode LSP");
                if let Some(pdu) = self.originate(level2) {
                    out.push(pdu);
                }
                if let Some(pdu) = self.originate_pseudonode(level2) {
                    out.push(pdu);
                }
                self.recompute_routes(out);
            }
            LanAction::DisChanged { us: false, .. } => {
                info!("DIS resignation: purging our pseudonode LSP");
                self.purge_pseudonode(level2, out);
                if let Some(pdu) = self.originate(level2) {
                    out.push(pdu);
                }
                self.recompute_routes(out);
            }
            LanAction::None => {}
        }
    }

    /// Originate our pseudonode LSP when we hold the DIS role (ISO
    /// §7.2.3: the pseudonode "shall report a link to each of the
    /// Intermediate systems ... with a zero metric" — ourselves
    /// included, §7.3.8's "own systemID with an appended zero octet").
    fn originate_pseudonode(&mut self, level2: bool) -> Option<Pdu> {
        let members: Vec<ExtIsNeighbor> = {
            let lan = self.lan[level_index(level2)].as_ref()?;
            if !lan.is_dis() {
                return None;
            }
            let mut members: Vec<ExtIsNeighbor> = lan
                .up_neighbors()
                .map(|n| ExtIsNeighbor {
                    id: NeighborId::new(n.system, 0),
                    metric: 0,
                    sub_tlvs: vec![],
                })
                .collect();
            members.push(ExtIsNeighbor {
                id: NeighborId::new(self.system_id, 0),
                metric: 0,
                sub_tlvs: vec![],
            });
            members
        };
        let bits = LspBits {
            partition: false,
            attached: [false; 4],
            overload: false,
            is_type: if level2 { Level::Level2 } else { Level::Level1 },
        };
        let tlvs = vec![
            Tlv::AreaAddresses(self.areas.clone()),
            Tlv::ProtocolsSupported(vec![NLPID_IPV4]),
            Tlv::ExtIsReachability(members),
        ];
        let now = self.now();
        let state = self.levels[level_index(level2)].as_mut()?;
        let seq = state.pseudo_seq.take_next()?;
        let id = LspId::new(self.system_id, LOCAL_CIRCUIT_ID, 0);
        let pdu = lsp_pdu(level2, id, seq, crate::MAX_AGE, bits, tlvs);
        let bytes = pdu.encode();
        let decoded = match Pdu::decode(&bytes).ok()?.body {
            PduBody::Lsp(l) => l,
            _ => return None,
        };
        match state.db.install_self(decoded, now) {
            Ok(()) => Some(pdu),
            Err(e) => {
                warn!("isisd: own pseudonode LSP install failed: {e:?}");
                None
            }
        }
    }

    /// Purge our pseudonode LSP on DIS resignation (§7.2.3: "set the
    /// Remaining Lifetime of those Link State PDUs to zero") — at the
    /// stored sequence number, which §7.3.16.3's zero-age rule makes
    /// beat the live copy.
    fn purge_pseudonode(&mut self, level2: bool, out: &mut Vec<Pdu>) {
        let id = LspId::new(self.system_id, LOCAL_CIRCUIT_ID, 0);
        let now = self.now();
        let Some(state) = self.levels[level_index(level2)].as_mut() else {
            return;
        };
        let Some(stored) = state.db.get(&id) else {
            return;
        };
        let (seq, bits) = (stored.lsp.sequence_number, stored.lsp.bits);
        let purge = lsp_pdu(level2, id, seq, 0, bits, vec![]);
        if let Some(PduBody::Lsp(l)) = Pdu::decode(&purge.encode()).ok().map(|p| p.body) {
            let _ = state.db.install(l, now);
        }
        out.push(purge);
    }

    fn handle_hello(&mut self, hello: crate::pdu::P2pHello, out: &mut Vec<Pdu>) {
        let info = HelloInfo {
            source: hello.source_id,
            circuit_type: hello.circuit_type,
            holding_time: hello.holding_time,
            areas: hello
                .tlvs
                .iter()
                .filter_map(|t| match t {
                    Tlv::AreaAddresses(a) => Some(a.clone()),
                    _ => None,
                })
                .flatten()
                .collect(),
            nlpids: hello
                .tlvs
                .iter()
                .filter_map(|t| match t {
                    Tlv::ProtocolsSupported(n) => Some(n.clone()),
                    _ => None,
                })
                .flatten()
                .collect(),
            threeway: hello.tlvs.iter().find_map(|t| match t {
                Tlv::ThreewayAdjacency(tw) => Some(tw.clone()),
                _ => None,
            }),
            pdu_length: hello.pdu_length,
        };
        let now = self.now();
        match process_hello(&mut self.adjacency, &self.circuit, &info, now) {
            Ok(action) => match action {
                AdjAction::AdjacencyUp(level) => {
                    info!(
                        neighbor = %self.adjacency.neighbor,
                        level = %level,
                        "adjacency UP"
                    );
                    // Originate (the adjacency is now in TLV 22) and
                    // validate the databases (ISO §7.3.18: a CSNP on
                    // adjacency establishment).
                    for level2 in self.active_levels().collect::<Vec<_>>() {
                        if let Some(pdu) = self.originate(level2) {
                            out.push(pdu);
                        }
                        out.push(self.build_csnp(level2));
                    }
                    self.recompute_routes(out);
                }
                AdjAction::AdjacencyDown(reason) => {
                    info!(neighbor = %self.adjacency.neighbor, reason, "adjacency DOWN");
                    for level2 in self.active_levels().collect::<Vec<_>>() {
                        if let Some(pdu) = self.originate(level2) {
                            out.push(pdu);
                        }
                    }
                    self.recompute_routes(out);
                }
                AdjAction::ResendHello => {
                    if let Some(hello) = self.build_hello() {
                        out.push(hello);
                    }
                }
                AdjAction::None => {}
            },
            Err(reason) => {
                // Acceptance rejection: logged, adjacency untouched.
                info!(source = %info.source, reason, "IIH rejected");
                let _ = out;
            }
        }
    }

    fn handle_lsp(&mut self, pdu_type: u8, lsp: Lsp, out: &mut Vec<Pdu>) {
        let level2 = pdu_type == crate::pdu::PDU_L2_LSP;
        let now = self.now();
        let echo = lsp.clone();
        let broadcast = self.config.interface.network == NetworkType::Broadcast;
        let Some(state) = self.levels[level_index(level2)].as_mut() else {
            return;
        };
        let outcome = state.db.install(lsp, now);
        match outcome {
            InstallOutcome::Installed => {
                // Flood onward (one circuit: re-send to the wire) and
                // acknowledge with a PSNP on p2p circuits (ISO
                // §7.3.15.1: p2p LSP receipts are PSNP-acknowledged;
                // on a LAN the DIS's periodic CSNP carries the ack).
                let pdu = lsp_pdu(
                    level2,
                    echo.id,
                    echo.sequence_number,
                    echo.remaining_lifetime,
                    echo.bits,
                    echo.tlvs.clone(),
                );
                out.push(pdu);
                if !broadcast {
                    out.push(self.ack_psnp(level2, &echo));
                }
                self.recompute_routes(out);
            }
            InstallOutcome::Duplicate => {
                if !broadcast {
                    out.push(self.ack_psnp(level2, &echo));
                }
            }
            InstallOutcome::OlderThanStored => {
                // §7.3.15.1: send our copy back.
                if let Some(stored) = state.db.get(&echo.id) {
                    let s = stored.lsp.clone();
                    let pdu = lsp_pdu(
                        level2,
                        s.id,
                        s.sequence_number,
                        s.remaining_lifetime,
                        s.bits,
                        s.tlvs,
                    );
                    out.push(pdu);
                }
            }
            InstallOutcome::ConfusionPurged => {
                if let Some(stored) = state.db.get(&echo.id) {
                    let s = stored.lsp.clone();
                    let pdu = lsp_pdu(level2, s.id, s.sequence_number, 0, s.bits, vec![]);
                    out.push(pdu);
                }
                self.recompute_routes(out);
            }
        }
    }

    fn handle_csnp(&mut self, pdu_type: u8, csnp: crate::pdu::Csnp, out: &mut Vec<Pdu>) {
        let level2 = pdu_type == crate::pdu::PDU_L2_CSNP;
        let Some(state) = self.levels[level_index(level2)].as_mut() else {
            return;
        };
        let entries: Vec<LspEntry> = csnp
            .tlvs
            .iter()
            .filter_map(|t| match t {
                Tlv::LspEntries(es) => Some(es.clone()),
                _ => None,
            })
            .flatten()
            .collect();
        let actions = state.db.process_csnp(&entries);
        // Send the ones we hold newer.
        for id in actions.to_send {
            if let Some(stored) = state.db.get(&id) {
                let s = stored.lsp.clone();
                let pdu = lsp_pdu(
                    level2,
                    s.id,
                    s.sequence_number,
                    s.remaining_lifetime,
                    s.bits,
                    s.tlvs,
                );
                out.push(pdu);
            }
        }
        // Request the missing/newer ones.
        if !actions.requests.is_empty() {
            out.push(psnp_pdu(
                level2,
                self.system_id,
                state.db.psnp_for(&actions.requests),
            ));
        }
        self.recompute_routes(out);
    }

    fn handle_psnp(&mut self, level2: bool, psnp: crate::pdu::Psnp, out: &mut Vec<Pdu>) {
        let entries: Vec<LspEntry> = psnp
            .tlvs
            .iter()
            .filter_map(|t| match t {
                Tlv::LspEntries(es) => Some(es.clone()),
                _ => None,
            })
            .flatten()
            .collect();
        {
            let Some(state) = self.levels[level_index(level2)].as_mut() else {
                return;
            };
            let to_send = state.db.process_psnp(&entries);
            for id in to_send {
                if let Some(stored) = state.db.get(&id) {
                    let s = stored.lsp.clone();
                    let pdu = lsp_pdu(
                        level2,
                        s.id,
                        s.sequence_number,
                        s.remaining_lifetime,
                        s.bits,
                        s.tlvs,
                    );
                    out.push(pdu);
                }
            }
        }
    }

    fn ack_psnp(&mut self, level2: bool, lsp: &Lsp) -> Pdu {
        let entry = LspEntry {
            remaining_lifetime: lsp.remaining_lifetime,
            lsp_id: lsp.id,
            sequence_number: lsp.sequence_number,
            checksum: lsp.checksum,
        };
        psnp_pdu(level2, self.system_id, vec![Tlv::LspEntries(vec![entry])])
    }

    // ---- builders -------------------------------------------------

    /// The IIH we transmit (pure — the test target): the fixed part,
    /// TLV 1/129/132, the three-way option from the live adjacency,
    /// and ISO §8.2.3's padding to the circuit MTU.
    pub fn build_hello(&self) -> Option<Pdu> {
        let mut tlvs = vec![
            Tlv::AreaAddresses(self.areas.clone()),
            Tlv::ProtocolsSupported(vec![NLPID_IPV4]),
        ];
        if let Some((addr, _plen)) = self.config.interface.address {
            tlvs.push(Tlv::IpInterfaceAddress(vec![addr]));
        }
        tlvs.push(Tlv::ThreewayAdjacency(
            self.adjacency.threeway_option(&self.circuit),
        ));
        let pdu = p2p_hello(
            self.config.interface.circuit_type,
            self.system_id,
            self.config
                .interface
                .hello_interval
                .saturating_mul(self.config.interface.hello_multiplier),
            1, // local circuit id (one circuit)
            tlvs,
        );
        // ISO 8.2.3's maxsize-1 rule with the LLC accounted: FRR pads
        // its PDU to MTU-3 (1497 on a 1500 circuit) so the LLC+PDU
        // payload fits the Ethernet MTU; we match (the wire dump
        // pinned it).
        let mut bytes = pdu.encode();
        crate::transport::pad_pdu(
            &mut bytes,
            self.config.interface.mtu as usize - crate::transport::LLC_ISIS.len(),
        );
        // The padding changed the total: re-patch the PDU length (the
        // fixed part's field) so the strict decoder accepts it.
        let total = bytes.len() as u16;
        bytes[17] = (total >> 8) as u8;
        bytes[18] = (total & 0xff) as u8;
        Pdu::decode(&bytes).ok()
    }

    /// Every IIH we transmit right now: one p2p hello, or one LAN
    /// IIH per level the daemon runs (broadcast mode — ISO §9.5/§9.6,
    /// the priority, LAN id and CODE 6 list of the fixed part/TLVs).
    pub fn build_hellos(&self) -> Vec<Pdu> {
        if self.config.interface.network == NetworkType::PointToPoint {
            return self.build_hello().into_iter().collect();
        }
        let mut out = Vec::new();
        for (slot, level2) in self.lan.iter().zip([false, true]) {
            let Some(lan) = slot.as_ref() else {
                continue;
            };
            let mut tlvs = vec![
                Tlv::AreaAddresses(self.areas.clone()),
                Tlv::ProtocolsSupported(vec![NLPID_IPV4]),
            ];
            if let Some((addr, _plen)) = self.config.interface.address {
                tlvs.push(Tlv::IpInterfaceAddress(vec![addr]));
            }
            let macs = lan.code6_list();
            if !macs.is_empty() {
                tlvs.push(Tlv::LanNeighbors(macs));
            }
            let lan_id = lan
                .lan_id()
                .unwrap_or(NeighborId::new(self.system_id, LOCAL_CIRCUIT_ID));
            let pdu = lan_hello(
                level2,
                self.config.interface.circuit_type,
                self.system_id,
                self.config
                    .interface
                    .hello_interval
                    .saturating_mul(self.config.interface.hello_multiplier),
                self.config.interface.priority,
                lan_id,
                tlvs,
            );
            // §8.2.3's maxsize-1 padding, the LAN IIH length field at
            // the same offset (bytes 17..19 — both hello families put
            // PDU Length after circuit type + source + holding time).
            let mut bytes = pdu.encode();
            crate::transport::pad_pdu(
                &mut bytes,
                self.config.interface.mtu as usize - crate::transport::LLC_ISIS.len(),
            );
            let total = bytes.len() as u16;
            bytes[17] = (total >> 8) as u8;
            bytes[18] = (total & 0xff) as u8;
            if let Ok(pdu) = Pdu::decode(&bytes) {
                out.push(pdu);
            }
        }
        out
    }

    /// The hello timer period: the configured interval, thirds when
    /// we hold the DIS role on a broadcast circuit (§9.5's
    /// dRISISHelloTimer = a third of iSISHelloTimer — the fast DIS
    /// hello; our one-circuit simplification applies it to every
    /// level we run).
    fn hello_interval(&self) -> Duration {
        let base = self.config.interface.hello_interval.max(1) as u64;
        if self.config.interface.network == NetworkType::Broadcast
            && self.lan.iter().flatten().any(|l| l.is_dis())
        {
            Duration::from_secs((base / 3).max(1))
        } else {
            Duration::from_secs(base)
        }
    }

    fn build_csnp(&mut self, level2: bool) -> Pdu {
        let now = self.now();
        let state = self.levels[level_index(level2)]
            .as_mut()
            .expect("active level");
        csnp_pdu(level2, self.system_id, state.db.csnp_entries(now))
    }

    // ---- SPF and export -------------------------------------------

    /// Whether we already originate `prefix` ourselves (interface or
    /// redistributed) — the inter-area sets skip those (no
    /// self-shadowing duplicates in one LSP).
    fn originates(&self, prefix: &(Ipv4Addr, u8)) -> bool {
        if self.config.interface.address == Some(*prefix) {
            return true;
        }
        self.redistributed.contains(prefix)
    }

    /// Recompute routes from all active levels and flush the diff to
    /// zebra, per RFC 1195 §3.10.2's preference ladder: for one
    /// prefix, "routes learned via level 1 routing" beat level 2
    /// routes; among same-level candidates, "routes using internal
    /// metrics only are always preferred to routes using external
    /// metrics"; then the shortest path (equal-cost load-splitting is
    /// permitted — v1 keeps the deterministic first next hop).
    fn recompute_routes(&mut self, out: &mut Vec<Pdu>) {
        let now = self.now();
        let results: Vec<(bool, SpfResult)> = self
            .active_levels()
            .map(|level2| {
                let level = if level2 { Level::Level2 } else { Level::Level1 };
                let state = self.levels[level_index(level2)].as_ref().unwrap();
                (level2, spf::run(self.system_id, level, &state.db, now))
            })
            .collect();

        let mut wanted: HashMap<(Ipv4Addr, u8), RouteEntry> = HashMap::new();
        // The ladder key per prefix: (level, external, metric).
        let mut best: HashMap<(Ipv4Addr, u8), (u8, u8, u64)> = HashMap::new();
        for (level2, result) in &results {
            for route in &result.routes {
                let Some(nexthop) = route.next_hops.first().and_then(|h| h.address) else {
                    warn!(prefix = ?route.prefix, "route without a usable nexthop (no TLV 132 on the path)");
                    continue;
                };
                let key = (u8::from(*level2), u8::from(route.external), route.metric);
                let wins = best.get(&route.prefix).is_none_or(|&k| key < k);
                if !wins {
                    continue;
                }
                let Ok(prefix) = common::prefix::Ipv4Prefix::new(route.prefix.0, route.prefix.1)
                else {
                    continue;
                };
                let entry = RouteEntry::new(
                    IpPrefix::V4(prefix),
                    RouteProtocol::IsIs,
                    NexthopGroup::single(Nexthop::Ipv4(nexthop)),
                    route.metric as u32,
                );
                wanted.insert(route.prefix, entry);
                best.insert(route.prefix, key);
            }
            // The L1 default route toward the nearest attached L2
            // (RFC 1195 §3.10.1): 0.0.0.0/0 at the attached
            // candidate's cost.
            if !level2 {
                if let Some(&(system, cost, ref hops)) = result.attached.first() {
                    if let Some(nexthop) = hops.first().and_then(|h| h.address) {
                        info!(attached = %system, cost, "L1 default route toward the nearest attached L2");
                        wanted.entry((Ipv4Addr::UNSPECIFIED, 0)).or_insert_with(|| {
                            RouteEntry::new(
                                IpPrefix::V4(
                                    common::prefix::Ipv4Prefix::new(Ipv4Addr::UNSPECIFIED, 0)
                                        .expect("0/0"),
                                ),
                                RouteProtocol::IsIs,
                                NexthopGroup::single(Nexthop::Ipv4(nexthop)),
                                cost as u32,
                            )
                        });
                    }
                }
            }
        }

        // ---- inter-area prefix movement ------------------------------

        // L2→L1 (RFC 5302), only when configured and both levels run:
        // the L2 view's prefixes re-advertised into our L1 LSP with
        // the up/down bit set ("L1L2 routers MUST set this bit to one
        // for prefixes that are derived from L2 routing and are
        // advertised into L1 LSPs"). Excluded: prefixes the L1 area
        // already reaches (leaking them would only shadow local
        // routing), prefixes whose L2 copy already carries the bit
        // (leaked down from an even higher domain — never re-leaked),
        // and our own origins.
        let mut new_leak: Vec<LeakedPrefix> = Vec::new();
        if self.config.redistribute_level2_into_l1 && results.len() == 2 {
            let (_, l2) = results.iter().find(|(l2, _)| *l2).expect("both levels");
            let (_, l1) = results.iter().find(|(l2, _)| !l2).expect("both levels");
            let l1_has: HashSet<(Ipv4Addr, u8)> = l1.routes.iter().map(|r| r.prefix).collect();
            for route in &l2.routes {
                if route.up_down || l1_has.contains(&route.prefix) {
                    continue;
                }
                new_leak.push(LeakedPrefix {
                    prefix: route.prefix,
                    metric: route.metric.min(u32::MAX as u64) as u32,
                    up_down: true,
                });
            }
        }
        new_leak.sort_by_key(|p| p.prefix);
        new_leak.dedup_by_key(|p| p.prefix);
        if new_leak != self.leaked_down {
            info!(count = new_leak.len(), "L2->L1 leak set changed");
            self.leaked_down = new_leak;
            if let Some(pdu) = self.originate(false) {
                out.push(pdu);
            }
        }

        // L1→L2 (RFC 1195's area-prefix re-advertisement by the
        // border): the L1 view's prefixes ride our L2 LSP with the
        // bit clear — except the RFC 5302 MUST NOT: "Prefixes with
        // the up/down bit set that are learned via L1 routing MUST
        // NOT be advertised by L1L2 routers back into L2", and our
        // own origins (already in both levels).
        let mut new_up: Vec<LeakedPrefix> = Vec::new();
        if results.len() == 2 {
            let (_, l1) = results.iter().find(|(l2, _)| !l2).expect("both levels");
            for route in &l1.routes {
                if route.up_down || self.originates(&route.prefix) {
                    continue;
                }
                new_up.push(LeakedPrefix {
                    prefix: route.prefix,
                    metric: route.metric.min(u32::MAX as u64) as u32,
                    up_down: false,
                });
            }
        }
        new_up.sort_by_key(|p| p.prefix);
        new_up.dedup_by_key(|p| p.prefix);
        if new_up != self.moved_up {
            info!(count = new_up.len(), "L1->L2 advertisement set changed");
            self.moved_up = new_up;
            if let Some(pdu) = self.originate(true) {
                out.push(pdu);
            }
        }

        // Flush the diff.
        let mut commands = Vec::new();
        for (prefix, entry) in &wanted {
            match self.installed.get(prefix) {
                Some(old) if *old == *entry => {}
                Some(_) => {
                    commands.push(ZedgeCommand::RouteDel(entry.clone()));
                    commands.push(ZedgeCommand::RouteAdd(entry.clone()));
                }
                None => {
                    info!(prefix = ?prefix, metric = entry.metric, "IS-IS route installed");
                    commands.push(ZedgeCommand::RouteAdd(entry.clone()));
                }
            }
        }
        for (prefix, entry) in &self.installed {
            if !wanted.contains_key(prefix) {
                info!(prefix = ?prefix, "IS-IS route withdrawn");
                commands.push(ZedgeCommand::RouteDel(entry.clone()));
            }
        }
        self.installed = wanted;
        if let Some(zapi) = &self.zapi {
            for command in commands {
                let _ = zapi.send(command);
            }
        }
        let _ = out;
    }

    // ---- periodic work -------------------------------------------

    pub fn tick(&mut self, out: &mut Vec<Pdu>) {
        let now = self.now();
        // The broadcast engines: hold expiry + DIS refresh (§8.4.1.5).
        for level2 in self.active_levels().collect::<Vec<_>>() {
            if let Some(lan) = self.lan[level_index(level2)].as_mut() {
                let actions = lan.tick(now);
                for action in actions {
                    self.on_lan_action(level2, action, out);
                }
            }
        }
        // The DIS duty (§7.3.15.3): a periodic CSNP every
        // CompleteSNPInterval on broadcast circuits (clock-driven,
        // not tick-counted).
        let csnp_due = self
            .last_csnp_at
            .is_none_or(|t| now.saturating_sub(t) >= COMPLETE_SNP_INTERVAL as u64);
        if csnp_due {
            self.last_csnp_at = Some(now);
            for level2 in self.active_levels().collect::<Vec<_>>() {
                if self.lan[level_index(level2)]
                    .as_ref()
                    .is_some_and(|l| l.is_dis())
                {
                    out.push(self.build_csnp(level2));
                }
            }
        }
        // Hold monitoring (ISO §8.2.5).
        if self.adjacency.hold_expired(now) {
            let action = process_hold_expired(&mut self.adjacency);
            if matches!(action, AdjAction::AdjacencyDown(_)) {
                info!("adjacency DOWN (hold time expired)");
                for level2 in self.active_levels().collect::<Vec<_>>() {
                    if let Some(pdu) = self.originate(level2) {
                        out.push(pdu);
                    }
                }
                self.recompute_routes(out);
            }
        }
        // Aging (purges flood; tombstones expire).
        for level2 in self.active_levels().collect::<Vec<_>>() {
            let state = self.levels[level_index(level2)].as_mut().unwrap();
            let purges = state.db.tick(now);
            let aged = !purges.is_empty();
            for purge in purges {
                out.push(purge);
            }
            if aged {
                self.recompute_routes(out);
            }
        }
        // Refresh.
        self.refresh_check(out);
    }

    pub fn redistribute(&mut self, prefix: (Ipv4Addr, u8), add: bool, out: &mut Vec<Pdu>) {
        if add {
            if !self.redistributed.contains(&prefix) {
                self.redistributed.push(prefix);
            }
        } else {
            self.redistributed.retain(|p| *p != prefix);
        }
        for level2 in self.active_levels().collect::<Vec<_>>() {
            if let Some(pdu) = self.originate(level2) {
                out.push(pdu);
            }
        }
        self.recompute_routes(out);
    }
}

/// The routes worth installing from one level's SPF result: the
/// derived IP routes (SPF `Route`s) — pure, the test target.
pub fn collect_routes(result: &SpfResult) -> Vec<&Route> {
    result.routes.iter().collect()
}

/// The run loop: PDUs and redistribute pushes in, PDUs out through
/// `send`, timers at 1 s.
pub async fn run(
    mut daemon: Daemon,
    mut events: mpsc::UnboundedReceiver<Event>,
    mut send: impl FnMut(Pdu) + Send + 'static,
) -> std::io::Result<()> {
    // The hello deadline re-arms with the live interval (thirds while
    // we hold the DIS role, §9.5's dRISISHelloTimer).
    let mut next_hello = tokio::time::Instant::now() + daemon.hello_interval();
    let mut second_ticker = tokio::time::interval(Duration::from_secs(1));
    second_ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    loop {
        tokio::select! {
            event = events.recv() => {
                match event {
                    Some(Event::Pdu(pdu, src_mac)) => {
                        let mut out = Vec::new();
                        daemon.handle_pdu(pdu, src_mac, &mut out);
                        for pdu in out {
                            send(pdu);
                        }
                    }
                    Some(Event::Redistributed { prefix, add }) => {
                        let mut out = Vec::new();
                        daemon.redistribute(prefix, add, &mut out);
                        for pdu in out {
                            send(pdu);
                        }
                    }
                    None => break,
                }
            }
            _ = tokio::time::sleep_until(next_hello) => {
                for hello in daemon.build_hellos() {
                    send(hello);
                }
                next_hello = tokio::time::Instant::now() + daemon.hello_interval();
            }
            _ = second_ticker.tick() => {
                let mut out = Vec::new();
                daemon.tick(&mut out);
                for pdu in out {
                    send(pdu);
                }
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::parse as parse_config;
    use crate::pdu::PduBody;
    use crate::tlv::ThreewayState;

    const CONF: &str = "\
router isis T
 net 49.0001.1921.6800.1002.00
 is-type level-2
 hostname r2
 interface eth0
  address 172.16.0.2/24
  circuit-type level-2
";

    fn daemon() -> Daemon {
        Daemon::new(parse_config(CONF).unwrap()).unwrap()
    }

    /// An L1L2 daemon (the inter-area configuration) with optional
    /// RFC 5302 leaking.
    fn l1l2_daemon(leak: bool) -> Daemon {
        let conf = format!(
            "\
router isis T
 net 49.0001.1921.6800.1002.00
 is-type level-1-2
 hostname r2
 {}
 interface eth0
  address 172.16.0.2/24
  circuit-type level-1-2
",
            if leak {
                " redistribute level-2 into level-1"
            } else {
                ""
            }
        );
        Daemon::new(parse_config(&conf).unwrap()).unwrap()
    }

    const PEER: SystemId = SystemId::from_bytes([0x19, 0x21, 0x68, 0, 0x10, 1]);

    /// Bring the adjacency up (legacy hello) on an L1L2 daemon.
    fn adjacency_up_l1l2(d: &mut Daemon, out: &mut Vec<Pdu>) {
        let hello = crate::pdu::p2p_hello(
            Level::Level1And2,
            PEER,
            30,
            9,
            vec![
                Tlv::AreaAddresses(vec![vec![0x49, 0x00, 0x01]]),
                Tlv::ProtocolsSupported(vec![NLPID_IPV4]),
                Tlv::IpInterfaceAddress(vec![Ipv4Addr::new(172, 16, 0, 1)]),
            ],
        );
        d.handle_pdu(hello, [0x02, 0, 0, 0, 0, 1], out);
        assert_eq!(d.adjacency.state, crate::adjacency::AdjacencyState::Up);
    }

    /// A peer LSP for `level2` carrying one wide prefix.
    fn peer_lsp(level2: bool, prefix: (Ipv4Addr, u8), metric: u32, up_down: bool) -> Pdu {
        lsp_pdu(
            level2,
            LspId::zero(PEER),
            1,
            1200,
            LspBits::default(),
            vec![
                Tlv::ProtocolsSupported(vec![NLPID_IPV4]),
                Tlv::IpInterfaceAddress(vec![Ipv4Addr::new(172, 16, 0, 1)]),
                Tlv::ExtIsReachability(vec![ExtIsNeighbor {
                    id: crate::system::NeighborId::new(
                        SystemId::from_bytes([0x19, 0x21, 0x68, 0, 0x10, 2]),
                        0,
                    ),
                    metric: 10,
                    sub_tlvs: vec![],
                }]),
                Tlv::ExtIpReachability(vec![WideIpReach {
                    metric,
                    up_down,
                    prefix,
                    sub_tlvs: vec![],
                }]),
            ],
        )
    }

    /// RFC 5302 §2: with leaking configured, an L2-derived prefix is
    /// re-advertised into our L1 LSP with the up/down bit set — the
    /// wire control octet carries 0x80.
    #[test]
    fn l2_to_l1_leak_sets_updown() {
        let mut d = l1l2_daemon(true);
        let mut out = Vec::new();
        adjacency_up_l1l2(&mut d, &mut out);
        assert!(d.levels[0].is_some() && d.levels[1].is_some());
        d.handle_pdu(
            peer_lsp(true, (Ipv4Addr::new(10, 30, 0, 0), 24), 10, false),
            [0x02, 0, 0, 0, 0, 1],
            &mut out,
        );
        assert_eq!(
            d.leaked_down,
            vec![LeakedPrefix {
                prefix: (Ipv4Addr::new(10, 30, 0, 0), 24),
                metric: 20,
                up_down: true,
            }],
            "SPF distance 10 + prefix metric 10, leaked down"
        );
        // The re-originated L1 LSP carries the 0x80 control bit.
        assert!(out.iter().any(|p| match &p.body {
            PduBody::Lsp(l) => {
                l.id == LspId::zero(d.system_id)
                    && l.tlvs.iter().any(|t| {
                        matches!(t, Tlv::ExtIpReachability(ps) if ps.iter().any(
                            |p| p.up_down && p.prefix == (Ipv4Addr::new(10, 30, 0, 0), 24)
                        ))
                    })
            }
            _ => false,
        }));
    }

    /// Without the knob there is no leaking (RFC 5302 leaking is
    /// opt-in configuration, not a default).
    #[test]
    fn no_leak_without_the_knob() {
        let mut d = l1l2_daemon(false);
        let mut out = Vec::new();
        adjacency_up_l1l2(&mut d, &mut out);
        d.handle_pdu(
            peer_lsp(true, (Ipv4Addr::new(10, 30, 0, 0), 24), 10, false),
            [0x02, 0, 0, 0, 0, 1],
            &mut out,
        );
        assert!(d.leaked_down.is_empty());
    }

    /// The border's L1→L2 side (RFC 1195's area-prefix
    /// re-advertisement): L1-learned prefixes ride the L2 LSP with
    /// the up/down bit clear.
    #[test]
    fn l1_to_l2_movement() {
        let mut d = l1l2_daemon(false);
        let mut out = Vec::new();
        adjacency_up_l1l2(&mut d, &mut out);
        d.handle_pdu(
            peer_lsp(false, (Ipv4Addr::new(10, 20, 0, 0), 24), 10, false),
            [0x02, 0, 0, 0, 0, 1],
            &mut out,
        );
        assert_eq!(
            d.moved_up,
            vec![LeakedPrefix {
                prefix: (Ipv4Addr::new(10, 20, 0, 0), 24),
                metric: 20,
                up_down: false,
            }]
        );
        // The re-originated L2 LSP carries it with the bit clear.
        assert!(out.iter().any(|p| match &p.body {
            PduBody::Lsp(l) => {
                l.id == LspId::zero(d.system_id)
                    && l.tlvs.iter().any(|t| {
                        matches!(t, Tlv::ExtIpReachability(ps) if ps.iter().any(
                            |p| !p.up_down && p.prefix == (Ipv4Addr::new(10, 20, 0, 0), 24)
                        ))
                    })
            }
            _ => false,
        }));
    }

    /// RFC 5302's loop-prevention MUST NOT: "Prefixes with the up/down
    /// bit set that are learned via L1 routing MUST NOT be advertised
    /// by L1L2 routers back into L2."
    #[test]
    fn updown_l1_routes_never_move_up() {
        let mut d = l1l2_daemon(false);
        let mut out = Vec::new();
        adjacency_up_l1l2(&mut d, &mut out);
        // The peer's L1 LSP carries a leaked-down prefix (bit set) —
        // another border's leak reaching us over L1.
        d.handle_pdu(
            peer_lsp(false, (Ipv4Addr::new(10, 99, 0, 0), 24), 10, true),
            [0x02, 0, 0, 0, 0, 1],
            &mut out,
        );
        assert!(d.moved_up.is_empty(), "leaked-down prefixes stay down");
        // The route itself is still used for forwarding.
        assert!(d.installed.contains_key(&(Ipv4Addr::new(10, 99, 0, 0), 24)));
    }

    /// RFC 1195 §3.10.2's ladder, both axes, with the daemon's own
    /// forwarding table as the surface: L1 beats L2 regardless of
    /// metric; internal beats external at the same level.
    #[test]
    fn preference_ladder() {
        // L1 (metric 100) vs L2 (metric 5): the L1 route wins.
        let mut d = l1l2_daemon(false);
        let mut out = Vec::new();
        adjacency_up_l1l2(&mut d, &mut out);
        let pfx = (Ipv4Addr::new(10, 77, 0, 0), 24);
        d.handle_pdu(
            peer_lsp(false, pfx, 100, false),
            [0x02, 0, 0, 0, 0, 1],
            &mut out,
        );
        d.handle_pdu(
            peer_lsp(true, pfx, 5, false),
            [0x02, 0, 0, 0, 0, 1],
            &mut out,
        );
        assert_eq!(d.installed.get(&pfx).unwrap().metric, 110, "10 + 100");

        // L2 internal (metric 100) vs L2 external (metric 1): internal
        // wins — narrow TLV 130 carries the external flag.
        let mut d2 = daemon();
        let mut out2 = Vec::new();
        let hello = crate::pdu::p2p_hello(
            Level::Level2,
            PEER,
            30,
            9,
            vec![
                Tlv::AreaAddresses(vec![vec![0x49, 0x00, 0x01]]),
                Tlv::ProtocolsSupported(vec![NLPID_IPV4]),
                Tlv::IpInterfaceAddress(vec![Ipv4Addr::new(172, 16, 0, 1)]),
            ],
        );
        d2.handle_pdu(hello, [0x02, 0, 0, 0, 0, 1], &mut out2);
        let ext = crate::tlv::NarrowIpReach {
            default_metric: crate::tlv::NarrowMetric {
                flag: true,
                up_down: false,
                value: 1,
            },
            delay_metric: crate::tlv::NarrowMetric {
                flag: true,
                up_down: false,
                value: 0,
            },
            expense_metric: crate::tlv::NarrowMetric {
                flag: true,
                up_down: false,
                value: 0,
            },
            error_metric: crate::tlv::NarrowMetric {
                flag: true,
                up_down: false,
                value: 0,
            },
            address: Ipv4Addr::new(10, 88, 0, 0),
            mask: Ipv4Addr::new(255, 255, 255, 0),
            external: true,
        };
        let internal = crate::tlv::NarrowIpReach {
            default_metric: crate::tlv::NarrowMetric {
                flag: false,
                up_down: false,
                value: 100,
            },
            delay_metric: crate::tlv::NarrowMetric {
                flag: true,
                up_down: false,
                value: 0,
            },
            expense_metric: crate::tlv::NarrowMetric {
                flag: true,
                up_down: false,
                value: 0,
            },
            error_metric: crate::tlv::NarrowMetric {
                flag: true,
                up_down: false,
                value: 0,
            },
            address: Ipv4Addr::new(10, 88, 0, 0),
            mask: Ipv4Addr::new(255, 255, 255, 0),
            external: false,
        };
        let narrow_lsp = lsp_pdu(
            true,
            LspId::zero(PEER),
            1,
            1200,
            LspBits::default(),
            vec![
                Tlv::ProtocolsSupported(vec![NLPID_IPV4]),
                Tlv::IpInterfaceAddress(vec![Ipv4Addr::new(172, 16, 0, 1)]),
                Tlv::ExtIsReachability(vec![ExtIsNeighbor {
                    id: crate::system::NeighborId::new(
                        SystemId::from_bytes([0x19, 0x21, 0x68, 0, 0x10, 2]),
                        0,
                    ),
                    metric: 10,
                    sub_tlvs: vec![],
                }]),
                Tlv::IpInternalReachability(vec![internal]),
                Tlv::IpExternalReachability(vec![ext]),
            ],
        );
        d2.handle_pdu(narrow_lsp, [0x02, 0, 0, 0, 0, 1], &mut out2);
        let pfx2 = (Ipv4Addr::new(10, 88, 0, 0), 24);
        assert_eq!(
            d2.installed.get(&pfx2).unwrap().metric,
            110,
            "internal (10 + 100) beats external (10 + 1)"
        );
    }

    // ---- broadcast/LAN (M2) ---------------------------------------

    const OUR_MAC: [u8; 6] = [0x02, 0, 0, 0, 0, 2];
    const PEER_MAC: [u8; 6] = [0x02, 0, 0, 0, 0, 1];

    fn bc_daemon() -> Daemon {
        let conf = "router isis T
 net 49.0001.1921.6800.1002.00
 is-type level-2
 hostname r2
 interface eth0
  address 172.16.0.2/24
  circuit-type level-2
  network broadcast
  priority 100
";
        let mut d = Daemon::new(parse_config(conf).unwrap()).unwrap();
        d.set_lan_mac(OUR_MAC);
        d
    }

    /// A peer's LAN IIH (CODE 6 optional).
    fn bc_peer_hello(priority: u8, code6: Vec<[u8; 6]>) -> Pdu {
        let mut tlvs = vec![
            Tlv::AreaAddresses(vec![vec![0x49, 0x00, 0x01]]),
            Tlv::ProtocolsSupported(vec![NLPID_IPV4]),
        ];
        if !code6.is_empty() {
            tlvs.push(Tlv::LanNeighbors(code6));
        }
        crate::pdu::lan_hello(
            true,
            Level::Level2,
            PEER,
            30,
            priority,
            crate::system::NeighborId::new(PEER, 1),
            tlvs,
        )
    }

    /// The LAN dance end to end: their IIH brings the adjacency Up,
    /// our higher priority wins the election, we originate the
    /// pseudonode LSP (§7.2.3: links to every member, ourselves
    /// included, at metric zero) and the router LSP's TLV 22 entry
    /// names the LAN.
    #[test]
    fn broadcast_dis_takeover_and_pseudonode() {
        let mut d = bc_daemon();
        // Their first IIH does not list us: Initializing, they are
        // the provisional DIS.
        let mut out = Vec::new();
        d.handle_pdu(bc_peer_hello(64, vec![]), PEER_MAC, &mut out);
        assert!(!d.lan[1].as_ref().unwrap().is_dis());

        // They list our MAC: Up (§8.4.1.5) — at priority 100 vs 64 we
        // take over and originate the pseudonode LSP.
        let mut out = Vec::new();
        d.handle_pdu(bc_peer_hello(64, vec![OUR_MAC]), PEER_MAC, &mut out);
        assert!(d.lan[1].as_ref().unwrap().is_dis());
        assert_eq!(
            d.lan[1].as_ref().unwrap().lan_id(),
            Some(NeighborId::new(d.system_id, 1)),
            "our LAN id: system + Local Circuit ID"
        );
        // The pseudonode LSP: TLV 22 to both members at metric 0.
        let pseudo = out
            .iter()
            .find(|p| matches!(&p.body, PduBody::Lsp(l) if l.id.pseudonode == 1))
            .expect("pseudonode LSP originated");
        let PduBody::Lsp(l) = &pseudo.body else {
            unreachable!()
        };
        let members = l
            .tlvs
            .iter()
            .find_map(|t| match t {
                Tlv::ExtIsReachability(ns) => Some(ns.clone()),
                _ => None,
            })
            .unwrap();
        assert_eq!(members.len(), 2, "the peer and ourselves (7.3.8)");
        assert!(members
            .iter()
            .all(|n| n.metric == 0 && !n.id.is_pseudonode()));
        assert!(members.iter().any(|n| n.id.system == d.system_id));
        assert!(members.iter().any(|n| n.id.system == PEER));
        // The router LSP's adjacency entry names the LAN vertex.
        let router = out
            .iter()
            .find(|p| matches!(&p.body, PduBody::Lsp(l) if l.id.pseudonode == 0))
            .expect("router LSP re-originated");
        let PduBody::Lsp(l) = &router.body else {
            unreachable!()
        };
        let entry = l
            .tlvs
            .iter()
            .find_map(|t| match t {
                Tlv::ExtIsReachability(ns) => Some(ns.clone()),
                _ => None,
            })
            .expect("TLV 22 present once Up");
        assert_eq!(entry[0].id, NeighborId::new(d.system_id, 1));
        assert_eq!(entry[0].metric, DEFAULT_CIRCUIT_METRIC);
    }

    /// The LAN IIH shape: PDU 16, our priority and the elected LAN
    /// id in the fixed part, CODE 6 listing the Up neighbours, MTU
    /// padding — and the DIS's fast hello interval (§9.5's third).
    #[test]
    fn broadcast_hello_shape() {
        let mut d = bc_daemon();
        let mut out = Vec::new();
        d.handle_pdu(bc_peer_hello(64, vec![OUR_MAC]), PEER_MAC, &mut out);
        let hellos = d.build_hellos();
        assert_eq!(hellos.len(), 1, "one level configured");
        let PduBody::LanHello(h) = &hellos[0].body else {
            unreachable!()
        };
        assert_eq!(h.priority, 100);
        assert_eq!(h.lan_id, NeighborId::new(d.system_id, 1), "we are the DIS");
        assert!(h
            .tlvs
            .iter()
            .any(|t| matches!(t, Tlv::LanNeighbors(m) if m == &[PEER_MAC])));
        assert!(h.tlvs.iter().any(|t| matches!(t, Tlv::Padding(_))));
        let bytes = hellos[0].encode();
        assert!(bytes.len() >= 1497, "padded toward the MTU");
        assert_eq!(
            d.hello_interval(),
            Duration::from_secs(3),
            "DIS hellos at a third of 10 s"
        );
    }

    /// A route over the LAN: the peer's router LSP names our
    /// pseudonode, our pseudonode LSP fans out — the SPF resolves
    /// the next hop through the LAN to the peer itself.
    #[test]
    fn broadcast_route_over_lan() {
        let mut d = bc_daemon();
        let mut out = Vec::new();
        d.handle_pdu(bc_peer_hello(64, vec![OUR_MAC]), PEER_MAC, &mut out);
        // The peer's router LSP: attached to OUR pseudonode, carrying
        // a prefix and its TLV 132 address.
        let lan = NeighborId::new(d.system_id, 1);
        let peer_lsp = lsp_pdu(
            true,
            LspId::zero(PEER),
            1,
            1200,
            LspBits::default(),
            vec![
                Tlv::ProtocolsSupported(vec![NLPID_IPV4]),
                Tlv::IpInterfaceAddress(vec![Ipv4Addr::new(172, 16, 0, 1)]),
                Tlv::ExtIsReachability(vec![ExtIsNeighbor {
                    id: lan,
                    metric: 10,
                    sub_tlvs: vec![],
                }]),
                Tlv::ExtIpReachability(vec![WideIpReach {
                    metric: 10,
                    up_down: false,
                    prefix: (Ipv4Addr::new(203, 0, 113, 0), 24),
                    sub_tlvs: vec![],
                }]),
            ],
        );
        let mut out = Vec::new();
        d.handle_pdu(peer_lsp, PEER_MAC, &mut out);
        let entry = d
            .installed
            .get(&(Ipv4Addr::new(203, 0, 113, 0), 24))
            .expect("route over the LAN");
        // 10 (our LAN attachment) + 10 (the prefix); the next hop is
        // the peer's own address (frames cross the segment straight
        // to its MAC).
        assert_eq!(entry.metric, 20);
        assert!(
            matches!(&entry.nexthops, group if format!("{group:?}").contains("172.16.0.1")),
            "next hop is the peer itself: {:?}",
            entry.nexthops
        );
    }

    /// §7.2.3's resignation: a higher-priority peer's IIH takes the
    /// DIS role and we PURGE our pseudonode LSP (lifetime 0).
    #[test]
    fn broadcast_resignation_purges_pseudonode() {
        let mut d = bc_daemon();
        let mut out = Vec::new();
        d.handle_pdu(bc_peer_hello(64, vec![OUR_MAC]), PEER_MAC, &mut out);
        assert!(d.lan[1].as_ref().unwrap().is_dis());
        // They come back at priority 127 (and a fresh LAN id).
        let mut out = Vec::new();
        d.handle_pdu(
            {
                let mut pdu = bc_peer_hello(127, vec![OUR_MAC]);
                if let PduBody::LanHello(h) = &mut pdu.body {
                    h.lan_id = NeighborId::new(PEER, 2);
                }
                pdu
            },
            PEER_MAC,
            &mut out,
        );
        assert!(!d.lan[1].as_ref().unwrap().is_dis());
        let purge = out
            .iter()
            .find(|p| matches!(&p.body, PduBody::Lsp(l) if l.id.pseudonode == 1 && l.remaining_lifetime == 0))
            .expect("our pseudonode LSP purged");
        let _ = purge;
        // Our DB holds the tombstone.
        let id = LspId::new(d.system_id, 1, 0);
        assert!(d.levels[1]
            .as_ref()
            .unwrap()
            .db
            .get(&id)
            .is_some_and(|s| s.lsp.is_purge()));
    }

    /// The DIS duty (§7.3.15.3): a periodic CSNP every
    /// CompleteSNPInterval while we hold the role.
    #[test]
    fn broadcast_dis_periodic_csnp() {
        let mut d = bc_daemon();
        let mut out = Vec::new();
        d.handle_pdu(bc_peer_hello(64, vec![OUR_MAC]), PEER_MAC, &mut out);
        d.time_travel(10);
        let mut out = Vec::new();
        d.tick(&mut out);
        assert!(
            out.iter().any(|p| matches!(p.body, PduBody::Csnp(_))),
            "the DIS sends a periodic CSNP"
        );
    }

    /// The IIH builder: circuit type, hold time, TLVs, TLV 240, and
    /// §8.2.3 padding to MTU-1.
    #[test]
    fn hello_builder_shape() {
        let d = daemon();
        let hello = d.build_hello().unwrap();
        let bytes = hello.encode();
        // Padded to at least 1499 (MTU 1500).
        assert!(bytes.len() >= 1499 - 2, "len {}", bytes.len());
        let PduBody::P2pHello(h) = hello.body else {
            unreachable!()
        };
        assert_eq!(h.circuit_type, Level::Level2);
        assert_eq!(h.source_id.to_string(), "1921.6800.1002");
        assert_eq!(h.holding_time, 30, "10 s x 3");
        assert!(h
            .tlvs
            .iter()
            .any(|t| matches!(t, Tlv::AreaAddresses(a) if a[0] == [0x49, 0x00, 0x01])));
        assert!(h
            .tlvs
            .iter()
            .any(|t| matches!(t, Tlv::ProtocolsSupported(n) if n == &[NLPID_IPV4])));
        assert!(h
            .tlvs
            .iter()
            .any(|t| matches!(t, Tlv::ThreewayAdjacency(tw) if tw.state == ThreewayState::Down)));
        assert!(h.tlvs.iter().any(|t| matches!(t, Tlv::Padding(_))));
    }

    /// Origination: the LSP carries areas, NLPID, hostname, the
    /// interface prefix; TLV 22 appears only when the adjacency is Up.
    #[test]
    fn own_lsp_content() {
        let mut d = daemon();
        let pdu = d.originate(true).unwrap();
        let PduBody::Lsp(l) = pdu.body else {
            unreachable!()
        };
        assert_eq!(l.id.to_string(), "1921.6800.1002.00-00");
        assert_eq!(l.sequence_number, 1);
        assert_eq!(l.remaining_lifetime, crate::MAX_AGE);
        assert!(l
            .tlvs
            .iter()
            .any(|t| matches!(t, Tlv::Hostname(n) if n == "r2")));
        assert!(
            !l.tlvs
                .iter()
                .any(|t| matches!(t, Tlv::ExtIsReachability(_))),
            "no adjacency yet"
        );
        assert!(l.tlvs.iter().any(|t| matches!(t, Tlv::ExtIpReachability(ps) if ps[0].prefix == (Ipv4Addr::new(172, 16, 0, 2), 24))));
        // Sequence advances on reorigination.
        let pdu = d.originate(true).unwrap();
        let PduBody::Lsp(l2) = pdu.body else {
            unreachable!()
        };
        assert_eq!(l2.sequence_number, 2);
    }

    /// A full exchange simulation, library level: adjacency up via
    /// the FSM, LSP in, SPF out, route diff computed (the zapi edge
    /// absent — the installed map is the assertion surface).
    #[test]
    fn exchange_simulation_installs_route() {
        let mut d = daemon();
        let peer = SystemId::from_bytes([0x19, 0x21, 0x68, 0x00, 0x10, 0x01]);
        // Bring the adjacency up (legacy hello: no TLV 240).
        let hello = crate::pdu::p2p_hello(
            Level::Level2,
            peer,
            30,
            9,
            vec![
                Tlv::AreaAddresses(vec![vec![0x49, 0x00, 0x01]]),
                Tlv::ProtocolsSupported(vec![NLPID_IPV4]),
                Tlv::IpInterfaceAddress(vec![Ipv4Addr::new(172, 16, 0, 1)]),
            ],
        );
        let mut out = Vec::new();
        d.handle_pdu(hello, [0x02, 0, 0, 0, 0, 1], &mut out);
        assert_eq!(d.adjacency.state, crate::adjacency::AdjacencyState::Up);
        // Our own LSP (with the adjacency) was originated.
        assert!(out.iter().any(|p| matches!(p.body, PduBody::Lsp(_))));
        // A CSNP was sent (7.3.18).
        assert!(out.iter().any(|p| matches!(p.body, PduBody::Csnp(_))));
        // Install the peer's LSP with a remote prefix.
        let peer_lsp = lsp_pdu(
            true,
            LspId::zero(peer),
            1,
            1200,
            LspBits::default(),
            vec![
                Tlv::ProtocolsSupported(vec![NLPID_IPV4]),
                Tlv::IpInterfaceAddress(vec![Ipv4Addr::new(172, 16, 0, 1)]),
                Tlv::ExtIsReachability(vec![ExtIsNeighbor {
                    id: crate::system::NeighborId::new(d.system_id, 0),
                    metric: 10,
                    sub_tlvs: vec![],
                }]),
                Tlv::ExtIpReachability(vec![
                    WideIpReach {
                        metric: 10,
                        up_down: false,
                        prefix: (Ipv4Addr::new(203, 0, 113, 0), 24),
                        sub_tlvs: vec![],
                    },
                    WideIpReach {
                        metric: 10,
                        up_down: false,
                        prefix: (Ipv4Addr::new(172, 16, 0, 0), 24),
                        sub_tlvs: vec![],
                    },
                ]),
            ],
        );
        let mut out = Vec::new();
        d.handle_pdu(peer_lsp, [0x02, 0, 0, 0, 0, 1], &mut out);
        // Route installed toward 203.0.113.0/24 via 172.16.0.1.
        let key = (Ipv4Addr::new(203, 0, 113, 0), 24);
        let entry = d.installed.get(&key).expect("route installed");
        assert_eq!(entry.metric, 20);
        assert!(matches!(entry.protocol, RouteProtocol::IsIs));
        // The neighbor's own transit prefix (172.16.0.0/24) is also
        // learned.
        assert!(d
            .installed
            .contains_key(&(Ipv4Addr::new(172, 16, 0, 0), 24)));
    }

    /// Redistribute pushes land in the originated LSP (the static
    /// feed → TLV 135).
    #[test]
    fn redistribute_feed() {
        let mut d = daemon();
        let mut out = Vec::new();
        d.redistribute((Ipv4Addr::new(198, 51, 100, 0), 24), true, &mut out);
        assert!(out.iter().any(|p| {
            matches!(&p.body, PduBody::Lsp(l) if l.tlvs.iter().any(|t| matches!(t,
                Tlv::ExtIpReachability(ps) if ps.iter().any(|p| p.prefix == (Ipv4Addr::new(198, 51, 100, 0), 24)))))
        }));
        // Withdraw: gone from the next origination.
        let mut out = Vec::new();
        d.redistribute((Ipv4Addr::new(198, 51, 100, 0), 24), false, &mut out);
        assert!(out.iter().all(|p| {
            matches!(&p.body, PduBody::Lsp(l) if !l.tlvs.iter().any(|t| matches!(t,
                Tlv::ExtIpReachability(ps) if ps.iter().any(|p| p.prefix == (Ipv4Addr::new(198, 51, 100, 0), 24)))))
        }));
    }

    /// The tick path: aging purges a stale peer LSP and withdraws its
    /// routes.
    #[test]
    fn tick_ages_out() {
        let mut d = daemon();
        let peer = SystemId::from_bytes([0x19, 0x21, 0x68, 0x00, 0x10, 0x01]);
        // Adjacency up (so our own LSP carries the TLV 22 edge).
        let hello = crate::pdu::p2p_hello(
            Level::Level2,
            peer,
            30,
            9,
            vec![
                Tlv::AreaAddresses(vec![vec![0x49, 0x00, 0x01]]),
                Tlv::ProtocolsSupported(vec![NLPID_IPV4]),
                Tlv::IpInterfaceAddress(vec![Ipv4Addr::new(172, 16, 0, 1)]),
            ],
        );
        let mut out = Vec::new();
        d.handle_pdu(hello, [0x02, 0, 0, 0, 0, 1], &mut out);
        // The peer's LSP at a 5 s lifetime, with the reverse edge.
        let peer_lsp = lsp_pdu(
            true,
            LspId::zero(peer),
            1,
            5,
            LspBits::default(),
            vec![
                Tlv::ProtocolsSupported(vec![NLPID_IPV4]),
                Tlv::IpInterfaceAddress(vec![Ipv4Addr::new(172, 16, 0, 1)]),
                Tlv::ExtIsReachability(vec![ExtIsNeighbor {
                    id: crate::system::NeighborId::new(d.system_id, 0),
                    metric: 10,
                    sub_tlvs: vec![],
                }]),
                Tlv::ExtIpReachability(vec![WideIpReach {
                    metric: 10,
                    up_down: false,
                    prefix: (Ipv4Addr::new(203, 0, 113, 0), 24),
                    sub_tlvs: vec![],
                }]),
            ],
        );
        let mut out = Vec::new();
        d.handle_pdu(peer_lsp, [0x02, 0, 0, 0, 0, 1], &mut out);
        assert!(d
            .installed
            .contains_key(&(Ipv4Addr::new(203, 0, 113, 0), 24)));
        // After its lifetime, the purge floods and the route
        // withdraws.
        d.time_travel(6);
        let mut out = Vec::new();
        d.tick(&mut out);
        assert!(
            out.iter()
                .any(|p| matches!(&p.body, PduBody::Lsp(l) if l.remaining_lifetime == 0)),
            "a synchronized purge"
        );
        assert!(!d
            .installed
            .contains_key(&(Ipv4Addr::new(203, 0, 113, 0), 24)));
    }
}
