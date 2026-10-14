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

use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::time::{Duration, Instant};

use common::{IpPrefix, Nexthop, NexthopGroup, RouteEntry, RouteProtocol};
use tokio::sync::mpsc;
use tracing::{info, warn};

use crate::adjacency::{
    process_hello, process_hold_expired, Action as AdjAction, Adjacency, CircuitContext, HelloInfo,
};
use crate::config::IsisdConfig;
use crate::lspdb::{InstallOutcome, Lspdb, SequenceCounter};
use crate::pdu::{
    csnp as csnp_pdu, lsp as lsp_pdu, p2p_hello, psnp as psnp_pdu, Lsp, LspBits, Pdu, PduBody,
};
use crate::spf::{self, Route, SpfResult};
use crate::system::{Level, LspId, SystemId};
use crate::tlv::{ExtIsNeighbor, LspEntry, Tlv, WideIpReach, NLPID_IPV4};
use crate::zedge::ZedgeCommand;

/// The interface metric we advertise on adjacency TLV 22 entries (the
/// FRR default `isis metric`).
pub const DEFAULT_CIRCUIT_METRIC: u32 = 10;

/// Refresh own LSPs when the remaining lifetime drops below this
/// (ISO §7.3.14's periodic regeneration; FRR refreshes at MaxAge-300).
const REFRESH_BELOW: u16 = 300;

/// Per-level state.
struct LevelState {
    db: Lspdb,
    seq: SequenceCounter,
}

/// Events into the daemon.
pub enum Event {
    /// A received PDU (already frame-parsed and codec-decoded).
    Pdu(Pdu),
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
    /// The zapi export edge (absent = standalone).
    zapi: Option<mpsc::UnboundedSender<ZedgeCommand>>,
    /// What we last told zebra (the route diff baseline).
    installed: HashMap<(Ipv4Addr, u8), RouteEntry>,
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
            });
        }
        if config.is_type.has_level2() {
            levels[1] = Some(LevelState {
                db: Lspdb::new(),
                seq: SequenceCounter::new(),
            });
        }
        if levels[0].is_none() && levels[1].is_none() {
            return Err(crate::error::IsisError::Config(
                "is-type leaves no level".into(),
            ));
        }
        Ok(Self {
            system_id,
            areas,
            circuit,
            adjacency: Adjacency::new(SystemId::from_bytes([0; 6])),
            levels,
            redistributed: Vec::new(),
            zapi: None,
            installed: HashMap::new(),
            config,
            start: Instant::now(),
        })
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

    /// The levels this daemon runs.
    fn active_levels(&self) -> impl Iterator<Item = bool> + '_ {
        [self.levels[0].is_some(), self.levels[1].is_some()]
            .into_iter()
            .filter(|&active| active)
    }

    // ---- origination ---------------------------------------------

    /// The TLV set of our own LSP at `level` (pure — the test target).
    fn own_tlvs(&self) -> Vec<Tlv> {
        let mut tlvs = vec![
            Tlv::AreaAddresses(self.areas.clone()),
            Tlv::ProtocolsSupported(vec![NLPID_IPV4]),
            Tlv::Hostname(self.config.hostname.clone()),
        ];
        if self.adjacency.state == crate::adjacency::AdjacencyState::Up {
            tlvs.push(Tlv::ExtIsReachability(vec![ExtIsNeighbor {
                id: crate::system::NeighborId::new(self.adjacency.neighbor, 0),
                metric: DEFAULT_CIRCUIT_METRIC,
                sub_tlvs: vec![],
            }]));
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
        let tlvs = self.own_tlvs();
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

    pub fn handle_pdu(&mut self, pdu: Pdu, out: &mut Vec<Pdu>) {
        match pdu.body {
            PduBody::P2pHello(hello) => self.handle_hello(hello, out),
            PduBody::Lsp(lsp) => self.handle_lsp(pdu.header.pdu_type, lsp, out),
            PduBody::Csnp(c) => self.handle_csnp(pdu.header.pdu_type, c, out),
            PduBody::Psnp(p) => {
                self.handle_psnp(pdu.header.pdu_type == crate::pdu::PDU_L2_PSNP, p, out)
            }
            PduBody::LanHello(_) => {
                // LAN IIHs: §Deferred with broadcast circuits.
            }
        }
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
        let Some(state) = self.levels[level_index(level2)].as_mut() else {
            return;
        };
        let outcome = state.db.install(lsp, now);
        match outcome {
            InstallOutcome::Installed => {
                // Flood onward (one circuit: re-send to the wire) and
                // acknowledge on the p2p circuit with a PSNP (ISO
                // §7.3.15.1: p2p LSP receipts are PSNP-acknowledged).
                let pdu = lsp_pdu(
                    level2,
                    echo.id,
                    echo.sequence_number,
                    echo.remaining_lifetime,
                    echo.bits,
                    echo.tlvs.clone(),
                );
                out.push(pdu);
                out.push(self.ack_psnp(level2, &echo));
                self.recompute_routes(out);
            }
            InstallOutcome::Duplicate => {
                out.push(self.ack_psnp(level2, &echo));
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
        let mut bytes = pdu.encode();
        crate::transport::pad_pdu(&mut bytes, self.config.interface.mtu as usize - 1);
        // The padding changed the total: re-patch the PDU length (the
        // fixed part's field) so the strict decoder accepts it.
        let total = bytes.len() as u16;
        bytes[17] = (total >> 8) as u8;
        bytes[18] = (total & 0xff) as u8;
        Pdu::decode(&bytes).ok()
    }

    fn build_csnp(&mut self, level2: bool) -> Pdu {
        let now = self.now();
        let state = self.levels[level_index(level2)]
            .as_mut()
            .expect("active level");
        csnp_pdu(level2, self.system_id, state.db.csnp_entries(now))
    }

    // ---- SPF and export -------------------------------------------

    /// Recompute routes from all active levels and flush the diff to
    /// zebra. L1 beats L2 for the same prefix (RFC 1195 §3.10.1).
    fn recompute_routes(&mut self, out: &mut Vec<Pdu>) {
        let now = self.now();
        let mut wanted: HashMap<(Ipv4Addr, u8), RouteEntry> = HashMap::new();
        for level2 in self.active_levels().collect::<Vec<_>>() {
            let level = if level2 { Level::Level2 } else { Level::Level1 };
            let state = self.levels[level_index(level2)].as_ref().unwrap();
            let result = spf::run(self.system_id, level, &state.db, now);
            for route in collect_routes(&result) {
                // L1 preference: an L1 route already collected wins.
                if !level2 && wanted.contains_key(&route.prefix) {
                    continue;
                }
                if level2 && wanted.contains_key(&route.prefix) {
                    continue;
                }
                let Some(nexthop) = route.next_hops.first().and_then(|h| h.address) else {
                    warn!(prefix = ?route.prefix, "route without a usable nexthop (no TLV 132 on the path)");
                    continue;
                };
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
                wanted.entry(route.prefix).or_insert(entry);
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
    let hello_every = Duration::from_secs(daemon.config.interface.hello_interval.max(1) as u64);
    let mut hello_ticker = tokio::time::interval(hello_every);
    hello_ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let mut second_ticker = tokio::time::interval(Duration::from_secs(1));
    second_ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    loop {
        tokio::select! {
            event = events.recv() => {
                match event {
                    Some(Event::Pdu(pdu)) => {
                        let mut out = Vec::new();
                        daemon.handle_pdu(pdu, &mut out);
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
            _ = hello_ticker.tick() => {
                if let Some(hello) = daemon.build_hello() {
                    send(hello);
                }
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
        d.handle_pdu(hello, &mut out);
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
        d.handle_pdu(peer_lsp, &mut out);
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
        d.handle_pdu(hello, &mut out);
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
        d.handle_pdu(peer_lsp, &mut out);
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
