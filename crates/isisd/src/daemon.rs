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
use crate::auth::{self, LevelAuth};
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

/// ISO §11's minimumBroadcastLSPTransmissionInterval-Default (33 ms),
/// so §7.3.15.6's "no more than 1000/33 LSPs in any one second
/// period" caps a circuit at 30.
const MAX_LSPS_PER_SECOND: usize = 30;

/// ISO §7.3.5 + §10.1's refresh jitter: fragment 0 refreshes at the
/// plain window; higher fragments (§7.3.5's "L > 0" clause) stagger
/// theirs by up to 25% so a large fragment set does not refresh in
/// one burst — deterministic per LSP id (an FNV-1a of the id), in
/// [REFRESH_BELOW × 3/4, REFRESH_BELOW).
fn refresh_threshold(id: LspId) -> u16 {
    if id.fragment == 0 {
        return REFRESH_BELOW;
    }
    let mut hash = 0xcbf2_9ce4_8422_2325u64;
    for b in id.system.0 {
        hash ^= b as u64;
        hash = hash.wrapping_mul(0x100_0000_01b3);
    }
    hash ^= id.pseudonode as u64;
    hash = hash.wrapping_mul(0x100_0000_01b3);
    hash ^= id.fragment as u64;
    hash = hash.wrapping_mul(0x100_0000_01b3);
    let jitter = (hash % (REFRESH_BELOW / 4) as u64) as u16;
    REFRESH_BELOW - jitter
}

/// The SPF back-off throttle (the ospfd `SpfScheduler` pattern,
/// FRR-parity shape): a change after an idle period schedules at the
/// initial delay; back-to-back changes walk the increment up to the
/// maximum; a run marks the cycle and the next quiet period of at
/// least the max delay resets it. `(0, 0, 0)` — the default — leaves
/// every change due immediately (compute-on-change).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct SpfThrottle {
    pub initial_ms: u64,
    pub increment_ms: u64,
    pub max_ms: u64,
    last_run: Option<u64>,
    next_due: Option<u64>,
    current_delay_ms: u64,
}

impl SpfThrottle {
    pub fn new(initial_ms: u64, increment_ms: u64, max_ms: u64) -> Self {
        Self {
            initial_ms,
            increment_ms,
            max_ms,
            ..Self::default()
        }
    }

    /// A topology change arrived at `now_ms`; returns the due time.
    /// Never earlier than an already-set due time.
    pub fn on_change(&mut self, now_ms: u64) -> Option<u64> {
        let idle = self
            .last_run
            .is_some_and(|t| now_ms.saturating_sub(t) >= self.max_ms);
        let delay = if self.last_run.is_none() || idle {
            self.initial_ms
        } else {
            self.current_delay_ms
                .saturating_add(self.increment_ms)
                .min(self.max_ms)
                .max(self.initial_ms)
        };
        self.current_delay_ms = delay;
        let proposed = now_ms.saturating_add(delay);
        self.next_due = Some(match self.next_due {
            Some(due) => due.max(proposed),
            None => proposed,
        });
        self.next_due
    }

    pub fn is_due(&self, now_ms: u64) -> bool {
        self.next_due.is_some_and(|d| now_ms >= d)
    }

    pub fn mark_run(&mut self, now_ms: u64) {
        self.last_run = Some(now_ms);
        self.next_due = None;
    }
}

/// ISO §7.3.15's circuit pacing, pure and clock-injected:
/// §7.3.15.5's p2p rule ("the interval between two consecutive
/// transmissions of the same LSP shall be at least
/// minimumLSPTransmissionInterval" — 5 s) and §7.3.15.6's broadcast
/// rate ("no more than 1000/33 LSPs in any one second period").
/// Admitted transmissions stamp both axes; the daemon queues what is
/// not admitted and retries on its 1 s tick (which also satisfies
/// §7.3.15.6's floor that the scan continues whenever there is
/// something to send).
#[derive(Debug, Clone, Default)]
pub struct LspRateLimiter {
    per_lsp_last: HashMap<LspId, u64>,
    sent_at: std::collections::VecDeque<u64>,
}

impl LspRateLimiter {
    /// Whether `id`'s LSP may be transmitted on the circuit at `now`.
    pub fn admit(&mut self, id: LspId, now: u64) -> bool {
        if let Some(&last) = self.per_lsp_last.get(&id) {
            if now.saturating_sub(last) < crate::MINIMUM_LSP_TRANSMISSION_INTERVAL as u64 {
                return false;
            }
        }
        while self
            .sent_at
            .front()
            .is_some_and(|&t| now.saturating_sub(t) >= 1)
        {
            self.sent_at.pop_front();
        }
        if self.sent_at.len() >= MAX_LSPS_PER_SECOND {
            return false;
        }
        self.sent_at.push_back(now);
        self.per_lsp_last.insert(id, now);
        true
    }
}

fn wide_prefix(addr: Ipv4Addr, plen: u8, metric: u32) -> WideIpReach {
    WideIpReach {
        metric,
        up_down: false,
        prefix: (addr, plen),
        sub_tlvs: vec![],
    }
}

/// The narrow twin of one TLV 22 adjacency (the deployed 11-octet
/// form: default metric first, the unsupported-metric S octets at
/// 0x80).
fn narrow_of_adjacency(n: &ExtIsNeighbor) -> crate::tlv::OldIsNeighbor {
    let narrow = |value: u16| crate::tlv::NarrowMetric {
        flag: false,
        up_down: false,
        value,
    };
    let unsupported = crate::tlv::NarrowMetric {
        flag: true,
        up_down: false,
        value: 0,
    };
    crate::tlv::OldIsNeighbor {
        id: n.id,
        default_metric: narrow(n.metric.min(63) as u16),
        delay_metric: unsupported,
        expense_metric: unsupported,
        error_metric: unsupported,
    }
}

/// The narrow twin of one TLV 135 prefix (internal reachability, the
/// up/down bit carried on the default-metric octet per RFC 5302 §2).
fn narrow_of_prefix(p: &WideIpReach) -> crate::tlv::NarrowIpReach {
    let default_metric = crate::tlv::NarrowMetric {
        flag: false,
        up_down: p.up_down,
        value: p.metric.min(63) as u16,
    };
    let unsupported = crate::tlv::NarrowMetric {
        flag: true,
        up_down: false,
        value: 0,
    };
    let mask = !u32::MAX.checked_shr(u32::from(p.prefix.1)).unwrap_or(0);
    crate::tlv::NarrowIpReach {
        default_metric,
        delay_metric: unsupported,
        expense_metric: unsupported,
        error_metric: unsupported,
        address: p.prefix.0,
        mask: Ipv4Addr::from(mask),
        external: false,
    }
}

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
    /// The router LSP fragment 0's sequence counter.
    seq: SequenceCounter,
    /// Higher fragments' counters (§7.3.16.1: "The sequence numbers
    /// the Intermediate system generates for its Link State PDUs with
    /// different values of LSP number are independent").
    frag_seqs: HashMap<u8, SequenceCounter>,
    /// The pseudonode LSP's counter (same independence).
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
    /// The circuit's LSP pacing state (§7.3.15.5/§7.3.15.6).
    rate: LspRateLimiter,
    /// The SPF back-off (the ospfd pattern; `(0,0,0)` = on-change).
    spf_sched: SpfThrottle,
    /// Whether a topology change awaits its SPF window.
    spf_dirty: bool,
    /// The start-of-run overload deadline (`on-startup <secs>`).
    overload_deadline: Option<u64>,
    /// LSPs waiting for their pacing slot (drained every tick —
    /// §7.3.15.6's floor: the scan continues while there is traffic).
    tx_queue: std::collections::VecDeque<Pdu>,
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
                frag_seqs: HashMap::new(),
                pseudo_seq: SequenceCounter::new(),
            });
        }
        if config.is_type.has_level2() {
            levels[1] = Some(LevelState {
                db: Lspdb::new(),
                seq: SequenceCounter::new(),
                frag_seqs: HashMap::new(),
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
        let config_spf_throttle = config.spf_throttle;
        let config_overload_deadline = config.overload.on_startup;
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
            rate: LspRateLimiter::default(),
            spf_sched: SpfThrottle::new(
                config_spf_throttle.0,
                config_spf_throttle.1,
                config_spf_throttle.2,
            ),
            spf_dirty: false,
            overload_deadline: config_overload_deadline,
            tx_queue: std::collections::VecDeque::new(),
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

    // ---- authentication (M3) --------------------------------------

    /// The level whose password authenticates one PDU (ISO §7.3.7/
    /// §7.3.9: L1 LSPs carry the area password, L2 the domain; IIHs
    /// follow their level, with the level-agnostic p2p IIH signed by
    /// the domain password when the circuit runs L2 — the
    /// circuitTransmitPassword elision, disclosed). SNPs only when
    /// their mode asks for it. `None` = transmit unsigned / accept
    /// unsigned.
    fn auth_for_pdu(&self, pdu_type: u8, for_snp: bool) -> Option<&LevelAuth> {
        use crate::pdu::{PDU_L1_CSNP, PDU_L1_LAN_HELLO, PDU_L1_LSP, PDU_L1_PSNP, PDU_P2P_HELLO};
        let level2 = match pdu_type {
            PDU_L1_LAN_HELLO | PDU_L1_LSP | PDU_L1_CSNP | PDU_L1_PSNP => false,
            PDU_P2P_HELLO => self.config.interface.circuit_type.has_level2(),
            _ => true,
        };
        let auth = &self.config.auth[usize::from(level2)];
        if for_snp {
            // SNPs ride the configured mode: Off = unsigned both
            // ways; SendOnly/Validate = signed.
            return match auth.snp {
                crate::auth::SnpAuth::Off => None,
                _ => Some(auth),
            };
        }
        auth.enabled().then_some(auth)
    }

    /// Whether this PDU type is an SNP (the per-PDU auth modes).
    fn is_snp(pdu_type: u8) -> bool {
        matches!(
            pdu_type,
            crate::pdu::PDU_L1_CSNP
                | crate::pdu::PDU_L2_CSNP
                | crate::pdu::PDU_L1_PSNP
                | crate::pdu::PDU_L2_PSNP
        )
    }

    /// Sign one outbound PDU (ISO §9.7's TLV 10): the live send key
    /// appends its TLV; an HMAC-MD5 value is computed over the
    /// encoded PDU per RFC 5304 §2 — with the auth value, and for
    /// LSPs the checksum and remaining lifetime, all zeroed — then
    /// patched in, with the LSP checksum recomputed over the signed
    /// bytes. The signed struct re-decodes so the database copy and
    /// the flooded copy agree: §7.3.16.2's confusion purge would
    /// otherwise meet our own unsigned checksum.
    fn auth_sign(&self, pdu: &mut Pdu) {
        let for_snp = Self::is_snp(pdu.header.pdu_type);
        let Some(auth) = self.auth_for_pdu(pdu.header.pdu_type, for_snp) else {
            return;
        };
        let now = self.now();
        let Some(key) = auth.chain.send_key(now) else {
            warn!("isisd: no live send key; transmitting unsigned (fail-visible)");
            return;
        };
        if pdu
            .tlvs()
            .iter()
            .any(|t| matches!(t, Tlv::Authentication { .. }))
        {
            return; // already carrying authentication (a re-flood)
        }
        let is_lsp = matches!(pdu.body, PduBody::Lsp(_));
        pdu.push_tlv(auth::auth_tlv(key));
        if key.algorithm != crate::auth::AuthAlgorithm::HmacMd5 {
            return;
        }
        let mut bytes = pdu.encode();
        let Some(at) = auth::find_auth_tlv(&bytes, pdu.header.length_indicator as usize) else {
            return;
        };
        let digest = auth::hmac_md5_digest(&bytes, at, is_lsp, &key.secret);
        auth::patch_digest(&mut bytes, at, &digest);
        if is_lsp {
            // The checksum covers the auth TLV: recompute over the
            // signed bytes (the field zeroed internally).
            let sum = crate::checksum::lsp_checksum(&mut bytes);
            bytes[24] = (sum >> 8) as u8;
            bytes[25] = (sum & 0xff) as u8;
        }
        if let Ok(signed) = Pdu::decode(&bytes) {
            *pdu = signed;
        }
    }

    /// Verify one inbound PDU against the configured passwords.
    /// Unsigned/incorrect PDUs are dropped (RFC 5304 §2: "MUST
    /// discard the PDU if the Authentication Value is incorrect";
    /// ISO §7.3.15.1: the tests apply when the receive passwords are
    /// non-null — unconfigured levels accept anything). The digest
    /// runs over the re-encoded bytes (the codec is byte-preserving,
    /// so they equal the wire bytes; the fields it may differ on —
    /// checksum, lifetime — are zeroed for the computation anyway).
    fn auth_verify(&self, pdu: &Pdu) -> Result<(), String> {
        let for_snp = Self::is_snp(pdu.header.pdu_type);
        let Some(level_auth) = self.auth_for_pdu(pdu.header.pdu_type, for_snp) else {
            return Ok(());
        };
        if for_snp && level_auth.snp == crate::auth::SnpAuth::SendOnly {
            return Ok(()); // the transition mode: tolerate on receipt
        }
        let bytes = pdu.encode();
        let is_lsp = matches!(pdu.body, PduBody::Lsp(_));
        auth::verify(
            &bytes,
            pdu.header.length_indicator as usize,
            is_lsp,
            &level_auth.chain,
            self.now(),
        )
        .map_err(|e| e.to_string())
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

    /// The millisecond clock (the SPF throttle's input — the ospfd
    /// pattern runs on ms granularity).
    fn now_ms(&self) -> u64 {
        self.start.elapsed().as_millis() as u64
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

    /// Whether the overload bit is currently on (ISO §9.8's LSPDBOL
    /// semantics): unconditionally, or inside the on-startup window.
    fn overload_active(&self) -> bool {
        self.config.overload.always
            || self
                .overload_deadline
                .is_some_and(|until| self.now() < until)
    }

    /// The TLV set of our own LSP at `level` (pure — the test target).
    /// Own prefixes (interface + redistributed) ride every level we
    /// run; the inter-area sets are level-specific: leaked-down
    /// prefixes (up/down set, RFC 5302) only in the L1 LSP,
    /// moved-up area prefixes (up/down clear) only in the L2 LSP.
    /// The metric-style selects the advertisement families (RFC
    /// 1195's transition mode carries both so narrow-only and
    /// wide-only peers can both read us); the overload and
    /// prefix-suppression knobs gate the prefix families.
    fn own_tlvs(&self, level2: bool) -> Vec<Tlv> {
        use crate::config::MetricStyle;
        let mut tlvs = vec![
            Tlv::AreaAddresses(self.areas.clone()),
            Tlv::ProtocolsSupported(vec![NLPID_IPV4]),
            Tlv::Hostname(self.config.hostname.clone()),
        ];
        let style = self.config.metric_style;
        let overload = self.overload_active();
        // Overload-with-suppress originates no prefixes at all (FRR's
        // suppress-prefixes); plain prefix-suppression omits only the
        // connected one (TLV 132 stays either way — next hops).
        let suppress_all = overload && self.config.overload.suppress_prefixes;
        let suppress_interface = suppress_all || self.config.interface.prefix_suppression;

        // The adjacency: the peer (p2p) or the LAN (broadcast).
        let adjacency: Vec<ExtIsNeighbor> = match self.config.interface.network {
            NetworkType::PointToPoint => {
                if self.adjacency.state == crate::adjacency::AdjacencyState::Up {
                    vec![ExtIsNeighbor {
                        id: NeighborId::new(self.adjacency.neighbor, 0),
                        metric: DEFAULT_CIRCUIT_METRIC,
                        sub_tlvs: vec![],
                    }]
                } else {
                    vec![]
                }
            }
            NetworkType::Broadcast => self
                .lan
                .get(usize::from(level2))
                .and_then(|l| l.as_ref())
                .and_then(|l| l.lan_id())
                .filter(|_| {
                    self.lan
                        .get(usize::from(level2))
                        .and_then(|l| l.as_ref())
                        .is_some_and(|l| l.up_neighbors().next().is_some())
                })
                .map(|lan_id| {
                    vec![ExtIsNeighbor {
                        id: lan_id,
                        metric: DEFAULT_CIRCUIT_METRIC,
                        sub_tlvs: vec![],
                    }]
                })
                .unwrap_or_default(),
        };
        if !adjacency.is_empty() {
            if matches!(style, MetricStyle::Wide | MetricStyle::Transition) {
                tlvs.push(Tlv::ExtIsReachability(adjacency.clone()));
            }
            if matches!(style, MetricStyle::Narrow | MetricStyle::Transition) {
                tlvs.push(Tlv::IsReachability(
                    adjacency.iter().map(narrow_of_adjacency).collect(),
                ));
            }
        }

        if let Some((addr, _plen)) = self.config.interface.address {
            tlvs.push(Tlv::IpInterfaceAddress(vec![addr]));
        }

        // The prefix set: the interface prefix (unless suppressed),
        // redistributed statics, and the inter-area set.
        let mut prefixes: Vec<WideIpReach> = Vec::new();
        if let Some((addr, plen)) = self.config.interface.address {
            if !suppress_interface {
                prefixes.push(wide_prefix(addr, plen, DEFAULT_CIRCUIT_METRIC));
            }
        }
        if !suppress_all {
            for &(addr, plen) in &self.redistributed {
                prefixes.push(wide_prefix(addr, plen, DEFAULT_CIRCUIT_METRIC));
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
                prefixes.push(WideIpReach {
                    metric,
                    up_down,
                    prefix: (addr, plen),
                    sub_tlvs: vec![],
                });
            }
        }
        if !prefixes.is_empty() {
            if matches!(style, MetricStyle::Wide | MetricStyle::Transition) {
                tlvs.push(Tlv::ExtIpReachability(prefixes.clone()));
            }
            if matches!(style, MetricStyle::Narrow | MetricStyle::Transition) {
                // The narrow metric tops out at 63 (six bits); wider
                // carried metrics clamp (disclosed: transition mode
                // leaks no wide-precision distances).
                tlvs.push(Tlv::IpInternalReachability(
                    prefixes.iter().map(narrow_of_prefix).collect(),
                ));
            }
        }
        tlvs
    }

    /// The LSP buffer budget (ISO §11's OriginatingLSPBufferSize:
    /// "less than or equal to the smallest MTU of any circuit", at
    /// least 512) minus the LSP fixed part.
    fn lsp_budget(&self) -> usize {
        self.config.interface.mtu.clamp(512, 1492) as usize - 27
    }

    /// Our own TLV set split into fragment bodies (§7.3.4) — pure,
    /// the test target.
    fn own_fragments(&self, level2: bool) -> Vec<Vec<Tlv>> {
        crate::fragment::fragment_tlvs(&self.own_tlvs(level2), self.lsp_budget())
    }

    /// (Re)originate our LSP set for `level`: fragment the TLVs
    /// (§7.3.4), originate each fragment with its independent
    /// sequence counter (§7.3.16.1), install into our own DB, and
    /// purge any higher fragment the new set no longer fills.
    fn originate(&mut self, level2: bool) -> Vec<Pdu> {
        let fragments = self.own_fragments(level2);
        let count = fragments.len();
        let mut out = Vec::new();
        for (frag_no, tlvs) in fragments.into_iter().enumerate() {
            if let Some(pdu) = self.originate_fragment(level2, frag_no as u8, tlvs) {
                out.push(pdu);
            }
        }
        self.purge_retired_fragments(level2, count, &mut out);
        out
    }

    /// Originate one fragment (§7.3.4h: on change, "the Intermediate
    /// system shall reissue only those Link State PDUs which are
    /// affected" — the refresh path calls this per stale fragment).
    fn originate_fragment(&mut self, level2: bool, fragment: u8, tlvs: Vec<Tlv>) -> Option<Pdu> {
        let bits = LspBits {
            partition: false,
            attached: [false; 4],
            overload: self.overload_active(),
            is_type: self.config.is_type,
        };
        let now = self.now();
        let seq = {
            let state = self.levels[level_index(level2)].as_mut()?;
            if fragment == 0 {
                state.seq.take_next()?
            } else {
                state
                    .frag_seqs
                    .entry(fragment)
                    .or_insert_with(SequenceCounter::new)
                    .take_next()?
            }
        };
        let id = LspId::new(self.system_id, 0, fragment);
        let mut pdu = lsp_pdu(level2, id, seq, crate::MAX_AGE, bits, tlvs);
        self.auth_sign(&mut pdu);
        let bytes = pdu.encode();
        let decoded = match Pdu::decode(&bytes).ok()?.body {
            PduBody::Lsp(l) => l,
            _ => return None,
        };
        match self.levels[level_index(level2)]
            .as_mut()?
            .db
            .install_self(decoded, now)
        {
            Ok(()) => Some(pdu),
            Err(e) => {
                warn!("isisd: own LSP fragment {fragment} install failed: {e:?}");
                None
            }
        }
    }

    /// §7.3.4: a non-zero LSP number with no information left is
    /// purged — anything we hold beyond the new fragment count goes
    /// out as a zero-lifetime tombstone at its stored sequence.
    fn purge_retired_fragments(&mut self, level2: bool, count: usize, out: &mut Vec<Pdu>) {
        let now = self.now();
        let retired: Vec<(LspId, u32, LspBits)> = {
            let Some(state) = self.levels[level_index(level2)].as_ref() else {
                return;
            };
            state
                .db
                .stored_lsps()
                .map(|s| s.lsp.id)
                .filter(|id| {
                    id.system == self.system_id
                        && id.pseudonode == 0
                        && (id.fragment as usize) >= count
                })
                .filter_map(|id| {
                    state
                        .db
                        .get(&id)
                        .map(|s| (id, s.lsp.sequence_number, s.lsp.bits))
                })
                .collect()
        };
        for (id, seq, bits) in retired {
            let mut purge = lsp_pdu(level2, id, seq, 0, bits, vec![]);
            if let Some(PduBody::Lsp(l)) = Pdu::decode(&purge.encode()).ok().map(|p| p.body) {
                let _ = self.levels[level_index(level2)]
                    .as_mut()
                    .map(|state| state.db.install(l, now));
            }
            self.auth_sign(&mut purge);
            out.push(purge);
        }
    }

    /// The own-LSP refresh check (ISO §7.3.14 with §7.3.5/§10.1's
    /// per-fragment jitter): reoriginate each fragment whose stored
    /// copy's remaining lifetime dropped below its jittered window —
    /// only the stale fragment (§7.3.4h).
    fn refresh_check(&mut self, out: &mut Vec<Pdu>) {
        let now = self.now();
        for level2 in self.active_levels().collect::<Vec<_>>() {
            let stale: Vec<u8> = {
                let state = self.levels[level_index(level2)].as_ref().unwrap();
                state
                    .db
                    .ids()
                    .filter(|id| id.system == self.system_id && id.pseudonode == 0)
                    .filter(|id| match state.db.get(id) {
                        Some(stored) => stored.remaining_lifetime(now) < refresh_threshold(*id),
                        None => id.fragment == 0, // absent fragment 0: originate
                    })
                    .map(|id| id.fragment)
                    .collect()
            };
            if stale.is_empty() {
                continue;
            }
            let fragments = self.own_fragments(level2);
            for fragment in stale {
                if let Some(tlvs) = fragments
                    .get(usize::from(fragment))
                    .filter(|_| (fragment as usize) < fragments.len())
                    .cloned()
                {
                    if let Some(pdu) = self.originate_fragment(level2, fragment, tlvs) {
                        out.push(pdu);
                    }
                }
                // A stale fragment beyond the new count retires via
                // the originate path's purge when content changed;
                // when only it aged (content identical), the empty
                // window cannot happen (fragments.len() covers it).
            }
        }
    }

    // ---- PDU handling --------------------------------------------

    pub fn handle_pdu(&mut self, pdu: Pdu, src_mac: [u8; 6], out: &mut Vec<Pdu>) {
        if let Err(reason) = self.auth_verify(&pdu) {
            info!(pdu_type = pdu.header.pdu_type, %reason, "PDU dropped: authentication");
            return;
        }
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
                out.extend(self.originate(level2));
                if let Some(pdu) = self.originate_pseudonode(level2) {
                    out.push(pdu);
                }
                out.push(self.build_csnp(level2));
                self.recompute_routes(out);
            }
            LanAction::NeighborDown(system) => {
                info!(neighbor = %system, "LAN adjacency DOWN");
                out.extend(self.originate(level2));
                if let Some(pdu) = self.originate_pseudonode(level2) {
                    out.push(pdu);
                }
                self.recompute_routes(out);
            }
            LanAction::DisChanged { us: true, .. } => {
                info!("DIS takeover: originating the pseudonode LSP");
                out.extend(self.originate(level2));
                if let Some(pdu) = self.originate_pseudonode(level2) {
                    out.push(pdu);
                }
                self.recompute_routes(out);
            }
            LanAction::DisChanged { us: false, .. } => {
                info!("DIS resignation: purging our pseudonode LSP");
                self.purge_pseudonode(level2, out);
                out.extend(self.originate(level2));
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
        let seq = {
            let state = self.levels[level_index(level2)].as_mut()?;
            state.pseudo_seq.take_next()?
        };
        let id = LspId::new(self.system_id, LOCAL_CIRCUIT_ID, 0);
        let mut pdu = lsp_pdu(level2, id, seq, crate::MAX_AGE, bits, tlvs);
        self.auth_sign(&mut pdu);
        let bytes = pdu.encode();
        let decoded = match Pdu::decode(&bytes).ok()?.body {
            PduBody::Lsp(l) => l,
            _ => return None,
        };
        match self.levels[level_index(level2)]
            .as_mut()?
            .db
            .install_self(decoded, now)
        {
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
        let Some((seq, bits)) = self.levels[level_index(level2)]
            .as_ref()
            .and_then(|state| state.db.get(&id))
            .map(|stored| (stored.lsp.sequence_number, stored.lsp.bits))
        else {
            return;
        };
        let mut purge = lsp_pdu(level2, id, seq, 0, bits, vec![]);
        self.auth_sign(&mut purge);
        if let Some(PduBody::Lsp(l)) = Pdu::decode(&purge.encode()).ok().map(|p| p.body) {
            let _ = self.levels[level_index(level2)]
                .as_mut()
                .map(|state| state.db.install(l, now));
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
                        out.extend(self.originate(level2));
                        out.push(self.build_csnp(level2));
                    }
                    self.recompute_routes(out);
                }
                AdjAction::AdjacencyDown(reason) => {
                    info!(neighbor = %self.adjacency.neighbor, reason, "adjacency DOWN");
                    for level2 in self.active_levels().collect::<Vec<_>>() {
                        out.extend(self.originate(level2));
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
            let mut psnp = psnp_pdu(level2, self.system_id, state.db.psnp_for(&actions.requests));
            self.auth_sign(&mut psnp);
            out.push(psnp);
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
        let mut psnp = psnp_pdu(level2, self.system_id, vec![Tlv::LspEntries(vec![entry])]);
        self.auth_sign(&mut psnp);
        psnp
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
        let mut padded = Pdu::decode(&bytes).ok()?;
        // RFC 5304 2: hello digests are computed after the padding.
        self.auth_sign(&mut padded);
        Some(padded)
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
            if let Ok(mut pdu) = Pdu::decode(&bytes) {
                // RFC 5304 2: hello digests are computed after the
                // padding.
                self.auth_sign(&mut pdu);
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
        let mut csnp = csnp_pdu(level2, self.system_id, state.db.csnp_entries(now));
        self.auth_sign(&mut csnp);
        csnp
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

    /// The throttled entry point every topology change goes through:
    /// mark dirty, schedule per the back-off, run when due (the
    /// default `(0, 0, 0)` throttle leaves every change due
    /// immediately — compute-on-change).
    fn recompute_routes(&mut self, out: &mut Vec<Pdu>) {
        self.spf_dirty = true;
        self.spf_sched.on_change(self.now_ms());
        self.maybe_run_spf(out);
    }

    fn maybe_run_spf(&mut self, out: &mut Vec<Pdu>) {
        if self.spf_dirty && self.spf_sched.is_due(self.now_ms()) {
            self.spf_dirty = false;
            self.spf_sched.mark_run(self.now_ms());
            self.run_spf(out);
        }
    }

    /// The actual computation: recompute routes from all active
    /// levels and flush the diff to zebra, per RFC 1195 §3.10.2's
    /// preference ladder: for one prefix, "routes learned via level 1
    /// routing" beat level 2 routes; among same-level candidates,
    /// "routes using internal metrics only are always preferred to
    /// routes using external metrics"; then the shortest path
    /// (equal-cost load-splitting is permitted — v1 keeps the
    /// deterministic first next hop).
    fn run_spf(&mut self, out: &mut Vec<Pdu>) {
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
            out.extend(self.originate(false));
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
            out.extend(self.originate(true));
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
        // The on-startup overload window closing: re-originate
        // without the bit (ISO §9.8's LSPDBOL; the restarted IS
        // transits again once converged).
        if !self.config.overload.always && self.overload_deadline.is_some_and(|until| now >= until)
        {
            self.overload_deadline = None;
            info!("on-startup overload window closed");
            for level2 in self.active_levels().collect::<Vec<_>>() {
                out.extend(self.originate(level2));
            }
        }
        // A deferred SPF window opening (the throttle).
        self.maybe_run_spf(out);
        // Hold monitoring (ISO §8.2.5).
        if self.adjacency.hold_expired(now) {
            let action = process_hold_expired(&mut self.adjacency);
            if matches!(action, AdjAction::AdjacencyDown(_)) {
                info!("adjacency DOWN (hold time expired)");
                for level2 in self.active_levels().collect::<Vec<_>>() {
                    out.extend(self.originate(level2));
                }
                self.recompute_routes(out);
            }
        }
        // Aging (purges flood; tombstones expire).
        for level2 in self.active_levels().collect::<Vec<_>>() {
            let state = self.levels[level_index(level2)].as_mut().unwrap();
            let purges = state.db.tick(now, level2);
            let aged = !purges.is_empty();
            for mut purge in purges {
                self.auth_sign(&mut purge);
                out.push(purge);
            }
            if aged {
                self.recompute_routes(out);
            }
        }
        // Refresh.
        self.refresh_check(out);
    }

    /// Dispatch produced PDUs: non-LSPs go straight out; LSPs pass
    /// the circuit's rate limiter (§7.3.15.5's per-LSP spacing,
    /// §7.3.15.6's per-second cap), with the blocked ones queued and
    /// retried — the queue is scanned head to tail, so a paced LSP
    /// does not block fresher ones (the §7.3.15.6 scan shape).
    pub fn pump(&mut self, out: Vec<Pdu>, send: &mut impl FnMut(Pdu)) {
        for pdu in out {
            if matches!(pdu.body, PduBody::Lsp(_)) {
                self.tx_queue.push_back(pdu);
            } else {
                send(pdu);
            }
        }
        let now = self.now();
        let mut admitted_any = true;
        while admitted_any {
            admitted_any = false;
            let mut blocked = std::collections::VecDeque::new();
            while let Some(pdu) = self.tx_queue.pop_front() {
                let ok = match &pdu.body {
                    PduBody::Lsp(l) => self.rate.admit(l.id, now),
                    _ => true,
                };
                if ok {
                    send(pdu);
                    admitted_any = true;
                } else {
                    blocked.push_back(pdu);
                }
            }
            self.tx_queue = blocked;
        }
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
            out.extend(self.originate(level2));
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
                        daemon.pump(out, &mut send);
                    }
                    Some(Event::Redistributed { prefix, add }) => {
                        let mut out = Vec::new();
                        daemon.redistribute(prefix, add, &mut out);
                        daemon.pump(out, &mut send);
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
                daemon.pump(out, &mut send);
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

    // ---- authentication (M3) --------------------------------------

    const AUTH_SECRET: &str = "hush-hush";

    fn auth_daemon() -> Daemon {
        let conf = "router isis T
 net 49.0001.1921.6800.1002.00
 is-type level-2
 hostname r2
 domain-password hmac-md5 hush-hush snp-auth validate
 interface eth0
  address 172.16.0.2/24
  circuit-type level-2
";
        Daemon::new(parse_config(conf).unwrap()).unwrap()
    }

    /// Sign a peer PDU with the shared secret (our own helpers, the
    /// RFC 5304 order).
    fn sign(pdu: &mut Pdu, key: &str, is_lsp: bool) {
        pdu.push_tlv(Tlv::Authentication {
            auth_type: crate::tlv::AUTH_HMAC_MD5,
            value: vec![0u8; 16],
        });
        let mut bytes = pdu.encode();
        let at = crate::auth::find_auth_tlv(&bytes, pdu.header.length_indicator as usize).unwrap();
        let digest = crate::auth::hmac_md5_digest(&bytes, at, is_lsp, key.as_bytes());
        crate::auth::patch_digest(&mut bytes, at, &digest);
        if is_lsp {
            let sum = crate::checksum::lsp_checksum(&mut bytes);
            bytes[24] = (sum >> 8) as u8;
            bytes[25] = (sum & 0xff) as u8;
        }
        *pdu = Pdu::decode(&bytes).unwrap();
    }

    fn peer_hello_pdu(signed: bool, key: &str) -> Pdu {
        let mut pdu = crate::pdu::p2p_hello(
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
        if signed {
            sign(&mut pdu, key, false);
        }
        pdu
    }

    /// RFC 5304 end to end at the daemon: unsigned IIHs are dropped
    /// ("MUST discard"), correctly signed ones pass, wrong keys do
    /// not.
    #[test]
    fn authenticated_adjacency_acceptance() {
        let mut d = auth_daemon();
        // Unsigned: rejected, adjacency untouched.
        let mut out = Vec::new();
        d.handle_pdu(peer_hello_pdu(false, ""), [2, 0, 0, 0, 0, 1], &mut out);
        assert_eq!(d.adjacency.state, crate::adjacency::AdjacencyState::Down);

        // Signed with the right key: accepted.
        let mut out = Vec::new();
        d.handle_pdu(
            peer_hello_pdu(true, AUTH_SECRET),
            [2, 0, 0, 0, 0, 1],
            &mut out,
        );
        assert_eq!(d.adjacency.state, crate::adjacency::AdjacencyState::Up);

        // A wrong key is dropped (the adjacency holds via hold time).
        let mut d2 = auth_daemon();
        let mut out = Vec::new();
        d2.handle_pdu(peer_hello_pdu(true, "wrong"), [2, 0, 0, 0, 0, 1], &mut out);
        assert_eq!(d2.adjacency.state, crate::adjacency::AdjacencyState::Down);
    }

    /// Our own originations carry TLV 10 and verify against the
    /// configured chain; so do the purges we initiate (RFC 5304 §2's
    /// unauthenticated-purge prohibition).
    #[test]
    fn originated_lsps_and_purges_are_signed() {
        let mut d = auth_daemon();
        let mut out = Vec::new();
        d.handle_pdu(
            peer_hello_pdu(true, AUTH_SECRET),
            [2, 0, 0, 0, 0, 1],
            &mut out,
        );
        // Every LSP we originated (router LSP, and any flood echo of
        // our own PDUs) carries a TLV 10.
        let l = out
            .iter()
            .find_map(|p| match &p.body {
                PduBody::Lsp(l) if l.id == LspId::zero(d.system_id) => Some(l.clone()),
                _ => None,
            })
            .expect("router LSP originated");
        assert!(l
            .tlvs
            .iter()
            .any(|t| matches!(t, Tlv::Authentication { auth_type, .. } if *auth_type == crate::tlv::AUTH_HMAC_MD5)));
        // The re-encoded PDU verifies against the domain chain.
        let mut verify_pdu = crate::pdu::lsp(
            true,
            l.id,
            l.sequence_number,
            l.remaining_lifetime,
            l.bits,
            l.tlvs.clone(),
        );
        let _ = &mut verify_pdu;
        let bytes = {
            let mut b = verify_pdu.encode();
            // checksum recomputed by encode equals the stored one;
            // verify over the struct's own encode
            let _ = &mut b;
            b
        };
        assert!(crate::auth::verify(&bytes, 27, true, &d.config.auth[1].chain, 0).is_ok());
        // The aging purge of the PEER's LSP is signed too (our own
        // LSP refreshes at the same boundary; the peer's has no
        // originator here to refresh it).
        let mut peer = peer_lsp(true, (Ipv4Addr::new(10, 60, 0, 0), 24), 10, false);
        sign(&mut peer, AUTH_SECRET, true);
        let mut out = Vec::new();
        d.handle_pdu(peer, [2, 0, 0, 0, 0, 1], &mut out);
        d.time_travel(1200);
        let mut out = Vec::new();
        d.tick(&mut out);
        assert!(out.iter().any(|p| matches!(&p.body,
            PduBody::Lsp(l) if l.is_purge() && l.id == LspId::zero(PEER)
                && l.tlvs.iter().any(|t| matches!(t, Tlv::Authentication { .. })))));
    }

    /// The SNP auth modes: `validate` signs our CSNPs and drops
    /// unsigned ones; `send-only` signs but tolerates; `off` never
    /// signs.
    #[test]
    fn snp_auth_modes() {
        // Validate: our own CSNP is signed; an unsigned CSNP is dropped.
        let mut d = auth_daemon();
        let mut out = Vec::new();
        d.handle_pdu(
            peer_hello_pdu(true, AUTH_SECRET),
            [2, 0, 0, 0, 0, 1],
            &mut out,
        );
        assert!(out.iter().any(|p| matches!(&p.body,
            PduBody::Csnp(c) if c.tlvs.iter().any(|t| matches!(t, Tlv::Authentication { .. })))));
        let unsigned = crate::pdu::csnp(true, PEER, vec![]);
        let mut out2 = Vec::new();
        d.handle_pdu(unsigned, [2, 0, 0, 0, 0, 1], &mut out2);
        // Dropped: no PSNP request emitted for its (empty) entries;
        // the observable: processing a signed one DOES run (it would
        // emit nothing too) — pin the drop via a distinguishable
        // body: a signed one passes, so give the unsigned one an
        // entry we hold older, forcing a PSNP request when accepted.
        let mut db_entry = LspId::zero(PEER);
        db_entry.fragment = 0;
        let entry = crate::tlv::LspEntry {
            remaining_lifetime: 1200,
            lsp_id: db_entry,
            sequence_number: 99,
            checksum: 0x5566,
        };
        let mut rich = crate::pdu::csnp(true, PEER, vec![Tlv::LspEntries(vec![entry])]);
        let mut out3 = Vec::new();
        d.handle_pdu(rich.clone(), [2, 0, 0, 0, 0, 1], &mut out3);
        assert!(
            !out3.iter().any(|p| matches!(p.body, PduBody::Psnp(_))),
            "unsigned CSNP dropped at validate"
        );
        sign(&mut rich, AUTH_SECRET, false);
        let mut out4 = Vec::new();
        d.handle_pdu(rich, [2, 0, 0, 0, 0, 1], &mut out4);
        assert!(
            out4.iter().any(|p| matches!(p.body, PduBody::Psnp(_))),
            "signed CSNP processed (a PSNP request)"
        );

        // Off: nothing signed, nothing required.
        let conf = "router isis T
 net 49.0001.1921.6800.1002.00
 is-type level-2
 hostname r2
 interface eth0
  address 172.16.0.2/24
  circuit-type level-2
";
        let mut plain = Daemon::new(parse_config(conf).unwrap()).unwrap();
        let mut out5 = Vec::new();
        plain.handle_pdu(peer_hello_pdu(false, ""), [2, 0, 0, 0, 0, 1], &mut out5);
        assert_eq!(plain.adjacency.state, crate::adjacency::AdjacencyState::Up);
        assert!(out5.iter().all(|p| !p
            .tlvs()
            .iter()
            .any(|t| matches!(t, Tlv::Authentication { .. }))));
    }

    // ---- M4: fragments, jitter, rate limiting ----------------------

    /// A small-MTU daemon carrying many redistributed prefixes — the
    /// fragmentation fixture.
    fn frag_daemon(prefixes: usize) -> Daemon {
        let conf = "router isis T
 net 49.0001.1921.6800.2002.00
 is-type level-2
 hostname frag-a
 interface eth0
  address 172.16.0.9/24
  circuit-type level-2
  mtu 512
";
        let mut d = Daemon::new(parse_config(conf).unwrap()).unwrap();
        for i in 0..prefixes {
            d.redistributed
                .push((Ipv4Addr::new(10, 200, i as u8, 0), 24));
        }
        d
    }

    /// §7.3.4/§7.3.16.1: a TLV set beyond one fragment originates as
    /// a fragment FAMILY — independent sequence numbers, correct LSP
    /// ids, and §7.3.4's retirement purge when the set shrinks.
    #[test]
    fn fragmented_origination_and_retirement() {
        let mut d = frag_daemon(60);
        let pdus = d.originate(true);
        assert!(pdus.len() >= 2, "60 prefixes at a 485-byte budget split");
        let ids: Vec<u8> = pdus
            .iter()
            .filter_map(|p| match &p.body {
                PduBody::Lsp(l) => Some(l.id.fragment),
                _ => None,
            })
            .collect();
        assert_eq!(ids, (0..ids.len() as u8).collect::<Vec<u8>>(), "0..n");
        // All fragments sit in our own DB.
        let state = d.levels[1].as_ref().unwrap();
        for frag in ids {
            assert!(state.db.get(&LspId::new(d.system_id, 0, frag)).is_some());
        }
        // Withdraw most prefixes: the family shrinks and the retired
        // fragment numbers go out as zero-lifetime purges.
        d.redistributed.truncate(2);
        let pdus = d.originate(true);
        let purges: Vec<u8> = pdus
            .iter()
            .filter_map(|p| match &p.body {
                PduBody::Lsp(l) if l.is_purge() => Some(l.id.fragment),
                _ => None,
            })
            .collect();
        assert!(!purges.is_empty(), "retired fragments purged");
        assert!(purges.iter().all(|f| *f > 0), "fragment 0 never retires");
    }

    /// §7.2.5 end to end: a peer merges our fragment family — a
    /// prefix riding the HIGHEST fragment routes only when fragment 0
    /// is present too, and is ignored without it.
    #[test]
    fn spf_merges_fragments() {
        let mut a = frag_daemon(60);
        let pdus = a.originate(true);
        let highest_prefix = a.redistributed.last().copied().unwrap();

        // A fresh daemon B: adjacency up toward A, then the fragments.
        let mut b = daemon();
        let hello = crate::pdu::p2p_hello(
            Level::Level2,
            a.system_id,
            30,
            9,
            vec![
                Tlv::AreaAddresses(vec![vec![0x49, 0x00, 0x01]]),
                Tlv::ProtocolsSupported(vec![NLPID_IPV4]),
                Tlv::IpInterfaceAddress(vec![Ipv4Addr::new(172, 16, 0, 1)]),
            ],
        );
        let mut out = Vec::new();
        b.handle_pdu(hello.clone(), [2, 0, 0, 0, 0, 1], &mut out);
        let mut out = Vec::new();
        for pdu in pdus.clone() {
            b.handle_pdu(pdu, [2, 0, 0, 0, 0, 1], &mut out);
        }
        assert!(
            b.installed.contains_key(&highest_prefix),
            "the highest fragment's prefix routes (merged)"
        );

        // Without fragment 0 the family is ignored (7.2.5): B' gets
        // only the higher fragments.
        let mut b2 = daemon();
        let mut out = Vec::new();
        b2.handle_pdu(hello.clone(), [2, 0, 0, 0, 0, 1], &mut out);
        let mut out = Vec::new();
        for pdu in pdus.into_iter().filter(|p| match &p.body {
            PduBody::Lsp(l) => l.id.fragment > 0,
            _ => false,
        }) {
            b2.handle_pdu(pdu, [2, 0, 0, 0, 0, 1], &mut out);
        }
        assert!(
            !b2.installed.contains_key(&highest_prefix),
            "no live fragment 0: the fragments are ignored"
        );
    }

    /// §7.3.5 + §10.1's jitter: fragment 0 refreshes at the plain
    /// window; higher fragments stagger deterministically inside
    /// [3/4·window, window).
    #[test]
    fn refresh_jitter_bounds() {
        let sys = SystemId::from_bytes([9, 9, 9, 9, 9, 9]);
        assert_eq!(refresh_threshold(LspId::zero(sys)), REFRESH_BELOW);
        let mut values = std::collections::BTreeSet::new();
        for frag in 1u8..64 {
            let t = refresh_threshold(LspId::new(sys, 0, frag));
            assert!(
                (REFRESH_BELOW - REFRESH_BELOW / 4..=REFRESH_BELOW).contains(&t),
                "fragment {frag}: {t}"
            );
            values.insert(t);
        }
        assert!(values.len() > 10, "the jitter spreads across fragments");
    }

    /// §7.3.15.5/§7.3.15.6 pacing: the same LSP waits out the 5 s
    /// interval; the circuit caps at 30 LSPs per second; a paced head
    /// does not block fresher LSPs; the next second admits the rest.
    #[test]
    fn lsp_rate_limiter() {
        let mut limiter = LspRateLimiter::default();
        let sys = SystemId::from_bytes([1, 1, 1, 1, 1, 1]);
        let a = LspId::new(sys, 0, 0);
        let b = LspId::new(sys, 0, 1);
        assert!(limiter.admit(a, 0));
        assert!(!limiter.admit(a, 3), "same LSP inside 5 s");
        assert!(limiter.admit(a, 5), "the interval elapsed");
        // 30 per second, distinct LSPs.
        let mut limiter = LspRateLimiter::default();
        for i in 0..30u16 {
            let id = LspId::new(SystemId::from_bytes([0, 0, 0, 0, 1, 0]), 0, i as u8);
            assert!(limiter.admit(id, 100), "LSP {i} of the 30");
        }
        assert!(!limiter.admit(b, 100), "the 31st in the same second");
        assert!(limiter.admit(b, 101), "the next second");
        // The head-of-line case: `a` is pacing but `b` still passes.
        let mut limiter = LspRateLimiter::default();
        assert!(limiter.admit(a, 200));
        assert!(!limiter.admit(a, 202));
        assert!(limiter.admit(b, 202), "a paced head blocks no one else");
    }

    /// The pump: blocked LSPs queue and leave on the next tick (the
    /// §7.3.15.6 floor).
    #[test]
    fn pump_queues_and_drains() {
        let mut d = daemon();
        let peer = SystemId::from_bytes([3, 3, 3, 3, 3, 3]);
        let lsp1 = lsp_pdu(true, LspId::zero(peer), 1, 1200, LspBits::default(), vec![]);
        let lsp2 = lsp_pdu(
            true,
            LspId::new(peer, 0, 1),
            1,
            1200,
            LspBits::default(),
            vec![],
        );
        let mut sent: Vec<Pdu> = Vec::new();
        d.pump(vec![lsp1.clone()], &mut |p| sent.push(p));
        assert_eq!(sent.len(), 1);
        // The same LSP again immediately: queued, not sent.
        d.pump(vec![lsp1], &mut |p| sent.push(p));
        assert_eq!(sent.len(), 1, "paced: held in the queue");
        // A different LSP passes while the first paces.
        d.pump(vec![lsp2], &mut |p| sent.push(p));
        assert_eq!(sent.len(), 2);
        // Five seconds later the queue drains (the tick floor).
        d.time_travel(5);
        d.pump(Vec::new(), &mut |p| sent.push(p));
        assert_eq!(sent.len(), 3, "the queued LSP left");
    }

    // ---- M5: the knobs ---------------------------------------------

    fn knob_daemon(extra: &str) -> Daemon {
        let conf = format!(
            "router isis T\n net 49.0001.1921.6800.1002.00\n is-type level-2\n hostname r2\n{extra}\
             \n interface eth0\n  address 172.16.0.2/24\n  circuit-type level-2\n"
        );
        Daemon::new(parse_config(&conf).unwrap()).unwrap()
    }

    /// `set-overload-bit`: the LSPDBOL rides our LSPs; the
    /// on-startup window clears it after the configured seconds and
    /// re-originates; suppress-prefixes originates no prefixes at
    /// all (TLV 132 stays).
    #[test]
    fn overload_knobs() {
        // Unconditional.
        let mut d = knob_daemon(" set-overload-bit");
        let pdus = d.originate(true);
        let PduBody::Lsp(l) = &pdus[0].body else {
            unreachable!()
        };
        assert!(l.bits.overload, "set-overload-bit rides the LSP");

        // On-startup: set inside the window, cleared after.
        let mut d = knob_daemon(" set-overload-bit on-startup 30");
        let pdus = d.originate(true);
        let PduBody::Lsp(l) = &pdus[0].body else {
            unreachable!()
        };
        assert!(l.bits.overload);
        d.time_travel(30);
        let mut out = Vec::new();
        d.tick(&mut out);
        assert!(
            out.iter()
                .any(|p| matches!(&p.body, PduBody::Lsp(l) if !l.bits.overload)),
            "re-originated without the bit once the window closed"
        );

        // suppress-prefixes: nothing in TLV 135, TLV 132 intact.
        let mut d = knob_daemon(" set-overload-bit suppress-prefixes");
        d.redistributed.push((Ipv4Addr::new(198, 51, 100, 0), 24));
        let pdus = d.originate(true);
        for pdu in &pdus {
            let PduBody::Lsp(l) = &pdu.body else {
                unreachable!()
            };
            assert!(
                !l.tlvs
                    .iter()
                    .any(|t| matches!(t, Tlv::ExtIpReachability(_))),
                "no prefixes while overloaded"
            );
            assert!(l.bits.overload);
        }
        let PduBody::Lsp(l) = &pdus[0].body else {
            unreachable!()
        };
        assert!(
            l.tlvs
                .iter()
                .any(|t| matches!(t, Tlv::IpInterfaceAddress(_))),
            "TLV 132 stays (next hops)"
        );
    }

    /// `prefix-suppression` (interface): the connected prefix leaves,
    /// redistributed prefixes and TLV 132 stay.
    #[test]
    fn prefix_suppression_knob() {
        let conf = "router isis T\n net 49.0001.1921.6800.1002.00\n is-type level-2\n hostname r2\n\
                    \n interface eth0\n  address 172.16.0.2/24\n  circuit-type level-2\n  prefix-suppression\n";
        let mut d = Daemon::new(parse_config(conf).unwrap()).unwrap();
        d.redistributed.push((Ipv4Addr::new(198, 51, 100, 0), 24));
        let pdus = d.originate(true);
        let PduBody::Lsp(l) = &pdus[0].body else {
            unreachable!()
        };
        let prefixes: Vec<(Ipv4Addr, u8)> = l
            .tlvs
            .iter()
            .filter_map(|t| match t {
                Tlv::ExtIpReachability(ps) => Some(ps.iter().map(|p| p.prefix).collect::<Vec<_>>()),
                _ => None,
            })
            .flatten()
            .collect();
        assert!(
            !prefixes.contains(&(Ipv4Addr::new(172, 16, 0, 2), 24)),
            "the connected prefix is suppressed"
        );
        assert!(
            prefixes.contains(&(Ipv4Addr::new(198, 51, 100, 0), 24)),
            "redistributed prefixes ride on"
        );
        assert!(l
            .tlvs
            .iter()
            .any(|t| matches!(t, Tlv::IpInterfaceAddress(_))));
    }

    /// `metric-style narrow|transition` origination: the narrow
    /// families ride the LSP (transition carries both).
    #[test]
    fn metric_style_origination() {
        // Narrow: TLV 2 + TLV 128, no wide family.
        let mut d = knob_daemon(" metric-style narrow");
        let mut out = Vec::new();
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
        d.handle_pdu(hello.clone(), [2, 0, 0, 0, 0, 1], &mut out);
        assert!(out.iter().any(|p| matches!(&p.body,
            PduBody::Lsp(l) if l.tlvs.iter().any(|t| matches!(t, Tlv::IsReachability(_))))));
        assert!(
            out.iter().any(|p| matches!(&p.body,
            PduBody::Lsp(l) if l.tlvs.iter().any(|t| matches!(t, Tlv::IpInternalReachability(_)))))
        );
        assert!(!out.iter().any(|p| matches!(&p.body, PduBody::Lsp(l) if l
                .tlvs
                .iter()
                .any(|t| matches!(t, Tlv::ExtIsReachability(_))))));

        // Transition: both families (RFC 1195's transition mode).
        let mut d = knob_daemon(" metric-style transition");
        let mut out = Vec::new();
        d.handle_pdu(hello, [2, 0, 0, 0, 0, 1], &mut out);
        assert!(out.iter().any(|p| matches!(&p.body,
            PduBody::Lsp(l) if l.tlvs.iter().any(|t| matches!(t, Tlv::ExtIsReachability(_))))));
        assert!(out.iter().any(|p| matches!(&p.body,
            PduBody::Lsp(l) if l.tlvs.iter().any(|t| matches!(t, Tlv::IsReachability(_))))));
        assert!(
            out.iter().any(|p| matches!(&p.body,
            PduBody::Lsp(l) if l.tlvs.iter().any(|t| matches!(t, Tlv::IpInternalReachability(_)))))
        );
    }

    /// The SPF back-off (the ospfd pattern): with a configured
    /// throttle, the first change runs immediately, back-to-back
    /// changes defer along the increment, and the deferred run lands
    /// once the window opens.
    #[test]
    fn spf_throttle_backoff() {
        // The pure scheduler ladder.
        let mut sched = SpfThrottle::new(10, 50, 200);
        assert_eq!(sched.on_change(1000), Some(1010), "initial delay");
        assert!(sched.is_due(1010));
        sched.mark_run(1010);
        // The walk includes the initial: 10 + 50 = 60.
        assert_eq!(sched.on_change(1011), Some(1071), "the increment");
        assert!(!sched.is_due(1070));
        assert!(sched.is_due(1071));
        sched.mark_run(1071);
        assert_eq!(sched.on_change(1072), Some(1072 + 110), "walking up");
        sched.mark_run(1182);
        assert_eq!(sched.on_change(1183), Some(1183 + 160), "toward the cap");
        sched.mark_run(1343);
        assert_eq!(sched.on_change(1344), Some(1344 + 200), "the cap");
        // An idle period resets to the initial delay.
        sched.mark_run(1600);
        assert_eq!(sched.on_change(1900), Some(1910), "idle reset");

        // The default computes on change.
        let mut sched = SpfThrottle::default();
        assert_eq!(sched.on_change(1), Some(1));
        assert!(sched.is_due(1));

        // The daemon gate: a throttled daemon defers the second
        // change and lands it on the next tick.
        let mut d = knob_daemon(" spf-throttle 0 5000 5000");
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
        let mut out = Vec::new();
        d.handle_pdu(hello, [2, 0, 0, 0, 0, 1], &mut out);
        // The adjacency-up SPF consumed the first window; both peer
        // LSPs land inside the back-off and defer...
        let mut out = Vec::new();
        d.handle_pdu(
            peer_lsp(true, (Ipv4Addr::new(10, 90, 0, 0), 24), 10, false),
            [2, 0, 0, 0, 0, 1],
            &mut out,
        );
        assert!(
            !d.installed.contains_key(&(Ipv4Addr::new(10, 90, 0, 0), 24)),
            "deferred inside the back-off window"
        );
        // A NEWER instance of the peer LSP (the confusion case would
        // otherwise purge it): sequence 2, both prefixes aboard.
        let mut newer = peer_lsp(true, (Ipv4Addr::new(10, 91, 0, 0), 24), 10, false);
        if let PduBody::Lsp(l) = &mut newer.body {
            l.sequence_number = 2;
            l.tlvs.push(Tlv::ExtIpReachability(vec![WideIpReach {
                metric: 10,
                up_down: false,
                prefix: (Ipv4Addr::new(10, 90, 0, 0), 24),
                sub_tlvs: vec![],
            }]));
        }
        let mut out = Vec::new();
        d.handle_pdu(newer, [2, 0, 0, 0, 0, 1], &mut out);
        assert!(!d.installed.contains_key(&(Ipv4Addr::new(10, 91, 0, 0), 24)));
        // ...and both land once the window opens.
        d.time_travel(6);
        let mut out = Vec::new();
        d.tick(&mut out);
        assert!(d.installed.contains_key(&(Ipv4Addr::new(10, 90, 0, 0), 24)));
        assert!(d.installed.contains_key(&(Ipv4Addr::new(10, 91, 0, 0), 24)));
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
        let pdus = d.originate(true);
        let pdu = &pdus[0];
        let PduBody::Lsp(l) = &pdu.body else {
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
        let pdus = d.originate(true);
        let PduBody::Lsp(l2) = &pdus[0].body else {
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
        // The peer's LSP with the reverse edge. Its advertised
        // lifetime is 5 s, but RFC 7987 stores it at MaxAge — aging
        // runs from 1200, not 5.
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
        // After the stored lifetime (RFC 7987's MaxAge, not the 5 s
        // it advertised), the purge floods and the route withdraws.
        d.time_travel(crate::MAX_AGE as u64);
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
