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

use crate::config::{AreaKind, InterfaceConfig, NetworkType, OspfdConfig};
use crate::exchange::{Conversation, ConversationParams, ConversationReport, Send};
use crate::iface::InterfaceFsm;
use crate::lsa::{Lsa, LsaKey, LsaType, Options, RouterId};
use crate::lsdb::{Lsdb, Readopt};
use crate::neighbor::{process_hello, AreaAdmission};
use crate::neighbor::{HelloParams, NeighborEvent, NeighborState};
use crate::origination::{build_external_lsa, build_router_lsa, InterfaceAdv};
use crate::packet::{Hello, LsUpdate, Packet, PacketBody};
use crate::spf::{self, Destination, SpfScheduler};
use crate::transport::{is_multicast_dst, unicast_ttl_ok, OspfRawSocket, Received};
use crate::zedge::{RedistributedRoute, ZedgeCommand};

/// An inbound packet event: (interface index, datagram).
pub type Inbound = (usize, Received);

/// One OSPF interface under the daemon.
pub struct Interface {
    pub name: String,
    /// The area this interface belongs to (§9.1: a router interface
    /// belongs to one and only one area).
    pub area: u32,
    pub cfg: InterfaceConfig,
    /// The interface's CONCRETE send-side auth view (Appendix D) —
    /// `cfg.auth.live_send_view(now)` at the last refresh (tick or
    /// packet event; a chain-configured interface's rollover pick
    /// advances within one tick, disclosed v1). Static modes are
    /// always their own view. Every transmit site stamps THIS
    /// (`packet_for`, the hello tick, retransmissions, the wire
    /// flush); a chain with no live key degrades to
    /// [`crate::auth::AuthConfig::None`] — the disclosed fail-closed
    /// path (peers discard the AuType-0 packets by D.5).
    pub live_auth: crate::auth::AuthConfig,
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
    /// Appendix D.3/D.4.3 step 5: the interface's ONE send-side
    /// cryptographic sequence counter, shared by the daemon's own
    /// packets (Hellos, floods) and every conversation on the
    /// interface — strictly increasing across the interface's whole
    /// packet stream.
    auth_tx_seq: std::sync::Arc<std::sync::atomic::AtomicU32>,
    /// §15/§D.3: this interface is a virtual link endpoint — its OSPF
    /// area is the BACKBONE (the link extends area 0); `transit_area`
    /// names the area the packets ride.
    pub virtual_link: bool,
    pub transit_area: Option<u32>,
    /// The other endpoint's Router ID.
    pub peer_router: Option<RouterId>,
    /// The other endpoint's IP address — §15: "discovered by looking
    /// up the router ID in the routing table" (the transit area's
    /// intra-area path). None until resolved: no Hellos before that.
    pub vlink_peer_ip: Option<Ipv4Addr>,
}

impl Interface {
    fn conversation_params(&self, kind: AreaKind) -> ConversationParams {
        ConversationParams {
            rxmt_interval: 5,
            mtu: self.cfg.mtu,
            // §C.3: the Options the DBD exchange carries — the E-bit
            // follows the area's ExternalRoutingCapability (§10.5's
            // agreement rule extends to the DD options check).
            options: area_options(kind),
            auth: self.live_auth.clone(),
            auth_seq: self.auth_tx_seq.clone(),
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

/// The Options octet we advertise for an area: E set only in
/// external-capable (normal) areas (§3.6/§10.5).
fn area_options(kind: AreaKind) -> Options {
    match kind {
        AreaKind::Normal => Options(Options::E),
        // RFC 3101 §2.1: E clear in NSSAs, N set in Hellos/DBDs.
        AreaKind::Nssa { .. } => Options(Options::NP),
        AreaKind::Stub | AreaKind::StubNoSummary => Options(0),
    }
}

/// Take the next sequence from an interface's shared crypto counter
/// (only in crypto mode — Null/Simple stamp nothing).
fn next_crypto_seq(
    counter: &std::sync::Arc<std::sync::atomic::AtomicU32>,
    auth: &crate::auth::AuthConfig,
) -> u32 {
    use std::sync::atomic::Ordering;
    match auth {
        crate::auth::AuthConfig::HmacSha256 { .. } | crate::auth::AuthConfig::KeyedMd5 { .. } => {
            counter.fetch_add(1, Ordering::Relaxed) + 1
        }
        _ => 0,
    }
}

/// The receive-side admission class for an area kind (§13 steps 1-3).
fn area_admission(kind: AreaKind) -> AreaAdmission {
    match kind {
        AreaKind::Normal => AreaAdmission::Normal,
        AreaKind::Stub => AreaAdmission::Stub,
        AreaKind::StubNoSummary => AreaAdmission::StubNoSummary,
        AreaKind::Nssa {
            no_summary: false, ..
        } => AreaAdmission::Nssa,
        AreaKind::Nssa {
            no_summary: true, ..
        } => AreaAdmission::NssaNoSummary,
    }
}

/// Per-area protocol state: the §12.2 database plus the §12.4/§16
/// bookkeeping that scopes to one area (router-LSA origination, the
/// SPF throttle). AS-external LSAs are mirrored into every area's
/// database (§7: "The list of AS-external-LSAs is also considered
/// to be part of each area's link state database") — except stub
/// areas, into which type-5s are not flooded at all (§3.6).
pub struct AreaState {
    pub lsdb: Lsdb,
    pub kind: crate::config::AreaKind,
    /// `area <id> default-cost` — the metric of the default summary
    /// into a stub area (§C.2).
    pub default_cost: u32,
    /// The configured `area <id> range` list (§12.4.3's type-3
    /// coalescing; RFC 3101 §3.2's Type-7 address ranges in an NSSA).
    pub ranges: Vec<crate::config::AreaRange>,
    /// RFC 3101 §3.1's NSSATranslatorRole + the live
    /// NSSATranslatorState (Candidate elections; Always enables) and
    /// the deposed translator's keep-translating deadline
    /// (TranslatorStabilityInterval, default 40 s).
    pub translator_role: crate::config::NssaTranslatorRole,
    pub translator_elected: bool,
    pub stability_until: Option<u64>,
    pub translator_stability_interval: u64,
    spf_sched: SpfScheduler,
    spf_dirty: bool,
    router_lsa_dirty: bool,
    /// The last §16.1 result — the incremental cache. Recomputed
    /// only when this area's topology changed (its own scheduler
    /// due); otherwise the router-wide §16 walk reuses it (§16.5's
    /// "it is not necessary to recalculate the entire routing
    /// table").
    last_result: Option<spf::SpfResult>,
    /// How many §16.1 runs this area has computed (test surface for
    /// the only-changed-areas-recompute property).
    spf_runs: u64,
}

impl AreaState {
    fn new(area: &crate::config::AreaConfig) -> Self {
        Self {
            lsdb: Lsdb::new(),
            kind: area.kind,
            default_cost: area.default_cost,
            ranges: area.ranges.clone(),
            translator_role: area.nssa_translator_role,
            translator_elected: false,
            stability_until: None,
            translator_stability_interval: area.translator_stability_interval,
            spf_sched: SpfScheduler::new(0, 50, 5000),
            spf_dirty: false,
            router_lsa_dirty: true,
            last_result: None,
            spf_runs: 0,
        }
    }

    /// Whether THIS area's translator duties run right now: an
    /// elected Candidate, an enabled Always, or a deposed translator
    /// still inside its TranslatorStabilityInterval (RFC 3101 §3.1:
    /// "it continues to perform its translation duties for the
    /// additional time interval").
    fn translator_active(&self, now: u64) -> bool {
        match self.translator_role {
            crate::config::NssaTranslatorRole::Always => true,
            crate::config::NssaTranslatorRole::Candidate => {
                self.translator_elected || self.stability_until.is_some_and(|d| now < d)
            }
        }
    }

    /// The Nt-bit view for origination (the state's letter: enabled
    /// or elected — a deposing translator no longer advertises Nt).
    fn translator_advertises_nt(&self) -> bool {
        match self.translator_role {
            crate::config::NssaTranslatorRole::Always => true,
            crate::config::NssaTranslatorRole::Candidate => self.translator_elected,
        }
    }
}

/// The daemon state machine core. `now` is monotonic seconds since
/// start (clock-injected throughout; `run` owns the real clock).
pub struct Ospfd {
    pub router_id: RouterId,
    pub interfaces: Vec<Interface>,
    /// One AreaState per attached area, keyed by area ID.
    pub areas: BTreeMap<u32, AreaState>,
    /// The exported route table (prefix string -> entry).
    routes: BTreeMap<String, RouteEntry>,
    /// Self-originated external LSAs (prefix string -> key).
    externals: BTreeMap<String, LsaKey>,
    /// Self-originated type-7s ((NSSA area, prefix string) -> key),
    /// RFC 3101 §2.4.
    type_sevens: BTreeMap<(u32, String), LsaKey>,
    /// Translated type-5s ((NSSA area, prefix string) -> key),
    /// RFC 3101 §3.2.
    translations: BTreeMap<(u32, String), LsaKey>,
    /// Self-originated network-LSAs per interface (§12.4.2) — the
    /// flush handles on losing DR.
    network_lsas: HashMap<usize, LsaKey>,
    /// Network-LSA re-origination pending per interface.
    network_lsa_dirty: Vec<usize>,
    /// Self-originated summary-LSAs ((area, key)), §12.4.3 — the
    /// withdrawal diff's baseline.
    summaries: BTreeMap<(u32, LsaKey), ()>,
    /// Whether any external LSA exists (the router-LSA E-bit, §12.4.4).
    asbr: bool,
    /// The router-wide §16 walk is due WITHOUT any area's §16.1
    /// recompute — the AS-scope class (type-5 installs, summary
    /// metric changes): §16.5/§16.6's "incremental updates" (only
    /// the affected route computations rerun; the SPT is unchanged).
    table_dirty: bool,
    zapi: Option<mpsc::UnboundedSender<ZedgeCommand>>,
    redistribute_static: bool,
    /// §C.1's RFC1583Compatibility (O-2, default enabled — the RFC's
    /// letter): gates §16.4.1's ASBR-path pruning in the §16.4
    /// external calculation and the §12.4.3 type-4 pick.
    rfc1583: bool,
    /// Receive-side TTL enforcement counter (night N1): unicast
    /// exchange packets dropped because their TTL is not 1 (§A.1's
    /// single-hop transmit mandate — a degraded TTL means the packet
    /// was relayed, not sent by an on-link peer). INFO-logged per
    /// drop. Multicast Hellos are not checked (the kernel's rule —
    /// see `transport.rs`).
    pub dropped_degraded_ttl: u64,
    /// The SAVNET agent hooks (experimental-savnet, default OFF, then
    /// default None — no agent hosted, no calls made): in-process
    /// reporting of SAV-relevant events. Changed LSAs report from the
    /// conversation reports' `changed` keys (exactly what the
    /// `InstallAndFlood { changed: true }` arm produced — the LSDB
    /// invalidation feed the IGP-side SAVNET designs key on);
    /// adjacency transitions report from every report consumer that
    /// sees them fire. Nothing on the wire depends on any of it.
    #[cfg(feature = "experimental-savnet")]
    sav_agent: Option<Arc<dyn sav::agent::SavAgent>>,
}

/// One network destination in the unified routing table (§11's
/// shape, the intra/inter distinction).
struct RibPath {
    prefix: Ipv4Prefix,
    /// §11's path type: false = intra-area, true = inter-area
    /// (summary-LSA-derived). External paths never enter the ribs —
    /// §16.4 builds them separately.
    inter_area: bool,
    /// The path's associated area.
    area: u32,
    cost: u32,
    hops: Vec<spf::NextHop>,
}

/// One per-area path to a router destination (ABR/ASBR, §16.1 step
/// 4 + §16.2's type-4 form).
struct RouterPath {
    area: u32,
    inter_area: bool,
    cost: u32,
    hops: Vec<spf::NextHop>,
    b_bit: bool,
    e_bit: bool,
}

/// §16.4.1's ASBR-path preference. RFC 2328 §16.4 step (3): if
/// `RFC1583Compatibility` is "disabled", prune the entry set per
/// §16.4.1 — intra-area non-backbone paths first, intra-backbone and
/// inter-area as equals; when "enabled" (§C.1's default) NO pruning
/// applies ("In any case, among the remaining routing table entries,
/// select the routing table entry with the least cost"). In both
/// settings: least cost, then the largest area ID (§16.4 step 3).
fn preferred_asbr_path(paths: &[RouterPath], rfc1583: bool) -> Option<&RouterPath> {
    paths.iter().min_by_key(|p| {
        // Enabled (or an intra-area non-backbone path under either
        // setting): tier 0 — no demotion.
        let tier = if rfc1583 || (!p.inter_area && p.area != 0) {
            0
        } else {
            1
        };
        (tier, p.cost, u32::MAX - p.area)
    })
}

/// Dedup a hop set (sorted, unique) — the equal-cost merges
/// accumulate duplicates across §16.2 steps (5)/(7).
fn dedup_hops(mut hops: Vec<spf::NextHop>) -> Vec<spf::NextHop> {
    hops.sort();
    hops.dedup();
    hops
}

/// Turn SPF next hops into kernel gateways: a next-hop router
/// address directly; a p2p first hop (no router address — §16.1.1's
/// p2p case) through the adjacency's peer address.
fn decorate_hops(ospfd: &Ospfd, hops: &[spf::NextHop]) -> Vec<Nexthop> {
    hops.iter()
        .filter_map(|nh| match nh.router {
            Some(r) => Some(Nexthop::Ipv4(r)),
            None => ospfd.p2p_peer_address(nh.interface).map(Nexthop::Ipv4),
        })
        .collect()
}

impl Ospfd {
    /// The first attached area's ID (single-area convenience).
    pub fn area_id(&self) -> u32 {
        *self.areas.keys().next().unwrap_or(&0)
    }

    /// Whether this router is an area border router (§12.4.3): an
    /// active attachment to the backbone plus at least one other
    /// area.
    fn is_abr(&self) -> bool {
        self.areas.len() > 1 && self.areas.contains_key(&0)
    }

    /// RFC 3101 §3.1: "All NSSA border routers must set the E-bit in
    /// the Type-1 router-LSAs of their directly attached non-stub
    /// areas, even when they are not translating. This allows other
    /// NSSA border routers to see their ASBR status across the AS's
    /// transit topology." v1's TranslatorRole is Always, so any
    /// border router with an attached NSSA translates.
    fn nssa_border(&self) -> bool {
        self.is_abr() && self.areas.values().any(|a| a.kind.nssa())
    }
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
        let mut areas = BTreeMap::new();
        for area in &cfg.areas {
            areas.insert(area.id, AreaState::new(area));
            for (name, icfg) in &area.interfaces {
                let Some((addr, mask)) = icfg.address else {
                    return Err(format!(
                        "interface {name}: address <a.b.c.d/m> is required (no static \
                         address and none in the zapi interface dump)"
                    ));
                };
                if addr.is_unspecified() || addr.is_loopback() {
                    return Err(format!(
                        "interface {name}: address must be a real interface address"
                    ));
                }
                let p2p = icfg.network_type == NetworkType::PointToPoint;
                let mut fsm = InterfaceFsm::new_with_priority(p2p, icfg.priority);
                // §9.3 InterfaceUp: the lower layer's usable-interface
                // signal. Static config (no dump): the config's address
                // IS the signal — v1 behavior, InterfaceUp fires at
                // construction. With the zapi interface dump merged in
                // (`ifdump`), the LIVE link state is the signal: an
                // interface the dump reports down (or loopback) stays in
                // Down — no Hellos, no router-LSA links — until ongoing
                // link-state tracking lands (§Deferred).
                let (_, actions) = if icfg.link_state == Some(false) {
                    // Stay Down; no WaitTimer is armed.
                    (crate::iface::InterfaceState::Down, Vec::new())
                } else {
                    fsm.fire(crate::iface::InterfaceEvent::InterfaceUp)
                };
                let wait_deadline =
                    if actions.contains(&crate::iface::InterfaceAction::StartWaitTimer) {
                        // The WaitTimer is the RouterDeadInterval (§9.5.1's
                        // startup form), clocked from the daemon's t=0.
                        Some(icfg.dead_interval as u64)
                    } else {
                        None
                    };
                interfaces.push(Interface {
                    name: name.clone(),
                    area: area.id,
                    // The concrete send view at t=0 (the tick refreshes
                    // it — chain rollover advances within one tick).
                    live_auth: icfg.auth.live_send_view(0),
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
                    auth_tx_seq: std::sync::Arc::new(std::sync::atomic::AtomicU32::new(0)),
                    virtual_link: false,
                    transit_area: None,
                    peer_router: None,
                    vlink_peer_ip: None,
                });
            }
        }
        // §D.3: one synthetic interface per configured virtual link —
        // a member of the BACKBONE riding the transit area.
        let mut vlinks: Vec<(u32, u32)> = Vec::new();
        for area in &cfg.areas {
            for peer in &area.virtual_links {
                vlinks.push((area.id, *peer));
            }
        }
        for (transit, peer) in vlinks {
            let addr = interfaces
                .iter()
                .find(|i| i.area == transit)
                .map(|i| i.addr)
                .unwrap_or(Ipv4Addr::UNSPECIFIED);
            let mut fsm = InterfaceFsm::new_with_priority(true, 1);
            let _ = fsm.fire(crate::iface::InterfaceEvent::InterfaceUp);
            interfaces.push(Interface {
                name: format!("vl-{peer}"),
                area: 0,
                live_auth: crate::auth::AuthConfig::None,
                cfg: InterfaceConfig::defaults(),
                addr,
                mask: Ipv4Addr::from(0xffff_ffff),
                p2p: true,
                fsm,
                dr: Ipv4Addr::UNSPECIFIED,
                bdr: Ipv4Addr::UNSPECIFIED,
                wait_deadline: None,
                claims: HashMap::new(),
                neighbors: HashMap::new(),
                hello_deadline: 0,
                auth_tx_seq: std::sync::Arc::new(std::sync::atomic::AtomicU32::new(0)),
                virtual_link: true,
                transit_area: Some(transit),
                peer_router: Some(RouterId(peer)),
                vlink_peer_ip: None,
            });
        }
        if interfaces.is_empty() {
            return Err("no interfaces configured".into());
        }
        if cfg.redistribute_static
            && !areas
                .values()
                .any(|a| a.kind.external_capable() || a.kind.nssa())
        {
            // §3.6: "AS boundary routers cannot be placed internal to
            // stub areas" — `redistribute static` with no
            // external-capable area attached is a configuration error.
            return Err(
                "redistribute static requires a non-stub area (§3.6: ASBRs cannot be internal to stub areas)"
                    .into(),
            );
        }
        Ok(Self {
            router_id: RouterId::from_ipv4(router_id),
            interfaces,
            areas,
            routes: BTreeMap::new(),
            externals: BTreeMap::new(),
            type_sevens: BTreeMap::new(),
            translations: BTreeMap::new(),
            network_lsas: HashMap::new(),
            network_lsa_dirty: Vec::new(),
            summaries: BTreeMap::new(),
            asbr: false,
            table_dirty: true,
            zapi: None,
            redistribute_static: cfg.redistribute_static,
            rfc1583: cfg.rfc1583_compatibility,
            dropped_degraded_ttl: 0,
            #[cfg(feature = "experimental-savnet")]
            sav_agent: None,
        })
    }

    pub fn attach_zapi(&mut self, tx: mpsc::UnboundedSender<ZedgeCommand>) {
        self.zapi = Some(tx);
    }

    /// Host a SAVNET agent (experimental-savnet; see
    /// docs/protocols/savnet.md): the daemon reports changed LSAs and
    /// adjacency transitions in-process. Monitor-only by contract —
    /// the agent's suggestions are logged observations, never
    /// enforcement inputs. Default None even under the flag: nothing
    /// hosts an agent in tonight's multi-process deployment (the
    /// in-process composition is a test/single-binary-deployment
    /// concern).
    #[cfg(feature = "experimental-savnet")]
    pub fn set_sav_agent(&mut self, agent: Arc<dyn sav::agent::SavAgent>) {
        self.sav_agent = Some(agent);
    }

    /// The hosted SAVNET agent, if any (experimental-savnet).
    #[cfg(feature = "experimental-savnet")]
    pub fn sav_agent(&self) -> Option<&Arc<dyn sav::agent::SavAgent>> {
        self.sav_agent.as_ref()
    }

    /// Report one SAVNET adjacency transition (experimental-savnet),
    /// called from every ConversationReport consumer that sees
    /// adjacency_up/adjacency_down fire. The interface model carries
    /// no kernel ifindex yet, so the event names the peer without
    /// one.
    #[cfg(feature = "experimental-savnet")]
    fn sav_report_adjacency(&self, idx: usize, peer: RouterId, up: bool) {
        let Some(agent) = &self.sav_agent else {
            return;
        };
        let address = self.interfaces[idx]
            .neighbors
            .get(&peer)
            .map(|conv| std::net::IpAddr::V4(conv.ip))
            .unwrap_or(std::net::IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED));
        let peer = sav::agent::SavPeer {
            address,
            remote_id: peer.0,
        };
        agent.on_event(if up {
            sav::agent::SavAgentEvent::AdjacencyUp {
                protocol: sav::agent::SavProtocol::Ospf,
                peer,
                ifindex: None,
            }
        } else {
            sav::agent::SavAgentEvent::AdjacencyDown {
                protocol: sav::agent::SavProtocol::Ospf,
                peer,
            }
        });
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

    /// Mark one area's routing calculation dirty (§16 runs on the
    /// throttle window — FRR-parity backoff). EVERY dirtying site
    /// must go through here: the scheduler's due deadline dies with
    /// `mark_run`, so a bare `spf_dirty` flag without `on_change`
    /// would never fire again.
    fn mark_spf_dirty(&mut self, area: u32, now: u64) {
        if let Some(a) = self.areas.get_mut(&area) {
            a.spf_sched.on_change(now * 1000);
            a.spf_dirty = true;
        }
    }

    /// Mark the router-wide table walk due without any §16.1
    /// recompute — the AS-scope class (§16.5/§16.6: a type-5 or
    /// summary-LSA change reruns only those route computations; the
    /// per-area SPT is untouched).
    fn mark_table_dirty(&mut self) {
        self.table_dirty = true;
    }

    #[cfg(test)]
    fn packet(&self, area: u32, body: PacketBody) -> Packet {
        make_packet(self.router_id, area, body)
    }

    /// `packet` with the target interface's auth stamped (Appendix
    /// D): the AuType/Authentication header fields, the crypto
    /// sequence bumped per send (D.4.3 step 5).
    fn packet_for(&mut self, iface_idx: usize, area: u32, body: PacketBody) -> Packet {
        let mut p = make_packet(self.router_id, area, body);
        // The LIVE view — a chain-configured interface stamps the
        // key the chain selects at the last refresh.
        let auth = self.interfaces[iface_idx].live_auth.clone();
        let seq = next_crypto_seq(&self.interfaces[iface_idx].auth_tx_seq, &auth);
        p.header.au_type = auth.au_type();
        p.header.authentication = auth.auth_field(seq);
        p
    }

    /// Interface advertisement snapshot for one area (§12.4.1's
    /// builder input — a router-LSA describes the router's links in
    /// THAT area only, §12.4.1).
    fn interface_advs(&self, area: u32) -> Vec<InterfaceAdv> {
        self.interfaces
            .iter()
            .filter(|i| i.area == area)
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
                    virtual_link: i.virtual_link,
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
            let area = self.interfaces[idx].area;
            if let Some(a) = self.areas.get_mut(&area) {
                a.router_lsa_dirty = true;
            }
            // §12.4.2: a former DR flushes its network-LSA.
            if was_role == crate::iface::InterfaceState::Dr
                && outcome.role != crate::iface::InterfaceState::Dr
            {
                if let Some(key) = self.network_lsas.remove(&idx) {
                    let aged = self
                        .areas
                        .get_mut(&area)
                        .and_then(|a| a.lsdb.premature_age(&key));
                    if let Some(maxage) = aged {
                        self.flood_own(&maxage, Some(area), now, out);
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
        let area = self.interfaces[idx].area;
        let iface = &mut self.interfaces[idx];
        let Some(area_state) = self.areas.get(&area) else {
            return;
        };
        if let Some(conv) = iface.neighbors.get_mut(&peer) {
            let (sends, report) =
                conv.fire_and_map(NeighborEvent::AdjOk(answer), &area_state.lsdb, now);
            out.extend(sends_into(idx, sends));
            if report.adjacency_up || report.adjacency_down {
                // The SAVNET adjacency report (experimental-savnet)
                // runs after the conversation borrows release.
                let _ = (iface, area_state);
                #[cfg(feature = "experimental-savnet")]
                self.sav_report_adjacency(idx, peer, report.adjacency_up);
                if let Some(a) = self.areas.get_mut(&area) {
                    a.router_lsa_dirty = true;
                }
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
        let (area, state, addr, mask, attached) = {
            let iface = &self.interfaces[idx];
            (
                iface.area,
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
                let aged = self
                    .areas
                    .get_mut(&area)
                    .and_then(|a| a.lsdb.premature_age(&key));
                if let Some(maxage) = aged {
                    self.flood_own(&maxage, Some(area), now, out);
                    info!(iface = %self.interfaces[idx].name, "ospfd: network-LSA flushed (§12.4.2)");
                }
            }
            return;
        }
        let adv = InterfaceAdv {
            state,
            p2p: false,
            virtual_link: false,
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
        let Some(area_state) = self.areas.get_mut(&area) else {
            return;
        };
        match area_state.lsdb.originate(lsa, now) {
            Ok(_) => {
                self.network_lsas.insert(idx, key);
                if let Some(entry) = area_state.lsdb.get(&key) {
                    let stored = entry.lsa.clone();
                    self.flood_own(&stored, Some(area), now, out);
                }
                self.mark_spf_dirty(area, now);
            }
            Err(e) => {
                // MinLSInterval — retry on a later tick.
                debug!(error = %e, "ospfd: network-LSA origination deferred");
            }
        }
    }

    /// (Re-)originate one area's router-LSA (§12.4.1: the LSA
    /// describes the router's links IN that area; the B-bit is set
    /// when the router is an area border router, §A.4.2) and flood
    /// it to the area's Full neighbors (§13.3 lists armed).
    fn originate_router_lsa(&mut self, area: u32, now: u64, out: &mut Vec<WireOut>) {
        let advs = self.interface_advs(area);
        // §A.4.2's V-bit: the router is an endpoint of a virtual link
        // using THIS area as transit (spf's TransitCapability input).
        let v_bit = self
            .interfaces
            .iter()
            .any(|i| i.virtual_link && i.transit_area == Some(area));
        // The E-bit: our own externals (§12.4.4) OR the RFC 3101
        // §3.1 NSSA-border duty in non-stub areas (the translated
        // type-5s advertise US as the ASBR — the transit topology
        // must see that status).
        let kind = self
            .areas
            .get(&area)
            .map(|a| a.kind)
            .unwrap_or(AreaKind::Normal);
        let e_bit = self.asbr || (kind.external_capable() && self.nssa_border());
        // RFC 3101 §3.1: "when an NSSA border router has its
        // NSSATranslatorState enabled, it sets bit Nt in the
        // router-LSA it originates into the NSSA" — this area's copy
        // only.
        let nt_bit = matches!(kind, AreaKind::Nssa { .. })
            && self.nssa_border()
            && self
                .areas
                .get(&area)
                .is_some_and(|a| a.translator_advertises_nt());
        let lsa = build_router_lsa(self.router_id, e_bit, self.is_abr(), v_bit, nt_bit, &advs);
        let Some(area_state) = self.areas.get_mut(&area) else {
            return;
        };
        match area_state.lsdb.originate(lsa, now) {
            Ok(_) => {
                area_state.router_lsa_dirty = false;
                // Flood the STORED instance — Lsdb::originate stamped
                // the sequence (§12.1.6); the builder's copy carries
                // the raw 0.
                let key = LsaKey {
                    ls_type: crate::lsa::LsaType::ROUTER,
                    link_state_id: crate::lsa::LinkStateId(self.router_id.0),
                    adv_router: self.router_id,
                };
                if let Some(entry) = area_state.lsdb.get(&key) {
                    let stored = entry.lsa.clone();
                    self.flood_own(&stored, Some(area), now, out);
                    // The area graph changed: §16 runs.
                    self.mark_spf_dirty(area, now);
                }
                info!(area, "ospfd: router-LSA originated");
            }
            Err(e) => {
                // MinLSInterval not elapsed — retry on the next tick.
                debug!(error = %e, "ospfd: router-LSA origination deferred (MinLSInterval)");
            }
        }
    }

    /// §12.4.4: originate the AS-external-LSA for a redistributed
    /// route and flood it AS-wide (type-5s are AS-scoped: originated
    /// in the first area's database, the same instance mirrored into
    /// every other area's — §7's "part of each area's link state
    /// database"); the router-LSA turns on its E-bit (the router is
    /// now an ASBR).
    fn originate_external(
        &mut self,
        prefix: Ipv4Prefix,
        metric: u32,
        now: u64,
        out: &mut Vec<WireOut>,
    ) {
        let mask = Ipv4Addr::from(u32::MAX << (32 - prefix.prefix_len()));
        // §7/§3.6: type-5s live in the external-capable (normal)
        // areas only — never originated or mirrored into stub or
        // NSSA areas.
        let master = self
            .areas
            .iter()
            .find(|(_, a)| a.kind.external_capable())
            .map(|(id, _)| *id);
        let mut originated = false;
        if let Some(master) = master {
            let lsa = build_external_lsa(self.router_id, prefix.addr(), mask, metric, true);
            let key = lsa.key();
            let Some(area_state) = self.areas.get_mut(&master) else {
                return;
            };
            if area_state.lsdb.originate(lsa, now).is_ok() {
                self.externals.insert(prefix.to_string(), key);
                originated = true;
                let stored = area_state.lsdb.get(&key).map(|e| e.lsa.clone());
                // Mirror the identical instance into every other
                // external-capable area (§7; stub/NSSA areas are
                // skipped — §3.6: AS-external-LSAs are not flooded
                // into them).
                if let Some(lsa) = &stored {
                    for other in self
                        .areas
                        .iter()
                        .filter(|(id, a)| **id != master && a.kind.external_capable())
                        .map(|(id, _)| *id)
                        .collect::<Vec<_>>()
                    {
                        if let Some(state) = self.areas.get_mut(&other) {
                            state.lsdb.mirror_originated(lsa, now);
                        }
                    }
                    self.flood_own(lsa, None, now, out);
                }
                info!(prefix = %prefix, "ospfd: external LSA originated");
            }
        }
        // RFC 3101 §2.4: the same external is imported into every
        // attached NSSA as a type-7 — area-scoped, FA from one of our
        // own NSSA interface addresses ("preference should be given
        // to the router's internal addresses"; the P-set form must be
        // non-zero, §2.3). A border router originating both forms
        // must clear the P-bit ("so that it isn't translated into a
        // Type-5 LSA by another NSSA border router").
        let has_normal = self.areas.values().any(|a| a.kind.external_capable());
        for nssa in self
            .areas
            .iter()
            .filter(|(_, a)| a.kind.nssa())
            .map(|(id, _)| *id)
            .collect::<Vec<_>>()
        {
            let Some(fa) = self
                .interfaces
                .iter()
                .find(|i| i.area == nssa)
                .map(|i| i.addr)
            else {
                continue;
            };
            let p_bit = !has_normal;
            let lsa = crate::origination::build_nssa_lsa(
                self.router_id,
                prefix.addr(),
                mask,
                metric,
                true,
                fa,
                p_bit,
            );
            let key = lsa.key();
            let Some(state) = self.areas.get_mut(&nssa) else {
                continue;
            };
            if state.lsdb.originate(lsa, now).is_ok() {
                self.type_sevens.insert((nssa, prefix.to_string()), key);
                originated = true;
                if let Some(entry) = state.lsdb.get(&key) {
                    let stored = entry.lsa.clone();
                    self.flood_own(&stored, Some(nssa), now, out);
                }
                self.mark_table_dirty();
                info!(area = nssa, prefix = %prefix, "ospfd: type-7 LSA originated (RFC 3101 §2.4)");
            }
        }
        if originated {
            let first = !self.asbr;
            self.asbr = true;
            self.mark_table_dirty();
            if first {
                // The E-bit change re-originates the router-LSA
                // (every area — the NSSA ASBR sets E per RFC 3101
                // §2.3).
                for area in self.areas.keys().copied().collect::<Vec<_>>() {
                    if let Some(a) = self.areas.get_mut(&area) {
                        a.router_lsa_dirty = true;
                    }
                }
            }
        }
    }

    /// Re-originate one type-7 in `area` from its stored shape (the
    /// §13.4 re-adoption path).
    fn originate_external_nssa_only(
        &mut self,
        area: u32,
        prefix: Ipv4Prefix,
        metric: u32,
        now: u64,
        out: &mut Vec<WireOut>,
    ) {
        let Some(fa) = self
            .interfaces
            .iter()
            .find(|i| i.area == area)
            .map(|i| i.addr)
        else {
            return;
        };
        let has_normal = self.areas.values().any(|a| a.kind.external_capable());
        let lsa = crate::origination::build_nssa_lsa(
            self.router_id,
            prefix.addr(),
            Ipv4Addr::from(u32::MAX << (32 - prefix.prefix_len())),
            metric,
            true,
            fa,
            !has_normal,
        );
        let key = lsa.key();
        let Some(state) = self.areas.get_mut(&area) else {
            return;
        };
        if state.lsdb.originate(lsa, now).is_ok() {
            self.type_sevens.insert((area, prefix.to_string()), key);
            if let Some(entry) = state.lsdb.get(&key) {
                let stored = entry.lsa.clone();
                self.flood_own(&stored, Some(area), now, out);
            }
            self.mark_spf_dirty(area, now);
        }
    }

    /// §12.4.4's withdrawal: premature-age the LSA in every area
    /// (§14.1) and flood the MaxAge instance.
    fn withdraw_external(&mut self, prefix_str: &str, now: u64, out: &mut Vec<WireOut>) {
        // RFC 3101 §2.4: the type-7s of the same prefix go too.
        let sevens: Vec<(u32, LsaKey)> = self
            .type_sevens
            .iter()
            .filter(|((_, p), _)| p == prefix_str)
            .map(|((a, _), k)| (*a, *k))
            .collect();
        for (nssa, key) in sevens {
            self.type_sevens.remove(&(nssa, prefix_str.to_string()));
            let aged = self
                .areas
                .get_mut(&nssa)
                .and_then(|s| s.lsdb.premature_age(&key));
            if let Some(maxage) = aged {
                self.flood_own(&maxage, Some(nssa), now, out);
                self.mark_table_dirty();
            }
        }
        // Translations of the withdrawn type-7s stop being justified
        // (RFC 3101 §3.2's flush side).
        let translated: Vec<((u32, String), LsaKey)> = self
            .translations
            .iter()
            .filter(|((_, p), _)| p == prefix_str)
            .map(|(tag, k)| (tag.clone(), *k))
            .collect();
        self.flush_translations(&translated, now, out);
        if let Some(key) = self.externals.remove(prefix_str) {
            let areas: Vec<u32> = self.areas.keys().copied().collect();
            let mut aged = false;
            for area in areas {
                if let Some(state) = self.areas.get_mut(&area) {
                    if let Some(lsa) = state.lsdb.premature_age(&key) {
                        if !aged {
                            self.flood_own(&lsa, None, now, out);
                            aged = true;
                        }
                    }
                }
            }
            info!(
                prefix = prefix_str,
                "ospfd: external LSA withdrawn (MaxAge)"
            );
        }
    }

    /// §13.4: whether the router currently wishes to originate the
    /// LSA named by `key`. The "no longer wishes" cases drive the
    /// flush: no advertisable route (externals), no longer DR for
    /// the network (network-LSAs), and the Router-ID-changed shape
    /// is handled by `is_our_network` below.
    fn wants_to_originate(&self, _area: u32, key: &LsaKey) -> bool {
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
            // §12.4.3's set: the summaries the fresh table last
            // justified (the default-cost summary into a stub area
            // and the type-7 NSSA default included).
            LsaType::SUMMARY_NETWORK | LsaType::SUMMARY_ASBR => {
                self.summaries.contains_key(&(_area, *key))
            }
            // RFC 3101 §2.4: our type-7s (redistributed routes) and
            // the NSSA default.
            LsaType::NSSA => {
                self.summaries.contains_key(&(_area, *key))
                    || self.type_sevens.values().any(|k| k == key)
            }
            _ => false,
        }
    }

    /// §13.4's reception of self-originated LSAs, run after the LSU's
    /// flooding install: by then the store holds the received
    /// instance whenever it won §13.1, so this sees exactly the
    /// adopted state. Two detections (§13.4): Advertising Router ==
    /// our ID, or a network-LSA whose Link State ID is one of our
    /// interface addresses.
    fn after_self_originated(&mut self, area: u32, lsas: &[Lsa], now: u64, out: &mut Vec<WireOut>) {
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
            let Some(state) = self.areas.get(&area) else {
                continue;
            };
            let Some(stored) = state.lsdb.get(&key) else {
                continue;
            };
            if stored.lsa.header.seq != lsa.header.seq || stored.lsa.header.is_max_age() {
                continue;
            }
            let stored = stored.lsa.clone();
            let want = self.wants_to_originate(area, &key);
            let readopt = if want {
                self.areas
                    .get_mut(&area)
                    .map(|s| s.lsdb.readopt_self_originated(lsa))
                    .unwrap_or(Readopt::Stale)
            } else {
                Readopt::NotOurs
            };
            match readopt {
                Readopt::Advanced => {
                    info!(key = ?key, "ospfd: adopting newer self-originated LSA (§13.4)");
                    // Re-originate past it on the next tick
                    // (MinLSInterval retries included).
                    match key.ls_type {
                        LsaType::ROUTER => {
                            if let Some(a) = self.areas.get_mut(&area) {
                                a.router_lsa_dirty = true;
                            }
                        }
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
                        // RFC 3101 §2.4's type-7: re-originate past
                        // the adopted instance (same §13.4 logic).
                        LsaType::NSSA => {
                            if let crate::lsa::LsaBody::AsExternal(ext) = &stored.body {
                                let prefix = Ipv4Prefix::new(
                                    stored.header.link_state_id.to_ipv4(),
                                    u32::from(ext.mask).count_ones() as u8,
                                )
                                .expect("type-7 mask");
                                let p_bit = stored.header.options.np_bit();
                                let has_normal =
                                    self.areas.values().any(|a| a.kind.external_capable());
                                let _ = p_bit && !has_normal; // P rule re-derived at build
                                let mut out2 = std::mem::take(out);
                                self.originate_external_nssa_only(
                                    area, prefix, ext.metric, now, &mut out2,
                                );
                                *out = out2;
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
                    let aged = self
                        .areas
                        .get_mut(&area)
                        .and_then(|s| s.lsdb.premature_age(&key));
                    if let Some(maxage) = aged {
                        self.flood_own(&maxage, Some(area), now, out);
                    }
                }
                Readopt::Stale | Readopt::NotOurs => {
                    if !want {
                        // §13.4's flush list: increment the received
                        // LSA's age to MaxAge and reflood (§14.1).
                        let aged = self
                            .areas
                            .get_mut(&area)
                            .and_then(|s| s.lsdb.premature_age(&key));
                        if let Some(maxage) = aged {
                            info!(key = ?key, "ospfd: flushing unwanted self-originated LSA (§13.4)");
                            self.flood_own(&maxage, Some(area), now, out);
                        }
                    }
                }
            }
        }
    }

    /// The AS-scope propagation for received type-5s: install the
    /// same instance into every other area's database (§7) and flood
    /// it out their Full adjacencies (§13 step 1f: AS-external LSAs
    /// go out every interface except the arrival one).
    fn mirror_as_scoped(
        &mut self,
        arrival_area: u32,
        lsas: &[Lsa],
        now: u64,
        out: &mut Vec<WireOut>,
    ) {
        for lsa in lsas {
            if lsa.header.ls_type != LsaType::AS_EXTERNAL {
                continue;
            }
            let areas: Vec<u32> = self
                .areas
                .iter()
                .filter(|(a, state)| **a != arrival_area && state.kind.external_capable())
                .map(|(a, _)| *a)
                .collect();
            for area in areas {
                let Some(state) = self.areas.get_mut(&area) else {
                    continue;
                };
                let before = state.lsdb.get(&lsa.key()).map(|e| e.lsa.header.seq);
                let _ = state.lsdb.install(lsa.clone(), true, now);
                let after = state.lsdb.get(&lsa.key()).map(|e| e.lsa.header.seq);
                if before != after || before.is_none() {
                    // Newly installed or advanced: flood it out this
                    // area's adjacencies.
                    if let Some(entry) = state.lsdb.get(&lsa.key()) {
                        let stored = entry.lsa.clone();
                        let _ = state;
                        self.flood_own(&stored, Some(area), now, out);
                        self.mark_table_dirty();
                        continue;
                    }
                }
            }
        }
    }

    /// Flood one LSA to the Full neighbors in scope, arming §13.3's
    /// retransmission lists. `scope`: `Some(area)` — the area-scoped
    /// LSAs (types 1-4, §13 step 1f's same-area rule); `None` — the
    /// AS-scoped type-5s (every area). The wire shape: p2p unicast
    /// per neighbor; broadcast networks multicast per §13.3/§A.1 —
    /// the DR and BDR send to AllSPFRouters (224.0.0.5), DR Others
    /// to AllDRouters (224.0.0.6) so only the DR/BDR process the
    /// flood. (Retransmissions stay unicast per neighbor — the
    /// RxmtInterval paths in `exchange`.)
    fn flood_own(&mut self, lsa: &Lsa, scope: Option<u32>, now: u64, out: &mut Vec<WireOut>) {
        // Collect (interface, neighbor ips, broadcast role) first,
        // then build packets (packet() borrows self immutably).
        let mut targets: Vec<(usize, u32, Vec<Ipv4Addr>, Option<bool>)> = Vec::new();
        for (idx, iface) in self.interfaces.iter_mut().enumerate() {
            if let Some(area) = scope {
                if iface.area != area {
                    continue;
                }
            }
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
            targets.push((idx, iface.area, ips, bcast_role));
        }
        for (idx, area, ips, bcast_role) in targets {
            match bcast_role {
                Some(dr_or_bdr) if !ips.is_empty() => {
                    // §13.3: one multicast LSU on the broadcast
                    // network; every Full neighbor is on the
                    // retransmission list.
                    let packet = self.packet_for(
                        idx,
                        area,
                        PacketBody::LsUpdate(LsUpdate {
                            lsas: vec![lsa.clone()],
                        }),
                    );
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
                        let packet = self.packet_for(
                            idx,
                            area,
                            PacketBody::LsUpdate(LsUpdate {
                                lsas: vec![lsa.clone()],
                            }),
                        );
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

    /// Appendix D.5: authenticate one received packet against the
    /// receiving interface's configured mode, then hand back the
    /// decoded packet. Failure discards the packet silently — §8.2's
    /// processing never starts, so no neighbor FSM event fires (the
    /// ONLY neighbor-state effect of sustained failure is the
    /// Inactivity Timer's eventual Down).
    fn authenticate(
        &mut self,
        iface_idx: usize,
        received: &Received,
        now: u64,
    ) -> Result<Packet, String> {
        let auth = self.interfaces[iface_idx].cfg.auth.clone();
        match auth.au_type() {
            0 => {
                // D.5 preamble: "the packet's AuType must match the
                // receiving interface's".
                let p = Packet::decode(&received.payload).map_err(|e| format!("decode: {e}"))?;
                if p.header.au_type != 0 {
                    return Err("AuType mismatch (0 expected)".into());
                }
                Ok(p)
            }
            1 => {
                // D.5.2: (1) the normal checksum (decode verified
                // it), (2) the Authentication field must equal the
                // configured password.
                let p = Packet::decode(&received.payload).map_err(|e| format!("decode: {e}"))?;
                let password = match &auth {
                    crate::auth::AuthConfig::Simple { password } => *password,
                    _ => unreachable!("au_type 1 is Simple"),
                };
                if p.header.au_type != 1 || p.header.authentication != u64::from_be_bytes(password)
                {
                    return Err("simple password mismatch (D.5.2 step 2)".into());
                }
                Ok(p)
            }
            _ => {
                // AuType 2 — D.5.3, in the RFC's order, over BOTH
                // crypto engines (RFC 5709 HMAC-SHA-256 and the
                // legacy D.4.3(6) keyed-MD5) and the key chains that
                // feed them (RFC 8177).
                let (p, trailer) =
                    Packet::decode_crypto(&received.payload).map_err(|e| format!("decode: {e}"))?;
                // (1) Key lookup by Key ID — for a chain, any key
                // whose ACCEPT lifetime is live at `now` (the
                // rollover overlap); for a static key, its own ID.
                let data = crate::auth::CryptoAuthData::from_u64(p.header.authentication);
                let view = auth.accept_view(now, data.key_id).ok_or_else(|| {
                    format!("Key ID {} not valid for reception here", data.key_id)
                })?;
                let (key, digest_len, engine) = match &view {
                    crate::auth::AuthConfig::HmacSha256 { key, .. } => {
                        (key.clone(), 32, "hmac-sha-256")
                    }
                    crate::auth::AuthConfig::KeyedMd5 { key, .. } => (key.clone(), 16, "md5"),
                    other => {
                        return Err(format!(
                            "chain resolved to a non-crypto view ({:?})",
                            other.au_type()
                        ))
                    }
                };
                if key.is_empty() {
                    return Err("no crypto key configured".into());
                }
                // (2) The per-neighbor sequence: "discard if the
                // packet's sequence number is less than the value
                // recorded in the neighbor data structure" (equal
                // passes — retransmissions).
                let peer = p.header.router_id;
                let recorded = self.interfaces[iface_idx]
                    .neighbors
                    .get(&peer)
                    .map(|c| c.rx_crypto_seq)
                    .unwrap_or(0);
                if data.seq < recorded {
                    return Err(format!(
                        "crypto sequence {} < recorded {recorded} (D.5.3 step 2)",
                        data.seq
                    ));
                }
                // (3) The digest with the KEY's algorithm (the
                // engine follows the key, not the interface):
                // packet ‖ Apad (RFC 5709 §3.3) for HMAC-SHA-256,
                // MD5(packet ‖ key) (D.4.3 step 6) for MD5 —
                // compared against the trailer.
                if trailer.len() != digest_len {
                    return Err(format!(
                        "trailer length {} (Auth Data Len says {})",
                        trailer.len(),
                        data.data_len
                    ));
                }
                let packet_bytes = &received.payload[..received.payload.len() - digest_len];
                let mac_ok = match &view {
                    crate::auth::AuthConfig::HmacSha256 { key, .. } => {
                        crate::auth::packet_mac(packet_bytes, key)[..] == trailer[..]
                    }
                    crate::auth::AuthConfig::KeyedMd5 { key, .. } => {
                        crate::auth::packet_mac_md5(packet_bytes, key)[..] == trailer[..]
                    }
                    _ => unreachable!("resolved above"),
                };
                if !mac_ok {
                    return Err(format!("{engine} digest mismatch (D.5.3 step 3)"));
                }
                // Accept: record the sequence (D.3) when the
                // neighbor structure exists.
                if let Some(c) = self.interfaces[iface_idx].neighbors.get_mut(&peer) {
                    c.rx_crypto_seq = data.seq;
                }
                Ok(p)
            }
        }
    }

    /// Process one inbound datagram (already demultiplexed to its
    /// interface by the run loop's on-link test).
    pub fn on_packet(&mut self, iface_idx: usize, received: &Received, now: u64) -> Vec<WireOut> {
        // Refresh the send view (chain rollover advances within one
        // event; static modes are a no-op clone).
        self.interfaces[iface_idx].live_auth =
            self.interfaces[iface_idx].cfg.auth.live_send_view(now);
        let out = Vec::new();
        // The receive-side TTL check (night N1, closing the W2-e
        // fence): §A.1 mandates TTL 1 on EVERY OSPF send, so a
        // UNICAST exchange packet (DD/LSR/LSU/LSAck, p2p Hellos)
        // arriving with a degraded TTL cannot have come from an
        // on-link peer — dropped and counted. Multicast Hellos keep
        // the kernel's rule: no check (RFC 2328 places no
        // receive-side TTL rule; §A.1's TTL-1 is a transmit
        // mandate). The check precedes authentication, the RFC
        // 5881 §5-style early discard (cheap; no crypto on doomed
        // packets).
        if !is_multicast_dst(received.dst) && !unicast_ttl_ok(received.ttl) {
            self.dropped_degraded_ttl += 1;
            info!(
                src = %received.src,
                dst = %received.dst,
                ttl = received.ttl,
                "ospfd: unicast packet dropped: TTL != 1 (RFC 2328 §A.1's single-hop TTL)"
            );
            return out;
        }
        // Appendix D.5: authenticate before ANY further processing
        // ("processing of the received packet, as described in
        // Section 8.2, continues only if the packet is
        // authenticated") — a failed packet is silently discarded:
        // no neighbor events, no LSAs, nothing.
        let packet = match self.authenticate(iface_idx, received, now) {
            Ok(p) => p,
            Err(e) => {
                debug!(error = %e, src = %received.src, "ospfd: packet failed authentication (App D.5)");
                return out;
            }
        };
        // §A.3.1 checks: version handled by decode; our own Router ID
        // (§A.3: "packets originating from itself"); the area.
        if packet.header.router_id == self.router_id {
            return out;
        }
        let area = self.interfaces[iface_idx].area;
        if packet.header.area_id != area {
            // §15: a backbone-area packet riding a non-backbone
            // interface is virtual-link traffic — process it on our
            // virtual link for that area.
            if let Some(vl) = self
                .interfaces
                .iter()
                .position(|i| i.virtual_link && i.area == packet.header.area_id)
            {
                return self.on_packet_on(vl, packet, received, now);
            }
            debug!(
                area = packet.header.area_id,
                src = %received.src,
                "ospfd: foreign area drop"
            );
            return out;
        }
        self.on_packet_on(iface_idx, packet, received, now)
    }

    /// The per-interface packet processing after authentication and
    /// demultiplexing.
    fn on_packet_on(
        &mut self,
        iface_idx: usize,
        packet: Packet,
        received: &Received,
        now: u64,
    ) -> Vec<WireOut> {
        let mut out = Vec::new();
        let area = self.interfaces[iface_idx].area;
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
        let kind = self
            .areas
            .get(&self.interfaces[iface_idx].area)
            .map(|a| a.kind)
            .unwrap_or(AreaKind::Normal);
        let admission = area_admission(kind);
        let hello_params = {
            let iface = &self.interfaces[iface_idx];
            HelloParams {
                network_mask: iface.mask,
                hello_interval: iface.cfg.hello_interval,
                router_dead_interval: iface.cfg.dead_interval,
                e_capable: kind.external_capable(),
                n_capable: kind.nssa(),
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
                let params = self.interfaces[iface_idx].conversation_params(kind);
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
                        Conversation::new(self.router_id, area, received.src, now, dead, params)
                    });
                conv.peer_router_id = Some(peer);
                conv.ip = received.src;
                let mut adj_change = false;
                let area_lsdb = self.areas.get(&area).map(|a| &a.lsdb);
                for event in events {
                    let (event_sends, report) = match area_lsdb {
                        Some(lsdb) => conv.fire_and_map(event, lsdb, now),
                        None => continue,
                    };
                    out.extend(sends_into(iface_idx, event_sends));
                    conv.touch_inactivity(now, dead);
                    match event {
                        NeighborEvent::TwoWayReceived => {
                            // §10.3's decision point: AdjOK? with
                            // §10.4's answer — p2p always adjacent;
                            // broadcast only with/toward the DR/BDR.
                            let (sends, report) = match area_lsdb {
                                Some(lsdb) => {
                                    conv.fire_and_map(NeighborEvent::AdjOk(adj_answer), lsdb, now)
                                }
                                None => continue,
                            };
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
                    if let Some(a) = self.areas.get_mut(&area) {
                        a.router_lsa_dirty = true;
                    }
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
                let mtu = self.interfaces[iface_idx].cfg.mtu;
                let iface = &mut self.interfaces[iface_idx];
                let Some(conv) = iface.neighbors.get_mut(&peer) else {
                    debug!(src = %received.src, "ospfd: conversation packet from unknown neighbor");
                    return out;
                };
                let Some(area_state) = self.areas.get_mut(&area) else {
                    return out;
                };
                let lsdb = &mut area_state.lsdb;
                let mut received_lsas: Option<Vec<Lsa>> = None;
                let (sends, report) = match &packet.body {
                    PacketBody::DbDescription(dd) => conv.handle_dbd(dd, peer, mtu, lsdb, now),
                    PacketBody::LsRequest(lsr) => conv.handle_lsr(lsr, lsdb, now),
                    PacketBody::LsUpdate(lsu) => {
                        let (sends, report) =
                            conv.handle_lsu(&lsu.lsas, lsdb, now, syncing, admission);
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
                // §13.4's self-originated reception + the §7/§13.1f
                // AS-scope propagation, after the flooding install.
                if let Some(lsas) = received_lsas {
                    self.after_self_originated(area, &lsas, now, &mut out);
                    self.mirror_as_scoped(area, &lsas, now, &mut out);
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
        let area = self.interfaces[iface_idx].area;
        // The SAVNET reports (experimental-savnet): adjacency
        // transitions and changed LSAs, in-process and monitor-only.
        #[cfg(feature = "experimental-savnet")]
        if let Some(peer_id) = peer {
            if report.adjacency_up {
                self.sav_report_adjacency(iface_idx, peer_id, true);
            }
            if report.adjacency_down {
                self.sav_report_adjacency(iface_idx, peer_id, false);
            }
            if !report.changed.is_empty() {
                if let Some(agent) = &self.sav_agent {
                    let peer = sav::agent::SavPeer {
                        address: self.interfaces[iface_idx]
                            .neighbors
                            .get(&peer_id)
                            .map(|conv| std::net::IpAddr::V4(conv.ip))
                            .unwrap_or(std::net::IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED)),
                        remote_id: peer_id.0,
                    };
                    // Exactly the InstallAndFlood { changed: true }
                    // products: each changed key is one LSA the §13
                    // flood installed with new contents.
                    for key in &report.changed {
                        agent.on_event(sav::agent::SavAgentEvent::LsaChanged {
                            peer: peer.clone(),
                            ls_type: key.ls_type.0,
                            link_state_id: Ipv4Addr::from(key.link_state_id.0),
                            adv_router: Ipv4Addr::from(key.adv_router.0),
                        });
                    }
                }
            }
        }
        if report.adjacency_up {
            info!(
                iface = %self.interfaces[iface_idx].name,
                neighbor = peer.map(|p| p.to_string()).unwrap_or_default(),
                "ospfd: adjacency FULL"
            );
            if let Some(a) = self.areas.get_mut(&area) {
                a.router_lsa_dirty = true;
            }
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
            // Appendix D.3: the neighbor's cryptographic sequence
            // number "is reset to zero" on the transition to Down.
            if let Some(peer_id) = peer {
                if let Some(conv) = self.interfaces[iface_idx].neighbors.get_mut(&peer_id) {
                    conv.rx_crypto_seq = 0;
                }
            }
            if let Some(a) = self.areas.get_mut(&area) {
                a.router_lsa_dirty = true;
            }
            if !self.interfaces[iface_idx].p2p
                && self.interfaces[iface_idx].fsm.state == crate::iface::InterfaceState::Dr
            {
                self.network_lsa_dirty.push(iface_idx);
            }
        }
        if !report.changed.is_empty() {
            // Class-based dirtying (§16.5/§16.6): router/network-LSA
            // changes recompute the area's SPT (on the FRR-parity
            // throttle backoff); the summary/external classes only
            // rerun the affected route computations.
            if report
                .changed
                .iter()
                .any(|k| matches!(k.ls_type, LsaType::ROUTER | LsaType::NETWORK))
            {
                self.mark_spf_dirty(area, now);
            } else {
                self.mark_table_dirty();
            }
        }
    }

    /// Fire the §16 routing calculation when any area's throttle
    /// window opens, then diff the route table and emit zapi
    /// adds/deletes. The walk is router-wide (§16's routing table is
    /// global): any area due → recompute everything — intra-area SPF
    /// per area (§16.1), the inter-area routes from the examined
    /// area's summary-LSAs (§16.2), the AS external routes with the
    /// full type-4 ASBR lookup (§16.4/§16.4.1), then the ABR's
    /// §12.4.3 summary origination off the fresh table.
    pub fn maybe_spf(
        &mut self,
        now: u64,
        out: &mut Vec<WireOut>,
        zapi_out: &mut Vec<ZedgeCommand>,
    ) {
        // The incremental scheduling wrapper (§16.5/§16.6's "it is
        // not necessary to recalculate the entire routing table"):
        // an area whose topology changed recomputes its §16.1 on its
        // OWN backoff schedule (FRR-parity throttle); unchanged
        // areas reuse their cached result. The AS-scope class
        // (type-5/summary changes — `table_dirty`) runs the
        // router-wide walk without ANY §16.1 recompute (the SPT is
        // untouched by those LSA classes).
        let any_due = self
            .areas
            .values()
            .any(|a| a.spf_dirty && a.spf_sched.is_due(now * 1000));
        if !any_due && !self.table_dirty {
            return;
        }
        let area_ids: Vec<u32> = self.areas.keys().copied().collect();
        // Refresh only the due-and-dirty areas; snapshot everyone's
        // result for the walk below.
        let mut results: Vec<(u32, spf::SpfResult)> = Vec::new();
        for area in &area_ids {
            let Some(a) = self.areas.get_mut(area) else {
                continue;
            };
            let recompute =
                a.spf_dirty && a.spf_sched.is_due(now * 1000) || a.last_result.is_none();
            if recompute {
                a.spf_sched.mark_run(now * 1000);
                a.spf_dirty = false;
                a.last_result = Some(spf::calculate(self.router_id, &a.lsdb));
                a.spf_runs += 1;
            }
            if let Some(r) = &a.last_result {
                results.push((*area, r.clone()));
            }
        }
        self.table_dirty = false;

        // ---- §16.1: the intra-area paths, per attached area ----
        // The unified routing table (§11's shape): network
        // destinations keyed by prefix; router destinations (ABR/
        // ASBR) keyed by Router ID, one path per area.
        let mut ribs: BTreeMap<(u32, u32), RibPath> = BTreeMap::new();
        let mut routers: BTreeMap<RouterId, Vec<RouterPath>> = BTreeMap::new();
        for (area, result) in &results {
            for route in &result.routes {
                match route.destination {
                    Destination::Network { addr, mask } => {
                        let prefix =
                            Ipv4Prefix::new(addr, mask_prefix(mask)).expect("valid mask from SPF");
                        let key = (u32::from(addr), u32::from(mask));
                        let hops = dedup_hops(route.next_hops.clone());
                        match ribs.get_mut(&key) {
                            // §16.2 step (6) analog: the intra-area
                            // minimum wins; equal costs merge hops.
                            Some(existing) if existing.cost < route.cost => {}
                            Some(existing) if existing.cost == route.cost => {
                                existing.hops.extend(hops);
                            }
                            Some(existing) => {
                                *existing = RibPath {
                                    prefix,
                                    inter_area: false,
                                    area: *area,
                                    cost: route.cost,
                                    hops,
                                };
                            }
                            None => {
                                ribs.insert(
                                    key,
                                    RibPath {
                                        prefix,
                                        inter_area: false,
                                        area: *area,
                                        cost: route.cost,
                                        hops,
                                    },
                                );
                            }
                        }
                    }
                    Destination::Router(id) => {
                        let flags = result.router_flags.get(&id).copied().unwrap_or_default();
                        routers.entry(id).or_default().push(RouterPath {
                            area: *area,
                            inter_area: false,
                            cost: route.cost,
                            hops: dedup_hops(route.next_hops.clone()),
                            b_bit: flags.b,
                            e_bit: flags.e,
                        });
                    }
                }
            }
        }

        // ---- RFC 3101 §3.1: the NSSA translator election ----
        // "An NSSA border router whose NSSA's NSSATranslatorRole is set
        // to Candidate must maintain a list of the NSSA's border
        // routers that are reachable both over the NSSA and as ASBRs
        // over the AS's transit topology. Any change in this list, or
        // to the Nt bit settings of members of this list, causes the
        // NSSA border router to reevaluate its NSSATranslatorState."
        // Reevaluated on every walk (the SPF results ARE the list's
        // inputs); an Always role needs no election ("When
        // NSSATranslatorRole is set to Always, Type-7 LSAs are always
        // translated").
        if self.is_abr() {
            let nssa_areas: Vec<u32> = self
                .areas
                .iter()
                .filter(|(_, a)| a.kind.nssa())
                .map(|(id, _)| *id)
                .collect();
            for nssa in nssa_areas {
                let Some(state) = self.areas.get_mut(&nssa) else {
                    continue;
                };
                if state.translator_role != crate::config::NssaTranslatorRole::Candidate {
                    continue;
                }
                // The list: other border routers with an intra-area
                // path over the NSSA (B-bit set in the NSSA's own
                // copy) AND reachability over the transit topology (a
                // path in another attached area — the §3.1 E-bit rule
                // makes that visibility the ASBR-status test).
                let nssa_result = results
                    .iter()
                    .find(|(area, _)| *area == nssa)
                    .map(|(_, r)| r.clone())
                    .unwrap_or_default();
                let mut outranked = false;
                for (rid, flags) in &nssa_result.router_flags {
                    if *rid == self.router_id || !flags.b {
                        continue;
                    }
                    let over_nssa = routers
                        .get(rid)
                        .is_some_and(|paths| paths.iter().any(|p| p.area == nssa && !p.inter_area));
                    let over_transit = routers
                        .get(rid)
                        .is_some_and(|paths| paths.iter().any(|p| p.area != nssa));
                    if !over_nssa || !over_transit {
                        continue;
                    }
                    // "If there exists another border router in this
                    // list whose router-LSA has bit Nt set or who has
                    // a higher router ID, then its
                    // NSSATranslatorState is disabled."
                    if flags.nt || rid.larger_than(self.router_id) {
                        outranked = true;
                        break;
                    }
                }
                let was = state.translator_elected;
                let stability_expired = state.stability_until.is_some_and(|d| now >= d);
                state.translator_elected = !outranked;
                if outranked && was {
                    // "An elected translator will continue to perform
                    // translation duties until supplanted ... it
                    // continues to perform its translation duties for
                    // the additional time interval defined by ...
                    // TranslatorStabilityInterval" (default 40 s) —
                    // arming only ever applies to a translator that
                    // WAS active (a never-elected router translates
                    // nothing and arms nothing).
                    state.stability_until = Some(now + state.translator_stability_interval);
                }
                if stability_expired {
                    // The window lapsed: retire it (a re-election in
                    // the same walk makes the window moot anyway).
                    state.stability_until = None;
                }
                if was != state.translator_elected {
                    info!(
                        nssa,
                        elected = state.translator_elected,
                        "ospfd: NSSA translator state changed (RFC 3101 3.1)"
                    );
                    // The Nt bit rides the NSSA's router-LSA.
                    state.router_lsa_dirty = true;
                }
            }
        }

        // ---- §16.2: the inter-area routes from summary-LSAs ----
        // "If the router has active attachments to multiple areas,
        // only backbone summary-LSAs are examined. Routers attached
        // to a single area examine that area's summary-LSAs."
        let summary_area = if self.areas.len() > 1 {
            if self.areas.contains_key(&0) {
                0
            } else {
                return;
            }
        } else {
            area_ids[0]
        };
        let summaries: Vec<Lsa> = self
            .areas
            .get(&summary_area)
            .map(|a| {
                a.lsdb
                    .all()
                    .filter(|e| {
                        matches!(
                            e.lsa.header.ls_type,
                            LsaType::SUMMARY_NETWORK | LsaType::SUMMARY_ASBR
                        )
                    })
                    .map(|e| e.lsa.clone())
                    .collect()
            })
            .unwrap_or_default();
        for lsa in &summaries {
            // (1) LSInfinity or MaxAge: examine the next LSA.
            let crate::lsa::LsaBody::Summary(body) = &lsa.body else {
                continue;
            };
            if body.metric >= crate::LS_INFINITY || lsa.header.is_max_age() {
                continue;
            }
            // (2) Self-originated: examine the next LSA.
            if lsa.header.adv_router == self.router_id {
                continue;
            }
            // (3) The own-active-range check: a summary-LSA whose
            // network falls inside one of OUR configured ranges that
            // we are ACTIVELY advertising (at least one contributing
            // intra-area route in the range's area) is not installed
            // — the inter-area view of a range we own is suppressed.
            let own_active_range = |prefix: &Ipv4Prefix| {
                self.areas.iter().any(|(area_id, a)| {
                    a.ranges.iter().any(|r| {
                        r.advertise
                            && r.prefix.prefix_len() <= prefix.prefix_len()
                            && r.prefix.contains(prefix.addr())
                            && ribs.values().any(|m| {
                                m.area == *area_id
                                    && !m.inter_area
                                    && r.prefix.prefix_len() <= m.prefix.prefix_len()
                                    && r.prefix.contains(m.prefix.addr())
                            })
                    })
                })
            };
            // (4) BR must be reachable in the examined area.
            let Some(br) = routers.get(&lsa.header.adv_router).and_then(|paths| {
                paths
                    .iter()
                    .find(|p| p.area == summary_area && !p.inter_area)
            }) else {
                continue;
            };
            let (br_cost, br_hops) = (br.cost, br.hops.clone());
            let iac = br_cost.saturating_add(body.metric);
            match lsa.header.ls_type {
                LsaType::SUMMARY_NETWORK => {
                    // (4): N's address = Link State ID masked by the
                    // body's mask.
                    let addr = Ipv4Addr::from(lsa.header.link_state_id.0 & u32::from(body.mask));
                    let key = (u32::from(addr), u32::from(body.mask));
                    let prefix =
                        Ipv4Prefix::new(addr, mask_prefix(body.mask)).expect("summary mask");
                    if own_active_range(&prefix) {
                        continue; // (3): our own active range owns this network
                    }
                    match ribs.get_mut(&key) {
                        // (5) no entry: install.
                        None => {
                            ribs.insert(
                                key,
                                RibPath {
                                    prefix,
                                    inter_area: true,
                                    area: summary_area,
                                    cost: iac,
                                    hops: br_hops.clone(),
                                },
                            );
                        }
                        // (6) intra-area paths present: do nothing.
                        Some(existing) if !existing.inter_area => {}
                        // (7) inter-area: cheaper overrides, equal merges.
                        Some(existing) if existing.cost < iac => {}
                        Some(existing) if existing.cost == iac => {
                            existing.hops.extend(br_hops.iter().copied());
                        }
                        Some(existing) => {
                            *existing = RibPath {
                                prefix,
                                inter_area: true,
                                area: summary_area,
                                cost: iac,
                                hops: br_hops.clone(),
                            };
                        }
                    }
                }
                LsaType::SUMMARY_ASBR => {
                    // (5) the router form: install an inter-area path
                    // for the ASBR unless an intra-area path exists
                    // (6) or a cheaper inter-area one does (7).
                    let id = RouterId(lsa.header.link_state_id.0);
                    let paths = routers.entry(id).or_default();
                    if paths.iter().any(|p| !p.inter_area) {
                        continue; // (6)
                    }
                    match paths
                        .iter_mut()
                        .find(|p| p.inter_area && p.area == summary_area)
                    {
                        Some(p) if p.cost < iac => {}
                        Some(p) if p.cost == iac => p.hops.extend(br_hops.iter().copied()),
                        Some(p) => {
                            *p = RouterPath {
                                area: summary_area,
                                inter_area: true,
                                cost: iac,
                                hops: br_hops.clone(),
                                b_bit: false,
                                e_bit: true,
                            }
                        }
                        None => paths.push(RouterPath {
                            area: summary_area,
                            inter_area: true,
                            cost: iac,
                            hops: br_hops,
                            b_bit: false,
                            e_bit: true,
                        }),
                    }
                }
                _ => {}
            }
        }

        // ---- §16.4: the AS external routes ----
        // Externals are AS-scoped (mirrored into every area's
        // database); the examined area's copy is authoritative.
        let mut fresh: BTreeMap<String, RouteEntry> = BTreeMap::new();
        // RFC 3101 §2.5 step (6)(e)'s preference ladder, recorded per
        // installed external prefix: 0 = type-7 P-set, 1 = type-5,
        // 2 = type-7 P-clear; ties break to the higher Router ID.
        let mut ext_rank: BTreeMap<String, (u8, u32)> = BTreeMap::new();
        let external_lsas: Vec<Lsa> = self
            .areas
            .get(&summary_area)
            .map(|a| {
                a.lsdb
                    .all()
                    .filter(|e| e.lsa.header.ls_type == LsaType::AS_EXTERNAL)
                    .map(|e| e.lsa.clone())
                    .collect()
            })
            .unwrap_or_default();
        for entry in &external_lsas {
            // (1) LSInfinity/MaxAge, (2) self-originated.
            if entry.header.is_max_age() {
                continue;
            }
            if entry.header.adv_router == self.router_id {
                continue;
            }
            let crate::lsa::LsaBody::AsExternal(ext) = &entry.body else {
                continue;
            };
            if ext.metric >= crate::LS_INFINITY {
                continue;
            }
            // (3) the preferred ASBR path (§16.4 step 3 + §16.4.1):
            // RFC1583Compatibility DISABLED prunes to intra-area
            // non-backbone paths first (intra-backbone and inter-area
            // as equals); ENABLED (§C.1's default) considers every
            // entry. Both: least cost, largest area ID breaking ties.
            let Some(asbr_path) = routers
                .get(&entry.header.adv_router)
                .and_then(|paths| preferred_asbr_path(paths, self.rfc1583))
            else {
                continue; // ASBR unreachable
            };
            // The forwarding address (§16.4 step 3b).
            let (x, hops) = if ext.forwarding_address != Ipv4Addr::UNSPECIFIED {
                let fa = ext.forwarding_address;
                let Some(fa_path) = ribs.values().find(|r| r.prefix.contains(fa)) else {
                    continue; // FA must have an intra/inter-area path
                };
                (fa_path.cost, fa_path.hops.clone())
            } else {
                (asbr_path.cost, asbr_path.hops.clone())
            };
            // (4)/(5): X (the intra-AS distance) + Y (the LSA metric).
            let cost = if ext.e_bit {
                ext.metric.min(crate::LS_INFINITY)
            } else {
                x.saturating_add(ext.metric)
            };
            let prefix = Ipv4Prefix::new(
                entry.header.link_state_id.to_ipv4(),
                u32::from(ext.mask).count_ones() as u8,
            )
            .expect("external mask");
            let mut group = NexthopGroup::new();
            for hop in decorate_hops(self, &hops) {
                group.add(hop, 1);
            }
            if group.is_empty() {
                continue;
            }
            let entry_out = RouteEntry::new(
                common::IpPrefix::V4(prefix),
                RouteProtocol::Ospf,
                group,
                cost,
            );
            fresh.insert(prefix.to_string(), entry_out);
            ext_rank.insert(prefix.to_string(), (1, entry.header.adv_router.0));
        }

        // ---- RFC 3101 §2.5: the type-7s of each attached NSSA ----
        // "AS external routes are calculated by examining
        // AS-external-LSAs, be they Type-5 or Type-7" — the type-7s
        // of every attached NSSA, with the ASBR/FA lookups restricted
        // to the LSA's originating NSSA (step 3's [NSSA] paragraphs).
        let nssa_areas: Vec<u32> = self
            .areas
            .iter()
            .filter(|(_, a)| a.kind.nssa())
            .map(|(id, _)| *id)
            .collect();
        for nssa in &nssa_areas {
            let Some(state) = self.areas.get(nssa) else {
                continue;
            };
            let sevens: Vec<Lsa> = state
                .lsdb
                .all()
                .filter(|e| e.lsa.header.ls_type == LsaType::NSSA)
                .map(|e| e.lsa.clone())
                .collect();
            for lsa in &sevens {
                // (1) LSInfinity/MaxAge, (2) self-originated.
                if lsa.header.is_max_age() {
                    continue;
                }
                if lsa.header.adv_router == self.router_id {
                    continue;
                }
                let crate::lsa::LsaBody::AsExternal(ext) = &lsa.body else {
                    continue;
                };
                if ext.metric >= crate::LS_INFINITY {
                    continue;
                }
                let p_bit = lsa.header.options.np_bit();
                let is_default =
                    lsa.header.link_state_id.0 == 0 && ext.mask == Ipv4Addr::UNSPECIFIED;
                if is_default {
                    // §2.5 step (3): a border router skips type-7
                    // defaults when suppressing summary import; the
                    // P-clear default rides Appendix E's technique —
                    // "an NSSA border router installs a Type-7 default
                    // LSA without propagating it" (§3.2 never
                    // translates a P-clear default, so the install is
                    // local-only). DISCLOSED divergence from FRR
                    // 10.2.2, probed live in the N3 interop: FRR
                    // stores the LSA but does not install the route —
                    // the RFC appendix's technique wins here.
                    if self.is_abr() {
                        let no_summary = matches!(
                            state.kind,
                            AreaKind::Nssa {
                                no_summary: true,
                                ..
                            }
                        );
                        if no_summary {
                            continue;
                        }
                    }
                }
                // (3) [NSSA]: "the routing table entry of its ASBR
                // must be found in the originating NSSA".
                let Some(asbr_path) = routers
                    .get(&lsa.header.adv_router)
                    .and_then(|paths| paths.iter().find(|p| p.area == *nssa && !p.inter_area))
                else {
                    continue;
                };
                // The forwarding address: "For a Type-7 LSA the
                // matching routing table entry must specify an
                // intra-area path through the LSA's originating NSSA".
                let (x, hops) = if ext.forwarding_address != Ipv4Addr::UNSPECIFIED {
                    let fa = ext.forwarding_address;
                    let Some(fa_path) = ribs
                        .values()
                        .find(|r| r.prefix.contains(fa) && r.area == *nssa && !r.inter_area)
                    else {
                        continue;
                    };
                    (fa_path.cost, fa_path.hops.clone())
                } else {
                    (asbr_path.cost, asbr_path.hops.clone())
                };
                let cost = if ext.e_bit {
                    ext.metric.min(crate::LS_INFINITY)
                } else {
                    x.saturating_add(ext.metric)
                };
                let prefix = Ipv4Prefix::new(
                    lsa.header.link_state_id.to_ipv4(),
                    u32::from(ext.mask).count_ones() as u8,
                )
                .expect("type-7 mask");
                let rank = if p_bit { 0u8 } else { 2u8 };
                let mine = (rank, lsa.header.adv_router.0);
                match ext_rank.get(&prefix.to_string()) {
                    Some(&(other_rank, other_adv))
                        if (other_rank, u32::MAX - other_adv) <= (mine.0, u32::MAX - mine.1) =>
                    {
                        continue; // existing path preferred (§2.5 (6)(e))
                    }
                    _ => {}
                }
                let mut group = NexthopGroup::new();
                for hop in decorate_hops(self, &hops) {
                    group.add(hop, 1);
                }
                if group.is_empty() {
                    continue;
                }
                let entry_out = RouteEntry::new(
                    common::IpPrefix::V4(prefix),
                    RouteProtocol::Ospf,
                    group,
                    cost,
                );
                fresh.insert(prefix.to_string(), entry_out);
                ext_rank.insert(prefix.to_string(), mine);
            }
        }

        // ---- the intra/inter-area export ----
        for path in ribs.values() {
            let mut group = NexthopGroup::new();
            for hop in decorate_hops(self, &path.hops) {
                group.add(hop, 1);
            }
            if group.is_empty() {
                continue;
            }
            let entry = RouteEntry::new(
                common::IpPrefix::V4(path.prefix),
                RouteProtocol::Ospf,
                group,
                path.cost,
            );
            fresh.insert(path.prefix.to_string(), entry);
        }

        // ---- §12.4.3 + RFC 3101: the ABR duties ----
        self.originate_summaries(&ribs, &routers, now, out, zapi_out);
        // RFC 3101 §3.2: the type-7 → type-5 translation, "performed
        // as part of the NSSA's Dijkstra calculation after Type-5 and
        // Type-7 routes have been calculated".
        self.translate_nssa(now, out);

        // ---- the export diff ----
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

        // ---- §15: virtual-link endpoint resolution ----
        // "The other endpoint of the virtual link is discovered by
        // looking up the virtual link's neighbor router ID in the
        // routing table" — the transit area's intra-area path to the
        // peer; the first next-hop router address is the endpoint's
        // own address in the directly-connected shape.
        for (area, result) in &results {
            let vlinks: Vec<usize> = self
                .interfaces
                .iter()
                .enumerate()
                .filter(|(_, i)| i.virtual_link && i.transit_area == Some(*area))
                .map(|(idx, _)| idx)
                .collect();
            for idx in vlinks {
                let Some(peer) = self.interfaces[idx].peer_router else {
                    continue;
                };
                let resolved = result.routes.iter().find_map(|r| {
                    match r.destination {
                        Destination::Router(rid) if rid == peer => {
                            r.next_hops.first().and_then(|nh| {
                                nh.router.or_else(|| {
                                    // A p2p first hop: the adjacency's
                                    // peer address on that interface.
                                    self.p2p_peer_address(nh.interface)
                                })
                            })
                        }
                        _ => None,
                    }
                });
                if resolved != self.interfaces[idx].vlink_peer_ip {
                    self.interfaces[idx].vlink_peer_ip = resolved;
                    if let Some(ip) = resolved {
                        info!(iface = %self.interfaces[idx].name, peer = %ip,
                              "ospfd: virtual link endpoint resolved (§15)");
                        if let Some(conv) = self.interfaces[idx].neighbors.get_mut(&peer) {
                            conv.ip = ip;
                        }
                        if let Some(a) = self.areas.get_mut(&0) {
                            a.router_lsa_dirty = true;
                        }
                    }
                }
            }
        }
    }

    /// §12.4.3's ABR duties, run off the fresh routing table: for
    /// every attached area A, originate type-3 summaries for the
    /// inter-area-eligible networks and type-4s for the preferred
    /// ASBR paths, and flush the summaries no longer justified.
    /// v1 scope (disclosed): no configured address ranges — the
    /// §12.4.3 default (one type-3 per network) applies; the
    /// coalescing/aggregation rules land with `area range` config.
    #[allow(clippy::too_many_arguments)]
    fn originate_summaries(
        &mut self,
        ribs: &BTreeMap<(u32, u32), RibPath>,
        routers: &BTreeMap<RouterId, Vec<RouterPath>>,
        now: u64,
        out: &mut Vec<WireOut>,
        _zapi_out: &mut Vec<ZedgeCommand>,
    ) {
        if !self.is_abr() {
            // Not an ABR: flush anything we may still hold (a lost
            // area), then done.
            let stale: Vec<(u32, LsaKey)> = self.summaries.keys().copied().collect();
            self.flush_summaries(&stale, now, out);
            return;
        }
        // The desired set: (area, key) -> metric.
        let mut desired: BTreeMap<(u32, LsaKey), u32> = BTreeMap::new();
        let area_ids: Vec<u32> = self.areas.keys().copied().collect();
        for area_a in &area_ids {
            let Some(target) = self.areas.get(area_a) else {
                continue;
            };
            let mut skip_type4 = false;
            match target.kind {
                AreaKind::Stub | AreaKind::StubNoSummary => {
                    // §3.6/§12.4.3.1: into a stub area the ABR
                    // advertises ONLY the default summary-LSA (metric
                    // = the area's default-cost) — no per-network
                    // type-3s in the no-summary (totally stubby)
                    // form, no type-4s (ASBR locations are
                    // meaningless without type-5s), no type-5s at all.
                    let key = LsaKey {
                        ls_type: LsaType::SUMMARY_NETWORK,
                        link_state_id: crate::lsa::LinkStateId(0),
                        adv_router: self.router_id,
                    };
                    desired.insert((*area_a, key), target.default_cost);
                    continue;
                }
                AreaKind::Nssa {
                    no_summary: true, ..
                } => {
                    // RFC 3101 §2.7: when summaries are not imported
                    // (FRR's totally-NSSA) the border's default goes
                    // out as a TYPE-3 — "This protects the NSSA from
                    // routing intra-AS traffic out the AS via the
                    // default route of a Type-7 default LSA".
                    let key = LsaKey {
                        ls_type: LsaType::SUMMARY_NETWORK,
                        link_state_id: crate::lsa::LinkStateId(0),
                        adv_router: self.router_id,
                    };
                    desired.insert((*area_a, key), target.default_cost);
                    continue;
                }
                AreaKind::Nssa { .. } => {
                    // RFC 3101 §2.4: "NSSA border routers must
                    // originate an LSA for the default destination
                    // into all their directly attached NSSAs"; with
                    // summaries imported (§2.7) the form must be a
                    // type-7 — P clear ("A Type-7 default LSA
                    // originated by an NSSA border router must have
                    // the P-bit clear"), metric = default-cost.
                    let key = LsaKey {
                        ls_type: LsaType::NSSA,
                        link_state_id: crate::lsa::LinkStateId(0),
                        adv_router: self.router_id,
                    };
                    desired.insert((*area_a, key), target.default_cost);
                    // No type-4s into an NSSA (§12.4.3's ASBR
                    // destinations are meaningless where type-5s
                    // cannot go; type-7s resolve their ASBRs inside
                    // the NSSA itself, §2.5 step 3).
                    skip_type4 = true;
                }
                AreaKind::Normal => {}
            }
            // ---- §12.4.3's address ranges: one summary per ACTIVE
            // range (its metric the minimum of the contributing
            // routes' costs, or the configured `cost` override), the
            // member networks' own summaries suppressed (a
            // DoNotAdvertise range suppresses them outright).
            // Ranges are configured on the range-OWNING area and
            // aggregate ITS intra-area routes advertised out.
            for area_s in &area_ids {
                if area_s == area_a {
                    continue; // never back into the range's own area
                }
                let Some(src) = self.areas.get(area_s) else {
                    continue;
                };
                for range in &src.ranges {
                    // "Active": at least one contributing intra-area
                    // route of the range's area (§12.4.3).
                    let members: Vec<u32> = ribs
                        .values()
                        .filter(|p| {
                            p.area == *area_s
                                && !p.inter_area
                                && range.prefix.prefix_len() <= p.prefix.prefix_len()
                                && range.prefix.contains(p.prefix.addr())
                        })
                        .map(|p| p.cost)
                        .collect();
                    if members.is_empty() {
                        continue; // inactive: no range summary, members individual
                    }
                    if !range.advertise {
                        continue; // DoNotAdvertise: members suppressed below
                    }
                    // The split-horizon gate on the contributing set:
                    // a range whose members' paths all leave through
                    // Area A itself is not advertised into A.
                    let via_target = ribs.values().any(|p| {
                        p.area == *area_s
                            && !p.inter_area
                            && range.prefix.prefix_len() <= p.prefix.prefix_len()
                            && range.prefix.contains(p.prefix.addr())
                            && self.hops_in_area(&p.hops) == Some(*area_a)
                    });
                    if via_target {
                        continue;
                    }
                    let metric = range
                        .cost
                        .unwrap_or_else(|| members.iter().copied().min().unwrap_or(0));
                    if metric >= crate::LS_INFINITY {
                        continue;
                    }
                    let key = LsaKey {
                        ls_type: LsaType::SUMMARY_NETWORK,
                        link_state_id: crate::lsa::LinkStateId(
                            u32::from(range.prefix.addr()) & Self::prefix_as_mask(&range.prefix),
                        ),
                        adv_router: self.router_id,
                    };
                    desired.insert((*area_a, key), metric);
                }
            }
            for path in ribs.values() {
                // §12.4.3's gating, in the RFC's order:
                // - Destination Type network (yes — ribs holds
                //   networks; externals never reach here).
                // - "the area associated with this set of paths is
                //   the Area A itself": skip.
                if path.area == *area_a {
                    continue;
                }
                // - The range-owning area's ACTIVE ranges claim their
                //   members (§12.4.3: "Instead ... a single
                //   summary-LSA is advertised for each range").
                if let Some(src) = self.areas.get(&path.area) {
                    if !path.inter_area
                        && src.ranges.iter().any(|r| {
                            r.prefix.prefix_len() <= path.prefix.prefix_len()
                                && r.prefix.contains(path.prefix.addr())
                                && ribs.values().any(|m| {
                                    m.area == path.area
                                        && !m.inter_area
                                        && r.prefix.prefix_len() <= m.prefix.prefix_len()
                                        && r.prefix.contains(m.prefix.addr())
                                })
                        })
                    {
                        continue;
                    }
                }
                // - "the next hops ... belong to Area A itself"
                //   (split horizon): skip.
                if self.hops_in_area(&path.hops) == Some(*area_a) {
                    continue;
                }
                // - "routing table cost equals or exceeds
                //   LSInfinity": skip.
                if path.cost >= crate::LS_INFINITY {
                    continue;
                }
                // - Inter-area routes: advertised into the OTHER
                //   areas only ("only intra-area routes are
                //   advertised into the backbone").
                if path.inter_area && *area_a == 0 {
                    continue;
                }
                let key = LsaKey {
                    ls_type: LsaType::SUMMARY_NETWORK,
                    link_state_id: crate::lsa::LinkStateId(u32::from(path.prefix.addr())),
                    adv_router: self.router_id,
                };
                desired.insert((*area_a, key), path.cost);
            }
            // Type-4: the ASBR-summary (ASBR destinations only —
            // ABR destinations are skipped per §12.4.3's first
            // bullet); not into stub/NSSA areas (handled above by
            // `continue`/`skip_type4`).
            if skip_type4 {
                continue;
            }
            for (rid, paths) in routers {
                // The same §16.4.1 preference FRR's ospf_abr task
                // applies to its type-4 picks (disclosed: RFC 2328
                // itself specifies the preference for §16.4; the
                // type-4 site inherits it for consistency).
                let Some(preferred) = preferred_asbr_path(paths, self.rfc1583) else {
                    continue;
                };
                // §12.4.3's first bullet: ABR destinations are
                // skipped — only AS boundary routers get type-4s.
                if !preferred.e_bit || preferred.b_bit {
                    continue;
                }
                if preferred.area == *area_a {
                    continue;
                }
                if self.hops_in_area(&preferred.hops) == Some(*area_a) {
                    continue;
                }
                if preferred.cost >= crate::LS_INFINITY {
                    continue;
                }
                let key = LsaKey {
                    ls_type: LsaType::SUMMARY_ASBR,
                    link_state_id: crate::lsa::LinkStateId(rid.0),
                    adv_router: self.router_id,
                };
                desired.insert((*area_a, key), preferred.cost);
            }
        }
        // Originate the new/changed; flush the stale.
        let current: Vec<((u32, LsaKey), u32)> = self
            .summaries
            .iter()
            .map(|(k, ())| {
                let metric = self
                    .areas
                    .get(&k.0)
                    .and_then(|a| a.lsdb.get(&k.1))
                    .and_then(|e| match &e.lsa.body {
                        crate::lsa::LsaBody::Summary(sm) => Some(sm.metric),
                        // The type-7 NSSA default's body is the
                        // external shape (RFC 3101 Appendix C).
                        crate::lsa::LsaBody::AsExternal(ext) => Some(ext.metric),
                        _ => None,
                    })
                    .unwrap_or(0);
                (*k, metric)
            })
            .collect();
        for ((area, key), metric) in current {
            match desired.get(&(area, key)) {
                Some(&want) if want == metric => {} // unchanged
                Some(_) => {
                    // cost changed: re-originate below (flush first
                    // through the premature-age + new instance).
                    self.summaries.remove(&(area, key));
                }
                None => {
                    self.summaries.remove(&(area, key));
                }
            }
        }
        for ((area, key), metric) in &desired {
            if self.summaries.contains_key(&(*area, *key)) {
                continue;
            }
            // Type 3: the network's mask comes from the RIB path
            // (the prefix's own length); type 4 carries mask 0
            // (§A.4.4) and names the ASBR by its Router ID.
            if key.ls_type == LsaType::NSSA {
                // The type-7 NSSA default (RFC 3101 §2.4/§2.7):
                // P clear ("A Type-7 default LSA originated by an
                // NSSA border router must have the P-bit clear"),
                // FA 0.0.0.0 (legal with P clear), metric =
                // default-cost. DISCLOSED divergence, probed live:
                // FRR 10.2.2 (BOTH P forms tested) does not install
                // a foreign border type-7 default into its OSPF
                // route table; the LSA itself is accepted and stored
                // (database-proven on the wire). Suspected gate:
                // FRR's translator election (the Nt bit we do not
                // yet originate).
                let lsa = crate::origination::build_nssa_lsa(
                    self.router_id,
                    Ipv4Addr::UNSPECIFIED,
                    Ipv4Addr::UNSPECIFIED,
                    *metric,
                    true,
                    Ipv4Addr::UNSPECIFIED,
                    false,
                );
                let Some(state) = self.areas.get_mut(area) else {
                    continue;
                };
                if state.lsdb.originate(lsa, now).is_ok() {
                    self.summaries.insert((*area, *key), ());
                    if let Some(entry) = state.lsdb.get(key) {
                        let stored = entry.lsa.clone();
                        info!(area, "ospfd: type-7 default originated (RFC 3101 §2.7)");
                        self.flood_own(&stored, Some(*area), now, out);
                        self.mark_table_dirty();
                    }
                }
                continue;
            }
            let type4 = key.ls_type == LsaType::SUMMARY_ASBR;
            let mask = if type4 || key.link_state_id.0 == 0 {
                // Type-4 names the ASBR by Router ID (mask 0); the
                // default summary (LS ID 0.0.0.0) carries mask
                // 0.0.0.0 (§12.4.3.1/§A.4.4).
                Ipv4Addr::UNSPECIFIED
            } else {
                // §12.4.3's range summaries FIRST: the LS ID is the
                // range network — a member network sharing the range's
                // address would otherwise shadow the range's mask.
                let range_mask = self.areas.values().find_map(|a| {
                    a.ranges
                        .iter()
                        .find(|r| {
                            u32::from(r.prefix.addr()) & Self::prefix_as_mask(&r.prefix)
                                == key.link_state_id.0
                        })
                        .map(|r| Ipv4Addr::from(u32::MAX << (32 - r.prefix.prefix_len())))
                });
                match range_mask {
                    Some(mask) => mask,
                    None => match ribs
                        .values()
                        .find(|r| u32::from(r.prefix.addr()) == key.link_state_id.0)
                        .map(|r| r.prefix)
                    {
                        Some(prefix) => Ipv4Addr::from(u32::MAX << (32 - prefix.prefix_len())),
                        None => continue,
                    },
                }
            };
            let lsa = crate::origination::build_summary_lsa(
                self.router_id,
                type4,
                Ipv4Addr::from(key.link_state_id.0),
                mask,
                *metric,
            );
            let Some(state) = self.areas.get_mut(area) else {
                continue;
            };
            match state.lsdb.originate(lsa, now) {
                Ok(_) => {
                    self.summaries.insert((*area, *key), ());
                    let stored = state.lsdb.get(key).map(|e| e.lsa.clone());
                    let _ = state;
                    if let Some(stored) = stored {
                        info!(area, key = ?key, "ospfd: summary-LSA originated (§12.4.3)");
                        self.flood_own(&stored, Some(*area), now, out);
                        self.mark_table_dirty();
                    }
                }
                Err(e) => {
                    debug!(error = %e, "ospfd: summary origination deferred");
                }
            }
        }
        // Flush the withdrawn summaries.
        let stale: Vec<(u32, LsaKey)> = self
            .summaries
            .keys()
            .filter(|k| !desired.contains_key(k))
            .copied()
            .collect();
        self.flush_summaries(&stale, now, out);
    }

    /// The most specific configured range containing `prefix`, if
    /// any (RFC 3101 §3.2's best-match: "there does not exist a more
    /// specific Type-7 address range that contains the LSA's
    /// network"; the same list serves §12.4.3's type-3 ranges).
    fn covering_range<'a>(
        ranges: &'a [crate::config::AreaRange],
        prefix: &Ipv4Prefix,
    ) -> Option<&'a crate::config::AreaRange> {
        ranges
            .iter()
            .filter(|r| {
                r.prefix.prefix_len() <= prefix.prefix_len() && r.prefix.contains(prefix.addr())
            })
            .max_by_key(|r| r.prefix.prefix_len())
    }

    /// A prefix's dotted-quad mask as a raw u32.
    fn prefix_as_mask(prefix: &Ipv4Prefix) -> u32 {
        if prefix.prefix_len() == 0 {
            0
        } else {
            u32::MAX << (32 - prefix.prefix_len())
        }
    }

    /// §3.2's Link State ID remapping: "in the case of multiple
    /// originations of Type-5 LSAs with the same network address but
    /// different mask, the link-state ID can also have one or more
    /// of the network's 'host' bits set" — when the natural ID (the
    /// network address) is already taken by one of OUR type-5s
    /// describing a different network, walk the host bits until a
    /// free ID is found.
    fn allocate_translated_lsid(&self, prefix: &Ipv4Prefix) -> u32 {
        let master = self
            .areas
            .iter()
            .find(|(_, a)| a.kind.external_capable())
            .map(|(id, _)| *id);
        let taken: std::collections::BTreeSet<u32> = self
            .areas
            .get(&master.unwrap_or(0))
            .map(|a| {
                a.lsdb
                    .all()
                    .filter(|e| {
                        e.lsa.header.ls_type == LsaType::AS_EXTERNAL
                            && e.lsa.header.adv_router == self.router_id
                            && !e.lsa.header.is_max_age()
                    })
                    .map(|e| e.lsa.header.link_state_id.0)
                    .collect()
            })
            .unwrap_or_default();
        let mask = Self::prefix_as_mask(prefix);
        let net = u32::from(prefix.addr()) & mask;
        // Walk the host bits (§3.2: "one or more of the network's
        // 'host' bits"), bounded at 2^24 to stay finite on tiny
        // prefixes.
        let host_bits = 32u32.saturating_sub(u32::from(prefix.prefix_len()));
        let steps: u32 = if host_bits >= 24 {
            1 << 24
        } else {
            1 << host_bits
        };
        for i in 0..steps {
            let candidate = net + i;
            if !taken.contains(&candidate) {
                return candidate;
            }
        }
        net
    }

    /// RFC 3101 §3.2: translate the NSSA's translatable type-7 LSAs
    /// into type-5 LSAs and flood them into the normal areas — the
    /// full §3.2 walk: step (1)'s gates (P-bit, FA 0.0.0.0, the
    /// best-matching range's DoNotAdvertise), step (2)'s plain
    /// translation (with the highest-Router-ID equivalence rule),
    /// step (3)'s Type-7 address-range aggregation (path type 2 if
    /// any member is type 2, metric = highest type-1 cost / highest
    /// type-2 cost + 1, FA 0.0.0.0, one type-5 per range), and the
    /// LS-ID host-bit remapping on collisions. Gated on the §3.1
    /// translator state (an elected Candidate, an enabled Always, or
    /// a deposed translator inside its stability interval).
    /// The type-7 *default* still never translates (the P-clear
    /// border default is not translatable by step (1); an internal
    /// ASBR's P-set default rides Appendix E — §Deferred).
    fn translate_nssa(&mut self, now: u64, out: &mut Vec<WireOut>) {
        // The desired set: (nssa area, advertised prefix string) ->
        // the type-5 shape (metric, e_bit, FA, aggregated?).
        let mut desired: BTreeMap<(u32, String), (u32, bool, Ipv4Addr, bool)> = BTreeMap::new();
        let nssa_areas: Vec<u32> = self
            .areas
            .iter()
            .filter(|(_, a)| a.kind.nssa())
            .map(|(id, _)| *id)
            .collect();
        for nssa in &nssa_areas {
            // The §3.1 gate: only a border router with the translator
            // state active translates (a deposed translator keeps
            // going through its stability interval).
            if !self.nssa_border() {
                continue;
            }
            let Some(state) = self.areas.get(nssa) else {
                continue;
            };
            if !state.translator_active(now) {
                continue; // desired stays empty: the flush below retires ours
            }
            let ranges = state.ranges.clone();
            // The translatable set (§3.2 step (1) gates), grouped by
            // their best-matching ADVERTISING range.
            // range-prefix-string -> members (metric, type-2?).
            let mut by_range: BTreeMap<String, Vec<(u32, bool)>> = BTreeMap::new();
            for entry in state.lsdb.all() {
                let lsa = &entry.lsa;
                if lsa.header.ls_type != LsaType::NSSA || lsa.header.is_max_age() {
                    continue;
                }
                // §3.2 step (1): "If the Type-7 LSA has the P-bit
                // clear, or its forwarding address is set to
                // 0.0.0.0 ... then do nothing with this Type-7 LSA".
                if !lsa.header.options.np_bit() {
                    continue;
                }
                let crate::lsa::LsaBody::AsExternal(ext) = &lsa.body else {
                    continue;
                };
                if ext.forwarding_address == Ipv4Addr::UNSPECIFIED {
                    continue;
                }
                let prefix = Ipv4Prefix::new(
                    lsa.header.link_state_id.to_ipv4(),
                    u32::from(ext.mask).count_ones() as u8,
                )
                .expect("type-7 mask");
                if prefix.prefix_len() == 0 {
                    continue; // the default never translates
                }
                if ext.metric >= crate::LS_INFINITY {
                    continue;
                }
                // Step (1)'s third gate: "the most specific Type-7
                // address range that subsumes the LSA's network has
                // DoNotAdvertise status".
                if let Some(range) = Self::covering_range(&ranges, &prefix) {
                    if !range.advertise {
                        continue;
                    }
                }
                // Steps (2)/(3) split: aggregated when an advertising
                // range strictly contains the network, plain when no
                // range matches or the range IS the network.
                match Self::covering_range(&ranges, &prefix) {
                    Some(range) if range.prefix.prefix_len() < prefix.prefix_len() => {
                        by_range
                            .entry(range.prefix.to_string())
                            .or_default()
                            .push((ext.metric, ext.e_bit));
                        // The member's own plain translation is
                        // suppressed ("at most a single Type-5 LSA is
                        // originated for each Type-7 address range").
                        continue;
                    }
                    _ => {
                        desired.insert(
                            (*nssa, prefix.to_string()),
                            (ext.metric, ext.e_bit, ext.forwarding_address, false),
                        );
                    }
                }
            }
            // Step (3): the aggregated type-5 per range.
            for (range_str, members) in by_range {
                let range: Ipv4Prefix = range_str.parse().expect("range prefix");
                // "plus any locally sourced Type-5 LSAs whose network
                // has the same [address,mask] pair" join the metric
                // computation.
                let mut members = members;
                if let Some(master) = self
                    .areas
                    .iter()
                    .find(|(_, a)| a.kind.external_capable())
                    .map(|(id, _)| *id)
                {
                    if let Some(a) = self.areas.get(&master) {
                        for e in a.lsdb.all() {
                            if e.lsa.header.ls_type == LsaType::AS_EXTERNAL
                                && e.lsa.header.adv_router == self.router_id
                                && !e.lsa.header.is_max_age()
                            {
                                if let crate::lsa::LsaBody::AsExternal(ext) = &e.lsa.body {
                                    let p = Ipv4Prefix::new(
                                        e.lsa.header.link_state_id.to_ipv4(),
                                        u32::from(ext.mask).count_ones() as u8,
                                    );
                                    if p.is_ok_and(|p| p == range) {
                                        members.push((ext.metric, ext.e_bit));
                                    }
                                }
                            }
                        }
                    }
                }
                // "If any of these LSAs have a path type of 2, the
                // range's path type is 2, otherwise it is 1. If the
                // range's path type is 1 its metric is the highest
                // cost amongst these LSAs; if the range's path type is
                // 2 its metric is the highest Type-2 cost + 1 ... to
                // ensure that the translated Type-5 LSA does not
                // appear closer on the NSSA border than a translatable
                // Type-7 LSA whose network has the same [address,mask]
                // pair and Type-2 cost."
                let type2 = members.iter().any(|(_, e)| *e);
                let metric = if type2 {
                    members
                        .iter()
                        .filter(|(_, e)| *e)
                        .map(|(m, _)| *m)
                        .max()
                        .unwrap_or(0)
                        .saturating_add(1)
                } else {
                    members.iter().map(|(m, _)| *m).max().unwrap_or(0)
                };
                // "The forwarding address is set to 0.0.0.0."
                desired.insert(
                    (*nssa, range.to_string()),
                    (metric, type2, Ipv4Addr::UNSPECIFIED, true),
                );
            }
        }
        // Originate the missing/changed: "The newly originated
        // Type-5 LSA will describe the same network and have the
        // same network mask, path type, metric, forwarding address
        // and external route tag as the Type-7 LSA. The advertising
        // router field will be the router ID of this NSSA border
        // router" (§3.2 step (2)).
        let master = self
            .areas
            .iter()
            .find(|(_, a)| a.kind.external_capable())
            .map(|(id, _)| *id);
        for ((nssa, prefix_str), (metric, e_bit, fa, aggregated)) in &desired {
            let prefix: Ipv4Prefix = prefix_str.parse().expect("prefix round-trip");
            // §3.2 step (2)'s equivalence rule: "the calculating
            // router has the highest router ID amongst NSSA
            // translators that have originated a functionally
            // equivalent Type-5 LSA (i.e. same destination, cost and
            // non-zero forwarding address)" — a higher-ID foreign
            // translator's equivalent type-5 wins; stand down.
            if !*aggregated && *fa != Ipv4Addr::UNSPECIFIED {
                let equivalent_from_higher = self
                    .areas
                    .get(&master.unwrap_or(0))
                    .map(|a| {
                        a.lsdb.all().any(|e| {
                            e.lsa.header.ls_type == LsaType::AS_EXTERNAL
                                && !e.lsa.header.is_max_age()
                                && e.lsa.header.adv_router != self.router_id
                                && e.lsa.header.adv_router.larger_than(self.router_id)
                                && matches!(&e.lsa.body, crate::lsa::LsaBody::AsExternal(ext)
                                    if ext.metric == *metric
                                        && ext.e_bit == *e_bit
                                        && ext.forwarding_address == *fa
                                        && Ipv4Prefix::new(
                                            e.lsa.header.link_state_id.to_ipv4(),
                                            u32::from(ext.mask).count_ones() as u8
                                        ).map(|p| p == prefix).unwrap_or(false))
                        })
                    })
                    .unwrap_or(false);
                if equivalent_from_higher {
                    continue;
                }
            }
            let current_ok = self
                .translations
                .get(&(*nssa, prefix_str.clone()))
                .and_then(|key| {
                    self.areas
                        .get(&master.unwrap_or(0))
                        .and_then(|a| a.lsdb.get(key))
                        .and_then(|e| match &e.lsa.body {
                            crate::lsa::LsaBody::AsExternal(ext) => {
                                Some((ext.metric, ext.e_bit, ext.forwarding_address))
                            }
                            _ => None,
                        })
                })
                .is_some_and(|(m, e, f)| m == *metric && e == *e_bit && f == *fa);
            if current_ok {
                continue;
            }
            let Some(master) = master else {
                continue; // no type-5-capable area: nothing to translate into
            };
            // §3.2's LS-ID remapping on collisions.
            let lsid = self.allocate_translated_lsid(&prefix);
            let mut lsa = crate::origination::build_external_lsa(
                self.router_id,
                Ipv4Addr::from(lsid & Self::prefix_as_mask(&prefix)),
                Ipv4Addr::from(u32::MAX << (32 - prefix.prefix_len())),
                *metric,
                *e_bit,
            );
            // The allocated ID must survive into the header (the
            // builder derives it from the address; the remap may have
            // walked host bits).
            lsa.header.link_state_id = crate::lsa::LinkStateId(lsid);
            if let crate::lsa::LsaBody::AsExternal(ext) = &mut lsa.body {
                ext.forwarding_address = *fa;
            }
            let key = lsa.key();
            let originated = self
                .areas
                .get_mut(&master)
                .is_some_and(|state| state.lsdb.originate(lsa, now).is_ok());
            if originated {
                // Old translation under a changed shape: flush first.
                if let Some(old) = self.translations.insert((*nssa, prefix_str.clone()), key) {
                    let areas: Vec<u32> = self.areas.keys().copied().collect();
                    for area in areas {
                        if let Some(st) = self.areas.get_mut(&area) {
                            let _ = st.lsdb.premature_age(&old);
                        }
                    }
                }
                let stored = self
                    .areas
                    .get(&master)
                    .and_then(|a| a.lsdb.get(&key))
                    .map(|e| e.lsa.clone());
                if let Some(stored) = &stored {
                    for other in self
                        .areas
                        .iter()
                        .filter(|(id, a)| **id != master && a.kind.external_capable())
                        .map(|(id, _)| *id)
                        .collect::<Vec<_>>()
                    {
                        if let Some(st) = self.areas.get_mut(&other) {
                            st.lsdb.mirror_originated(stored, now);
                        }
                    }
                    self.flood_own(stored, None, now, out);
                }
                info!(
                    nssa,
                    prefix = prefix_str,
                    "ospfd: type-7 translated to type-5 (RFC 3101 §3.2)"
                );
                self.mark_table_dirty();
            }
        }
        // Flush the translations no longer justified.
        let stale: Vec<(u32, String)> = self
            .translations
            .keys()
            .filter(|k| !desired.contains_key(k))
            .cloned()
            .collect();
        let stale = stale
            .into_iter()
            .filter_map(|k| self.translations.get(&k).map(|key| (k, *key)))
            .collect::<Vec<_>>();
        self.flush_translations(&stale, now, out);
    }

    /// Flush translated type-5s: premature-age everywhere (§14.1)
    /// and reflood.
    fn flush_translations(
        &mut self,
        stale: &[((u32, String), LsaKey)],
        now: u64,
        out: &mut Vec<WireOut>,
    ) {
        for (tag, key) in stale {
            self.translations.remove(tag);
            let areas: Vec<u32> = self.areas.keys().copied().collect();
            let mut aged = false;
            for area in areas {
                if let Some(state) = self.areas.get_mut(&area) {
                    if let Some(lsa) = state.lsdb.premature_age(key) {
                        if !aged {
                            self.flood_own(&lsa, None, now, out);
                            aged = true;
                        }
                    }
                }
            }
            info!(
                prefix = &tag.1,
                "ospfd: translated type-5 flushed (RFC 3101 §3.2)"
            );
        }
    }

    /// §12.4.3's withdrawal: "If a router advertises a summary-LSA
    /// for a destination which then becomes unreachable ... the LSA
    /// should also be flushed" — premature age (§14.1) + reflood.
    fn flush_summaries(&mut self, stale: &[(u32, LsaKey)], now: u64, out: &mut Vec<WireOut>) {
        for (area, key) in stale {
            self.summaries.remove(&(*area, *key));
            let aged = self
                .areas
                .get_mut(area)
                .and_then(|a| a.lsdb.premature_age(key));
            if let Some(maxage) = aged {
                info!(area, key = ?key, "ospfd: summary-LSA flushed (§12.4.3)");
                self.flood_own(&maxage, Some(*area), now, out);
                self.mark_table_dirty();
            }
        }
    }

    /// The area an interface address belongs to (the next hops'
    /// associated area, §12.4.3's split-horizon input).
    fn hops_in_area(&self, hops: &[spf::NextHop]) -> Option<u32> {
        let first = hops.first()?;
        self.interfaces
            .iter()
            .find(|i| i.addr == first.interface)
            .map(|i| i.area)
    }

    /// The 1-second tick: hellos, the WaitTimer, neighbor timers,
    /// aging, deferred originations, SPF.
    pub fn tick(&mut self, now: u64, out: &mut Vec<WireOut>, zapi_out: &mut Vec<ZedgeCommand>) {
        // §C.3 Hellos.
        let router_id = self.router_id;
        for (idx, iface) in self.interfaces.iter_mut().enumerate() {
            // The send-view refresh: a chain-configured interface
            // advances to its current most-recent-live-start key
            // (RFC 8177 rollover, one-tick granularity, disclosed).
            iface.live_auth = iface.cfg.auth.live_send_view(now);
            // §15: a virtual link sends nothing until its other
            // endpoint's address is discovered by the routing table.
            if iface.virtual_link && iface.vlink_peer_ip.is_none() {
                continue;
            }
            // §9.3/§C.3: an interface in Down sends no Hellos ("the
            // interface is unusable... no protocol traffic"). Only the
            // merged live link state leaves an interface Down at
            // construction today (the ifdump down/loopback case);
            // static-config interfaces fire InterfaceUp as before.
            if iface.fsm.state == crate::iface::InterfaceState::Down {
                continue;
            }
            if now >= iface.hello_deadline {
                iface.hello_deadline = now + iface.cfg.hello_interval as u64;
                let kind = self
                    .areas
                    .get(&iface.area)
                    .map(|a| a.kind)
                    .unwrap_or(AreaKind::Normal);
                let auth = iface.live_auth.clone();
                let seq = next_crypto_seq(&iface.auth_tx_seq, &auth);
                let mut packet = make_hello(router_id, iface.area, iface, kind);
                packet.header.au_type = auth.au_type();
                packet.header.authentication = auth.auth_field(seq);
                // §15: virtual-link packets are unicast to the other
                // endpoint's (resolved) address.
                let to = match iface.vlink_peer_ip {
                    Some(peer) => WireTo::Unicast(peer),
                    None => WireTo::Multicast,
                };
                out.push(WireOut {
                    iface: idx,
                    to,
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
            for (idx, key) in &down_events {
                info!(neighbor = %key, "ospfd: neighbor timed out (Inactivity Timer)");
                let area = self.interfaces[*idx].area;
                if let Some(a) = self.areas.get_mut(&area) {
                    a.router_lsa_dirty = true;
                }
                // §9.2's second NeighborChange cause: a neighbor left
                // the bidirectional set — re-elect on broadcast, and
                // the network-LSA's attached list lost a router.
                if !self.interfaces[*idx].p2p {
                    self.run_election(*idx, now, out);
                    self.network_lsa_dirty.push(*idx);
                }
            }
        }
        // §14 aging, per area. MaxAge instances reflood with the
        // area's own packet header on each interface. The syncing
        // fact is evaluated once per tick (no adjacency state changes
        // inside this pass).
        let syncing = self.any_syncing();
        let area_ids: Vec<u32> = self.areas.keys().copied().collect();
        // §14 MaxAge refloods and §12.4 refresh floods, collected
        // under the per-area borrow and put on the wire after it.
        let mut pending_maxage_floods: Vec<(u32, Vec<Lsa>)> = Vec::new();
        for area in area_ids {
            let Some(state) = self.areas.get_mut(&area) else {
                continue;
            };
            let report = state.lsdb.tick_aging(now);
            // §12.4 refresh of every self-originated LSA. Collected
            // first (flood_own cannot run under the area borrow):
            // the router-LSA + network-LSA paths mark dirty as
            // before; every other self-originated LSA (summaries,
            // type-5s, type-7s, translated copies) re-originates its
            // stored body at the next sequence — the N2 daemon only
            // refreshed router/network LSAs, silently aging the rest
            // out at MaxAge.
            let mut refresh_floods: Vec<(Lsa, Option<u32>)> = Vec::new();
            for key in report.refresh_due {
                match key.ls_type {
                    LsaType::ROUTER => state.router_lsa_dirty = true,
                    LsaType::NETWORK => {
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
                    _ => {
                        if let Some(entry) = state.lsdb.get(&key) {
                            let mut lsa = entry.lsa.clone();
                            lsa.header.ls_age = 0;
                            if state.lsdb.originate(lsa, now).is_ok() {
                                let stored = state.lsdb.get(&key).map(|e| e.lsa.clone());
                                if let Some(stored) = stored {
                                    let scope = if key.ls_type == LsaType::AS_EXTERNAL {
                                        None // AS-scoped
                                    } else {
                                        Some(area) // area-scoped
                                    };
                                    refresh_floods.push((stored, scope));
                                }
                            }
                        }
                    }
                }
            }
            // (flood_own needs &mut self — deferred past the area
            // borrow below.)
            let mut pending_refresh_floods = refresh_floods;
            if !report.max_age.is_empty() {
                // §14: reflood the MaxAge instances (the flush);
                // removal follows flush_ready below once acked.
                let lsas: Vec<Lsa> = report
                    .max_age
                    .iter()
                    .filter_map(|k| state.lsdb.get(k).map(|e| e.lsa.clone()))
                    .collect();
                pending_maxage_floods.push((area, lsas));
            }
            let flushable = state.lsdb.flush_ready(syncing);
            let mut spt_changed = false;
            let mut table_changed = false;
            for key in flushable {
                if state.lsdb.remove(&key).is_some() {
                    debug!(key = ?key, "ospfd: LSA flushed (MaxAge)");
                    if matches!(key.ls_type, LsaType::ROUTER | LsaType::NETWORK) {
                        spt_changed = true;
                    } else {
                        table_changed = true;
                    }
                    // A withdrawn summary changes the inter-area
                    // table.
                    self.summaries.remove(&(area, key));
                }
            }
            if spt_changed {
                self.mark_spf_dirty(area, now);
            }
            if table_changed {
                self.mark_table_dirty();
            }
            // §12.4 refresh floods, now past the area borrow.
            for (lsa, scope) in pending_refresh_floods.drain(..) {
                self.flood_own(&lsa, scope, now, out);
            }
        }
        // §14 MaxAge refloods on the wire (auth-stamped per
        // interface).
        for (area, lsas) in pending_maxage_floods.drain(..) {
            if lsas.is_empty() {
                continue;
            }
            for idx in 0..self.interfaces.len() {
                if self.interfaces[idx].area != area {
                    continue;
                }
                let packet = self.packet_for(
                    idx,
                    area,
                    PacketBody::LsUpdate(LsUpdate { lsas: lsas.clone() }),
                );
                out.push(WireOut {
                    iface: idx,
                    to: WireTo::Multicast,
                    packet,
                });
            }
        }
        // Deferred originations (MinLSInterval retries): every
        // area's router-LSA, the pending network-LSAs.
        let dirty_areas: Vec<u32> = self
            .areas
            .iter()
            .filter(|(_, a)| a.router_lsa_dirty)
            .map(|(id, _)| *id)
            .collect();
        for area in dirty_areas {
            self.originate_router_lsa(area, now, out);
        }
        let dirty_networks: Vec<usize> = std::mem::take(&mut self.network_lsa_dirty);
        for idx in dirty_networks {
            self.originate_network_lsa(idx, now, out);
        }
        // RFC 3101 §3.1's TranslatorStabilityInterval deadline: a
        // deposed translator's keep-translating window lapsing must
        // force a walk (the retirement flush runs in the walk).
        if self
            .areas
            .values()
            .any(|a| a.stability_until.is_some_and(|d| now >= d))
        {
            self.mark_table_dirty();
        }
        // SPF when due.
        self.maybe_spf(now, out, zapi_out);
    }

    /// A redistributed static route from zebra (§12.4.4).
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

fn make_hello(router_id: RouterId, area_id: u32, iface: &Interface, kind: AreaKind) -> Packet {
    let body = PacketBody::Hello(Hello {
        // §C.3: the mask of the attached network; 0.0.0.0 is the
        // convention on p2p (ignored by receivers anyway).
        network_mask: if iface.p2p {
            Ipv4Addr::UNSPECIFIED
        } else {
            iface.mask
        },
        hello_interval: iface.cfg.hello_interval,
        // §10.5/§3.6: the E-bit agrees with the area's
        // ExternalRoutingCapability — clear in stub areas.
        options: area_options(kind),
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
        // Appendix D: crypto mode appends the digest trailer at the
        // wire boundary (RFC 2328 D.3 / RFC 5709 §3.3).
        let bytes =
            crate::auth::encode_for_wire(&wire.packet, &core.interfaces[wire.iface].live_auth);
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

    /// Single-area convenience: the (first) area's LSDB.
    fn lsdb_of(core: &Ospfd) -> &Lsdb {
        &core.areas.values().next().unwrap().lsdb
    }

    fn mark_router_lsa_dirty(core: &mut Ospfd) {
        for a in core.areas.values_mut() {
            a.router_lsa_dirty = true;
        }
    }

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
            // The live send view — the flush_wire mirror (a
            // chain-configured interface stamps the key its chain
            // selects at the last refresh, not the raw chain config).
            let payload = crate::auth::encode_for_wire(&packet, &from.interfaces[0].live_auth);
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

                    ttl: 1,
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
            assert!(lsdb_of(me).contains(&key), "{other}'s router-LSA installed");
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
        mark_router_lsa_dirty(&mut a);
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
        let pre_restart = lsdb_of(&b).get(&key).unwrap().lsa.clone();
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
            lsdb_of(&a2).get(&key).unwrap().lsa.header.seq,
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
            lsdb_of(&a2).next_seq_for(&key).unwrap() > seq as i32,
            "tracking advanced past the received instance"
        );
        let mut a2_seq = lsdb_of(&a2).get(&key).unwrap().lsa.header.seq;
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
            a2_seq = lsdb_of(&a2).get(&key).unwrap().lsa.header.seq;
        }
        assert_eq!(
            lsdb_of(&a2).get(&key).unwrap().lsa.header.seq,
            seq + 1,
            "the re-originated instance is one past the adopted one (§13.4)"
        );
        // B accepted it (§13.1: S+1 beats S).
        assert_eq!(lsdb_of(&b).get(&key).unwrap().lsa.header.seq, seq + 1);
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
            .packet(
                b.area_id(),
                PacketBody::LsUpdate(LsUpdate {
                    lsas: vec![foreign.clone()],
                }),
            )
            .encode();
        let out = a.on_packet(
            0,
            &crate::transport::Received {
                src: b.interfaces[0].addr,
                dst: crate::packet::ALL_SPF_ROUTERS,
                payload,

                ttl: 1,
            },
            now + 1,
        );
        // The flush reflood went out and the stored copy is MaxAge.
        assert!(
            out.iter()
                .any(|w| matches!(w.packet.body, PacketBody::LsUpdate(_))),
            "the MaxAge instance is reflooded (§14.1)"
        );
        let stored = lsdb_of(&a).get(&key).unwrap();
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
        let from_auth = cores[from].interfaces[0].cfg.auth.clone();
        // The on-link destinations: multicast reaches every core,
        // unicast only the addressed neighbor (§A.1).
        let targets: Vec<usize> = (0..cores.len())
            .filter(|i| *i != from && !dead.contains(i))
            .collect();
        for (dst, packet) in bodies(outs) {
            let payload = crate::auth::encode_for_wire(&packet, &from_auth);
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

                            ttl: 1,
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
                for state in core.areas.values() {
                    for entry in state.lsdb.all() {
                        // Ages advance every second (§14 steady
                        // state) — seq alone captures instance churn.
                        h = h.wrapping_mul(31).wrapping_add(entry.lsa.header.seq as u64);
                    }
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
            let entry = lsdb_of(core)
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
            let entry = lsdb_of(core).get(&key).unwrap();
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

    // ---- inter-area (§16.2/§16.4/§12.4.3) ----------------------------

    /// An ABR core: eth0 in area 0 (to the area-0 peer), eth1 in
    /// area 1 (to the area-1 peer), p2p both.
    fn abr_core() -> Ospfd {
        let text = concat!(
            "router ospf\n",
            " router-id 10.255.2.1\n",
            " area 0.0.0.0\n",
            "  interface eth0\n",
            "   address 10.10.0.1/30\n",
            "   network-type point-to-point\n",
            "   hello-interval 1\n",
            "   dead-interval 4\n",
            " area 0.0.0.1\n",
            "  interface eth1\n",
            "   address 10.20.0.1/30\n",
            "   network-type point-to-point\n",
            "   hello-interval 1\n",
            "   dead-interval 4\n",
            " redistribute static\n",
        );
        Ospfd::new(&parse_config(text).unwrap()).unwrap()
    }

    fn area0_core() -> Ospfd {
        let text = "router ospf\n router-id 10.255.1.1\n area 0.0.0.0\n  interface eth0\n   address 10.10.0.2/30\n   network-type point-to-point\n   hello-interval 1\n   dead-interval 4\n";
        Ospfd::new(&parse_config(text).unwrap()).unwrap()
    }

    fn area1_core(redistribute: bool) -> Ospfd {
        let text = format!(
            "router ospf\n router-id 10.255.3.1\n area 0.0.0.1\n  interface eth1\n   address 10.20.0.2/30\n   network-type point-to-point\n   hello-interval 1\n   dead-interval 4\n{}",
            if redistribute { " redistribute static\n" } else { "" }
        );
        Ospfd::new(&parse_config(&text).unwrap()).unwrap()
    }

    /// The multi-interface deliver: the source address is the SENDING
    /// interface's (WireOut.iface), the area check keeps foreign-area
    /// packets out (B and C share the wire but not an area).
    fn deliver_multi(
        cores: &mut [Ospfd],
        from: usize,
        outs: &[WireOut],
        now: u64,
        queue: &mut Vec<(usize, Vec<WireOut>)>,
    ) {
        for w in outs {
            let src = cores[from].interfaces[w.iface].addr;
            let payload =
                crate::auth::encode_for_wire(&w.packet, &cores[from].interfaces[w.iface].cfg.auth);
            let pkt_area = w.packet.header.area_id;
            let dst = match w.to {
                WireTo::Unicast(d) => Some(d),
                _ => None,
            };
            for (i, core) in cores.iter_mut().enumerate() {
                if i == from {
                    continue;
                }
                // The run loop's on-link demux, area-aware: process
                // on the receiver's interface in the packet's area
                // (a unicast must also match the addressed interface).
                let Some(rx) = core.interfaces.iter().position(|x| x.area == pkt_area) else {
                    continue;
                };
                if let Some(d) = dst {
                    if core.interfaces[rx].addr != d {
                        continue;
                    }
                }
                let replies = core.on_packet(
                    rx,
                    &crate::transport::Received {
                        src,
                        dst: crate::packet::ALL_SPF_ROUTERS,
                        payload: payload.clone(),

                        ttl: 1,
                    },
                    now,
                );
                if !replies.is_empty() {
                    queue.push((i, replies));
                }
            }
        }
    }

    /// Run a multi-interface mesh to state-stability (the run_mesh
    /// digest, generalized).
    fn run_multi(cores: &mut [Ospfd], start: u64, stable_for: u64) -> u64 {
        let mut now = start;
        let mut queue: Vec<(usize, Vec<WireOut>)> = Vec::new();
        let mut zap: Vec<crate::zedge::ZedgeCommand> = Vec::new();
        let mut outs: Vec<Vec<WireOut>> = cores.iter_mut().map(|_| Vec::new()).collect();
        for i in 0..cores.len() {
            cores[i].tick(now, &mut outs[i], &mut zap);
        }

        for (i, o) in outs.iter().enumerate() {
            deliver_multi(cores, i, o, now, &mut queue);
        }
        let digest = |cores: &[Ospfd]| -> u64 {
            let mut h: u64 = 0x9e37_79b9;
            for core in cores {
                for iface in &core.interfaces {
                    for (rid, c) in &iface.neighbors {
                        h = h.wrapping_mul(31).wrapping_add(rid.0 as u64);
                        h = h.wrapping_mul(31).wrapping_add(c.state() as u64);
                    }
                }
                for state in core.areas.values() {
                    for entry in state.lsdb.all() {
                        h = h.wrapping_mul(31).wrapping_add(entry.lsa.header.seq as u64);
                    }
                    h = h.wrapping_mul(31).wrapping_add(state.lsdb.len() as u64);
                }
                h = h.wrapping_mul(31).wrapping_add(core.routes.len() as u64);
                h = h.wrapping_mul(31).wrapping_add(core.summaries.len() as u64);
            }
            h
        };
        let mut last = digest(cores);
        let mut quiet = 0u64;
        for _ in 0..600 {
            while !queue.is_empty() {
                let batch = std::mem::take(&mut queue);
                for (from, outs) in batch {
                    deliver_multi(cores, from, &outs, now, &mut queue);
                }
            }
            let d = digest(cores);
            if d == last {
                quiet += 1;
                if quiet >= stable_for {
                    return now;
                }
            } else {
                if now > 30 && now < 42 {
                    for (i, core) in cores.iter().enumerate() {
                        for (area, state) in &core.areas {
                            for e in state.lsdb.all() {
                                eprintln!(
                                    "t={now} core {i} area {area} {:?} id={:08x} adv={:08x} seq={:08x} age={}",
                                    e.lsa.header.ls_type,
                                    e.lsa.header.link_state_id.0,
                                    e.lsa.header.adv_router.0,
                                    e.lsa.header.seq,
                                    e.lsa.header.ls_age,
                                );
                            }
                        }
                    }
                }
                quiet = 0;
                last = d;
            }
            now += 1;
            let mut outs: Vec<Vec<WireOut>> = cores.iter_mut().map(|_| Vec::new()).collect();
            for i in 0..cores.len() {
                cores[i].tick(now, &mut outs[i], &mut zap);
            }
            for (i, o) in outs.iter().enumerate() {
                deliver_multi(cores, i, o, now, &mut queue);
            }
        }
        panic!("inter-area mesh never settled");
    }

    /// §16.2 step (6): intra-area paths are always preferred over
    /// the summary-LSA form — a type-3 for a destination the area
    /// already routes internally changes nothing.
    #[test]
    fn intra_area_beats_the_summary_lsa() {
        let mut a = core_for("10.255.1.1", "eth0", "10.77.0.1");
        let mut b = core_for("10.255.2.1", "eth0", "10.77.0.2");
        let now = run_to_full(&mut a, &mut b, 0);
        // Inject a foreign type-3 into A's area-0 database for the
        // SAME prefix B's stub already provides (10.77.0.0/30, intra
        // cost 10), advertised by B at a LOWER metric (3): the
        // intra-area path must still win (§16.2 step 6).
        let forged = crate::origination::build_summary_lsa(
            b.router_id,
            false,
            ip("10.77.0.0"),
            ip("255.255.255.252"),
            3,
        )
        .with_computed_header();
        let mut out = Vec::new();
        let mut zap = Vec::new();
        // Install via the flooding path (as if received).
        let payload = b
            .packet(
                b.area_id(),
                PacketBody::LsUpdate(LsUpdate { lsas: vec![forged] }),
            )
            .encode();
        a.on_packet(
            0,
            &crate::transport::Received {
                src: b.interfaces[0].addr,
                dst: crate::packet::ALL_SPF_ROUTERS,
                payload,

                ttl: 1,
            },
            now + 1,
        );
        // Let the SPF throttle open.
        a.tick(now + 3, &mut out, &mut zap);
        let route = a.routes.get("10.77.0.0/30").expect("the route exists");
        assert_eq!(
            route.metric, 10,
            "the intra-area path (cost 10) wins over the cheaper summary (§16.2 step 6)"
        );
    }

    /// §16.4 step (1): a type-5 whose metric is LSInfinity
    /// describes no usable path — no route is installed.
    #[test]
    fn ls_infinity_external_installs_no_route() {
        let mut a = core_for("10.255.1.1", "eth0", "10.77.0.1");
        let mut b = core_for("10.255.2.1", "eth0", "10.77.0.2");
        let now = run_to_full(&mut a, &mut b, 0);
        let lsa = crate::origination::build_external_lsa(
            b.router_id,
            ip("203.0.113.0"),
            ip("255.255.255.0"),
            crate::LS_INFINITY,
            true,
        )
        .with_computed_header();
        let payload = b
            .packet(
                b.area_id(),
                PacketBody::LsUpdate(LsUpdate { lsas: vec![lsa] }),
            )
            .encode();
        let mut out = Vec::new();
        let mut zap = Vec::new();
        a.on_packet(
            0,
            &crate::transport::Received {
                src: b.interfaces[0].addr,
                dst: crate::packet::ALL_SPF_ROUTERS,
                payload,

                ttl: 1,
            },
            now + 1,
        );
        a.tick(now + 3, &mut out, &mut zap);
        assert!(
            !a.routes.contains_key("203.0.113.0/24"),
            "LSInfinity externals install no route (§16.4 step 1)"
        );
    }

    /// §16.4 step 3b: a type-5 with a non-zero forwarding address
    /// resolves through the routing table's path to the FA, not the
    /// ASBR.
    #[test]
    fn external_forwarding_address_resolves_via_the_fa_path() {
        let mut a = core_for("10.255.1.1", "eth0", "10.77.0.1");
        let mut b = core_for("10.255.2.1", "eth0", "10.77.0.2");
        let now = run_to_full(&mut a, &mut b, 0);
        // A type-5 from B (the ASBR) with FA = B's own address: the
        // FA falls inside the on-link stub 10.77.0.0/30 — the FA
        // path (cost 10) supplies the next hop.
        let mut lsa = crate::origination::build_external_lsa(
            b.router_id,
            ip("203.0.113.0"),
            ip("255.255.255.0"),
            50,
            true,
        )
        .with_computed_header();
        if let crate::lsa::LsaBody::AsExternal(ext) = &mut lsa.body {
            ext.forwarding_address = b.interfaces[0].addr;
        }
        let lsa = lsa.with_computed_header();
        let payload = b
            .packet(
                b.area_id(),
                PacketBody::LsUpdate(LsUpdate { lsas: vec![lsa] }),
            )
            .encode();
        let mut out = Vec::new();
        let mut zap = Vec::new();
        a.on_packet(
            0,
            &crate::transport::Received {
                src: b.interfaces[0].addr,
                dst: crate::packet::ALL_SPF_ROUTERS,
                payload,

                ttl: 1,
            },
            now + 1,
        );
        a.tick(now + 3, &mut out, &mut zap);
        let route = a.routes.get("203.0.113.0/24").expect("the external route");
        assert_eq!(route.metric, 50, "type-2 external: the LSA metric");
        assert!(
            route
                .nexthops
                .hops()
                .iter()
                .any(|(nh, _)| matches!(nh, Nexthop::Ipv4(x) if *x == b.interfaces[0].addr)),
            "the next hop is the forwarding address (§16.4 step 3b)"
        );
    }

    /// §16.4.1's preference over hand-built path sets: with
    /// RFC1583Compatibility DISABLED, an intra-area non-backbone path
    /// beats every other shape regardless of cost ("always the most
    /// preferred"); ENABLED (§C.1's default) applies no pruning —
    /// least cost, then the largest area ID (§16.4 step 3).
    #[test]
    fn asbr_path_preference_follows_rfc1583() {
        let path = |area: u32, inter: bool, cost: u32| RouterPath {
            area,
            inter_area: inter,
            cost,
            hops: vec![],
            b_bit: false,
            e_bit: true,
        };
        // Intra-area-1 (cost 50) vs intra-backbone (cost 10) vs
        // inter-area (cost 10): disabled takes the non-backbone
        // intra path despite the cost; enabled applies no pruning —
        // least cost wins (an area-0 path, cost 10).
        let paths = vec![path(1, false, 50), path(0, false, 10), path(0, true, 10)];
        assert_eq!(preferred_asbr_path(&paths, false).unwrap().cost, 50);
        assert_eq!(preferred_asbr_path(&paths, true).unwrap().cost, 10);
        assert_eq!(preferred_asbr_path(&paths, true).unwrap().area, 0);
        // Without the non-backbone path, disabled groups backbone
        // and inter-area as equals (cost decides, then the larger
        // area — identical to enabled).
        let paths = vec![path(0, false, 30), path(0, true, 10)];
        assert_eq!(preferred_asbr_path(&paths, false).unwrap().cost, 10);
        assert_eq!(preferred_asbr_path(&paths, true).unwrap().cost, 10);
        // Equal (cost, shape): the largest area ID wins (§16.4 step
        // 3), under BOTH settings.
        let paths = vec![path(2, true, 10), path(5, true, 10)];
        assert_eq!(preferred_asbr_path(&paths, false).unwrap().area, 5);
        assert_eq!(preferred_asbr_path(&paths, true).unwrap().area, 5);
        assert!(preferred_asbr_path(&[], true).is_none());
    }

    /// §16.4 step (3) end to end (O-2): the same ASBR reachable
    /// intra-area through the backbone (cost 10) AND a non-backbone
    /// area (cost 50). RFC1583Compatibility DISABLED picks the
    /// non-backbone path ("always the most preferred", §16.4.1) —
    /// the external next hop is the area-1 link; ENABLED (§C.1's
    /// default) picks least cost — the area-0 link. Both settings
    /// demonstrably change the documented tiebreak.
    #[test]
    fn rfc1583_knob_changes_the_external_tiebreak() {
        let run = |rfc1583: &str| -> (Vec<Nexthop>, u32) {
            // A: eth0 in area 0 (cost 10) and eth1 in area 1 (cost
            // 50), both p2p to B's matching interface; B: the ASBR.
            let a_conf = format!(
                "router ospf\n router-id 10.255.1.1\n{rfc1583} area 0.0.0.0\n  interface eth0\n   address 10.10.0.1/30\n   network-type point-to-point\n   hello-interval 1\n   dead-interval 4\n area 0.0.0.1\n  interface eth1\n   address 10.20.0.1/30\n   cost 50\n   network-type point-to-point\n   hello-interval 1\n   dead-interval 4\n"
            );
            let b_conf = "\
router ospf\n router-id 10.255.3.1\n area 0.0.0.0\n  interface eth0\n   address 10.10.0.2/30\n   network-type point-to-point\n   hello-interval 1\n   dead-interval 4\n area 0.0.0.1\n  interface eth1\n   address 10.20.0.2/30\n   network-type point-to-point\n   hello-interval 1\n   dead-interval 4\n redistribute static\n";
            let mut cores = vec![
                Ospfd::new(&parse_config(&a_conf).unwrap()).unwrap(),
                Ospfd::new(&parse_config(b_conf).unwrap()).unwrap(),
            ];
            let now = run_multi(&mut cores, 0, 8);
            assert!(
                cores[0]
                    .neighbor_states()
                    .iter()
                    .filter(|(_, _, s)| *s == NeighborState::Full)
                    .count()
                    >= 2,
                "both A-B adjacencies Full"
            );
            // B redistributes a type-2 static (metric 20).
            let mut out: Vec<WireOut> = Vec::new();
            cores[1].on_redistribute_add(
                crate::zedge::RedistributedRoute {
                    prefix: common::IpPrefix::V4(Ipv4Prefix::new(ip("203.0.113.0"), 24).unwrap()),
                    metric: 20,
                },
                now + 1,
                &mut out,
            );
            deliver_multi(&mut cores, 1, &out, now + 1, &mut Vec::new());
            run_multi(&mut cores, now + 2, 10);
            let route = cores[0].routes.get("203.0.113.0/24").expect("installed");
            (
                route.nexthops.hops().iter().map(|(nh, _)| *nh).collect(),
                route.metric,
            )
        };
        // DISABLED: §16.4.1's non-backbone path wins despite 5x the
        // cost — the next hop rides the area-1 link.
        let (hops, metric) = run(" rfc1583-compatibility disabled\n");
        assert_eq!(metric, 20, "type-2 external: the LSA metric");
        assert!(
            hops.iter()
                .any(|nh| matches!(nh, Nexthop::Ipv4(x) if *x == ip("10.20.0.2"))),
            "disabled: the non-backbone ASBR path ({hops:?})"
        );
        assert!(
            !hops
                .iter()
                .any(|nh| matches!(nh, Nexthop::Ipv4(x) if *x == ip("10.10.0.2"))),
            "disabled: the cheaper backbone path loses (§16.4.1)"
        );
        // ENABLED (the default): no pruning — least cost wins.
        let (hops, metric) = run("");
        assert_eq!(metric, 20);
        assert!(
            hops.iter()
                .any(|nh| matches!(nh, Nexthop::Ipv4(x) if *x == ip("10.10.0.2"))),
            "enabled: least cost wins ({hops:?})"
        );
        assert!(
            !hops
                .iter()
                .any(|nh| matches!(nh, Nexthop::Ipv4(x) if *x == ip("10.20.0.2"))),
            "enabled: the non-backbone preference is gone"
        );
    }

    #[test]
    fn abr_summarizes_routes_inter_area_and_resolves_type4() {
        // §12.4.3/§16.2/§16.4 in one topology: A (us) is the ABR
        // between area 0 (peer B) and area 1 (peer C, an ASBR
        // redistributing a static). B and C share no area.
        let mut cores = vec![abr_core(), area0_core(), area1_core(true)];
        let (a, b, c) = (0, 1, 2);
        let now = run_multi(&mut cores, 0, 8);

        // The adjacencies: A-B in area 0, A-C in area 1.
        let full = |x: usize, y: usize| {
            let peer = cores[y].router_id;
            cores[x]
                .interfaces
                .iter()
                .any(|i| i.neighbors.get(&peer).map(|c| c.state()) == Some(NeighborState::Full))
        };
        assert!(full(a, b) && full(b, a), "A-B Full (area 0)");
        assert!(full(a, c) && full(c, a), "A-C Full (area 1)");

        // A is an ABR: both router-LSAs carry the B-bit (§A.4.2).
        for area in [0u32, 1] {
            let key = crate::lsa::LsaKey {
                ls_type: LsaType::ROUTER,
                link_state_id: crate::lsa::LinkStateId(cores[a].router_id.0),
                adv_router: cores[a].router_id,
            };
            let entry = cores[a].areas.get(&area).unwrap().lsdb.get(&key).unwrap();
            let crate::lsa::LsaBody::Router(body) = &entry.lsa.body else {
                panic!()
            };
            assert!(body.b_bit, "area {area} router-LSA carries the B-bit");
        }

        // §12.4.3: A's summaries — type-3 for each area's stubs into
        // the other area (split horizon keeps the own-area route out),
        // and a type-4 for C (the ASBR in area 1) into area 0.
        let summary = |core: &Ospfd, area: u32, t: LsaType, id: u32| {
            core.areas
                .get(&area)
                .unwrap()
                .lsdb
                .get(&LsaKey {
                    ls_type: t,
                    link_state_id: crate::lsa::LinkStateId(id),
                    adv_router: core.router_id,
                })
                .is_some()
        };
        assert!(
            summary(
                &cores[a],
                0,
                LsaType::SUMMARY_NETWORK,
                u32::from(ip("10.20.0.0"))
            ),
            "A summarizes the area-1 stub into the backbone"
        );
        assert!(
            summary(
                &cores[a],
                1,
                LsaType::SUMMARY_NETWORK,
                u32::from(ip("10.10.0.0"))
            ),
            "A summarizes the area-0 stub into area 1"
        );
        assert!(
            !summary(
                &cores[a],
                0,
                LsaType::SUMMARY_NETWORK,
                u32::from(ip("10.10.0.0"))
            ),
            "split horizon: the backbone's own network is not re-advertised into it"
        );
        // §16.2 on B: the inter-area route via A's type-3 — cost =
        // B→A (10) + A's summary metric (10).
        let b_route = cores[b].routes.get("10.20.0.0/30").unwrap();
        assert_eq!(b_route.metric, 20, "the inter-area cost is BR + summary");
        assert!(
            b_route
                .nexthops
                .hops()
                .iter()
                .any(|(nh, _)| matches!(nh, Nexthop::Ipv4(x) if *x == ip("10.10.0.1"))),
            "the inter-area next hop is the BR (A)"
        );
        // §16.2 on C: the backbone stub via A's type-3.
        assert!(
            cores[c].routes.contains_key("10.10.0.0/30"),
            "C routes the area-0 network through the summary"
        );

        // §16.4 on B: C's redistributed static resolves through the
        // type-4 ASBR path — B installs the external route via A.
        // C becomes an ASBR only when the static is pushed (§12.4.4:
        // the E-bit follows the external origination).
        let mut out: Vec<WireOut> = Vec::new();
        cores[c].on_redistribute_add(
            crate::zedge::RedistributedRoute {
                prefix: common::IpPrefix::V4(Ipv4Prefix::new(ip("203.0.113.0"), 24).unwrap()),
                metric: 20,
            },
            now + 1,
            &mut out,
        );
        deliver_multi(&mut cores, c, &out, now + 1, &mut Vec::new());
        let now2 = run_multi(&mut cores, now + 2, 10);
        // Now C is an ASBR: A's §12.4.3 duties include the type-4
        // for C into the backbone — and only there.
        assert!(
            summary(&cores[a], 0, LsaType::SUMMARY_ASBR, cores[c].router_id.0),
            "A originates the type-4 for C (the ASBR) into the backbone"
        );
        assert!(
            !summary(&cores[a], 1, LsaType::SUMMARY_ASBR, cores[c].router_id.0),
            "no type-4 into C's own area (§12.4.3's own-area rule)"
        );
        assert!(
            cores[b].routes.contains_key("203.0.113.0/24"),
            "B resolves C's external through A's type-4 (§16.4)"
        );
        let b_ext = cores[b].routes.get("203.0.113.0/24").unwrap();
        assert!(
            b_ext
                .nexthops
                .hops()
                .iter()
                .any(|(nh, _)| matches!(nh, Nexthop::Ipv4(x) if *x == ip("10.10.0.1"))),
            "the external next hop is the ABR on the ASBR path"
        );
        // The type-5 reached B's database through the AS-scope
        // mirroring (§7) — B holds it in area 0.
        let ext_key = LsaKey {
            ls_type: LsaType::AS_EXTERNAL,
            link_state_id: crate::lsa::LinkStateId(u32::from(ip("203.0.113.0"))),
            adv_router: cores[c].router_id,
        };
        assert!(
            cores[b].areas.get(&0).unwrap().lsdb.contains(&ext_key),
            "the type-5 lives in B's area-0 database (§7 mirroring)"
        );
        let _ = now2;
    }

    // ---- stub areas (§3.6/§C.2, N3 M1) --------------------------------

    /// A stub-area core with fast p2p timers.
    fn stub_core(router_id: &str, addr: &str, no_summary: bool) -> Ospfd {
        let text = format!(
            "router ospf\n router-id {router_id}\n area 0.0.0.1 stub{}\n  interface eth1\n   address {addr}/30\n   network-type point-to-point\n   hello-interval 1\n   dead-interval 4\n",
            if no_summary { " no-summary" } else { "" }
        );
        Ospfd::new(&parse_config(&text).unwrap()).unwrap()
    }

    /// §3.6's agreement rule (§9.5/§10.5): every router in the area
    /// agrees on stub-ness via the Hello E-bit. Our stub-area Hellos
    /// carry E clear; a Hello with E set is rejected (the packet is
    /// discarded, no neighbor forms), E clear is accepted.
    #[test]
    fn stub_area_hello_e_bit_agreement() {
        let mut a = stub_core("10.255.9.1", "10.99.0.1", false);
        // Our own Hellos out of a stub area: E clear (§C.2).
        let mut out = Vec::new();
        let mut zap = Vec::new();
        a.tick(0, &mut out, &mut zap);
        let hello = out
            .iter()
            .find(|w| matches!(w.packet.body, PacketBody::Hello(_)))
            .expect("hello sent");
        match &hello.packet.body {
            PacketBody::Hello(h) => {
                assert!(!h.options.e_bit(), "stub-area Hello carries E clear");
            }
            _ => unreachable!(),
        }
        // A forged peer Hello with E set: rejected (§10.5's E-bit
        // mismatch with ExternalRoutingCapability).
        let peer = core_for("10.255.8.1", "eth0", "10.99.0.2");
        let hello = Hello {
            network_mask: Ipv4Addr::UNSPECIFIED,
            hello_interval: 1,
            options: Options(Options::E),
            router_priority: 1,
            router_dead_interval: 4,
            designated_router: Ipv4Addr::UNSPECIFIED,
            backup_designated_router: Ipv4Addr::UNSPECIFIED,
            neighbors: vec![],
        };
        let payload = peer.packet(1, PacketBody::Hello(hello.clone())).encode();
        let replies = a.on_packet(
            0,
            &crate::transport::Received {
                src: ip("10.99.0.2"),
                dst: crate::packet::ALL_SPF_ROUTERS,
                payload,

                ttl: 1,
            },
            1,
        );
        assert!(replies.is_empty(), "no answer to the mismatched Hello");
        assert!(
            a.neighbor_states().is_empty(),
            "no neighbor forms under an E-bit mismatch (§3.6 agreement)"
        );
        // The same Hello with E clear: the neighbor forms (Init).
        let mut ok = hello.clone();
        ok.options = Options(0);
        let payload = peer.packet(1, PacketBody::Hello(ok)).encode();
        a.on_packet(
            0,
            &crate::transport::Received {
                src: ip("10.99.0.2"),
                dst: crate::packet::ALL_SPF_ROUTERS,
                payload,

                ttl: 1,
            },
            2,
        );
        assert!(
            !a.neighbor_states().is_empty(),
            "E-clear Hello accepted in the stub area"
        );
    }

    /// §13 step 3 at the daemon boundary: a type-5 arriving on a stub
    /// adjacency is silently discarded; FRR's no-summary discards the
    /// summaries too.
    #[test]
    fn stub_area_boundary_admission() {
        let mk = |no_summary: bool| {
            (
                stub_core("10.255.9.1", "10.99.0.1", no_summary),
                stub_core("10.255.9.2", "10.99.0.2", no_summary),
            )
        };
        // Plain stub: type-5 discarded, type-3 admitted.
        let (mut a, mut b) = mk(false);
        let now = run_to_full(&mut a, &mut b, 0);
        let ext = crate::origination::build_external_lsa(
            b.router_id,
            ip("198.51.100.0"),
            ip("255.255.255.0"),
            20,
            true,
        )
        .with_computed_header();
        let sum = crate::origination::build_summary_lsa(
            b.router_id,
            false,
            ip("203.0.113.0"),
            ip("255.255.255.0"),
            10,
        )
        .with_computed_header();
        let payload = b
            .packet(
                1,
                PacketBody::LsUpdate(LsUpdate {
                    lsas: vec![ext.clone(), sum.clone()],
                }),
            )
            .encode();
        a.on_packet(
            0,
            &crate::transport::Received {
                src: b.interfaces[0].addr,
                dst: crate::packet::ALL_SPF_ROUTERS,
                payload,

                ttl: 1,
            },
            now + 1,
        );
        assert!(
            !lsdb_of(&a).contains(&ext.key()),
            "type-5 not admitted into a stub area (§13 step 3)"
        );
        assert!(
            lsdb_of(&a).contains(&sum.key()),
            "type-3 admitted into a plain stub area"
        );
        // Totally stubby: the type-3 is discarded too (FRR no-summary).
        let (mut a, mut b) = mk(true);
        let now = run_to_full(&mut a, &mut b, 0);
        let payload = b
            .packet(
                1,
                PacketBody::LsUpdate(LsUpdate {
                    lsas: vec![sum.clone()],
                }),
            )
            .encode();
        a.on_packet(
            0,
            &crate::transport::Received {
                src: b.interfaces[0].addr,
                dst: crate::packet::ALL_SPF_ROUTERS,
                payload,

                ttl: 1,
            },
            now + 1,
        );
        assert!(
            !lsdb_of(&a).contains(&sum.key()),
            "type-3 not admitted into a totally stubby area (no-summary)"
        );
    }

    /// The ABR with a second area-1 interface (two intra networks:
    /// 10.20.0.0/30 and 10.20.4.0/30) and an optional area-1 range.
    fn abr_core_ranged(range: &str) -> Ospfd {
        let text = format!(
            concat!(
                "router ospf\n",
                " router-id 10.255.2.1\n",
                " area 0.0.0.0\n",
                "  interface eth0\n",
                "   address 10.10.0.1/30\n",
                "   network-type point-to-point\n",
                "   hello-interval 1\n",
                "   dead-interval 4\n",
                " area 0.0.0.1\n",
                "  interface eth1\n",
                "   address 10.20.0.1/30\n",
                "   network-type point-to-point\n",
                "   hello-interval 1\n",
                "   dead-interval 4\n",
                "  interface eth2\n",
                "   address 10.20.4.1/30\n",
                "   hello-interval 1\n",
                "   dead-interval 4\n",
                "{range}",
            ),
            range = range,
        );
        Ospfd::new(&parse_config(&text).unwrap()).unwrap()
    }

    /// §12.4.3's address ranges: the range-owning area's two intra
    /// networks coalesce into ONE range summary in the other areas
    /// (metric = the members' minimum), the per-network summaries
    /// suppressed; a configured `cost` overrides the metric;
    /// DoNotAdvertise suppresses everything.
    #[test]
    fn area_ranges_coalesce_summaries() {
        let run = |range: &str| {
            let mut cores = vec![abr_core_ranged(range), area0_core()];
            let now = run_multi(&mut cores, 0, 10);
            let abr = &cores[0];
            let a0 = abr.areas.get(&0).unwrap();
            let summaries: Vec<(u32, u8, u32)> = a0
                .lsdb
                .all()
                .filter(|e| {
                    e.lsa.header.ls_type == LsaType::SUMMARY_NETWORK
                        && e.lsa.header.adv_router == abr.router_id
                        && !e.lsa.header.is_max_age()
                })
                .filter_map(|e| {
                    let crate::lsa::LsaBody::Summary(sm) = &e.lsa.body else {
                        return None;
                    };
                    Some((
                        e.lsa.header.link_state_id.0 & u32::from(sm.mask),
                        u32::from(sm.mask).count_ones() as u8,
                        sm.metric,
                    ))
                })
                .collect();
            (summaries, now)
        };
        // The plain range: ONE /16 summary (metric = the members'
        // minimum = the interface cost 10), no per-network /30s.
        let (summaries, _now) = run(" area 0.0.0.1 range 10.20.0.0/16\n");
        assert_eq!(
            summaries,
            vec![(u32::from(ip("10.20.0.0")), 16, 10)],
            "one coalesced /16 at the members' minimum (12.4.3): {summaries:?}"
        );
        // The cost override.
        let (summaries, _) = run(" area 0.0.0.1 range 10.20.0.0/16 advertise cost 5\n");
        assert_eq!(
            summaries,
            vec![(u32::from(ip("10.20.0.0")), 16, 5)],
            "the configured cost overrides: {summaries:?}"
        );
        // DoNotAdvertise: nothing for the members.
        let (summaries, _) = run(" area 0.0.0.1 range 10.20.0.0/16 not-advertise\n");
        assert!(
            summaries.is_empty(),
            "a DoNotAdvertise range suppresses the members (12.4.3): {summaries:?}"
        );
    }

    /// §16.2 step (3): a foreign summary-LSA describing a network
    /// inside one of OUR actively-advertised ranges is not installed
    /// as an inter-area route (the range is ours).
    #[test]
    fn own_active_range_shields_foreign_summaries() {
        let mut cores = vec![
            abr_core_ranged(" area 0.0.0.1 range 10.20.0.0/16\n"),
            area0_core(),
        ];
        let now = run_multi(&mut cores, 0, 10);
        // The range is ACTIVE (two contributing intra routes).
        let abr = &mut cores[0];
        assert!(
            abr.areas.get(&0).unwrap().lsdb.contains(&LsaKey {
                ls_type: LsaType::SUMMARY_NETWORK,
                link_state_id: crate::lsa::LinkStateId(u32::from(ip("10.20.0.0"))),
                adv_router: abr.router_id,
            }),
            "our range summary is advertised (the range is active)"
        );
        // A FOREIGN summary-LSA for a network inside the range,
        // injected into the backbone (a foreign ABR's view).
        let foreign = crate::lsa::Lsa {
            header: crate::lsa::LsaHeader {
                ls_age: 1,
                options: Options(0x02),
                ls_type: LsaType::SUMMARY_NETWORK,
                link_state_id: crate::lsa::LinkStateId(u32::from(ip("10.20.4.0"))),
                // Advertised by the ADJACENT area-0 peer (16.2 (4):
                // the BR must be reachable in the examined area).
                adv_router: RouterId(u32::from(ip("10.255.1.1"))),
                seq: 0x8000_0001,
                checksum: 0,
                length: 0,
            },
            body: crate::lsa::LsaBody::Summary(crate::lsa::SummaryLsa {
                mask: ip("255.255.255.0"),
                metric: 3,
                tos: vec![],
            }),
        };
        // And a control: a foreign summary OUTSIDE our ranges still
        // installs (the shield is range-scoped, not a blanket drop).
        let control = crate::lsa::Lsa {
            header: crate::lsa::LsaHeader {
                ls_age: 1,
                options: Options(0x02),
                ls_type: LsaType::SUMMARY_NETWORK,
                link_state_id: crate::lsa::LinkStateId(u32::from(ip("10.99.0.0"))),
                adv_router: RouterId(u32::from(ip("10.255.1.1"))),
                seq: 0x8000_0001,
                checksum: 0,
                length: 0,
            },
            body: crate::lsa::LsaBody::Summary(crate::lsa::SummaryLsa {
                mask: ip("255.255.255.0"),
                metric: 3,
                tos: vec![],
            }),
        };
        let a0 = abr.areas.get_mut(&0).unwrap();
        let _ = a0.lsdb.install(foreign.with_computed_header(), true, now);
        let _ = a0.lsdb.install(control.with_computed_header(), true, now);
        // The direct install bypasses the change-class marking —
        // mark the AS-scope class and run the walk.
        cores[0].table_dirty = true;
        let mut out = Vec::new();
        let mut zap = Vec::new();
        cores[0].maybe_spf(now + 1, &mut out, &mut zap);
        // The foreign 10.20.4.0/24 inter-area route is NOT installed
        // (16.2 (3)); the control outside the range IS.
        assert!(
            !cores[0].routes.contains_key("10.20.4.0/24"),
            "the foreign summary inside our active range is not installed (16.2 (3))"
        );
        assert!(
            cores[0].routes.contains_key("10.99.0.0/24"),
            "a foreign summary outside our ranges installs normally"
        );
    }

    /// The ABR's stub duties (§3.6/§12.4.3.1/§C.2): advertise the
    /// default summary (default-cost metric) and nothing else into the
    /// stub area; type-5s from the ASBR never reach it; the internal
    /// router routes the default through the ABR.
    #[test]
    fn abr_advertises_stub_default_and_shields_externals() {
        let abr_text = concat!(
            "router ospf\n",
            " router-id 10.255.2.1\n",
            " area 0.0.0.0\n",
            "  interface eth0\n",
            "   address 10.10.0.1/30\n",
            "   network-type point-to-point\n",
            "   hello-interval 1\n",
            "   dead-interval 4\n",
            " area 0.0.0.1 stub\n",
            "  interface eth1\n",
            "   address 10.20.0.1/30\n",
            "   network-type point-to-point\n",
            "   hello-interval 1\n",
            "   dead-interval 4\n",
            " area 0.0.0.1 default-cost 25\n",
        );
        let mut cores = vec![
            Ospfd::new(&parse_config(abr_text).unwrap()).unwrap(),
            area0_core(),
            stub_core("10.255.3.1", "10.20.0.2", false),
        ];
        let (a, _b, c) = (0, 1, 2);
        let now = run_multi(&mut cores, 0, 8);

        // The stub default summary: type-3, LS ID 0.0.0.0, mask
        // 0.0.0.0, metric = default-cost 25 (§12.4.3.1), present in
        // the internal router's database.
        let default_key = LsaKey {
            ls_type: LsaType::SUMMARY_NETWORK,
            link_state_id: crate::lsa::LinkStateId(0),
            adv_router: cores[a].router_id,
        };
        let entry = cores[c]
            .areas
            .get(&1)
            .unwrap()
            .lsdb
            .get(&default_key)
            .expect("the stub default summary (§12.4.3.1)");
        let crate::lsa::LsaBody::Summary(body) = &entry.lsa.body else {
            panic!()
        };
        assert_eq!(body.metric, 25, "metric = the area's default-cost");
        assert_eq!(body.mask, Ipv4Addr::UNSPECIFIED, "default mask 0.0.0.0");

        // The internal router routes the default through the ABR:
        // §16.2 cost = BR distance (10, the p2p link) + the summary
        // metric (the default-cost 25).
        let def = cores[c].routes.get("0.0.0.0/0").expect("the default route");
        assert_eq!(def.metric, 35);
        assert!(def
            .nexthops
            .hops()
            .iter()
            .any(|(nh, _)| matches!(nh, Nexthop::Ipv4(x) if *x == ip("10.20.0.1"))));

        // The ASBR's external never enters the stub area (§3.6): not
        // in the internal router's database, not even in the ABR's
        // own stub-area database (mirroring skips it), and no type-4s
        // for the ASBR anywhere in the stub.
        let mut out: Vec<WireOut> = Vec::new();
        cores[_b].on_redistribute_add(
            crate::zedge::RedistributedRoute {
                prefix: common::IpPrefix::V4(Ipv4Prefix::new(ip("203.0.113.0"), 24).unwrap()),
                metric: 20,
            },
            now + 1,
            &mut out,
        );
        deliver_multi(&mut cores, _b, &out, now + 1, &mut Vec::new());
        let now2 = run_multi(&mut cores, now + 2, 10);
        let ext_key = LsaKey {
            ls_type: LsaType::AS_EXTERNAL,
            link_state_id: crate::lsa::LinkStateId(u32::from(ip("203.0.113.0"))),
            adv_router: cores[_b].router_id,
        };
        assert!(
            !cores[c].areas.get(&1).unwrap().lsdb.contains(&ext_key),
            "no type-5 in the internal stub router's database (§3.6)"
        );
        assert!(
            !cores[a].areas.get(&1).unwrap().lsdb.contains(&ext_key),
            "the ABR never mirrors type-5s into its stub area (§7 + §3.6)"
        );
        let any_t4 = cores[c]
            .areas
            .get(&1)
            .unwrap()
            .lsdb
            .all()
            .any(|e| e.lsa.header.ls_type == LsaType::SUMMARY_ASBR);
        assert!(!any_t4, "no type-4 summaries in the stub area");
        let any_t5 = cores[c]
            .areas
            .get(&1)
            .unwrap()
            .lsdb
            .all()
            .any(|e| e.lsa.header.ls_type == LsaType::AS_EXTERNAL);
        assert!(!any_t5, "no type-5s anywhere in the stub LSDB");
        let _ = now2;
    }

    // ---- NSSA (RFC 3101, N3 M2) --------------------------------------

    /// An NSSA-area core with fast p2p timers (optionally an ASBR).
    fn nssa_core(router_id: &str, addr: &str, redistribute: bool, no_summary: bool) -> Ospfd {
        let text = format!(
            "router ospf\n router-id {router_id}\n area 0.0.0.1 nssa{}\n  interface eth1\n   address {addr}/30\n   network-type point-to-point\n   hello-interval 1\n   dead-interval 4\n{}",
            if no_summary { " no-summary" } else { "" },
            if redistribute { " redistribute static\n" } else { "" }
        );
        Ospfd::new(&parse_config(&text).unwrap()).unwrap()
    }

    /// An ABR core: eth0 in area 0, eth1 in an NSSA area 1.
    fn nssa_abr_core(nssa_flags: &str) -> Ospfd {
        let text = format!(
            concat!(
                "router ospf\n",
                " router-id 10.255.2.1\n",
                " area 0.0.0.0\n",
                "  interface eth0\n",
                "   address 10.10.0.1/30\n",
                "   network-type point-to-point\n",
                "   hello-interval 1\n",
                "   dead-interval 4\n",
                " area 0.0.0.1 nssa{nssa_flags}\n",
                "  interface eth1\n",
                "   address 10.20.0.1/30\n",
                "   network-type point-to-point\n",
                "   hello-interval 1\n",
                "   dead-interval 4\n",
            ),
            nssa_flags = nssa_flags,
        );
        Ospfd::new(&parse_config(&text).unwrap()).unwrap()
    }

    /// RFC 3101 §2.1: the N-bit agreement — our NSSA Hellos carry N
    /// set / E clear; a Hello without N (or with E&N) is dropped.
    #[test]
    fn nssa_hello_n_bit_agreement() {
        let mut a = nssa_core("10.255.9.1", "10.99.0.1", false, false);
        let mut out = Vec::new();
        let mut zap = Vec::new();
        a.tick(0, &mut out, &mut zap);
        let hello = out
            .iter()
            .find(|w| matches!(w.packet.body, PacketBody::Hello(_)))
            .expect("hello sent");
        match &hello.packet.body {
            PacketBody::Hello(h) => {
                assert!(h.options.np_bit(), "NSSA Hello carries the N-bit");
                assert!(!h.options.e_bit(), "...and E clear (§2.1)");
            }
            _ => unreachable!(),
        }
        let peer = core_for("10.255.8.1", "eth0", "10.99.0.2");
        let hello = Hello {
            network_mask: Ipv4Addr::UNSPECIFIED,
            hello_interval: 1,
            options: Options(0), // no N: mismatch
            router_priority: 1,
            router_dead_interval: 4,
            designated_router: Ipv4Addr::UNSPECIFIED,
            backup_designated_router: Ipv4Addr::UNSPECIFIED,
            neighbors: vec![],
        };
        let payload = peer.packet(1, PacketBody::Hello(hello.clone())).encode();
        a.on_packet(
            0,
            &crate::transport::Received {
                src: ip("10.99.0.2"),
                dst: crate::packet::ALL_SPF_ROUTERS,
                payload,

                ttl: 1,
            },
            1,
        );
        assert!(
            a.neighbor_states().is_empty(),
            "no neighbor forms under an N-bit mismatch (RFC 3101 §2.1)"
        );
        // E and N both set is always wrong.
        let mut bad = hello.clone();
        bad.options = Options(Options::E | Options::NP);
        let payload = peer.packet(1, PacketBody::Hello(bad)).encode();
        a.on_packet(
            0,
            &crate::transport::Received {
                src: ip("10.99.0.2"),
                dst: crate::packet::ALL_SPF_ROUTERS,
                payload,

                ttl: 1,
            },
            2,
        );
        assert!(a.neighbor_states().is_empty(), "E&N both set is dropped");
        // N set, E clear: accepted.
        let mut ok = hello;
        ok.options = Options(Options::NP);
        let payload = peer.packet(1, PacketBody::Hello(ok)).encode();
        a.on_packet(
            0,
            &crate::transport::Received {
                src: ip("10.99.0.2"),
                dst: crate::packet::ALL_SPF_ROUTERS,
                payload,

                ttl: 1,
            },
            3,
        );
        assert!(!a.neighbor_states().is_empty(), "N-set Hello accepted");
    }

    /// The receive-side TTL wall closed (night N1) — the drop/pass
    /// matrix at the daemon level. The policy keys on the IP-level
    /// destination class and TTL: a UNICAST exchange packet (p2p
    /// conversations; dst = our address) with a degraded TTL is
    /// dropped before ANY §8.2 processing and counted; the identical
    /// packet at TTL 1 (§A.1's send value) is processed; a multicast
    /// Hello keeps the kernel's rule — no TTL gate.
    #[test]
    fn receive_ttl_enforcement_drop_pass_matrix() {
        let mut a = core_for("10.255.1.1", "eth0", "10.99.0.1");
        let b = core_for("10.255.1.2", "eth0", "10.99.0.2");
        let hello = Hello {
            network_mask: Ipv4Addr::from(0xffff_fffc),
            // core_for's interfaces run the §C.3 defaults (10/40) —
            // the crafted Hello must agree or §10.5 rejects it.
            hello_interval: 10,
            options: Options(Options::E),
            router_priority: 1,
            router_dead_interval: 40,
            designated_router: Ipv4Addr::UNSPECIFIED,
            backup_designated_router: Ipv4Addr::UNSPECIFIED,
            neighbors: vec![],
        };
        let payload = b.packet(0, PacketBody::Hello(hello.clone())).encode();

        // Drop arm: unicast dst (us) at TTL 63 — relayed-looking.
        a.on_packet(
            0,
            &crate::transport::Received {
                src: ip("10.99.0.2"),
                dst: a.interfaces[0].addr,
                payload: payload.clone(),
                ttl: 63,
            },
            1,
        );
        assert!(
            a.neighbor_states().is_empty(),
            "a degraded-TTL unicast never reaches §8.2"
        );
        assert_eq!(a.dropped_degraded_ttl, 1, "and it is counted");

        // Pass arm: the same packet at §A.1's TTL 1 is processed.
        a.on_packet(
            0,
            &crate::transport::Received {
                src: ip("10.99.0.2"),
                dst: a.interfaces[0].addr,
                payload: payload.clone(),
                ttl: 1,
            },
            2,
        );
        assert!(
            !a.neighbor_states().is_empty(),
            "TTL-1 unicast is processed normally"
        );
        assert_eq!(a.dropped_degraded_ttl, 1, "the pass arm does not count");

        // Multicast arm: Hellos keep the kernel's rule — a degraded
        // TTL on 224.0.0.5 traffic is not gated (RFC 2328 places no
        // receive-side TTL rule; §A.1's TTL-1 is a transmit mandate).
        let mut c = core_for("10.255.1.3", "eth0", "10.99.0.5");
        let d = core_for("10.255.1.4", "eth0", "10.99.0.6");
        let payload = d.packet(0, PacketBody::Hello(hello)).encode();
        c.on_packet(
            0,
            &crate::transport::Received {
                src: ip("10.99.0.6"),
                dst: crate::packet::ALL_SPF_ROUTERS,
                payload,
                ttl: 63,
            },
            1,
        );
        assert!(
            !c.neighbor_states().is_empty(),
            "a multicast Hello is not TTL-gated (kernel's rule)"
        );
        assert_eq!(c.dropped_degraded_ttl, 0, "the multicast arm never counts");
    }

    /// RFC 3101 §2.3/§13: type-7s flood within the NSSA and are
    /// discarded in normal areas; type-5s are discarded in the NSSA.
    #[test]
    fn nssa_boundary_admission() {
        // In the NSSA: type-5 discarded, type-7 admitted.
        let mut a = nssa_core("10.255.9.1", "10.99.0.1", false, false);
        let mut b = nssa_core("10.255.9.2", "10.99.0.2", false, false);
        let now = run_to_full(&mut a, &mut b, 0);
        let ext = crate::origination::build_external_lsa(
            b.router_id,
            ip("198.51.100.0"),
            ip("255.255.255.0"),
            20,
            true,
        )
        .with_computed_header();
        let seven = crate::origination::build_nssa_lsa(
            b.router_id,
            ip("198.51.100.0"),
            ip("255.255.255.0"),
            20,
            true,
            ip("10.99.0.2"),
            true,
        )
        .with_computed_header();
        let payload = b
            .packet(
                1,
                PacketBody::LsUpdate(LsUpdate {
                    lsas: vec![ext.clone(), seven.clone()],
                }),
            )
            .encode();
        a.on_packet(
            0,
            &crate::transport::Received {
                src: b.interfaces[0].addr,
                dst: crate::packet::ALL_SPF_ROUTERS,
                payload,

                ttl: 1,
            },
            now + 1,
        );
        assert!(
            !lsdb_of(&a).contains(&ext.key()),
            "type-5 not admitted into the NSSA (§2.1)"
        );
        assert!(
            lsdb_of(&a).contains(&seven.key()),
            "type-7 admitted within its NSSA (§2.3)"
        );
        // In a normal area: the type-7 is discarded.
        let mut x = core_for("10.255.7.1", "eth0", "10.98.0.1");
        let mut y = core_for("10.255.7.2", "eth0", "10.98.0.2");
        let now2 = run_to_full(&mut x, &mut y, 0);
        let payload = y
            .packet(
                0,
                PacketBody::LsUpdate(LsUpdate {
                    lsas: vec![seven.clone()],
                }),
            )
            .encode();
        x.on_packet(
            0,
            &crate::transport::Received {
                src: y.interfaces[0].addr,
                dst: crate::packet::ALL_SPF_ROUTERS,
                payload,

                ttl: 1,
            },
            now2 + 1,
        );
        assert!(
            !lsdb_of(&x).contains(&seven.key()),
            "type-7 discarded outside its NSSA (§2.3: only flooded within the NSSA)"
        );
    }

    /// RFC 3101 §2.4 origination: an NSSA-internal ASBR's type-7
    /// carries P set + a non-zero FA from its own NSSA address; a
    /// border router originating BOTH forms clears the P-bit.
    #[test]
    fn type_seven_origination_follows_the_p_bit_rules() {
        // Internal ASBR (no normal area): P set, FA = its NSSA
        // interface address.
        let mut a = nssa_core("10.255.3.1", "10.20.0.2", true, false);
        let mut out = Vec::new();
        a.on_redistribute_add(
            crate::zedge::RedistributedRoute {
                prefix: common::IpPrefix::V4(Ipv4Prefix::new(ip("203.0.113.0"), 24).unwrap()),
                metric: 20,
            },
            0,
            &mut out,
        );
        let key = LsaKey {
            ls_type: LsaType::NSSA,
            link_state_id: crate::lsa::LinkStateId(u32::from(ip("203.0.113.0"))),
            adv_router: a.router_id,
        };
        let entry = lsdb_of(&a).get(&key).expect("type-7 originated");
        assert!(
            entry.lsa.header.options.np_bit(),
            "internal ASBR sets the P-bit (§2.4)"
        );
        let crate::lsa::LsaBody::AsExternal(ext) = &entry.lsa.body else {
            panic!()
        };
        assert_eq!(
            ext.forwarding_address,
            ip("10.20.0.2"),
            "FA = the ASBR's own NSSA address (P-set demands non-zero, §2.3)"
        );
        // Border router (normal area attached): the type-7 gets P
        // clear; the type-5 goes to the normal area only.
        let mut abr = nssa_abr_core("");
        let mut out = Vec::new();
        abr.on_redistribute_add(
            crate::zedge::RedistributedRoute {
                prefix: common::IpPrefix::V4(Ipv4Prefix::new(ip("203.0.113.0"), 24).unwrap()),
                metric: 20,
            },
            0,
            &mut out,
        );
        let entry = abr
            .areas
            .get(&1)
            .unwrap()
            .lsdb
            .get(&LsaKey {
                ls_type: LsaType::NSSA,
                link_state_id: crate::lsa::LinkStateId(u32::from(ip("203.0.113.0"))),
                adv_router: abr.router_id,
            })
            .expect("the border's type-7");
        assert!(
            !entry.lsa.header.options.np_bit(),
            "border router originating both forms clears the P-bit (§2.4)"
        );
        let t5 = abr
            .areas
            .get(&0)
            .unwrap()
            .lsdb
            .get(&LsaKey {
                ls_type: LsaType::AS_EXTERNAL,
                link_state_id: crate::lsa::LinkStateId(u32::from(ip("203.0.113.0"))),
                adv_router: abr.router_id,
            })
            .expect("the border's type-5 in the normal area");
        let _ = t5;
    }

    /// The NSSA end-to-end: an internal ASBR's type-7 is translated
    /// by the ABR into a type-5 (FA preserved, adv router = the ABR —
    /// §3.2 step (2)), the area-0 peer routes the external through
    /// the ABR, and another internal router routes the type-7 per
    /// §2.5 (the ASBR itself skips its own LSA, §2.5 step 2).
    #[test]
    fn nssa_translates_and_routes_end_to_end() {
        let mut cores = vec![
            nssa_abr_core(""),
            area0_core(),
            nssa_core("10.255.3.1", "10.20.0.2", true, false),
            // A second internal NSSA router sharing the simulated
            // segment — the type-7 consumer.
            nssa_core("10.255.4.1", "10.20.0.3", false, false),
        ];
        let (a, b, c, d) = (0, 1, 2, 3);
        let now = run_multi(&mut cores, 0, 8);

        // The internal ASBR redistributes.
        let mut out: Vec<WireOut> = Vec::new();
        cores[c].on_redistribute_add(
            crate::zedge::RedistributedRoute {
                prefix: common::IpPrefix::V4(Ipv4Prefix::new(ip("203.0.113.0"), 24).unwrap()),
                metric: 20,
            },
            now + 1,
            &mut out,
        );
        deliver_multi(&mut cores, c, &out, now + 1, &mut Vec::new());
        let now2 = run_multi(&mut cores, now + 2, 12);

        // The translated type-5 in the ABR's backbone database: adv
        // router = the ABR, FA copied from the type-7.
        let t5_key = LsaKey {
            ls_type: LsaType::AS_EXTERNAL,
            link_state_id: crate::lsa::LinkStateId(u32::from(ip("203.0.113.0"))),
            adv_router: cores[a].router_id,
        };
        let entry = cores[a]
            .areas
            .get(&0)
            .unwrap()
            .lsdb
            .get(&t5_key)
            .expect("the translated type-5 (§3.2)");
        let crate::lsa::LsaBody::AsExternal(ext) = &entry.lsa.body else {
            panic!()
        };
        assert_eq!(
            ext.forwarding_address,
            ip("10.20.0.2"),
            "the translation copies the type-7's FA (§3.2 step 2)"
        );
        // It reached the area-0 peer, which routes the external
        // through the ABR (the FA resolves inside the NSSA — the
        // ABR's FA-path next hop is the ASBR direction).
        assert!(
            cores[b].areas.get(&0).unwrap().lsdb.contains(&t5_key),
            "the translated type-5 flooded to the area-0 peer"
        );
        let ext_route = cores[b].routes.get("203.0.113.0/24").expect("B routes it");
        assert!(
            ext_route
                .nexthops
                .hops()
                .iter()
                .any(|(nh, _)| matches!(nh, Nexthop::Ipv4(x) if *x == ip("10.10.0.1"))),
            "the area-0 peer's next hop is the ABR"
        );
        // The second internal router routes the external via §2.5:
        // the type-7's FA path inside the NSSA (type-2 metric 20;
        // next hop left unasserted — `decorate_hops`' p2p
        // peer-address pick is unordered with two Full neighbors on
        // the simulated shared segment).
        let int_route = cores[d]
            .routes
            .get("203.0.113.0/24")
            .expect("D routes the type-7");
        assert_eq!(int_route.metric, 20, "type-2 external metric");
        // The ASBR itself skips its own type-7 (§2.5 step 2).
        assert!(
            !cores[c].routes.contains_key("203.0.113.0/24"),
            "the ASBR installs no route from its own type-7"
        );
        let _ = now2;
    }

    /// RFC 3101 §2.4/§2.7 defaults: a plain NSSA gets the border's
    /// type-7 default (P clear); a no-summary NSSA gets a type-3
    /// default instead.
    #[test]
    fn nssa_border_defaults_pick_the_right_form() {
        let run = |flags: &str| {
            let mut cores = vec![nssa_abr_core(flags), area0_core()];
            let (a, b) = (0, 1);
            let now = run_multi(&mut cores, 0, 8);
            let internal = cores[a].areas.get(&1).unwrap();
            let t7 = internal.lsdb.get(&LsaKey {
                ls_type: LsaType::NSSA,
                link_state_id: crate::lsa::LinkStateId(0),
                adv_router: cores[a].router_id,
            });
            let t3 = internal.lsdb.get(&LsaKey {
                ls_type: LsaType::SUMMARY_NETWORK,
                link_state_id: crate::lsa::LinkStateId(0),
                adv_router: cores[a].router_id,
            });
            let now2 = now;
            let _ = (b, now2);
            (t7.map(|e| e.lsa.clone()), t3.map(|e| e.lsa.clone()))
        };
        // Plain NSSA: the type-7 default. RFC 3101 §2.4's letter
        // says P clear for a border default; FRR 10.2.2 (probed
        // live, the interop leg) does not install the P-clear form —
        // we send the interoperable P-set form (divergence recorded
        // in docs/protocols/ospf.md).
        let (t7, t3) = run("");
        let t7 = t7.expect("the type-7 default in a plain NSSA (§2.4)");
        assert!(
            !t7.header.options.np_bit(),
            "the border's type-7 default has P clear (§2.4's letter)"
        );
        let crate::lsa::LsaBody::AsExternal(ext) = &t7.body else {
            panic!()
        };
        assert_eq!(ext.mask, Ipv4Addr::UNSPECIFIED, "0.0.0.0/0");
        assert!(
            t3.is_none(),
            "no type-3 default while summaries are imported (§2.7)"
        );
        // Totally-NSSA: the type-3 default (§2.7's protection).
        let (t7, t3) = run(" no-summary");
        assert!(t7.is_none(), "no type-7 default under no-summary");
        let t3 = t3.expect("the type-3 default in a totally-NSSA (§2.7)");
        let crate::lsa::LsaBody::Summary(sm) = &t3.body else {
            panic!()
        };
        assert_eq!(sm.metric, 1, "default-cost");
    }

    // ---- the NSSA translator remainder (RFC 3101 3.1/3.2/E) -------

    /// The ABR config with extra area-parameter lines (ranges, the
    /// translator role) and an explicit router id / addresses.
    fn nssa_abr_core_rid(
        router_id: &str,
        a0_addr: &str,
        a1_addr: &str,
        nssa_flags: &str,
        extra: &str,
    ) -> Ospfd {
        let text = format!(
            concat!(
                "router ospf\n",
                " router-id {router_id}\n",
                " area 0.0.0.0\n",
                "  interface eth0\n",
                "   address {a0_addr}/30\n",
                "   network-type point-to-point\n",
                "   hello-interval 1\n",
                "   dead-interval 4\n",
                " area 0.0.0.1 nssa{nssa_flags}\n",
                "  interface eth1\n",
                "   address {a1_addr}/30\n",
                "   network-type point-to-point\n",
                "   hello-interval 1\n",
                "   dead-interval 4\n",
                "{extra}",
            ),
            router_id = router_id,
            a0_addr = a0_addr,
            a1_addr = a1_addr,
            nssa_flags = nssa_flags,
            extra = extra,
        );
        Ospfd::new(&parse_config(&text).unwrap()).unwrap()
    }

    /// RFC 3101 3.1: a Candidate border router stands down when a
    /// higher-ID border router is reachable over both the NSSA and
    /// the transit topology; the elected translator sets Nt in its
    /// NSSA router-LSA; a deposed translator keeps translating
    /// through the stability interval, then flushes. Appendix E: the
    /// FOREIGN border P-clear type-7 default installs locally and
    /// never propagates.
    #[test]
    fn nssa_translator_election_stands_down_for_the_higher_id() {
        let mk = |role: &str| {
            vec![
                // Us: the Candidate (or Always) ABR, rid 10.255.2.1.
                nssa_abr_core_rid(
                    "10.255.2.1",
                    "10.10.0.1",
                    "10.20.0.1",
                    "",
                    &format!(" area 0.0.0.1 nssa translate-{role}\n"),
                ),
                // The peer ABR — HIGHER router ID, adjacent in both
                // areas (reachable over the NSSA AND the transit
                // topology: the 3.1 election list).
                nssa_abr_core_rid(
                    "10.255.9.1",
                    "10.10.0.2",
                    "10.20.0.9",
                    "",
                    " area 0.0.0.1 nssa translate-candidate\n",
                ),
                // The NSSA-internal ASBR (the type-7 source).
                nssa_core("10.255.3.1", "10.20.0.2", true, false),
            ]
        };
        let redistribute = |cores: &mut [Ospfd], now: u64| {
            let mut out: Vec<WireOut> = Vec::new();
            cores[2].on_redistribute_add(
                crate::zedge::RedistributedRoute {
                    prefix: common::IpPrefix::V4(Ipv4Prefix::new(ip("203.0.113.0"), 24).unwrap()),
                    metric: 20,
                },
                now,
                &mut out,
            );
            deliver_multi(cores, 2, &out, now, &mut Vec::new());
        };
        // ---- Candidate: outranked by the higher ID ----
        let mut cores = mk("candidate");
        let now = run_multi(&mut cores, 0, 10);
        redistribute(&mut cores, now + 1);
        let now2 = run_multi(&mut cores, now + 2, 12);
        let _ = now2;
        // The election: we stood down; the peer (no one higher) was
        // elected and advertises Nt in its NSSA router-LSA.
        let ours = cores[0].areas.get(&1).unwrap();
        assert!(
            !ours.translator_elected,
            "outranked by the higher-ID border router (3.1)"
        );
        let our_router = ours
            .lsdb
            .get(&LsaKey {
                ls_type: LsaType::ROUTER,
                link_state_id: crate::lsa::LinkStateId(u32::from(ip("10.255.2.1"))),
                adv_router: cores[0].router_id,
            })
            .map(|e| e.lsa.clone())
            .expect("our NSSA router-LSA");
        let crate::lsa::LsaBody::Router(r) = &our_router.body else {
            panic!()
        };
        assert!(!r.nt_bit, "a disabled translator clears Nt (3.1)");
        let peer_router = ours
            .lsdb
            .get(&LsaKey {
                ls_type: LsaType::ROUTER,
                link_state_id: crate::lsa::LinkStateId(u32::from(ip("10.255.9.1"))),
                adv_router: cores[1].router_id,
            })
            .map(|e| e.lsa.clone())
            .expect("the peer's NSSA router-LSA");
        let crate::lsa::LsaBody::Router(r) = &peer_router.body else {
            panic!()
        };
        assert!(r.nt_bit, "the elected translator sets Nt (3.1)");
        // Bring-up nuance (the RFC's own sequencing): we were
        // elected before the peer's adjacency made it into the
        // election list, so our deposition arms the stability
        // interval — "an elected translator will continue to perform
        // translation duties until supplanted" (3.1). The interval
        // must be armed and our translations still held.
        let until = cores[0].areas.get(&1).unwrap().stability_until;
        assert!(until.is_some(), "the deposition armed the interval");
        // Past the interval: the deposed translator stands down for
        // real — its translations flush. The WHOLE mesh keeps ticking
        // (a lone-core tick would expire the adjacencies and re-elect
        // us — a harness artifact, not a protocol event).
        let mut t = now2;
        while t < until.unwrap() + 2 {
            t += 1;
            let mut outs: Vec<Vec<WireOut>> = cores.iter_mut().map(|_| Vec::new()).collect();
            let mut zaps: Vec<Vec<ZedgeCommand>> = cores.iter_mut().map(|_| Vec::new()).collect();
            for (i, core) in cores.iter_mut().enumerate() {
                core.tick(t, &mut outs[i], &mut zaps[i]);
            }
            let mut queue: Vec<(usize, Vec<WireOut>)> = Vec::new();
            for (i, o) in outs.iter().enumerate() {
                if !o.is_empty() {
                    deliver_multi(&mut cores, i, o, t, &mut queue);
                }
            }
            while !queue.is_empty() {
                let batch = std::mem::take(&mut queue);
                for (from, o) in batch {
                    deliver_multi(&mut cores, from, &o, t, &mut queue);
                }
            }
        }
        // The PEER translated (adv = peer), not us.
        let peer_t5 = LsaKey {
            ls_type: LsaType::AS_EXTERNAL,
            link_state_id: crate::lsa::LinkStateId(u32::from(ip("203.0.113.0"))),
            adv_router: cores[1].router_id,
        };
        let our_t5 = LsaKey {
            ls_type: LsaType::AS_EXTERNAL,
            link_state_id: crate::lsa::LinkStateId(u32::from(ip("203.0.113.0"))),
            adv_router: cores[0].router_id,
        };
        assert!(
            cores[0].areas.get(&0).unwrap().lsdb.contains(&peer_t5),
            "the elected translator's type-5 is in the backbone"
        );
        assert!(
            !cores[0]
                .areas
                .get(&0)
                .unwrap()
                .lsdb
                .get(&our_t5)
                .is_some_and(|e| !e.lsa.header.is_max_age()),
            "we did not keep translating past the stability interval"
        );
        assert!(cores[0].translations.is_empty(), "no translations held");
        // Appendix E: the PEER's border type-7 default (P clear) is
        // foreign to us — we INSTALL it locally (never propagating).
        assert!(
            cores[0].routes.contains_key("0.0.0.0/0"),
            "Appendix E: the foreign P-clear type-7 default installs on the border (locally)"
        );
        // And nothing translated the default anywhere.
        let default_t5 = LsaKey {
            ls_type: LsaType::AS_EXTERNAL,
            link_state_id: crate::lsa::LinkStateId(0),
            adv_router: cores[1].router_id,
        };
        assert!(
            !cores[0].areas.get(&0).unwrap().lsdb.contains(&default_t5),
            "the type-7 default never becomes a type-5"
        );
        let _ = now2;

        // ---- Always: enabled regardless of the higher ID ----
        let mut cores = mk("always");
        let now = run_multi(&mut cores, 0, 10);
        redistribute(&mut cores, now + 1);
        let _now2 = run_multi(&mut cores, now + 2, 12);
        assert!(
            cores[0].areas.get(&1).unwrap().translator_role
                == crate::config::NssaTranslatorRole::Always
        );
        assert!(
            cores[0].areas.get(&0).unwrap().lsdb.contains(&LsaKey {
                ls_type: LsaType::AS_EXTERNAL,
                link_state_id: crate::lsa::LinkStateId(u32::from(ip("203.0.113.0"))),
                adv_router: cores[0].router_id,
            }),
            "Always translates unconditionally (3.1)"
        );
    }

    /// RFC 3101 3.2 step (3): the Type-7 address-range aggregation —
    /// one type-5 per range, path type 2 when any member is type 2
    /// with metric = highest type-2 cost + 1, FA 0.0.0.0 — and step
    /// (1)'s DoNotAdvertise suppression.
    #[test]
    fn nssa_type7_range_aggregates_and_suppresses() {
        let mk = |range: &str| {
            vec![
                nssa_abr_core_rid(
                    "10.255.2.1",
                    "10.10.0.1",
                    "10.20.0.1",
                    "",
                    &format!(" area 0.0.0.1 range {range}\n"),
                ),
                area0_core(),
                nssa_core("10.255.3.1", "10.20.0.2", true, false),
            ]
        };
        let mut cores = mk("203.0.0.0/16");
        let now = run_multi(&mut cores, 0, 10);
        // Two type-7 members inside the range: an E2 (metric 20) and
        // an E1 (metric 10).
        for (net, metric) in [("203.0.113.0", 20u32), ("203.0.114.0", 10)] {
            let mut out: Vec<WireOut> = Vec::new();
            cores[2].on_redistribute_add(
                crate::zedge::RedistributedRoute {
                    prefix: common::IpPrefix::V4(Ipv4Prefix::new(ip(net), 24).unwrap()),
                    metric,
                },
                now + 1,
                &mut out,
            );
            deliver_multi(&mut cores, 2, &out, now + 1, &mut Vec::new());
        }
        let _now2 = run_multi(&mut cores, now + 2, 12);
        // ONE aggregated type-5 for the range: 203.0.0.0/16, type 2
        // (a member is type 2), metric 21 (20 + 1), FA 0.0.0.0.
        let agg = cores[0]
            .areas
            .get(&0)
            .unwrap()
            .lsdb
            .get(&LsaKey {
                ls_type: LsaType::AS_EXTERNAL,
                link_state_id: crate::lsa::LinkStateId(u32::from(ip("203.0.0.0"))),
                adv_router: cores[0].router_id,
            })
            .map(|e| e.lsa.clone())
            .expect("the aggregated type-5 for the range");
        let crate::lsa::LsaBody::AsExternal(ext) = &agg.body else {
            panic!()
        };
        assert_eq!(u32::from(ext.mask).count_ones(), 16, "the range's /16 mask");
        assert!(ext.e_bit, "path type 2 (a member is type 2)");
        assert_eq!(ext.metric, 21, "the highest Type-2 cost + 1");
        assert_eq!(
            ext.forwarding_address,
            Ipv4Addr::UNSPECIFIED,
            "the aggregated type-5's FA is 0.0.0.0"
        );
        // The members' plain translations are suppressed.
        for net in ["203.0.113.0", "203.0.114.0"] {
            assert!(
                !cores[0].areas.get(&0).unwrap().lsdb.contains(&LsaKey {
                    ls_type: LsaType::AS_EXTERNAL,
                    link_state_id: crate::lsa::LinkStateId(u32::from(ip(net))),
                    adv_router: cores[0].router_id,
                }),
                "no plain type-5 for the range member {net} (3.2 step 3)"
            );
        }
        // DoNotAdvertise: nothing leaves the NSSA.
        let mut cores = mk("203.0.0.0/16 not-advertise");
        let now = run_multi(&mut cores, 0, 10);
        let mut out: Vec<WireOut> = Vec::new();
        cores[2].on_redistribute_add(
            crate::zedge::RedistributedRoute {
                prefix: common::IpPrefix::V4(Ipv4Prefix::new(ip("203.0.113.0"), 24).unwrap()),
                metric: 20,
            },
            now + 1,
            &mut out,
        );
        deliver_multi(&mut cores, 2, &out, now + 1, &mut Vec::new());
        let _now2 = run_multi(&mut cores, now + 2, 12);
        let ours: Vec<LsaKey> = cores[0]
            .areas
            .get(&0)
            .unwrap()
            .lsdb
            .all()
            .filter(|e| {
                e.lsa.header.ls_type == LsaType::AS_EXTERNAL
                    && e.lsa.header.adv_router == cores[0].router_id
                    && !e.lsa.header.is_max_age()
            })
            .map(|e| e.lsa.key())
            .collect();
        assert!(
            ours.iter()
                .all(|k| k.link_state_id.0 == u32::from(ip("198.51.100.0"))),
            "a DoNotAdvertise range suppresses everything but the lab's own external: {ours:?}"
        );
    }

    /// RFC 3101 3.2's LS-ID remapping: a translated type-5 whose
    /// natural Link State ID is already taken by one of OUR type-5s
    /// describing a different network walks the host bits.
    #[test]
    fn translated_ls_id_remaps_on_collision() {
        let mut cores = vec![
            // Us: the ABR AND an ASBR — our own /24 external occupies
            // the natural LS ID 203.0.113.0.
            {
                let mut core = nssa_abr_core_rid("10.255.2.1", "10.10.0.1", "10.20.0.1", "", "");
                core.redistribute_static = true;
                core
            },
            area0_core(),
            nssa_core("10.255.3.1", "10.20.0.2", true, false),
        ];
        let now = run_multi(&mut cores, 0, 10);
        // Our own /24 type-5 (LS ID = 203.0.113.0).
        let mut out: Vec<WireOut> = Vec::new();
        cores[0].on_redistribute_add(
            crate::zedge::RedistributedRoute {
                prefix: common::IpPrefix::V4(Ipv4Prefix::new(ip("203.0.113.0"), 24).unwrap()),
                metric: 5,
            },
            now + 1,
            &mut out,
        );
        // The ASBR's type-7 for the SAME address with a DIFFERENT
        // mask (/25) — the collision case.
        let mut out2: Vec<WireOut> = Vec::new();
        cores[2].on_redistribute_add(
            crate::zedge::RedistributedRoute {
                prefix: common::IpPrefix::V4(Ipv4Prefix::new(ip("203.0.113.0"), 25).unwrap()),
                metric: 20,
            },
            now + 1,
            &mut out2,
        );
        deliver_multi(&mut cores, 2, &out2, now + 1, &mut Vec::new());
        let _now2 = run_multi(&mut cores, now + 2, 14);
        // The translation took a host-bit LS ID.
        let translated: Vec<(u32, u8)> = cores[0]
            .areas
            .get(&0)
            .unwrap()
            .lsdb
            .all()
            .filter(|e| {
                e.lsa.header.ls_type == LsaType::AS_EXTERNAL
                    && e.lsa.header.adv_router == cores[0].router_id
                    && !e.lsa.header.is_max_age()
            })
            .filter_map(|e| {
                let crate::lsa::LsaBody::AsExternal(ext) = &e.lsa.body else {
                    return None;
                };
                Some((
                    e.lsa.header.link_state_id.0,
                    u32::from(ext.mask).count_ones() as u8,
                ))
            })
            .collect();
        assert!(
            translated.contains(&(u32::from(ip("203.0.113.0")), 24)),
            "our own /24 keeps the natural LS ID"
        );
        assert!(
            translated.contains(&(u32::from(ip("203.0.113.1")), 25)),
            "the /25 translation walked the host bits to .1 (3.2): {translated:?}"
        );
    }

    /// A core with simple-password auth on its interface.
    fn simple_auth_core(router_id: &str, addr: &str, password: &str) -> Ospfd {
        let text = format!(
            "router ospf\n router-id {router_id}\n area 0.0.0.0\n  interface eth0\n   address {addr}/30\n   network-type point-to-point\n   hello-interval 1\n   dead-interval 4\n   authentication-key {password}\n"
        );
        Ospfd::new(&parse_config(&text).unwrap()).unwrap()
    }

    fn hmac_core(router_id: &str, addr: &str, key_id: u8, key: &str) -> Ospfd {
        let text = format!(
            "router ospf\n router-id {router_id}\n area 0.0.0.0\n  interface eth0\n   address {addr}/30\n   network-type point-to-point\n   hello-interval 1\n   dead-interval 4\n   authentication message-digest\n   message-digest-key {key_id} hmac-sha-256 {key}\n"
        );
        Ospfd::new(&parse_config(&text).unwrap()).unwrap()
    }

    #[test]
    fn simple_password_matches_form_adjacency_and_mismatches_do_not() {
        // Matching passwords: Full adjacency through the signed wire.
        let mut a = simple_auth_core("10.255.1.1", "10.77.0.1", "s3cret");
        let mut b = simple_auth_core("10.255.2.1", "10.77.0.2", "s3cret");
        let now = run_to_full(&mut a, &mut b, 0);
        assert!(a
            .neighbor_states()
            .iter()
            .any(|(_, _, s)| *s == NeighborState::Full));
        // The packets on the wire carry AuType 1 + the padded field
        // (a tick past the hello deadline).
        let mut out = Vec::new();
        let mut zap = Vec::new();
        a.tick(now + 10, &mut out, &mut zap);
        assert!(out.iter().any(|w| {
            w.packet.header.au_type == 1
                && w.packet.header.authentication == u64::from_be_bytes(*b"s3cret\0\0")
        }));

        // A MISMATCHED peer never forms a neighbor: its Hellos are
        // discarded before §10.5 processing (App D.5).
        let c = simple_auth_core("10.255.3.1", "10.77.0.3", "wrongpw");
        // One mismatched hello, properly checksummed (AuType 1 +
        // the wrong 64-bit password): discarded before §10.5, no
        // neighbor forms (D.5.2).
        let mut hello = make_hello(c.router_id, 0, &c.interfaces[0], AreaKind::Normal);
        hello.header.au_type = 1;
        hello.header.authentication = u64::from_be_bytes(*b"wrongpw\0");
        let payload = hello.encode();
        let replies = a.on_packet(
            0,
            &crate::transport::Received {
                src: c.interfaces[0].addr,
                dst: crate::packet::ALL_SPF_ROUTERS,
                payload,

                ttl: 1,
            },
            now + 2,
        );
        assert!(replies.is_empty());
        assert!(
            !a.neighbor_states()
                .iter()
                .any(|(_, rid, _)| *rid == c.router_id),
            "no neighbor forms under a password mismatch (D.5.2)"
        );

        // The established adjacency under a password change: B stops
        // authenticating correctly (forged wrong-password Hellos keep
        // arriving); within RouterDeadInterval A's Inactivity Timer
        // fires — the neighbor goes Down, the auth-only effect.
        let peer_id = b.router_id;
        for t in 1..=6u64 {
            let mut hello = make_hello(b.router_id, 0, &b.interfaces[0], AreaKind::Normal);
            hello.header.au_type = 1;
            hello.header.authentication = u64::from_be_bytes(*b"wrongpw\0");
            // Re-encode under the right checksum convention: build
            // via the packet codec (checksum computed in simple mode
            // over the auth-excluded region).
            let payload = hello.encode();
            a.on_packet(
                0,
                &crate::transport::Received {
                    src: b.interfaces[0].addr,
                    dst: crate::packet::ALL_SPF_ROUTERS,
                    payload,

                    ttl: 1,
                },
                now + t,
            );
        }
        // Quiet ticks past RouterDeadInterval (4 s).
        for t in 2..=8u64 {
            let mut oa = Vec::new();
            let mut zap2 = Vec::new();
            a.tick(now + t, &mut oa, &mut zap2);
        }
        let state = a
            .neighbor_states()
            .iter()
            .find(|(_, rid, _)| *rid == peer_id)
            .map(|(_, _, s)| *s);
        assert_eq!(
            state,
            Some(NeighborState::Down),
            "the mismatched adjacency dies via the Inactivity Timer (Down)"
        );
    }

    /// D.5.3 end to end: HMAC-SHA-256 signed packets form and keep a
    /// Full adjacency; tampered digests and replayed (older)
    /// sequences are discarded; the Down transition resets the
    /// recorded sequence (D.3).
    #[test]
    fn hmac_crypto_signs_rejects_tampering_and_replay() {
        let mut a = hmac_core("10.255.1.1", "10.77.0.1", 1, "ospfkey");
        let mut b = hmac_core("10.255.2.1", "10.77.0.2", 1, "ospfkey");
        let now = run_to_full(&mut a, &mut b, 0);
        assert!(a
            .neighbor_states()
            .iter()
            .any(|(_, _, s)| *s == NeighborState::Full));

        // A tampered payload fails the digest (D.5.3 step 3): flip
        // one body byte inside a signed hello.
        let hello = make_hello(b.router_id, 0, &b.interfaces[0], AreaKind::Normal);
        let seq = 900u32; // any non-decreasing value
        let mut signed = {
            let mut p = hello.clone();
            p.header.au_type = 2;
            p.header.authentication = crate::auth::CryptoAuthData {
                key_id: 1,
                data_len: 32,
                seq,
            }
            .to_u64();
            p.encode() // leaves the checksum 0 (au_type 2)
        };
        let mac = crate::auth::packet_mac(&signed, b"ospfkey");
        signed.extend_from_slice(&mac);
        let mut tampered = signed.clone();
        let last = tampered.len() - 5;
        tampered[last] ^= 0x01;
        let replies = a.on_packet(
            0,
            &crate::transport::Received {
                src: b.interfaces[0].addr,
                dst: crate::packet::ALL_SPF_ROUTERS,
                payload: tampered,

                ttl: 1,
            },
            now + 1,
        );
        assert!(replies.is_empty(), "tampered packet discarded");
        // The clean signed packet passes and records the sequence.
        let replies = a.on_packet(
            0,
            &crate::transport::Received {
                src: b.interfaces[0].addr,
                dst: crate::packet::ALL_SPF_ROUTERS,
                payload: signed,

                ttl: 1,
            },
            now + 2,
        );
        // A Hello needs no reply obligation; acceptance shows in the
        // recorded sequence below (and the neighbor stays up).
        assert!(replies.is_empty());
        assert_eq!(
            a.interfaces[0]
                .neighbors
                .get(&b.router_id)
                .map(|c| c.rx_crypto_seq),
            Some(900),
            "the accepted sequence is recorded (D.3)"
        );

        // Replay: an OLDER sequence is discarded even with a valid
        // MAC (D.5.3 step 2 fires before the digest).
        let older = {
            let mut p = hello;
            p.header.au_type = 2;
            p.header.authentication = crate::auth::CryptoAuthData {
                key_id: 1,
                data_len: 32,
                seq: 899,
            }
            .to_u64();
            let mut buf = p.encode();
            let mac = crate::auth::packet_mac(&buf, b"ospfkey");
            buf.extend_from_slice(&mac);
            buf
        };
        let replies = a.on_packet(
            0,
            &crate::transport::Received {
                src: b.interfaces[0].addr,
                dst: crate::packet::ALL_SPF_ROUTERS,
                payload: older,

                ttl: 1,
            },
            now + 3,
        );
        assert!(
            replies.is_empty(),
            "replayed older sequence discarded (D.5.3 step 2)"
        );
        assert_eq!(
            a.interfaces[0]
                .neighbors
                .get(&b.router_id)
                .map(|c| c.rx_crypto_seq),
            Some(900),
            "the recorded sequence did not regress"
        );

        // A wrong Key ID is discarded before any digest work.
        let wrong_id = {
            let mut p = make_hello(b.router_id, 0, &b.interfaces[0], AreaKind::Normal);
            p.header.au_type = 2;
            p.header.authentication = crate::auth::CryptoAuthData {
                key_id: 7,
                data_len: 32,
                seq: 901,
            }
            .to_u64();
            let mut buf = p.encode();
            let mac = crate::auth::packet_mac(&buf, b"ospfkey");
            buf.extend_from_slice(&mac);
            buf
        };
        let replies = a.on_packet(
            0,
            &crate::transport::Received {
                src: b.interfaces[0].addr,
                dst: crate::packet::ALL_SPF_ROUTERS,
                payload: wrong_id,

                ttl: 1,
            },
            now + 4,
        );
        assert!(
            replies.is_empty(),
            "unknown Key ID discarded (D.5.3 step 1)"
        );
    }

    /// The wire conventions (D.3/D.4.3): the trailer sits past the
    /// OSPF length, the checksum is 0, and decode_crypto splits it
    /// back off.
    #[test]
    fn crypto_wire_conventions_hold() {
        let mut a = hmac_core("10.255.1.1", "10.77.0.1", 1, "ospfkey");
        let mut out = Vec::new();
        let mut zap = Vec::new();
        a.tick(0, &mut out, &mut zap);
        let bytes =
            crate::auth::encode_for_wire(&out[0].packet.clone(), &a.interfaces[0].cfg.auth.clone());
        let length = u16::from_be_bytes([bytes[2], bytes[3]]) as usize;
        assert_eq!(
            length,
            bytes.len() - 32,
            "the OSPF length excludes the 32-byte trailer (D.3)"
        );
        assert_eq!(
            &bytes[12..14],
            &[0, 0],
            "checksum zero in crypto mode (D.4.3 step 2)"
        );
        let (packet, trailer) = Packet::decode_crypto(&bytes).unwrap();
        assert_eq!(trailer.len(), 32);
        assert_eq!(packet.header.au_type, 2);
        // The plain decoder rejects the trailer (strict framing).
        assert!(Packet::decode(&bytes).is_err());
    }

    /// The RFC 8177 key chain end to end (O-8): two chain-configured
    /// cores reach Full signing with the chain's live key; the
    /// rollover (key 1 → key 2 at t=600, different algorithms) rides
    /// through the overlapping accept window with the adjacency
    /// intact — accept-any-live/send-highest, RFC 2328 D.4.3/D.5.3;
    /// and a packet stamped with a Key ID the chain does not hold is
    /// discarded before any digest work (D.5.3 step 1).
    #[test]
    fn key_chain_signs_verifies_rejects_and_rolls_over() {
        // The chain: key 1 (HMAC-SHA-256) always live; key 2 (MD5)
        // becomes the send pick at t=600, accepted from t=600. The
        // accept overlap (key 1 still accepted) is the graceful
        // rollover's window.
        let chain_conf = "\
key chain kc1
 key 1
  key-string old-secret
  cryptographic-algorithm hmac-sha-256
  send-lifetime 0 infinite
  accept-lifetime 0 infinite
 key 2
  key-string new-secret
  cryptographic-algorithm md5
  send-lifetime 600 infinite
  accept-lifetime 600 infinite
";
        let core = |router_id: &str, addr: &str| -> Ospfd {
            let text = format!(
                "router ospf\n router-id {router_id}\n area 0.0.0.0\n  interface eth0\n   address {addr}/30\n   network-type point-to-point\n   hello-interval 1\n   dead-interval 4\n   authentication key-chain kc1\n{chain_conf}"
            );
            Ospfd::new(&parse_config(&text).unwrap()).unwrap()
        };
        let mut a = core("10.255.1.1", "10.77.0.1");
        let mut b = core("10.255.2.1", "10.77.0.2");
        // The construction resolved the chain to the live key-1 view.
        assert_eq!(
            a.interfaces[0].live_auth,
            crate::auth::AuthConfig::HmacSha256 {
                key_id: 1,
                key: b"old-secret".to_vec()
            }
        );
        let now = run_to_full(&mut a, &mut b, 0);
        assert!(a
            .neighbor_states()
            .iter()
            .any(|(_, _, s)| *s == NeighborState::Full));
        // Keep the hellos flowing every second through the rollover
        // boundary (RouterDeadInterval is 4 s — silence would flap
        // the adjacency for reasons the chain did not cause).
        let rollover = 600u64;
        let mut saw_key2_field = false;
        let mut zap = Vec::new();
        for t in (now + 1)..=(rollover + 10) {
            let mut oa = Vec::new();
            a.tick(t, &mut oa, &mut zap);
            if t > rollover {
                // The send view advanced to key 2 (MD5 — the later
                // start wins, RFC 2328 D.4.3) and the wire packet
                // carries its Figure-18 field.
                assert_eq!(
                    a.interfaces[0].live_auth,
                    crate::auth::AuthConfig::KeyedMd5 {
                        key_id: 2,
                        key: b"new-secret".to_vec()
                    },
                    "the send pick rolled over (t={t})"
                );
                for w in &oa {
                    let f = crate::auth::CryptoAuthData::from_u64(w.packet.header.authentication);
                    if w.packet.header.au_type == 2 && w.packet.header.packet_type == 1 {
                        // Fresh Hellos stamp the rolled-over key;
                        // RxmtInterval retransmissions replay the
                        // stored packet they were built from (key 1,
                        // still accepted in the overlap).
                        assert_eq!(f.key_id, 2, "fresh sends stamp the rolled-over key");
                        assert_eq!(f.data_len, 16, "MD5's Auth Data Len (D.4.3 step 4)");
                        saw_key2_field = true;
                    }
                }
            }
            pump(&mut a, &mut b, oa, t);
            let mut ob = Vec::new();
            b.tick(t, &mut ob, &mut zap);
            pump(&mut b, &mut a, ob, t);
        }
        assert!(saw_key2_field, "MD5-signed packets went on the wire");
        assert!(
            a.neighbor_states()
                .iter()
                .any(|(_, _, s)| *s == NeighborState::Full),
            "the adjacency survives the rollover"
        );
        let after = rollover + 10;

        // A packet stamped with a Key ID the chain does not hold is
        // discarded before any digest work (D.5.3 step 1).
        let hello = make_hello(b.router_id, 0, &b.interfaces[0], AreaKind::Normal);
        let wrong = {
            let mut p = hello.clone();
            p.header.au_type = 2;
            p.header.authentication = crate::auth::CryptoAuthData {
                key_id: 9,
                data_len: 32,
                seq: 5000,
            }
            .to_u64();
            let mut buf = p.encode();
            let mac = crate::auth::packet_mac(&buf, b"whatever");
            buf.extend_from_slice(&mac);
            buf
        };
        let replies = a.on_packet(
            0,
            &crate::transport::Received {
                src: b.interfaces[0].addr,
                dst: crate::packet::ALL_SPF_ROUTERS,
                payload: wrong,

                ttl: 1,
            },
            after + 1,
        );
        assert!(replies.is_empty(), "unknown Key ID discarded");

        // A validly-signed packet under a still-accepted key (key 1's
        // accept window never closed) verifies during the overlap —
        // the accept-any-live rule.
        let overlap = {
            let mut p = hello;
            p.header.au_type = 2;
            p.header.authentication = crate::auth::CryptoAuthData {
                key_id: 1,
                data_len: 32,
                seq: 5001,
            }
            .to_u64();
            let mut buf = p.encode();
            let mac = crate::auth::packet_mac(&buf, b"old-secret");
            buf.extend_from_slice(&mac);
            buf
        };
        let replies = a.on_packet(
            0,
            &crate::transport::Received {
                src: b.interfaces[0].addr,
                dst: crate::packet::ALL_SPF_ROUTERS,
                payload: overlap,

                ttl: 1,
            },
            after + 2,
        );
        assert!(replies.is_empty(), "hellos need no reply");
        assert_eq!(
            a.interfaces[0]
                .neighbors
                .get(&b.router_id)
                .map(|c| c.rx_crypto_seq),
            Some(5001),
            "key 1 still verifies during the accept overlap (8177 2.3)"
        );
    }

    // ---- incremental SPF (§16.5/§16.6, N3 M4) -----------------------

    fn spf_runs(core: &Ospfd, area: u32) -> u64 {
        core.areas.get(&area).map(|a| a.spf_runs).unwrap_or(0)
    }

    /// A random router-LSA for the mutation sequences (the W5B
    /// fixed-seed convention; links may dangle — one-way edges are
    /// legal input the SPT simply drops).
    fn random_router_lsa(seed: &mut u64, rid: u32, seq: u32) -> Lsa {
        // XorShift64 — the same convention as spf.rs's tests.
        fn next(state: &mut u64) -> u64 {
            *state ^= *state << 13;
            *state ^= *state >> 7;
            *state ^= *state << 17;
            *state
        }
        let rng = &mut || next(seed);
        let n_links = (rng() % 4) as usize;
        let mut links = Vec::new();
        for i in 0..n_links {
            let peer = 10 + (rng() % 6) as u32;
            links.push(crate::lsa::RouterLink {
                link_id: crate::lsa::LinkStateId(
                    Ipv4Addr::new(10, 200, (peer % 256) as u8, 1).into(),
                ),
                link_data: u32::from(Ipv4Addr::new(172, 31, rid as u8, (i + 1) as u8)),
                link_type: if rng() % 2 == 0 {
                    crate::lsa::LinkType::PointToPoint
                } else {
                    crate::lsa::LinkType::Stub
                },
                metric: (1 + rng() % 9) as u16,
                tos: vec![],
            });
        }
        Lsa {
            header: crate::lsa::LsaHeader {
                ls_age: 1,
                options: Options(Options::E),
                ls_type: LsaType::ROUTER,
                link_state_id: crate::lsa::LinkStateId(rid),
                adv_router: RouterId(rid),
                seq,
                checksum: 0,
                length: 0,
            },
            body: crate::lsa::LsaBody::Router(crate::lsa::RouterLsa {
                v_bit: false,
                e_bit: rng() % 4 == 0,
                b_bit: rng() % 4 == 0,
                nt_bit: false,
                links,
            }),
        }
        .with_computed_header()
    }

    /// Only the CHANGED area recomputes its §16.1: the unchanged
    /// area's Dijkstra run count does not move.
    #[test]
    fn only_changed_areas_recompute() {
        let mut cores = vec![abr_core(), area0_core(), area1_core(false)];
        let now = run_multi(&mut cores, 0, 8);
        let abr = &mut cores[0];
        // Drain any deferred (MinLSInterval) originations so the
        // baseline is quiet.
        let mut o = Vec::new();
        let mut z = Vec::new();
        abr.tick(now + 1, &mut o, &mut z);
        let (runs0, runs1) = (spf_runs(abr, 0), spf_runs(abr, 1));
        assert!(runs0 > 0 && runs1 > 0, "both areas computed at least once");
        // A topology change in area 1 only.
        let mut seed = 7u64;
        let lsa = random_router_lsa(&mut seed, 0x0a0a_0a0a, 5);
        let mut out = Vec::new();
        let mut zap = Vec::new();
        {
            let state = abr.areas.get_mut(&1).unwrap();
            let _ = state.lsdb.install(lsa, true, now + 2);
        }
        abr.mark_spf_dirty(1, now + 2);
        abr.tick(now + 3, &mut out, &mut zap);
        assert_eq!(spf_runs(abr, 1), runs1 + 1, "the changed area recomputed");
        assert_eq!(spf_runs(abr, 0), runs0, "the untouched area did not");
    }

    /// The AS-scope class (§16.5/§16.6): a type-5 change reruns the
    /// route walk with NO §16.1 recompute at all.
    #[test]
    fn type5_change_updates_routes_without_spt_recompute() {
        let mut cores = vec![abr_core(), area0_core()];
        let now = run_multi(&mut cores, 0, 8);
        let peer_id = cores[1].router_id;
        let abr = &mut cores[0];
        let (runs0, runs1) = (spf_runs(abr, 0), spf_runs(abr, 1));
        let ext = crate::origination::build_external_lsa(
            peer_id,
            ip("198.51.100.0"),
            ip("255.255.255.0"),
            20,
            true,
        )
        .with_computed_header();
        {
            let state = abr.areas.get_mut(&0).unwrap();
            let _ = state.lsdb.install(ext, true, now + 1);
        }
        abr.mark_table_dirty();
        let mut out = Vec::new();
        let mut zap = Vec::new();
        abr.tick(now + 2, &mut out, &mut zap);
        assert_eq!(spf_runs(abr, 0), runs0, "area 0's SPT untouched (§16.6)");
        assert_eq!(spf_runs(abr, 1), runs1, "area 1's SPT untouched");
        assert!(
            abr.routes.contains_key("198.51.100.0/24"),
            "the external route still installed (the walk ran)"
        );
    }

    /// Per-area backoff independence: a flap storm in one area backs
    /// ITS scheduler off (FRR-parity 50 ms increments) while a quiet
    /// area's single change runs at the initial delay.
    #[test]
    fn per_area_backoff_is_independent() {
        let mut abr = abr_core();
        let mut zap = Vec::new();
        let mut out = Vec::new();
        abr.tick(0, &mut out, &mut zap);
        // Prime: one run each at t=0 (initial delay 0).
        let (_, runs1) = (spf_runs(&abr, 0), spf_runs(&abr, 1));
        // Refresh area 0's last_run at t=10 first (one change, one
        // run), so the storm below arrives OUTSIDE the idle window.
        let mut seed = 1u64;
        let lsa = random_router_lsa(&mut seed, 0x0b0b_0b01, 3);
        {
            let state = abr.areas.get_mut(&0).unwrap();
            let _ = state.lsdb.install(lsa, true, 10);
        }
        abr.mark_spf_dirty(0, 10);
        let mut o = Vec::new();
        let mut z = Vec::new();
        abr.maybe_spf(10, &mut o, &mut z);
        let runs0 = spf_runs(&abr, 0);
        // 20 rapid topology changes in area 0 within the same
        // instant: current_delay climbs to 1000 ms — due at t=11 s.
        for i in 0..20u32 {
            let mut seed = (i + 1) as u64;
            let lsa = random_router_lsa(&mut seed, 0x0b0b_0b00 + i, 3);
            {
                let state = abr.areas.get_mut(&0).unwrap();
                let _ = state.lsdb.install(lsa, true, 10);
            }
            abr.mark_spf_dirty(0, 10);
        }
        // One quiet change in area 1 at the same instant.
        let mut seed = 99u64;
        let lsa = random_router_lsa(&mut seed, 0x0c0c_0c0c, 3);
        {
            let state = abr.areas.get_mut(&1).unwrap();
            let _ = state.lsdb.install(lsa, true, 10);
        }
        abr.mark_spf_dirty(1, 10);
        let mut out = Vec::new();
        let mut zap2 = Vec::new();
        abr.maybe_spf(10, &mut out, &mut zap2);
        assert_eq!(
            spf_runs(&abr, 1),
            runs1 + 1,
            "the single-change area ran at the initial delay"
        );
        assert_eq!(
            spf_runs(&abr, 0),
            runs0,
            "the storming area's backoff deferred its run"
        );
        // Its due time arrives a second later.
        let mut out = Vec::new();
        let mut zap3 = Vec::new();
        abr.maybe_spf(11, &mut out, &mut zap3);
        assert_eq!(spf_runs(&abr, 0), runs0 + 1, "the deferred run fired");
    }

    /// The agreement property (W5B fixed-seed convention): randomized
    /// LSDB mutation sequences produce IDENTICAL routing tables
    /// under the incremental scheduler and a forced-full twin.
    #[test]
    fn property_incremental_and_full_recompute_agree() {
        struct XorShift(u64);
        impl XorShift {
            fn next(&mut self) -> u64 {
                self.0 ^= self.0 << 13;
                self.0 ^= self.0 >> 7;
                self.0 ^= self.0 << 17;
                self.0
            }
        }
        for seed in [0x0050_0466_0170_0310u64, 0x7ea1_0002_dead_0003] {
            let mut rng = XorShift(seed);
            let mut incremental = abr_core();
            let mut full = abr_core();
            let mut now = 1u64;
            for step in 0..60u32 {
                let area = u32::from(rng.next().is_multiple_of(2));
                let rid = 0x0a64_0000 + (rng.next() % 8) as u32;
                let lsa = random_router_lsa(&mut rng.0, rid, 0x8000_0001u32 + step);
                for core in [&mut incremental, &mut full] {
                    let state = core.areas.get_mut(&area).unwrap();
                    let _ = state.lsdb.install(lsa.clone(), true, now);
                }
                // The incremental core dirties only the changed
                // area; the twin forces a full recompute everywhere.
                // The evaluation clock jumps past the throttle's
                // maximum (5 s) each step, so both schedulers leave
                // their idle cycles and run at the initial delay —
                // the comparison is about WHAT recomputes, not when.
                incremental.mark_spf_dirty(area, now);
                full.mark_spf_dirty(0, now);
                full.mark_spf_dirty(1, now);
                now += 10;
                let mut o1 = Vec::new();
                let mut z1 = Vec::new();
                let mut o2 = Vec::new();
                let mut z2 = Vec::new();
                incremental.maybe_spf(now, &mut o1, &mut z1);
                full.maybe_spf(now, &mut o2, &mut z2);
                assert_eq!(
                    incremental.routes, full.routes,
                    "seed {seed:016x} step {step}: tables diverged"
                );
            }
            // And the incremental core genuinely skipped work: the
            // untouched area ran far fewer §16.1 computations.
            let (inc0, inc1) = (spf_runs(&incremental, 0), spf_runs(&incremental, 1));
            let (full0, full1) = (spf_runs(&full, 0), spf_runs(&full, 1));
            assert_eq!(full0, full1, "the twin recomputed both areas every step");
            assert!(
                inc0 + inc1 < full0 + full1,
                "incremental ({inc0}+{inc1}) did less work than full ({full0}+{full1})"
            );
        }
    }

    // ---- virtual links (§15/§D.3, N3 M5) -----------------------------

    fn vlabr(router_id: &str, a0_addr: &str, a1_addr: &str, peer: &str) -> Ospfd {
        let text = format!(
            "router ospf\n router-id {router_id}\n area 0.0.0.0\n  interface eth0\n   address {a0_addr}/30\n   network-type point-to-point\n   hello-interval 1\n   dead-interval 4\n area 0.0.0.1\n  interface eth1\n   address {a1_addr}/30\n   network-type point-to-point\n   hello-interval 1\n   dead-interval 4\n area 0.0.0.1 virtual-link {peer}\n"
        );
        Ospfd::new(&parse_config(&text).unwrap()).unwrap()
    }

    /// The §15 partitioned backbone: R1 and R2 split area 0 between
    /// them, joined only by the virtual link over area 1. R3 hangs
    /// off R1's half, R4 off R2's — routes cross only through the
    /// virtual link: the transit-area adjacency resolves the
    /// endpoint (§15), the vlink adjacency forms over unicast
    /// backbone-area packets, the backbone router-LSAs grow type-4
    /// links (§D.3), and the transit router-LSAs set the V-bit.
    #[test]
    fn virtual_link_joins_a_partitioned_backbone() {
        let mut cores = vec![
            vlabr("10.255.1.1", "10.10.0.1", "10.20.0.1", "10.255.2.1"),
            vlabr("10.255.2.1", "10.30.0.1", "10.20.0.2", "10.255.1.1"),
            area0_core(), // 10.10.0.2, R3
            area0_core(), // 10.10.0.2 -> patch to 10.30.0.2, R4
        ];
        // Patch the fourth core onto R2's half (its own address).
        {
            let r4 = "router ospf\n router-id 10.255.4.1\n area 0.0.0.0\n  interface eth0\n   address 10.30.0.2/30\n   network-type point-to-point\n   hello-interval 1\n   dead-interval 4\n";
            cores[3] = Ospfd::new(&parse_config(r4).unwrap()).unwrap();
        }
        // R3's core from area0_core() has the right address already
        // (10.10.0.2).

        // Delivery: unicast by destination address (any interface of
        // any core — virtual-link packets ride the transit wire but
        // carry the backbone area); multicast to every core with an
        // interface in the packet's area.
        fn deliver_vl(
            cores: &mut [Ospfd],
            from: usize,
            outs: &[WireOut],
            now: u64,
            queue: &mut Vec<(usize, Vec<WireOut>)>,
        ) {
            for w in outs {
                let src = cores[from].interfaces[w.iface].addr;
                let payload = crate::auth::encode_for_wire(
                    &w.packet,
                    &cores[from].interfaces[w.iface].cfg.auth,
                );
                let pkt_area = w.packet.header.area_id;
                let dst = match w.to {
                    WireTo::Unicast(d) => Some(d),
                    _ => None,
                };
                for (i, core) in cores.iter_mut().enumerate() {
                    if i == from {
                        continue;
                    }
                    let Some(rx) = core.interfaces.iter().position(|x| match dst {
                        Some(d) => x.addr == d,
                        None => x.area == pkt_area,
                    }) else {
                        continue;
                    };
                    let replies = core.on_packet(
                        rx,
                        &crate::transport::Received {
                            src,
                            dst: crate::packet::ALL_SPF_ROUTERS,
                            payload: payload.clone(),

                            ttl: 1,
                        },
                        now,
                    );
                    if !replies.is_empty() {
                        queue.push((i, replies));
                    }
                }
            }
        }

        // Settle loop (the run_multi digest shape).
        let mut now = 0u64;
        let mut queue: Vec<(usize, Vec<WireOut>)> = Vec::new();
        let mut zap: Vec<crate::zedge::ZedgeCommand> = Vec::new();
        let digest = |cores: &[Ospfd]| -> u64 {
            let mut h: u64 = 0x9e37_79b9;
            for core in cores {
                for iface in &core.interfaces {
                    for (rid, c) in &iface.neighbors {
                        h = h.wrapping_mul(31).wrapping_add(rid.0 as u64);
                        h = h.wrapping_mul(31).wrapping_add(c.state() as u64);
                    }
                }
                for state in core.areas.values() {
                    for entry in state.lsdb.all() {
                        h = h.wrapping_mul(31).wrapping_add(entry.lsa.header.seq as u64);
                    }
                }
                h = h.wrapping_mul(31).wrapping_add(core.routes.len() as u64);
            }
            h
        };
        let mut outs: Vec<Vec<WireOut>> = cores.iter_mut().map(|_| Vec::new()).collect();
        for (i, o) in outs.iter_mut().enumerate() {
            cores[i].tick(now, o, &mut zap);
        }
        for (i, o) in outs.iter_mut().enumerate() {
            if !o.is_empty() {
                let taken = std::mem::take(o);
                deliver_vl(&mut cores, i, &taken, now, &mut queue);
            }
        }
        let mut last = digest(&cores);
        let mut quiet = 0u64;
        for _ in 0..700 {
            while !queue.is_empty() {
                let batch = std::mem::take(&mut queue);
                for (from, o) in batch {
                    deliver_vl(&mut cores, from, &o, now, &mut queue);
                }
            }
            let d = digest(&cores);
            if d == last {
                quiet += 1;
                if quiet >= 12 {
                    break;
                }
            } else {
                quiet = 0;
                last = d;
            }
            now += 1;
            let mut outs: Vec<Vec<WireOut>> = cores.iter_mut().map(|_| Vec::new()).collect();
            for (i, o) in outs.iter_mut().enumerate() {
                cores[i].tick(now, o, &mut zap);
            }
            for (i, o) in outs.iter().enumerate() {
                if !o.is_empty() {
                    deliver_vl(&mut cores, i, o, now, &mut queue);
                }
            }
        }
        let (r1, r2, r3, r4) = (0usize, 1, 2, 3);

        // The transit adjacency is Full and the vlink resolved + Full.
        let vlfull = |core: &Ospfd, peer: RouterId| {
            core.interfaces
                .iter()
                .find(|i| i.virtual_link)
                .and_then(|i| i.neighbors.get(&peer))
                .is_some_and(|c| c.state() == NeighborState::Full)
        };
        assert!(vlfull(&cores[r1], cores[r2].router_id), "R1's vlink Full");
        assert!(vlfull(&cores[r2], cores[r1].router_id), "R2's vlink Full");
        assert_eq!(
            cores[r1]
                .interfaces
                .iter()
                .find(|i| i.virtual_link)
                .unwrap()
                .vlink_peer_ip,
            Some(ip("10.20.0.2")),
            "§15: the endpoint resolved from the area-1 routing table"
        );

        // §D.3: the backbone router-LSAs carry the type-4 link.
        let r1_a0 = cores[r1]
            .areas
            .get(&0)
            .unwrap()
            .lsdb
            .get(&LsaKey {
                ls_type: LsaType::ROUTER,
                link_state_id: crate::lsa::LinkStateId(cores[r1].router_id.0),
                adv_router: cores[r1].router_id,
            })
            .unwrap()
            .lsa
            .clone();
        let crate::lsa::LsaBody::Router(body) = &r1_a0.body else {
            panic!()
        };
        assert!(
            body.links
                .iter()
                .any(|l| l.link_type == crate::lsa::LinkType::Virtual
                    && l.link_id.0 == cores[r2].router_id.0),
            "R1's backbone router-LSA carries the type-4 virtual link"
        );
        // The V-bit rides the TRANSIT area's router-LSA (§A.4.2).
        let r1_a1 = cores[r1]
            .areas
            .get(&1)
            .unwrap()
            .lsdb
            .get(&LsaKey {
                ls_type: LsaType::ROUTER,
                link_state_id: crate::lsa::LinkStateId(cores[r1].router_id.0),
                adv_router: cores[r1].router_id,
            })
            .unwrap()
            .lsa
            .clone();
        let crate::lsa::LsaBody::Router(body1) = &r1_a1.body else {
            panic!()
        };
        assert!(
            body1.v_bit,
            "the transit-area router-LSA sets V (§16.1 step 2)"
        );

        // The proof of the whole milestone: R3 routes R4's half of
        // the backbone and vice versa — through the virtual link.
        assert!(
            cores[r3].routes.contains_key("10.30.0.0/30"),
            "R3 routes the far half of the partitioned backbone: {:?}",
            cores[r3].routes.keys().collect::<Vec<_>>()
        );
        assert!(
            cores[r4].routes.contains_key("10.10.0.0/30"),
            "R4 routes the near half"
        );
        let _ = r2;
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
            let entry = lsdb_of(core)
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

    // --- SAVNET agent hooks (experimental-savnet only) ---

    #[cfg(feature = "experimental-savnet")]
    mod savnet_hooks {
        use super::*;
        use std::sync::Mutex as StdMutex;

        /// An agent that records every event (the contract-test shape
        /// from the sav crate, local copy so the wiring is proven
        /// against the daemon's own call sites).
        #[derive(Default)]
        struct RecordingAgent {
            events: StdMutex<Vec<sav::agent::SavAgentEvent>>,
        }

        impl sav::agent::SavAgent for RecordingAgent {
            fn on_event(&self, event: sav::agent::SavAgentEvent) {
                self.events.lock().unwrap().push(event);
            }
            fn binding_suggestions(&self) -> Vec<sav::agent::SavBindingSuggestion> {
                Vec::new()
            }
        }

        /// No agent hosted by default (the anchors' default-none
        /// shape): the flag compiles the hooks, but nothing hosts an
        /// agent in tonight's multi-process deployment.
        #[test]
        fn the_agent_defaults_to_none() {
            let core = core_for("10.255.1.1", "eth0", "10.77.0.1");
            assert!(core.sav_agent().is_none());
        }

        /// Two cores pumped to mutual Full adjacency with agents
        /// hosted: each daemon reports the adjacency transition (up,
        /// with the peer's address and router-id bits) and the changed
        /// LSAs the InstallAndFlood arm installed — the other's
        /// type-1 router-LSA at minimum.
        #[test]
        fn adjacency_and_lsa_events_report_over_a_real_exchange() {
            let agent_a = std::sync::Arc::new(RecordingAgent::default());
            let agent_b = std::sync::Arc::new(RecordingAgent::default());
            let mut a = core_for("10.255.1.1", "eth0", "10.77.0.1");
            let mut b = core_for("10.255.2.1", "eth0", "10.77.0.2");
            a.set_sav_agent(
                std::sync::Arc::clone(&agent_a) as std::sync::Arc<dyn sav::agent::SavAgent>
            );
            b.set_sav_agent(
                std::sync::Arc::clone(&agent_b) as std::sync::Arc<dyn sav::agent::SavAgent>
            );
            for core in [&mut a, &mut b] {
                core.interfaces[0]
                    .fsm
                    .fire(crate::iface::InterfaceEvent::InterfaceUp);
            }
            run_to_full(&mut a, &mut b, 0);

            for (agent, me, other_addr, other_id) in [
                (&agent_a, "A", "10.77.0.2", "10.255.2.1"),
                (&agent_b, "B", "10.77.0.1", "10.255.1.1"),
            ] {
                let events = agent.events.lock().unwrap();
                // The adjacency-up transition for the other router
                // (its interface address and router-id bits).
                assert!(
                    events.iter().any(|event| matches!(
                        event,
                        sav::agent::SavAgentEvent::AdjacencyUp { peer, .. }
                            if peer.address == ip(other_addr)
                                && peer.remote_id == u32::from(ip(other_id))
                    )),
                    "{me}: adjacency up reported with the peer identity"
                );
                // The changed-LSA feed: the other's router-LSA
                // (type 1) arrived through the InstallAndFlood arm.
                assert!(
                    events.iter().any(|event| matches!(
                        event,
                        sav::agent::SavAgentEvent::LsaChanged { ls_type, adv_router, .. }
                            if *ls_type == 1 && *adv_router == ip(other_id)
                    )),
                    "{me}: the peer's router-LSA change reported"
                );
            }
        }

        /// Equivalence inside the feature-on build: with NO agent
        /// hosted, the same exchange settles to Full exactly as the
        /// feature-off daemon does (the hooks never fire — the
        /// default-off contract's in-flag mirror).
        #[test]
        fn without_a_hosted_agent_the_exchange_is_unchanged() {
            let mut a = core_for("10.255.1.1", "eth0", "10.77.0.1");
            let mut b = core_for("10.255.2.1", "eth0", "10.77.0.2");
            for core in [&mut a, &mut b] {
                core.interfaces[0]
                    .fsm
                    .fire(crate::iface::InterfaceEvent::InterfaceUp);
            }
            run_to_full(&mut a, &mut b, 0);
            assert!(a.sav_agent().is_none() && b.sav_agent().is_none());
        }
    }
}
