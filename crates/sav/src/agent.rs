//! The SAVNET agent interface — the in-process hooks protocol anchors
//! (bgpd's `on_message`, ospfd's `InstallAndFlood` products) call to
//! report SAV-relevant events and from which binding suggestions are
//! received. Everything here is behind the crate's
//! `experimental-savnet` feature (default OFF) per the repo AGENTS.md
//! SAVNET rules: draft-dependent wire protocols (intra-domain
//! IGP/BGP signaling, inter-domain) stay OUT until drafts stabilize —
//! this interface is **in-process only**: no serialization, no
//! sockets, no wire codecs (see docs/protocols/savnet.md for the
//! design note and what stays out).
//!
//! # Shape
//!
//! The trait is object-safe (`dyn SavAgent`) so an anchor holds one
//! optional shared handle ([`std::sync::Arc<dyn SavAgent>`]) and
//! calls it at its hook points; the events are owned values over
//! common/sav types only ([`IpPrefix`], [`IpAddr`], ifindex `u32`,
//! `Ipv4Addr` LSA identity) — each anchor translates its
//! protocol-native data at the call site, keeping the SAV layer free
//! of BGP/OSPF types (the dependency direction the architecture
//! pins: `common` and the protocol crates never depend on `sav`'s
//! internals, and nothing here needs theirs).
//!
//! Two directions, matching the anchor hooks' needs:
//!
//! - **Events in** ([`SavAgent::on_event`]): a route
//!   installed/withdrawn (BGP Adj-RIB-In granularity — pre-best-path,
//!   the RFC 8704 §3.1 candidate space), an LSA installed with
//!   changed contents (the IGP-side LSDB invalidation feed), or a
//!   peer adjacency up/down.
//! - **Suggestions out** ([`SavAgent::binding_suggestions`]): the
//!   agent's current source-prefix → ingress-interface proposals.
//!
//! # The default agent (monitor-only)
//!
//! [`MonitorAgent`] is the default implementation savd hosts: it logs
//! every event, derives adjacency-based suggestions (the
//! EFP-uRPF-adjacent heuristic: a prefix announced by a peer whose
//! adjacency names an interface is suggested for that interface,
//! RFC 8704 §3's grouping intuition), and — per the repo's
//! log-before-drop rule — **nothing it suggests is ever enforced**:
//! savd's evaluate logs each suggestion and moves on. Turning a
//! suggestion into a [`crate::Binding`] is deliberately not wired:
//! that is a draft-dependent decision (which confirmation protocol,
//! TTL policy, precedence slot) the owner has not made.
//!
//! # Process topology (honest scoping)
//!
//! bgpd, ospfd, and savd are separate processes in today's interim
//! multi-process shape, and this interface is in-process by design —
//! so an anchor's hook calls reach an agent instance inside the
//! ANCHOR's process (tests compose them in-process today; the
//! architecture's single-binary default deployment makes the
//! composition production-real tomorrow). savd's hosted agent
//! additionally observes savd's own ZAPI RIB view (the [`SavEventSource::RibView`]
//! events, no peer granularity) so the default host has a real feed
//! in production; the adjacency-derived suggestion path needs
//! anchor-side events and therefore produces suggestions only where
//! the composition is in-process. No transport is added to bridge
//! the processes — that would be a wire protocol by another name.

use std::collections::{BTreeMap, BTreeSet};
use std::net::{IpAddr, Ipv4Addr};
use std::sync::Mutex;

use common::IpPrefix;
use tracing::info;

/// How many events the [`MonitorAgent`] retains for suggestion
/// derivation — a bounded window, so a long-lived daemon's agent
/// state stays constant-bounded (the oldest events drop; suggestions
/// are best-effort observations, never authoritative state).
const MONITOR_WINDOW: usize = 1024;

/// Which protocol anchor an event came from (the SAV layer's
/// provenance axis; anchors translate their native identity into it).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum SavProtocol {
    /// bgpd (peer identity = the BGP neighbor).
    Bgp,
    /// ospfd (peer identity = the OSPF neighbor).
    Ospf,
}

impl std::fmt::Display for SavProtocol {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            SavProtocol::Bgp => "bgp",
            SavProtocol::Ospf => "ospf",
        })
    }
}

/// A peer/adjacency identity as the anchors report it: the session
/// address plus one protocol-native identifier (BGP remote AS, OSPF
/// router ID) — opaque to the SAV layer.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SavPeer {
    /// The peer's address on the session/network.
    pub address: IpAddr,
    /// The protocol's own identifier for the peer (remote AS number,
    /// router ID bits) — carried opaque.
    pub remote_id: u32,
}

/// Where a route event came from.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum SavEventSource {
    /// bgpd's Adj-RIB-In (announce/withdraw at `on_message`'s UPDATE
    /// arm — pre-best-path, the RFC 8704 candidate space).
    Bgp(SavPeer),
    /// ospfd's LSDB (an LSA installed with changed contents — the
    /// `InstallAndFlood` products; the IGP-side invalidation feed).
    Ospf(SavPeer),
    /// savd's own ZAPI RIB view (redistribution pushes; no peer
    /// granularity — the default host's production feed).
    RibView,
}

impl SavEventSource {
    /// The peer identity, when the source has one.
    pub fn peer(&self) -> Option<&SavPeer> {
        match self {
            SavEventSource::Bgp(peer) | SavEventSource::Ospf(peer) => Some(peer),
            SavEventSource::RibView => None,
        }
    }
}

impl std::fmt::Display for SavEventSource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SavEventSource::Bgp(peer) => {
                write!(f, "bgp peer {} as{}", peer.address, peer.remote_id)
            }
            SavEventSource::Ospf(peer) => {
                write!(f, "ospf peer {} rtr{}", peer.address, peer.remote_id)
            }
            SavEventSource::RibView => f.write_str("rib-view"),
        }
    }
}

/// One SAV-relevant event an anchor reports. Owned values over
/// common/sav types only — the anchors translate protocol-native data
/// at the call site.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SavAgentEvent {
    /// A route was installed into the anchor's pre-best-path view
    /// (BGP announce) or the daemon observed one arrive (savd's ZAPI
    /// view). `nexthop` is the protocol next hop when the anchor
    /// knows one.
    RouteInstalled {
        source: SavEventSource,
        prefix: IpPrefix,
        nexthop: Option<IpAddr>,
    },
    /// A route left the anchor's view (BGP withdraw / ZAPI del).
    RouteWithdrawn {
        source: SavEventSource,
        prefix: IpPrefix,
    },
    /// An LSA was installed with changed contents (ospfd's
    /// `InstallAndFlood` product — the LSDB invalidation the IGP-side
    /// SAVNET designs key on). Identity is the OSPF LSA triple.
    LsaChanged {
        peer: SavPeer,
        ls_type: u16,
        link_state_id: Ipv4Addr,
        adv_router: Ipv4Addr,
    },
    /// A peer adjacency came up (BGP Established; OSPF Full).
    AdjacencyUp {
        protocol: SavProtocol,
        peer: SavPeer,
        /// The adjacency's interface when the anchor knows it
        /// (ospfd's interface model carries no kernel ifindex yet —
        /// `None` tonight).
        ifindex: Option<u32>,
    },
    /// A peer adjacency went down.
    AdjacencyDown {
        protocol: SavProtocol,
        peer: SavPeer,
    },
}

impl std::fmt::Display for SavAgentEvent {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SavAgentEvent::RouteInstalled {
                source,
                prefix,
                nexthop,
            } => match nexthop {
                Some(nexthop) => write!(f, "route {prefix} installed via {nexthop} from {source}"),
                None => write!(f, "route {prefix} installed from {source}"),
            },
            SavAgentEvent::RouteWithdrawn { source, prefix } => {
                write!(f, "route {prefix} withdrawn from {source}")
            }
            SavAgentEvent::LsaChanged {
                peer,
                ls_type,
                link_state_id,
                adv_router,
            } => write!(
                f,
                "lsa type-{ls_type} {link_state_id} adv {adv_router} changed from ospf peer {}",
                peer.address
            ),
            SavAgentEvent::AdjacencyUp {
                protocol,
                peer,
                ifindex,
            } => match ifindex {
                Some(ifindex) => write!(
                    f,
                    "adjacency up {protocol} peer {} as/if#{}",
                    peer.address, ifindex
                ),
                None => write!(f, "adjacency up {protocol} peer {}", peer.address),
            },
            SavAgentEvent::AdjacencyDown { protocol, peer } => {
                write!(f, "adjacency down {protocol} peer {}", peer.address)
            }
        }
    }
}

/// One binding suggestion: the agent proposes that sources inside
/// `prefix` may legitimately arrive on `ifindexes`. A suggestion is
/// an *observation for the operator*, never an enforcement input:
/// the monitor-only contract (log-before-drop) means nothing acts on
/// it without explicit operator config, and no landed path turns it
/// into a [`crate::Binding`] — that is deliberately behind the
/// draft-stabilization gate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SavBindingSuggestion {
    /// The source prefix the suggestion covers.
    pub prefix: IpPrefix,
    /// The ingress interfaces the agent proposes (sorted, deduped).
    pub ifindexes: Vec<u32>,
    /// The announcing source (provenance for the operator).
    pub source: SavEventSource,
}

impl std::fmt::Display for SavBindingSuggestion {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let ifindexes: Vec<String> = self.ifindexes.iter().map(|i| format!("if#{i}")).collect();
        write!(
            f,
            "{} -> [{}] (from {})",
            self.prefix,
            ifindexes.join(", "),
            self.source
        )
    }
}

/// The SAVNET agent interface: what the protocol anchors call.
/// Object-safe, `Send + Sync` — an anchor holds one optional shared
/// handle and calls it at its hook points (feature-gated at the
/// anchors' side too).
pub trait SavAgent: Send + Sync {
    /// Report one SAV-relevant event. Must not panic on unordered
    /// input (a Down before its Up, a withdraw before the install).
    fn on_event(&self, event: SavAgentEvent);

    /// The agent's current binding suggestions (monitor-only
    /// observations; deterministic order — sorted by prefix).
    fn binding_suggestions(&self) -> Vec<SavBindingSuggestion>;
}

/// The default agent savd hosts: **monitor-only**. Every event logs;
/// suggestions derive from the recorded events by the
/// EFP-uRPF-adjacent adjacency heuristic (a prefix announced by a
/// peer whose adjacency names an interface is suggested for that
/// interface — RFC 8704 §3's grouping intuition at adjacency
/// granularity), and nothing enforces them: the log-before-drop
/// rule. Callers log each suggestion ([`SavDaemon`]'s evaluate does)
/// and move on.
///
/// The heuristic needs adjacency events carrying an interface, which
/// only the anchor-side feeds produce — savd's own production feed
/// ([`SavEventSource::RibView`]) has no peer granularity, so a
/// production savd agent records and logs events but suggests
/// nothing tonight (disclosed in the module docs: no transport
/// bridges the processes, by design).
pub struct MonitorAgent {
    /// The bounded event window (see [`MONITOR_WINDOW`]).
    events: Mutex<Vec<SavAgentEvent>>,
}

impl MonitorAgent {
    /// An empty agent.
    pub fn new() -> Self {
        Self {
            events: Mutex::new(Vec::new()),
        }
    }

    /// The retained event window, oldest first (bounded; the
    /// test/inspection surface — suggestions derive from the same
    /// replay).
    pub fn events(&self) -> Vec<SavAgentEvent> {
        self.events.lock().unwrap().clone()
    }
}

impl Default for MonitorAgent {
    fn default() -> Self {
        Self::new()
    }
}

impl SavAgent for MonitorAgent {
    fn on_event(&self, event: SavAgentEvent) {
        info!(event = %event, "savd: savnet agent event (monitor-only)");
        let mut events = self.events.lock().unwrap();
        if events.len() >= MONITOR_WINDOW {
            // Drop the oldest half — amortized bounded growth.
            let split = events.len() - MONITOR_WINDOW / 2;
            events.drain(..split);
        }
        events.push(event);
    }

    fn binding_suggestions(&self) -> Vec<SavBindingSuggestion> {
        let events = self.events.lock().unwrap();
        // Replay the window into live state: the adjacency map (peer
        // address -> interface; Up with an interface sets, Down
        // clears) and the installed set ((source, prefix) — install
        // sets, withdraw clears; unordered input tolerated: a clear
        // of something absent is a no-op).
        let mut adjacency: BTreeMap<IpAddr, u32> = BTreeMap::new();
        let mut installed: BTreeSet<(SavEventSource, IpPrefix)> = BTreeSet::new();
        for event in events.iter() {
            match event {
                SavAgentEvent::AdjacencyUp {
                    peer,
                    ifindex: Some(ifindex),
                    ..
                } => {
                    adjacency.insert(peer.address, *ifindex);
                }
                SavAgentEvent::AdjacencyDown { peer, .. } => {
                    adjacency.remove(&peer.address);
                }
                SavAgentEvent::RouteInstalled { source, prefix, .. } => {
                    installed.insert((source.clone(), *prefix));
                }
                SavAgentEvent::RouteWithdrawn { source, prefix } => {
                    installed.remove(&(source.clone(), *prefix));
                }
                // LSA changes feed LSDB-aware agents (draft-dependent
                // work); the adjacency heuristic does not consume them.
                SavAgentEvent::LsaChanged { .. } => {}
                // An Up without an interface leaves the adjacency
                // interface-unknown: nothing to suggest on.
                SavAgentEvent::AdjacencyUp { ifindex: None, .. } => {}
            }
        }
        // The suggestion set: one per (announcing peer, prefix) pair
        // whose adjacency names an interface; per-prefix ifindex
        // unions across announcing peers (the EFP-uRPF "same origin,
        // any receiving interface" intuition).
        let mut per_prefix: BTreeMap<IpPrefix, BTreeSet<u32>> = BTreeMap::new();
        let mut provenance: BTreeMap<IpPrefix, SavEventSource> = BTreeMap::new();
        for (source, prefix) in &installed {
            let Some(peer) = source.peer() else {
                continue; // RibView: no peer granularity, no suggestion
            };
            let Some(&ifindex) = adjacency.get(&peer.address) else {
                continue; // adjacency interface unknown (or gone)
            };
            per_prefix.entry(*prefix).or_default().insert(ifindex);
            // Deterministic provenance: the first announcing source
            // in (source, prefix) order names the suggestion.
            provenance.entry(*prefix).or_insert_with(|| source.clone());
        }
        per_prefix
            .into_iter()
            .map(|(prefix, ifindexes)| SavBindingSuggestion {
                prefix,
                ifindexes: ifindexes.into_iter().collect(),
                source: provenance.remove(&prefix).expect("prefix present"),
            })
            .collect()
    }
}
