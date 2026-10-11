//! SAVNET agent contract tests (experimental-savnet only — this file
//! compiles to nothing in the default build): the interface's
//! monitor-only contract with a mock anchor, i.e. a fake bgpd/ospfd
//! call site that holds the agent the way the anchors will
//! (`Arc<dyn SavAgent>`) and fires the anchor-shaped event sequences
//! at it.
//!
//! The contract under test (docs/protocols/savnet.md):
//! - events are recorded in order and logged (the monitor surface);
//! - suggestions are the adjacency-derived heuristic — a prefix
//!   announced by a peer whose adjacency names an interface is
//!   suggested for that interface, per-prefix egress unions across
//!   peers (the EFP-uRPF "same origin, any receiving interface"
//!   intuition, RFC 8704 §3);
//! - no peer granularity (RibView) or no adjacency interface ⇒ no
//!   suggestion — the agent never invents an interface;
//! - unordered input never panics and leaves consistent state;
//! - the anchors' composition shape (`Arc<dyn SavAgent>`) type-checks
//!   and drives the whole sequence end to end.

#![cfg(feature = "experimental-savnet")]

use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;

use common::IpPrefix;
use sav::agent::{
    MonitorAgent, SavAgent, SavAgentEvent, SavBindingSuggestion, SavEventSource, SavPeer,
    SavProtocol,
};

fn prefix(s: &str) -> IpPrefix {
    s.parse().unwrap()
}

fn peer_v4(address: [u8; 4], remote_id: u32) -> SavPeer {
    SavPeer {
        address: IpAddr::V4(Ipv4Addr::from(address)),
        remote_id,
    }
}

fn bgp_source(address: [u8; 4], remote_id: u32) -> SavEventSource {
    SavEventSource::Bgp(peer_v4(address, remote_id))
}

/// The mock anchor: holds the agent exactly as bgpd/ospfd will (one
/// optional shared `Arc<dyn SavAgent>`), and exposes the anchor-shaped
/// reporting calls the protocol crates' hook points make.
struct MockAnchor {
    agent: Option<Arc<dyn SavAgent>>,
}

impl MockAnchor {
    fn new() -> Self {
        Self { agent: None }
    }

    fn with_agent(mut self, agent: Arc<impl SavAgent + 'static>) -> Self {
        self.agent = Some(agent);
        self
    }

    /// bgpd's Established transition / ospfd's Full.
    fn adjacency_up(&self, protocol: SavProtocol, peer: &SavPeer, ifindex: Option<u32>) {
        if let Some(agent) = &self.agent {
            agent.on_event(SavAgentEvent::AdjacencyUp {
                protocol,
                peer: peer.clone(),
                ifindex,
            });
        }
    }

    /// bgpd's session end / ospfd's adjacency destruction.
    fn adjacency_down(&self, protocol: SavProtocol, peer: &SavPeer) {
        if let Some(agent) = &self.agent {
            agent.on_event(SavAgentEvent::AdjacencyDown {
                protocol,
                peer: peer.clone(),
            });
        }
    }

    /// bgpd's `on_message` UPDATE arm (announce).
    fn route_installed(&self, source: &SavEventSource, prefix: IpPrefix, nexthop: Option<IpAddr>) {
        if let Some(agent) = &self.agent {
            agent.on_event(SavAgentEvent::RouteInstalled {
                source: source.clone(),
                prefix,
                nexthop,
            });
        }
    }

    /// bgpd's `on_message` UPDATE arm (withdraw).
    fn route_withdrawn(&self, source: &SavEventSource, prefix: IpPrefix) {
        if let Some(agent) = &self.agent {
            agent.on_event(SavAgentEvent::RouteWithdrawn {
                source: source.clone(),
                prefix,
            });
        }
    }

    fn suggestions(&self) -> Vec<SavBindingSuggestion> {
        self.agent
            .as_ref()
            .map(|agent| agent.binding_suggestions())
            .unwrap_or_default()
    }
}

/// The monitor agent records events in order (the observability
/// contract) and an anchor with no agent is inert (the anchors'
/// default-none shape).
#[test]
fn events_are_recorded_in_order_and_a_bare_anchor_is_inert() {
    let anchor = MockAnchor::new();
    assert!(anchor.suggestions().is_empty(), "no agent: nothing");

    let peer = peer_v4([192, 0, 2, 9], 65001);
    let agent = Arc::new(MonitorAgent::new());
    let anchor = MockAnchor::new().with_agent(Arc::clone(&agent));
    anchor.adjacency_up(SavProtocol::Bgp, &peer, Some(2));
    anchor.route_installed(
        &bgp_source([192, 0, 2, 9], 65001),
        prefix("203.0.113.0/24"),
        None,
    );
    let events = agent.events();
    assert_eq!(events.len(), 2, "every reported event is recorded");
    assert_eq!(
        events[0],
        SavAgentEvent::AdjacencyUp {
            protocol: SavProtocol::Bgp,
            peer: peer.clone(),
            ifindex: Some(2),
        }
    );
    assert!(matches!(events[1], SavAgentEvent::RouteInstalled { .. }));
}

/// The suggestion heuristic's happy path: an adjacency naming an
/// interface plus installs from that peer yield exactly one suggestion
/// per prefix, carrying that interface.
#[test]
fn adjacency_backed_installs_suggest_the_adjacency_interface() {
    let agent = Arc::new(MonitorAgent::new());
    let anchor = MockAnchor::new().with_agent(Arc::clone(&agent));
    let peer = peer_v4([192, 0, 2, 9], 65001);
    anchor.adjacency_up(SavProtocol::Bgp, &peer, Some(2));
    anchor.route_installed(
        &bgp_source([192, 0, 2, 9], 65001),
        prefix("203.0.113.0/24"),
        None,
    );
    anchor.route_installed(
        &bgp_source([192, 0, 2, 9], 65001),
        prefix("198.51.100.0/24"),
        None,
    );

    let suggestions = anchor.suggestions();
    assert_eq!(suggestions.len(), 2, "one per prefix");
    assert_eq!(suggestions[0].prefix, prefix("198.51.100.0/24"));
    assert_eq!(suggestions[0].ifindexes, vec![2]);
    assert_eq!(suggestions[1].prefix, prefix("203.0.113.0/24"));
    assert_eq!(suggestions[1].ifindexes, vec![2]);
}

/// No interface, no suggestion: an adjacency without an ifindex
/// (bgpd's shape tonight — the session knows addresses, not kernel
/// interfaces) and the peer-less RibView feed both never invent an
/// interface.
#[test]
fn without_an_interface_or_peer_there_is_no_suggestion() {
    let agent = Arc::new(MonitorAgent::new());
    let anchor = MockAnchor::new().with_agent(Arc::clone(&agent));
    // bgpd shape: adjacency known, interface unknown.
    let peer = peer_v4([192, 0, 2, 9], 65001);
    anchor.adjacency_up(SavProtocol::Bgp, &peer, None);
    anchor.route_installed(
        &bgp_source([192, 0, 2, 9], 65001),
        prefix("203.0.113.0/24"),
        None,
    );
    // savd shape: RibView events carry no peer at all.
    anchor.route_installed(&SavEventSource::RibView, prefix("198.51.100.0/24"), None);
    assert!(
        anchor.suggestions().is_empty(),
        "the agent never invents an interface"
    );
}

/// Per-prefix egress unions across announcing peers (the EFP-uRPF
/// same-origin-any-interface intuition), and a withdrawn prefix stops
/// being suggested.
#[test]
fn suggestions_union_interfaces_across_peers_and_withdrawals_clear() {
    let agent = Arc::new(MonitorAgent::new());
    let anchor = MockAnchor::new().with_agent(Arc::clone(&agent));
    let peer1 = peer_v4([192, 0, 2, 9], 65001);
    let peer2 = peer_v4([198, 51, 100, 9], 65002);
    anchor.adjacency_up(SavProtocol::Bgp, &peer1, Some(2));
    anchor.adjacency_up(SavProtocol::Bgp, &peer2, Some(3));
    // Both peers announce the same prefix: union of interfaces.
    anchor.route_installed(
        &bgp_source([192, 0, 2, 9], 65001),
        prefix("203.0.113.0/24"),
        None,
    );
    anchor.route_installed(
        &bgp_source([198, 51, 100, 9], 65002),
        prefix("203.0.113.0/24"),
        None,
    );
    anchor.route_installed(
        &bgp_source([192, 0, 2, 9], 65001),
        prefix("198.18.0.0/15"),
        None,
    );
    let suggestions = anchor.suggestions();
    assert_eq!(suggestions.len(), 2);
    assert_eq!(suggestions[1].prefix, prefix("203.0.113.0/24"));
    assert_eq!(suggestions[1].ifindexes, vec![2, 3], "union, sorted");

    // One peer withdraws: the other's interface keeps the suggestion.
    anchor.route_withdrawn(
        &bgp_source([198, 51, 100, 9], 65002),
        prefix("203.0.113.0/24"),
    );
    let suggestions = anchor.suggestions();
    assert_eq!(suggestions[1].ifindexes, vec![2]);

    // Both withdraw: the prefix stops being suggested entirely.
    anchor.route_withdrawn(&bgp_source([192, 0, 2, 9], 65001), prefix("203.0.113.0/24"));
    assert_eq!(anchor.suggestions().len(), 1);
}

/// Adjacency down clears that peer's suggestions; unordered input (a
/// Down before its Up, a withdraw before the install) never panics
/// and leaves consistent state.
#[test]
fn adjacency_down_clears_and_unordered_events_never_panic() {
    let agent = Arc::new(MonitorAgent::new());
    let anchor = MockAnchor::new().with_agent(Arc::clone(&agent));
    let peer = peer_v4([192, 0, 2, 9], 65001);

    // Unordered: withdraw and Down before anything arrived.
    anchor.route_withdrawn(&bgp_source([192, 0, 2, 9], 65001), prefix("203.0.113.0/24"));
    anchor.adjacency_down(SavProtocol::Bgp, &peer);
    assert!(anchor.suggestions().is_empty());

    // Then the ordered shape: Up, install, suggestion; Down clears.
    anchor.adjacency_up(SavProtocol::Bgp, &peer, Some(2));
    anchor.route_installed(
        &bgp_source([192, 0, 2, 9], 65001),
        prefix("203.0.113.0/24"),
        None,
    );
    assert_eq!(anchor.suggestions().len(), 1);
    anchor.adjacency_down(SavProtocol::Bgp, &peer);
    assert!(
        anchor.suggestions().is_empty(),
        "adjacency down retires the peer's suggestions"
    );
}

/// The ospfd feed: LSA-changed events (the InstallAndFlood products)
/// are recorded and logged like any other event; the adjacency
/// heuristic does not consume them (LSDB-aware derivation is
/// draft-dependent work), but an adjacency naming an interface plus
/// ospfd-side installs compose identically to the bgpd shape.
#[test]
fn ospfd_lsa_and_adjacency_events_compose() {
    let agent = Arc::new(MonitorAgent::new());
    let anchor = MockAnchor::new().with_agent(Arc::clone(&agent));
    let peer = peer_v4([10, 1, 1, 9], 0x0a010109);
    anchor.adjacency_up(SavProtocol::Ospf, &peer, Some(4));
    anchor.route_installed(
        &SavEventSource::Ospf(peer.clone()),
        prefix("10.9.0.0/16"),
        None,
    );
    // The InstallAndFlood product: an LSA installed with changed
    // contents, reported with its LSA identity.
    anchor.route_installed(
        &SavEventSource::RibView, // (recorded shape variety)
        prefix("10.8.0.0/16"),
        Some(IpAddr::V4(Ipv4Addr::new(10, 1, 1, 9))),
    );
    let events = agent.events();
    assert!(
        events.len() >= 3,
        "adjacency, installs, and any LSA events all recorded"
    );

    // The LsaChanged event itself records (the ospfd anchor reports it
    // per changed LSA key); the heuristic skips it without panicking.
    let lsa_event = SavAgentEvent::LsaChanged {
        peer: peer.clone(),
        ls_type: 1,
        link_state_id: Ipv4Addr::new(10, 0, 0, 1),
        adv_router: Ipv4Addr::new(10, 1, 1, 9),
    };
    agent.on_event(lsa_event.clone());
    assert_eq!(agent.events().last(), Some(&lsa_event));

    // The suggestion follows the adjacency interface.
    let suggestions = anchor.suggestions();
    assert_eq!(suggestions.len(), 1);
    assert_eq!(suggestions[0].prefix, prefix("10.9.0.0/16"));
    assert_eq!(suggestions[0].ifindexes, vec![4]);
}

/// The monitor agent's event window is bounded: past
/// `MONITOR_WINDOW` events the oldest half drops and the retained
/// state stays consistent (the newest adjacency + install still
/// suggest; the evicted ones stop).
#[test]
fn the_event_window_is_bounded_and_consistent() {
    let agent = MonitorAgent::new();
    // Window-size probe via events(): fill well past the bound with
    // alternating adjacency flaps, then confirm the retained window is
    // bounded and the replay stays deterministic.
    let peer = peer_v4([192, 0, 2, 9], 65001);
    for i in 0..2600 {
        if i % 2 == 0 {
            agent.on_event(SavAgentEvent::AdjacencyUp {
                protocol: SavProtocol::Bgp,
                peer: peer.clone(),
                ifindex: Some(i % 7 + 1),
            });
        } else {
            agent.on_event(SavAgentEvent::AdjacencyDown {
                protocol: SavProtocol::Bgp,
                peer: peer.clone(),
            });
        }
    }
    assert!(
        agent.events().len() <= 1024,
        "the retained window never exceeds the bound"
    );
    // An Up then an install after the churn still suggest (the window
    // holds live state, not just history).
    agent.on_event(SavAgentEvent::AdjacencyUp {
        protocol: SavProtocol::Bgp,
        peer: peer.clone(),
        ifindex: Some(2),
    });
    agent.on_event(SavAgentEvent::RouteInstalled {
        source: bgp_source([192, 0, 2, 9], 65001),
        prefix: prefix("203.0.113.0/24"),
        nexthop: None,
    });
    let suggestions = agent.binding_suggestions();
    assert_eq!(suggestions.len(), 1);
    assert_eq!(suggestions[0].ifindexes, vec![2]);
}

/// Suggestions render for the operator (the log line's shape) —
/// smoke-level: Display mentions prefix, interface, and source.
#[test]
fn suggestions_render_for_the_operator() {
    let agent = MonitorAgent::new();
    let peer = peer_v4([192, 0, 2, 9], 65001);
    agent.on_event(SavAgentEvent::AdjacencyUp {
        protocol: SavProtocol::Bgp,
        peer: peer.clone(),
        ifindex: Some(2),
    });
    agent.on_event(SavAgentEvent::RouteInstalled {
        source: bgp_source([192, 0, 2, 9], 65001),
        prefix: prefix("203.0.113.0/24"),
        nexthop: None,
    });
    let rendered = agent.binding_suggestions()[0].to_string();
    assert!(rendered.contains("203.0.113.0/24"));
    assert!(rendered.contains("if#2"));
    assert!(rendered.contains("bgp"));
}
