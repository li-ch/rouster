//! The RIB driver: the slice of the main loop that turns ZAPI
//! [`RibCommand`]s into RIB mutations, NHT/interface replies, and (when
//! routes changed) a reconcile pass.
//!
//! Factored out of `main` (Z4) so the staticd end-to-end test can drive
//! the exact main-loop behavior in-process against a mock dataplane —
//! `main` itself runs this against netlink inside its `tokio::select!`.
//!
//! Z3B adds the event-driven direction: the driver holds each attached
//! session's push channel and fans updates out on RIB activity —
//! NEXTHOP_UPDATE when a registered nexthop's resolution flips on a
//! dataplane event ([`RibDriver::apply_event`]), REDISTRIBUTE_ROUTE_ADD
//! when a ZAPI route command changes the best route for a prefix and a
//! session registered REDISTRIBUTE interest in its type. W2 completes the
//! pair: a best route that vanishes fans REDISTRIBUTE_ROUTE_DEL (32)
//! carrying the withdrawn route to the same interested sessions.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::net::{IpAddr, Ipv4Addr};

use common::{Dataplane, DataplaneEvent, IpPrefix, Nexthop, NexthopGroup, RouteEntry, TableId};
use rib::Rib;
use tokio::sync::mpsc;
use tracing::{debug, info, warn};

use zapi::{route_type_from, InterfaceMirror, RibCommand, SessionPush, DEFAULT_TABLE};

/// RIB plus the driver-side registration state ZAPI sessions feed.
pub struct RibDriver {
    pub rib: Rib,
    /// Push channel per attached session, keyed by the server-assigned
    /// owner id. Attached at accept time (`RibCommand::AttachSession`);
    /// pruned when a push finds the session gone.
    sessions: HashMap<u64, mpsc::Sender<SessionPush>>,
    /// NEXTHOP_REGISTER interests per owner, with the last resolution the
    /// owner was told (the answer to its register). A dataplane event that
    /// changes a resolution pushes an update only when it differs from
    /// this — no flip, no push.
    nht_registrations: HashMap<u64, BTreeMap<IpPrefix, Option<Nexthop>>>,
    /// REDISTRIBUTE_ADD interests per owner: (afi, route_type, instance).
    redistributes: HashMap<u64, BTreeSet<(u8, u8, u16)>>,
}

impl Default for RibDriver {
    fn default() -> Self {
        Self::new()
    }
}

/// ZAPI AFI values (frr `lib/prefix.h`): AFI_IP / AFI_IP6.
fn afi_of(prefix: &IpPrefix) -> u8 {
    match prefix {
        IpPrefix::V4(_) => 1,
        IpPrefix::V6(_) => 2,
    }
}

fn prefix_addr(prefix: &IpPrefix) -> IpAddr {
    match prefix {
        IpPrefix::V4(p) => IpAddr::V4(p.addr()),
        IpPrefix::V6(p) => IpAddr::V6(p.addr()),
    }
}

impl RibDriver {
    pub fn new() -> Self {
        Self {
            rib: Rib::new(),
            sessions: HashMap::new(),
            nht_registrations: HashMap::new(),
            redistributes: HashMap::new(),
        }
    }

    /// Applies one ZAPI session command to the RIB and the driver-side
    /// registries. Returns whether the protocol tables changed (the
    /// caller reconciles on change). Route mutations that change a
    /// prefix's best route also fan REDISTRIBUTE_ROUTE_ADD pushes out to
    /// interested sessions.
    pub fn apply(&mut self, command: RibCommand) -> bool {
        match command {
            RibCommand::AttachSession { owner, push } => {
                self.sessions.insert(owner, push);
                debug!(owner, "zapi: session attached (push channel open)");
                false
            }
            RibCommand::AddRoute(entry) => {
                info!(prefix = %entry.prefix, protocol = ?entry.protocol, "zapi: route add");
                let (table, prefix) = (entry.table, entry.prefix);
                let before = self.best_of(table, prefix);
                self.rib.add_route(entry);
                self.push_best_change(table, prefix, before);
                true
            }
            RibCommand::DeleteRoute {
                table,
                prefix,
                protocol,
            } => {
                let before = self.best_of(table, prefix);
                let removed = self.rib.table_mut(table).remove(&prefix, protocol);
                if removed {
                    info!(prefix = %prefix, ?protocol, "zapi: route delete");
                    self.push_best_change(table, prefix, before);
                } else {
                    debug!(prefix = %prefix, ?protocol, "zapi: route delete for absent route");
                }
                removed
            }
            // Answer immediately from the RIB's current resolution; the
            // stored value is the flip baseline for apply_event.
            RibCommand::RegisterNexthop {
                owner,
                prefix,
                reply,
            } => {
                let resolution = self.rib.lookup_nexthop(prefix_addr(&prefix));
                self.nht_registrations
                    .entry(owner)
                    .or_default()
                    .insert(prefix, resolution);
                let _ = reply.send(resolution);
                false
            }
            RibCommand::UnregisterNexthop { owner, prefix } => {
                if let Some(set) = self.nht_registrations.get_mut(&owner) {
                    set.remove(&prefix);
                    if set.is_empty() {
                        self.nht_registrations.remove(&owner);
                    }
                }
                false
            }
            RibCommand::RegisterRedistribute {
                owner,
                afi,
                route_type,
                instance,
            } => {
                self.redistributes
                    .entry(owner)
                    .or_default()
                    .insert((afi, route_type, instance));
                debug!(owner, afi, route_type, instance, "zapi: redistribute add");
                // FRR zebra replays the current best routes of the
                // registered type on REDISTRIBUTE_ADD — staticd/bgpd expect
                // the dump on (re)connect (W2, closing Z3B disclosure 1).
                // Same push form as a best-change push; main table only
                // (the ZAPI edge lands every client route there).
                let dumped: Vec<RouteEntry> = self
                    .rib
                    .table(DEFAULT_TABLE)
                    .map(|table| {
                        table
                            .iter()
                            .filter_map(|(prefix, _)| table.best(prefix).cloned())
                            .filter(|best| {
                                afi_of(&best.prefix) == afi
                                    && route_type_from(best.protocol) == route_type
                            })
                            .collect()
                    })
                    .unwrap_or_default();
                for best in dumped {
                    let entry = self.push_form(&best);
                    info!(
                        owner,
                        prefix = %entry.prefix,
                        "zapi: initial redistribute dump push"
                    );
                    self.push(owner, SessionPush::RedistributeRouteAdd(entry));
                }
                false
            }
            RibCommand::UnregisterRedistribute {
                owner,
                afi,
                route_type,
                instance,
            } => {
                if let Some(set) = self.redistributes.get_mut(&owner) {
                    set.remove(&(afi, route_type, instance));
                    if set.is_empty() {
                        self.redistributes.remove(&owner);
                    }
                }
                false
            }
            RibCommand::RequestInterfaces { reply } => {
                let mirror: Vec<InterfaceMirror> = self
                    .rib
                    .interfaces()
                    .iter()
                    .map(|(&ifindex, iface)| InterfaceMirror {
                        ifindex,
                        name: iface.name.clone(),
                        is_up: iface.is_up,
                        addresses: iface.addresses.clone(),
                    })
                    .collect();
                let _ = reply.send(mirror);
                false
            }
            RibCommand::RequestRouterId { reply } => {
                let router_id = self.router_id();
                debug!(?router_id, "zapi: router-id derived");
                let _ = reply.send(router_id);
                false
            }
        }
    }

    /// Applies one dataplane event to the RIB mirror and re-evaluates
    /// every registered nexthop through the RIB's resolution query
    /// (P0B): link and address events can flip a gateway between
    /// resolved and unresolved, and each flip pushes a NEXTHOP_UPDATE to
    /// the owning session. Route events cannot change (direct)
    /// resolution, so they skip the pass.
    pub fn apply_event(&mut self, ev: &DataplaneEvent) {
        let flips_resolution = matches!(
            ev,
            DataplaneEvent::LinkNew { .. }
                | DataplaneEvent::LinkDel { .. }
                | DataplaneEvent::AddressNew { .. }
                | DataplaneEvent::AddressDel { .. }
        );
        self.rib.apply_event(ev);
        if flips_resolution {
            self.reevaluate_nht();
        }
    }

    /// The resolution table every registered interest is re-checked
    /// against; only actual flips produce pushes.
    fn reevaluate_nht(&mut self) {
        let rib = &self.rib;
        let mut flips: Vec<(u64, IpPrefix, Option<Nexthop>)> = Vec::new();
        for (&owner, registrations) in &mut self.nht_registrations {
            for (prefix, last_told) in registrations {
                let resolution = rib.lookup_nexthop(prefix_addr(prefix));
                if *last_told != resolution {
                    flips.push((owner, *prefix, resolution));
                    *last_told = resolution;
                }
            }
        }
        for (owner, prefix, resolution) in flips {
            info!(owner, %prefix, resolved = resolution.is_some(), "zapi: NHT flip");
            self.push(owner, SessionPush::NexthopResolution { prefix, resolution });
        }
    }

    fn best_of(&self, table: TableId, prefix: IpPrefix) -> Option<RouteEntry> {
        self.rib.table(table).and_then(|t| t.best(&prefix)).cloned()
    }

    /// The router-id rousterd derives for ROUTER_ID_UPDATE (18) answers:
    /// FRR's documented default — the highest IPv4 address on an UP
    /// loopback interface, falling back to the highest IPv4 address on any
    /// UP interface, `None` when no UP interface carries one. Simplified
    /// vs FRR: loopbacks are recognized by a `lo` name prefix (the mirror
    /// has no IFF_LOOPBACK bit) and IPv6 addresses never participate
    /// (ZAPI's router-id is an IPv4 construct). The 127/8 range is
    /// excluded like zebra does (`IPV4_NET127`, zebra/router-id.c): a
    /// Linux `lo` always carries 127.0.0.1, and answering with it would
    /// give every client the same router-id — live-observed with ospfd,
    /// whose same-id neighbors can never become adjacent. Config override
    /// is future northbound-config work.
    fn router_id(&self) -> Option<Ipv4Addr> {
        let mut loopback: Vec<Ipv4Addr> = Vec::new();
        let mut any_up: Vec<Ipv4Addr> = Vec::new();
        for iface in self.rib.interfaces().values().filter(|i| i.is_up) {
            let pool = if iface.name.starts_with("lo") {
                &mut loopback
            } else {
                &mut any_up
            };
            for prefix in &iface.addresses {
                if let IpPrefix::V4(p) = prefix {
                    if p.addr().is_loopback() {
                        continue;
                    }
                    pool.push(p.addr());
                }
            }
        }
        let pool = if loopback.is_empty() {
            any_up
        } else {
            loopback
        };
        pool.into_iter().max()
    }

    /// Fans a REDISTRIBUTE_ROUTE_ADD out to the sessions registered for
    /// the new best route's (afi, type) when `before` differs from the
    /// current best; a best route that vanished instead fans a
    /// REDISTRIBUTE_ROUTE_DEL carrying the withdrawn route to the sessions
    /// registered for ITS (afi, type) — the same zsend_redistribute_route
    /// body as the ADD (W2, closing Z3B's disclosed cut).
    fn push_best_change(&mut self, table: TableId, prefix: IpPrefix, before: Option<RouteEntry>) {
        let after = self.best_of(table, prefix);
        if after == before {
            return;
        }
        let Some(best) = after else {
            let Some(withdrawn) = before else {
                return;
            };
            let afi = afi_of(&withdrawn.prefix);
            let route_type = route_type_from(withdrawn.protocol);
            let owners: Vec<u64> = self
                .redistributes
                .iter()
                .filter(|(_, keys)| keys.iter().any(|k| k.0 == afi && k.1 == route_type))
                .map(|(&owner, _)| owner)
                .collect();
            if owners.is_empty() {
                return;
            }
            let entry = self.push_form(&withdrawn);
            info!(
                %prefix,
                table,
                route_type,
                sessions = owners.len(),
                "zapi: best route withdrawn; pushing REDISTRIBUTE_ROUTE_DEL"
            );
            for owner in owners {
                self.push(owner, SessionPush::RedistributeRouteDel(entry.clone()));
            }
            return;
        };
        let afi = afi_of(&best.prefix);
        let route_type = route_type_from(best.protocol);
        // RouteEntry carries no instance, so registration instances are
        // matched on (afi, type) only.
        let owners: Vec<u64> = self
            .redistributes
            .iter()
            .filter(|(_, keys)| keys.iter().any(|k| k.0 == afi && k.1 == route_type))
            .map(|(&owner, _)| owner)
            .collect();
        if owners.is_empty() {
            return;
        }
        let entry = self.push_form(&best);
        info!(
            %prefix,
            table,
            route_type,
            sessions = owners.len(),
            "zapi: best route changed; pushing REDISTRIBUTE_ROUTE_ADD"
        );
        for owner in owners {
            self.push(owner, SessionPush::RedistributeRouteAdd(entry.clone()));
        }
    }

    /// The wire-facing form of a route: gateway hops rewritten to their
    /// resolved (ifindex-carrying) form where the RIB can resolve them —
    /// unresolved gateways keep their gateway form, which is exactly the
    /// shape an NHT-tracking client knows how to consume.
    fn push_form(&self, entry: &RouteEntry) -> RouteEntry {
        let mut form = entry.clone();
        let mut hops = NexthopGroup::new();
        for &(hop, weight) in entry.nexthops.hops() {
            let hop = match hop {
                Nexthop::Ipv4(gate) => self.rib.lookup_nexthop(IpAddr::V4(gate)).unwrap_or(hop),
                Nexthop::Ipv6(gate) => self.rib.lookup_nexthop(IpAddr::V6(gate)).unwrap_or(hop),
                Nexthop::Blackhole
                | Nexthop::IfIndex(_)
                | Nexthop::Ipv4If(..)
                | Nexthop::Ipv6If(..) => hop,
            };
            hops.add(hop, weight);
        }
        form.nexthops = hops;
        form
    }

    /// Queues one push to one session. Bounded and non-blocking: the main
    /// loop must never stall on a slow daemon. A full queue drops the
    /// update with a warning (a stuck client re-syncs on re-registration
    /// or reconnect); a closed channel means the session is gone and
    /// prunes every registration it left behind.
    fn push(&mut self, owner: u64, item: SessionPush) {
        let Some(session) = self.sessions.get(&owner) else {
            debug!(owner, "zapi: push for unattached session dropped");
            return;
        };
        match session.try_send(item) {
            Ok(()) => {}
            Err(mpsc::error::TrySendError::Full(_)) => {
                warn!(owner, "zapi: session push queue full; update dropped");
            }
            Err(mpsc::error::TrySendError::Closed(_)) => {
                self.sessions.remove(&owner);
                self.nht_registrations.remove(&owner);
                self.redistributes.remove(&owner);
                debug!(owner, "zapi: session gone; registries pruned");
            }
        }
    }

    /// Waits for one command, then drains everything else that arrived
    /// with it (a daemon often bursts), reconciling once for the whole
    /// batch if routes changed — the same batching `main`'s select loop
    /// performs. Blocking on the first receive is what lets reply-carrying
    /// commands (NEXTHOP_REGISTER blocks its session until answered) run
    /// concurrently with the sending session.
    pub async fn drive<D: Dataplane>(
        &mut self,
        rx: &mut mpsc::Receiver<RibCommand>,
        dp: &D,
    ) -> bool {
        let mut changed = self.apply(rx.recv().await.expect("command arrives"));
        while let Ok(command) = rx.try_recv() {
            changed |= self.apply(command);
        }
        if changed {
            self.rib.reconcile(dp).await;
        }
        changed
    }

    /// Applies whatever commands are already queued, reconciling if routes
    /// changed. Never blocks.
    pub async fn drain<D: Dataplane>(
        &mut self,
        rx: &mut mpsc::Receiver<RibCommand>,
        dp: &D,
    ) -> bool {
        let mut changed = false;
        while let Ok(command) = rx.try_recv() {
            changed |= self.apply(command);
        }
        if changed {
            self.rib.reconcile(dp).await;
        }
        changed
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use common::{NexthopGroup, RouteProtocol};
    use zapi::route_type;

    /// Attaches a fake session and returns its push receiver.
    fn attach(driver: &mut RibDriver, owner: u64) -> mpsc::Receiver<SessionPush> {
        let (tx, rx) = mpsc::channel(16);
        driver.apply(RibCommand::AttachSession { owner, push: tx });
        rx
    }

    fn register_nht(driver: &mut RibDriver, owner: u64, prefix: &str) -> Option<Nexthop> {
        let (tx, rx) = tokio::sync::oneshot::channel();
        driver.apply(RibCommand::RegisterNexthop {
            owner,
            prefix: prefix.parse().unwrap(),
            reply: tx,
        });
        rx.blocking_recv().expect("answer")
    }

    fn static_entry(prefix: &str, hop: Nexthop, metric: u32) -> RouteEntry {
        RouteEntry::new(
            prefix.parse().unwrap(),
            RouteProtocol::Static,
            NexthopGroup::single(hop),
            metric,
        )
    }

    fn link_up(ifindex: u32) -> DataplaneEvent {
        DataplaneEvent::LinkNew {
            ifindex,
            name: format!("eth{ifindex}"),
            is_up: true,
            vrf_table: None,
            master_ifindex: None,
        }
    }

    fn link_down(ifindex: u32) -> DataplaneEvent {
        DataplaneEvent::LinkNew {
            ifindex,
            name: format!("eth{ifindex}"),
            is_up: false,
            vrf_table: None,
            master_ifindex: None,
        }
    }

    fn addr_new(ifindex: u32, prefix: &str) -> DataplaneEvent {
        DataplaneEvent::AddressNew {
            ifindex,
            prefix: prefix.parse().unwrap(),
        }
    }

    #[test]
    fn attach_session_records_push_sender() {
        let mut driver = RibDriver::new();
        let rx = attach(&mut driver, 1);
        assert!(driver.sessions.contains_key(&1));
        drop(rx);
    }

    /// The core Z3B flip: a registered-but-unresolved gateway resolves
    /// when a covering address appears, and ONLY the flip pushes.
    #[test]
    fn nht_flip_on_address_add_pushes_resolution() {
        let mut driver = RibDriver::new();
        let mut pushes = attach(&mut driver, 1);

        let answer = register_nht(&mut driver, 1, "10.9.9.9/32");
        assert_eq!(answer, None, "no mirror yet: unresolved");

        driver.apply_event(&link_up(2));
        assert!(
            pushes.try_recv().is_err(),
            "link alone covers nothing: no flip, no push"
        );

        driver.apply_event(&addr_new(2, "10.9.9.1/24"));
        match pushes.try_recv().expect("flip pushed") {
            SessionPush::NexthopResolution { prefix, resolution } => {
                assert_eq!(prefix, "10.9.9.9/32".parse().unwrap());
                assert_eq!(
                    resolution,
                    Some(Nexthop::Ipv4If("10.9.9.9".parse().unwrap(), 2))
                );
            }
            other => panic!("expected NexthopResolution, got {other:?}"),
        }
        assert!(
            pushes.try_recv().is_err(),
            "the duplicate event below must not re-push"
        );
        driver.apply_event(&addr_new(2, "10.9.9.1/24")); // duplicate: idempotent
        assert!(pushes.try_recv().is_err(), "no flip, no push");
    }

    /// Both directions: resolution disappears when the link goes down and
    /// comes back when it returns.
    #[test]
    fn nht_flip_on_link_down_and_back_pushes_both_ways() {
        let mut driver = RibDriver::new();
        let mut pushes = attach(&mut driver, 1);
        driver.apply_event(&link_up(3));
        driver.apply_event(&addr_new(3, "192.0.2.1/24"));

        let answer = register_nht(&mut driver, 1, "192.0.2.9/32");
        assert_eq!(
            answer,
            Some(Nexthop::Ipv4If("192.0.2.9".parse().unwrap(), 3)),
            "resolved at registration time"
        );
        assert!(pushes.try_recv().is_err(), "registration answers directly");

        driver.apply_event(&link_down(3));
        match pushes.try_recv().expect("unresolve pushed") {
            SessionPush::NexthopResolution { resolution, .. } => {
                assert_eq!(resolution, None);
            }
            other => panic!("expected NexthopResolution, got {other:?}"),
        }

        driver.apply_event(&link_up(3));
        match pushes.try_recv().expect("re-resolve pushed") {
            SessionPush::NexthopResolution { resolution, .. } => {
                assert_eq!(
                    resolution,
                    Some(Nexthop::Ipv4If("192.0.2.9".parse().unwrap(), 3))
                );
            }
            other => panic!("expected NexthopResolution, got {other:?}"),
        }
    }

    /// Route events never re-run resolution (direct resolution depends
    /// only on the interface mirror).
    #[test]
    fn route_events_do_not_re_evaluate_nht() {
        let mut driver = RibDriver::new();
        let mut pushes = attach(&mut driver, 1);
        assert_eq!(register_nht(&mut driver, 1, "10.9.9.9/32"), None);
        driver.apply_event(&DataplaneEvent::RouteNew {
            table: 254,
            prefix: "10.9.9.0/24".parse().unwrap(),
            protocol: RouteProtocol::Kernel,
            metric: 0,
        });
        assert!(
            pushes.try_recv().is_err(),
            "a kernel route event is not a resolution flip"
        );
    }

    /// Neighbour events are read-only awareness (W3): even a neighbour for
    /// the tracked gateway IP appearing/disappearing must not look like a
    /// resolution flip — resolution stays prefix-based.
    #[test]
    fn neighbour_events_do_not_re_evaluate_nht() {
        use common::NeighbourEntry;

        let mut driver = RibDriver::new();
        let mut pushes = attach(&mut driver, 1);
        driver.apply_event(&link_up(2));
        driver.apply_event(&addr_new(2, "203.0.113.1/24"));
        assert!(register_nht(&mut driver, 1, "203.0.113.9/32").is_some());

        driver.apply_event(&DataplaneEvent::NeighbourNew {
            entry: NeighbourEntry::from_rtnetlink(
                "203.0.113.9".parse().unwrap(),
                2,
                Some(vec![0x02, 0x00, 0x00, 0x00, 0x00, 0x09]),
                0x80, // NUD_PERMANENT
                0,
            ),
        });
        driver.apply_event(&DataplaneEvent::NeighbourDel {
            ip: "203.0.113.9".parse().unwrap(),
            link_ifindex: 2,
        });
        assert!(
            pushes.try_recv().is_err(),
            "neighbour events are not resolution flips"
        );
        // The mirror itself did update through the same driver path.
        assert!(driver
            .rib
            .lookup_neighbour("203.0.113.9".parse().unwrap(), 2)
            .is_none());
    }

    /// A route add that becomes the best route pushes to the session that
    /// registered REDISTRIBUTE for its type — in push form (gateway hops
    /// resolved).
    #[test]
    fn best_route_change_pushes_redistribute() {
        let mut driver = RibDriver::new();
        let mut pushes = attach(&mut driver, 7);
        driver.apply(RibCommand::RegisterRedistribute {
            owner: 7,
            afi: 1,
            route_type: route_type::STATIC,
            instance: 0,
        });
        driver.apply_event(&link_up(2));
        driver.apply_event(&addr_new(2, "203.0.113.1/24"));

        driver.apply(RibCommand::AddRoute(static_entry(
            "198.51.100.0/24",
            Nexthop::Ipv4("203.0.113.9".parse().unwrap()),
            5,
        )));
        match pushes.try_recv().expect("push on best change") {
            SessionPush::RedistributeRouteAdd(entry) => {
                assert_eq!(entry.prefix, "198.51.100.0/24".parse().unwrap());
                assert_eq!(entry.metric, 5);
                assert_eq!(
                    entry.nexthops.hops(),
                    &[(Nexthop::Ipv4If("203.0.113.9".parse().unwrap(), 2), 1)],
                    "gateway hop resolved to ifindex form for the push"
                );
            }
            other => panic!("expected RedistributeRouteAdd, got {other:?}"),
        }
        assert!(pushes.try_recv().is_err(), "one push per change");
    }

    /// Adding a candidate that does NOT change the best route pushes
    /// nothing; replacing the best with a better same-protocol route
    /// pushes the new best; withdrawing the best pushes a DEL (32)
    /// carrying the withdrawn route — the W2 completion of the former
    /// "best gone, no push" pin.
    #[test]
    fn redistribute_push_gates_on_actual_best_change() {
        let mut driver = RibDriver::new();
        let mut pushes = attach(&mut driver, 1);
        driver.apply(RibCommand::RegisterRedistribute {
            owner: 1,
            afi: 1,
            route_type: route_type::STATIC,
            instance: 0,
        });

        driver.apply(RibCommand::AddRoute(static_entry(
            "198.51.100.0/24",
            Nexthop::IfIndex(2),
            20,
        )));
        assert!(matches!(
            pushes.try_recv().expect("new best pushes"),
            SessionPush::RedistributeRouteAdd(_)
        ));

        // A worse candidate from another protocol: best unchanged.
        let mut ospf = static_entry("198.51.100.0/24", Nexthop::IfIndex(3), 0);
        ospf.protocol = RouteProtocol::Ospf;
        driver.apply(RibCommand::AddRoute(ospf));
        assert!(pushes.try_recv().is_err(), "best unchanged: no push");

        // A better static replaces the best (same protocol, lower metric).
        driver.apply(RibCommand::AddRoute(static_entry(
            "198.51.100.0/24",
            Nexthop::IfIndex(2),
            10,
        )));
        match pushes.try_recv().expect("new best pushes") {
            SessionPush::RedistributeRouteAdd(entry) => assert_eq!(entry.metric, 10),
            other => panic!("expected RedistributeRouteAdd, got {other:?}"),
        }

        // Withdrawing a non-best candidate: best unchanged.
        driver.apply(RibCommand::DeleteRoute {
            table: 254,
            prefix: "198.51.100.0/24".parse().unwrap(),
            protocol: RouteProtocol::Ospf,
        });
        assert!(pushes.try_recv().is_err(), "best still static: no push");

        // Withdrawing the best itself (last candidate): best gone, the DEL
        // push carries the withdrawn route (W2).
        driver.apply(RibCommand::DeleteRoute {
            table: 254,
            prefix: "198.51.100.0/24".parse().unwrap(),
            protocol: RouteProtocol::Static,
        });
        match pushes.try_recv().expect("best withdrawn pushes DEL") {
            SessionPush::RedistributeRouteDel(entry) => {
                assert_eq!(entry.prefix, "198.51.100.0/24".parse().unwrap());
                assert_eq!(entry.protocol, RouteProtocol::Static);
                assert_eq!(entry.metric, 10, "the withdrawn best's metric");
            }
            other => panic!("expected RedistributeRouteDel, got {other:?}"),
        }
        assert!(pushes.try_recv().is_err(), "one push per withdrawal");
    }

    /// A best-route withdrawal pushes a DEL only to sessions registered
    /// for the WITHDRAWN route's type (not the surviving protocol's), and
    /// the push is in resolved push form.
    #[test]
    fn best_route_withdrawal_pushes_del_for_the_withdrawn_type() {
        let mut driver = RibDriver::new();
        let mut static_pushes = attach(&mut driver, 1); // wants static
        let mut ospf_pushes = attach(&mut driver, 2); // wants ospf
        driver.apply(RibCommand::RegisterRedistribute {
            owner: 1,
            afi: 1,
            route_type: route_type::STATIC,
            instance: 0,
        });
        driver.apply(RibCommand::RegisterRedistribute {
            owner: 2,
            afi: 1,
            route_type: route_type::OSPF,
            instance: 0,
        });
        driver.apply_event(&link_up(2));
        driver.apply_event(&addr_new(2, "203.0.113.1/24"));

        // Static best with a resolvable gateway; drain its ADD push.
        driver.apply(RibCommand::AddRoute(static_entry(
            "198.51.100.0/24",
            Nexthop::Ipv4("203.0.113.9".parse().unwrap()),
            5,
        )));
        match static_pushes.try_recv().expect("static ADD pushed") {
            SessionPush::RedistributeRouteAdd(entry) => {
                assert_eq!(
                    entry.nexthops.hops(),
                    &[(Nexthop::Ipv4If("203.0.113.9".parse().unwrap(), 2), 1)]
                );
            }
            other => panic!("expected RedistributeRouteAdd, got {other:?}"),
        }

        // Withdraw it: the static-registered session gets the DEL (with
        // the hop in resolved push form); the ospf-registered session
        // hears nothing.
        driver.apply(RibCommand::DeleteRoute {
            table: 254,
            prefix: "198.51.100.0/24".parse().unwrap(),
            protocol: RouteProtocol::Static,
        });
        match static_pushes.try_recv().expect("static DEL pushed") {
            SessionPush::RedistributeRouteDel(entry) => {
                assert_eq!(entry.prefix, "198.51.100.0/24".parse().unwrap());
                assert_eq!(entry.protocol, RouteProtocol::Static);
                assert_eq!(
                    entry.nexthops.hops(),
                    &[(Nexthop::Ipv4If("203.0.113.9".parse().unwrap(), 2), 1)],
                    "the withdrawn route rides in push form"
                );
            }
            other => panic!("expected RedistributeRouteDel, got {other:?}"),
        }
        assert!(
            ospf_pushes.try_recv().is_err(),
            "an ospf-registered session gets no static DEL"
        );
        assert!(static_pushes.try_recv().is_err(), "one DEL per withdrawal");
    }

    /// REDISTRIBUTE_ADD replays the current best routes of the registered
    /// type (FRR zebra's initial dump): prefix-sorted, push-form hops, and
    /// filtered on both afi and type.
    #[test]
    fn redistribute_registration_dumps_current_best_routes() {
        let mut driver = RibDriver::new();
        let mut pushes = attach(&mut driver, 1);
        driver.apply_event(&link_up(2));
        driver.apply_event(&addr_new(2, "203.0.113.1/24"));

        // Two static (one with a resolvable gateway) and one ospf route,
        // plus an IPv6 static; nothing is registered yet, so no pushes.
        driver.apply(RibCommand::AddRoute(static_entry(
            "198.51.100.0/24",
            Nexthop::Ipv4("203.0.113.9".parse().unwrap()),
            5,
        )));
        driver.apply(RibCommand::AddRoute(static_entry(
            "203.0.113.0/24",
            Nexthop::Blackhole,
            7,
        )));
        let mut ospf = static_entry("192.0.2.0/24", Nexthop::IfIndex(2), 0);
        ospf.protocol = RouteProtocol::Ospf;
        driver.apply(RibCommand::AddRoute(ospf));
        let v6 = static_entry("2001:db8::/32", Nexthop::Blackhole, 0);
        driver.apply(RibCommand::AddRoute(v6));
        assert!(
            pushes.try_recv().is_err(),
            "no registration yet: adds push nothing"
        );

        // Register static+IPv4: exactly the two v4 static bests, in prefix
        // order (BTreeMap iteration), gateway hop resolved.
        driver.apply(RibCommand::RegisterRedistribute {
            owner: 1,
            afi: 1,
            route_type: route_type::STATIC,
            instance: 0,
        });
        let mut prefixes = Vec::new();
        for _ in 0..2 {
            match pushes.try_recv().expect("dump push") {
                SessionPush::RedistributeRouteAdd(entry) => prefixes.push(entry.prefix),
                other => panic!("expected RedistributeRouteAdd, got {other:?}"),
            }
        }
        assert_eq!(
            prefixes,
            vec![
                "198.51.100.0/24".parse::<IpPrefix>().unwrap(),
                "203.0.113.0/24".parse::<IpPrefix>().unwrap()
            ],
            "prefix-sorted dump, only the registered type/afi"
        );
        assert!(
            pushes.try_recv().is_err(),
            "ospf and v6 static are not in the dump"
        );

        // A later best change still pushes normally (the dump did not
        // consume the registration).
        driver.apply(RibCommand::AddRoute(static_entry(
            "198.51.100.0/24",
            Nexthop::Blackhole,
            3,
        )));
        assert!(matches!(
            pushes.try_recv().expect("best change still pushes"),
            SessionPush::RedistributeRouteAdd(_)
        ));

        // Registering a type with no routes dumps nothing.
        let mut bgp_pushes = attach(&mut driver, 2);
        driver.apply(RibCommand::RegisterRedistribute {
            owner: 2,
            afi: 1,
            route_type: route_type::BGP,
            instance: 0,
        });
        assert!(bgp_pushes.try_recv().is_err(), "no BGP routes: empty dump");
    }

    /// The fan-out filters on both AFI and route type.
    #[test]
    fn redistribute_fan_out_respects_afi_and_type() {
        let mut driver = RibDriver::new();
        let mut pushes = attach(&mut driver, 1);
        driver.apply(RibCommand::RegisterRedistribute {
            owner: 1,
            afi: 2, // IPv6 only
            route_type: route_type::STATIC,
            instance: 0,
        });
        driver.apply(RibCommand::AddRoute(static_entry(
            "198.51.100.0/24",
            Nexthop::Blackhole,
            0,
        )));
        assert!(
            pushes.try_recv().is_err(),
            "v6-registered session gets no v4 push"
        );

        let mut v6 = static_entry("2001:db8::/32", Nexthop::Blackhole, 0);
        driver.apply(RibCommand::AddRoute(v6.clone()));
        v6.protocol = RouteProtocol::Ospf;
        assert!(matches!(
            pushes.try_recv().expect("v6 static pushes"),
            SessionPush::RedistributeRouteAdd(_)
        ));

        // Wrong type: an OSPF route does not reach a static-only session.
        driver.apply(RibCommand::AddRoute(v6));
        assert!(pushes.try_recv().is_err(), "type filter holds");
    }

    /// A dead session is pruned on the first push attempt, and its
    /// registrations go with it (Z3 disclosure 4 resolved).
    #[test]
    fn dead_session_pruned_with_its_registrations() {
        let mut driver = RibDriver::new();
        let pushes = attach(&mut driver, 9);
        driver.apply(RibCommand::RegisterRedistribute {
            owner: 9,
            afi: 1,
            route_type: route_type::STATIC,
            instance: 0,
        });
        assert_eq!(register_nht(&mut driver, 9, "10.9.9.9/32"), None);
        drop(pushes); // session gone

        // The push attempt discovers the closed channel and prunes.
        driver.apply(RibCommand::AddRoute(static_entry(
            "198.51.100.0/24",
            Nexthop::Blackhole,
            0,
        )));
        assert!(!driver.sessions.contains_key(&9));
        assert!(!driver.nht_registrations.contains_key(&9));
        assert!(!driver.redistributes.contains_key(&9));

        // A re-attached owner works cleanly afterwards (with a fresh
        // registration — the prune took the old one, as asserted above).
        let mut fresh = attach(&mut driver, 9);
        driver.apply(RibCommand::RegisterRedistribute {
            owner: 9,
            afi: 1,
            route_type: route_type::STATIC,
            instance: 0,
        });
        driver.apply(RibCommand::AddRoute(static_entry(
            "203.0.113.0/24",
            Nexthop::Blackhole,
            0,
        )));
        assert!(matches!(
            fresh.try_recv().expect("re-attached session pushes"),
            SessionPush::RedistributeRouteAdd(_)
        ));
    }

    /// The router-id derivation behind ROUTER_ID_UPDATE answers: loopbacks
    /// win over higher non-loopback addresses, the fallback pool is any UP
    /// interface, DOWN interfaces and IPv6 never contribute, and no
    /// candidates means None.
    #[test]
    fn router_id_prefers_highest_loopback_then_any_up() {
        let mut driver = RibDriver::new();
        assert_eq!(driver.router_id(), None, "no mirror: nothing to derive");

        // Loopback preferred even though eth0's address is higher.
        driver.apply_event(&link_up(1)); // name eth1 — see link_up()
        driver.apply_event(&DataplaneEvent::LinkNew {
            ifindex: 4,
            name: "lo".into(),
            is_up: true,
            vrf_table: None,
            master_ifindex: None,
        });
        driver.apply_event(&addr_new(4, "10.0.0.5/32"));
        // 127/8 never contributes: without the exclusion every Linux lo
        // would answer 127.0.0.1 and same-id OSPF neighbors could never
        // become adjacent (live-observed with ospfd, Z5C).
        driver.apply_event(&addr_new(4, "127.0.0.1/8"));
        driver.apply_event(&DataplaneEvent::LinkNew {
            ifindex: 2,
            name: "eth0".into(),
            is_up: true,
            vrf_table: None,
            master_ifindex: None,
        });
        driver.apply_event(&addr_new(2, "192.168.1.1/24"));
        assert_eq!(
            driver.router_id(),
            Some("10.0.0.5".parse::<std::net::Ipv4Addr>().unwrap()),
            "loopback address wins over the higher eth0 address"
        );

        // Highest among multiple loopbacks.
        driver.apply_event(&addr_new(4, "10.0.0.9/32"));
        assert_eq!(
            driver.router_id(),
            Some("10.0.0.9".parse::<std::net::Ipv4Addr>().unwrap())
        );

        // Loopback down: fall back to the highest UP non-loopback address.
        driver.apply_event(&DataplaneEvent::LinkNew {
            ifindex: 4,
            name: "lo".into(),
            is_up: false,
            vrf_table: None,
            master_ifindex: None,
        });
        assert_eq!(
            driver.router_id(),
            Some("192.168.1.1".parse::<std::net::Ipv4Addr>().unwrap())
        );

        // A higher address on a DOWN interface and IPv6 addresses never
        // contribute.
        driver.apply_event(&DataplaneEvent::LinkNew {
            ifindex: 3,
            name: "eth1".into(),
            is_up: false,
            vrf_table: None,
            master_ifindex: None,
        });
        driver.apply_event(&addr_new(3, "200.0.0.1/24"));
        assert_eq!(
            driver.router_id(),
            Some("192.168.1.1".parse::<std::net::Ipv4Addr>().unwrap()),
            "down interface ignored even with the highest address"
        );
        driver.apply_event(&addr_new(2, "2001:db8::1/64"));
        assert_eq!(
            driver.router_id(),
            Some("192.168.1.1".parse::<std::net::Ipv4Addr>().unwrap()),
            "IPv6 never participates"
        );
    }

    /// A loopback whose only IPv4 address is 127/8 (the Linux default
    /// before any address is added) contributes nothing: the fallback
    /// pool answers instead — zebra's `IPV4_NET127` rule.
    #[test]
    fn router_id_skips_loopback_range_addresses() {
        let mut driver = RibDriver::new();
        driver.apply_event(&DataplaneEvent::LinkNew {
            ifindex: 1,
            name: "lo".into(),
            is_up: true,
            vrf_table: None,
            master_ifindex: None,
        });
        driver.apply_event(&addr_new(1, "127.0.0.1/8"));
        assert_eq!(
            driver.router_id(),
            None,
            "127/8 alone derives nothing — no candidate remains"
        );
        driver.apply_event(&addr_new(1, "10.0.0.1/32"));
        driver.apply_event(&addr_new(1, "127.0.0.9/32"));
        assert_eq!(
            driver.router_id(),
            Some("10.0.0.1".parse::<std::net::Ipv4Addr>().unwrap()),
            "whole 127/8 range excluded, not just 127.0.0.1"
        );
    }

    /// Pushes for owners that never attached (e.g. commands racing the
    /// attach) are dropped, not fatal.
    #[test]
    fn push_without_attach_is_dropped() {
        let mut driver = RibDriver::new();
        driver.apply(RibCommand::RegisterRedistribute {
            owner: 42,
            afi: 1,
            route_type: route_type::STATIC,
            instance: 0,
        });
        driver.apply(RibCommand::AddRoute(static_entry(
            "198.51.100.0/24",
            Nexthop::Blackhole,
            0,
        )));
        assert!(driver.sessions.is_empty());
    }
}
