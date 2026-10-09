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
//! carrying the withdrawn route to the same interested sessions. M2
//! closes the last gap: a SIGHUP config swap rides the same fan-out —
//! [`RibDriver::reload_static`] snapshots the bests a reload can touch,
//! swaps the static candidates, and re-checks each through the
//! best-change push. A2 gives the derived router-id the same event-driven
//! treatment: an address/link event that changes the id pushes
//! ROUTER_ID_UPDATE to every session that registered with ROUTER_ID_ADD
//! ([`RibDriver::reevaluate_router_id`]).

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::net::{IpAddr, Ipv4Addr};

use common::{
    Dataplane, DataplaneEvent, IpPrefix, LinkFlags, Nexthop, NexthopGroup, RouteEntry, TableId,
};
use rib::Rib;
use tokio::sync::mpsc;
use tracing::{debug, info, warn};

use zapi::{route_type_from, InterfaceMirror, RibCommand, SessionPush, DEFAULT_TABLE};

/// A client's identity as announced in its first HELLO (M6):
/// `(redist_default, instance, session_id)` — stable across one daemon's
/// reconnects (the same zclient re-HELLOs with the same fields) and
/// distinct between bgpd's three connections (main 10/0/0, auxiliary
/// 0x12/0/0, label-manager 10/0/1; pinned doc HELLO table). Approximation:
/// two daemons announcing the same triple would be conflated — nothing in
/// the observed universe does.
type ClientIdentity = (u8, u16, u32);

/// One live NEXTHOP_REGISTER interest: the registration flag that shapes
/// resolution (`resolve_via_default` — ospfd's NSSA default import check
/// sets it, staticd/bgpd do not; A23) plus the last resolution the owner
/// was told, the flip baseline for re-evaluation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct NhtReg {
    resolve_via_default: bool,
    last_told: Option<Nexthop>,
}

/// RIB plus the driver-side registration state ZAPI sessions feed.
pub struct RibDriver {
    pub rib: Rib,
    /// Push channel per attached session, keyed by the server-assigned
    /// owner id. Attached at accept time (`RibCommand::AttachSession`);
    /// pruned when a push finds the session gone.
    sessions: HashMap<u64, mpsc::Sender<SessionPush>>,
    /// NEXTHOP_REGISTER interests per owner, with the registration flags
    /// and the last resolution the owner was told (the answer to its
    /// register). A dataplane event that changes a resolution pushes an
    /// update only when it differs from this — no flip, no push.
    nht_registrations: HashMap<u64, BTreeMap<IpPrefix, NhtReg>>,
    /// REDISTRIBUTE_ADD interests per owner: (afi, route_type, instance).
    redistributes: HashMap<u64, BTreeSet<(u8, u8, u16)>>,
    /// HELLO-announced identity per owner (M6), the key into the two
    /// reconnect memories below.
    identities: HashMap<u64, ClientIdentity>,
    /// REDISTRIBUTE registrations remembered BEYOND their session's death,
    /// keyed by client identity (M6). bgpd's reconnect burst omits
    /// REDISTRIBUTE_ADD (pinned doc, operational finding 5) — a
    /// reconnecting incarnation of the same identity re-adopts these and
    /// gets the current state dumped instead of waiting for a
    /// re-registration that never comes. Cleared only by an explicit
    /// REDISTRIBUTE_DELETE; in-memory, so a rousterd restart loses it
    /// (disclosed: the restart flavor of the B1 D2 stale-client risk is
    /// narrowed, not closed).
    remembered: BTreeMap<ClientIdentity, BTreeSet<(u8, u8, u16)>>,
    /// The redistribute routes an identity was last TOLD, in push form,
    /// recorded only when a push was actually queued (M6) — the delta
    /// baseline: on re-establish, routes here that no longer exist are
    /// DELed so the client's stale copy is withdrawn. Approximation:
    /// queued ≠ delivered (a client dying with a full socket loses the
    /// distinction — D4's class); a push dropped for a full queue is
    /// treated as never told, so the next establish re-sends it as an ADD.
    last_known: BTreeMap<ClientIdentity, BTreeMap<IpPrefix, RouteEntry>>,
    /// ROUTER_ID_ADD interests per owner, with the last id the owner was
    /// told (the answer to its ROUTER_ID_ADD, or the latest push) — the
    /// flip baseline for [`RibDriver::reevaluate_router_id`] (A2). FRR
    /// zebra's `rid_clients` twin; unlike REDISTRIBUTE (operational
    /// finding 5) every daemon re-sends ROUTER_ID_ADD in its reconnect
    /// burst, so the interest is session-scoped and needs no
    /// identity-keyed memory.
    router_id_interests: HashMap<u64, Option<Ipv4Addr>>,
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
            identities: HashMap::new(),
            remembered: BTreeMap::new(),
            last_known: BTreeMap::new(),
            router_id_interests: HashMap::new(),
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
            // The reconnect resync (M6): adopt what this identity
            // registered before and dump the CURRENT state as a delta —
            // ADDs for everything present (idempotent refresh, zebra's
            // registration-dump semantics), DELs for what the identity was
            // last told but no longer exists. An extension past real
            // zebra, which never re-syncs a client that does not
            // re-register (exactly the gap that leaves bgpd stale).
            RibCommand::SessionEstablished {
                owner,
                protocol,
                instance,
                session_id,
            } => {
                let identity = (protocol, instance, session_id);
                self.identities.insert(owner, identity);
                // A bygone earlier connection of the same identity needs
                // no explicit retirement here: its registrations transfer
                // through `remembered` below, and its dead channel is
                // pruned lazily by the next push, exactly like any dead
                // session (pre-M6 behavior).
                let Some(keys) = self.remembered.get(&identity).cloned() else {
                    debug!(
                        owner,
                        ?identity,
                        "zapi: session established (no remembered registrations)"
                    );
                    return false;
                };
                if keys.is_empty() {
                    return false;
                }
                self.redistributes
                    .entry(owner)
                    .or_default()
                    .extend(keys.iter().copied());
                info!(
                    owner,
                    ?identity,
                    keys = keys.len(),
                    "zapi: session established; adopting remembered redistribute registrations (reconnect without REDISTRIBUTE_ADD)"
                );
                let mut adds_delivered: Vec<RouteEntry> = Vec::new();
                let mut dels_delivered: Vec<IpPrefix> = Vec::new();
                for &(afi, route_type, _instance) in &keys {
                    let current = self.dump_set(afi, route_type);
                    let present: BTreeSet<IpPrefix> =
                        current.iter().map(|best| best.prefix).collect();
                    for best in &current {
                        let entry = self.push_form(best);
                        info!(
                            owner,
                            prefix = %entry.prefix,
                            "zapi: reconnect redistribute dump push"
                        );
                        if self.push(owner, SessionPush::RedistributeRouteAdd(entry.clone())) {
                            adds_delivered.push(entry);
                        }
                    }
                    // The DEL half of the delta: what this identity was
                    // last told of this (afi, type) that is now gone.
                    let vanished: Vec<RouteEntry> = self
                        .last_known
                        .get(&identity)
                        .map(|told| {
                            told.values()
                                .filter(|e| {
                                    afi_of(&e.prefix) == afi
                                        && route_type_from(e.protocol) == route_type
                                        && !present.contains(&e.prefix)
                                })
                                .cloned()
                                .collect()
                        })
                        .unwrap_or_default();
                    for gone in &vanished {
                        info!(
                            owner,
                            prefix = %gone.prefix,
                            "zapi: reconnect redistribute dump DEL (vanished while away)"
                        );
                        if self.push(owner, SessionPush::RedistributeRouteDel(gone.clone())) {
                            dels_delivered.push(gone.prefix);
                        }
                    }
                }
                // Bookkeeping after the pushes (no overlapping borrows):
                // the baseline becomes exactly what was (queue-)delivered.
                let key_pairs: BTreeSet<(u8, u8)> = keys.iter().map(|k| (k.0, k.1)).collect();
                let told = self.last_known.entry(identity).or_default();
                told.retain(|_, entry| {
                    key_pairs.contains(&(afi_of(&entry.prefix), route_type_from(entry.protocol)))
                });
                for entry in adds_delivered {
                    told.insert(entry.prefix, entry);
                }
                for prefix in dels_delivered {
                    told.remove(&prefix);
                }
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
                resolve_via_default,
                reply,
            } => {
                let resolution = self
                    .rib
                    .lookup_nexthop_routed(prefix_addr(&prefix), resolve_via_default);
                self.nht_registrations.entry(owner).or_default().insert(
                    prefix,
                    NhtReg {
                        resolve_via_default,
                        last_told: resolution,
                    },
                );
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
                // M6: the registration outlives the session, keyed by the
                // owner's HELLO identity, so a reconnecting incarnation
                // re-adopts it (bgpd never re-sends cmd 12 on reconnect).
                if let Some(&identity) = self.identities.get(&owner) {
                    self.remembered
                        .entry(identity)
                        .or_default()
                        .insert((afi, route_type, instance));
                }
                debug!(owner, afi, route_type, instance, "zapi: redistribute add");
                // FRR zebra replays the current best routes of the
                // registered type on REDISTRIBUTE_ADD — staticd/bgpd expect
                // the dump on (re)connect (W2, closing Z3B disclosure 1).
                // Same push form as a best-change push; main table only
                // (the ZAPI edge lands every client route there).
                let dumped = self.dump_set(afi, route_type);
                let mut delivered: Vec<RouteEntry> = Vec::new();
                for best in dumped {
                    let entry = self.push_form(&best);
                    info!(
                        owner,
                        prefix = %entry.prefix,
                        "zapi: initial redistribute dump push"
                    );
                    if self.push(owner, SessionPush::RedistributeRouteAdd(entry.clone())) {
                        delivered.push(entry);
                    }
                }
                if let Some(&identity) = self.identities.get(&owner) {
                    let told = self.last_known.entry(identity).or_default();
                    for entry in delivered {
                        told.insert(entry.prefix, entry);
                    }
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
                // M6: an explicit unregister also erases the reconnect
                // memory — a re-establishing incarnation of the identity
                // must not resurrect an interest the client withdrew.
                if let Some(&identity) = self.identities.get(&owner) {
                    if let Some(set) = self.remembered.get_mut(&identity) {
                        set.remove(&(afi, route_type, instance));
                        if set.is_empty() {
                            self.remembered.remove(&identity);
                        }
                    }
                    if let Some(told) = self.last_known.get_mut(&identity) {
                        told.retain(|_, entry| {
                            !(afi_of(&entry.prefix) == afi
                                && route_type_from(entry.protocol) == route_type)
                        });
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
                        flags: iface.flags,
                        addresses: iface.addresses.clone(),
                    })
                    .collect();
                let _ = reply.send(mirror);
                false
            }
            // Answer immediately from the current derivation; the stored
            // value is the flip baseline for reevaluate_router_id (A2 —
            // the RegisterNexthop pattern: the session answer carries this
            // id, so it is what the owner was told).
            RibCommand::RequestRouterId { owner, reply } => {
                let router_id = self.router_id();
                debug!(owner, ?router_id, "zapi: router-id derived");
                self.router_id_interests.insert(owner, router_id);
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
    /// resolution, so they skip the pass. The same link/address events
    /// can change the derived router-id (A2), so they also re-run the
    /// router-id evaluation for ROUTER_ID_ADD-registered sessions.
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
            self.reevaluate_router_id();
        }
    }

    /// The resolution table every registered interest is re-checked
    /// against; only actual flips produce pushes.
    fn reevaluate_nht(&mut self) {
        let rib = &self.rib;
        let mut flips: Vec<(u64, IpPrefix, Option<Nexthop>)> = Vec::new();
        for (&owner, registrations) in &mut self.nht_registrations {
            for (prefix, reg) in registrations {
                let resolution =
                    rib.lookup_nexthop_routed(prefix_addr(prefix), reg.resolve_via_default);
                if reg.last_told != resolution {
                    flips.push((owner, *prefix, resolution));
                    reg.last_told = resolution;
                }
            }
        }
        for (owner, prefix, resolution) in flips {
            info!(owner, %prefix, resolved = resolution.is_some(), "zapi: NHT flip");
            self.push(owner, SessionPush::NexthopResolution { prefix, resolution });
        }
    }

    /// The router-id twin of [`Self::reevaluate_nht`] (A2): re-derives the
    /// id once per link/address event and pushes ROUTER_ID_UPDATE to every
    /// ROUTER_ID_ADD-registered owner whose last-told id differs. An id
    /// that becomes underivable updates the baseline but pushes nothing —
    /// FRR zebra skips registered clients on a zero id too
    /// (`router_id_update`, frr-10.2.2 zebra/router-id.c, which carries a
    /// TODO for exactly this case); like NHT, the baseline moves whether
    /// or not the push was queued (a stuck client re-asks on its next
    /// ROUTER_ID_ADD or reconnect, both of which re-register).
    fn reevaluate_router_id(&mut self) {
        let current = self.router_id();
        let flips: Vec<u64> = self
            .router_id_interests
            .iter_mut()
            .filter_map(|(&owner, last_told)| {
                if *last_told != current {
                    *last_told = current;
                    Some(owner)
                } else {
                    None
                }
            })
            .collect();
        for owner in flips {
            if let Some(router_id) = current {
                info!(owner, %router_id, "zapi: router-id change");
                self.push(owner, SessionPush::RouterIdUpdate(router_id));
            } else {
                debug!(
                    owner,
                    "zapi: router-id underivable; registered clients not notified (per zebra)"
                );
            }
        }
    }

    fn best_of(&self, table: TableId, prefix: IpPrefix) -> Option<RouteEntry> {
        self.rib.table(table).and_then(|t| t.best(&prefix)).cloned()
    }

    /// The router-id rousterd derives for ROUTER_ID_UPDATE (18) answers:
    /// FRR's documented default — the highest IPv4 address on an UP
    /// loopback interface, falling back to the highest IPv4 address on any
    /// UP interface, `None` when no UP interface carries one. Loopbacks
    /// are recognized by the kernel's IFF_LOOPBACK bit in the mirrored
    /// link flags (A12 — previously a `lo` name-prefix convention; a
    /// renamed or nonstandard loopback device now works, and an `lo`-named
    /// non-loopback no longer wins). IPv6 addresses never participate
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
            let pool = if iface.flags.contains(LinkFlags::LOOPBACK) {
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

    /// SIGHUP reload: swap the config-derived static routes through the
    /// RIB's soft-reconfiguration reload and fan the redistribute pushes
    /// a direct rib mutation cannot reach — a config swap that changes a
    /// prefix's best route must tell the registered sessions exactly like
    /// a route command would. Bests are snapshotted over the prefixes the
    /// swap can touch (the incoming keys plus the static keys already
    /// installed) and re-checked after the swap through
    /// [`RibDriver::push_best_change`], so unchanged prefixes stay silent.
    pub fn reload_static(&mut self, routes: &[RouteEntry]) {
        let mut keys: BTreeSet<(TableId, IpPrefix)> =
            routes.iter().map(|r| (r.table, r.prefix)).collect();
        keys.extend(self.rib.static_keys());
        let before: Vec<(TableId, IpPrefix, Option<RouteEntry>)> = keys
            .into_iter()
            .map(|(table, prefix)| (table, prefix, self.best_of(table, prefix)))
            .collect();
        self.rib.reload_static(routes);
        for (table, prefix, before) in before {
            self.push_best_change(table, prefix, before);
        }
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
                if self.push(owner, SessionPush::RedistributeRouteDel(entry.clone())) {
                    self.record_forgotten(owner, entry.prefix);
                }
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
            let clone = entry.clone();
            if self.push(owner, SessionPush::RedistributeRouteAdd(clone)) {
                self.record_told(owner, entry.clone());
            }
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

    /// The best routes of one (afi, route type) in the main table — the
    /// initial-dump set, shared by the registration (W2) and reconnect
    /// (M6) paths. Prefix-sorted (BTreeMap iteration).
    fn dump_set(&self, afi: u8, route_type: u8) -> Vec<RouteEntry> {
        self.rib
            .table(DEFAULT_TABLE)
            .map(|table| {
                table
                    .iter()
                    .filter_map(|(prefix, _)| table.best(prefix).cloned())
                    .filter(|best| {
                        afi_of(&best.prefix) == afi && route_type_from(best.protocol) == route_type
                    })
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Records a successfully queued redistribute ADD as the identity's
    /// last-known state (the M6 delta baseline for reconnect DELs).
    fn record_told(&mut self, owner: u64, entry: RouteEntry) {
        if let Some(&identity) = self.identities.get(&owner) {
            self.last_known
                .entry(identity)
                .or_default()
                .insert(entry.prefix, entry);
        }
    }

    /// Removes a prefix from the identity's last-known state (its DEL was
    /// queued — the client, if alive, was told to forget it).
    fn record_forgotten(&mut self, owner: u64, prefix: IpPrefix) {
        if let Some(&identity) = self.identities.get(&owner) {
            if let Some(told) = self.last_known.get_mut(&identity) {
                told.remove(&prefix);
            }
        }
    }

    /// Queues one push to one session. Bounded and non-blocking: the main
    /// loop must never stall on a slow daemon. Returns whether the push
    /// was queued — callers feeding the M6 delta baseline must not record
    /// a push a dead or full queue swallowed. A full queue drops the
    /// update with a warning (a stuck client re-syncs on re-registration
    /// or reconnect); a closed channel means the session is gone and
    /// prunes every registration it left behind (the identity-keyed
    /// reconnect memory deliberately survives).
    fn push(&mut self, owner: u64, item: SessionPush) -> bool {
        let Some(session) = self.sessions.get(&owner) else {
            debug!(owner, "zapi: push for unattached session dropped");
            return false;
        };
        match session.try_send(item) {
            Ok(()) => true,
            Err(mpsc::error::TrySendError::Full(_)) => {
                warn!(owner, "zapi: session push queue full; update dropped");
                false
            }
            Err(mpsc::error::TrySendError::Closed(_)) => {
                self.sessions.remove(&owner);
                self.nht_registrations.remove(&owner);
                self.redistributes.remove(&owner);
                self.identities.remove(&owner);
                self.router_id_interests.remove(&owner);
                debug!(owner, "zapi: session gone; registries pruned");
                false
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

    fn register_nht(
        driver: &mut RibDriver,
        owner: u64,
        prefix: &str,
        resolve_via_default: bool,
    ) -> Option<Nexthop> {
        let (tx, rx) = tokio::sync::oneshot::channel();
        driver.apply(RibCommand::RegisterNexthop {
            owner,
            prefix: prefix.parse().unwrap(),
            resolve_via_default,
            reply: tx,
        });
        rx.blocking_recv().expect("answer")
    }

    /// ROUTER_ID_ADD from `owner` (A2): returns the answer the session
    /// encodes, and registers the owner for change pushes.
    fn request_router_id(driver: &mut RibDriver, owner: u64) -> Option<Ipv4Addr> {
        let (tx, rx) = tokio::sync::oneshot::channel();
        driver.apply(RibCommand::RequestRouterId { owner, reply: tx });
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
        link_up_named(ifindex, &format!("eth{ifindex}"))
    }

    /// An UP broadcast link under an explicit name (the A12 router-id test
    /// needs a nonstandard `lo`-prefixed one that carries NO loopback bit).
    fn link_up_named(ifindex: u32, name: &str) -> DataplaneEvent {
        DataplaneEvent::LinkNew {
            ifindex,
            name: name.into(),
            is_up: true,
            flags: LinkFlags::up_broadcast(),
            vrf_table: None,
            master_ifindex: None,
        }
    }

    fn link_down(ifindex: u32) -> DataplaneEvent {
        DataplaneEvent::LinkNew {
            ifindex,
            name: format!("eth{ifindex}"),
            is_up: false,
            flags: LinkFlags::default(),
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

    /// A loopback link event: the kernel's IFF_LOOPBACK bit set (what the
    /// router-id derivation keys on since A12 — not the name).
    fn lo_link(ifindex: u32, name: &str, is_up: bool) -> DataplaneEvent {
        let mut flags = LinkFlags::LOOPBACK | LinkFlags::RUNNING;
        if is_up {
            flags |= LinkFlags::UP;
        }
        DataplaneEvent::LinkNew {
            ifindex,
            name: name.into(),
            is_up,
            flags,
            vrf_table: None,
            master_ifindex: None,
        }
    }

    #[test]
    fn attach_session_records_push_sender() {
        let mut driver = RibDriver::new();
        let rx = attach(&mut driver, 1);
        assert!(driver.sessions.contains_key(&1));
        drop(rx);
    }

    /// A23: an ospfd-shaped registration (`resolve_via_default`, the NSSA
    /// default import check's 0.0.0.0/0) is answered from the kernel
    /// mirror, while a flag-unset registration of the same prefix keeps
    /// the connected-only answer; a link/address flip still re-evaluates
    /// both with their own semantics (here: a bare-gateway mirrored
    /// default whose gateway comes on-link).
    #[test]
    fn ospfd_shaped_registration_answers_from_kernel_mirror() {
        use std::net::Ipv4Addr;
        let mut driver = RibDriver::new();
        let mut ospfd = attach(&mut driver, 1);
        let mut staticd = attach(&mut driver, 2);

        // A mirrored default with a bare gateway (no oif observed).
        driver.apply_event(&DataplaneEvent::RouteNew {
            table: 254,
            prefix: "0.0.0.0/0".parse().unwrap(),
            protocol: RouteProtocol::Kernel,
            metric: 0,
            gateway: Some(IpAddr::V4(Ipv4Addr::new(198, 51, 100, 1))),
            oif: None,
        });

        // staticd shape (flag 0): 0.0.0.0 is never on-link → unresolved.
        assert_eq!(register_nht(&mut driver, 2, "0.0.0.0/0", false), None);
        // ospfd shape (flag 1): the mirror's gateway is not on-link yet —
        // the routed answer is honest about that too.
        assert_eq!(register_nht(&mut driver, 1, "0.0.0.0/0", true), None);
        assert!(ospfd.try_recv().is_err(), "registration answers directly");
        assert!(staticd.try_recv().is_err());

        // The gateway's prefix appearing on-link resolves the mirrored
        // default's gateway — the routed interest flips, the flag-unset
        // one (still connected-only over 0.0.0.0) does not.
        driver.apply_event(&link_up(3));
        driver.apply_event(&addr_new(3, "198.51.100.2/24"));
        match ospfd.try_recv().expect("flip pushed") {
            SessionPush::NexthopResolution { prefix, resolution } => {
                assert_eq!(prefix, "0.0.0.0/0".parse().unwrap());
                assert_eq!(
                    resolution,
                    Some(Nexthop::Ipv4If(Ipv4Addr::new(198, 51, 100, 1), 3))
                );
            }
            other => panic!("expected NexthopResolution, got {other:?}"),
        }
        assert!(
            staticd.try_recv().is_err(),
            "flag-unset interest stays unresolved: no flip"
        );
    }

    /// The core Z3B flip: a registered-but-unresolved gateway resolves
    /// when a covering address appears, and ONLY the flip pushes.
    #[test]
    fn nht_flip_on_address_add_pushes_resolution() {
        let mut driver = RibDriver::new();
        let mut pushes = attach(&mut driver, 1);

        let answer = register_nht(&mut driver, 1, "10.9.9.9/32", false);
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

        let answer = register_nht(&mut driver, 1, "192.0.2.9/32", false);
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
        assert_eq!(register_nht(&mut driver, 1, "10.9.9.9/32", false), None);
        driver.apply_event(&DataplaneEvent::RouteNew {
            table: 254,
            prefix: "10.9.9.0/24".parse().unwrap(),
            protocol: RouteProtocol::Kernel,
            metric: 0,
            gateway: None,
            oif: None,
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
        assert!(register_nht(&mut driver, 1, "203.0.113.9/32", false).is_some());

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

    /// M2: a SIGHUP-style config swap through the driver fans the same
    /// redistribute pushes route commands get — ADD for a prefix whose
    /// best appeared or was replaced by a better one, DEL for one whose
    /// best vanished (in resolved push form), silence for prefixes the
    /// reload left alone.
    #[test]
    fn config_reload_pushes_redistribute_for_changed_bests() {
        let mut driver = RibDriver::new();
        let mut pushes = attach(&mut driver, 1);
        driver.apply(RibCommand::RegisterRedistribute {
            owner: 1,
            afi: 1,
            route_type: route_type::STATIC,
            instance: 0,
        });
        driver.apply_event(&link_up(2));
        driver.apply_event(&addr_new(2, "203.0.113.1/24"));

        // Running config, installed through the same reload path; the two
        // initial ADDs are the pre-reload state this test reloads from.
        driver.reload_static(&[
            static_entry(
                "198.51.100.0/24",
                Nexthop::Ipv4("203.0.113.9".parse().unwrap()),
                20,
            ),
            static_entry("203.0.113.0/24", Nexthop::Blackhole, 7),
        ]);
        for _ in 0..2 {
            assert!(matches!(
                pushes.try_recv().expect("initial install ADD"),
                SessionPush::RedistributeRouteAdd(_)
            ));
        }

        // SIGHUP: one prefix re-announced with a better metric, one kept
        // byte-identical, one new. Exactly the two changed bests push.
        driver.reload_static(&[
            static_entry(
                "198.51.100.0/24",
                Nexthop::Ipv4("203.0.113.9".parse().unwrap()),
                10,
            ),
            static_entry("203.0.113.0/24", Nexthop::Blackhole, 7),
            static_entry("192.0.2.0/24", Nexthop::Blackhole, 3),
        ]);
        let mut seen: BTreeMap<IpPrefix, (&'static str, u32)> = BTreeMap::new();
        while let Ok(push) = pushes.try_recv() {
            match push {
                SessionPush::RedistributeRouteAdd(entry) => {
                    assert!(
                        seen.insert(entry.prefix, ("ADD", entry.metric)).is_none(),
                        "one push per changed prefix"
                    );
                }
                other => panic!("unexpected push: {other:?}"),
            }
        }
        assert_eq!(seen.len(), 2, "the identical prefix stays silent");
        assert_eq!(
            seen[&"192.0.2.0/24".parse::<IpPrefix>().unwrap()],
            ("ADD", 3),
            "new prefix announced"
        );
        assert_eq!(
            seen[&"198.51.100.0/24".parse::<IpPrefix>().unwrap()],
            ("ADD", 10),
            "better replacement pushes the new best"
        );

        // Second SIGHUP drops the gateway route entirely: a DEL carrying
        // the withdrawn best, gateway hop in resolved push form.
        driver.reload_static(&[
            static_entry("203.0.113.0/24", Nexthop::Blackhole, 7),
            static_entry("192.0.2.0/24", Nexthop::Blackhole, 3),
        ]);
        match pushes.try_recv().expect("withdrawn best pushes DEL") {
            SessionPush::RedistributeRouteDel(entry) => {
                assert_eq!(entry.prefix, "198.51.100.0/24".parse().unwrap());
                assert_eq!(entry.metric, 10, "the withdrawn best's metric");
                assert_eq!(
                    entry.nexthops.hops(),
                    &[(Nexthop::Ipv4If("203.0.113.9".parse().unwrap(), 2), 1)],
                    "the DEL rides in resolved push form"
                );
            }
            other => panic!("expected RedistributeRouteDel, got {other:?}"),
        }
        assert!(pushes.try_recv().is_err(), "one push per withdrawal");
    }

    /// M2 discipline: a reload that changes no best route pushes nothing
    /// — a byte-identical config keeps every candidate (soft
    /// reconfiguration), and sessions registered for other types stay
    /// silent through static churn.
    #[test]
    fn config_reload_without_best_changes_pushes_nothing() {
        let mut driver = RibDriver::new();
        let mut static_pushes = attach(&mut driver, 1);
        let mut ospf_pushes = attach(&mut driver, 2);
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

        let running = vec![
            static_entry("198.51.100.0/24", Nexthop::Blackhole, 20),
            static_entry("203.0.113.0/24", Nexthop::Blackhole, 7),
        ];
        driver.reload_static(&running);
        for _ in 0..2 {
            assert!(matches!(
                static_pushes.try_recv().expect("initial install ADD"),
                SessionPush::RedistributeRouteAdd(_)
            ));
        }

        // Same config again: candidates are replaced same-protocol but
        // every best is identical — silence everywhere.
        driver.reload_static(&running);
        assert!(
            static_pushes.try_recv().is_err(),
            "identical reload: no push"
        );
        assert!(ospf_pushes.try_recv().is_err(), "no ospf best ever changed");

        // Static churn still never reaches the ospf-registered session;
        // the static-registered one sees only the dropped best.
        driver.reload_static(&[static_entry("198.51.100.0/24", Nexthop::Blackhole, 20)]);
        assert!(matches!(
            static_pushes.try_recv().expect("dropped best pushes DEL"),
            SessionPush::RedistributeRouteDel(_)
        ));
        assert!(
            ospf_pushes.try_recv().is_err(),
            "type filter holds through reload"
        );
        assert!(static_pushes.try_recv().is_err(), "one push per reload");
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

    fn establish(owner: u64, protocol: u8, session_id: u32) -> RibCommand {
        RibCommand::SessionEstablished {
            owner,
            protocol,
            instance: 0,
            session_id,
        }
    }

    /// M6, the D2 reconnect shape: bgpd (identity 10/0/0) registers
    /// `redistribute static` and is told two routes; its connection dies
    /// WITHOUT unregistering (bgpd never sends cmd 13, pinned doc); one
    /// route vanishes while it is away — the best-change DEL finds the
    /// dead channel and is dropped; the daemon reconnects and HELLOs
    /// only (finding 5: no REDISTRIBUTE_ADD re-sent). The remembered
    /// registration is adopted, the surviving route is re-dumped as an
    /// ADD, the vanished one is DELed from the baseline the identity was
    /// last told — and adoption re-arms the live best-change path.
    #[test]
    fn reconnect_establish_adopts_registrations_and_dumps_delta() {
        let mut driver = RibDriver::new();
        let mut bgpd = attach(&mut driver, 1);
        driver.apply(establish(1, 10, 0));
        assert!(
            bgpd.try_recv().is_err(),
            "first establish of an identity dumps nothing"
        );
        driver.apply_event(&link_up(2));
        driver.apply_event(&addr_new(2, "203.0.113.1/24"));
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
        driver.apply(RibCommand::RegisterRedistribute {
            owner: 1,
            afi: 1,
            route_type: route_type::STATIC,
            instance: 0,
        });
        // The W2 registration dump: both routes, prefix order — this is
        // also the delta baseline the reconnect below diffs against.
        for prefix in ["198.51.100.0/24", "203.0.113.0/24"] {
            match bgpd.try_recv().expect("registration dump ADD") {
                SessionPush::RedistributeRouteAdd(entry) => {
                    assert_eq!(entry.prefix, prefix.parse::<IpPrefix>().unwrap());
                }
                other => panic!("expected RedistributeRouteAdd, got {other:?}"),
            }
        }

        // The connection dies; a route vanishes while the daemon is away
        // (the DEL push finds the closed channel and is dropped — the
        // baseline keeps the route, which is exactly why the reconnect
        // must DEL it again).
        drop(bgpd);
        driver.apply(RibCommand::DeleteRoute {
            table: 254,
            prefix: "198.51.100.0/24".parse().unwrap(),
            protocol: RouteProtocol::Static,
        });

        // bgpd reconnects: NEW session id, SAME HELLO identity, and per
        // the pinned capture it does NOT re-send REDISTRIBUTE_ADD.
        let mut bgpd2 = attach(&mut driver, 2);
        driver.apply(establish(2, 10, 0));
        match bgpd2
            .try_recv()
            .expect("reconnect dump ADD for the survivor")
        {
            SessionPush::RedistributeRouteAdd(entry) => {
                assert_eq!(entry.prefix, "203.0.113.0/24".parse::<IpPrefix>().unwrap());
            }
            other => panic!("expected RedistributeRouteAdd, got {other:?}"),
        }
        match bgpd2
            .try_recv()
            .expect("reconnect dump DEL for the vanished route")
        {
            SessionPush::RedistributeRouteDel(entry) => {
                assert_eq!(entry.prefix, "198.51.100.0/24".parse::<IpPrefix>().unwrap());
                assert_eq!(
                    entry.protocol,
                    RouteProtocol::Static,
                    "the DEL carries the route as it last was"
                );
            }
            other => panic!("expected RedistributeRouteDel, got {other:?}"),
        }
        assert!(bgpd2.try_recv().is_err(), "the delta is exactly two pushes");

        // Adoption re-armed the live push path: a later best change
        // reaches the reconnecting session without any re-registration.
        driver.apply(RibCommand::AddRoute(static_entry(
            "192.0.2.0/24",
            Nexthop::Blackhole,
            3,
        )));
        assert!(matches!(
            bgpd2
                .try_recv()
                .expect("best change reaches the re-adopted session"),
            SessionPush::RedistributeRouteAdd(_)
        ));
    }

    /// M6 discipline: an identity with no remembered registrations gets
    /// NOTHING on establish — staticd's and ospfd's connect bursts (they
    /// never send REDISTRIBUTE_ADD) must not see surprise frames, even
    /// with routes of their own type sitting in the RIB.
    #[test]
    fn fresh_identity_establish_pushes_nothing() {
        let mut driver = RibDriver::new();
        let mut staticd = attach(&mut driver, 1);
        driver.apply(establish(1, 4, 0)); // staticd
        driver.apply_event(&link_up(2));
        driver.apply_event(&addr_new(2, "203.0.113.1/24"));
        driver.apply(RibCommand::AddRoute(static_entry(
            "203.0.113.0/24",
            Nexthop::Blackhole,
            7,
        )));
        let mut ospfd = attach(&mut driver, 2);
        driver.apply(establish(2, 7, 0)); // ospfd
        assert!(staticd.try_recv().is_err());
        assert!(
            ospfd.try_recv().is_err(),
            "unknown identity: no dump on establish"
        );
    }

    /// M6: an explicit REDISTRIBUTE_DELETE erases the reconnect memory —
    /// a re-establishing incarnation of the identity must not resurrect
    /// an interest the client withdrew (no capture ever showed bgpd send
    /// cmd 13, but if it does, it means it).
    #[test]
    fn unregister_erases_the_reconnect_memory() {
        let mut driver = RibDriver::new();
        let bgpd = attach(&mut driver, 1);
        driver.apply(establish(1, 10, 0));
        driver.apply(RibCommand::RegisterRedistribute {
            owner: 1,
            afi: 1,
            route_type: route_type::STATIC,
            instance: 0,
        });
        driver.apply(RibCommand::UnregisterRedistribute {
            owner: 1,
            afi: 1,
            route_type: route_type::STATIC,
            instance: 0,
        });
        drop(bgpd);
        let mut bgpd2 = attach(&mut driver, 2);
        driver.apply(establish(2, 10, 0));
        assert!(
            bgpd2.try_recv().is_err(),
            "unregistered interest stays unregistered across reconnect"
        );
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
        assert_eq!(register_nht(&mut driver, 9, "10.9.9.9/32", false), None);
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
        driver.apply_event(&lo_link(4, "lo", true));
        driver.apply_event(&addr_new(4, "10.0.0.5/32"));
        // 127/8 never contributes: without the exclusion every Linux lo
        // would answer 127.0.0.1 and same-id OSPF neighbors could never
        // become adjacent (live-observed with ospfd, Z5C).
        driver.apply_event(&addr_new(4, "127.0.0.1/8"));
        driver.apply_event(&link_up(2));
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
        driver.apply_event(&lo_link(4, "lo", false));
        assert_eq!(
            driver.router_id(),
            Some("192.168.1.1".parse::<std::net::Ipv4Addr>().unwrap())
        );

        // A higher address on a DOWN interface and IPv6 addresses never
        // contribute.
        driver.apply_event(&link_down(3));
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
        driver.apply_event(&lo_link(1, "lo", true));
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
            Some("10.0.0.1".parse::<Ipv4Addr>().unwrap()),
            "whole 127/8 range excluded, not just 127.0.0.1"
        );
    }

    /// A12: loopback detection keys on the mirrored IFF_LOOPBACK bit, not
    /// the interface name. An `lo`-named link WITHOUT the bit lands in the
    /// any-up pool (so a higher non-loopback address can win), and a
    /// nonstandard loopback name WITH the bit takes loopback precedence —
    /// the two cases the retired `lo`-prefix convention got wrong.
    #[test]
    fn router_id_loopback_detection_is_flag_based() {
        let mut driver = RibDriver::new();

        // "lo"-named but no LOOPBACK bit (e.g. a renamed ethernet): NOT a
        // loopback — its address competes in the any-up pool.
        driver.apply_event(&link_up_named(2, "lo200"));
        driver.apply_event(&addr_new(2, "10.0.0.5/32"));
        assert_eq!(
            driver.router_id(),
            Some("10.0.0.5".parse::<Ipv4Addr>().unwrap()),
            "lo-named non-loopback still derives (any-up pool)"
        );

        // A real loopback under a nonstandard name, with a LOWER address:
        // the bit, not the name or the address height, decides the pool.
        driver.apply_event(&lo_link(4, "loopback-core", true));
        driver.apply_event(&addr_new(4, "10.0.0.1/32"));
        assert_eq!(
            driver.router_id(),
            Some("10.0.0.1".parse::<Ipv4Addr>().unwrap()),
            "IFF_LOOPBACK bit wins over the higher any-up address"
        );

        // And the bit flapping re-pools the same interface (kernel flag
        // change arrives as a fresh RTM_NEWLINK).
        driver.apply_event(&DataplaneEvent::LinkNew {
            ifindex: 4,
            name: "loopback-core".into(),
            is_up: true,
            flags: LinkFlags::up_broadcast(),
            vrf_table: None,
            master_ifindex: None,
        });
        assert_eq!(
            driver.router_id(),
            Some("10.0.0.5".parse::<Ipv4Addr>().unwrap()),
            "LOOPBACK bit gone: back to the highest any-up address"
        );
    }

    /// A2: a derived router-id change on an address/link event pushes
    /// ROUTER_ID_UPDATE to every session that registered with
    /// ROUTER_ID_ADD — and only to those. The underivable direction stays
    /// silent (per zebra's documented skip) but still moves the baseline,
    /// so the id coming back pushes again.
    #[test]
    fn router_id_change_pushes_update_to_registered_sessions() {
        let mut driver = RibDriver::new();
        let mut ospfd = attach(&mut driver, 1);
        let mut bgpd = attach(&mut driver, 2);
        let mut staticd = attach(&mut driver, 3); // never sends ROUTER_ID_ADD

        assert_eq!(
            request_router_id(&mut driver, 1),
            None,
            "no mirror: underivable"
        );
        assert_eq!(request_router_id(&mut driver, 2), None);
        assert!(ospfd.try_recv().is_err(), "None answers no frame");

        // An address appears: the id derives and both registered sessions
        // are told, unprompted.
        driver.apply_event(&link_up(2));
        driver.apply_event(&addr_new(2, "192.0.2.1/24"));
        for (name, rx) in [("ospfd", &mut ospfd), ("bgpd", &mut bgpd)] {
            match rx.try_recv().expect("registered session is told") {
                SessionPush::RouterIdUpdate(id) => assert_eq!(
                    id,
                    "192.0.2.1".parse::<Ipv4Addr>().unwrap(),
                    "{name} sees the derived id"
                ),
                other => panic!("expected RouterIdUpdate, got {other:?}"),
            }
        }
        assert!(
            staticd.try_recv().is_err(),
            "a session that never registered is not told"
        );

        // Idempotent events and id-neutral links push nothing.
        driver.apply_event(&addr_new(2, "192.0.2.1/24"));
        driver.apply_event(&link_up(9)); // new UP link, no addresses
        assert!(ospfd.try_recv().is_err(), "no id change, no push");
        assert!(bgpd.try_recv().is_err());

        // A higher address changes the id: one push each, new value.
        driver.apply_event(&addr_new(2, "198.51.100.1/24"));
        match ospfd.try_recv().expect("change pushes") {
            SessionPush::RouterIdUpdate(id) => {
                assert_eq!(id, "198.51.100.1".parse::<Ipv4Addr>().unwrap())
            }
            other => panic!("expected RouterIdUpdate, got {other:?}"),
        }
        assert!(matches!(
            bgpd.try_recv().expect("change pushes"),
            SessionPush::RouterIdUpdate(_)
        ));

        // The carrying link goes down: the id becomes underivable — no
        // push (zebra skips registered clients on a zero id), and the
        // baseline moves silently.
        driver.apply_event(&link_down(2));
        assert!(ospfd.try_recv().is_err(), "underivable pushes nothing");
        assert!(bgpd.try_recv().is_err());

        // The link returns: the id re-derives and is pushed again — proof
        // the silent baseline update above happened.
        driver.apply_event(&link_up(2));
        match ospfd.try_recv().expect("re-derive pushes") {
            SessionPush::RouterIdUpdate(id) => {
                assert_eq!(
                    id,
                    "198.51.100.1".parse::<Ipv4Addr>().unwrap(),
                    "addresses survive the link bounce in the mirror"
                )
            }
            other => panic!("expected RouterIdUpdate, got {other:?}"),
        }
        assert!(matches!(
            bgpd.try_recv().expect("re-derive pushes"),
            SessionPush::RouterIdUpdate(_)
        ));
        assert!(
            staticd.try_recv().is_err(),
            "the never-registered session stays silent throughout"
        );
    }

    /// A2 discipline: a dead session's router-id interest is pruned by the
    /// first push attempt, exactly like the other registries.
    #[test]
    fn dead_session_prunes_router_id_interest() {
        let mut driver = RibDriver::new();
        let pushes = attach(&mut driver, 9);
        assert_eq!(request_router_id(&mut driver, 9), None);
        drop(pushes); // session gone

        driver.apply_event(&link_up(2));
        driver.apply_event(&addr_new(2, "192.0.2.1/24"));
        assert!(!driver.sessions.contains_key(&9), "closed channel pruned");
        assert!(
            !driver.router_id_interests.contains_key(&9),
            "router-id interest pruned with the session"
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
