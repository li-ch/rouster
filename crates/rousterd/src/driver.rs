//! The RIB driver: the slice of the main loop that turns ZAPI
//! [`RibCommand`]s into RIB mutations, NHT/interface replies, and (when
//! routes changed) a reconcile pass.
//!
//! Factored out of `main` (Z4) so the staticd end-to-end test can drive
//! the exact main-loop behavior in-process against a mock dataplane —
//! `main` itself runs this against netlink inside its `tokio::select!`.

use std::collections::{BTreeSet, HashMap};

use common::{Dataplane, IpPrefix};
use rib::Rib;
use tokio::sync::mpsc;
use tracing::{debug, info};

use zapi::{InterfaceMirror, RibCommand};

/// RIB plus the driver-side registration state ZAPI sessions feed.
pub struct RibDriver {
    pub rib: Rib,
    /// NEXTHOP_REGISTER interests per owner (server-assigned connection
    /// id); Z3B re-evaluates these on dataplane events.
    nht_registrations: HashMap<u64, BTreeSet<IpPrefix>>,
    /// REDISTRIBUTE_ADD interests per owner; Z3B pushes route updates to
    /// these.
    redistributes: HashMap<u64, BTreeSet<(u8, u8, u16)>>,
}

impl Default for RibDriver {
    fn default() -> Self {
        Self::new()
    }
}

impl RibDriver {
    pub fn new() -> Self {
        Self {
            rib: Rib::new(),
            nht_registrations: HashMap::new(),
            redistributes: HashMap::new(),
        }
    }

    /// Applies one ZAPI session command to the RIB and the driver-side
    /// registries. Returns whether the protocol tables changed (the
    /// caller reconciles on change).
    pub fn apply(&mut self, command: RibCommand) -> bool {
        match command {
            RibCommand::AddRoute(entry) => {
                info!(prefix = %entry.prefix, protocol = ?entry.protocol, "zapi: route add");
                self.rib.add_route(entry);
                true
            }
            RibCommand::DeleteRoute {
                table,
                prefix,
                protocol,
            } => {
                let removed = self.rib.table_mut(table).remove(&prefix, protocol);
                if removed {
                    info!(prefix = %prefix, ?protocol, "zapi: route delete");
                } else {
                    debug!(prefix = %prefix, ?protocol, "zapi: route delete for absent route");
                }
                removed
            }
            // Answer immediately from the RIB's current resolution; the
            // registration itself is Z3B's input (event-driven
            // re-evaluation).
            RibCommand::RegisterNexthop {
                owner,
                prefix,
                reply,
            } => {
                self.nht_registrations
                    .entry(owner)
                    .or_default()
                    .insert(prefix);
                let resolution = self.rib.lookup_nexthop(prefix_addr(&prefix));
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
            // Tonight: store only (REDISTRIBUTE_ROUTE_ADD push is Z3B).
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

fn prefix_addr(prefix: &IpPrefix) -> std::net::IpAddr {
    match prefix {
        IpPrefix::V4(p) => std::net::IpAddr::V4(p.addr()),
        IpPrefix::V6(p) => std::net::IpAddr::V6(p.addr()),
    }
}
