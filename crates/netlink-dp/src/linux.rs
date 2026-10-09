//! Real rtnetlink-backed dataplane (Linux only).

use std::collections::BTreeMap;
use std::sync::Mutex;

use common::{
    Dataplane, DataplaneError, DataplaneEvent, IpPrefix, Ipv4Prefix, Ipv6Prefix,
    NeighbourCacheInfo, NeighbourEntry, NeighbourProtocol, Nexthop, RouteEntry, RouteProtocol,
    SavMonitorCounts, SavProgram,
};
use futures::TryStreamExt;
use netlink_packet_route::address::{AddressAttribute, AddressMessage};
use netlink_packet_route::link::{
    InfoData, InfoVrf, LinkAttribute, LinkFlags, LinkInfo, LinkMessage,
};
use netlink_packet_route::neighbour::{NeighbourAddress, NeighbourAttribute, NeighbourMessage};
use netlink_packet_route::route::{
    RouteAddress, RouteAttribute, RouteMessage, RouteNextHop, RouteProtocol as NlRouteProtocol,
    RouteScope, RouteType,
};
use netlink_packet_route::{AddressFamily, RouteNetlinkMessage};
use rtnetlink::packet_core::{NetlinkMessage, NetlinkPayload};
use rtnetlink::sys::{protocols::NETLINK_ROUTE, AsyncSocket, SocketAddr, TokioSocket};
use tracing::{debug, info, instrument, warn};

use crate::sav::SysctlPlan;
use crate::sav_state;

/// Where the applied-SAV state file lives (the daemon run dir AGENTS.md
/// sanctions; `/run/rouster`). Cross-process persistence: a restarted
/// daemon — or the smoke binary's one-process-per-command shape — reads
/// what a previous process applied, so clear/replace can restore the
/// true pre-SAV values.
const SAV_STATE_DIR: &str = "/run/rouster";
const SAV_STATE_PATH: &str = "/run/rouster/sav-applied";

/// Netlink-backed dataplane handle.
///
/// Owns the multicast event receiver; `next_event` drives the kernel→RIB
/// direction of the mirror. SAV enforcement state (`sav_applied`) records
/// the rp_filter values this handle wrote and the pre-SAV values to
/// restore on clear/replace.
pub struct NetlinkDataplane {
    handle: rtnetlink::Handle,
    messages: futures::channel::mpsc::UnboundedReceiver<(
        NetlinkMessage<RouteNetlinkMessage>,
        SocketAddr,
    )>,
    /// ifindex → (interface name at write time, pre-SAV rp_filter,
    /// applied value). Interior-mutable so the `&self` trait methods
    /// can update it; never held across an await.
    sav_applied: Mutex<BTreeMap<u32, (String, u8, u8)>>,
}

impl NetlinkDataplane {
    /// Opens the netlink connection, subscribed to link/address/route/
    /// neighbour multicast groups so kernel changes arrive as events.
    ///
    /// The returned future is the connection driver; spawn it on the runtime
    /// (e.g. `tokio::spawn(conn)`).
    #[allow(clippy::type_complexity)]
    pub fn new() -> std::io::Result<(Self, impl std::future::Future<Output = ()> + Send)> {
        let mut socket = TokioSocket::new(NETLINK_ROUTE)?;
        let groups = libc::RTMGRP_LINK
            | libc::RTMGRP_IPV4_IFADDR
            | libc::RTMGRP_IPV6_IFADDR
            | libc::RTMGRP_IPV4_ROUTE
            | libc::RTMGRP_IPV6_ROUTE
            | libc::RTMGRP_NEIGH;
        socket
            .socket_mut()
            .bind(&SocketAddr::new(0, groups as u32))?;

        let (connection, handle, messages) = rtnetlink::from_socket(socket);
        Ok((
            Self {
                handle,
                messages,
                sav_applied: Mutex::new(BTreeMap::new()),
            },
            connection,
        ))
    }

    pub fn handle(&self) -> &rtnetlink::Handle {
        &self.handle
    }

    /// Initial mirror: dumps kernel links, addresses, and kernel-origin
    /// routes as synthetic `LinkNew`/`AddressNew`/`RouteNew` events, in an
    /// order the RIB can apply directly.
    pub async fn dump_state(&self) -> Result<Vec<DataplaneEvent>, DataplaneError> {
        let mut events = Vec::new();

        let mut links = self.handle.link().get().execute();
        while let Some(msg) = links.try_next().await.map_err(nl_err)? {
            if let Some(ev) = link_event(&msg, true) {
                events.push(ev);
            }
        }

        let mut addrs = self.handle.address().get().execute();
        while let Some(msg) = addrs.try_next().await.map_err(nl_err)? {
            if let Some(ev) = address_event(&msg, true) {
                events.push(ev);
            }
        }

        // Same filter and mapping as the live route notifications.
        let mut routes = self.handle.route().get(RouteMessage::default()).execute();
        while let Some(msg) = routes.try_next().await.map_err(nl_err)? {
            if let Some(ev) = route_new_event(&msg) {
                events.push(ev);
            }
        }

        // Neighbour table (ARP/NDP), same mapping as the live notifications.
        let mut neighs = self.handle.neighbours().get().execute();
        while let Some(msg) = neighs.try_next().await.map_err(nl_err)? {
            if let Some(ev) = neighbour_event(&msg, true) {
                events.push(ev);
            }
        }

        Ok(events)
    }

    /// Counts routes currently in the kernel. Phase 0 uses this as a minimal
    /// "mirror" sanity check; full route reconciliation comes later.
    pub async fn dump_route_count(&self) -> Result<usize, DataplaneError> {
        let mut dump = self.handle.route().get(RouteMessage::default()).execute();
        let mut count = 0usize;
        while let Some(_msg) = dump.try_next().await.map_err(nl_err)? {
            count += 1;
        }
        Ok(count)
    }

    /// Next kernel event, mapped to a [`DataplaneEvent`]. Returns `None` when
    /// the connection is closed. Unmapped message kinds are skipped.
    pub async fn next_event(&mut self) -> Option<DataplaneEvent> {
        use futures::StreamExt;
        loop {
            let (msg, _addr) = self.messages.next().await?;
            let NetlinkPayload::InnerMessage(inner) = msg.payload else {
                continue;
            };
            let ev = match inner {
                RouteNetlinkMessage::NewLink(m) => link_event(&m, true),
                RouteNetlinkMessage::DelLink(m) => Some(DataplaneEvent::LinkDel {
                    ifindex: m.header.index,
                }),
                RouteNetlinkMessage::NewAddress(m) => address_event(&m, true),
                RouteNetlinkMessage::DelAddress(m) => address_event(&m, false),
                RouteNetlinkMessage::NewRoute(m) => route_new_event(&m),
                RouteNetlinkMessage::DelRoute(m) => route_del_event(&m),
                RouteNetlinkMessage::NewNeighbour(m) => neighbour_event(&m, true),
                RouteNetlinkMessage::DelNeighbour(m) => neighbour_event(&m, false),
                // Kernel neighbour-resolution requests (RTM_GETNEIGH) and
                // everything unmapped are skipped.
                _ => None,
            };
            if ev.is_some() {
                return ev;
            }
        }
    }
}

/// `RT_TABLE_COMPAT` — header marker for routing tables addressed by
/// `RTA_TABLE` (ids > 255).
const RT_TABLE_COMPAT: u8 = 252;

/// Maps a kernel link message to a `LinkNew` event (name resolution and
/// VRF awareness included).
///
/// VRF modeling: a link of kind "vrf" (`IFLA_INFO_KIND`) carries its bound
/// routing table in `IFLA_VRF_TABLE` — netlink-packet-route parses that
/// pairing as [`LinkInfo::Data`](`InfoData::Vrf`), so seeing the variant
/// is itself the kind check and [`InfoVrf::TableId`] the table. Enslavement
/// arrives as `IFLA_MASTER` ([`LinkAttribute::Controller`], the master
/// device's ifindex — a VRF device here, though bridges and bonds share
/// the attribute).
fn link_event(msg: &LinkMessage, _is_new: bool) -> Option<DataplaneEvent> {
    let name = msg.attributes.iter().find_map(|a| match a {
        LinkAttribute::IfName(n) => Some(n.clone()),
        _ => None,
    })?;
    let mut vrf_table = None;
    let mut master_ifindex = None;
    for attr in &msg.attributes {
        match attr {
            LinkAttribute::Controller(ix) => master_ifindex = Some(*ix),
            LinkAttribute::LinkInfo(infos) => {
                for info in infos {
                    if let LinkInfo::Data(InfoData::Vrf(nlas)) = info {
                        vrf_table = nlas.iter().find_map(|nla| match nla {
                            InfoVrf::TableId(t) => Some(*t),
                            // InfoVrf is non_exhaustive; unknown vrf
                            // attributes carry no table.
                            _ => None,
                        });
                    }
                }
            }
            _ => {}
        }
    }
    Some(DataplaneEvent::LinkNew {
        ifindex: msg.header.index,
        name,
        is_up: msg.header.flags.contains(LinkFlags::Up),
        vrf_table,
        master_ifindex,
    })
}

/// Maps a kernel address message to an `AddressNew`/`AddressDel` event.
fn address_event(msg: &AddressMessage, is_new: bool) -> Option<DataplaneEvent> {
    let addr = msg.attributes.iter().find_map(|a| match a {
        AddressAttribute::Address(ip) => Some(*ip),
        _ => None,
    })?;
    let prefix: IpPrefix = match addr {
        std::net::IpAddr::V4(a) => Ipv4Prefix::new(a, msg.header.prefix_len).ok()?.into(),
        std::net::IpAddr::V6(a) => Ipv6Prefix::new(a, msg.header.prefix_len).ok()?.into(),
    };
    Some(if is_new {
        DataplaneEvent::AddressNew {
            ifindex: msg.header.index,
            prefix,
        }
    } else {
        DataplaneEvent::AddressDel {
            ifindex: msg.header.index,
            prefix,
        }
    })
}

fn nl_err(e: rtnetlink::Error) -> DataplaneError {
    DataplaneError::Other(e.to_string())
}

/// Maps a kernel neighbour message (RTM_NEWNEIGH / RTM_DELNEIGH, and the
/// dump replies, which share NewNeighbour's shape) to a mirror event.
///
/// Entries without `NDA_DST` (bridge FDB rows key on lladdr instead) are
/// skipped: they are not IP neighbours. State and flag bits pass through
/// to [`NeighbourEntry::from_rtnetlink`] unfiltered, and the optional
/// `NDA_CACHEINFO` (ageing statistics) and `NDA_PROTOCOL` (originating
/// RTPROT) attributes ride along when present — the mirror keeps exactly
/// what the kernel reported.
fn neighbour_event(msg: &NeighbourMessage, is_new: bool) -> Option<DataplaneEvent> {
    let ip = msg.attributes.iter().find_map(|a| match a {
        NeighbourAttribute::Destination(NeighbourAddress::Inet(a)) => {
            Some(std::net::IpAddr::V4(*a))
        }
        NeighbourAttribute::Destination(NeighbourAddress::Inet6(a)) => {
            Some(std::net::IpAddr::V6(*a))
        }
        _ => None,
    })?;
    let link_ifindex = msg.header.ifindex;
    if is_new {
        let lladdr = msg.attributes.iter().find_map(|a| match a {
            NeighbourAttribute::LinkLocalAddress(bytes) => Some(bytes.clone()),
            _ => None,
        });
        let cacheinfo = msg.attributes.iter().find_map(|a| match a {
            NeighbourAttribute::CacheInfo(ci) => Some(NeighbourCacheInfo {
                confirmed: ci.confirmed,
                used: ci.used,
                updated: ci.updated,
                refcnt: ci.refcnt,
            }),
            _ => None,
        });
        let protocol = msg.attributes.iter().find_map(|a| match a {
            // RouteProtocol here is the wire RTPROT discriminant; the
            // From<RouteProtocol> for u8 impl covers every variant of the
            // #[non_exhaustive] enum, so the raw value passes through
            // without a match to go stale.
            NeighbourAttribute::Protocol(p) => Some(NeighbourProtocol::from_bits(u8::from(*p))),
            _ => None,
        });
        Some(DataplaneEvent::NeighbourNew {
            entry: NeighbourEntry::from_rtnetlink(
                ip,
                link_ifindex,
                lladdr,
                msg.header.state.into(),
                msg.header.flags.bits(),
            )
            .with_cacheinfo(cacheinfo)
            .with_protocol(protocol),
        })
    } else {
        Some(DataplaneEvent::NeighbourDel { ip, link_ifindex })
    }
}

/// Maps a kernel NewRoute notification to a mirror event.
///
/// Feedback-loop filter: every route Rouster programs echoes back on this
/// socket, so only kernel-origin routes (`RTPROT_KERNEL`/`RTPROT_BOOT`-class
/// — administrative additions like `ip route add`) become mirror events;
/// static/bgp/ospf/rip origins are ours and are skipped.
fn route_new_event(msg: &RouteMessage) -> Option<DataplaneEvent> {
    if !matches!(
        msg.header.protocol,
        NlRouteProtocol::Kernel | NlRouteProtocol::Boot
    ) {
        return None;
    }
    Some(DataplaneEvent::RouteNew {
        table: route_table(msg),
        prefix: route_prefix(msg)?,
        protocol: RouteProtocol::Kernel,
        metric: route_metric(msg),
    })
}

/// Maps a kernel DelRoute notification. Forwarded regardless of origin: a
/// deletion of a route we believed installed means someone else removed it,
/// and the RIB must drop its belief so reconcile reinstalls what is still
/// desired. Our own withdrawals echo here too, but replaying them is
/// idempotent.
fn route_del_event(msg: &RouteMessage) -> Option<DataplaneEvent> {
    Some(DataplaneEvent::RouteDel {
        table: route_table(msg),
        prefix: route_prefix(msg)?,
    })
}

/// Routing table of a route message; `RTA_TABLE` overrides the 8-bit header
/// field for ids > 255.
fn route_table(msg: &RouteMessage) -> u32 {
    msg.attributes
        .iter()
        .find_map(|a| match a {
            RouteAttribute::Table(t) => Some(*t),
            _ => None,
        })
        .unwrap_or(msg.header.table as u32)
}

/// Destination prefix; a message without `RTA_DST` is the default route of
/// its address family.
fn route_prefix(msg: &RouteMessage) -> Option<IpPrefix> {
    let dst = msg.attributes.iter().find_map(|a| match a {
        RouteAttribute::Destination(d) => Some(d.clone()),
        _ => None,
    });
    let len = msg.header.destination_prefix_length;
    match (msg.header.address_family, dst) {
        (AddressFamily::Inet, Some(RouteAddress::Inet(a))) => {
            Ipv4Prefix::new(a, len).ok().map(Into::into)
        }
        (AddressFamily::Inet6, Some(RouteAddress::Inet6(a))) => {
            Ipv6Prefix::new(a, len).ok().map(Into::into)
        }
        (AddressFamily::Inet, None) => Ipv4Prefix::new(std::net::Ipv4Addr::UNSPECIFIED, len)
            .ok()
            .map(Into::into),
        (AddressFamily::Inet6, None) => Ipv6Prefix::new(std::net::Ipv6Addr::UNSPECIFIED, len)
            .ok()
            .map(Into::into),
        _ => None,
    }
}

fn route_metric(msg: &RouteMessage) -> u32 {
    msg.attributes
        .iter()
        .find_map(|a| match a {
            RouteAttribute::Priority(m) => Some(*m),
            _ => None,
        })
        .unwrap_or(0)
}

/// Rejects a gateway whose address family differs from the route's prefix
/// (RFC 5549-style cross-AF nexthops are not supported yet).
fn check_same_af(entry: &RouteEntry, gateway: &RouteAddress) -> Result<(), DataplaneError> {
    let same = matches!(
        (entry.prefix, gateway),
        (IpPrefix::V4(_), RouteAddress::Inet(_)) | (IpPrefix::V6(_), RouteAddress::Inet6(_))
    );
    if same {
        Ok(())
    } else {
        Err(DataplaneError::Unsupported(
            "cross-AF nexthop (RFC 5549) not supported yet",
        ))
    }
}

/// Maps Rouster's route protocol to an RTPROT_* value.
fn nl_protocol(entry: &RouteEntry) -> NlRouteProtocol {
    use common::RouteProtocol as P;
    match entry.protocol {
        P::Kernel => NlRouteProtocol::Kernel,
        P::Connected => NlRouteProtocol::Kernel, // connected routes are kernel-owned
        P::Static => NlRouteProtocol::Static,
        P::Bgp => NlRouteProtocol::Bgp,
        // The kernel has no RTPROT_ISIS; fall back to Static.
        P::Ospf => NlRouteProtocol::Ospf,
        P::IsIs => NlRouteProtocol::Static,
        P::Rip => NlRouteProtocol::Rip,
        P::Local => NlRouteProtocol::Static,
    }
}

/// Builds the netlink route message shared by RTM_NEWROUTE and RTM_DELROUTE.
///
/// Nexthop mapping: a group of ≥2 hops is programmed as `RTA_MULTIPATH`
/// (one `rtnexthop` per hop: gateway attribute + ifindex, weight byte from
/// the group's weight); single-hop groups and blackholes use direct
/// `RTA_GATEWAY`/`RTA_OIF` attributes. Nexthop *objects* (`RTA_NH_ID`) are
/// a documented follow-up.
fn build_message(entry: &RouteEntry) -> Result<RouteMessage, DataplaneError> {
    let mut msg = RouteMessage::default();

    match entry.prefix {
        IpPrefix::V4(p) => {
            msg.header.address_family = AddressFamily::Inet;
            msg.header.destination_prefix_length = p.prefix_len();
            msg.attributes
                .push(RouteAttribute::Destination(RouteAddress::Inet(p.addr())));
        }
        IpPrefix::V6(p) => {
            msg.header.address_family = AddressFamily::Inet6;
            msg.header.destination_prefix_length = p.prefix_len();
            msg.attributes
                .push(RouteAttribute::Destination(RouteAddress::Inet6(p.addr())));
        }
    }

    // rtm_table is 8 bits. Ids > 255 follow the kernel/iproute2 convention:
    // the header carries RT_TABLE_COMPAT and RTA_TABLE the real id (the
    // kernel prefers RTA_TABLE whenever present; the mirror-read side
    // already decodes both).
    if entry.table > 255 {
        msg.header.table = RT_TABLE_COMPAT;
        msg.attributes.push(RouteAttribute::Table(entry.table));
    } else {
        msg.header.table = entry.table as u8;
    }
    msg.header.protocol = nl_protocol(entry);
    msg.header.scope = RouteScope::Universe;
    msg.header.kind = RouteType::Unicast;
    msg.attributes.push(RouteAttribute::Priority(entry.metric));

    let hops = entry.nexthops.hops();
    if hops.len() >= 2 {
        // ECMP: RTA_MULTIPATH. Hops must be in resolved programming form
        // (each carries an ifindex); the RIB's reconcile guarantees that,
        // and the kernel needs an ifindex per rtnexthop anyway.
        let mut multipath = Vec::with_capacity(hops.len());
        for &(hop, weight) in hops {
            let (gateway, ifindex) = match hop {
                Nexthop::Ipv4If(gw, ix) => (Some(RouteAddress::Inet(gw)), ix),
                Nexthop::Ipv6If(gw, ix) => (Some(RouteAddress::Inet6(gw)), ix),
                Nexthop::IfIndex(ix) => (None, ix),
                Nexthop::Ipv4(_) | Nexthop::Ipv6(_) => {
                    return Err(DataplaneError::Unsupported(
                        "unresolved gateway in ECMP group; resolution must precede programming",
                    ));
                }
                Nexthop::Blackhole => {
                    return Err(DataplaneError::Unsupported(
                        "blackhole cannot be part of an ECMP group",
                    ));
                }
            };
            if let Some(addr) = &gateway {
                check_same_af(entry, addr)?;
            }
            // RTNH weight byte: stored as weight - 1 (equal weights → 0),
            // matching iproute2. (`RouteNextHop` is `#[non_exhaustive]`,
            // so it is built from `default()` + field writes.)
            let mut nexthop = RouteNextHop::default();
            nexthop.hops = weight.saturating_sub(1);
            nexthop.interface_index = ifindex;
            if let Some(addr) = gateway {
                nexthop.attributes.push(RouteAttribute::Gateway(addr));
            }
            multipath.push(nexthop);
        }
        msg.attributes.push(RouteAttribute::MultiPath(multipath));
        return Ok(msg);
    }

    let hop = hops.first().map(|(h, _)| *h).unwrap_or(Nexthop::Blackhole);

    match hop {
        Nexthop::Ipv4(gw) => msg
            .attributes
            .push(RouteAttribute::Gateway(RouteAddress::Inet(gw))),
        Nexthop::IfIndex(ix) => msg.attributes.push(RouteAttribute::Oif(ix)),
        Nexthop::Ipv4If(gw, ix) => {
            msg.attributes
                .push(RouteAttribute::Gateway(RouteAddress::Inet(gw)));
            msg.attributes.push(RouteAttribute::Oif(ix));
        }
        Nexthop::Ipv6(gw) => {
            if matches!(entry.prefix, IpPrefix::V4(_)) {
                return Err(DataplaneError::Unsupported(
                    "cross-AF nexthop (RFC 5549) not supported yet",
                ));
            }
            msg.attributes
                .push(RouteAttribute::Gateway(RouteAddress::Inet6(gw)));
        }
        Nexthop::Ipv6If(gw, ix) => {
            if matches!(entry.prefix, IpPrefix::V4(_)) {
                return Err(DataplaneError::Unsupported(
                    "cross-AF nexthop (RFC 5549) not supported yet",
                ));
            }
            msg.attributes
                .push(RouteAttribute::Gateway(RouteAddress::Inet6(gw)));
            msg.attributes.push(RouteAttribute::Oif(ix));
        }
        Nexthop::Blackhole => {
            msg.header.kind = RouteType::BlackHole;
            // Blackhole routes carry no nexthop attributes.
            msg.attributes
                .retain(|a| !matches!(a, RouteAttribute::Gateway(_) | RouteAttribute::Oif(_)));
        }
    }

    Ok(msg)
}

/// The per-interface rp_filter sysctl path. rp_filter has no rtnetlink
/// API (like nftables, whose only config channel is netlink-less: the
/// `nft` binary) — the procfs file is the kernel's interface, so the
/// dataplane crate writing it directly is the sanctioned channel; all
/// dataplane I/O stays inside this crate either way.
fn rp_filter_path(name: &str) -> String {
    format!("/proc/sys/net/ipv4/conf/{name}/rp_filter")
}

fn read_rp_filter(name: &str) -> Result<u8, DataplaneError> {
    let raw = std::fs::read_to_string(rp_filter_path(name))?;
    raw.trim()
        .parse::<u8>()
        .map_err(|e| DataplaneError::Other(format!("rp_filter of {name} is not a number: {e}")))
}

fn write_rp_filter(name: &str, value: u8) -> Result<(), DataplaneError> {
    std::fs::write(rp_filter_path(name), value.to_string())?;
    Ok(())
}

/// One interface the SAV plan covers, resolved for execution.
struct SavTarget {
    ifindex: u32,
    name: String,
    value: u8,
}

impl NetlinkDataplane {
    /// Dumps link ifindex → name (the translation the sysctl backend
    /// needs: rules speak ifindex, /proc/sys speaks names).
    async fn link_names(&self) -> Result<BTreeMap<u32, String>, DataplaneError> {
        let mut names = BTreeMap::new();
        let mut links = self.handle.link().get().execute();
        while let Some(msg) = links.try_next().await.map_err(nl_err)? {
            if let Some(LinkAttribute::IfName(name)) = msg
                .attributes
                .iter()
                .find(|a| matches!(a, LinkAttribute::IfName(_)))
            {
                names.insert(msg.header.index, name.clone());
            }
        }
        Ok(names)
    }

    /// Resolve the plan's ifindexes to names; every ifindex must exist
    /// (programming a rule for a vanished interface is an error, not a
    /// skip — a silent skip would report protection that does not
    /// exist).
    async fn resolve_sav_targets(
        &self,
        plan: &SysctlPlan,
    ) -> Result<Vec<SavTarget>, DataplaneError> {
        let names = self.link_names().await?;
        let mut targets = Vec::with_capacity(plan.rp_filter.len());
        for (&ifindex, &value) in &plan.rp_filter {
            let Some(name) = names.get(&ifindex) else {
                return Err(DataplaneError::Other(format!(
                    "sav install: ifindex {ifindex} has no interface (cannot set rp_filter)"
                )));
            };
            targets.push(SavTarget {
                ifindex,
                name: name.clone(),
                value,
            });
        }
        Ok(targets)
    }

    /// Merge the on-disk applied state into the in-memory map. In-memory
    /// entries win (this process is the freshest truth); disk entries
    /// fill what a previous process recorded — without this, a fresh
    /// process would clear nothing and believe nothing was ever applied.
    fn merge_applied_from_disk(&self) {
        let Ok(text) = std::fs::read_to_string(SAV_STATE_PATH) else {
            return; // no state file: nothing was ever applied here
        };
        let mut map = self.sav_applied.lock().unwrap();
        for (ifindex, entry) in sav_state::decode(&text) {
            map.entry(ifindex).or_insert(entry);
        }
    }

    /// Persist the applied map so a later process (restarted daemon, or
    /// the smoke binary's next command) can still restore pre-SAV
    /// values. A failure here is reported: silent success would mean a
    /// clear that cannot undo.
    fn persist_applied(&self) -> Result<(), DataplaneError> {
        std::fs::create_dir_all(SAV_STATE_DIR)?;
        let text = sav_state::encode(&self.sav_applied.lock().unwrap());
        std::fs::write(SAV_STATE_PATH, text)?;
        Ok(())
    }
}

impl Dataplane for NetlinkDataplane {
    /// Installs or atomically replaces a route (RTM_NEWROUTE, NLM_F_REPLACE).
    #[instrument(skip(self), fields(prefix = %entry.prefix))]
    async fn route_replace(&self, entry: &RouteEntry) -> Result<(), DataplaneError> {
        let msg = build_message(entry)?;
        self.handle
            .route()
            .add(msg)
            .replace()
            .execute()
            .await
            .map_err(nl_err)?;
        debug!("route installed");
        Ok(())
    }

    #[instrument(skip(self), fields(prefix = %entry.prefix))]
    async fn route_delete(&self, entry: &RouteEntry) -> Result<(), DataplaneError> {
        let msg = build_message(entry)?;
        if let Err(e) = self.handle.route().del(msg).execute().await {
            // ESRCH: the kernel no longer holds this route. That is the
            // goal state of a delete, so it is success — notably when a
            // link-down flushed the route without a DELROUTE notification
            // (the RIB must be able to drop its belief, or a later
            // re-resolve would wrongly look already-programmed).
            let already_absent = matches!(
                &e,
                rtnetlink::Error::NetlinkError(m)
                    if m.code == std::num::NonZeroI32::new(-libc::ESRCH)
            );
            if !already_absent {
                return Err(nl_err(e));
            }
            debug!("route already absent (ESRCH); delete is idempotent");
        }
        debug!("route deleted");
        Ok(())
    }

    /// Install or replace a SAV program on the rp_filter backend
    /// (see [`crate::sav`] for the mapping and its disclosed
    /// approximations).
    ///
    /// Replace semantics: interfaces the previous program covered but
    /// this one does not are restored to their pre-SAV values. Failures
    /// are reported after the fact; successfully written interfaces
    /// stay recorded so [`Dataplane::sav_clear`] can still undo them.
    #[instrument(skip(self))]
    async fn sav_install(&self, program: &SavProgram) -> Result<(), DataplaneError> {
        let plan = SysctlPlan::from_program(program);
        for (op, reason) in &plan.rejected {
            warn!(op = ?op, reason, "sav op not expressible on the rp_filter backend");
        }
        for &ifindex in &plan.monitored {
            info!(
                ifindex,
                "sav monitor: no kernel rule installed (rp_filter has no count-only mode); \
                 counting via the sav layer's route-lookup simulation"
            );
        }

        let targets = self.resolve_sav_targets(&plan).await?;
        let planned: BTreeMap<u32, u8> = plan.rp_filter.clone();
        // A previous process may have applied rules this one must
        // replace or revert (state file; see SAV_STATE_PATH).
        self.merge_applied_from_disk();

        // Revert interfaces that leave the program before writing the
        // new ones — no window where an interface is both stale and new.
        let revert: Vec<(u32, String, u8)> = {
            let applied = self.sav_applied.lock().unwrap();
            applied
                .iter()
                .filter(|(ifindex, _)| !planned.contains_key(ifindex))
                .map(|(&ifindex, (name, prior, _))| (ifindex, name.clone(), *prior))
                .collect()
        };
        let mut first_err = None;
        for (ifindex, name, prior) in revert {
            match write_rp_filter(&name, prior) {
                Ok(()) => {
                    info!(ifindex, iface = %name, rp_filter = prior, "sav revert (left program)");
                    self.sav_applied.lock().unwrap().remove(&ifindex);
                }
                Err(e) => {
                    warn!(ifindex, iface = %name, error = %e, "sav revert failed");
                    first_err = first_err.or(Some(e));
                }
            }
        }

        for target in &targets {
            let SavTarget {
                ifindex,
                name,
                value,
            } = target;
            // Keep the ORIGINAL prior on re-apply so clear restores the
            // true pre-SAV value, not a mid-program one.
            let prior = match self.sav_applied.lock().unwrap().get(ifindex) {
                Some((_, prior, _)) => *prior,
                None => read_rp_filter(name)?,
            };
            write_rp_filter(name, *value)?;
            self.sav_applied
                .lock()
                .unwrap()
                .insert(*ifindex, (name.clone(), prior, *value));
            info!(
                ifindex,
                iface = %name,
                rp_filter = target.value,
                "sav rp_filter written"
            );
        }
        if first_err.is_none() {
            self.persist_applied()?;
        }
        match first_err {
            Some(e) => Err(e),
            None => Ok(()),
        }
    }

    /// The rp_filter backend exposes no per-rule kernel counters (a
    /// strict/loose value drops, it does not count) — the pre-registered
    /// answer is `Unsupported`, and monitor counting runs in the sav
    /// layer's route-lookup simulation (`sav::monitor`).
    async fn sav_monitor_counts(&self) -> Result<SavMonitorCounts, DataplaneError> {
        Err(DataplaneError::Unsupported(
            "rp_filter backend has no per-rule kernel counters; monitor counting runs in the \
             sav layer (route-lookup simulation)",
        ))
    }

    /// Remove every installed SAV rule, restoring each interface's
    /// pre-SAV rp_filter value. Interfaces that vanished (no name in a
    /// link dump) have nothing left to restore and are dropped from
    /// the applied set with a debug note.
    #[instrument(skip(self))]
    async fn sav_clear(&self) -> Result<(), DataplaneError> {
        self.merge_applied_from_disk();
        let applied: Vec<(u32, String, u8)> = {
            let map = self.sav_applied.lock().unwrap();
            map.iter()
                .map(|(&ifindex, (name, prior, _))| (ifindex, name.clone(), *prior))
                .collect()
        };
        let mut first_err = None;
        for (ifindex, name, prior) in applied {
            match write_rp_filter(&name, prior) {
                Ok(()) => {
                    info!(ifindex, iface = %name, rp_filter = prior, "sav cleared (restored)");
                    self.sav_applied.lock().unwrap().remove(&ifindex);
                }
                Err(e) => {
                    warn!(ifindex, iface = %name, error = %e, "sav clear failed");
                    first_err = first_err.or(Some(e));
                }
            }
        }
        if first_err.is_none() {
            self.persist_applied()?;
        }
        match first_err {
            Some(e) => Err(e),
            None => Ok(()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The sysctl path is the canonical procfs location keyed by
    /// interface name (what the container smoke greps for).
    #[test]
    fn rp_filter_path_is_canonical_procfs() {
        assert_eq!(
            rp_filter_path("vethspoof"),
            "/proc/sys/net/ipv4/conf/vethspoof/rp_filter"
        );
    }
}
