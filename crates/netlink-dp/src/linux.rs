//! Real rtnetlink-backed dataplane (Linux only).

use std::collections::BTreeMap;
use std::net::IpAddr;
use std::sync::Mutex;

use common::{
    Dataplane, DataplaneError, DataplaneEvent, IpPrefix, Ipv4Prefix, Ipv6Prefix,
    NeighbourCacheInfo, NeighbourEntry, NeighbourProtocol, Nexthop, RouteEntry, RouteProtocol,
    SavMonitorCounts, SavProgram, SavProgramOp,
};
use futures::stream::StreamExt;
use futures::TryStreamExt;
use netlink_packet_route::address::{AddressAttribute, AddressMessage};
use netlink_packet_route::link::{
    InfoData, InfoVrf, LinkAttribute, LinkFlags as NlLinkFlags, LinkInfo, LinkMessage,
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
use crate::sav_nft::{self, SavBackend};
use crate::sav_state;

/// Where the applied-SAV state file lives (the daemon run dir AGENTS.md
/// sanctions; `/run/rouster`). Cross-process persistence: a restarted
/// daemon — or the smoke binary's one-process-per-command shape — reads
/// what a previous process applied, so clear/replace can restore the
/// true pre-SAV values. The file's first line stamps the writing boot
/// (see [`read_boot_id`]); state from any other boot is discarded
/// (ifindexes are per-boot and a reboot may have reordered them).
const SAV_STATE_DIR: &str = "/run/rouster";
const SAV_STATE_PATH: &str = "/run/rouster/sav-applied";
/// The nft backend's applied marker (same run dir, namespaced format —
/// see [`sav_state::encode_nft`]).
const NFT_STATE_PATH: &str = "/run/rouster/sav-nft-applied";
/// The ruleset file the nft backend applies with `nft -f`: operator
/// evidence first (the enforced ruleset, verbatim), and the churn
/// guard's comparison key second (an identical replay must not rewrite
/// the table — a rewrite would reset the kernel counters).
const NFT_RULESET_PATH: &str = "/run/rouster/sav-nft.ruleset";
/// The machine's boot identity. Not the wall clock: a value that
/// changes iff the kernel rebooted (and with it, the ifindex
/// allocation order the state file's keys depend on).
const BOOT_ID_PATH: &str = "/proc/sys/kernel/random/boot_id";

/// Netlink-backed dataplane handle.
///
/// Owns the multicast event receiver; `next_event` drives the kernel→RIB
/// direction of the mirror. SAV enforcement routes through
/// [`SavBackend`] (rp_filter sysctls, the default, or the nftables
/// ruleset — see [`crate::sav_nft`]); the rp_filter state
/// (`sav_applied`) records the values this handle wrote and the
/// pre-SAV values to restore on clear/replace.
pub struct NetlinkDataplane {
    handle: rtnetlink::Handle,
    messages: futures::channel::mpsc::UnboundedReceiver<(
        NetlinkMessage<RouteNetlinkMessage>,
        SocketAddr,
    )>,
    /// Mirror refresh queued by the last receive-overrun resync (F9),
    /// drained one event per `next_event` call ahead of new socket
    /// traffic. Empty unless an overrun was observed.
    resync_backlog: std::collections::VecDeque<DataplaneEvent>,
    /// ifindex → (interface name at write time, pre-SAV rp_filter,
    /// applied value). Interior-mutable so the `&self` trait methods
    /// can update it; never held across an await.
    sav_applied: Mutex<BTreeMap<u32, (String, u8, u8)>>,
    /// The nft backend's counter-units map (op, valid unit, invalid
    /// unit) of the last program THIS HANDLE installed — the per-op
    /// attribution [`Dataplane::sav_monitor_per_op`] reads counters
    /// back through. `None` until the first install (and after clear):
    /// per-op attribution is install-scoped by design, because the
    /// kernel counter NAMES are minted at install time from the
    /// then-current interface names — only the installing process
    /// holds the mapping that explains them. savd always installs
    /// before reading (its evaluate installs, then counts), so the
    /// daemon flow never sees `None`; a handle that never installed
    /// answers `Unsupported` rather than guessing.
    sav_nft_counters: Mutex<Option<Vec<(SavProgramOp, String, String)>>>,
    /// Which enforcement surface the SAV trait ops route to (default
    /// rp_filter — the long-landed behavior).
    sav_backend: SavBackend,
}

impl NetlinkDataplane {
    /// Opens the netlink connection, subscribed to link/address/route/
    /// neighbour multicast groups so kernel changes arrive as events.
    ///
    /// F9's optional half: the receive buffer is enlarged to
    /// [`NL_RCVBUF_ASK`] before binding. The daemon's own ~65k
    /// notifications/s install storm (every programmed route echoes back
    /// on this socket) overruns the kernel-default rcvbuf in ~25 ms of
    /// reader starvation; the harness workaround raised the sysctls, this
    /// is the daemon asking for the same slack itself. Best-effort and
    /// disclosed: plain `SO_RCVBUF` is capped by `net.core.rmem_max`
    /// (raising it further would take `SO_RCVBUFFORCE`, which netlink-sys
    /// does not expose); the ACK timeout below is the recovery path that
    /// makes a lost datagram survivable regardless.
    #[allow(clippy::type_complexity)]
    pub fn new() -> std::io::Result<(Self, impl std::future::Future<Output = ()> + Send)> {
        let mut socket = TokioSocket::new(NETLINK_ROUTE)?;
        if let Err(e) = socket.socket_mut().set_rx_buf_sz(NL_RCVBUF_ASK) {
            warn!(
                ask = NL_RCVBUF_ASK,
                error = %e,
                "cannot enlarge the netlink receive buffer (F9); keeping the kernel default"
            );
        }
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
                resync_backlog: std::collections::VecDeque::new(),
                sav_applied: Mutex::new(BTreeMap::new()),
                sav_nft_counters: Mutex::new(None),
                sav_backend: SavBackend::default(),
            },
            connection,
        ))
    }

    /// Select the SAV enforcement surface (rp_filter sysctls by
    /// default; `SavBackend::Nft` routes the SAV trait ops to the
    /// nftables ruleset — see [`crate::sav_nft`]). Builder form on the
    /// constructed handle: `NetlinkDataplane::new()?.0.with_sav_backend(..)`.
    pub fn with_sav_backend(mut self, backend: SavBackend) -> Self {
        self.sav_backend = backend;
        self
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
    ///
    /// F9: a receive overrun (the framed layer's ENOBUFS marker — the
    /// kernel dropped datagrams) does not kill the socket, it only leaves
    /// the mirror behind: the marker triggers a bounded link/address
    /// re-dump whose events are drained ahead of new traffic, and every
    /// in-flight request still awaiting its ACK is re-issued by
    /// [`ack_bounded`] on its deadline.
    pub async fn next_event(&mut self) -> Option<DataplaneEvent> {
        let NetlinkDataplane {
            messages,
            resync_backlog,
            handle,
            ..
        } = self;
        next_event_with(messages, resync_backlog, || {
            resync_link_address_mirror(handle)
        })
        .await
    }
}

/// How one received netlink message steps the event loop.
#[derive(Debug)]
enum RxStep {
    /// A mirror event for the RIB.
    Event(DataplaneEvent),
    /// Received but not mirrored: the feedback filter's non-kernel-origin
    /// route echoes, or a kind this mirror does not track.
    Skip,
    /// The framed layer's ENOBUFS marker (NLMSG_OVERRUN): the kernel
    /// dropped datagrams while the receive buffer was full.
    Overrun,
}

/// Classifies one message off the wire (the mapping half of
/// [`next_event_with`]; kept pure for the overrun-path tests).
fn classify_rx(msg: NetlinkMessage<RouteNetlinkMessage>) -> RxStep {
    let NetlinkPayload::InnerMessage(inner) = msg.payload else {
        return match msg.payload {
            NetlinkPayload::Overrun(_) => RxStep::Overrun,
            _ => RxStep::Skip,
        };
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
    match ev {
        Some(ev) => RxStep::Event(ev),
        None => RxStep::Skip,
    }
}

/// The drain-and-resync event loop (F9), over any message stream:
/// queued resync events first, then the next stream message mapped by
/// [`classify_rx`]. An [`RxStep::Overrun`] warns, runs `resync`, and
/// queues its events — the stream is not dead, just behind, so reading
/// continues right where it is.
async fn next_event_with<S, F, Fut>(
    messages: &mut S,
    resync_backlog: &mut std::collections::VecDeque<DataplaneEvent>,
    mut resync: F,
) -> Option<DataplaneEvent>
where
    S: futures::Stream<Item = (NetlinkMessage<RouteNetlinkMessage>, SocketAddr)> + Unpin,
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = Vec<DataplaneEvent>>,
{
    loop {
        if let Some(ev) = resync_backlog.pop_front() {
            return Some(ev);
        }
        let (msg, _addr) = futures::StreamExt::next(messages).await?;
        crate::cpucensus::NL_EVENTS_RX.bump();
        match classify_rx(msg) {
            RxStep::Event(ev) => return Some(ev),
            RxStep::Skip => {
                crate::cpucensus::NL_EVENTS_DROPPED.bump();
            }
            RxStep::Overrun => {
                crate::cpucensus::NL_OVERRUNS.bump();
                warn!(
                    "netlink socket overrun (ENOBUFS): the kernel dropped datagrams; \
                     re-syncing the link/address mirror (in-flight requests re-issue \
                     on their ACK deadline)"
                );
                *resync_backlog = resync().await.into();
            }
        }
    }
}

/// The overrun mirror resync: re-dump LINKS and ADDRESSES only (F9).
///
/// Scope, disclosed: interfaces are a small bounded table, so this dump
/// is cheap and cannot meaningfully feed the next overrun; a full ROUTE
/// re-dump can (on the very install storm that overran the buffer it
/// would pull every echo back through the same rcvbuf), so route mirror
/// truth keeps its existing repair paths — in-flight installs verify via
/// [`ack_bounded`], and the periodic reconcile re-establishes desired
/// state. Bounded by [`NL_ACK_TIMEOUT`]: a silent dump yields the events
/// collected so far rather than a hang.
async fn resync_link_address_mirror(handle: &rtnetlink::Handle) -> Vec<DataplaneEvent> {
    let mut events = Vec::new();
    let dump = async {
        let mut links = handle.link().get().execute();
        while let Some(msg) = links.try_next().await.map_err(|e| e.to_string())? {
            if let Some(ev) = link_event(&msg, true) {
                events.push(ev);
            }
        }
        let mut addrs = handle.address().get().execute();
        while let Some(msg) = addrs.try_next().await.map_err(|e| e.to_string())? {
            if let Some(ev) = address_event(&msg, true) {
                events.push(ev);
            }
        }
        Ok::<(), String>(())
    };
    if let Err(reason) = tokio::time::timeout(NL_ACK_TIMEOUT, dump).await {
        warn!(
            collected = events.len(),
            reason = %reason,
            "overrun resync dump went silent; applying the partial mirror refresh"
        );
    }
    events
}

/// `RT_TABLE_COMPAT` — header marker for routing tables addressed by
/// `RTA_TABLE` (ids > 255).
const RT_TABLE_COMPAT: u8 = 252;

/// Maps a kernel link message to a `LinkNew` event (name resolution, link
/// flags, and VRF awareness included).
///
/// VRF modeling: a link of kind "vrf" (`IFLA_INFO_KIND`) carries its bound
/// routing table in `IFLA_VRF_TABLE` — netlink-packet-route parses that
/// pairing as [`LinkInfo::Data`](`InfoData::Vrf`), so seeing the variant
/// is itself the kind check and [`InfoVrf::TableId`] the table. Enslavement
/// arrives as `IFLA_MASTER` ([`LinkAttribute::Controller`], the master
/// device's ifindex — a VRF device here, though bridges and bonds share
/// the attribute).
///
/// Flags: the header's `ifi_flags` word passes through whole (raw bits,
/// unnamed ones included) — `is_up` is derived from `IFF_UP` as before,
/// and the mirror keeps the rest (LOOPBACK, BROADCAST, MULTICAST,
/// RUNNING, …) for consumers that gate on them (the ZAPI interface
/// mirror relays the word verbatim, like zebra).
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
        is_up: msg.header.flags.contains(NlLinkFlags::Up),
        flags: common::LinkFlags::from_bits(msg.header.flags.bits()),
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
        gateway: route_gateway(msg),
        oif: route_oif(msg),
    })
}

/// Gateway of a route message (`RTA_GATEWAY`), as a plain IP. Cross-AF
/// gateways are dropped (the programming path rejects them too,
/// `check_same_af`); mirror detail must be as trustworthy as what we
/// would ourselves install.
fn route_gateway(msg: &RouteMessage) -> Option<IpAddr> {
    msg.attributes.iter().find_map(|a| match a {
        RouteAttribute::Gateway(RouteAddress::Inet(a)) => Some(IpAddr::V4(*a)),
        RouteAttribute::Gateway(RouteAddress::Inet6(a)) => Some(IpAddr::V6(*a)),
        _ => None,
    })
}

/// Output interface of a route message (`RTA_OIF`).
fn route_oif(msg: &RouteMessage) -> Option<u32> {
    msg.attributes.iter().find_map(|a| match a {
        RouteAttribute::Oif(ix) => Some(*ix),
        _ => None,
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
        P::Ospf => NlRouteProtocol::Ospf,
        // RTPROT_ISIS (187) — netlink-packet-route has the variant and
        // common's NeighbourProtocol::ISIS pinned the value long ago;
        // the old Static fallback predates both (S10-a M6).
        P::IsIs => NlRouteProtocol::Isis,
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
    let _census = crate::cpucensus::scope(&crate::cpucensus::NL_BUILD);
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

/// This machine's current boot id (procfs, same sanctioned channel as
/// the rp_filter files). It stamps the applied-state file: it changes
/// exactly when the kernel reboots — and with it the ifindex
/// allocation order — so a mismatch means the persisted ifindex keys
/// cannot be trusted. An unreadable/empty boot id is an error: a file
/// stamped with "unknown" would be silently restorable forever.
fn read_boot_id() -> Result<String, DataplaneError> {
    let raw = std::fs::read_to_string(BOOT_ID_PATH)?;
    let id = raw.trim();
    if id.is_empty() {
        return Err(DataplaneError::Other(format!(
            "boot id at {BOOT_ID_PATH} is empty; cannot stamp SAV state"
        )));
    }
    Ok(id.to_string())
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
    ///
    /// Boot safety: the file is only honored when its boot-id stamp
    /// matches this boot. A mismatch (the machine rebooted, so
    /// ifindexes may have been reordered onto other interfaces — or the
    /// boot id cannot be read at all) discards the file: this process
    /// starts from a fresh install surface, as if nothing had ever
    /// been applied.
    fn merge_applied_from_disk(&self) {
        let Ok(text) = std::fs::read_to_string(SAV_STATE_PATH) else {
            return; // no state file: nothing was ever applied here
        };
        let boot_id = match read_boot_id() {
            Ok(id) => id,
            Err(e) => {
                warn!(
                    error = %e,
                    "cannot determine boot id; ignoring persisted SAV state"
                );
                return;
            }
        };
        let mut map = self.sav_applied.lock().unwrap();
        match sav_state::decode(&text, &boot_id) {
            sav_state::DecodeOutcome::Current(entries) => {
                for (ifindex, entry) in entries {
                    map.entry(ifindex).or_insert(entry);
                }
            }
            sav_state::DecodeOutcome::ForeignBoot => {
                warn!(
                    "discarding sav-applied state from a different boot \
                     (ifindexes may have been reordered)"
                );
            }
        }
    }

    /// Persist the applied map — stamped with this boot's id — so a
    /// later process (restarted daemon, or the smoke binary's next
    /// command) can still restore pre-SAV values. A failure here is
    /// reported: silent success would mean a clear that cannot undo.
    /// (An empty map writes an empty file, overwriting any stale one.)
    fn persist_applied(&self) -> Result<(), DataplaneError> {
        std::fs::create_dir_all(SAV_STATE_DIR)?;
        let boot_id = read_boot_id()?;
        let text = sav_state::encode(&boot_id, &self.sav_applied.lock().unwrap());
        std::fs::write(SAV_STATE_PATH, text)?;
        Ok(())
    }
}

/// How many route requests may be in flight before the next send
/// waits (bench F8). Each `execute()` still awaits its own ACK —
/// every route stays verified — but with a bounded pipeline the
/// socket and the kernel work continuously instead of the caller
/// sleeping between single-route round-trips. 512 is plenty: the
/// netlink send buffer backpressures well below this on default
/// `wmem_default`.
const NL_ROUTE_PIPELINE: usize = 512;

/// F9 (the PERF-P0 escalation): how long one netlink request may stay
/// silent before it is re-issued. Sized from measurement, not guess:
/// the F8 receipt's healthy install ACK latency is single-digit
/// milliseconds (1,126,481 routes in 17.0 s ≈ 66k ACKs/s through the
/// 512-deep pipeline ⇒ ~8 ms queue-depth latency per request), so 10 s
/// is ~1000x the healthy bound — a wedged install recovers in seconds
/// instead of parking the daemon's whole select! loop forever (the
/// 2026-10-15/16 bench wedges: one rcvbuf overrun dropped install ACKs;
/// netlink-proto 0.12.2 request futures have no timeout of their own).
const NL_ACK_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);
/// Attempts per request under [`ack_bounded`]: the original send plus
/// two re-issues. Route programming is idempotent (NLM_F_REPLACE, and
/// deletes tolerate ESRCH), so a re-issue cannot double-install; after
/// the budget the request is reported lost and the reconcile tick
/// retries the route as a whole.
const NL_ACK_ATTEMPTS: usize = 3;
/// F9's optional half: the receive-buffer size the daemon asks for at
/// socket creation (see [`NetlinkDataplane::new`] for the sizing story
/// and the `rmem_max` cap disclosure).
const NL_RCVBUF_ASK: libc::c_int = 8 * 1024 * 1024;

/// The bounded-ACK outcome of one netlink request (F9).
enum AckWait<T> {
    /// The kernel answered inside the deadline — with success or with a
    /// netlink error (an answer is an answer; errors never re-issue).
    Answered(Result<T, rtnetlink::Error>),
    /// Every attempt stayed silent past [`NL_ACK_TIMEOUT`]: the ACK is
    /// presumed lost to a receive-buffer overrun.
    Silent,
}

/// Runs one netlink request attempt under [`NL_ACK_TIMEOUT`], logging
/// and re-issuing while the kernel stays silent (F9's resync).
///
/// A timed-out attempt is dropped, not leaked on the wire: the kernel
/// may still be processing it, and the request machinery's pending
/// entry ages out of netlink-proto's table when (or if) the late reply
/// arrives. Programming is idempotent, so overlap between a slow
/// original and its re-issue converges to the same kernel state.
async fn ack_bounded<T, F, Fut>(what: &'static str, attempt: F) -> AckWait<T>
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = Result<T, rtnetlink::Error>>,
{
    ack_bounded_within(NL_ACK_TIMEOUT, what, attempt).await
}

/// [`ack_bounded`] with an explicit deadline — the test seam (the
/// production bound is minutes too long to wait in real time, and the
/// workspace's tokio carries no `test-util` feature to pause it).
async fn ack_bounded_within<T, F, Fut>(
    deadline: std::time::Duration,
    what: &'static str,
    mut attempt: F,
) -> AckWait<T>
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = Result<T, rtnetlink::Error>>,
{
    for no in 1..=NL_ACK_ATTEMPTS {
        match tokio::time::timeout(deadline, attempt()).await {
            Ok(answer) => return AckWait::Answered(answer),
            Err(_elapsed) => {
                warn!(
                    request = what,
                    attempt = no,
                    ?deadline,
                    "netlink request silent (ACK lost to an rcvbuf overrun?); re-issuing"
                );
            }
        }
    }
    AckWait::Silent
}

impl Dataplane for NetlinkDataplane {
    /// Installs or atomically replaces a route (RTM_NEWROUTE, NLM_F_REPLACE).
    ///
    /// F9: the ACK wait is bounded — a lost ACK (rcvbuf overrun) re-issues
    /// the idempotent replace instead of hanging the caller.
    #[instrument(level = "debug", skip(self), fields(prefix = %entry.prefix))]
    async fn route_replace(&self, entry: &RouteEntry) -> Result<(), DataplaneError> {
        let msg = build_message(entry)?;
        let _census = crate::cpucensus::scope(&crate::cpucensus::NL_REQUEST);
        match ack_bounded("route add/replace", || {
            self.handle.route().add(msg.clone()).replace().execute()
        })
        .await
        {
            AckWait::Answered(result) => result.map_err(nl_err)?,
            AckWait::Silent => {
                return Err(DataplaneError::Other(format!(
                    "netlink route add/replace for {} silent past {} attempts at {:?} \
                     (F9: ACK presumed lost to an rcvbuf overrun)",
                    entry.prefix, NL_ACK_ATTEMPTS, NL_ACK_TIMEOUT
                )));
            }
        }
        debug!("route installed");
        Ok(())
    }

    #[instrument(level = "debug", skip(self), fields(prefix = %entry.prefix))]
    async fn route_delete(&self, entry: &RouteEntry) -> Result<(), DataplaneError> {
        let msg = build_message(entry)?;
        let _census = crate::cpucensus::scope(&crate::cpucensus::NL_REQUEST);
        match ack_bounded("route delete", || {
            self.handle.route().del(msg.clone()).execute()
        })
        .await
        {
            AckWait::Answered(result) => {
                if let Err(e) = result {
                    // ESRCH: the kernel no longer holds this route. That is
                    // the goal state of a delete, so it is success — notably
                    // when a link-down flushed the route without a DELROUTE
                    // notification (the RIB must be able to drop its belief,
                    // or a later re-resolve would wrongly look
                    // already-programmed).
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
            }
            AckWait::Silent => {
                return Err(DataplaneError::Other(format!(
                    "netlink route delete for {} silent past {} attempts at {:?} \
                     (F9: ACK presumed lost to an rcvbuf overrun)",
                    entry.prefix, NL_ACK_ATTEMPTS, NL_ACK_TIMEOUT
                )));
            }
        }
        debug!("route deleted");
        Ok(())
    }

    /// Pipelined installs (bench F8): the per-route `execute().await`
    /// costs a full netlink round-trip — write, sleep, ACK wake — per
    /// route; a 1.1M-route install measured 235 CPU-s (~208 µs/route)
    /// against FRR zebra's batched ~8.6 µs/route. Bounded in-flight
    /// requests with ordered results (`buffered`, not
    /// `buffer_unordered` — callers zip results back to keys by
    /// index).
    async fn route_replace_batch(&self, entries: &[RouteEntry]) -> Vec<Result<(), DataplaneError>> {
        // Index-mapped, not element-mapped: the trait method's
        // returned future borrows the element lifetime (RPITIT), and a
        // closure cannot be higher-ranked over that — capturing the
        // slice itself sidesteps the HRTB entirely.
        futures::stream::iter(0..entries.len())
            .map(|i| async move { self.route_replace(&entries[i]).await })
            .buffered(NL_ROUTE_PIPELINE)
            .collect()
            .await
    }

    /// The delete-side twin of [`Self::route_replace_batch`].
    async fn route_delete_batch(&self, entries: &[RouteEntry]) -> Vec<Result<(), DataplaneError>> {
        futures::stream::iter(0..entries.len())
            .map(|i| async move { self.route_delete(&entries[i]).await })
            .buffered(NL_ROUTE_PIPELINE)
            .collect()
            .await
    }

    /// Install or replace a SAV program on the configured backend
    /// ([`SavBackend`]): the rp_filter sysctl surface (default; see
    /// [`crate::sav`] for the mapping and its disclosed approximations)
    /// or the nftables ruleset ([`crate::sav_nft`] — the content-
    /// enforcing surface with kernel monitor counters). Both sides
    /// honor replace semantics and carry a churn guard; their
    /// backend-specific contracts are on the private install methods.
    #[instrument(skip(self))]
    async fn sav_install(&self, program: &SavProgram) -> Result<(), DataplaneError> {
        match self.sav_backend {
            SavBackend::RpFilter => self.sav_install_rp_filter(program).await,
            SavBackend::Nft => self.sav_install_nft(program).await,
        }
    }

    /// Monitor counters: the nft backend reads its named counters back
    /// from the kernel (the A18 dataplane-first path's first answering
    /// backend); the rp_filter surface has no per-rule counters — its
    /// pre-registered answer stays `Unsupported`, and monitor counting
    /// runs in the sav layer's route-lookup simulation.
    async fn sav_monitor_counts(&self) -> Result<SavMonitorCounts, DataplaneError> {
        match self.sav_backend {
            SavBackend::RpFilter => Err(DataplaneError::Unsupported(
                "rp_filter backend has no per-rule kernel counters; monitor counting runs in the \
                 sav layer (route-lookup simulation)",
            )),
            SavBackend::Nft => {
                let out = run_nft(&["list", "counters"])?;
                let packets = sav_nft::parse_counter_packets(&out, sav_nft::NFT_TABLE);
                let counts = sav_nft::aggregate_counts(&packets);
                debug!(%counts, "sav nft monitor counters read");
                Ok(counts)
            }
        }
    }

    /// Per-op monitor counters (N6B): the nft backend joins its
    /// install-time counter-units map with the same `nft list counters`
    /// read the aggregate uses — one row per placed op, its two named
    /// counters' packets. Attribution is install-scoped (the counter
    /// names are minted at install time): a handle that never installed
    /// — or cleared — answers `Unsupported` rather than guessing at
    /// units it cannot explain; savd installs before reading, so its
    /// flow always answers. The rp_filter surface keeps its
    /// pre-registered `Unsupported` (no per-rule counters at all).
    async fn sav_monitor_per_op(
        &self,
    ) -> Result<Vec<(SavProgramOp, SavMonitorCounts)>, DataplaneError> {
        match self.sav_backend {
            SavBackend::RpFilter => Err(DataplaneError::Unsupported(
                "rp_filter backend has no per-rule kernel counters; per-op counting runs in the \
                 sav layer (route-lookup simulation)",
            )),
            SavBackend::Nft => {
                let units = self.sav_nft_counters.lock().unwrap().clone();
                let Some(units) = units else {
                    return Err(DataplaneError::Unsupported(
                        "nft backend has no installed program on this handle to attribute \
                         counters to (install first; counter names are minted at install time)",
                    ));
                };
                let out = run_nft(&["list", "counters"])?;
                let packets = sav_nft::parse_counter_packets(&out, sav_nft::NFT_TABLE);
                let rows = sav_nft::attribute_counts(&units, &packets);
                debug!(rows = rows.len(), "sav nft per-op monitor counters read");
                Ok(rows)
            }
        }
    }

    /// Remove every installed SAV rule on the configured backend: the
    /// sysctl side restores each interface's pre-SAV rp_filter value;
    /// the nft side destroys the wholly-owned table (a single command —
    /// nothing outside it was ever touched).
    #[instrument(skip(self))]
    async fn sav_clear(&self) -> Result<(), DataplaneError> {
        match self.sav_backend {
            SavBackend::RpFilter => self.sav_clear_rp_filter().await,
            SavBackend::Nft => self.sav_clear_nft(),
        }
    }
}

impl NetlinkDataplane {
    /// The rp_filter install path (default backend).
    ///
    /// Replace semantics: interfaces the previous program covered but
    /// this one does not are restored to their pre-SAV values. Failures
    /// are reported after the fact; successfully written interfaces
    /// stay recorded so [`Dataplane::sav_clear`] can still undo them.
    ///
    /// Churn guard: a replay whose resolved plan already matches the
    /// applied map — same ifindexes, names, and values, in-memory or
    /// restored from the state file by `merge_applied_from_disk` —
    /// writes nothing at all, neither the sysctls nor the state file.
    /// savd re-evaluates on every dirtying event, so identical
    /// replays are the common case; a restarted process replays onto
    /// the state its predecessor left the same way.
    async fn sav_install_rp_filter(&self, program: &SavProgram) -> Result<(), DataplaneError> {
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
        // A previous process may have applied rules this one must
        // replace or revert (state file; see SAV_STATE_PATH).
        self.merge_applied_from_disk();

        // Churn guard: split the resolved plan into the writes and
        // reverts still owed; both empty is an identical replay that
        // must touch neither procfs nor the state file.
        let planned: Vec<(u32, String, u8)> = targets
            .into_iter()
            .map(|t| (t.ifindex, t.name, t.value))
            .collect();
        let delta = {
            let applied = self.sav_applied.lock().unwrap();
            sav_state::replay_delta(&planned, &applied)
        };
        if delta.writes.is_empty() && delta.reverts.is_empty() {
            debug!("sav replay matches applied state; no sysctl or state writes");
            return Ok(());
        }

        // Revert interfaces that leave the program before writing the
        // new ones — no window where an interface is both stale and new.
        let mut first_err = None;
        for (ifindex, name, prior) in delta.reverts {
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

        for (ifindex, name, value) in delta.writes {
            // Keep the ORIGINAL prior on re-apply so clear restores the
            // true pre-SAV value — but only when the recorded entry is
            // about this same interface: a name mismatch means the
            // ifindex was recycled and the recorded prior belongs to a
            // different sysctl file, so read the current one instead.
            let prior = match self.sav_applied.lock().unwrap().get(&ifindex) {
                Some((applied_name, prior, _)) if applied_name == &name => *prior,
                _ => read_rp_filter(&name)?,
            };
            write_rp_filter(&name, value)?;
            self.sav_applied
                .lock()
                .unwrap()
                .insert(ifindex, (name.clone(), prior, value));
            info!(
                ifindex,
                iface = %name,
                rp_filter = value,
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

    /// The rp_filter clear path: restore each interface's pre-SAV
    /// rp_filter value. Interfaces that vanished (no name in a link
    /// dump) have nothing left to restore and are dropped from the
    /// applied set with a debug note (in `merge_applied_from_disk`).
    async fn sav_clear_rp_filter(&self) -> Result<(), DataplaneError> {
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

    /// The nft install path (SavBackend::Nft).
    ///
    /// Exec choice (disclosed): the ruleset is applied by executing the
    /// `nft` binary (`nft -f <file>`, and `destroy table` for the
    /// replace pre-clean) — nftables' only sanctioned config channel;
    /// there is no rtnetlink API for it (the same reason the sysctl
    /// backend writes procfs), and a libnftn* dependency is not
    /// authorized. All dataplane I/O stays inside this crate
    /// (invariant #6). The execs are short-lived local subprocesses —
    /// the same blocking class as the procfs writes above.
    ///
    /// Replace semantics: the table is wholly owned, so replace is
    /// destroy-and-recreate. The generated file lands at
    /// [`NFT_RULESET_PATH`] first (operator evidence — the enforced
    /// ruleset verbatim) and is the churn guard's comparison key: an
    /// identical replay (file bytes match AND the table is still
    /// present) touches nothing — notably it does not reset the kernel
    /// counters, which savd's event-driven re-evaluations must not do.
    async fn sav_install_nft(&self, program: &SavProgram) -> Result<(), DataplaneError> {
        let names = self.link_names().await?;
        let rs =
            sav_nft::ruleset(program, &names).map_err(|e| DataplaneError::Other(e.to_string()))?;
        for (op, reason) in &rs.ignored {
            warn!(op = ?op, reason, "sav op not placed in the nft ruleset");
        }

        // The per-op attribution map is remembered from the generation
        // itself — BEFORE the churn guard — so an identical replay (no
        // table rewrite, counters preserved) refreshes the same map and
        // `sav_monitor_per_op` keeps answering. An empty program owns
        // no counters: the map is Some(empty), which reads back as
        // zero rows (no table, nothing attributed).
        *self.sav_nft_counters.lock().unwrap() = Some(rs.counters.clone());

        // Churn guard (file is the truth; presence cross-checked
        // against the kernel so an externally destroyed table is
        // reinstalled, never skipped over).
        let applied_text = std::fs::read_to_string(NFT_RULESET_PATH).unwrap_or_default();
        let table_present = self.nft_table_exists();
        let want_table = !rs.text.is_empty();
        if applied_text == rs.text && table_present == want_table {
            debug!("sav nft replay matches the applied ruleset; no table rewrite");
            return Ok(());
        }

        // Crash observability: name what a previous process left
        // enforced (the marker is diagnostics — clear/replace work
        // without it; see sav_state::encode_nft for why that is enough).
        if let Ok(text) = std::fs::read_to_string(NFT_STATE_PATH) {
            if let Ok(boot_id) = read_boot_id() {
                if let Some(predecessor) = sav_state::decode_nft(&text, &boot_id) {
                    if !predecessor.is_empty() {
                        let names: Vec<&str> =
                            predecessor.iter().map(|(_, name)| name.as_str()).collect();
                        info!(interfaces = ?names, "sav nft: replacing a previously applied table");
                    }
                }
            }
        }

        // Replace: destroy-or-noop (rc nonzero here only logs — the
        // apply below surfaces real trouble), then apply the fresh
        // file. An empty program leaves no table at all.
        match run_nft(&["destroy", "table", sav_nft::NFT_FAMILY, sav_nft::NFT_TABLE]) {
            Ok(_) => {}
            Err(e) => warn!(error = %e, "sav nft: pre-install destroy failed; applying anyway"),
        }
        if rs.text.is_empty() {
            remove_run_file(NFT_RULESET_PATH);
            remove_run_file(NFT_STATE_PATH);
            info!("sav nft: empty program — table destroyed, nothing applied");
            return Ok(());
        }
        std::fs::create_dir_all(SAV_STATE_DIR)?;
        std::fs::write(NFT_RULESET_PATH, &rs.text)?;
        run_nft(&["-f", NFT_RULESET_PATH])?;
        info!(
            interfaces = ?rs.interfaces.len(),
            "sav nft ruleset applied ({} bytes)",
            rs.text.len()
        );
        self.persist_nft_marker(&rs.interfaces)
    }

    /// The nft clear path: one `destroy table` (the table is wholly
    /// owned — nothing outside it was ever written), then the ruleset
    /// file and marker go too. `destroy` answers rc 0 for an absent
    /// table as well, so a fresh process with nothing applied still
    /// clears cleanly.
    fn sav_clear_nft(&self) -> Result<(), DataplaneError> {
        run_nft(&["destroy", "table", sav_nft::NFT_FAMILY, sav_nft::NFT_TABLE])?;
        remove_run_file(NFT_RULESET_PATH);
        remove_run_file(NFT_STATE_PATH);
        // No table, nothing to attribute: back to the never-installed
        // answer (Unsupported) — an empty install is the Some(empty)
        // shape that honestly reads zero rows instead.
        *self.sav_nft_counters.lock().unwrap() = None;
        info!("sav nft table destroyed");
        Ok(())
    }

    /// Persist the applied marker (boot-id stamped; see
    /// [`sav_state::encode_nft`]).
    fn persist_nft_marker(
        &self,
        ifaces: &[(u32, String, common::SavEnforce)],
    ) -> Result<(), DataplaneError> {
        std::fs::create_dir_all(SAV_STATE_DIR)?;
        let boot_id = read_boot_id()?;
        let ifaces: Vec<(u32, String)> = ifaces
            .iter()
            .map(|(ifindex, name, _)| (*ifindex, name.clone()))
            .collect();
        std::fs::write(NFT_STATE_PATH, sav_state::encode_nft(&boot_id, &ifaces))?;
        Ok(())
    }

    /// Whether the rouster table exists in the kernel. Best-effort by
    /// design: a false "absent" only means the churn guard re-applies
    /// (the safe direction — enforcement is never skipped over); real
    /// failures surface on the apply/destroy paths.
    fn nft_table_exists(&self) -> bool {
        run_nft(&["list", "table", sav_nft::NFT_FAMILY, sav_nft::NFT_TABLE]).is_ok()
    }
}

/// Execute `nft <args>`, returning stdout; a spawn failure (no binary)
/// and a nonzero exit both error — stderr rides along for the caller's
/// log. Blocking by design (short-lived local subprocess, the procfs
/// write class; see `sav_install_nft`'s exec disclosure).
fn run_nft(args: &[&str]) -> Result<String, DataplaneError> {
    let output = std::process::Command::new("nft")
        .args(args)
        .output()
        .map_err(DataplaneError::Io)?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
        return Err(DataplaneError::Other(format!(
            "nft {args:?} failed ({}): {stderr}",
            output.status
        )));
    }
    Ok(String::from_utf8_lossy(&output.stdout).into_owned())
}

/// Remove a run-dir file quietly when absent (clear paths).
fn remove_run_file(path: &str) {
    if let Err(e) = std::fs::remove_file(path) {
        if e.kind() != std::io::ErrorKind::NotFound {
            warn!(path, error = %e, "run file removal failed");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rtnetlink::packet_core::NetlinkHeader;

    /// The sysctl path is the canonical procfs location keyed by
    /// interface name (what the container smoke greps for).
    #[test]
    fn rp_filter_path_is_canonical_procfs() {
        assert_eq!(
            rp_filter_path("vethspoof"),
            "/proc/sys/net/ipv4/conf/vethspoof/rp_filter"
        );
    }

    // ---- F9: the bounded ACK + resync --------------------------------

    /// The wedge shape from the bench evidence: the first attempt's ACK
    /// never arrives (the kernel dropped it), the second lands — the
    /// request re-issues instead of hanging. The seam deadline keeps the
    /// wait at milliseconds (production runs [`NL_ACK_TIMEOUT`]).
    #[tokio::test]
    async fn ack_bounded_reissues_a_silent_request_and_recovers() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        let attempts = AtomicUsize::new(0);
        let outcome: AckWait<()> =
            ack_bounded_within(std::time::Duration::from_millis(10), "test", || {
                let silent = attempts.fetch_add(1, Ordering::SeqCst) == 0;
                async move {
                    if silent {
                        futures::future::pending::<()>().await;
                        unreachable!("the wedged attempt must be dropped at its deadline");
                    }
                    Ok(())
                }
            })
            .await;
        assert!(matches!(outcome, AckWait::Answered(Ok(()))));
        assert_eq!(attempts.load(Ordering::SeqCst), 2);
    }

    /// A permanently silent request consumes exactly the attempt budget
    /// and reports `Silent` — the caller surfaces an error instead of
    /// parking forever (the F9 wedge the escalation pinned).
    #[tokio::test]
    async fn ack_bounded_gives_up_after_the_attempt_budget() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        let attempts = AtomicUsize::new(0);
        let outcome: AckWait<()> =
            ack_bounded_within(std::time::Duration::from_millis(10), "test", || {
                attempts.fetch_add(1, Ordering::SeqCst);
                futures::future::pending::<Result<(), rtnetlink::Error>>()
            })
            .await;
        assert!(matches!(outcome, AckWait::Silent));
        assert_eq!(attempts.load(Ordering::SeqCst), NL_ACK_ATTEMPTS);
    }

    /// A kernel ANSWER — success or error — is final on the first
    /// attempt: re-issuing an answered error would only duplicate
    /// kernel work (ESRCH tolerance is the caller's business).
    #[tokio::test]
    async fn ack_bounded_forwards_kernel_errors_without_reissue() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        let attempts = AtomicUsize::new(0);
        let outcome: AckWait<()> = ack_bounded("test", || {
            attempts.fetch_add(1, Ordering::SeqCst);
            async { Err(rtnetlink::Error::RequestFailed) }
        })
        .await;
        assert!(matches!(
            outcome,
            AckWait::Answered(Err(rtnetlink::Error::RequestFailed))
        ));
        assert_eq!(attempts.load(Ordering::SeqCst), 1);
    }

    /// The framed layer's ENOBUFS synthesis (framed.rs: default header,
    /// NLMSG_OVERRUN, empty body) classifies as the resync trigger;
    /// inner messages keep their event/skip mapping.
    #[test]
    fn overrun_marker_classifies_for_resync() {
        let overrun = NetlinkMessage::new(
            NetlinkHeader::default(),
            NetlinkPayload::Overrun(Vec::new()),
        );
        assert!(matches!(classify_rx(overrun), RxStep::Overrun));

        let mut link = LinkMessage::default();
        link.header.index = 2;
        link.attributes.push(LinkAttribute::IfName("eth0".into()));
        let new_link = NetlinkMessage::new(
            NetlinkHeader::default(),
            NetlinkPayload::InnerMessage(RouteNetlinkMessage::NewLink(link)),
        );
        match classify_rx(new_link) {
            RxStep::Event(DataplaneEvent::LinkNew { ifindex, .. }) => assert_eq!(ifindex, 2),
            other => panic!("expected a LinkNew event, got {other:?}"),
        }
    }

    /// The drain-and-resync ordering: events already queued ahead of an
    /// overrun marker surface first, the resync's mirror refresh drains
    /// next, and the stream behind the marker continues — recovery, not
    /// restart (the "socket is not dead, just behind" contract).
    #[tokio::test]
    async fn overrun_pump_drains_resyncs_then_recovers() {
        fn link_msg(ifindex: u32, name: &str) -> NetlinkMessage<RouteNetlinkMessage> {
            let mut link = LinkMessage::default();
            link.header.index = ifindex;
            link.attributes.push(LinkAttribute::IfName(name.into()));
            NetlinkMessage::new(
                NetlinkHeader::default(),
                NetlinkPayload::InnerMessage(RouteNetlinkMessage::NewLink(link)),
            )
        }
        let addr = SocketAddr::new(0, 0);
        let mut stream = futures::stream::iter(vec![
            (link_msg(2, "eth0"), addr),
            (
                NetlinkMessage::new(
                    NetlinkHeader::default(),
                    NetlinkPayload::Overrun(Vec::new()),
                ),
                addr,
            ),
            (link_msg(3, "eth1"), addr),
        ]);
        let mut backlog = std::collections::VecDeque::new();

        // Before the marker: the plain event.
        let first = next_event_with(&mut stream, &mut backlog, || async { Vec::new() }).await;
        assert!(matches!(
            first,
            Some(DataplaneEvent::LinkNew { ifindex: 2, .. })
        ));

        // The marker: the resync queue fills, and its events drain ahead
        // of the stream (marker events stand in for the re-dump here —
        // `resync_link_address_mirror` needs a live kernel) — starting
        // with the very call that observed the marker.
        let resync_first = next_event_with(&mut stream, &mut backlog, || async {
            vec![
                DataplaneEvent::LinkDel { ifindex: 98 },
                DataplaneEvent::LinkDel { ifindex: 99 },
            ]
        })
        .await;
        assert!(matches!(
            resync_first,
            Some(DataplaneEvent::LinkDel { ifindex: 98 })
        ));
        let resync_second =
            next_event_with(&mut stream, &mut backlog, || async { Vec::new() }).await;
        assert!(matches!(
            resync_second,
            Some(DataplaneEvent::LinkDel { ifindex: 99 })
        ));

        // Behind the marker: reading continues where it left off.
        let after = next_event_with(&mut stream, &mut backlog, || async { Vec::new() }).await;
        assert!(matches!(
            after,
            Some(DataplaneEvent::LinkNew { ifindex: 3, .. })
        ));
        let end = next_event_with(&mut stream, &mut backlog, || async { Vec::new() }).await;
        assert!(end.is_none());
    }
}
