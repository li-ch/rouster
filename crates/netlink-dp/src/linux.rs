//! Real rtnetlink-backed dataplane (Linux only).

use common::{
    Dataplane, DataplaneError, DataplaneEvent, IpPrefix, Ipv4Prefix, Ipv6Prefix, Nexthop,
    RouteEntry, RouteProtocol,
};
use futures::TryStreamExt;
use netlink_packet_route::address::{AddressAttribute, AddressMessage};
use netlink_packet_route::link::{LinkAttribute, LinkFlags, LinkMessage};
use netlink_packet_route::route::{
    RouteAddress, RouteAttribute, RouteMessage, RouteProtocol as NlRouteProtocol, RouteScope,
    RouteType,
};
use netlink_packet_route::{AddressFamily, RouteNetlinkMessage};
use rtnetlink::packet_core::{NetlinkMessage, NetlinkPayload};
use rtnetlink::sys::{protocols::NETLINK_ROUTE, AsyncSocket, SocketAddr, TokioSocket};
use tracing::{debug, instrument};

/// Netlink-backed dataplane handle.
///
/// Owns the multicast event receiver; `next_event` drives the kernel→RIB
/// direction of the mirror.
pub struct NetlinkDataplane {
    handle: rtnetlink::Handle,
    messages: futures::channel::mpsc::UnboundedReceiver<(
        NetlinkMessage<RouteNetlinkMessage>,
        SocketAddr,
    )>,
}

impl NetlinkDataplane {
    /// Opens the netlink connection, subscribed to link/address/route
    /// multicast groups so kernel changes arrive as events.
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
            | libc::RTMGRP_IPV6_ROUTE;
        socket
            .socket_mut()
            .bind(&SocketAddr::new(0, groups as u32))?;

        let (connection, handle, messages) = rtnetlink::from_socket(socket);
        Ok((Self { handle, messages }, connection))
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
                _ => None,
            };
            if ev.is_some() {
                return ev;
            }
        }
    }
}

/// Maps a kernel link message to a `LinkNew` event (name resolution included).
fn link_event(msg: &LinkMessage, _is_new: bool) -> Option<DataplaneEvent> {
    let name = msg.attributes.iter().find_map(|a| match a {
        LinkAttribute::IfName(n) => Some(n.clone()),
        _ => None,
    })?;
    Some(DataplaneEvent::LinkNew {
        ifindex: msg.header.index,
        name,
        is_up: msg.header.flags.contains(LinkFlags::Up),
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
/// Phase 0 limitation: only the first nexthop is programmed; ECMP via
/// RTA_MULTIPATH / nexthop objects is the immediate follow-up.
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

    msg.header.table = entry.table as u8; // TODO(phase-0): RTA_TABLE for ids > 255
    msg.header.protocol = nl_protocol(entry);
    msg.header.scope = RouteScope::Universe;
    msg.header.kind = RouteType::Unicast;
    msg.attributes.push(RouteAttribute::Priority(entry.metric));

    let hop = entry
        .nexthops
        .hops()
        .first()
        .map(|(h, _)| *h)
        .unwrap_or(Nexthop::Blackhole);

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
        self.handle
            .route()
            .del(msg)
            .execute()
            .await
            .map_err(nl_err)?;
        debug!("route deleted");
        Ok(())
    }
}
