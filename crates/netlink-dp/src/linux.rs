//! Real rtnetlink-backed dataplane (Linux only).

use common::{Dataplane, DataplaneError, Nexthop, RouteEntry};
use futures::TryStreamExt;
use netlink_packet_route::route::{
    RouteAddress, RouteAttribute, RouteMessage, RouteProtocol as NlRouteProtocol, RouteScope,
    RouteType,
};
use netlink_packet_route::AddressFamily;
use tracing::{debug, instrument};

/// Netlink-backed dataplane handle.
pub struct NetlinkDataplane {
    handle: rtnetlink::Handle,
}

impl NetlinkDataplane {
    /// Opens the netlink connection. The returned future is the connection
    /// driver; spawn it on the runtime (e.g. `tokio::spawn(conn)`).
    pub fn new() -> std::io::Result<(Self, impl std::future::Future<Output = ()> + Send)> {
        let (connection, handle, _messages) = rtnetlink::new_connection()?;
        Ok((Self { handle }, connection))
    }

    pub fn handle(&self) -> &rtnetlink::Handle {
        &self.handle
    }

    /// Counts routes currently in the kernel. Phase 0 uses this as a minimal
    /// "mirror" sanity check; full RIB sync comes with the event stream work.
    pub async fn dump_route_count(&self) -> Result<usize, DataplaneError> {
        let mut dump = self.handle.route().get(RouteMessage::default()).execute();
        let mut count = 0usize;
        while let Some(_msg) = dump.try_next().await.map_err(nl_err)? {
            count += 1;
        }
        Ok(count)
    }
}

fn nl_err(e: rtnetlink::Error) -> DataplaneError {
    DataplaneError::Other(e.to_string())
}

/// Maps Rouster's route protocol to an RTPROT_* value.
fn nl_protocol(entry: &RouteEntry) -> NlRouteProtocol {
    use common::RouteProtocol as P;
    match entry.protocol {
        P::Kernel => NlRouteProtocol::Kernel,
        P::Connected => NlRouteProtocol::Kernel, // connected routes are kernel-owned
        P::Static => NlRouteProtocol::Static,
        P::Bgp => NlRouteProtocol::Bgp,
        // The kernel has no RTPROT_ISIS; use OSPF-class "other IGP" values
        // only where they exist, otherwise fall back to Static.
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
        common::IpPrefix::V4(p) => {
            msg.header.address_family = AddressFamily::Inet;
            msg.header.destination_prefix_length = p.prefix_len();
            msg.attributes
                .push(RouteAttribute::Destination(RouteAddress::Inet(p.addr())));
        }
        common::IpPrefix::V6(p) => {
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
        // An IPv6 nexthop on an IPv4 route (or vice versa) is the extended
        // nexthop case (RFC 5549); out of Phase 0 scope.
        Nexthop::Ipv6(_) | Nexthop::Ipv6If(..) => {
            if matches!(entry.prefix, common::IpPrefix::V4(_)) {
                return Err(DataplaneError::Unsupported(
                    "cross-AF nexthop (RFC 5549) not supported yet",
                ));
            }
            match hop {
                Nexthop::Ipv6(gw) => msg
                    .attributes
                    .push(RouteAttribute::Gateway(RouteAddress::Inet6(gw))),
                Nexthop::Ipv6If(gw, ix) => {
                    msg.attributes
                        .push(RouteAttribute::Gateway(RouteAddress::Inet6(gw)));
                    msg.attributes.push(RouteAttribute::Oif(ix));
                }
                _ => unreachable!(),
            }
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
