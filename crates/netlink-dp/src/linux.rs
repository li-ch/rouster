//! Real rtnetlink-backed dataplane (Linux only).

use common::{Dataplane, DataplaneError, RouteEntry};
use tracing::debug;

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
}

impl Dataplane for NetlinkDataplane {
    async fn route_replace(&self, entry: &RouteEntry) -> Result<(), DataplaneError> {
        // TODO(phase-0): encode RTM_NEWROUTE with NLM_F_REPLACE |
        // NLM_F_CREATE — v4/v6 prefix, nexthop group (multipath via
        // RTA_MULTIPATH or nexthop objects), table id, protocol (RTPROT_*).
        debug!(prefix = %entry.prefix, "netlink-dp: route_replace (stub)");
        let _ = &self.handle;
        Ok(())
    }

    async fn route_delete(&self, entry: &RouteEntry) -> Result<(), DataplaneError> {
        // TODO(phase-0): encode RTM_DELROUTE.
        debug!(prefix = %entry.prefix, "netlink-dp: route_delete (stub)");
        let _ = &self.handle;
        Ok(())
    }
}
