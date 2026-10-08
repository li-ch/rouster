//! Non-Linux stub: keeps the workspace buildable on macOS/BSD dev machines.
//!
//! Any attempt to construct the dataplane fails with
//! [`DataplaneError::Unsupported`]; route operations never succeed here.

use common::{Dataplane, DataplaneError, RouteEntry};

/// Stub dataplane for non-Linux platforms.
pub struct NetlinkDataplane {
    _private: (),
}

impl NetlinkDataplane {
    pub fn new() -> std::io::Result<(Self, std::future::Ready<()>)> {
        Err(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "netlink dataplane is only available on Linux",
        ))
    }

    pub async fn dump_route_count(&self) -> Result<usize, DataplaneError> {
        Err(DataplaneError::Unsupported(
            "netlink dataplane is only available on Linux",
        ))
    }
}

impl Dataplane for NetlinkDataplane {
    async fn route_replace(&self, _entry: &RouteEntry) -> Result<(), DataplaneError> {
        Err(DataplaneError::Unsupported(
            "netlink dataplane is only available on Linux",
        ))
    }

    async fn route_delete(&self, _entry: &RouteEntry) -> Result<(), DataplaneError> {
        Err(DataplaneError::Unsupported(
            "netlink dataplane is only available on Linux",
        ))
    }
}
