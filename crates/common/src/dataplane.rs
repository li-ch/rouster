//! The dataplane abstraction.
//!
//! Everything that programs or observes the forwarding plane goes through this
//! trait: netlink (today), FPM/eBPF (later). No component outside the
//! dataplane crate(s) may talk to the kernel directly.

use std::fmt;
use std::future::Future;

use crate::route::RouteEntry;

/// Error type for dataplane operations.
#[derive(Debug, thiserror::Error)]
pub enum DataplaneError {
    #[error("dataplane I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("dataplane operation not supported: {0}")]
    Unsupported(&'static str),
    #[error("dataplane error: {0}")]
    Other(String),
}

/// Events observed from the forwarding plane (link/address/neighbour changes).
///
/// Phase 0 syncs these from netlink; the RIB consumes them for nexthop
/// resolution and interface tracking.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DataplaneEvent {
    LinkNew { ifindex: u32, name: String },
    LinkDel { ifindex: u32 },
    // TODO(phase-0): address/neighbour events.
}

impl fmt::Display for DataplaneEvent {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DataplaneEvent::LinkNew { ifindex, name } => {
                write!(f, "link new: {name} (ifindex {ifindex})")
            }
            DataplaneEvent::LinkDel { ifindex } => write!(f, "link del: ifindex {ifindex}"),
        }
    }
}

/// The forwarding-plane interface.
///
/// Implemented by `netlink-dp` today; FPM/eBPF backends plug in later without
/// touching the RIB or protocol crates.
pub trait Dataplane {
    /// Atomically install or replace a route (RTM_NEWROUTE NLM_F_REPLACE).
    fn route_replace(
        &self,
        entry: &RouteEntry,
    ) -> impl Future<Output = Result<(), DataplaneError>> + Send;

    /// Remove a route (RTM_DELROUTE).
    fn route_delete(
        &self,
        entry: &RouteEntry,
    ) -> impl Future<Output = Result<(), DataplaneError>> + Send;

    // TODO(phase-0): initial dump + event stream (links, addresses, routes,
    // neighbours), nexthop-group objects, VRF/netns awareness.
}
