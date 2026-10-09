//! Linux dataplane backend over rtnetlink.
//!
//! The only crate allowed to talk to the kernel. Implements
//! [`common::Dataplane`]; later backends (FPM, eBPF) plug in behind the same
//! trait.
//!
//! Platform note: rtnetlink is Linux-only. On non-Linux platforms this crate
//! compiles to a stub that fails at construction with
//! [`DataplaneError::Unsupported`], keeping the workspace buildable on macOS
//! dev machines. Real dataplane testing runs in Linux netns/Containerlab
//! topologies.

#[cfg(target_os = "linux")]
mod linux;
#[cfg(not(target_os = "linux"))]
mod stub;

#[cfg(target_os = "linux")]
pub use linux::NetlinkDataplane;
#[cfg(not(target_os = "linux"))]
pub use stub::NetlinkDataplane;

/// SAV program → rp_filter sysctl translation (pure, cross-platform so
/// its unit tests run on dev machines; the Linux impl executes it).
pub mod sav;

// TODO(phase-0): netns awareness; TODO(phase-1): nexthop-group objects.
// (Link — including VRF device/table association —, address, route, and
// neighbour dumps/events are implemented above.)
