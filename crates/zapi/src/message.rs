//! ZAPI message model.
//!
//! Phase 1 scope: the subset needed for FRR bgpd/ospfd to attach and install
//! routes — interface add/update/delete, router-id, route add/delete, nexthop
//! tracking, redistribute. Everything else decodes as `Unknown` and is logged.
//!
//! NOTE: command numbering follows FRR's `zapi_msg` / `zebra_message_types_t`;
//! exact values are pinned per supported FRR release (see implementation plan,
//! risk "ZAPI drift"). Fill in during Phase 1 against a pinned FRR version.

use common::RouteEntry;

/// ZAPI command codes (subset; numeric values pinned in Phase 1).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ZapiCommand {
    InterfaceAdd,
    InterfaceDelete,
    InterfaceAddressAdd,
    InterfaceAddressDelete,
    RouterIdAdd,
    RouteAdd,
    RouteDelete,
    NexthopRegister,
    NexthopUnregister,
    RedistributeAdd,
    RedistributeDelete,
    /// Any command outside the supported subset.
    Unknown(u16),
}

/// Decoded ZAPI message (subset for Phase 1).
#[derive(Debug, Clone, PartialEq)]
pub enum ZapiMessage {
    InterfaceAdd { ifindex: u32, name: String },
    RouteAdd(RouteEntry),
    RouteDelete(RouteEntry),
    // TODO(phase-1): full message set + bodies.
    Unknown { command: u16, body: Vec<u8> },
}
