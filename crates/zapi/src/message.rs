//! ZAPI message model.
//!
//! Phase 1 scope: the subset needed for FRR bgpd/ospfd to attach and install
//! routes — interface add/update/delete, router-id, route add/delete, nexthop
//! tracking, redistribute. Everything else decodes as `Unknown` and is logged.
//!
//! NOTE: command numbering follows FRR's `zapi_msg` / `zebra_message_types_t`.
//! Values for FRR 10.2.2 (ZAPI v6) are PINNED in
//! `docs/interop/zapi-10.2-pinned.md` — captured empirically against the real
//! release (wire fixtures in `tests/fixtures/`) and cross-checked against the
//! build's own message table. Highlights: INTERFACE_ADD=0, ROUTE_ADD=9,
//! ROUTE_DELETE=10, REDISTRIBUTE_ADD=12, ROUTER_ID_ADD=16, HELLO=19,
//! NEXTHOP_REGISTER=21, BFD_CLIENT_REGISTER=36, LABEL_MANAGER_CONNECT=49,
//! ROUTE_NOTIFY_REQUEST=126. Z2 turns these into this enum's discriminants.

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
