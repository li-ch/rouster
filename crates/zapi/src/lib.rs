//! ZAPI — the FRR zebra protocol — codec and server.
//!
//! This crate is an **interop edge** (see docs/architecture.md): it lets real
//! FRR protocol daemons (bgpd, ospfd, …) attach to Rouster's RIB. ZAPI is an
//! adapter surface here, never an internal architecture.
//!
//! Wire format reference: `docs/interop/zapi-10.2-pinned.md` (empirical
//! capture against FRR 10.2.2) plus the crate docs on each body type.

#![forbid(unsafe_code)]

pub mod client;
pub mod header;
pub mod message;
pub mod server;

pub use client::{route_add_message, route_delete_message, route_type_from, ZapiClient};
/// Re-exported for edge consumers (bfdd's zapi edge builds
/// `ZapiBfdDestStatus` prefixes without depending on `common`
/// themselves — P2-a deliberately kept bfdd dependency-light).
pub use common::IpPrefix;
pub use header::{ZapiHeader, ZapiHeaderError, ZAPI_HEADER_LEN, ZAPI_MARKER, ZAPI_VERSION};
pub use message::{
    bfd_status, blackhole_type, message_flag, nexthop_flag, nexthop_type, route_notify_note,
    route_type, ZapiBfdDestStatus, ZapiBfdSessionCmd, ZapiCodecError, ZapiCommand, ZapiHello,
    ZapiInterface, ZapiInterfaceAddress, ZapiMessage, ZapiNeighNotify, ZapiNeighRegister,
    ZapiNexthop, ZapiNexthopRegister, ZapiNexthopUpdate, ZapiRedistribute, ZapiRoute,
    ZapiRouteNotifyOwner, ZapiRouterIdUpdate, ZEBRA_NEIGH_STATE_FAILED,
};
pub use server::{
    run_session, serve, InterfaceMirror, NhtRegistration, RibCommand, SessionPush, ZapiSession,
    DEFAULT_TABLE,
};
