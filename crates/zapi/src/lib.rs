//! ZAPI — the FRR zebra protocol — codec and server.
//!
//! This crate is an **interop edge** (see docs/architecture.md): it lets real
//! FRR protocol daemons (bgpd, ospfd, …) attach to Rouster's RIB. ZAPI is an
//! adapter surface here, never an internal architecture.
//!
//! Wire format reference: `docs/interop/zapi-10.2-pinned.md` (empirical
//! capture against FRR 10.2.2) plus the crate docs on each body type.

pub mod client;
pub mod header;
pub mod message;
pub mod server;

pub use client::{route_add_message, route_delete_message, route_type_from, ZapiClient};
pub use header::{ZapiHeader, ZapiHeaderError, ZAPI_HEADER_LEN, ZAPI_MARKER, ZAPI_VERSION};
pub use message::{
    blackhole_type, message_flag, nexthop_flag, nexthop_type, route_type, ZapiCodecError,
    ZapiCommand, ZapiHello, ZapiInterface, ZapiInterfaceAddress, ZapiMessage, ZapiNexthop,
    ZapiNexthopRegister, ZapiNexthopUpdate, ZapiRedistribute, ZapiRoute, ZapiRouterIdUpdate,
};
pub use server::{
    run_session, serve, InterfaceMirror, NhtRegistration, RibCommand, SessionPush, ZapiSession,
    DEFAULT_TABLE,
};
