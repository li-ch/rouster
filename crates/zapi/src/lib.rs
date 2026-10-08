//! ZAPI — the FRR zebra protocol — codec and server.
//!
//! This crate is an **interop edge** (see docs/architecture.md): it lets real
//! FRR protocol daemons (bgpd, ospfd, …) attach to Rouster's RIB. ZAPI is an
//! adapter surface here, never an internal architecture.
//!
//! Wire format reference: FRR developer guide, "Zebra Protocol" chapter.

pub mod header;
pub mod message;
pub mod server;

pub use header::{ZapiHeader, ZAPI_HEADER_LEN, ZAPI_MARKER, ZAPI_VERSION};
pub use message::{ZapiCommand, ZapiMessage};
