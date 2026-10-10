//! Rouster `rpki` — the RPKI/RTR client + ROV/ASPA library (Phase 2
//! stream P2-c).
//!
//! This crate is a **library for the edge**: bgpd's import policy
//! consumes the VRP and ASPA tables and the validation verdicts; there
//! is no daemon of its own this round (see docs/architecture.md,
//! "RPKI from the start").
//!
//! Layout:
//! - [`pdu`]: the RTR wire codec — RFC 8210 §5, plus the version-2
//!   additions of draft-ietf-sidrops-8210bis-27 (ASPA PDU, 64 KiB
//!   cap, error codes 9–12) and version-0 (RFC 6810) downgrade
//!   shapes.
//! - [`vrp`]: the Validated ROA Payload table with RFC 6811
//!   covering/matching semantics.
//! - [`rov`]: RFC 6811 §2 prefix-origin validation (the pure
//!   NotFound/Valid/Invalid function over the VRP set).

pub mod pdu;
pub mod rov;
pub mod vrp;

pub use pdu::{
    ErrorCode, Pdu, PayloadFlags, Timing, MAX_PDU_LEN, RTR_PORT, VERSION_0, VERSION_1,
    VERSION_2, HIGHEST_VERSION,
};
pub use rov::{validate, OriginAsn, Validity};
pub use vrp::{Vrp, VrpTable};
