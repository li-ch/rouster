//! BGP wire/protocol error type: every error carries the NOTIFICATION
//! (code, subcode) pair it maps to per RFC 4271 §4.5 (error/subcode
//! tables in §4.1/§4.2/§4.3 plus the §6 handling rules), so the session
//! layer can answer malformed input with the exact message the RFC
//! prescribes instead of inventing one.

/// Error codes (RFC 4271 §4.5).
pub mod error_code {
    pub const MESSAGE_HEADER: u8 = 1;
    pub const OPEN_MESSAGE: u8 = 2;
    pub const UPDATE_MESSAGE: u8 = 3;
    pub const HOLD_TIMER_EXPIRED: u8 = 4;
    pub const FINITE_STATE_MACHINE: u8 = 5;
    pub const CEASE: u8 = 6;
}

/// Message Header error subcodes (RFC 4271 §4.5).
pub mod header_subcode {
    pub const CONNECTION_NOT_SYNCHRONIZED: u8 = 1;
    pub const BAD_MESSAGE_LENGTH: u8 = 2;
    pub const BAD_MESSAGE_TYPE: u8 = 3;
}

/// OPEN Message error subcodes (RFC 4271 §4.5).
pub mod open_subcode {
    pub const UNSUPPORTED_VERSION_NUMBER: u8 = 1;
    pub const BAD_PEER_AS: u8 = 2;
    pub const BAD_BGP_IDENTIFIER: u8 = 3;
    pub const UNSUPPORTED_OPTIONAL_PARAMETER: u8 = 4;
    pub const UNACCEPTABLE_HOLD_TIME: u8 = 6;
}

/// UPDATE Message error subcodes (RFC 4271 §4.5).
pub mod update_subcode {
    pub const MALFORMED_ATTRIBUTE_LIST: u8 = 1;
    pub const UNRECOGNIZED_WELL_KNOWN_ATTRIBUTE: u8 = 2;
    pub const MISSING_WELL_KNOWN_ATTRIBUTE: u8 = 3;
    pub const ATTRIBUTE_FLAGS_ERROR: u8 = 4;
    pub const ATTRIBUTE_LENGTH_ERROR: u8 = 5;
    pub const INVALID_ORIGIN: u8 = 6;
    pub const INVALID_NEXT_HOP: u8 = 8;
    pub const OPTIONAL_ATTRIBUTE_ERROR: u8 = 9;
    pub const INVALID_NETWORK_FIELD: u8 = 10;
    pub const MALFORMED_AS_PATH: u8 = 11;
}

/// NOTIFICATION Cease subcodes (RFC 4486; only the ones bgpd sends).
pub mod cease_subcode {
    pub const MAX_PREFIXES: u8 = 1;
    pub const ADMIN_SHUTDOWN: u8 = 2;
    pub const PEER_DECONFIGURED: u8 = 3;
    pub const ADMIN_RESET: u8 = 4;
}

/// A codec or protocol error. `notification` holds the (code, subcode)
/// the RFC prescribes when the peer must be told; `None` marks local
/// framing errors that close the connection without a wire answer.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{message}")]
pub struct BgpError {
    pub message: String,
    pub notification: Option<(u8, u8)>,
}

impl BgpError {
    /// A local error with no NOTIFICATION mapping.
    pub fn local(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
            notification: None,
        }
    }

    /// An error that maps onto a NOTIFICATION with `data` the caller may
    /// append when building the message.
    pub fn notify(code: u8, subcode: u8, message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
            notification: Some((code, subcode)),
        }
    }
}

/// Result alias for the codec.
pub type BgpResult<T> = Result<T, BgpError>;
