//! Fuzz the ZAPI codec edge: FRR header framing + per-command body
//! decode (AGENTS.md invariant 7 — "fuzz every wire codec"). The
//! decode `Result` is the oracle: `Ok` and `Err` are both fine; a
//! panic (unwrap/index/slice) inside the codec is the bug.
//!
//! Input shape: a whole ZAPI message as the session layer hands it to
//! the codec — 10-byte header (length/marker/version/vrf/command)
//! followed by the body. The header's length field frames the body
//! the way the server slices it.

#![no_main]

use libfuzzer_sys::fuzz_target;
use zapi::{ZapiHeader, ZapiMessage, ZAPI_HEADER_LEN};

fuzz_target!(|data: &[u8]| {
    if data.len() < ZAPI_HEADER_LEN {
        return;
    }
    let Ok(header) = ZapiHeader::decode(&data[..ZAPI_HEADER_LEN]) else {
        return;
    };
    // The framing layer trusts the declared length when the buffer
    // holds it; a short buffer contributes whatever remains.
    let end = (header.length as usize).min(data.len());
    let body = &data[ZAPI_HEADER_LEN..end];
    let _ = ZapiMessage::decode(header.command, body);
});
