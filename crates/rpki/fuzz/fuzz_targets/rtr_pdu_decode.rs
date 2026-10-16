//! Fuzz the RTR protocol codec (RPKI-to-Router, RFC 8210 PDU decode)
//! — AGENTS.md invariant 7. The decode `Result` is the oracle; a
//! panic inside the codec is the bug.
//!
//! Input shape: a stream prefix exactly as `rpki::client` reads it —
//! the decoder consumes the PDU at the front and reports the bytes
//! consumed; trailing bytes are the next PDU's business.

#![no_main]

use libfuzzer_sys::fuzz_target;
use rpki::pdu::Pdu;

fuzz_target!(|data: &[u8]| {
    let _ = Pdu::decode(data);
});
