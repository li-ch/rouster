//! Fuzz the BGP message codec (RFC 4271 §4 + MP extensions, RFC 7606
//! error handling, RFC 7911 ADD-PATH direction) — AGENTS.md
//! invariant 7. The decode `Result` is the oracle; a panic inside the
//! codec is the bug.
//!
//! Input shape: one steering byte (bit 0 picks 4-octet AS mode, bit
//! 1 selects strict RFC 4271 handling over the RFC 7606 default),
//! then one whole BGP message (16-byte marker, length, type) exactly
//! as the session layer frames it.

#![no_main]

use bgpd::attr::{AddPathCtx, UpdateHandling};
use bgpd::message::BgpMessage;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if data.is_empty() {
        return;
    }
    let asn4 = data[0] & 0x01 != 0;
    let handling = if data[0] & 0x02 != 0 {
        UpdateHandling::StrictRfc4271
    } else {
        // The modern default (RFC 7606) — the mode production runs.
        UpdateHandling::default()
    };
    let frame = &data[1..];
    let _ = BgpMessage::decode(frame, asn4);
    let _ = BgpMessage::decode_with_handling(frame, asn4, handling, AddPathCtx::default());
});
