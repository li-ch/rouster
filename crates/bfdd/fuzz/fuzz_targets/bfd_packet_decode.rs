//! Fuzz the BFD Control packet codec (RFC 5880 §4/§6.8.6 decode and
//! validation) under both version policies — AGENTS.md invariant 7.
//! The decode `Result` is the oracle; a panic inside the codec is the
//! bug.
//!
//! Input shape: one steering byte (bit 0 selects the draft-0
//! compatibility policy over strict version-1), then the control
//! packet. The steering byte is also tried as a packet lead byte
//! under the default policy so both policies see fuzzed version
//! bits.

#![no_main]

use bfdd::packet::{BfdPacket, VersionPolicy};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if data.is_empty() {
        return;
    }
    let policy = if data[0] & 0x01 != 0 {
        VersionPolicy::AcceptDraft0
    } else {
        VersionPolicy::Version1Only
    };
    let _ = BfdPacket::decode(&data[1..], policy);
    let _ = BfdPacket::decode(data, VersionPolicy::default());
});
