//! Fuzz the IS-IS wire codecs: whole-PDU decode (`pdu.rs` — common
//! header + per-PDU-type body) and the raw TLV stream decoder
//! (`tlv.rs`) — AGENTS.md invariant 7. The decode `Result` is the
//! oracle; a panic inside the codec is the bug.

#![no_main]

use isisd::pdu::Pdu;
use isisd::tlv::decode_tlvs;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = Pdu::decode(data);
    let _ = decode_tlvs(data);
});
