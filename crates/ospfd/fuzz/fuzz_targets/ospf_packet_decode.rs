//! Fuzz the OSPF wire codecs — both AF-generic halves of the family:
//! v2 packets (`packet.rs`, plain + crypto-auth framing), v3 packets
//! (`packet_v3.rs`, whose checksum pseudo-header carries the IPv6
//! src/dst), and the LSA codecs (`lsa.rs`, `lsa_v3.rs`) — AGENTS.md
//! invariant 7. The decode `Result` is the oracle; a panic inside the
//! codec is the bug.
//!
//! Input shape: for v3 packets, the first 32 bytes double as the
//! source and destination IPv6 addresses of the pseudo-header (the
//! fuzzed packet proper is the remainder); v2 packets and LSAs take
//! the whole input.

#![no_main]

use libfuzzer_sys::fuzz_target;
use ospfd::lsa::Lsa;
use ospfd::lsa_v3::LsaV3;
use ospfd::packet::Packet;
use ospfd::packet_v3::PacketV3;
use std::net::Ipv6Addr;

fuzz_target!(|data: &[u8]| {
    let _ = Packet::decode(data);
    let _ = Packet::decode_crypto(data);
    let _ = Lsa::decode(data);
    let _ = LsaV3::decode(data);
    if data.len() >= 32 {
        let mut src = [0u8; 16];
        let mut dst = [0u8; 16];
        src.copy_from_slice(&data[..16]);
        dst.copy_from_slice(&data[16..32]);
        let _ = PacketV3::decode(&data[32..], Ipv6Addr::from(src), Ipv6Addr::from(dst));
    }
});
