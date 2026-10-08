//! Golden tests against the Z1 wire fixtures (FRR 10.2.2).
//!
//! Every parseable message in `tests/fixtures/*.log` must (a) decode into
//! the hand-derived expected [`ZapiMessage`] literal below, and (b)
//! re-encode byte-identically. The fixtures are ground truth
//! (`docs/interop/zapi-10.2-pinned.md`): if one of these tests fails, the
//! codec is wrong, not the fixture.

use std::fmt::Write as _;
use std::path::Path;

use bytes::BytesMut;
use zapi::{
    blackhole_type, message_flag, nexthop_type, route_type, ZapiHeader, ZapiHello,
    ZapiInterfaceAddress, ZapiMessage, ZapiNexthop, ZapiNexthopRegister, ZapiRedistribute,
    ZapiRoute, ZAPI_HEADER_LEN,
};

struct FixtureMessage {
    conn: u64,
    seq: u64,
    cmd: u16,
    len: u16,
    hdr: Vec<u8>,
    body: Vec<u8>,
}

/// Extracts every `msg=` line from a zapi-sniff capture log.
fn parse_fixture(path: &Path) -> Vec<FixtureMessage> {
    let text = std::fs::read_to_string(path).expect("fixture readable");
    let mut out = Vec::new();
    for line in text.lines() {
        if !line.contains(" msg=") {
            continue; // START/CONNECT/REPLY/EOF lines
        }
        let mut conn = 0;
        let mut seq = 0;
        let mut cmd = None;
        let mut len = None;
        let mut hdr = None;
        let mut body = None;
        for tok in line.split_whitespace() {
            if let Some(v) = tok.strip_prefix("conn=") {
                conn = v.parse().unwrap_or(0);
            } else if let Some(v) = tok.strip_prefix("msg=") {
                seq = v.parse().unwrap_or(0);
            } else if let Some(v) = tok.strip_prefix("cmd=") {
                cmd = Some(v.parse().expect("cmd is numeric"));
            } else if let Some(v) = tok.strip_prefix("len=") {
                len = Some(v.parse().expect("len is numeric"));
            } else if let Some(v) = tok.strip_prefix("hdr=") {
                hdr = Some(unhex(v));
            } else if let Some(v) = tok.strip_prefix("body=") {
                body = Some(unhex(v));
            }
        }
        let (Some(cmd), Some(len), Some(hdr), Some(body)) = (cmd, len, hdr, body) else {
            panic!("malformed fixture line: {line}");
        };
        out.push(FixtureMessage {
            conn,
            seq,
            cmd,
            len,
            hdr,
            body,
        });
    }
    out
}

fn unhex(s: &str) -> Vec<u8> {
    assert_eq!(s.len() % 2, 0, "even-length hex, got {s:?}");
    s.as_bytes()
        .chunks(2)
        .map(|p| u8::from_str_radix(std::str::from_utf8(p).unwrap(), 16).unwrap())
        .collect()
}

fn hexs(b: &[u8]) -> String {
    let mut s = String::new();
    for byte in b {
        let _ = write!(s, "{byte:02x}");
    }
    s
}

fn staticd_fixture() -> Vec<FixtureMessage> {
    parse_fixture(&Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/staticd-10.2.2.log"))
}

fn bgpd_fixture() -> Vec<FixtureMessage> {
    parse_fixture(&Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/bgpd-10.2.2.log"))
}

/// Hand-derived expectation for every distinct staticd message, straight
/// from the pinned doc. An unmatched body fails loudly.
fn expected_staticd(msg: &FixtureMessage) -> ZapiMessage {
    match (msg.cmd, hexs(&msg.body).as_str()) {
        (19, "0400000000000000") => ZapiMessage::Hello(ZapiHello {
            redist_default: route_type::STATIC,
            instance: 0,
            session_id: 0,
            synchronous: 0,
        }),
        (0, "") => ZapiMessage::InterfaceAddRequest,
        (126, "01") => ZapiMessage::RouteNotifyRequest { flag: 1 },
        (16, "0001") => ZapiMessage::RouterIdAdd { afi: 1 },
        (21, "00000001000220c0000201") => ZapiMessage::NexthopRegister(ZapiNexthopRegister {
            connected: false,
            resolve_via_default: false,
            safi: 1,
            prefix: "192.0.2.1/32".parse().unwrap(),
        }),
        (9, "0400000000004100000003010218cb007100010000000006000101") => {
            ZapiMessage::RouteAdd(ZapiRoute {
                route_type: route_type::STATIC,
                instance: 0,
                flags: 0x41,
                message: message_flag::NEXTHOP | message_flag::DISTANCE,
                safi: 1,
                prefix: "203.0.113.0/24".parse().unwrap(),
                src_prefix: None,
                nhg_id: 0,
                nexthops: vec![ZapiNexthop {
                    vrf_id: 0,
                    nh_type: nexthop_type::BLACKHOLE,
                    flags: 0,
                    gate: None,
                    ifindex: 0,
                    bh_type: blackhole_type::REJECT,
                    tail: Vec::new(),
                }],
                backup_nexthops: Vec::new(),
                distance: Some(1),
                metric: None,
                tag: None,
                mtu: None,
                tableid: None,
                opaque: None,
            })
        }
        (10, "0400000000004100000003010218c63364000001") => ZapiMessage::RouteDelete(ZapiRoute {
            route_type: route_type::STATIC,
            instance: 0,
            flags: 0x41,
            message: message_flag::NEXTHOP | message_flag::DISTANCE,
            safi: 1,
            prefix: "198.51.100.0/24".parse().unwrap(),
            src_prefix: None,
            nhg_id: 0,
            nexthops: Vec::new(),
            backup_nexthops: Vec::new(),
            distance: Some(1),
            metric: None,
            tag: None,
            mtu: None,
            tableid: None,
            opaque: None,
        }),
        other => panic!("staticd fixture: no hand-derived literal for {other:?}"),
    }
}

/// Hand-derived expectation for every distinct bgpd message.
fn expected_bgpd(msg: &FixtureMessage) -> ZapiMessage {
    match (msg.cmd, hexs(&msg.body).as_str()) {
        (19, "0a00000000000000") => ZapiMessage::Hello(ZapiHello {
            redist_default: route_type::BGP,
            instance: 0,
            session_id: 0,
            synchronous: 0,
        }),
        (19, "1200000000000000") => ZapiMessage::Hello(ZapiHello {
            redist_default: 0x12, // bgpd's auxiliary zclient; semantics open
            instance: 0,
            session_id: 0,
            synchronous: 0,
        }),
        (19, "0a00000000000101") => ZapiMessage::Hello(ZapiHello {
            redist_default: route_type::BGP,
            instance: 0,
            session_id: 1, // label-manager (synchronous) client
            synchronous: 1,
        }),
        (0, "") => ZapiMessage::InterfaceAddRequest,
        (16, "0001") => ZapiMessage::RouterIdAdd { afi: 1 },
        (36, "00000175") => ZapiMessage::BfdClientRegister { pid: 373 },
        (36, "00000217") => ZapiMessage::BfdClientRegister { pid: 535 },
        (12, "01040000") => ZapiMessage::RedistributeAdd(ZapiRedistribute {
            afi: 1,
            route_type: route_type::STATIC,
            instance: 0,
        }),
        (21, "010000010002200a090909") => ZapiMessage::NexthopRegister(ZapiNexthopRegister {
            connected: true,
            resolve_via_default: false,
            safi: 1,
            prefix: "10.9.9.9/32".parse().unwrap(),
        }),
        (49, "0a0000") => ZapiMessage::LabelManagerConnect {
            proto: route_type::BGP,
            instance: 0,
        },
        other => panic!("bgpd fixture: no hand-derived literal for {other:?}"),
    }
}

#[test]
fn staticd_fixture_full_decode() {
    let msgs = staticd_fixture();
    assert_eq!(msgs.len(), 15, "staticd fixture holds 15 messages");
    for msg in &msgs {
        let decoded = ZapiMessage::decode(msg.cmd, &msg.body)
            .unwrap_or_else(|e| panic!("conn={} msg={}: {e}", msg.conn, msg.seq));
        assert_eq!(
            decoded,
            expected_staticd(msg),
            "conn={} msg={} cmd={}",
            msg.conn,
            msg.seq,
            msg.cmd
        );
        assert_eq!(decoded.command(), msg.cmd);
    }
}

#[test]
fn bgpd_fixture_full_decode() {
    let msgs = bgpd_fixture();
    assert_eq!(msgs.len(), 23, "bgpd fixture holds 23 messages");
    for msg in &msgs {
        let decoded = ZapiMessage::decode(msg.cmd, &msg.body)
            .unwrap_or_else(|e| panic!("conn={} msg={}: {e}", msg.conn, msg.seq));
        assert_eq!(
            decoded,
            expected_bgpd(msg),
            "conn={} msg={} cmd={}",
            msg.conn,
            msg.seq,
            msg.cmd
        );
        assert_eq!(decoded.command(), msg.cmd);
    }
}

#[test]
fn staticd_fixture_bodies_roundtrip_byte_identical() {
    for msg in staticd_fixture() {
        let decoded = ZapiMessage::decode(msg.cmd, &msg.body).expect("decodes");
        let mut buf = BytesMut::new();
        decoded.encode_body(&mut buf).expect("encodes");
        assert_eq!(
            buf.as_ref(),
            msg.body.as_slice(),
            "conn={} msg={} cmd={}",
            msg.conn,
            msg.seq,
            msg.cmd
        );
    }
}

#[test]
fn bgpd_fixture_bodies_roundtrip_byte_identical() {
    for msg in bgpd_fixture() {
        let decoded = ZapiMessage::decode(msg.cmd, &msg.body).expect("decodes");
        let mut buf = BytesMut::new();
        decoded.encode_body(&mut buf).expect("encodes");
        assert_eq!(
            buf.as_ref(),
            msg.body.as_slice(),
            "conn={} msg={} cmd={}",
            msg.conn,
            msg.seq,
            msg.cmd
        );
    }
}

#[test]
fn fixture_headers_stay_consistent_with_bodies() {
    for msg in staticd_fixture().into_iter().chain(bgpd_fixture()) {
        let header = ZapiHeader::decode(&msg.hdr)
            .unwrap_or_else(|e| panic!("conn={} msg={}: {e}", msg.conn, msg.seq));
        assert_eq!(header.command, msg.cmd);
        assert_eq!(header.length, msg.len);
        assert_eq!(header.length as usize, ZAPI_HEADER_LEN + msg.body.len());
        assert_eq!(header.marker, 254);
        assert_eq!(header.version, 6);
        assert_eq!(header.vrf_id, 0);
    }
}

/// The one zebra→client message shape we can partially derive from the
/// fixtures: replying to staticd's NEXTHOP_REGISTER with the same prefix
/// produces a NEXTHOP_UPDATE whose registered-prefix region mirrors the
/// register framing (family u16 + plen + full address). SPEC-side check.
#[test]
fn nexthop_update_registered_prefix_mirrors_register_framing() {
    use common::IpPrefix;
    use zapi::ZapiNexthopUpdate;

    let reg: IpPrefix = "192.0.2.1/32".parse().unwrap();
    let update = ZapiNexthopUpdate::unresolved(reg, 1);
    let msg = ZapiMessage::NexthopUpdate(update);
    let mut buf = BytesMut::new();
    msg.encode_body(&mut buf).expect("encodes");
    let wire = buf.to_vec();
    // The registered prefix sits after message(u32)+safi(u16): offset 6.
    // Its framing must equal the fixture register's tail `0002 20 c0000201`.
    assert_eq!(&wire[6..13], &unhex("000220c0000201"));
    // And the decoded update round-trips.
    assert_eq!(
        ZapiMessage::decode(23, &wire).unwrap(),
        msg,
        "nexthop update round-trip"
    );
}

/// Interface-address adds (zebra→client) for the fixture prefixes encode
/// with the PSIZE-independent full-length address framing. SPEC-side check
/// exercising the encode path Z3 will use.
#[test]
fn interface_address_encode_shape() {
    let msg = ZapiMessage::InterfaceAddressAdd(ZapiInterfaceAddress {
        ifindex: 2,
        flags: 0,
        address: "203.0.113.1/24".parse().unwrap(),
        destination: None,
    });
    let mut buf = BytesMut::new();
    msg.encode_body(&mut buf).expect("encodes");
    // ifindex u32, flags u8, family u8(2), 4B address, plen u8(24), 4B zeros.
    assert_eq!(buf.to_vec(), unhex("000000020002cb0071011800000000"));
    assert_eq!(ZapiMessage::decode(2, &buf).unwrap(), msg);
}
