//! Over-the-wire integration test (the z5-family convention, in
//! process): a real TCP listener, a real connect, the full BGP
//! exchange on the loopback socket — Established both sides, the
//! `network` line delivered, NOTIFICATION teardown observed.
//!
//! This is the gate before the container interop: the same wire
//! behavior FRR's bgpd will exercise, without docker.

use std::sync::{Arc, Mutex};
use std::time::Duration;

use bgpd::config::parse_config;
use bgpd::daemon::Daemon;
use bgpd::peer::{ConfiguredNetworks, RecordingSink, SharedSink};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::watch;

const CONFIG: &str = "\
router bgp 65000
 bgp router-id 10.0.0.1
 neighbor 127.0.0.1 remote-as 65001
 neighbor 127.0.0.1 passive
 network 203.0.113.0/24
";

/// Reads one BGP frame from a real socket.
async fn read_frame(sock: &mut tokio::net::TcpStream) -> Vec<u8> {
    let mut header = vec![0u8; 19];
    sock.read_exact(&mut header).await.unwrap();
    let len = u16::from_be_bytes([header[16], header[17]]) as usize;
    let mut body = vec![0u8; len - 19];
    sock.read_exact(&mut body).await.unwrap();
    header.extend_from_slice(&body);
    header
}

async fn write_frame(sock: &mut tokio::net::TcpStream, frame: &[u8]) {
    sock.write_all(frame).await.unwrap();
    sock.flush().await.unwrap();
}

/// Frames until one of `want` message types arrives (skipping
/// KEEPALIVEs), returning it decoded.
async fn until_message(sock: &mut tokio::net::TcpStream, want: u8) -> bgpd::message::BgpMessage {
    loop {
        let frame = read_frame(sock).await;
        let message = bgpd::message::BgpMessage::decode(&frame, true).unwrap();
        if message.message_type() == want {
            return message;
        }
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn two_speakers_over_tcp_reach_established_and_exchange_a_prefix() {
    let config = parse_config(CONFIG).unwrap();
    let sink = SharedSink(Arc::new(Mutex::new(RecordingSink::default())));
    let out_rib = Arc::new(ConfiguredNetworks::from_config(&config));

    let daemon = Daemon::bind(config).await.unwrap();
    let port = daemon.local_addr().unwrap().port();

    let (stop_tx, stop_rx) = watch::channel(false);
    let (_refresh_tx, refresh_rx) = watch::channel(0u64);
    let daemon_task = tokio::spawn(async move {
        let reach: Arc<dyn bgpd::zedge::PeerReachability> = Arc::new(bgpd::zedge::AlwaysReachable);
        daemon
            .run(sink, out_rib, stop_rx, refresh_rx, reach)
            .await
            .unwrap();
    });

    // The "other speaker": connects in (the passive path; the
    // connector will also dial us and lose the §6.8 first-wins race
    // or win it — either way exactly one session runs).
    let mut peer = tokio::time::timeout(
        Duration::from_secs(10),
        tokio::net::TcpStream::connect(("127.0.0.1", port)),
    )
    .await
    .unwrap()
    .unwrap();

    // Read our OPEN, answer with ours (AS 65001, hold 30, refresh +
    // AS4 capabilities like a real FRR peer).
    let open = until_message(&mut peer, 1).await;
    let their_open = match open {
        bgpd::message::BgpMessage::Open(o) => o,
        other => panic!("expected OPEN, got {other:?}"),
    };
    assert_eq!(their_open.peer_as4(), 65000);
    assert_eq!(
        their_open.bgp_id,
        "10.0.0.1".parse::<std::net::Ipv4Addr>().unwrap()
    );

    use bgpd::capability::Capability;
    let mine = bgpd::message::BgpMessage::Open(bgpd::message::BgpOpen::new(
        65001,
        30,
        "10.0.0.2".parse().unwrap(),
        vec![
            Capability::Multiprotocol { afi: 1, safi: 1 },
            Capability::RouteRefresh,
        ],
    ));
    write_frame(&mut peer, &mine.encode(true).unwrap()).await;

    // KEEPALIVE exchange (theirs arrives on Event 19, ours answers).
    let keepalive = until_message(&mut peer, 4).await;
    assert!(matches!(keepalive, bgpd::message::BgpMessage::Keepalive));
    write_frame(
        &mut peer,
        &bgpd::message::BgpMessage::Keepalive.encode(true).unwrap(),
    )
    .await;

    // Established: the network line arrives as an UPDATE with the
    // eBGP AS_PATH prepend and ORIGIN IGP.
    let update = until_message(&mut peer, 2).await;
    let update = match update {
        bgpd::message::BgpMessage::Update(u) => u,
        other => panic!("expected UPDATE, got {other:?}"),
    };
    assert_eq!(update.nlri, vec!["203.0.113.0/24".parse().unwrap()]);
    assert_eq!(update.as_path().unwrap().path_length(), 1);
    assert_eq!(update.origin(), Some(bgpd::attr::Origin::Igp));

    // Ask for a re-advertisement (RFC 2918): the refresh request is
    // answered by the same UPDATE again.
    write_frame(
        &mut peer,
        &bgpd::message::route_refresh(1, 1).encode(true).unwrap(),
    )
    .await;
    let again = until_message(&mut peer, 2).await;
    assert!(matches!(again, bgpd::message::BgpMessage::Update(_)));

    // Graceful shutdown: stop channel (= SIGTERM) → Cease observed.
    stop_tx.send(true).unwrap();
    let notification = until_message(&mut peer, 3).await;
    match notification {
        bgpd::message::BgpMessage::Notification(n) => {
            assert_eq!(n.code, 6, "Cease");
            assert_eq!(n.subcode, bgpd::error::cease_subcode::ADMIN_SHUTDOWN);
        }
        other => panic!("expected NOTIFICATION, got {other:?}"),
    }

    tokio::time::timeout(Duration::from_secs(10), daemon_task)
        .await
        .unwrap()
        .unwrap();
}

// ---- N5: route-server mode, two real sessions into one wiring ---
//
// Two RS clients (AS 65001 at 192.0.2.101, AS 65002 at
// 192.0.2.102) against the binary's own wiring (Loc-RIB with the
// RS-client set, RibSink, LocRibOut): client A's route must reach
// client B with A's own AS_PATH (no RS prepend), A's next hop
// preserved, MED intact — FRR `route-server-client` transparent mode
// (doc/user/routeserver.rst). The sessions are real PeerSessions
// over duplex pairs (the daemon's own session type); B establishes
// after A announced, matching the v1 Adj-RIB-Out shape (initial
// advertisement at Established).

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn route_server_reflects_between_clients_transparently() {
    use bgpd::attr::{AsPath, Origin, PathAttribute};
    use bgpd::fsm::SessionConfig;
    use bgpd::message::{BgpMessage, BgpOpen, BgpUpdate};
    use bgpd::peer::{OutRib, PeerInfo, PeerSession, SharedSink};
    use bgpd::rib::{LocRib, LocRibOut, RibSink};
    use std::net::{IpAddr, Ipv4Addr};

    async fn read_frame(io: &mut tokio::io::DuplexStream) -> Vec<u8> {
        let mut header = vec![0u8; 19];
        io.read_exact(&mut header).await.unwrap();
        let len = u16::from_be_bytes([header[16], header[17]]) as usize;
        let mut body = vec![0u8; len - 19];
        io.read_exact(&mut body).await.unwrap();
        header.extend_from_slice(&body);
        header
    }

    async fn write_frame(io: &mut tokio::io::DuplexStream, frame: &[u8]) {
        io.write_all(frame).await.unwrap();
        io.flush().await.unwrap();
    }

    async fn until(io: &mut tokio::io::DuplexStream, want: u8) -> bgpd::message::BgpMessage {
        loop {
            let frame = read_frame(io).await;
            let message = bgpd::message::BgpMessage::decode(&frame, true).unwrap();
            if message.message_type() == want {
                return message;
            }
        }
    }

    // The binary's route-server wiring.
    let loc_rib = Arc::new(Mutex::new(LocRib::new(65000)));
    loc_rib.lock().unwrap().set_route_server_clients(vec![
        "192.0.2.101".parse::<IpAddr>().unwrap(),
        "192.0.2.102".parse::<IpAddr>().unwrap(),
    ]);
    let sink = SharedSink(Arc::new(Mutex::new(RibSink::new(Arc::clone(&loc_rib)))));
    let out_rib: Arc<dyn OutRib> = Arc::new(LocRibOut::new(
        Arc::clone(&loc_rib),
        bgpd::peer::ConfiguredNetworks::new(65000, vec![]),
        Arc::new(bgpd::rib::AcceptAll),
    ));

    fn session(
        io: tokio::io::DuplexStream,
        addr: &str,
        remote_as: u32,
        out_rib: Arc<dyn OutRib>,
    ) -> PeerSession<tokio::io::DuplexStream> {
        PeerSession::new(
            io,
            SessionConfig::new(65000, Ipv4Addr::new(10, 0, 0, 1), 90),
            PeerInfo {
                address: addr.parse().unwrap(),
                remote_as,
                bgp_id: None,
            },
            "192.0.2.100".parse().unwrap(),
            Some(out_rib),
            std::time::Duration::ZERO,
        )
    }

    // Client A: handshake + announce 203.0.113.0/24 with MED 77 and
    // next hop 192.0.2.101.
    let (a_ours, mut a_io) = tokio::io::duplex(8192);
    let mut a_sess = session(a_ours, "192.0.2.101", 65001, Arc::clone(&out_rib));
    let mut a_sink = sink.clone();
    let a_driver = tokio::spawn(async move { a_sess.run(&mut a_sink).await });
    let _ = until(&mut a_io, 1).await;
    write_frame(
        &mut a_io,
        &BgpMessage::Open(BgpOpen::new(65001, 30, "10.1.1.1".parse().unwrap(), vec![]))
            .encode(true)
            .unwrap(),
    )
    .await;
    let _ = until(&mut a_io, 4).await;
    write_frame(&mut a_io, &BgpMessage::Keepalive.encode(true).unwrap()).await;
    write_frame(
        &mut a_io,
        &BgpMessage::Update(BgpUpdate {
            withdrawn: vec![],
            attrs: vec![
                PathAttribute::Origin(Origin::Igp),
                PathAttribute::AsPath(AsPath::sequence([65001])),
                PathAttribute::NextHop("192.0.2.101".parse().unwrap()),
                PathAttribute::Med(77),
            ],
            nlri: vec!["203.0.113.0/24".parse().unwrap()],
        })
        .encode(true)
        .unwrap(),
    )
    .await;

    // Client B establishes AFTER A announced: its initial dump must
    // carry A's route, transparently.
    let (b_ours, mut b_io) = tokio::io::duplex(8192);
    let mut b_sess = session(b_ours, "192.0.2.102", 65002, Arc::clone(&out_rib));
    let mut b_sink = sink.clone();
    let b_driver = tokio::spawn(async move { b_sess.run(&mut b_sink).await });
    let _ = until(&mut b_io, 1).await;
    write_frame(
        &mut b_io,
        &BgpMessage::Open(BgpOpen::new(65002, 30, "10.2.2.2".parse().unwrap(), vec![]))
            .encode(true)
            .unwrap(),
    )
    .await;
    let _ = until(&mut b_io, 4).await;
    write_frame(&mut b_io, &BgpMessage::Keepalive.encode(true).unwrap()).await;

    let update = until(&mut b_io, 2).await;
    let update = match update {
        BgpMessage::Update(u) => u,
        other => panic!("expected UPDATE, got {other:?}"),
    };
    assert_eq!(update.nlri, vec!["203.0.113.0/24".parse().unwrap()]);
    let path = update.as_path().unwrap();
    assert_eq!(path.path_length(), 1, "only client A's AS");
    assert!(
        !path
            .segments
            .iter()
            .any(|s| matches!(s, bgpd::attr::AsSegment::Sequence(v) if v.contains(&65000))),
        "the route server's AS is never prepended (transparent mode)"
    );
    assert_eq!(
        update.attr(3),
        Some(&PathAttribute::NextHop("192.0.2.101".parse().unwrap())),
        "client A's next hop preserved"
    );
    assert_eq!(
        update.attr(4),
        Some(&PathAttribute::Med(77)),
        "MED (IGP metric) preserved"
    );

    a_driver.abort();
    b_driver.abort();
}
