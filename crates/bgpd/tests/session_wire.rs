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
        daemon
            .run(sink, out_rib, stop_rx, refresh_rx)
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
