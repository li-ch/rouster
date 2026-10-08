//! Loopback integration: `serve()` on a real Unix-domain socket file, a
//! client speaking the Z2 codec, and a driver on the command channel —
//! the same shape as rousterd's main loop, without the netlink dataplane
//! (so it runs on any host).

use std::path::PathBuf;
use std::sync::atomic::{AtomicU32, Ordering};

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixStream;
use tokio::sync::mpsc;
use zapi::{RibCommand, ZapiCommand, ZapiHeader, ZapiHello, ZapiMessage, ZAPI_HEADER_LEN};

/// Unique socket path per call (tests share one process and temp dir).
fn temp_socket(tag: &str) -> PathBuf {
    static COUNTER: AtomicU32 = AtomicU32::new(0);
    let n = COUNTER.fetch_add(1, Ordering::SeqCst);
    std::env::temp_dir().join(format!(
        "rouster-zapi-loopback-{tag}-{}-{n}.sock",
        std::process::id()
    ))
}

/// Test client over a real Unix stream.
struct TestClient {
    io: UnixStream,
}

impl TestClient {
    async fn connect(path: &std::path::Path) -> Self {
        // serve() binds synchronously when its task first polls; awaiting
        // connect yields, so by then the listener exists. Retry a few
        // times anyway rather than sleeping on a timer.
        for _ in 0..10 {
            match UnixStream::connect(path).await {
                Ok(io) => return Self { io },
                Err(_) => tokio::task::yield_now().await,
            }
        }
        panic!("could not connect to {}", path.display());
    }

    async fn send(&mut self, msg: &ZapiMessage, vrf_id: u32) {
        let frame = msg.encode_frame(vrf_id).expect("encode");
        self.io.write_all(&frame).await.expect("send");
    }

    async fn read_frame(&mut self) -> (ZapiHeader, Vec<u8>) {
        let mut header_buf = [0u8; ZAPI_HEADER_LEN];
        self.io.read_exact(&mut header_buf).await.expect("header");
        let header = ZapiHeader::decode(&header_buf).expect("header decodes");
        let mut body = vec![0u8; header.length as usize - ZAPI_HEADER_LEN];
        self.io.read_exact(&mut body).await.expect("body");
        (header, body)
    }

    async fn handshake(&mut self) {
        self.send(
            &ZapiMessage::Hello(ZapiHello {
                redist_default: 4,
                instance: 0,
                session_id: 0,
                synchronous: 0,
            }),
            0,
        )
        .await;
        let (header, _) = self.read_frame().await;
        assert_eq!(ZapiCommand::from_u16(header.command), ZapiCommand::Hello);
    }
}

#[tokio::test]
async fn serve_answers_hello_on_real_socket() {
    let socket = temp_socket("hello");
    let (tx, mut rx) = mpsc::channel::<RibCommand>(16);
    let server = tokio::spawn({
        let socket = socket.clone();
        async move { zapi::serve(&socket, tx).await }
    });

    let mut client = TestClient::connect(&socket).await;
    client.handshake().await;

    server.abort();
    let _ = std::fs::remove_file(&socket);
    rx.close();
}

#[tokio::test]
async fn serve_replaces_stale_socket_file() {
    let socket = temp_socket("stale");
    std::fs::write(&socket, b"leftover garbage").expect("create stale file");
    let (tx, mut rx) = mpsc::channel::<RibCommand>(16);
    let server = tokio::spawn({
        let socket = socket.clone();
        async move { zapi::serve(&socket, tx).await }
    });

    // A client can connect and handshake: the stale file was replaced.
    let mut client = TestClient::connect(&socket).await;
    client.handshake().await;

    server.abort();
    let _ = std::fs::remove_file(&socket);
    rx.close();
}

/// Two simultaneous sessions (bgpd-style: one daemon, several zclient
/// connections) share the command queue; each gets a distinct owner id.
#[tokio::test]
async fn two_concurrent_sessions_share_one_command_queue() {
    let socket = temp_socket("two");
    let (tx, mut rx) = mpsc::channel::<RibCommand>(16);
    let server = tokio::spawn({
        let socket = socket.clone();
        async move { zapi::serve(&socket, tx).await }
    });

    let mut c1 = TestClient::connect(&socket).await;
    let mut c2 = TestClient::connect(&socket).await;
    c1.handshake().await;
    c2.handshake().await;

    // Each accepted connection attaches its push channel first (Z3B):
    // two attach commands carry the same distinct owner ids the session
    // commands below use. The senders are held so the sessions' push
    // channels stay open for the rest of the test.
    let mut attached = Vec::new();
    let mut _push_senders = Vec::new();
    for _ in 0..2 {
        match rx.recv().await.expect("attach command") {
            RibCommand::AttachSession { owner, push } => {
                attached.push(owner);
                _push_senders.push(push);
            }
            other => panic!("expected AttachSession, got {other:?}"),
        }
    }
    attached.sort_unstable();
    assert_eq!(attached, vec![1u64, 2], "one attach per accepted session");

    // Both sessions emit route adds; both arrive on the one queue, each
    // tagged with its session's owner id (1 and 2 in accept order).
    let route = ZapiMessage::RouteAdd(zapi::ZapiRoute {
        route_type: zapi::route_type::STATIC,
        instance: 0,
        flags: 0x41,
        message: zapi::message_flag::NEXTHOP | zapi::message_flag::DISTANCE,
        safi: 1,
        prefix: "203.0.113.0/24".parse().unwrap(),
        src_prefix: None,
        nhg_id: 0,
        nexthops: vec![zapi::ZapiNexthop::new_blackhole(
            0,
            zapi::blackhole_type::REJECT,
        )],
        backup_nexthops: Vec::new(),
        distance: Some(1),
        metric: None,
        tag: None,
        mtu: None,
        tableid: None,
        opaque: None,
    });
    c1.send(&route, 0).await;
    c2.send(&route, 0).await;

    // Both adds arrive on the one queue.
    for _ in 0..2 {
        match rx.recv().await.expect("command") {
            RibCommand::AddRoute(entry) => {
                assert_eq!(entry.prefix, "203.0.113.0/24".parse().unwrap());
                assert_eq!(entry.protocol, common::RouteProtocol::Static);
            }
            other => panic!("unexpected command {other:?}"),
        }
    }

    // The NHT registers that follow carry distinct owner ids (1 and 2,
    // accept order) — the serialization-disclosure's accountability hook.
    let register = ZapiMessage::NexthopRegister(zapi::ZapiNexthopRegister {
        connected: false,
        resolve_via_default: false,
        safi: 1,
        prefix: "192.0.2.1/32".parse().unwrap(),
    });
    c1.send(&register, 0).await;
    c2.send(&register, 0).await;
    let mut owners = Vec::new();
    for _ in 0..2 {
        match rx.recv().await.expect("register command") {
            RibCommand::RegisterNexthop { owner, reply, .. } => {
                owners.push(owner);
                let _ = reply.send(None);
            }
            other => panic!("unexpected command {other:?}"),
        }
    }
    owners.sort_unstable();
    assert_eq!(owners, vec![1u64, 2], "distinct owner ids per session");

    // Both clients get their unresolved NEXTHOP_UPDATE.
    let (h1, _) = c1.read_frame().await;
    assert_eq!(
        ZapiCommand::from_u16(h1.command),
        ZapiCommand::NexthopUpdate
    );
    let (h2, _) = c2.read_frame().await;
    assert_eq!(
        ZapiCommand::from_u16(h2.command),
        ZapiCommand::NexthopUpdate
    );

    server.abort();
    let _ = std::fs::remove_file(&socket);
    rx.close();
}
