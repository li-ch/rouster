//! The bfdd zapi edge over a REAL unix socket (the savd integration
//! recipe): a mock rousterd accepts the daemon's connection, reads the
//! pinned connect burst, forwards a REGISTER (27) for a loopback
//! destination, and receives the transition reports back — including
//! the 25-byte UP frame byte-for-byte (the Phase C pin).

use std::path::PathBuf;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::Duration;

use bfdd::daemon::{parse_bfdd_config, BfddDaemon};
use bfdd::zapi::{spawn_zapi_edge, ZapiEdgeEvent};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::mpsc;
use zapi::{
    bfd_status, ZapiBfdDestStatus, ZapiBfdSessionCmd, ZapiCommand, ZapiHeader, ZapiMessage,
    ZAPI_HEADER_LEN,
};

/// One daemon per host: the shared 3784 listener bind (the daemon
/// test-module constraint, made visible for this integration test).
static DAEMON_TEST_LOCK: std::sync::LazyLock<tokio::sync::Mutex<()>> =
    std::sync::LazyLock::new(|| tokio::sync::Mutex::new(()));

fn temp_socket(tag: &str) -> PathBuf {
    static COUNTER: AtomicU32 = AtomicU32::new(0);
    let n = COUNTER.fetch_add(1, Ordering::SeqCst);
    std::env::temp_dir().join(format!(
        "rouster-bfdd-zapi-edge-{tag}-{}-{n}.sock",
        std::process::id()
    ))
}

/// Reads one framed message off the mock's side.
async fn read_frame(io: &mut UnixStream) -> (ZapiHeader, Vec<u8>) {
    let mut header_buf = [0u8; ZAPI_HEADER_LEN];
    io.read_exact(&mut header_buf).await.expect("header");
    let header = ZapiHeader::decode(&header_buf).expect("header decodes");
    let mut body = vec![0u8; header.length as usize - ZAPI_HEADER_LEN];
    io.read_exact(&mut body).await.expect("body");
    (header, body)
}

async fn write_frame(io: &mut UnixStream, msg: &ZapiMessage) {
    let frame = msg.encode_frame(0).expect("encode");
    io.write_all(&frame).await.expect("write");
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn single_hop_register(dst: &str, min_ms: u32) -> ZapiBfdSessionCmd {
    ZapiBfdSessionCmd {
        pid: 4242,
        dst: dst.parse().unwrap(),
        min_rx_ms: min_ms,
        min_tx_ms: min_ms,
        detection_multiplier: 3,
        mhop: false,
        src: "0.0.0.0".parse().unwrap(),
        hops: 1,
        ifname: None,
        cbit: false,
        profile: None,
    }
}

#[tokio::test]
async fn edge_serves_register_and_reports_transitions() {
    let _guard = DAEMON_TEST_LOCK.lock().await;
    let socket = temp_socket("edge");
    let listener = UnixListener::bind(&socket).expect("bind mock rousterd");

    // The daemon with the transition feed wired (the binary's shape):
    // one task owns the daemon and drains the edge events into
    // add/remove_dynamic_peer; the test drives the mock's side.
    let (status_tx, status_rx) = mpsc::channel(64);
    let mut edge = spawn_zapi_edge(socket.clone(), status_rx);
    let (daemon_ready_tx, daemon_ready_rx) = tokio::sync::oneshot::channel();
    let daemon_task = tokio::spawn(async move {
        let config = parse_bfdd_config("").expect("empty config");
        let mut daemon = BfddDaemon::spawn_with_status_feed(config, Some(status_tx))
            .await
            .expect("daemon spawns");
        daemon_ready_tx.send(()).expect("test waits");
        while let Some(event) = edge.events.recv().await {
            match event {
                ZapiEdgeEvent::Register(cmd) => daemon
                    .add_dynamic_peer(&cmd)
                    .await
                    .expect("dynamic session"),
                ZapiEdgeEvent::Deregister(cmd) => {
                    daemon.remove_dynamic_peer(cmd.dst, cmd.mhop).await
                }
            }
        }
        daemon.shutdown_all().await;
    });

    let (mut mock, _addr) = listener.accept().await.expect("mock accepts");
    daemon_ready_rx.await.expect("daemon ready");

    // 1. The connect burst: HELLO (redist 26 = ZEBRA_ROUTE_BFD), the
    //    empty INTERFACE_ADD, the 4-byte REPLAY.
    let (h, b) = read_frame(&mut mock).await;
    assert_eq!(ZapiCommand::from_u16(h.command), ZapiCommand::Hello);
    assert_eq!(b[0], 26, "redist_default = ZEBRA_ROUTE_BFD (the 1a pin)");
    assert_eq!(b.len(), 8);
    let (h, b) = read_frame(&mut mock).await;
    assert_eq!(ZapiCommand::from_u16(h.command), ZapiCommand::InterfaceAdd);
    assert!(b.is_empty(), "the registration-request form");
    let (h, b) = read_frame(&mut mock).await;
    assert_eq!(ZapiCommand::from_u16(h.command), ZapiCommand::BfdDestReplay);
    assert_eq!(b.len(), 4, "the pid-only replay form");
    let daemon_pid = u32::from_be_bytes(b.try_into().unwrap());

    // 2. Forward a REGISTER for a loopback destination (100 ms x3, the
    //    pinned single-hop shape).
    let cmd = single_hop_register("127.0.0.1", 100);
    write_frame(&mut mock, &ZapiMessage::BfdDestRegister(cmd.clone())).await;

    // 3. The dynamic session establishes with itself over loopback and
    //    every transition is reported — the DOWN report may or may not
    //    land before UP depending on scheduling; wait for UP.
    let deadline = tokio::time::Instant::now() + Duration::from_secs(30);
    let mut saw_up = false;
    let mut up_body = Vec::new();
    while !saw_up {
        let (h, b) = tokio::time::timeout_at(deadline, read_frame(&mut mock))
            .await
            .expect("a report arrives");
        assert_eq!(
            ZapiCommand::from_u16(h.command),
            ZapiCommand::BfdDestReplay,
            "transition reports ride command 30 (Phase C)"
        );
        assert_eq!(b.len(), 25, "pid + the 26 tuple");
        let reported_pid = u32::from_be_bytes(b[..4].try_into().unwrap());
        assert_eq!(reported_pid, daemon_pid, "the daemon's own pid");
        let status = ZapiBfdDestStatus::decode(&b[4..]).expect("the 26 tuple decodes");
        assert_eq!(status.dst.to_string(), "127.0.0.1/32");
        assert_eq!(status.ifindex, 0, "the Phase C bfdd-side value");
        if status.status == bfd_status::UP {
            saw_up = true;
            up_body = b;
        }
    }
    // The exact UP frame, byte-for-byte in the Phase C shape.
    assert_eq!(
        hex(&up_body),
        format!("{daemon_pid:08x}00000000027f000001200000000402000000002000"),
        "pid + ifindex 0 + dst 127.0.0.1/32 + UP(4) + wildcard src + cbit 0"
    );

    // 4. DEREGISTER: the session gets the graceful RFC 5882 §8 hold
    //    (AdminDown held one Detection Time = 300 ms here) and the
    //    final report carries ADMIN_DOWN.
    write_frame(&mut mock, &ZapiMessage::BfdDestDeregister(cmd)).await;
    let deadline = tokio::time::Instant::now() + Duration::from_secs(30);
    let mut saw_admin_down = false;
    while !saw_admin_down {
        let (h, b) = tokio::time::timeout_at(deadline, read_frame(&mut mock))
            .await
            .expect("a report arrives");
        assert_eq!(ZapiCommand::from_u16(h.command), ZapiCommand::BfdDestReplay);
        let status = ZapiBfdDestStatus::decode(&b[4..]).expect("decodes");
        if status.status == bfd_status::ADMIN_DOWN {
            saw_admin_down = true;
        }
    }

    drop(mock);
    daemon_task.abort();
    let _ = std::fs::remove_file(&socket);
}
