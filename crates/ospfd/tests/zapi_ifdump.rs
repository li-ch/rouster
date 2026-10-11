//! ADD-C2 end-to-end: ospfd's interface dump over a REAL `zapi::serve`
//! Unix socket — the z5-family convention (the same shape as
//! rousterd's `zapi_rib_loop` harness): a real server encoding the
//! dump frames, a real `ZapiClient` decoding them, a mini driver
//! answering `RibCommand`s from a canned interface mirror, then the
//! merge and daemon construction on the merged config.

use std::path::PathBuf;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Mutex;

use common::{IpPrefix, LinkFlags};
use tokio::sync::mpsc;
use zapi::{InterfaceMirror, RibCommand, SessionPush, ZapiClient};

use ospfd::config;
use ospfd::daemon::Ospfd;
use ospfd::ifdump;

fn temp_socket(tag: &str) -> PathBuf {
    static COUNTER: AtomicU32 = AtomicU32::new(0);
    let n = COUNTER.fetch_add(1, Ordering::SeqCst);
    std::env::temp_dir().join(format!(
        "ospfd-ifdump-{tag}-{}-{n}.sock",
        std::process::id()
    ))
}

/// Push senders from `AttachSession` commands, held for the test's
/// lifetime (dropping one would close its session's push channel —
/// the rousterd test harness's rule).
static PUSH_SENDERS: Mutex<Vec<mpsc::Sender<SessionPush>>> = Mutex::new(Vec::new());

/// The canned interface mirror the mini driver dumps: an up broadcast
/// eth0 (v4 primary + v6), a DOWN eth1 with an address, and nothing
/// for a third statically-configured interface.
fn mirror() -> Vec<InterfaceMirror> {
    vec![
        InterfaceMirror {
            ifindex: 2,
            name: "eth0".to_string(),
            is_up: true,
            vrf_id: 0,
            master_ifindex: None,
            flags: LinkFlags::up_broadcast(),
            addresses: vec![
                "10.0.0.1/24".parse::<IpPrefix>().unwrap(),
                "fe80::1/64".parse::<IpPrefix>().unwrap(),
            ],
        },
        InterfaceMirror {
            ifindex: 3,
            name: "eth1".to_string(),
            is_up: false,
            vrf_id: 0,
            master_ifindex: None,
            flags: LinkFlags::default(),
            addresses: vec!["10.0.1.1/30".parse::<IpPrefix>().unwrap()],
        },
    ]
}

/// Mini main-loop: answers exactly `n` commands the way rousterd's
/// driver does for this flow (attach, establish, the dump request,
/// the marker register, its unregister). Awaiting each command yields,
/// so the session task runs deterministically between applies (the
/// rousterd harness's rule).
async fn drive_n(rx: &mut mpsc::Receiver<RibCommand>, mirror: &[InterfaceMirror], n: usize) {
    for _ in 0..n {
        let command = rx.recv().await.expect("command arrives");
        match command {
            RibCommand::AttachSession { push, .. } => {
                PUSH_SENDERS.lock().unwrap().push(push);
            }
            RibCommand::SessionEstablished { .. } => {}
            RibCommand::RequestInterfaces { reply } => {
                let _ = reply.send(mirror.to_vec());
            }
            // The marker's answer: unresolved is fine — the sync only
            // needs the frame as the dump-end delimiter.
            RibCommand::RegisterNexthop { reply, .. } => {
                let _ = reply.send(None);
            }
            RibCommand::UnregisterNexthop { .. } => {}
            other => panic!("unexpected command for this flow: {other:?}"),
        }
    }
}

/// The full ADD-C2 startup path minus the process: serve, connect,
/// HELLO + dump request + marker, collect, merge, construct.
#[tokio::test]
async fn interface_dump_over_real_socket_feeds_the_daemon() {
    let path = temp_socket("e2e");
    let (tx, mut rx) = mpsc::channel(16);
    let server_path = path.clone();
    let server = tokio::spawn(async move {
        zapi::serve(&server_path, tx).await.expect("serve binds");
    });

    // The client connects once the listener is up (bounded yield-retry).
    let mut client = None;
    for _ in 0..100 {
        match ZapiClient::connect(&path).await {
            Ok(c) => {
                client = Some(c);
                break;
            }
            Err(_) => tokio::task::yield_now().await,
        }
    }
    let mut client = client.expect("server accepts the connection");

    // The five commands this session produces, driven concurrently
    // with the sync (the register reply unblocks the marker wait).
    let mirror = mirror();
    let driver = tokio::spawn(async move { drive_n(&mut rx, &mirror, 5).await });

    let dump = ifdump::sync(&mut client).await.expect("dump syncs");
    driver.await.expect("driver finished");

    // The dump reflects the mirror through the REAL wire encode/decode.
    assert_eq!(dump.len(), 2);
    let eth0 = dump.get("eth0").expect("eth0 dumped");
    assert!(eth0.operative);
    assert_eq!(eth0.ifindex, 2);
    assert_eq!(
        eth0.addresses.iter().map(|a| a.prefix).collect::<Vec<_>>(),
        vec![
            "10.0.0.1/24".parse::<IpPrefix>().unwrap(),
            "fe80::1/64".parse::<IpPrefix>().unwrap(),
        ]
    );
    let eth1 = dump.get("eth1").expect("eth1 dumped");
    assert!(!eth1.operative, "the mirror's flags 0 word relays as down");

    // Merge with a config whose eth0 has NO static address (the whole
    // point), eth1 has one, and eth9 is unknown to the dump.
    let mut config = config::parse(
        "zapi socket placeholder\nrouter ospf\n router-id 1.2.3.4\n area 0.0.0.0\n  \
         interface eth0\n  interface eth1\n   address 192.0.2.9/24\n  \
         interface eth9\n   address 198.51.100.7/30\n",
    )
    .unwrap();
    let report = dump.merge_into(&mut config);
    assert_eq!(report.dynamic_address, 2);
    assert_eq!(report.static_fallback, 1);
    assert_eq!(report.down, 1);

    // The daemon constructs from the MERGED config: eth0 runs on the
    // dumped address (no static one existed), the dumped-down eth1
    // stays in Down, the unknown eth9 keeps its static config.
    let core = Ospfd::new(&config).expect("core constructs on the merged config");
    assert_eq!(core.interfaces[0].name, "eth0");
    assert_eq!(
        core.interfaces[0].addr,
        "10.0.0.1".parse::<std::net::Ipv4Addr>().unwrap()
    );
    assert_eq!(
        core.interfaces[0].mask,
        "255.255.255.0".parse::<std::net::Ipv4Addr>().unwrap()
    );
    assert_ne!(
        core.interfaces[0].fsm.state,
        ospfd::iface::InterfaceState::Down,
        "the operative interface fired InterfaceUp"
    );
    assert_eq!(
        core.interfaces[1].fsm.state,
        ospfd::iface::InterfaceState::Down,
        "the dumped-down interface stays Down"
    );
    assert_eq!(
        core.interfaces[2].addr,
        "198.51.100.7".parse::<std::net::Ipv4Addr>().unwrap(),
        "the not-dumped interface keeps its static address"
    );
    assert_ne!(
        core.interfaces[2].fsm.state,
        ospfd::iface::InterfaceState::Down,
        "the static-config interface fires InterfaceUp (v1 behavior)"
    );

    server.abort();
}

/// The dump sync tolerates an interface the config does not use (the
/// mirror may hold more interfaces than the OSPF config names) and a
/// config interface the mirror does not know — both directions of the
/// name join — over the same real socket.
#[tokio::test]
async fn dump_and_config_join_by_name_both_ways() {
    let path = temp_socket("join");
    let (tx, mut rx) = mpsc::channel(16);
    let server_path = path.clone();
    let server = tokio::spawn(async move {
        zapi::serve(&server_path, tx).await.expect("serve binds");
    });
    let mut client = None;
    for _ in 0..100 {
        match ZapiClient::connect(&path).await {
            Ok(c) => {
                client = Some(c);
                break;
            }
            Err(_) => tokio::task::yield_now().await,
        }
    }
    let mut client = client.expect("server accepts the connection");

    let driver = tokio::spawn(async move { drive_n(&mut rx, &mirror(), 5).await });
    let dump = ifdump::sync(&mut client).await.expect("dump syncs");
    driver.await.expect("driver finished");

    // A config naming only an unknown interface: full static fallback,
    // the dump's extra interface (eth1) simply unused.
    let mut config = config::parse(
        "router ospf\n router-id 9.9.9.9\n area 0.0.0.0\n  interface tun0\n   \
         address 203.0.113.1/32\n",
    )
    .unwrap();
    let report = dump.merge_into(&mut config);
    assert_eq!(report.dynamic_address, 0);
    assert_eq!(report.static_fallback, 1);
    assert_eq!(report.down, 0);
    assert_eq!(dump.len(), 2, "the dump itself still holds both");

    server.abort();
}
