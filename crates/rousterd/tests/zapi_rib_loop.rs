//! End-to-end ZAPI loop: a real `serve()` socket, a codec-speaking client,
//! and a driver that applies `RibCommand`s into a real `rib::Rib` and
//! reconciles against a mock dataplane — the same shape as rousterd's main
//! loop, without netlink (so it runs on any host).

use std::future::Future;
use std::net::IpAddr;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Mutex;

use common::{
    Dataplane, DataplaneError, DataplaneEvent, IpPrefix, Nexthop, RouteEntry, RouteProtocol,
};
use rib::Rib;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixStream;
use tokio::sync::mpsc;
use zapi::{
    blackhole_type, message_flag, route_type, InterfaceMirror, RibCommand, ZapiCommand, ZapiHeader,
    ZapiHello, ZapiMessage, ZapiNexthopRegister, ZapiRoute, ZAPI_HEADER_LEN,
};

/// Dataplane mock that records installs and withdrawals (same shape as the
/// rib crate's tests; its futures are always Ready).
#[derive(Default)]
struct MockDp {
    installed: Mutex<Vec<RouteEntry>>,
    removed: Mutex<Vec<RouteEntry>>,
}

impl MockDp {
    fn installed(&self) -> Vec<RouteEntry> {
        self.installed.lock().unwrap().clone()
    }

    fn removed(&self) -> Vec<RouteEntry> {
        self.removed.lock().unwrap().clone()
    }
}

impl Dataplane for MockDp {
    fn route_replace(
        &self,
        entry: &RouteEntry,
    ) -> impl Future<Output = Result<(), DataplaneError>> + Send {
        self.installed.lock().unwrap().push(entry.clone());
        std::future::ready(Ok(()))
    }

    fn route_delete(
        &self,
        entry: &RouteEntry,
    ) -> impl Future<Output = Result<(), DataplaneError>> + Send {
        self.removed.lock().unwrap().push(entry.clone());
        std::future::ready(Ok(()))
    }
}

fn temp_socket(tag: &str) -> PathBuf {
    static COUNTER: AtomicU32 = AtomicU32::new(0);
    let n = COUNTER.fetch_add(1, Ordering::SeqCst);
    std::env::temp_dir().join(format!(
        "rousterd-rib-loop-{tag}-{}-{n}.sock",
        std::process::id()
    ))
}

/// The staticd ROUTE_ADD fixture (203.0.113.0/24 reject-blackhole).
fn staticd_route_add() -> ZapiMessage {
    ZapiMessage::RouteAdd(ZapiRoute {
        route_type: route_type::STATIC,
        instance: 0,
        flags: 0x41,
        message: message_flag::NEXTHOP | message_flag::DISTANCE,
        safi: 1,
        prefix: "203.0.113.0/24".parse().unwrap(),
        src_prefix: None,
        nhg_id: 0,
        nexthops: vec![zapi::ZapiNexthop::new_blackhole(0, blackhole_type::REJECT)],
        backup_nexthops: Vec::new(),
        distance: Some(1),
        metric: None,
        tag: None,
        mtu: None,
        tableid: None,
        opaque: None,
    })
}

fn staticd_route_delete() -> ZapiMessage {
    ZapiMessage::RouteDelete(ZapiRoute {
        route_type: route_type::STATIC,
        instance: 0,
        flags: 0x41,
        message: message_flag::NEXTHOP | message_flag::DISTANCE,
        safi: 1,
        prefix: "203.0.113.0/24".parse().unwrap(),
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
    })
}

/// Mini main-loop: applies commands to the RIB exactly like rousterd's
/// `apply_rib_command` (route mutations + NHT/interface replies). Blocks
/// for the first command (the session task needs scheduling before it
/// exists), then drains whatever else is ready.
async fn drive(rib: &mut Rib, rx: &mut mpsc::Receiver<RibCommand>) -> bool {
    let mut changed = false;
    let first = rx.recv().await.expect("at least one command");
    changed |= apply_command(rib, first);
    while let Ok(command) = rx.try_recv() {
        changed |= apply_command(rib, command);
    }
    changed
}

fn apply_command(rib: &mut Rib, command: RibCommand) -> bool {
    match command {
        RibCommand::AddRoute(entry) => {
            rib.add_route(entry);
            true
        }
        RibCommand::DeleteRoute {
            table,
            prefix,
            protocol,
        } => rib.table_mut(table).remove(&prefix, protocol),
        RibCommand::RegisterNexthop { prefix, reply, .. } => {
            let _ = reply.send(rib.lookup_nexthop(prefix_addr(&prefix)));
            false
        }
        RibCommand::UnregisterNexthop { .. } => false,
        RibCommand::RegisterRedistribute { .. } | RibCommand::UnregisterRedistribute { .. } => {
            false
        }
        RibCommand::RequestInterfaces { reply } => {
            let mirror: Vec<InterfaceMirror> = rib
                .interfaces()
                .iter()
                .map(|(&ifindex, iface)| InterfaceMirror {
                    ifindex,
                    name: iface.name.clone(),
                    is_up: iface.is_up,
                    addresses: iface.addresses.clone(),
                })
                .collect();
            let _ = reply.send(mirror);
            false
        }
    }
}

fn prefix_addr(prefix: &IpPrefix) -> IpAddr {
    match prefix {
        IpPrefix::V4(p) => IpAddr::V4(p.addr()),
        IpPrefix::V6(p) => IpAddr::V6(p.addr()),
    }
}

/// Test client: connect, handshake, exchange framed messages.
struct TestClient {
    io: UnixStream,
}

impl TestClient {
    async fn connect(path: &std::path::Path) -> Self {
        for _ in 0..10 {
            match UnixStream::connect(path).await {
                Ok(io) => return Self { io },
                Err(_) => tokio::task::yield_now().await,
            }
        }
        panic!("could not connect to {}", path.display());
    }

    async fn handshake(&mut self) {
        let hello = ZapiMessage::Hello(ZapiHello {
            redist_default: 4,
            instance: 0,
            session_id: 0,
            synchronous: 0,
        });
        let frame = hello.encode_frame(0).unwrap();
        self.io.write_all(&frame).await.expect("send hello");
        let (header, _) = self.read_frame().await;
        assert_eq!(ZapiCommand::from_u16(header.command), ZapiCommand::Hello);
    }

    async fn send(&mut self, msg: &ZapiMessage) {
        let frame = msg.encode_frame(0).unwrap();
        self.io.write_all(&frame).await.expect("send");
    }

    async fn read_frame(&mut self) -> (ZapiHeader, Vec<u8>) {
        let mut header_buf = [0u8; ZAPI_HEADER_LEN];
        self.io.read_exact(&mut header_buf).await.expect("header");
        let header = ZapiHeader::decode(&header_buf).unwrap();
        let mut body = vec![0u8; header.length as usize - ZAPI_HEADER_LEN];
        self.io.read_exact(&mut body).await.expect("body");
        (header, body)
    }
}

/// Serves on `path` and returns the command receiver plus the server task.
fn spawn_server(
    path: &std::path::Path,
) -> (mpsc::Receiver<RibCommand>, tokio::task::JoinHandle<()>) {
    let (tx, rx) = mpsc::channel(16);
    let path = path.to_path_buf();
    let server = tokio::spawn(async move {
        zapi::serve(&path, tx).await.expect("serve binds");
    });
    (rx, server)
}

#[tokio::test]
async fn route_add_from_zapi_programs_mock_dataplane() {
    let socket = temp_socket("add");
    let (mut rx, server) = spawn_server(&socket);
    let mut client = TestClient::connect(&socket).await;
    client.handshake().await;

    client.send(&staticd_route_add()).await;
    // The command crosses the channel once the session task runs; recv()
    // (blocking) yields to let it, then the driver applies + reconciles.
    let command = rx.recv().await.expect("AddRoute arrives");
    let mut rib = Rib::new();
    let dp = MockDp::default();
    match command {
        RibCommand::AddRoute(entry) => rib.add_route(entry),
        other => panic!("expected AddRoute, got {other:?}"),
    }
    rib.reconcile(&dp).await;

    // The mapped entry, exactly: static /24 blackhole in table 254.
    assert_eq!(dp.installed().len(), 1);
    let entry = &dp.installed()[0];
    assert_eq!(entry.prefix, "203.0.113.0/24".parse::<IpPrefix>().unwrap());
    assert_eq!(entry.protocol, RouteProtocol::Static);
    assert_eq!(entry.table, 254);
    assert_eq!(entry.nexthops.hops(), &[(Nexthop::Blackhole, 1)]);
    assert!(dp.removed().is_empty());

    server.abort();
    let _ = std::fs::remove_file(&socket);
}

#[tokio::test]
async fn route_delete_from_zapi_withdraws_from_mock_dataplane() {
    let socket = temp_socket("del");
    let (mut rx, server) = spawn_server(&socket);
    let mut client = TestClient::connect(&socket).await;
    client.handshake().await;

    let mut rib = Rib::new();
    let dp = MockDp::default();

    client.send(&staticd_route_add()).await;
    match rx.recv().await.expect("AddRoute") {
        RibCommand::AddRoute(entry) => rib.add_route(entry),
        other => panic!("expected AddRoute, got {other:?}"),
    }
    rib.reconcile(&dp).await;
    assert_eq!(dp.installed().len(), 1);

    client.send(&staticd_route_delete()).await;
    match rx.recv().await.expect("DeleteRoute") {
        RibCommand::DeleteRoute {
            table,
            prefix,
            protocol,
        } => {
            assert!(rib.table_mut(table).remove(&prefix, protocol));
        }
        other => panic!("expected DeleteRoute, got {other:?}"),
    }
    rib.reconcile(&dp).await;

    assert_eq!(dp.removed().len(), 1, "withdrawn after the delete");
    assert_eq!(
        dp.removed()[0].prefix,
        "203.0.113.0/24".parse::<IpPrefix>().unwrap()
    );

    server.abort();
    let _ = std::fs::remove_file(&socket);
}

/// The full NHT path against the REAL resolver: a gateway on a connected
/// (mirrored) subnet is answered resolved with its ifindex, end to end.
#[tokio::test]
async fn nht_register_resolved_through_real_rib() {
    let socket = temp_socket("nht");
    let (mut rx, server) = spawn_server(&socket);
    let mut client = TestClient::connect(&socket).await;
    client.handshake().await;

    // Interface mirror: eth2 (ifindex 2) up with 192.0.2.1/24.
    let mut rib = Rib::new();
    rib.apply_event(&DataplaneEvent::LinkNew {
        ifindex: 2,
        name: "eth2".to_string(),
        is_up: true,
    });
    rib.apply_event(&DataplaneEvent::AddressNew {
        ifindex: 2,
        prefix: "192.0.2.1/24".parse().unwrap(),
    });

    // staticd's NEXTHOP_REGISTER for its gateway on that subnet.
    client
        .send(&ZapiMessage::NexthopRegister(ZapiNexthopRegister {
            connected: false,
            resolve_via_default: false,
            safi: 1,
            prefix: "192.0.2.9/32".parse().unwrap(),
        }))
        .await;
    drive(&mut rib, &mut rx).await;

    let (header, body) = client.read_frame().await;
    assert_eq!(
        ZapiCommand::from_u16(header.command),
        ZapiCommand::NexthopUpdate
    );
    let update = zapi::ZapiNexthopUpdate::decode(&body).unwrap();
    assert!(update.is_resolved());
    assert_eq!(update.nexthops.len(), 1);
    assert_eq!(update.nexthops[0].nh_type, zapi::nexthop_type::IPV4_IFINDEX);
    assert_eq!(update.nexthops[0].ifindex, 2, "resolved via eth2");

    // And the unresolved complement: an off-subnet gateway gets the
    // zeroed-tail form.
    client
        .send(&ZapiMessage::NexthopRegister(ZapiNexthopRegister {
            connected: false,
            resolve_via_default: false,
            safi: 1,
            prefix: "198.51.100.9/32".parse().unwrap(),
        }))
        .await;
    drive(&mut rib, &mut rx).await;
    let (header, body) = client.read_frame().await;
    assert_eq!(
        ZapiCommand::from_u16(header.command),
        ZapiCommand::NexthopUpdate
    );
    let update = zapi::ZapiNexthopUpdate::decode(&body).unwrap();
    assert!(!update.is_resolved(), "off-subnet gateway stays unresolved");

    server.abort();
    let _ = std::fs::remove_file(&socket);
}

/// INTERFACE_ADD requests are answered from the RIB's interface mirror —
/// through the real serve() socket.
#[tokio::test]
async fn interface_dump_answered_from_rib_mirror() {
    let socket = temp_socket("iface");
    let (mut rx, server) = spawn_server(&socket);
    let mut client = TestClient::connect(&socket).await;
    client.handshake().await;

    let mut rib = Rib::new();
    rib.apply_event(&DataplaneEvent::LinkNew {
        ifindex: 7,
        name: "eth7".to_string(),
        is_up: true,
    });
    rib.apply_event(&DataplaneEvent::AddressNew {
        ifindex: 7,
        prefix: "198.51.100.1/25".parse().unwrap(),
    });

    client.send(&ZapiMessage::InterfaceAddRequest).await;
    drive(&mut rib, &mut rx).await;

    let (h1, b1) = client.read_frame().await;
    assert_eq!(ZapiCommand::from_u16(h1.command), ZapiCommand::InterfaceAdd);
    let intf = zapi::ZapiInterface::decode(&b1).unwrap();
    assert_eq!(intf.ifname, "eth7");
    assert_eq!(intf.ifindex, 7);
    assert_eq!(intf.status, 1);

    let (h2, b2) = client.read_frame().await;
    assert_eq!(
        ZapiCommand::from_u16(h2.command),
        ZapiCommand::InterfaceAddressAdd
    );
    let addr = zapi::ZapiInterfaceAddress::decode(&b2).unwrap();
    assert_eq!(addr.address, "198.51.100.1/25".parse::<IpPrefix>().unwrap());
    assert_eq!(addr.ifindex, 7);

    server.abort();
    let _ = std::fs::remove_file(&socket);
}
