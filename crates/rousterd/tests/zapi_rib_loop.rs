//! End-to-end ZAPI loop: a real `serve()` socket, a codec-speaking client,
//! and a driver that applies `RibCommand`s into a real `rib::Rib` and
//! reconciles against a mock dataplane — the same shape as rousterd's main
//! loop, without netlink (so it runs on any host).
//!
//! Z3B adds the event-driven direction: the `rousterd::driver::RibDriver`
//! tests below push NEXTHOP_UPDATE on dataplane-event resolution flips and
//! REDISTRIBUTE_ROUTE_ADD on best-route changes, unprompted, over the same
//! socket.

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
/// driver (route mutations + NHT/interface replies), exactly `n` of them,
/// awaiting each. The explicit count matters: every connection queues an
/// `AttachSession` first (Z3B), which without the count would end a
/// drain-style batch before the session's request lands — and a
/// reply-carrying command (NEXTHOP_REGISTER blocks its session) would
/// then deadlock against a client blocked on its reply. Awaiting each
/// command yields, so the session task runs deterministically between
/// applies.
async fn drive_n(rib: &mut Rib, rx: &mut mpsc::Receiver<RibCommand>, n: usize) -> bool {
    let mut changed = false;
    for _ in 0..n {
        let command = rx.recv().await.expect("command arrives");
        changed |= apply_command(rib, command);
    }
    changed
}

/// Push senders from `AttachSession` commands, kept alive for the test's
/// lifetime: this raw-RIB mini driver has no push consumer, and dropping
/// a sender would close its session's push channel.
static PUSH_SENDERS: Mutex<Vec<mpsc::Sender<zapi::SessionPush>>> = Mutex::new(Vec::new());

fn apply_command(rib: &mut Rib, command: RibCommand) -> bool {
    match command {
        RibCommand::AttachSession { push, .. } => {
            PUSH_SENDERS.lock().unwrap().push(push);
            false
        }
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
    // (blocking) yields to let it. Attach arrives first (Z3B), the route
    // second; the driver applies both, then reconciles.
    assert!(
        matches!(
            rx.recv().await.expect("attach"),
            RibCommand::AttachSession { .. }
        ),
        "every connection attaches its push channel first"
    );
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
    drive_n(&mut rib, &mut rx, 2).await; // attach + AddRoute
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
    drive_n(&mut rib, &mut rx, 2).await; // attach + register

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
    drive_n(&mut rib, &mut rx, 1).await; // the second register
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
    drive_n(&mut rib, &mut rx, 2).await; // attach + interface dump

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

// --- Event-driven pushes (Z3B): real serve() socket + real RibDriver ---

use rousterd::driver::RibDriver;
use zapi::{ZapiNexthop, ZapiNexthopUpdate, ZapiRedistribute};

/// The RibDriver twin of [`drive_n`]: applies exactly `n` commands,
/// awaiting each (same deadlock rationale — see drive_n).
async fn drive_driver_n(driver: &mut RibDriver, rx: &mut mpsc::Receiver<RibCommand>, n: usize) {
    for _ in 0..n {
        let command = rx.recv().await.expect("command arrives");
        driver.apply(command);
    }
}

fn nht_register(prefix: &str) -> ZapiMessage {
    ZapiMessage::NexthopRegister(ZapiNexthopRegister {
        connected: false,
        resolve_via_default: false,
        safi: 1,
        prefix: prefix.parse().unwrap(),
    })
}

/// The full Z3B NHT flow: register unresolved, then a dataplane event (the
/// covering address appears) flips the resolution and the update is pushed
/// to the client unprompted — over a real socket, through the real driver.
#[tokio::test]
async fn nht_flip_on_address_add_pushed_over_real_socket() {
    let socket = temp_socket("flip-up");
    let (mut rx, server) = spawn_server(&socket);
    let mut client = TestClient::connect(&socket).await;
    client.handshake().await;

    let mut driver = RibDriver::new();
    let _dp = MockDp::default();

    // Register with no mirror at all: answered unresolved.
    client.send(&nht_register("10.9.9.9/32")).await;
    drive_driver_n(&mut driver, &mut rx, 2).await; // attach + register
    let (header, body) = client.read_frame().await;
    assert_eq!(
        ZapiCommand::from_u16(header.command),
        ZapiCommand::NexthopUpdate
    );
    assert!(!ZapiNexthopUpdate::decode(&body).unwrap().is_resolved());

    // The dataplane grows the covering subnet (exactly what the main
    // loop's next_event arm feeds the driver).
    driver.apply_event(&DataplaneEvent::LinkNew {
        ifindex: 2,
        name: "eth2".to_string(),
        is_up: true,
    });
    driver.apply_event(&DataplaneEvent::AddressNew {
        ifindex: 2,
        prefix: "10.9.9.1/24".parse().unwrap(),
    });

    // The flip arrives on its own — no request in flight.
    let (header, body) = client.read_frame().await;
    assert_eq!(
        ZapiCommand::from_u16(header.command),
        ZapiCommand::NexthopUpdate
    );
    let update = ZapiNexthopUpdate::decode(&body).unwrap();
    assert!(update.is_resolved());
    assert_eq!(update.registered_prefix, "10.9.9.9/32".parse().unwrap());
    assert_eq!(update.nexthops.len(), 1);
    assert_eq!(update.nexthops[0].nh_type, zapi::nexthop_type::IPV4_IFINDEX);
    assert_eq!(update.nexthops[0].ifindex, 2);
    assert_eq!(
        update.nexthops[0].gate,
        Some(IpAddr::V4("10.9.9.9".parse().unwrap()))
    );

    server.abort();
    let _ = std::fs::remove_file(&socket);
}

/// The other flip direction: link down unresolves a gateway that was
/// answered resolved, and the client is told.
#[tokio::test]
async fn nht_flip_on_link_down_pushed_over_real_socket() {
    let socket = temp_socket("flip-down");
    let (mut rx, server) = spawn_server(&socket);
    let mut client = TestClient::connect(&socket).await;
    client.handshake().await;

    // Mirror first: the register is answered resolved.
    let mut driver = RibDriver::new();
    let _dp = MockDp::default();
    driver.apply_event(&DataplaneEvent::LinkNew {
        ifindex: 3,
        name: "eth3".to_string(),
        is_up: true,
    });
    driver.apply_event(&DataplaneEvent::AddressNew {
        ifindex: 3,
        prefix: "192.0.2.1/24".parse().unwrap(),
    });

    client.send(&nht_register("192.0.2.9/32")).await;
    drive_driver_n(&mut driver, &mut rx, 2).await; // attach + register
    let (header, body) = client.read_frame().await;
    assert_eq!(
        ZapiCommand::from_u16(header.command),
        ZapiCommand::NexthopUpdate
    );
    let update = ZapiNexthopUpdate::decode(&body).unwrap();
    assert!(update.is_resolved());
    assert_eq!(update.nexthops[0].ifindex, 3);

    // The link goes down: the gateway unresolves, the client is pushed the
    // zeroed-tail form.
    driver.apply_event(&DataplaneEvent::LinkNew {
        ifindex: 3,
        name: "eth3".to_string(),
        is_up: false,
    });
    let (header, body) = client.read_frame().await;
    assert_eq!(
        ZapiCommand::from_u16(header.command),
        ZapiCommand::NexthopUpdate
    );
    let update = ZapiNexthopUpdate::decode(&body).unwrap();
    assert!(!update.is_resolved());
    assert_eq!(update.registered_prefix, "192.0.2.9/32".parse().unwrap());

    server.abort();
    let _ = std::fs::remove_file(&socket);
}

/// The redistribute flow in the FRR shape: bgpd registers REDISTRIBUTE
/// static; staticd installs a static route; the best-route change pushes
/// REDISTRIBUTE_ROUTE_ADD to bgpd (and only bgpd), with the gateway hop
/// in resolved (ifindex-carrying) form.
#[tokio::test]
async fn redistribute_route_add_pushed_over_real_socket() {
    let socket = temp_socket("redist");
    let (mut rx, server) = spawn_server(&socket);
    let mut bgpd = TestClient::connect(&socket).await;
    bgpd.handshake().await;
    let mut staticd = TestClient::connect(&socket).await;
    staticd.handshake().await;

    let mut driver = RibDriver::new();
    let dp = MockDp::default();

    // bgpd wants static routes redistributed.
    bgpd.send(&ZapiMessage::RedistributeAdd(ZapiRedistribute {
        afi: 1,
        route_type: route_type::STATIC,
        instance: 0,
    }))
    .await;

    // The subnet that will carry staticd's gateway.
    driver.apply_event(&DataplaneEvent::LinkNew {
        ifindex: 2,
        name: "eth2".to_string(),
        is_up: true,
    });
    driver.apply_event(&DataplaneEvent::AddressNew {
        ifindex: 2,
        prefix: "203.0.113.1/24".parse().unwrap(),
    });

    // staticd installs a static route with a gateway on that subnet.
    staticd
        .send(&ZapiMessage::RouteAdd(ZapiRoute {
            route_type: route_type::STATIC,
            instance: 0,
            flags: 0x41,
            message: message_flag::NEXTHOP | message_flag::DISTANCE,
            safi: 1,
            prefix: "198.51.100.0/24".parse().unwrap(),
            src_prefix: None,
            nhg_id: 0,
            nexthops: vec![ZapiNexthop::new_ipv4(0, "203.0.113.9".parse().unwrap())],
            backup_nexthops: Vec::new(),
            distance: Some(1),
            metric: None,
            tag: None,
            mtu: None,
            tableid: None,
            opaque: None,
        }))
        .await;
    // attach(bgpd) + attach(staticd) + redistribute(bgpd) + route(staticd).
    drive_driver_n(&mut driver, &mut rx, 4).await;
    driver.rib.reconcile(&dp).await;

    // The route was programmed (resolved through the mirror)...
    assert_eq!(dp.installed().len(), 1);
    assert_eq!(
        dp.installed()[0].prefix,
        "198.51.100.0/24".parse::<IpPrefix>().unwrap()
    );

    // ...and bgpd — which asked for it — gets the push, unprompted.
    let (header, body) = bgpd.read_frame().await;
    assert_eq!(header.command, 31, "ZEBRA_REDISTRIBUTE_ROUTE_ADD");
    match ZapiMessage::decode(31, &body).unwrap() {
        ZapiMessage::RedistributeRouteAdd(route) => {
            assert_eq!(route.route_type, route_type::STATIC);
            assert_eq!(route.flags, 0x08, "ZEBRA_FLAG_SELECTED");
            assert_eq!(route.prefix, "198.51.100.0/24".parse().unwrap());
            assert_eq!(route.distance, Some(1));
            assert_eq!(route.nexthops.len(), 1);
            assert_eq!(route.nexthops[0].nh_type, zapi::nexthop_type::IPV4_IFINDEX);
            assert_eq!(
                route.nexthops[0].ifindex, 2,
                "gateway resolved for the push"
            );
            assert_eq!(
                route.nexthops[0].gate,
                Some(IpAddr::V4("203.0.113.9".parse().unwrap()))
            );
        }
        other => panic!("expected RedistributeRouteAdd, got {other:?}"),
    }

    server.abort();
    let _ = std::fs::remove_file(&socket);
}
