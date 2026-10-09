//! Z4 end-to-end: the staticd client logic against the REAL rousterd
//! core — a `zapi::serve` socket, the factored main loop
//! (`rousterd::driver::RibDriver`) over a mock dataplane — no netlink,
//! real Unix sockets, no timers.
//!
//! Proven here, causally (every wait is on a channel or a socket read,
//! never a sleep):
//! - HELLO exchange (client sees the echo),
//! - ROUTE_ADDs observed by the driver's RIB,
//! - NEXTHOP_UPDATE round-trip for the registered gateway (resolved,
//!   carrying the mock interface's ifindex) and the unresolved complement,
//! - resolution-filtered programming: the mock dataplane records
//!   `route_replace` ONLY for the gateway-resolvable route,
//! - withdrawal on reload: ROUTE_DELETEs (SIGHUP semantics via the
//!   `reload` function hook, not a signal) withdraw the programmed route.

use std::future::Future;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Mutex;

use common::{
    Dataplane, DataplaneError, DataplaneEvent, IpPrefix, Nexthop, RouteEntry, RouteProtocol,
};
use rousterd::driver::RibDriver;
use rousterd::staticd::StaticDaemon;
use tokio::sync::mpsc;
use zapi::{RibCommand, ZapiNexthopUpdate};

/// Dataplane mock that records installs and withdrawals (same shape as
/// the rib crate's and Z3 loop tests' mocks; futures always Ready).
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
    std::env::temp_dir().join(format!("rousterd-z4-{tag}-{}-{n}.sock", std::process::id()))
}

/// Serves on `path`; returns the command receiver and the server task.
fn spawn_server(
    path: &std::path::Path,
) -> (mpsc::Receiver<RibCommand>, tokio::task::JoinHandle<()>) {
    let (tx, rx) = mpsc::channel(256);
    let path = path.to_path_buf();
    let server = tokio::spawn(async move {
        zapi::serve(&path, tx).await.expect("serve binds");
    });
    (rx, server)
}

/// The config the staticd logic installs:
/// - 198.51.100.0/24 via 192.0.2.9 — on the mock interface's connected
///   subnet, so it IS programmable,
/// - 203.0.113.0/24 via 100.64.0.1 — off any connected subnet: held in
///   the RIB, never programmed (the resolution filter under test).
const CONFIG_TEXT: &str = "\
ip route 198.51.100.0/24 192.0.2.9
ip route 203.0.113.0/24 100.64.0.1
";

/// Runs the staticd initial load concurrently with the driver servicing
/// the command queue — the load's lock-step NHT reads REQUIRE the driver
/// to answer RegisterNexthop mid-flight, so neither future can run alone.
/// No timers: each iteration applies one received command, and the load's
/// own completion ends the loop.
async fn drive_initial_load(
    driver: &mut RibDriver,
    rx: &mut mpsc::Receiver<RibCommand>,
    dp: &MockDp,
    daemon_load: impl Future<Output = std::io::Result<()>>,
) -> std::io::Result<()> {
    let mut load = std::pin::pin!(daemon_load);
    loop {
        tokio::select! {
            result = &mut load => return result,
            Some(command) = rx.recv() => {
                driver.apply(command);
                let _ = driver.drain(rx, dp).await;
            }
        }
    }
}

#[tokio::test]
async fn staticd_e2e_install_nht_filter_and_withdrawal() {
    let socket = temp_socket("e2e");
    let _ = std::fs::remove_file(&socket);
    let (mut rx, server) = spawn_server(&socket);

    // rousterd core, in-process: the factored main loop + a mock
    // dataplane + the mirrored interface state that resolves 192.0.2.x
    // (what netlink would have told rousterd about eth2).
    let mut driver = RibDriver::new();
    let dp = MockDp::default();
    driver.rib.apply_event(&DataplaneEvent::LinkNew {
        ifindex: 2,
        name: "eth2".to_string(),
        is_up: true,
        vrf_table: None,
        master_ifindex: None,
    });
    driver.rib.apply_event(&DataplaneEvent::AddressNew {
        ifindex: 2,
        prefix: "192.0.2.1/24".parse().unwrap(),
    });

    // The staticd daemon logic, fed by the same parser rousterd uses.
    let config = rousterd::config::parse_config(CONFIG_TEXT).expect("config parses");
    assert_eq!(config.static_routes.len(), 2, "two routes in the config");

    let mut daemon = loop {
        match StaticDaemon::connect(&socket).await {
            Ok(daemon) => break daemon,
            Err(_) => tokio::task::yield_now().await,
        }
    };
    let routes = config.static_routes.clone();
    drive_initial_load(&mut driver, &mut rx, &dp, async {
        daemon.initial_load(&routes).await
    })
    .await
    .expect("initial load");

    // HELLO exchange: proven by initial_load returning at all (it returns
    // only after reading the echoed HELLO). ROUTE_ADDs observed: both
    // prefixes are candidates in the driver's RIB.
    let table = driver.rib.table(254).expect("main table");
    assert!(
        table
            .best(&"198.51.100.0/24".parse::<IpPrefix>().unwrap())
            .is_some(),
        "resolvable route reached the RIB"
    );
    assert!(
        table
            .best(&"203.0.113.0/24".parse::<IpPrefix>().unwrap())
            .is_some(),
        "unresolvable route reached the RIB too (held, not programmed)"
    );

    // NEXTHOP_UPDATE round-trip: both registered gateways got their
    // answer at the client — resolved for the on-subnet one (carrying the
    // mock interface's ifindex 2), the zeroed unresolved form for the
    // other.
    let resolved: Vec<&ZapiNexthopUpdate> = daemon
        .updates()
        .iter()
        .filter(|u| u.is_resolved())
        .collect();
    let unresolved: Vec<&ZapiNexthopUpdate> = daemon
        .updates()
        .iter()
        .filter(|u| !u.is_resolved())
        .collect();
    assert_eq!(daemon.updates().len(), 2, "one update per distinct gateway");
    assert_eq!(resolved.len(), 1, "192.0.2.9 resolves via the mirror");
    assert_eq!(unresolved.len(), 1, "100.64.0.1 is off-subnet");
    assert_eq!(
        resolved[0].registered_prefix,
        "192.0.2.9/32".parse::<IpPrefix>().unwrap()
    );
    assert_eq!(resolved[0].nexthops.len(), 1);
    assert_eq!(resolved[0].nexthops[0].ifindex, 2, "resolved through eth2");
    assert_eq!(
        unresolved[0].registered_prefix,
        "100.64.0.1/32".parse::<IpPrefix>().unwrap()
    );

    // Resolution-filtered programming: exactly one route_replace, for the
    // resolvable route, in resolved (ifindex-carrying) form.
    assert_eq!(
        dp.installed().len(),
        1,
        "only the resolvable route is programmed"
    );
    assert_eq!(dp.removed().len(), 0);
    let installed = &dp.installed()[0];
    assert_eq!(
        installed.prefix,
        "198.51.100.0/24".parse::<IpPrefix>().unwrap()
    );
    assert_eq!(installed.protocol, RouteProtocol::Static);
    assert_eq!(
        installed.nexthops.hops(),
        &[(Nexthop::Ipv4If("192.0.2.9".parse().unwrap(), 2), 1)],
        "programmed in resolved form via eth2"
    );

    // SIGHUP semantics with an empty config (the function hook, not a
    // signal): ROUTE_DELETEs flow, the driver withdraws the programmed
    // route from the dataplane.
    daemon.reload(&[]).await.expect("reload to empty");
    // Marker ping: its echo is written only after both DELETEs (and the
    // gateway UNREGISTERs) were fully handled by the session.
    daemon.ping().await.expect("ping after reload");
    while let Ok(command) = rx.try_recv() {
        driver.apply(command);
    }
    driver.rib.reconcile(&dp).await;

    assert_eq!(
        dp.removed().len(),
        1,
        "the programmed route withdrawn after the reload"
    );
    assert_eq!(
        dp.removed()[0].prefix,
        "198.51.100.0/24".parse::<IpPrefix>().unwrap()
    );
    assert!(
        driver
            .rib
            .table(254)
            .expect("main table")
            .best(&"198.51.100.0/24".parse::<IpPrefix>().unwrap())
            .is_none(),
        "the RIB no longer holds the withdrawn prefix"
    );

    drop(daemon);
    server.abort();
    let _ = std::fs::remove_file(&socket);
}
