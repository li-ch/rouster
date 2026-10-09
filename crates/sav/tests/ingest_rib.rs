//! W5 INGEST readout: build a Rib over the mock-Dataplane recipe (same
//! shape as `rousterd/tests/staticd_e2e.rs` and the rib crate's own
//! tests: recording mock, futures always `Ready`), install routes whose
//! egress interfaces resolve, reconcile so the resolution is proven the
//! reconcile way, ingest into a Sib, and assert `interfaces_for` —
//! including the default-route fallback marker semantics.

use std::future::Future;
use std::net::IpAddr;
use std::sync::Mutex;

use common::{
    Dataplane, DataplaneError, DataplaneEvent, IpPrefix, Nexthop, NexthopGroup, RouteEntry,
    RouteProtocol,
};
use rib::Rib;
use sav::{BindingOrigin, InterfaceRef, Sib};

/// Dataplane mock that records installs and withdrawals (the existing
/// recipe; futures always Ready, so `block_on` drives reconcile in a
/// single poll).
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

/// Minimal executor (the rib crate's test recipe): nothing in the mock
/// ever returns Pending for long, so a polling spin on a no-op waker is
/// enough.
fn block_on<F: Future>(fut: F) -> F::Output {
    use std::pin::pin;
    use std::task::{Context, Poll, Waker};

    let waker = Waker::noop();
    let mut cx = Context::from_waker(waker);
    let mut fut = pin!(fut);
    loop {
        match fut.as_mut().poll(&mut cx) {
            Poll::Ready(out) => return out,
            Poll::Pending => std::thread::yield_now(),
        }
    }
}

fn ip(s: &str) -> IpAddr {
    s.parse().unwrap()
}

fn iface(ifindex: u32, name: &str) -> InterfaceRef {
    InterfaceRef::If {
        ifindex,
        name: Some(name.into()),
    }
}

fn link(ifindex: u32, name: &str) -> DataplaneEvent {
    DataplaneEvent::LinkNew {
        ifindex,
        name: name.into(),
        is_up: true,
        flags: common::LinkFlags::up_broadcast(),
        vrf_table: None,
        master_ifindex: None,
    }
}

fn address(ifindex: u32, prefix: &str) -> DataplaneEvent {
    DataplaneEvent::AddressNew {
        ifindex,
        prefix: prefix.parse().unwrap(),
    }
}

fn gw_hop(gw: &str) -> Nexthop {
    match ip(gw) {
        IpAddr::V4(a) => Nexthop::Ipv4(a),
        IpAddr::V6(a) => Nexthop::Ipv6(a),
    }
}

fn gw_route(prefix: &str, gw: &str) -> RouteEntry {
    RouteEntry::new(
        prefix.parse().unwrap(),
        RouteProtocol::Static,
        NexthopGroup::single(gw_hop(gw)),
        0,
    )
}

/// The fixture: eth0 (192.0.2.0/24), eth1 (198.51.100.0/24), eth2
/// (2001:db8:1::/64), plus seven routes — five resolvable (including an
/// ECMP pair and a default), one with an off-subnet gateway (held in the
/// RIB, never programmed), one blackhole — and one kernel-mirror route.
fn fixture() -> (Rib, MockDp) {
    let mut rib = Rib::new();
    rib.apply_event(&link(2, "eth0"));
    rib.apply_event(&address(2, "192.0.2.1/24"));
    rib.apply_event(&link(3, "eth1"));
    rib.apply_event(&address(3, "198.51.100.1/24"));
    rib.apply_event(&link(4, "eth2"));
    rib.apply_event(&address(4, "2001:db8:1::1/64"));

    rib.add_route(gw_route("10.0.0.0/16", "192.0.2.9")); // -> eth0
    rib.add_route(gw_route("10.0.5.0/24", "198.51.100.9")); // -> eth1
    rib.add_route(gw_route("2001:db8:2::/48", "2001:db8:1::42")); // -> eth2
    rib.add_route(gw_route("0.0.0.0/0", "192.0.2.9")); // default -> eth0

    // ECMP: one leg per v4 interface.
    let mut group = NexthopGroup::new();
    group.add(gw_hop("192.0.2.9"), 1);
    group.add(gw_hop("198.51.100.9"), 1);
    rib.add_route(RouteEntry::new(
        "10.9.0.0/16".parse().unwrap(),
        RouteProtocol::Static,
        group,
        0,
    ));

    // Off-subnet gateway: held in the RIB, never programmed.
    rib.add_route(gw_route("203.0.113.0/24", "100.64.0.1"));
    // Blackhole: programmable, but never a SIB binding.
    rib.add_route(RouteEntry::new(
        "198.18.0.0/15".parse().unwrap(),
        RouteProtocol::Static,
        NexthopGroup::single(Nexthop::Blackhole),
        0,
    ));

    // Kernel-mirror route (observed state): must NOT feed the SIB.
    rib.apply_event(&DataplaneEvent::RouteNew {
        table: 254,
        prefix: "192.0.2.0/24".parse().unwrap(),
        protocol: RouteProtocol::Kernel,
        metric: 0,
        gateway: None,
        oif: None,
    });

    let dp = MockDp::default();
    block_on(rib.reconcile(&dp));
    (rib, dp)
}

#[test]
fn resolved_egress_feeds_the_sib() {
    let (rib, dp) = fixture();

    // The "egress interfaces resolve" premise, pinned the reconcile way:
    // six routes programmed (the unresolved-gateway one held), each
    // gateway hop rewritten to ifindex-carrying form.
    assert_eq!(dp.installed().len(), 6);
    assert!(dp.removed().is_empty());
    let installed = dp.installed();
    let default_install = installed
        .iter()
        .find(|e| e.prefix == "0.0.0.0/0".parse::<IpPrefix>().unwrap())
        .unwrap();
    assert_eq!(
        default_install.nexthops.hops(),
        &[(Nexthop::Ipv4If("192.0.2.9".parse().unwrap(), 2), 1)],
        "the default route's egress resolved to eth0 (ifindex 2)"
    );

    let sib = Sib::from_rib(&rib);
    // Held route, blackhole route, and the kernel mirror produce no
    // bindings: five rib-origin bindings for the five resolvable routes.
    assert_eq!(sib.bindings().count(), 5);

    assert_eq!(sib.interfaces_for(ip("10.0.5.7")), vec![iface(3, "eth1")]);
    assert_eq!(sib.interfaces_for(ip("10.0.9.9")), vec![iface(2, "eth0")]);
    assert_eq!(
        sib.interfaces_for(ip("10.9.1.1")),
        vec![iface(2, "eth0"), iface(3, "eth1")],
        "the ECMP route binds both egress interfaces"
    );
    assert_eq!(
        sib.interfaces_for(ip("2001:db8:2::77")),
        vec![iface(4, "eth2")]
    );
}

#[test]
fn default_route_falls_back_to_the_any_interface_marker() {
    let (rib, _dp) = fixture();
    let sib = Sib::from_rib(&rib);

    // Covered only by the default route: the answer is the "any
    // interface" marker — NOT eth0, the default's actual egress —
    // because the default route is not a wildcard binding over all
    // interfaces. Downstream: no conclusion, unknown != invalid.
    assert_eq!(
        sib.interfaces_for(ip("172.16.0.1")),
        vec![InterfaceRef::Any]
    );

    // The held (unresolved-gateway) route's source space also falls
    // through to the default: no binding was derived from it.
    assert_eq!(
        sib.interfaces_for(ip("203.0.113.7")),
        vec![InterfaceRef::Any]
    );

    // The kernel mirror's route must not have become a binding: if it
    // had, 192.0.2.55 would answer eth0 instead of the default fallback.
    assert_eq!(
        sib.interfaces_for(ip("192.0.2.55")),
        vec![InterfaceRef::Any]
    );

    // No v6 default route exists, so an unmatched v6 source has no
    // conclusion at all (empty, still never a verdict).
    assert!(sib.interfaces_for(ip("2001:db8:99::1")).is_empty());

    // The stored default binding keeps its concrete egress (snapshot /
    // debug state), and the marker is synthesized only at query time.
    let default = sib
        .binding(&"0.0.0.0/0".parse().unwrap(), BindingOrigin::Rib)
        .unwrap();
    assert_eq!(default.interfaces, vec![iface(2, "eth0")]);
    assert_eq!(default.origin, BindingOrigin::Rib);
}
