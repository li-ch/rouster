//! The rousterd operator status dump (A21) — the daemon's RIB and
//! mirror state as one line-based run-dir file.
//!
//! The savd/bfdd shape applied to the main daemon: `/run/rouster/
//! rousterd.status`, refreshed on the main loop's convergence cadence
//! (the reconcile tick — the same funnel that re-programs drift), one
//! keyword-first line per fact, additive fields only, written
//! warn-never-fail (a failed write never fails the daemon). The file
//! is the source for `rousterctl show interface|neighbour|vrf|rib
//! summary` and the vty's `show interface` family
//! (docs/operator-surfaces.md §2.3).
//!
//! Format (v1):
//!
//! ```text
//! rousterd 0.0.0 pid 4242
//! router-id 192.0.2.1
//! interfaces 3
//! interface lo ifindex 1 up flags UP|LOOPBACK|RUNNING vrf -
//!   address 127.0.0.1/8
//! interface vrf-blue ifindex 5 up flags UP|BROADCAST|RUNNING|MULTICAST vrf - vrf-table 1001
//! interface eth1 ifindex 6 up flags UP|BROADCAST|RUNNING|MULTICAST vrf vrf-blue
//! neighbours 1
//! neighbour 198.51.100.9 ifindex 2 state REACHABLE lladdr 02:00:00:00:00:11
//! tables 2
//! table 254 routes 3 prefixes 2 connected 2 kernel 4 vrf -
//! table 1001 routes 0 prefixes 0 connected 1 kernel 1 vrf vrf-blue
//! ```
//!
//! Contracts worth pinning:
//!
//! - **Tolerance** is the consumer's job (the S3 conventions): unknown
//!   lines are counted and dropped, known keywords are picked wherever
//!   they sit, parsing never fails. The writer may add fields freely.
//! - **Table enumeration**: table ids are `{main} ∪ static keys ∪
//!   connected keys ∪ every mirrored VRF device's table`. The rib
//!   exposes no "all table ids" iterator; protocol tables reachable
//!   only through ZAPI route adds in ids outside that set are not
//!   listed (nothing does that today — bgpd/ospfd target 254 —
//!   disclosed here so the gap is known when it first matters).
//! - **Router-id** is derived here from the interface mirror with the
//!   driver's algorithm (highest IPv4 on an UP loopback, 127/8
//!   excluded, else highest IPv4 on any UP interface). The driver's
//!   [`crate::driver::RibDriver`] keeps its own copy for
//!   ROUTER_ID_UPDATE answers; this is a deliberate duplication so
//!   the status surface never reaches into driver state.
//! - **Lifecycle**: unlike savd/bfdd there is no pidfile and no
//!   clean-exit removal (the one-line wiring budget); the header pid
//!   makes a stale file detectable — consumers assess liveness from it
//!   and report the file as the last-known record.

use std::collections::BTreeSet;
use std::net::Ipv4Addr;
use std::path::Path;

use common::IpPrefix;
use common::TableId;
use rib::{InterfaceState, Rib, MAIN_TABLE};

/// Default status file (A21): refreshed by the main loop's reconcile
/// tick.
pub const DEFAULT_STATUS_FILE: &str = "/run/rouster/rousterd.status";

/// Renders the snapshot text (pure — the unit tests pin it; `publish`
/// only adds the filesystem).
pub fn status_text(rib: &Rib, pid: u32) -> String {
    let mut out = format!(
        "rousterd {} pid {pid}\nrouter-id {}\n",
        env!("CARGO_PKG_VERSION"),
        router_id(rib).map(|id| id.to_string()).unwrap_or_else(|| "none".into())
    );

    // Interfaces, ifindex order (the mirror's own ordering).
    out.push_str(&format!("interfaces {}\n", rib.interfaces().len()));
    for (ifindex, iface) in rib.interfaces() {
        out.push_str(&interface_line(*ifindex, iface, rib));
        for prefix in &iface.addresses {
            out.push_str(&format!("  address {prefix}\n"));
        }
    }

    // Neighbours, mirror order ((ip, ifindex)).
    out.push_str(&format!("neighbours {}\n", rib.neighbours().len()));
    for entry in rib.neighbours().values() {
        out.push_str(&format!(
            "neighbour {} ifindex {} state {} lladdr {}\n",
            entry.ip,
            entry.link_ifindex,
            entry.state,
            lladdr_hex(entry.lladdr.as_deref())
        ));
    }

    // Tables, id order: counts plus the owning VRF device.
    let tables = table_ids(rib);
    out.push_str(&format!("tables {}\n", tables.len()));
    for id in tables {
        let (routes, prefixes) = rib
            .table(id)
            .map(count_table)
            .unwrap_or((0, 0));
        let connected = rib
            .connected_table(id)
            .map(count_table)
            .unwrap_or((0, 0))
            .0;
        let kernel = rib.kernel_table(id).map(count_table).unwrap_or((0, 0)).0;
        let vrf = rib
            .vrf_of_table(id)
            .map(|(_, iface)| iface.name.clone())
            .unwrap_or_else(|| "-".into());
        out.push_str(&format!(
            "table {id} routes {routes} prefixes {prefixes} connected {connected} kernel {kernel} vrf {vrf}\n"
        ));
    }
    out
}

/// Publishes the snapshot to the run dir; diagnostics only — a failed
/// write warns and never fails the caller (the savd/bfdd rule).
pub fn publish(rib: &Rib) {
    publish_to(Path::new(DEFAULT_STATUS_FILE), rib, std::process::id());
}

/// `publish` against an explicit path (the test surface).
pub fn publish_to(path: &Path, rib: &Rib, pid: u32) {
    if let Some(parent) = path.parent() {
        if let Err(err) = std::fs::create_dir_all(parent) {
            tracing::warn!(%err, path = %path.display(), "rousterd: status dir create failed");
            return;
        }
    }
    if let Err(err) = std::fs::write(path, status_text(rib, pid)) {
        tracing::warn!(%err, path = %path.display(), "rousterd: status file write failed");
    }
}

/// One `interface` line: membership (`vrf <name>` = the VRF device
/// this link is enslaved to, `-` otherwise) and, for a VRF device
/// itself, the table it binds (`vrf-table <id>`).
fn interface_line(ifindex: u32, iface: &InterfaceState, rib: &Rib) -> String {
    let vrf = iface
        .master_ifindex
        .and_then(|master| rib.interfaces().get(&master))
        .filter(|master| master.vrf_table.is_some())
        .map(|master| master.name.clone())
        .unwrap_or_else(|| "-".into());
    let mut line = format!(
        "interface {} ifindex {ifindex} {} flags {} vrf {vrf}",
        iface.name,
        if iface.is_up { "up" } else { "down" },
        iface.flags
    );
    if let Some(table) = iface.vrf_table {
        line.push_str(&format!(" vrf-table {table}"));
    }
    line.push('\n');
    line
}

/// The driver's router-id derivation, re-implemented over the mirror
/// (the driver's copy is private and this surface may not reach into
/// driver state): highest IPv4 address on an UP loopback interface,
/// 127/8 excluded, else highest IPv4 on any UP interface.
fn router_id(rib: &Rib) -> Option<Ipv4Addr> {
    let mut loopback: Vec<Ipv4Addr> = Vec::new();
    let mut any_up: Vec<Ipv4Addr> = Vec::new();
    for iface in rib.interfaces().values().filter(|i| i.is_up) {
        let pool = if iface.flags.contains(common::LinkFlags::LOOPBACK) {
            &mut loopback
        } else {
            &mut any_up
        };
        for prefix in &iface.addresses {
            if let IpPrefix::V4(p) = prefix {
                if p.addr().is_loopback() {
                    continue;
                }
                pool.push(p.addr());
            }
        }
    }
    let pool = if loopback.is_empty() { any_up } else { loopback };
    pool.into_iter().max()
}

/// The table ids the dump lists (see the module docs' enumeration
/// contract).
fn table_ids(rib: &Rib) -> BTreeSet<TableId> {
    let mut ids = BTreeSet::from([MAIN_TABLE]);
    ids.extend(rib.static_keys().map(|(table, _)| table));
    ids.extend(rib.connected_keys().map(|(table, _)| table));
    ids.extend(
        rib.interfaces()
            .values()
            .filter_map(|iface| iface.vrf_table),
    );
    ids
}

/// `(candidate count, prefix count)` of one table's entries.
fn count_table(table: &rib::Table) -> (usize, usize) {
    let prefixes = table.iter().count();
    let routes = table.iter().map(|(_, candidates)| candidates.len()).sum();
    (routes, prefixes)
}

/// Link-layer address as colon-separated hex (`02:00:00:00:00:11`),
/// `-` when absent — [`common::NeighbourEntry`]'s own rendering,
/// re-implemented because its helper is private.
fn lladdr_hex(bytes: Option<&[u8]>) -> String {
    match bytes {
        Some(bytes) => bytes
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<Vec<_>>()
            .join(":"),
        None => "-".to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use common::{
        DataplaneEvent, IpPrefix, Ipv4Prefix, LinkFlags, NeighbourEntry, NeighbourState,
        RouteEntry, RouteProtocol,
    };
    use std::net::IpAddr;

    fn link(
        ifindex: u32,
        name: &str,
        up: bool,
        flags: LinkFlags,
        vrf_table: Option<TableId>,
        master: Option<u32>,
    ) -> DataplaneEvent {
        DataplaneEvent::LinkNew {
            ifindex,
            name: name.into(),
            is_up: up,
            flags,
            vrf_table,
            master_ifindex: master,
        }
    }

    fn addr(ifindex: u32, text: &str) -> DataplaneEvent {
        DataplaneEvent::AddressNew {
            ifindex,
            prefix: text.parse().unwrap(),
        }
    }

    fn v4(text: &str) -> IpAddr {
        text.parse().unwrap()
    }

    fn prefix(text: &str) -> IpPrefix {
        text.parse::<Ipv4Prefix>().unwrap().into()
    }

    /// A populated rib: loopback, two VRFs' worth of links, addresses,
    /// static/kernel routes, and a neighbour.
    fn populated() -> Rib {
        let mut rib = Rib::new();
        rib.apply_event(&link(1, "lo", true, LinkFlags::up_loopback(), None, None));
        rib.apply_event(&addr(1, "127.0.0.1/8"));
        rib.apply_event(&link(
            2,
            "eth0",
            true,
            LinkFlags::up_broadcast(),
            None,
            None,
        ));
        rib.apply_event(&addr(2, "192.0.2.1/24"));
        rib.apply_event(&addr(2, "2001:db8::1/64"));
        rib.apply_event(&link(
            5,
            "vrf-blue",
            true,
            LinkFlags::up_broadcast(),
            Some(1001),
            None,
        ));
        rib.apply_event(&link(
            6,
            "eth1",
            true,
            LinkFlags::up_broadcast(),
            None,
            Some(5),
        ));
        rib.apply_event(&addr(6, "198.51.100.1/24"));

        // A static route in main (candidate + prefix count 1 each).
        let mut entry = RouteEntry::new(
            prefix("203.0.113.0/24"),
            RouteProtocol::Static,
            common::NexthopGroup::new(),
            0,
        );
        entry.table = MAIN_TABLE;
        rib.add_route(entry);
        // Kernel-origin mirrors land via events (RouteNew filters to
        // kernel-origin protocols).
        rib.apply_event(&DataplaneEvent::RouteNew {
            table: MAIN_TABLE,
            prefix: prefix("198.18.0.0/15"),
            protocol: RouteProtocol::Kernel,
            metric: 0,
            gateway: None,
            oif: Some(2),
        });
        rib.apply_event(&DataplaneEvent::RouteNew {
            table: 1001,
            prefix: prefix("198.51.100.0/24"),
            protocol: RouteProtocol::Kernel,
            metric: 0,
            gateway: None,
            oif: Some(6),
        });

        rib.apply_event(&DataplaneEvent::NeighbourNew {
            entry: NeighbourEntry::from_rtnetlink(
                v4("198.51.100.9"),
                6,
                Some(vec![0x02, 0x00, 0x00, 0x00, 0x00, 0x11]),
                NeighbourState::REACHABLE.bits(),
                0,
            ),
        });
        rib.apply_event(&DataplaneEvent::NeighbourNew {
            entry: NeighbourEntry::from_rtnetlink(
                v4("192.0.2.10"),
                2,
                None,
                NeighbourState::INCOMPLETE.bits(),
                0,
            ),
        });
        rib
    }

        #[test]
    fn header_carries_version_pid_and_derived_router_id() {
        let rib = populated();
        let text = status_text(&rib, 4242);
        assert!(text.starts_with(
            format!("rousterd {} pid 4242\n", env!("CARGO_PKG_VERSION")).as_str()
        ));
        // The highest non-127/8 v4 on an UP interface (eth1's
        // 198.51.100.1 beats eth0's 192.0.2.1; no loopback competes).
        assert!(text.contains("\nrouter-id 198.51.100.1\n"));
    }

    #[test]
    fn router_id_none_when_no_up_v4_address() {
        let mut rib = Rib::new();
        rib.apply_event(&link(
            1,
            "lo",
            true,
            LinkFlags::up_loopback(),
            None,
            None,
        ));
        rib.apply_event(&addr(1, "127.0.0.1/8")); // 127/8 excluded
        let text = status_text(&rib, 1);
        assert!(text.contains("\nrouter-id none\n"));
    }

    #[test]
    fn router_id_prefers_loopback_over_any_up() {
        let mut rib = Rib::new();
        rib.apply_event(&link(
            2,
            "eth0",
            true,
            LinkFlags::up_broadcast(),
            None,
            None,
        ));
        rib.apply_event(&addr(2, "192.0.2.1/24"));
        rib.apply_event(&link(
            9,
            "lo9",
            true,
            LinkFlags::up_loopback(),
            None,
            None,
        ));
        rib.apply_event(&addr(9, "198.51.100.7/32"));
        let text = status_text(&rib, 1);
        assert!(text.contains("\nrouter-id 198.51.100.7\n"));
    }

    #[test]
    fn interface_lines_carry_name_ifindex_state_flags_vrf_and_addresses() {
        let rib = populated();
        let text = status_text(&rib, 4242);
        assert!(text.contains("interfaces 4\n"));
        assert!(text
            .contains("interface lo ifindex 1 up flags UP|LOOPBACK|RUNNING vrf -\n  address 127.0.0.1/8\n"));
        // The VRF device: no master, but its bound table.
        assert!(text.contains("interface vrf-blue ifindex 5 up flags UP|BROADCAST|RUNNING|MULTICAST vrf - vrf-table 1001\n"));
        // The enslaved member: the master's name as its vrf.
        assert!(text.contains("interface eth1 ifindex 6 up flags UP|BROADCAST|RUNNING|MULTICAST vrf vrf-blue\n"));
    }

    #[test]
    fn a_down_interface_renders_down() {
        let mut rib = Rib::new();
        rib.apply_event(&link(
            2,
            "eth0",
            false,
            LinkFlags::BROADCAST,
            None,
            None,
        ));
        let text = status_text(&rib, 1);
        assert!(text.contains("interface eth0 ifindex 2 down flags BROADCAST vrf -\n"));
    }

    #[test]
    fn neighbour_lines_carry_ip_ifindex_state_and_lladdr() {
        let rib = populated();
        let text = status_text(&rib, 4242);
        assert!(text.contains("neighbours 2\n"));
        assert!(text.contains(
            "neighbour 198.51.100.9 ifindex 6 state REACHABLE lladdr 02:00:00:00:00:11\n"
        ));
        assert!(text
            .contains("neighbour 192.0.2.10 ifindex 2 state INCOMPLETE lladdr -\n"));
    }

    #[test]
    fn table_lines_carry_counts_and_the_owning_vrf() {
        let rib = populated();
        let text = status_text(&rib, 4242);
        assert!(text.contains("tables 2\n"));
        // Main: 1 static candidate over 1 prefix; connected = eth0's
        // two addresses + loopback's one = 3; kernel = 1 mirror entry.
        assert!(text
            .contains("table 254 routes 1 prefixes 1 connected 3 kernel 1 vrf -\n"));
        // VRF-blue's table: no protocol routes, eth1's connected route
        // (a member's connected route lands in the VRF's table), one
        // kernel mirror entry.
        assert!(text
            .contains("table 1001 routes 0 prefixes 0 connected 1 kernel 1 vrf vrf-blue\n"));
    }

    #[test]
    fn an_empty_rib_renders_the_minimal_dump() {
        let rib = Rib::new();
        let text = status_text(&rib, 7);
        let lines: Vec<&str> = text.lines().collect();
        assert_eq!(
            lines,
            vec![
                format!("rousterd {} pid 7", env!("CARGO_PKG_VERSION")).as_str(),
                "router-id none",
                "interfaces 0",
                "neighbours 0",
                "tables 1",
                "table 254 routes 0 prefixes 0 connected 0 kernel 0 vrf -",
            ]
        );
    }

    #[test]
    fn publish_writes_the_file_and_creates_the_run_dir() {
        let rib = populated();
        let dir = std::env::temp_dir().join(format!(
            "rousterd-status-{}-{}",
            std::process::id(),
            line!()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        let path = dir.join("nested/rousterd.status");
        publish_to(&path, &rib, 4242);
        let text = std::fs::read_to_string(&path).expect("status file written");
        assert!(text.starts_with("rousterd "));
        assert!(text.contains("\nrouter-id 198.51.100.1\n"));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn publish_never_fails_on_an_unwritable_path() {
        let rib = Rib::new();
        // A path whose parent is a regular file: create_dir_all fails,
        // the call must return (not panic) and stay quiet about it.
        let file = std::env::temp_dir().join(format!(
            "rousterd-status-blocker-{}",
            std::process::id()
        ));
        std::fs::write(&file, "not a dir").unwrap();
        publish_to(&file.join("rousterd.status"), &rib, 1);
        let _ = std::fs::remove_file(&file);
    }

    #[test]
    fn table_enumeration_includes_static_only_and_connected_only_tables() {
        let mut rib = Rib::new();
        // A static route in a table nothing else touches.
        let mut entry = RouteEntry::new(
            prefix("203.0.113.0/24"),
            RouteProtocol::Static,
            common::NexthopGroup::new(),
            0,
        );
        entry.table = 500;
        rib.add_route(entry);
        let text = status_text(&rib, 1);
        assert!(text.contains("\ntables 2\n"));
        assert!(text.contains("\ntable 500 routes 1 prefixes 1 connected 0 kernel 0 vrf -\n"));
    }
}
