//! `rousterd.status` parsing — the vty view over the ONE run-dir
//! reader (`common::rundir`, the N8 consolidation; the format
//! contract is docs/operator-surfaces.md §2.3; the writer is
//! `crates/rousterd/src/status.rs`):
//!
//! ```text
//! rousterd 0.0.0 pid 4242
//! router-id 198.51.100.1
//! interfaces 4
//! interface eth0 ifindex 2 up flags UP|BROADCAST|RUNNING|MULTICAST vrf -
//!   address 192.0.2.1/24
//! neighbours 2
//! neighbour 192.0.2.10 ifindex 2 state INCOMPLETE lladdr -
//! tables 2
//! table 254 routes 1 prefixes 1 connected 3 kernel 1 vrf -
//! ```
//!
//! The shared reader owns the tolerance contract (unknown *lines*
//! counted and dropped; known *keywords* picked out wherever they
//! sit; a value position never swallows another keyword; indented
//! `address` lines attach to the interface above them; a malformed
//! number leaves its field unset; parsing never fails). [`RibStatus`]
//! is this crate's projection of the reader's result: the rows the
//! vty renders, without the count claims rousterctl carries.

pub use common::rundir::{IfaceLine, NeighLine, TableLine};

/// The vty projection of a parsed `rousterd.status`: the rows, the
/// header facts, and the unrecognized-line count.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RibStatus {
    pub version: Option<String>,
    pub pid: Option<u32>,
    pub router_id: Option<String>,
    pub interfaces: Vec<IfaceLine>,
    pub neighbours: Vec<NeighLine>,
    pub tables: Vec<TableLine>,
    pub unknown_lines: usize,
}

impl RibStatus {
    /// Parses a status file's content. Never fails.
    pub fn parse(text: &str) -> RibStatus {
        common::rundir::parse_rousterd(text).into()
    }

    /// The interfaces a `name` filter selects (all when `None`).
    pub fn interfaces_matching(&self, name: Option<&str>) -> Vec<&IfaceLine> {
        common::rundir::interfaces_matching(&self.interfaces, name)
    }

    /// The neighbours the `filter` selects (all when `None`): a bare
    /// address or a CIDR prefix, either family.
    pub fn neighbours_matching(&self, filter: Option<&str>) -> Vec<&NeighLine> {
        common::rundir::neighbours_matching(&self.neighbours, filter)
    }
}

impl From<common::rundir::RousterdStatus> for RibStatus {
    fn from(parsed: common::rundir::RousterdStatus) -> RibStatus {
        // The count claims are rousterctl's; the vty renderers trust
        // the rows they parsed.
        RibStatus {
            version: parsed.version,
            pid: parsed.pid,
            router_id: parsed.router_id,
            interfaces: parsed.interfaces,
            neighbours: parsed.neighbours,
            tables: parsed.tables,
            unknown_lines: parsed.unknown_lines,
        }
    }
}

/// Does this token satisfy the vty's address-or-prefix parameter kind?
/// (Either family, bare or CIDR — the grammar's validator, shared
/// with the reader's filter machinery.)
pub fn accepts_addr_or_prefix(token: &str) -> bool {
    common::rundir::accepts_addr_or_prefix(token)
}

#[cfg(test)]
mod tests {
    use super::*;

    const TODAY: &str = "\
rousterd 0.0.0 pid 4242
router-id 198.51.100.1
interfaces 4
interface lo ifindex 1 up flags UP|LOOPBACK|RUNNING vrf -
  address 127.0.0.1/8
interface eth0 ifindex 2 up flags UP|BROADCAST|RUNNING|MULTICAST vrf -
  address 192.0.2.1/24
  address 2001:db8::1/64
interface vrf-blue ifindex 5 up flags UP|BROADCAST|RUNNING|MULTICAST vrf - vrf-table 1001
interface eth1 ifindex 6 up flags UP|BROADCAST|RUNNING|MULTICAST vrf vrf-blue
  address 198.51.100.1/24
neighbours 2
neighbour 192.0.2.10 ifindex 2 state INCOMPLETE lladdr -
neighbour 198.51.100.9 ifindex 6 state REACHABLE lladdr 02:00:00:00:00:11
tables 2
table 254 routes 1 prefixes 1 connected 3 kernel 1 vrf -
table 1001 routes 0 prefixes 0 connected 1 kernel 1 vrf vrf-blue
";

    #[test]
    fn parses_todays_full_shape() {
        let parsed = RibStatus::parse(TODAY);
        assert_eq!(parsed.version.as_deref(), Some("0.0.0"));
        assert_eq!(parsed.pid, Some(4242));
        assert_eq!(parsed.router_id.as_deref(), Some("198.51.100.1"));
        assert_eq!(parsed.interfaces.len(), 4);
        let eth0 = &parsed.interfaces[1];
        assert_eq!(eth0.ifindex, Some(2));
        assert_eq!(eth0.up, Some(true));
        assert_eq!(eth0.addresses.len(), 2);
        assert_eq!(parsed.interfaces[2].vrf_table, Some(1001));
        assert_eq!(parsed.interfaces[3].vrf.as_deref(), Some("vrf-blue"));
        assert_eq!(parsed.neighbours.len(), 2);
        assert_eq!(
            parsed.neighbours[1].lladdr.as_deref(),
            Some("02:00:00:00:00:11")
        );
        assert_eq!(parsed.tables[0].connected, Some(3));
        assert_eq!(parsed.tables[1].vrf.as_deref(), Some("vrf-blue"));
        assert_eq!(parsed.unknown_lines, 0);
    }

    #[test]
    fn future_fields_ride_and_unknown_lines_count() {
        let text = "\
rousterd 2.0.0 pid 51234 uptime 3600s
router-id 192.0.2.1 origin derived
interfaces 1
interface eth0 ifindex 2 up flags UP|RUNNING vrf - mtu 1500
  address 192.0.2.1/24 preferred
agent session 99 something
table 254 routes 1 prefixes 1 connected 2 kernel 3 vrf - label main
";
        let parsed = RibStatus::parse(text);
        assert_eq!(parsed.pid, Some(51_234));
        assert_eq!(parsed.router_id.as_deref(), Some("192.0.2.1"));
        assert_eq!(parsed.interfaces[0].ifindex, Some(2));
        assert_eq!(parsed.tables[0].kernel, Some(3));
        assert_eq!(parsed.unknown_lines, 1);
    }

    #[test]
    fn malformed_lines_leave_fields_unset() {
        let text = "\
rousterd x.y pid nope
router-id not-an-ip
interface eth0 ifindex NaN up flags vrf
neighbour not-an-ip ifindex two state lladdr
table 254 routes many prefixes 0 connected 0 kernel 0 vrf -
";
        let parsed = RibStatus::parse(text);
        assert_eq!(parsed.pid, None);
        assert_eq!(parsed.router_id, None);
        let eth0 = &parsed.interfaces[0];
        assert_eq!(eth0.ifindex, None);
        assert_eq!(eth0.flags, None);
        assert!(parsed.neighbours.is_empty());
        assert_eq!(parsed.tables[0].routes, None);
        assert_eq!(parsed.tables[0].prefixes, Some(0));
    }

    #[test]
    fn neighbour_filters_match_prefix_and_family() {
        let parsed = RibStatus::parse(TODAY);
        assert_eq!(parsed.neighbours_matching(None).len(), 2);
        assert_eq!(parsed.neighbours_matching(Some("192.0.2.10")).len(), 1);
        assert_eq!(parsed.neighbours_matching(Some("192.0.2.0/24")).len(), 1);
        assert_eq!(
            parsed.neighbours_matching(Some("198.51.100.64/26")).len(),
            0
        );
        assert_eq!(parsed.neighbours_matching(Some("2001:db8::/32")).len(), 0);
    }

    #[test]
    fn interface_name_filter_selects() {
        let parsed = RibStatus::parse(TODAY);
        assert_eq!(parsed.interfaces_matching(None).len(), 4);
        assert_eq!(parsed.interfaces_matching(Some("eth1")).len(), 1);
        assert!(parsed.interfaces_matching(Some("eth9")).is_empty());
    }

    #[test]
    fn addr_or_prefix_validator() {
        assert!(accepts_addr_or_prefix("192.0.2.1"));
        assert!(accepts_addr_or_prefix("192.0.2.0/24"));
        assert!(accepts_addr_or_prefix("2001:db8::1"));
        assert!(accepts_addr_or_prefix("2001:db8::/64"));
        assert!(!accepts_addr_or_prefix("192.0.2.0/33"));
        assert!(!accepts_addr_or_prefix("wat"));
        assert!(!accepts_addr_or_prefix(""));
    }
}
