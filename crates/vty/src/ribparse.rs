//! Tolerant parsing of `rousterd.status` — the S3/W1-c conventions
//! applied to the main daemon's dump (crates/rousterd/src/status.rs
//! writes it; the format contract is docs/operator-surfaces.md
//! §2.3). The third run-dir publisher, re-implemented in-crate per
//! the W1-c deviation (edge adapters stay decoupled; consolidation
//! is an owner decision recorded in docs/protocols/vty.md).
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
//! Tolerance contract: unknown *lines* are counted and dropped;
//! known *keywords* are picked out wherever they sit, so added fields
//! ride along harmlessly; indented `address` lines attach to the
//! interface above them; a value position never swallows another
//! keyword; a malformed number leaves its field unset. Parsing never
//! fails.

use std::net::IpAddr;

/// One `interface` line plus its `address` children.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct IfaceLine {
    pub name: Option<String>,
    pub ifindex: Option<u32>,
    pub up: Option<bool>,
    pub flags: Option<String>,
    pub vrf: Option<String>,
    pub vrf_table: Option<u32>,
    pub addresses: Vec<String>,
}

/// One `neighbour` line.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct NeighLine {
    pub ip: Option<IpAddr>,
    pub ifindex: Option<u32>,
    pub state: Option<String>,
    pub lladdr: Option<String>,
}

/// One `table` line.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TableLine {
    pub id: Option<u32>,
    pub routes: Option<u64>,
    pub prefixes: Option<u64>,
    pub connected: Option<u64>,
    pub kernel: Option<u64>,
    pub vrf: Option<String>,
}

/// A parsed `rousterd.status`.
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
        let mut parsed = RibStatus::default();
        for line in text.lines() {
            let line = line.trim_end_matches('\r').trim_end();
            if line.is_empty() {
                continue;
            }
            // Indented lines are children of the interface above.
            if line.starts_with(' ') || line.starts_with('\t') {
                let body = line.trim();
                if let Some(address) = body.strip_prefix("address ") {
                    if let Some(iface) = parsed.interfaces.last_mut() {
                        iface.addresses.push(address.trim().to_string());
                        continue;
                    }
                }
                parsed.unknown_lines += 1;
                continue;
            }
            let tokens: Vec<&str> = line.split_whitespace().collect();
            match tokens[0] {
                "rousterd" => parse_header(&mut parsed, &tokens),
                "router-id" => {
                    if let Some(value) = tokens.get(1) {
                        if value.parse::<IpAddr>().is_ok() {
                            parsed.router_id = Some(value.to_string());
                        }
                    }
                }
                "interface" => {
                    let mut iface = IfaceLine::default();
                    parse_iface_body(&mut iface, &tokens[1..]);
                    if iface.name.is_some() || iface.ifindex.is_some() {
                        parsed.interfaces.push(iface);
                    } else {
                        parsed.unknown_lines += 1;
                    }
                }
                "neighbour" => {
                    let mut neigh = NeighLine::default();
                    parse_neigh_body(&mut neigh, &tokens[1..]);
                    if neigh.ip.is_some() || neigh.ifindex.is_some() {
                        parsed.neighbours.push(neigh);
                    } else {
                        parsed.unknown_lines += 1;
                    }
                }
                "table" => {
                    let mut table = TableLine {
                        id: tokens.get(1).and_then(|t| t.parse().ok()),
                        ..TableLine::default()
                    };
                    parse_table_body(&mut table, &tokens[2..]);
                    if table.id.is_some() {
                        parsed.tables.push(table);
                    } else {
                        parsed.unknown_lines += 1;
                    }
                }
                // Count lines (`interfaces N`, ...) are known but
                // informational — the renderers trust the rows they
                // parsed, so these are dropped without counting.
                "interfaces" | "neighbours" | "tables" => {}
                _ => parsed.unknown_lines += 1,
            }
        }
        parsed
    }

    /// The interfaces the `name` filter selects (all when `None`).
    pub fn interfaces_matching(&self, name: Option<&str>) -> Vec<&IfaceLine> {
        self.interfaces
            .iter()
            .filter(|iface| name.is_none_or(|want| iface.name.as_deref() == Some(want)))
            .collect()
    }

    /// The neighbours the `filter` selects (all when `None`): a bare
    /// address or a CIDR prefix, either family.
    pub fn neighbours_matching(&self, filter: Option<&str>) -> Vec<&NeighLine> {
        let filter = filter.and_then(parse_filter);
        self.neighbours
            .iter()
            .filter(|neigh| match (&filter, neigh.ip) {
                (Some(filter), Some(ip)) => filter.contains(ip),
                _ => true,
            })
            .collect()
    }
}

/// Header line: `rousterd <version> pid <pid>`, keyword-picked.
fn parse_header(parsed: &mut RibStatus, tokens: &[&str]) {
    if let Some(version) = tokens.get(1) {
        if *version != "pid" {
            parsed.version = Some(version.to_string());
        }
    }
    if let Some(position) = tokens.iter().position(|token| *token == "pid") {
        if let Some(value) = tokens.get(position + 1) {
            parsed.pid = value.parse().ok();
        }
    }
}

/// Keywords of the `interface` line: a value position never swallows
/// one of these.
const IFACE_KEYWORDS: [&str; 6] = ["ifindex", "up", "down", "flags", "vrf", "vrf-table"];

fn parse_iface_body(iface: &mut IfaceLine, tokens: &[&str]) {
    if let Some(name) = tokens.first() {
        iface.name = Some(name.to_string());
    }
    for (index, token) in tokens.iter().enumerate().skip(1) {
        match *token {
            "up" => iface.up = Some(true),
            "down" => iface.up = Some(false),
            "ifindex" | "vrf-table" => {
                if let Some(value) = value_of(tokens, index, &IFACE_KEYWORDS) {
                    let number = value.parse().ok();
                    match *token {
                        "ifindex" => iface.ifindex = number,
                        _ => iface.vrf_table = number,
                    }
                }
            }
            "flags" => {
                if let Some(value) = value_of(tokens, index, &IFACE_KEYWORDS) {
                    iface.flags = Some(value.to_string());
                }
            }
            "vrf" => {
                if let Some(value) = value_of(tokens, index, &IFACE_KEYWORDS) {
                    iface.vrf = Some(value.to_string());
                }
            }
            _ => {}
        }
    }
}

const NEIGH_KEYWORDS: [&str; 3] = ["ifindex", "state", "lladdr"];

fn parse_neigh_body(neigh: &mut NeighLine, tokens: &[&str]) {
    if let Some(ip) = tokens.first() {
        neigh.ip = ip.parse().ok();
    }
    for (index, token) in tokens.iter().enumerate().skip(1) {
        let Some(value) = value_of(tokens, index, &NEIGH_KEYWORDS) else {
            continue;
        };
        match *token {
            "ifindex" => neigh.ifindex = value.parse().ok(),
            "state" => neigh.state = Some(value.to_string()),
            "lladdr" => neigh.lladdr = Some(value.to_string()),
            _ => {}
        }
    }
}

const TABLE_KEYWORDS: [&str; 5] = ["routes", "prefixes", "connected", "kernel", "vrf"];

fn parse_table_body(table: &mut TableLine, tokens: &[&str]) {
    for (index, token) in tokens.iter().enumerate() {
        let Some(value) = value_of(tokens, index, &TABLE_KEYWORDS) else {
            continue;
        };
        let number = value.parse().ok();
        match *token {
            "routes" => table.routes = number,
            "prefixes" => table.prefixes = number,
            "connected" => table.connected = number,
            "kernel" => table.kernel = number,
            "vrf" => table.vrf = Some(value.to_string()),
            _ => {}
        }
    }
}

/// The token after `index`, when it exists and is not itself a
/// keyword.
fn value_of<'a>(tokens: &'a [&'a str], index: usize, keywords: &[&str]) -> Option<&'a str> {
    let value = tokens.get(index + 1)?;
    (!keywords.contains(value)).then_some(*value)
}

/// A parsed neighbour filter (see [`RibStatus::neighbours_matching`]).
struct Filter {
    base: u128,
    width: u32,
    family_v4: bool,
}

impl Filter {
    fn contains(&self, ip: IpAddr) -> bool {
        match ip {
            IpAddr::V4(v4) if self.family_v4 => {
                in_window(u32::from(v4) as u128, self.base, self.width.min(32), 32)
            }
            IpAddr::V6(v6) if !self.family_v4 => {
                in_window(u128::from(v6), self.base, self.width.min(128), 128)
            }
            _ => false,
        }
    }
}

fn in_window(addr: u128, base: u128, width: u32, family_len: u32) -> bool {
    let shift = family_len - width;
    (addr >> shift) == (base >> shift)
}

fn parse_filter(text: &str) -> Option<Filter> {
    let (addr_text, len_text) = match text.split_once('/') {
        Some((addr, len)) => (addr, Some(len)),
        None => (text, None),
    };
    if let Ok(v4) = addr_text.parse::<std::net::Ipv4Addr>() {
        let width = match len_text {
            Some(len) => len.parse::<u32>().ok().filter(|l| *l <= 32)?,
            None => 32,
        };
        return Some(Filter {
            base: u32::from(v4) as u128,
            width,
            family_v4: true,
        });
    }
    if let Ok(v6) = addr_text.parse::<std::net::Ipv6Addr>() {
        let width = match len_text {
            Some(len) => len.parse::<u32>().ok().filter(|l| *l <= 128)?,
            None => 128,
        };
        return Some(Filter {
            base: u128::from(v6),
            width,
            family_v4: false,
        });
    }
    None
}

/// Does this token satisfy the vty's address-or-prefix parameter kind?
/// (Either family, bare or CIDR — the grammar's validator.)
pub fn accepts_addr_or_prefix(token: &str) -> bool {
    parse_filter(token).is_some()
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
