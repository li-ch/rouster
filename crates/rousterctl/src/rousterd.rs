//! Parsing and rendering of `rousterd.status` — the main daemon's
//! A21 dump (crates/rousterd/src/status.rs writes it; the format
//! contract is docs/operator-surfaces.md §2.3):
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
//! Tolerance contract (the S3 rules, the daemon's format may grow):
//! unknown *lines* are counted and dropped; known *keywords* are
//! picked out wherever they sit on their line, so added fields ride
//! along harmlessly; indented `address` lines attach to the interface
//! above them; a malformed number leaves its field unset rather than
//! failing the parse. Parsing never fails.

use std::net::IpAddr;

use crate::liveness::PidState;

/// One `interface` line plus its `address` children.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct IfaceLine {
    pub name: Option<String>,
    pub ifindex: Option<u32>,
    /// `Some(true)`/`Some(false)` from the `up`/`down` word.
    pub up: Option<bool>,
    /// The flags word, verbatim (`UP|RUNNING|0x30`).
    pub flags: Option<String>,
    /// The VRF device this interface is enslaved to (`-` = none).
    pub vrf: Option<String>,
    /// The table this interface binds when it IS a VRF device.
    pub vrf_table: Option<u32>,
    /// The `address` child lines, verbatim.
    pub addresses: Vec<String>,
}

/// One `neighbour` line.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct NeighLine {
    pub ip: Option<IpAddr>,
    pub ifindex: Option<u32>,
    /// The state word, verbatim (`REACHABLE`, `INCOMPLETE|FAILED`, ...).
    pub state: Option<String>,
    /// Colon-separated hex, or `-` while resolution is pending.
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
    /// The owning VRF device's name (`-` = the default table).
    pub vrf: Option<String>,
}

/// A parsed `rousterd.status`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RousterdStatus {
    pub version: Option<String>,
    pub pid: Option<u32>,
    /// The derived router-id (`none` parses to `None`).
    pub router_id: Option<String>,
    /// The interface count the file claimed.
    pub interfaces_claim: Option<u64>,
    pub interfaces: Vec<IfaceLine>,
    /// The neighbour count the file claimed.
    pub neighbours_claim: Option<u64>,
    pub neighbours: Vec<NeighLine>,
    /// The table count the file claimed.
    pub tables_claim: Option<u64>,
    pub tables: Vec<TableLine>,
    /// How many lines matched nothing this version knows.
    pub unknown_lines: usize,
}

impl RousterdStatus {
    /// Parses a status file's content. Never fails: unrecognized or
    /// malformed pieces simply do not populate their fields.
    pub fn parse(text: &str) -> RousterdStatus {
        let mut parsed = RousterdStatus::default();
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
                    // Only a real address renders; a malformed word
                    // leaves the field unset (never guessed).
                    if let Some(value) = tokens.get(1) {
                        if value.parse::<std::net::IpAddr>().is_ok() {
                            parsed.router_id = Some(value.to_string());
                        }
                    }
                }
                "interfaces" => {
                    parsed.interfaces_claim = tokens.get(1).and_then(|t| t.parse().ok())
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
                "neighbours" => {
                    parsed.neighbours_claim = tokens.get(1).and_then(|t| t.parse().ok())
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
                "tables" => parsed.tables_claim = tokens.get(1).and_then(|t| t.parse().ok()),
                "table" => {
                    let mut table = TableLine::default();
                    table.id = tokens.get(1).and_then(|t| t.parse().ok());
                    parse_table_body(&mut table, &tokens[2..]);
                    if table.id.is_some() {
                        parsed.tables.push(table);
                    } else {
                        parsed.unknown_lines += 1;
                    }
                }
                _ => parsed.unknown_lines += 1,
            }
        }
        parsed
    }

    /// The header block every terminal render shares: daemon, pid,
    /// liveness assessment, router-id.
    pub fn header_lines(&self, pid_state: PidState) -> Vec<String> {
        vec![
            format!(
                "rousterd {}  pid {}  {}",
                self.version.as_deref().unwrap_or("?"),
                self.pid
                    .map(|p| p.to_string())
                    .unwrap_or_else(|| "?".into()),
                pid_state.assessment(),
            ),
            format!("router-id {}", self.router_id.as_deref().unwrap_or("none")),
        ]
    }

    /// The interfaces the `name` filter selects (all when `None`).
    pub fn interfaces_matching(&self, name: Option<&str>) -> Vec<&IfaceLine> {
        self.interfaces
            .iter()
            .filter(|iface| name.is_none_or(|want| iface.name.as_deref() == Some(want)))
            .collect()
    }

    /// The neighbours the `prefix` filter selects (all when `None`).
    /// `prefix` is a bare address or a CIDR prefix, either family; a
    /// neighbour matches when its ip falls inside.
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

    /// The VRF devices the dump knows: every interface carrying a
    /// `vrf-table`, with the member count and the owning table line's
    /// counters (when that table is listed).
    pub fn vrfs(&self) -> Vec<VrfView> {
        self.interfaces
            .iter()
            .filter(|iface| iface.vrf_table.is_some())
            .map(|iface| {
                let table = iface.vrf_table.unwrap_or(0);
                let members = self
                    .interfaces
                    .iter()
                    .filter(|member| member.vrf.as_deref() == iface.name.as_deref())
                    .count();
                let counts = self.tables.iter().find(|t| t.id == Some(table));
                VrfView {
                    name: iface.name.clone().unwrap_or_else(|| "?".into()),
                    ifindex: iface.ifindex,
                    table,
                    members,
                    up: iface.up,
                    counts: counts.cloned(),
                }
            })
            .collect()
    }

    /// `show interface`: aligned interface table (or the filter-miss
    /// complaint line).
    pub fn render_interfaces(&self, name: Option<&str>) -> String {
        let selected = self.interfaces_matching(name);
        if let Some(want) = name {
            if selected.is_empty() {
                return format!("(no interface named {want} in the published dump)");
            }
        }
        let headers = [
            "NAME",
            "IFINDEX",
            "STATE",
            "FLAGS",
            "VRF",
            "VRF-TABLE",
            "ADDRESSES",
        ];
        let rows: Vec<[String; 7]> = selected
            .iter()
            .map(|iface| {
                [
                    iface.name.clone().unwrap_or_else(|| "?".into()),
                    iface
                        .ifindex
                        .map(|i| i.to_string())
                        .unwrap_or_else(|| "?".into()),
                    match iface.up {
                        Some(true) => "up".into(),
                        Some(false) => "down".into(),
                        None => "?".into(),
                    },
                    iface.flags.clone().unwrap_or_else(|| "-".into()),
                    dash_none(iface.vrf.as_deref()),
                    iface
                        .vrf_table
                        .map(|t| t.to_string())
                        .unwrap_or_else(|| "-".into()),
                    if iface.addresses.is_empty() {
                        "-".into()
                    } else {
                        iface.addresses.join(" ")
                    },
                ]
            })
            .collect();
        render_table(&headers, &rows)
    }

    /// `show neighbour [PREFIX]`: aligned neighbour table (or the
    /// filter-miss complaint line).
    pub fn render_neighbours(&self, filter: Option<&str>) -> String {
        let selected = self.neighbours_matching(filter);
        if filter.is_some() && selected.is_empty() {
            return "(no neighbour matches the filter in the published dump)".into();
        }
        let headers = ["IP", "IFINDEX", "STATE", "LLADDR"];
        let rows: Vec<[String; 4]> = selected
            .iter()
            .map(|neigh| {
                [
                    neigh
                        .ip
                        .map(|ip| ip.to_string())
                        .unwrap_or_else(|| "?".into()),
                    neigh
                        .ifindex
                        .map(|i| i.to_string())
                        .unwrap_or_else(|| "?".into()),
                    neigh.state.clone().unwrap_or_else(|| "?".into()),
                    neigh.lladdr.clone().unwrap_or_else(|| "?".into()),
                ]
            })
            .collect();
        render_table(&headers, &rows)
    }

    /// `show vrf`: one line per VRF device.
    pub fn render_vrfs(&self) -> String {
        let vrfs = self.vrfs();
        if vrfs.is_empty() {
            return "(no VRF devices mirrored — `ip link add <name> type vrf ...`)".into();
        }
        let headers = [
            "NAME", "IFINDEX", "TABLE", "MEMBERS", "STATE", "ROUTES", "KERNEL",
        ];
        let rows: Vec<[String; 7]> = vrfs
            .iter()
            .map(|vrf| {
                [
                    vrf.name.clone(),
                    vrf.ifindex
                        .map(|i| i.to_string())
                        .unwrap_or_else(|| "?".into()),
                    vrf.table.to_string(),
                    vrf.members.to_string(),
                    match vrf.up {
                        Some(true) => "up".into(),
                        Some(false) => "down".into(),
                        None => "?".into(),
                    },
                    vrf.counts
                        .as_ref()
                        .and_then(|t| t.routes)
                        .map(|n| n.to_string())
                        .unwrap_or_else(|| "-".into()),
                    vrf.counts
                        .as_ref()
                        .and_then(|t| t.kernel)
                        .map(|n| n.to_string())
                        .unwrap_or_else(|| "-".into()),
                ]
            })
            .collect();
        render_table(&headers, &rows)
    }

    /// `show rib summary`: the per-table counts.
    pub fn render_rib_summary(&self) -> String {
        let headers = ["TABLE", "ROUTES", "PREFIXES", "CONNECTED", "KERNEL", "VRF"];
        let rows: Vec<[String; 6]> = self
            .tables
            .iter()
            .map(|table| {
                [
                    table
                        .id
                        .map(|i| i.to_string())
                        .unwrap_or_else(|| "?".into()),
                    opt_u64(table.routes),
                    opt_u64(table.prefixes),
                    opt_u64(table.connected),
                    opt_u64(table.kernel),
                    dash_none(table.vrf.as_deref()),
                ]
            })
            .collect();
        render_table(&headers, &rows)
    }

    /// The unrecognized-line disclosure, when there was one.
    pub fn unknown_disclosure(&self) -> String {
        format!(
            "({} unrecognized line{} — the daemon's format is newer than this rousterctl)\n",
            self.unknown_lines,
            if self.unknown_lines == 1 { "" } else { "s" },
        )
    }

    /// The JSON form of the interface view (one machine-readable
    /// object, hand-escaped — v1 carries no JSON dependency).
    pub fn render_interfaces_json(&self, pid_state: PidState, name: Option<&str>) -> String {
        let selected = self.interfaces_matching(name);
        let rows: Vec<String> = selected
            .iter()
            .map(|iface| {
                format!(
                    "{{\"name\":{},\"ifindex\":{},\"up\":{},\"flags\":{},\"vrf\":{},\"vrf_table\":{},\"addresses\":[{}]}}",
                    json_opt_string(iface.name.as_deref()),
                    json_opt_u32(iface.ifindex),
                    match iface.up {
                        Some(v) => v.to_string(),
                        None => "null".into(),
                    },
                    json_opt_string(iface.flags.as_deref()),
                    json_opt_string(iface.vrf.as_deref().filter(|v| *v != "-")),
                    json_opt_u32(iface.vrf_table),
                    iface
                        .addresses
                        .iter()
                        .map(|a| json_string(a))
                        .collect::<Vec<_>>()
                        .join(","),
                )
            })
            .collect();
        self.json_envelope(pid_state, "interfaces", &rows)
    }

    /// The JSON form of the neighbour view.
    pub fn render_neighbours_json(&self, pid_state: PidState, filter: Option<&str>) -> String {
        let selected = self.neighbours_matching(filter);
        let rows: Vec<String> = selected
            .iter()
            .map(|neigh| {
                format!(
                    "{{\"ip\":{},\"ifindex\":{},\"state\":{},\"lladdr\":{}}}",
                    json_opt_string(neigh.ip.as_ref().map(|ip| ip.to_string()).as_deref()),
                    json_opt_u32(neigh.ifindex),
                    json_opt_string(neigh.state.as_deref()),
                    json_opt_string(neigh.lladdr.as_deref().filter(|l| *l != "-")),
                )
            })
            .collect();
        self.json_envelope(pid_state, "neighbours", &rows)
    }

    /// The JSON form of the VRF view.
    pub fn render_vrfs_json(&self, pid_state: PidState) -> String {
        let rows: Vec<String> = self
            .vrfs()
            .iter()
            .map(|vrf| {
                format!(
                    "{{\"name\":{},\"ifindex\":{},\"table\":{},\"members\":{},\"up\":{},\"routes\":{},\"kernel\":{}}}",
                    json_string(&vrf.name),
                    json_opt_u32(vrf.ifindex),
                    vrf.table,
                    vrf.members,
                    match vrf.up {
                        Some(v) => v.to_string(),
                        None => "null".into(),
                    },
                    json_opt_u64(vrf.counts.as_ref().and_then(|t| t.routes)),
                    json_opt_u64(vrf.counts.as_ref().and_then(|t| t.kernel)),
                )
            })
            .collect();
        self.json_envelope(pid_state, "vrfs", &rows)
    }

    /// The JSON form of the rib summary.
    pub fn render_rib_summary_json(&self, pid_state: PidState) -> String {
        let rows: Vec<String> = self
            .tables
            .iter()
            .map(|table| {
                format!(
                    "{{\"table\":{},\"routes\":{},\"prefixes\":{},\"connected\":{},\"kernel\":{},\"vrf\":{}}}",
                    json_opt_u32(table.id),
                    json_opt_u64(table.routes),
                    json_opt_u64(table.prefixes),
                    json_opt_u64(table.connected),
                    json_opt_u64(table.kernel),
                    json_opt_string(table.vrf.as_deref().filter(|v| *v != "-")),
                )
            })
            .collect();
        self.json_envelope(pid_state, "tables", &rows)
    }

    /// The shared JSON envelope: daemon facts plus the view's rows.
    fn json_envelope(&self, pid_state: PidState, view: &str, rows: &[String]) -> String {
        format!(
            "{{\"daemon\":\"rousterd\",\"version\":{},\"pid\":{},\"pid_state\":\"{}\",\"router_id\":{},\"{view}\":[{}],\"unknown_lines\":{}}}",
            json_opt_string(self.version.as_deref()),
            json_opt_u32(self.pid),
            pid_state.json_word(),
            json_opt_string(self.router_id.as_deref()),
            rows.join(","),
            self.unknown_lines,
        )
    }
}

/// One VRF device's view: the interface that defines it plus the
/// derived member count and its table line's counters.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VrfView {
    pub name: String,
    pub ifindex: Option<u32>,
    pub table: u32,
    pub members: usize,
    pub up: Option<bool>,
    pub counts: Option<TableLine>,
}

/// Header line: `rousterd <version> pid <pid>`, keyword-picked so
/// added fields cannot hide either piece.
fn parse_header(parsed: &mut RousterdStatus, tokens: &[&str]) {
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
/// one of these (a `flags` with its value missing must not eat the
/// next keyword).
const IFACE_KEYWORDS: [&str; 6] = ["ifindex", "up", "down", "flags", "vrf", "vrf-table"];

/// Interface body (after `interface`): the name, then keyword-scanned
/// fields (`ifindex`, `up`/`down`, `flags`, `vrf`, `vrf-table`).
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

/// The token after `index`, when it exists and is not itself a
/// keyword (a keyword in value position means the field's value is
/// missing, not that the keyword is the value).
fn value_of<'a>(tokens: &'a [&'a str], index: usize, keywords: &[&str]) -> Option<&'a str> {
    let value = tokens.get(index + 1)?;
    (!keywords.contains(value)).then_some(*value)
}

/// Keywords of the `neighbour` line.
const NEIGH_KEYWORDS: [&str; 3] = ["ifindex", "state", "lladdr"];

/// Neighbour body (after `neighbour`): the ip, then keyword-scanned
/// `ifindex`/`state`/`lladdr`.
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

/// Table body (after `table <id>`): keyword-scanned counters and the
/// owning `vrf`.
const TABLE_KEYWORDS: [&str; 6] = [
    "routes",
    "prefixes",
    "connected",
    "kernel",
    "vrf",
    "vrf-table",
];

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

/// A parsed neighbour filter: either family, bare address or CIDR
/// prefix (a bare address is a /32 or /128).
struct Filter {
    base: u128,
    width: u32,
    family_v4: bool,
}

impl Filter {
    fn contains(&self, ip: IpAddr) -> bool {
        match ip {
            IpAddr::V4(v4) if self.family_v4 => {
                let addr = u32::from(v4) as u128;
                in_window(addr, self.base, self.width.min(32), 32)
            }
            IpAddr::V6(v6) if !self.family_v4 => {
                in_window(u128::from(v6), self.base, self.width.min(128), 128)
            }
            _ => false,
        }
    }
}

/// Is `addr` inside `base/width` (an `family_len`-bit family)?
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

/// Is this filter token shape-valid (for the args-layer usage error)?
/// Accepts either family, bare or CIDR.
pub fn valid_filter(text: &str) -> bool {
    parse_filter(text).is_some()
}

/// The aligned table (two-space gutters), shared by every view.
fn render_table<const N: usize>(headers: &[&str], rows: &[[String; N]]) -> String {
    let columns = headers.len();
    let widths: Vec<usize> = (0..columns)
        .map(|column| {
            rows.iter()
                .map(|row| row[column].len())
                .chain([headers[column].len()])
                .max()
                .unwrap_or(0)
        })
        .collect();
    let mut out = String::new();
    let header_cells: Vec<String> = headers
        .iter()
        .enumerate()
        .map(|(column, header)| format!("{header:<width$}", width = widths[column]))
        .collect();
    out.push_str(&header_cells.join("  "));
    out.push('\n');
    for row in rows {
        let cells: Vec<String> = row
            .iter()
            .enumerate()
            .map(|(column, cell)| format!("{cell:<width$}", width = widths[column]))
            .collect();
        out.push_str(&cells.join("  "));
        out.push('\n');
    }
    out
}

/// `-` for the `-`/unset marker the dump uses.
fn dash_none(value: Option<&str>) -> String {
    match value {
        Some("-") | None => "-".into(),
        Some(other) => other.to_string(),
    }
}

fn opt_u64(value: Option<u64>) -> String {
    value.map(|v| v.to_string()).unwrap_or_else(|| "-".into())
}

/// Escapes a string for embedding in a JSON string literal.
fn json_escape(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for character in text.chars() {
        match character {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            control if (control as u32) < 0x20 => {
                out.push_str(&format!("\\u{:04x}", control as u32));
            }
            other => out.push(other),
        }
    }
    out
}

fn json_opt_string(text: Option<&str>) -> String {
    match text {
        Some(text) => format!("\"{}\"", json_escape(text)),
        None => "null".into(),
    }
}

fn json_string(text: &str) -> String {
    format!("\"{}\"", json_escape(text))
}

fn json_opt_u32(value: Option<u32>) -> String {
    match value {
        Some(value) => value.to_string(),
        None => "null".into(),
    }
}

fn json_opt_u64(value: Option<u64>) -> String {
    match value {
        Some(value) => value.to_string(),
        None => "null".into(),
    }
}
