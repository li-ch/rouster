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
//! Tolerance contract (the S3 rules, the daemon's format may grow;
//! owned by the ONE shared reader, `common::rundir` — the N8
//! consolidation): unknown *lines* are counted and dropped; known
//! *keywords* are picked out wherever they sit on their line, so
//! added fields ride along harmlessly; indented `address` lines
//! attach to the interface above them; a malformed number leaves its
//! field unset rather than failing the parse. Parsing never fails.
//! This module is rousterctl's projection: the reader's typed result
//! plus the CLI's filters and renderers.

use common::rundir;

use crate::liveness::PidState;

/// The dump's line shapes, as the shared reader types them.
pub use common::rundir::{IfaceLine, NeighLine, TableLine};

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
    /// Parses a status file's content (the shared reader, mapped).
    /// Never fails: unrecognized or malformed pieces simply do not
    /// populate their fields.
    pub fn parse(text: &str) -> RousterdStatus {
        rundir::parse_rousterd(text).into()
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
        rundir::interfaces_matching(&self.interfaces, name)
    }

    /// The neighbours the `prefix` filter selects (all when `None`).
    /// `prefix` is a bare address or a CIDR prefix, either family; a
    /// neighbour matches when its ip falls inside.
    pub fn neighbours_matching(&self, filter: Option<&str>) -> Vec<&NeighLine> {
        rundir::neighbours_matching(&self.neighbours, filter)
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

/// The reader's result, mapped one-to-one (this crate keeps the
/// count claims; the vty projection drops them).
impl From<rundir::RousterdStatus> for RousterdStatus {
    fn from(parsed: rundir::RousterdStatus) -> RousterdStatus {
        RousterdStatus {
            version: parsed.version,
            pid: parsed.pid,
            router_id: parsed.router_id,
            interfaces_claim: parsed.interfaces_claim,
            interfaces: parsed.interfaces,
            neighbours_claim: parsed.neighbours_claim,
            neighbours: parsed.neighbours,
            tables_claim: parsed.tables_claim,
            tables: parsed.tables,
            unknown_lines: parsed.unknown_lines,
        }
    }
}

/// Is this filter token shape-valid (for the args-layer usage error)?
/// Accepts either family, bare or CIDR (the shared reader's
/// validator).
pub fn valid_filter(text: &str) -> bool {
    rundir::accepts_addr_or_prefix(text)
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
