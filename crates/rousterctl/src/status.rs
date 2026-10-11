//! Parsing and rendering of savd's published status file.
//!
//! The file is line-based, written by savd after every evaluate (the
//! A21 surface):
//!
//! ```text
//! savd 0.0.0 pid 4242
//! config mode strict-uRPF action monitor poll 5s interfaces 2 bindings 0
//! installed 2 rules
//! rule allow if#2 [198.51.100.0/24] strict monitor
//! monitor source simulation invalid=0 valid=0 unknown=0
//! count iba permit #2 [198.51.100.0/24] monitor invalid=0 valid=3 unknown=0
//! ```
//!
//! Tolerance contract (the daemon's format may grow; owned by the
//! ONE shared reader, `common::rundir` — the N8 consolidation):
//! unknown lines are counted and dropped; known keywords are picked
//! out wherever they sit on their line, so added fields ride along
//! harmlessly; a `rule` line matching no known shape is kept verbatim
//! as a [`RuleLine::Raw`] so no operator data is lost. Parsing never
//! fails — whatever is recognized is reported.
//!
//! This module is rousterctl's projection: the reader's typed result
//! mapped onto the CLI's [`RuleLine`] shape, plus the terminal and
//! JSON renderers.

use common::rundir;

use crate::liveness::PidState;

/// The `config` line's recognized keywords (the reader's
/// [`common::rundir::SavConfig`], under the name this crate's public
/// surface has always used).
pub use common::rundir::SavConfig as ConfigLine;

/// The `monitor` line's counters (the reader's
/// [`common::rundir::SavMonitor`], ditto).
pub use common::rundir::SavMonitor as MonitorLine;

/// One per-op `count` line (the reader's
/// [`common::rundir::SavCount`], ditto — GSC §4 "count").
pub use common::rundir::SavCount as CountLine;

/// One `rule` line: the four op shapes savd renders today, plus the
/// verbatim fallback for shapes this version does not know.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RuleLine {
    /// `allow if#N [prefixes] urpf action` (IBA).
    IfaceAllow {
        ifindex: u32,
        prefixes: Vec<String>,
        urpf: String,
        action: String,
    },
    /// `block if#N [prefixes] action` (IBB).
    IfaceBlock {
        ifindex: u32,
        prefixes: Vec<String>,
        action: String,
    },
    /// `allow PREFIX if [ifindexes] action` (PBA).
    PrefixAllow {
        prefix: String,
        ifindexes: Vec<u32>,
        action: String,
    },
    /// `block PREFIX if [ifindexes] action` (PBB).
    PrefixBlock {
        prefix: String,
        ifindexes: Vec<u32>,
        action: String,
    },
    /// A rule shape this version does not know, verbatim.
    Raw(String),
}

impl RuleLine {
    /// The `allow`/`block` polarity (blank for raw lines).
    pub fn polarity(&self) -> &str {
        match self {
            RuleLine::IfaceAllow { .. } | RuleLine::PrefixAllow { .. } => "allow",
            RuleLine::IfaceBlock { .. } | RuleLine::PrefixBlock { .. } => "block",
            RuleLine::Raw(_) => "",
        }
    }

    /// The enforcement action (`monitor`/`drop`, blank for raw lines).
    pub fn action(&self) -> &str {
        match self {
            RuleLine::IfaceAllow { action, .. }
            | RuleLine::IfaceBlock { action, .. }
            | RuleLine::PrefixAllow { action, .. }
            | RuleLine::PrefixBlock { action, .. } => action,
            RuleLine::Raw(_) => "",
        }
    }

    /// The rule's anchor: `if#N` for interface-scale rules, the prefix
    /// for router-scale rules (the raw text for raw lines).
    pub fn target(&self) -> String {
        match self {
            RuleLine::IfaceAllow { ifindex, .. } | RuleLine::IfaceBlock { ifindex, .. } => {
                format!("if#{ifindex}")
            }
            RuleLine::PrefixAllow { prefix, .. } | RuleLine::PrefixBlock { prefix, .. } => {
                prefix.clone()
            }
            RuleLine::Raw(text) => text.clone(),
        }
    }

    /// The rule's member set, rendered `[a, b]` like the source line.
    pub fn members(&self) -> String {
        match self {
            RuleLine::IfaceAllow { prefixes, .. } | RuleLine::IfaceBlock { prefixes, .. } => {
                format!("[{}]", prefixes.join(", "))
            }
            RuleLine::PrefixAllow { ifindexes, .. } | RuleLine::PrefixBlock { ifindexes, .. } => {
                let items: Vec<String> = ifindexes.iter().map(|i| i.to_string()).collect();
                format!("[{}]", items.join(", "))
            }
            RuleLine::Raw(_) => String::new(),
        }
    }

    /// The generator-semantics hint (`strict`/`loose`); blank where
    /// the op shape carries none (and for raw lines).
    pub fn urpf(&self) -> &str {
        match self {
            RuleLine::IfaceAllow { urpf, .. } => urpf,
            _ => "",
        }
    }
}

/// A parsed `savd.status`: everything this version recognized.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SavStatus {
    /// The daemon's version string.
    pub version: Option<String>,
    /// The pid the daemon recorded.
    pub pid: Option<u32>,
    /// The running-config summary.
    pub config: ConfigLine,
    /// `Some(false)` when the file said `(never evaluated)`.
    pub evaluated: Option<bool>,
    /// The rule count the file claimed.
    pub installed_claim: Option<u64>,
    /// The rule lines, in file order (`Raw` keeps unknown shapes).
    pub rules: Vec<RuleLine>,
    /// The last evaluate's monitor counters.
    pub monitor: MonitorLine,
    /// The per-op `count` lines, in file order (GSC §4 "count"; only
    /// ops that judged something render).
    pub counts: Vec<CountLine>,
    /// How many lines matched nothing this version knows.
    pub unknown_lines: usize,
}

impl SavStatus {
    /// Parses a status file's content (the shared reader, mapped).
    /// Never fails: unrecognized or malformed pieces simply do not
    /// populate their fields.
    pub fn parse(text: &str) -> SavStatus {
        rundir::parse_savd(text).into()
    }

    /// Renders the status for a terminal: aligned rule table, config,
    /// counters, and the pid liveness assessment.
    pub fn render_terminal(&self, pid_state: PidState) -> String {
        let pid = self
            .pid
            .map(|p| p.to_string())
            .unwrap_or_else(|| "?".into());
        let assessment = match pid_state {
            PidState::Running => "running",
            PidState::Dead => "dead (stale files)",
            PidState::Unknown => "liveness unknown",
        };
        let mut out = format!(
            "savd {}  pid {pid}  {assessment}\n",
            self.version.as_deref().unwrap_or("?"),
        );

        out.push_str("config");
        if let Some(mode) = &self.config.mode {
            out.push_str(&format!("  mode {mode}"));
        }
        if let Some(action) = &self.config.action {
            out.push_str(&format!("  action {action}"));
        }
        if let Some(secs) = self.config.poll_secs {
            out.push_str(&format!("  poll {secs}s"));
        }
        if let Some(interfaces) = self.config.interfaces {
            out.push_str(&format!("  interfaces {interfaces}"));
        }
        if let Some(bindings) = self.config.bindings {
            out.push_str(&format!("  bindings {bindings}"));
        }
        out.push('\n');

        match (self.installed_claim, self.evaluated) {
            (Some(count), Some(false)) => {
                out.push_str(&format!("installed {count} rules (never evaluated)\n"))
            }
            (Some(count), _) => out.push_str(&format!("installed {count} rules\n")),
            (None, _) => out.push_str("installed ? rules\n"),
        }

        if !self.rules.is_empty() {
            out.push('\n');
            out.push_str(&render_rule_table(&self.rules));
            out.push('\n');
        }

        out.push_str("monitor");
        if let Some(source) = &self.monitor.source {
            out.push_str(&format!("  source {source}"));
        }
        if let Some(invalid) = self.monitor.invalid {
            out.push_str(&format!("  invalid={invalid}"));
        }
        if let Some(valid) = self.monitor.valid {
            out.push_str(&format!("  valid={valid}"));
        }
        if let Some(unknown) = self.monitor.unknown {
            out.push_str(&format!("  unknown={unknown}"));
        }
        out.push('\n');

        // The per-op cut of the same view (GSC §4 "count"): one line
        // per op that judged something, the op rendered as the file
        // carries it.
        for count in &self.counts {
            out.push_str("count");
            out.push_str(&format!("  {}", count.op));
            if let Some(invalid) = count.invalid {
                out.push_str(&format!("  invalid={invalid}"));
            }
            if let Some(valid) = count.valid {
                out.push_str(&format!("  valid={valid}"));
            }
            if let Some(unknown) = count.unknown {
                out.push_str(&format!("  unknown={unknown}"));
            }
            out.push('\n');
        }

        if self.unknown_lines > 0 {
            out.push_str(&format!(
                "({} unrecognized line{} — the daemon's format is newer than this rousterctl)\n",
                self.unknown_lines,
                if self.unknown_lines == 1 { "" } else { "s" },
            ));
        }
        out
    }

    /// Renders the status as one compact JSON object (hand-built and
    /// escaped — v1 carries no JSON dependency).
    pub fn render_json(&self, pid_state: PidState) -> String {
        let state = match pid_state {
            PidState::Running => "running",
            PidState::Dead => "dead",
            PidState::Unknown => "unknown",
        };
        let config = format!(
            "{{\"mode\":{},\"action\":{},\"poll_secs\":{},\"interfaces\":{},\"bindings\":{}}}",
            json_opt_string(self.config.mode.as_deref()),
            json_opt_string(self.config.action.as_deref()),
            json_opt_u64(self.config.poll_secs),
            json_opt_u64(self.config.interfaces),
            json_opt_u64(self.config.bindings),
        );
        let rules: Vec<String> = self
            .rules
            .iter()
            .map(|rule| match rule {
                RuleLine::IfaceAllow {
                    ifindex,
                    prefixes,
                    urpf,
                    action,
                } => format!(
                    "{{\"kind\":\"iface-allow\",\"ifindex\":{ifindex},\"prefixes\":{},\"urpf\":{},\"action\":{}}}",
                    json_strings(prefixes),
                    json_string(urpf),
                    json_string(action),
                ),
                RuleLine::IfaceBlock {
                    ifindex,
                    prefixes,
                    action,
                } => format!(
                    "{{\"kind\":\"iface-block\",\"ifindex\":{ifindex},\"prefixes\":{},\"action\":{}}}",
                    json_strings(prefixes),
                    json_string(action),
                ),
                RuleLine::PrefixAllow {
                    prefix,
                    ifindexes,
                    action,
                } => format!(
                    "{{\"kind\":\"prefix-allow\",\"prefix\":{},\"ifindexes\":[{}],\"action\":{}}}",
                    json_string(prefix),
                    ifindexes
                        .iter()
                        .map(|i| i.to_string())
                        .collect::<Vec<_>>()
                        .join(","),
                    json_string(action),
                ),
                RuleLine::PrefixBlock {
                    prefix,
                    ifindexes,
                    action,
                } => format!(
                    "{{\"kind\":\"prefix-block\",\"prefix\":{},\"ifindexes\":[{}],\"action\":{}}}",
                    json_string(prefix),
                    ifindexes
                        .iter()
                        .map(|i| i.to_string())
                        .collect::<Vec<_>>()
                        .join(","),
                    json_string(action),
                ),
                RuleLine::Raw(text) => format!(
                    "{{\"kind\":\"raw\",\"raw\":{}}}",
                    json_string(text),
                ),
            })
            .collect();
        let counts: Vec<String> = self
            .counts
            .iter()
            .map(|count| {
                format!(
                    "{{\"op\":{},\"invalid\":{},\"valid\":{},\"unknown\":{}}}",
                    json_string(&count.op),
                    json_opt_u64(count.invalid),
                    json_opt_u64(count.valid),
                    json_opt_u64(count.unknown),
                )
            })
            .collect();
        format!(
            "{{\"daemon\":\"savd\",\"version\":{},\"pid\":{},\"pid_state\":\"{state}\",\"config\":{config},\"evaluated\":{},\"installed_rules\":{},\"rules\":[{}],\"monitor\":{{\"source\":{},\"invalid\":{},\"valid\":{},\"unknown\":{}}},\"counts\":[{}],\"unknown_lines\":{}}}",
            json_opt_string(self.version.as_deref()),
            json_opt_u32(self.pid),
            json_bool(self.evaluated),
            json_opt_u64(self.installed_claim),
            rules.join(","),
            json_opt_string(self.monitor.source.as_deref()),
            json_opt_u64(self.monitor.invalid),
            json_opt_u64(self.monitor.valid),
            json_opt_u64(self.monitor.unknown),
            counts.join(","),
            self.unknown_lines,
        )
    }
}

/// The reader's result mapped onto the CLI's shapes. The rule
/// polarity split is total: the reader's `Iface`/`Prefix` variants
/// only ever carry `allow`/`block` (anything else degraded to `Raw`
/// at parse time), and the allow shape always carries its urpf hint.
impl From<rundir::SavStatus> for SavStatus {
    fn from(parsed: rundir::SavStatus) -> SavStatus {
        SavStatus {
            version: parsed.version,
            pid: parsed.pid,
            config: parsed.config,
            evaluated: parsed.evaluated,
            installed_claim: parsed.installed_claim,
            rules: parsed.rules.into_iter().map(RuleLine::from).collect(),
            monitor: parsed.monitor,
            counts: parsed.counts,
            unknown_lines: parsed.unknown_lines,
        }
    }
}

impl From<rundir::SavRule> for RuleLine {
    fn from(rule: rundir::SavRule) -> RuleLine {
        match rule {
            rundir::SavRule::Iface {
                polarity,
                ifindex,
                prefixes,
                urpf,
                action,
            } => match polarity.as_str() {
                "allow" => RuleLine::IfaceAllow {
                    ifindex,
                    prefixes,
                    urpf: urpf.unwrap_or_default(),
                    action,
                },
                _ => RuleLine::IfaceBlock {
                    ifindex,
                    prefixes,
                    action,
                },
            },
            rundir::SavRule::Prefix {
                polarity,
                prefix,
                ifindexes,
                action,
            } => match polarity.as_str() {
                "allow" => RuleLine::PrefixAllow {
                    prefix,
                    ifindexes,
                    action,
                },
                _ => RuleLine::PrefixBlock {
                    prefix,
                    ifindexes,
                    action,
                },
            },
            rundir::SavRule::Raw(text) => RuleLine::Raw(text),
        }
    }
}

/// The aligned rule table (two-space gutters; `-` marks a cell the
/// op shape does not carry).
fn render_rule_table(rules: &[RuleLine]) -> String {
    let headers = ["IDX", "POLARITY", "TARGET", "MEMBERS", "URPF", "ACTION"];
    let rows: Vec<[String; 6]> = rules
        .iter()
        .enumerate()
        .map(|(index, rule)| {
            [
                (index + 1).to_string(),
                dash_empty(rule.polarity()),
                rule.target(),
                dash_empty(&rule.members()),
                dash_empty(rule.urpf()),
                dash_empty(rule.action()),
            ]
        })
        .collect();

    let widths: Vec<usize> = (0..headers.len())
        .map(|column| {
            rows.iter()
                .map(|row| row[column].len())
                .chain([headers[column].len()])
                .max()
                .unwrap_or(0)
        })
        .collect();

    let mut table = String::new();
    let header_cells: Vec<String> = headers
        .iter()
        .enumerate()
        .map(|(column, header)| format!("{header:<width$}", width = widths[column]))
        .collect();
    table.push_str(&header_cells.join("  "));
    table.push('\n');
    for row in rows {
        let cells: Vec<String> = row
            .iter()
            .enumerate()
            .map(|(column, cell)| format!("{cell:<width$}", width = widths[column]))
            .collect();
        table.push_str(&cells.join("  "));
        table.push('\n');
    }
    table
}

/// `-` for the empty cells a rule shape does not carry.
fn dash_empty(text: &str) -> String {
    if text.is_empty() {
        "-".into()
    } else {
        text.to_string()
    }
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

/// A JSON string literal (or `null`).
fn json_opt_string(text: Option<&str>) -> String {
    match text {
        Some(text) => format!("\"{}\"", json_escape(text)),
        None => "null".into(),
    }
}

fn json_string(text: &str) -> String {
    format!("\"{}\"", json_escape(text))
}

fn json_strings(items: &[String]) -> String {
    let items: Vec<String> = items.iter().map(|item| json_string(item)).collect();
    format!("[{}]", items.join(","))
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

fn json_bool(value: Option<bool>) -> String {
    match value {
        Some(value) => value.to_string(),
        None => "null".into(),
    }
}
