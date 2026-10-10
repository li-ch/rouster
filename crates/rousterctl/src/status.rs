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
//! ```
//!
//! Tolerance contract (the daemon's format may grow): unknown lines
//! are counted and dropped; known keywords are picked out wherever
//! they sit on their line, so added fields ride along harmlessly; a
//! `rule` line matching no known shape is kept verbatim as a
//! [`RuleLine::Raw`] so no operator data is lost. Parsing never
//! fails — whatever is recognized is reported.

use crate::liveness::PidState;

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

/// The `config` line's recognized keywords; unrecognized ones are
/// ignored (the format may grow).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ConfigLine {
    /// e.g. `strict-uRPF`.
    pub mode: Option<String>,
    /// e.g. `monitor`.
    pub action: Option<String>,
    /// The `poll Ns` cadence.
    pub poll_secs: Option<u64>,
    /// The configured interface stanza count.
    pub interfaces: Option<u64>,
    /// The configured binding line count.
    pub bindings: Option<u64>,
}

/// The `monitor` line's counters; each is individually optional so a
/// malformed one does not erase its siblings.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct MonitorLine {
    /// `simulation` or `dataplane`.
    pub source: Option<String>,
    /// Sources judged invalid.
    pub invalid: Option<u64>,
    /// Sources judged valid.
    pub valid: Option<u64>,
    /// Sources no rule judged.
    pub unknown: Option<u64>,
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
    /// How many lines matched nothing this version knows.
    pub unknown_lines: usize,
}

impl SavStatus {
    /// Parses a status file's content. Never fails: unrecognized or
    /// malformed pieces simply do not populate their fields.
    pub fn parse(text: &str) -> SavStatus {
        let mut parsed = SavStatus::default();
        for line in text.lines() {
            let line = line.trim_end_matches('\r').trim_end();
            if line.is_empty() {
                continue;
            }
            let tokens: Vec<&str> = line.split_whitespace().collect();
            match tokens[0] {
                "savd" => parse_header(&mut parsed, &tokens),
                "config" => parse_config(&mut parsed.config, &tokens),
                "installed" => parse_installed(&mut parsed, &tokens),
                "rule" => {
                    let raw = line.strip_prefix("rule ").unwrap_or(line);
                    parsed.rules.push(parse_rule(raw));
                }
                "monitor" => parse_monitor(&mut parsed.monitor, &tokens),
                _ => parsed.unknown_lines += 1,
            }
        }
        parsed
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
        format!(
            "{{\"daemon\":\"savd\",\"version\":{},\"pid\":{},\"pid_state\":\"{state}\",\"config\":{config},\"evaluated\":{},\"installed_rules\":{},\"rules\":[{}],\"monitor\":{{\"source\":{},\"invalid\":{},\"valid\":{},\"unknown\":{}}},\"unknown_lines\":{}}}",
            json_opt_string(self.version.as_deref()),
            json_opt_u32(self.pid),
            json_bool(self.evaluated),
            json_opt_u64(self.installed_claim),
            rules.join(","),
            json_opt_string(self.monitor.source.as_deref()),
            json_opt_u64(self.monitor.invalid),
            json_opt_u64(self.monitor.valid),
            json_opt_u64(self.monitor.unknown),
            self.unknown_lines,
        )
    }
}

/// Header line: `savd <version> pid <pid>` — both pieces are picked
/// out by keyword so future header fields cannot hide them.
fn parse_header(parsed: &mut SavStatus, tokens: &[&str]) {
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

/// Config line: keyword/value pairs scanned wherever they sit, so
/// reordered or newly added keywords ride along harmlessly.
fn parse_config(config: &mut ConfigLine, tokens: &[&str]) {
    for (index, token) in tokens.iter().enumerate().skip(1) {
        let Some(value) = tokens.get(index + 1) else {
            break;
        };
        match *token {
            "mode" => config.mode = Some(value.to_string()),
            "action" => config.action = Some(value.to_string()),
            "poll" => config.poll_secs = value.strip_suffix('s').unwrap_or(value).parse().ok(),
            "interfaces" => config.interfaces = value.parse().ok(),
            "bindings" => config.bindings = value.parse().ok(),
            _ => {}
        }
    }
}

/// Installed line: `installed <N> rules` (optionally `(never
/// evaluated)`). A count we cannot read makes the line unrecognized.
fn parse_installed(parsed: &mut SavStatus, tokens: &[&str]) {
    let never = tokens.contains(&"(never");
    match tokens.get(1).and_then(|token| token.parse::<u64>().ok()) {
        Some(count) => {
            parsed.installed_claim = Some(count);
            parsed.evaluated = Some(!never);
        }
        None if never => parsed.evaluated = Some(false),
        None => parsed.unknown_lines += 1,
    }
}

/// Monitor line: `monitor source <s> invalid=<n> valid=<n>
/// unknown=<n>`, keyword-scanned so added counters are ignored.
fn parse_monitor(monitor: &mut MonitorLine, tokens: &[&str]) {
    for (index, token) in tokens.iter().enumerate().skip(1) {
        if *token == "source" {
            if let Some(value) = tokens.get(index + 1) {
                monitor.source = Some(value.to_string());
            }
            continue;
        }
        if let Some((key, value)) = token.split_once('=') {
            let number = value.parse().ok();
            match key {
                "invalid" => monitor.invalid = number,
                "valid" => monitor.valid = number,
                "unknown" => monitor.unknown = number,
                _ => {}
            }
        }
    }
}

/// One rule body (after `rule `): the four shapes savd renders today,
/// falling back to [`RuleLine::Raw`] for anything else.
fn parse_rule(raw: &str) -> RuleLine {
    let tokens: Vec<&str> = raw.split_whitespace().collect();
    let Some(&polarity) = tokens.first() else {
        return RuleLine::Raw(raw.to_string());
    };
    // Interface scale: `allow if#N [prefixes] (urpf) action`.
    if let Some(second) = tokens.get(1) {
        if let Some(index_text) = second.strip_prefix("if#") {
            let Some(ifindex) = index_text.parse::<u32>().ok() else {
                return RuleLine::Raw(raw.to_string());
            };
            let Some((prefixes, tail)) = bracket_set(&tokens[2..]) else {
                return RuleLine::Raw(raw.to_string());
            };
            return match (polarity, tail.as_slice()) {
                ("allow", [urpf, action]) => RuleLine::IfaceAllow {
                    ifindex,
                    prefixes,
                    urpf: (*urpf).to_string(),
                    action: (*action).to_string(),
                },
                ("block", [action]) => RuleLine::IfaceBlock {
                    ifindex,
                    prefixes,
                    action: (*action).to_string(),
                },
                _ => RuleLine::Raw(raw.to_string()),
            };
        }
    }
    // Router scale: `allow PREFIX if [ifindexes] action`.
    if tokens.get(2) == Some(&"if") {
        let prefix = tokens[1].to_string();
        let Some((members, tail)) = bracket_set(&tokens[3..]) else {
            return RuleLine::Raw(raw.to_string());
        };
        let ifindexes: Option<Vec<u32>> = members.iter().map(|m| m.parse().ok()).collect();
        let Some(ifindexes) = ifindexes else {
            return RuleLine::Raw(raw.to_string());
        };
        return match (polarity, tail.as_slice()) {
            ("allow", [action]) => RuleLine::PrefixAllow {
                prefix,
                ifindexes,
                action: (*action).to_string(),
            },
            ("block", [action]) => RuleLine::PrefixBlock {
                prefix,
                ifindexes,
                action: (*action).to_string(),
            },
            _ => RuleLine::Raw(raw.to_string()),
        };
    }
    RuleLine::Raw(raw.to_string())
}

/// Splits a token slice at its bracketed `[...]` set: the set's
/// members and the tokens after the closing `]`. `None` when the
/// slice does not start at `[` or the set never closes.
fn bracket_set<'a>(tokens: &'a [&'a str]) -> Option<(Vec<String>, Vec<&'a str>)> {
    let first = tokens.first()?;
    if !first.starts_with('[') {
        return None;
    }
    let mut end = 0;
    while end < tokens.len() && !tokens[end].ends_with(']') {
        end += 1;
    }
    if end == tokens.len() {
        return None;
    }
    let inner = tokens[..=end].join(" ");
    let inner = inner.trim_start_matches('[').trim_end_matches(']');
    let members = inner
        .split(", ")
        .filter(|member| !member.is_empty())
        .map(|member| member.to_string())
        .collect();
    Some((members, tokens[end + 1..].to_vec()))
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
