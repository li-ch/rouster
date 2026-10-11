//! The run-dir status reader — ONE tolerant parser for the three
//! status files Rouster daemons publish (`docs/operator-surfaces.md`
//! §2): `savd.status`, `bfdd.status`, `rousterd.status`.
//!
//! Placement (N8, disclosed): common normally hosts core-adjacent
//! shared types; this module is the sanctioned exception — the shared
//! *edge plumbing* both operator surfaces (rousterctl, vty) read the
//! same files through, so the parser exists once instead of once per
//! consumer. The module is std-only like the rest of the reader
//! contract.
//!
//! The tolerance contract (the S3 semantics; the formats are the
//! daemons' to grow, readers adapt, never the reverse):
//!
//! - unknown *lines* are counted (`unknown_lines`) and dropped;
//! - known *keywords* are picked out wherever they sit on their line,
//!   so fields added later ride along harmlessly;
//! - a value position never swallows another keyword (a `flags` whose
//!   value is missing does not eat the next word);
//! - a `rule` line matching no known shape is kept verbatim
//!   ([`SavRule::Raw`]) so no operator data is lost;
//! - a malformed number leaves its field unset rather than failing
//!   the parse.
//!
//! Parsing never fails: whatever is recognized is reported. The
//! fixture corpus pinning all three formats lives in
//! `crates/common/tests/fixtures/` (the union of the per-consumer
//! corpora; the consumers keep their mirrors for their own suites).

use std::net::IpAddr;

// ------------------------------------------------------------ the engine

/// One normalized line of a status file: CR and trailing whitespace
/// trimmed, blank lines skipped, indentation flagged.
struct Line<'a> {
    /// The trimmed line (leading whitespace intact — child detection
    /// needs it, and verbatim fallbacks keep it).
    text: &'a str,
    /// The line began with whitespace (a child of the entry above).
    child: bool,
}

/// The normalized non-empty lines of a status file, in file order.
fn normalized_lines(text: &str) -> impl Iterator<Item = Line<'_>> {
    text.lines().filter_map(|raw| {
        let text = raw.trim_end_matches('\r').trim_end();
        if text.is_empty() {
            return None;
        }
        Some(Line {
            child: text.starts_with(' ') || text.starts_with('\t'),
            text,
        })
    })
}

/// The unknown-line tally is the engine's bookkeeping, not each
/// handler's: a handler that cannot honestly claim its line returns
/// `false` and the engine counts it.
trait Tally {
    fn bump_unknown(&mut self);
}

/// One table entry: the handler for lines whose first token is
/// `kind`. Returning `false` means "not recognized after all" (the
/// engine counts the line unknown).
type Handler<S> = fn(state: &mut S, tokens: &[&str], line: &str) -> bool;

/// How a format treats child (indented) lines.
enum Children<S> {
    /// No child grammar: indented lines flow through the main table
    /// like any other (savd — the daemon writes no child lines, and
    /// the historical readers never special-cased them).
    Through,
    /// Child lines attach to the entry above (`address` on
    /// interfaces, `last-transition` on sessions); the handler
    /// returns `false` when the body is not its child kind, and then
    /// the line counts unknown.
    Attach(fn(state: &mut S, line: &str) -> bool),
}

/// One format's parser table: first-token dispatch over the shared
/// tolerant reader.
struct Format<'a, S> {
    children: Children<S>,
    entries: &'a [(&'a str, Handler<S>)],
}

/// The tolerant reader every format runs on: walk the normalized
/// lines, hand each to its table entry (or the child policy), and
/// count what nothing claims. This is the single loop that used to
/// exist in three copies.
fn read<S: Default + Tally>(text: &str, format: Format<'_, S>) -> S {
    let mut state = S::default();
    for line in normalized_lines(text) {
        if line.child {
            if let Children::Attach(attach) = format.children {
                if attach(&mut state, line.text) {
                    continue;
                }
                state.bump_unknown();
                continue;
            }
        }
        let tokens: Vec<&str> = line.text.split_whitespace().collect();
        // A normalized line always carries at least one token.
        let first = tokens[0];
        let mut recognized = false;
        for (kind, handler) in format.entries {
            if first == *kind {
                recognized = handler(&mut state, &tokens, line.text);
                break;
            }
        }
        if !recognized {
            state.bump_unknown();
        }
    }
    state
}

// ------------------------------------------------------ shared primitives

/// Header line, shared shape: `<daemon> <version> ... pid <pid>` —
/// both pieces picked out by keyword so future header fields cannot
/// hide them.
fn daemon_header(tokens: &[&str]) -> (Option<String>, Option<u32>) {
    let mut out = (None, None);
    if let Some(version) = tokens.get(1) {
        if *version != "pid" {
            out.0 = Some(version.to_string());
        }
    }
    if let Some(position) = tokens.iter().position(|token| *token == "pid") {
        if let Some(value) = tokens.get(position + 1) {
            out.1 = value.parse().ok();
        }
    }
    out
}

/// The token after `index`, when it exists and is not itself one of
/// `keywords` (a keyword in value position means the field's value is
/// missing, not that the keyword is the value).
fn value_of<'a>(tokens: &'a [&'a str], index: usize, keywords: &[&str]) -> Option<&'a str> {
    let value = tokens.get(index + 1)?;
    (!keywords.contains(value)).then_some(*value)
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

// ------------------------------------------------------------ savd.status

/// One `rule` line: the four op shapes savd renders today, plus the
/// verbatim fallback for shapes this reader does not know.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SavRule {
    /// `allow|block if#N [prefixes] (urpf) action` (interface scale).
    Iface {
        /// `allow` or `block`.
        polarity: String,
        /// The rule's ifindex.
        ifindex: u32,
        /// The prefix set.
        prefixes: Vec<String>,
        /// The generator hint (`strict`/`loose`); `Some` only on the
        /// allow shape, which carries it.
        urpf: Option<String>,
        /// The enforcement action.
        action: String,
    },
    /// `allow|block PREFIX if [ifindexes] action` (router scale).
    Prefix {
        /// `allow` or `block`.
        polarity: String,
        /// The anchored prefix.
        prefix: String,
        /// The member ifindex set.
        ifindexes: Vec<u32>,
        /// The enforcement action.
        action: String,
    },
    /// A rule shape this reader does not know, verbatim.
    Raw(String),
}

impl SavRule {
    /// Row cells for the rule table every consumer renders:
    /// (polarity, target, members, urpf, action) — blank where the op
    /// shape carries nothing.
    pub fn cells(&self) -> [String; 5] {
        match self {
            SavRule::Iface {
                polarity,
                ifindex,
                prefixes,
                urpf,
                action,
            } => [
                polarity.clone(),
                format!("if#{ifindex}"),
                format!("[{}]", prefixes.join(", ")),
                urpf.clone().unwrap_or_default(),
                action.clone(),
            ],
            SavRule::Prefix {
                polarity,
                prefix,
                ifindexes,
                action,
            } => {
                let members: Vec<String> = ifindexes.iter().map(|i| i.to_string()).collect();
                [
                    polarity.clone(),
                    prefix.clone(),
                    format!("[{}]", members.join(", ")),
                    String::new(),
                    action.clone(),
                ]
            }
            SavRule::Raw(text) => [
                String::new(),
                text.clone(),
                String::new(),
                String::new(),
                String::new(),
            ],
        }
    }
}

/// The savd `config` line's recognized keywords; unrecognized ones
/// are ignored (the format may grow).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SavConfig {
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

/// The savd `monitor` line's counters; each is individually optional
/// so a malformed one does not erase its siblings.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SavMonitor {
    /// `simulation` or `dataplane`.
    pub source: Option<String>,
    /// Sources judged invalid.
    pub invalid: Option<u64>,
    /// Sources judged valid.
    pub valid: Option<u64>,
    /// Sources no rule judged.
    pub unknown: Option<u64>,
}

/// A parsed `savd.status`: everything this reader recognized.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SavStatus {
    /// The daemon's version string.
    pub version: Option<String>,
    /// The pid the daemon recorded.
    pub pid: Option<u32>,
    /// The running-config summary.
    pub config: SavConfig,
    /// `Some(false)` when the file said `(never evaluated)`.
    pub evaluated: Option<bool>,
    /// The rule count the file claimed.
    pub installed_claim: Option<u64>,
    /// The rule lines, in file order (`Raw` keeps unknown shapes).
    pub rules: Vec<SavRule>,
    /// The last evaluate's monitor counters.
    pub monitor: SavMonitor,
    /// How many lines matched nothing this reader knows.
    pub unknown_lines: usize,
}

impl Tally for SavStatus {
    fn bump_unknown(&mut self) {
        self.unknown_lines += 1;
    }
}

/// The savd parser table.
const SAVD_TABLE: &[(&str, Handler<SavStatus>)] = &[
    ("savd", h_savd_header),
    ("config", h_savd_config),
    ("installed", h_savd_installed),
    ("rule", h_savd_rule),
    ("monitor", h_savd_monitor),
];

/// Parses `savd.status`. Never fails: unrecognized or malformed
/// pieces simply do not populate their fields.
pub fn parse_savd(text: &str) -> SavStatus {
    read(
        text,
        Format {
            children: Children::Through,
            entries: SAVD_TABLE,
        },
    )
}

impl SavStatus {
    /// Parses a status file's content (the method form of
    /// [`parse_savd`]). Never fails.
    pub fn parse(text: &str) -> SavStatus {
        parse_savd(text)
    }
}

fn h_savd_header(state: &mut SavStatus, tokens: &[&str], _line: &str) -> bool {
    let (version, pid) = daemon_header(tokens);
    state.version = version;
    state.pid = pid;
    true
}

/// Config line: keyword/value pairs scanned wherever they sit, so
/// reordered or newly added keywords ride along harmlessly.
fn h_savd_config(state: &mut SavStatus, tokens: &[&str], _line: &str) -> bool {
    for (index, token) in tokens.iter().enumerate().skip(1) {
        let Some(value) = tokens.get(index + 1) else {
            break;
        };
        match *token {
            "mode" => state.config.mode = Some(value.to_string()),
            "action" => state.config.action = Some(value.to_string()),
            "poll" => {
                state.config.poll_secs = value.strip_suffix('s').unwrap_or(value).parse().ok()
            }
            "interfaces" => state.config.interfaces = value.parse().ok(),
            "bindings" => state.config.bindings = value.parse().ok(),
            _ => {}
        }
    }
    true
}

/// Installed line: `installed <N> rules` (optionally `(never
/// evaluated)`). A count this reader cannot read makes the line
/// unrecognized.
fn h_savd_installed(state: &mut SavStatus, tokens: &[&str], _line: &str) -> bool {
    let never = tokens.contains(&"(never");
    match tokens.get(1).and_then(|token| token.parse::<u64>().ok()) {
        Some(count) => {
            state.installed_claim = Some(count);
            state.evaluated = Some(!never);
            true
        }
        None if never => {
            state.evaluated = Some(false);
            true
        }
        None => false,
    }
}

/// One rule body (after `rule `): the four shapes savd renders today,
/// falling back to [`SavRule::Raw`] for anything else.
fn h_savd_rule(state: &mut SavStatus, _tokens: &[&str], line: &str) -> bool {
    let raw = line.strip_prefix("rule ").unwrap_or(line);
    state.rules.push(parse_sav_rule(raw));
    true
}

/// Monitor line: `monitor source <s> invalid=<n> valid=<n>
/// unknown=<n>`, keyword-scanned so added counters are ignored.
fn h_savd_monitor(state: &mut SavStatus, tokens: &[&str], _line: &str) -> bool {
    for (index, token) in tokens.iter().enumerate().skip(1) {
        if *token == "source" {
            if let Some(value) = tokens.get(index + 1) {
                state.monitor.source = Some(value.to_string());
            }
            continue;
        }
        if let Some((key, value)) = token.split_once('=') {
            let number = value.parse().ok();
            match key {
                "invalid" => state.monitor.invalid = number,
                "valid" => state.monitor.valid = number,
                "unknown" => state.monitor.unknown = number,
                _ => {}
            }
        }
    }
    true
}

/// The rule shapes: interface scale `allow|block if#N [prefixes]
/// (urpf) action` and router scale `allow|block PREFIX if
/// [ifindexes] action`; everything else stays verbatim.
fn parse_sav_rule(raw: &str) -> SavRule {
    let tokens: Vec<&str> = raw.split_whitespace().collect();
    let Some(&polarity) = tokens.first() else {
        return SavRule::Raw(raw.to_string());
    };
    // Interface scale: `allow|block if#N [prefixes] (urpf) action`.
    if let Some(second) = tokens.get(1) {
        if let Some(index_text) = second.strip_prefix("if#") {
            let Some(ifindex) = index_text.parse::<u32>().ok() else {
                return SavRule::Raw(raw.to_string());
            };
            let Some((prefixes, tail)) = bracket_set(&tokens[2..]) else {
                return SavRule::Raw(raw.to_string());
            };
            return match tail.as_slice() {
                [urpf_or_action] => {
                    // One trailing word is the action (block shape);
                    // `allow` carries urpf + action, so one word only
                    // fits the block shape — kept raw otherwise.
                    match polarity {
                        "block" => SavRule::Iface {
                            polarity: polarity.to_string(),
                            ifindex,
                            prefixes,
                            urpf: None,
                            action: urpf_or_action.to_string(),
                        },
                        _ => SavRule::Raw(raw.to_string()),
                    }
                }
                [urpf, action] if polarity == "allow" => SavRule::Iface {
                    polarity: polarity.to_string(),
                    ifindex,
                    prefixes,
                    urpf: Some((*urpf).to_string()),
                    action: (*action).to_string(),
                },
                _ => SavRule::Raw(raw.to_string()),
            };
        }
    }
    // Router scale: `allow|block PREFIX if [ifindexes] action`.
    if tokens.get(2) == Some(&"if") {
        let prefix = tokens[1].to_string();
        let Some((members, tail)) = bracket_set(&tokens[3..]) else {
            return SavRule::Raw(raw.to_string());
        };
        let ifindexes: Option<Vec<u32>> = members.iter().map(|m| m.parse().ok()).collect();
        let Some(ifindexes) = ifindexes else {
            return SavRule::Raw(raw.to_string());
        };
        return match tail.as_slice() {
            [action] if matches!(polarity, "allow" | "block") => SavRule::Prefix {
                polarity: polarity.to_string(),
                prefix,
                ifindexes,
                action: (*action).to_string(),
            },
            _ => SavRule::Raw(raw.to_string()),
        };
    }
    SavRule::Raw(raw.to_string())
}

// ------------------------------------------------------------ bfdd.status

/// One bfdd `session` line, keyword-scanned.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct BfdSession {
    /// The peer address (v4 or v6, verbatim).
    pub peer: Option<String>,
    /// The session state (`Up`, `Down`, `Init`, `AdminDown`, ...).
    pub state: Option<String>,
    /// The diagnostic code.
    pub diag: Option<u32>,
    /// Our discriminator.
    pub local_discr: Option<u32>,
    /// The learned remote discriminator.
    pub remote_discr: Option<u32>,
    /// The negotiated detection time.
    pub detection_time_ms: Option<u64>,
    /// The negotiated transmit interval.
    pub tx_interval_ms: Option<u64>,
    /// The indented `last-transition` child line, verbatim.
    pub last_transition: Option<String>,
}

/// A parsed `bfdd.status`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct BfdStatus {
    /// The daemon's version string.
    pub version: Option<String>,
    /// The pid the daemon recorded.
    pub pid: Option<u32>,
    /// The peer count the file claimed.
    pub peers_claim: Option<u64>,
    /// The session lines, in file order.
    pub sessions: Vec<BfdSession>,
    /// How many lines matched nothing this reader knows.
    pub unknown_lines: usize,
}

impl Tally for BfdStatus {
    fn bump_unknown(&mut self) {
        self.unknown_lines += 1;
    }
}

/// The bfdd parser table.
const BFDD_TABLE: &[(&str, Handler<BfdStatus>)] = &[
    ("bfdd", h_bfdd_header),
    ("peers", h_bfdd_peers),
    ("session", h_bfdd_session),
];

/// Parses `bfdd.status`. Never fails.
pub fn parse_bfdd(text: &str) -> BfdStatus {
    read(
        text,
        Format {
            children: Children::Attach(attach_bfdd_child),
            entries: BFDD_TABLE,
        },
    )
}

impl BfdStatus {
    /// Parses a status file's content (the method form of
    /// [`parse_bfdd`]). Never fails.
    pub fn parse(text: &str) -> BfdStatus {
        parse_bfdd(text)
    }
}

fn h_bfdd_header(state: &mut BfdStatus, tokens: &[&str], _line: &str) -> bool {
    let (version, pid) = daemon_header(tokens);
    state.version = version;
    state.pid = pid;
    true
}

fn h_bfdd_peers(state: &mut BfdStatus, tokens: &[&str], _line: &str) -> bool {
    state.peers_claim = tokens.get(1).and_then(|t| t.parse().ok());
    true
}

/// Session body (after `session`): keyword/value pairs scanned
/// wherever they sit, so added fields ride along.
fn h_bfdd_session(state: &mut BfdStatus, tokens: &[&str], _line: &str) -> bool {
    let mut session = BfdSession::default();
    for (index, token) in tokens.iter().enumerate().skip(1) {
        let Some(value) = tokens.get(index + 1) else {
            break;
        };
        match *token {
            "peer" => session.peer = Some(value.to_string()),
            "state" => session.state = Some(value.to_string()),
            "diag" => session.diag = value.parse().ok(),
            "local-discr" => session.local_discr = value.parse().ok(),
            "remote-discr" => session.remote_discr = value.parse().ok(),
            "detection-time" => {
                session.detection_time_ms = value.strip_suffix("ms").unwrap_or(value).parse().ok()
            }
            "tx-interval" => {
                session.tx_interval_ms = value.strip_suffix("ms").unwrap_or(value).parse().ok()
            }
            _ => {}
        }
    }
    // A session line without even a peer or state is too broken to
    // carry anything — it counts unknown.
    if session.peer.is_some() || session.state.is_some() {
        state.sessions.push(session);
        true
    } else {
        false
    }
}

/// The indented `last-transition` child attaches to the session
/// above; anything else (or no session above) counts unknown.
fn attach_bfdd_child(state: &mut BfdStatus, line: &str) -> bool {
    let body = line.trim();
    if let Some(field) = body.strip_prefix("last-transition ") {
        if let Some(session) = state.sessions.last_mut() {
            session.last_transition = Some(field.to_string());
            return true;
        }
    }
    false
}

// -------------------------------------------------------- rousterd.status

/// One rousterd `interface` line plus its `address` children.
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

/// One rousterd `neighbour` line.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct NeighLine {
    pub ip: Option<IpAddr>,
    pub ifindex: Option<u32>,
    /// The state word, verbatim (`REACHABLE`, `INCOMPLETE|FAILED`, ...).
    pub state: Option<String>,
    /// Colon-separated hex, or `-` while resolution is pending.
    pub lladdr: Option<String>,
}

/// One rousterd `table` line.
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
    /// How many lines matched nothing this reader knows.
    pub unknown_lines: usize,
}

impl Tally for RousterdStatus {
    fn bump_unknown(&mut self) {
        self.unknown_lines += 1;
    }
}

/// The rousterd parser table.
const ROUSTERD_TABLE: &[(&str, Handler<RousterdStatus>)] = &[
    ("rousterd", h_rousterd_header),
    ("router-id", h_rousterd_router_id),
    ("interfaces", h_rousterd_interfaces_claim),
    ("interface", h_rousterd_interface),
    ("neighbours", h_rousterd_neighbours_claim),
    ("neighbour", h_rousterd_neighbour),
    ("tables", h_rousterd_tables_claim),
    ("table", h_rousterd_table),
];

/// Parses `rousterd.status`. Never fails.
pub fn parse_rousterd(text: &str) -> RousterdStatus {
    read(
        text,
        Format {
            children: Children::Attach(attach_rousterd_child),
            entries: ROUSTERD_TABLE,
        },
    )
}

impl RousterdStatus {
    /// Parses a status file's content (the method form of
    /// [`parse_rousterd`]). Never fails.
    pub fn parse(text: &str) -> RousterdStatus {
        parse_rousterd(text)
    }

    /// The interfaces a `name` filter selects (all when `None`).
    pub fn interfaces_matching(&self, name: Option<&str>) -> Vec<&IfaceLine> {
        interfaces_matching(&self.interfaces, name)
    }

    /// The neighbours a `filter` selects (all when `None`): a bare
    /// address or a CIDR prefix, either family.
    pub fn neighbours_matching(&self, filter: Option<&str>) -> Vec<&NeighLine> {
        neighbours_matching(&self.neighbours, filter)
    }
}

fn h_rousterd_header(state: &mut RousterdStatus, tokens: &[&str], _line: &str) -> bool {
    let (version, pid) = daemon_header(tokens);
    state.version = version;
    state.pid = pid;
    true
}

/// Only a real address renders; a malformed word leaves the field
/// unset (never guessed).
fn h_rousterd_router_id(state: &mut RousterdStatus, tokens: &[&str], _line: &str) -> bool {
    if let Some(value) = tokens.get(1) {
        if value.parse::<IpAddr>().is_ok() {
            state.router_id = Some(value.to_string());
        }
    }
    true
}

fn h_rousterd_interfaces_claim(state: &mut RousterdStatus, tokens: &[&str], _line: &str) -> bool {
    state.interfaces_claim = tokens.get(1).and_then(|t| t.parse().ok());
    true
}

/// Keywords of the `interface` line: a value position never swallows
/// one of these.
const IFACE_KEYWORDS: [&str; 6] = ["ifindex", "up", "down", "flags", "vrf", "vrf-table"];

fn h_rousterd_interface(state: &mut RousterdStatus, tokens: &[&str], _line: &str) -> bool {
    let mut iface = IfaceLine::default();
    if let Some(name) = tokens.get(1) {
        iface.name = Some(name.to_string());
    }
    for (index, token) in tokens.iter().enumerate().skip(2) {
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
    // An interface line without even a name or ifindex is too broken
    // to be an interface — it counts unknown.
    if iface.name.is_some() || iface.ifindex.is_some() {
        state.interfaces.push(iface);
        true
    } else {
        false
    }
}

fn h_rousterd_neighbours_claim(state: &mut RousterdStatus, tokens: &[&str], _line: &str) -> bool {
    state.neighbours_claim = tokens.get(1).and_then(|t| t.parse().ok());
    true
}

/// Keywords of the `neighbour` line.
const NEIGH_KEYWORDS: [&str; 3] = ["ifindex", "state", "lladdr"];

fn h_rousterd_neighbour(state: &mut RousterdStatus, tokens: &[&str], _line: &str) -> bool {
    let mut neigh = NeighLine::default();
    if let Some(ip) = tokens.get(1) {
        neigh.ip = ip.parse().ok();
    }
    for (index, token) in tokens.iter().enumerate().skip(2) {
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
    // Without an ip or ifindex the line anchors to nothing — unknown.
    if neigh.ip.is_some() || neigh.ifindex.is_some() {
        state.neighbours.push(neigh);
        true
    } else {
        false
    }
}

fn h_rousterd_tables_claim(state: &mut RousterdStatus, tokens: &[&str], _line: &str) -> bool {
    state.tables_claim = tokens.get(1).and_then(|t| t.parse().ok());
    true
}

/// Keywords of the `table` line.
const TABLE_KEYWORDS: [&str; 6] = [
    "routes",
    "prefixes",
    "connected",
    "kernel",
    "vrf",
    "vrf-table",
];

fn h_rousterd_table(state: &mut RousterdStatus, tokens: &[&str], _line: &str) -> bool {
    let Some(id) = tokens.get(1).and_then(|t| t.parse().ok()) else {
        // No readable table id — the line cannot anchor, unknown.
        return false;
    };
    let mut table = TableLine {
        id: Some(id),
        ..TableLine::default()
    };
    for (index, token) in tokens.iter().enumerate().skip(2) {
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
    state.tables.push(table);
    true
}

/// The indented `address` child attaches to the interface above;
/// anything else (or no interface above) counts unknown.
fn attach_rousterd_child(state: &mut RousterdStatus, line: &str) -> bool {
    let body = line.trim();
    if let Some(address) = body.strip_prefix("address ") {
        if let Some(iface) = state.interfaces.last_mut() {
            iface.addresses.push(address.trim().to_string());
            return true;
        }
    }
    false
}

// ------------------------------------------------- shared view selections

/// The interfaces a `name` filter selects (all when `None`).
pub fn interfaces_matching<'a>(
    interfaces: &'a [IfaceLine],
    name: Option<&str>,
) -> Vec<&'a IfaceLine> {
    interfaces
        .iter()
        .filter(|iface| name.is_none_or(|want| iface.name.as_deref() == Some(want)))
        .collect()
}

/// The neighbours a `filter` selects (all when `None`): a bare
/// address or a CIDR prefix, either family.
pub fn neighbours_matching<'a>(
    neighbours: &'a [NeighLine],
    filter: Option<&str>,
) -> Vec<&'a NeighLine> {
    let filter = filter.and_then(parse_filter);
    neighbours
        .iter()
        .filter(|neigh| match (&filter, neigh.ip) {
            (Some(filter), Some(ip)) => filter.contains(ip),
            _ => true,
        })
        .collect()
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
                in_window(u32::from(v4) as u128, self.base, self.width.min(32), 32)
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

/// Is this token shape-valid as an address-or-prefix parameter
/// (either family, bare or CIDR)? The grammar validator both edge
/// surfaces share.
pub fn accepts_addr_or_prefix(token: &str) -> bool {
    parse_filter(token).is_some()
}

#[cfg(test)]
mod tests {
    use super::*;

    // ---------------------------------------------------------- savd

    const SAVD_TODAY: &str = "\
savd 0.0.0 pid 4242
config mode strict-uRPF action monitor poll 5s interfaces 2 bindings 0
installed 4 rules
rule allow if#2 [198.51.100.0/24] strict monitor
rule block if#7 [192.0.2.0/26] drop
rule allow 2001:db8:1::/48 if [2, 3] monitor
rule block 192.0.2.128/25 if [7, 9] monitor
monitor source simulation invalid=1 valid=2 unknown=3
";

    #[test]
    fn savd_today_parses_completely() {
        let parsed = parse_savd(SAVD_TODAY);
        assert_eq!(parsed.version.as_deref(), Some("0.0.0"));
        assert_eq!(parsed.pid, Some(4242));
        assert_eq!(parsed.config.mode.as_deref(), Some("strict-uRPF"));
        assert_eq!(parsed.config.action.as_deref(), Some("monitor"));
        assert_eq!(parsed.config.poll_secs, Some(5));
        assert_eq!(parsed.config.interfaces, Some(2));
        assert_eq!(parsed.config.bindings, Some(0));
        assert_eq!(parsed.installed_claim, Some(4));
        assert_eq!(parsed.evaluated, Some(true));
        assert_eq!(parsed.rules.len(), 4);
        assert_eq!(parsed.monitor.source.as_deref(), Some("simulation"));
        assert_eq!(parsed.monitor.invalid, Some(1));
        assert_eq!(parsed.monitor.valid, Some(2));
        assert_eq!(parsed.monitor.unknown, Some(3));
        assert_eq!(parsed.unknown_lines, 0);
    }

    #[test]
    fn savd_rule_shapes_split_by_scale_and_polarity() {
        let parsed = parse_savd(SAVD_TODAY);
        assert!(matches!(
            &parsed.rules[0],
            SavRule::Iface { polarity, ifindex: 2, urpf: Some(hint), action, .. }
                if polarity == "allow" && hint == "strict" && action == "monitor"
        ));
        assert!(matches!(
            &parsed.rules[1],
            SavRule::Iface { polarity, ifindex: 7, urpf: None, action, .. }
                if polarity == "block" && action == "drop"
        ));
        assert!(matches!(
            &parsed.rules[2],
            SavRule::Prefix { polarity, ifindexes, action, .. }
                if polarity == "allow" && ifindexes == &vec![2, 3] && action == "monitor"
        ));
        assert!(matches!(
            &parsed.rules[3],
            SavRule::Prefix { polarity, ifindexes, action, .. }
                if polarity == "block" && ifindexes == &vec![7, 9]
        ));
    }

    #[test]
    fn savd_unknown_rule_shapes_stay_verbatim() {
        let parsed = parse_savd("savd 0.0.0 pid 1\nrule frob if#2 [x] magic\nrule allow\n");
        assert_eq!(parsed.rules.len(), 2);
        assert!(matches!(&parsed.rules[0], SavRule::Raw(t) if t == "frob if#2 [x] magic"));
        assert!(matches!(&parsed.rules[1], SavRule::Raw(t) if t == "allow"));
    }

    #[test]
    fn savd_future_fields_and_unknown_lines_ride_along() {
        let text = "\
savd 2.0.0 pid 51234 uptime 3600s
config mode EFP-uRPF action monitor poll 5s interfaces 2 bindings 1 ttl-window 90s
installed 1 rules
rule allow if#2 [198.51.100.0/24] strict monitor expires-in 120s
agent session 3 peers 1
monitor source dataplane invalid=1 valid=2 unknown=3 window 60s
";
        let parsed = parse_savd(text);
        assert_eq!(parsed.version.as_deref(), Some("2.0.0"));
        assert_eq!(parsed.pid, Some(51234));
        assert_eq!(parsed.config.bindings, Some(1));
        // The extra `expires-in` tail makes the rule unknown-shape —
        // kept verbatim, not lost.
        assert!(matches!(&parsed.rules[0], SavRule::Raw(_)));
        // The whole unknown `agent` line is counted, not fatal.
        assert_eq!(parsed.unknown_lines, 1);
        assert_eq!(parsed.monitor.source.as_deref(), Some("dataplane"));
    }

    #[test]
    fn savd_malformed_numbers_leave_fields_unset() {
        let parsed = parse_savd("savd x pid notanumber\ninstalled NaN rules\n");
        assert_eq!(parsed.version.as_deref(), Some("x"));
        assert_eq!(parsed.pid, None);
        assert_eq!(parsed.installed_claim, None);
        assert_eq!(parsed.evaluated, None);
        // `installed NaN rules` carries no readable count — unknown.
        assert_eq!(parsed.unknown_lines, 1);
    }

    #[test]
    fn savd_never_evaluated_marker_is_recognized() {
        let parsed = parse_savd("savd 0.0.0 pid 9\ninstalled 0 rules (never evaluated)\n");
        assert_eq!(parsed.installed_claim, Some(0));
        assert_eq!(parsed.evaluated, Some(false));
        assert_eq!(parsed.unknown_lines, 0);
    }

    #[test]
    fn savd_indented_lines_flow_through_the_table() {
        // savd has no child grammar: an indented line is just a line
        // (the daemon never writes one; the pin keeps the engine's
        // Through policy honest).
        let parsed = parse_savd("savd 0.0.0 pid 1\n  installed 2 rules\n  wat\n");
        assert_eq!(parsed.installed_claim, Some(2));
        assert_eq!(parsed.unknown_lines, 1);
    }

    // ---------------------------------------------------------- bfdd

    const BFDD_TODAY: &str = "\
bfdd 0.0.0 pid 4711
peers 2
session peer 192.0.2.2 state Up diag 0 local-discr 1 remote-discr 7 detection-time 900ms tx-interval 300ms
session peer 2001:db8::2 state Down diag 1 local-discr 2 remote-discr 0 detection-time 900ms tx-interval 300ms
  last-transition Up -> Down (Control Detection Time Expired (1), timeout while Up)
";

    #[test]
    fn bfdd_today_parses_completely() {
        let parsed = parse_bfdd(BFDD_TODAY);
        assert_eq!(parsed.version.as_deref(), Some("0.0.0"));
        assert_eq!(parsed.pid, Some(4711));
        assert_eq!(parsed.peers_claim, Some(2));
        assert_eq!(parsed.sessions.len(), 2);
        let first = &parsed.sessions[0];
        assert_eq!(first.peer.as_deref(), Some("192.0.2.2"));
        assert_eq!(first.state.as_deref(), Some("Up"));
        assert_eq!(first.diag, Some(0));
        assert_eq!(first.local_discr, Some(1));
        assert_eq!(first.remote_discr, Some(7));
        assert_eq!(first.detection_time_ms, Some(900));
        assert_eq!(first.tx_interval_ms, Some(300));
        assert_eq!(parsed.unknown_lines, 0);
    }

    #[test]
    fn bfdd_last_transition_attaches_to_the_session_above() {
        let parsed = parse_bfdd(BFDD_TODAY);
        assert_eq!(parsed.sessions[0].last_transition, None);
        assert_eq!(
            parsed.sessions[1].last_transition.as_deref(),
            Some("Up -> Down (Control Detection Time Expired (1), timeout while Up)")
        );
    }

    #[test]
    fn bfdd_malformed_variants_stay_defensive() {
        let text = "\
bfdd x pid nope
peers NaN
session nonsense entirely
session peer 192.0.2.2 state Up diag X local-discr -1 remote-discr z detection-time 900ms tx-interval 300ms
  last-transition
  unknown-child wat
";
        let parsed = parse_bfdd(text);
        assert_eq!(parsed.version.as_deref(), Some("x"));
        assert_eq!(parsed.pid, None);
        assert_eq!(
            parsed.peers_claim, None,
            "`peers NaN` is known-but-unreadable"
        );
        assert_eq!(
            parsed.sessions.len(),
            1,
            "the peerless session counts unknown"
        );
        assert_eq!(parsed.sessions[0].diag, None);
        assert_eq!(parsed.sessions[0].local_discr, None);
        assert_eq!(parsed.sessions[0].remote_discr, None);
        assert_eq!(parsed.sessions[0].peer.as_deref(), Some("192.0.2.2"));
        // session-without-peer, the empty last-transition child, the
        // unknown child: three unrecognized lines.
        assert_eq!(parsed.unknown_lines, 3);
    }

    #[test]
    fn bfdd_empty_and_never_started_parse_quietly() {
        assert_eq!(parse_bfdd(""), BfdStatus::default());
        let parsed = parse_bfdd("bfdd 0.0.0 pid 5\npeers 0\n");
        assert_eq!(parsed.peers_claim, Some(0));
        assert!(parsed.sessions.is_empty());
    }

    // -------------------------------------------------------- rousterd

    const ROUSTERD_TODAY: &str = "\
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
    fn rousterd_today_parses_completely() {
        let parsed = parse_rousterd(ROUSTERD_TODAY);
        assert_eq!(parsed.version.as_deref(), Some("0.0.0"));
        assert_eq!(parsed.pid, Some(4242));
        assert_eq!(parsed.router_id.as_deref(), Some("198.51.100.1"));
        assert_eq!(parsed.interfaces_claim, Some(4));
        assert_eq!(parsed.neighbours_claim, Some(2));
        assert_eq!(parsed.tables_claim, Some(2));
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
    fn rousterd_future_fields_ride_and_unknown_lines_count() {
        let text = "\
rousterd 2.0.0 pid 51234 uptime 3600s
router-id 192.0.2.1 origin derived
interfaces 1
interface eth0 ifindex 2 up flags UP|RUNNING vrf - mtu 1500
  address 192.0.2.1/24 preferred
agent session 99 something
table 254 routes 1 prefixes 1 connected 2 kernel 3 vrf - label main
";
        let parsed = parse_rousterd(text);
        assert_eq!(parsed.pid, Some(51_234));
        assert_eq!(parsed.router_id.as_deref(), Some("192.0.2.1"));
        assert_eq!(parsed.interfaces[0].ifindex, Some(2));
        assert_eq!(parsed.tables[0].kernel, Some(3));
        assert_eq!(parsed.unknown_lines, 1);
    }

    #[test]
    fn rousterd_malformed_variants_stay_defensive() {
        let text = "\
rousterd x.y pid nope
router-id not-an-ip
interface eth0 ifindex NaN up flags vrf
neighbour not-an-ip ifindex two state lladdr
table 254 routes many prefixes 0 connected 0 kernel 0 vrf -
";
        let parsed = parse_rousterd(text);
        assert_eq!(parsed.pid, None);
        assert_eq!(parsed.router_id, None);
        let eth0 = &parsed.interfaces[0];
        assert_eq!(eth0.ifindex, None);
        assert_eq!(eth0.flags, None, "a missing flags value must not eat `vrf`");
        assert!(
            parsed.neighbours.is_empty(),
            "a neighbour without anchors counts unknown"
        );
        assert_eq!(parsed.tables[0].routes, None);
        assert_eq!(parsed.tables[0].prefixes, Some(0));
    }

    #[test]
    fn rousterd_child_lines_attach_or_count_unknown() {
        let text = "\
rousterd 0.0.0 pid 1
interface eth0 ifindex 2 up
  address 192.0.2.1/24
  tunnel something
  address 2001:db8::1/64
";
        let parsed = parse_rousterd(text);
        assert_eq!(
            parsed.interfaces[0].addresses,
            vec!["192.0.2.1/24".to_string(), "2001:db8::1/64".to_string()]
        );
        assert_eq!(parsed.unknown_lines, 1, "the unknown child counts");
        // An address with no interface above also counts unknown.
        let parsed = parse_rousterd("rousterd 0.0.0 pid 1\n  address 192.0.2.1/24\n");
        assert_eq!(parsed.unknown_lines, 1);
    }

    #[test]
    fn crlf_and_blank_lines_are_tolerated() {
        let text = "savd 0.0.0 pid 7\r\n\r\ninstalled 1 rules\r\n   \n";
        let parsed = parse_savd(text);
        assert_eq!(parsed.pid, Some(7));
        assert_eq!(parsed.installed_claim, Some(1));
        assert_eq!(parsed.unknown_lines, 0);
    }

    // ------------------------------------------------- view selections

    #[test]
    fn filters_match_prefix_and_family() {
        let parsed = parse_rousterd(ROUSTERD_TODAY);
        assert_eq!(neighbours_matching(&parsed.neighbours, None).len(), 2);
        assert_eq!(
            neighbours_matching(&parsed.neighbours, Some("192.0.2.10")).len(),
            1
        );
        assert_eq!(
            neighbours_matching(&parsed.neighbours, Some("192.0.2.0/24")).len(),
            1
        );
        assert_eq!(
            neighbours_matching(&parsed.neighbours, Some("198.51.100.64/26")).len(),
            0
        );
        assert_eq!(
            neighbours_matching(&parsed.neighbours, Some("2001:db8::/32")).len(),
            0
        );
        assert_eq!(interfaces_matching(&parsed.interfaces, None).len(), 4);
        assert_eq!(
            interfaces_matching(&parsed.interfaces, Some("eth1")).len(),
            1
        );
        assert!(interfaces_matching(&parsed.interfaces, Some("eth9")).is_empty());
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
