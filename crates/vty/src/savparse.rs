//! Tolerant parsing of `savd.status` — the rousterctl S3
//! conventions, re-implemented in-crate (the two edge adapters stay
//! decoupled; consolidation is §Deferred).
//!
//! Format (as published, `docs/operator-surfaces.md` §2.1):
//!
//! ```text
//! savd 0.0.0 pid 4242
//! config mode strict-uRPF action monitor poll 5s interfaces 2 bindings 0
//! installed 2 rules
//! rule allow if#2 [198.51.100.0/24] strict monitor
//! monitor source simulation invalid=0 valid=0 unknown=0
//! ```
//!
//! Tolerance contract: unknown *lines* are counted and dropped;
//! known *keywords* are picked out wherever they sit on their line,
//! so added fields ride along harmlessly; a `rule` line matching no
//! known shape is kept verbatim so no operator data is lost; a
//! malformed number leaves its field unset. Parsing never fails.

/// One `rule` line: the four op shapes savd renders today, plus the
/// verbatim fallback.
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
        /// The generator hint (`strict`/`loose`), when present.
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
    /// A rule shape this version does not know, verbatim.
    Raw(String),
}

impl SavRule {
    /// Row cells for the rule table: (polarity, target, members,
    /// urpf, action).
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

/// The `config` line's recognized keywords.
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

/// The `monitor` line's counters.
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

/// A parsed `savd.status`.
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
    /// The rule lines, in file order.
    pub rules: Vec<SavRule>,
    /// The last evaluate's monitor counters.
    pub monitor: SavMonitor,
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
}

/// Header line: `savd <version> pid <pid>` — both pieces picked out
/// by keyword so future header fields cannot hide them.
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

/// Config line: keyword/value pairs scanned wherever they sit.
fn parse_config(config: &mut SavConfig, tokens: &[&str]) {
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

/// Installed line: `installed <N> rules`, optionally `(never
/// evaluated)`.
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

/// Monitor line: keyword-scanned so added counters are ignored.
fn parse_monitor(monitor: &mut SavMonitor, tokens: &[&str]) {
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

/// One rule body (after `rule `).
fn parse_rule(raw: &str) -> SavRule {
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
                    // fits the block shape or an allow without the
                    // hint — kept raw when the polarity demands two.
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

/// Splits a token slice at its bracketed `[...]` set: the members
/// and the tokens after the closing `]`. `None` when the slice does
/// not start at `[` or the set never closes.
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

#[cfg(test)]
mod tests {
    use super::*;

    const TODAY: &str = "\
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
    fn parses_todays_full_shape() {
        let parsed = SavStatus::parse(TODAY);
        assert_eq!(parsed.version.as_deref(), Some("0.0.0"));
        assert_eq!(parsed.pid, Some(4242));
        assert_eq!(parsed.config.mode.as_deref(), Some("strict-uRPF"));
        assert_eq!(parsed.config.poll_secs, Some(5));
        assert_eq!(parsed.installed_claim, Some(4));
        assert_eq!(parsed.rules.len(), 4);
        assert_eq!(parsed.monitor.valid, Some(2));
        assert_eq!(parsed.unknown_lines, 0);
    }

    #[test]
    fn rule_shapes_split_by_scale() {
        let parsed = SavStatus::parse(TODAY);
        assert!(matches!(
            &parsed.rules[0],
            SavRule::Iface { urpf: Some(hint), .. } if hint == "strict"
        ));
        assert!(matches!(
            &parsed.rules[1],
            SavRule::Iface { urpf: None, .. }
        ));
        assert!(
            matches!(&parsed.rules[2], SavRule::Prefix { ifindexes, .. } if ifindexes == &vec![2, 3])
        );
        assert!(matches!(&parsed.rules[3], SavRule::Prefix { .. }));
    }

    #[test]
    fn unknown_rule_shapes_are_kept_verbatim() {
        let parsed = SavStatus::parse("savd 0.0.0 pid 1\nrule frob if#2 [x] magic\n");
        assert_eq!(parsed.rules.len(), 1);
        assert!(matches!(&parsed.rules[0], SavRule::Raw(text) if text.contains("frob")));
    }

    #[test]
    fn future_fields_and_lines_ride_along() {
        let text = "\
savd 2.0.0 pid 51234 uptime 3600s
config mode EFP-uRPF action monitor poll 5s interfaces 2 bindings 1 ttl-window 90s
installed 1 rules
rule allow if#2 [198.51.100.0/24] strict monitor expires-in 120s
agent session 3 peers 1
monitor source dataplane invalid=1 valid=2 unknown=3 window 60s
";
        let parsed = SavStatus::parse(text);
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
    fn malformed_numbers_leave_their_field_unset() {
        let parsed = SavStatus::parse("savd x pid notanumber\ninstalled NaN rules\n");
        assert_eq!(parsed.version.as_deref(), Some("x"));
        assert_eq!(parsed.pid, None);
        assert_eq!(parsed.installed_claim, None);
        assert_eq!(parsed.evaluated, None);
    }

    #[test]
    fn never_evaluated_marker_is_recognized() {
        let parsed = SavStatus::parse("savd 0.0.0 pid 9\ninstalled 0 rules (never evaluated)\n");
        assert_eq!(parsed.installed_claim, Some(0));
        assert_eq!(parsed.evaluated, Some(false));
    }
}
