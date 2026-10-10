//! The Cisco-style command word tree — table-driven parsing with
//! abbreviated unambiguous commands, `?` help at any node, and
//! ambiguity errors.
//!
//! A command is a static slice of [`Tok`]s: literal words
//! (abbreviatable — `sh ver` is `show version`, as in vtysh) and
//! parameter placeholders (`<A.B.C.D/M>` &c., validated std-only).
//! Registration walks the slice into a tree of nodes; matching walks
//! input tokens down the same tree:
//!
//! - an **exact** literal match wins immediately over everything
//!   else (so `blackhole` is never ambiguous with a gateway
//!   address);
//! - otherwise a literal matches by prefix (`en` → `enable`) and a
//!   parameter matches only if the token passes its validation;
//!   more than one surviving candidate is an ambiguity error;
//! - arriving at a node with no leaf after consuming all tokens is
//!   `% Incomplete command.`;
//! - a token with no candidate is `% Unknown command: <input>`
//!   (the error shape real FRR 10.2.2 produced, quarantine B7 §4).
//!
//! Help (`?`) is the same walk stopping at the last node: the
//! surviving children are listed with their help text, plus `<cr>`
//! when the input already forms a complete command.

/// A parameter placeholder's validation kind. All checks are
/// std-only — pulling a parser crate for five shapes would outweigh
/// the problem (an owner decision to record, not a patch detail).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ParamKind {
    /// A single word: `[A-Za-z0-9._-]+` (hostnames, names). The
    /// charset excludes `>` and whitespace so a prompt built from
    /// it can never be confused with output framing (see
    /// [`crate::protocol`]).
    Word,
    /// `<A.B.C.D>` — an IPv4 address.
    Ipv4,
    /// `<A.B.C.D/M>` — an IPv4 prefix, length 0..=32.
    Ipv4Prefix,
    /// `<X:X::X:X/M>` — an IPv6 prefix, length 0..=128.
    Ipv6Prefix,
    /// `<U32>` — a plain unsigned 32-bit number.
    U32,
    /// The rest of the line, verbatim (route-map display lines).
    /// Must be nonempty; no other constraint — the line is kept for
    /// display, not interpreted.
    Rest,
}

impl ParamKind {
    /// The placeholder as help output renders it.
    pub fn display_name(self) -> &'static str {
        match self {
            ParamKind::Word => "<WORD>",
            ParamKind::Ipv4 => "<A.B.C.D>",
            ParamKind::Ipv4Prefix => "<A.B.C.D/M>",
            ParamKind::Ipv6Prefix => "<X:X::X:X/M>",
            ParamKind::U32 => "<U32>",
            ParamKind::Rest => "<LINE>",
        }
    }

    /// Does `token` satisfy this kind?
    fn accepts(self, token: &str) -> bool {
        match self {
            ParamKind::Word => {
                !token.is_empty()
                    && token
                        .chars()
                        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-'))
            }
            ParamKind::Ipv4 => token.parse::<std::net::Ipv4Addr>().is_ok(),
            ParamKind::Ipv4Prefix => is_prefix(token, 32),
            ParamKind::Ipv6Prefix => is_prefix(token, 128),
            ParamKind::U32 => token.parse::<u32>().is_ok(),
            ParamKind::Rest => !token.is_empty(),
        }
    }
}

/// `A.B.C.D/M` / `X:X::X:X/M` shape: an address, a slash, and a
/// length within `max_len`.
fn is_prefix(token: &str, max_len: u8) -> bool {
    let Some((addr, len)) = token.split_once('/') else {
        return false;
    };
    let addr_ok = match max_len {
        32 => addr.parse::<std::net::Ipv4Addr>().is_ok(),
        128 => addr.parse::<std::net::Ipv6Addr>().is_ok(),
        _ => false,
    };
    addr_ok && len.parse::<u8>().is_ok_and(|len| len <= max_len)
}

/// One grammar element: a literal word or a parameter placeholder.
#[derive(Debug, Clone)]
pub enum Tok {
    /// A literal word, abbreviatable from any nonempty prefix.
    Lit {
        /// The word itself (`show`).
        word: &'static str,
        /// One-line help shown by `?`.
        help: &'static str,
    },
    /// A parameter placeholder capturing the token verbatim.
    Param {
        /// The placeholder's kind (drives validation + display).
        kind: ParamKind,
        /// One-line help shown by `?`.
        help: &'static str,
    },
}

impl Tok {
    /// How `?` renders this element.
    fn display(&self) -> String {
        match self {
            Tok::Lit { word, .. } => (*word).to_string(),
            Tok::Param { kind, .. } => kind.display_name().to_string(),
        }
    }

    fn help_text(&self) -> &str {
        match self {
            Tok::Lit { help, .. } | Tok::Param { help, .. } => help,
        }
    }
}

/// What a matched command asks the session to do. Kept here (with
/// the parser vocabulary) so [`crate::commands`] registers specs and
/// [`crate::session`] interprets them against one enum.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Action {
    // exec surface
    ShowVersion,
    ShowSav,
    ShowSavRules,
    ShowBfd,
    ShowBfdSummary,
    ShowRunningConfig,
    List,
    Enable,
    Disable,
    Exit,
    End,
    ConfTerm,
    RouterBgp,
    AddressFamily,
    ExitAddressFamily,
    Write,
    // config-mode grammar (parse-only, the B7 observed subset)
    Hostname,
    FrrVersion,
    FrrDefaults,
    LineVty,
    IpRoute,
    NoIpRoute,
    RouteMap,
    BgpImportCheck,
    NoBgpImportCheck,
    BgpRouterId,
    BgpNeighbor,
    AfNetwork,
    AfRedistributeStatic,
}

/// One registered command: grammar plus the action a full match
/// triggers. The whole v1 table lives in [`crate::commands`].
#[derive(Debug, Clone)]
pub struct Cmd {
    /// The grammar, in order.
    pub toks: Vec<Tok>,
    /// What a full match does.
    pub action: Action,
    /// The command's one-line help (`list`, `?` at the leaf).
    pub help: &'static str,
}

/// Why a line did not match.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MatchErr {
    /// A token matched no candidate.
    Unknown,
    /// More than one candidate survived a token.
    Ambiguous(Vec<String>),
    /// The line is a valid prefix of commands but not one itself.
    Incomplete,
    /// A parameter token failed its validation.
    InvalidParam {
        /// The offending token.
        token: String,
        /// What was expected instead.
        expected: &'static str,
    },
}

impl MatchErr {
    /// The vty error line for this failure (Cisco/FRR wording; the
    /// `Unknown` shape is the one quarantine B7 §4 observed on real
    /// FRR 10.2.2: `% Unknown command: router static`).
    pub fn error_line(&self, input: &str) -> String {
        match self {
            MatchErr::Unknown => format!("% Unknown command: {input}"),
            MatchErr::Ambiguous(candidates) => {
                format!("% Ambiguous command: {input} ({})", candidates.join(", "))
            }
            MatchErr::Incomplete => "% Incomplete command.".to_string(),
            MatchErr::InvalidParam { token, expected } => {
                format!("% Invalid input: {token} — expected {expected}")
            }
        }
    }
}

/// A successful match.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Match {
    /// The matched command's action.
    pub action: Action,
    /// Captured parameter tokens, in grammar order.
    pub params: Vec<String>,
}

/// The result of a `?` help request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Help {
    /// The candidates at this point: (display, help) pairs — the
    /// `<cr>` pseudo-entry appears when the input already forms a
    /// complete command.
    Entries(Vec<(String, String)>),
    /// The input cannot prefix any command.
    Err(MatchErr),
}

/// One tree node: children with their [`Tok`]s, plus the command
/// index if a full command ends here.
#[derive(Debug, Default)]
struct Node {
    children: Vec<(Tok, Node)>,
    leaf: Option<usize>,
}

/// The matching step shared by `find` and `help`: the one child that
/// survives `token` (exact literal first, then the single survivor
/// of prefixes and valid params).
fn step<'a>(node: &'a Node, token: &str) -> Result<&'a (Tok, Node), MatchErr> {
    if let Some(child) = node
        .children
        .iter()
        .find(|(t, _)| matches!(t, Tok::Lit { word, .. } if *word == token))
    {
        return Ok(child);
    }
    let mut candidates = node
        .children
        .iter()
        .filter(|(t, _)| match t {
            Tok::Lit { word, .. } => word.starts_with(token),
            Tok::Param { kind, .. } => kind.accepts(token),
        })
        .collect::<Vec<_>>()
        .into_iter();
    match (candidates.next(), candidates.next()) {
        (Some(only), None) => Ok(only),
        // No survivor: when a parameter sits at this point the token
        // is reported against what was expected (`% Invalid input:
        // ... — expected <A.B.C.D/M>`), otherwise it is simply
        // unknown.
        (None, None) => match node
            .children
            .iter()
            .find(|(t, _)| matches!(t, Tok::Param { kind, .. } if !kind.accepts(token)))
        {
            Some((Tok::Param { kind, .. }, _)) => Err(MatchErr::InvalidParam {
                token: token.to_string(),
                expected: kind.display_name(),
            }),
            _ => Err(MatchErr::Unknown),
        },
        _ => Err(MatchErr::Ambiguous(
            node.children
                .iter()
                .filter(|(t, _)| match t {
                    Tok::Lit { word, .. } => word.starts_with(token),
                    Tok::Param { kind, .. } => kind.accepts(token),
                })
                .map(|(t, _)| t.display())
                .collect(),
        )),
    }
}

/// A mode's command tree.
#[derive(Debug, Default)]
pub struct WordTree {
    root: Node,
    cmds: Vec<Cmd>,
}

impl WordTree {
    /// An empty tree.
    pub fn new() -> WordTree {
        WordTree::default()
    }

    /// Registers one command.
    pub fn insert(&mut self, cmd: Cmd) {
        let index = self.cmds.len();
        let mut node = &mut self.root;
        for tok in &cmd.toks {
            let same = |t: &Tok| {
                matches!(
                    (t, tok),
                    (Tok::Lit { word: a, .. }, Tok::Lit { word: b, .. }) if a == b
                ) || (matches!(t, Tok::Param { .. }) && matches!(tok, Tok::Param { .. }))
            };
            let next = match node.children.iter().position(|(t, _)| same(t)) {
                Some(position) => &mut node.children[position].1,
                None => {
                    node.children.push((tok.clone(), Node::default()));
                    let last = node.children.len() - 1;
                    &mut node.children[last].1
                }
            };
            node = next;
        }
        node.leaf = Some(index);
        self.cmds.push(cmd);
    }

    /// Matches a token slice against the tree.
    pub fn find(&self, tokens: &[&str]) -> Result<Match, MatchErr> {
        let mut node = &self.root;
        let mut params = Vec::new();
        for token in tokens {
            let (tok, next) = step(node, token)?;
            if matches!(tok, Tok::Param { .. }) {
                params.push((*token).to_string());
            }
            node = next;
        }
        match node.leaf {
            Some(index) => Ok(Match {
                action: self.cmds[index].action,
                params,
            }),
            None => Err(MatchErr::Incomplete),
        }
    }

    /// `?` help: for input made of complete `tokens` (each possibly
    /// abbreviated) plus an optional trailing partial word (the
    /// `sh?` no-space form), the candidates that could come next.
    pub fn help(&self, tokens: &[&str], partial: Option<&str>) -> Help {
        let mut node = &self.root;
        for token in tokens {
            match step(node, token) {
                Ok((_, next)) => node = next,
                Err(err) => return Help::Err(err),
            }
        }
        if let Some(frag) = partial.filter(|f| !f.is_empty()) {
            let mut candidates: Vec<(String, String)> = node
                .children
                .iter()
                .filter_map(|(t, _)| match t {
                    Tok::Lit { word, help } => word
                        .starts_with(frag)
                        .then(|| ((*word).to_string(), (*help).to_string())),
                    Tok::Param { .. } => None,
                })
                .collect();
            candidates.sort();
            if candidates.is_empty() {
                return Help::Err(MatchErr::Unknown);
            }
            return Help::Entries(candidates);
        }
        let mut entries: Vec<(String, String)> = node
            .children
            .iter()
            .map(|(t, _)| (t.display(), t.help_text().to_string()))
            .collect();
        entries.sort();
        if node.leaf.is_some() {
            entries.push(("<cr>".to_string(), String::new()));
        }
        if entries.is_empty() {
            return Help::Err(MatchErr::Incomplete);
        }
        Help::Entries(entries)
    }

    /// Every registered command, as `list` prints them (grammar
    /// rendered, then help).
    pub fn command_lines(&self) -> Vec<String> {
        let mut lines = Vec::new();
        for cmd in &self.cmds {
            let words: Vec<String> = cmd.toks.iter().map(|t| t.display()).collect();
            lines.push(format!("{}  {}", words.join(" "), cmd.help));
        }
        lines
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn lit(word: &'static str, help: &'static str) -> Tok {
        Tok::Lit { word, help }
    }

    fn tree() -> WordTree {
        let mut t = WordTree::new();
        t.insert(Cmd {
            toks: vec![lit("show", ""), lit("version", "")],
            action: Action::ShowVersion,
            help: "version",
        });
        t.insert(Cmd {
            toks: vec![lit("show", ""), lit("sav", "")],
            action: Action::ShowSav,
            help: "sav",
        });
        t.insert(Cmd {
            toks: vec![lit("show", ""), lit("sav", ""), lit("rules", "")],
            action: Action::ShowSavRules,
            help: "rules",
        });
        t.insert(Cmd {
            toks: vec![lit("enable", "")],
            action: Action::Enable,
            help: "enable",
        });
        t.insert(Cmd {
            toks: vec![lit("exit", "")],
            action: Action::Exit,
            help: "exit",
        });
        t
    }

    #[test]
    fn full_words_match() {
        let t = tree();
        assert_eq!(
            t.find(&["show", "version"]).unwrap().action,
            Action::ShowVersion
        );
    }

    #[test]
    fn abbreviated_unambiguous_prefix_matches() {
        let t = tree();
        assert_eq!(t.find(&["sh", "ver"]).unwrap().action, Action::ShowVersion);
        assert_eq!(t.find(&["sh", "sa"]).unwrap().action, Action::ShowSav);
    }

    #[test]
    fn ambiguous_prefix_is_an_error_naming_candidates() {
        let t = tree();
        // `e` prefixes both `enable` and `exit`.
        let err = t.find(&["e"]).unwrap_err();
        assert_eq!(
            err,
            MatchErr::Ambiguous(vec!["enable".into(), "exit".into()])
        );
    }

    #[test]
    fn exact_word_beats_ambiguity() {
        let t = tree();
        assert_eq!(t.find(&["enable"]).unwrap().action, Action::Enable);
    }

    #[test]
    fn complete_command_wins_over_extension() {
        let t = tree();
        // `show sav` is itself a command even though `show sav
        // rules` extends it.
        assert_eq!(t.find(&["show", "sav"]).unwrap().action, Action::ShowSav);
        assert_eq!(
            t.find(&["show", "sav", "rules"]).unwrap().action,
            Action::ShowSavRules
        );
    }

    #[test]
    fn prefix_of_a_command_only_is_incomplete() {
        let t = tree();
        assert_eq!(t.find(&["show"]).unwrap_err(), MatchErr::Incomplete);
    }

    #[test]
    fn unknown_word_is_reported_with_the_b7_shape() {
        let t = tree();
        let err = t.find(&["show", "frobnicate"]).unwrap_err();
        assert_eq!(
            err.error_line("show frobnicate"),
            "% Unknown command: show frobnicate"
        );
    }

    #[test]
    fn help_lists_children_with_their_help() {
        let t = tree();
        let Help::Entries(entries) = t.help(&["sh"], None) else {
            panic!("expected entries");
        };
        let words: Vec<&str> = entries.iter().map(|(w, _)| w.as_str()).collect();
        assert!(words.contains(&"version") && words.contains(&"sav"));
    }

    #[test]
    fn help_offers_cr_when_the_command_is_already_complete() {
        let t = tree();
        let Help::Entries(entries) = t.help(&["sh", "ver"], None) else {
            panic!("expected entries");
        };
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].0, "<cr>");
    }

    #[test]
    fn help_after_a_partial_word_lists_completions() {
        let t = tree();
        let Help::Entries(entries) = t.help(&[], Some("sh")) else {
            panic!("expected entries");
        };
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].0, "show");
    }

    #[test]
    fn params_validate_and_capture() {
        let mut t = WordTree::new();
        t.insert(Cmd {
            toks: vec![
                lit("ip", ""),
                lit("route", ""),
                Tok::Param {
                    kind: ParamKind::Ipv4Prefix,
                    help: "prefix",
                },
                lit("blackhole", ""),
            ],
            action: Action::IpRoute,
            help: "static",
        });
        t.insert(Cmd {
            toks: vec![
                lit("ip", ""),
                lit("route", ""),
                Tok::Param {
                    kind: ParamKind::Ipv4Prefix,
                    help: "prefix",
                },
                Tok::Param {
                    kind: ParamKind::Ipv4,
                    help: "gateway",
                },
            ],
            action: Action::IpRoute,
            help: "static",
        });
        let m = t
            .find(&["ip", "route", "203.0.113.0/24", "blackhole"])
            .unwrap();
        assert_eq!(m.params, vec!["203.0.113.0/24"]);
        let m = t
            .find(&["ip", "route", "203.0.113.0/24", "192.0.2.1"])
            .unwrap();
        assert_eq!(m.params.len(), 2);
        // `blackhole` is not ambiguous with a gateway-shaped param
        // (exact literal wins), and at a param position a token that
        // fails validation names the expectation rather than being
        // merely unknown.
        assert_eq!(
            t.find(&["ip", "route", "203.0.113.0/24", "via"])
                .unwrap_err(),
            MatchErr::InvalidParam {
                token: "via".into(),
                expected: "<A.B.C.D>"
            }
        );
        // A malformed prefix is an invalid param, not unknown.
        assert_eq!(
            t.find(&["ip", "route", "203.0.113.0/33", "blackhole"])
                .unwrap_err(),
            MatchErr::InvalidParam {
                token: "203.0.113.0/33".into(),
                expected: "<A.B.C.D/M>"
            }
        );
    }

    #[test]
    fn list_renders_every_registered_command() {
        let t = tree();
        let lines = t.command_lines();
        assert_eq!(lines.len(), 5);
        assert!(lines.iter().any(|l| l.starts_with("show version")));
    }
}
