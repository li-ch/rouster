//! The per-connection session — a pure state machine so every line
//! behavior is testable without a socket.
//!
//! State: the mode stack (`user → enable → configure [→
//! config-router → config-router-af]`), the hostname (the prompt's
//! name), and the parse-only session config tree. The server feeds
//! lines in and writes [`Outcome`] out; `exit` at the bottom of the
//! stack asks the server to close the connection.
//!
//! Cisco behaviors v1 keeps: abbreviated unambiguous commands, `?`
//! help anywhere (with `<cr>` when the line already matches), `do
//! <exec command>` from config family modes, `end` jumping to
//! enable, `disable` dropping to user. v1 has no enable password
//! (disclosed: one more thing nobody has designed yet).

use std::path::PathBuf;

use crate::commands;
use crate::config::{Af, AfLine, Nexthop, SessionConfig};
use crate::protocol;
use crate::render;
use crate::tree::{Action, Help, WordTree};

/// Server facts the session renders into `show version`.
#[derive(Debug, Clone)]
pub struct ServerInfo {
    /// The address the listener is bound to.
    pub bind: String,
    /// The port the listener is bound to.
    pub port: u16,
    /// The run dir every show command reads.
    pub run_dir: PathBuf,
    /// When the server started (for uptime).
    pub started: std::time::Instant,
    /// The server's own pid.
    pub pid: u32,
}

/// One connection's mode stack entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Mode {
    /// `host>` — unprivileged exec.
    User,
    /// `host#` — privileged exec.
    Enable,
    /// `host(config)#` — configuration.
    Config,
    /// `host(config-router)#` — a `router bgp <asn>` node.
    ConfigRouter {
        /// The AS this router node configures.
        asn: String,
    },
    /// `host(config-router-af)#` — an address-family node.
    ConfigRouterAf {
        /// The AS of the owning router node.
        asn: String,
        /// The family's own name (`ipv4 unicast`).
        family: String,
    },
}

impl Mode {
    /// The prompt between the hostname and the mode suffix.
    fn suffix(&self) -> &'static str {
        match self {
            Mode::User => "> ",
            Mode::Enable => "# ",
            Mode::Config => "(config)# ",
            Mode::ConfigRouter { .. } => "(config-router)# ",
            Mode::ConfigRouterAf { .. } => "(config-router-af)# ",
        }
    }

    /// The config family (anything past enable).
    fn is_config_family(&self) -> bool {
        matches!(
            self,
            Mode::Config | Mode::ConfigRouter { .. } | Mode::ConfigRouterAf { .. }
        )
    }
}

/// What handling one line produced.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Outcome {
    /// Output lines to print (each CRLF-terminated by the server).
    Lines(Vec<String>),
    /// Close the connection (`exit` at the bottom of the stack).
    Close,
}

impl Outcome {
    /// No output (empty line, or a command that prints nothing).
    fn empty() -> Outcome {
        Outcome::Lines(Vec::new())
    }
}

/// The session state machine.
pub struct Session {
    /// The prompt's hostname (also the config's `hostname`).
    pub hostname: String,
    /// The mode stack; the top is current.
    pub modes: Vec<Mode>,
    /// The parse-only session config.
    pub config: SessionConfig,
    /// Server facts for `show version`.
    pub info: ServerInfo,
}

impl Session {
    /// A fresh session in user mode.
    pub fn new(hostname: String, info: ServerInfo) -> Session {
        Session {
            hostname,
            modes: vec![Mode::User],
            config: SessionConfig::new(),
            info,
        }
    }

    /// The current mode.
    fn mode(&self) -> &Mode {
        self.modes.last().expect("mode stack is never empty")
    }

    /// The current prompt (hostname + mode suffix).
    pub fn prompt(&self) -> String {
        format!("{}{}", self.hostname, self.mode().suffix())
    }

    /// The current mode's command tree.
    fn tree(&self) -> WordTree {
        match self.mode() {
            Mode::User => commands::user_tree(),
            Mode::Enable => commands::enable_tree(),
            Mode::Config => commands::config_tree(),
            Mode::ConfigRouter { .. } => commands::config_router_tree(),
            Mode::ConfigRouterAf { .. } => commands::config_af_tree(),
        }
    }

    /// Handles one input line (CRLF already stripped).
    pub fn handle_line(&mut self, line: &str) -> Outcome {
        let line = line.trim();
        if line.is_empty() {
            return Outcome::empty();
        }
        if line.ends_with('?') {
            return self.help(line);
        }
        // `do <exec command>` — run exec commands from config family
        // modes (Cisco's escape hatch, handled before the trees
        // because it takes a whole line, not a word).
        if self.mode().is_config_family() {
            if line == "do" {
                return Outcome::Lines(vec!["% Incomplete command.".into()]);
            }
            if let Some(rest) = line.strip_prefix("do ") {
                let rest = rest.trim_start();
                let tokens: Vec<&str> = rest.split_whitespace().collect();
                return self.exec(&commands::enable_tree(), &tokens, rest);
            }
        }
        let tokens: Vec<&str> = line.split_whitespace().collect();
        let tree = self.tree();
        self.exec(&tree, &tokens, line)
    }

    /// Match `tokens` against `tree` and run the action.
    fn exec(&mut self, tree: &WordTree, tokens: &[&str], line: &str) -> Outcome {
        match tree.find(tokens) {
            Ok(m) => self.run(m.action, &m.params),
            Err(err) => Outcome::Lines(vec![err.error_line(line)]),
        }
    }

    /// The `?` help path: split the raw line at the `?`; the words
    /// before it walk the tree, and — when the `?` touches a word
    /// (`sh?`, Cisco's no-space form) — that fragment filters the
    /// candidate words instead of descending.
    fn help(&mut self, line: &str) -> Outcome {
        let raw = line.strip_suffix('?').unwrap_or(line);
        let mut tokens: Vec<&str> = raw.split_whitespace().collect();
        let partial = if raw.is_empty() || raw.ends_with(' ') {
            None
        } else {
            tokens.pop()
        };
        let tree = self.tree();
        let mut out = Vec::new();
        match tree.help(&tokens, partial) {
            Help::Entries(entries) => {
                let width = entries.iter().map(|(w, _)| w.len()).max().unwrap_or(0);
                for (word, help) in entries {
                    out.push(format!("{word:<width$}  {help}", width = width));
                }
            }
            Help::Err(err) => out.push(err.error_line(raw.trim())),
        }
        Outcome::Lines(out)
    }

    /// Runs a matched action.
    fn run(&mut self, action: Action, params: &[String]) -> Outcome {
        match action {
            Action::ShowVersion => Outcome::Lines(render::show_version(self)),
            Action::ShowSav => Outcome::Lines(render::show_sav(&self.info.run_dir, false)),
            Action::ShowSavRules => Outcome::Lines(render::show_sav(&self.info.run_dir, true)),
            Action::ShowBfd => Outcome::Lines(render::show_bfd(&self.info.run_dir, false)),
            Action::ShowBfdSummary => Outcome::Lines(render::show_bfd(&self.info.run_dir, true)),
            Action::ShowInterface => Outcome::Lines(render::show_interfaces(
                &self.info.run_dir,
                params.first().map(String::as_str),
            )),
            Action::ShowIpInterface => Outcome::Lines(render::show_interfaces(
                &self.info.run_dir,
                params.first().map(String::as_str),
            )),
            Action::ShowNeighbor => Outcome::Lines(render::show_neighbors(
                &self.info.run_dir,
                params.first().map(String::as_str),
            )),
            Action::ShowVrf => Outcome::Lines(render::show_vrf(&self.info.run_dir)),
            Action::ShowRibSummary | Action::ShowIpRouteSummary => {
                Outcome::Lines(render::show_rib_summary(&self.info.run_dir))
            }
            Action::ShowRunningConfig => {
                let hostname = self.hostname.clone();
                Outcome::Lines(
                    self.config
                        .render(&hostname)
                        .lines()
                        .map(String::from)
                        .collect(),
                )
            }
            Action::List => Outcome::Lines(self.tree().command_lines()),
            Action::Enable => {
                if *self.mode() == Mode::User {
                    self.modes.push(Mode::Enable);
                }
                Outcome::empty()
            }
            Action::Disable => {
                self.modes.truncate(1);
                Outcome::empty()
            }
            Action::Exit | Action::ExitAddressFamily => {
                self.modes.pop();
                if self.modes.is_empty() {
                    Outcome::Close
                } else {
                    Outcome::empty()
                }
            }
            Action::End => {
                // From anywhere in the config family, back to
                // enable; below enable `end` is not registered.
                self.modes.truncate(self.modes.len().min(2));
                Outcome::empty()
            }
            Action::ConfTerm => {
                if *self.mode() == Mode::Enable {
                    self.modes.push(Mode::Config);
                }
                Outcome::empty()
            }
            Action::Write => Outcome::Lines(vec![
                "% Configuration apply is deferred in vty v1 (parse-only).".into(),
                "  The session config is kept for display via `show running-config`;".into(),
                "  apply needs the owner's transactional-config design".into(),
                "  (docs/protocols/vty.md, §Deferred).".into(),
            ]),
            Action::Hostname => {
                let name = params[0].clone();
                self.hostname = name.clone();
                self.config.set_hostname(name);
                Outcome::empty()
            }
            Action::FrrVersion => {
                self.config.set_frr_version(params[0].clone());
                Outcome::empty()
            }
            Action::FrrDefaults => {
                self.config.set_frr_defaults(params[0].clone());
                Outcome::empty()
            }
            Action::LineVty => {
                self.config.set_line_vty();
                Outcome::empty()
            }
            Action::IpRoute => {
                let (af, prefix, nexthop) = static_route(params);
                self.config.add_static(af, prefix, nexthop);
                Outcome::empty()
            }
            Action::NoIpRoute => {
                let (af, prefix, nexthop) = static_route(params);
                self.config.remove_static(af, &prefix, Some(&nexthop));
                Outcome::empty()
            }
            Action::RouteMap => {
                self.config.add_route_map(params[0].clone());
                Outcome::empty()
            }
            Action::RouterBgp => {
                let asn = params[0].clone();
                self.config.bgp_mut(asn.clone());
                self.modes.push(Mode::ConfigRouter { asn });
                Outcome::empty()
            }
            Action::BgpImportCheck => {
                self.with_router_bgp(|bgp| bgp.set_import_check(true));
                Outcome::empty()
            }
            Action::NoBgpImportCheck => {
                self.with_router_bgp(|bgp| bgp.set_import_check(false));
                Outcome::empty()
            }
            Action::BgpRouterId => {
                let id = params[0].clone();
                self.with_router_bgp(|bgp| bgp.set_router_id(id));
                Outcome::empty()
            }
            Action::BgpNeighbor => {
                let (addr, remote_as) = (params[0].clone(), params[1].clone());
                self.with_router_bgp(|bgp| bgp.add_neighbor(addr, remote_as));
                Outcome::empty()
            }
            Action::AddressFamily => {
                if let Mode::ConfigRouter { asn } = self.mode() {
                    let asn = asn.clone();
                    let family = "ipv4 unicast".to_string();
                    self.config.bgp_mut(asn.clone()).af_mut(&family);
                    self.modes.push(Mode::ConfigRouterAf { asn, family });
                }
                Outcome::empty()
            }
            Action::AfNetwork => {
                let prefix = params[0].clone();
                self.with_af_lines(|lines| lines.push(AfLine::Network(prefix)));
                Outcome::empty()
            }
            Action::AfRedistributeStatic => {
                self.with_af_lines(|lines| {
                    if !lines
                        .iter()
                        .any(|l| matches!(l, AfLine::RedistributeStatic))
                    {
                        lines.push(AfLine::RedistributeStatic);
                    }
                });
                Outcome::empty()
            }
        }
    }

    /// Mutates the router-bgp node the current mode selects
    /// (`bgp_mut` re-creates it if a previous action removed it,
    /// which none can — mode stack and config stay in lockstep).
    fn with_router_bgp(&mut self, f: impl FnOnce(&mut crate::config::BgpNode)) {
        if let Mode::ConfigRouter { asn } | Mode::ConfigRouterAf { asn, .. } = self.mode() {
            let asn = asn.clone();
            f(self.config.bgp_mut(asn));
        }
    }

    /// Mutates the address-family lines the current mode selects.
    fn with_af_lines(&mut self, f: impl FnOnce(&mut Vec<AfLine>)) {
        if let Mode::ConfigRouterAf { asn, family } = self.mode() {
            let (asn, family) = (asn.clone(), family.clone());
            let bgp = self.config.bgp_mut(asn);
            f(bgp.af_mut(&family));
        }
    }
}

/// Rebuilds the static-route tuple from matched params: v4 blackhole
/// (`[prefix, "blackhole"]`), v4 gateway (`[prefix, gw]`), v6
/// blackhole (`[prefix, "blackhole"]`). The grammar that matched
/// does not ride along with `find`, so the prefix's shape decides
/// the family (`:` = IPv6).
fn static_route(params: &[String]) -> (Af, String, Nexthop) {
    let prefix = params[0].clone();
    let tail = params.get(1).cloned().unwrap_or_else(|| "blackhole".into());
    let af = if prefix.contains(':') { Af::V6 } else { Af::V4 };
    let nexthop = if tail == "blackhole" {
        Nexthop::Blackhole
    } else {
        Nexthop::Addr(tail)
    };
    (af, prefix, nexthop)
}

/// The banner every connection sees first (protocol disclosure
/// included — v1 is a plain TCP line protocol, and says so).
pub fn banner() -> String {
    protocol::banner(crate::VERSION)
}
