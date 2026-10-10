//! The parse-only session config tree — config mode in v1 accepts
//! the quarantine-B7 observed frr.conf grammar subset and echoes it
//! back via `show running-config`. Nothing is applied: apply needs
//! the owner's transactional-config design (§Deferred in
//! `docs/protocols/vty.md`), and this module records that anchor.
//!
//! Rendering follows the FRR shape observed in B7: router-bgp
//! children get one leading space, address-family children two, `!`
//! separates stanzas, `end` closes the file.

/// The address family a static route belongs to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Af {
    /// `ip route`.
    V4,
    /// `ipv6 route`.
    V6,
}

impl Af {
    /// The keyword that introduced the route.
    pub fn keyword(self) -> &'static str {
        match self {
            Af::V4 => "ip",
            Af::V6 => "ipv6",
        }
    }
}

/// One route's nexthop form.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Nexthop {
    /// `blackhole`.
    Blackhole,
    /// A gateway address.
    Addr(String),
}

impl Nexthop {
    /// As rendered in a config line.
    pub fn text(&self) -> &str {
        match self {
            Nexthop::Blackhole => "blackhole",
            Nexthop::Addr(addr) => addr,
        }
    }
}

/// One address-family line inside a router-bgp node.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AfLine {
    /// `network <prefix>`.
    Network(String),
    /// `redistribute static`.
    RedistributeStatic,
}

impl AfLine {
    fn text(&self) -> String {
        match self {
            AfLine::Network(prefix) => format!("network {prefix}"),
            AfLine::RedistributeStatic => "redistribute static".into(),
        }
    }
}

/// One child line of a router-bgp node (B7 §3's observed set).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BgpLine {
    /// `bgp network import-check` on or off (off renders with the
    /// `no` prefix — the form B7 observed).
    ImportCheck(bool),
    /// `bgp router-id <v4>`.
    RouterId(String),
    /// `neighbor <v4> remote-as <asn>`.
    Neighbor {
        /// The neighbor's address.
        addr: String,
        /// The neighbor's remote AS.
        remote_as: String,
    },
    /// `address-family ipv4 unicast` with its child lines.
    AddressFamily {
        /// The family's own name (`ipv4 unicast`).
        name: String,
        /// The family's child lines.
        lines: Vec<AfLine>,
    },
}

impl BgpLine {
    /// The line as `show running-config` renders it (one-space
    /// indent; address-family children get their own two-space
    /// lines inside).
    fn render(&self) -> Vec<String> {
        match self {
            BgpLine::ImportCheck(true) => vec![" bgp network import-check".into()],
            BgpLine::ImportCheck(false) => vec![" no bgp network import-check".into()],
            BgpLine::RouterId(id) => vec![format!(" bgp router-id {id}")],
            BgpLine::Neighbor { addr, remote_as } => {
                vec![format!(" neighbor {addr} remote-as {remote_as}")]
            }
            BgpLine::AddressFamily { name, lines } => {
                let mut out = vec![format!(" address-family {name}")];
                out.extend(lines.iter().map(|line| format!("  {}", line.text())));
                out.push(" exit-address-family".into());
                out
            }
        }
    }
}

/// One top-level config node.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CfgNode {
    /// `frr version <s>`.
    FrrVersion(String),
    /// `frr defaults <s>`.
    FrrDefaults(String),
    /// `hostname <s>` (kept in sync with the session's prompt).
    Hostname(String),
    /// `line vty`.
    LineVty,
    /// `ip|ipv6 route <prefix> <nh>`.
    StaticRoute {
        /// The family keyword that introduced the route.
        af: Af,
        /// The destination prefix, verbatim.
        prefix: String,
        /// The nexthop form.
        nexthop: Nexthop,
    },
    /// A `route-map ...` line, kept verbatim for display.
    RouteMap(String),
    /// A `router bgp <asn>` node with its children.
    RouterBgp(BgpNode),
}

/// A router-bgp node: the AS plus its child lines, in entry order.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BgpNode {
    /// The AS number string.
    pub asn: String,
    /// The child lines.
    pub lines: Vec<BgpLine>,
}

impl BgpNode {
    /// Sets the import-check line (replaces any previous one).
    pub fn set_import_check(&mut self, on: bool) {
        self.lines.retain(|l| !matches!(l, BgpLine::ImportCheck(_)));
        self.lines.push(BgpLine::ImportCheck(on));
    }

    /// Sets the router-id line (replaces any previous one).
    pub fn set_router_id(&mut self, id: String) {
        self.lines.retain(|l| !matches!(l, BgpLine::RouterId(_)));
        self.lines.push(BgpLine::RouterId(id));
    }

    /// Adds (or replaces, keyed on the address) a neighbor line.
    pub fn add_neighbor(&mut self, addr: String, remote_as: String) {
        self.lines
            .retain(|l| !matches!(l, BgpLine::Neighbor { addr: a, .. } if *a == addr));
        self.lines.push(BgpLine::Neighbor { addr, remote_as });
    }

    /// The address-family node named `name`, created if absent.
    pub fn af_mut(&mut self, name: &str) -> &mut Vec<AfLine> {
        let existing = self
            .lines
            .iter()
            .position(|l| matches!(l, BgpLine::AddressFamily { name: n, .. } if n == name));
        let index = existing.unwrap_or_else(|| {
            self.lines.push(BgpLine::AddressFamily {
                name: name.to_string(),
                lines: Vec::new(),
            });
            self.lines.len() - 1
        });
        let Some(BgpLine::AddressFamily { lines, .. }) = self.lines.get_mut(index) else {
            unreachable!("just pushed or found");
        };
        lines
    }
}

/// The session's configuration — parse-only in v1.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SessionConfig {
    /// Top-level nodes in entry order (headers first is a
    /// rendering concern, not an invariant).
    pub nodes: Vec<CfgNode>,
}

impl SessionConfig {
    /// An empty config.
    pub fn new() -> SessionConfig {
        SessionConfig::default()
    }

    /// Sets `hostname` (replaces any previous one).
    pub fn set_hostname(&mut self, name: String) {
        match self
            .nodes
            .iter_mut()
            .find(|n| matches!(n, CfgNode::Hostname(_)))
        {
            Some(CfgNode::Hostname(existing)) => *existing = name,
            _ => self.nodes.push(CfgNode::Hostname(name)),
        }
    }

    /// Sets `frr version` (replaces any previous one).
    pub fn set_frr_version(&mut self, version: String) {
        match self
            .nodes
            .iter_mut()
            .find(|n| matches!(n, CfgNode::FrrVersion(_)))
        {
            Some(CfgNode::FrrVersion(existing)) => *existing = version,
            _ => self.nodes.push(CfgNode::FrrVersion(version)),
        }
    }

    /// Sets `frr defaults` (replaces any previous one).
    pub fn set_frr_defaults(&mut self, defaults: String) {
        match self
            .nodes
            .iter_mut()
            .find(|n| matches!(n, CfgNode::FrrDefaults(_)))
        {
            Some(CfgNode::FrrDefaults(existing)) => *existing = defaults,
            _ => self.nodes.push(CfgNode::FrrDefaults(defaults)),
        }
    }

    /// Marks the `line vty` stanza present.
    pub fn set_line_vty(&mut self) {
        if !self.nodes.iter().any(|n| matches!(n, CfgNode::LineVty)) {
            self.nodes.push(CfgNode::LineVty);
        }
    }

    /// Adds a static route unless the same (af, prefix, nexthop)
    /// triple is already present.
    pub fn add_static(&mut self, af: Af, prefix: String, nexthop: Nexthop) {
        let exists = self.nodes.iter().any(|n| {
            matches!(
                n,
                CfgNode::StaticRoute { af: a, prefix: p, nexthop: nh }
                    if *a == af && *p == prefix && *nh == nexthop
            )
        });
        if !exists {
            self.nodes.push(CfgNode::StaticRoute {
                af,
                prefix,
                nexthop,
            });
        }
    }

    /// Removes static routes matching (af, prefix) — all nexthops,
    /// or only the one named by `nexthop` when given.
    pub fn remove_static(&mut self, af: Af, prefix: &str, nexthop: Option<&Nexthop>) {
        self.nodes.retain(|n| {
            !matches!(
                n,
                CfgNode::StaticRoute { af: a, prefix: p, nexthop: nh }
                    if *a == af && p == prefix && nexthop_is(nexthop, nh)
            )
        });
    }

    /// Adds a verbatim route-map line.
    pub fn add_route_map(&mut self, rest: String) {
        self.nodes.push(CfgNode::RouteMap(rest));
    }

    /// The router-bgp node for `asn`, created if absent.
    pub fn bgp_mut(&mut self, asn: String) -> &mut BgpNode {
        let existing = self
            .nodes
            .iter()
            .position(|n| matches!(n, CfgNode::RouterBgp(node) if node.asn == asn));
        let index = existing.unwrap_or_else(|| {
            self.nodes.push(CfgNode::RouterBgp(BgpNode {
                asn,
                lines: Vec::new(),
            }));
            self.nodes.len() - 1
        });
        let Some(CfgNode::RouterBgp(node)) = self.nodes.get_mut(index) else {
            unreachable!("just pushed or found");
        };
        node
    }

    /// `show running-config` rendering: the FRR file shape — header
    /// directives, the hostname, then `!`-separated stanzas in the
    /// canonical order (statics, route-maps, router-bgp, `line vty`
    /// last; entry order kept within a kind), bgp nesting at the
    /// observed indentations, `end` closing. `!` separators are
    /// regenerated, never stored.
    pub fn render(&self, hostname: &str) -> String {
        let mut out = String::new();
        for node in &self.nodes {
            match node {
                CfgNode::FrrVersion(version) => {
                    out.push_str(&format!("frr version {version}\n"));
                }
                CfgNode::FrrDefaults(defaults) => {
                    out.push_str(&format!("frr defaults {defaults}\n"));
                }
                _ => {}
            }
        }
        out.push_str(&format!("hostname {hostname}\n"));
        let mut stanzas = self.nodes.clone();
        stanzas.sort_by_key(stanza_order);
        for node in &stanzas {
            match node {
                CfgNode::FrrVersion(_) | CfgNode::FrrDefaults(_) | CfgNode::Hostname(_) => {}
                CfgNode::StaticRoute {
                    af,
                    prefix,
                    nexthop,
                } => {
                    out.push_str(&format!(
                        "!\n{} route {prefix} {}\n",
                        af.keyword(),
                        nexthop.text()
                    ));
                }
                CfgNode::RouteMap(rest) => out.push_str(&format!("!\nroute-map {rest}\n")),
                CfgNode::RouterBgp(bgp) => {
                    out.push_str(&format!("!\nrouter bgp {}\n", bgp.asn));
                    for line in &bgp.lines {
                        for text in line.render() {
                            out.push_str(&text);
                            out.push('\n');
                        }
                    }
                }
                CfgNode::LineVty => out.push_str("!\nline vty\n"),
            }
        }
        out.push_str("end\n");
        out
    }
}

/// The canonical stanza order for rendering (stable within a kind —
/// `sort_by_key` is stable, so entry order survives).
fn stanza_order(node: &CfgNode) -> u8 {
    match node {
        CfgNode::FrrVersion(_) | CfgNode::FrrDefaults(_) | CfgNode::Hostname(_) => 0,
        CfgNode::StaticRoute { .. } => 1,
        CfgNode::RouteMap(_) => 2,
        CfgNode::RouterBgp(_) => 3,
        CfgNode::LineVty => 4,
    }
}

/// Retain predicate helper: does removal `nexthop` (None = any)
/// cover this stored nexthop?
fn nexthop_is(wanted: Option<&Nexthop>, stored: &Nexthop) -> bool {
    match wanted {
        None => true,
        Some(wanted) => wanted == stored,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_config_renders_hostname_and_end() {
        let config = SessionConfig::new();
        assert_eq!(config.render("rouster"), "hostname rouster\nend\n");
    }

    #[test]
    fn hostname_replaces_rather_than_accumulates() {
        let mut config = SessionConfig::new();
        config.set_hostname("r1".into());
        config.set_hostname("r2".into());
        assert_eq!(config.render("r2"), "hostname r2\nend\n");
    }

    #[test]
    fn static_routes_render_in_family_order() {
        let mut config = SessionConfig::new();
        config.add_static(Af::V4, "203.0.113.0/24".into(), Nexthop::Blackhole);
        config.add_static(
            Af::V4,
            "198.51.100.0/24".into(),
            Nexthop::Addr("192.0.2.1".into()),
        );
        config.add_static(Af::V6, "2001:db8::/32".into(), Nexthop::Blackhole);
        let text = config.render("r1");
        assert!(text.contains("ip route 203.0.113.0/24 blackhole\n"));
        assert!(text.contains("ip route 198.51.100.0/24 192.0.2.1\n"));
        assert!(text.contains("ipv6 route 2001:db8::/32 blackhole\n"));
    }

    #[test]
    fn duplicate_static_route_is_idempotent() {
        let mut config = SessionConfig::new();
        config.add_static(Af::V4, "203.0.113.0/24".into(), Nexthop::Blackhole);
        config.add_static(Af::V4, "203.0.113.0/24".into(), Nexthop::Blackhole);
        assert_eq!(
            config
                .nodes
                .iter()
                .filter(|n| matches!(n, CfgNode::StaticRoute { .. }))
                .count(),
            1
        );
    }

    #[test]
    fn no_ip_route_removes_only_the_named_one() {
        let mut config = SessionConfig::new();
        config.add_static(Af::V4, "203.0.113.0/24".into(), Nexthop::Blackhole);
        config.add_static(
            Af::V4,
            "203.0.113.0/24".into(),
            Nexthop::Addr("192.0.2.1".into()),
        );
        config.remove_static(
            Af::V4,
            "203.0.113.0/24",
            Some(&Nexthop::Addr("192.0.2.1".into())),
        );
        let routes: Vec<_> = config
            .nodes
            .iter()
            .filter_map(|n| match n {
                CfgNode::StaticRoute { nexthop, .. } => Some(nexthop.clone()),
                _ => None,
            })
            .collect();
        assert_eq!(routes, vec![Nexthop::Blackhole]);
        // And the any-nexthop form clears the rest.
        config.remove_static(Af::V4, "203.0.113.0/24", None);
        assert!(!config
            .nodes
            .iter()
            .any(|n| matches!(n, CfgNode::StaticRoute { .. })));
    }

    #[test]
    fn bgp_node_renders_the_b7_observed_shape() {
        let mut config = SessionConfig::new();
        let bgp = config.bgp_mut("65000".into());
        bgp.lines.push(BgpLine::ImportCheck(false));
        bgp.lines.push(BgpLine::RouterId("192.0.2.254".into()));
        bgp.lines.push(BgpLine::Neighbor {
            addr: "192.0.2.2".into(),
            remote_as: "65000".into(),
        });
        let af = bgp.af_mut("ipv4 unicast");
        af.push(AfLine::Network("203.0.113.0/24".into()));
        af.push(AfLine::RedistributeStatic);
        let text = config.render("r1");
        let expected = "\
router bgp 65000
 no bgp network import-check
 bgp router-id 192.0.2.254
 neighbor 192.0.2.2 remote-as 65000
 address-family ipv4 unicast
  network 203.0.113.0/24
  redistribute static
 exit-address-family
";
        assert!(text.contains(expected), "rendered:\n{text}");
    }

    #[test]
    fn route_map_lines_are_kept_verbatim() {
        let mut config = SessionConfig::new();
        config.add_route_map("RM-IN permit 10".into());
        let text = config.render("r1");
        assert!(text.contains("route-map RM-IN permit 10\n"));
    }

    #[test]
    fn full_file_renders_with_separators_and_end() {
        let mut config = SessionConfig::new();
        config.set_frr_version("10.2".into());
        config.set_frr_defaults("traditional".into());
        config.set_hostname("r1".into());
        config.set_line_vty();
        config.add_static(Af::V4, "203.0.113.0/24".into(), Nexthop::Blackhole);
        let text = config.render("r1");
        assert!(text.starts_with("frr version 10.2\nfrr defaults traditional\n"));
        assert!(text.contains("!\nip route 203.0.113.0/24 blackhole\n"));
        assert!(text.ends_with("!\nline vty\nend\n"));
    }
}
