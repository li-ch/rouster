//! The session config tree — config mode accepts the quarantine-B7
//! observed frr.conf grammar subset into typed nodes; since S8-c M4
//! the tree is the modeled half of the canonical merge: [`crate::
//! writer`] projects these nodes into `daemon rousterd`/`daemon
//! bgpd` sections of the canonical `rouster.conf` shape and renders
//! the merged view for `show running-config` and `write`.

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

/// One child line of a router-bgp node (B7 §3's observed set).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BgpLine {
    /// `bgp network import-check` on or off.
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

/// The session's configuration — the typed, editable half of the
/// canonical merge (S8-c M4).
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
    fn hostname_replaces_rather_than_accumulates() {
        let mut config = SessionConfig::new();
        config.set_hostname("r1".into());
        config.set_hostname("r2".into());
        assert!(matches!(
            config.nodes.as_slice(),
            [CfgNode::Hostname(name)] if name == "r2"
        ));
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
    fn route_map_lines_are_kept_verbatim() {
        let mut config = SessionConfig::new();
        config.add_route_map("RM-IN permit 10".into());
        assert!(matches!(
            config.nodes.as_slice(),
            [CfgNode::RouteMap(rest)] if rest == "RM-IN permit 10"
        ));
    }
}
