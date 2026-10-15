//! The session config tree — config mode accepts the quarantine-B7
//! observed frr.conf grammar subset; since S8-c M4 the tree was the
//! modeled half of the canonical merge, and since **S11-a M5 the
//! tree is a `yang::DataTree` bound to the `rouster-vty` model**
//! (`yang/rouster-vty.yang`, embedded in `crates/yang`): every
//! config-mode edit builds a YANG-tree operation (set/merge/delete
//! via the same paths configd's bind uses), and `show
//! running-config` renders FROM the tree. The vtysh grammar stays
//! the EDGE surface (invariant 5: a translator, never the source
//! of truth) — [`crate::writer`] renders the canonical view from
//! this tree and merges the unmodeled passthrough around it.

use yang::data::{DataTree, Path};

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

    /// The model container the family lives under.
    fn container(self) -> &'static str {
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

fn p(segs: &str) -> Path {
    Path::parse(segs).unwrap_or_else(|e| panic!("literal path `{segs}`: {e}"))
}

/// The session's configuration — a YANG data tree against the
/// `rouster-vty` model plus nothing else (one source of truth).
///
/// All mutation methods are the translator: the vtysh-shaped edge
/// grammar has already validated the token shapes, so tree errors
/// here are bugs, not operator errors — they are dropped from the
/// API surface and disclosed by `debug_assert`s in debug builds.
#[derive(Debug, Clone)]
pub struct SessionConfig {
    pub tree: DataTree,
}

impl Default for SessionConfig {
    fn default() -> Self {
        SessionConfig {
            tree: DataTree::empty(yang::models::schema("rouster-vty")),
        }
    }
}

impl PartialEq for SessionConfig {
    /// Structural equality over the trees (the house test need).
    fn eq(&self, other: &Self) -> bool {
        format!("{:?}", self.tree.children) == format!("{:?}", other.tree.children)
    }
}

impl Eq for SessionConfig {}

impl SessionConfig {
    /// An empty config.
    pub fn new() -> SessionConfig {
        SessionConfig::default()
    }

    fn set(&mut self, segs: &str, value: &str) {
        debug_assert!(self.tree.set(&p(segs), value, None).is_ok());
    }

    fn touch(&mut self, segs: &str) {
        debug_assert!(self.tree.set_container(&p(segs)).is_ok());
    }

    fn push_value(&mut self, segs: &str, value: &str) {
        if !self.tree.get_values(&p(segs)).iter().any(|v| v == value) {
            debug_assert!(self.tree.set_leaf_list(&p(segs), value, None).is_ok());
        }
    }

    // ---- display-only directives (the `! vtyd:` comments) ----

    /// Sets `hostname` (replaces any previous one).
    pub fn set_hostname(&mut self, name: String) {
        self.set("/hostname", &name);
    }

    pub fn hostname(&self) -> Option<String> {
        self.tree.get_value(&p("/hostname"))
    }

    /// Sets `frr version` (replaces any previous one).
    pub fn set_frr_version(&mut self, version: String) {
        self.set("/frr/version", &version);
    }

    /// Sets `frr defaults` (replaces any previous one).
    pub fn set_frr_defaults(&mut self, defaults: String) {
        self.set("/frr/defaults", &defaults);
    }

    /// Marks the `line vty` stanza present.
    pub fn set_line_vty(&mut self) {
        self.touch("/line/vty");
    }

    // ---- static routes (`ip|ipv6 route <prefix> <nexthop>`) ----

    /// Adds a static route's nexthop under its prefix entry
    /// (idempotent on the exact triple — the B7 behavior).
    pub fn add_static(&mut self, af: Af, prefix: String, nexthop: Nexthop) {
        let base = format!("/{c}/route[prefix={prefix}]", c = af.container());
        self.touch(&base);
        self.set(&format!("{base}/prefix"), &prefix);
        let nh = format!("{base}/nexthop");
        self.push_value(&nh, nexthop.text());
    }

    /// Removes static routes matching (af, prefix) — the named
    /// nexthop only, or the whole entry when `nexthop` is `None`.
    pub fn remove_static(&mut self, af: Af, prefix: &str, nexthop: Option<&Nexthop>) {
        let base = format!("/{c}/route[prefix={prefix}]", c = af.container());
        let entry = p(&base);
        match nexthop {
            None => {
                let _ = self.tree.delete(&entry);
            }
            Some(nh) => {
                let values = self.tree.get_values(&p(&format!("{base}/nexthop")));
                if values.len() <= 1 {
                    let _ = self.tree.delete(&entry);
                } else {
                    let _ = self
                        .tree
                        .delete_value(&p(&format!("{base}/nexthop")), nh.text());
                }
            }
        }
    }

    /// Adds a verbatim route-map line.
    pub fn add_route_map(&mut self, rest: String) {
        self.push_value("/route-map", &rest);
    }

    // ---- router bgp ----

    fn bgp_base(asn: &str) -> String {
        format!("/router/bgp[local-as={asn}]")
    }

    /// Ensures the `router bgp <asn>` node exists (the mode entry).
    pub fn bgp_open(&mut self, asn: String) {
        let base = Self::bgp_base(&asn);
        self.touch(&base);
        self.set(&format!("{base}/local-as"), &asn);
    }

    /// Sets the import-check line (replaces any previous one).
    pub fn bgp_set_import_check(&mut self, asn: &str, on: bool) {
        let base = Self::bgp_base(asn);
        self.touch(&base);
        self.set(&format!("{base}/bgp/network-import-check"), &on.to_string());
    }

    /// Sets the router-id line (replaces any previous one).
    pub fn bgp_set_router_id(&mut self, asn: &str, id: String) {
        let base = Self::bgp_base(asn);
        self.touch(&base);
        self.set(&format!("{base}/bgp/router-id"), &id);
    }

    /// Adds (or replaces, keyed on the address) a neighbor line.
    pub fn bgp_add_neighbor(&mut self, asn: &str, addr: String, remote_as: String) {
        let base = Self::bgp_base(asn);
        let nb = format!("{base}/neighbor[address={addr}]");
        self.touch(&nb);
        self.set(&format!("{nb}/address"), &addr);
        self.set(&format!("{nb}/remote-as"), &remote_as);
    }

    /// The address-family subtree, created if absent (the mode
    /// entry; `family` is the `ipv4 unicast` shape).
    pub fn af_open(&mut self, asn: &str, _family: &str) {
        let base = Self::bgp_base(asn);
        self.touch(&base);
    }

    /// Adds an address-family `network <prefix>` line.
    pub fn af_add_network(&mut self, asn: &str, prefix: String) {
        let path = format!(
            "{}/address-family/ipv4/unicast/network",
            Self::bgp_base(asn)
        );
        self.push_value(&path, &prefix);
    }

    /// Marks `redistribute static` present (idempotent).
    pub fn af_add_redistribute_static(&mut self, asn: &str) {
        let path = format!(
            "{}/address-family/ipv4/unicast/redistribute",
            Self::bgp_base(asn)
        );
        if self.tree.get_value(&p(&path)).is_none() {
            self.set(&path, "static");
        }
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
        assert_eq!(config.hostname().as_deref(), Some("r2"));
    }

    #[test]
    fn duplicate_static_route_is_idempotent() {
        let mut config = SessionConfig::new();
        config.add_static(Af::V4, "203.0.113.0/24".into(), Nexthop::Blackhole);
        config.add_static(Af::V4, "203.0.113.0/24".into(), Nexthop::Blackhole);
        assert_eq!(
            config
                .tree
                .get_values(&p("/ip/route[prefix=203.0.113.0/24]/nexthop")),
            vec!["blackhole".to_string()]
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
        assert_eq!(
            config
                .tree
                .get_values(&p("/ip/route[prefix=203.0.113.0/24]/nexthop")),
            vec!["blackhole".to_string()]
        );
        // And the any-nexthop form clears the rest.
        config.remove_static(Af::V4, "203.0.113.0/24", None);
        assert!(config
            .tree
            .get(&p("/ip/route[prefix=203.0.113.0/24]"))
            .is_none());
    }

    #[test]
    fn route_map_lines_are_kept_in_order() {
        let mut config = SessionConfig::new();
        config.add_route_map("RM-IN permit 10".into());
        config.add_route_map("RM-OUT deny 20".into());
        assert_eq!(
            config.tree.get_values(&p("/route-map")),
            vec!["RM-IN permit 10".to_string(), "RM-OUT deny 20".to_string()]
        );
    }

    #[test]
    fn bgp_neighbors_key_by_address() {
        let mut config = SessionConfig::new();
        config.bgp_open("65000".into());
        config.bgp_add_neighbor("65000", "192.0.2.9".into(), "65001".into());
        config.bgp_add_neighbor("65000", "192.0.2.9".into(), "65002".into());
        config.bgp_add_neighbor("65000", "198.51.100.9".into(), "65003".into());
        assert_eq!(
            config
                .tree
                .get_value(&p(
                    "/router/bgp[local-as=65000]/neighbor[address=192.0.2.9]/remote-as"
                ))
                .as_deref(),
            Some("65002")
        );
        assert_eq!(
            config
                .tree
                .get_value(&p(
                    "/router/bgp[local-as=65000]/neighbor[address=198.51.100.9]/remote-as"
                ))
                .as_deref(),
            Some("65003")
        );
    }

    #[test]
    fn edits_build_valid_yang_trees() {
        let mut config = SessionConfig::new();
        config.set_hostname("r1".into());
        config.set_line_vty();
        config.add_static(Af::V4, "203.0.113.0/24".into(), Nexthop::Blackhole);
        config.add_static(
            Af::V6,
            "2001:db8:1::/48".into(),
            Nexthop::Addr("2001:db8::1".into()),
        );
        config.bgp_open("65000".into());
        config.bgp_set_router_id("65000", "10.0.0.1".into());
        config.bgp_set_import_check("65000", true);
        config.bgp_add_neighbor("65000", "192.0.2.9".into(), "65001".into());
        config.af_open("65000", "ipv4 unicast");
        config.af_add_network("65000", "203.0.113.0/24".into());
        config.af_add_redistribute_static("65000");
        assert!(
            config.tree.validate().is_empty(),
            "{:?}",
            config.tree.validate()
        );
    }
}
