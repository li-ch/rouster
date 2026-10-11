//! `bgpd.conf` parser — the A11/B7 grammar conventions: line-based,
//! strict (unknown directives rejected with line numbers), one
//! `router bgp <as>` stanza, `neighbor` sub-lines shaped like the
//! frr.conf subset B7 surveyed:
//!
//! ```text
//! zapi socket /run/rouster/zapi.api
//! listen-port 179
//! hold-time 90
//! router bgp 65000
//!  bgp router-id 10.0.0.1
//!  neighbor 192.0.2.9 remote-as 65001
//!  neighbor 192.0.2.9 passive
//!  neighbor 192.0.2.9 timers 10 30
//!  neighbor 192.0.2.9 mrai 0
//!  neighbor 192.0.2.9 role peer
//!  neighbor 192.0.2.9 update-error-handling rfc7606
//!  neighbor 192.0.2.9 route-server
//!  neighbor 192.0.2.9 graceful-restart 120
//!  network 203.0.113.0/24
//!  network 2001:db8:1::/48
//!  import IN
//!  export OUT
//! rpki
//!  cache 192.0.2.10 3323
//!  vrp-file /etc/rouster/vrps.conf
//!  reject-invalid true
//! aspa advisory
//! route-map IN permit 10
//!  match ip address prefix-list CUST
//!  set local-preference 200
//! ip prefix-list CUST seq 5 permit 203.0.113.0/24
//! ```
//!
//! `listen-port` allows an unprivileged port for tests (179 requires
//! CAP_NET_BIND_SERVICE; the smoke runs as container root so the
//! default stands there). `mrai` seconds default 0 — FRR-compatible
//! (FRR ships MRAI=0); RFC 4271 §10 suggests 30 s for eBGP — §Deferred
//! as a tuning decision.
//!
//! W2-d: `import`/`export` name route-maps defined by the policy
//! stanzas (`route-map`, `ip|ipv6 prefix-list`, `bgp as-path
//! access-list`, `bgp community-list standard` — the W1-a
//! compatibility grammar). Those lines are collected verbatim into
//! [`BgpdConfig::policy_text`] — a blank-padded fragment that keeps
//! the file's line numbers, so `policy::parse_policy_config` errors
//! point at the real file — and compiled at startup by
//! `policy_engine::compile_named_policy`.

use std::collections::BTreeMap;
use std::net::{IpAddr, Ipv4Addr};
use std::path::PathBuf;

use common::IpPrefix;

/// RFC 9234 §4 BGP roles (the three a plain transit speaker needs;
/// RS/RS-client are §Deferred with route-server mode).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    Customer,
    Peer,
    Provider,
}

impl Role {
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "customer" => Some(Role::Customer),
            "peer" => Some(Role::Peer),
            "provider" => Some(Role::Provider),
            _ => None,
        }
    }
}

impl std::fmt::Display for Role {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            Role::Customer => "customer",
            Role::Peer => "peer",
            Role::Provider => "provider",
        };
        f.write_str(s)
    }
}

/// The `rpki` stanza: one cache connection or one static fixture
/// file, plus the ROV enforcement knob.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RpkiConfig {
    /// `cache <host> <port>`: an RTR session (RFC 8210).
    pub cache: Option<(String, u16)>,
    /// `vrp-file <path>`: static VRP/ASPA fixture (test mode).
    pub vrp_file: Option<PathBuf>,
    /// `reject-invalid <bool>` — reject ROV-Invalid routes at import
    /// (RFC 6811 §2's recommended local policy; default true).
    pub reject_invalid: bool,
}

impl Default for RpkiConfig {
    fn default() -> Self {
        Self {
            cache: None,
            vrp_file: None,
            reject_invalid: true,
        }
    }
}

/// ASPA verification mode (draft-ietf-sidrops-aspa-verification-28):
/// `advisory` records the verdict on the path only (default v1);
/// `enforce` additionally rejects Invalid ones at import.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum AspaMode {
    #[default]
    Advisory,
    Enforce,
}

/// Per-neighbor UPDATE error handling (N5): `rfc7606` is the modern
/// default (attribute discard / treat-as-withdraw per RFC 7606 §7);
/// `strict-rfc4271` restores the RFC 4271 §6.3 session-reset
/// behavior.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum UpdateErrorHandling {
    #[default]
    Rfc7606,
    StrictRfc4271,
}

impl UpdateErrorHandling {
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "rfc7606" => Some(Self::Rfc7606),
            "strict-rfc4271" => Some(Self::StrictRfc4271),
            _ => None,
        }
    }

    /// The decoder-level mode; `internal` refines RFC 7606 §7's
    /// LOCAL_PREF row (the session type is negotiated, so the wire
    /// value is chosen at decode time).
    pub fn handling(self, internal: bool) -> crate::attr::UpdateHandling {
        match self {
            Self::Rfc7606 => crate::attr::UpdateHandling::Rfc7606 { internal },
            Self::StrictRfc4271 => crate::attr::UpdateHandling::StrictRfc4271,
        }
    }
}

impl std::fmt::Display for UpdateErrorHandling {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            Self::Rfc7606 => "rfc7606",
            Self::StrictRfc4271 => "strict-rfc4271",
        };
        f.write_str(s)
    }
}

/// Per-neighbor configuration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NeighborConfig {
    pub address: IpAddr,
    pub remote_as: u32,
    pub passive: bool,
    /// `timers <keepalive> <hold>` override; falls back to global.
    pub timers: Option<(u16, u16)>,
    /// MinRouteAdvertisementInterval, seconds (0 = off, the default).
    pub mrai: u64,
    /// RFC 9234 §4 role toward this neighbor (drives OTC and the
    /// ASPA verify procedure selection).
    pub role: Option<Role>,
    /// UPDATE error handling: `rfc7606` (default) or
    /// `strict-rfc4271` (N5, RFC 7606).
    pub update_handling: UpdateErrorHandling,
    /// Route-server client (N5): routes from this neighbor are
    /// reflected to other clients transparently — no local-AS
    /// prepend, NEXT_HOP/MED preserved (FRR `neighbor PEER
    /// route-server-client`, doc/user/routeserver.rst).
    pub route_server: bool,
    /// Graceful Restart sending side (RFC 4724 §4.2, N5): the
    /// Restart Time advertised in the capability (seconds, 1..=4095
    /// — the 12-bit wire field). The receiving side is always on for
    /// peers that advertise the capability.
    pub graceful_restart: Option<u16>,
}

/// The whole daemon config.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BgpdConfig {
    pub local_as: u32,
    /// Derived when absent: like FRR, we require an address; v1 makes
    /// it mandatory if any neighbor exists (a deterministic id beats
    /// a guessed one).
    pub router_id: Option<Ipv4Addr>,
    pub networks: Vec<IpPrefix>,
    pub neighbors: BTreeMap<IpAddr, NeighborConfig>,
    pub zapi_socket: Option<PathBuf>,
    pub listen_port: u16,
    pub hold_time: u16,
    /// Named import/export route-maps (W2-d); `None` = accept-all.
    pub import_filter: Option<String>,
    pub export_filter: Option<String>,
    /// The `rpki` stanza (W2-d); `None` fields = RPKI off.
    pub rpki: RpkiConfig,
    /// `aspa advisory|enforce`.
    pub aspa: AspaMode,
    /// Policy stanzas extracted verbatim (blank-padded: line numbers
    /// match the source file). Empty when none are present.
    pub policy_text: String,
}

impl Default for BgpdConfig {
    fn default() -> Self {
        Self {
            local_as: 0,
            router_id: None,
            networks: Vec::new(),
            neighbors: BTreeMap::new(),
            zapi_socket: None,
            listen_port: 179,
            hold_time: 90,
            import_filter: None,
            export_filter: None,
            rpki: RpkiConfig::default(),
            aspa: AspaMode::default(),
            policy_text: String::new(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ConfigError {
    #[error("line {line}: {message}")]
    Line { line: usize, message: String },
}

fn err(line: usize, message: impl Into<String>) -> ConfigError {
    ConfigError::Line {
        line,
        message: message.into(),
    }
}

/// First tokens that open a policy stanza (the W1-a compatibility
/// grammar's stanza heads). `bgp` only counts for the two policy
/// forms — `bgp router-id` is a router directive.
fn is_policy_stanza_head(tokens: &[&str]) -> bool {
    matches!(
        tokens,
        ["route-map", ..]
            | ["ip", "prefix-list", ..]
            | ["ipv6", "prefix-list", ..]
            | ["bgp", "as-path", ..]
            | ["bgp", "community-list", ..]
    )
}

/// First tokens of route-map child lines (only meaningful while a
/// route-map stanza is open — nothing else in bgpd.conf starts with
/// these).
fn is_policy_child(tokens: &[&str]) -> bool {
    matches!(
        tokens,
        ["match", ..] | ["set", ..] | ["continue", ..] | ["on-match", ..] | ["description", ..]
    )
}

/// Parses a config document. One whitespace-separated token context:
/// `router bgp <as>` opens the stanza; sub-lines are indented or not
/// (FRR accepts both through vtysh; we accept either). Policy-stanza
/// lines are diverted verbatim into [`BgpdConfig::policy_text`]
/// (blank-padded so line numbers survive the handoff).
pub fn parse_config(input: &str) -> Result<BgpdConfig, ConfigError> {
    let mut config = BgpdConfig::default();
    let mut in_router = false;
    let mut router_seen = false;
    let mut in_rpki = false;
    let mut in_route_map = false;
    let mut policy_lines: Vec<String> = Vec::new();

    for (idx, raw) in input.lines().enumerate() {
        let line_no = idx + 1;
        let line = raw.trim();
        if line.is_empty() || line.starts_with('!') || line.starts_with('#') {
            policy_lines.push(String::new());
            continue;
        }
        let tokens: Vec<&str> = line.split_whitespace().collect();

        // One fragment slot per input line (blank for non-policy
        // lines) so the policy grammar's line-numbered errors point at
        // the real file. Policy stanzas are diverted verbatim,
        // interpreted by the W1-a grammar at startup (never silently
        // dropped).
        let diverted = if is_policy_stanza_head(&tokens) {
            in_route_map = tokens[0] == "route-map";
            policy_lines.push(line.to_string());
            true
        } else if in_route_map && is_policy_child(&tokens) {
            policy_lines.push(line.to_string());
            true
        } else {
            in_route_map = false;
            policy_lines.push(String::new());
            false
        };
        if diverted {
            continue;
        }

        match tokens.as_slice() {
            ["zapi", "socket", path] => {
                config.zapi_socket = Some(PathBuf::from(path));
            }
            ["listen-port", port] => {
                let port: u16 = port.parse().map_err(|_| {
                    err(line_no, format!("listen-port expects a port, got `{port}`"))
                })?;
                config.listen_port = port;
            }
            ["hold-time", secs] => {
                let secs: u16 = secs.parse().map_err(|_| {
                    err(line_no, format!("hold-time expects seconds, got `{secs}`"))
                })?;
                if (1..=2).contains(&secs) {
                    return Err(err(
                        line_no,
                        "hold-time must be zero or at least three (RFC 4271 §4.2)",
                    ));
                }
                config.hold_time = secs;
            }
            ["router", "bgp", asn] => {
                if router_seen {
                    return Err(err(line_no, "a second `router bgp` stanza (one instance)"));
                }
                let asn: u32 = asn.parse().map_err(|_| {
                    err(
                        line_no,
                        format!("router bgp expects an AS number, got `{asn}`"),
                    )
                })?;
                config.local_as = asn;
                in_router = true;
                in_rpki = false;
                router_seen = true;
            }
            ["rpki"] => {
                in_rpki = true;
                in_router = false;
            }
            ["cache", host, port] if in_rpki => {
                if config.rpki.vrp_file.is_some() {
                    return Err(err(
                        line_no,
                        "rpki cache and vrp-file are mutually exclusive",
                    ));
                }
                let port: u16 = port
                    .parse()
                    .map_err(|_| err(line_no, format!("cache expects a port, got `{port}`")))?;
                config.rpki.cache = Some((host.to_string(), port));
            }
            ["vrp-file", path] if in_rpki => {
                if config.rpki.cache.is_some() {
                    return Err(err(
                        line_no,
                        "rpki cache and vrp-file are mutually exclusive",
                    ));
                }
                config.rpki.vrp_file = Some(PathBuf::from(path));
            }
            ["reject-invalid", value] if in_rpki => {
                config.rpki.reject_invalid = parse_bool(value).ok_or_else(|| {
                    err(
                        line_no,
                        format!("reject-invalid expects true|false, got `{value}`"),
                    )
                })?;
            }
            ["aspa", mode] => {
                config.aspa = match *mode {
                    "advisory" => AspaMode::Advisory,
                    "enforce" => AspaMode::Enforce,
                    _ => {
                        return Err(err(
                            line_no,
                            format!("aspa expects advisory|enforce, got `{mode}`"),
                        ))
                    }
                };
            }
            ["import", name] if in_router => {
                set_filter_name(&mut config.import_filter, name, line_no, "import")?;
            }
            ["export", name] if in_router => {
                set_filter_name(&mut config.export_filter, name, line_no, "export")?;
            }
            ["bgp", "router-id", id] if in_router => {
                let id: Ipv4Addr = id.parse().map_err(|_| {
                    err(
                        line_no,
                        format!("router-id expects an IPv4 address, got `{id}`"),
                    )
                })?;
                if id.is_unspecified() || id.octets()[0] >= 224 {
                    return Err(err(
                        line_no,
                        format!("{id} is not a valid unicast host address for a BGP Identifier"),
                    ));
                }
                config.router_id = Some(id);
            }
            ["network", prefix] if in_router => {
                let prefix: IpPrefix = prefix.parse().map_err(|_| {
                    err(line_no, format!("network expects a prefix, got `{prefix}`"))
                })?;
                if config.networks.contains(&prefix) {
                    return Err(err(line_no, format!("duplicate network {prefix}")));
                }
                config.networks.push(prefix);
            }
            ["neighbor", addr, rest @ ..] if in_router => {
                let addr: IpAddr = addr.parse().map_err(|_| {
                    err(
                        line_no,
                        format!("neighbor expects an address, got `{addr}`"),
                    )
                })?;
                match rest {
                    ["remote-as", asn] => {
                        let asn: u32 = asn.parse().map_err(|_| {
                            err(
                                line_no,
                                format!("remote-as expects an AS number, got `{asn}`"),
                            )
                        })?;
                        let neighbor = config.neighbors.entry(addr).or_insert(NeighborConfig {
                            address: addr,
                            remote_as: asn,
                            passive: false,
                            timers: None,
                            mrai: 0,
                            role: None,
                            update_handling: UpdateErrorHandling::default(),
                            route_server: false,
                            graceful_restart: None,
                        });
                        if neighbor.remote_as != asn {
                            return Err(err(
                                line_no,
                                format!(
                                    "neighbor {addr} remote-as conflicts with an earlier value"
                                ),
                            ));
                        }
                    }
                    ["passive"] => {
                        let neighbor = require_neighbor(&mut config, addr, line_no)?;
                        neighbor.passive = true;
                    }
                    ["timers", ka, hold] => {
                        let ka: u16 = ka.parse().map_err(|_| {
                            err(
                                line_no,
                                format!("timers keepalive must be seconds, got `{ka}`"),
                            )
                        })?;
                        let hold: u16 = hold.parse().map_err(|_| {
                            err(
                                line_no,
                                format!("timers hold must be seconds, got `{hold}`"),
                            )
                        })?;
                        if ka * 3 > hold {
                            return Err(err(
                                line_no,
                                "keepalive interval exceeds hold/3 (keepalive must fire at least 3x per hold)",
                            ));
                        }
                        let neighbor = require_neighbor(&mut config, addr, line_no)?;
                        neighbor.timers = Some((ka, hold));
                    }
                    ["mrai", secs] => {
                        let secs: u64 = secs.parse().map_err(|_| {
                            err(line_no, format!("mrai expects seconds, got `{secs}`"))
                        })?;
                        let neighbor = require_neighbor(&mut config, addr, line_no)?;
                        neighbor.mrai = secs;
                    }
                    ["role", role] => {
                        let role = Role::parse(role).ok_or_else(|| {
                            err(
                                line_no,
                                format!(
                                    "neighbor role expects customer|peer|provider, got `{role}`"
                                ),
                            )
                        })?;
                        let neighbor = require_neighbor(&mut config, addr, line_no)?;
                        neighbor.role = Some(role);
                    }
                    ["route-server"] => {
                        let neighbor = require_neighbor(&mut config, addr, line_no)?;
                        neighbor.route_server = true;
                    }
                    ["graceful-restart", secs] => {
                        let secs: u16 = secs.parse().map_err(|_| {
                            err(
                                line_no,
                                format!("graceful-restart expects seconds 1..=4095, got `{secs}`"),
                            )
                        })?;
                        if !(1..=4095).contains(&secs) {
                            return Err(err(
                                line_no,
                                format!("graceful-restart expects seconds 1..=4095, got `{secs}` (the RFC 4724 §3 12-bit field)"),
                            ));
                        }
                        let neighbor = require_neighbor(&mut config, addr, line_no)?;
                        neighbor.graceful_restart = Some(secs);
                    }
                    ["update-error-handling", mode] => {
                        let handling = UpdateErrorHandling::parse(mode).ok_or_else(|| {
                            err(
                                line_no,
                                format!(
                                    "update-error-handling expects rfc7606|strict-rfc4271, got `{mode}`"
                                ),
                            )
                        })?;
                        let neighbor = require_neighbor(&mut config, addr, line_no)?;
                        neighbor.update_handling = handling;
                    }
                    _ => {
                        return Err(err(
                            line_no,
                            format!(
                                "unknown neighbor directive: `neighbor {addr} {}`",
                                rest.join(" ")
                            ),
                        ))
                    }
                }
            }
            _ => return Err(err(line_no, format!("unknown directive: `{line}`"))),
        }
    }

    if !router_seen {
        return Err(err(0, "no `router bgp <as>` stanza"));
    }
    if !config.neighbors.is_empty() && config.router_id.is_none() {
        return Err(err(
            0,
            "`bgp router-id` is required when neighbors are configured (v1: deterministic id)",
        ));
    }
    config.policy_text = policy_lines.join("\n");
    Ok(config)
}

fn parse_bool(s: &str) -> Option<bool> {
    match s {
        "true" | "on" | "yes" => Some(true),
        "false" | "off" | "no" => Some(false),
        _ => None,
    }
}

fn set_filter_name(
    slot: &mut Option<String>,
    name: &str,
    line: usize,
    which: &str,
) -> Result<(), ConfigError> {
    if slot.is_some() {
        return Err(err(line, format!("a second `{which}` directive")));
    }
    *slot = Some(name.to_string());
    Ok(())
}

fn require_neighbor(
    config: &mut BgpdConfig,
    addr: IpAddr,
    line: usize,
) -> Result<&mut NeighborConfig, ConfigError> {
    config
        .neighbors
        .get_mut(&addr)
        .ok_or_else(|| err(line, format!("neighbor {addr} has no remote-as yet")))
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = "\
# rouster bgpd
zapi socket /run/rouster/zapi.api
router bgp 65000
 bgp router-id 10.0.0.1
 neighbor 192.0.2.9 remote-as 65001
 neighbor 192.0.2.9 timers 10 30
 network 203.0.113.0/24
 network 2001:db8:1::/48
";

    #[test]
    fn parses_the_sample() {
        let config = parse_config(SAMPLE).unwrap();
        assert_eq!(config.local_as, 65000);
        assert_eq!(config.router_id, Some("10.0.0.1".parse().unwrap()));
        assert_eq!(config.listen_port, 179, "default TCP 179");
        assert_eq!(config.hold_time, 90, "§10 default");
        assert_eq!(
            config.zapi_socket,
            Some(PathBuf::from("/run/rouster/zapi.api"))
        );
        assert_eq!(config.networks.len(), 2);
        let neighbor = &config.neighbors[&"192.0.2.9".parse::<IpAddr>().unwrap()];
        assert_eq!(neighbor.remote_as, 65001);
        assert!(!neighbor.passive);
        assert_eq!(neighbor.timers, Some((10, 30)));
    }

    #[test]
    fn unprivileged_listen_port_for_tests() {
        let config =
            parse_config("router bgp 1\nbgp router-id 10.0.0.1\nlisten-port 1179\n").unwrap();
        assert_eq!(config.listen_port, 1179);
    }

    #[test]
    fn unknown_directive_rejected_with_line_number() {
        let e = parse_config("router bgp 1\nbgp router-id 10.0.0.1\ntable 42\n").unwrap_err();
        assert_eq!(e, err(3, "unknown directive: `table 42`"));
    }

    #[test]
    fn neighbor_directives_before_remote_as_rejected() {
        let e = parse_config("router bgp 1\nbgp router-id 10.0.0.1\nneighbor 192.0.2.9 passive\n")
            .unwrap_err();
        assert!(e.to_string().contains("no remote-as yet"));
    }

    #[test]
    fn conflicting_remote_as_rejected() {
        let e = parse_config(
            "router bgp 1\nbgp router-id 10.0.0.1\nneighbor 192.0.2.9 remote-as 2\nneighbor 192.0.2.9 remote-as 3\n",
        )
        .unwrap_err();
        assert!(e.to_string().contains("conflicts"));
    }

    #[test]
    fn second_router_stanza_rejected() {
        let e = parse_config("router bgp 1\nbgp router-id 10.0.0.1\nrouter bgp 2\n").unwrap_err();
        assert!(e.to_string().contains("second"));
    }

    #[test]
    fn hold_time_one_or_two_rejected() {
        let e = parse_config("router bgp 1\nbgp router-id 10.0.0.1\nhold-time 2\n").unwrap_err();
        assert!(e.to_string().contains("§4.2"));
    }

    #[test]
    fn timers_must_leave_room_for_three_keepalives() {
        let e = parse_config(
            "router bgp 1\nbgp router-id 10.0.0.1\nneighbor 192.0.2.9 remote-as 2\nneighbor 192.0.2.9 timers 20 30\n",
        )
        .unwrap_err();
        assert!(e.to_string().contains("hold/3"));
    }

    #[test]
    fn router_id_required_with_neighbors() {
        let e = parse_config("router bgp 1\nneighbor 192.0.2.9 remote-as 2\n").unwrap_err();
        assert!(e.to_string().contains("router-id"));
    }

    #[test]
    fn router_id_must_be_unicast_host() {
        let e = parse_config("router bgp 1\nbgp router-id 224.0.0.1\n").unwrap_err();
        assert!(e.to_string().contains("unicast"));
    }

    #[test]
    fn missing_router_stanza_rejected() {
        let e = parse_config("hold-time 90\n").unwrap_err();
        assert!(e.to_string().contains("router bgp"));
    }

    #[test]
    fn duplicate_network_rejected() {
        let e = parse_config(
            "router bgp 1\nbgp router-id 10.0.0.1\nnetwork 203.0.113.0/24\nnetwork 203.0.113.0/24\n",
        )
        .unwrap_err();
        assert!(e.to_string().contains("duplicate network"));
    }

    #[test]
    fn passive_and_mrai_parse() {
        let config = parse_config(
            "router bgp 65000\nbgp router-id 10.0.0.1\nneighbor 192.0.2.9 remote-as 65001\nneighbor 192.0.2.9 passive\nneighbor 192.0.2.9 mrai 5\n",
        )
        .unwrap();
        let neighbor = &config.neighbors[&"192.0.2.9".parse::<IpAddr>().unwrap()];
        assert!(neighbor.passive);
        assert_eq!(neighbor.mrai, 5);
    }

    // ---- W2-d: import/export + policy stanzas + rpki/aspa/roles ---

    const POLICY_SAMPLE: &str = "\
router bgp 65000
 bgp router-id 10.0.0.1
 neighbor 192.0.2.9 remote-as 65001
 neighbor 192.0.2.9 role peer
 import IN
 export OUT
route-map IN permit 10
 match ip address prefix-list CUST
 set local-preference 200
ip prefix-list CUST seq 5 permit 203.0.113.0/24
";

    #[test]
    fn import_export_and_policy_stanzas_extract() {
        let config = parse_config(POLICY_SAMPLE).unwrap();
        assert_eq!(config.import_filter.as_deref(), Some("IN"));
        assert_eq!(config.export_filter.as_deref(), Some("OUT"));
        assert_eq!(
            config.neighbors[&"192.0.2.9".parse::<IpAddr>().unwrap()].role,
            Some(Role::Peer)
        );
        // The fragment keeps file line numbers: the route-map head is
        // on line 7, its match child on line 8.
        let lines: Vec<&str> = config.policy_text.lines().collect();
        assert_eq!(lines.len(), 10, "blank-padded to the file's shape");
        assert_eq!(lines[6], "route-map IN permit 10");
        assert_eq!(lines[7], "match ip address prefix-list CUST");
        assert_eq!(lines[8], "set local-preference 200");
        assert_eq!(lines[9], "ip prefix-list CUST seq 5 permit 203.0.113.0/24");
        // And the extracted grammar actually parses.
        let doc = policy::parse_policy_config(&config.policy_text).unwrap();
        assert!(doc.route_maps.contains_key("IN"));
    }

    #[test]
    fn second_import_directive_rejected() {
        let e = parse_config("router bgp 65000\nbgp router-id 10.0.0.1\nimport A\nimport B\n")
            .unwrap_err();
        assert!(e.to_string().contains("second"), "{e}");
    }

    #[test]
    fn rpki_stanza_parses() {
        let config = parse_config(
            "router bgp 65000\nbgp router-id 10.0.0.1\nrpki\ncache 192.0.2.10 3323\nreject-invalid false\n",
        )
        .unwrap();
        assert_eq!(config.rpki.cache, Some(("192.0.2.10".to_string(), 3323)));
        assert!(!config.rpki.reject_invalid);
        assert_eq!(config.aspa, AspaMode::Advisory, "default");
    }

    #[test]
    fn rpki_defaults_reject_invalid_true() {
        let config =
            parse_config("router bgp 65000\nbgp router-id 10.0.0.1\nrpki\nvrp-file /tmp/x\n")
                .unwrap();
        assert!(config.rpki.reject_invalid, "RFC 6811 §2 recommendation");
        assert_eq!(config.rpki.vrp_file, Some(PathBuf::from("/tmp/x")));
    }

    #[test]
    fn rpki_cache_and_vrp_file_mutually_exclusive() {
        let e = parse_config(
            "router bgp 65000\nbgp router-id 10.0.0.1\nrpki\nvrp-file /tmp/x\ncache 192.0.2.10 3323\n",
        )
        .unwrap_err();
        assert!(e.to_string().contains("mutually exclusive"), "{e}");
    }

    #[test]
    fn aspa_enforce_parses_and_bad_mode_rejected() {
        let config =
            parse_config("router bgp 65000\nbgp router-id 10.0.0.1\naspa enforce\n").unwrap();
        assert_eq!(config.aspa, AspaMode::Enforce);
        let e =
            parse_config("router bgp 65000\nbgp router-id 10.0.0.1\naspa strict\n").unwrap_err();
        assert!(e.to_string().contains("advisory|enforce"), "{e}");
    }

    #[test]
    fn neighbor_role_parses_and_rejects_junk() {
        let config = parse_config(
            "router bgp 65000\nbgp router-id 10.0.0.1\nneighbor 192.0.2.9 remote-as 65001\nneighbor 192.0.2.9 role customer\n",
        )
        .unwrap();
        assert_eq!(
            config.neighbors[&"192.0.2.9".parse::<IpAddr>().unwrap()].role,
            Some(Role::Customer)
        );
        let e = parse_config(
            "router bgp 65000\nbgp router-id 10.0.0.1\nneighbor 192.0.2.9 remote-as 65001\nneighbor 192.0.2.9 role rs\n",
        )
        .unwrap_err();
        assert!(e.to_string().contains("customer|peer|provider"), "{e}");
    }

    #[test]
    fn policy_children_outside_route_map_are_unknown_directives() {
        // A stray `match ...` with no open route-map is a bgpd
        // directive error, not silently swallowed into the fragment.
        let e = parse_config("router bgp 65000\nbgp router-id 10.0.0.1\nset local-preference 5\n")
            .unwrap_err();
        assert!(e.to_string().contains("unknown directive"), "{e}");
    }

    // ---- N5: RFC 7606 error-handling knob --------------------------

    #[test]
    fn update_error_handling_defaults_to_rfc7606_and_parses_both() {
        let config = parse_config(
            "router bgp 65000\nbgp router-id 10.0.0.1\nneighbor 192.0.2.9 remote-as 65001\n",
        )
        .unwrap();
        assert_eq!(
            config.neighbors[&"192.0.2.9".parse::<IpAddr>().unwrap()].update_handling,
            UpdateErrorHandling::Rfc7606,
            "the modern default (RFC 7606)"
        );
        let config = parse_config(
            "router bgp 65000\nbgp router-id 10.0.0.1\nneighbor 192.0.2.9 remote-as 65001\nneighbor 192.0.2.9 update-error-handling strict-rfc4271\n",
        )
        .unwrap();
        assert_eq!(
            config.neighbors[&"192.0.2.9".parse::<IpAddr>().unwrap()].update_handling,
            UpdateErrorHandling::StrictRfc4271
        );
        let e = parse_config(
            "router bgp 65000\nbgp router-id 10.0.0.1\nneighbor 192.0.2.9 remote-as 65001\nneighbor 192.0.2.9 update-error-handling lax\n",
        )
        .unwrap_err();
        assert!(e.to_string().contains("rfc7606|strict-rfc4271"), "{e}");
        // The decoder-level mapping (the LOCAL_PREF row's `internal`
        // refinement is chosen at decode time).
        assert!(matches!(
            UpdateErrorHandling::Rfc7606.handling(true),
            crate::attr::UpdateHandling::Rfc7606 { internal: true }
        ));
        assert!(matches!(
            UpdateErrorHandling::StrictRfc4271.handling(true),
            crate::attr::UpdateHandling::StrictRfc4271
        ));
    }

    #[test]
    fn graceful_restart_knob_parses_with_bounds() {
        let config = parse_config(
            "router bgp 65000\nbgp router-id 10.0.0.1\nneighbor 192.0.2.9 remote-as 65001\nneighbor 192.0.2.9 graceful-restart 120\n",
        )
        .unwrap();
        assert_eq!(
            config.neighbors[&"192.0.2.9".parse::<IpAddr>().unwrap()].graceful_restart,
            Some(120)
        );
        for bad in ["0", "4096", "junk"] {
            let e = parse_config(&format!(
                "router bgp 65000\nbgp router-id 10.0.0.1\nneighbor 192.0.2.9 remote-as 65001\nneighbor 192.0.2.9 graceful-restart {bad}\n"
            ))
            .unwrap_err();
            assert!(e.to_string().contains("1..=4095"), "{bad}: {e}");
        }
        // Unconfigured neighbors default to None (receiving side only).
        let bare = parse_config(
            "router bgp 65000\nbgp router-id 10.0.0.1\nneighbor 192.0.2.9 remote-as 65001\n",
        )
        .unwrap();
        assert_eq!(
            bare.neighbors[&"192.0.2.9".parse::<IpAddr>().unwrap()].graceful_restart,
            None
        );
    }

    #[test]
    fn route_server_client_knob_parses() {
        let config = parse_config(
            "router bgp 65000\nbgp router-id 10.0.0.1\nneighbor 192.0.2.101 remote-as 65001\nneighbor 192.0.2.101 route-server\n",
        )
        .unwrap();
        assert!(config.neighbors[&"192.0.2.101".parse::<IpAddr>().unwrap()].route_server);
        let config = parse_config(
            "router bgp 65000\nbgp router-id 10.0.0.1\nneighbor 192.0.2.101 remote-as 65001\n",
        )
        .unwrap();
        assert!(!config.neighbors[&"192.0.2.101".parse::<IpAddr>().unwrap()].route_server);
        let e = parse_config(
            "router bgp 65000\nbgp router-id 10.0.0.1\nneighbor 192.0.2.101 route-server\n",
        )
        .unwrap_err();
        assert!(e.to_string().contains("no remote-as yet"), "{e}");
    }
}
