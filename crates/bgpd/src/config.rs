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
//!  network 203.0.113.0/24
//!  network 2001:db8:1::/48
//! ```
//!
//! `listen-port` allows an unprivileged port for tests (179 requires
//! CAP_NET_BIND_SERVICE; the smoke runs as container root so the
//! default stands there). `mrai` seconds default 0 — FRR-compatible
//! (FRR ships MRAI=0); RFC 4271 §10 suggests 30 s for eBGP — §Deferred
//! as a tuning decision.

use std::collections::BTreeMap;
use std::net::{IpAddr, Ipv4Addr};
use std::path::PathBuf;

use common::IpPrefix;

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

/// Parses a config document. One whitespace-separated token context:
/// `router bgp <as>` opens the stanza; sub-lines are indented or not
/// (FRR accepts both through vtysh; we accept either).
pub fn parse_config(input: &str) -> Result<BgpdConfig, ConfigError> {
    let mut config = BgpdConfig::default();
    let mut in_router = false;
    let mut router_seen = false;

    for (idx, raw) in input.lines().enumerate() {
        let line_no = idx + 1;
        let line = raw.trim();
        if line.is_empty() || line.starts_with('!') || line.starts_with('#') {
            continue;
        }
        let tokens: Vec<&str> = line.split_whitespace().collect();
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
                router_seen = true;
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
    Ok(config)
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
}
