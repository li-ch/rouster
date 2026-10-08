//! Minimal daemon configuration for Phase 0/1.
//!
//! FRR-flavored line format (a strict subset, so files remain valid input for
//! the future frr.conf importer):
//!
//! ```text
//! ip   route <PREFIX> {<GATEWAY>... | blackhole}
//! ipv6 route <PREFIX> {<GATEWAY>... | blackhole}
//! zapi socket <PATH>     # enable the ZAPI edge server (default: off)
//! ```
//!
//! Two or more gateways program an ECMP route (equal weights; `RTA_MULTIPATH`
//! at the kernel): `ip route 198.51.100.0/24 192.0.2.1 192.0.2.2`. All
//! gateways on a line must share the route's address family.
//!
//! Blank lines and lines starting with `!` or `#` are ignored. The
//! `zapi socket` line is optional: without it no ZAPI server runs (the
//! `--once` CI behavior is unchanged); it takes effect at startup only —
//! a changed path on SIGHUP reload is refused with a warning.

use std::net::{Ipv4Addr, Ipv6Addr};
use std::path::PathBuf;

use common::{IpPrefix, Nexthop, NexthopGroup, RouteEntry, RouteProtocol};

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum ConfigError {
    #[error("line {line}: {reason}")]
    Line { line: usize, reason: String },
}

#[derive(Debug, Default, PartialEq, Eq)]
pub struct Config {
    pub static_routes: Vec<RouteEntry>,
    /// ZAPI server socket path; `None` = server off.
    pub zapi_socket: Option<PathBuf>,
}

fn fail(line: usize, reason: impl Into<String>) -> ConfigError {
    ConfigError::Line {
        line,
        reason: reason.into(),
    }
}

/// Parses the full config file.
pub fn parse_config(input: &str) -> Result<Config, ConfigError> {
    let mut config = Config::default();

    for (idx, raw) in input.lines().enumerate() {
        let line_no = idx + 1;
        let line = raw.trim();
        if line.is_empty() || line.starts_with('!') || line.starts_with('#') {
            continue;
        }

        let tokens: Vec<&str> = line.split_whitespace().collect();
        match tokens.as_slice() {
            ["zapi", "socket", path] => {
                if config.zapi_socket.replace(PathBuf::from(*path)).is_some() {
                    return Err(fail(line_no, "duplicate `zapi socket` line"));
                }
            }
            ["ip", "route", rest @ ..] => {
                config
                    .static_routes
                    .push(parse_route_line(false, rest, line_no)?);
            }
            ["ipv6", "route", rest @ ..] => {
                config
                    .static_routes
                    .push(parse_route_line(true, rest, line_no)?);
            }
            _ => {
                return Err(fail(
                    line_no,
                    format!(
                        "expected `ip route ...`, `ipv6 route ...`, or `zapi socket <PATH>`, got `{line}`"
                    ),
                ));
            }
        }
    }

    Ok(config)
}

fn parse_route_line(is_v6: bool, rest: &[&str], line_no: usize) -> Result<RouteEntry, ConfigError> {
    let Some((prefix_tok, gateways)) = rest.split_first() else {
        return Err(fail(line_no, "expected `<PREFIX> <GATEWAY...|blackhole>`"));
    };

    let prefix: IpPrefix = prefix_tok
        .parse()
        .map_err(|e| fail(line_no, format!("bad prefix `{prefix_tok}`: {e}")))?;

    // Reject cross-AF lines early (`ip route` must carry an IPv4 prefix).
    match (is_v6, prefix) {
        (false, IpPrefix::V4(_)) | (true, IpPrefix::V6(_)) => {}
        _ => return Err(fail(line_no, "address family mismatch")),
    }

    if gateways.is_empty() {
        return Err(fail(line_no, "expected `<PREFIX> <GATEWAY...|blackhole>`"));
    }
    if gateways == ["blackhole"] {
        return Ok(RouteEntry::new(
            prefix,
            RouteProtocol::Static,
            NexthopGroup::single(Nexthop::Blackhole),
            0,
        ));
    }

    // One or more gateways (>= 2 → ECMP): all must share the route's AF.
    let mut group = NexthopGroup::new();
    for nexthop in gateways {
        let hop = if is_v6 {
            let gw: Ipv6Addr = nexthop
                .parse()
                .map_err(|_| fail(line_no, format!("bad IPv6 gateway `{nexthop}`")))?;
            Nexthop::Ipv6(gw)
        } else {
            let gw: Ipv4Addr = nexthop
                .parse()
                .map_err(|_| fail(line_no, format!("bad IPv4 gateway `{nexthop}`")))?;
            Nexthop::Ipv4(gw)
        };
        // A duplicate gateway adds no path diversity and the kernel rejects
        // identical multipath entries; refuse it at parse time.
        if group.hops().iter().any(|&(h, _)| h == hop) {
            return Err(fail(line_no, format!("duplicate gateway `{nexthop}`")));
        }
        group.add(hop, 1);
    }

    Ok(RouteEntry::new(prefix, RouteProtocol::Static, group, 0))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn routes(input: &str) -> Vec<RouteEntry> {
        parse_config(input).unwrap().static_routes
    }

    #[test]
    fn parses_static_routes() {
        let text = "! comment\n\
                    ip route 198.51.100.0/24 192.0.2.1\n\
                    ip route 203.0.113.0/24 blackhole\n\
                    ipv6 route 2001:db8:1::/48 2001:db8::1\n";
        let routes = routes(text);
        assert_eq!(routes.len(), 3);
        assert_eq!(routes[1].nexthops.hops()[0].0, Nexthop::Blackhole);
        assert_eq!(routes[0].protocol, RouteProtocol::Static);
    }

    #[test]
    fn rejects_af_mismatch() {
        assert!(parse_config("ip route 2001:db8::/32 blackhole").is_err());
        assert!(parse_config("ipv6 route 10.0.0.0/8 blackhole").is_err());
    }

    // --- ECMP gateway lists (P0C) ---

    #[test]
    fn parses_one_gateway_line_as_before() {
        let routes = routes("ip route 198.51.100.0/24 192.0.2.1\n");
        assert_eq!(routes.len(), 1);
        assert_eq!(
            routes[0].nexthops.hops(),
            &[(Nexthop::Ipv4("192.0.2.1".parse().unwrap()), 1)]
        );
    }

    #[test]
    fn parses_two_gateway_ecmp_line() {
        let routes = routes("ip route 198.51.100.0/24 192.0.2.1 192.0.2.2\n");
        assert_eq!(
            routes[0].nexthops.hops(),
            &[
                (Nexthop::Ipv4("192.0.2.1".parse().unwrap()), 1),
                (Nexthop::Ipv4("192.0.2.2".parse().unwrap()), 1),
            ]
        );
    }

    #[test]
    fn parses_three_gateway_ecmp_line() {
        let routes = routes("ip route 203.0.113.0/24 192.0.2.1 192.0.2.2 192.0.2.3\n");
        assert_eq!(routes[0].nexthops.hops().len(), 3);
        assert_eq!(
            routes[0].nexthops.hops()[2].0,
            Nexthop::Ipv4("192.0.2.3".parse().unwrap())
        );
    }

    #[test]
    fn parses_ipv6_ecmp_line() {
        let routes = routes("ipv6 route 2001:db8:1::/48 2001:db8::1 2001:db8::2\n");
        assert_eq!(
            routes[0].nexthops.hops(),
            &[
                (Nexthop::Ipv6("2001:db8::1".parse().unwrap()), 1),
                (Nexthop::Ipv6("2001:db8::2".parse().unwrap()), 1),
            ]
        );
    }

    #[test]
    fn rejects_mixed_family_gateway_list() {
        // v6 gateway on an `ip route` line (AF mismatch vs the v4 prefix).
        assert!(parse_config("ip route 198.51.100.0/24 192.0.2.1 2001:db8::2").is_err());
        // v4 gateway on an `ipv6 route` line.
        assert!(parse_config("ipv6 route 2001:db8:1::/48 2001:db8::1 192.0.2.2").is_err());
    }

    #[test]
    fn rejects_duplicate_gateways() {
        assert!(parse_config("ip route 198.51.100.0/24 192.0.2.1 192.0.2.1").is_err());
    }

    #[test]
    fn rejects_bad_ecmp_lines() {
        // Prefix with no gateway.
        assert!(parse_config("ip route 198.51.100.0/24").is_err());
        // blackhole is a standalone nexthop; it cannot join a gateway list.
        assert!(parse_config("ip route 198.51.100.0/24 192.0.2.1 blackhole").is_err());
    }

    #[test]
    fn rejects_garbage() {
        assert!(parse_config("router bgp 65001").is_err());
    }

    #[test]
    fn parses_zapi_socket_line() {
        let text = "ip route 203.0.113.0/24 blackhole\n\
                    zapi socket /run/rouster/zserv.api\n";
        let config = parse_config(text).unwrap();
        assert_eq!(
            config.zapi_socket,
            Some(PathBuf::from("/run/rouster/zserv.api"))
        );
        assert_eq!(config.static_routes.len(), 1);
    }

    #[test]
    fn zapi_socket_defaults_off() {
        let config = parse_config("ip route 203.0.113.0/24 blackhole\n").unwrap();
        assert_eq!(config.zapi_socket, None);
        let empty = parse_config("").unwrap();
        assert_eq!(empty, Config::default());
    }

    #[test]
    fn rejects_bad_zapi_lines() {
        assert!(parse_config("zapi socket").is_err(), "missing path");
        assert!(
            parse_config("zapi socket /a\nzapi socket /b").is_err(),
            "duplicate line"
        );
        assert!(
            parse_config("zapi frobnicate").is_err(),
            "unknown directive"
        );
    }
}
