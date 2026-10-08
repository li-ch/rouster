//! Minimal static-route configuration for Phase 0.
//!
//! FRR-flavored line format (a strict subset, so files remain valid input for
//! the future frr.conf importer):
//!
//! ```text
//! ip   route <PREFIX> {<GATEWAY> | blackhole}
//! ipv6 route <PREFIX> {<GATEWAY> | blackhole}
//! ```
//!
//! Blank lines and lines starting with `!` or `#` are ignored.

use std::net::{Ipv4Addr, Ipv6Addr};

use common::{IpPrefix, Nexthop, NexthopGroup, RouteEntry, RouteProtocol};

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum ConfigError {
    #[error("line {line}: {reason}")]
    Line { line: usize, reason: String },
}

fn fail(line: usize, reason: impl Into<String>) -> ConfigError {
    ConfigError::Line {
        line,
        reason: reason.into(),
    }
}

/// Parses static routes from config text.
pub fn parse_static_routes(input: &str) -> Result<Vec<RouteEntry>, ConfigError> {
    let mut out = Vec::new();

    for (idx, raw) in input.lines().enumerate() {
        let line_no = idx + 1;
        let line = raw.trim();
        if line.is_empty() || line.starts_with('!') || line.starts_with('#') {
            continue;
        }

        let tokens: Vec<&str> = line.split_whitespace().collect();
        let (is_v6, rest) = match tokens.as_slice() {
            ["ip", "route", rest @ ..] => (false, rest),
            ["ipv6", "route", rest @ ..] => (true, rest),
            _ => {
                return Err(fail(
                    line_no,
                    format!("expected `ip route ...` or `ipv6 route ...`, got `{line}`"),
                ));
            }
        };

        let [prefix, nexthop] = rest else {
            return Err(fail(line_no, "expected `<PREFIX> <GATEWAY|blackhole>`"));
        };

        let prefix: IpPrefix = prefix
            .parse()
            .map_err(|e| fail(line_no, format!("bad prefix `{prefix}`: {e}")))?;

        // Reject cross-AF lines early (`ip route` must carry an IPv4 prefix).
        match (is_v6, prefix) {
            (false, IpPrefix::V4(_)) | (true, IpPrefix::V6(_)) => {}
            _ => return Err(fail(line_no, "address family mismatch")),
        }

        let hop = if *nexthop == "blackhole" {
            Nexthop::Blackhole
        } else if is_v6 {
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

        out.push(RouteEntry::new(
            prefix,
            RouteProtocol::Static,
            NexthopGroup::single(hop),
            0,
        ));
    }

    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_static_routes() {
        let text = "! comment\n\
                    ip route 198.51.100.0/24 192.0.2.1\n\
                    ip route 203.0.113.0/24 blackhole\n\
                    ipv6 route 2001:db8:1::/48 2001:db8::1\n";
        let routes = parse_static_routes(text).unwrap();
        assert_eq!(routes.len(), 3);
        assert_eq!(routes[1].nexthops.hops()[0].0, Nexthop::Blackhole);
        assert_eq!(routes[0].protocol, RouteProtocol::Static);
    }

    #[test]
    fn rejects_af_mismatch() {
        assert!(parse_static_routes("ip route 2001:db8::/32 blackhole").is_err());
        assert!(parse_static_routes("ipv6 route 10.0.0.0/8 blackhole").is_err());
    }

    #[test]
    fn rejects_garbage() {
        assert!(parse_static_routes("router bgp 65001").is_err());
    }
}
