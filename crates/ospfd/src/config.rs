//! `ospfd.conf` parser — the A11/B7 grammar conventions (line-based,
//! strict, unknown directives rejected with line numbers), shaped
//! like the frr.conf subset:
//!
//! ```text
//! zapi socket /run/rouster/zapi.api
//! router ospf
//!  router-id 10.0.0.1
//!  area 0.0.0.0
//!   interface eth0
//!    cost 10
//!    hello-interval 10
//!    dead-interval 40
//!    priority 1
//!   network 10.0.0.0/24 area 0.0.0.0
//!  redistribute static
//! ```
//!
//! v1 semantic surface (the W2-e scope): one `router ospf` stanza,
//! one area (the backbone or an area ID — multiple areas are
//! §Deferred), interface stanzas carrying the §C.3 parameters SPF and
//! Hello actually consume (cost, hello/dead intervals, priority),
//! plus `network <prefix> area <id>` for the classic
//! interface-by-address binding. `redistribute static` is collected
//! for the M5 zapi edge.
//!
//! The socket layer is deliberately absent: OSPF runs over raw IP
//! protocol 89 with IP_ADD_MEMBERSHIP on 224.0.0.5/224.0.0.6 — std
//! `net` has no raw sockets, and adopting `socket2` for ospfd is an
//! owner-gated decision (recorded in the stream report; bfdd already
//! took that step under W1-b M6).

use std::collections::BTreeMap;
use std::net::Ipv4Addr;

/// The parsed daemon configuration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OspfdConfig {
    /// The zapi socket path (`zapi socket` line; the daemon's RIB
    /// edge — absent means run standalone).
    pub zapi_socket: Option<String>,
    pub router_id: Option<Ipv4Addr>,
    /// The single area (v1). Keyed by area ID; OSPF area IDs are
    /// 32-bit dotted quads but compare as raw u32.
    pub area_id: u32,
    pub interfaces: BTreeMap<String, InterfaceConfig>,
    /// network-prefix -> area bindings (frr's classic form).
    pub networks: Vec<(u32, u8, u32)>,
    /// `redistribute static`.
    pub redistribute_static: bool,
}

/// Per-interface parameters (§C.3 subset).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InterfaceConfig {
    pub cost: u16,
    pub hello_interval: u16,
    pub dead_interval: u32,
    pub priority: u8,
}

impl Default for InterfaceConfig {
    fn default() -> Self {
        // §C.3 defaults: HelloInterval 10, RouterDeadInterval 40,
        // cost 10 (FRR parity; RFC 2328 leaves cost to the operator),
        // priority 1.
        Self {
            cost: 10,
            hello_interval: 10,
            dead_interval: 40,
            priority: 1,
        }
    }
}

fn parse_error(line_no: usize, msg: &str) -> crate::error::OspfError {
    crate::error::OspfError::Config(format!("line {line_no}: {msg}"))
}

fn parse_ipv4(s: &str) -> Option<Ipv4Addr> {
    s.parse().ok()
}

/// Parse an `ospfd.conf`. Strict: indentation marks stanza nesting
/// (top level or one blank prefix), everything else is a parse error
/// with its line number.
pub fn parse(text: &str) -> Result<OspfdConfig, crate::error::OspfError> {
    let mut cfg = OspfdConfig {
        zapi_socket: None,
        router_id: None,
        area_id: 0,
        interfaces: BTreeMap::new(),
        networks: vec![],
        redistribute_static: false,
    };
    let mut in_router = false;
    let mut current_area: Option<u32> = None;

    for (idx, raw) in text.lines().enumerate() {
        let line_no = idx + 1;
        let trimmed = raw.trim_end();
        if trimmed.trim().is_empty() {
            continue;
        }
        let depth = trimmed.len() - trimmed.trim_start().len();
        let words: Vec<&str> = trimmed.split_whitespace().collect();
        let Some(&first) = words.first() else {
            continue;
        };
        // depth 0 = top level, 1 = router level, 2 = area level,
        // 3+ = interface parameter level.
        let level = match depth {
            0 => 0,
            1 => 1,
            _ => 2,
        };
        match (level, in_router) {
            (0, false) => match first {
                "zapi" => {
                    if words.len() != 3 || words[1] != "socket" {
                        return Err(parse_error(line_no, "expected: zapi socket <path>"));
                    }
                    if cfg.zapi_socket.is_some() {
                        return Err(parse_error(line_no, "duplicate zapi socket line"));
                    }
                    cfg.zapi_socket = Some(words[2].to_string());
                }
                "router" => {
                    if words.len() != 2 || words[1] != "ospf" {
                        return Err(parse_error(line_no, "expected: router ospf"));
                    }
                    if in_router {
                        return Err(parse_error(line_no, "duplicate router ospf stanza"));
                    }
                    in_router = true;
                }
                other => {
                    return Err(parse_error(
                        line_no,
                        &format!("unknown top-level directive `{other}`"),
                    ))
                }
            },
            (0, true) => {
                return Err(parse_error(
                    line_no,
                    "directive inside the router stanza must be indented",
                ))
            }
            (_, false) => return Err(parse_error(line_no, "directive outside the router stanza")),
            (1, true) => {
                // router-level sub-directives.
                match first {
                    "router-id" => {
                        if words.len() != 2 {
                            return Err(parse_error(line_no, "expected: router-id <a.b.c.d>"));
                        }
                        let Some(id) = parse_ipv4(words[1]) else {
                            return Err(parse_error(line_no, "bad router-id address"));
                        };
                        if cfg.router_id.replace(id).is_some() {
                            return Err(parse_error(line_no, "duplicate router-id"));
                        }
                    }
                    "area" => {
                        if words.len() != 2 {
                            return Err(parse_error(line_no, "expected: area <id>"));
                        }
                        let Some(area) = parse_ipv4(words[1]) else {
                            return Err(parse_error(line_no, "bad area id"));
                        };
                        let raw = u32::from(area);
                        if cfg.interfaces.contains_key(&area.to_string())
                            || current_area.replace(raw).is_some()
                        {
                            return Err(parse_error(line_no, "duplicate area stanza"));
                        }
                        cfg.area_id = raw;
                    }
                    "network" => {
                        // network <prefix> area <id> — the classic
                        // binding; must match the single area (v1).
                        if words.len() != 4 || words[2] != "area" {
                            return Err(parse_error(
                                line_no,
                                "expected: network <a.b.c.d/m> area <id>",
                            ));
                        }
                        let Some((net, len)) = parse_prefix(words[1]) else {
                            return Err(parse_error(line_no, "bad network prefix"));
                        };
                        let Some(area) = parse_ipv4(words[3]) else {
                            return Err(parse_error(line_no, "bad area id"));
                        };
                        cfg.networks.push((net, len, u32::from(area)));
                    }
                    "redistribute" => {
                        if words.len() != 2 || words[1] != "static" {
                            return Err(parse_error(line_no, "expected: redistribute static"));
                        }
                        cfg.redistribute_static = true;
                    }
                    other => {
                        return Err(parse_error(
                            line_no,
                            &format!("unknown router-level directive `{other}`"),
                        ))
                    }
                }
            }
            (_, true) => {
                // area-level sub-directives (level 2+).
                match first {
                    "interface" => {
                        if words.len() != 2 {
                            return Err(parse_error(line_no, "expected: interface <name>"));
                        }
                        if cfg
                            .interfaces
                            .insert(words[1].to_string(), InterfaceConfig::default())
                            .is_some()
                        {
                            return Err(parse_error(line_no, "duplicate interface stanza"));
                        }
                    }
                    "network" => {
                        if words.len() != 4 || words[2] != "area" {
                            return Err(parse_error(
                                line_no,
                                "expected: network <a.b.c.d/m> area <id>",
                            ));
                        }
                        let Some((net, len)) = parse_prefix(words[1]) else {
                            return Err(parse_error(line_no, "bad network prefix"));
                        };
                        let Some(area) = parse_ipv4(words[3]) else {
                            return Err(parse_error(line_no, "bad area id"));
                        };
                        cfg.networks.push((net, len, u32::from(area)));
                    }
                    "cost" | "hello-interval" | "dead-interval" | "priority" => {
                        // Interface parameter inside the LAST interface
                        // stanza; BTreeMap order cannot express
                        // "last", so we require the parameter to
                        // follow its interface line directly — strict
                        // and deterministic.
                        let Some((name, iface)) = cfg.interfaces.iter_mut().next_back() else {
                            return Err(parse_error(line_no, "parameter without an interface"));
                        };
                        let _ = name;
                        let value: u32 = words
                            .get(1)
                            .and_then(|v| v.parse().ok())
                            .ok_or_else(|| parse_error(line_no, "expected a number"))?;
                        match first {
                            "cost" => iface.cost = value as u16,
                            "hello-interval" => iface.hello_interval = value as u16,
                            "dead-interval" => iface.dead_interval = value,
                            "priority" => iface.priority = value as u8,
                            _ => unreachable!(),
                        }
                    }
                    other => {
                        return Err(parse_error(
                            line_no,
                            &format!("unknown area-level directive `{other}`"),
                        ))
                    }
                }
            }
        }
    }
    if !in_router {
        return Err(parse_error(
            text.lines().count(),
            "missing `router ospf` stanza",
        ));
    }
    Ok(cfg)
}

fn parse_prefix(s: &str) -> Option<(u32, u8)> {
    let (addr, len) = s.split_once('/')?;
    let addr: Ipv4Addr = addr.parse().ok()?;
    let len: u8 = len.parse().ok()?;
    if len > 32 {
        return None;
    }
    Some((u32::from(addr), len))
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = "\
zapi socket /run/rouster/zapi.api
router ospf
 router-id 10.9.9.1
 area 0.0.0.0
  interface eth0
   cost 5
   hello-interval 10
   dead-interval 40
   priority 2
  network 10.9.9.0/24 area 0.0.0.0
 redistribute static
";

    #[test]
    fn parses_the_sample() {
        let cfg = parse(SAMPLE).unwrap();
        assert_eq!(cfg.zapi_socket.as_deref(), Some("/run/rouster/zapi.api"));
        assert_eq!(cfg.router_id, Some("10.9.9.1".parse().unwrap()));
        assert_eq!(cfg.area_id, 0);
        let eth0 = cfg.interfaces.get("eth0").unwrap();
        assert_eq!(eth0.cost, 5);
        assert_eq!(eth0.hello_interval, 10);
        assert_eq!(eth0.dead_interval, 40);
        assert_eq!(eth0.priority, 2);
        assert_eq!(
            cfg.networks,
            vec![(u32::from("10.9.9.0".parse::<Ipv4Addr>().unwrap()), 24, 0)]
        );
        assert!(cfg.redistribute_static);
    }

    #[test]
    fn defaults_apply() {
        let cfg = parse("router ospf\n area 0.0.0.1\n  interface lo\n").unwrap();
        assert_eq!(cfg.area_id, 1);
        assert_eq!(cfg.interfaces["lo"], InterfaceConfig::default());
    }

    #[test]
    fn strict_errors_carry_line_numbers() {
        // Unknown top-level directive.
        let err = parse("frobnicate 1\nrouter ospf\n").unwrap_err();
        assert!(err.to_string().contains("line 1"), "{err}");
        // Unknown router-level directive.
        let err = parse("router ospf\n frob 1\n").unwrap_err();
        assert!(err.to_string().contains("line 2"), "{err}");
        // Duplicate router-id.
        let err = parse("router ospf\n router-id 1.1.1.1\n router-id 2.2.2.2\n").unwrap_err();
        assert!(err.to_string().contains("line 3"), "{err}");
        // Bad prefix.
        let err = parse("router ospf\n network 10.0.0.0/33 area 0\n").unwrap_err();
        assert!(err.to_string().contains("line 2"), "{err}");
        // Interface parameter with no interface stanza.
        let err = parse("router ospf\n area 0.0.0.0\n  cost 5\n").unwrap_err();
        assert!(err.to_string().contains("line 3"), "{err}");
        // Missing router stanza entirely.
        assert!(parse("zapi socket /x\n").is_err());
        // Unindented router-level line.
        let err = parse("router ospf\nrouter-id 1.1.1.1\n").unwrap_err();
        assert!(err.to_string().contains("line 2"), "{err}");
    }

    #[test]
    fn parameter_attaches_to_last_interface() {
        let cfg =
            parse("router ospf\n area 0.0.0.0\n  interface eth0\n  interface eth1\n   cost 7\n")
                .unwrap();
        assert_eq!(cfg.interfaces["eth1"].cost, 7);
        assert_eq!(cfg.interfaces["eth0"].cost, 10, "default untouched");
    }
}
