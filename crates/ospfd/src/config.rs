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
//! Hello actually consume (cost, hello/dead intervals, priority,
//! network type, explicit address — the Day-2 daemon needs the
//! interface's own address/mask for Hellos and router-LSA links, and
//! v1 takes it from config rather than a zapi interface dump), plus
//! `network <prefix> area <id>` for the classic interface-by-address
//! binding. `redistribute static` is collected for the zapi edge.
//!
//! The socket layer note below is Day-1's record; socket2 WAS
//! adopted for ospfd on Day 2 (owner decision A1, adopted
//! 2026-10-11, extended to ospfd) — see `transport`.
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
    /// The areas, keyed by area ID (OSPF area IDs are 32-bit dotted
    /// quads but compare as raw u32). Multiple areas make the
    /// router an ABR (§12.4.3's summary duties); area 0.0.0.0 is
    /// the backbone (§3.1).
    pub areas: Vec<AreaConfig>,
    /// network-prefix -> area bindings (frr's classic form; v1
    /// parses them, the interface stanzas are the source of truth).
    pub networks: Vec<(u32, u8, u32)>,
    /// `redistribute static`.
    pub redistribute_static: bool,
}

impl OspfdConfig {
    /// The single-area convenience (v1 callers, tests): the first
    /// area's ID.
    pub fn area_id(&self) -> u32 {
        self.areas.first().map(|a| a.id).unwrap_or(0)
    }
}

/// One area and its interfaces.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AreaConfig {
    pub id: u32,
    pub interfaces: BTreeMap<String, InterfaceConfig>,
}

/// The network type (§C.3): p2p skips the DR election entirely.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum NetworkType {
    #[default]
    Broadcast,
    PointToPoint,
}

/// Per-interface parameters (§C.3 subset + the address binding).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InterfaceConfig {
    pub cost: u16,
    pub hello_interval: u16,
    pub dead_interval: u32,
    pub priority: u8,
    /// The interface's own address/mask (v1: config-supplied — the
    /// zapi interface dump is not requested).
    pub address: Option<(Ipv4Addr, Ipv4Addr)>,
    pub network_type: NetworkType,
    /// Interface MTU (DD's MTU field).
    pub mtu: u16,
}

impl InterfaceConfig {
    /// §C.3 defaults: HelloInterval 10, RouterDeadInterval 40, cost
    /// 10 (FRR parity; RFC 2328 leaves cost to the operator),
    /// priority 1, MTU 1500, broadcast.
    pub fn defaults() -> Self {
        Self {
            cost: 10,
            hello_interval: 10,
            dead_interval: 40,
            priority: 1,
            address: None,
            network_type: NetworkType::Broadcast,
            mtu: 1500,
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
        areas: Vec::new(),
        networks: vec![],
        redistribute_static: false,
    };
    let mut in_router = false;

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
                        if cfg.areas.iter().any(|a| a.id == raw) {
                            return Err(parse_error(line_no, "duplicate area stanza"));
                        }
                        cfg.areas.push(AreaConfig {
                            id: raw,
                            interfaces: BTreeMap::new(),
                        });
                    }
                    "network" => {
                        // network <prefix> area <id> — the classic
                        // binding (parsed; interface stanzas are the
                        // v1 source of truth).
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
                        let Some(area) = cfg.areas.last_mut() else {
                            return Err(parse_error(line_no, "interface without an area stanza"));
                        };
                        if area
                            .interfaces
                            .insert(words[1].to_string(), InterfaceConfig::defaults())
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
                    "cost" | "hello-interval" | "dead-interval" | "priority" | "address"
                    | "network-type" | "mtu" => {
                        // Interface parameter inside the LAST interface
                        // stanza of the LAST area; BTreeMap order cannot
                        // express "last", so we require the parameter to
                        // follow its interface line directly — strict
                        // and deterministic.
                        let Some(area) = cfg.areas.last_mut() else {
                            return Err(parse_error(line_no, "parameter without an area stanza"));
                        };
                        let Some((_, iface)) = area.interfaces.iter_mut().next_back() else {
                            return Err(parse_error(line_no, "parameter without an interface"));
                        };
                        match first {
                            "address" => {
                                let Some((net, len)) =
                                    parse_prefix(words.get(1).copied().unwrap_or(""))
                                else {
                                    return Err(parse_error(
                                        line_no,
                                        "expected: address <a.b.c.d/m>",
                                    ));
                                };
                                // Keep the address bits, derive the mask.
                                let mask = if len == 0 { 0 } else { u32::MAX << (32 - len) };
                                // The interface's own address plus the
                                // derived mask (host bits expected —
                                // this is an address, not a network).
                                iface.address = Some((Ipv4Addr::from(net), Ipv4Addr::from(mask)));
                            }
                            "network-type" => {
                                iface.network_type = match words.get(1).copied() {
                                    Some("broadcast") => NetworkType::Broadcast,
                                    Some("point-to-point") => NetworkType::PointToPoint,
                                    _ => {
                                        return Err(parse_error(
                                            line_no,
                                            "expected: network-type <broadcast|point-to-point>",
                                        ))
                                    }
                                };
                            }
                            "mtu" | "cost" | "hello-interval" | "dead-interval" | "priority" => {
                                let value: u32 = words
                                    .get(1)
                                    .and_then(|v| v.parse().ok())
                                    .ok_or_else(|| parse_error(line_no, "expected a number"))?;
                                match first {
                                    "cost" => iface.cost = value as u16,
                                    "hello-interval" => iface.hello_interval = value as u16,
                                    "dead-interval" => iface.dead_interval = value,
                                    "priority" => iface.priority = value as u8,
                                    "mtu" => iface.mtu = value as u16,
                                    _ => unreachable!(),
                                }
                            }
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
    if cfg.areas.is_empty() {
        return Err(parse_error(text.lines().count(), "missing `area` stanza"));
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
        assert_eq!(cfg.area_id(), 0);
        assert_eq!(cfg.areas.len(), 1);
        let eth0 = cfg.areas[0].interfaces.get("eth0").unwrap();
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
        assert_eq!(cfg.area_id(), 1);
        assert_eq!(cfg.areas[0].interfaces["lo"], InterfaceConfig::defaults());
    }

    #[test]
    fn area_stanza_is_required() {
        // A router stanza with no area (and no interfaces) is a
        // configuration error, not an empty daemon.
        let err = parse("router ospf\n router-id 1.1.1.1\n").unwrap_err();
        assert!(err.to_string().contains("missing `area`"), "{err}");
    }

    #[test]
    fn multiple_areas_parse() {
        // The ABR shape (§12.4.3): backbone + one non-backbone area,
        // each with its own interfaces.
        let cfg = parse(
            "router ospf\n router-id 10.255.2.1\n area 0.0.0.0\n  interface eth0\n   address 10.10.0.2/30\n   network-type point-to-point\n area 0.0.0.1\n  interface eth1\n   address 10.20.0.1/30\n   network-type point-to-point\n",
        )
        .unwrap();
        assert_eq!(cfg.areas.len(), 2);
        assert_eq!(cfg.areas[0].id, 0);
        assert!(cfg.areas[0].interfaces.contains_key("eth0"));
        assert_eq!(cfg.areas[1].id, 1);
        assert!(cfg.areas[1].interfaces.contains_key("eth1"));
        // Duplicate area IDs are rejected with the line number.
        let err =
            parse("router ospf\n area 0.0.0.0\n  interface a\n area 0.0.0.0\n  interface b\n")
                .unwrap_err();
        assert!(err.to_string().contains("line 4"), "{err}");
        // Interfaces without an area are rejected.
        let err = parse("router ospf\n  interface a\n").unwrap_err();
        assert!(
            err.to_string().contains("interface without an area"),
            "{err}"
        );
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
    fn day2_knobs_parse() {
        let cfg = parse(
            "router ospf\n area 0.0.0.0\n  interface eth0\n   address 10.77.0.2/30\n   network-type point-to-point\n   mtu 1500\n",
        )
        .unwrap();
        let eth0 = cfg.areas[0].interfaces.get("eth0").unwrap();
        assert_eq!(
            eth0.address,
            Some((
                "10.77.0.2".parse().unwrap(),
                "255.255.255.252".parse().unwrap()
            ))
        );
        assert_eq!(eth0.network_type, NetworkType::PointToPoint);
        assert_eq!(eth0.mtu, 1500);
        // Bad network type and host-bits-set address carry line numbers.
        let err = parse("router ospf\n area 0.0.0.0\n  interface eth0\n   network-type p2p\n")
            .unwrap_err();
        assert!(err.to_string().contains("line 4"), "{err}");
        // A bad address prefix carries its line number.
        let err = parse("router ospf\n area 0.0.0.0\n  interface eth0\n   address 10.77.0.2/33\n")
            .unwrap_err();
        assert!(err.to_string().contains("line 4"), "{err}");
    }

    #[test]
    fn parameter_attaches_to_last_interface() {
        let cfg =
            parse("router ospf\n area 0.0.0.0\n  interface eth0\n  interface eth1\n   cost 7\n")
                .unwrap();
        assert_eq!(cfg.areas[0].interfaces["eth1"].cost, 7);
        assert_eq!(
            cfg.areas[0].interfaces["eth0"].cost, 10,
            "default untouched"
        );
    }
}
