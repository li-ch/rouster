//! `isisd.conf` parser — the A11/B7 grammar conventions (line-based,
//! strict, unknown directives rejected with line numbers), shaped
//! after ospfd's:
//!
//! ```text
//! zapi socket /var/run/frr/zserv.api
//! router isis ROUSTER
//!  net 49.0001.1921.6800.1002.00
//!  is-type level-1-2
//!  metric-style wide
//!  hostname rouster-r2
//!  redistribute static
//!  redistribute level-2 into level-1
//!  interface eth0
//!   address 172.16.0.2/24
//!   circuit-type level-1-2
//!   network broadcast
//!   hello-interval 10
//!   hello-multiplier 3
//!   mtu 1500
//! ```
//!
//! v1 semantic surface: one `router isis` stanza, one NET (the
//! system ID and area come from it — RFC 1195 §?: "the NET ... one
//! per IS"; multiple NETs are the §Deferred synonymous-area ladder),
//! p2p interface stanzas (one circuit per daemon — the transport's
//! no-bind fence), wide metric-style (narrow is parsed for the
//! grammar but originates nothing — disclosed), `redistribute
//! static` collected for the zapi edge.
//!
//! The NET (Network Entity Title): an ISO address of 8..=20 octets
//! whose last 7 are the 6-octet system ID and a zero NSEL —
//! "49.0001.1921.6800.1002.00" is `[49 00 01 19 21 68 00 10 02 00]`.
//! The area addresses the router advertises (TLV 1) are the NET's
//! leading octets.

use std::net::Ipv4Addr;

use crate::auth::{AuthAlgorithm, AuthKey, KeyChain, LevelAuth, Lifetime, SnpAuth};
use crate::system::{Level, SystemId};

/// The parsed daemon configuration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IsisdConfig {
    pub zapi_socket: Option<String>,
    /// The router tag (`router isis <tag>` — FRR's area name).
    pub tag: String,
    /// The NET bytes (the full title).
    pub net: Vec<u8>,
    pub is_type: Level,
    pub metric_style: MetricStyle,
    /// The dynamic hostname we advertise (TLV 137, RFC 5301).
    pub hostname: String,
    pub redistribute_static: bool,
    /// RFC 5302 route leaking: advertise L2-derived prefixes into L1
    /// with the up/down bit set (`redistribute level-2 into level-1`).
    pub redistribute_level2_into_l1: bool,
    /// Per-level authentication (index 0 = the area password, 1 = the
    /// domain password — ISO §7.3.7/§7.3.9).
    pub auth: [LevelAuth; 2],
    pub interface: InterfaceConfig,
}

impl IsisdConfig {
    /// The system ID from the NET (its last 7 octets minus the NSEL).
    pub fn system_id(&self) -> Option<SystemId> {
        system_id_from_net(&self.net)
    }

    /// The area addresses for TLV 1 (the NET's leading octets).
    pub fn area_address(&self) -> Vec<u8> {
        self.net[..self.net.len() - 7].to_vec()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum MetricStyle {
    /// TLV 22/135 only.
    #[default]
    Wide,
    /// Accepted for the grammar; v1 still originates wide (the
    /// transition mode is §Deferred — disclosed).
    Narrow,
    Transition,
}

/// The circuit's network type (FRR's `isis network`): p2p IIHs with
/// RFC 5303's three-way handshake, or LAN IIHs with ISO 10589's DIS
/// election and pseudonode LSPs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum NetworkType {
    #[default]
    PointToPoint,
    Broadcast,
}

/// Per-interface parameters.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InterfaceConfig {
    pub name: String,
    /// The interface's IPv4 (the TLV 132 source and the LSP prefix).
    pub address: Option<(Ipv4Addr, u8)>,
    pub circuit_type: Level,
    pub network: NetworkType,
    /// The LAN priority (ISO §9.5's 7-bit DIS election input; 0..=127,
    /// FRR's default 64).
    pub priority: u8,
    pub hello_interval: u16,
    /// holding time = interval × multiplier (FRR's shape).
    pub hello_multiplier: u16,
    pub mtu: u16,
}

impl Default for InterfaceConfig {
    fn default() -> Self {
        Self {
            name: String::new(),
            address: None,
            circuit_type: Level::Level1And2,
            network: NetworkType::PointToPoint,
            priority: 64,
            hello_interval: 10,
            hello_multiplier: 3,
            mtu: 1500,
        }
    }
}

/// Parse a NET: dotted hex, even digit count, 8..=20 bytes, NSEL 0.
/// Returns the raw bytes.
pub fn parse_net(s: &str) -> Result<Vec<u8>, String> {
    let cleaned: String = s.chars().filter(|c| *c != '.').collect();
    if cleaned.is_empty() || !cleaned.len().is_multiple_of(2) {
        return Err(format!("net {s:?}: dotted hex with an even digit count"));
    }
    if !cleaned.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(format!("net {s:?}: hex digits only"));
    }
    let bytes: Vec<u8> = cleaned
        .as_bytes()
        .chunks(2)
        .map(|p| u8::from_str_radix(std::str::from_utf8(p).unwrap(), 16).unwrap())
        .collect();
    if !(8..=20).contains(&bytes.len()) {
        return Err(format!(
            "net {s:?}: {} octets (a NET is 8..=20)",
            bytes.len()
        ));
    }
    if *bytes.last().unwrap() != 0 {
        return Err(format!("net {s:?}: the NSEL (last octet) must be 00"));
    }
    Ok(bytes)
}

/// The system ID inside NET bytes.
pub fn system_id_from_net(net: &[u8]) -> Option<SystemId> {
    if net.len() < 8 {
        return None;
    }
    let start = net.len() - 7;
    Some(SystemId::from_bytes([
        net[start],
        net[start + 1],
        net[start + 2],
        net[start + 3],
        net[start + 4],
        net[start + 5],
    ]))
}

fn parse_error(line_no: usize, msg: &str) -> crate::error::IsisError {
    crate::error::IsisError::Config(format!("line {line_no}: {msg}"))
}

/// Parse the whole config.
pub fn parse(text: &str) -> Result<IsisdConfig, crate::error::IsisError> {
    let mut config = IsisdConfig {
        zapi_socket: None,
        tag: String::new(),
        net: vec![],
        is_type: Level::Level1And2,
        metric_style: MetricStyle::Wide,
        hostname: String::new(),
        redistribute_static: false,
        redistribute_level2_into_l1: false,
        auth: Default::default(),
        interface: InterfaceConfig::default(),
    };
    let mut in_router = false;
    let mut in_interface = false;
    let mut saw_router = false;

    for (idx, raw) in text.lines().enumerate() {
        let line_no = idx + 1;
        let line = raw.trim_end();
        if line.trim().is_empty() {
            continue;
        }
        let indent = line.len() - line.trim_start().len();
        let words: Vec<&str> = line.split_whitespace().collect();
        let directive = words[0];

        if !in_router {
            match directive {
                "zapi" if words.len() == 2 && words[1] == "socket" => {
                    return Err(parse_error(line_no, "`zapi socket <path>` takes the path"));
                }
                "zapi" if words.len() == 3 && words[1] == "socket" => {
                    config.zapi_socket = Some(words[2].to_string());
                }
                "router" if words.len() == 3 && words[1] == "isis" => {
                    if saw_router {
                        return Err(parse_error(line_no, "one `router isis` stanza (v1)"));
                    }
                    config.tag = words[2].to_string();
                    in_router = true;
                    saw_router = true;
                }
                other => {
                    return Err(parse_error(
                        line_no,
                        &format!("unknown top-level directive `{other}`"),
                    ))
                }
            }
            continue;
        }

        // Inside `router isis`.
        match (indent, directive) {
            (0, "router") => return Err(parse_error(line_no, "one `router isis` stanza (v1)")),
            (0, _) => {
                return Err(parse_error(
                    line_no,
                    "directives inside `router isis` are indented (end the stanza first)",
                ))
            }
            _ => {}
        }

        if in_interface {
            match directive {
                "address" | "ip" => {
                    let value = if directive == "ip" {
                        if words.len() != 3 || words[1] != "address" {
                            return Err(parse_error(line_no, "`ip address <a.b.c.d/plen>`"));
                        }
                        words[2]
                    } else {
                        if words.len() != 2 {
                            return Err(parse_error(line_no, "`address <a.b.c.d/plen>`"));
                        }
                        words[1]
                    };
                    let (addr, plen) = value
                        .split_once('/')
                        .and_then(|(a, p)| Some((a.parse().ok()?, p.parse().ok()?)))
                        .ok_or_else(|| parse_error(line_no, &format!("bad address {value:?}")))?;
                    if plen > 32 {
                        return Err(parse_error(line_no, "prefix length above 32"));
                    }
                    config.interface.address = Some((addr, plen));
                }
                "circuit-type" => {
                    if words.len() != 2 {
                        return Err(parse_error(
                            line_no,
                            "`circuit-type <level-1|level-2|level-1-2>`",
                        ));
                    }
                    config.interface.circuit_type = parse_level(words[1]).ok_or_else(|| {
                        parse_error(line_no, &format!("bad circuit-type {:?}", words[1]))
                    })?;
                }
                "priority" => {
                    if words.len() != 2 {
                        return Err(parse_error(line_no, "`priority <0-127>`"));
                    }
                    let value: u8 = words[1]
                        .parse()
                        .map_err(|_| parse_error(line_no, "priority is numeric"))?;
                    if value > 127 {
                        return Err(parse_error(line_no, "priority is 0..=127"));
                    }
                    config.interface.priority = value;
                }
                "network" => {
                    if words.len() != 2 {
                        return Err(parse_error(line_no, "`network <point-to-point|broadcast>`"));
                    }
                    config.interface.network = match words[1] {
                        "point-to-point" => NetworkType::PointToPoint,
                        "broadcast" => NetworkType::Broadcast,
                        other => {
                            return Err(parse_error(
                                line_no,
                                &format!("bad network type {other:?}"),
                            ))
                        }
                    };
                }
                "hello-interval" => {
                    if words.len() != 2 {
                        return Err(parse_error(line_no, "`hello-interval <seconds>`"));
                    }
                    config.interface.hello_interval = words[1]
                        .parse()
                        .map_err(|_| parse_error(line_no, "hello-interval is numeric"))?;
                }
                "hello-multiplier" => {
                    if words.len() != 2 {
                        return Err(parse_error(line_no, "`hello-multiplier <n>`"));
                    }
                    config.interface.hello_multiplier = words[1]
                        .parse()
                        .map_err(|_| parse_error(line_no, "hello-multiplier is numeric"))?;
                }
                "mtu" => {
                    if words.len() != 2 {
                        return Err(parse_error(line_no, "`mtu <bytes>`"));
                    }
                    config.interface.mtu = words[1]
                        .parse()
                        .map_err(|_| parse_error(line_no, "mtu is numeric"))?;
                }
                "interface" => {
                    return Err(parse_error(
                        line_no,
                        "one interface stanza (one circuit per daemon, v1)",
                    ))
                }
                other => {
                    return Err(parse_error(
                        line_no,
                        &format!("unknown interface directive `{other}`"),
                    ))
                }
            }
            continue;
        }

        match directive {
            "net" => {
                if words.len() != 2 {
                    return Err(parse_error(line_no, "`net <title>`"));
                }
                config.net = parse_net(words[1]).map_err(|m| parse_error(line_no, &m))?;
            }
            "is-type" => {
                if words.len() != 2 {
                    return Err(parse_error(
                        line_no,
                        "`is-type <level-1|level-2|level-1-2>`",
                    ));
                }
                config.is_type = parse_level(words[1])
                    .ok_or_else(|| parse_error(line_no, &format!("bad is-type {:?}", words[1])))?;
            }
            "metric-style" => {
                if words.len() != 2 {
                    return Err(parse_error(
                        line_no,
                        "`metric-style <wide|narrow|transition>`",
                    ));
                }
                config.metric_style = match words[1] {
                    "wide" => MetricStyle::Wide,
                    "narrow" => MetricStyle::Narrow,
                    "transition" => MetricStyle::Transition,
                    other => {
                        return Err(parse_error(line_no, &format!("bad metric-style {other:?}")))
                    }
                };
            }
            "area-password" | "domain-password" => {
                let level2 = directive == "domain-password";
                let (algorithm, secret) = match words.get(1).copied() {
                    Some("cleartext") => (AuthAlgorithm::Cleartext, 2),
                    Some("hmac-md5") => (AuthAlgorithm::HmacMd5, 2),
                    _ => {
                        return Err(parse_error(
                            line_no,
                            &format!("`{directive} cleartext|hmac-md5 <secret> [snp-auth off|send-only|validate]`"),
                        ))
                    }
                };
                let Some(secret) = words.get(secret) else {
                    return Err(parse_error(line_no, "the password string is required"));
                };
                let mut snp = SnpAuth::Off;
                match (words.get(3).copied(), words.get(4)) {
                    (None, None) => {}
                    (Some("snp-auth"), Some(mode)) => {
                        snp = SnpAuth::parse(mode).ok_or_else(|| {
                            parse_error(
                                line_no,
                                &format!("bad snp-auth mode {mode:?} (off|send-only|validate)"),
                            )
                        })?;
                    }
                    _ => {
                        return Err(parse_error(
                            line_no,
                            "expected `[snp-auth off|send-only|validate]` after the secret",
                        ))
                    }
                }
                config.auth[usize::from(level2)] = LevelAuth {
                    chain: KeyChain {
                        keys: vec![AuthKey {
                            algorithm,
                            secret: secret.as_bytes().to_vec(),
                            send_lifetime: Lifetime::ALWAYS,
                            accept_lifetime: Lifetime::ALWAYS,
                        }],
                    },
                    snp,
                };
            }
            "hostname" => {
                if words.len() != 2 {
                    return Err(parse_error(line_no, "`hostname <name>`"));
                }
                config.hostname = words[1].to_string();
            }
            "redistribute" => {
                if words.len() == 2 && words[1] == "static" {
                    config.redistribute_static = true;
                } else if words.len() == 4
                    && words[1] == "level-2"
                    && words[2] == "into"
                    && words[3] == "level-1"
                {
                    config.redistribute_level2_into_l1 = true;
                } else {
                    return Err(parse_error(
                        line_no,
                        "`redistribute static` or `redistribute level-2 into level-1` (v1)",
                    ));
                }
            }
            "interface" => {
                if words.len() != 2 {
                    return Err(parse_error(line_no, "`interface <name>`"));
                }
                config.interface.name = words[1].to_string();
                in_interface = true;
            }
            other => {
                return Err(parse_error(
                    line_no,
                    &format!("unknown router directive `{other}`"),
                ))
            }
        }
    }

    if !saw_router {
        return Err(parse_error(0, "no `router isis` stanza"));
    }
    if config.net.is_empty() {
        return Err(parse_error(0, "no `net` (the system id comes from it)"));
    }
    if config.hostname.is_empty() {
        config.hostname = std::env::var("HOSTNAME").unwrap_or_else(|_| "rouster-isisd".into());
        if config.hostname.is_empty() {
            config.hostname = "rouster-isisd".into();
        }
    }
    if config.interface.name.is_empty() {
        return Err(parse_error(0, "no `interface` stanza"));
    }
    Ok(config)
}

fn parse_level(s: &str) -> Option<Level> {
    match s {
        "level-1" => Some(Level::Level1),
        "level-2" => Some(Level::Level2),
        "level-1-2" | "level-2-1" => Some(Level::Level1And2),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = "\
zapi socket /var/run/frr/zserv.api
router isis ROUSTER
 net 49.0001.1921.6800.1002.00
 is-type level-1-2
 metric-style wide
 hostname rouster-r2
 redistribute static
 interface eth0
  address 172.16.0.2/24
  circuit-type level-1-2
  hello-interval 5
  hello-multiplier 3
  mtu 1500
";

    #[test]
    fn sample_parses() {
        let config = parse(SAMPLE).unwrap();
        assert_eq!(
            config.zapi_socket.as_deref(),
            Some("/var/run/frr/zserv.api")
        );
        assert_eq!(config.tag, "ROUSTER");
        assert_eq!(
            config.net,
            vec![0x49, 0x00, 0x01, 0x19, 0x21, 0x68, 0x00, 0x10, 0x02, 0x00]
        );
        assert_eq!(
            config.system_id().unwrap().to_string(),
            "1921.6800.1002",
            "the NET's sysid"
        );
        assert_eq!(config.area_address(), vec![0x49, 0x00, 0x01]);
        assert_eq!(config.is_type, Level::Level1And2);
        assert!(config.redistribute_static);
        assert_eq!(config.interface.name, "eth0");
        assert_eq!(
            config.interface.address,
            Some((Ipv4Addr::new(172, 16, 0, 2), 24))
        );
        assert_eq!(config.interface.hello_interval, 5);
        assert_eq!(config.interface.hello_multiplier, 3);
    }

    #[test]
    fn net_rules() {
        assert!(parse_net("49.0001.1921.6800.1002.00").is_ok());
        // Short (no room for sysid + NSEL).
        assert!(parse_net("49.00").is_err());
        // NSEL must be zero.
        assert!(parse_net("49.0001.1921.6800.1002.01").is_err());
        // Odd hex digit count.
        assert!(parse_net("49.001").is_err());
        // Non-hex.
        assert!(parse_net("49.0001.1921.6800.100Z.00").is_err());
        // 20-octet title accepted; 21 (42 digits) rejected.
        assert!(
            parse_net("49.0000.0000.0000.0000.0000.0000.0000.1921.6800.1002.0000.00.00").is_err()
        );
    }

    #[test]
    fn rejects_unknown_directives_with_line_numbers() {
        let err = parse("frobnicate 1\n").unwrap_err();
        assert!(err.to_string().contains("line 1"), "{err}");
        let err = parse("router isis X\n net 49.0001.1921.6800.1002.00\n  bogus\n").unwrap_err();
        assert!(err.to_string().contains("line 3"), "{err}");
        assert!(
            err.to_string().contains("unknown router directive"),
            "{err}"
        );
        // No net.
        let err = parse("router isis X\n interface eth0\n").unwrap_err();
        assert!(err.to_string().contains("no `net`"), "{err}");
        // Two router stanzas.
        let err =
            parse("router isis A\n net 49.0001.1921.6800.1001.00\nrouter isis B\n").unwrap_err();
        assert!(err.to_string().contains("one `router isis`"), "{err}");
    }

    #[test]
    fn defaults_apply() {
        let config =
            parse("router isis T\n net 49.0001.1921.6800.1001.00\n interface eth1\n").unwrap();
        assert_eq!(config.is_type, Level::Level1And2);
        assert_eq!(config.metric_style, MetricStyle::Wide);
        assert_eq!(config.interface.hello_interval, 10);
        assert_eq!(config.interface.hello_multiplier, 3);
        assert_eq!(config.interface.mtu, 1500);
        assert!(!config.redistribute_static);
        assert!(!config.redistribute_level2_into_l1);
        assert_eq!(config.interface.circuit_type, Level::Level1And2);
    }

    /// RFC 5302 leaking is opt-in: `redistribute level-2 into level-1`
    /// parses (and only that shape does).
    #[test]
    fn level2_into_level1_knob() {
        let config = parse(
            "router isis T\n net 49.0001.1921.6800.1001.00\n redistribute level-2 into level-1\n interface eth1\n",
        )
        .unwrap();
        assert!(config.redistribute_level2_into_l1);
        assert!(!config.redistribute_static);
        // Both knobs together are fine.
        let config = parse(
            "router isis T\n net 49.0001.1921.6800.1001.00\n redistribute static\n redistribute level-2 into level-1\n interface eth1\n",
        )
        .unwrap();
        assert!(config.redistribute_static && config.redistribute_level2_into_l1);
        // The reverse direction is not a v1 directive.
        for bad in [
            "redistribute level-1 into level-2",
            "redistribute level-2",
            "redistribute level-2 into level-1 extra",
        ] {
            let text =
                format!("router isis T\n net 49.0001.1921.6800.1001.00\n {bad}\n interface eth1\n");
            let err = parse(&text).unwrap_err();
            assert!(
                err.to_string().contains("redistribute"),
                "{err} for {bad:?}"
            );
        }
    }

    /// The circuit's network type: p2p (default) or broadcast (the
    /// DIS/pseudonode mode).
    #[test]
    fn network_type_directive() {
        let config = parse(
            "router isis T\n net 49.0001.1921.6800.1001.00\n interface eth1\n  network broadcast\n",
        )
        .unwrap();
        assert_eq!(config.interface.network, NetworkType::Broadcast);
        // The default.
        let config =
            parse("router isis T\n net 49.0001.1921.6800.1001.00\n interface eth1\n").unwrap();
        assert_eq!(config.interface.network, NetworkType::PointToPoint);
        // Bad value.
        let err = parse(
            "router isis T\n net 49.0001.1921.6800.1001.00\n interface eth1\n  network carrier-pigeon\n",
        )
        .unwrap_err();
        assert!(err.to_string().contains("network"), "{err}");
    }

    /// The LAN priority directive (0..=127, default 64).
    #[test]
    fn priority_directive() {
        let config = parse(
            "router isis T\n net 49.0001.1921.6800.1001.00\n interface eth1\n  priority 127\n",
        )
        .unwrap();
        assert_eq!(config.interface.priority, 127);
        assert_eq!(
            parse("router isis T\n net 49.0001.1921.6800.1001.00\n interface eth1\n")
                .unwrap()
                .interface
                .priority,
            64
        );
        assert!(parse(
            "router isis T\n net 49.0001.1921.6800.1001.00\n interface eth1\n  priority 128\n"
        )
        .is_err());
    }

    /// The per-level passwords: both modes, both levels, the snp-auth
    /// suffix, and the rejection shapes.
    #[test]
    fn password_directives() {
        let config = parse(
            "router isis T\n net 49.0001.1921.6800.1001.00\n area-password cleartext plain-one\n domain-password hmac-md5 hush-hush snp-auth validate\n interface eth1\n",
        )
        .unwrap();
        let l1 = &config.auth[0];
        assert_eq!(l1.chain.keys.len(), 1);
        assert_eq!(
            l1.chain.keys[0].algorithm,
            crate::auth::AuthAlgorithm::Cleartext
        );
        assert_eq!(l1.chain.keys[0].secret, b"plain-one".to_vec());
        assert_eq!(l1.snp, crate::auth::SnpAuth::Off);
        let l2 = &config.auth[1];
        assert_eq!(
            l2.chain.keys[0].algorithm,
            crate::auth::AuthAlgorithm::HmacMd5
        );
        assert_eq!(l2.snp, crate::auth::SnpAuth::Validate);
        // send-only parses.
        let config = parse(
            "router isis T\n net 49.0001.1921.6800.1001.00\n domain-password cleartext pw snp-auth send-only\n interface eth1\n",
        )
        .unwrap();
        assert_eq!(config.auth[1].snp, crate::auth::SnpAuth::SendOnly);
        // Rejections: bad mode, unknown algorithm, missing secret,
        // snp-auth without a mode.
        for bad in [
            "domain-password cleartext pw snp-auth sometimes",
            "domain-password sha256 pw",
            "domain-password hmac-md5",
            "domain-password cleartext pw snp-auth",
        ] {
            let text =
                format!("router isis T\n net 49.0001.1921.6800.1001.00\n {bad}\n interface eth1\n");
            assert!(parse(&text).is_err(), "{bad:?} must not parse");
        }
        // Unconfigured by default.
        let plain =
            parse("router isis T\n net 49.0001.1921.6800.1001.00\n interface eth1\n").unwrap();
        assert!(!plain.auth[0].enabled() && !plain.auth[1].enabled());
    }
}
