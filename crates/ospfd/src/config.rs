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
//! network type, explicit address — the STATIC address source; the
//! zapi interface dump (`ifdump`) overrides it when a zapi socket is
//! configured), plus `network <prefix> area <id>` for the classic
//! interface-by-address binding. `redistribute static` is collected
//! for the zapi edge.
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
use std::net::{Ipv4Addr, Ipv6Addr};

/// The address family the daemon runs (S7-a). v1: one family per
/// process, selected under `router ospf` — `address-family
/// ipv6-unicast` runs the OSPFv3 core (`daemon_v3`); the default
/// (unset) is the OSPFv2 daemon. RFC 5838's multi-instance future
/// rides with its own grammar.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum AddressFamily {
    #[default]
    Ipv4,
    Ipv6,
}

/// The parsed daemon configuration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OspfdConfig {
    /// The zapi socket path (`zapi socket` line; the daemon's RIB
    /// edge — absent means run standalone).
    pub zapi_socket: Option<String>,
    pub router_id: Option<Ipv4Addr>,
    /// `address-family ipv6-unicast`: run the OSPFv3 core.
    pub family: AddressFamily,
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
    pub kind: AreaKind,
    /// `area <id> virtual-link <router-id>` (§D.3/§15): the virtual
    /// links using this area as transit, by the other endpoint's
    /// Router ID.
    pub virtual_links: Vec<u32>,
    /// `area <id> default-cost` (§C.2): the metric of the default
    /// summary-LSA an ABR advertises into a stub area. FRR parity:
    /// default 1.
    pub default_cost: u32,
    pub interfaces: BTreeMap<String, InterfaceConfig>,
}

/// The area type (§3.6 stub areas; RFC 3101 NSSA lands with the same
/// plumbing). The backbone cannot be a stub area (§3.6: "Virtual links
/// cannot be configured through stub areas. In addition, AS boundary
/// routers cannot be placed internal to stub areas." — and §6 ties
/// stub areas to non-backbone transit).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum AreaKind {
    #[default]
    Normal,
    /// `area <id> stub`: no AS-external-LSAs flooded in (§3.6); the
    /// ABRs advertise a default summary-LSA (§12.4.3.1).
    Stub,
    /// `area <id> stub no-summary` (FRR's totally stubby): summary
    /// LSAs (types 3/4) are not admitted either — the default is the
    /// only inter-area route.
    StubNoSummary,
    /// `area <id> nssa` (RFC 3101): no type-5s, but type-7 externals
    /// live in the area and the ABR translates the P-set ones into
    /// type-5s for the transit topology.
    Nssa {
        no_summary: bool,
        /// FRR's `nssa default-information-originate` — accepted for
        /// grammar compatibility; the RFC-mandatory border default
        /// (§2.4/§2.7) is originated either way (see docs).
        default_information_originate: bool,
    },
}

impl AreaKind {
    /// §3.6/§10.5: ExternalRoutingCapability is false in stub areas
    /// and in NSSAs (RFC 3101 §2.1: interfaces in an NSSA neither
    /// send nor receive type-5s).
    pub fn external_capable(self) -> bool {
        matches!(self, AreaKind::Normal)
    }

    /// Type-7s may be originated/flooded (NSSA only, RFC 3101 §2.3).
    pub fn nssa(self) -> bool {
        matches!(self, AreaKind::Nssa { .. })
    }
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
    /// The interface's own address/mask. The STATIC source: the zapi
    /// interface dump (`ifdump`) overrides it per interface when it
    /// knows a live non-secondary IPv4 address; this stays the
    /// fallback (standalone mode, unknown interfaces, v6-only).
    pub address: Option<(Ipv4Addr, Ipv4Addr)>,
    /// The LIVE link state from the zapi interface dump: `Some(true)`
    /// operative (and not loopback), `Some(false)` down/loopback —
    /// the interface does not fire §9.3's InterfaceUp at construction
    /// and stays Down. `None` = no dump (standalone v1: InterfaceUp
    /// fires at construction, the config's address IS the lower
    /// layer's usable signal).
    pub link_state: Option<bool>,
    pub network_type: NetworkType,
    /// Interface MTU (DD's MTU field). The dump's MTU overrides it
    /// when one was reported.
    pub mtu: u16,
    /// Packet authentication (Appendix D): None / simple password /
    /// HMAC-SHA-256 cryptographic.
    pub auth: crate::auth::AuthConfig,
    /// The OSPFv3 runtime's §2.5 link-local source address
    /// (`link-local <fe80::...>`; required for the v6 core).
    pub link_local: Option<Ipv6Addr>,
    /// The OSPFv3 Instance ID (§A.3.1): received packets whose
    /// Instance ID differs are discarded. Defaults to 0.
    pub instance_id: u8,
    /// An explicit kernel ifindex pin (the Interface ID + multicast
    /// join argument); `None` resolves from the interface name at
    /// daemon construction (`/proc/net/if_inet6`).
    pub ifindex: Option<u32>,
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
            link_state: None,
            network_type: NetworkType::Broadcast,
            mtu: 1500,
            auth: crate::auth::AuthConfig::None,
            link_local: None,
            instance_id: 0,
            ifindex: None,
        }
    }
}

/// Merge a re-declared area kind with the existing one (the nssa
/// flags OR together — FRR accepts `area X nssa` then
/// `area X nssa no-summary` as refinements).
fn merge_area_kind(old: AreaKind, new: AreaKind) -> AreaKind {
    match (old, new) {
        (
            AreaKind::Nssa {
                no_summary: a,
                default_information_originate: b,
            },
            AreaKind::Nssa {
                no_summary: c,
                default_information_originate: d,
            },
        ) => AreaKind::Nssa {
            no_summary: a || c,
            default_information_originate: b || d,
        },
        (_, n) => n,
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
        family: AddressFamily::default(),
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
                    "address-family" => {
                        if words.len() != 2 || words[1] != "ipv6-unicast" {
                            return Err(parse_error(
                                line_no,
                                "expected: address-family ipv6-unicast (v1)",
                            ));
                        }
                        if cfg.family != AddressFamily::default() {
                            return Err(parse_error(line_no, "duplicate address-family"));
                        }
                        cfg.family = AddressFamily::Ipv6;
                    }
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
                        // area <id> [stub [no-summary]] · area <id>
                        // default-cost <n> — the FRR grammar's area
                        // parameters; parameter lines may reopen an
                        // already-declared area (FRR's own files write
                        // `area X stub` and `area X default-cost N`
                        // separately).
                        if words.len() < 2 {
                            return Err(parse_error(line_no, "expected: area <id>"));
                        }
                        let Some(area) = parse_ipv4(words[1]) else {
                            return Err(parse_error(line_no, "bad area id"));
                        };
                        let raw = u32::from(area);
                        let kind = match words[2..] {
                            [] => None,
                            ["stub"] => Some(AreaKind::Stub),
                            ["stub", "no-summary"] => Some(AreaKind::StubNoSummary),
                            ["nssa"] => Some(AreaKind::Nssa {
                                no_summary: false,
                                default_information_originate: false,
                            }),
                            ["nssa", "no-summary"] => Some(AreaKind::Nssa {
                                no_summary: true,
                                default_information_originate: false,
                            }),
                            ["nssa", "default-information-originate"] => {
                                Some(AreaKind::Nssa {
                                    no_summary: false,
                                    default_information_originate: true,
                                })
                            }
                            ["nssa", "no-summary", "default-information-originate"] => {
                                Some(AreaKind::Nssa {
                                    no_summary: true,
                                    default_information_originate: true,
                                })
                            }
                            ["virtual-link", peer] => {
                                // §15/§D.3: the other endpoint's
                                // Router ID.
                                let Some(peer) = parse_ipv4(peer) else {
                                    return Err(parse_error(
                                        line_no,
                                        "expected: virtual-link <router-id>",
                                    ));
                                };
                                let peer = u32::from(peer);
                                if raw == 0 {
                                    return Err(parse_error(
                                        line_no,
                                        "virtual links do not transit the backbone (§15)",
                                    ));
                                }
                                match cfg.areas.iter_mut().find(|a| a.id == raw) {
                                    Some(existing) => {
                                        if existing.kind.external_capable()
                                            || matches!(existing.kind, AreaKind::Nssa { .. })
                                        {
                                            if !existing.virtual_links.contains(&peer) {
                                                existing.virtual_links.push(peer);
                                            }
                                        } else {
                                            return Err(parse_error(
                                                line_no,
                                                "virtual links cannot be configured through stub areas (§3.6)",
                                            ));
                                        }
                                    }
                                    None => cfg.areas.push(AreaConfig {
                                        id: raw,
                                        kind: AreaKind::Normal,
                                        default_cost: 1,
                                        virtual_links: vec![peer],
                                        interfaces: BTreeMap::new(),
                                    }),
                                }
                                continue;
                            }
                            ["default-cost", n] => {
                                let cost = n.parse().ok().filter(|v| *v <= 0x00ff_ffff).ok_or_else(
                                    || {
                                        parse_error(
                                            line_no,
                                            "expected: default-cost <0-16777215>",
                                        )
                                    },
                                )?;
                                if let Some(existing) =
                                    cfg.areas.iter_mut().find(|a| a.id == raw)
                                {
                                    existing.default_cost = cost;
                                } else {
                                    cfg.areas.push(AreaConfig {
                                        id: raw,
                                        kind: AreaKind::Normal,
                                        default_cost: cost,
                                        virtual_links: Vec::new(),
                                        interfaces: BTreeMap::new(),
                                    });
                                }
                                continue;
                            }
                            _ => {
                                return Err(parse_error(
                                    line_no,
                                    "expected: area <id> [stub [no-summary]] | area <id> default-cost <0-16777215>",
                                ))
                            }
                        };
                        if let Some(set) = kind {
                            if raw == 0 {
                                // §3.6: the backbone cannot be a stub area.
                                return Err(parse_error(
                                    line_no,
                                    "the backbone (area 0.0.0.0) cannot be a stub area (§3.6)",
                                ));
                            }
                            match cfg.areas.iter_mut().find(|a| a.id == raw) {
                                Some(existing) => {
                                    existing.kind = merge_area_kind(existing.kind, set)
                                }
                                None => cfg.areas.push(AreaConfig {
                                    id: raw,
                                    kind: set,
                                    default_cost: 1,
                                    virtual_links: Vec::new(),
                                    interfaces: BTreeMap::new(),
                                }),
                            }
                            continue;
                        }
                        if cfg.areas.iter().any(|a| a.id == raw) {
                            return Err(parse_error(line_no, "duplicate area stanza"));
                        }
                        cfg.areas.push(AreaConfig {
                            id: raw,
                            kind: AreaKind::Normal,
                            default_cost: 1,
                            virtual_links: Vec::new(),
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
                    | "network-type" | "mtu" | "authentication-key" | "authentication"
                    | "message-digest-key" | "link-local" | "instance-id" | "ifindex" => {
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
                            "authentication-key" => {
                                // FRR's `ip ospf authentication-key
                                // AUTH_KEY` (≤8 chars, null-padded
                                // to the 64-bit field — D.4.2 step 3).
                                let raw = words.get(1).copied().unwrap_or("");
                                let bytes = raw.as_bytes();
                                if bytes.is_empty() || bytes.len() > 8 {
                                    return Err(parse_error(
                                        line_no,
                                        "expected: authentication-key <1-8 chars>",
                                    ));
                                }
                                let mut pw = [0u8; 8];
                                pw[..bytes.len()].copy_from_slice(bytes);
                                iface.auth = crate::auth::AuthConfig::Simple { password: pw };
                            }
                            "authentication" => {
                                // FRR's `ip ospf authentication
                                // message-digest` (the plain
                                // `authentication` form is the
                                // area-level default; per-interface we
                                // only carry the override).
                                if words.len() != 2 || words[1] != "message-digest" {
                                    return Err(parse_error(
                                        line_no,
                                        "expected: authentication message-digest",
                                    ));
                                }
                                // Enables AuType 2 once a key exists;
                                // a missing key errors at daemon
                                // construction (the key may parse
                                // later in the stanza).
                                if iface.auth == crate::auth::AuthConfig::None {
                                    iface.auth = crate::auth::AuthConfig::HmacSha256 {
                                        key_id: 0,
                                        key: Vec::new(),
                                    };
                                }
                            }
                            "message-digest-key" => {
                                // FRR's message-digest-key carries
                                // only `md5`; we expose the RFC 5709
                                // MUST-level digest explicitly
                                // (grammar deviation, disclosed).
                                let id: u8 =
                                    words.get(1).and_then(|v| v.parse().ok()).ok_or_else(|| {
                                        parse_error(
                                            line_no,
                                            "expected: message-digest-key <id 1-255>",
                                        )
                                    })?;
                                if id == 0 {
                                    return Err(parse_error(line_no, "key id must be 1-255"));
                                }
                                if words.get(2).copied() != Some("hmac-sha-256") {
                                    return Err(parse_error(
                                        line_no,
                                        "expected: message-digest-key <id> hmac-sha-256 <key>",
                                    ));
                                }
                                let Some(key) = words.get(3) else {
                                    return Err(parse_error(
                                        line_no,
                                        "expected: message-digest-key <id> hmac-sha-256 <key>",
                                    ));
                                };
                                iface.auth = crate::auth::AuthConfig::HmacSha256 {
                                    key_id: id,
                                    key: key.as_bytes().to_vec(),
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
                            // The OSPFv3 runtime's interface lines
                            // (S7-a): the §2.5 link-local source, the
                            // §A.3.1 Instance ID, and an explicit
                            // ifindex pin (tests; production resolves
                            // the kernel index from the name).
                            "link-local" => {
                                let Some(addr) = words.get(1).and_then(|v| v.parse().ok()) else {
                                    return Err(parse_error(
                                        line_no,
                                        "expected: link-local <fe80::...>",
                                    ));
                                };
                                iface.link_local = Some(addr);
                            }
                            "instance-id" => {
                                let value: u32 =
                                    words.get(1).and_then(|v| v.parse().ok()).ok_or_else(|| {
                                        parse_error(line_no, "expected: instance-id <0-255>")
                                    })?;
                                if value > 255 {
                                    return Err(parse_error(
                                        line_no,
                                        "instance-id is an octet (0-255, A.3.1)",
                                    ));
                                }
                                iface.instance_id = value as u8;
                            }
                            "ifindex" => {
                                let value: u32 = words
                                    .get(1)
                                    .and_then(|v| v.parse().ok())
                                    .ok_or_else(|| parse_error(line_no, "expected: ifindex <n>"))?;
                                iface.ifindex = Some(value);
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

    // ---- stub areas (§3.6/§C.2, N3 M1) --------------------------------

    #[test]
    fn stub_area_config_parses() {
        // FRR's shape: the area kind on the area line, default-cost on
        // its own line reopening the same area.
        let cfg = parse(concat!(
            "router ospf\n",
            " router-id 10.255.2.1\n",
            " area 0.0.0.0\n",
            "  interface eth0\n",
            "   address 10.10.0.1/30\n",
            "   network-type point-to-point\n",
            " area 0.0.0.1 stub\n",
            "  interface eth1\n",
            "   address 10.20.0.1/30\n",
            "   network-type point-to-point\n",
            " area 0.0.0.1 default-cost 25\n",
        ))
        .unwrap();
        assert_eq!(cfg.areas.len(), 2);
        assert_eq!(cfg.areas[1].kind, AreaKind::Stub);
        assert_eq!(cfg.areas[1].default_cost, 25);
        // The one-line no-summary form (FRR's totally stuby).
        let cfg = parse("router ospf\n area 0.0.0.2 stub no-summary\n").unwrap();
        assert_eq!(cfg.areas[0].kind, AreaKind::StubNoSummary);
        // The separate-line form of no-summary merges too.
        let cfg =
            parse("router ospf\n area 0.0.0.2 stub\n area 0.0.0.2 stub no-summary\n").unwrap();
        assert_eq!(cfg.areas[0].kind, AreaKind::StubNoSummary);
        // default-cost defaults to 1 (FRR parity).
        let cfg = parse("router ospf\n area 0.0.0.1 stub\n").unwrap();
        assert_eq!(cfg.areas[0].default_cost, 1);
    }

    #[test]
    fn nssa_area_config_parses() {
        let cfg = parse("router ospf\n area 0.0.0.1 nssa\n").unwrap();
        assert_eq!(
            cfg.areas[0].kind,
            AreaKind::Nssa {
                no_summary: false,
                default_information_originate: false
            }
        );
        // The FRR knob forms.
        let cfg = parse("router ospf\n area 0.0.0.1 nssa default-information-originate\n").unwrap();
        assert!(matches!(
            cfg.areas[0].kind,
            AreaKind::Nssa {
                default_information_originate: true,
                ..
            }
        ));
        let cfg =
            parse("router ospf\n area 0.0.0.1 nssa no-summary default-information-originate\n")
                .unwrap();
        assert!(matches!(
            cfg.areas[0].kind,
            AreaKind::Nssa {
                no_summary: true,
                default_information_originate: true
            }
        ));
        // Reopen merges the flags (FRR refinements).
        let cfg =
            parse("router ospf\n area 0.0.0.1 nssa\n area 0.0.0.1 nssa no-summary\n").unwrap();
        assert!(matches!(
            cfg.areas[0].kind,
            AreaKind::Nssa {
                no_summary: true,
                ..
            }
        ));
        // The backbone cannot be an NSSA (RFC 3101 §3.1's transit
        // role presupposes a non-backbone area).
        let err = parse("router ospf\n area 0.0.0.0 nssa\n").unwrap_err();
        assert!(err.to_string().contains("backbone"), "{err}");
    }

    #[test]
    fn auth_directives_parse() {
        // The simple password (FRR's `ip ospf authentication-key`).
        let cfg =
            parse("router ospf\n area 0.0.0.0\n  interface eth0\n   authentication-key s3cret\n")
                .unwrap();
        assert_eq!(
            cfg.areas[0].interfaces["eth0"].auth,
            crate::auth::AuthConfig::Simple {
                password: *b"s3cret\0\0"
            },
            "null-padded to the 64-bit field (D.4.2 step 3)"
        );
        // The crypto form: authentication message-digest + the key.
        let cfg = parse(
            "router ospf\n area 0.0.0.0\n  interface eth0\n   authentication message-digest\n   message-digest-key 3 hmac-sha-256 ospfkey\n",
        )
        .unwrap();
        assert_eq!(
            cfg.areas[0].interfaces["eth0"].auth,
            crate::auth::AuthConfig::HmacSha256 {
                key_id: 3,
                key: b"ospfkey".to_vec()
            }
        );
        // Strictness: >8-char password, bad key id, wrong algorithm
        // keyword — all carry line numbers.
        let err = parse(
            "router ospf\n area 0.0.0.0\n  interface eth0\n   authentication-key ninechars\n",
        )
        .unwrap_err();
        assert!(err.to_string().contains("line 4"), "{err}");
        let err = parse(
            "router ospf\n area 0.0.0.0\n  interface eth0\n   message-digest-key 0 hmac-sha-256 k\n",
        )
        .unwrap_err();
        assert!(err.to_string().contains("line 4"), "{err}");
        let err =
            parse("router ospf\n area 0.0.0.0\n  interface eth0\n   message-digest-key 1 md5 k\n")
                .unwrap_err();
        assert!(err.to_string().contains("line 4"), "{err}");
    }

    #[test]
    fn virtual_link_directives_parse() {
        let cfg = parse(
            "router ospf\n area 0.0.0.1\n  interface eth1\n area 0.0.0.1 virtual-link 10.255.2.1\n",
        )
        .unwrap();
        assert_eq!(
            cfg.areas[0].virtual_links,
            vec![u32::from(Ipv4Addr::new(10, 255, 2, 1))]
        );
        // §3.6: virtual links cannot be configured through stub areas.
        let err = parse("router ospf\n area 0.0.0.1 stub\n area 0.0.0.1 virtual-link 10.255.2.1\n")
            .unwrap_err();
        assert!(err.to_string().contains("stub areas"), "{err}");
        // §15: they do not transit the backbone.
        let err = parse("router ospf\n area 0.0.0.0\n area 0.0.0.0 virtual-link 10.255.2.1\n")
            .unwrap_err();
        assert!(err.to_string().contains("backbone"), "{err}");
        // Bad router-id.
        let err = parse("router ospf\n area 0.0.0.1 virtual-link not-an-ip\n").unwrap_err();
        assert!(err.to_string().contains("line 2"), "{err}");
    }

    #[test]
    fn stub_area_config_is_strict() {
        // §3.6: the backbone cannot be a stub area.
        let err = parse("router ospf\n area 0.0.0.0 stub\n").unwrap_err();
        assert!(err.to_string().contains("backbone"), "{err}");
        assert!(err.to_string().contains("line 2"), "{err}");
        // ... in either form.
        let err = parse("router ospf\n area 0.0.0.0\n area 0.0.0.0 stub no-summary\n").unwrap_err();
        assert!(err.to_string().contains("backbone"), "{err}");
        // Unknown area parameter carries the line number.
        let err = parse("router ospf\n area 0.0.0.1 frob\n").unwrap_err();
        assert!(err.to_string().contains("line 2"), "{err}");
        // Out-of-range default-cost.
        let err = parse("router ospf\n area 0.0.0.1 default-cost 16777216\n").unwrap_err();
        assert!(err.to_string().contains("line 2"), "{err}");
        // A bare duplicate area line is still a duplicate.
        let err = parse("router ospf\n area 0.0.0.1\n area 0.0.0.1\n").unwrap_err();
        assert!(err.to_string().contains("duplicate area"), "{err}");
    }

    /// The OSPFv3 runtime's config surface (S7-a): the
    /// `address-family ipv6-unicast` selector, the interface's
    /// `link-local` source, `instance-id`, and the `ifindex` pin.
    #[test]
    fn ospfv3_address_family_and_interface_lines() {
        let cfg = parse(
            "router ospf\n address-family ipv6-unicast\n router-id 10.255.2.1\n area 0.0.0.0\n  interface eth0\n   link-local fe80::a1:1\n   instance-id 7\n   ifindex 3\n   network-type point-to-point\n redistribute static\n",
        )
        .unwrap();
        assert_eq!(cfg.family, AddressFamily::Ipv6);
        let iface = &cfg.areas[0].interfaces["eth0"];
        assert_eq!(
            iface.link_local,
            Some("fe80::a1:1".parse::<Ipv6Addr>().unwrap())
        );
        assert_eq!(iface.instance_id, 7);
        assert_eq!(iface.ifindex, Some(3));
        // The default family is v4 (absent selector).
        let cfg = parse("router ospf\n router-id 10.0.0.1\n area 0.0.0.0\n  interface eth0\n   address 10.0.0.1/30\n").unwrap();
        assert_eq!(cfg.family, AddressFamily::Ipv4);
        assert_eq!(cfg.areas[0].interfaces["eth0"].instance_id, 0);
        // Strictness: unknown family and out-of-range instance IDs.
        let err = parse("router ospf\n address-family ipv4-unicast\n").unwrap_err();
        assert!(err.to_string().contains("ipv6-unicast"), "{err}");
        let err = parse("router ospf\n area 0.0.0.0\n  interface eth0\n   instance-id 256\n")
            .unwrap_err();
        assert!(err.to_string().contains("0-255"), "{err}");
    }
}
