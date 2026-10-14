//! `ospfd.conf` parser — the A11/B7 grammar conventions (line-based,
//! strict, unknown directives rejected with line numbers), shaped
//! like the frr.conf subset:
//!
//! ```text
//! zapi socket /run/rouster/zapi.api
//! key chain kc1
//!  key 1
//!   key-string old-secret
//!   cryptographic-algorithm hmac-sha-256
//!   send-lifetime 0 infinite
//!   accept-lifetime 0 3600
//!  key 2
//!   key-string new-secret
//!   cryptographic-algorithm md5
//!   send-lifetime 3600 infinite
//!   accept-lifetime 3600 infinite
//! router ospf
//!  router-id 10.0.0.1
//!  area 0.0.0.0
//!   interface eth0
//!    authentication key-chain kc1
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

use common::Ipv6Prefix;

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
    /// The named key chains (RFC 8177), referenced from interface
    /// auth by name (`authentication key-chain <name>`). The
    /// top-level `key chain` stanza is FRR's placement (the edge
    /// grammar); resolution to concrete keys happens at parse end.
    pub key_chains: Vec<crate::keychain::KeyChain>,
    /// `redistribute static`.
    pub redistribute_static: bool,
    /// `rfc1583-compatibility <enabled|disabled>` (§C.1, O-2): the
    /// §16.4 ASBR-path preference. Default ENABLED — RFC 2328 §C.1:
    /// "Set to 'enabled' by default" (FRR 10.2.2's probed default is
    /// disabled; the RFC's letter wins here, divergence disclosed).
    pub rfc1583_compatibility: bool,
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
    /// The OSPFv3 interface prefixes (`prefix <v6/len>`, RFC 5340
    /// C.3's list): carried in the link-LSA (§4.4.3.8) and advertised
    /// by the intra-area-prefix-LSAs (§4.4.3.9 — the p2p ones at the
    /// interface cost in the router-referenced IAPR; the broadcast
    /// ones by the link's DR at metric 0 in the network-referenced
    /// IAPR).
    pub prefixes_v6: Vec<Ipv6Prefix>,
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
            prefixes_v6: Vec::new(),
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

/// The open `key <id>` sub-stanza of a `key chain` stanza: its
/// opening line and the required-parameter markers (RFC 8177 §2.2:
/// key-string and crypto-algorithm are required key parameters — the
/// strict-house reading; an incomplete sub-stanza errors at its
/// opening line).
#[derive(Default)]
struct OpenKey {
    open: bool,
    line: usize,
    have_string: bool,
    have_algo: bool,
}

impl OpenKey {
    /// The close point: every depth-0 stanza line and EOF run this.
    fn close(
        &mut self,
        chains: &[crate::keychain::KeyChain],
        chain: Option<usize>,
    ) -> Result<(), crate::error::OspfError> {
        if !self.open {
            return Ok(());
        }
        self.open = false;
        let (have_string, have_algo, line) = (self.have_string, self.have_algo, self.line);
        self.have_string = false;
        self.have_algo = false;
        if let Some(ci) = chain {
            let kc = &chains[ci];
            let id = kc.keys.last().unwrap().key_id;
            if !have_string {
                return Err(parse_error(
                    line,
                    &format!(
                        "key {id} in chain {}: missing key-string (RFC 8177 2.2)",
                        kc.name
                    ),
                ));
            }
            if !have_algo {
                return Err(parse_error(
                    line,
                    &format!(
                        "key {id} in chain {}: missing cryptographic-algorithm (RFC 8177 2.2)",
                        kc.name
                    ),
                ));
            }
        }
        Ok(())
    }
}

/// Parse an `ospfd.conf`. Strict: indentation marks stanza nesting
/// (top level or one blank prefix), everything else is a parse error
/// with its line number.
///
/// The `key chain` stanza (RFC 8177, the O-8 shape) lives at depth 0
/// beside `router ospf` (FRR's own placement in frr.conf): a
/// depth-0 stanza line closes whatever stanza is open, so either
/// declaration order parses. Its nesting is `key chain <name>` →
/// `key <1-255>` → key parameters (key-string,
/// cryptographic-algorithm, send/accept-lifetime). Interfaces
/// reference a chain by name (`authentication key-chain <name>`);
/// references resolve at parse END.
pub fn parse(text: &str) -> Result<OspfdConfig, crate::error::OspfError> {
    let mut cfg = OspfdConfig {
        zapi_socket: None,
        router_id: None,
        family: AddressFamily::default(),
        areas: Vec::new(),
        networks: vec![],
        key_chains: Vec::new(),
        redistribute_static: false,
        rfc1583_compatibility: true,
    };
    let mut in_router = false;
    // The `key chain` stanza state: index of the open chain, whether
    // a `key <id>` sub-stanza is open (and its opening line + the
    // required-parameter markers), and the interface references
    // awaiting end-of-parse resolution. Depth-0 lines close the
    // stanza (indentation is the only nesting signal).
    let mut chain: Option<usize> = None;
    let mut open_key = OpenKey::default();
    // (line, area index, interface name, chain name) — resolved
    // against `cfg.key_chains` after the last line.
    let mut chain_refs: Vec<(usize, usize, String, String)> = Vec::new();
    // `key chain` stanzas may interleave around `router ospf`, but
    // only ONE router stanza exists: remember it was seen.
    let mut saw_router = false;

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
        // depth 0 = top level, 1 = router/key-chain level, 2+ =
        // area / key-parameter level.
        let level = match depth {
            0 => 0,
            1 => 1,
            _ => 2,
        };
        // The key-chain stanza path: a chain is open, the line is
        // indented, and the router stanza is not (the depth-0
        // routing below closes whichever stanza is open).
        if let (true, Some(ci)) = (level > 0 && !in_router, chain) {
            match (level, first) {
                (1, "key") => {
                    open_key.close(&cfg.key_chains, chain)?;
                    // `key <1-255>` — OSPF's Figure-18 Key ID is an
                    // octet (RFC 8177's uint64 narrowed to what the
                    // v2 wire can stamp).
                    if words.len() != 2 {
                        return Err(parse_error(line_no, "expected: key <1-255>"));
                    }
                    let id: u16 = words[1].parse().map_err(|_| {
                        parse_error(line_no, "expected: key <1-255> (the Figure-18 Key ID)")
                    })?;
                    if id == 0 || id > 255 {
                        return Err(parse_error(
                            line_no,
                            "key id must be 1-255 (the Figure-18 octet)",
                        ));
                    }
                    if cfg.key_chains[ci]
                        .keys
                        .iter()
                        .any(|k| k.key_id as u16 == id)
                    {
                        return Err(parse_error(
                            line_no,
                            &format!("duplicate key {id} in chain {}", cfg.key_chains[ci].name),
                        ));
                    }
                    cfg.key_chains[ci].keys.push(crate::keychain::KeyEntry {
                        key_id: id as u8,
                        // Placeholder until `cryptographic-algorithm`
                        // arrives; the open-key close rejects a key
                        // that never got one.
                        algorithm: crate::keychain::KeyAlgorithm::HmacSha256,
                        secret: Vec::new(),
                        send_lifetime: crate::keychain::Lifetime::ALWAYS,
                        accept_lifetime: crate::keychain::Lifetime::ALWAYS,
                    });
                    open_key = OpenKey {
                        open: true,
                        line: line_no,
                        have_string: false,
                        have_algo: false,
                    };
                }
                (1, other) => {
                    return Err(parse_error(
                        line_no,
                        &format!("unknown key-chain directive `{other}` (expected: key <1-255>)"),
                    ))
                }
                (2, "key-string") => {
                    if !open_key.open {
                        return Err(parse_error(line_no, "key-string outside a key stanza"));
                    }
                    if words.len() != 2 {
                        return Err(parse_error(line_no, "expected: key-string <secret>"));
                    }
                    cfg.key_chains[ci].keys.last_mut().unwrap().secret =
                        words[1].as_bytes().to_vec();
                    open_key.have_string = true;
                }
                (2, "cryptographic-algorithm") => {
                    if !open_key.open {
                        return Err(parse_error(
                            line_no,
                            "cryptographic-algorithm outside a key stanza",
                        ));
                    }
                    if words.len() != 2 {
                        return Err(parse_error(
                            line_no,
                            "expected: cryptographic-algorithm <md5|hmac-sha-256>",
                        ));
                    }
                    let algo = match words[1] {
                        "md5" => crate::keychain::KeyAlgorithm::Md5,
                        "hmac-sha-256" => crate::keychain::KeyAlgorithm::HmacSha256,
                        other => {
                            return Err(parse_error(
                                line_no,
                                &format!(
                                    "unsupported cryptographic-algorithm `{other}` \
                                     (ospfd ships md5 + hmac-sha-256)"
                                ),
                            ))
                        }
                    };
                    cfg.key_chains[ci].keys.last_mut().unwrap().algorithm = algo;
                    open_key.have_algo = true;
                }
                (2, lifetime @ ("send-lifetime" | "accept-lifetime")) => {
                    if !open_key.open {
                        return Err(parse_error(
                            line_no,
                            &format!("{lifetime} outside a key stanza"),
                        ));
                    }
                    // `<start> (<end>|infinite)` — seconds on the
                    // daemon's injected clock (v1; wall-clock/NTP
                    // anchoring rides the `now` seam, see keychain.rs).
                    // The window is half-open: start inclusive, end
                    // exclusive (RFC 2328 D.4.3/D.5.3).
                    if words.len() != 3 {
                        return Err(parse_error(
                            line_no,
                            "expected: send/accept-lifetime <start> <end|infinite>",
                        ));
                    }
                    let start: u64 = words[1]
                        .parse()
                        .map_err(|_| parse_error(line_no, "bad lifetime start"))?;
                    let end = match words[2] {
                        "infinite" => None,
                        v => Some(
                            v.parse::<u64>()
                                .map_err(|_| parse_error(line_no, "bad lifetime end"))?,
                        ),
                    };
                    if end.is_some_and(|e| start >= e) {
                        return Err(parse_error(
                            line_no,
                            "lifetime window is empty (start must precede end; half-open)",
                        ));
                    }
                    let key = cfg.key_chains[ci].keys.last_mut().unwrap();
                    let slot = if lifetime == "send-lifetime" {
                        &mut key.send_lifetime
                    } else {
                        &mut key.accept_lifetime
                    };
                    *slot = crate::keychain::Lifetime {
                        start: Some(start),
                        end,
                    };
                }
                (2, other) => {
                    return Err(parse_error(
                        line_no,
                        &format!("unknown key parameter `{other}`"),
                    ))
                }
                _ => unreachable!("levels above 2 collapse to 2"),
            }
            continue;
        }
        match (level, in_router) {
            (0, _) => {
                // A depth-0 stanza line: close the open key (if any)
                // before routing the line itself.
                open_key.close(&cfg.key_chains, chain)?;
                match first {
                    "zapi" => {
                        if in_router {
                            return Err(parse_error(
                                line_no,
                                "directive inside the router stanza must be indented",
                            ));
                        }
                        if chain.is_some() {
                            return Err(parse_error(
                                line_no,
                                "zapi socket must precede the key chain stanza",
                            ));
                        }
                        if words.len() != 3 || words[1] != "socket" {
                            return Err(parse_error(line_no, "expected: zapi socket <path>"));
                        }
                        if cfg.zapi_socket.is_some() {
                            return Err(parse_error(line_no, "duplicate zapi socket line"));
                        }
                        cfg.zapi_socket = Some(words[2].to_string());
                    }
                    "router" => {
                        if in_router || saw_router {
                            return Err(parse_error(line_no, "duplicate router ospf stanza"));
                        }
                        if words.len() != 2 || words[1] != "ospf" {
                            return Err(parse_error(line_no, "expected: router ospf"));
                        }
                        // The `router ospf` line closes an open chain
                        // stanza (the shared depth-0 routing).
                        chain = None;
                        in_router = true;
                        saw_router = true;
                    }
                    "key" => {
                        // `key chain <name>` — RFC 8177's stanza at
                        // frr.conf's own depth-0 placement.
                        if words.len() != 3 || words[1] != "chain" {
                            return Err(parse_error(line_no, "expected: key chain <name>"));
                        }
                        let name = words[2];
                        if cfg.key_chains.iter().any(|c| c.name == name) {
                            return Err(parse_error(
                                line_no,
                                &format!("duplicate key chain `{name}`"),
                            ));
                        }
                        cfg.key_chains.push(crate::keychain::KeyChain {
                            name: name.to_string(),
                            keys: Vec::new(),
                        });
                        // Opening the chain closes the router stanza.
                        in_router = false;
                        chain = Some(cfg.key_chains.len() - 1);
                        open_key = OpenKey::default();
                    }
                    other => {
                        if in_router {
                            return Err(parse_error(
                                line_no,
                                "directive inside the router stanza must be indented",
                            ));
                        }
                        return Err(parse_error(
                            line_no,
                            &format!("unknown top-level directive `{other}`"),
                        ));
                    }
                }
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
                    "rfc1583-compatibility" => {
                        // §C.1's global knob (O-2). FRR spells it as
                        // the `ospf rfc1583compatibility` toggle under
                        // router ospf — the edge translates.
                        if words.len() != 2 {
                            return Err(parse_error(
                                line_no,
                                "expected: rfc1583-compatibility <enabled|disabled>",
                            ));
                        }
                        cfg.rfc1583_compatibility = match words[1] {
                            "enabled" => true,
                            "disabled" => false,
                            _ => {
                                return Err(parse_error(
                                    line_no,
                                    "expected: rfc1583-compatibility <enabled|disabled>",
                                ))
                            }
                        };
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
                    | "message-digest-key" | "link-local" | "instance-id" | "ifindex"
                    | "prefix" => {
                        // Interface parameter inside the LAST interface
                        // stanza of the LAST area; BTreeMap order cannot
                        // express "last", so we require the parameter to
                        // follow its interface line directly — strict
                        // and deterministic.
                        let area_idx = cfg.areas.len() - 1;
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
                                // only carry the override), and FRR's
                                // `ip ospf authentication key-chain
                                // NAME` — the RFC 8177 reference
                                // (O-8), resolved at parse end.
                                if words.len() == 3 && words[1] == "key-chain" {
                                    // Record the reference; the chain
                                    // stanza may appear later in the
                                    // file (both orders parse). The
                                    // area index is computed before
                                    // the `area` borrow below ends.
                                    let iname = area.interfaces.keys().next_back().unwrap().clone();
                                    chain_refs.push((
                                        line_no,
                                        area_idx,
                                        iname.clone(),
                                        words[2].to_string(),
                                    ));
                                } else if words.len() == 2 && words[1] == "message-digest" {
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
                                } else {
                                    return Err(parse_error(
                                        line_no,
                                        "expected: authentication message-digest | authentication key-chain <name>",
                                    ));
                                }
                            }
                            "message-digest-key" => {
                                // FRR's message-digest-key carries
                                // only `md5`; we spell the RFC 5709
                                // MUST-level digest explicitly (the
                                // one grammar addition, disclosed).
                                // S8-b: both engines parse (the
                                // key chains select per key; the
                                // static form follows).
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
                                let Some(key) = words.get(3) else {
                                    return Err(parse_error(
                                        line_no,
                                        "expected: message-digest-key <id> <md5|hmac-sha-256> <key>",
                                    ));
                                };
                                iface.auth = match words.get(2).copied() {
                                    Some("md5") => crate::auth::AuthConfig::KeyedMd5 {
                                        key_id: id,
                                        key: key.as_bytes().to_vec(),
                                    },
                                    Some("hmac-sha-256") => crate::auth::AuthConfig::HmacSha256 {
                                        key_id: id,
                                        key: key.as_bytes().to_vec(),
                                    },
                                    _ => {
                                        return Err(parse_error(
                                        line_no,
                                        "expected: message-digest-key <id> <md5|hmac-sha-256> <key>",
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
                            // The OSPFv3 interface prefixes (RFC 5340
                            // C.3): multiple lines allowed, each
                            // carried in the link-LSA and advertised
                            // by the IAPRs (§4.4.3.9).
                            "prefix" => {
                                let Some(p) =
                                    words.get(1).and_then(|v| v.parse::<Ipv6Prefix>().ok())
                                else {
                                    return Err(parse_error(
                                        line_no,
                                        "expected: prefix <x:x::x/len>",
                                    ));
                                };
                                if !iface.prefixes_v6.contains(&p) {
                                    iface.prefixes_v6.push(p);
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
    // EOF: validate the last open key (the same close the depth-0
    // stanza lines run).
    open_key.close(&cfg.key_chains, chain)?;
    // The router-stanza requirement keys off `saw_router`: a
    // trailing `key chain` stanza legitimately closes the router
    // stanza (in_router=false) without un-seeing it.
    if !saw_router {
        return Err(parse_error(
            text.lines().count(),
            "missing `router ospf` stanza",
        ));
    }
    if cfg.areas.is_empty() {
        return Err(parse_error(text.lines().count(), "missing `area` stanza"));
    }
    // Resolve the interface key-chain references (either declaration
    // order parses; the O-8 rule: interfaces reference by name).
    for (line, area_idx, iface_name, chain_name) in chain_refs {
        let Some(kc) = cfg.key_chains.iter().find(|c| c.name == chain_name) else {
            return Err(parse_error(
                line,
                &format!("unknown key chain `{chain_name}` (authentication key-chain)"),
            ));
        };
        let Some(area) = cfg.areas.get_mut(area_idx) else {
            return Err(parse_error(line, "key-chain reference without an area"));
        };
        let Some(iface) = area.interfaces.get_mut(&iface_name) else {
            return Err(parse_error(
                line,
                "key-chain reference without an interface",
            ));
        };
        iface.auth = crate::auth::AuthConfig::KeyChain { chain: kc.clone() };
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
    fn v3_prefix_lines_parse_in_order_and_dedupe() {
        // RFC 5340 C.3's interface prefix list: multiple `prefix`
        // lines collect in declaration order; a duplicate is a no-op.
        let cfg = parse("router ospf\n address-family ipv6-unicast\n router-id 1.1.1.1\n area 0.0.0.0\n  interface eth0\n   link-local fe80::1\n   ifindex 3\n   prefix 2001:db8:1::/64\n   prefix 2001:db8:2::/64\n   prefix 2001:db8:1::/64\n").unwrap();
        let eth0 = &cfg.areas[0].interfaces["eth0"];
        assert_eq!(
            eth0.prefixes_v6,
            vec![
                "2001:db8:1::/64".parse::<Ipv6Prefix>().unwrap(),
                "2001:db8:2::/64".parse().unwrap()
            ],
            "declaration order, duplicates dropped"
        );
        // A malformed prefix errors at its line.
        let err = parse("router ospf\n area 0.0.0.0\n  interface eth0\n   prefix 2001:db8::/129\n")
            .unwrap_err();
        assert!(err.to_string().contains("prefix"), "{err}");
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
        // The legacy static form (S8-b): FRR's own `md5` keyword now
        // parses to the KeyedMd5 engine.
        let cfg = parse(
            "router ospf\n area 0.0.0.0\n  interface eth0\n   message-digest-key 2 md5 legacykey\n",
        )
        .unwrap();
        assert_eq!(
            cfg.areas[0].interfaces["eth0"].auth,
            crate::auth::AuthConfig::KeyedMd5 {
                key_id: 2,
                key: b"legacykey".to_vec()
            }
        );
        // Strictness: >8-char password, bad key id, unknown algorithm
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
            parse("router ospf\n area 0.0.0.0\n  interface eth0\n   message-digest-key 1 sha1 k\n")
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

    /// §C.1's RFC1583Compatibility knob (O-2): default ENABLED per the
    /// RFC's letter ("Set to 'enabled' by default" — FRR 10.2.2's
    /// probed default is disabled; the divergence is disclosed in
    /// ospf.md), both spellings parse, anything else carries its line.
    #[test]
    fn rfc1583_compatibility_parses() {
        // The default: enabled (§C.1).
        let cfg = parse("router ospf\n area 0.0.0.0\n").unwrap();
        assert!(cfg.rfc1583_compatibility, "§C.1: enabled by default");
        // Both spellings.
        let cfg = parse("router ospf\n rfc1583-compatibility disabled\n area 0.0.0.0\n").unwrap();
        assert!(!cfg.rfc1583_compatibility);
        let cfg = parse("router ospf\n rfc1583-compatibility enabled\n area 0.0.0.0\n").unwrap();
        assert!(cfg.rfc1583_compatibility);
        // Strictness: a bad value and a duplicate carry line numbers.
        let err = parse("router ospf\n rfc1583-compatibility maybe\n area 0.0.0.0\n").unwrap_err();
        assert!(err.to_string().contains("<enabled|disabled>"), "{err}");
        assert!(err.to_string().contains("line 2"), "{err}");
    }

    // ---- key chains (RFC 8177, O-8, S8-b) -------------------------

    /// The chain stanza grammar (FRR's placement and keywords, the
    /// RFC 8177 shape): `key chain` at depth 0 beside `router ospf`,
    /// `key <id>` carrying key-string, the algorithm, and the
    /// half-open send/accept lifetimes. Either declaration order
    /// parses (the reference resolves at parse end).
    #[test]
    fn key_chain_stanza_parses() {
        use crate::auth::AuthConfig;
        use crate::keychain::{KeyAlgorithm, Lifetime};
        // The chain AFTER the router stanza (a depth-0 sibling).
        let cfg = parse(concat!(
            "router ospf\n",
            " router-id 10.255.2.1\n",
            " area 0.0.0.0\n",
            "  interface eth0\n",
            "   address 10.77.0.1/30\n",
            "   network-type point-to-point\n",
            "   authentication key-chain kc1\n",
            "key chain kc1\n",
            " key 1\n",
            "  key-string old-secret\n",
            "  cryptographic-algorithm hmac-sha-256\n",
            "  send-lifetime 0 infinite\n",
            "  accept-lifetime 0 3600\n",
            " key 2\n",
            "  key-string new-secret\n",
            "  cryptographic-algorithm md5\n",
            "  send-lifetime 3600 infinite\n",
            "  accept-lifetime 3600 infinite\n",
        ))
        .unwrap();
        assert_eq!(cfg.key_chains.len(), 1);
        let kc = &cfg.key_chains[0];
        assert_eq!(kc.name, "kc1");
        assert_eq!(kc.keys.len(), 2);
        assert_eq!(
            kc.keys[0],
            crate::keychain::KeyEntry {
                key_id: 1,
                algorithm: KeyAlgorithm::HmacSha256,
                secret: b"old-secret".to_vec(),
                send_lifetime: Lifetime {
                    start: Some(0),
                    end: None
                },
                accept_lifetime: Lifetime {
                    start: Some(0),
                    end: Some(3600)
                },
            }
        );
        assert_eq!(kc.keys[1].key_id, 2);
        assert_eq!(kc.keys[1].algorithm, KeyAlgorithm::Md5);
        // The interface's reference resolved to the chain by name.
        assert!(matches!(
            cfg.areas[0].interfaces["eth0"].auth,
            AuthConfig::KeyChain { ref chain } if chain.name == "kc1"
        ));
        // The chain BEFORE the router stanza parses identically.
        let cfg = parse(concat!(
            "key chain kc1\n",
            " key 1\n",
            "  key-string s\n",
            "  cryptographic-algorithm md5\n",
            "router ospf\n",
            " area 0.0.0.0\n",
            "  interface eth0\n",
            "   authentication key-chain kc1\n",
        ))
        .unwrap();
        assert!(matches!(
            cfg.areas[0].interfaces["eth0"].auth,
            AuthConfig::KeyChain { ref chain } if chain.keys.len() == 1
        ));
        // A second chain stanza after the router stanza, and a second
        // interface referencing it (multiple chains coexist; a
        // no-lifetime key defaults to ALWAYS per RFC 8177).
        let cfg = parse(concat!(
            "router ospf\n",
            " area 0.0.0.0\n",
            "  interface eth0\n",
            "   authentication key-chain kc1\n",
            "  interface eth1\n",
            "   authentication key-chain kc2\n",
            "key chain kc1\n",
            " key 1\n",
            "  key-string a\n",
            "  cryptographic-algorithm md5\n",
            "key chain kc2\n",
            " key 7\n",
            "  key-string b\n",
            "  cryptographic-algorithm hmac-sha-256\n",
            "  accept-lifetime 100 200\n",
        ))
        .unwrap();
        assert_eq!(cfg.key_chains.len(), 2);
        assert!(matches!(
            cfg.areas[0].interfaces["eth1"].auth,
            AuthConfig::KeyChain { ref chain } if chain.keys[0].key_id == 7
                && chain.keys[0].send_lifetime == Lifetime::ALWAYS
                && chain.keys[0].accept_lifetime
                    == Lifetime { start: Some(100), end: Some(200) }
        ));
    }

    /// The chain grammar's strict face: every malformed shape errors
    /// with its line number (the A11/B7 house rule).
    #[test]
    fn key_chain_stanza_is_strict() {
        // Unknown chain reference (the O-8 resolution error).
        let err = parse(concat!(
            "router ospf\n",
            " area 0.0.0.0\n",
            "  interface eth0\n",
            "   authentication key-chain nosuch\n",
            "key chain other\n",
            " key 1\n",
            "  key-string a\n",
            "  cryptographic-algorithm md5\n",
        ))
        .unwrap_err();
        assert!(err.to_string().contains("unknown key chain"), "{err}");
        assert!(err.to_string().contains("line 4"), "{err}");
        // Duplicate chain name.
        let err = parse(concat!(
            "router ospf\n area 0.0.0.0\n",
            "key chain kc\n key 1\n  key-string a\n  cryptographic-algorithm md5\n",
            "key chain kc\n",
        ))
        .unwrap_err();
        assert!(err.to_string().contains("duplicate key chain"), "{err}");
        // Duplicate key id inside one chain.
        let err = parse(concat!(
            "router ospf\n area 0.0.0.0\n",
            "key chain kc\n",
            " key 1\n  key-string a\n  cryptographic-algorithm md5\n",
            " key 1\n  key-string b\n  cryptographic-algorithm md5\n",
        ))
        .unwrap_err();
        assert!(err.to_string().contains("duplicate key 1"), "{err}");
        assert!(err.to_string().contains("line 7"), "{err}");
        // Key ID bounds: the Figure-18 octet.
        for bad in ["0", "256"] {
            let text = format!(
                "router ospf\n area 0.0.0.0\nkey chain kc\n key {bad}\n  key-string a\n  cryptographic-algorithm md5\n"
            );
            let err = parse(&text).unwrap_err();
            assert!(err.to_string().contains("1-255"), "key {bad}: {err}");
        }
        // Missing key-string / algorithm (RFC 8177 §2.2's required
        // parameters) — the error anchors at the key's opening line.
        let err = parse(concat!(
            "router ospf\n area 0.0.0.0\n",
            "key chain kc\n key 1\n  cryptographic-algorithm md5\n",
        ))
        .unwrap_err();
        assert!(err.to_string().contains("missing key-string"), "{err}");
        assert!(err.to_string().contains("line 4"), "{err}");
        let err = parse(concat!(
            "router ospf\n area 0.0.0.0\n",
            "key chain kc\n key 1\n  key-string a\n",
        ))
        .unwrap_err();
        assert!(err.to_string().contains("cryptographic-algorithm"), "{err}");
        // Unsupported algorithm (ospfd ships md5 + hmac-sha-256).
        let err = parse(concat!(
            "router ospf\n area 0.0.0.0\n",
            "key chain kc\n key 1\n  key-string a\n  cryptographic-algorithm hmac-sha-512\n",
        ))
        .unwrap_err();
        assert!(err.to_string().contains("hmac-sha-256"), "{err}");
        // An empty lifetime window is rejected.
        let err = parse(concat!(
            "router ospf\n area 0.0.0.0\n",
            "key chain kc\n key 1\n  key-string a\n  cryptographic-algorithm md5\n",
            "  send-lifetime 100 100\n",
        ))
        .unwrap_err();
        assert!(err.to_string().contains("empty"), "{err}");
        // Lifetime missing its end bound.
        let err = parse(concat!(
            "router ospf\n area 0.0.0.0\n",
            "key chain kc\n key 1\n  key-string a\n  cryptographic-algorithm md5\n",
            "  accept-lifetime 100\n",
        ))
        .unwrap_err();
        assert!(err.to_string().contains("infinite"), "{err}");
        // Unknown key parameter and key-chain directive.
        let err = parse(concat!(
            "router ospf\n area 0.0.0.0\n",
            "key chain kc\n key 1\n  key-string a\n  cryptographic-algorithm md5\n  frob 1\n",
        ))
        .unwrap_err();
        assert!(err.to_string().contains("unknown key parameter"), "{err}");
        let err = parse("router ospf\n area 0.0.0.0\nkey chain kc\n keys 1\n").unwrap_err();
        assert!(err.to_string().contains("key <1-255>"), "{err}");
        // Key parameters outside a key stanza.
        let err = parse("router ospf\n area 0.0.0.0\nkey chain kc\n  key-string a\n").unwrap_err();
        assert!(err.to_string().contains("outside a key stanza"), "{err}");
        // The stale zapi-placement rule still holds (zapi precedes
        // the stanzas).
        let err = parse(concat!(
            "key chain kc\n key 1\n  key-string a\n  cryptographic-algorithm md5\n",
            "zapi socket /run/rouster/zapi.api\n",
        ))
        .unwrap_err();
        assert!(
            err.to_string().contains("zapi socket must precede"),
            "{err}"
        );
        // One router stanza per file, even interleaved with chains.
        let err = parse(concat!(
            "router ospf\n area 0.0.0.0\n",
            "key chain kc\n key 1\n  key-string a\n  cryptographic-algorithm md5\n",
            "router ospf\n",
        ))
        .unwrap_err();
        assert!(err.to_string().contains("duplicate router ospf"), "{err}");
    }
}
