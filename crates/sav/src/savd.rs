//! savd — the SAV daemon logic (W8): holds the SIB, regenerates rules on
//! RIB changes, and programs enforcement through the
//! [`Dataplane`](common::Dataplane) trait, **monitor-only by default**
//! (repo AGENTS.md: "Enforcement defaults to log/monitor before drop").
//!
//! The daemon state machine lives here (not in the binary) so tests drive
//! the exact production logic over duplex pairs and a mock dataplane —
//! the same split as `rousterd::staticd` (the proven daemon shape this
//! follows: thin binary, testable core).
//!
//! # RIB coupling (the pre-registered choice, disclosed)
//!
//! savd is a separate process; it cannot share rousterd's in-process
//! RIB, and its own netlink mirror would see only kernel routes (which
//! the SIB never ingests, W5). So the RIB view arrives over the existing
//! ZAPI client edge, exactly like staticd, using ONLY existing message
//! types:
//!
//! - [`ZapiClient::send_redistribute_add`] for every protocol route
//!   type × AFI — the server's W2 behavior answers each registration
//!   with the initial dump of that type's current best main-table
//!   routes, then event-driven `REDISTRIBUTE_ROUTE_ADD/DEL` pushes.
//!   Pushes are in *push form* (gateway hops already resolved to
//!   ifindex-carrying form), which is exactly what
//!   [`Sib::ingest_rib`] consumes; the local mirror is a plain
//!   [`Rib`] fed from those pushes.
//! - A transient dummy `NEXTHOP_REGISTER` after the registrations is
//!   the causality marker: its reply can only be produced after the
//!   driver processed every earlier `RegisterRedistribute`, so once the
//!   marker is read the whole dump is at least queued. ZAPI has no
//!   end-of-dump marker, so a bounded quiet window
//!   ([`SYNC_SETTLE`]) collects what follows.
//! - The interface mirror (names, addresses) comes from savd's own
//!   netlink dataplane dump/events — the same kernel truth the
//!   enforcement backend writes to. No new IPC, no wire changes.
//!
//! # Event-driven re-evaluation + deletion hysteresis (A10)
//!
//! savd is an EVENT-DRIVEN consumer: every mirror change that can
//! alter the program (a redistribute push, an interface/address event)
//! sets a dirty flag ([`SavDaemon::take_dirty`]), and the resident
//! select loop re-evaluates — regenerate + install — on the flag
//! instead of waiting for the poll tick. The poll cadence stays as the
//! safety net (and SIGHUP still re-evaluates); neighbour observations
//! feed only the spoof counter and never dirty the view.
//!
//! Deletions ride a short hysteresis window (RFC 8704 §3.6.2:
//! "Deleting entries from the RPF lists SHOULD be delayed by a
//! predetermined amount ... when responding to route withdrawals"; see
//! `away/2026-10-09/quarantine/B5-urpf-notes.md` §2.6): a prefix that
//! leaves a still-present allowlist is held installed for the
//! configured `hysteresis <secs>` window (A10's fixed 3 s is the
//! default; a pending-deletions set the select loop's timer arm
//! flushes), so a withdraw/re-advertise transient never flickers the
//! dataplane — the re-advertised prefix is absorbed silently.
//! Additions and whole-op removals (the allowlist's generator mode,
//! interface, or action changed — operator intent, not a route flap)
//! apply immediately. The spoof monitor judges the same effective ops
//! the dataplane enforces, so counters and enforcement never disagree.
//!
//! The `collision-policy` knob selects GSC §3's resolution for mode
//! collisions at compile time ([`CollisionPolicy`]): `ignore` (the
//! default — colliding block-mode rules are dropped with a warning) or
//! `subtract` (the merge-by-subtraction variant GSC §5 prefers when
//! data-plane memory allows, landed in A6 unwired). (GSC =
//! `draft-ietf-savnet-general-sav-capabilities-03`, published
//! 2026-06-21 — the pinned revision the mode taxonomy and collision
//! model are implemented against; SAV-3, owner-adjudicated 2026-10-14.)
//! The uRPF
//! generators emit only IBA rules, which cannot collide — the knob is
//! wiring for the first IBB/PBB rule source (W6 §Deferred 1's operator
//! builder, a SAVNET agent); both policies compile today's rule sets
//! byte-identically.
//!
//! The churn log renders at field granularity (A20): now that every
//! mirror change re-evaluates, the common change is a few prefixes
//! moving on a persistent allowlist, and [`rule_changes`] logs exactly
//! those members instead of the whole op twice (the op-set difference
//! [`program_diff`] computes is unchanged — a logging compression, not
//! an install-behavior change; the dataplane always receives the full
//! new program).
//!
//! # Binding TTL sweep (A22)
//!
//! Every evaluate runs one bounded TTL sweep over the freshly built SIB
//! ([`Sib::sweep`], on an injected clock the daemon reads exactly once
//! per evaluate): bindings whose optional expiry has passed are removed
//! *before* rule generation, so the generated program never asserts an
//! expired binding, and a swept prefix leaves its allowlist through the
//! normal diff — riding the same RFC 8704 §3.6.2 hysteresis window as
//! any withdrawal (a re-learn inside the window is absorbed silently).
//!
//! Honest disclosure: **no landed origin sets a finite TTL**. Rib
//! bindings are wholesale re-derived on every evaluate (effectively
//! fresh — a deadline would misexpire bindings whose route is still
//! present), and Config bindings are operator-pinned (the SIB
//! structurally rejects an expiry on them), so today's sweep always
//! reports empty. The mechanism — the `expires_at` field, the sweep,
//! this wiring, the injectable clock — lands ready for the SAVNET
//! agent's future dynamic feed, which will stamp and refresh deadlines.
//! The sweep clock is `std::time::Instant` (monotonic, injectable so
//! tests pause it by owning the closure) and is deliberately separate
//! from the hysteresis clock (tokio's pausable runtime `Instant`, which
//! the deferred-delete tests drive through `start_paused`).
//!
//! # Hosted SAVNET agent (experimental-savnet, default OFF)
//!
//! Behind the flag, savd hosts the default [`crate::agent::MonitorAgent`]
//! ([`SavDaemon::set_agent`]): the daemon's own ZAPI RIB view feeds it
//! route events and every evaluate logs its binding suggestions —
//! **monitor-only** (the log-before-drop rule): no suggestion is
//! enforced, stored as a binding, or compiled into a rule; the
//! enforcement path is deliberately unwired until the SAVNET drafts
//! stabilize (docs/protocols/savnet.md). The interface itself is
//! in-process hooks only — no serialization, no sockets, no wire
//! codecs — so an anchor's hook calls reach an agent inside the
//! anchor's process (tests compose them; the architecture's
//! single-binary default deployment makes the composition
//! production-real); savd's own feed is the production-visible half.
//!
//! The hosting model is pinned (SAV-4, owner-adjudicated 2026-10-14):
//! **anchor-local no-op agents + savd-as-reference**. Each protocol
//! anchor registers its own (no-op/logger) agent in-process — savd
//! cannot receive another daemon's hook calls, and none are invented —
//! and savd's hosted MonitorAgent is the *reference implementation*
//! visible in tests, which the single-binary default deployment later
//! promotes to the production default host. Multi-process interim:
//! anchors without a registered agent simply no-op their hooks.
//!
//! # Config (`/etc/savd.conf`-shaped)
//!
//! Simple line grammar consistent with rousterd's (blank/`!`/`#`
//! ignored; whitespace-separated tokens):
//!
//! ```text
//! mode <strict|loose|fp|efp>        ! global default generator mode
//! action <monitor|drop>             ! invalid-verdict action (default monitor)
//! poll <secs>                       ! RIB re-evaluation cadence (default 5)
//! hysteresis <secs>                 ! RFC 8704 §3.6.2 deletion window (default 3)
//! collision-policy <ignore|subtract>
//!                                   ! GSC §3 collision resolution (default ignore)
//! backend <rp_filter|nft>           ! enforcement surface (default rp_filter)
//! i-understand-drop-mode yes        ! required friction to start in drop mode
//! interface <name>                  ! opens a per-interface stanza
//!   mode <strict|loose|fp|efp>      ! per-interface mode override
//!   mode barsav                     ! BAR-SAV derivation gates this iface
//!   role <customer|peer|provider>   ! required with mode barsav (the
//!                                   ! neighbor's RFC 9234 role)
//!   remote-as <asn>                 ! required with mode barsav (AS-k,
//!                                   ! BAR-SAV -10 §4 Step 1)
//! barsav feed <path>                ! bgpd's Adj-RIB-In snapshot (M3)
//! barsav vrp-file <path>            ! RPKI snapshot (bgpd vrp-file format)
//! barsav local-as <asn>             ! the local AS (cone guard; 0 = unset)
//! barsav provider-exempt <prefix>   ! BAR-SAV -10 §8 Step 7 exemption
//! binding <prefix> interface <name>...
//!                                   ! operator SIB binding (Config origin)
//! ```
//!
//! `mode` is the one position-dependent directive (inside a stanza it
//! overrides that interface's generator mode; outside it sets the
//! global default the stanzas inherit). `action drop` refuses to start
//! (and refuses to reload) without the explicit
//! `i-understand-drop-mode yes` line — deliberate friction on the one
//! action that can blackhole legitimate traffic.
//!
//! `binding` lines are position-independent operator bindings: sources
//! inside `<prefix>` may legitimately arrive on the named interfaces,
//! overriding the RIB-derived binding for that same prefix (the SIB's
//! documented precedence — Config shadows Rib per prefix; a longer RIB
//! prefix still wins on specificity). One line per prefix; names
//! resolve against the local mirror at evaluation time, so a name not
//! (yet) mirrored warns and drops out while a line with no resolved
//! name at all stores nothing (unknown ≠ invalid) — the poll/event
//! re-evaluations re-resolve. A config swap (SIGHUP) replaces the
//! whole Config origin through [`Sib::replace_origin`].

use std::fmt;
use std::path::PathBuf;
use std::time::Duration;

use common::{
    Dataplane, DataplaneError, DataplaneEvent, IpPrefix, SavMonitorCounts, SavProgram, SavProgramOp,
};
use rib::Rib;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::time::{timeout, Instant};
use tracing::{debug, info, warn};
use zapi::{route_type, ZapiClient, ZapiMessage};

// The hosted agent's trait methods (experimental-savnet only).
#[cfg(feature = "experimental-savnet")]
use crate::agent::SavAgent;
use crate::barsav::{
    generate_barsav, parse_barsav_feed, parse_rpki_snapshot, BarNeighbor, BarPath, BarRole,
    BarsavInput,
};
use crate::gen::{generate_urpf, RuleOrigin, UrpfMode};
use crate::mode::{SavAction, SavConfig, ValidationMode};
use crate::monitor::SpoofMonitor;
use crate::program::program;
use crate::table::{compile_with, CollisionPolicy, SavOp, Verdict};
use crate::{Binding, BindingOrigin, InterfaceRef, Sib, MAIN_TABLE};

/// Default hysteresis window for allowlist deletions (RFC 8704 §3.6.2):
/// the fixed 3 s value A10 pinned, now the default of the configurable
/// `hysteresis <secs>` knob — long enough to absorb a redistribute
/// flap, short enough that a real withdrawal converges promptly.
pub const DEFAULT_HYSTERESIS_SECS: u64 = 3;

/// The default window as a duration ([`DEFAULT_HYSTERESIS_SECS`]);
/// the deferred-delete tests advance the paused clock by exactly this.
#[cfg(test)]
const DEFERRED_DELETE_DELAY: Duration = Duration::from_secs(DEFAULT_HYSTERESIS_SECS);

/// Quiet window after the sync marker: anything the server still had
/// queued arrives within it (the dump is produced synchronously inside
/// the driver's registration handling). Bounded so a busy server
/// cannot stall startup indefinitely.
const SYNC_SETTLE: Duration = Duration::from_millis(250);

/// savd announces no protocol of its own in HELLO — it is a consumer of
/// redistribution, not a route source (`redist_default = 0`; the server
/// echoes any value).
const SAVD_PROTOCOL: u8 = 0;

/// The route types whose best main-table routes savd wants in its view:
/// every protocol that can land routes via ZAPI `ROUTE_ADD`. System/
/// kernel/connect never appear as protocol-table routes on any landed
/// path (kernel observation lives in the kernel mirror, which the SIB
/// never ingests — W5).
const ROUTE_TYPES_OF_INTEREST: [u8; 7] = [
    route_type::STATIC,
    route_type::RIP,
    route_type::RIPNG,
    route_type::OSPF,
    route_type::OSPF6,
    route_type::ISIS,
    route_type::BGP,
];

/// ZAPI AFI values: AFI_IP / AFI_IP6.
const AFIS: [u8; 2] = [1, 2];

/// Default RIB re-evaluation cadence when the config carries no
/// `poll` line.
pub const DEFAULT_POLL_SECS: u64 = 5;

/// The dummy prefix used as the initial-sync causality marker (a /32 no
/// interface ever carries, so its NHT answer can only be the marker).
fn sync_marker() -> IpPrefix {
    "0.0.0.0/32".parse().expect("static prefix parses")
}

/// One configured interface stanza: the name (resolved to an ifindex
/// against the local mirror at evaluation time), its generator mode,
/// and — when `mode barsav` selected the BAR-SAV derivation — the
/// neighbor's role and AS-k (draft-ietf-sidrops-bar-sav-10 §2/§4
/// Step 1: customer and lateral peer run §4, provider runs §8).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InterfaceLine {
    pub name: String,
    pub mode: UrpfMode,
    /// `mode barsav` was set in this stanza (the uRPF `mode` above is
    /// then ignored).
    pub barsav: bool,
    /// `role <customer|peer|provider>` (required iff barsav).
    pub role: Option<BarRole>,
    /// `remote-as <asn>`: AS-k (required iff barsav).
    pub remote_as: Option<u32>,
}

/// One configured `binding <prefix> interface <name>...` line: an
/// operator-pinned ingress set for a source prefix — the SIB's
/// [`BindingOrigin::Config`] slot, shadowing the RIB-derived binding
/// for the same prefix. Names resolve against the local mirror at
/// evaluation time (same rule as stanza names).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BindingLine {
    pub prefix: IpPrefix,
    pub interfaces: Vec<String>,
}

/// The enforcement surface the daemon asks the dataplane to install
/// SAV programs on — the config knob selecting between the two landed
/// backends behind the same [`common::Dataplane`] trait ops.
///
/// This enum is the sav-side mirror of `netlink_dp::sav_nft::SavBackend`
/// (the dependency direction forbids sharing: the dataplane crate must
/// not see the sav layer, so the binary translates between the two —
/// the same orphan-rule pattern the action enums use).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum SavdBackend {
    /// rp_filter sysctls: kernel FIB uRPF, no monitor counters (the
    /// landed W7 surface; still the default).
    #[default]
    RpFilter,
    /// The nftables ruleset backend (N6): per-interface allowlist
    /// content enforced in `table inet rouster_sav`, monitor actions
    /// as kernel counters (`sav_monitor_counts` answers from them).
    Nft,
}

impl fmt::Display for SavdBackend {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            SavdBackend::RpFilter => "rp_filter",
            SavdBackend::Nft => "nft",
        })
    }
}

/// The parsed savd configuration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SavdConfig {
    /// Global default generator mode (`mode` outside any stanza).
    pub mode: UrpfMode,
    /// What enforcement does with invalid verdicts — Monitor unless the
    /// operator opts into Drop explicitly.
    pub action: SavAction,
    /// RIB re-evaluation cadence in seconds.
    pub poll_secs: u64,
    /// The RFC 8704 §3.6.2 deletion-hysteresis window in seconds
    /// (A10's fixed 3 s is the default). Parsed ≥ 1 — a zero window
    /// would re-introduce the withdraw/re-advertise flap the
    /// hysteresis exists to absorb, so the parser rejects it.
    pub hysteresis_secs: u64,
    /// GSC §3 collision resolution handed to [`crate::table::compile_with`]
    /// (default [`CollisionPolicy::Ignore`], today's behavior; the uRPF
    /// generators emit only IBA rules, which cannot collide — the knob
    /// is wiring for the first IBB/PBB rule source).
    pub collision_policy: CollisionPolicy,
    /// The enforcement surface SAV programs install on (default
    /// [`SavdBackend::RpFilter`] — unchanged since W7; `nft` selects
    /// the content-enforcing, counter-bearing ruleset backend).
    pub backend: SavdBackend,
    /// `i-understand-drop-mode yes` — the friction line drop mode
    /// requires.
    pub drop_ack: bool,
    /// Configured interface stanzas, in file order.
    pub interfaces: Vec<InterfaceLine>,
    /// Configured `binding` lines, in file order (one per prefix).
    pub bindings: Vec<BindingLine>,
    /// `barsav feed <path>`: bgpd's read-only Adj-RIB-In snapshot
    /// (the M3 edge) — the BAR-SAV derivation's path source.
    pub barsav_feed: Option<PathBuf>,
    /// `barsav vrp-file <path>`: the RPKI snapshot feeding §4 Step 11
    /// / §8 Step 4 (bgpd's vrp-file format; ROAs and ASPAs both).
    pub barsav_vrp_file: Option<PathBuf>,
    /// `barsav local-as <asn>`: the local AS for the cone guard (0 =
    /// unset; the guard is inert then, disclosed).
    pub barsav_local_as: u32,
    /// `barsav provider-exempt <prefix>` lines: BAR-SAV -10 §8
    /// Step 7's local exemptions, in file order.
    pub barsav_provider_exempt: Vec<IpPrefix>,
}

impl Default for SavdConfig {
    fn default() -> Self {
        Self {
            mode: UrpfMode::Strict,
            action: SavAction::Monitor,
            poll_secs: DEFAULT_POLL_SECS,
            hysteresis_secs: DEFAULT_HYSTERESIS_SECS,
            collision_policy: CollisionPolicy::Ignore,
            backend: SavdBackend::RpFilter,
            drop_ack: false,
            interfaces: Vec::new(),
            bindings: Vec::new(),
            barsav_feed: None,
            barsav_vrp_file: None,
            barsav_local_as: 0,
            barsav_provider_exempt: Vec::new(),
        }
    }
}

impl fmt::Display for SavdConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "mode {} action {} poll {}s interfaces {} bindings {} collision {} hysteresis {}s \
             backend {}",
            self.mode,
            self.action,
            self.poll_secs,
            self.interfaces.len(),
            self.bindings.len(),
            self.collision_policy,
            self.hysteresis_secs,
            self.backend
        )?;
        if self.barsav_feed.is_some() || self.interfaces.iter().any(|i| i.barsav) {
            write!(
                f,
                " barsav[ifaces {} feed {} vrps {} exempt {}]",
                self.interfaces.iter().filter(|i| i.barsav).count(),
                self.barsav_feed.is_some(),
                self.barsav_vrp_file.is_some(),
                self.barsav_provider_exempt.len()
            )?;
        }
        Ok(())
    }
}

impl SavdConfig {
    /// The deliberate-friction gate: drop mode must be acknowledged.
    /// Monitor needs no acknowledgement (it is the safe default).
    pub fn validate(&self) -> Result<(), String> {
        if self.action.is_drop() && !self.drop_ack {
            return Err(
                "refusing to run in drop mode: add `i-understand-drop-mode yes` \
                 to the savd config (drop can blackhole legitimate traffic)"
                    .into(),
            );
        }
        Ok(())
    }

    /// The re-evaluation cadence as a duration.
    pub fn poll_interval(&self) -> Duration {
        Duration::from_secs(self.poll_secs)
    }

    /// The deletion-hysteresis window as a duration (RFC 8704 §3.6.2).
    pub fn hysteresis_delay(&self) -> Duration {
        Duration::from_secs(self.hysteresis_secs)
    }
}

/// Config parse errors, rousterd's shape (line-numbered).
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum SavdConfigError {
    #[error("line {line}: {reason}")]
    Line { line: usize, reason: String },
    #[error("{0}")]
    Validation(String),
}

fn fail(line: usize, reason: impl Into<String>) -> SavdConfigError {
    SavdConfigError::Line {
        line,
        reason: reason.into(),
    }
}

fn parse_mode(token: &str) -> Option<UrpfMode> {
    match token {
        "strict" => Some(UrpfMode::Strict),
        "loose" => Some(UrpfMode::Loose),
        "fp" => Some(UrpfMode::Fp),
        "efp" => Some(UrpfMode::Efp),
        _ => None,
    }
}

/// Parses the savd config file (see the module docs for the grammar).
pub fn parse_savd_config(input: &str) -> Result<SavdConfig, SavdConfigError> {
    let mut config = SavdConfig::default();
    let mut seen_global_mode = false;
    let mut seen_action = false;
    let mut seen_poll = false;
    let mut seen_hysteresis = false;
    let mut seen_collision_policy = false;
    let mut seen_backend = false;
    let mut seen_drop_ack = false;

    for (idx, raw) in input.lines().enumerate() {
        let line_no = idx + 1;
        let line = raw.trim();
        if line.is_empty() || line.starts_with('!') || line.starts_with('#') {
            continue;
        }
        let tokens: Vec<&str> = line.split_whitespace().collect();
        match tokens.as_slice() {
            // Position-dependent: inside an open stanza this overrides
            // that interface's mode; before any stanza it is the global
            // default the stanzas inherit.
            ["mode", m] if !config.interfaces.is_empty() => {
                let iface = config.interfaces.last_mut().expect("stanza open");
                if *m == "barsav" {
                    // BAR-SAV (draft-ietf-sidrops-bar-sav-10): the
                    // derivation replaces the uRPF generator for this
                    // interface; role/remote-as complete the stanza.
                    iface.barsav = true;
                } else {
                    match parse_mode(m) {
                        Some(mode) => iface.mode = mode,
                        None => {
                            return Err(fail(
                                line_no,
                                format!("bad mode `{m}` (strict|loose|fp|efp|barsav)"),
                            ))
                        }
                    }
                }
            }
            ["mode", m] => {
                if seen_global_mode {
                    return Err(fail(line_no, "duplicate global `mode` line"));
                }
                if *m == "barsav" {
                    return Err(fail(
                        line_no,
                        "`mode barsav` selects the per-interface BAR-SAV derivation; \
                         it cannot be the global default",
                    ));
                }
                match parse_mode(m) {
                    Some(mode) => config.mode = mode,
                    None => {
                        return Err(fail(
                            line_no,
                            format!("bad mode `{m}` (strict|loose|fp|efp)"),
                        ))
                    }
                }
                seen_global_mode = true;
            }
            ["role", r] if !config.interfaces.is_empty() => {
                let iface = config.interfaces.last_mut().expect("stanza open");
                match BarRole::parse(r) {
                    Some(role) => iface.role = Some(role),
                    None => {
                        return Err(fail(
                            line_no,
                            format!("bad role `{r}` (customer|peer|provider)"),
                        ))
                    }
                }
            }
            ["remote-as", asn] if !config.interfaces.is_empty() => {
                let iface = config.interfaces.last_mut().expect("stanza open");
                let asn: u32 = asn
                    .parse()
                    .map_err(|_| fail(line_no, format!("bad remote-as `{asn}`")))?;
                iface.remote_as = Some(asn);
            }
            ["interface", name] => {
                if name.len() > 15 {
                    // Linux IFNAMSIZ-1: the kernel cannot have such an
                    // interface, so the line can never match anything.
                    return Err(fail(
                        line_no,
                        format!("interface name `{name}` longer than 15 characters"),
                    ));
                }
                if config.interfaces.iter().any(|i| i.name == *name) {
                    return Err(fail(line_no, format!("duplicate interface `{name}`")));
                }
                config.interfaces.push(InterfaceLine {
                    name: (*name).to_string(),
                    mode: config.mode,
                    barsav: false,
                    role: None,
                    remote_as: None,
                });
            }
            // Position-independent operator binding (the SIB's Config
            // origin): one line per prefix, at least one interface name.
            ["binding", prefix, "interface", names @ ..] => {
                let prefix: IpPrefix = prefix
                    .parse()
                    .map_err(|_| fail(line_no, format!("bad prefix `{prefix}`")))?;
                if names.is_empty() {
                    return Err(fail(line_no, "binding needs at least one interface name"));
                }
                for (i, name) in names.iter().enumerate() {
                    if name.len() > 15 {
                        // Linux IFNAMSIZ-1, the same rule as `interface`.
                        return Err(fail(
                            line_no,
                            format!("interface name `{name}` longer than 15 characters"),
                        ));
                    }
                    if names.iter().skip(i + 1).any(|other| other == name) {
                        return Err(fail(
                            line_no,
                            format!("duplicate interface name `{name}` in binding"),
                        ));
                    }
                }
                if config.bindings.iter().any(|b| b.prefix == prefix) {
                    return Err(fail(line_no, format!("duplicate binding for `{prefix}`")));
                }
                config.bindings.push(BindingLine {
                    prefix,
                    interfaces: names.iter().map(|name| (*name).to_string()).collect(),
                });
            }
            // The BAR-SAV inputs (draft-ietf-sidrops-bar-sav-10): the
            // M3 feed, the RPKI snapshot, the local AS, and §8
            // Step 7's exemptions.
            ["barsav", "feed", p] => {
                if config.barsav_feed.is_some() {
                    return Err(fail(line_no, "duplicate `barsav feed` line"));
                }
                config.barsav_feed = Some(PathBuf::from(p));
            }
            ["barsav", "vrp-file", p] => {
                if config.barsav_vrp_file.is_some() {
                    return Err(fail(line_no, "duplicate `barsav vrp-file` line"));
                }
                config.barsav_vrp_file = Some(PathBuf::from(p));
            }
            ["barsav", "local-as", asn] => {
                if config.barsav_local_as != 0 {
                    return Err(fail(line_no, "duplicate `barsav local-as` line"));
                }
                let asn: u32 = asn
                    .parse()
                    .map_err(|_| fail(line_no, format!("bad local-as `{asn}`")))?;
                config.barsav_local_as = asn;
            }
            ["barsav", "provider-exempt", prefix] => {
                let prefix: IpPrefix = prefix
                    .parse()
                    .map_err(|_| fail(line_no, format!("bad prefix `{prefix}`")))?;
                if config.barsav_provider_exempt.contains(&prefix) {
                    return Err(fail(line_no, format!("duplicate exemption `{prefix}`")));
                }
                config.barsav_provider_exempt.push(prefix);
            }
            ["action", a] => {
                if seen_action {
                    return Err(fail(line_no, "duplicate `action` line"));
                }
                match *a {
                    "monitor" => config.action = SavAction::Monitor,
                    "drop" => config.action = SavAction::Drop,
                    _ => return Err(fail(line_no, format!("bad action `{a}` (monitor|drop)"))),
                }
                seen_action = true;
            }
            ["poll", n] => {
                if seen_poll {
                    return Err(fail(line_no, "duplicate `poll` line"));
                }
                let secs: u64 = n
                    .parse()
                    .map_err(|_| fail(line_no, format!("bad poll seconds `{n}`")))?;
                if secs == 0 {
                    return Err(fail(line_no, "poll must be at least 1 second"));
                }
                config.poll_secs = secs;
                seen_poll = true;
            }
            // RFC 8704 §3.6.2 deletion-hysteresis window (A10's fixed
            // 3 s as the default).
            ["hysteresis", n] => {
                if seen_hysteresis {
                    return Err(fail(line_no, "duplicate `hysteresis` line"));
                }
                let secs: u64 = n
                    .parse()
                    .map_err(|_| fail(line_no, format!("bad hysteresis seconds `{n}`")))?;
                if secs == 0 {
                    return Err(fail(
                        line_no,
                        "hysteresis must be at least 1 second (0 would flap withdrawals)",
                    ));
                }
                config.hysteresis_secs = secs;
                seen_hysteresis = true;
            }
            // GSC §3 collision resolution (A6 landed Subtract unwired).
            ["collision-policy", p] => {
                if seen_collision_policy {
                    return Err(fail(line_no, "duplicate `collision-policy` line"));
                }
                match *p {
                    "ignore" => config.collision_policy = CollisionPolicy::Ignore,
                    "subtract" => config.collision_policy = CollisionPolicy::Subtract,
                    _ => {
                        return Err(fail(
                            line_no,
                            format!("bad collision-policy `{p}` (ignore|subtract)"),
                        ))
                    }
                }
                seen_collision_policy = true;
            }
            // Enforcement surface selection (N6): the dataplane backend
            // SAV programs install on. Default unchanged (rp_filter).
            ["backend", b] => {
                if seen_backend {
                    return Err(fail(line_no, "duplicate `backend` line"));
                }
                match *b {
                    "rp_filter" => config.backend = SavdBackend::RpFilter,
                    "nft" => config.backend = SavdBackend::Nft,
                    _ => return Err(fail(line_no, format!("bad backend `{b}` (rp_filter|nft)"))),
                }
                seen_backend = true;
            }
            ["i-understand-drop-mode", ack] => {
                if seen_drop_ack {
                    return Err(fail(line_no, "duplicate `i-understand-drop-mode` line"));
                }
                match *ack {
                    "yes" => config.drop_ack = true,
                    "no" => config.drop_ack = false,
                    _ => {
                        return Err(fail(
                            line_no,
                            format!("bad i-understand-drop-mode `{ack}` (yes|no)"),
                        ))
                    }
                }
                seen_drop_ack = true;
            }
            _ => {
                return Err(fail(
                    line_no,
                    format!(
                        "expected `mode <strict|loose|fp|efp|barsav>`, \
                         `role <customer|peer|provider>`, `remote-as <asn>`, \
                         `action <monitor|drop>`, `poll <secs>`, `hysteresis <secs>`, \
                         `collision-policy <ignore|subtract>`, \
                         `backend <rp_filter|nft>`, \
                         `i-understand-drop-mode <yes|no>`, `interface <name>`, \
                         `barsav feed|vrp-file|local-as|provider-exempt ...`, or \
                         `binding <prefix> interface <name>...`, got `{line}`"
                    ),
                ))
            }
        }
    }
    // BAR-SAV stanza completeness: `mode barsav` requires the role
    // and AS-k; the two lines on a non-barsav stanza are config
    // errors (they would silently do nothing).
    for iface in &config.interfaces {
        if iface.barsav {
            if iface.role.is_none() || iface.remote_as.is_none() {
                return Err(fail(
                    0,
                    format!(
                        "interface `{}`: mode barsav requires `role <customer|peer|provider>` \
                         and `remote-as <asn>`",
                        iface.name
                    ),
                ));
            }
        } else if iface.role.is_some() || iface.remote_as.is_some() {
            return Err(fail(
                0,
                format!(
                    "interface `{}`: `role`/`remote-as` without `mode barsav`",
                    iface.name
                ),
            ));
        }
    }
    config.validate().map_err(SavdConfigError::Validation)?;
    Ok(config)
}

/// The rendered difference between two installed programs: ops only in
/// the new program (`added`) and ops only in the old one (`removed`).
/// Both operand lists come normalized from [`SavProgram::ops`], so a
/// value-based difference is exact. [`rule_changes`] renders this same
/// difference at member granularity for the churn log.
pub fn program_diff(
    old: &[SavProgramOp],
    new: &[SavProgramOp],
) -> (Vec<SavProgramOp>, Vec<SavProgramOp>) {
    let mut added = Vec::new();
    for op in new {
        if !old.contains(op) {
            added.push(op.clone());
        }
    }
    let mut removed = Vec::new();
    for op in old {
        if !new.contains(op) {
            removed.push(op.clone());
        }
    }
    (added, removed)
}

/// One rendered difference between two installed programs at field
/// granularity (A20) — the churn log's unit. An op whose identity
/// persists between the programs (same variant, same every field but
/// its set member) renders as only the members that moved; an op with
/// no same-identity counterpart renders whole. Built exclusively from
/// [`program_diff`]'s output, so the field-level view is a finer
/// RENDERING of the same op-set difference, never a different one
/// (what the dataplane installs is untouched: the full new program).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RuleChange {
    /// An op the old program has no same-identity counterpart for (a
    /// new interface, mode, or action — operator intent, the w8
    /// reload case).
    OpAdded(SavProgramOp),
    /// An op whose identity left the new program entirely.
    OpRemoved(SavProgramOp),
    /// A persistent interface-scale op (IBA/IBB) whose prefix set
    /// changed: `added`/`removed` are exactly the prefixes that moved
    /// (one side may be empty).
    PrefixesChanged {
        /// The new op — the current truth; its identity fields render
        /// the context.
        op: SavProgramOp,
        /// Prefixes only the new set has.
        added: Vec<IpPrefix>,
        /// Prefixes only the old set had.
        removed: Vec<IpPrefix>,
    },
    /// A persistent router-scale op (PBA/PBB) whose interface set
    /// changed — the same shape as [`RuleChange::PrefixesChanged`]
    /// with interface indexes as the members.
    IfindexesChanged {
        /// The new op (the current truth).
        op: SavProgramOp,
        /// Interface indexes only the new set has.
        added: Vec<u32>,
        /// Interface indexes only the old set had.
        removed: Vec<u32>,
    },
}

impl fmt::Display for RuleChange {
    /// Operator-facing one-liner (the daemon's churn log): a member
    /// delta renders the op's context once plus only the members that
    /// moved — e.g. `allow if#2 strict monitor +[203.0.113.0/24]` —
    /// so a one-prefix change on a large allowlist is one short line,
    /// not the whole set printed twice. Whole ops render through
    /// [`SavProgramOp`]'s Display.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            RuleChange::OpAdded(op) => write!(f, "{op} added"),
            RuleChange::OpRemoved(op) => write!(f, "{op} removed"),
            RuleChange::PrefixesChanged { op, added, removed } => {
                write!(f, "{}", op_context(op))?;
                write_members(
                    f,
                    added.iter().map(|p| p.to_string()),
                    removed.iter().map(|p| p.to_string()),
                )
            }
            RuleChange::IfindexesChanged { op, added, removed } => {
                write!(f, "{}", op_context(op))?;
                write_members(
                    f,
                    added.iter().map(|i| i.to_string()),
                    removed.iter().map(|i| i.to_string()),
                )
            }
        }
    }
}

/// The field-level companion to [`program_diff`] (A20): renders the
/// same op-set difference at the granularity that compresses churn
/// logs on large sets — a prefix joining or leaving a persistent
/// allowlist names that prefix, instead of logging the whole op as
/// removed plus re-added with the full set. Every op `program_diff`
/// reports lands here exactly once (paired by identity into a member
/// delta, or whole as [`RuleChange::OpAdded`] /
/// [`RuleChange::OpRemoved`]), so this is a logging change, not an
/// install-behavior change.
pub fn rule_changes(old: &[SavProgramOp], new: &[SavProgramOp]) -> Vec<RuleChange> {
    let (added, removed) = program_diff(old, new);
    // Old ops the op-set diff reports, consumed as each pairs with a
    // new op by identity; the leftovers render whole (removed ops).
    let mut unpaired = removed;
    let mut changes = Vec::new();
    for op in added {
        let Some(index) = unpaired.iter().position(|prev| same_identity(prev, &op)) else {
            changes.push(RuleChange::OpAdded(op));
            continue;
        };
        let prev = unpaired.remove(index);
        // same_identity pairs only within a variant family, so the
        // differing field is exactly the set member; only actual
        // movement renders (an identity-paired op with identical
        // members would BE the same op, which program_diff never
        // reports — the guard keeps a future op shape from logging a
        // no-op line).
        match (&prev, &op) {
            (
                SavProgramOp::IfaceAllow {
                    prefixes: old_set, ..
                }
                | SavProgramOp::IfaceBlock {
                    prefixes: old_set, ..
                },
                SavProgramOp::IfaceAllow {
                    prefixes: new_set, ..
                }
                | SavProgramOp::IfaceBlock {
                    prefixes: new_set, ..
                },
            ) => {
                let (moved_in, moved_out) = set_delta(old_set, new_set);
                if !moved_in.is_empty() || !moved_out.is_empty() {
                    changes.push(RuleChange::PrefixesChanged {
                        op,
                        added: moved_in,
                        removed: moved_out,
                    });
                }
            }
            (
                SavProgramOp::PrefixAllow {
                    ifindexes: old_set, ..
                }
                | SavProgramOp::PrefixBlock {
                    ifindexes: old_set, ..
                },
                SavProgramOp::PrefixAllow {
                    ifindexes: new_set, ..
                }
                | SavProgramOp::PrefixBlock {
                    ifindexes: new_set, ..
                },
            ) => {
                let (moved_in, moved_out) = set_delta(old_set, new_set);
                if !moved_in.is_empty() || !moved_out.is_empty() {
                    changes.push(RuleChange::IfindexesChanged {
                        op,
                        added: moved_in,
                        removed: moved_out,
                    });
                }
            }
            // same_identity never pairs across variant families;
            // defensive — render whole rather than guess a member field.
            _ => changes.push(RuleChange::OpAdded(op)),
        }
    }
    for op in unpaired {
        changes.push(RuleChange::OpRemoved(op));
    }
    changes
}

/// Whether two ops share an identity: same variant with every field
/// except the set member equal (an `IfaceAllow` is its ifindex + uRPF
/// hint + action; the prefix set is the mutable part). An identity
/// change — different interface, mode, or action — is a new op (the
/// w8 reload case: monitor→drop renders whole ops), while a persistent
/// identity with a changed set renders as the members that moved.
fn same_identity(a: &SavProgramOp, b: &SavProgramOp) -> bool {
    match (a, b) {
        (
            SavProgramOp::IfaceAllow {
                ifindex: a_ifindex,
                urpf: a_urpf,
                action: a_action,
                ..
            },
            SavProgramOp::IfaceAllow {
                ifindex: b_ifindex,
                urpf: b_urpf,
                action: b_action,
                ..
            },
        ) => a_ifindex == b_ifindex && a_urpf == b_urpf && a_action == b_action,
        (
            SavProgramOp::IfaceBlock {
                ifindex: a_ifindex,
                action: a_action,
                ..
            },
            SavProgramOp::IfaceBlock {
                ifindex: b_ifindex,
                action: b_action,
                ..
            },
        ) => a_ifindex == b_ifindex && a_action == b_action,
        (
            SavProgramOp::PrefixAllow {
                prefix: a_prefix,
                action: a_action,
                ..
            },
            SavProgramOp::PrefixAllow {
                prefix: b_prefix,
                action: b_action,
                ..
            },
        ) => a_prefix == b_prefix && a_action == b_action,
        (
            SavProgramOp::PrefixBlock {
                prefix: a_prefix,
                action: a_action,
                ..
            },
            SavProgramOp::PrefixBlock {
                prefix: b_prefix,
                action: b_action,
                ..
            },
        ) => a_prefix == b_prefix && a_action == b_action,
        _ => false,
    }
}

/// The members that moved between two renditions of an op's set field:
/// present only in the new set, present only in the old set. Both
/// operand sets come normalized sorted from [`SavProgram::ops`], so
/// the results stay sorted.
fn set_delta<T: Copy + Eq>(old: &[T], new: &[T]) -> (Vec<T>, Vec<T>) {
    let added = new.iter().copied().filter(|m| !old.contains(m)).collect();
    let removed = old.iter().copied().filter(|m| !new.contains(m)).collect();
    (added, removed)
}

/// The op rendered without its set member — the persistent context a
/// member-delta line names, mirroring [`SavProgramOp`]'s Display shape
/// minus the bracketed set (e.g. `allow if#2 strict monitor`).
fn op_context(op: &SavProgramOp) -> String {
    match op {
        SavProgramOp::IfaceAllow {
            ifindex,
            urpf,
            action,
            ..
        } => format!("allow if#{ifindex} {urpf} {action}"),
        SavProgramOp::IfaceBlock {
            ifindex, action, ..
        } => {
            format!("block if#{ifindex} {action}")
        }
        SavProgramOp::PrefixAllow { prefix, action, .. } => {
            format!("allow {prefix} {action}")
        }
        SavProgramOp::PrefixBlock { prefix, action, .. } => {
            format!("block {prefix} {action}")
        }
    }
}

/// ` +[a, b] -[c]` for a member delta, with either side omitted when
/// empty.
fn write_members(
    f: &mut fmt::Formatter<'_>,
    added: impl Iterator<Item = String>,
    removed: impl Iterator<Item = String>,
) -> fmt::Result {
    let added: Vec<String> = added.collect();
    let removed: Vec<String> = removed.collect();
    if !added.is_empty() {
        write!(f, " +[{}]", added.join(", "))?;
    }
    if !removed.is_empty() {
        write!(f, " -[{}]", removed.join(", "))?;
    }
    Ok(())
}

/// One allowlist prefix whose deletion is being held for the hysteresis
/// window (RFC 8704 §3.6.2). The identity is the allowlist the prefix
/// belongs to — generator mode + interface + action: the deletion stays
/// deferred only while that same allowlist persists in the desired
/// view. A withdrawal that removes the whole op (mode/action config
/// change, interface gone) is an operator or link event, not a route
/// flap, and applies immediately through the normal diff.
#[derive(Debug, Clone)]
struct PendingDeletion {
    mode: UrpfMode,
    ifindex: u32,
    action: SavAction,
    prefix: IpPrefix,
    deadline: Instant,
}

impl PendingDeletion {
    /// Whether this entry defers exactly the given prefix on the given
    /// allowlist identity (the re-registration guard: an already-held
    /// deletion keeps its original deadline).
    fn is_for(&self, mode: UrpfMode, ifindex: u32, action: SavAction, prefix: IpPrefix) -> bool {
        self.mode == mode
            && self.ifindex == ifindex
            && self.action == action
            && self.prefix == prefix
    }
}

/// The desired allowlist for one (mode, ifindex, action) identity in an
/// op list, or `None` when no such op exists (the identity is gone).
fn iba_allowlist(
    ops: &[(UrpfMode, SavOp)],
    mode: UrpfMode,
    ifindex: u32,
    action: SavAction,
) -> Option<&[IpPrefix]> {
    ops.iter().find_map(|(m, op)| match op {
        SavOp::IbaPermit {
            ifindex: i,
            action: a,
            prefixes,
            ..
        } if *m == mode && *i == ifindex && *a == action => Some(&prefixes[..]),
        _ => None,
    })
}

/// Which source fed the monitor-counts log line of the last
/// [`SavDaemon::evaluate`] (dataplane-first, simulation fallback): a
/// backend that can read real per-rule counters answers
/// [`Dataplane::sav_monitor_counts`] and its numbers feed the line;
/// one that cannot (Unsupported — today's rp_filter backend has no
/// per-rule counters) falls back to the sav layer's route-lookup
/// simulation, and the line names which one spoke.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CountsSource {
    /// The backend answered `sav_monitor_counts` (kernel counters).
    Dataplane,
    /// The backend cannot answer (Unsupported) or failed to; the
    /// simulation's counters fed the line.
    Simulation,
}

impl fmt::Display for CountsSource {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            CountsSource::Dataplane => "dataplane",
            CountsSource::Simulation => "simulation",
        })
    }
}

/// The savd core: a ZAPI client (RIB view), the local mirror it feeds,
/// the spoof counter, and what is currently installed.
pub struct SavDaemon<IO> {
    client: ZapiClient<IO>,
    /// The local RIB view: protocol best routes from redistribution
    /// pushes (main table) + the interface/kernel mirrors from savd's
    /// own dataplane events.
    rib: Rib,
    monitor: SpoofMonitor,
    /// What was last handed to the dataplane (None = never evaluated).
    installed: Option<SavProgram>,
    /// The ops behind `installed`, desired ∪ deferred prefixes, with
    /// each op's generator mode (the deferral scan's before-picture).
    effective_ops: Vec<(UrpfMode, SavOp)>,
    /// Allowlist deletions being held for the hysteresis window
    /// (RFC 8704 §3.6.2), flushed by the deadline.
    pending_deletions: Vec<PendingDeletion>,
    /// The view changed since the last evaluate in a way that can alter
    /// the program (redistribute push, interface/address event) — the
    /// select loop re-evaluates on this flag instead of waiting for the
    /// poll tick. Neighbour observations never set it (counter-only).
    dirty: bool,
    config: SavdConfig,
    /// The clock the per-evaluate SIB TTL sweep reads (A22): monotonic
    /// wall time by default, injectable ([`SavDaemon::set_clock`]) so
    /// tests pause and advance it by owning the closure — the sweep is
    /// this clock's only reader. Deliberately a different clock than
    /// the hysteresis deadlines, which ride tokio's pausable runtime
    /// `Instant` for the `start_paused` deferred-delete tests.
    clock: Box<dyn Fn() -> std::time::Instant + Send>,
    /// The `(prefix, origin)` keys the last evaluate's TTL sweep
    /// removed (A22) — test-visible like `last_counts`, and empty
    /// until an origin stamps expiries (none does tonight; see the
    /// module docs' honest disclosure).
    last_swept: Vec<(IpPrefix, BindingOrigin)>,
    /// The source and numbers of the last evaluate's monitor-counts
    /// log line (dataplane-first, simulation fallback) — test-visible
    /// so the switch is asserted, not just eyeballed in logs. The
    /// pre-first-evaluate value is the simulation's zero counts.
    last_counts: (CountsSource, SavMonitorCounts),
    /// The backend's per-op counter rows when the last evaluate's
    /// per-op read answered (N6B): `Some` means the count lines render
    /// from these kernel-sourced rows (and `last_counts` is their sum,
    /// source [`CountsSource::Dataplane`]); `None` means the backend
    /// could not attribute per op and the simulation's per-op tallies
    /// render instead, exactly as before. Never evaluates leave it
    /// `None`.
    last_per_op: Option<Vec<(SavProgramOp, SavMonitorCounts)>>,
    /// The hosted SAVNET agent (experimental-savnet, default OFF and
    /// then default None): savd's own ZAPI RIB view feeds it events
    /// and every evaluate logs its suggestions — monitor-only, the
    /// log-before-drop rule. See [`crate::agent`] for the interface
    /// and its honest process-topology scoping.
    #[cfg(feature = "experimental-savnet")]
    agent: Option<crate::agent::MonitorAgent>,
    /// The suggestions the last evaluate logged (test-visible evidence
    /// of the monitor-only contract: logged, never enforced).
    #[cfg(feature = "experimental-savnet")]
    last_suggestions: Vec<crate::agent::SavBindingSuggestion>,
}

impl<IO> SavDaemon<IO>
where
    IO: AsyncRead + AsyncWrite + Unpin,
{
    /// Wraps an established ZAPI client with an empty view.
    pub fn new(client: ZapiClient<IO>) -> Self {
        Self {
            client,
            rib: Rib::new(),
            monitor: SpoofMonitor::new(&[]),
            installed: None,
            effective_ops: Vec::new(),
            pending_deletions: Vec::new(),
            dirty: false,
            config: SavdConfig::default(),
            clock: Box::new(std::time::Instant::now),
            last_swept: Vec::new(),
            last_counts: (CountsSource::Simulation, SavMonitorCounts::default()),
            last_per_op: None,
            #[cfg(feature = "experimental-savnet")]
            agent: None,
            #[cfg(feature = "experimental-savnet")]
            last_suggestions: Vec::new(),
        }
    }

    /// Host the SAVNET agent (experimental-savnet). From the next
    /// push/evaluate on: savd's own ZAPI RIB view feeds the agent
    /// route events, and every evaluate logs the agent's binding
    /// suggestions — **monitor-only**: no suggestion becomes a
    /// [`Binding`] or a rule without explicit operator config, and no
    /// landed path turns one into either (draft-dependent; see
    /// docs/protocols/savnet.md).
    #[cfg(feature = "experimental-savnet")]
    pub fn set_agent(&mut self, agent: crate::agent::MonitorAgent) {
        self.agent = Some(agent);
    }

    /// The hosted agent, if any.
    #[cfg(feature = "experimental-savnet")]
    pub fn agent(&self) -> Option<&crate::agent::MonitorAgent> {
        self.agent.as_ref()
    }

    /// The suggestions the last evaluate logged (monitor-only
    /// evidence; empty until an evaluate runs with an agent hosted).
    #[cfg(feature = "experimental-savnet")]
    pub fn last_suggestions(&self) -> &[crate::agent::SavBindingSuggestion] {
        &self.last_suggestions
    }

    /// Replace the running configuration (SIGHUP semantics; the caller
    /// re-parses and re-validates — a rejected reload never reaches
    /// here). The next evaluate feeds the new `binding` lines into the
    /// SIB's Config origin wholesale (replace semantics are per origin).
    pub fn set_config(&mut self, config: SavdConfig) {
        self.config = config;
    }

    /// The running configuration.
    pub fn config(&self) -> &SavdConfig {
        &self.config
    }

    /// The program currently installed at the dataplane.
    pub fn installed(&self) -> Option<&SavProgram> {
        self.installed.as_ref()
    }

    /// The accumulated monitor counters (the spoof counter).
    pub fn counts(&self) -> common::SavMonitorCounts {
        self.monitor.counts()
    }

    /// The source and numbers of the last evaluate's monitor-counts
    /// log line: dataplane when the backend answered
    /// `sav_monitor_counts` (directly, or via the per-op read whose
    /// rows were summed), the simulation otherwise. [`Self::counts`]
    /// keeps reporting the simulation counter either way (it is the
    /// spoof counter, not whatever the backend last said).
    pub fn last_counts(&self) -> (CountsSource, SavMonitorCounts) {
        self.last_counts
    }

    /// The backend's per-op counter rows from the last evaluate
    /// (N6B): `Some` when the backend answered
    /// [`Dataplane::sav_monitor_per_op`] — these rows feed the status
    /// `count` lines and `last_counts` is their sum; `None` when it
    /// could not (per-op lines fall back to the simulation's
    /// tallies).
    pub fn last_per_op(&self) -> Option<&[(SavProgramOp, SavMonitorCounts)]> {
        self.last_per_op.as_deref()
    }

    /// Replace the clock the per-evaluate SIB TTL sweep reads (A22).
    /// The default is the monotonic wall clock; tests inject a
    /// controlled — effectively paused — one by owning the closure.
    /// The sweep is this clock's only reader, so one evaluate reads it
    /// exactly once.
    pub fn set_clock(&mut self, clock: impl Fn() -> std::time::Instant + Send + 'static) {
        self.clock = Box::new(clock);
    }

    /// The `(prefix, origin)` keys the last evaluate's TTL sweep
    /// removed (A22) — empty until an origin stamps expiries. No
    /// landed origin does tonight (see the module docs' honest
    /// disclosure); the SAVNET agent's dynamic feed will be the first.
    pub fn last_swept(&self) -> &[(IpPrefix, BindingOrigin)] {
        &self.last_swept
    }

    /// Operator status snapshot (A21): the daemon's state as plain
    /// text — pid, running config, the installed program (the W8
    /// `installed` surface, one `rule` line per op in the same
    /// rendering the rule logs use, plus the op's provenance —
    /// " (from <origin>)" appended when the compiled op records one,
    /// A7 riding A21), and the last evaluate's monitor counts with the
    /// source that fed them. The thin binary publishes this to a
    /// run-dir status file after every evaluate (`savd --show` prints
    /// it) — the rule set without log greps, with no IPC and no wire
    /// changes.
    pub fn status_text(&self, pid: u32) -> String {
        let mut out = format!(
            "savd {} pid {pid}\nconfig {}\n",
            env!("CARGO_PKG_VERSION"),
            self.config
        );
        match &self.installed {
            None => out.push_str("installed 0 rules (never evaluated)\n"),
            Some(program) => {
                out.push_str(&format!("installed {} rules\n", program.ops().len()));
                for op in program.ops() {
                    match program_op_origin(&self.effective_ops, op) {
                        Some(origin) => {
                            out.push_str(&format!("rule {op} (from {origin})\n"));
                        }
                        None => out.push_str(&format!("rule {op}\n")),
                    }
                }
            }
        }
        let (source, counts) = self.last_counts;
        out.push_str(&format!("monitor source {source} {counts}\n"));
        // GSC §4 "count", per-rule. When the backend answered the
        // per-op read (N6B), its kernel-sourced rows render — each
        // program op paired back to the effective op it was compiled
        // from, so the line is the SAME rendering the simulation rows
        // use (provenance included). Otherwise the simulation's per-op
        // verdict tallies render, exactly as before (this can coexist
        // with a `dataplane` aggregate line only for a backend that
        // answers the aggregate but not per-op — none landed today;
        // disclosed). Only ops that have judged anything render;
        // backend rows are in canonical op order, simulation rows in
        // effective order (ifindex/prefix ascending).
        match &self.last_per_op {
            Some(rows) => {
                for (op, tallies) in rows {
                    if tallies_judged(tallies) {
                        match program_op_sav(&self.effective_ops, op) {
                            Some(sav_op) => {
                                out.push_str(&format!("count {sav_op} {tallies}\n"));
                            }
                            // Unreachable in the daemon flow (every
                            // installed op compiles from an effective
                            // one); the program op's own rendering
                            // keeps a foreign row honest, never lost.
                            None => out.push_str(&format!("count {op} {tallies}\n")),
                        }
                    }
                }
            }
            None => {
                for (op, tallies) in self.monitor.per_op() {
                    if tallies_judged(tallies) {
                        out.push_str(&format!("count {op} {tallies}\n"));
                    }
                }
            }
        }
        out
    }

    /// Whether a mirror change since the last evaluate can have
    /// altered the program (the select loop's event-driven
    /// re-evaluation trigger).
    pub fn is_dirty(&self) -> bool {
        self.dirty
    }

    /// Take the dirty flag — the select loop's pattern: check it after
    /// each handled event and evaluate immediately when set.
    pub fn take_dirty(&mut self) -> bool {
        std::mem::take(&mut self.dirty)
    }

    /// The earliest pending-deletion deadline, for the select loop's
    /// hysteresis flush timer; `None` when nothing is deferred.
    pub fn deletion_deadline(&self) -> Option<Instant> {
        self.pending_deletions.iter().map(|d| d.deadline).min()
    }

    /// HELLO + redistribute registration + the initial best-route dump,
    /// ending with the view logged. See the module docs for the sync
    /// protocol.
    pub async fn initial_sync(&mut self) -> std::io::Result<()> {
        let hello = self.client.handshake(SAVD_PROTOCOL).await?;
        info!(protocol = hello.redist_default, "savd: session established");

        for &route_type in &ROUTE_TYPES_OF_INTEREST {
            for &afi in &AFIS {
                self.client
                    .send_redistribute_add(afi, route_type, 0)
                    .await?;
            }
        }

        // Causality marker: the dummy NHT reply can only be produced
        // after every earlier registration was handled by the driver,
        // so the whole dump is queued (or written) by the time it is
        // read.
        let marker = sync_marker();
        self.client.send_nexthop_register(marker).await?;
        loop {
            match self.client.read_message().await? {
                ZapiMessage::NexthopUpdate(update) if update.registered_prefix == marker => {
                    break;
                }
                other => self.apply_push(other),
            }
        }
        // No end-of-dump marker exists in ZAPI: collect what follows
        // within a bounded quiet window. The event-driven
        // re-evaluation (and the poll tick behind it) converge on top
        // of whatever arrived, so this window is a startup-latency
        // optimization, not a correctness gate.
        while let Ok(message) = timeout(SYNC_SETTLE, self.client.read_message()).await {
            self.apply_push(message?);
        }
        // The dummy interest has served its purpose; take it back so
        // rousterd keeps no dead NHT state.
        self.client.send_nexthop_unregister(marker).await?;

        let routes = self
            .rib
            .table(MAIN_TABLE)
            .map(|t| t.iter().count())
            .unwrap_or(0);
        info!(
            routes,
            interfaces = self.rib.interfaces().len(),
            "savd: rib view synced"
        );
        Ok(())
    }

    /// Applies one incoming zebra message to the RIB view:
    /// REDISTRIBUTE_ROUTE_ADD/DEL update the protocol-route mirror and
    /// mark the view dirty (the select loop re-evaluates on the flag);
    /// everything else is logged at debug and does not dirty (the
    /// program cannot have changed).
    pub fn apply_push(&mut self, message: ZapiMessage) {
        match message {
            ZapiMessage::RedistributeRouteAdd(route) => {
                if let Some(mut entry) = route.to_route_entry() {
                    // The server lands client routes in the main table;
                    // the mirror must match (to_route_entry defaults
                    // there too; this is the same pin).
                    entry.table = MAIN_TABLE;
                    debug!(prefix = %entry.prefix, "savd: rib push add");
                    // The hosted SAVNET agent's production feed
                    // (experimental-savnet): savd's own RIB view, no
                    // peer granularity (the agent's RibView source).
                    // Monitor-only — the event is recorded/logged,
                    // nothing derives from it without explicit config.
                    #[cfg(feature = "experimental-savnet")]
                    if let Some(agent) = &self.agent {
                        let nexthop =
                            entry
                                .nexthops
                                .hops()
                                .first()
                                .and_then(|&(hop, _)| match hop {
                                    common::Nexthop::Ipv4(g) | common::Nexthop::Ipv4If(g, _) => {
                                        Some(std::net::IpAddr::V4(g))
                                    }
                                    common::Nexthop::Ipv6(g) | common::Nexthop::Ipv6If(g, _) => {
                                        Some(std::net::IpAddr::V6(g))
                                    }
                                    _ => None,
                                });
                        agent.on_event(crate::agent::SavAgentEvent::RouteInstalled {
                            source: crate::agent::SavEventSource::RibView,
                            prefix: entry.prefix,
                            nexthop,
                        });
                    }
                    self.rib.add_route(entry);
                    self.dirty = true;
                } else {
                    warn!("savd: redistribute push with unmapped type ignored");
                }
            }
            ZapiMessage::RedistributeRouteDel(route) => match route.protocol() {
                Some(protocol) => {
                    debug!(prefix = %route.prefix, "savd: rib push del");
                    #[cfg(feature = "experimental-savnet")]
                    if let Some(agent) = &self.agent {
                        agent.on_event(crate::agent::SavAgentEvent::RouteWithdrawn {
                            source: crate::agent::SavEventSource::RibView,
                            prefix: route.prefix,
                        });
                    }
                    self.rib
                        .table_mut(MAIN_TABLE)
                        .remove(&route.prefix, protocol);
                    self.dirty = true;
                }
                None => warn!("savd: redistribute del with unmapped type ignored"),
            },
            other => {
                debug!(command = other.command(), "savd: zebra push skipped");
            }
        }
    }

    /// Reads one message off the session and applies it (the resident
    /// loop's ZAPI arm). A read error is session loss, propagated.
    pub async fn read_message(&mut self) -> std::io::Result<()> {
        let message = self.client.read_message().await?;
        self.apply_push(message);
        Ok(())
    }

    /// Applies one dataplane event to the local mirror. Neighbour
    /// observations feed the spoof counter — a neighbour entry proves
    /// an address spoke on an interface, which is a real (ARP/NDP
    /// granularity, not per-packet) traffic observation of exactly the
    /// (source, ingress) shape the monitor judges. Interface/address
    /// (and kernel-route mirror) events additionally mark the view
    /// dirty: names resolve against the mirror, so the program can
    /// change with them; neighbour events never dirty it (counter-only
    /// — they are the high-frequency feed).
    pub fn apply_event(&mut self, ev: &DataplaneEvent) {
        if let DataplaneEvent::NeighbourNew { entry } = ev {
            let verdict = self.monitor.observe(entry.ip, entry.link_ifindex);
            if matches!(verdict, Verdict::Invalid) {
                info!(
                    source = %entry.ip,
                    ingress = entry.link_ifindex,
                    invalid = self.monitor.counts().invalid,
                    "savd: monitor spoof-observed (no drop in monitor mode)"
                );
            }
        }
        if !matches!(
            ev,
            DataplaneEvent::NeighbourNew { .. } | DataplaneEvent::NeighbourDel { .. }
        ) {
            self.dirty = true;
        }
        self.rib.apply_event(ev);
    }

    /// Resolve the configured interface names against the local mirror.
    /// Unknown names warn and are skipped (the interface may appear
    /// later; the poll tick re-resolves).
    fn resolved_interfaces(&self) -> Vec<(u32, UrpfMode)> {
        let mut out = Vec::new();
        for line in &self.config.interfaces {
            if line.barsav {
                continue; // the BAR-SAV partition builds below
            }
            match self
                .rib
                .interfaces()
                .iter()
                .find(|(_, iface)| iface.name == line.name)
            {
                Some((&ifindex, _)) => out.push((ifindex, line.mode)),
                None => warn!(
                    interface = %line.name,
                    "savd: configured interface not in mirror (yet); skipped"
                ),
            }
        }
        out
    }

    /// The resolved BAR-SAV stanzas: (ifindex, the whole stanza line).
    /// Same mirror resolution as [`Self::resolved_interfaces`]; a
    /// `barsav` stanza whose name is not (yet) mirrored warns and is
    /// skipped (nothing derives for it — unknown ≠ invalid).
    fn resolved_barsav(&self) -> Vec<(u32, &InterfaceLine)> {
        let mut out = Vec::new();
        for line in &self.config.interfaces {
            if !line.barsav {
                continue;
            }
            match self
                .rib
                .interfaces()
                .iter()
                .find(|(_, iface)| iface.name == line.name)
            {
                Some((&ifindex, _)) => out.push((ifindex, line)),
                None => warn!(
                    interface = %line.name,
                    "savd: barsav interface not in mirror (yet); skipped"
                ),
            }
        }
        out
    }

    /// Which interface a peer address is on-link for: the mirror's
    /// CONNECT table (every address on every UP interface as its
    /// network prefix) read through the public rib surface — the
    /// first connected prefix containing the address answers with its
    /// egress ifindex. Single-hop eBGP's shape; a multi-hop peer
    /// resolves to nothing and the feed line drops out (disclosed —
    /// iBGP and multi-hop feeds are §Deferred with the agent wire).
    fn connected_ifindex_of(&self, peer: std::net::IpAddr) -> Option<u32> {
        let table = self.rib.connected_table(MAIN_TABLE)?;
        for (prefix, candidates) in table.iter() {
            if !crate::prefix_contains(*prefix, peer) {
                continue;
            }
            for entry in candidates {
                for egress in crate::rib_egress(&self.rib, &entry.nexthops) {
                    if let Some(ifindex) = egress.ifindex() {
                        return Some(ifindex);
                    }
                }
            }
        }
        None
    }

    /// Run the BAR-SAV derivation over the configured inputs
    /// (draft-ietf-sidrops-bar-sav-10 §4/§8): bgpd's feed snapshot +
    /// the RPKI snapshot + the resolved stanzas. `Err(())` = an input
    /// file is missing or unparseable — the caller leaves every
    /// BAR-SAV interface UNJUDGED (unknown ≠ invalid: no seeded empty
    /// allowlist, no spoof counters), the fail-open posture of §7.5.1
    /// ("fail open" to loose uRPF / no enforcement on RPKI failure).
    fn barsav_derivation(
        &self,
        stanzas: &[(u32, &InterfaceLine)],
    ) -> Result<crate::barsav::BarsavDerivation, ()> {
        let Some(feed_path) = self.config.barsav_feed.clone() else {
            warn!("savd: barsav stanzas configured but no `barsav feed` path; unjudged");
            return Err(());
        };
        let feed_text = std::fs::read_to_string(&feed_path).map_err(|e| {
            warn!(error = %e, path = %feed_path.display(),
                "savd: barsav feed unreadable; interfaces unjudged (unknown != invalid)");
        })?;
        let feed = parse_barsav_feed(&feed_text).map_err(|e| {
            warn!(error = %e, path = %feed_path.display(),
                "savd: barsav feed unparseable; interfaces unjudged");
        })?;
        let (vrps, aspas) = match &self.config.barsav_vrp_file {
            Some(path) => {
                let text = std::fs::read_to_string(path).map_err(|e| {
                    warn!(error = %e, path = %path.display(),
                        "savd: barsav vrp-file unreadable; interfaces unjudged");
                })?;
                parse_rpki_snapshot(&text).map_err(|e| {
                    warn!(error = %e, path = %path.display(),
                        "savd: barsav vrp-file unparseable; interfaces unjudged");
                })?
            }
            None => (rpki::VrpTable::new(), rpki::AspaTable::new()),
        };
        // The stanza side: one BarNeighbor per resolved interface.
        let neighbors: Vec<BarNeighbor> = stanzas
            .iter()
            .map(|&(ifindex, line)| {
                BarNeighbor::new(
                    ifindex,
                    line.remote_as.expect("parser guarantees remote-as"),
                    line.role.expect("parser guarantees role"),
                )
            })
            .collect();
        // The feed side: peer address -> ifindex through the mirror's
        // connected prefixes (single-hop eBGP — the on-link case;
        // multi-hop peers do not resolve and drop out with a debug
        // line, disclosed). The stanza join then knows each path's
        // receiving interface for the §4 preamble's role-selected
        // verification.
        let mut paths = Vec::new();
        for line in &feed {
            let Some(ifindex) = self.connected_ifindex_of(line.peer) else {
                debug!(peer = %line.peer, "savd: barsav feed peer not on-link; skipped");
                continue;
            };
            paths.push(BarPath {
                prefix: line.prefix,
                as_path: line.as_path.clone(),
                has_as_set: line.has_as_set,
                ingress: ifindex,
            });
        }
        let input = BarsavInput {
            local_as: self.config.barsav_local_as,
            neighbors: &neighbors,
            paths: &paths,
            vrps: &vrps,
            aspas: &aspas,
            provider_exempt: &self.config.barsav_provider_exempt,
        };
        Ok(generate_barsav(&input))
    }

    /// Feed the configured `binding` lines into the SIB's Config origin
    /// (the W5 [`Sib::replace_origin`] surface — wholesale replace, so
    /// a config swap drops every old line): names resolve against the
    /// local mirror the same way stanza names do; a name not (yet)
    /// mirrored warns and drops out, and a line with no resolved name
    /// stores nothing rather than an empty interface set (unknown ≠
    /// invalid — the SIB's stored invariant).
    fn apply_config_bindings(&self, sib: &mut Sib) {
        let mut made = Vec::new();
        for line in &self.config.bindings {
            let mut interfaces = Vec::new();
            for name in &line.interfaces {
                match self
                    .rib
                    .interfaces()
                    .iter()
                    .find(|(_, iface)| iface.name == *name)
                {
                    Some((&ifindex, iface)) => interfaces.push(InterfaceRef::If {
                        ifindex,
                        name: Some(iface.name.clone()),
                    }),
                    None => warn!(
                        interface = %name,
                        prefix = %line.prefix,
                        "savd: binding interface not in mirror (yet); skipped"
                    ),
                }
            }
            if interfaces.is_empty() {
                warn!(
                    prefix = %line.prefix,
                    "savd: binding stored nothing (no resolved interface; unknown != invalid)"
                );
                continue;
            }
            made.push(Binding {
                prefix: line.prefix,
                interfaces,
                origin: BindingOrigin::Config,
                // Operator-pinned: no expiry (the SIB would reject one —
                // `SavError::PinnedExpiry`).
                expires_at: None,
            });
        }
        // Every binding above names at least one concrete interface, so
        // this cannot reject; the warn documents the invariant.
        if let Err(err) = sib.replace_origin(BindingOrigin::Config, made) {
            warn!(%err, "savd: config bindings rejected by the SIB");
        }
    }

    /// Build the current view from the mirror: SIB from the RIB mirror
    /// plus the configured `binding` lines (Config origin, shadowing
    /// Rib per prefix), one bounded TTL sweep (A22), one generator
    /// partition per configured mode, compiled and tagged with the
    /// producing mode (so each op's uRPF hint matches it, and the
    /// hysteresis pass can group ops by identity).
    fn build_ops(&mut self) -> Vec<(UrpfMode, SavOp)> {
        let mut sib = Sib::from_rib(&self.rib);
        self.apply_config_bindings(&mut sib);
        // One bounded TTL sweep per evaluate (A22), on the injected
        // clock: expired bindings leave the SIB BEFORE rule generation,
        // so the program never asserts one. A swept prefix then drops
        // out of its allowlist through the normal diff — riding the
        // same RFC 8704 §3.6.2 deletion hysteresis as any withdrawal.
        let swept = sib.sweep((self.clock)());
        for (prefix, origin) in &swept {
            info!(
                prefix = %prefix,
                origin = %origin,
                "savd: expired SIB binding swept (TTL; uninstall rides the deletion hysteresis)"
            );
        }
        self.last_swept = swept;
        let mut partitions: Vec<(UrpfMode, SavConfig)> = Vec::new();
        for (ifindex, mode) in self.resolved_interfaces() {
            if let Some((_, cfg)) = partitions.iter_mut().find(|(m, _)| *m == mode) {
                cfg.enable_interface(ifindex, ValidationMode::Iba, self.config.action);
            } else {
                let mut cfg = SavConfig::new();
                cfg.enable_interface(ifindex, ValidationMode::Iba, self.config.action);
                partitions.push((mode, cfg));
            }
        }
        let mut ops: Vec<(UrpfMode, SavOp)> = Vec::new();
        for (mode, cfg) in &partitions {
            let rules = generate_urpf(*mode, &sib, &self.rib, cfg);
            for op in compile_with(&rules, cfg, self.config.collision_policy) {
                ops.push((*mode, op));
            }
        }
        // The BAR-SAV partition (draft-ietf-sidrops-bar-sav-10 §4/§8,
        // S9-a M2/M3): the derivation runs over bgpd's read-only feed
        // + the RPKI snapshot, its typed IBA rules compile through the
        // SAME table manager (provenance bar-sav riding the ops), the
        // action is the config's — Monitor unless the operator's
        // `action drop` + friction line said otherwise (the house
        // rule). The ops tag Loose: the program hint a content-blind
        // rp_filter backend approximates with (route-existence —
        // disclosed; the nft backend enforces the allowlist CONTENT)
        // and the hysteresis identity (mode, ifindex, action — the
        // ifindex keeps BAR-SAV and uRPF-loose identities apart).
        // An input file that is missing or unparseable derives
        // NOTHING and enables nothing: every BAR-SAV interface stays
        // unjudged (unknown ≠ invalid — the §7.5.1 fail-open
        // posture), never a seeded deny-all.
        let stanzas = self.resolved_barsav();
        if !stanzas.is_empty() {
            if let Ok(derivation) = self.barsav_derivation(&stanzas) {
                for result in &derivation.results {
                    match result {
                        crate::barsav::IfaceResult::Customer(c) => info!(
                            ifindex = c.ifindex,
                            role = %c.role,
                            cone = c.cone.len(),
                            prefixes = c.allowlist.len(),
                            "savd: barsav allowlist derived (bar-sav -10 §4)"
                        ),
                        crate::barsav::IfaceResult::Provider(p) => info!(
                            ifindex = p.ifindex,
                            du = p.du.len(),
                            subtracted = p.s.len(),
                            prefixes = p.allowlist.len(),
                            "savd: barsav provider allowlist derived (bar-sav -10 §8)"
                        ),
                    }
                }
                if derivation.paths_excluded > 0 {
                    debug!(
                        excluded = derivation.paths_excluded,
                        "savd: barsav paths excluded by the §4 preamble (ROV/ASPA/as-set)"
                    );
                }
                let rules = derivation.rules();
                let mut cfg = SavConfig::new();
                for (ifindex, _) in &stanzas {
                    cfg.enable_interface(*ifindex, ValidationMode::Iba, self.config.action);
                }
                for op in compile_with(&rules, &cfg, self.config.collision_policy) {
                    ops.push((UrpfMode::Loose, op));
                }
            }
        }
        ops
    }

    /// Re-evaluate the view and converge the dataplane onto it:
    /// regenerate rules, log the startup rule set or the diff at info,
    /// install through the trait when the program changed, and log the
    /// monitor counts — dataplane-first: a backend that answers
    /// [`Dataplane::sav_monitor_counts`] feeds the line, anything else
    /// falls back to the simulation's counts, and the line names the
    /// source. An identical regeneration installs nothing
    /// (the churn guard W7 deferred at the backend, applied here).
    /// This call covers every mirror change since the last evaluate
    /// (it consumes the dirty flag); the poll tick and the select
    /// loop's event-driven path both land here.
    ///
    /// Allowlist deletions ride the RFC 8704 §3.6.2 hysteresis window
    /// ([`DEFERRED_DELETE_DELAY`]): a prefix leaving a still-present
    /// allowlist stays enforced until its deadline (a re-advertisement
    /// inside the window is absorbed with zero dataplane churn), while
    /// additions and whole-op removals (mode/action/interface changes)
    /// apply immediately.
    pub async fn evaluate<D: Dataplane>(&mut self, dp: &D) -> std::io::Result<()> {
        self.dirty = false;
        let desired = self.build_ops();

        // Reconcile the pending set against the fresh view: absorbed
        // (the prefix came back — the transient never happened), dropped
        // (the allowlist identity is gone — the removal applies now
        // through the normal diff, no flap to absorb), or still held.
        self.pending_deletions.retain(|d| {
            match iba_allowlist(&desired, d.mode, d.ifindex, d.action) {
                None => false,
                Some(held) => {
                    if held.contains(&d.prefix) {
                        info!(
                            ifindex = d.ifindex,
                            prefix = %d.prefix,
                            "savd: withdrawal reversed inside the hysteresis window (prefix retained)"
                        );
                        false
                    } else {
                        true
                    }
                }
            }
        });

        // Newly withdrawn prefixes on still-present allowlists enter the
        // pending set (an already-held deletion keeps its deadline — the
        // window must not stretch on every re-evaluation). Registration
        // runs BEFORE the expiry pass: an entry registered now carries
        // now+DELAY and cannot expire in the same call, while a
        // previously-held entry is skipped here (still in the set) and
        // expires below without being re-registered — effective_ops has
        // not caught up with the flush yet.
        let now = Instant::now();
        for (mode, op) in &self.effective_ops {
            let SavOp::IbaPermit {
                ifindex,
                action,
                prefixes,
                ..
            } = op
            else {
                continue;
            };
            let Some(desired_prefixes) = iba_allowlist(&desired, *mode, *ifindex, *action) else {
                continue;
            };
            for prefix in prefixes {
                if desired_prefixes.contains(prefix) {
                    continue;
                }
                if self
                    .pending_deletions
                    .iter()
                    .any(|d| d.is_for(*mode, *ifindex, *action, *prefix))
                {
                    continue;
                }
                self.pending_deletions.push(PendingDeletion {
                    mode: *mode,
                    ifindex: *ifindex,
                    action: *action,
                    prefix: *prefix,
                    deadline: now + self.config.hysteresis_delay(),
                });
                info!(
                    ifindex = *ifindex,
                    prefix = %prefix,
                    "savd: rule prefix deletion deferred (RFC 8704 §3.6.2 hysteresis)"
                );
            }
        }

        // Expired deferrals leave now: their prefixes drop out of the
        // effective set below and uninstall through the normal diff.
        self.pending_deletions.retain(|d| {
            if d.deadline <= now {
                info!(
                    ifindex = d.ifindex,
                    prefix = %d.prefix,
                    "savd: deferred deletion applied (hysteresis window elapsed)"
                );
                false
            } else {
                true
            }
        });

        // Effective = desired ∪ held prefixes: the dataplane (and the
        // spoof monitor below) keep enforcing through the window.
        let mut effective = desired.clone();
        for d in &self.pending_deletions {
            for (mode, op) in effective.iter_mut() {
                if *mode != d.mode {
                    continue;
                }
                if let SavOp::IbaPermit {
                    ifindex,
                    action,
                    prefixes,
                    ..
                } = op
                {
                    if *ifindex == d.ifindex && *action == d.action && !prefixes.contains(&d.prefix)
                    {
                        prefixes.push(d.prefix);
                        prefixes.sort();
                        prefixes.dedup();
                    }
                }
            }
        }
        self.effective_ops = effective.clone();
        self.monitor.set_ops(
            &effective
                .iter()
                .map(|(_, op)| op.clone())
                .collect::<Vec<_>>(),
        );

        let target = SavProgram::from_ops(
            effective
                .iter()
                .flat_map(|(mode, op)| program(std::slice::from_ref(op), *mode).ops().to_vec()),
        );

        match &self.installed {
            None => {
                for op in target.ops() {
                    info!(rule = %op, "savd: rule");
                }
                info!(
                    ops = target.ops().len(),
                    %self.config,
                    "savd: rule set installed (monitor action logs, drop action enforces)"
                );
                self.install(dp, &target).await?;
            }
            Some(prev) if *prev != target => {
                // Field-granular churn log (A20): ops whose identity
                // persists render only the members that moved — one
                // short line per changed allowlist instead of the whole
                // set twice — while genuinely new and removed ops keep
                // their whole-op lines. Rendering only: the install
                // below still swaps the entire program.
                let changes = rule_changes(prev.ops(), target.ops());
                for change in &changes {
                    match change {
                        RuleChange::OpAdded(op) => info!(rule = %op, "savd: rule added"),
                        RuleChange::OpRemoved(op) => info!(rule = %op, "savd: rule removed"),
                        RuleChange::PrefixesChanged { .. } => {
                            info!(change = %change, "savd: rule prefixes changed");
                        }
                        RuleChange::IfindexesChanged { .. } => {
                            info!(change = %change, "savd: rule ifindexes changed");
                        }
                    }
                }
                let ops_added = changes
                    .iter()
                    .filter(|c| matches!(c, RuleChange::OpAdded(_)))
                    .count();
                let ops_removed = changes
                    .iter()
                    .filter(|c| matches!(c, RuleChange::OpRemoved(_)))
                    .count();
                let prefixes_moved = changes
                    .iter()
                    .map(|c| match c {
                        RuleChange::PrefixesChanged { added, removed, .. } => {
                            added.len() + removed.len()
                        }
                        _ => 0,
                    })
                    .sum::<usize>();
                let ifindexes_moved = changes
                    .iter()
                    .map(|c| match c {
                        RuleChange::IfindexesChanged { added, removed, .. } => {
                            added.len() + removed.len()
                        }
                        _ => 0,
                    })
                    .sum::<usize>();
                info!(
                    ops_added,
                    ops_removed,
                    prefixes_moved,
                    ifindexes_moved,
                    deferred = self.pending_deletions.len(),
                    %self.config,
                    "savd: rule set changed"
                );
                self.install(dp, &target).await?;
            }
            _ => debug!("savd: rule set unchanged; nothing installed"),
        }

        // Dataplane-first monitor counts (A18), per-op first (N6B): a
        // backend that can attribute its counters per op answers
        // `sav_monitor_per_op` and its rows ARE the monitor view — the
        // aggregate line renders their sum (the rows sum to the
        // aggregate by construction) and the status `count` lines ride
        // the same kernel-sourced rows. A backend that cannot
        // (Unsupported — today's rp_filter backend: a strict/loose
        // value drops, it does not count) falls back to the aggregate
        // read, then to the simulation's counts; failed reads fall
        // back the same way rather than failing the evaluate
        // (diagnostics never take enforcement down), and the line
        // names which source fed it.
        let (source, counts, per_op) = match dp.sav_monitor_per_op().await {
            Ok(rows) => {
                let total = rows
                    .iter()
                    .fold(SavMonitorCounts::default(), |mut acc, (_, c)| {
                        acc.invalid += c.invalid;
                        acc.valid += c.valid;
                        acc.unknown += c.unknown;
                        acc
                    });
                (CountsSource::Dataplane, total, Some(rows))
            }
            Err(DataplaneError::Unsupported(reason)) => {
                debug!(
                    reason,
                    "savd: backend has no per-op monitor counters; trying the aggregate read"
                );
                let (source, counts) = match dp.sav_monitor_counts().await {
                    Ok(counts) => (CountsSource::Dataplane, counts),
                    Err(DataplaneError::Unsupported(reason)) => {
                        debug!(
                            reason,
                            "savd: backend has no monitor counters; simulation feeds the line"
                        );
                        (CountsSource::Simulation, self.monitor.counts())
                    }
                    Err(err) => {
                        warn!(error = %err, "savd: backend monitor-count read failed; simulation feeds the line");
                        (CountsSource::Simulation, self.monitor.counts())
                    }
                };
                (source, counts, None)
            }
            Err(err) => {
                warn!(error = %err, "savd: backend per-op monitor-count read failed; trying the aggregate read");
                let (source, counts) = match dp.sav_monitor_counts().await {
                    Ok(counts) => (CountsSource::Dataplane, counts),
                    Err(_) => (CountsSource::Simulation, self.monitor.counts()),
                };
                (source, counts, None)
            }
        };
        self.last_counts = (source, counts);
        self.last_per_op = per_op;
        info!(
            source = %source,
            invalid = counts.invalid,
            valid = counts.valid,
            unknown = counts.unknown,
            "savd: monitor counts (invalid = spoof counter)"
        );
        // Per-rule verdict tallies (GSC §4 "count"), the periodic debug
        // line: one per op that has judged anything — kernel-sourced
        // when the per-op read answered, the simulation's tallies
        // otherwise (the same rows `status_text` renders either way).
        match &self.last_per_op {
            Some(rows) => {
                for (op, tallies) in rows {
                    if tallies_judged(tallies) {
                        debug!(
                            rule = %op,
                            invalid = tallies.invalid,
                            valid = tallies.valid,
                            unknown = tallies.unknown,
                            "savd: per-rule monitor tallies (GSC §4 count; kernel counters)"
                        );
                    }
                }
            }
            None => {
                for (op, tallies) in self.monitor.per_op() {
                    if tallies_judged(tallies) {
                        debug!(
                            rule = %op,
                            invalid = tallies.invalid,
                            valid = tallies.valid,
                            unknown = tallies.unknown,
                            "savd: per-rule monitor tallies (GSC §4 count; simulation)"
                        );
                    }
                }
            }
        }

        // The hosted SAVNET agent's suggestions (experimental-savnet):
        // every suggestion logs, NOTHING enforces — the log-before-drop
        // rule. No suggestion becomes a Binding or a rule tonight; the
        // enforcement path is deliberately unwired until the drafts
        // stabilize and the owner decides the confirmation protocol
        // (docs/protocols/savnet.md).
        #[cfg(feature = "experimental-savnet")]
        {
            let suggestions = self
                .agent
                .as_ref()
                .map(|agent| agent.binding_suggestions())
                .unwrap_or_default();
            for suggestion in &suggestions {
                info!(
                    suggestion = %suggestion,
                    "savd: savnet agent suggestion (monitor-only, not enforced)"
                );
            }
            self.last_suggestions = suggestions;
        }
        Ok(())
    }

    async fn install<D: Dataplane>(&mut self, dp: &D, program: &SavProgram) -> std::io::Result<()> {
        dp.sav_install(program).await.map_err(dp_err)?;
        self.installed = Some(program.clone());
        Ok(())
    }

    /// Remove everything this daemon installed (SIGTERM/SIGINT path —
    /// leave the kernel clean).
    pub async fn clear<D: Dataplane>(&self, dp: &D) -> std::io::Result<()> {
        dp.sav_clear().await.map_err(dp_err)?;
        info!("savd: installed rules cleared");
        Ok(())
    }
}

fn dp_err(err: DataplaneError) -> std::io::Error {
    std::io::Error::other(err.to_string())
}

/// Whether a per-op tally row has judged anything (the status/log
/// render filter: zero rows are noise).
fn tallies_judged(tallies: &SavMonitorCounts) -> bool {
    tallies.invalid + tallies.valid + tallies.unknown > 0
}

/// The effective [`SavOp`] one installed program op was compiled
/// from, found by re-deriving each effective op's program form and
/// matching it against the installed one — identity-exact (every
/// field the program op holds, action and uRPF hint included). `None`
/// when no effective op matches. The pairing behind the `rule` lines'
/// provenance suffix and the backend-sourced `count` lines' rendering
/// (they render the effective op so the line shape is the same
/// whichever source fed the numbers).
fn program_op_sav<'a>(effective: &'a [(UrpfMode, SavOp)], op: &SavProgramOp) -> Option<&'a SavOp> {
    for (mode, sav_op) in effective {
        if program(std::slice::from_ref(sav_op), *mode).ops().first() == Some(op) {
            return Some(sav_op);
        }
    }
    None
}

/// The provenance of one installed program op (A7 riding A21): the
/// origin the effective [`SavOp`] it was compiled from carries.
/// `None` when no effective op matches or the op recorded no origin:
/// an origin-less or disagreeing merge never guesses a source (B5
/// observation 5).
fn program_op_origin(effective: &[(UrpfMode, SavOp)], op: &SavProgramOp) -> Option<RuleOrigin> {
    program_op_sav(effective, op).and_then(|sav_op| sav_op.origin())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::future::Future;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex};

    use common::{
        NeighbourEntry, Nexthop, NexthopGroup, RouteEntry, RouteProtocol, SavEnforce, SavUrpf,
    };
    use zapi::{ZapiHeader, ZapiNexthop, ZapiNexthopUpdate, ZapiRoute, ZAPI_HEADER_LEN};

    // ---- config parser ----

    fn cfg(input: &str) -> SavdConfig {
        parse_savd_config(input).unwrap()
    }

    #[test]
    fn parses_the_full_grammar() {
        let config = cfg("! monitor by default until acknowledged\n \
             mode strict\n\
             poll 2\n\
             hysteresis 10\n\
             collision-policy subtract\n \
             interface vethlegit\n \
             mode loose\n \
             interface vethspoof\n\
             binding 203.0.113.0/24 interface vethlegit vethspoof\n\
             binding 2001:db8::/64 interface vethlegit\n\
             # strict inherited from the global mode\n\
             ");
        assert_eq!(config.mode, UrpfMode::Strict);
        assert_eq!(config.action, SavAction::Monitor);
        assert_eq!(config.poll_secs, 2);
        assert_eq!(
            config.hysteresis_secs, 10,
            "the RFC 8704 §3.6.2 window knob"
        );
        assert_eq!(
            config.collision_policy,
            CollisionPolicy::Subtract,
            "the GSC §3 merge-by-subtraction knob (A6's unwired mode)"
        );
        assert!(!config.drop_ack);
        assert_eq!(
            config.interfaces,
            vec![
                InterfaceLine {
                    name: "vethlegit".into(),
                    mode: UrpfMode::Loose,
                    barsav: false,
                    role: None,
                    remote_as: None,
                },
                InterfaceLine {
                    name: "vethspoof".into(),
                    mode: UrpfMode::Strict,
                    barsav: false,
                    role: None,
                    remote_as: None,
                },
            ]
        );
        assert_eq!(
            config.bindings,
            vec![
                BindingLine {
                    prefix: "203.0.113.0/24".parse().unwrap(),
                    interfaces: vec!["vethlegit".into(), "vethspoof".into()],
                },
                BindingLine {
                    prefix: "2001:db8::/64".parse().unwrap(),
                    interfaces: vec!["vethlegit".into()],
                },
            ],
            "binding is position-independent (parsed inside the stanzas, global)"
        );
        assert_eq!(config.poll_interval(), Duration::from_secs(2));
    }

    #[test]
    fn empty_config_is_monitor_strict_with_default_poll() {
        let config = cfg("");
        assert_eq!(config, SavdConfig::default());
        assert_eq!(config.mode, UrpfMode::Strict);
        assert_eq!(config.action, SavAction::Monitor, "monitor default");
        assert_eq!(config.poll_secs, DEFAULT_POLL_SECS);
        assert!(config.validate().is_ok(), "monitor needs no friction");
    }

    #[test]
    fn per_interface_mode_overrides_and_global_is_the_default() {
        let config = cfg("mode fp\ninterface a\nmode efp\ninterface b\nmode efp\n");
        assert_eq!(config.mode, UrpfMode::Fp);
        assert_eq!(config.interfaces[0].mode, UrpfMode::Efp);
        assert_eq!(config.interfaces[1].mode, UrpfMode::Efp);
        // A stanza opened AFTER the global line inherits the global.
        let config = cfg("mode loose\ninterface c\n");
        assert_eq!(config.interfaces[0].mode, UrpfMode::Loose);
        // A stanza opened BEFORE any global line inherits the built-in
        // default (strict).
        let config = cfg("interface d\n");
        assert_eq!(config.interfaces[0].mode, UrpfMode::Strict);
    }

    #[test]
    fn rejects_bad_lines_with_line_numbers() {
        let cases = [
            ("mode bogus", "bad mode"),
            ("action block", "bad action"),
            ("poll 0", "zero poll"),
            ("poll x", "non-numeric poll"),
            ("interface", "missing name"),
            ("interface a b", "extra token"),
            ("interface muchtoolonginterface", "over-IFNAMSIZ name"),
            ("interface a\ninterface a", "duplicate interface"),
            ("mode strict\nmode loose", "duplicate global mode"),
            ("action monitor\naction drop", "duplicate action"),
            ("poll 1\npoll 2", "duplicate poll"),
            (
                "i-understand-drop-mode yes\ni-understand-drop-mode no",
                "duplicate ack",
            ),
            ("i-understand-drop-mode maybe", "bad ack value"),
            ("hysteresis 0", "zero hysteresis"),
            ("hysteresis x", "non-numeric hysteresis"),
            ("hysteresis 1\nhysteresis 2", "duplicate hysteresis"),
            ("collision-policy merge", "bad collision policy"),
            (
                "collision-policy ignore\ncollision-policy subtract",
                "duplicate collision policy",
            ),
            ("binding", "bare binding"),
            (
                "binding 10.0.0.0/8 eth2",
                "binding without the interface keyword",
            ),
            ("binding 10.0.0.0/8 interface", "binding with no names"),
            ("binding bogus interface eth2", "bad prefix"),
            (
                "binding 10.0.0.0/8 interface muchtoolonginterface",
                "over-IFNAMSIZ binding name",
            ),
            (
                "binding 10.0.0.0/8 interface a a",
                "duplicate name in one binding",
            ),
            (
                "binding 10.0.0.0/8 interface a\nbinding 10.0.0.0/8 interface b",
                "duplicate binding prefix",
            ),
            ("wat", "unknown directive"),
        ];
        for (input, why) in cases {
            assert!(parse_savd_config(input).is_err(), "{why}: {input:?}");
        }
        // The line number is carried.
        match parse_savd_config("mode strict\n\nbogus") {
            Err(SavdConfigError::Line { line, .. }) => assert_eq!(line, 3),
            other => panic!("expected line error, got {other:?}"),
        }
    }

    #[test]
    fn drop_mode_requires_the_friction_line() {
        // Refusal without it, at parse time...
        let err = parse_savd_config("action drop\n").unwrap_err();
        assert!(
            err.to_string().contains("i-understand-drop-mode"),
            "refusal names the friction line: {err}"
        );
        // ...and against an already-built config (the reload path).
        let config = SavdConfig {
            action: SavAction::Drop,
            ..SavdConfig::default()
        };
        assert!(config.validate().is_err());

        // With it, drop parses and validates.
        let config = cfg("action drop\ni-understand-drop-mode yes\n");
        assert!(config.action.is_drop());
        assert!(config.validate().is_ok());
        // A friction line without drop mode is harmless.
        assert!(cfg("i-understand-drop-mode yes\n").validate().is_ok());
    }

    /// KNOBS, default equivalence (the w8 smoke must stay green
    /// unmodified): absent knobs, and knobs explicitly set to today's
    /// values, parse to byte-identical configs — A10's fixed 3 s window
    /// and A6's unwired Ignore policy are exactly the defaults.
    #[test]
    fn knob_defaults_preserve_todays_behavior() {
        let absent = cfg("");
        let explicit = cfg("hysteresis 3\ncollision-policy ignore\nbackend rp_filter\n");
        assert_eq!(absent, SavdConfig::default());
        assert_eq!(
            explicit, absent,
            "explicit today-values parse to the same config as no knobs at all"
        );
        assert_eq!(absent.hysteresis_secs, DEFAULT_HYSTERESIS_SECS);
        assert_eq!(absent.hysteresis_delay(), DEFERRED_DELETE_DELAY);
        assert_eq!(absent.collision_policy, CollisionPolicy::Ignore);
        assert_eq!(absent.backend, SavdBackend::RpFilter, "default unchanged");
        // The Display (status/config log lines) appends the knobs after
        // the existing fields — additive, never reordered.
        assert_eq!(
            explicit.to_string(),
            format!(
                "mode strict-uRPF action monitor poll {DEFAULT_POLL_SECS}s interfaces 0 \
                 bindings 0 collision ignore hysteresis {DEFAULT_HYSTERESIS_SECS}s \
                 backend rp_filter"
            )
        );
    }

    /// KNOB, backend: `backend nft` selects the nftables enforcement
    /// surface; duplicates and unknown values refuse (A11's grammar
    /// discipline), and the Display carries the selection.
    #[test]
    fn backend_knob_selects_the_nft_surface() {
        let config = cfg("backend nft\n");
        assert_eq!(config.backend, SavdBackend::Nft);
        assert_eq!(config.backend.to_string(), "nft");
        assert!(config.to_string().ends_with("backend nft"));

        assert_eq!(
            parse_savd_config("backend nft\nbackend rp_filter\n")
                .unwrap_err()
                .to_string(),
            "line 2: duplicate `backend` line"
        );
        let err = parse_savd_config("backend iptables\n")
            .unwrap_err()
            .to_string();
        assert!(
            err.contains("bad backend `iptables` (rp_filter|nft)"),
            "{err}"
        );
    }

    /// KNOB WIRING, hysteresis: `hysteresis <secs>` reaches the
    /// pending-deletion deadline — with a 60 s window a withdrawal is
    /// still enforced well past the old fixed 3 s, and flushes only at
    /// the configured deadline (paused clock).
    #[tokio::test(start_paused = true)]
    async fn hysteresis_knob_reaches_the_deletion_deadline() {
        let (client_io, server) =
            spawn_fake_zebra(vec![ZapiMessage::RedistributeRouteAdd(dumped_route())]);
        let mut daemon = daemon_with_interfaces(client_io);
        let mut config = daemon.config().clone();
        config.hysteresis_secs = 60;
        daemon.set_config(config);
        daemon.initial_sync().await.unwrap();
        let dp = MockSavDp::default();
        daemon.evaluate(&dp).await.unwrap();

        daemon.apply_push(ZapiMessage::RedistributeRouteDel(route_del()));
        daemon.take_dirty();
        daemon.evaluate(&dp).await.unwrap();
        assert_eq!(
            daemon.installed().unwrap().ops(),
            &[
                monitor_allow(2, &["198.51.100.0/24"]),
                monitor_allow(3, &[])
            ],
            "held inside the configured window"
        );

        // Past the OLD fixed 3 s window the prefix is still enforced:
        // the knob, not the constant, owns the deadline.
        tokio::time::advance(DEFERRED_DELETE_DELAY + Duration::from_secs(10)).await;
        daemon.evaluate(&dp).await.unwrap();
        assert_eq!(dp.installed.lock().unwrap().len(), 1, "still held");

        // The configured 60 s elapse: the deletion finally applies.
        tokio::time::advance(Duration::from_secs(47)).await;
        daemon.evaluate(&dp).await.unwrap();
        assert_eq!(
            daemon.installed().unwrap().ops(),
            &[monitor_allow(2, &[]), monitor_allow(3, &[])]
        );
        assert!(daemon.deletion_deadline().is_none());
        drop(daemon);
        let _ = server.await;
    }

    /// KNOB WIRING, collision policy: `collision-policy subtract` is
    /// handed to compile_with, but the uRPF generators emit only IBA
    /// rules — GSC §3 collisions need IBB/PBB rules — so both policies
    /// compile today's rule sets byte-identically (the w8 program shape
    /// is policy-invariant until an IBB/PBB source lands).
    #[tokio::test]
    async fn collision_policy_knob_leaves_urpf_programs_identical() {
        let (client_io, server) =
            spawn_fake_zebra(vec![ZapiMessage::RedistributeRouteAdd(dumped_route())]);
        let mut daemon = daemon_with_interfaces(client_io);
        daemon.initial_sync().await.unwrap();
        let dp = MockSavDp::default();
        daemon.evaluate(&dp).await.unwrap();
        let ignore_program = daemon.installed().unwrap().clone();

        let mut config = daemon.config().clone();
        config.collision_policy = CollisionPolicy::Subtract;
        daemon.set_config(config);
        daemon.evaluate(&dp).await.unwrap();
        assert_eq!(
            daemon.installed().unwrap(),
            &ignore_program,
            "no IBB/PBB rule source exists: Subtract cannot perturb the program"
        );
        drop(daemon);
        let _ = server.await;
    }

    // ---- program diff ----

    fn allow(ifindex: u32, prefixes: &[&str], action: SavEnforce) -> SavProgramOp {
        SavProgramOp::IfaceAllow {
            ifindex,
            prefixes: prefixes.iter().map(|p| p.parse().unwrap()).collect(),
            urpf: SavUrpf::Strict,
            action,
        }
    }

    #[test]
    fn diff_reports_added_and_removed_ops_only() {
        let old = [allow(2, &["198.51.100.0/24"], SavEnforce::Monitor)];
        let new = [
            allow(2, &[], SavEnforce::Monitor),
            allow(3, &["198.51.100.0/24"], SavEnforce::Monitor),
        ];
        let (added, removed) = program_diff(&old, &new);
        assert_eq!(
            added,
            vec![
                allow(2, &[], SavEnforce::Monitor),
                allow(3, &["198.51.100.0/24"], SavEnforce::Monitor),
            ]
        );
        assert_eq!(
            removed,
            vec![allow(2, &["198.51.100.0/24"], SavEnforce::Monitor)]
        );

        // Identity: no change, no diff.
        let (added, removed) = program_diff(&old, &old);
        assert!(added.is_empty() && removed.is_empty());
    }

    #[test]
    fn field_diff_names_moved_prefixes_on_a_persistent_allowlist() {
        // The churn case A20 compresses: prefixes join and leave an
        // allowlist whose identity (ifindex + uRPF hint + action)
        // persists. The field-level diff names exactly the prefixes
        // that moved; program_diff's op-set semantics are untouched
        // (it still reports both whole ops).
        let old = [allow(
            2,
            &["198.51.100.0/24", "203.0.113.0/24"],
            SavEnforce::Monitor,
        )];
        let new = [allow(
            2,
            &["192.0.2.0/24", "203.0.113.0/24"],
            SavEnforce::Monitor,
        )];
        let changes = rule_changes(&old, &new);
        assert_eq!(
            changes,
            vec![RuleChange::PrefixesChanged {
                op: allow(2, &["192.0.2.0/24", "203.0.113.0/24"], SavEnforce::Monitor),
                added: vec!["192.0.2.0/24".parse().unwrap()],
                removed: vec!["198.51.100.0/24".parse().unwrap()],
            }],
            "one delta for the persistent allowlist, naming the moved prefixes"
        );
        assert_eq!(
            changes[0].to_string(),
            "allow if#2 strict monitor +[192.0.2.0/24] -[198.51.100.0/24]",
            "context once, then only the members that moved"
        );

        // One-sided renderings omit the empty side.
        let grown = rule_changes(
            &[allow(2, &["198.51.100.0/24"], SavEnforce::Monitor)],
            &[allow(
                2,
                &["198.51.100.0/24", "203.0.113.0/24"],
                SavEnforce::Monitor,
            )],
        );
        assert_eq!(
            grown[0].to_string(),
            "allow if#2 strict monitor +[203.0.113.0/24]"
        );
        let shrunk = rule_changes(
            &[allow(2, &["198.51.100.0/24"], SavEnforce::Monitor)],
            &[allow(2, &[], SavEnforce::Monitor)],
        );
        assert_eq!(
            shrunk[0].to_string(),
            "allow if#2 strict monitor -[198.51.100.0/24]"
        );

        // Op-set semantics intact: the same inputs still diff as whole
        // ops at the program_diff level.
        let (added, removed) = program_diff(&old, &new);
        assert_eq!(added, vec![new[0].clone()]);
        assert_eq!(removed, vec![old[0].clone()]);
    }

    #[test]
    fn field_diff_keeps_whole_ops_for_new_and_removed_identities() {
        // Genuinely new op (a new interface's allowlist), removed op
        // (the interface left the program), and an action swap — a NEW
        // identity, operator intent (the w8 reload case), not a member
        // move — all render whole, exactly program_diff's op sets.
        let old = [
            allow(2, &["198.51.100.0/24"], SavEnforce::Monitor),
            allow(3, &["192.0.2.0/24"], SavEnforce::Monitor),
        ];
        let new = [
            allow(2, &["198.51.100.0/24"], SavEnforce::Drop),
            allow(4, &["203.0.113.0/24"], SavEnforce::Monitor),
        ];
        assert_eq!(
            rule_changes(&old, &new),
            vec![
                RuleChange::OpAdded(allow(2, &["198.51.100.0/24"], SavEnforce::Drop)),
                RuleChange::OpAdded(allow(4, &["203.0.113.0/24"], SavEnforce::Monitor)),
                RuleChange::OpRemoved(allow(2, &["198.51.100.0/24"], SavEnforce::Monitor)),
                RuleChange::OpRemoved(allow(3, &["192.0.2.0/24"], SavEnforce::Monitor)),
            ],
            "no identity persisted: whole-op lines only, in program_diff's order"
        );

        // Identity: no change, no lines.
        assert!(rule_changes(&old, &old).is_empty());
    }

    #[test]
    fn field_diff_covers_exactly_the_op_set_difference() {
        // Mixed change: a persistent allowlist gains a prefix, a
        // router-scale PBA op's interface set turns over, and a whole
        // op leaves. Every op program_diff reports is either a
        // whole-op line or the op behind exactly one member delta —
        // the field-level diff renders the same difference finer,
        // never different.
        let pba = |ifindexes: &[u32]| SavProgramOp::PrefixAllow {
            prefix: "203.0.113.0/24".parse().unwrap(),
            ifindexes: ifindexes.to_vec(),
            action: SavEnforce::Monitor,
        };
        let old = [
            allow(2, &["198.51.100.0/24"], SavEnforce::Monitor),
            pba(&[2, 3]),
            allow(9, &["192.0.2.0/24"], SavEnforce::Monitor),
        ];
        let new = [
            allow(
                2,
                &["198.51.100.0/24", "203.0.113.0/24"],
                SavEnforce::Monitor,
            ),
            pba(&[3, 4]),
        ];
        let changes = rule_changes(&old, &new);
        assert_eq!(
            changes,
            vec![
                RuleChange::PrefixesChanged {
                    op: allow(
                        2,
                        &["198.51.100.0/24", "203.0.113.0/24"],
                        SavEnforce::Monitor
                    ),
                    added: vec!["203.0.113.0/24".parse().unwrap()],
                    removed: vec![],
                },
                RuleChange::IfindexesChanged {
                    op: pba(&[3, 4]),
                    added: vec![4],
                    removed: vec![2],
                },
                RuleChange::OpRemoved(allow(9, &["192.0.2.0/24"], SavEnforce::Monitor)),
            ]
        );
        assert_eq!(
            changes[1].to_string(),
            "allow 203.0.113.0/24 monitor +[4] -[2]"
        );

        // Same op-set difference underneath: two new ops (both paired
        // into deltas), three old ops (two paired, one removed whole).
        let (added, removed) = program_diff(&old, &new);
        assert_eq!(added.len(), 2);
        assert_eq!(removed.len(), 3);
    }

    // ---- daemon over a duplex fake zebra (the staticd test shape) ----

    /// What the mock's counter reads answer: `Unsupported` (the
    /// default — the trait-default shape today's rp_filter backend
    /// keeps for both reads), `Counts` (an aggregate-only answering
    /// backend), `PerOp` (a backend that attributes per op — the
    /// nft shape), or `Failed` (a read that errors).
    #[derive(Default)]
    enum MockCounts {
        #[default]
        Unsupported,
        Counts(SavMonitorCounts),
        PerOp(Vec<(SavProgramOp, SavMonitorCounts)>),
        Failed,
    }

    /// Dataplane mock recording SAV installs/clears (the W5/W7 recipe:
    /// futures always Ready).
    #[derive(Default)]
    struct MockSavDp {
        installed: Mutex<Vec<SavProgram>>,
        cleared: Mutex<u32>,
        counts_answer: Mutex<MockCounts>,
    }

    impl Dataplane for MockSavDp {
        fn route_replace(
            &self,
            _entry: &RouteEntry,
        ) -> impl Future<Output = Result<(), DataplaneError>> + Send {
            std::future::ready(Ok(()))
        }
        fn route_delete(
            &self,
            _entry: &RouteEntry,
        ) -> impl Future<Output = Result<(), DataplaneError>> + Send {
            std::future::ready(Ok(()))
        }
        fn sav_install(
            &self,
            program: &SavProgram,
        ) -> impl Future<Output = Result<(), DataplaneError>> + Send {
            self.installed.lock().unwrap().push(program.clone());
            std::future::ready(Ok(()))
        }
        fn sav_monitor_counts(
            &self,
        ) -> impl Future<Output = Result<SavMonitorCounts, DataplaneError>> + Send {
            std::future::ready(match &*self.counts_answer.lock().unwrap() {
                MockCounts::Unsupported => Err(DataplaneError::Unsupported(
                    "mock: no per-rule counters (trait-default shape)",
                )),
                MockCounts::Counts(counts) => Ok(*counts),
                // The daemon flow never reaches the aggregate read when
                // per-op answered; keep the mode's aggregate honest.
                MockCounts::PerOp(_) => Err(DataplaneError::Unsupported(
                    "mock: per-op mode answers sav_monitor_per_op",
                )),
                MockCounts::Failed => Err(DataplaneError::Other(
                    "mock: monitor-count read failed".into(),
                )),
            })
        }
        fn sav_monitor_per_op(
            &self,
        ) -> impl Future<Output = Result<Vec<(SavProgramOp, SavMonitorCounts)>, DataplaneError>> + Send
        {
            std::future::ready(match &*self.counts_answer.lock().unwrap() {
                MockCounts::Unsupported | MockCounts::Counts(_) => {
                    Err(DataplaneError::Unsupported("mock: no per-op counters"))
                }
                MockCounts::PerOp(rows) => Ok(rows.clone()),
                MockCounts::Failed => Err(DataplaneError::Other(
                    "mock: per-op monitor-count read failed".into(),
                )),
            })
        }
        fn sav_clear(&self) -> impl Future<Output = Result<(), DataplaneError>> + Send {
            *self.cleared.lock().unwrap() += 1;
            std::future::ready(Ok(()))
        }
    }

    /// A static best route for `prefix` egressing `ifindex` (push form:
    /// ifindex-carrying nexthop); `dumped_route` is the W8 fixture
    /// (198.51.100.0/24 via ifindex 2, the asymmetric-arrival shape).
    fn route_push(prefix: &str, ifindex: u32) -> ZapiRoute {
        ZapiRoute {
            route_type: route_type::STATIC,
            instance: 0,
            flags: 0x08,
            message: zapi::message::message_flag::NEXTHOP
                | zapi::message::message_flag::DISTANCE
                | zapi::message::message_flag::METRIC
                | zapi::message::message_flag::MTU,
            safi: 1,
            prefix: prefix.parse().unwrap(),
            src_prefix: None,
            nhg_id: 0,
            nexthops: vec![ZapiNexthop::new_ifindex(0, ifindex)],
            backup_nexthops: Vec::new(),
            distance: Some(1),
            metric: Some(0),
            tag: None,
            mtu: Some(0),
            tableid: None,
            opaque: None,
        }
    }

    /// The one route the fake zebra dumps: 198.51.100.0/24 best via
    /// ifindex 2, i.e. the asymmetric-arrival fixture.
    fn dumped_route() -> ZapiRoute {
        route_push("198.51.100.0/24", 2)
    }

    /// Fake rousterd: echoes HELLO; on each REDISTRIBUTE_ADD pushes the
    /// current dump (one route); answers NEXTHOP_REGISTER with an
    /// update for the same prefix. Returns on client disconnect.
    async fn fake_zebra(
        server: &mut tokio::io::DuplexStream,
        dump: Vec<ZapiMessage>,
    ) -> std::io::Result<()> {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        loop {
            let mut header_buf = [0u8; ZAPI_HEADER_LEN];
            server.read_exact(&mut header_buf).await?;
            let header = ZapiHeader::decode(&header_buf).unwrap();
            let mut body = vec![0u8; header.length as usize - ZAPI_HEADER_LEN];
            server.read_exact(&mut body).await?;
            let message = ZapiMessage::decode(header.command, &body).unwrap();
            match message {
                ZapiMessage::Hello(hello) => {
                    server
                        .write_all(&ZapiMessage::Hello(hello).encode_frame(0).unwrap())
                        .await?;
                }
                ZapiMessage::RedistributeAdd(_) => {
                    for push in &dump {
                        server.write_all(&push.encode_frame(0).unwrap()).await?;
                    }
                }
                ZapiMessage::NexthopRegister(register) => {
                    let update = ZapiNexthopUpdate::unresolved(register.prefix, register.safi);
                    server
                        .write_all(&ZapiMessage::NexthopUpdate(update).encode_frame(0).unwrap())
                        .await?;
                }
                _ => {} // unregister etc.: no reply
            }
        }
    }

    fn spawn_fake_zebra(
        dump: Vec<ZapiMessage>,
    ) -> (tokio::io::DuplexStream, tokio::task::JoinHandle<()>) {
        let (client_io, mut server_io) = tokio::io::duplex(64 * 1024);
        (
            client_io,
            tokio::spawn(async move {
                let _ = fake_zebra(&mut server_io, dump).await;
            }),
        )
    }

    /// The daemon fixture: interfaces eth2 (ifindex 2) and eth3
    /// (ifindex 3) mirrored, strict on both, monitor action.
    fn daemon_with_interfaces(
        client_io: tokio::io::DuplexStream,
    ) -> SavDaemon<tokio::io::DuplexStream> {
        let mut daemon = SavDaemon::new(ZapiClient::new(client_io));
        daemon.apply_event(&link_up(2, "eth2"));
        daemon.apply_event(&link_up(3, "eth3"));
        let config = SavdConfig {
            interfaces: vec![
                InterfaceLine {
                    name: "eth2".into(),
                    mode: UrpfMode::Strict,
                    barsav: false,
                    role: None,
                    remote_as: None,
                },
                InterfaceLine {
                    name: "eth3".into(),
                    mode: UrpfMode::Strict,
                    barsav: false,
                    role: None,
                    remote_as: None,
                },
            ],
            ..SavdConfig::default()
        };
        daemon.set_config(config);
        daemon
    }

    fn link_up(ifindex: u32, name: &str) -> DataplaneEvent {
        DataplaneEvent::LinkNew {
            ifindex,
            name: name.into(),
            is_up: true,
            flags: common::LinkFlags::up_broadcast(),
            vrf_table: None,
            master_ifindex: None,
        }
    }

    fn neighbour_new(ip: &str, ifindex: u32) -> DataplaneEvent {
        DataplaneEvent::NeighbourNew {
            entry: NeighbourEntry::from_rtnetlink(
                ip.parse().unwrap(),
                ifindex,
                Some(vec![0x02, 0, 0, 0, 0, 0x09]),
                0x80,
                0,
            ),
        }
    }

    fn monitor_allow(ifindex: u32, prefixes: &[&str]) -> SavProgramOp {
        allow(ifindex, prefixes, SavEnforce::Monitor)
    }

    fn drop_allow(ifindex: u32, prefixes: &[&str]) -> SavProgramOp {
        allow(ifindex, prefixes, SavEnforce::Drop)
    }

    /// WIRED, in-process: initial_sync collects the redistribute dump
    /// into the RIB view, and the first evaluate builds the SIB from it
    /// and installs the strict monitor program — the /24 allowed on its
    /// egress (ifindex 2) and the empty deny-all allowlist on ifindex 3
    /// (GSC §2.1), both monitor-action.
    #[tokio::test]
    async fn initial_sync_builds_sib_and_installs_monitor_program() {
        let (client_io, server) =
            spawn_fake_zebra(vec![ZapiMessage::RedistributeRouteAdd(dumped_route())]);
        let mut daemon = daemon_with_interfaces(client_io);
        daemon.initial_sync().await.unwrap();

        // The dump landed in the protocol table, not a kernel mirror.
        assert_eq!(
            daemon
                .rib
                .table(MAIN_TABLE)
                .and_then(|t| t.best(&"198.51.100.0/24".parse().unwrap()))
                .map(|b| b.nexthops.hops().to_vec()),
            Some(vec![(Nexthop::IfIndex(2), 1)]),
            "push-form ifindex hop mirrored as-is"
        );

        let dp = MockSavDp::default();
        daemon.evaluate(&dp).await.unwrap();
        let program = daemon.installed().expect("installed").clone();
        assert_eq!(
            program.ops(),
            &[
                monitor_allow(2, &["198.51.100.0/24"]),
                monitor_allow(3, &[]),
            ]
        );
        assert_eq!(dp.installed.lock().unwrap().len(), 1);

        // An identical re-evaluation installs nothing new (churn guard).
        daemon.evaluate(&dp).await.unwrap();
        assert_eq!(
            dp.installed.lock().unwrap().len(),
            1,
            "unchanged: no install"
        );
        drop(daemon);
        let _ = server.await;
    }

    /// A redistribution withdrawal dirties the view and the loop's
    /// re-evaluation runs immediately — but the deletion rides the
    /// RFC 8704 §3.6.2 hysteresis window: the prefix stays enforced
    /// until the window elapses (the select loop's timer arm), then
    /// finally leaves (paused clock: the deadline is advanced by hand).
    #[tokio::test(start_paused = true)]
    async fn withdrawal_defers_the_deletion_then_applies_it() {
        let (client_io, server) =
            spawn_fake_zebra(vec![ZapiMessage::RedistributeRouteAdd(dumped_route())]);
        let mut daemon = daemon_with_interfaces(client_io);
        daemon.initial_sync().await.unwrap();
        let dp = MockSavDp::default();
        daemon.evaluate(&dp).await.unwrap();
        assert_eq!(
            daemon.installed().unwrap().ops(),
            &[
                monitor_allow(2, &["198.51.100.0/24"]),
                monitor_allow(3, &[])
            ]
        );

        // Withdraw: the push dirties the view, the loop re-evaluates
        // immediately — and the deletion is HELD, not applied.
        daemon.apply_push(ZapiMessage::RedistributeRouteDel(route_del()));
        assert!(daemon.take_dirty(), "the withdrawal dirties the view");
        daemon.evaluate(&dp).await.unwrap();
        assert_eq!(
            daemon.installed().unwrap().ops(),
            &[
                monitor_allow(2, &["198.51.100.0/24"]),
                monitor_allow(3, &[])
            ],
            "prefix still enforced inside the hysteresis window"
        );
        assert_eq!(
            dp.installed.lock().unwrap().len(),
            1,
            "deferred: nothing installed"
        );
        assert!(
            daemon.deletion_deadline().is_some(),
            "the loop's timer arm has a deadline to flush"
        );

        // Re-evaluation inside the window is a no-op: the deferral is
        // not re-registered (the deadline keeps its original position).
        daemon.evaluate(&dp).await.unwrap();
        assert_eq!(dp.installed.lock().unwrap().len(), 1);

        // The window elapses: the timer arm's evaluate applies it.
        tokio::time::advance(DEFERRED_DELETE_DELAY + Duration::from_millis(1)).await;
        daemon.evaluate(&dp).await.unwrap();
        // The prefix left the allowlist; the deny-all op stays (IBA is
        // still enabled on ifindex 2 — now allowing nothing).
        assert_eq!(
            daemon.installed().unwrap().ops(),
            &[monitor_allow(2, &[]), monitor_allow(3, &[])]
        );
        assert_eq!(
            dp.installed.lock().unwrap().len(),
            2,
            "expired deletion installed"
        );
        assert!(daemon.deletion_deadline().is_none());
        drop(daemon);
        let _ = server.await;
    }

    /// A REDISTRIBUTE_ROUTE_DEL frame for the dumped static route.
    fn route_del() -> ZapiRoute {
        ZapiRoute {
            nexthops: Vec::new(),
            ..dumped_route()
        }
    }

    /// Event-driven re-evaluation (A10): a redistribute push marks the
    /// view dirty — the select loop re-evaluates on the flag instead of
    /// waiting for the poll tick — and evaluate consumes it. Neighbour
    /// observations and skipped zebra messages never dirty (the program
    /// cannot change); interface events do (name resolution).
    #[tokio::test]
    async fn pushes_mark_the_view_dirty_and_evaluate_consumes_it() {
        let (client_io, server) =
            spawn_fake_zebra(vec![ZapiMessage::RedistributeRouteAdd(dumped_route())]);
        let mut daemon = daemon_with_interfaces(client_io);
        daemon.initial_sync().await.unwrap();
        let dp = MockSavDp::default();
        daemon.evaluate(&dp).await.unwrap();
        assert!(!daemon.is_dirty(), "evaluate covers the sync's pushes");

        // A neighbour observation feeds only the spoof counter.
        daemon.apply_event(&neighbour_new("198.51.100.9", 3));
        assert!(!daemon.is_dirty(), "counter-only: no re-evaluation");

        // A new route push dirties the view (an interface event too)...
        daemon.apply_push(ZapiMessage::RedistributeRouteAdd(route_push(
            "203.0.113.0/24",
            2,
        )));
        assert!(daemon.is_dirty());
        daemon.apply_event(&link_up(4, "eth4"));
        assert!(
            daemon.is_dirty(),
            "interface events dirty (name resolution)"
        );
        assert!(daemon.take_dirty());
        assert!(!daemon.is_dirty(), "taken once");

        // ...and the loop's evaluate installs the new prefix immediately
        // — no poll tick involved.
        daemon.evaluate(&dp).await.unwrap();
        assert!(!daemon.is_dirty(), "evaluate consumes the flag");
        assert_eq!(
            daemon.installed().unwrap().ops(),
            &[
                monitor_allow(2, &["198.51.100.0/24", "203.0.113.0/24"]),
                monitor_allow(3, &[]),
            ],
            "strict gained exactly the new prefix's egress"
        );
        assert_eq!(dp.installed.lock().unwrap().len(), 2);

        // Skipped zebra traffic does not dirty (mirror unchanged).
        daemon.apply_push(ZapiMessage::NexthopUpdate(ZapiNexthopUpdate::unresolved(
            "192.0.2.0/24".parse().unwrap(),
            1,
        )));
        assert!(!daemon.is_dirty());
        drop(daemon);
        let _ = server.await;
    }

    /// Hysteresis separates additions from deletions (RFC 8704 §3.6.2):
    /// in one push burst the new prefix installs immediately while the
    /// withdrawn one is held; a re-advertisement inside the window is
    /// absorbed with ZERO dataplane churn (paused clock).
    #[tokio::test(start_paused = true)]
    async fn hysteresis_holds_deletions_but_applies_additions_immediately() {
        let (client_io, server) =
            spawn_fake_zebra(vec![ZapiMessage::RedistributeRouteAdd(dumped_route())]);
        let mut daemon = daemon_with_interfaces(client_io);
        daemon.initial_sync().await.unwrap();
        let dp = MockSavDp::default();
        daemon.evaluate(&dp).await.unwrap();
        assert_eq!(dp.installed.lock().unwrap().len(), 1);

        // One burst: withdraw the installed prefix, advertise a new one
        // on the same egress.
        daemon.apply_push(ZapiMessage::RedistributeRouteDel(route_del()));
        daemon.apply_push(ZapiMessage::RedistributeRouteAdd(route_push(
            "203.0.113.0/24",
            2,
        )));
        daemon.take_dirty();
        daemon.evaluate(&dp).await.unwrap();

        // The addition applied immediately; the deletion is held.
        assert_eq!(
            daemon.installed().unwrap().ops(),
            &[
                monitor_allow(2, &["198.51.100.0/24", "203.0.113.0/24"]),
                monitor_allow(3, &[])
            ],
            "new prefix enforced now, withdrawn prefix held through the window"
        );
        assert_eq!(
            dp.installed.lock().unwrap().len(),
            2,
            "addition installed without waiting"
        );

        // Transient: the withdrawn prefix is re-advertised inside the
        // window — absorbed, nothing churns.
        daemon.apply_push(ZapiMessage::RedistributeRouteAdd(dumped_route()));
        daemon.take_dirty();
        daemon.evaluate(&dp).await.unwrap();
        assert_eq!(
            dp.installed.lock().unwrap().len(),
            2,
            "absorbed: no install"
        );
        assert!(daemon.deletion_deadline().is_none(), "no deferral left");

        // Withdraw it for real and let the window elapse.
        daemon.apply_push(ZapiMessage::RedistributeRouteDel(route_del()));
        daemon.take_dirty();
        daemon.evaluate(&dp).await.unwrap();
        assert_eq!(dp.installed.lock().unwrap().len(), 2, "still held");
        tokio::time::advance(DEFERRED_DELETE_DELAY + Duration::from_millis(1)).await;
        daemon.evaluate(&dp).await.unwrap();
        assert_eq!(
            daemon.installed().unwrap().ops(),
            &[monitor_allow(2, &["203.0.113.0/24"]), monitor_allow(3, &[])],
            "only the survived prefix is enforced"
        );
        assert_eq!(dp.installed.lock().unwrap().len(), 3, "expiry installed");
        drop(daemon);
        let _ = server.await;
    }

    /// RELOAD, in-process: SIGHUP semantics swap the config (drop +
    /// friction acknowledged — the caller validated) and the next
    /// evaluate carries the Drop action into the program; CLEAR-EXIT
    /// then removes the installed set.
    #[tokio::test]
    async fn reload_to_drop_mode_changes_action_in_program() {
        let (client_io, server) =
            spawn_fake_zebra(vec![ZapiMessage::RedistributeRouteAdd(dumped_route())]);
        let mut daemon = daemon_with_interfaces(client_io);
        daemon.initial_sync().await.unwrap();
        let dp = MockSavDp::default();
        daemon.evaluate(&dp).await.unwrap();

        let mut config = daemon.config().clone();
        config.action = SavAction::Drop;
        config.drop_ack = true;
        config.validate().unwrap();
        daemon.set_config(config);
        daemon.evaluate(&dp).await.unwrap();
        assert_eq!(
            daemon.installed().unwrap().ops(),
            &[drop_allow(2, &["198.51.100.0/24"]), drop_allow(3, &[])]
        );

        daemon.clear(&dp).await.unwrap();
        assert_eq!(*dp.cleared.lock().unwrap(), 1, "CLEAN-EXIT path clears");
        drop(daemon);
        let _ = server.await;
    }

    /// CONFIG-BINDINGS (A11): `binding <prefix> interface <name>...`
    /// lines feed the SIB's Config origin with per-prefix shadowing of
    /// the RIB binding (the SIB's documented precedence): the dumped
    /// route says 198.51.100.0/24 egresses eth2, but the operator pins
    /// it to eth3, so strict moves the prefix across the program; a
    /// config-only prefix lands where pinned; a name missing from the
    /// mirror drops out of its line (the resolved name still answers);
    /// a line with NO resolved name stores nothing. A regeneration over
    /// the same config is byte-stable (churn guard).
    #[tokio::test]
    async fn config_bindings_shadow_rib_per_prefix() {
        let (client_io, server) =
            spawn_fake_zebra(vec![ZapiMessage::RedistributeRouteAdd(dumped_route())]);
        let mut daemon = daemon_with_interfaces(client_io);
        let mut config = daemon.config().clone();
        config.bindings = cfg("binding 198.51.100.0/24 interface eth3\n\
             binding 203.0.113.0/24 interface eth2\n\
             binding 192.0.2.0/24 interface eth2 eth9\n\
             binding 198.18.0.0/15 interface eth9\n")
        .bindings;
        daemon.set_config(config);
        daemon.initial_sync().await.unwrap();
        let dp = MockSavDp::default();
        daemon.evaluate(&dp).await.unwrap();
        assert_eq!(
            daemon.installed().unwrap().ops(),
            &[
                monitor_allow(2, &["192.0.2.0/24", "203.0.113.0/24"]),
                monitor_allow(3, &["198.51.100.0/24"]),
            ],
            "config pinned 198.51.100.0/24 to eth3 (rib egress eth2 shadowed);\n\
             203.0.113.0/24 config-only on eth2; 192.0.2.0/24 resolved through \
             eth2 alone (eth9 unmirrored, dropped); 198.18.0.0/15 stored nothing"
        );

        // Byte-stable: an identical regeneration installs nothing.
        daemon.evaluate(&dp).await.unwrap();
        assert_eq!(
            dp.installed.lock().unwrap().len(),
            1,
            "unchanged: no install"
        );
        drop(daemon);
        let _ = server.await;
    }

    /// RELOAD-WHOLESALE (A11): a config swap replaces the Config origin
    /// wholesale — the old `binding` lines are gone and the new line
    /// answers alone, the previously shadowed rib binding resurfaces
    /// (198.51.100.0/24 back on its rib egress eth2). Prefixes leaving
    /// a still-present allowlist ride the same RFC 8704 §3.6.2 window
    /// as any withdrawal (the deferral is origin-blind by design), so
    /// the old config's prefixes are held through the window and then
    /// expire (paused clock).
    #[tokio::test(start_paused = true)]
    async fn reload_replaces_config_bindings_wholesale() {
        let (client_io, server) =
            spawn_fake_zebra(vec![ZapiMessage::RedistributeRouteAdd(dumped_route())]);
        let mut daemon = daemon_with_interfaces(client_io);
        let mut config = daemon.config().clone();
        config.bindings = cfg("binding 198.51.100.0/24 interface eth3\n\
             binding 203.0.113.0/24 interface eth3\n")
        .bindings;
        daemon.set_config(config);
        daemon.initial_sync().await.unwrap();
        let dp = MockSavDp::default();
        daemon.evaluate(&dp).await.unwrap();
        assert_eq!(
            daemon.installed().unwrap().ops(),
            &[
                monitor_allow(2, &[]),
                monitor_allow(3, &["198.51.100.0/24", "203.0.113.0/24"]),
            ],
            "both prefixes pinned to eth3; the rib egress eth2 is shadowed"
        );

        // SIGHUP semantics: one different line replaces the whole origin.
        let mut reloaded = daemon.config().clone();
        reloaded.bindings = cfg("binding 192.0.2.0/24 interface eth2\n").bindings;
        daemon.set_config(reloaded);
        daemon.evaluate(&dp).await.unwrap();
        assert_eq!(
            daemon.installed().unwrap().ops(),
            &[
                monitor_allow(2, &["192.0.2.0/24", "198.51.100.0/24"]),
                monitor_allow(3, &["198.51.100.0/24", "203.0.113.0/24"]),
            ],
            "the new binding applied immediately and the lifted shadow \
             resurfaced the rib binding on eth2; the old config prefixes \
             leaving eth3's surviving allowlist are held (hysteresis)"
        );

        // Window elapsed: no trace of the old lines remains.
        tokio::time::advance(DEFERRED_DELETE_DELAY + Duration::from_millis(1)).await;
        daemon.evaluate(&dp).await.unwrap();
        assert_eq!(
            daemon.installed().unwrap().ops(),
            &[
                monitor_allow(2, &["192.0.2.0/24", "198.51.100.0/24"]),
                monitor_allow(3, &[]),
            ],
            "wholesale replace: only the reloaded line answers; eth3 deny-all again"
        );
        assert!(
            daemon.deletion_deadline().is_none(),
            "no deferral left from the swapped-out config"
        );
        drop(daemon);
        let _ = server.await;
    }

    /// TTL SWEEP WIRING (A22): every evaluate runs exactly one bounded
    /// SIB sweep on the injected clock (the injected closure IS the
    /// paused clock — the test owns time), and the swept keys surface
    /// on `last_swept`. Honest no-op today, asserted not assumed: no
    /// landed origin stamps an expiry (rib bindings re-derive wholesale
    /// per evaluate; config bindings are pinned), so nothing is ever
    /// swept and the program stays byte-stable — the churn guard holds
    /// through the sweep path.
    #[tokio::test]
    async fn evaluate_sweeps_the_sib_once_per_evaluate_on_the_injected_clock() {
        let (client_io, server) =
            spawn_fake_zebra(vec![ZapiMessage::RedistributeRouteAdd(dumped_route())]);
        let mut daemon = daemon_with_interfaces(client_io);
        let reads = Arc::new(AtomicUsize::new(0));
        let t0 = std::time::Instant::now();
        {
            let reads = reads.clone();
            daemon.set_clock(move || {
                reads.fetch_add(1, Ordering::SeqCst);
                t0
            });
        }
        daemon.initial_sync().await.unwrap();
        assert_eq!(
            reads.load(Ordering::SeqCst),
            0,
            "the sweep clock is read by evaluate alone, not by the sync"
        );

        let dp = MockSavDp::default();
        daemon.evaluate(&dp).await.unwrap();
        assert_eq!(
            reads.load(Ordering::SeqCst),
            1,
            "one bounded sweep per evaluate"
        );
        assert!(
            daemon.last_swept().is_empty(),
            "no landed origin sets a finite TTL tonight — the sweep is an honest no-op"
        );
        assert_eq!(
            daemon.installed().unwrap().ops(),
            &[
                monitor_allow(2, &["198.51.100.0/24"]),
                monitor_allow(3, &[])
            ],
            "the program is exactly the pre-sweep shape"
        );

        // Re-evaluation reads the clock once more and still sweeps
        // nothing: byte-stable, no install.
        daemon.evaluate(&dp).await.unwrap();
        assert_eq!(reads.load(Ordering::SeqCst), 2);
        assert!(daemon.last_swept().is_empty());
        assert_eq!(
            dp.installed.lock().unwrap().len(),
            1,
            "the no-op sweep churns nothing"
        );
        drop(daemon);
        let _ = server.await;
    }

    /// MONITOR-DEFAULT, in-process: neighbour observations on the
    /// empty-allowlist interface raise the spoof counter; on the
    /// allowed interface they count valid; the monitor never drops
    /// (no dataplane call happens between evaluates).
    #[tokio::test]
    async fn neighbour_observations_raise_the_spoof_counter() {
        let (client_io, server) =
            spawn_fake_zebra(vec![ZapiMessage::RedistributeRouteAdd(dumped_route())]);
        let mut daemon = daemon_with_interfaces(client_io);
        daemon.initial_sync().await.unwrap();
        let dp = MockSavDp::default();
        daemon.evaluate(&dp).await.unwrap();

        daemon.apply_event(&neighbour_new("198.51.100.9", 3)); // wrong interface
        daemon.apply_event(&neighbour_new("198.51.100.9", 3)); // again: rises
        daemon.apply_event(&neighbour_new("198.51.100.9", 2)); // egress: valid
        daemon.apply_event(&neighbour_new("203.0.113.5", 9)); // unjudged iface
        let counts = daemon.counts();
        assert_eq!(
            counts.invalid, 2,
            "spoof counter counts wrong-iface sources"
        );
        assert_eq!(counts.valid, 1);
        assert_eq!(counts.unknown, 1, "unknown != invalid");
        assert_eq!(
            dp.installed.lock().unwrap().len(),
            1,
            "observing installs nothing"
        );

        // Regeneration keeps the counter (set_ops semantics, one level up).
        daemon.evaluate(&dp).await.unwrap();
        assert_eq!(daemon.counts().invalid, 2);
        drop(daemon);
        let _ = server.await;
    }

    /// A18, the answering path: when the backend answers
    /// `sav_monitor_counts`, ITS numbers feed the counts log line (not
    /// the simulation's), `counts()` keeps reporting the simulation
    /// counter (the spoof counter, whatever the backend last said), and
    /// the source is re-decided on every evaluate — a backend that
    /// stops answering falls back to the simulation on the next one.
    #[tokio::test]
    async fn dataplane_answered_counts_feed_the_log_line() {
        let (client_io, server) =
            spawn_fake_zebra(vec![ZapiMessage::RedistributeRouteAdd(dumped_route())]);
        let mut daemon = daemon_with_interfaces(client_io);
        daemon.initial_sync().await.unwrap();
        let backend_counts = SavMonitorCounts {
            invalid: 7,
            valid: 5,
            unknown: 3,
        };
        let dp = MockSavDp {
            counts_answer: Mutex::new(MockCounts::Counts(backend_counts)),
            ..MockSavDp::default()
        };
        daemon.evaluate(&dp).await.unwrap();

        // The simulation counter rises independently of the backend.
        daemon.apply_event(&neighbour_new("198.51.100.9", 3)); // invalid
        daemon.apply_event(&neighbour_new("198.51.100.9", 2)); // valid
        daemon.evaluate(&dp).await.unwrap();
        assert_eq!(
            daemon.last_counts(),
            (CountsSource::Dataplane, backend_counts),
            "the backend's numbers feed the line, not the simulation's"
        );
        assert_eq!(
            daemon.counts(),
            SavMonitorCounts {
                invalid: 1,
                valid: 1,
                unknown: 0
            },
            "counts() keeps reporting the simulation counter"
        );

        // The backend stops answering (back to the Unsupported shape):
        // the next evaluate re-decides and the simulation feeds the line.
        *dp.counts_answer.lock().unwrap() = MockCounts::Unsupported;
        daemon.evaluate(&dp).await.unwrap();
        assert_eq!(
            daemon.last_counts(),
            (CountsSource::Simulation, daemon.counts()),
            "fallback resumes on the next evaluate with the simulation's numbers"
        );
        drop(daemon);
        let _ = server.await;
    }

    /// A18, the fallback path: Unsupported (today's rp_filter shape —
    /// a strict/loose value drops, it does not count) feeds the line
    /// from the simulation, and so does a FAILED read — diagnostics
    /// never fail the evaluate.
    #[tokio::test]
    async fn unsupported_or_failed_counts_reads_fall_back_to_the_simulation() {
        let (client_io, server) =
            spawn_fake_zebra(vec![ZapiMessage::RedistributeRouteAdd(dumped_route())]);
        let mut daemon = daemon_with_interfaces(client_io);
        daemon.initial_sync().await.unwrap();
        let dp = MockSavDp::default();
        daemon.evaluate(&dp).await.unwrap();

        daemon.apply_event(&neighbour_new("198.51.100.9", 3)); // invalid
        daemon.apply_event(&neighbour_new("198.51.100.9", 3)); // rises
        daemon.evaluate(&dp).await.unwrap();
        assert_eq!(
            daemon.last_counts(),
            (
                CountsSource::Simulation,
                SavMonitorCounts {
                    invalid: 2,
                    valid: 0,
                    unknown: 0
                }
            ),
            "Unsupported: the simulation feeds the line"
        );

        // A failed read (not Unsupported) is the same fallback, not an
        // evaluate error.
        *dp.counts_answer.lock().unwrap() = MockCounts::Failed;
        daemon.evaluate(&dp).await.unwrap();
        assert_eq!(
            daemon.last_counts(),
            (CountsSource::Simulation, daemon.counts()),
            "a failed read falls back too"
        );
        drop(daemon);
        let _ = server.await;
    }

    /// STATUS SURFACE (A21): `status_text` renders the daemon's own
    /// state — before the first evaluate nothing is installed; after it
    /// the `rule` lines are exactly the installed program's ops (the W8
    /// `installed` surface), the config line is the running config, and
    /// the monitor line carries the last evaluate's counts and source;
    /// a spoof observation moves the counter and the next evaluate's
    /// status reflects it.
    #[tokio::test]
    async fn status_reflects_installed_state() {
        let (client_io, server) =
            spawn_fake_zebra(vec![ZapiMessage::RedistributeRouteAdd(dumped_route())]);
        let mut daemon = daemon_with_interfaces(client_io);
        daemon.initial_sync().await.unwrap();

        let before = daemon.status_text(4242);
        assert!(before.contains("pid 4242"), "the caller's pid is named");
        assert!(
            before.contains("installed 0 rules (never evaluated)"),
            "pre-evaluate: nothing installed"
        );
        assert!(
            before.contains("monitor source simulation invalid=0 valid=0 unknown=0"),
            "counts default to the simulation's zeros"
        );

        let dp = MockSavDp::default();
        daemon.evaluate(&dp).await.unwrap();
        let after = daemon.status_text(4242);
        assert!(
            after
                .contains("config mode strict-uRPF action monitor poll 5s interfaces 2 bindings 0"),
            "the running config renders"
        );
        assert!(after.contains("installed 2 rules"));
        assert!(
            after.contains("rule allow if#2 [198.51.100.0/24] strict monitor"),
            "the installed ops render (the rule-log rendering)"
        );
        assert!(after.contains("rule allow if#3 [] strict monitor"));

        // The spoof counter feeds the line through the next evaluate.
        daemon.apply_event(&neighbour_new("198.51.100.9", 3)); // wrong interface
        daemon.evaluate(&dp).await.unwrap();
        assert!(
            daemon
                .status_text(4242)
                .contains("monitor source simulation invalid=1"),
            "the counts move with the daemon's state"
        );
        drop(daemon);
        let _ = server.await;
    }

    /// GSC §4 "count" per-rule tallies in the status surface: spoof
    /// observations attribute to the deciding op's `count` line (the
    /// effective ops' own rendering, provenance included), unjudged
    /// observations attribute nowhere, ops that judged nothing render
    /// no line, and a byte-identical regeneration keeps the tallies.
    #[tokio::test]
    async fn status_carries_per_rule_count_lines() {
        let (client_io, server) =
            spawn_fake_zebra(vec![ZapiMessage::RedistributeRouteAdd(dumped_route())]);
        let mut daemon = daemon_with_interfaces(client_io);
        daemon.initial_sync().await.unwrap();
        let dp = MockSavDp::default();
        daemon.evaluate(&dp).await.unwrap();
        let before = daemon.status_text(4242);
        assert!(
            !before.contains("count "),
            "pre-observation: no count lines (nothing judged)"
        );

        // Two spoofs on eth3's deny-all, one legit on eth2, one unjudged
        // on ifindex 9 (no mode).
        daemon.apply_event(&neighbour_new("198.51.100.9", 3));
        daemon.apply_event(&neighbour_new("198.51.100.9", 3));
        daemon.apply_event(&neighbour_new("198.51.100.9", 2));
        daemon.apply_event(&neighbour_new("203.0.113.5", 9));
        daemon.evaluate(&dp).await.unwrap();
        let after = daemon.status_text(4242);
        assert!(
            after.contains(
                "count iba permit #2 [198.51.100.0/24] monitor (from fib) invalid=0 valid=1 unknown=0"
            ),
            "the deciding op's own line carries its valid tally: {after}"
        );
        assert!(
            after.contains("count iba permit #3 [] monitor invalid=2 valid=0 unknown=0"),
            "the spoofed arrivals attribute to the deny-all op: {after}"
        );
        assert_eq!(
            after.matches("count ").count(),
            2,
            "only ops that judged something render a count line"
        );

        // A byte-identical regeneration keeps both tallies.
        daemon.evaluate(&dp).await.unwrap();
        assert!(daemon
            .status_text(4242)
            .contains("count iba permit #3 [] monitor invalid=2 valid=0 unknown=0"));
        drop(daemon);
        let _ = server.await;
    }

    /// N6B: when the backend answers the PER-OP read (the nft shape),
    /// its kernel-sourced rows ARE the count-line view — same line
    /// rendering as the simulation rows (effective-op vocabulary,
    /// provenance included), but the numbers are the backend's, the
    /// aggregate line is the rows' sum with source dataplane, and the
    /// simulation's own tallies (moved by neighbour observations in
    /// parallel) never leak into the lines. A row for an op the daemon
    /// did not compile (foreign residue) renders the program op's own
    /// vocabulary rather than being dropped. When the backend stops
    /// answering per op, the next evaluate falls back to the
    /// simulation rows and the aggregate path, exactly as before.
    #[tokio::test]
    async fn per_op_backend_rows_feed_the_count_lines() {
        let (client_io, server) =
            spawn_fake_zebra(vec![ZapiMessage::RedistributeRouteAdd(dumped_route())]);
        let mut daemon = daemon_with_interfaces(client_io);
        daemon.initial_sync().await.unwrap();
        let dp = MockSavDp::default();
        daemon.evaluate(&dp).await.unwrap();
        assert!(daemon.last_per_op().is_none(), "default mock: no per-op");

        // Backend rows keyed by the daemon's own installed ops, plus
        // one foreign row (an op no effective op pairs with).
        let (op2, op3) = (
            monitor_allow(2, &["198.51.100.0/24"]),
            monitor_allow(3, &[]),
        );
        let foreign = monitor_allow(9, &["203.0.113.0/24"]);
        let rows = vec![
            (
                op2.clone(),
                SavMonitorCounts {
                    invalid: 1,
                    valid: 6,
                    unknown: 0,
                },
            ),
            (
                op3.clone(),
                SavMonitorCounts {
                    invalid: 13,
                    valid: 0,
                    unknown: 0,
                },
            ),
            (
                foreign.clone(),
                SavMonitorCounts {
                    invalid: 2,
                    valid: 0,
                    unknown: 0,
                },
            ),
        ];
        *dp.counts_answer.lock().unwrap() = MockCounts::PerOp(rows);
        // In parallel the simulation judges different numbers (1
        // valid, 2 invalid) — the lines must show the BACKEND's.
        daemon.apply_event(&neighbour_new("198.51.100.9", 2)); // valid
        daemon.apply_event(&neighbour_new("198.51.100.9", 3)); // invalid
        daemon.apply_event(&neighbour_new("198.51.100.9", 3)); // invalid
        daemon.evaluate(&dp).await.unwrap();

        assert_eq!(
            daemon.last_counts(),
            (
                CountsSource::Dataplane,
                SavMonitorCounts {
                    invalid: 16,
                    valid: 6,
                    unknown: 0
                }
            ),
            "the aggregate line is the per-op rows' sum, backend-sourced"
        );
        let status = daemon.status_text(4242);
        assert!(
            status.contains(
                "count iba permit #2 [198.51.100.0/24] monitor (from fib) invalid=1 valid=6 unknown=0"
            ),
            "backend row, effective-op rendering with provenance: {status}"
        );
        assert!(
            status.contains("count iba permit #3 [] monitor invalid=13 valid=0 unknown=0"),
            "the deny-all's backend numbers, not the simulation's 2: {status}"
        );
        assert!(
            status.contains("count allow if#9 [203.0.113.0/24] strict monitor invalid=2"),
            "a foreign row keeps the program-op rendering (never dropped): {status}"
        );
        assert_eq!(
            status.matches("count ").count(),
            3,
            "every judged backend row renders, simulation rows do not mix in"
        );

        // The backend stops answering per op: the next evaluate
        // re-decides — simulation rows return, last_per_op clears.
        *dp.counts_answer.lock().unwrap() = MockCounts::Unsupported;
        daemon.evaluate(&dp).await.unwrap();
        assert!(daemon.last_per_op().is_none());
        assert_eq!(
            daemon.last_counts(),
            (CountsSource::Simulation, daemon.counts()),
            "the aggregate falls back the A18 way"
        );
        let status = daemon.status_text(4242);
        assert!(
            status.contains("count iba permit #3 [] monitor invalid=2 valid=0 unknown=0"),
            "simulation rows render again: {status}"
        );
        drop(daemon);
        let _ = server.await;
    }

    /// A7 riding A21 (provenance in operator output): each `rule` line
    /// appends " (from <origin>)" when the op's contributing rules
    /// agreed on one — fib (rib-derived best route), bgp (a BGP-learned
    /// one), static (an operator binding) — and stays bare when the op
    /// recorded none (the seeded empty allowlist) or its rules
    /// disagreed (a merged op never guesses a source). One origin per
    /// interface: compile folds every IBA rule on an interface into one
    /// allowlist op, so distinct origins need distinct interfaces.
    #[tokio::test]
    async fn status_rule_lines_carry_provenance() {
        let (client_io, server) =
            spawn_fake_zebra(vec![ZapiMessage::RedistributeRouteAdd(dumped_route())]);
        let mut daemon = SavDaemon::new(ZapiClient::new(client_io));
        daemon.apply_event(&link_up(2, "eth2"));
        daemon.apply_event(&link_up(3, "eth3"));
        daemon.apply_event(&link_up(4, "eth4"));
        daemon.set_config(SavdConfig {
            interfaces: vec![
                InterfaceLine {
                    name: "eth2".into(),
                    mode: UrpfMode::Strict,
                    barsav: false,
                    role: None,
                    remote_as: None,
                },
                InterfaceLine {
                    name: "eth3".into(),
                    mode: UrpfMode::Strict,
                    barsav: false,
                    role: None,
                    remote_as: None,
                },
                InterfaceLine {
                    name: "eth4".into(),
                    mode: UrpfMode::Strict,
                    barsav: false,
                    role: None,
                    remote_as: None,
                },
            ],
            ..SavdConfig::default()
        });
        daemon.initial_sync().await.unwrap();
        let dp = MockSavDp::default();
        daemon.evaluate(&dp).await.unwrap();
        let phase1 = daemon.status_text(4242);
        assert!(
            phase1.contains("rule allow if#2 [198.51.100.0/24] strict monitor (from fib)"),
            "the rib-derived rule names its source: {phase1}"
        );
        assert!(
            phase1.contains("rule allow if#3 [] strict monitor\n"),
            "the seeded empty allowlist carries no origin (bare line): {phase1}"
        );

        // A BGP-learned route on eth4 and an operator binding on eth3.
        daemon.apply_push(ZapiMessage::RedistributeRouteAdd(ZapiRoute {
            route_type: route_type::BGP,
            ..route_push("203.0.113.0/24", 4)
        }));
        let mut config = daemon.config().clone();
        config.bindings = cfg("binding 192.0.2.0/24 interface eth3\n").bindings;
        daemon.set_config(config);
        daemon.take_dirty();
        daemon.evaluate(&dp).await.unwrap();
        let phase2 = daemon.status_text(4242);
        assert!(
            phase2.contains("rule allow if#3 [192.0.2.0/24] strict monitor (from static)"),
            "the operator binding's rule: {phase2}"
        );
        assert!(
            phase2.contains("rule allow if#4 [203.0.113.0/24] strict monitor (from bgp)"),
            "the BGP-learned best route: {phase2}"
        );

        // Disagreeing origins on one interface: an extra static binding
        // joins eth2's fib-derived allowlist — the merged op declines.
        let mut mixed = daemon.config().clone();
        mixed.bindings =
            cfg("binding 192.0.2.0/24 interface eth3\nbinding 198.18.0.0/15 interface eth2\n")
                .bindings;
        daemon.set_config(mixed);
        daemon.take_dirty();
        daemon.evaluate(&dp).await.unwrap();
        assert!(
            daemon
                .status_text(4242)
                .contains("rule allow if#2 [198.18.0.0/15, 198.51.100.0/24] strict monitor\n"),
            "static + fib on one allowlist: no suffix, never a guess: {}",
            daemon.status_text(4242)
        );
        drop(daemon);
        let _ = server.await;
    }

    /// Provenance follows the view: a config swap that lifts an
    /// operator shadow resurfaces the rib binding, and the rule line's
    /// origin flips with it — the suffix is derived from the CURRENT
    /// effective ops on every status render, not cached.
    #[tokio::test(start_paused = true)]
    async fn provenance_follows_regeneration() {
        let (client_io, server) =
            spawn_fake_zebra(vec![ZapiMessage::RedistributeRouteAdd(dumped_route())]);
        let mut daemon = daemon_with_interfaces(client_io);
        let mut config = daemon.config().clone();
        config.bindings = cfg("binding 198.51.100.0/24 interface eth3\n").bindings;
        daemon.set_config(config);
        daemon.initial_sync().await.unwrap();
        let dp = MockSavDp::default();
        daemon.evaluate(&dp).await.unwrap();
        assert!(
            daemon
                .status_text(4242)
                .contains("rule allow if#3 [198.51.100.0/24] strict monitor (from static)"),
            "operator-pinned: the shadow answers as static"
        );
        assert!(
            daemon
                .status_text(4242)
                .contains("rule allow if#2 [] strict monitor\n"),
            "the shadowed rib egress compiled to the empty allowlist"
        );

        // SIGHUP: the binding line is gone — the rib binding resurfaces
        // on its own egress (an addition, immediate) and the prefix on
        // eth3 rides the hysteresis window (paused clock: still held).
        let reloaded = daemon.config().clone();
        daemon.set_config(SavdConfig {
            bindings: Vec::new(),
            ..reloaded
        });
        daemon.evaluate(&dp).await.unwrap();
        let status = daemon.status_text(4242);
        assert!(
            status.contains("rule allow if#2 [198.51.100.0/24] strict monitor (from fib)"),
            "the resurfaced rib binding names fib: {status}"
        );
        assert!(
            status.contains("rule allow if#3 [198.51.100.0/24] strict monitor\n"),
            "eth3 still enforces the prefix through the hysteresis window, but on \
             the desired op's origin — the static rule that produced it is gone \
             from the view, so the line is bare: {status}"
        );
        drop(daemon);
        let _ = server.await;
    }

    /// A configured interface missing from the mirror is skipped with a
    /// warning, not fatal — the poll tick picks it up when it appears.
    #[tokio::test]
    async fn unresolved_interface_is_skipped() {
        let (client_io, server) = spawn_fake_zebra(vec![]);
        let mut daemon = daemon_with_interfaces(client_io);
        let mut config = daemon.config().clone();
        config.interfaces.push(InterfaceLine {
            name: "eth9".into(),
            mode: UrpfMode::Strict,
            barsav: false,
            role: None,
            remote_as: None,
        });
        daemon.set_config(config);
        daemon.initial_sync().await.unwrap();
        let dp = MockSavDp::default();
        daemon.evaluate(&dp).await.unwrap();
        assert_eq!(
            daemon.installed().unwrap().ops().len(),
            2,
            "eth9 contributed no op"
        );
        drop(daemon);
        let _ = server.await;
    }

    /// Loose/strict partitioning: two configured interfaces with two
    /// modes produce two ops with the right uRPF hints per mode.
    #[tokio::test]
    async fn mixed_modes_partition_the_program_with_per_mode_hints() {
        let (client_io, server) =
            spawn_fake_zebra(vec![ZapiMessage::RedistributeRouteAdd(dumped_route())]);
        let mut daemon = SavDaemon::new(ZapiClient::new(client_io));
        daemon.apply_event(&link_up(2, "eth2"));
        daemon.apply_event(&link_up(3, "eth3"));
        let config = SavdConfig {
            interfaces: vec![
                InterfaceLine {
                    name: "eth2".into(),
                    mode: UrpfMode::Strict,
                    barsav: false,
                    role: None,
                    remote_as: None,
                },
                InterfaceLine {
                    name: "eth3".into(),
                    mode: UrpfMode::Loose,
                    barsav: false,
                    role: None,
                    remote_as: None,
                },
            ],
            ..SavdConfig::default()
        };
        daemon.set_config(config);
        daemon.initial_sync().await.unwrap();
        let dp = MockSavDp::default();
        daemon.evaluate(&dp).await.unwrap();
        assert_eq!(
            daemon.installed().unwrap().ops(),
            &[
                SavProgramOp::IfaceAllow {
                    ifindex: 2,
                    prefixes: vec!["198.51.100.0/24".parse().unwrap()],
                    urpf: SavUrpf::Strict,
                    action: SavEnforce::Monitor,
                },
                SavProgramOp::IfaceAllow {
                    ifindex: 3,
                    prefixes: vec!["198.51.100.0/24".parse().unwrap()],
                    urpf: SavUrpf::Loose,
                    action: SavEnforce::Monitor,
                },
            ],
            "strict allows only the egress; loose (route existence) allows both"
        );
        drop(daemon);
        let _ = server.await;
    }

    /// The unused-import shape of the mock's Dataplane impl (keeps the
    /// helpers referenced when only a subset of tests compile changes).
    #[allow(dead_code)]
    fn _route_entry_helpers() -> (RouteEntry, NexthopGroup, RouteProtocol) {
        (
            RouteEntry::new(
                "0.0.0.0/0".parse().unwrap(),
                RouteProtocol::Static,
                NexthopGroup::single(Nexthop::Blackhole),
                0,
            ),
            NexthopGroup::new(),
            RouteProtocol::Static,
        )
    }

    // ---- hosted SAVNET agent (experimental-savnet only) ----

    #[cfg(feature = "experimental-savnet")]
    mod savnet_host {
        use super::*;

        #[tokio::test]
        async fn the_agent_defaults_to_none() {
            let (client_io, _server) = spawn_fake_zebra(vec![]);
            let daemon = SavDaemon::new(ZapiClient::new(client_io));
            assert!(daemon.agent().is_none(), "no agent until set_agent");
            assert!(daemon.last_suggestions().is_empty());
        }

        /// The production feed: pushes report RibView route events to
        /// the hosted agent; the evaluate's suggestion pass stays empty
        /// (no adjacency, no peer granularity) and the installed
        /// program is exactly the no-agent shape.
        #[tokio::test]
        async fn ribview_pushes_feed_the_agent_and_nothing_enforces() {
            let (client_io, server) =
                spawn_fake_zebra(vec![ZapiMessage::RedistributeRouteAdd(dumped_route())]);
            let mut daemon = daemon_with_interfaces(client_io);
            daemon.set_agent(crate::agent::MonitorAgent::new());
            daemon.initial_sync().await.unwrap();
            // A push after sync (the event-driven path).
            daemon.apply_push(ZapiMessage::RedistributeRouteDel(route_del()));

            // Every registration re-dumps the route (the fake zebra's
            // per-registration behavior): 7 types x 2 AFIs = 14 adds
            // during sync, then the explicit del.
            let events = daemon.agent().unwrap().events();
            assert_eq!(events.len(), 15, "14 dump adds + 1 push del reported");
            assert!(events[..14]
                .iter()
                .all(|event| matches!(event, crate::agent::SavAgentEvent::RouteInstalled { .. })));
            assert!(matches!(
                events[14],
                crate::agent::SavAgentEvent::RouteWithdrawn { .. }
            ));

            let dp = MockSavDp::default();
            daemon.evaluate(&dp).await.unwrap();
            assert!(
                daemon.last_suggestions().is_empty(),
                "RibView has no peer granularity: no suggestion, nothing enforced"
            );
            // The del removed the only route: the strict allowlist on
            // if#2 empties (the program IS the no-agent shape — the
            // agent never touched it).
            assert_eq!(
                daemon.installed().unwrap().ops(),
                &[monitor_allow(2, &[]), monitor_allow(3, &[])]
            );
            drop(daemon);
            let _ = server.await;
        }

        /// The monitor-only contract, program-equality form: with and
        /// without a hosted agent, the same push/evaluate sequence
        /// installs byte-identical programs (the agent changes logs,
        /// never enforcement — feature-on equivalence with the
        /// default-off build's daemon).
        #[tokio::test]
        async fn a_hosted_agent_changes_no_installed_program() {
            async fn sequence(with_agent: bool) -> SavProgram {
                let (client_io, server) =
                    spawn_fake_zebra(vec![ZapiMessage::RedistributeRouteAdd(dumped_route())]);
                let mut daemon = daemon_with_interfaces(client_io);
                if with_agent {
                    daemon.set_agent(crate::agent::MonitorAgent::new());
                }
                daemon.initial_sync().await.unwrap();
                let dp = MockSavDp::default();
                daemon.evaluate(&dp).await.unwrap();
                let program = daemon.installed().unwrap().clone();
                drop(daemon);
                let _ = server.await;
                program
            }
            let bare = sequence(false).await;
            let hosted = sequence(true).await;
            assert_eq!(
                bare.ops(),
                hosted.ops(),
                "hosting the monitor agent changes no installed op"
            );
            assert_eq!(bare.ops()[0], monitor_allow(2, &["198.51.100.0/24"]));
        }
    }

    // ---- BAR-SAV (S9-a M3 wiring; draft-ietf-sidrops-bar-sav-10) ----

    fn address_up(ifindex: u32, prefix: &str) -> DataplaneEvent {
        DataplaneEvent::AddressNew {
            ifindex,
            prefix: prefix.parse().unwrap(),
        }
    }

    fn temp_file(name: &str, content: &str) -> std::path::PathBuf {
        let dir =
            std::env::temp_dir().join(format!("savd-barsav-test-{}-{name}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join(name);
        std::fs::write(&path, content).unwrap();
        path
    }

    #[test]
    fn parses_the_barsav_grammar() {
        let config = cfg("\n\
             barsav feed /run/rouster/barsav-adj-rib-in.txt\n\
             barsav vrp-file /etc/rouster/rpki.snapshot\n\
             barsav local-as 65000\n\
             barsav provider-exempt 192.0.2.0/24\n\
             barsav provider-exempt 198.18.0.0/15\n\
             interface vethcust\n\
             mode barsav\n\
             role customer\n\
             remote-as 64500\n\
             interface vethpeer\n\
             mode barsav\n\
             role peer\n\
             remote-as 64501\n\
             interface vethprov\n\
             mode barsav\n\
             role provider\n\
             remote-as 64502\
             ");
        assert_eq!(
            config.barsav_feed,
            Some("/run/rouster/barsav-adj-rib-in.txt".into())
        );
        assert_eq!(
            config.barsav_vrp_file,
            Some("/etc/rouster/rpki.snapshot".into())
        );
        assert_eq!(config.barsav_local_as, 65000);
        assert_eq!(config.barsav_provider_exempt.len(), 2);
        let [cust, peer, prov] = &config.interfaces[..] else {
            panic!("three stanzas");
        };
        assert!(cust.barsav && cust.role == Some(BarRole::Customer));
        assert_eq!(cust.remote_as, Some(64500));
        assert!(peer.barsav && peer.role == Some(BarRole::LateralPeer));
        assert!(prov.barsav && prov.role == Some(BarRole::Provider));
        // The running-config line names the barsav partition.
        assert!(config.to_string().contains("barsav[ifaces 3 feed true"));
    }

    #[test]
    fn rejects_bad_barsav_config() {
        let cases = [
            ("mode barsav", "barsav as the global default"),
            (
                "interface a\nmode barsav",
                "barsav stanza without role/remote-as",
            ),
            (
                "interface a\nmode barsav\nrole customer",
                "role without remote-as",
            ),
            (
                "interface a\nrole customer\nremote-as 1",
                "role/remote-as without mode barsav",
            ),
            ("interface a\nmode barsav\nrole lateral", "bad role token"),
            (
                "interface a\nmode barsav\nrole customer\nremote-as x",
                "bad remote-as",
            ),
            ("barsav feed /a\nbarsav feed /b", "duplicate feed"),
            (
                "barsav vrp-file /a\nbarsav vrp-file /b",
                "duplicate vrp-file",
            ),
            ("barsav local-as 1\nbarsav local-as 2", "duplicate local-as"),
            (
                "barsav provider-exempt 10.0.0.0/8\nbarsav provider-exempt 10.0.0.0/8",
                "duplicate exemption",
            ),
            ("barsav provider-exempt nope", "bad exemption prefix"),
            ("barsav bogus x", "unknown barsav directive"),
        ];
        for (input, why) in cases {
            assert!(parse_savd_config(input).is_err(), "{why}: `{input}`");
        }
    }

    /// The daemon end of the M3 feed: bgpd's feed, the RPKI snapshot
    /// and the on-link mirror drive build_ops — the derived IBA ops,
    /// provenance bar-sav, tagged Loose (the program hint), carrying
    /// the monitor action by default. Topology (global-range neighbor
    /// ASNs, staying outside §4 Step 6's special-purpose removal set):
    /// local AS 64512; customer AS 64600 on eth2 (192.0.2.0/24, peer
    /// .9) with deep customer AS 64601; lateral peer AS 64700 on eth3
    /// (198.51.100.0/24, peer .2); provider AS 64800 on eth4.
    fn barsav_daemon(
        feed_path: std::path::PathBuf,
        vrp_path: std::path::PathBuf,
    ) -> SavDaemon<tokio::io::DuplexStream> {
        let (client_io, _server) = tokio::io::duplex(64);
        let mut daemon = SavDaemon::new(ZapiClient::new(client_io));
        daemon.apply_event(&link_up(2, "eth2"));
        daemon.apply_event(&link_up(3, "eth3"));
        daemon.apply_event(&link_up(4, "eth4"));
        daemon.apply_event(&address_up(2, "192.0.2.1/24"));
        daemon.apply_event(&address_up(3, "198.51.100.1/24"));
        daemon.apply_event(&address_up(4, "203.0.113.1/24"));
        daemon.set_config(SavdConfig {
            interfaces: vec![
                {
                    let mut l = InterfaceLine {
                        name: "eth2".into(),
                        mode: UrpfMode::Strict,
                        barsav: true,
                        role: Some(BarRole::Customer),
                        remote_as: Some(64600),
                    };
                    l.mode = UrpfMode::Strict;
                    l
                },
                InterfaceLine {
                    name: "eth3".into(),
                    mode: UrpfMode::Strict,
                    barsav: true,
                    role: Some(BarRole::LateralPeer),
                    remote_as: Some(64700),
                },
                InterfaceLine {
                    name: "eth4".into(),
                    mode: UrpfMode::Strict,
                    barsav: true,
                    role: Some(BarRole::Provider),
                    remote_as: Some(64800),
                },
            ],
            barsav_feed: Some(feed_path),
            barsav_vrp_file: Some(vrp_path),
            barsav_local_as: 64512,
            ..SavdConfig::default()
        });
        daemon
    }

    fn barsav_feed_fixture() -> (std::path::PathBuf, std::path::PathBuf) {
        let feed = temp_file(
            "feed.txt",
            "198.51.100.0/24 peer 192.0.2.9 path 64600\n\
             203.0.113.0/24 peer 192.0.2.9 path 64600 64601\n\
             192.0.2.0/24 peer 198.51.100.2 path 64700\n\
             198.18.0.0/15 peer 203.0.113.9 path 64800\
             ",
        );
        let vrps = temp_file(
            "rpki.snapshot",
            "vrp 198.51.100.0/24 max 24 as 64600\n\
             vrp 203.0.113.0/24 max 24 as 64601\n\
             aspa 64601 provider 64600\
             ",
        );
        (feed, vrps)
    }

    #[test]
    fn barsav_ops_derive_from_the_feed_end_to_end() {
        let (feed, vrps) = barsav_feed_fixture();
        let mut daemon = barsav_daemon(feed, vrps);
        let ops = daemon.build_ops();
        let permit = |ifindex: u32| {
            ops.iter()
                .find(|(mode, op)| {
                    *mode == UrpfMode::Loose
                        && matches!(op, SavOp::IbaPermit { ifindex: i, .. } if *i == ifindex)
                })
                .map(|(_, op)| op.clone())
                .unwrap_or_else(|| panic!("barsav op for ifindex {ifindex}"))
        };
        // Customer (§4): the cone's two prefixes.
        match permit(2) {
            SavOp::IbaPermit {
                prefixes,
                action,
                origin,
                ..
            } => {
                assert_eq!(
                    prefixes,
                    vec![
                        "198.51.100.0/24".parse().unwrap(),
                        "203.0.113.0/24".parse().unwrap()
                    ]
                );
                assert_eq!(action, SavAction::Monitor, "monitor default");
                assert_eq!(origin, Some(RuleOrigin::BarSav));
            }
            _ => panic!("iba op"),
        }
        // Lateral peer (§2): its own prefix.
        match permit(3) {
            SavOp::IbaPermit { prefixes, .. } => {
                assert_eq!(prefixes, vec!["192.0.2.0/24".parse().unwrap()]);
            }
            _ => panic!("iba op"),
        }
        // Provider (§8): loose − S; both cone prefixes are
        // cone-exclusive here (ROV-valid, clean attestations), so the
        // provider allowlist keeps only the peer's and far prefixes.
        match permit(4) {
            SavOp::IbaPermit { prefixes, .. } => {
                assert_eq!(
                    prefixes,
                    vec![
                        "192.0.2.0/24".parse().unwrap(),
                        "198.18.0.0/15".parse().unwrap()
                    ]
                );
            }
            _ => panic!("iba op"),
        }
        assert_eq!(ops.len(), 3, "exactly the three barsav interfaces");
    }

    /// The feed-unavailable posture: a missing or unparseable input
    /// derives NOTHING and enables NOTHING — no seeded empty
    /// allowlist, no deny-all — every BAR-SAV interface unjudged
    /// (unknown ≠ invalid; the §7.5.1 fail-open shape).
    #[test]
    fn barsav_feed_unavailable_leaves_interfaces_unjudged() {
        let (feed, vrps) = barsav_feed_fixture();
        // Missing file.
        let mut daemon = barsav_daemon(
            std::path::PathBuf::from("/nonexistent/barsav-feed"),
            vrps.clone(),
        );
        assert!(daemon.build_ops().is_empty());
        // Unparseable feed.
        let bad = temp_file("bad-feed.txt", "total junk\n");
        let mut daemon = barsav_daemon(bad, vrps.clone());
        assert!(daemon.build_ops().is_empty());
        // Unreadable vrp-file.
        let mut daemon = barsav_daemon(
            feed.clone(),
            std::path::PathBuf::from("/nonexistent/rpki.snapshot"),
        );
        assert!(daemon.build_ops().is_empty());
        // And the good files still work (the controls above did not
        // consume the fixtures' validity).
        let mut daemon = barsav_daemon(feed.clone(), vrps);
        assert_eq!(daemon.build_ops().len(), 3);
    }

    /// A feed peer that is not on-link (no connected prefix covers
    /// it) drops out of the derivation — multi-hop/iBGP feeds are
    /// §Deferred; the single-hop eBGP case is tonight's scope.
    #[test]
    fn barsav_off_link_feed_peers_drop_out() {
        let (feed, vrps) = barsav_feed_fixture();
        let mut daemon = barsav_daemon(feed, vrps);
        // eth3's address leaves: its peer 198.51.100.2 is no longer
        // on-link, so the peer interface's own prefix no longer
        // derives (Q2 loses the 64700-originated path).
        daemon.apply_event(&DataplaneEvent::AddressDel {
            ifindex: 3,
            prefix: "198.51.100.1/24".parse().unwrap(),
        });
        let ops = daemon.build_ops();
        let peer_op = ops
            .iter()
            .find(|(_, op)| matches!(op, SavOp::IbaPermit { ifindex: 3, .. }))
            .expect("peer op still seeded");
        match peer_op.1 {
            SavOp::IbaPermit { ref prefixes, .. } => {
                // The peer's stanza exists, so the op seeds; but no
                // path derives for it anymore (its only feed line
                // dropped out) — the empty allowlist is the honest
                // derivation (GSC §2.1 deny-all, monitor action).
                assert!(prefixes.is_empty());
            }
            _ => panic!("iba op"),
        }
    }
}
