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
//! leaves a still-present allowlist is held installed for
//! [`DEFERRED_DELETE_DELAY`] (a pending-deletions set the select loop's
//! timer arm flushes), so a withdraw/re-advertise transient never
//! flickers the dataplane — the re-advertised prefix is absorbed
//! silently. Additions and whole-op removals (the allowlist's
//! generator mode, interface, or action changed — operator intent, not
//! a route flap) apply immediately. The spoof monitor judges the same
//! effective ops the dataplane enforces, so counters and enforcement
//! never disagree.
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
//! i-understand-drop-mode yes        ! required friction to start in drop mode
//! interface <name>                  ! opens a per-interface stanza
//!   mode <strict|loose|fp|efp>      ! per-interface mode override
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
use std::time::Duration;

use common::{Dataplane, DataplaneError, DataplaneEvent, IpPrefix, SavProgram, SavProgramOp};
use rib::Rib;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::time::{timeout, Instant};
use tracing::{debug, info, warn};
use zapi::{route_type, ZapiClient, ZapiMessage};

use crate::gen::{generate_urpf, UrpfMode};
use crate::mode::{SavAction, SavConfig, ValidationMode};
use crate::monitor::SpoofMonitor;
use crate::program::program;
use crate::table::{compile, SavOp, Verdict};
use crate::{Binding, BindingOrigin, InterfaceRef, Sib, MAIN_TABLE};

/// Hysteresis window for allowlist deletions (RFC 8704 §3.6.2): a
/// withdrawn prefix stays enforced this long before it finally
/// uninstalls, so withdraw/re-advertise transients never flicker the
/// dataplane. Short and fixed (not configurable) tonight, disclosed:
/// long enough to absorb a redistribute flap, short enough that a real
/// withdrawal converges promptly — and the select loop's timer arm
/// flushes exactly at the deadline, independent of the poll cadence.
const DEFERRED_DELETE_DELAY: Duration = Duration::from_secs(3);

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
/// against the local mirror at evaluation time) and its generator mode.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InterfaceLine {
    pub name: String,
    pub mode: UrpfMode,
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
    /// `i-understand-drop-mode yes` — the friction line drop mode
    /// requires.
    pub drop_ack: bool,
    /// Configured interface stanzas, in file order.
    pub interfaces: Vec<InterfaceLine>,
    /// Configured `binding` lines, in file order (one per prefix).
    pub bindings: Vec<BindingLine>,
}

impl Default for SavdConfig {
    fn default() -> Self {
        Self {
            mode: UrpfMode::Strict,
            action: SavAction::Monitor,
            poll_secs: DEFAULT_POLL_SECS,
            drop_ack: false,
            interfaces: Vec::new(),
            bindings: Vec::new(),
        }
    }
}

impl fmt::Display for SavdConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "mode {} action {} poll {}s interfaces {} bindings {}",
            self.mode,
            self.action,
            self.poll_secs,
            self.interfaces.len(),
            self.bindings.len()
        )
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
                match parse_mode(m) {
                    Some(mode) => iface.mode = mode,
                    None => {
                        return Err(fail(
                            line_no,
                            format!("bad mode `{m}` (strict|loose|fp|efp)"),
                        ))
                    }
                }
            }
            ["mode", m] => {
                if seen_global_mode {
                    return Err(fail(line_no, "duplicate global `mode` line"));
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
                        "expected `mode <strict|loose|fp|efp>`, `action <monitor|drop>`, \
                         `poll <secs>`, `i-understand-drop-mode <yes|no>`, \
                         `interface <name>`, or `binding <prefix> interface <name>...`, \
                         got `{line}`"
                    ),
                ))
            }
        }
    }
    config.validate().map_err(SavdConfigError::Validation)?;
    Ok(config)
}

/// The rendered difference between two installed programs: ops only in
/// the new program (`added`) and ops only in the old one (`removed`).
/// Both operand lists come normalized from [`SavProgram::ops`], so a
/// value-based difference is exact.
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
        }
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
                    self.rib.add_route(entry);
                    self.dirty = true;
                } else {
                    warn!("savd: redistribute push with unmapped type ignored");
                }
            }
            ZapiMessage::RedistributeRouteDel(route) => match route.protocol() {
                Some(protocol) => {
                    debug!(prefix = %route.prefix, "savd: rib push del");
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
    /// Rib per prefix), one generator partition per configured mode,
    /// compiled and tagged with the producing mode (so each op's uRPF
    /// hint matches it, and the hysteresis pass can group ops by
    /// identity).
    fn build_ops(&self) -> Vec<(UrpfMode, SavOp)> {
        let mut sib = Sib::from_rib(&self.rib);
        self.apply_config_bindings(&mut sib);
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
            for op in compile(&rules, cfg) {
                ops.push((*mode, op));
            }
        }
        ops
    }

    /// Re-evaluate the view and converge the dataplane onto it:
    /// regenerate rules, log the startup rule set or the diff at info,
    /// install through the trait when the program changed, and log the
    /// monitor counters. An identical regeneration installs nothing
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
                    deadline: now + DEFERRED_DELETE_DELAY,
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
                let (added, removed) = program_diff(prev.ops(), target.ops());
                for op in &added {
                    info!(rule = %op, "savd: rule added");
                }
                for op in &removed {
                    info!(rule = %op, "savd: rule removed");
                }
                info!(
                    added = added.len(),
                    removed = removed.len(),
                    deferred = self.pending_deletions.len(),
                    %self.config,
                    "savd: rule set changed"
                );
                self.install(dp, &target).await?;
            }
            _ => debug!("savd: rule set unchanged; nothing installed"),
        }

        let counts = self.monitor.counts();
        info!(
            invalid = counts.invalid,
            valid = counts.valid,
            unknown = counts.unknown,
            "savd: monitor counts (invalid = spoof counter)"
        );
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::future::Future;
    use std::sync::Mutex;

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
        let config = cfg("! monitor by default until acknowledged\n\
             mode strict\n\
             poll 2\n\
             interface vethlegit\n\
             mode loose\n\
             interface vethspoof\n\
             binding 203.0.113.0/24 interface vethlegit vethspoof\n\
             binding 2001:db8::/64 interface vethlegit\n\
             # strict inherited from the global mode\n\
             ");
        assert_eq!(config.mode, UrpfMode::Strict);
        assert_eq!(config.action, SavAction::Monitor);
        assert_eq!(config.poll_secs, 2);
        assert!(!config.drop_ack);
        assert_eq!(
            config.interfaces,
            vec![
                InterfaceLine {
                    name: "vethlegit".into(),
                    mode: UrpfMode::Loose
                },
                InterfaceLine {
                    name: "vethspoof".into(),
                    mode: UrpfMode::Strict
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

    // ---- daemon over a duplex fake zebra (the staticd test shape) ----

    /// Dataplane mock recording SAV installs/clears (the W5/W7 recipe:
    /// futures always Ready).
    #[derive(Default)]
    struct MockSavDp {
        installed: Mutex<Vec<SavProgram>>,
        cleared: Mutex<u32>,
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
                },
                InterfaceLine {
                    name: "eth3".into(),
                    mode: UrpfMode::Strict,
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
            "config pinned 198.51.100.0/24 to eth3 (rib egress eth2 shadowed); \
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
                },
                InterfaceLine {
                    name: "eth3".into(),
                    mode: UrpfMode::Loose,
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
}
