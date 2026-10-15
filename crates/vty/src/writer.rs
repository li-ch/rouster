//! The write path (S8-c M4): config-mode edits accumulate into the
//! canonical `rouster.conf` shape (the configd grammar,
//! `docs/protocols/config.md` §1), and `write file` / `write memory`
//! hands the merged document to `configd apply` — a process spawn of
//! the CLI surface, no IPC invention (the vty.md "Config apply" seam,
//! landed as its interim named: configd owns the transaction, vtyd
//! is the translator).
//!
//! The merge model, honest about what the vty grammar can speak:
//!
//! - **Modeled** lines are projected between the canonical file and
//!   the session tree both ways: `daemon rousterd`'s `ip`/`ipv6
//!   route <prefix> <gw|blackhole>` lines (the vty subset and
//!   rousterd's grammar are the same FRR cut), and `daemon bgpd`'s
//!   `router bgp <asn>` stanza — `bgp router-id`, `neighbor
//!   remote-as`, router-level `network` (bgpd has no address-family
//!   stanza; the vty AF node flattens into these, the recorded
//!   design), and `route-map` stanzas (bgpd's policy grammar eats
//!   them verbatim). Two modeled lines have NO bgpd grammar today —
//!   `bgp network import-check` and `redistribute static` — so they
//!   ride the canonical file as comments (`! bgp network
//!   import-check`), preserved for display, poisonous to nothing.
//! - **Everything else rides verbatim**: whole `daemon savd`/`bfdd`/
//!   `ospfd` sections, `zapi socket` and `table <N>` static forms
//!   under rousterd, bgpd policy stanzas beyond route-map, the
//!   configd-owned `router-id` top-level line, plain comments. A
//!   `write` never destroys config the vty grammar cannot speak.
//! - **Display-only directives** (`frr version`, `frr defaults`,
//!   `hostname`, `line vty` — no daemon consumes them from a file,
//!   the recorded design's rule) round-trip as `! vtyd:` comment
//!   lines: legal canonical comments, lossless, and `show
//!   running-config` shows exactly what `write` writes.
//!
//! `write memory` is `write file` here — one canonical file is both
//! the running and the startup config — disclosed at point of use.
//!
//! The backend blocks while configd runs (validation spawns, the
//! apply, post-signal verification — each internally bounded, the
//! whole child bounded by [`RUN_TIMEOUT`]). vtyd is an operator
//! surface, one command at a time; the connection waits, which is
//! what an operator at a `write` prompt expects anyway.

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use crate::config::{Af, Nexthop, SessionConfig};

/// Daemon sections in canonical render order (configd's registry
/// order: the RIB first, protocols after).
const DAEMON_ORDER: [&str; 5] = ["rousterd", "savd", "bfdd", "ospfd", "bgpd"];

/// How long the spawned configd may run in total (its validation,
/// apply, and verification passes are each internally bounded; this
/// is the outer belt so a wedged child cannot wedge a connection).
const RUN_TIMEOUT: Duration = Duration::from_secs(110);

/// The env var that pins the configd binary (the flagless fallback).
pub const CONFIGD_BIN_ENV: &str = "ROUSTER_CONFIGD_BIN";

/// What a `write` hands back to the operator: plain lines.
pub type WriteLines = Vec<String>;

/// The write path's actuator. The session calls [`WriteBackend::
/// write`] with the merged canonical text; the lines it returns are
/// the operator's output, verbatim.
pub trait WriteBackend: Send + Sync {
    fn write(&self, canonical: &str) -> WriteLines;
}

/// The canonical-document state a session merges onto: every line of
/// the existing canonical file the vty grammar does NOT model, kept
/// verbatim (with its original indentation) so a `write` round-trips
/// what it cannot speak.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CanonState {
    /// Unmodeled top-level lines, in file order (`router-id …`,
    /// plain comments).
    pub top: Vec<String>,
    /// Unmodeled body lines per daemon section, in file order.
    pub passthrough: Vec<(String, Vec<String>)>,
}

impl CanonState {
    /// Loads a canonical file, projecting the lines the vty grammar
    /// models into `config` and keeping everything else verbatim. A
    /// missing or unreadable file is an empty state (a fresh
    /// install: the first `write` creates the canonical). Tolerant,
    /// never panicking: a file configd would refuse surfaces at the
    /// `configd apply` the write spawns, with configd's own
    /// line-numbered complaint — the honest place for that error.
    pub fn load(path: &Path, config: &mut SessionConfig) -> CanonState {
        let mut state = CanonState::default();
        let Ok(text) = fs::read_to_string(path) else {
            return state;
        };
        let mut section: Option<(String, Vec<String>)> = None;
        for raw in text.lines() {
            let line = raw.trim_end();
            let trimmed = line.trim();
            if let Some((name, passthrough)) = &mut section {
                if trimmed == "}" {
                    state
                        .passthrough
                        .push((name.clone(), std::mem::take(passthrough)));
                    section = None;
                    continue;
                }
                project_or_keep(name, trimmed, line, config, passthrough);
                continue;
            }
            // Top level: a section opener, a vtyd display comment,
            // or an unmodeled line kept verbatim.
            if let Some(rest) = trimmed.strip_prefix("daemon ") {
                let name = rest.trim().strip_suffix('{').unwrap_or(rest).trim();
                if !name.is_empty() && !name.contains(char::is_whitespace) {
                    section = Some((name.to_string(), Vec::new()));
                    continue;
                }
            }
            if let Some(rest) = trimmed.strip_prefix("! vtyd: ") {
                feed_display(rest, config);
                continue;
            }
            state.top.push(line.to_string());
        }
        if let Some((name, passthrough)) = section {
            // An unclosed section: keep it verbatim rather than
            // dropping the operator's bytes (configd will refuse it
            // with the opener's line number if it really is broken).
            state.passthrough.push((name, passthrough));
        }
        state
    }

    /// This daemon's unmodeled body lines (empty when none).
    fn body(&self, daemon: &str) -> &[String] {
        self.passthrough
            .iter()
            .find(|(name, _)| name == daemon)
            .map(|(_, lines)| lines.as_slice())
            .unwrap_or(&[])
    }
}

/// Projects one section body line into the session tree when the vty
/// grammar models it; otherwise keeps the line verbatim.
fn project_or_keep(
    daemon: &str,
    trimmed: &str,
    raw: &str,
    config: &mut SessionConfig,
    passthrough: &mut Vec<String>,
) {
    let tokens: Vec<&str> = trimmed.split_whitespace().collect();
    match daemon {
        "rousterd" => {
            // Only the exact shapes the vty grammar can render back;
            // `table <N>` forms and everything else ride verbatim.
            match tokens.as_slice() {
                ["ip", "route", prefix, tail @ ..] if tail.len() <= 1 => {
                    if let Some(nexthop) = nexthop_of(tail.first().copied()) {
                        config.add_static(Af::V4, (*prefix).to_string(), nexthop);
                        return;
                    }
                }
                ["ipv6", "route", prefix, tail @ ..] if tail.len() <= 1 => {
                    if let Some(nexthop) = nexthop_of(tail.first().copied()) {
                        config.add_static(Af::V6, (*prefix).to_string(), nexthop);
                        return;
                    }
                }
                _ => {}
            }
            passthrough.push(raw.to_string());
        }
        "bgpd" => {
            match tokens.as_slice() {
                ["router", "bgp", asn] => {
                    config.bgp_open((*asn).to_string());
                    // Track "inside the stanza" implicitly: the child
                    // match arms below only parse right after a
                    // router line opened it... but bgpd accepts
                    // children anywhere after the stanza head, and
                    // interleaved stanzas divert to policy. Keep it
                    // simple and positional: model only the exact
                    // line shapes (they are unambiguous in bgpd's
                    // grammar regardless of stanza state).
                    return;
                }
                ["bgp", "router-id", id] => {
                    if let ModeledBgp::As(asn) = modeled_bgp(config) {
                        config.bgp_set_router_id(&asn, (*id).to_string());
                        return;
                    }
                }
                ["neighbor", addr, "remote-as", remote_as] => {
                    if let ModeledBgp::As(asn) = modeled_bgp(config) {
                        config.bgp_add_neighbor(
                            &asn,
                            (*addr).to_string(),
                            (*remote_as).to_string(),
                        );
                        return;
                    }
                }
                ["network", prefix] => {
                    if let ModeledBgp::As(asn) = modeled_bgp(config) {
                        config.af_add_network(&asn, (*prefix).to_string());
                        return;
                    }
                }
                // The two modeled-but-grammared-nowhere lines ride as
                // comments; load them back.
                ["!", "bgp", "network", "import-check"] => {
                    if let ModeledBgp::As(asn) = modeled_bgp(config) {
                        config.bgp_set_import_check(&asn, true);
                        return;
                    }
                }
                ["!", "no", "bgp", "network", "import-check"] => {
                    if let ModeledBgp::As(asn) = modeled_bgp(config) {
                        config.bgp_set_import_check(&asn, false);
                        return;
                    }
                }
                ["!", "redistribute", "static"] => {
                    if let ModeledBgp::As(asn) = modeled_bgp(config) {
                        config.af_add_redistribute_static(&asn);
                        return;
                    }
                }
                ["route-map", rest @ ..] if !rest.is_empty() => {
                    config.add_route_map(rest.join(" "));
                    return;
                }
                _ => {}
            }
            passthrough.push(raw.to_string());
        }
        _ => passthrough.push(raw.to_string()),
    }
}

/// The most recently opened modeled router-bgp stanza's AS (the
/// projection state for bgpd child lines): the LAST bgp entry in
/// the tree's document order.
enum ModeledBgp {
    As(String),
    None,
}

fn modeled_bgp(config: &SessionConfig) -> ModeledBgp {
    // Walk /router's bgp list entries; the tree keeps document
    // order, so the last entry is the most recently opened stanza.
    let base = yang::data::Path::parse("/router/bgp").expect("literal path");
    if let Some(node) = config.tree.get(&base) {
        if let yang::data::NodeKind::List(entries) = &node.kind {
            if let Some(last) = entries.last() {
                if let yang::data::NodeKind::Entry { keys, .. } = &last.kind {
                    if let Some((_, asn)) = keys.first() {
                        return ModeledBgp::As(asn.clone());
                    }
                }
            }
        }
    }
    ModeledBgp::None
}

/// A nexthop token to its modeled form (`blackhole` or an address).
fn nexthop_of(token: Option<&str>) -> Option<Nexthop> {
    match token {
        None => None, // bare `ip route <p>` is not the vty shape; keep verbatim
        Some("blackhole") => Some(Nexthop::Blackhole),
        Some(addr) if addr.parse::<std::net::IpAddr>().is_ok() => {
            Some(Nexthop::Addr((*addr).to_string()))
        }
        _ => None,
    }
}

/// Feeds a `! vtyd:` display comment back into the session tree.
fn feed_display(rest: &str, config: &mut SessionConfig) {
    let tokens: Vec<&str> = rest.split_whitespace().collect();
    match tokens.as_slice() {
        ["hostname", name] => config.set_hostname((*name).to_string()),
        ["frr", "version", version] => config.set_frr_version((*version).to_string()),
        ["frr", "defaults", profile] => config.set_frr_defaults((*profile).to_string()),
        ["line", "vty"] => config.set_line_vty(),
        _ => {}
    }
}

/// Renders the merged canonical document FROM THE SESSION TREE
/// (S11-a M5): the display-only directives as `! vtyd:` comments,
/// the unmodeled top-level lines verbatim, then one section per
/// daemon in registry order — the session's modeled lines first
/// (walked off the YANG tree's document order), the unmodeled body
/// verbatim after. This is what `write` writes and what `show
/// running-config` shows: one view, the canonical one.
pub fn render_canonical(config: &SessionConfig, doc: &CanonState) -> String {
    let mut out = String::new();
    // Display-only directives, in the tree's document order (the
    // operator's entry order).
    for line in display_directives(config) {
        out.push_str(&line);
        out.push('\n');
    }
    for line in &doc.top {
        out.push_str(line);
        out.push('\n');
    }
    for daemon in DAEMON_ORDER {
        let modeled = modeled_body(daemon, config);
        let passthrough = doc.body(daemon);
        if modeled.is_empty() && passthrough.is_empty() {
            continue;
        }
        out.push_str(&format!("daemon {daemon} {{\n"));
        // Modeled lines get the canonical indent; passthrough lines
        // ride byte-verbatim (their original indentation is the
        // operator's, cosmetic to every token-per-line grammar).
        for line in modeled {
            out.push_str("    ");
            out.push_str(&line);
            out.push('\n');
        }
        for line in passthrough {
            out.push_str(line);
            out.push('\n');
        }
        out.push_str("}\n");
    }
    // Any passthrough section under a name configd does not know
    // (cannot come from a configd-applied file, but the loader is
    // tolerant): keep it, verbatim, after the known sections.
    for (name, lines) in &doc.passthrough {
        if DAEMON_ORDER.contains(&name.as_str()) || lines.is_empty() {
            continue;
        }
        out.push_str(&format!("daemon {name} {{\n"));
        for line in lines {
            out.push_str(line);
            out.push('\n');
        }
        out.push_str("}\n");
    }
    out
}

/// The `! vtyd:` display comments, in the tree's document order.
fn display_directives(config: &SessionConfig) -> Vec<String> {
    use yang::data::NodeKind;
    let mut out = Vec::new();
    let path = |segs: &str| yang::data::Path::parse(segs).expect("literal path");
    for node in &config.tree.children {
        match (&node.name[..], &node.kind) {
            ("hostname", NodeKind::Leaf { value, .. }) => {
                out.push(format!("! vtyd: hostname {value}"));
            }
            ("frr", NodeKind::Container(children)) => {
                for child in children {
                    match (&child.name[..], &child.kind) {
                        ("version", NodeKind::Leaf { value, .. }) => {
                            out.push(format!("! vtyd: frr version {value}"));
                        }
                        ("defaults", NodeKind::Leaf { value, .. }) => {
                            out.push(format!("! vtyd: frr defaults {value}"));
                        }
                        _ => {}
                    }
                }
            }
            ("line", NodeKind::Container(children))
                if children.iter().any(|c| c.name == "vty") =>
            {
                out.push("! vtyd: line vty".to_string());
            }
            _ => {}
        }
    }
    let _ = path;
    out
}

/// The session's modeled body lines for one daemon section — walked
/// off the YANG tree (document order), projected to the canonical
/// grammar shapes.
fn modeled_body(daemon: &str, config: &SessionConfig) -> Vec<String> {
    use yang::data::{Node, NodeKind};
    let path = |segs: &str| yang::data::Path::parse(segs).expect("literal path");
    fn val(n: &Node) -> Option<&String> {
        match &n.kind {
            NodeKind::Leaf { value, .. } => Some(value),
            _ => None,
        }
    }
    let mut body = Vec::new();
    match daemon {
        "rousterd" => {
            // Static routes: one line per (prefix, nexthop), in the
            // tree's document order — v4 and v6 interleaved by their
            // containers' creation order.
            for af_container in ["ip", "ipv6"] {
                let af = if af_container == "ip" { Af::V4 } else { Af::V6 };
                let base = path(&format!("/{af_container}/route"));
                if let Some(Node {
                    kind: NodeKind::List(entries),
                    ..
                }) = config.tree.get(&base)
                {
                    for entry in entries {
                        let NodeKind::Entry { keys, children, .. } = &entry.kind else {
                            continue;
                        };
                        let Some((_, prefix)) = keys.first() else {
                            continue;
                        };
                        for node in children.iter().filter(|n| n.name == "nexthop") {
                            if let NodeKind::LeafList(values) = &node.kind {
                                for v in values {
                                    body.push(format!(
                                        "{} route {prefix} {}",
                                        af.keyword(),
                                        v.value
                                    ));
                                }
                            }
                        }
                    }
                }
            }
        }
        "bgpd" => {
            // Router stanzas in document order; route-map lines
            // after them (the tree stores them at the root — the
            // one ordering the flattened canonical form loses).
            let base = path("/router/bgp");
            if let Some(Node {
                kind: NodeKind::List(entries),
                ..
            }) = config.tree.get(&base)
            {
                for entry in entries {
                    let NodeKind::Entry { keys, children, .. } = &entry.kind else {
                        continue;
                    };
                    let Some((_, asn)) = keys.first() else {
                        continue;
                    };
                    body.push(format!("router bgp {asn}"));
                    for node in children {
                        match (&node.name[..], &node.kind) {
                            ("bgp", NodeKind::Container(bgp_children)) => {
                                for child in bgp_children {
                                    match (&child.name[..], &child.kind) {
                                        ("router-id", _) => {
                                            if let Some(id) = val(child) {
                                                body.push(format!("bgp router-id {id}"));
                                            }
                                        }
                                        ("network-import-check", _) => {
                                            if let Some(v) = val(child) {
                                                body.push(format!(
                                                    "! {}bgp network import-check",
                                                    if v == "true" { "" } else { "no " }
                                                ));
                                            }
                                        }
                                        _ => {}
                                    }
                                }
                            }
                            ("neighbor", NodeKind::List(nbs)) => {
                                for nb in nbs {
                                    let NodeKind::Entry { keys, children, .. } = &nb.kind else {
                                        continue;
                                    };
                                    let Some((_, addr)) = keys.first() else {
                                        continue;
                                    };
                                    let remote_as = children
                                        .iter()
                                        .find(|c| c.name == "remote-as")
                                        .and_then(val);
                                    if let Some(remote_as) = remote_as {
                                        body.push(format!("neighbor {addr} remote-as {remote_as}"));
                                    }
                                }
                            }
                            // Flattened to router level: bgpd's
                            // grammar has no address-family stanza
                            // (the recorded design).
                            ("address-family", NodeKind::Container(afs)) => {
                                for af_container in afs {
                                    if let NodeKind::Container(families) = &af_container.kind {
                                        for family in families {
                                            if let NodeKind::Container(unicast) = &family.kind {
                                                for leaf in unicast {
                                                    match (&leaf.name[..], &leaf.kind) {
                                                        ("network", NodeKind::LeafList(values)) => {
                                                            for v in values {
                                                                body.push(format!(
                                                                    "network {}",
                                                                    v.value
                                                                ));
                                                            }
                                                        }
                                                        ("redistribute", _)
                                                            if val(leaf).is_some() =>
                                                        {
                                                            body.push(
                                                                "! redistribute static"
                                                                    .to_string(),
                                                            );
                                                        }
                                                        _ => {}
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                            _ => {}
                        }
                    }
                }
            }
            for rm in config.tree.get_values(&path("/route-map")) {
                body.push(format!("route-map {rm}"));
            }
        }
        _ => {}
    }
    body
}

/// The real backend: stage the canonical file atomically, then spawn
/// `configd apply` over it (the CLI surface — no IPC invention) and
/// relay its report lines. Forwarded dirs match vtyd's own so the
/// container and the operator see one deployment shape.
pub struct ConfigdBackend {
    canonical: PathBuf,
    run_dir: PathBuf,
    etc_dir: PathBuf,
}

impl ConfigdBackend {
    pub fn new(canonical: PathBuf, run_dir: PathBuf, etc_dir: PathBuf) -> Self {
        ConfigdBackend {
            canonical,
            run_dir,
            etc_dir,
        }
    }
}

impl WriteBackend for ConfigdBackend {
    fn write(&self, canonical: &str) -> WriteLines {
        if let Err(err) = write_atomic(&self.canonical, canonical) {
            return vec![format!(
                "% Cannot write {}: {err}",
                self.canonical.display()
            )];
        }
        let Some(bin) = resolve_configd() else {
            return vec![
                format!(
                    "Canonical staged at {} — but no configd binary found \
                     (looked: ${CONFIGD_BIN_ENV}, vtyd's own dir, PATH).",
                    self.canonical.display()
                ),
                "% Write incomplete: the canonical file is NOT applied.".into(),
            ];
        };
        let mut command = Command::new(&bin);
        command
            .arg("apply")
            .arg(&self.canonical)
            .arg("--run-dir")
            .arg(&self.run_dir)
            .arg("--etc-dir")
            .arg(&self.etc_dir);
        match run_bounded(command) {
            Ok((Some(0), text)) => relay(text),
            Ok((code, text)) => {
                let mut out = vec![format!(
                    "% Configuration apply FAILED (configd exit {code:?}) — \
                     verify state, do not trust this line alone:"
                )];
                out.extend(relay(text));
                out
            }
            Err(note) => vec![format!(
                "% configd could not run ({note}); canonical staged at {}",
                self.canonical.display()
            )],
        }
    }
}

/// Relays configd's output lines (its own `configd:` prefix carries
/// the provenance), dropping empties.
fn relay(text: String) -> WriteLines {
    text.lines()
        .filter(|line| !line.trim().is_empty())
        .map(String::from)
        .collect()
}

/// Finds the configd binary: the env pin, vtyd's own executable dir
/// (the cargo target layout and every deployment image put the
/// suite's binaries side by side), then `PATH`.
fn resolve_configd() -> Option<PathBuf> {
    if let Ok(path) = std::env::var(CONFIGD_BIN_ENV) {
        let path = PathBuf::from(path);
        if is_executable(&path) {
            return Some(path);
        }
    }
    if let Ok(exe) = std::env::current_exe() {
        if let Some(dir) = exe.parent() {
            let candidate = dir.join("configd");
            if is_executable(&candidate) {
                return Some(candidate);
            }
        }
    }
    if let Ok(path) = std::env::var("PATH") {
        for dir in path.split(':').filter(|d| !d.is_empty()) {
            let candidate = PathBuf::from(dir).join("configd");
            if is_executable(&candidate) {
                return Some(candidate);
            }
        }
    }
    None
}

fn is_executable(path: &Path) -> bool {
    let Ok(meta) = fs::metadata(path) else {
        return false;
    };
    meta.is_file() && (meta.permissions().mode() & 0o111 != 0)
}

/// Runs a command with a hard total bound; kills the child if it
/// overruns. Returns the (exit code, combined stdout+stderr).
fn run_bounded(mut command: Command) -> Result<(Option<i32>, String), String> {
    command.stdin(Stdio::null());
    command.stdout(Stdio::piped());
    command.stderr(Stdio::piped());
    let mut child = command.spawn().map_err(|e| e.to_string())?;
    let deadline = Instant::now() + RUN_TIMEOUT;
    loop {
        match child.try_wait() {
            Ok(Some(status)) => {
                let mut text = String::new();
                if let Some(mut pipe) = child.stdout.take() {
                    let _ = std::io::Read::read_to_string(&mut pipe, &mut text);
                }
                if let Some(mut pipe) = child.stderr.take() {
                    let _ = std::io::Read::read_to_string(&mut pipe, &mut text);
                }
                return Ok((status.code(), text));
            }
            Ok(None) => {
                if Instant::now() >= deadline {
                    let _ = child.kill();
                    let _ = child.wait();
                    return Err("timed out".to_string());
                }
                std::thread::sleep(Duration::from_millis(20));
            }
            Err(err) => return Err(err.to_string()),
        }
    }
}

/// Temp + fsync + rename in the destination directory (a daemon or
/// configd never re-reads a half-written canonical).
fn write_atomic(dest: &Path, text: &str) -> std::io::Result<()> {
    use std::io::Write;
    let dir = dest.parent().unwrap_or_else(|| Path::new("."));
    fs::create_dir_all(dir)?;
    let name = dest
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| "canonical".into());
    let temp = dir.join(format!(".{name}.vtyd-tmp-{}", std::process::id()));
    let mut file = fs::File::create(&temp)?;
    file.write_all(text.as_bytes())?;
    file.sync_all()?;
    drop(file);
    match fs::rename(&temp, dest) {
        Ok(()) => Ok(()),
        Err(err) => {
            let _ = fs::remove_file(&temp);
            Err(err)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scratch(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "vty-writer-{tag}-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    const CANONICAL: &str = "\
router-id 198.51.100.1
! operator comment
daemon rousterd {
    zapi socket /run/rouster/zserv.api
    ip route 203.0.113.0/24 blackhole
    ip route 198.51.100.0/24 192.0.2.1
    ipv6 route 2001:db8::/32 blackhole
}
daemon savd {
    mode strict
    poll 2
}
daemon bgpd {
    router bgp 65000
    bgp router-id 192.0.2.254
    neighbor 192.0.2.2 remote-as 65001
    network 203.0.113.0/24
    route-map RM-IN permit 10
}
";

    #[test]
    fn load_projects_the_modeled_lines_and_keeps_the_rest() {
        let dir = scratch("load");
        let path = dir.join("rouster.conf");
        fs::write(&path, CANONICAL).unwrap();
        let mut config = SessionConfig::new();
        let state = CanonState::load(&path, &mut config);

        // Modeled (S11-a M5): the tree carries the statics, the bgp
        // stanza, the route-map — asserted through the tree paths.
        let p = |segs: &str| yang::data::Path::parse(segs).unwrap();
        assert_eq!(
            config
                .tree
                .get_values(&p("/ip/route[prefix=203.0.113.0/24]/nexthop")),
            vec!["blackhole".to_string()]
        );
        assert_eq!(
            config
                .tree
                .get_values(&p("/ip/route[prefix=198.51.100.0/24]/nexthop")),
            vec!["192.0.2.1".to_string()]
        );
        assert_eq!(
            config
                .tree
                .get_values(&p("/ipv6/route[prefix=2001:db8::/32]/nexthop")),
            vec!["blackhole".to_string()]
        );
        assert!(config
            .tree
            .get_value(&p("/router/bgp[local-as=65000]/bgp/router-id"))
            .is_some());
        assert_eq!(
            config.tree.get_values(&p("/route-map")),
            vec!["RM-IN permit 10".to_string()]
        );

        // Kept verbatim: the top-level lines, zapi socket (original
        // indentation included), the whole savd section.
        assert_eq!(
            state.top,
            vec!["router-id 198.51.100.1", "! operator comment"]
        );
        assert_eq!(
            state.body("rousterd"),
            ["    zapi socket /run/rouster/zserv.api"]
        );
        assert_eq!(state.body("savd").len(), 2);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn render_is_the_merged_canonical_and_round_trips() {
        let dir = scratch("render");
        let path = dir.join("rouster.conf");
        fs::write(&path, CANONICAL).unwrap();
        let mut config = SessionConfig::new();
        let state = CanonState::load(&path, &mut config);

        // Session edits: add a static, drop another.
        config.add_static(
            Af::V4,
            "198.18.0.0/15".into(),
            Nexthop::Addr("192.0.2.9".into()),
        );
        config.remove_static(Af::V4, "203.0.113.0/24", Some(&Nexthop::Blackhole));
        config.set_frr_version("10.2".into());

        let text = render_canonical(&config, &state);
        for needle in [
            "! vtyd: frr version 10.2",
            "router-id 198.51.100.1",
            "daemon rousterd {",
            "zapi socket /run/rouster/zserv.api",
            "ip route 198.51.100.0/24 192.0.2.1",
            "ip route 198.18.0.0/15 192.0.2.9",
            "ipv6 route 2001:db8::/32 blackhole",
            "daemon savd {\n    mode strict\n    poll 2\n}",
            "daemon bgpd {",
            "router bgp 65000",
            "bgp router-id 192.0.2.254",
            "neighbor 192.0.2.2 remote-as 65001",
            "network 203.0.113.0/24",
            "route-map RM-IN permit 10",
        ] {
            assert!(text.contains(needle), "missing {needle:?} in:\n{text}");
        }
        assert!(
            !text.contains("ip route 203.0.113.0/24"),
            "the removed static must not ride through:\n{text}"
        );

        // Round-trip: reloading the render and rendering AGAIN yields
        // byte-identical text (render-stability — node entry order
        // may differ across the load, the canonical bytes may not).
        let round = dir.join("round-trip.conf");
        fs::write(&round, &text).unwrap();
        let mut reloaded = SessionConfig::new();
        let restate = CanonState::load(&round, &mut reloaded);
        assert_eq!(render_canonical(&reloaded, &restate), text);
        assert_eq!(restate.top, state.top);
        assert_eq!(restate.body("savd"), state.body("savd"));
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn display_directives_round_trip_through_the_vtyd_comments() {
        let mut config = SessionConfig::new();
        config.set_hostname("edge-1".into());
        config.set_frr_version("10.2".into());
        config.set_frr_defaults("traditional".into());
        config.set_line_vty();
        let text = render_canonical(&config, &CanonState::default());
        // Entry order is the rule (the display directives render in
        // the order the operator set them).
        assert_eq!(
            text,
            "! vtyd: hostname edge-1\n\
             ! vtyd: frr version 10.2\n\
             ! vtyd: frr defaults traditional\n\
             ! vtyd: line vty\n"
        );
        // And back.
        let dir = scratch("display");
        let path = dir.join("rouster.conf");
        fs::write(&path, &text).unwrap();
        let mut reloaded = SessionConfig::new();
        CanonState::load(&path, &mut reloaded);
        assert_eq!(reloaded, config);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_missing_canonical_is_an_empty_state() {
        let mut config = SessionConfig::new();
        let state = CanonState::load(Path::new("/nonexistent/rouster.conf"), &mut config);
        assert_eq!(state, CanonState::default());
        assert!(config.tree.source_lines().is_empty());
    }

    #[test]
    fn unmodeled_static_forms_ride_verbatim_not_half_modeled() {
        let dir = scratch("tableform");
        let path = dir.join("rouster.conf");
        fs::write(
            &path,
            "daemon rousterd {\n    ip route 10.0.0.0/8 192.0.2.1 table 100\n}\n",
        )
        .unwrap();
        let mut config = SessionConfig::new();
        let state = CanonState::load(&path, &mut config);
        assert!(
            config.tree.source_lines().is_empty(),
            "the table form is not modeled"
        );
        // Kept verbatim, original indentation included.
        assert_eq!(
            state.body("rousterd"),
            ["    ip route 10.0.0.0/8 192.0.2.1 table 100"]
        );
        // And rendering keeps it byte-identical.
        let text = render_canonical(&config, &state);
        assert!(text.contains("ip route 10.0.0.0/8 192.0.2.1 table 100\n"));
        let _ = fs::remove_dir_all(&dir);
    }

    /// Configd discovery goes through the process env
    /// ([`CONFIGD_BIN_ENV`]), so every discovery-touching test holds
    /// this lock for its whole body (env is process-global; the
    /// tests run on parallel threads).
    static ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    /// A configd stand-in: exits 0 and says so, or exits 1 when the
    /// staged canonical contains the marker word.
    struct StandinConfigd {
        canonical: PathBuf,
        run_dir: PathBuf,
    }

    impl WriteBackend for StandinConfigd {
        fn write(&self, canonical: &str) -> WriteLines {
            let backend = ConfigdBackend::new(
                self.canonical.clone(),
                self.run_dir.clone(),
                PathBuf::from("/nonexistent-etc"),
            );
            std::env::set_var(CONFIGD_BIN_ENV, standin_script(&self.run_dir));
            backend.write(canonical)
        }
    }

    fn standin_script(dir: &Path) -> PathBuf {
        let path = dir.join("configd");
        fs::write(
            &path,
            "#!/bin/sh\n\
             case \"$1 $2\" in\n\
             'apply '*)\n\
             if grep -q REFUSE-ME \"$2\"; then \
             echo 'configd: savd: line 3: standin refusal' >&2; exit 1; fi; \
             echo 'configd: savd -> /etc/savd.conf (18 bytes), not running'; \
             echo 'configd: generation 7 recorded (hash abc)'; exit 0;;\n\
             esac\n\
             exit 2\n",
        )
        .unwrap();
        let mut perms = fs::metadata(&path).unwrap().permissions();
        use std::os::unix::fs::PermissionsExt;
        perms.set_mode(0o755);
        fs::set_permissions(&path, perms).unwrap();
        path
    }

    #[test]
    fn the_backend_stages_and_spawns_and_relays() {
        let _env = ENV_LOCK.lock().unwrap();
        let dir = scratch("backend");
        let backend = StandinConfigd {
            canonical: dir.join("rouster.conf"),
            run_dir: dir.clone(),
        };
        let lines = backend.write("daemon savd {\nmode strict\n}\n");
        std::env::remove_var(CONFIGD_BIN_ENV);
        assert!(
            lines.iter().any(|l| l.contains("generation 7 recorded")),
            "{lines:?}"
        );
        assert!(lines.iter().any(|l| l.contains("savd -> ")), "{lines:?}");
        // The canonical was staged where configd was told to look.
        assert_eq!(
            fs::read_to_string(dir.join("rouster.conf")).unwrap(),
            "daemon savd {\nmode strict\n}\n"
        );
        // No temp litter in the staging dir.
        assert_eq!(fs::read_dir(&dir).unwrap().count(), 2); // rouster.conf + configd
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_configd_refusal_relays_the_failure_shape() {
        let _env = ENV_LOCK.lock().unwrap();
        let dir = scratch("refuse");
        let backend = StandinConfigd {
            canonical: dir.join("rouster.conf"),
            run_dir: dir.clone(),
        };
        let lines = backend.write("daemon savd {\nmode REFUSE-ME\n}\n");
        std::env::remove_var(CONFIGD_BIN_ENV);
        assert!(
            lines
                .iter()
                .any(|l| l.starts_with("% Configuration apply FAILED")),
            "{lines:?}"
        );
        assert!(
            lines.iter().any(|l| l.contains("standin refusal")),
            "{lines:?}"
        );
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_missing_configd_is_staged_not_applied() {
        let _env = ENV_LOCK.lock().unwrap();
        let dir = scratch("nobin");
        // Point the env pin at a nonexistent binary; the fallbacks
        // (vtyd's own dir, PATH) find no configd in the test
        // environment.
        std::env::set_var(CONFIGD_BIN_ENV, dir.join("no-such-configd"));
        let backend = ConfigdBackend::new(
            dir.join("rouster.conf"),
            dir.clone(),
            PathBuf::from("/nonexistent-etc"),
        );
        let lines = backend.write("daemon savd {\nmode strict\n}\n");
        std::env::remove_var(CONFIGD_BIN_ENV);
        assert!(
            lines.iter().any(|l| l.contains("no configd binary found")),
            "{lines:?}"
        );
        assert!(
            lines.iter().any(|l| l.starts_with("% Write incomplete")),
            "{lines:?}"
        );
        // The canonical is still staged (the operator can apply it
        // by hand once configd exists).
        assert!(dir.join("rouster.conf").exists());
        let _ = fs::remove_dir_all(&dir);
    }
}
