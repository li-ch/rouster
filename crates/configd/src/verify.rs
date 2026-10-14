//! Post-signal acknowledgment verification (S8-c M3): after apply +
//! SIGHUP, re-read each signaled daemon's published status file and
//! confirm the daemon actually LOADED the new config — the machinery
//! behind auto-rollback-on-failure (S7-c §Deferred-4).
//!
//! What each daemon can honestly report today (the run-dir contract,
//! `docs/operator-surfaces.md` §2):
//!
//! | Daemon | Ack surface | Check |
//! |---|---|---|
//! | `savd` | `savd.status`'s `config` line | the projection of the rendered body — `poll <N>s`, `interfaces <n>`, `bindings <n>` — appears in the status |
//! | `bfdd` | `bfdd.status`'s session lines | every `peer <ip>` in the rendered body appears in a `session peer <ip>` line (subset: dynamic zapi sessions must not cause false failures; a refused *removal* is therefore not detected — disclosed) |
//! | `rousterd` | none | `rousterd.status` carries interface/route tables, not config content — no ack surface today (`no-ack-surface`, §Deferred) |
//! | `ospfd`/`bgpd` | — | never signaled (no SIGHUP arm); nothing to verify |
//!
//! The decision procedure per polled daemon (deadline-bounded):
//!
//! - status content **matches** the projection → `confirmed` (the
//!   SIGHUP arm publishes immediately after its reload, so this is
//!   fast on success);
//! - the status was **rewritten after the signal** (mtime advanced
//!   past the pre-signal stat — or the file did not exist before)
//!   and the content **does not match** → `failed`: the daemon's own
//!   current word disagrees with the rendered config, which is
//!   exactly a refused reload (the daemon keeps its running config
//!   and keeps republishing it);
//! - deadline hit with neither → `unverified` (never a rollback
//!   trigger: absence of evidence is not evidence — the
//!   verify-state-never-trust-rc discipline);
//! - no status file ever appeared → `no-status`.
//!
//! A `failed` verdict drives [`crate::apply`]'s auto-rollback: the
//! previous generation's bytes are re-applied as a NEW generation and
//! the apply reports failure.
//!
//! The savd projection needs the daemon's default poll cadence when
//! the rendered body has no `poll` line: 5 s, savd's
//! `DEFAULT_POLL_SECS` (configd cannot depend on the sav crate — the
//! manifest fence — so the constant is mirrored here, disclosed in
//! docs/protocols/config.md, and pinned by test against the real
//! savd.status shape).

use std::path::Path;
use std::time::{Duration, SystemTime};

use common::rundir;

use crate::tree::Daemon;

/// How long to wait for a daemon's post-signal status rewrite.
pub const VERIFY_TIMEOUT: Duration = Duration::from_secs(10);
/// The poll cadence while waiting.
const POLL_INTERVAL: Duration = Duration::from_millis(100);
/// savd's default poll cadence (`sav::savd::DEFAULT_POLL_SECS`,
/// mirrored — no cross-crate dependency; the manifest fence).
const SAVD_DEFAULT_POLL_SECS: u64 = 5;

/// One daemon's verification verdict.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Ack {
    /// The daemon's status carries the rendered config's projection.
    Confirmed,
    /// The daemon publishes no status file at all.
    NoStatus,
    /// The daemon's status file carries no config ack surface
    /// (rousterd today).
    NoSurface,
    /// Deadline hit without a confirming or refuting rewrite.
    Unverified,
    /// The daemon's rewritten status disagrees with the rendered
    /// config — a refused reload. `expected`/`seen` are
    /// operator-facing summaries.
    Failed { expected: String, seen: String },
}

impl Ack {
    /// The status-file/CLI word.
    pub fn word(&self) -> &'static str {
        match self {
            Ack::Confirmed => "confirmed",
            Ack::NoStatus => "no-status",
            Ack::NoSurface => "no-ack-surface",
            Ack::Unverified => "unverified",
            Ack::Failed { .. } => "failed",
        }
    }
}

/// The savd projection of a rendered `daemon savd` body: the three
/// countable knobs the status `config` line carries.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SavdProjection {
    pub poll_secs: u64,
    pub interfaces: u64,
    pub bindings: u64,
}

impl SavdProjection {
    /// Projects a rendered savd body (the pre-apply gate has already
    /// guaranteed it parses, so line scanning is safe).
    pub fn of(rendered: &str) -> Self {
        let mut poll_secs = SAVD_DEFAULT_POLL_SECS;
        let mut interfaces = 0;
        let mut bindings = 0;
        for line in rendered.lines() {
            let mut tokens = line.split_whitespace();
            match tokens.next() {
                Some("poll") => {
                    if let Some(value) = tokens.next().and_then(|t| t.parse().ok()) {
                        poll_secs = value;
                    }
                }
                Some("interface") => interfaces += 1,
                Some("binding") => bindings += 1,
                _ => {}
            }
        }
        Self {
            poll_secs,
            interfaces,
            bindings,
        }
    }

    fn render(&self) -> String {
        format!(
            "poll {}s interfaces {} bindings {}",
            self.poll_secs, self.interfaces, self.bindings
        )
    }
}

/// Checks a savd.status text against the projection. `None` when the
/// status does not carry a complete enough `config` line to judge
/// (no-evidence, not failure).
fn check_savd(status_text: &str, expected: &SavdProjection) -> Option<bool> {
    let config = &rundir::parse_savd(status_text).config;
    match (config.poll_secs, config.interfaces, config.bindings) {
        (Some(poll), Some(ifaces), Some(bindings)) => Some(
            poll == expected.poll_secs
                && ifaces == expected.interfaces
                && bindings == expected.bindings,
        ),
        _ => None,
    }
}

/// The bfdd projection: the peer addresses of the rendered body.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BfddProjection {
    pub peers: Vec<String>,
}

impl BfddProjection {
    pub fn of(rendered: &str) -> Self {
        let mut peers = Vec::new();
        for line in rendered.lines() {
            let mut tokens = line.split_whitespace();
            if tokens.next() == Some("peer") {
                if let Some(peer) = tokens.next() {
                    peers.push(peer.to_string());
                }
            }
        }
        Self { peers }
    }

    fn render(&self) -> String {
        format!("peers {:?}", self.peers)
    }
}

/// Checks a bfdd.status text against the projection (subset
/// semantics: every configured peer must appear in a session line;
/// extra dynamic sessions are fine). `None` when the status carries
/// no session lines to judge with.
fn check_bfdd(status_text: &str, expected: &BfddProjection) -> Option<bool> {
    let status = rundir::parse_bfdd(status_text);
    if status.sessions.is_empty() {
        return None;
    }
    let live: Vec<&str> = status
        .sessions
        .iter()
        .filter_map(|session| session.peer.as_deref())
        .collect();
    Some(
        expected
            .peers
            .iter()
            .all(|peer| live.contains(&peer.as_str())),
    )
}

/// The ack surface a daemon exposes (`None` = the daemon is never a
/// verification candidate).
pub fn ack_file(daemon: Daemon, run_dir: &Path) -> Option<std::path::PathBuf> {
    match daemon {
        Daemon::Savd => Some(run_dir.join("savd.status")),
        Daemon::Bfdd => Some(run_dir.join("bfdd.status")),
        Daemon::Rousterd | Daemon::Ospfd | Daemon::Bgpd => None,
    }
}

/// The projection a daemon's rendered body is checked against
/// (rousterd/ospfd/bgpd have none).
pub fn projection(daemon: Daemon, rendered: &str) -> Option<Projection> {
    match daemon {
        Daemon::Savd => Some(Projection::Savd(SavdProjection::of(rendered))),
        Daemon::Bfdd => Some(Projection::Bfdd(BfddProjection::of(rendered))),
        Daemon::Rousterd | Daemon::Ospfd | Daemon::Bgpd => None,
    }
}

/// A daemon's expected-config projection.
pub enum Projection {
    Savd(SavdProjection),
    Bfdd(BfddProjection),
}

impl Projection {
    fn check(&self, status_text: &str) -> Option<bool> {
        match self {
            Projection::Savd(expected) => check_savd(status_text, expected),
            Projection::Bfdd(expected) => check_bfdd(status_text, expected),
        }
    }

    fn render(&self) -> String {
        match self {
            Projection::Savd(expected) => expected.render(),
            Projection::Bfdd(expected) => expected.render(),
        }
    }
}

/// Verifies one signaled daemon: polls its status file until the
/// projection is confirmed, refuted (a post-signal rewrite that
/// disagrees), or the deadline passes. `pre_signal_mtime` is the
/// file's mtime captured BEFORE the SIGHUP (`None` = the file did
/// not exist).
pub fn verify(
    daemon: Daemon,
    status_path: &Path,
    pre_signal_mtime: Option<SystemTime>,
    expected: &Projection,
    deadline: std::time::Instant,
) -> Ack {
    let mut saw_file = false;
    loop {
        match std::fs::read_to_string(status_path) {
            Ok(text) => {
                saw_file = true;
                match expected.check(&text) {
                    Some(true) => return Ack::Confirmed,
                    Some(false) => {
                        // A disagreement only counts once the daemon
                        // has spoken since the signal: a stale
                        // pre-signal file is no evidence.
                        let rewritten = match pre_signal_mtime {
                            None => true,
                            Some(pre) => mtime_of(status_path).is_none_or(|now| now > pre),
                        };
                        if rewritten {
                            return Ack::Failed {
                                expected: expected.render(),
                                seen: config_summary(daemon, &text),
                            };
                        }
                    }
                    None => {} // not enough signal to judge
                }
            }
            Err(_) if !saw_file => { /* no file yet */ }
            Err(_) => return Ack::NoStatus, // existed, then vanished
        }
        if std::time::Instant::now() >= deadline {
            return if saw_file {
                Ack::Unverified
            } else {
                Ack::NoStatus
            };
        }
        std::thread::sleep(POLL_INTERVAL);
    }
}

/// The file's mtime, if it can be read.
fn mtime_of(path: &Path) -> Option<SystemTime> {
    std::fs::metadata(path).ok().and_then(|m| m.modified().ok())
}

/// A one-line summary of what the daemon's status actually says (the
/// `seen` half of a failure).
fn config_summary(daemon: Daemon, status_text: &str) -> String {
    match daemon {
        Daemon::Savd => {
            let config = &rundir::parse_savd(status_text).config;
            format!(
                "poll {} interfaces {} bindings {}",
                config
                    .poll_secs
                    .map(|p| format!("{p}s"))
                    .unwrap_or_else(|| "?".into()),
                config
                    .interfaces
                    .map(|n| n.to_string())
                    .unwrap_or_else(|| "?".into()),
                config
                    .bindings
                    .map(|n| n.to_string())
                    .unwrap_or_else(|| "?".into()),
            )
        }
        Daemon::Bfdd => {
            let status = rundir::parse_bfdd(status_text);
            let peers: Vec<&str> = status
                .sessions
                .iter()
                .filter_map(|s| s.peer.as_deref())
                .collect();
            format!("peers {:?}", peers)
        }
        Daemon::Rousterd | Daemon::Ospfd | Daemon::Bgpd => "no ack surface".to_string(),
    }
}

/// Captures a status file's mtime BEFORE the signal (the comparison
/// point for "the daemon has spoken since").
pub fn pre_signal_mtime(daemon: Daemon, run_dir: &Path) -> Option<SystemTime> {
    ack_file(daemon, run_dir).and_then(|path| mtime_of(&path))
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAVD_STATUS: &str = "savd 0.0.0 pid 4242\n\
        config mode strict-uRPF action monitor poll 3s interfaces 2 bindings 0 collision ignore hysteresis 3s backend rp_filter\n\
        installed 2 rules\n\
        rule allow if#2 [198.51.100.0/24] strict monitor\n";

    const BFDD_STATUS: &str = "bfdd 0.0.0 pid 4243\n\
        peers 2\n\
        dropped-degraded-ttl 0\n\
        session peer 192.0.2.9 state Down diag None local-discr 1 remote-discr 0 detection-time 2700ms tx-interval 300ms\n\
        session peer 198.51.100.9 state Down diag None local-discr 2 remote-discr 0 detection-time 2700ms tx-interval 300ms\n";

    #[test]
    fn savd_projection_counts_the_rendered_body() {
        assert_eq!(
            SavdProjection::of("mode strict\ninterface veths1\n  mode strict\npoll 3\n"),
            SavdProjection {
                poll_secs: 3,
                interfaces: 1,
                bindings: 0
            }
        );
        // No poll line: savd's default cadence (mirrored constant).
        assert_eq!(SavdProjection::of("").poll_secs, 5);
        // `binding` lines count; comments do not.
        assert_eq!(
            SavdProjection::of("! binding not a line\nbinding 192.0.2.0/24 interface veths1\n")
                .bindings,
            1
        );
    }

    #[test]
    fn savd_check_confirms_the_real_status_shape() {
        let expected = SavdProjection::of("interface veths1\ninterface veths2\npoll 3\n");
        assert_eq!(check_savd(SAVD_STATUS, &expected), Some(true));
        let stale = SavdProjection::of("interface veths1\npoll 2\n");
        assert_eq!(check_savd(SAVD_STATUS, &stale), Some(false));
        // An incomplete config line is no evidence, not a failure.
        assert_eq!(check_savd("savd 0.0.0 pid 1\n", &expected), None);
    }

    #[test]
    fn bfdd_projection_reads_peer_lines() {
        assert_eq!(
            BfddProjection::of(
                "peer 192.0.2.9\n  transmit-interval 300\npeer 198.51.100.9 multihop\n"
            )
            .peers,
            vec!["192.0.2.9".to_string(), "198.51.100.9".to_string()]
        );
    }

    #[test]
    fn bfdd_check_is_subset_so_dynamic_sessions_cannot_false_fail() {
        let expected = BfddProjection {
            peers: vec!["192.0.2.9".to_string()],
        };
        // The status holds BOTH configured peers plus one unknown
        // dynamic session: subset passes.
        let with_dynamic = format!("{BFDD_STATUS}session peer 203.0.113.9 state Up diag None local-discr 3 remote-discr 9 detection-time 900ms tx-interval 300ms\n");
        assert_eq!(check_bfdd(&with_dynamic, &expected), Some(true));
        // A configured peer missing from the sessions: failure.
        let missing = BfddProjection {
            peers: vec![
                "192.0.2.9".to_string(),
                "198.51.100.9".to_string(),
                "203.0.113.9".to_string(),
            ],
        };
        assert_eq!(check_bfdd(BFDD_STATUS, &missing), Some(false));
        // No sessions at all: no evidence.
        assert_eq!(check_bfdd("bfdd 0.0.0 pid 1\npeers 0\n", &expected), None);
    }

    #[test]
    fn verify_confirms_immediately_when_the_status_already_matches() {
        let dir = std::env::temp_dir().join(format!(
            "configd-verify-fast-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let status = dir.join("savd.status");
        std::fs::write(&status, SAVD_STATUS).unwrap();
        let pre = mtime_of(&status);
        let expected = Projection::Savd(SavdProjection::of(
            "interface veths1\ninterface veths2\npoll 3\n",
        ));
        let ack = verify(
            Daemon::Savd,
            &status,
            pre,
            &expected,
            std::time::Instant::now() + VERIFY_TIMEOUT,
        );
        assert_eq!(ack, Ack::Confirmed);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn verify_fails_only_after_a_post_signal_rewrite() {
        let dir = std::env::temp_dir().join(format!(
            "configd-verify-rewrite-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let status = dir.join("savd.status");
        // The daemon keeps its OLD config (a refused reload): the
        // file starts stale, then the daemon's next poll tick
        // rewrites it — still old values.
        std::fs::write(&status, SAVD_STATUS.replace("poll 3s", "poll 2s")).unwrap();
        let pre = mtime_of(&status);
        let expected = Projection::Savd(SavdProjection::of(
            "interface veths1\ninterface veths2\npoll 3\n",
        ));

        // A background "daemon" rewrites the status a moment later
        // (the poll-tick republish).
        let rewriter = dir.join("savd.status");
        std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(250));
            std::fs::write(&rewriter, SAVD_STATUS.replace("poll 3s", "poll 2s")).unwrap();
        });

        let ack = verify(
            Daemon::Savd,
            &status,
            pre,
            &expected,
            std::time::Instant::now() + VERIFY_TIMEOUT,
        );
        match ack {
            Ack::Failed { expected, seen } => {
                assert!(expected.contains("poll 3s"), "{expected}");
                assert!(seen.contains("poll 2s"), "{seen}");
            }
            other => panic!("expected Failed, got {other:?}"),
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_stale_file_with_no_rewrite_is_unverified_not_failed() {
        let dir = std::env::temp_dir().join(format!(
            "configd-verify-stale-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let status = dir.join("savd.status");
        std::fs::write(&status, SAVD_STATUS.replace("poll 3s", "poll 2s")).unwrap();
        let pre = mtime_of(&status);
        let expected = Projection::Savd(SavdProjection::of("poll 9\n"));
        // Short deadline: the file is never rewritten, so absence of
        // evidence must come back unverified.
        let ack = verify(
            Daemon::Savd,
            &status,
            pre,
            &expected,
            std::time::Instant::now() + Duration::from_millis(300),
        );
        assert_eq!(ack, Ack::Unverified);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_daemon_that_never_published_is_no_status() {
        let dir = std::env::temp_dir().join(format!(
            "configd-verify-none-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let expected = Projection::Bfdd(BfddProjection::of("peer 192.0.2.9\n"));
        let ack = verify(
            Daemon::Bfdd,
            &dir.join("bfdd.status"),
            None,
            &expected,
            std::time::Instant::now() + Duration::from_millis(200),
        );
        assert_eq!(ack, Ack::NoStatus);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn only_savd_and_bfdd_carry_an_ack_surface() {
        let run_dir = Path::new("/run/rouster");
        assert_eq!(ack_file(Daemon::Rousterd, run_dir), None);
        assert_eq!(ack_file(Daemon::Ospfd, run_dir), None);
        assert_eq!(ack_file(Daemon::Bgpd, run_dir), None);
        assert_eq!(
            ack_file(Daemon::Savd, run_dir),
            Some(run_dir.join("savd.status"))
        );
        assert_eq!(
            ack_file(Daemon::Bfdd, run_dir),
            Some(run_dir.join("bfdd.status"))
        );
        // And the projection mirrors that.
        assert!(projection(Daemon::Rousterd, "ip route 1.2.3.0/24 blackhole\n").is_none());
        assert!(projection(Daemon::Savd, "mode strict\n").is_some());
    }
}
