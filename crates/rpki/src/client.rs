//! The RTR session client: one cache connection driven into the
//! shared VRP/ASPA tables.
//!
//! Session shape per RFC 8210 §8 (8210bis-27 §8): connect, then the
//! router MUST open with a Reset Query (or a Serial Query when it
//! holds unexpired data and remembers the Session ID, §8.1); the cache
//! answers Cache Response → payload PDUs → End of Data. Timing follows
//! the End-of-Data intervals (§6): refresh polls double as the
//! application-layer keep-alive (§8.1), failed polls retry after the
//! Retry Interval, and data is flushed once the Expire Interval passes
//! without a successful poll. Errors follow §12: fatal codes drop the
//! session and flush everything learned from the cache; No Data
//! Available (2), Unsupported Protocol Version (4) and Cache
//! Restart/Shutdown (12/13) are non-fatal. Version negotiation is
//! §7/bis-§7: start at [`HIGHEST_VERSION`], downgrade to the version
//! an Error Code 4 names unless that version already failed, and abort
//! the transport once version 0 has failed.
//!
//! The clock is tokio's (`tokio::time`), so tests run it paused and
//! auto-advanced; no wall-clock reads anywhere in the client.

use std::collections::BTreeSet;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, TcpStream as Stream};
use tokio::sync::mpsc;
use tokio::sync::watch;
use tokio::time::{sleep_until, Instant};

use crate::aspa::AspaTable;
use crate::pdu::{be_u32_len, DecodeError, ErrorCode, Pdu, Timing, HIGHEST_VERSION, VERSION_0};
use crate::vrp::{Vrp, VrpTable};

/// Default RTR port (RFC 8210 §9, service "rpki-rtr").
pub const DEFAULT_CACHE_PORT: u16 = crate::pdu::RTR_PORT;

/// Cap on the Erroneous PDU copy inside an Error Report we send
/// (RFC 8210 §5.11 allows truncation for over-long PDUs).
const ERROR_ENCAPSULATION_MAX: usize = 1024;

/// One BGPsec router key, pass-through storage (RFC 8210 §5.10: the
/// router compares {SKI, ASN, Subject Public Key} tuples, never
/// parsing the SPKI).
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct RouterKeyEntry {
    pub asn: u32,
    pub ski: [u8; 20],
    pub spki: Vec<u8>,
}

/// How much of the cache-session state machine is visible outside the
/// client — the data view bgpd's policy engine cares about.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum CacheState {
    /// No usable data: never connected, flushed after a fatal error /
    /// cache shutdown, or expired past the Expire Interval.
    #[default]
    None,
    /// Transport up, protocol version not yet agreed (RFC 8210 §7).
    Negotiating,
    /// A Cache Response is open; payload PDUs are being applied.
    Receiving,
    /// A full (Reset Query) load completed; serial armed for
    /// incremental updates (RFC 8210 §8.1).
    Fresh,
    /// An incremental (Serial Query) exchange completed (§8.2).
    Serial,
    /// The cache answered Error Code 2 (§8.4).
    NoData,
}

/// Everything one cache session teaches the local router.
#[derive(Debug, Default)]
pub struct CacheTables {
    pub vrps: VrpTable,
    pub aspa: AspaTable,
    pub router_keys: BTreeSet<RouterKeyEntry>,
    pub state: CacheState,
    pub session_id: Option<u16>,
    pub serial: Option<u32>,
    pub timing: Option<Timing>,
    pub protocol_version: Option<u8>,
}

impl CacheTables {
    /// Flush all data learned from the cache (RFC 8210 §5.1 on
    /// session-id change; bis §12 on fatal errors; §6 on expiry).
    pub fn flush(&mut self) {
        self.vrps.clear();
        self.aspa.clear();
        self.router_keys.clear();
        self.state = CacheState::None;
        self.session_id = None;
        self.serial = None;
        self.timing = None;
        self.protocol_version = None;
    }
}

/// The shared handle a consumer (bgpd import policy) reads through.
pub type SharedTables = Arc<Mutex<CacheTables>>;

/// Client configuration. Everything timing-related comes from the
/// cache's End-of-Data PDUs (RFC 8210 §6); before the first
/// successful poll the client reconnects on a short fixed delay (see
/// [`FAST_RECONNECT`]) and retries a No-Data cache on the §6 default
/// Retry Interval.
#[derive(Debug, Clone)]
pub struct ClientConfig {
    pub cache_addr: SocketAddr,
    /// Highest RTR version this client will offer; negotiation starts
    /// here and downgrades on Error Code 4 (bis §7). Defaults to
    /// [`HIGHEST_VERSION`]. Pin it lower for caches that close the
    /// transport silently on an unknown version instead of answering
    /// code 4 — gortr v0.14.x does exactly that (see
    /// docs/protocols/rpki.md, "Real-cache interop"); there is no
    /// signal to downgrade on, so the pin is the operator's.
    pub max_version: u8,
}

impl ClientConfig {
    pub fn new(cache_addr: SocketAddr) -> Self {
        ClientConfig {
            cache_addr,
            max_version: HIGHEST_VERSION,
        }
    }
}

/// Delay between connection attempts before the first successful
/// synchronization. RFC 8210 §6's default Retry Interval (600 s) is
/// meant for "a router [that] has never issued a successful query
/// against a particular cache" in the data sense; a cache dropping
/// the transport before any End of Data (gortr v0.14.x on a version
/// it does not speak) would otherwise cost the full 600 s per
/// attempt. Once a session has reached End of Data, the cache's own
/// Retry Interval governs.
const FAST_RECONNECT: Duration = Duration::from_secs(1);

/// The reconnect delay for the next attempt: the negotiated Retry
/// Interval once the cache has ever served data, [`FAST_RECONNECT`]
/// before that.
fn reconnect_delay(ever_synced: bool, retry_interval: Duration) -> Duration {
    if ever_synced {
        retry_interval
    } else {
        FAST_RECONNECT
    }
}

/// Version negotiation state that outlives any one connection
/// (8210bis-27 §7): the version agreed so far and every version
/// offered, so a reconnecting client re-opens at the version the
/// cache accepted instead of re-offering one it already rejected.
#[derive(Debug)]
struct Negotiation {
    version: Option<u8>,
    attempted: Vec<u8>,
}

/// Messages from the per-connection reader task.
enum FromCache {
    /// A decoded PDU plus its raw bytes (Error Reports encapsulate
    /// the raw form).
    Pdu(Pdu, Vec<u8>),
    /// Bytes that would not decode.
    Corrupt(Vec<u8>, DecodeError),
    Eof,
    Io(std::io::Error),
}

/// Which query a Cache Response answers — a response to a Reset Query
/// replaces the whole table (RFC 8210 §5.5), one to a Serial Query
/// applies deltas.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum QueryKind {
    Reset,
    Serial,
}

/// What one connection ended with, for the reconnect loop's logging.
enum SessionEnd {
    /// Peer closed or IO failed; data (if any) stays until expiry.
    Transport(String),
    /// We sent an Error Report and dropped: everything is flushed
    /// (bis §12 fatal-error rule).
    Fatal(&'static str),
    /// Non-fatal error report received (2/4/12/13): no flush.
    Reported(ErrorCode),
    /// Shutdown requested.
    Stopped,
}

/// The RTR client. [`RtrClient::spawn`] runs the connect/negotiate/
/// poll loop until the shutdown channel fires; it owns nothing else —
/// all learned data lands in the [`SharedTables`] it was built with.
pub struct RtrClient {
    config: ClientConfig,
    tables: SharedTables,
}

impl RtrClient {
    /// Create the client and the tables handle it will fill.
    pub fn new(config: ClientConfig) -> (RtrClient, SharedTables) {
        let tables = Arc::new(Mutex::new(CacheTables::default()));
        (RtrClient::with_tables(config, tables.clone()), tables)
    }

    /// Attach to externally owned tables (bgpd's use).
    pub fn with_tables(config: ClientConfig, tables: SharedTables) -> RtrClient {
        RtrClient { config, tables }
    }

    /// Run the client until `shutdown` yields `true`. Reconnects with
    /// the Retry Interval between attempts; keeps the Expire Interval
    /// armed across reconnects so stale data cannot outlive it.
    pub async fn run(&self, mut shutdown: watch::Receiver<bool>) {
        // RFC 8210 §6: "If the router has never issued a successful
        // query against a particular cache, it SHOULD retry
        // periodically using the default Retry Interval."
        let mut retry_interval = Duration::from_secs(u64::from(Timing::DEFAULT.retry_interval));
        let mut expire_at: Option<Instant> = None;
        // Negotiation state spans connections (bis §7): a version the
        // cache named or accepted on an earlier connection sticks.
        let mut negotiation = Negotiation {
            version: None,
            attempted: vec![self.config.max_version],
        };
        let mut ever_synced = false;
        loop {
            // Note: the connect attempt itself is not raced against
            // the expire deadline — the OS bounds it (SYN retries)
            // far below any sane §6 Expire Interval, and the sleeps
            // below carry the between-sessions deadline (a cache that
            // died with its port refusing connections parks the
            // client in THIS loop; the live gortr lesson).
            let connect = tokio::select! {
                _ = shutdown.changed() => return,
                stream = TcpStream::connect(self.config.cache_addr) => stream,
            };
            let stream = match connect {
                Ok(s) => s,
                Err(e) => {
                    tracing::warn!(cache = %self.config.cache_addr, error = %e, "rpki: cache connect failed");
                    match wait_or_expire(
                        reconnect_delay(ever_synced, retry_interval),
                        &mut shutdown,
                        &expire_at,
                    )
                    .await
                    {
                        WaitOutcome::Shutdown => return,
                        WaitOutcome::Expired => self.expire_flush(&mut expire_at),
                        WaitOutcome::Done => {}
                    }
                    continue;
                }
            };
            match self
                .run_session(
                    stream,
                    &mut shutdown,
                    &mut expire_at,
                    &mut retry_interval,
                    &mut negotiation,
                    &mut ever_synced,
                )
                .await
            {
                SessionEnd::Stopped => return,
                SessionEnd::Transport(why) => {
                    tracing::info!(cache = %self.config.cache_addr, why, "rpki: cache session ended");
                }
                SessionEnd::Fatal(why) => {
                    tracing::error!(cache = %self.config.cache_addr, why, "rpki: fatal error, flushing cache data");
                    self.lock().flush();
                    expire_at = None;
                }
                SessionEnd::Reported(code) => {
                    tracing::warn!(cache = %self.config.cache_addr, ?code, "rpki: cache sent an error report");
                }
            }
            // The expire deadline survives the reconnect (the data is
            // still trusted until then, RFC 8210 §6) — and races this
            // sleep the same way.
            match wait_or_expire(
                reconnect_delay(ever_synced, retry_interval),
                &mut shutdown,
                &expire_at,
            )
            .await
            {
                WaitOutcome::Shutdown => {
                    if expire_at.is_some() {
                        tracing::warn!(
                            "rpki: shutdown with data still held; caller owns the tables"
                        );
                    }
                    return;
                }
                WaitOutcome::Expired => self.expire_flush(&mut expire_at),
                WaitOutcome::Done => {}
            }
        }
    }

    /// The §6 expire action: data learned from the cache is dropped
    /// once the Expire Interval passes without a successful poll.
    fn expire_flush(&self, expire_at: &mut Option<Instant>) {
        tracing::warn!(cache = %self.config.cache_addr, "rpki: expire interval passed, flushing cache data");
        self.lock().flush();
        *expire_at = None;
    }

    /// Spawn [`RtrClient::run`] on a new task.
    pub fn spawn(self, shutdown: watch::Receiver<bool>) -> tokio::task::JoinHandle<()> {
        tokio::spawn(async move { self.run(shutdown).await })
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, CacheTables> {
        // Poisoning would mean a panic while holding the lock inside
        // table mutation; treat it as a caller-side bug and propagate.
        self.tables.lock().unwrap()
    }

    #[allow(clippy::too_many_arguments)]
    async fn run_session(
        &self,
        stream: Stream,
        shutdown: &mut watch::Receiver<bool>,
        expire_at: &mut Option<Instant>,
        retry_interval: &mut Duration,
        negotiation: &mut Negotiation,
        ever_synced: &mut bool,
    ) -> SessionEnd {
        let _ = stream.set_nodelay(true);
        let (rx_half, mut tx_half) = stream.into_split();
        let (from_cache_tx, mut from_cache_rx) = mpsc::channel::<FromCache>(16);
        let reader = tokio::spawn(read_loop(rx_half, from_cache_tx));

        // Negotiation state (RFC 8210 §7 / bis §7), shared across the
        // connection's life and remembered by the caller's reconnect
        // loop: `version` is the agreed session version (None until
        // fixed), `attempted` every version offered so far.
        let Negotiation { version, attempted } = negotiation;

        // Current session bookkeeping.
        let (have_sid, have_serial) = {
            let t = self.lock();
            (t.session_id, t.serial)
        };
        let mut receiving = false; // a Cache Response sequence is open
        let mut rx_sid_held: u16 = 0; // the session id that opened it
        let mut last_reset_response = false; // it answered a Reset Query
        let mut pending_query: Option<QueryKind>;
        let mut refresh_at: Option<Instant> = None;
        let end: SessionEnd;

        // §8.1: Serial Query iff unexpired data + remembered Session
        // ID, else Reset Query.
        let open_query = |version: u8| -> Pdu {
            match (have_sid, have_serial) {
                (Some(sid), Some(serial)) => Pdu::SerialQuery {
                    version,
                    session_id: sid,
                    serial,
                },
                _ => Pdu::ResetQuery { version },
            }
        };
        pending_query = match (have_sid, have_serial) {
            (Some(_), Some(_)) => Some(QueryKind::Serial),
            _ => Some(QueryKind::Reset),
        };
        // Open at the version the cache last accepted when there is
        // one (bis §7 negotiation memory across reconnects), else the
        // configured ceiling.
        let open_version = (*version).unwrap_or(self.config.max_version);
        if write_pdu(&mut tx_half, &open_query(open_version))
            .await
            .is_err()
        {
            end = SessionEnd::Transport("write of opening query failed".into());
            reader.abort();
            return end;
        }
        self.lock().state = CacheState::Negotiating;

        loop {
            enum Wakeup {
                FromCache(FromCache),
                Timer(Instant),
                Shutdown,
            }
            // While a Cache Response sequence is open the §5.5 full
            // load is REPLACING the table (already cleared at the
            // response); the §6 expire deadline protects data HELD
            // from the last successful poll, so it stays disarmed
            // until the End of Data re-arms it. (The live gortr run
            // showed why: a mid-reload flush loses payload PDUs and
            // leaves a partial table behind.)
            let next_timer = [refresh_at, if receiving { None } else { *expire_at }]
                .into_iter()
                .flatten()
                .min();
            let timer = async {
                match next_timer {
                    Some(at) => sleep_until(at).await,
                    None => std::future::pending::<()>().await,
                }
            };
            let wake = tokio::select! {
                m = from_cache_rx.recv() => match m {
                    Some(m) => Wakeup::FromCache(m),
                    None => Wakeup::FromCache(FromCache::Eof),
                },
                _ = timer => Wakeup::Timer(next_timer.unwrap()),
                _ = shutdown.changed() => Wakeup::Shutdown,
            };
            match wake {
                Wakeup::Shutdown => {
                    end = SessionEnd::Stopped;
                    break;
                }
                Wakeup::Timer(at) => {
                    if Some(at) == *expire_at {
                        // RFC 8210 §6: data "MUST NOT" be retained past
                        // the Expire Interval without a successful poll.
                        self.expire_flush(expire_at);
                        refresh_at = None;
                    } else if Some(at) == refresh_at {
                        // §6 refresh poll; doubles as the §8.1
                        // application-layer keep-alive.
                        refresh_at = None;
                        let (sid, serial, timing) = {
                            let t = self.lock();
                            (t.session_id, t.serial, t.timing)
                        };
                        let refresh = timing
                            .map(|t| Duration::from_secs(u64::from(t.refresh_interval)))
                            .unwrap_or_else(|| {
                                Duration::from_secs(u64::from(Timing::DEFAULT.refresh_interval))
                            });
                        if let (Some(sid), Some(serial), Some(v)) = (sid, serial, *version) {
                            let q = Pdu::SerialQuery {
                                version: v,
                                session_id: sid,
                                serial,
                            };
                            if write_pdu(&mut tx_half, &q).await.is_err() {
                                end = SessionEnd::Transport("refresh query write failed".into());
                                break;
                            }
                            pending_query = Some(QueryKind::Serial);
                            // §6: "Countdown for this timer starts upon
                            // receipt of the containing End Of Data PDU"
                            // — no restart at send time; a response-less
                            // poll is covered by the expire deadline.
                            let _ = refresh;
                        }
                    }
                }
                Wakeup::FromCache(message) => {
                    let (pdu, raw) = match message {
                        FromCache::Pdu(pdu, raw) => (pdu, raw),
                        FromCache::Eof => {
                            end = SessionEnd::Transport("cache closed the connection".into());
                            break;
                        }
                        FromCache::Io(e) => {
                            end = SessionEnd::Transport(format!("cache io error: {e}"));
                            break;
                        }
                        FromCache::Corrupt(raw, err) => {
                            tracing::warn!(%err, "rpki: undecodable PDU from cache");
                            let _ = send_error(
                                &mut tx_half,
                                version.unwrap_or(self.config.max_version),
                                ErrorCode::CorruptData,
                                &raw,
                                Some(&format!("undecodable PDU: {err}")),
                            )
                            .await;
                            end = SessionEnd::Fatal("corrupt PDU from cache");
                            break;
                        }
                    };

                    // Version stability (RFC 8210 §7): once negotiated,
                    // any other version is fatal — except an Error
                    // Report, which never gets answered (§5.11).
                    match (&*version, pdu.version()) {
                        (Some(v), pv) if pv != *v && !matches!(pdu, Pdu::ErrorReport { .. }) => {
                            let _ = send_error(
                                &mut tx_half,
                                *v,
                                ErrorCode::UnexpectedProtocolVersion,
                                &raw,
                                Some("protocol version changed mid-session"),
                            )
                            .await;
                            end = SessionEnd::Fatal("protocol version changed mid-session");
                            break;
                        }
                        _ => {}
                    }

                    match pdu {
                        Pdu::SerialNotify {
                            session_id, serial, ..
                        } => {
                            // §8.2: a hint — query now instead of
                            // waiting out the Refresh Interval. Ignored
                            // while a response is open or version is
                            // still being negotiated (§7 requires the
                            // router to ignore notifies during
                            // negotiation).
                            if version.is_some() && !receiving {
                                let (sid, held_serial, v) = {
                                    let t = self.lock();
                                    (t.session_id, t.serial, *version)
                                };
                                if let (Some(sid), Some(s), Some(v)) = (sid, held_serial, v) {
                                    if session_id != sid {
                                        // §5.1: any session-id mismatch,
                                        // on any PDU, means the cache
                                        // instance changed — terminate
                                        // with code 0 and flush.
                                        let _ = send_error(
                                            &mut tx_half,
                                            v,
                                            ErrorCode::CorruptData,
                                            &raw,
                                            Some("serial notify session id mismatch"),
                                        )
                                        .await;
                                        end = SessionEnd::Fatal("notify session id mismatch");
                                        break;
                                    }
                                    // §5.2: a matching notify with news
                                    // may trigger an immediate query.
                                    if serial != s {
                                        let q = Pdu::SerialQuery {
                                            version: v,
                                            session_id: sid,
                                            serial: s,
                                        };
                                        if write_pdu(&mut tx_half, &q).await.is_err() {
                                            end = SessionEnd::Transport(
                                                "notify query write failed".into(),
                                            );
                                            break;
                                        }
                                        pending_query = Some(QueryKind::Serial);
                                    }
                                }
                            }
                        }
                        Pdu::CacheReset { .. } => {
                            // §8.3: the cache cannot serve the serial;
                            // the router MUST fall back to a Reset Query
                            // (single-cache case).
                            receiving = false;
                            if version.is_none() {
                                // Any well-formed response fixes the
                                // session version (§7).
                                *version = Some(pdu.version());
                            }
                            let v = version.unwrap_or(self.config.max_version);
                            if write_pdu(&mut tx_half, &Pdu::ResetQuery { version: v })
                                .await
                                .is_err()
                            {
                                end = SessionEnd::Transport("reset query write failed".into());
                                break;
                            }
                            pending_query = Some(QueryKind::Reset);
                            self.lock().state = CacheState::Negotiating;
                        }
                        Pdu::CacheResponse { session_id, .. } => {
                            if receiving {
                                let _ = send_error(
                                    &mut tx_half,
                                    version.unwrap_or(self.config.max_version),
                                    ErrorCode::CorruptData,
                                    &raw,
                                    Some("cache response inside an open sequence"),
                                )
                                .await;
                                end = SessionEnd::Fatal("nested cache response");
                                break;
                            }
                            if version.is_none() {
                                *version = Some(pdu.version());
                            }
                            let was_reset_query = pending_query.take() == Some(QueryKind::Reset);
                            last_reset_response = was_reset_query;
                            // §5.1: a session-id change mid-relationship
                            // is fatal, code 0, with a full flush. (A
                            // reset response may legitimately change it —
                            // e.g. after a cache restart.)
                            let known_sid = self.lock().session_id;
                            if !was_reset_query {
                                if let Some(known) = known_sid {
                                    if known != session_id {
                                        let _ = send_error(
                                            &mut tx_half,
                                            version.unwrap_or(self.config.max_version),
                                            ErrorCode::CorruptData,
                                            &raw,
                                            Some("session id changed"),
                                        )
                                        .await;
                                        end = SessionEnd::Fatal("session id mismatch");
                                        break;
                                    }
                                }
                            }
                            let mut t = self.lock();
                            if was_reset_query {
                                // §5.5: the reset response is the whole
                                // current database — start from scratch.
                                t.vrps.clear();
                                t.aspa.clear();
                                t.router_keys.clear();
                            }
                            t.session_id = Some(session_id);
                            t.protocol_version = Some(pdu.version());
                            t.state = CacheState::Receiving;
                            receiving = true;
                            rx_sid_held = session_id;
                        }
                        Pdu::EndOfData {
                            session_id,
                            serial,
                            timing,
                            ..
                        } => {
                            if !receiving {
                                let _ = send_error(
                                    &mut tx_half,
                                    version.unwrap_or(self.config.max_version),
                                    ErrorCode::CorruptData,
                                    &raw,
                                    Some("end of data without a cache response"),
                                )
                                .await;
                                end = SessionEnd::Fatal("orphan end of data");
                                break;
                            }
                            receiving = false;
                            let was_reset = last_reset_response;
                            let rx_sid = rx_sid_held;
                            // §5.8: EoD's Session ID must match the Cache
                            // Response that opened the sequence.
                            if session_id != rx_sid {
                                let _ = send_error(
                                    &mut tx_half,
                                    version.unwrap_or(self.config.max_version),
                                    ErrorCode::CorruptData,
                                    &raw,
                                    Some("end of data session id mismatch"),
                                )
                                .await;
                                end = SessionEnd::Fatal("eod session id mismatch");
                                break;
                            }
                            let timing = timing.unwrap_or(Timing::DEFAULT);
                            let now = Instant::now();
                            refresh_at =
                                Some(now + Duration::from_secs(u64::from(timing.refresh_interval)));
                            *retry_interval = Duration::from_secs(u64::from(timing.retry_interval));
                            *expire_at =
                                Some(now + Duration::from_secs(u64::from(timing.expire_interval)));
                            // The cache has now served data at least
                            // once: reconnects fall back to the Retry
                            // Interval it named (RFC 8210 §6).
                            *ever_synced = true;
                            let mut t = self.lock();
                            t.serial = Some(serial);
                            t.session_id = Some(session_id);
                            t.timing = Some(timing);
                            t.protocol_version = Some(pdu.version());
                            t.state = if was_reset {
                                CacheState::Fresh
                            } else {
                                CacheState::Serial
                            };
                            tracing::info!(
                                cache = %self.config.cache_addr,
                                serial,
                                session_id,
                                vrps = t.vrps.len(),
                                aspas = t.aspa.len(),
                                "rpki: cache synchronized"
                            );
                        }
                        Pdu::ErrorReport {
                            error_code,
                            ref text,
                            ..
                        } => {
                            match error_code {
                                ErrorCode::UnsupportedProtocolVersion => {
                                    // bis §7: retry at the version the
                                    // error names, unless that version
                                    // already failed (then abort the
                                    // transport; negotiation is
                                    // hopeless — including at 0).
                                    let named = pdu.version();
                                    if named == VERSION_0 && attempted.contains(&VERSION_0) {
                                        end = SessionEnd::Reported(error_code);
                                        break;
                                    }
                                    if attempted.contains(&named)
                                        || named > self.config.max_version
                                        || named > HIGHEST_VERSION
                                    {
                                        end = SessionEnd::Reported(error_code);
                                        break;
                                    }
                                    attempted.push(named);
                                    *version = Some(named);
                                    if write_pdu(&mut tx_half, &open_query(named)).await.is_err() {
                                        end = SessionEnd::Transport(
                                            "downgrade query write failed".into(),
                                        );
                                        break;
                                    }
                                }
                                ErrorCode::NoDataAvailable => {
                                    // §8.4: retry periodically with Reset
                                    // Queries until a usable load arrives.
                                    // §8.4 names no interval of its own; the
                                    // cache's Retry Interval governs once
                                    // one is known, and the pre-sync fast
                                    // delay does before that (a fresh
                                    // gortr whose initial file read failed
                                    // answers the FIRST query with code 2 —
                                    // the N7 live capture — and must not
                                    // cost the 600 s §6 default).
                                    self.lock().state = CacheState::NoData;
                                    let wait = reconnect_delay(*ever_synced, *retry_interval);
                                    match wait_or_expire(wait, shutdown, expire_at).await {
                                        WaitOutcome::Shutdown => {
                                            end = SessionEnd::Stopped;
                                            break;
                                        }
                                        // Held data (if any) cannot outlive
                                        // the Expire Interval while we wait
                                        // out a No-Data cache (§6).
                                        WaitOutcome::Expired => {
                                            self.expire_flush(expire_at);
                                        }
                                        WaitOutcome::Done => {}
                                    }
                                    let v = version.unwrap_or(self.config.max_version);
                                    if write_pdu(&mut tx_half, &Pdu::ResetQuery { version: v })
                                        .await
                                        .is_err()
                                    {
                                        end = SessionEnd::Transport(
                                            "no-data retry write failed".into(),
                                        );
                                        break;
                                    }
                                    pending_query = Some(QueryKind::Reset);
                                }
                                ErrorCode::CacheRestart | ErrorCode::CacheShutdown => {
                                    // bis §8.5/§8.6: log, close, retry on
                                    // the Retry Interval. Data stays
                                    // until the expire deadline (which
                                    // stays armed in run()).
                                    if error_code == ErrorCode::CacheShutdown {
                                        // The operator asked for a flush.
                                        self.lock().flush();
                                        *expire_at = None;
                                    }
                                    end = SessionEnd::Reported(error_code);
                                    break;
                                }
                                other => {
                                    tracing::error!(
                                        code = other.to_u16(),
                                        text = text.as_deref().unwrap_or(""),
                                        "rpki: fatal error report from cache"
                                    );
                                    end = SessionEnd::Fatal("cache sent a fatal error report");
                                    break;
                                }
                            }
                        }
                        payload @ (Pdu::Ipv4Prefix { .. }
                        | Pdu::Ipv6Prefix { .. }
                        | Pdu::RouterKey { .. }
                        | Pdu::Aspa { .. }) => {
                            if !receiving {
                                let _ = send_error(
                                    &mut tx_half,
                                    version.unwrap_or(self.config.max_version),
                                    ErrorCode::InvalidRequest,
                                    &raw,
                                    Some("payload PDU outside a cache response"),
                                )
                                .await;
                                end = SessionEnd::Fatal("payload outside a sequence");
                                break;
                            }
                            if let Some(code) = payload.aspa_provider_list_error() {
                                let _ = send_error(
                                    &mut tx_half,
                                    version.unwrap_or(self.config.max_version),
                                    code,
                                    &raw,
                                    Some("aspa provider list error"),
                                )
                                .await;
                                end = SessionEnd::Fatal("aspa provider list error");
                                break;
                            }
                            let verdict = self.apply_payload(&payload);
                            if let Err((code, why)) = verdict {
                                let _ = send_error(
                                    &mut tx_half,
                                    version.unwrap_or(self.config.max_version),
                                    code,
                                    &raw,
                                    Some(why),
                                )
                                .await;
                                end = SessionEnd::Fatal("payload apply failed");
                                break;
                            }
                        }
                        Pdu::SerialQuery { .. } | Pdu::ResetQuery { .. } => {
                            // Router-side PDUs have no meaning coming
                            // from the cache.
                            let _ = send_error(
                                &mut tx_half,
                                version.unwrap_or(self.config.max_version),
                                ErrorCode::InvalidRequest,
                                &raw,
                                Some("query PDU from cache"),
                            )
                            .await;
                            end = SessionEnd::Fatal("query PDU from cache");
                            break;
                        }
                    }
                }
            }
        }
        reader.abort();
        let _ = tx_half.shutdown().await;
        // A Cache Response sequence that never reached its End of
        // Data leaves a PARTIAL table (a reset response already
        // cleared §5.5's "whole current database"; a delta response
        // is half-applied). Retaining either would betray §6's
        // successful-poll premise: flush, and the next connection
        // re-opens with a Reset Query.
        if receiving {
            tracing::warn!(
                cache = %self.config.cache_addr,
                "rpki: session ended mid cache response, flushing partial data"
            );
            self.lock().flush();
            *expire_at = None;
        }
        end
    }

    /// Apply one payload PDU; errors carry the RTR error code the
    /// session must report (7 duplicate / 6 unknown withdrawal).
    fn apply_payload(&self, pdu: &Pdu) -> Result<(), (ErrorCode, &'static str)> {
        let mut t = self.lock();
        match pdu {
            Pdu::Ipv4Prefix { flags, .. } | Pdu::Ipv6Prefix { flags, .. } => {
                let vrp = Vrp::from_prefix_pdu(pdu).expect("prefix pdu checked by caller");
                t.vrps.apply(vrp, *flags).map_err(|e| match e {
                    crate::vrp::VrpTableError::DuplicateAnnouncement(_) => (
                        ErrorCode::DuplicateAnnouncementReceived,
                        "duplicate vrp announcement",
                    ),
                    crate::vrp::VrpTableError::UnknownWithdrawal(_) => (
                        ErrorCode::WithdrawalOfUnknownRecord,
                        "withdrawal of unknown vrp",
                    ),
                })
            }
            Pdu::RouterKey {
                flags,
                ski,
                asn,
                spki,
                ..
            } => {
                let key = RouterKeyEntry {
                    asn: *asn,
                    ski: *ski,
                    spki: spki.clone(),
                };
                if flags.announce {
                    if !t.router_keys.insert(key) {
                        return Err((
                            ErrorCode::DuplicateAnnouncementReceived,
                            "duplicate router key announcement",
                        ));
                    }
                } else if !t.router_keys.remove(&key) {
                    return Err((
                        ErrorCode::WithdrawalOfUnknownRecord,
                        "withdrawal of unknown router key",
                    ));
                }
                Ok(())
            }
            Pdu::Aspa {
                flags,
                customer_asn,
                providers,
                ..
            } => {
                let set: BTreeSet<u32> = providers.iter().copied().collect();
                t.aspa
                    .apply(*customer_asn, *flags, set)
                    .map(|_| ())
                    .map_err(|e| match e {
                        crate::aspa::AspaTableError::DuplicateAnnouncement(_) => (
                            ErrorCode::DuplicateAnnouncementReceived,
                            "duplicate aspa announcement",
                        ),
                        crate::aspa::AspaTableError::UnknownWithdrawal(_) => (
                            ErrorCode::WithdrawalOfUnknownRecord,
                            "withdrawal of unknown aspa",
                        ),
                    })
            }
            _ => Ok(()),
        }
    }
}

/// Read PDUs until the stream ends, forwarding them (and their raw
/// bytes) to the session loop.
async fn read_loop(mut rx: tokio::net::tcp::OwnedReadHalf, tx: mpsc::Sender<FromCache>) {
    let mut buf: Vec<u8> = Vec::with_capacity(4096);
    let mut chunk = [0u8; 4096];
    loop {
        let n = match rx.read(&mut chunk).await {
            Ok(0) => {
                let _ = tx.send(FromCache::Eof).await;
                return;
            }
            Ok(n) => n,
            Err(e) => {
                let _ = tx.send(FromCache::Io(e)).await;
                return;
            }
        };
        buf.extend_from_slice(&chunk[..n]);
        loop {
            if buf.len() < 8 {
                break;
            }
            let declared = match be_u32_len(&buf) {
                Some(d) => d,
                None => break,
            };
            if buf.len() < declared as usize {
                break; // need more bytes
            }
            match Pdu::decode(&buf) {
                Ok((pdu, used)) => {
                    let raw = buf[..used].to_vec();
                    buf.drain(..used);
                    if tx.send(FromCache::Pdu(pdu, raw)).await.is_err() {
                        return;
                    }
                }
                Err(err) => {
                    let raw = buf.clone();
                    buf.clear();
                    if tx.send(FromCache::Corrupt(raw, err)).await.is_err() {
                        return;
                    }
                }
            }
        }
    }
}

async fn write_pdu<W>(w: &mut W, pdu: &Pdu) -> std::io::Result<()>
where
    W: AsyncWriteExt + Unpin,
{
    let bytes = pdu
        .encode(pdu.version())
        .map_err(|e| std::io::Error::other(format!("encode: {e}")))?;
    w.write_all(&bytes).await?;
    w.flush().await
}

async fn send_error<W>(
    w: &mut W,
    version: u8,
    code: ErrorCode,
    raw: &[u8],
    text: Option<&str>,
) -> std::io::Result<()>
where
    W: AsyncWriteExt + Unpin,
{
    let encap = &raw[..raw.len().min(ERROR_ENCAPSULATION_MAX)];
    let report = Pdu::ErrorReport {
        version,
        error_code: code,
        erroneous_pdu: encap.to_vec(),
        text: text.map(str::to_string),
    };
    write_pdu(w, &report).await
}

/// Resolve when the expire deadline passes; never resolves while no
/// deadline is armed (RFC 8210 §6 racing between sessions).
async fn expire_timer(deadline: Option<Instant>) {
    match deadline {
        Some(at) => sleep_until(at).await,
        None => std::future::pending::<()>().await,
    }
}

/// Outcome of a bounded wait that also races the expire deadline.
enum WaitOutcome {
    /// The duration elapsed.
    Done,
    /// Shutdown was requested.
    Shutdown,
    /// The expire deadline fired first (§6).
    Expired,
}

/// Sleep for `d`, unless shutdown fires or the §6 expire deadline
/// passes first — held data must never outlive the Expire Interval,
/// including while parked in the reconnect loop with no session
/// timers armed (the live gortr lesson: cache dead, port refusing).
async fn wait_or_expire(
    d: Duration,
    shutdown: &mut watch::Receiver<bool>,
    expire_at: &Option<Instant>,
) -> WaitOutcome {
    tokio::select! {
        _ = tokio::time::sleep(d) => WaitOutcome::Done,
        _ = shutdown.changed() => WaitOutcome::Shutdown,
        _ = expire_timer(*expire_at) => WaitOutcome::Expired,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_state_is_none_and_flush_restores_it() {
        let mut t = CacheTables::default();
        assert_eq!(t.state, CacheState::None);
        t.vrps
            .apply(
                Vrp {
                    prefix: "192.0.2.0/24".parse().unwrap(),
                    max_len: 24,
                    asn: 64512,
                },
                crate::pdu::PayloadFlags::ANNOUNCE,
            )
            .unwrap();
        t.state = CacheState::Fresh;
        t.session_id = Some(7);
        t.serial = Some(3);
        t.flush();
        assert_eq!(t.state, CacheState::None);
        assert!(t.vrps.is_empty());
        assert_eq!(t.session_id, None);
    }

    #[test]
    fn default_port_matches_rfc() {
        // RFC 8210 §9: the rpki-rtr port.
        assert_eq!(DEFAULT_CACHE_PORT, 323);
    }

    #[test]
    fn default_config_offers_the_highest_version() {
        // bis §7: negotiation starts at the router's highest version
        // unless the operator pinned lower (the gortr knob).
        let cfg = ClientConfig::new("127.0.0.1:8282".parse().unwrap());
        assert_eq!(cfg.max_version, HIGHEST_VERSION);
    }

    #[test]
    fn reconnect_is_fast_until_the_cache_has_served_data() {
        // Pre-sync failures (a cache closing on an unknown version,
        // connection refused) cost FAST_RECONNECT, not the §6 default
        // 600 s retry — the gortr silent-close lesson.
        let retry = Duration::from_secs(600);
        assert_eq!(reconnect_delay(false, retry), FAST_RECONNECT);
        // Once a session reached End of Data, the cache's own Retry
        // Interval governs (RFC 8210 §6).
        assert_eq!(reconnect_delay(true, retry), retry);
        assert_eq!(
            reconnect_delay(true, Duration::from_secs(5)),
            Duration::from_secs(5)
        );
    }
}
