//! P2-c M5: session-client integration tests against an in-test mock
//! cache over a real TCP socket (the z5-family convention: the script
//! IS the mock's scripted PDU sequence).
//!
//! Scenarios (each cites the RFC 8210 / 8210bis-27 conversation it
//! exercises):
//! 1. full refresh — §8.1 start-or-restart: Reset Query → Cache
//!    Response → payloads → End of Data;
//! 2. incremental serial update — §8.2 typical exchange via a Serial
//!    Notify hint, deltas applied;
//! 3. cache restart — §8.3: Serial Query answered by Cache Reset →
//!    the client re-queries with a Reset Query and takes a full load;
//! 4. fatal error teardown — §12: error report drops the session and
//!    flushes everything learned;
//! 5. version downgrade — §7/bis §7: Error Code 4 names version 1,
//!    the client re-queries at v1 and completes there;
//! 6. no data available — §8.4: Error Code 2, NoData state, periodic
//!    Reset Query retry on the same connection;
//! 7. duplicate announcement — §5.6: the client answers with Error
//!    Code 7, drops, flushes;
//! 8. refresh keep-alive + expire — §6: the refresh poll doubles as
//!    keep-alive, then a silent cache past the Expire Interval
//!    flushes the data;
//! 9. session-id mismatch — §5.1: a Serial Notify carrying a foreign
//!    Session ID is itself the mismatch ("at any time ... either party
//!    finds that the value of the Session ID is not the same");
//!    code-0 teardown with a flush. (Delivered via notify on purpose:
//!    the mock performs no blocking read after End of Data — under
//!    the paused clock each mock read-park lets auto-advance fire one
//!    client timer, and a chain of two such parks reaches the Expire
//!    Interval, which would legitimately flush mid-conversation.)
//!
//! Clock: every test runs tokio's paused clock (`start_paused`), so
//! the RFC's default intervals (retry 600 s, expire 7200 s) elapse
//! instantly and deterministically.

use std::sync::{Arc, Mutex};
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::watch;

use rpki::client::{CacheState, CacheTables, ClientConfig, RtrClient};
use rpki::{
    ErrorCode, Pdu, PayloadFlags, Timing, VERSION_1, VERSION_2,
};

type Tables = Arc<Mutex<CacheTables>>;

/// The scenarios are timing-shaped conversations against tokio's
/// paused clock; a contention-induced scheduling change in a parallel
/// run can reorder which side parks first and let auto-advance fire
/// client timers mid-conversation (a legitimate refresh poll landing
/// between mock writes). Serializing the binary makes the schedule
/// deterministic; unit and property tests stay parallel.
static SERIAL: std::sync::Mutex<()> = std::sync::Mutex::new(());

fn serial() -> std::sync::MutexGuard<'static, ()> {
    SERIAL.lock().unwrap_or_else(|e| e.into_inner())
}

// ---- mock-cache plumbing ---------------------------------------------

struct Fixture {
    listener: TcpListener,
    tables: Tables,
    shutdown: watch::Sender<bool>,
    handle: tokio::task::JoinHandle<()>,
}

impl Fixture {
    async fn new() -> Fixture {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (client, tables) = RtrClient::new(ClientConfig::new(addr));
        let (shutdown, rx) = watch::channel(false);
        let handle = client.spawn(rx);
        Fixture {
            listener,
            tables,
            shutdown,
            handle,
        }
    }

    async fn accept(&self) -> TcpStream {
        let (sock, _) = self.listener.accept().await.unwrap();
        sock
    }

    async fn stop(self) {
        self.shutdown.send(true).unwrap();
        self.handle.await.unwrap();
    }
}

/// Read exactly one PDU (framed by the declared length) from the
/// mock-cache side.
async fn read_one(sock: &mut TcpStream) -> Vec<u8> {
    let mut hdr = [0u8; 8];
    sock.read_exact(&mut hdr).await.unwrap();
    let len = u32::from_be_bytes([hdr[4], hdr[5], hdr[6], hdr[7]]) as usize;
    let mut full = hdr.to_vec();
    full.resize(len, 0);
    sock.read_exact(&mut full[8..]).await.unwrap();
    full
}

/// Read one PDU, skipping refresh-interval Serial Queries the client
/// legitimately emits while the paused clock auto-advances (RFC 8210
/// §6 keep-alive). Safe for awaiting a specific reply because that
/// reply is always written before any reconnect-era query could be.
async fn read_skipping_refresh_queries(sock: &mut TcpStream, sid: u16, serial: u32) -> Pdu {
    loop {
        let raw = read_one(sock).await;
        let (pdu, _) = Pdu::decode(&raw).unwrap();
        if let Pdu::SerialQuery {
            session_id, serial: s, ..
        } = &pdu
        {
            if *session_id == sid && *s == serial {
                continue;
            }
        }
        return pdu;
    }
}

async fn expect(sock: &mut TcpStream, want: Pdu) {
    let raw = read_one(sock).await;
    let (got, used) = Pdu::decode(&raw).unwrap();
    assert_eq!(used, raw.len());
    assert_eq!(got, want, "cache-side query mismatch");
}

async fn send(sock: &mut TcpStream, pdu: &Pdu) {
    let bytes = pdu.encode(pdu.version()).unwrap();
    sock.write_all(&bytes).await.unwrap();
    sock.flush().await.unwrap();
}

fn roa4(version: u8, prefix: &str, max_len: u8, asn: u32) -> Pdu {
    Pdu::Ipv4Prefix {
        version,
        flags: PayloadFlags::ANNOUNCE,
        prefix: prefix.parse().unwrap(),
        max_len,
        asn,
    }
}

fn roa4_withdraw(version: u8, prefix: &str, max_len: u8, asn: u32) -> Pdu {
    Pdu::Ipv4Prefix {
        version,
        flags: PayloadFlags::WITHDRAW,
        prefix: prefix.parse().unwrap(),
        max_len,
        asn,
    }
}

fn aspa_announce(customer: u32, providers: Vec<u32>) -> Pdu {
    Pdu::Aspa {
        version: VERSION_2,
        flags: PayloadFlags::ANNOUNCE,
        customer_asn: customer,
        providers,
    }
}

fn cache_response(version: u8, session_id: u16) -> Pdu {
    Pdu::CacheResponse {
        version,
        session_id,
    }
}

fn eod(version: u8, session_id: u16, serial: u32, timing: Timing) -> Pdu {
    Pdu::EndOfData {
        version,
        session_id,
        serial,
        timing: Some(timing),
    }
}

fn error_report(version: u8, code: ErrorCode, text: &str) -> Pdu {
    Pdu::ErrorReport {
        version,
        error_code: code,
        erroneous_pdu: vec![],
        text: Some(text.to_string()),
    }
}

/// A consistent view of the shared tables for assertions.
#[derive(Debug, PartialEq)]
struct Snap {
    state: CacheState,
    vrps: usize,
    aspas: usize,
    serial: Option<u32>,
    session_id: Option<u16>,
    version: Option<u8>,
    timing: Option<Timing>,
}

fn snap(t: &Tables) -> Snap {
    let t = t.lock().unwrap();
    Snap {
        state: t.state,
        vrps: t.vrps.len(),
        aspas: t.aspa.len(),
        serial: t.serial,
        session_id: t.session_id,
        version: t.protocol_version,
        timing: t.timing,
    }
}

async fn wait_until(t: &Tables, ok: impl Fn(&Snap) -> bool) -> Snap {
    for _ in 0..20_000 {
        let s = snap(t);
        if ok(&s) {
            return s;
        }
        tokio::time::sleep(Duration::from_millis(1)).await;
    }
    panic!("tables never reached the expected state: {:?}", snap(t));
}

// ---- 1. full refresh (§8.1) ------------------------------------------

#[tokio::test(start_paused = true)]
async fn full_refresh_populates_tables() {
    let _serial = serial();
    let fx = Fixture::new().await;
    let mut cache = fx.accept().await;

    expect(&mut cache, Pdu::ResetQuery { version: VERSION_2 }).await;

    let sid = 0x1234;
    send(&mut cache, &cache_response(VERSION_2, sid)).await;
    send(&mut cache, &roa4(VERSION_2, "192.0.2.0/24", 24, 64512)).await;
    send(&mut cache, &roa4(VERSION_2, "198.51.100.0/24", 24, 64513)).await;
    send(
        &mut cache,
        &Pdu::Ipv6Prefix {
            version: VERSION_2,
            flags: PayloadFlags::ANNOUNCE,
            prefix: "2001:db8::/32".parse().unwrap(),
            max_len: 48,
            asn: 64512,
        },
    )
    .await;
    send(&mut cache, &aspa_announce(64512, vec![64500])).await;
    send(
        &mut cache,
        &Pdu::RouterKey {
            version: VERSION_2,
            flags: PayloadFlags::ANNOUNCE,
            ski: [7u8; 20],
            asn: 64512,
            spki: vec![0x30, 0x59],
        },
    )
    .await;
    send(&mut cache, &eod(VERSION_2, sid, 5, Timing::DEFAULT)).await;

    let s = wait_until(&fx.tables, |s| s.state == CacheState::Fresh).await;
    assert_eq!(s.vrps, 3);
    assert_eq!(s.aspas, 1);
    assert_eq!(s.serial, Some(5));
    assert_eq!(s.session_id, Some(sid));
    assert_eq!(s.version, Some(VERSION_2));
    assert_eq!(s.timing, Some(Timing::DEFAULT));
    // Router keys stored pass-through.
    assert_eq!(fx.tables.lock().unwrap().router_keys.len(), 1);

    fx.stop().await;
}

// ---- 2. incremental serial update (§8.2) -----------------------------

#[tokio::test(start_paused = true)]
async fn serial_notify_drives_incremental_update() {
    let _serial = serial();
    let fx = Fixture::new().await;
    let mut cache = fx.accept().await;
    expect(&mut cache, Pdu::ResetQuery { version: VERSION_2 }).await;
    let sid = 0x1234;
    send(&mut cache, &cache_response(VERSION_2, sid)).await;
    send(&mut cache, &roa4(VERSION_2, "192.0.2.0/24", 24, 64512)).await;
    send(&mut cache, &roa4(VERSION_2, "198.51.100.0/24", 24, 64513)).await;
    send(&mut cache, &aspa_announce(64512, vec![64500])).await;
    send(&mut cache, &eod(VERSION_2, sid, 5, Timing::DEFAULT)).await;
    wait_until(&fx.tables, |s| s.state == CacheState::Fresh).await;

    // The cache's data updated: a Serial Notify hints at serial 6.
    send(
        &mut cache,
        &Pdu::SerialNotify {
            version: VERSION_2,
            session_id: sid,
            serial: 6,
        },
    )
    .await;
    expect(
        &mut cache,
        Pdu::SerialQuery {
            version: VERSION_2,
            session_id: sid,
            serial: 5,
        },
    )
    .await;

    // Deltas since serial 5: withdraw one ROA, announce a new one,
    // replace the ASPA (bis §5.12 replacement semantics).
    send(&mut cache, &cache_response(VERSION_2, sid)).await;
    send(&mut cache, &roa4_withdraw(VERSION_2, "198.51.100.0/24", 24, 64513)).await;
    send(&mut cache, &roa4(VERSION_2, "203.0.113.0/24", 24, 64514)).await;
    send(&mut cache, &aspa_announce(64512, vec![64501, 64502])).await;
    send(&mut cache, &eod(VERSION_2, sid, 6, Timing::DEFAULT)).await;

    let s = wait_until(&fx.tables, |s| s.state == CacheState::Serial && s.serial == Some(6)).await;
    assert_eq!(s.vrps, 2); // 2 - 1 + 1
    assert_eq!(s.aspas, 1); // replaced, not added
    let providers = fx
        .tables
        .lock()
        .unwrap()
        .aspa
        .get(64512)
        .map(|s| s.iter().copied().collect::<Vec<u32>>())
        .unwrap();
    assert_eq!(providers, vec![64501, 64502]);

    fx.stop().await;
}

// ---- 3. cache restart → serial mismatch → re-query (§8.3) ------------

#[tokio::test(start_paused = true)]
async fn cache_reset_after_serial_mismatch_falls_back_to_reset_query() {
    let _serial = serial();
    let fx = Fixture::new().await;
    let mut first = fx.accept().await;
    expect(&mut first, Pdu::ResetQuery { version: VERSION_2 }).await;
    let sid = 0x1234;
    send(&mut first, &cache_response(VERSION_2, sid)).await;
    send(&mut first, &roa4(VERSION_2, "192.0.2.0/24", 24, 64512)).await;
    send(&mut first, &eod(VERSION_2, sid, 5, Timing::DEFAULT)).await;
    wait_until(&fx.tables, |s| s.state == CacheState::Fresh).await;

    // Transport drops; the client holds the data (§8.1: Serial Query
    // is appropriate while data is unexpired) and reconnects on the
    // Retry Interval.
    drop(first);
    let mut second = fx.accept().await;
    expect(
        &mut second,
        Pdu::SerialQuery {
            version: VERSION_2,
            session_id: sid,
            serial: 5,
        },
    )
    .await;

    // The cache restarted: it cannot serve serial 5.
    send(&mut second, &Pdu::CacheReset { version: VERSION_2 }).await;
    expect(&mut second, Pdu::ResetQuery { version: VERSION_2 }).await;

    // Full reload at a new serial.
    let new_sid = 0x4321;
    send(&mut second, &cache_response(VERSION_2, new_sid)).await;
    send(&mut second, &roa4(VERSION_2, "192.0.2.0/24", 24, 64512)).await;
    send(&mut second, &roa4(VERSION_2, "198.51.100.0/24", 24, 64513)).await;
    send(&mut second, &eod(VERSION_2, new_sid, 7, Timing::DEFAULT)).await;

    let s = wait_until(&fx.tables, |s| s.state == CacheState::Fresh).await;
    assert_eq!(s.vrps, 2);
    assert_eq!(s.serial, Some(7));
    assert_eq!(s.session_id, Some(new_sid));

    fx.stop().await;
}

// ---- 4. fatal error teardown (§12) ------------------------------------

#[tokio::test(start_paused = true)]
async fn fatal_error_report_drops_and_flushes() {
    let _serial = serial();
    let fx = Fixture::new().await;
    let mut cache = fx.accept().await;
    expect(&mut cache, Pdu::ResetQuery { version: VERSION_2 }).await;
    let sid = 0x1234;
    send(&mut cache, &cache_response(VERSION_2, sid)).await;
    send(&mut cache, &roa4(VERSION_2, "192.0.2.0/24", 24, 64512)).await;
    send(&mut cache, &eod(VERSION_2, sid, 5, Timing::DEFAULT)).await;
    wait_until(&fx.tables, |s| s.state == CacheState::Fresh).await;

    // Code 1 Internal Error is fatal: session drops, data flushes.
    send(&mut cache, &error_report(VERSION_2, ErrorCode::InternalError, "oom")).await;

    let s = wait_until(&fx.tables, |s| s.state == CacheState::None && s.vrps == 0).await;
    assert_eq!(s.serial, None);
    // The client closed its side.
    let mut sink = [0u8; 16];
    let n = cache.read(&mut sink).await.unwrap();
    assert_eq!(n, 0, "client should have closed the connection");

    fx.stop().await;
}

// ---- 5. version downgrade v2 → v1 (§7) --------------------------------

#[tokio::test(start_paused = true)]
async fn unsupported_version_downgrades_to_cache_version() {
    let _serial = serial();
    let fx = Fixture::new().await;
    let mut cache = fx.accept().await;

    expect(&mut cache, Pdu::ResetQuery { version: VERSION_2 }).await;
    send(
        &mut cache,
        &error_report(VERSION_1, ErrorCode::UnsupportedProtocolVersion, "try v1"),
    )
    .await;

    // bis §7: re-query at the version the error named.
    expect(&mut cache, Pdu::ResetQuery { version: VERSION_1 }).await;
    let sid = 0x00ff;
    send(&mut cache, &cache_response(VERSION_1, sid)).await;
    send(&mut cache, &roa4(VERSION_1, "192.0.2.0/24", 24, 64512)).await;
    send(&mut cache, &eod(VERSION_1, sid, 1, Timing::DEFAULT)).await;

    let s = wait_until(&fx.tables, |s| s.state == CacheState::Fresh).await;
    assert_eq!(s.version, Some(VERSION_1));
    assert_eq!(s.vrps, 1);

    fx.stop().await;
}

// ---- 6. no data available (§8.4) ---------------------------------------

#[tokio::test(start_paused = true)]
async fn no_data_available_marks_state_and_retries() {
    let _serial = serial();
    let fx = Fixture::new().await;
    let mut cache = fx.accept().await;

    expect(&mut cache, Pdu::ResetQuery { version: VERSION_2 }).await;
    send(
        &mut cache,
        &error_report(VERSION_2, ErrorCode::NoDataAvailable, "rebuilding"),
    )
    .await;
    wait_until(&fx.tables, |s| s.state == CacheState::NoData).await;

    // §8.4: periodic Reset Queries until a usable load arrives — on
    // the Retry Interval, on the same connection.
    expect(&mut cache, Pdu::ResetQuery { version: VERSION_2 }).await;
    let sid = 0x1234;
    send(&mut cache, &cache_response(VERSION_2, sid)).await;
    send(&mut cache, &roa4(VERSION_2, "192.0.2.0/24", 24, 64512)).await;
    send(&mut cache, &eod(VERSION_2, sid, 1, Timing::DEFAULT)).await;

    let s = wait_until(&fx.tables, |s| s.state == CacheState::Fresh).await;
    assert_eq!(s.vrps, 1);

    fx.stop().await;
}

// ---- 7. duplicate announcement (§5.6 → code 7) -------------------------

#[tokio::test(start_paused = true)]
async fn duplicate_announcement_reports_code7_and_flushes() {
    let _serial = serial();
    let fx = Fixture::new().await;
    let mut cache = fx.accept().await;
    expect(&mut cache, Pdu::ResetQuery { version: VERSION_2 }).await;
    let sid = 0x1234;
    send(&mut cache, &cache_response(VERSION_2, sid)).await;
    let dup = roa4(VERSION_2, "192.0.2.0/24", 24, 64512);
    send(&mut cache, &dup).await;
    // The same {Prefix, Len, Max-Len, ASN} twice: RFC 8210 §5.6 says
    // the router SHOULD raise code 7.
    send(&mut cache, &dup).await;

    let raw = read_one(&mut cache).await;
    let (report, _) = Pdu::decode(&raw).unwrap();
    let Pdu::ErrorReport {
        error_code,
        erroneous_pdu,
        ..
    } = &report
    else {
        panic!("expected an error report, got {report:?}")
    };
    assert_eq!(*error_code, ErrorCode::DuplicateAnnouncementReceived);
    // The offending PDU is encapsulated verbatim.
    let expected = dup.encode(VERSION_2).unwrap();
    assert_eq!(erroneous_pdu, &expected);

    let s = wait_until(&fx.tables, |s| s.state == CacheState::None && s.vrps == 0).await;
    assert_eq!(s.serial, None);

    fx.stop().await;
}

// ---- 8. refresh keep-alive + expire interval (§6) ----------------------

#[tokio::test(start_paused = true)]
async fn refresh_keepalive_then_expiry_flushes() {
    let _serial = serial();
    let fx = Fixture::new().await;
    let mut cache = fx.accept().await;
    expect(&mut cache, Pdu::ResetQuery { version: VERSION_2 }).await;
    let sid = 0x1234;
    // Tight-but-legal ordering: refresh at 1 s, expire at 2 s, so the
    // keep-alive Serial Query is observable before expiry.
    let timing = Timing {
        refresh_interval: 1,
        retry_interval: 1,
        expire_interval: 2,
    };
    send(&mut cache, &cache_response(VERSION_2, sid)).await;
    send(&mut cache, &roa4(VERSION_2, "192.0.2.0/24", 24, 64512)).await;
    send(&mut cache, &eod(VERSION_2, sid, 5, timing)).await;
    wait_until(&fx.tables, |s| s.state == CacheState::Fresh).await;

    // §6/§8.1: the refresh poll is the application-layer keep-alive.
    expect(
        &mut cache,
        Pdu::SerialQuery {
            version: VERSION_2,
            session_id: sid,
            serial: 5,
        },
    )
    .await;

    // The cache goes silent; past the Expire Interval the data "MUST
    // NOT" be retained.
    let s = wait_until(&fx.tables, |s| s.state == CacheState::None && s.vrps == 0).await;
    assert_eq!(s.serial, None);

    fx.stop().await;
}

// ---- 9. session-id mismatch (§5.1 → code 0) ----------------------------

#[tokio::test(start_paused = true)]
async fn session_id_change_terminates_with_code0_and_flushes() {
    let _serial = serial();
    let fx = Fixture::new().await;
    let mut cache = fx.accept().await;
    expect(&mut cache, Pdu::ResetQuery { version: VERSION_2 }).await;
    let sid = 0x1234;
    send(&mut cache, &cache_response(VERSION_2, sid)).await;
    send(&mut cache, &roa4(VERSION_2, "192.0.2.0/24", 24, 64512)).await;
    send(&mut cache, &eod(VERSION_2, sid, 5, Timing::DEFAULT)).await;
    wait_until(&fx.tables, |s| s.state == CacheState::Fresh).await;

    // A notify from a "different cache instance" (new Session ID):
    // §5.1 demands immediate termination with Error Code 0 and a full
    // flush.
    send(
        &mut cache,
        &Pdu::SerialNotify {
            version: VERSION_2,
            session_id: 0x9999,
            serial: 6,
        },
    )
    .await;

    let report = read_skipping_refresh_queries(&mut cache, sid, 5).await;
    let Pdu::ErrorReport { error_code, .. } = &report else {
        panic!("expected an error report, got {report:?}")
    };
    assert_eq!(*error_code, ErrorCode::CorruptData);

    let s = wait_until(&fx.tables, |s| s.state == CacheState::None && s.vrps == 0).await;
    assert_eq!(s.session_id, None);

    fx.stop().await;
}
