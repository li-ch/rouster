//! zapi-sniff — empirical ZAPI wire capture (debug tool, NOT production surface).
//!
//! Masquerades as zebra: binds the Unix socket FRR daemons are pointed at via
//! `-z`, accepts their connections, and logs every ZAPI message they send —
//! timestamp, connection id, hex header, hex body, and a one-line decode via
//! [`zapi::ZapiHeader::decode`] with the command number as-is. The point is to
//! pin FRR 10.2.2 command numbers and body layouts from a real release
//! (docs/interop/zapi-10.2-pinned.md) instead of guessing; the captured logs
//! under `crates/zapi/tests/fixtures/` become golden fixtures for the codec.
//!
//! With `--respond-hello` it additionally replies to the first message whose
//! command equals `--hello-cmd` (default 8, the empirically confirmed
//! ZEBRA_HELLO) by echoing back a minimal HELLO of the same body — to see how
//! far a daemon proceeds when zebra talks back. If the daemon hangs up, run
//! without it: silent mode still captures the initial burst, and daemons
//! reconnect, so retries are captured too.
//!
//! Dependency-free by design: std + tokio + the crate's own header codec.
//! Usage: zapi-sniff --socket /var/run/frr/zserv.api --log /tmp/cap.log
//!                 [--respond-hello] [--hello-cmd N]

use std::io::Write as _;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{UnixListener, UnixStream};

use zapi::header::ZapiHeaderError;
use zapi::{ZapiHeader, ZAPI_HEADER_LEN};

/// Max bytes buffered per connection before we declare the peer garbage and
/// hang up (a stuck resync must not grow memory forever). ZAPI messages are
/// small (STREAM_SIZE in FRR is a few KiB); 1 MiB is far above any real burst.
const MAX_BUF: usize = 1024 * 1024;

/// One parsed wire frame.
#[derive(Debug, PartialEq, Eq)]
struct Frame {
    header: ZapiHeader,
    body: Vec<u8>,
}

/// Try to parse one ZAPI frame off the front of `buf`.
///
/// Returns `Ok(Some(frame))` when a complete frame is present, `Ok(None)`
/// when more bytes are needed (caller reads again), and `Err` when the header
/// itself is malformed — callers resync by dropping one byte and retrying.
/// Resync is best-effort: a misaligned prefix that happens to form a
/// plausible-but-large length makes the parser wait instead of erroring
/// (bounded by MAX_BUF). Peers that speak clean ZAPI from byte zero, like FRR
/// daemons connecting to a fresh socket, never hit this.
fn parse_frame(buf: &[u8]) -> Result<Option<Frame>, ZapiHeaderError> {
    if buf.len() < ZAPI_HEADER_LEN {
        return Ok(None);
    }
    let header = ZapiHeader::decode(buf)?;
    let total = header.length as usize;
    if buf.len() < total {
        return Ok(None);
    }
    let body = buf[ZAPI_HEADER_LEN..total].to_vec();
    Ok(Some(Frame { header, body }))
}

/// ISO-8601 UTC timestamp with microseconds, no external crates (Howard
/// Hinnant's civil-from-days algorithm).
fn iso8601_now() -> String {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("clock before epoch");
    let secs = now.as_secs() as i64;
    let micros = now.subsec_micros();
    let days = secs.div_euclid(86_400);
    let secs_of_day = secs.rem_euclid(86_400);
    let (h, m, s) = (
        secs_of_day / 3600,
        (secs_of_day % 3600) / 60,
        secs_of_day % 60,
    );
    // civil_from_days: days since 1970-01-01 -> (y, m, d)
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let mth = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if mth <= 2 { y + 1 } else { y };
    format!("{y:04}-{mth:02}-{d:02}T{h:02}:{m:02}:{s:02}.{micros:06}Z")
}

fn hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

/// Shared append-only log file (each connection task holds a clone of the Arc).
type LogSink = Arc<Mutex<std::fs::File>>;

fn log_line(sink: &LogSink, line: &str) {
    let mut f = sink.lock().expect("log sink poisoned");
    let _ = writeln!(f, "{line}");
    let _ = f.flush();
}

struct Args {
    socket: PathBuf,
    log: PathBuf,
    respond_hello: bool,
    hello_cmd: u16,
}

fn parse_args() -> Result<Args, String> {
    let mut socket = None;
    let mut log = None;
    let mut respond_hello = false;
    let mut hello_cmd: u16 = 8;
    let mut it = std::env::args().skip(1);
    while let Some(arg) = it.next() {
        match arg.as_str() {
            "--socket" | "-s" => socket = Some(it.next().ok_or("--socket needs a value")?.into()),
            "--log" | "-l" => log = Some(it.next().ok_or("--log needs a value")?.into()),
            "--respond-hello" => respond_hello = true,
            "--hello-cmd" => {
                hello_cmd = it
                    .next()
                    .ok_or("--hello-cmd needs a value")?
                    .parse()
                    .map_err(|e| format!("bad --hello-cmd: {e}"))?
            }
            other => return Err(format!("unknown argument: {other}")),
        }
    }
    Ok(Args {
        socket: socket.ok_or("--socket is required (e.g. /var/run/frr/zserv.api)")?,
        log: log.ok_or("--log is required")?,
        respond_hello,
        hello_cmd,
    })
}

#[tokio::main]
async fn main() -> std::process::ExitCode {
    let args = match parse_args() {
        Ok(a) => a,
        Err(e) => {
            eprintln!("zapi-sniff: {e}");
            eprintln!(
                "usage: zapi-sniff --socket PATH --log PATH [--respond-hello] [--hello-cmd N]"
            );
            return std::process::ExitCode::from(2);
        }
    };
    let file = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&args.log)
        .unwrap_or_else(|e| panic!("cannot open log {}: {e}", args.log.display()));
    let sink: LogSink = Arc::new(Mutex::new(file));
    log_line(
        &sink,
        &format!(
            "ts={} event=START socket={} respond_hello={} hello_cmd={}",
            iso8601_now(),
            args.socket.display(),
            args.respond_hello,
            args.hello_cmd
        ),
    );

    if args.socket.exists() {
        std::fs::remove_file(&args.socket).expect("cannot remove stale socket");
    }
    let listener = UnixListener::bind(&args.socket)
        .unwrap_or_else(|e| panic!("cannot bind {}: {e}", args.socket.display()));
    // FRR daemons drop privileges to user `frr`, and connecting to a Unix
    // socket requires WRITE permission on the socket file. A root-owned 755
    // socket is unreachable for them (empirically confirmed: staticd silently
    // retries forever). Widen to 666 — this is a debug tool in a container;
    // the real ZAPI server will manage ownership properly.
    let _ = std::fs::set_permissions(
        &args.socket,
        std::os::unix::fs::PermissionsExt::from_mode(0o666),
    );
    eprintln!(
        "zapi-sniff: listening on {} (log: {})",
        args.socket.display(),
        args.log.display()
    );

    let next_conn = Arc::new(AtomicU64::new(1));
    loop {
        let (stream, _addr) = match listener.accept().await {
            Ok(x) => x,
            Err(e) => {
                eprintln!("zapi-sniff: accept failed: {e}");
                continue;
            }
        };
        let conn = next_conn.fetch_add(1, Ordering::SeqCst);
        let sink = Arc::clone(&sink);
        let respond_hello = args.respond_hello;
        let hello_cmd = args.hello_cmd;
        tokio::spawn(async move {
            handle_conn(stream, conn, sink, respond_hello, hello_cmd).await;
        });
    }
}

async fn handle_conn(
    mut stream: UnixStream,
    conn: u64,
    sink: LogSink,
    respond_hello: bool,
    hello_cmd: u16,
) {
    log_line(
        &sink,
        &format!("ts={} conn={conn} event=CONNECT", iso8601_now()),
    );
    let mut buf: Vec<u8> = Vec::with_capacity(4096);
    let mut chunk = [0u8; 4096];
    let mut msgs: u64 = 0;
    let mut replied = false;
    'conn: loop {
        // Parse as many whole frames as the buffer holds, then read more.
        loop {
            match parse_frame(&buf) {
                Ok(Some(frame)) => {
                    let total = frame.header.length as usize;
                    buf.drain(..total);
                    msgs += 1;
                    log_line(
                        &sink,
                        &format!(
                            "ts={} conn={conn} msg={msgs} cmd={} len={} marker={} version={} vrf={} hdr={} body={} decode={:?}",
                            iso8601_now(),
                            frame.header.command,
                            frame.header.length,
                            frame.header.marker,
                            frame.header.version,
                            frame.header.vrf_id,
                            header_hex(&frame.header),
                            hex(&frame.body),
                            frame.header,
                        ),
                    );
                    if respond_hello && !replied && frame.header.command == hello_cmd {
                        replied = true;
                        let mut reply = vec![0u8; ZAPI_HEADER_LEN];
                        ZapiHeader::new(
                            frame.header.command,
                            frame.header.vrf_id,
                            frame.body.len(),
                        )
                        .encode(&mut reply);
                        reply.extend_from_slice(&frame.body);
                        match stream.write_all(&reply).await {
                            Ok(()) => log_line(
                                &sink,
                                &format!(
                                    "ts={} conn={conn} event=REPLY cmd={} len={} body={}",
                                    iso8601_now(),
                                    frame.header.command,
                                    reply.len(),
                                    hex(&frame.body),
                                ),
                            ),
                            Err(e) => log_line(
                                &sink,
                                &format!(
                                    "ts={} conn={conn} event=REPLY_FAILED err={e}",
                                    iso8601_now()
                                ),
                            ),
                        }
                    }
                }
                Ok(None) => break, // need more bytes
                Err(e) => {
                    log_line(
                        &sink,
                        &format!(
                            "ts={} conn={conn} event=HEADER_ERROR err={e:?} skipping=1byte at={}",
                            iso8601_now(),
                            hex(&buf[..buf.len().min(ZAPI_HEADER_LEN)])
                        ),
                    );
                    if buf.is_empty() {
                        continue 'conn;
                    }
                    buf.remove(0); // resync: slide one byte and retry
                }
            }
            if buf.len() > MAX_BUF {
                log_line(
                    &sink,
                    &format!(
                        "ts={} conn={conn} event=BUFFER_OVERFLOW limit={MAX_BUF}",
                        iso8601_now()
                    ),
                );
                break 'conn;
            }
        }
        let n = match stream.read(&mut chunk).await {
            Ok(0) => break,
            Ok(n) => n,
            Err(e) => {
                log_line(
                    &sink,
                    &format!("ts={} conn={conn} event=READ_ERR err={e}", iso8601_now()),
                );
                break;
            }
        };
        buf.extend_from_slice(&chunk[..n]);
        if buf.len() > MAX_BUF {
            log_line(
                &sink,
                &format!(
                    "ts={} conn={conn} event=BUFFER_OVERFLOW limit={MAX_BUF}",
                    iso8601_now()
                ),
            );
            break;
        }
    }
    let _ = stream.shutdown().await;
    log_line(
        &sink,
        &format!(
            "ts={} conn={conn} event=EOF msgs={msgs} buffered={}",
            iso8601_now(),
            buf.len()
        ),
    );
}

fn header_hex(header: &ZapiHeader) -> String {
    let mut v = vec![0u8; ZAPI_HEADER_LEN];
    header.encode(&mut v);
    hex(&v)
}

#[cfg(test)]
mod tests {
    use super::*;
    use zapi::{ZAPI_MARKER, ZAPI_VERSION};

    fn frame_bytes(command: u16, vrf_id: u32, body: &[u8]) -> Vec<u8> {
        let mut v = vec![0u8; ZAPI_HEADER_LEN];
        ZapiHeader::new(command, vrf_id, body.len()).encode(&mut v);
        v.extend_from_slice(body);
        v
    }

    #[test]
    fn parses_complete_frame_with_body() {
        let bytes = frame_bytes(8, 0, &[0, 0, 0, 1, 0]);
        let f = parse_frame(&bytes)
            .expect("header decodes")
            .expect("complete");
        assert_eq!(f.header.command, 8);
        assert_eq!(f.header.marker, ZAPI_MARKER);
        assert_eq!(f.header.version, ZAPI_VERSION);
        assert_eq!(f.header.vrf_id, 0);
        assert_eq!(f.body, vec![0, 0, 0, 1, 0]);
    }

    #[test]
    fn waits_when_body_incomplete() {
        let bytes = frame_bytes(23, 7, &[0xaa; 10]);
        assert!(parse_frame(&bytes[..15]).expect("decodes").is_none());
        assert!(parse_frame(&bytes[..bytes.len() - 1])
            .expect("decodes")
            .is_none());
        assert!(parse_frame(&bytes).expect("decodes").is_some());
    }

    #[test]
    fn waits_when_header_incomplete() {
        let bytes = frame_bytes(23, 7, &[0xaa; 4]);
        for cut in 0..ZAPI_HEADER_LEN {
            assert!(parse_frame(&bytes[..cut]).expect("decodes").is_none());
        }
        assert!(parse_frame(&bytes).expect("decodes").is_some());
    }

    #[test]
    fn rejects_bad_length_before_bodying() {
        // length field says 4 (< header len): malformed regardless of body.
        let mut bytes = frame_bytes(8, 0, &[0; 3]);
        bytes[0] = 0;
        bytes[1] = 4;
        assert_eq!(parse_frame(&bytes), Err(ZapiHeaderError::BadLength(4)));
    }

    #[test]
    fn resync_finds_frame_after_garbage_prefix() {
        let good = frame_bytes(5, 0, &[1, 2, 3]);
        let mut bytes = vec![0xff, 0xfe, 0xed]; // 3 garbage bytes
        bytes.extend_from_slice(&good);
        // Whole buffer: the first parse fails (garbage decodes to a zero
        // version) — the signal the resync loop drops one byte on. Not every
        // misaligned prefix errors: e.g. skipping just one byte forms a
        // plausible-but-huge length (0xfeed) and the parser WAITS instead —
        // resync is best-effort, bounded by MAX_BUF.
        assert!(parse_frame(&bytes).is_err());
        assert_eq!(
            parse_frame(&bytes[1..]).expect("decodes"),
            None,
            "garbage length 0xfeed makes the parser wait for more bytes"
        );
        // Skip exactly the garbage and the frame is found intact.
        let f = parse_frame(&bytes[3..])
            .expect("decodes")
            .expect("complete");
        assert_eq!(f.header.command, 5);
        assert_eq!(f.body, vec![1, 2, 3]);
    }
}
