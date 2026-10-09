//! zapi-notify-probe — empirical ROUTE_NOTIFY_OWNER capture tool (debug,
//! NOT production surface).
//!
//! The CLIENT twin of zapi-sniff: instead of masquerading as zebra, it
//! connects to a REAL zebra's zserv socket as a daemon would, sends the
//! staticd-shaped burst HELLO + ROUTE_NOTIFY_REQUEST(126) + ROUTE_ADD, and
//! logs every frame zebra returns — timestamp, command, hex header, hex
//! body, and a one-line decode via [`zapi::ZapiMessage::decode`] when the
//! codec knows the command. The object under test is
//! ZEBRA_ROUTE_NOTIFY_OWNER (11): whether zebra answers the REQUEST at all
//! (no-answer is also a pin) and the exact body it sends asynchronously
//! when the added route's install status is decided
//! (docs/interop/zapi-10.2-pinned.md).
//!
//! Sends raw pinned bytes (fixture bodies captured from staticd), not
//! re-encodings, so the outgoing side is byte-identical to the captured
//! daemon regardless of codec drift.
//!
//! Dependency-free by design: std + tokio + the crate's own codec.
//! Usage: zapi-notify-probe --socket /var/run/frr/zserv.api --log /tmp/cap.log
//!                     [--secs 10]
//!
//! Exit code 0 when the capture window elapsed (log is the evidence); 1 on
//! connect/write failure.

use std::io::Write as _;
use std::path::PathBuf;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixStream;
use tokio::time::{timeout, Duration};

use zapi::{ZapiHeader, ZapiMessage, ZAPI_HEADER_LEN};

/// HELLO (19) body, the exact 8 bytes staticd sends: redist_default=4
/// (ZEBRA_ROUTE_STATIC), instance 0, session_id 0, synchronous 0
/// (client.rs fixture pin).
const HELLO_BODY: &[u8] = &[0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];

/// ROUTE_NOTIFY_REQUEST (126) body, the pinned staticd byte: flag = 1
/// (enable owner-status notifications).
const NOTIFY_REQ_BODY: &[u8] = &[0x01];

/// ROUTE_ADD (9) body, the exact fixture bytes staticd sends for its
/// blackhole 203.0.113.0/24 (client.rs fixture pin): type 4 (STATIC),
/// instance 0, flags 0x41, message NEXTHOP|DISTANCE, safi 1, one BLACKHOLE
/// nexthop, distance 1.
const ROUTE_ADD_BODY: &[u8] = &[
    0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x41, 0x00, 0x00, 0x00, 0x03, 0x01, 0x02, 0x18, 0xcb, 0x00,
    0x71, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x06, 0x00, 0x01, 0x01,
];

/// ROUTE_DELETE (10) body for the same prefix, the exact fixture shape
/// staticd sends: 20 bytes = header fields + prefix + u16 NEXTHOP count
/// 0 + distance 1. The count is u16; one byte short makes zebra parse
/// count=1 and die reading the phantom nexthop's vrf u32. Sent
/// mid-window so the capture also covers the REMOVED-flavour notify for
/// the delete path.
const ROUTE_DELETE_BODY: &[u8] = &[
    0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x41, 0x00, 0x00, 0x00, 0x03, 0x01, 0x02, 0x18, 0xcb, 0x00,
    0x71, 0x00, 0x00, 0x01,
];

/// ZEBRA_ROUTE_NOTIFY_OWNER command number (pinned doc table row 11).
const ZEBRA_ROUTE_NOTIFY_OWNER: u16 = 11;

/// ISO-8601 UTC timestamp with microseconds (same helper as zapi-sniff).
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

/// One outgoing frame, raw and pinned.
fn frame(command: u16, body: &[u8]) -> Vec<u8> {
    let mut v = vec![0u8; ZAPI_HEADER_LEN];
    ZapiHeader::new(command, 0, body.len()).encode(&mut v);
    v.extend_from_slice(body);
    v
}

/// One-way decode line for an inbound frame: the codec's best effort with
/// a marker when it does not model the command (the interesting case for
/// cmd 11 until this capture pins it).
fn decode_line(command: u16, body: &[u8]) -> String {
    match ZapiMessage::decode(command, body) {
        Ok(msg) => format!("{msg:?}"),
        Err(err) => format!("UNDECODABLE: {err}"),
    }
}

struct Args {
    socket: PathBuf,
    log: PathBuf,
    secs: u64,
}

fn parse_args() -> Result<Args, String> {
    let mut socket = None;
    let mut log = None;
    let mut secs: u64 = 10;
    let mut it = std::env::args().skip(1);
    while let Some(arg) = it.next() {
        match arg.as_str() {
            "--socket" | "-s" => socket = Some(it.next().ok_or("--socket needs a value")?.into()),
            "--log" | "-l" => log = Some(it.next().ok_or("--log needs a value")?.into()),
            "--secs" => {
                secs = it
                    .next()
                    .ok_or("--secs needs a value")?
                    .parse()
                    .map_err(|e| format!("bad --secs: {e}"))?
            }
            other => return Err(format!("unknown argument: {other}")),
        }
    }
    Ok(Args {
        socket: socket.ok_or("--socket is required (e.g. /var/run/frr/zserv.api)")?,
        log: log.ok_or("--log is required")?,
        secs,
    })
}

fn log_line(mut f: &std::fs::File, line: &str) {
    let _ = writeln!(f, "{line}");
    let _ = f.flush();
}

#[tokio::main]
async fn main() -> std::process::ExitCode {
    let args = match parse_args() {
        Ok(a) => a,
        Err(e) => {
            eprintln!("zapi-notify-probe: {e}");
            eprintln!("usage: zapi-notify-probe --socket PATH --log PATH [--secs N]");
            return std::process::ExitCode::from(2);
        }
    };
    let file = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&args.log)
        .unwrap_or_else(|e| panic!("cannot open log {}: {e}", args.log.display()));

    let mut stream = match UnixStream::connect(&args.socket).await {
        Ok(s) => s,
        Err(e) => {
            log_line(
                &file,
                &format!("ts={} event=CONNECT_FAILED err={e}", iso8601_now()),
            );
            eprintln!(
                "zapi-notify-probe: connect to {} failed: {e}",
                args.socket.display()
            );
            return std::process::ExitCode::from(1);
        }
    };
    log_line(
        &file,
        &format!(
            "ts={} event=CONNECT socket={} secs={}",
            iso8601_now(),
            args.socket.display(),
            args.secs
        ),
    );

    // The staticd-shaped burst: HELLO, notify request, route add. Logged as
    // SENT lines with the exact bytes so the capture is self-describing.
    for (name, command, body) in [
        ("HELLO", 19u16, HELLO_BODY),
        ("ROUTE_NOTIFY_REQUEST", 126, NOTIFY_REQ_BODY),
        ("ROUTE_ADD", 9, ROUTE_ADD_BODY),
    ] {
        let out = frame(command, body);
        if let Err(e) = stream.write_all(&out).await {
            log_line(
                &file,
                &format!("ts={} event=SEND_FAILED name={name} err={e}", iso8601_now()),
            );
            return std::process::ExitCode::from(1);
        }
        log_line(
            &file,
            &format!(
                "ts={} event=SENT name={name} cmd={command} hdr={} body={}",
                iso8601_now(),
                hex(&out[..ZAPI_HEADER_LEN]),
                hex(body),
            ),
        );
    }

    // Capture window: read frames until --secs elapse or zebra hangs up.
    let mut cmd11 = 0usize;
    let mut msgs = 0usize;
    let window = Duration::from_secs(args.secs);
    let mut header_buf = [0u8; ZAPI_HEADER_LEN];
    let mut half = args.secs / 2;
    if half == 0 {
        half = 1;
    }
    // Send the ROUTE_DELETE mid-window: captures any REMOVED-flavour notify
    // while the window is still recording.
    let delete_at = Duration::from_secs(half);
    let mut deleted = false;
    let started = std::time::Instant::now();
    loop {
        let remaining = window.saturating_sub(started.elapsed());
        if remaining.is_zero() {
            break;
        }
        if !deleted && started.elapsed() >= delete_at {
            let out = frame(10, ROUTE_DELETE_BODY);
            if stream.write_all(&out).await.is_ok() {
                log_line(
                    &file,
                    &format!(
                        "ts={} event=SENT name=ROUTE_DELETE cmd=10 hdr={} body={}",
                        iso8601_now(),
                        hex(&out[..ZAPI_HEADER_LEN]),
                        hex(ROUTE_DELETE_BODY),
                    ),
                );
            }
            deleted = true;
        }
        // While the delete is still pending, cap each read at the delete
        // deadline so the loop wakes up to send it (a blocking read_exact
        // would otherwise hold past the deadline until the next frame).
        let read_budget = if deleted {
            remaining
        } else {
            delete_at
                .saturating_sub(started.elapsed())
                .max(Duration::from_millis(50))
        };
        let header = match timeout(read_budget, stream.read_exact(&mut header_buf)).await {
            // Short-budget wake-up before the delete: loop around so the
            // head sends it; after the delete this means the window ended.
            Err(_) if !deleted => continue,
            Err(_) => break, // window elapsed
            Ok(Err(e)) => {
                log_line(
                    &file,
                    &format!("ts={} event=READ_ERR err={e}", iso8601_now()),
                );
                break;
            }
            Ok(Ok(_)) => header_buf,
        };
        let header = match ZapiHeader::decode(&header) {
            Ok(h) => h,
            Err(e) => {
                log_line(
                    &file,
                    &format!(
                        "ts={} event=HEADER_ERROR err={e:?} at={}",
                        iso8601_now(),
                        hex(&header)
                    ),
                );
                break;
            }
        };
        let mut body = vec![0u8; header.length as usize - ZAPI_HEADER_LEN];
        let remaining = window.saturating_sub(started.elapsed());
        match timeout(remaining, stream.read_exact(&mut body)).await {
            Err(_) => {
                log_line(
                    &file,
                    &format!("ts={} event=WINDOW_END mid_body", iso8601_now()),
                );
                break;
            }
            Ok(Err(e)) => {
                log_line(
                    &file,
                    &format!("ts={} event=READ_ERR err={e}", iso8601_now()),
                );
                break;
            }
            Ok(Ok(_)) => {}
        }
        msgs += 1;
        if header.command == ZEBRA_ROUTE_NOTIFY_OWNER {
            cmd11 += 1;
        }
        log_line(
            &file,
            &format!(
                "ts={} msg={msgs} cmd={} len={} vrf={} hdr={} body={} decode={}",
                iso8601_now(),
                header.command,
                header.length,
                header.vrf_id,
                hex(&header_buf),
                hex(&body),
                decode_line(header.command, &body),
            ),
        );
    }
    let _ = stream.shutdown().await;
    log_line(
        &file,
        &format!("ts={} event=END msgs={msgs} cmd11={cmd11}", iso8601_now()),
    );
    eprintln!(
        "zapi-notify-probe: window done, msgs={msgs} cmd11={cmd11} (log: {})",
        args.log.display()
    );
    std::process::ExitCode::SUCCESS
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The outgoing HELLO must be byte-identical to the staticd fixture
    /// body pinned in the codec tests.
    #[test]
    fn hello_body_is_fixture_shape() {
        assert_eq!(HELLO_BODY.len(), 8);
        assert_eq!(HELLO_BODY[0], 0x04, "redist_default = ZEBRA_ROUTE_STATIC");
        let decoded = ZapiMessage::decode(19, HELLO_BODY).unwrap();
        assert_eq!(
            decoded,
            ZapiMessage::Hello(zapi::ZapiHello {
                redist_default: 4,
                instance: 0,
                session_id: 0,
                synchronous: 0,
            })
        );
    }

    /// The outgoing ROUTE_ADD must be byte-identical to the captured
    /// staticd blackhole fixture (client.rs pin) — the tool must not drift
    /// from the pinned bytes.
    #[test]
    fn route_add_body_is_fixture_bytes() {
        assert_eq!(
            ROUTE_ADD_BODY,
            &[
                0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x41, 0x00, 0x00, 0x00, 0x03, 0x01, 0x02, 0x18,
                0xcb, 0x00, 0x71, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x06, 0x00, 0x01, 0x01
            ][..]
        );
        // And it must actually decode as the route it claims to be.
        match ZapiMessage::decode(9, ROUTE_ADD_BODY).unwrap() {
            ZapiMessage::RouteAdd(route) => {
                assert_eq!(route.prefix.to_string(), "203.0.113.0/24");
                assert_eq!(route.route_type, 4);
            }
            other => panic!("not a RouteAdd: {other:?}"),
        }
    }

    /// The outgoing ROUTE_DELETE must decode as a delete of the SAME
    /// prefix the add installed (guards the fixture shape: a stray byte
    /// makes real zebra silently skip the delete — observed live).
    #[test]
    fn route_delete_body_decodes_same_prefix() {
        match ZapiMessage::decode(10, ROUTE_DELETE_BODY).unwrap() {
            ZapiMessage::RouteDelete(route) => {
                assert_eq!(route.prefix.to_string(), "203.0.113.0/24");
                assert!(
                    route.nexthops.is_empty(),
                    "fixture delete carries no nexthops"
                );
            }
            other => panic!("not a RouteDelete: {other:?}"),
        }
    }

    /// Frame builder produces a well-formed versioned header around the
    /// pinned body.
    #[test]
    fn frame_wraps_header_around_body() {
        let out = frame(126, NOTIFY_REQ_BODY);
        assert_eq!(out.len(), ZAPI_HEADER_LEN + 1);
        let header = ZapiHeader::decode(&out[..ZAPI_HEADER_LEN]).unwrap();
        assert_eq!(header.command, 126);
        assert_eq!(header.length as usize, out.len());
        assert_eq!(out[ZAPI_HEADER_LEN], 0x01);
    }
}
