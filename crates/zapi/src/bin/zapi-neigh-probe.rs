//! zapi-neigh-probe — empirical capture tool for the neighbour messages
//! (NEIGH_REGISTER/ADDED/REMOVED) and the VRF/table-carrying interface
//! and redistribute-route bodies (debug, NOT production surface).
//!
//! The CLIENT twin of zapi-sniff (same pattern as zapi-notify-probe):
//! connects to a REAL zebra's zserv socket, sends a registration burst,
//! and logs every frame zebra pushes back — timestamp, command, hex
//! header/body, best-effort codec decode. The script driving the
//! container mutates kernel state during the capture window (neighbour
//! add/replace/del on a dummy, VRF device + slave, static routes in the
//! main and a VRF table) so the asynchronous pushes arrive in-window:
//!
//!   - ZEBRA_NEIGH_REGISTER (131): body pinned from the frr-10.2.2
//!     source (cached `lib/zclient.c` `zclient_register_neigh`: `afi`
//!     u16) — the probe sends `0001` (AFI_IP) and the pin is whether
//!     zebra then pushes ZEBRA_NEIGH_ADDED (128) / ZEBRA_NEIGH_REMOVED
//!     (129) as neighbours change, and their exact bodies.
//!   - INTERFACE_ADD (0) request: with a VRF device + enslaved dummy in
//!     place, the mirror dump's frames pin what a VRF slave's body
//!     carries (the `link_ifindex` field) and whether the vrf device
//!     itself is dumped (plus the connect-time VRF_ADD (33) frames).
//!   - REDISTRIBUTE_ADD (12, static): static routes added in the main
//!     table and in a VRF table during the window pin the
//!     REDISTRIBUTE_ROUTE_ADD (31) body's TABLEID field policy.
//!
//! Sends raw pinned bytes (fixture bodies captured from real daemons),
//! not re-encodings, so the outgoing side is byte-identical to a real
//! client regardless of codec drift.
//!
//! Usage: zapi-neigh-probe --socket /var/run/frr/zserv.api --log /tmp/cap.log
//!                     [--secs 20]

use std::io::Write as _;
use std::path::PathBuf;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixStream;
use tokio::time::{timeout, Duration};

use zapi::{ZapiHeader, ZapiMessage, ZAPI_HEADER_LEN};

/// HELLO (19) body, the exact 8 bytes staticd sends (fixture pin).
const HELLO_BODY: &[u8] = &[0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];

/// ZEBRA_NEIGH_REGISTER (131) body, source-pinned from the cached
/// frr-10.2.2 `lib/zclient.c` (`zclient_register_neigh`): `afi` u16 —
/// AFI_IP = 1.
const NEIGH_REGISTER_BODY: &[u8] = &[0x00, 0x01];

/// ZEBRA_REDISTRIBUTE_ADD (12) body, the pinned bgpd fixture shape
/// (`redistribute static`): afi 1 | route type 4 (STATIC) | instance 0.
const REDISTRIBUTE_ADD_BODY: &[u8] = &[0x01, 0x04, 0x00, 0x00];

/// Command numbers of interest (pinned doc table; the probes assert
/// them in tests, non-test builds just carry the constants for clarity).
#[allow(dead_code)]
const ZEBRA_NEIGH_ADDED: u16 = 128;
#[allow(dead_code)]
const ZEBRA_NEIGH_REMOVED: u16 = 129;
#[allow(dead_code)]
const ZEBRA_INTERFACE_ADD: u16 = 0;
#[allow(dead_code)]
const ZEBRA_REDISTRIBUTE_ROUTE_ADD: u16 = 31;
#[allow(dead_code)]
const ZEBRA_VRF_ADD: u16 = 33;

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

/// One-way decode line for an inbound frame.
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
    let mut secs: u64 = 20;
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
            eprintln!("zapi-neigh-probe: {e}");
            eprintln!("usage: zapi-neigh-probe --socket PATH --log PATH [--secs N]");
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
                "zapi-neigh-probe: connect to {} failed: {e}",
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

    // Registration burst: HELLO, neighbour interest (afi IPv4), interface
    // state request (empty body), redistribute static.
    let burst: [(&str, u16, &[u8]); 4] = [
        ("HELLO", 19u16, HELLO_BODY),
        ("NEIGH_REGISTER", 131, NEIGH_REGISTER_BODY),
        ("INTERFACE_ADD_REQUEST", 0, &[]),
        ("REDISTRIBUTE_ADD", 12, REDISTRIBUTE_ADD_BODY),
    ];
    for (name, command, body) in burst {
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

    // Capture window: the driving script mutates kernel/zebra state
    // (neighbours, routes) while this loop records every pushed frame.
    let mut counts = std::collections::BTreeMap::new();
    let window = Duration::from_secs(args.secs);
    let mut header_buf = [0u8; ZAPI_HEADER_LEN];
    let started = std::time::Instant::now();
    loop {
        let remaining = window.saturating_sub(started.elapsed());
        if remaining.is_zero() {
            break;
        }
        let header = match timeout(remaining, stream.read_exact(&mut header_buf)).await {
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
        match timeout(
            window.saturating_sub(started.elapsed()),
            stream.read_exact(&mut body),
        )
        .await
        {
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
        *counts.entry(header.command).or_insert(0usize) += 1;
        log_line(
            &file,
            &format!(
                "ts={} cmd={} len={} vrf={} hdr={} body={} decode={}",
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
    let summary: Vec<String> = counts
        .iter()
        .map(|(&cmd, &n)| format!("cmd{cmd}={n}"))
        .collect();
    log_line(
        &file,
        &format!("ts={} event=END {}", iso8601_now(), summary.join(" ")),
    );
    eprintln!(
        "zapi-neigh-probe: window done, {} (log: {})",
        summary.join(" "),
        args.log.display()
    );
    std::process::ExitCode::SUCCESS
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The outgoing HELLO must stay byte-identical to the staticd fixture.
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

    /// NEIGH_REGISTER body is the source-pinned shape: exactly `afi` u16,
    /// AFI_IP = 1.
    #[test]
    fn neigh_register_body_is_source_pinned_shape() {
        assert_eq!(NEIGH_REGISTER_BODY, &[0x00, 0x01]);
        assert_eq!(NEIGH_REGISTER_BODY.len(), 2, "afi u16 and nothing else");
    }

    /// REDISTRIBUTE_ADD body is the pinned bgpd fixture shape.
    #[test]
    fn redistribute_add_body_is_fixture_shape() {
        assert_eq!(REDISTRIBUTE_ADD_BODY, &[0x01, 0x04, 0x00, 0x00]);
        match ZapiMessage::decode(12, REDISTRIBUTE_ADD_BODY).unwrap() {
            ZapiMessage::RedistributeAdd(redist) => {
                assert_eq!(redist.afi, 1);
                assert_eq!(redist.route_type, zapi::route_type::STATIC);
            }
            other => panic!("not a RedistributeAdd: {other:?}"),
        }
    }

    /// Frame builder wraps a well-formed header around each pinned body.
    #[test]
    fn frame_wraps_header_around_body() {
        let out = frame(131, NEIGH_REGISTER_BODY);
        assert_eq!(out.len(), ZAPI_HEADER_LEN + 2);
        let header = ZapiHeader::decode(&out[..ZAPI_HEADER_LEN]).unwrap();
        assert_eq!(header.command, 131);
        assert_eq!(header.length as usize, out.len());
    }

    /// The command numbers of interest match the pinned doc table.
    #[test]
    fn command_numbers_match_pinned_table() {
        assert_eq!(ZEBRA_NEIGH_ADDED, 128);
        assert_eq!(ZEBRA_NEIGH_REMOVED, 129);
        assert_eq!(ZEBRA_INTERFACE_ADD, 0);
        assert_eq!(ZEBRA_REDISTRIBUTE_ROUTE_ADD, 31);
        assert_eq!(ZEBRA_VRF_ADD, 33);
    }
}
