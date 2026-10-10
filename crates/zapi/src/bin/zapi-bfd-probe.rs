//! zapi-bfd-probe — empirical BFD zapi capture tool (debug, NOT production
//! surface).
//!
//! The CLIENT twin of zapi-sniff for the BFD message family: connects to a
//! REAL zebra's zserv socket as a daemon would, sends the bgpd-shaped HELLO
//! + ZEBRA_BFD_CLIENT_REGISTER (36, pid) + one ZEBRA_BFD_DEST_REGISTER
//! (27) for `--peer`, and logs every frame zebra pushes back — the
//! ZEBRA_INTERFACE_BFD_DEST_UPDATE (26) / BFD_DEST_UPDATE (29) bodies the
//! pinned doc needs. With a real bfdd also attached to the same zebra, the
//! registered destination becomes a live BFD session: bringing the peer up
//! and killing it captures the Up and Down pushes.
//!
//! Outgoing REGISTER bodies are built from the W1-b wire pin (a real
//! bgpd 10.2.2 multihop frame, byte-identical golden test below) and the
//! frr-10.2.2 `lib/bfd.c` `zclient_bfd_command` layout: pid u32 | family
//! u16 | dst (4/16) | min_rx u32 | min_tx u32 | detect-mult u8 | mhop u8
//! | family u16 | src (4/16) | hops u8 | ifnamelen u8 [+name] | cbit u8 |
//! profilelen u8 [+name] — all big-endian.
//!
//! Usage: zapi-bfd-probe --socket /var/run/frr/zserv.api --log /tmp/cap.log
//!                --peer 192.0.2.9 [--min-rx 100] [--min-tx 100]
//!                [--detect-mult 3] [--multihop --source 192.0.2.1]
//!                [--vrf 0] [--secs 30] [--deregister-at secs]
//!
//! Exit 0 when the capture window elapsed (log is the evidence); 1 on
//! connect/write failure.

use std::io::Write as _;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::path::PathBuf;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixStream;
use tokio::time::{timeout, Duration};

use zapi::{ZapiHeader, ZapiMessage, ZAPI_HEADER_LEN};

/// ZEBRA_HELLO (19) body, the bgpd main-zclient shape (pinned doc: redist
/// byte 0x0a = ZEBRA_ROUTE_BGP, instance 0, session 0, synchronous 0).
const HELLO_BODY: &[u8] = &[0x0a, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];

/// The BFD_DEST_REGISTER (27) body per the W1-b pin + frr-10.2.2
/// `zclient_bfd_command`. Timers are MILLISECONDS (bgpd's captured frame
/// carried 300/300 = BFD_DEF_MIN_RX/TX).
#[derive(Debug, Clone, PartialEq, Eq)]
struct BfdRegister {
    pid: u32,
    vrf_id: u32,
    dst: IpAddr,
    min_rx_ms: u32,
    min_tx_ms: u32,
    detect_mult: u8,
    mhop: bool,
    src: IpAddr,
    hops: u8,
    ifname: Option<String>,
    cbit: bool,
    profile: Option<String>,
}

impl BfdRegister {
    fn encode(&self) -> Vec<u8> {
        let mut b = Vec::with_capacity(30);
        b.extend_from_slice(&self.pid.to_be_bytes());
        let (family, dst, src): (u16, &[u8], &[u8]) = match (self.dst, self.src) {
            (IpAddr::V4(d), IpAddr::V4(s)) => (2, &d.octets(), &s.octets()),
            (IpAddr::V6(d), IpAddr::V6(s)) => (10, &d.octets(), &s.octets()),
            _ => panic!("src/dst family mismatch"),
        };
        b.extend_from_slice(&family.to_be_bytes());
        b.extend_from_slice(dst);
        b.extend_from_slice(&self.min_rx_ms.to_be_bytes());
        b.extend_from_slice(&self.min_tx_ms.to_be_bytes());
        b.push(self.detect_mult);
        b.push(u8::from(self.mhop));
        b.extend_from_slice(&family.to_be_bytes());
        b.extend_from_slice(src);
        b.push(self.hops);
        // Single-hop carries the interface when known; multihop never does
        // (frr-10.2.2 lib/bfd.c sends ifnamelen 0 when mhop).
        let ifname = if self.mhop { None } else { self.ifname.as_deref() };
        match ifname {
            Some(name) => {
                b.push(name.len() as u8);
                b.extend_from_slice(name.as_bytes());
            }
            None => b.push(0),
        }
        b.push(u8::from(self.cbit));
        match &self.profile {
            Some(p) => {
                b.push(p.len() as u8);
                b.extend_from_slice(p.as_bytes());
            }
            None => b.push(0),
        }
        b
    }
}

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
fn frame(command: u16, vrf_id: u32, body: &[u8]) -> Vec<u8> {
    let mut v = vec![0u8; ZAPI_HEADER_LEN];
    ZapiHeader::new(command, vrf_id, body.len()).encode(&mut v);
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
    peer: IpAddr,
    min_rx: u32,
    min_tx: u32,
    detect_mult: u8,
    multihop: bool,
    source: Option<IpAddr>,
    ifname: Option<String>,
    vrf_id: u32,
    secs: u64,
    /// When set, send ZEBRA_BFD_DEST_DEREGISTER (28) this many seconds into
    /// the window (the deregister pin).
    deregister_at: Option<u64>,
}

fn parse_args() -> Result<Args, String> {
    let mut socket = None;
    let mut log = None;
    let mut peer = None;
    let mut min_rx = 100;
    let mut min_tx = 100;
    let mut detect_mult = 3;
    let mut multihop = false;
    let mut source = None;
    let mut ifname = None;
    let mut vrf_id = 0u32;
    let mut secs = 30u64;
    let mut deregister_at = None;
    let mut it = std::env::args().skip(1);
    while let Some(arg) = it.next() {
        match arg.as_str() {
            "--socket" | "-s" => socket = Some(it.next().ok_or("--socket needs a value")?.into()),
            "--log" | "-l" => log = Some(it.next().ok_or("--log needs a value")?.into()),
            "--peer" | "-p" => {
                peer = Some(
                    it.next()
                        .ok_or("--peer needs a value")?
                        .parse()
                        .map_err(|e| format!("bad --peer: {e}"))?,
                )
            }
            "--min-rx" => {
                min_rx = it
                    .next()
                    .ok_or("--min-rx needs a value")?
                    .parse()
                    .map_err(|e| format!("bad --min-rx: {e}"))?
            }
            "--min-tx" => {
                min_tx = it
                    .next()
                    .ok_or("--min-tx needs a value")?
                    .parse()
                    .map_err(|e| format!("bad --min-tx: {e}"))?
            }
            "--detect-mult" => {
                detect_mult = it
                    .next()
                    .ok_or("--detect-mult needs a value")?
                    .parse()
                    .map_err(|e| format!("bad --detect-mult: {e}"))?
            }
            "--multihop" => multihop = true,
            "--source" => {
                source = Some(
                    it.next()
                        .ok_or("--source needs a value")?
                        .parse()
                        .map_err(|e| format!("bad --source: {e}"))?,
                )
            }
            "--ifname" => {
                ifname = Some(it.next().ok_or("--ifname needs a value")?)
            }
            "--vrf" => {
                vrf_id = it
                    .next()
                    .ok_or("--vrf needs a value")?
                    .parse()
                    .map_err(|e| format!("bad --vrf: {e}"))?
            }
            "--secs" => {
                secs = it
                    .next()
                    .ok_or("--secs needs a value")?
                    .parse()
                    .map_err(|e| format!("bad --secs: {e}"))?
            }
            "--deregister-at" => {
                deregister_at = Some(
                    it.next()
                        .ok_or("--deregister-at needs a value")?
                        .parse()
                        .map_err(|e| format!("bad --deregister-at: {e}"))?,
                )
            }
            other => return Err(format!("unknown argument: {other}")),
        }
    }
    Ok(Args {
        socket: socket.ok_or("--socket is required (e.g. /var/run/frr/zserv.api)")?,
        log: log.ok_or("--log is required")?,
        peer: peer.ok_or("--peer is required (the BFD destination)")?,
        min_rx,
        min_tx,
        detect_mult,
        multihop,
        source,
        ifname,
        vrf_id,
        secs,
        deregister_at,
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
            eprintln!("zapi-bfd-probe: {e}");
            eprintln!(
                "usage: zapi-bfd-probe --socket PATH --log PATH --peer IP [--min-rx MS] \
                 [--min-tx MS] [--detect-mult N] [--multihop --source IP] [--ifname NAME] \
                 [--vrf ID] [--secs N] [--deregister-at N]"
            );
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
                "zapi-bfd-probe: connect to {} failed: {e}",
                args.socket.display()
            );
            return std::process::ExitCode::from(1);
        }
    };
    log_line(
        &file,
        &format!(
            "ts={} event=CONNECT socket={} peer={} min_rx={} min_tx={} mult={} mhop={} src={:?} ifname={:?} vrf={} secs={} dereg_at={:?}",
            iso8601_now(),
            args.socket.display(),
            args.peer,
            args.min_rx,
            args.min_tx,
            args.detect_mult,
            args.multihop,
            args.source,
            args.ifname,
            args.vrf_id,
            args.secs,
            args.deregister_at,
        ),
    );

    // The bgpd-shaped burst: HELLO, BFD client registration (pid), the
    // destination registration. Logged with exact bytes so the capture is
    // self-describing.
    let register = BfdRegister {
        pid: std::process::id(),
        vrf_id: args.vrf_id,
        dst: args.peer,
        min_rx_ms: args.min_rx,
        min_tx_ms: args.min_tx,
        detect_mult: args.detect_mult,
        mhop: args.multihop,
        src: args.source.unwrap_or(match args.peer {
            IpAddr::V4(_) => IpAddr::V4(Ipv4Addr::UNSPECIFIED),
            IpAddr::V6(_) => IpAddr::V6(Ipv6Addr::UNSPECIFIED),
        }),
        hops: if args.multihop { 255 } else { 1 },
        ifname: args.ifname.clone(),
        cbit: false,
        profile: None,
    };
    let pid_bytes = std::process::id().to_be_bytes().to_vec();
    for (name, command, body) in [
        ("HELLO", 19u16, HELLO_BODY.to_vec()),
        ("BFD_CLIENT_REGISTER", 36, pid_bytes),
        ("BFD_DEST_REGISTER", 27, register.encode()),
    ] {
        let out = frame(command, args.vrf_id, &body);
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
                "ts={} event=SENT name={name} cmd={command} vrf={} hdr={} body={}",
                iso8601_now(),
                args.vrf_id,
                hex(&out[..ZAPI_HEADER_LEN]),
                hex(&body),
            ),
        );
    }

    // Capture window: read frames until --secs elapse or zebra hangs up.
    // An optional mid-window DEREGISTER (28) captures the deregister pin;
    // the body is the register's (frr sends the same layout minus nothing:
    // HAVE_BFDD deregisters keep the timer/address fields — ptm_adapter.c
    // reads the same shape).
    let mut msgs = 0usize;
    let mut cmd26 = 0usize;
    let window = Duration::from_secs(args.secs);
    let mut deregistered = false;
    let mut header_buf = [0u8; ZAPI_HEADER_LEN];
    let started = std::time::Instant::now();
    loop {
        let remaining = window.saturating_sub(started.elapsed());
        if remaining.is_zero() {
            break;
        }
        if let Some(at) = args.deregister_at {
            if !deregistered && started.elapsed() >= Duration::from_secs(at) {
                let body = register.encode();
                let out = frame(28, args.vrf_id, &body);
                if stream.write_all(&out).await.is_ok() {
                    log_line(
                        &file,
                        &format!(
                            "ts={} event=SENT name=BFD_DEST_DEREGISTER cmd=28 hdr={} body={}",
                            iso8601_now(),
                            hex(&out[..ZAPI_HEADER_LEN]),
                            hex(&body),
                        ),
                    );
                }
                deregistered = true;
            }
        }
        // While the deregister is pending, cap each read at its deadline.
        let read_budget = if deregistered || args.deregister_at.is_none() {
            remaining
        } else {
            let at = Duration::from_secs(args.deregister_at.unwrap());
            at.saturating_sub(started.elapsed()).max(Duration::from_millis(50))
        };
        let header = match timeout(read_budget, stream.read_exact(&mut header_buf)).await {
            Err(_) if args.deregister_at.is_some() && !deregistered => continue,
            Err(_) => break,
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
                log_line(&file, &format!("ts={} event=WINDOW_END mid_body", iso8601_now()));
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
        if header.command == 26 || header.command == 29 {
            cmd26 += 1;
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
        &format!("ts={} event=END msgs={msgs} bfd_updates={cmd26}", iso8601_now()),
    );
    eprintln!(
        "zapi-bfd-probe: window done, msgs={msgs} bfd_updates={cmd26} (log: {})",
        args.log.display()
    );
    std::process::ExitCode::SUCCESS
}

#[cfg(test)]
mod tests {
    use super::*;

    fn unhex(s: &str) -> Vec<u8> {
        s.as_bytes()
            .chunks(2)
            .map(|p| u8::from_str_radix(std::str::from_utf8(p).unwrap(), 16).unwrap())
            .collect()
    }

    /// GOLDEN: the register builder reproduces the exact 30 bytes a real
    /// bgpd 10.2.2 sent on the wire (W1-b Phase A capture,
    /// quarantine/bfd-zapi/phase-a-sniff.log): pid 81, AF_INET, dst
    /// 198.51.100.9, 300/300 ms, detect-mult 3, mhop, src 192.168.215.3,
    /// hops 255, no ifname (multihop), no cbit, no profile.
    #[test]
    fn register_encodes_the_captured_bgpd_frame() {
        let reg = BfdRegister {
            pid: 0x51,
            vrf_id: 0,
            dst: "198.51.100.9".parse().unwrap(),
            min_rx_ms: 300,
            min_tx_ms: 300,
            detect_mult: 3,
            mhop: true,
            src: "192.168.215.3".parse().unwrap(),
            hops: 255,
            ifname: Some("eth0".to_string()), // multihop suppresses it
            cbit: false,
            profile: None,
        };
        assert_eq!(
            reg.encode(),
            unhex("000000510002c63364090000012c0000012c03010002c0a8d703ff000000")
        );
    }

    /// The single-hop shape: mhop 0, wildcard src, hops 1, ifname carried
    /// when known (the lib/bfd.c HAVE_BFDD single-hop branch).
    #[test]
    fn register_encodes_single_hop_with_ifname() {
        let reg = BfdRegister {
            pid: 4242,
            vrf_id: 0,
            dst: "192.0.2.9".parse().unwrap(),
            min_rx_ms: 100,
            min_tx_ms: 100,
            detect_mult: 3,
            mhop: false,
            src: "0.0.0.0".parse().unwrap(),
            hops: 1,
            ifname: Some("eth0".to_string()),
            cbit: false,
            profile: None,
        };
        let bytes = reg.encode();
        assert_eq!(bytes.len(), 30 + 4, "ifname rides after ifnamelen");
        assert_eq!(
            bytes,
            unhex("000010920002c0000209000000640000006403000002000000000104657468300000")
        );
        // ...and without a known interface the body is exactly 30 bytes.
        let reg = BfdRegister { ifname: None, ..reg };
        assert_eq!(reg.encode().len(), 30);
        assert_eq!(
            reg.encode(),
            unhex("000010920002c00002090000006400000064030000020000000001000000")
        );
    }

    /// The v6 form sizes addresses at 16 bytes in both slots.
    #[test]
    fn register_encodes_ipv6() {
        let reg = BfdRegister {
            pid: 7,
            vrf_id: 0,
            dst: "2001:db8::9".parse().unwrap(),
            min_rx_ms: 300,
            min_tx_ms: 300,
            detect_mult: 3,
            mhop: true,
            src: "2001:db8::1".parse().unwrap(),
            hops: 255,
            ifname: None,
            cbit: false,
            profile: None,
        };
        let bytes = reg.encode();
        assert_eq!(bytes.len(), 4 + 2 + 16 + 4 + 4 + 1 + 1 + 2 + 16 + 1 + 1 + 1 + 1);
        assert_eq!(&bytes[..6], &unhex("00000007000a")[..]);
        assert_eq!(&bytes[bytes.len() - 3..], &unhex("000000")[..]);
    }

    /// HELLO must be byte-identical to the bgpd fixture shape.
    #[test]
    fn hello_body_is_bgpd_shape() {
        assert_eq!(HELLO_BODY.len(), 8);
        assert_eq!(HELLO_BODY[0], 0x0a, "redist_default = ZEBRA_ROUTE_BGP");
        assert_eq!(
            ZapiMessage::decode(19, HELLO_BODY).unwrap(),
            ZapiMessage::Hello(zapi::ZapiHello {
                redist_default: 10,
                instance: 0,
                session_id: 0,
                synchronous: 0,
            })
        );
    }

    /// The frame builder wraps a well-formed header around the body.
    #[test]
    fn frame_wraps_header_around_body() {
        let body = [0u8; 30];
        let out = frame(27, 0, &body);
        assert_eq!(out.len(), ZAPI_HEADER_LEN + 30);
        let header = ZapiHeader::decode(&out[..ZAPI_HEADER_LEN]).unwrap();
        assert_eq!(header.command, 27);
        assert_eq!(header.length as usize, out.len());
    }
}
