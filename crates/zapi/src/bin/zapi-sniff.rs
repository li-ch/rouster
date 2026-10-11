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
//! With `--respond-labelmgr` it answers EVERY ZEBRA_LABEL_MANAGER_CONNECT
//! (49) with the pinned reply form (proto + instance + result 0) — bgpd's
//! config apply blocks forever on that synchronous RPC when the masquerade
//! stays silent (pinned doc, operational finding 3; W1-b hit it live pushing
//! `router bgp` with a `neighbor ... bfd` through `vtysh -b`), so captures
//! that need bgpd to reach its config need the answer.
//!
//! With `--respond-iface <NAME:IFINDEX:ADDR/PLEN>` it answers the empty-body
//! INTERFACE_ADD (0) registration with one interface dump + one address
//! frame for the named interface, advertising the interface's HOST
//! address (the connected-route form real zebra pushes). bgpd arms
//! single-hop BFD at config-apply with NO interface or NHT knowledge at
//! all (M1 wire pin: the apply-time REGISTER fires against a bare
//! masquerade; classification is `PEER_IS_MULTIHOP` — same-AS ⇒ iBGP ⇒
//! multihop — not an NHT property; the W1-b "NHT-unresolved neighbors
//! are treated as multihop" reading was a misdiagnosis of a same-AS
//! config). What the interface dump IS load-bearing for: bgpd's
//! session-establish path (`bgp_zebra_nexthop_set` →
//! `if_lookup_by_ipv4_exact`) and therefore the ifname/local-address
//! UPDATE (29) a real EBGP session triggers.
//! With `--respond-nht` it answers every ZEBRA_NEXTHOP_REGISTER (21) with a
//! resolved NEXTHOP_UPDATE over a connected route through that interface —
//! what lets bgpd's connect logic pass the ebgp connected check.
//!
//! Dependency-free by design: std + tokio + the crate's own header codec.
//! Usage: zapi-sniff --socket /var/run/frr/zserv.api --log /tmp/cap.log
//!                 [--respond-hello] [--hello-cmd N]

use std::io::Write as _;
use std::path::PathBuf;
use std::str::FromStr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{UnixListener, UnixStream};

use zapi::header::ZapiHeaderError;
use zapi::{
    ZapiHeader, ZapiInterface, ZapiInterfaceAddress, ZapiMessage, ZapiNexthop, ZapiNexthopRegister,
    ZapiNexthopUpdate, ZAPI_HEADER_LEN,
};

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

/// The synthetic interface the `--respond-iface` mode advertises: a name,
/// an ifindex, and one address (host form) whose connected route bgpd's
/// `if_lookup_by_ipv4_exact` matches on session-establish.
#[derive(Debug, Clone, PartialEq, Eq)]
struct FakeIface {
    name: String,
    ifindex: u32,
    addr: std::net::IpAddr,
    plen: u8,
}

impl FromStr for FakeIface {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        // NAME:IFINDEX:ADDR/PLEN
        let (name, rest) = s
            .split_once(':')
            .ok_or_else(|| format!("expected NAME:IFINDEX:ADDR/PLEN, got `{s}`"))?;
        let (ifindex, addr) = rest
            .split_once(':')
            .ok_or_else(|| format!("expected NAME:IFINDEX:ADDR/PLEN, got `{s}`"))?;
        let (addr, plen) = addr
            .split_once('/')
            .ok_or_else(|| format!("address needs a /PLEN, got `{s}`"))?;
        Ok(Self {
            name: name.to_string(),
            ifindex: ifindex
                .parse()
                .map_err(|_| format!("bad ifindex `{ifindex}`"))?,
            addr: addr.parse().map_err(|_| format!("bad address `{addr}`"))?,
            plen: plen
                .parse()
                .map_err(|_| format!("bad prefix length `{plen}`"))?,
        })
    }
}

struct Args {
    socket: PathBuf,
    log: PathBuf,
    respond_hello: bool,
    hello_cmd: u16,
    respond_labelmgr: bool,
    respond_iface: Option<FakeIface>,
    respond_nht: bool,
}

fn parse_args() -> Result<Args, String> {
    let mut socket = None;
    let mut log = None;
    let mut respond_hello = false;
    let mut hello_cmd: u16 = 8;
    let mut respond_labelmgr = false;
    let mut respond_iface = None;
    let mut respond_nht = false;
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
            "--respond-labelmgr" => respond_labelmgr = true,
            "--respond-iface" => {
                respond_iface = Some(
                    it.next()
                        .ok_or("--respond-iface needs NAME:IFINDEX:ADDR/PLEN")?
                        .parse()?,
                )
            }
            "--respond-nht" => respond_nht = true,
            other => return Err(format!("unknown argument: {other}")),
        }
    }
    Ok(Args {
        socket: socket.ok_or("--socket is required (e.g. /var/run/frr/zserv.api)")?,
        log: log.ok_or("--log is required")?,
        respond_hello,
        hello_cmd,
        respond_labelmgr,
        respond_iface,
        respond_nht,
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
            "ts={} event=START socket={} respond_hello={} hello_cmd={} respond_labelmgr={} respond_iface={:?} respond_nht={}",
            iso8601_now(),
            args.socket.display(),
            args.respond_hello,
            args.hello_cmd,
            args.respond_labelmgr,
            args.respond_iface,
            args.respond_nht,
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
        let responders = Responders {
            hello: args.respond_hello,
            hello_cmd: args.hello_cmd,
            labelmgr: args.respond_labelmgr,
            iface: args.respond_iface.clone(),
            nht: args.respond_nht,
        };
        tokio::spawn(async move {
            handle_conn(stream, conn, sink, responders).await;
        });
    }
}

/// The per-connection answer policy (what the masquerade replies to).
#[derive(Debug, Clone)]
struct Responders {
    hello: bool,
    hello_cmd: u16,
    labelmgr: bool,
    iface: Option<FakeIface>,
    nht: bool,
}

async fn handle_conn(mut stream: UnixStream, conn: u64, sink: LogSink, responders: Responders) {
    let Responders {
        hello: respond_hello,
        hello_cmd,
        labelmgr: respond_labelmgr,
        iface: respond_iface,
        nht: respond_nht,
    } = responders;
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
                                    iso8601_now(),
                                ),
                            ),
                        }
                    }
                    // ZEBRA_LABEL_MANAGER_CONNECT (49): the synchronous
                    // RPC bgpd's config apply blocks on (pinned doc,
                    // operational finding 3). The reply form is the
                    // client body + trailing result u8 (0 = success);
                    // answering every occurrence, not just the first —
                    // reconnects re-ask.
                    if respond_labelmgr && frame.header.command == 49 && frame.body.len() == 3 {
                        let mut reply_body = frame.body.clone();
                        reply_body.push(0); // result: success
                        let mut reply = vec![0u8; ZAPI_HEADER_LEN];
                        ZapiHeader::new(
                            frame.header.command,
                            frame.header.vrf_id,
                            reply_body.len(),
                        )
                        .encode(&mut reply);
                        reply.extend_from_slice(&reply_body);
                        match stream.write_all(&reply).await {
                            Ok(()) => log_line(
                                &sink,
                                &format!(
                                    "ts={} conn={conn} event=REPLY_LMC cmd=49 len={} body={}",
                                    iso8601_now(),
                                    reply.len(),
                                    hex(&reply_body),
                                ),
                            ),
                            Err(e) => log_line(
                                &sink,
                                &format!(
                                    "ts={} conn={conn} event=REPLY_LMC_FAILED err={e}",
                                    iso8601_now(),
                                ),
                            ),
                        }
                    }
                    // INTERFACE_ADD registration (empty body): the
                    // interface dump a real zebra answers with. Needed
                    // to arm bgpd's single-hop BFD (W1-b finding).
                    if let Some(iface) = &respond_iface {
                        if frame.header.command == 0 && frame.body.is_empty() {
                            match iface_reply(iface) {
                                Ok(frames) => {
                                    for reply in frames {
                                        match stream.write_all(&reply).await {
                                            Ok(()) => log_line(
                                                &sink,
                                                &format!(
                                                    "ts={} conn={conn} event=REPLY_IFACE len={} body={}",
                                                    iso8601_now(),
                                                    reply.len(),
                                                    hex(&reply[ZAPI_HEADER_LEN..]),
                                                ),
                                            ),
                                            Err(e) => log_line(
                                                &sink,
                                                &format!(
                                                    "ts={} conn={conn} event=REPLY_IFACE_FAILED err={e}",
                                                    iso8601_now(),
                                                ),
                                            ),
                                        }
                                    }
                                }
                                Err(e) => log_line(
                                    &sink,
                                    &format!(
                                        "ts={} conn={conn} event=REPLY_IFACE_BUILD_FAILED err={e}",
                                        iso8601_now(),
                                    ),
                                ),
                            }
                        }
                    }
                    // NEXTHOP_REGISTER (21): answer with a resolved
                    // NEXTHOP_UPDATE over the fake connected route.
                    if respond_nht && frame.header.command == 21 {
                        if let Some(iface) = &respond_iface {
                            match ZapiNexthopRegister::decode(&frame.body) {
                                Ok(register) => match nht_reply(&register, iface) {
                                    Ok(reply) => match stream.write_all(&reply).await {
                                        Ok(()) => log_line(
                                            &sink,
                                            &format!(
                                                "ts={} conn={conn} event=REPLY_NHT len={} body={}",
                                                iso8601_now(),
                                                reply.len(),
                                                hex(&reply[ZAPI_HEADER_LEN..]),
                                            ),
                                        ),
                                        Err(e) => log_line(
                                            &sink,
                                            &format!(
                                                "ts={} conn={conn} event=REPLY_NHT_FAILED err={e}",
                                                iso8601_now(),
                                            ),
                                        ),
                                    },
                                    Err(e) => log_line(
                                        &sink,
                                        &format!(
                                            "ts={} conn={conn} event=REPLY_NHT_BUILD_FAILED err={e}",
                                            iso8601_now(),
                                        ),
                                    ),
                                },
                                Err(e) => log_line(
                                    &sink,
                                    &format!(
                                        "ts={} conn={conn} event=REPLY_NHT_DECODE_FAILED err={e:?}",
                                        iso8601_now(),
                                    ),
                                ),
                            }
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

/// ZEBRA_INTERFACE_ACTIVE (frr-10.2.2 `lib/zebra.h`): the bit zebra's
/// interface dumps carry for an operative interface; what makes bgpd's
/// `if_lookup_by_ipv4` candidate usable.
const ZEBRA_INTERFACE_ACTIVE: u64 = 0x1;

/// The interface-dump answer for `--respond-iface`: one INTERFACE_ADD
/// frame plus one INTERFACE_ADDRESS_ADD for the synthetic interface.
/// SPEC bodies (the pinned doc's source-verified zebra→client layouts).
fn iface_reply(iface: &FakeIface) -> Result<Vec<Vec<u8>>, String> {
    // The interface's own HOST address at the configured prefix length —
    // the form real zebra's INTERFACE_ADDRESS_ADD carries (a connected
    // route derived from the interface address), and the form bgpd's
    // `if_lookup_by_ipv4_exact` matches on session-establish
    // (`bgp_zebra_nexthop_set`): masking the host bits to the network
    // address makes every exact lookup miss and the BGP session can
    // never come up (found live in the M1 single-hop pin run).
    let prefix: common::IpPrefix = match iface.addr {
        std::net::IpAddr::V4(a) => {
            if iface.plen > 32 {
                return Err(format!("bad v4 prefix length /{}", iface.plen));
            }
            format!("{a}/{}", iface.plen)
                .parse()
                .map_err(|e: common::PrefixError| e.to_string())?
        }
        std::net::IpAddr::V6(a) => {
            if iface.plen != 128 {
                return Err(format!(
                    "v6 --respond-iface needs the full /128 address, got /{}",
                    iface.plen
                ));
            }
            format!("{a}/128")
                .parse()
                .map_err(|e: common::PrefixError| e.to_string())?
        }
    };
    let mut intf = ZapiInterface::new(&iface.name, iface.ifindex);
    intf.flags = ZEBRA_INTERFACE_ACTIVE;
    intf.mtu = 1500;
    intf.mtu6 = 1500;
    let dump = ZapiMessage::InterfaceAdd(intf)
        .encode_frame(0)
        .map_err(|e| e.to_string())?
        .to_vec();
    let addr = ZapiMessage::InterfaceAddressAdd(ZapiInterfaceAddress {
        ifindex: iface.ifindex,
        flags: 0,
        address: prefix,
        destination: None,
    })
    .encode_frame(0)
    .map_err(|e| e.to_string())?
    .to_vec();
    Ok(vec![dump, addr])
}

/// The NHT answer for `--respond-nht`: a NEXTHOP_UPDATE resolving the
/// registered prefix over a connected route through the `--respond-iface`
/// interface (SPEC body, `zebra_send_rnh_update` shape).
fn nht_reply(register: &ZapiNexthopRegister, iface: &FakeIface) -> Result<Vec<u8>, String> {
    // Plain IFINDEX nexthop: what a connected route's rib match carries
    // (no gateway) — the form that makes bgpd classify the peer as
    // directly connected (shared_network) and arm SINGLE-hop BFD.
    let hop = ZapiNexthop::new_ifindex(0, iface.ifindex);
    let update = ZapiNexthopUpdate::resolved(
        register.prefix,
        register.safi,
        2, // ZEBRA_ROUTE_CONNECT
        0,
        0,
        vec![hop],
    );
    Ok(ZapiMessage::NexthopUpdate(update)
        .encode_frame(0)
        .map_err(|e| e.to_string())?
        .to_vec())
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

    /// The --respond-iface spec parses NAME:IFINDEX:ADDR/PLEN and rejects
    /// malformed forms.
    #[test]
    fn fake_iface_spec_parses() {
        let f: FakeIface = "eth0:2:192.168.215.2/16".parse().unwrap();
        assert_eq!(f.name, "eth0");
        assert_eq!(f.ifindex, 2);
        assert_eq!(
            f.addr,
            std::net::IpAddr::from(std::net::Ipv4Addr::new(192, 168, 215, 2))
        );
        assert_eq!(f.plen, 16);
        for bad in [
            "eth0",
            "eth0:2",
            "eth0:two:192.168.215.2/16",
            "eth0:2:192.168.215.2",
            "eth0:2:notanip/16",
        ] {
            assert!(bad.parse::<FakeIface>().is_err(), "{bad} parsed");
        }
    }

    /// The interface answer carries one INTERFACE_ADD dump (ACTIVE flag,
    /// name, ifindex) and one INTERFACE_ADDRESS_ADD whose prefix is the
    /// NETWORK address (host bits masked off) — both re-decodable.
    #[test]
    fn iface_reply_decodes_back() {
        let f: FakeIface = "eth0:2:192.168.215.2/16".parse().unwrap();
        let frames = iface_reply(&f).unwrap();
        assert_eq!(frames.len(), 2);
        match ZapiMessage::decode(0, &frames[0][ZAPI_HEADER_LEN..]).unwrap() {
            ZapiMessage::InterfaceAdd(i) => {
                assert_eq!(i.ifname, "eth0");
                assert_eq!(i.ifindex, 2);
                assert_eq!(i.flags, ZEBRA_INTERFACE_ACTIVE);
            }
            other => panic!("not an InterfaceAdd dump: {other:?}"),
        }
        match ZapiMessage::decode(2, &frames[1][ZAPI_HEADER_LEN..]).unwrap() {
            ZapiMessage::InterfaceAddressAdd(a) => {
                assert_eq!(a.ifindex, 2);
                assert_eq!(
                    a.address.to_string(),
                    "192.168.215.2/16",
                    "the interface's HOST address (real zebra's form; the masked network form makes bgpd's exact lookup miss)"
                );
            }
            other => panic!("not an InterfaceAddressAdd: {other:?}"),
        }
    }

    /// The NHT answer resolves the REGISTERED prefix (echoed back) over a
    /// connected route with an ifindex-carrying nexthop — the shape
    /// `bgp_nht_validate` accepts.
    #[test]
    fn nht_reply_resolves_registered_prefix() {
        let f: FakeIface = "eth0:2:192.168.215.2/16".parse().unwrap();
        let register = ZapiNexthopRegister {
            connected: false,
            resolve_via_default: false,
            safi: 1,
            prefix: "192.168.215.1/32".parse().unwrap(),
        };
        let frame = nht_reply(&register, &f).unwrap();
        let header = ZapiHeader::decode(&frame[..ZAPI_HEADER_LEN]).unwrap();
        assert_eq!(header.command, 23);
        match ZapiMessage::decode(23, &frame[ZAPI_HEADER_LEN..]).unwrap() {
            ZapiMessage::NexthopUpdate(u) => {
                assert_eq!(u.registered_prefix, register.prefix);
                assert!(u.is_resolved());
                assert_eq!(u.nexthops.len(), 1);
                assert_eq!(u.nexthops[0].ifindex, 2);
                assert_eq!(
                    u.nexthops[0].nh_type,
                    zapi::nexthop_type::IFINDEX,
                    "a connected route carries an ifindex-only nexthop"
                );
            }
            other => panic!("not a NexthopUpdate: {other:?}"),
        }
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
