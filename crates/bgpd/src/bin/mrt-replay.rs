//! mrt-replay — the E1 injector (D1(c) switch leg): replays a
//! TABLE_DUMP_V2 MRT RIB dump as a BGP speaker into a SUT.
//!
//! The gate run `gate-20261015T051919Z` measured exabgp 5.0.14 at
//! ~36 msg/s sustained (reactor-paced, 7% CPU) with deterministic
//! hold-time death under bulk API — below the D1 ≥2× headroom bar
//! against a fast SUT. This tool is the pre-registered replacement:
//! it parses the MRT directly (raw, pre-decompressed — no new crate
//! deps), performs attribute surgery on the raw TLV bytes (NEXT_HOP
//! rewrite, AS_PATH prepend), packs consecutive same-attribute routes
//! into one UPDATE (deterministic given feed order), and drives the
//! BGP session itself (OPEN → KEEPALIVE → UPDATEs → EOR).
//!
//! Pick rule (parity with scripts/bench-mrt2announce.py): the lowest
//! peer-index RIB entry per prefix.
//!
//! Usage:
//!   bunzip2 rib.*.bz2  # raw MRT only
//!   mrt-replay --peer 172.31.255.20:179 --local-addr 172.31.255.10 \
//!     --local-as 65412 --peer-as 65000 --router-id 172.31.255.10 \
//!     --mrt rib.mrt [--prepend-as 65412] [--next-hop 172.31.255.10] \
//!     [--limit N] [--offset N] [--rate 0] [--hold 90] [--pack 64]
//!
//! Observability: stderr lines REPLAY-START / REPLAY-FIRST-UPDATE /
//! REPLAY-PROGRESS / REPLAY-LAST-UPDATE with wall+mono clocks and
//! counts; exit 0 only if EOR was sent after the full request.

use std::io::Read;
use std::net::{Ipv4Addr, SocketAddrV4};
use std::time::Duration;

use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::Mutex;
use tokio::time::sleep;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut peer = String::new();
    let mut local_addr = String::new();
    let mut local_as: u32 = 65412;
    let mut peer_as: u32 = 65000;
    let mut router_id = String::new();
    let mut mrt = String::new();
    let mut prepend_as: u32 = 0;
    let mut next_hop = String::new();
    let mut limit: usize = 0;
    let mut offset: usize = 0;
    let mut rate: f64 = 0.0;
    let mut hold: u16 = 90;
    let mut pack: usize = 64;
    let mut linger: u64 = 3600;

    fn need(it: &mut impl Iterator<Item = String>, k: &str) -> String {
        it.next().unwrap_or_else(|| panic!("{k} requires a value"))
    }
    let mut it = std::env::args().skip(1);
    while let Some(arg) = it.next() {
        match arg.as_str() {
            "--peer" => peer = need(&mut it, "--peer"),
            "--local-addr" => local_addr = need(&mut it, "--local-addr"),
            "--local-as" => local_as = need(&mut it, "--local-as").parse().unwrap(),
            "--peer-as" => peer_as = need(&mut it, "--peer-as").parse().unwrap(),
            "--router-id" => router_id = need(&mut it, "--router-id"),
            "--mrt" => mrt = need(&mut it, "--mrt"),
            "--prepend-as" => prepend_as = need(&mut it, "--prepend-as").parse().unwrap(),
            "--next-hop" => next_hop = need(&mut it, "--next-hop"),
            "--limit" => limit = need(&mut it, "--limit").parse().unwrap(),
            "--offset" => offset = need(&mut it, "--offset").parse().unwrap(),
            "--rate" => rate = need(&mut it, "--rate").parse().unwrap(),
            "--hold" => hold = need(&mut it, "--hold").parse().unwrap(),
            "--pack" => pack = need(&mut it, "--pack").parse().unwrap(),
            "--linger" => linger = need(&mut it, "--linger").parse().unwrap(),
            other => panic!("unknown argument {other}"),
        }
    }
    assert!(
        !peer.is_empty() && !local_addr.is_empty() && !mrt.is_empty(),
        "mrt-replay: --peer, --local-addr and --mrt are required"
    );
    let _ = &local_addr; // accepted for the local bind; the kernel picks

    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?;
    rt.block_on(run(
        peer.parse().map_err(|_| "bad --peer")?,
        local_as,
        peer_as,
        router_id.parse().map_err(|_| "bad --router-id")?,
        &mrt,
        prepend_as,
        next_hop.parse().ok(),
        limit,
        offset,
        rate,
        hold,
        pack,
        linger,
    ))
}

macro_rules! ensure {
    ($cond:expr, $($msg:tt)*) => {
        if !($cond) { return Err(format!($($msg)*).into()); }
    };
}

fn bgp_frame(msg_type: u8, body: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(19 + body.len());
    out.extend_from_slice(&[0xFFu8; 16]);
    let len = (19 + body.len()) as u16;
    out.extend_from_slice(&len.to_be_bytes());
    out.push(msg_type);
    out.extend_from_slice(body);
    out
}

fn open_body(asn: u32, hold: u16, id: Ipv4Addr) -> Vec<u8> {
    let caps = {
        let mut c = Vec::new();
        // Four-octet AS number (RFC 6793)
        c.push(65u8);
        c.push(4);
        c.extend_from_slice(&asn.to_be_bytes());
        // Route refresh (RFC 2918)
        c.push(2);
        c.push(0);
        c
    };
    let mut b = Vec::new();
    b.push(4); // version
    b.extend_from_slice(&(asn.min(65535) as u16).to_be_bytes());
    b.extend_from_slice(&hold.to_be_bytes());
    b.extend_from_slice(&id.octets());
    b.push((2 + caps.len()) as u8); // Opt Parm Len: type+len+caps bytes
    b.push(2); // capability param
    b.push(caps.len() as u8);
    b.extend_from_slice(&caps);
    b
}

/// Walk the attribute TLVs, rewrite NEXT_HOP's value in place.
fn rewrite_next_hop(attrs: &mut [u8], nh: Ipv4Addr) {
    let mut i = 0usize;
    while i + 3 <= attrs.len() {
        let flags = attrs[i];
        let atype = attrs[i + 1];
        let mut p = i + 2;
        let alen = if flags & 0x10 != 0 {
            let l = u16::from_be_bytes([attrs[p], attrs[p + 1]]) as usize;
            p += 2;
            l
        } else {
            let l = attrs[p] as usize;
            p += 1;
            l
        };
        if atype == 3 && alen == 4 && p + 4 <= attrs.len() {
            attrs[p..p + 4].copy_from_slice(&nh.octets());
        }
        i = p + alen;
    }
}

/// Prepend one ASN to the first AS_SEQUENCE segment (RFC 4271
/// §5.1.2a; AS4 encoding, which is what the dump and both SUTs
/// speak). If the path opens with an AS_SET, a new sequence segment
/// is placed before it. The attribute section is re-serialized (each
/// attribute gets a correct short/extended length field).
fn prepend_as_path(attrs: &mut Vec<u8>, asn: u32) {
    let mut parts: Vec<(u8, u8, Vec<u8>)> = Vec::new(); // (flags, type, body)
    let mut i = 0usize;
    while i + 3 <= attrs.len() {
        let flags = attrs[i];
        let atype = attrs[i + 1];
        let mut p = i + 2;
        let alen = if flags & 0x10 != 0 {
            let l = u16::from_be_bytes([attrs[p], attrs[p + 1]]) as usize;
            p += 2;
            l
        } else {
            let l = attrs[p] as usize;
            p += 1;
            l
        };
        if p + alen > attrs.len() {
            return; // malformed tail: leave untouched
        }
        parts.push((flags, atype, attrs[p..p + alen].to_vec()));
        i = p + alen;
    }
    let mut out = Vec::with_capacity(attrs.len() + 4);
    for (flags, atype, body) in parts {
        let body = if atype == 2 && !body.is_empty() {
            let mut rebuilt = Vec::with_capacity(body.len() + 6);
            if body[0] == 2 && body.len() >= 2 && body[1] < 255 {
                // room in the first AS_SEQUENCE: prepend into it
                let seg_len = body[1] as usize;
                rebuilt.push(2);
                rebuilt.push((seg_len + 1) as u8);
                rebuilt.extend_from_slice(&asn.to_be_bytes());
                rebuilt.extend_from_slice(&body[2..]);
            } else {
                // AS_SET opens the path, or a full 255-ASN segment:
                // a fresh one-ASN segment goes in front instead
                rebuilt.push(2);
                rebuilt.push(1);
                rebuilt.extend_from_slice(&asn.to_be_bytes());
                rebuilt.extend_from_slice(&body);
            }
            rebuilt
        } else {
            body
        };
        out.push(flags);
        out.push(atype);
        if body.len() > 255 || flags & 0x10 != 0 {
            out.extend_from_slice(&(body.len() as u16).to_be_bytes());
        } else {
            out.push(body.len() as u8);
        }
        out.extend_from_slice(&body);
    }
    *attrs = out;
}

struct MrtEntry {
    prefix: Vec<u8>, // (len, addr bytes)
    attrs: Vec<u8>,
}

/// Streaming TABLE_DUMP_V2 / RIB_IPV4_UNICAST reader: yields the
/// lowest-peer-index entry per prefix.
fn mrt_entries(
    r: &mut impl Read,
    offset: usize,
    limit: usize,
) -> Result<Vec<MrtEntry>, std::io::Error> {
    let mut out = Vec::new();
    let mut hdr = [0u8; 12];
    let mut seen: usize = 0;
    loop {
        match r.read_exact(&mut hdr) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => break,
            Err(e) => return Err(e),
        }
        // MRT common header: timestamp(4) | type(2) | subtype(2) | length(4)
        let mtype = u16::from_be_bytes([hdr[4], hdr[5]]);
        let msubtype = u16::from_be_bytes([hdr[6], hdr[7]]);
        let mlen = u32::from_be_bytes([hdr[8], hdr[9], hdr[10], hdr[11]]) as usize;
        let mut body = vec![0u8; mlen];
        r.read_exact(&mut body)?;
        if mtype != 13 || msubtype != 2 {
            continue;
        }
        let plen = body[4] as usize;
        let nbytes = plen.div_ceil(8);
        // NLRI wire form: length byte + only the significant octets
        let mut prefix = vec![plen as u8];
        prefix.extend_from_slice(&body[5..5 + nbytes]);
        let mut p = 5 + nbytes;
        let ecount = u16::from_be_bytes([body[p], body[p + 1]]) as usize;
        p += 2;
        let mut best: Option<(u16, usize, usize)> = None; // (peer idx, attr start, attr len)
        for _ in 0..ecount {
            let peer_idx = u16::from_be_bytes([body[p], body[p + 1]]);
            p += 6; // peer idx + originated time
            let alen = u16::from_be_bytes([body[p], body[p + 1]]) as usize;
            p += 2;
            if best.is_none() || best.is_some_and(|(b, _, _)| peer_idx < b) {
                best = Some((peer_idx, p, alen));
            }
            p += alen;
        }
        seen += 1;
        if seen <= offset {
            continue;
        }
        if let Some((_, start, alen)) = best {
            out.push(MrtEntry {
                prefix,
                attrs: body[start..start + alen].to_vec(),
            });
        }
        if limit != 0 && out.len() >= limit {
            break;
        }
    }
    Ok(out)
}

fn update_frame(attrs: &[u8], nlri: &[Vec<u8>]) -> Vec<u8> {
    let mut body = Vec::with_capacity(4 + attrs.len());
    body.extend_from_slice(&0u16.to_be_bytes()); // withdrawn len
    body.extend_from_slice(&(attrs.len() as u16).to_be_bytes());
    body.extend_from_slice(attrs);
    for p in nlri {
        body.extend_from_slice(p);
    }
    bgp_frame(2, &body)
}

fn now_wall() -> f64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs_f64()
}

async fn read_frame(
    r: &mut tokio::net::tcp::OwnedReadHalf,
) -> Result<(u8, Vec<u8>), std::io::Error> {
    let mut hdr = [0u8; 19];
    r.read_exact(&mut hdr).await?;
    let len = u16::from_be_bytes([hdr[16], hdr[17]]) as usize;
    let mut body = vec![0u8; len.saturating_sub(19)];
    r.read_exact(&mut body).await?;
    Ok((hdr[18], body))
}

#[allow(clippy::too_many_arguments)]
async fn run(
    peer: SocketAddrV4,
    local_as: u32,
    peer_as: u32,
    router_id: Ipv4Addr,
    mrt: &str,
    prepend: u32,
    next_hop: Option<Ipv4Addr>,
    limit: usize,
    offset: usize,
    rate: f64,
    hold: u16,
    pack: usize,
    linger: u64,
) -> Result<(), Box<dyn std::error::Error>> {
    eprintln!(
        "REPLAY-START wall={:.6} mono={:.6} mrt={} peer={}",
        now_wall(),
        tokio::time::Instant::now().elapsed().as_secs_f64(),
        mrt,
        peer
    );
    let mut f = std::fs::File::open(mrt)?;
    let entries = mrt_entries(&mut f, offset, limit)?;
    eprintln!("REPLAY-PARSED routes={}", entries.len());

    let stream = TcpStream::connect(peer).await?;
    stream.set_nodelay(true)?;
    let (mut rd, wr) = stream.into_split();
    let wr: Arc<Mutex<_>> = Arc::new(Mutex::new(wr));

    // OPEN exchange
    {
        let mut guard = wr.lock().await;
        guard
            .write_all(&bgp_frame(1, &open_body(local_as, hold, router_id)))
            .await?;
    }
    let (t, body) = read_frame(&mut rd).await?;
    ensure!(t == 1, "expected OPEN, got type {t} ({} bytes)", body.len());
    // 4-byte AS check: peer OPEN carries cap 65 with its AS
    // OPEN body: version(1) | ASN(2) | hold(2) | id(4) | opt params
    let peer_open_as = u16::from_be_bytes([body[1], body[2]]);
    let mut peer4 = peer_open_as as u32;
    if peer_open_as == 23456 {
        // scan optional params for the 4-octet AS capability
        let opt_len = body[9] as usize;
        let mut p = 10usize;
        while p + 2 <= 10 + opt_len && p < body.len() {
            let ptype = body[p];
            let plen = body[p + 1] as usize;
            if ptype == 2 && plen >= 6 && body[p + 2] == 65 {
                peer4 = u32::from_be_bytes(body[p + 4..p + 8].try_into().unwrap());
            }
            p += 2 + plen;
        }
    }
    ensure!(peer4 == peer_as, "peer AS {peer4} != expected {peer_as}");
    {
        let mut guard = wr.lock().await;
        guard.write_all(&bgp_frame(4, &[])).await?; // KEEPALIVE
    }
    let (t, _) = read_frame(&mut rd).await?;
    eprintln!("DEBUG second frame type={t}");
    ensure!(t == 4, "expected KEEPALIVE, got type {t}");
    eprintln!(
        "REPLAY-ESTABLISHED wall={:.6} mono={:.6} peer_as={peer4}",
        now_wall(),
        tokio::time::Instant::now().elapsed().as_secs_f64()
    );

    // reader task: answer KEEPALIVEs, watch for NOTIFICATION
    let wr2 = Arc::clone(&wr);
    let reader = tokio::spawn(async move {
        loop {
            match read_frame(&mut rd).await {
                Ok((4, _)) => {
                    if let Ok(mut g) = wr2.try_lock() {
                        let _ = g.write_all(&bgp_frame(4, &[])).await;
                    }
                }
                Ok((3, b)) => {
                    eprintln!(
                        "REPLAY-NOTIFICATION code={} subcode={}",
                        b[0],
                        b.get(1).copied().unwrap_or(0)
                    );
                    return;
                }
                Ok(_) => {}
                Err(_) => return,
            }
        }
    });

    // our own keepalive timer (independent of the reader's replies)
    let wr_ka = Arc::clone(&wr);
    let ka = tokio::spawn(async move {
        let period = Duration::from_secs((hold as u64 / 3).max(5));
        loop {
            sleep(period).await;
            if let Ok(mut g) = wr_ka.try_lock() {
                if g.write_all(&bgp_frame(4, &[])).await.is_err() {
                    return;
                }
            }
        }
    });

    // replay: pack consecutive same-attribute routes into one UPDATE
    let mut msgs: usize = 0;
    let mut routes: usize = 0;
    let mut first = true;
    let mut nlri: Vec<Vec<u8>> = Vec::new();
    let mut cur_attrs: Vec<u8> = Vec::new();
    let flush = |nlri: &mut Vec<Vec<u8>>, attrs: &mut Vec<u8>, msgs: &mut usize| -> usize {
        if nlri.is_empty() {
            return 0;
        }
        *msgs += 1;
        let n = nlri.len();
        nlri.clear();
        attrs.clear();
        n
    };

    let ka_period = if rate > 0.0 {
        Duration::from_secs_f64(1.0 / rate)
    } else {
        Duration::ZERO
    };
    for e in entries {
        let mut attrs = e.attrs.clone();
        if let Some(nh) = next_hop {
            rewrite_next_hop(&mut attrs, nh);
        }
        if prepend != 0 {
            prepend_as_path(&mut attrs, prepend);
        }
        if !nlri.is_empty() && (attrs != cur_attrs || nlri.len() >= pack) {
            let frame = update_frame(&cur_attrs, &nlri);
            let mut g = wr.lock().await;
            g.write_all(&frame).await?;
            drop(g);
            let n = flush(&mut nlri, &mut cur_attrs, &mut msgs);
            routes += n;
            if first {
                eprintln!(
                    "REPLAY-FIRST-UPDATE wall={:.6} mono={:.6}",
                    now_wall(),
                    tokio::time::Instant::now().elapsed().as_secs_f64()
                );
                first = false;
            }
            if rate > 0.0 {
                sleep(ka_period).await;
            }
        }
        cur_attrs = attrs;
        nlri.push(e.prefix);
        if routes % 100_000 < pack && routes > 0 && !nlri.is_empty() && msgs.is_multiple_of(4096) {
            eprintln!(
                "REPLAY-PROGRESS routes={routes} msgs={msgs} wall={:.6}",
                now_wall()
            );
        }
    }
    if !nlri.is_empty() {
        let frame = update_frame(&cur_attrs, &nlri);
        wr.lock().await.write_all(&frame).await?;
        routes += flush(&mut nlri, &mut cur_attrs, &mut msgs);
    }
    // EOR for ipv4-unicast: empty withdrawn + empty attrs (RFC 4724
    // §3) — the 4-byte body keeps the message at the 23-byte minimum.
    wr.lock()
        .await
        .write_all(&bgp_frame(2, &[0, 0, 0, 0]))
        .await?;
    eprintln!(
        "REPLAY-LAST-UPDATE wall={:.6} mono={:.6} routes={routes} msgs={msgs}",
        now_wall(),
        tokio::time::Instant::now().elapsed().as_secs_f64()
    );
    // Hold the session (keepalives) so the SUT's table survives to be
    // measured: an abrupt close or Cease makes both SUTs flush the
    // learned routes. The harness kills the injector at run end.
    sleep(Duration::from_secs(linger)).await;
    Ok(())
}
