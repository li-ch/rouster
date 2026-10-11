//! `rtr-check` — connect the RTR client to a real cache and report.
//!
//! The smoke-proof half of the gortr runbook
//! (docs/protocols/rpki.md, "Real-cache interop"): it runs
//! [`RtrClient`] against a cache address, prints every cache-state
//! transition as it happens (so a driver script can watch the session
//! progress live), and exits 0 only when every assertion asked for on
//! the command line held:
//!
//! ```text
//! rtr-check --cache 127.0.0.1:8282 --max-version 1 \
//!   --expect-state Fresh --expect-serial 0 --expect-vrps 3 \
//!   --expect-version 1 --expect-session-id 42 \
//!   --rov 192.0.2.0/24,64512,Valid --rov 8.8.8.0/24,15169,NotFound
//! ```
//!
//! `--max-version 1` is the gortr v0.14.x pin: that cache closes the
//! transport silently on a version it does not speak, so the operator
//! (or smoke) caps the offer instead of relying on the RFC 8210 §7
//! code-4 downgrade that never comes.
//!
//! Assertions arm only after the first observed state transition: the
//! tables start at `None`/0 by construction, so a terminal assertion
//! like `--expect-state None` (the expire-flush leg) must match the
//! flush, not the virgin snapshot.
//!
//! Exit codes: 0 all assertions held; 1 an assertion failed or the
//! timeout hit first; 2 usage error.

use std::net::SocketAddr;
use std::process::ExitCode;
use std::time::Duration;

use rpki::client::{CacheState, CacheTables};
use rpki::rov::{OriginAsn, Validity};
use rpki::{ClientConfig, RtrClient, HIGHEST_VERSION};
use tokio::sync::watch;
use tokio::time::{sleep, timeout};

use common::IpPrefix;

/// What the operator asked to hold at the moment of exit.
struct Expectations {
    state: Option<CacheState>,
    serial: Option<u32>,
    vrps: Option<usize>,
    version: Option<u8>,
    session_id: Option<u16>,
    rov: Vec<(IpPrefix, u32, Validity)>,
}

impl Expectations {
    fn empty() -> Expectations {
        Expectations {
            state: None,
            serial: None,
            vrps: None,
            version: None,
            session_id: None,
            rov: Vec::new(),
        }
    }

    fn any(&self) -> bool {
        self.state.is_some()
            || self.serial.is_some()
            || self.vrps.is_some()
            || self.version.is_some()
            || self.session_id.is_some()
            || !self.rov.is_empty()
    }
}

/// One printable view of the shared tables.
#[derive(Debug, PartialEq, Clone)]
struct View {
    state: CacheState,
    version: Option<u8>,
    session_id: Option<u16>,
    serial: Option<u32>,
    vrps: usize,
    aspas: usize,
    keys: usize,
}

impl View {
    fn take(t: &CacheTables) -> View {
        View {
            state: t.state,
            version: t.protocol_version,
            session_id: t.session_id,
            serial: t.serial,
            vrps: t.vrps.len(),
            aspas: t.aspa.len(),
            keys: t.router_keys.len(),
        }
    }

    fn line(&self) -> String {
        let or = |v: String| if v.is_empty() { "-".to_string() } else { v };
        format!(
            "state={:?} version={} sid={} serial={} vrps={} aspas={} keys={}",
            self.state,
            or(self.version.map(|v| v.to_string()).unwrap_or_default()),
            or(self.session_id.map(|v| v.to_string()).unwrap_or_default()),
            or(self.serial.map(|v| v.to_string()).unwrap_or_default()),
            self.vrps,
            self.aspas,
            self.keys,
        )
    }

    fn holds(&self, e: &Expectations) -> Result<(), String> {
        if let Some(want) = e.state {
            if self.state != want {
                return Err(format!("state {:?} != {:?}", self.state, want));
            }
        }
        if let Some(want) = e.serial {
            if self.serial != Some(want) {
                return Err(format!("serial {:?} != {}", self.serial, want));
            }
        }
        if let Some(want) = e.vrps {
            if self.vrps != want {
                return Err(format!("vrps {} != {}", self.vrps, want));
            }
        }
        if let Some(want) = e.version {
            if self.version != Some(want) {
                return Err(format!("version {:?} != {}", self.version, want));
            }
        }
        if let Some(want) = e.session_id {
            if self.session_id != Some(want) {
                return Err(format!("session id {:?} != {}", self.session_id, want));
            }
        }
        Ok(())
    }
}

fn usage_error(msg: &str) -> ExitCode {
    eprintln!("rtr-check: {msg}");
    eprintln!(
        "usage: rtr-check [--cache IP:PORT] [--max-version N] [--expect-state Fresh|Serial|None|NoData] \
         [--expect-serial N] [--expect-vrps N] [--expect-version N] [--expect-session-id N] \
         [--rov PREFIX,ASN,Valid|Invalid|NotFound]... [--timeout SECS]"
    );
    ExitCode::from(2)
}

fn parse_state(s: &str) -> Option<CacheState> {
    match s {
        "None" => Some(CacheState::None),
        "Negotiating" => Some(CacheState::Negotiating),
        "Receiving" => Some(CacheState::Receiving),
        "Fresh" => Some(CacheState::Fresh),
        "Serial" => Some(CacheState::Serial),
        "NoData" => Some(CacheState::NoData),
        _ => None,
    }
}

fn parse_validity(s: &str) -> Option<Validity> {
    match s {
        "Valid" => Some(Validity::Valid),
        "Invalid" => Some(Validity::Invalid),
        "NotFound" => Some(Validity::NotFound),
        _ => None,
    }
}

/// Everything the command line asked for.
struct Args {
    cache: SocketAddr,
    max_version: u8,
    expect: Expectations,
    timeout: Duration,
}

fn parse_args(argv: Vec<String>) -> Result<Args, String> {
    let mut args = Args {
        cache: "127.0.0.1:8282".parse().expect("default cache addr"),
        max_version: HIGHEST_VERSION,
        expect: Expectations::empty(),
        timeout: Duration::from_secs(30),
    };
    let mut it = argv.into_iter();
    while let Some(flag) = it.next() {
        let mut value = || it.next().ok_or_else(|| format!("{flag} needs a value"));
        match flag.as_str() {
            "--cache" => {
                let v = value()?;
                args.cache = v
                    .parse()
                    .map_err(|_| format!("--cache wants IP:PORT, got {v:?}"))?;
            }
            "--max-version" => {
                args.max_version = value()?
                    .parse()
                    .map_err(|_| "--max-version wants a number".to_string())?
            }
            "--expect-state" => {
                let v = value()?;
                args.expect.state = Some(parse_state(&v).ok_or_else(|| {
                    format!("--expect-state wants Fresh|Serial|None|NoData|..., got {v:?}")
                })?);
            }
            "--expect-serial" => {
                args.expect.serial = Some(
                    value()?
                        .parse()
                        .map_err(|_| "--expect-serial wants a number".to_string())?,
                )
            }
            "--expect-vrps" => {
                args.expect.vrps = Some(
                    value()?
                        .parse()
                        .map_err(|_| "--expect-vrps wants a number".to_string())?,
                )
            }
            "--expect-version" => {
                args.expect.version = Some(
                    value()?
                        .parse()
                        .map_err(|_| "--expect-version wants a number".to_string())?,
                )
            }
            "--expect-session-id" => {
                args.expect.session_id = Some(
                    value()?
                        .parse()
                        .map_err(|_| "--expect-session-id wants a number".to_string())?,
                )
            }
            "--rov" => {
                let raw = value()?;
                let parts: Vec<&str> = raw.split(',').collect();
                if parts.len() != 3 {
                    return Err(format!("--rov wants PREFIX,ASN,Verdict, got {raw:?}"));
                }
                let prefix: IpPrefix = parts[0]
                    .parse()
                    .map_err(|_| format!("bad prefix {:?}", parts[0]))?;
                let asn: u32 = parts[1]
                    .parse()
                    .map_err(|_| format!("bad asn {:?}", parts[1]))?;
                let verdict = parse_validity(parts[2]).ok_or_else(|| {
                    format!(
                        "--rov verdict wants Valid|Invalid|NotFound, got {:?}",
                        parts[2]
                    )
                })?;
                args.expect.rov.push((prefix, asn, verdict));
            }
            "--timeout" => {
                let secs: u64 = value()?
                    .parse()
                    .map_err(|_| "--timeout wants seconds".to_string())?;
                args.timeout = Duration::from_secs(secs);
            }
            other => return Err(format!("unknown flag {other:?}")),
        }
    }
    if !args.expect.any() {
        return Err("nothing to check: give at least one --expect-*/--rov".into());
    }
    Ok(args)
}

#[tokio::main]
async fn main() -> ExitCode {
    // The client's own session log lines ("rpki: cache synchronized
    // ...") land on stderr (no ANSI), mirroring the daemon bins; the
    // rtr-check state lines below go to stdout for drivers to grep.
    let _ = tracing_subscriber::fmt()
        .with_ansi(false)
        .with_writer(std::io::stderr)
        .try_init();
    let args = match parse_args(std::env::args().skip(1).collect()) {
        Ok(a) => a,
        Err(msg) => return usage_error(&msg),
    };

    println!(
        "rtr-check: cache={} max-version={}",
        args.cache, args.max_version
    );
    let (client, tables) = RtrClient::new(ClientConfig {
        cache_addr: args.cache,
        max_version: args.max_version,
    });
    let (shutdown, shutdown_rx) = watch::channel(false);
    let handle = client.spawn(shutdown_rx);

    let verdict = timeout(args.timeout, async {
        let mut last: Option<View> = None;
        // Assertions about the terminal state (e.g. `--expect-state
        // None` after an expire flush) must not match the INITIAL
        // snapshot — the tables start at None vrps=0 by construction.
        // They arm only once the session has actually moved once.
        let mut armed = false;
        loop {
            let (view, rov_verdicts) = {
                let t = tables.lock().unwrap();
                let v = View::take(&t);
                let rovs = args
                    .expect
                    .rov
                    .iter()
                    .map(|(prefix, asn, want)| {
                        let got = t.vrps.validate(prefix, OriginAsn::new(*asn));
                        (*prefix, *asn, *want, got)
                    })
                    .collect::<Vec<_>>();
                (v, rovs)
            };
            if last.as_ref() != Some(&view) {
                if last.is_some() {
                    armed = true;
                }
                println!("rtr-check: {}", view.line());
                last = Some(view.clone());
            }
            if !armed {
                sleep(Duration::from_millis(100)).await;
                continue;
            }
            if let Err(why) = view.holds(&args.expect) {
                // Not there yet (or genuinely wrong); keep polling
                // until the deadline decides.
                tracing::debug!("rtr-check: not yet: {why}");
            } else {
                let mut ok = true;
                for (prefix, asn, want, got) in &rov_verdicts {
                    if want == got {
                        println!("rtr-check: rov {prefix} origin {asn} -> {got} (expected {want}) OK");
                    } else {
                        println!(
                            "rtr-check: rov {prefix} origin {asn} -> {got} (expected {want}) MISMATCH"
                        );
                        ok = false;
                    }
                }
                if ok {
                    return Ok(view);
                }
                return Err(format!("rov mismatch at {}", view.line()));
            }
            sleep(Duration::from_millis(100)).await;
        }
    })
    .await;

    // Orderly teardown: signal, join (bounded), then report.
    let _ = shutdown.send(true);
    if timeout(Duration::from_secs(5), handle).await.is_err() {
        println!("rtr-check: client did not stop within 5s (aborting)");
    }

    match verdict {
        Ok(Ok(view)) => {
            println!("rtr-check: PASS {}", view.line());
            ExitCode::SUCCESS
        }
        Ok(Err(why)) => {
            println!("rtr-check: FAIL {why}");
            ExitCode::FAILURE
        }
        Err(_) => {
            let t = tables.lock().unwrap();
            println!("rtr-check: FAIL timeout; last: {}", View::take(&t).line());
            ExitCode::FAILURE
        }
    }
}
