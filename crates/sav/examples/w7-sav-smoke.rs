//! W7 SAV enforcement smoke binary — the musl consumer that drives the
//! enforcement leg inside the test container
//! (`scripts/test-w7-sav.sh`).
//!
//! Everything goes through the `Dataplane` trait (architecture
//! invariant: the dataplane crate owns all kernel I/O): `install`
//! builds the same IBA ops the SAV table manager would compile from
//! the container topology, converts them with [`sav::program`], and
//! installs them on the real netlink backend; `simulate` runs the
//! monitor-mode route-lookup counting; `clear` removes what was
//! installed.
//!
//! Usage (no external crates — manual arg parsing):
//!
//! ```text
//! w7-sav-smoke install  --mode strict|loose --action monitor|drop \
//!                       --iba <ifindex>[:<prefix>] [--iba ...]
//! w7-sav-smoke simulate --mode ... --iba ... --observe <ip>@<ifindex> [...]
//! w7-sav-smoke clear
//! ```

use std::net::IpAddr;
use std::process::ExitCode;

use common::{Dataplane, IpPrefix};
use netlink_dp::NetlinkDataplane;
use sav::gen::UrpfMode;
use sav::mode::{SavAction, ValidationMode};
use sav::monitor::SpoofMonitor;
use sav::program::program;
use sav::table::SavOp;

fn main() -> ExitCode {
    // Logs from the dataplane crate (which rp_filter values it wrote)
    // to stderr; results on stdout for the script to grep. Same
    // subscriber shape as rousterd's logging (no env-filter feature).
    let _ = tracing_subscriber::fmt()
        .with_ansi(false)
        .with_writer(std::io::stderr)
        .try_init();
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.first().map(String::as_str) {
        Some("install") => run(&args[1..], Command::Install),
        Some("simulate") => run(&args[1..], Command::Simulate),
        Some("clear") => run(&args[1..], Command::Clear),
        _ => {
            eprintln!("usage: w7-sav-smoke install|simulate|clear [options]");
            eprintln!("  install|simulate: --mode strict|loose --action monitor|drop");
            eprintln!("                    --iba <ifindex>[:<prefix>] (repeatable)");
            eprintln!("  simulate also:     --observe <ip>@<ifindex> (repeatable)");
            ExitCode::FAILURE
        }
    }
}

#[derive(Clone, Copy, PartialEq)]
enum Command {
    Install,
    Simulate,
    Clear,
}

/// One parsed `--iba` entry: an interface and its allowlist prefix.
struct Iba {
    ifindex: u32,
    prefixes: Vec<IpPrefix>,
}

fn run(args: &[String], command: Command) -> ExitCode {
    let mut mode = UrpfMode::Strict;
    let mut action = SavAction::Monitor;
    let mut ibas: Vec<Iba> = Vec::new();
    let mut observes: Vec<(IpAddr, u32)> = Vec::new();

    let mut it = args.iter();
    while let Some(arg) = it.next() {
        match arg.as_str() {
            "--mode" => match it.next().map(String::as_str) {
                Some("strict") => mode = UrpfMode::Strict,
                Some("loose") => mode = UrpfMode::Loose,
                other => {
                    eprintln!("bad --mode {other:?} (strict|loose)");
                    return ExitCode::FAILURE;
                }
            },
            "--action" => match it.next().map(String::as_str) {
                Some("monitor") => action = SavAction::Monitor,
                Some("drop") => action = SavAction::Drop,
                other => {
                    eprintln!("bad --action {other:?} (monitor|drop)");
                    return ExitCode::FAILURE;
                }
            },
            "--iba" => {
                let Some(spec) = it.next() else {
                    eprintln!("--iba needs <ifindex>[:<prefix>]");
                    return ExitCode::FAILURE;
                };
                match parse_iba(spec) {
                    Ok(iba) => ibas.push(iba),
                    Err(e) => {
                        eprintln!("bad --iba {spec:?}: {e}");
                        return ExitCode::FAILURE;
                    }
                }
            }
            "--observe" => {
                let Some(spec) = it.next() else {
                    eprintln!("--observe needs <ip>@<ifindex>");
                    return ExitCode::FAILURE;
                };
                match parse_observe(spec) {
                    Some(pair) => observes.push(pair),
                    None => {
                        eprintln!("bad --observe {spec:?} (<ip>@<ifindex>)");
                        return ExitCode::FAILURE;
                    }
                }
            }
            other => {
                eprintln!("unknown option {other:?}");
                return ExitCode::FAILURE;
            }
        }
    }

    // Compile: one IBA op per interface (prefixes merged, sorted,
    // deduplicated — the compile step's normalization), exactly the
    // shape `sav::table::compile` emits for IBA-configured interfaces.
    let mut ops: Vec<SavOp> = Vec::new();
    for iba in &ibas {
        let mut prefixes = iba.prefixes.clone();
        prefixes.sort();
        prefixes.dedup();
        ops.push(SavOp::IbaPermit {
            ifindex: iba.ifindex,
            prefixes,
            action,
        });
    }

    if command == Command::Simulate {
        let mut monitor = SpoofMonitor::new(&ops);
        for &(source, ingress) in &observes {
            let verdict = monitor.observe(source, ingress);
            println!("sav-verdict: {source} @ ingress {ingress} -> {verdict} ({mode} {action})");
        }
        let counts = monitor.counts();
        println!(
            "sav-monitor: invalid={} valid={} unknown={}",
            counts.invalid, counts.valid, counts.unknown
        );
        return ExitCode::SUCCESS;
    }

    // Install/clear: real dataplane through the trait.
    let runtime = match tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    {
        Ok(rt) => rt,
        Err(e) => {
            eprintln!("runtime: {e}");
            return ExitCode::FAILURE;
        }
    };
    runtime.block_on(async move {
        let (dp, conn) = match NetlinkDataplane::new() {
            Ok(pair) => pair,
            Err(e) => {
                eprintln!("netlink dataplane: {e}");
                return ExitCode::FAILURE;
            }
        };
        tokio::spawn(conn);
        let result = if command == Command::Install {
            let program = program(&ops, mode);
            dp.sav_install(&program).await
        } else {
            dp.sav_clear().await
        };
        match result {
            Ok(()) => {
                let what = if command == Command::Install {
                    format!(
                        "install ok: {} iba op(s), mode {mode}, action {action}, \
                         validation mode {}",
                        ops.len(),
                        ValidationMode::Iba
                    )
                } else {
                    "clear ok".to_string()
                };
                println!("sav-{what}");
                ExitCode::SUCCESS
            }
            Err(e) => {
                eprintln!("dataplane: {e}");
                ExitCode::FAILURE
            }
        }
    })
}

/// `ifindex` or `ifindex:prefix` — a missing prefix is the empty
/// allowlist (deny-all under strict, GSC §2.1).
fn parse_iba(spec: &str) -> Result<Iba, String> {
    let (ifindex, prefix) = match spec.split_once(':') {
        Some((ifindex, prefix)) => (ifindex, Some(prefix)),
        None => (spec, None),
    };
    let ifindex: u32 = ifindex.parse().map_err(|e| format!("ifindex: {e}"))?;
    let prefixes = match prefix {
        Some(p) => vec![p.parse::<IpPrefix>().map_err(|e| e.to_string())?],
        None => Vec::new(),
    };
    Ok(Iba { ifindex, prefixes })
}

fn parse_observe(spec: &str) -> Option<(IpAddr, u32)> {
    let (ip, ifindex) = spec.split_once('@')?;
    Some((ip.parse().ok()?, ifindex.parse().ok()?))
}
