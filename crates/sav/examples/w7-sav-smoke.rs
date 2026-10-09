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
//!                       --iba <ifindex>[:<prefix>[,<prefix>...]] [--iba ...]
//! w7-sav-smoke simulate --mode ... --iba ... --observe <ip>@<ifindex> [...]
//! w7-sav-smoke clear
//! ```
//!
//! A per-interface allowlist of several prefixes is written either as
//! one comma-split `--iba` or as repeated `--iba` flags for the same
//! ifindex (they merge; the compile step below still emits one op per
//! interface).

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
            eprintln!("                    --iba <ifindex>[:<prefix>[,<prefix>...]]");
            eprintln!("                      (repeatable; entries for one ifindex merge)");
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
                    eprintln!("--iba needs <ifindex>[:<prefix>[,<prefix>...]]");
                    return ExitCode::FAILURE;
                };
                match parse_iba(spec) {
                    Ok(iba) => push_iba(&mut ibas, iba),
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
            origin: None,
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

/// `ifindex` or `ifindex:prefix[,prefix...]` — a missing or empty
/// prefix list is the empty allowlist (deny-all under strict,
/// GSC §2.1); comma-separated prefixes build a multi-prefix allowlist
/// in a single flag.
fn parse_iba(spec: &str) -> Result<Iba, String> {
    let (ifindex, prefixes) = match spec.split_once(':') {
        Some((ifindex, prefixes)) => (ifindex, prefixes),
        None => (spec, ""),
    };
    let ifindex: u32 = ifindex.parse().map_err(|e| format!("ifindex: {e}"))?;
    let prefixes = if prefixes.is_empty() {
        Vec::new()
    } else {
        prefixes
            .split(',')
            .map(|p| p.parse::<IpPrefix>().map_err(|e| e.to_string()))
            .collect::<Result<Vec<_>, _>>()?
    };
    Ok(Iba { ifindex, prefixes })
}

/// Repeated `--iba` flags for one interface extend its allowlist
/// instead of stacking a second op for the same ifindex (the compile
/// step still merges/sorts/dedups per interface).
fn push_iba(ibas: &mut Vec<Iba>, iba: Iba) {
    match ibas.iter_mut().find(|e| e.ifindex == iba.ifindex) {
        Some(existing) => existing.prefixes.extend(iba.prefixes),
        None => ibas.push(iba),
    }
}

fn parse_observe(spec: &str) -> Option<(IpAddr, u32)> {
    let (ip, ifindex) = spec.split_once('@')?;
    Some((ip.parse().ok()?, ifindex.parse().ok()?))
}

// No `[[example]] test = true` convention exists in this workspace, so
// these run via `cargo test -p sav --examples` (self-verification);
// plain `cargo test` still compile-checks the file.
#[cfg(test)]
mod tests {
    use super::*;

    fn prefix(p: &str) -> IpPrefix {
        p.parse().expect("valid prefix")
    }

    #[test]
    fn comma_split_builds_multi_prefix_allowlist() {
        let iba = parse_iba("2:10.0.0.0/24,10.0.1.0/24,2001:db8::/32").unwrap();
        assert_eq!(iba.ifindex, 2);
        assert_eq!(
            iba.prefixes,
            vec![
                prefix("10.0.0.0/24"),
                prefix("10.0.1.0/24"),
                prefix("2001:db8::/32")
            ]
        );
    }

    #[test]
    fn repeatable_flags_merge_per_interface() {
        let mut ibas = Vec::new();
        for spec in ["2:10.0.0.0/24", "3:198.51.100.0/24", "2:10.0.1.0/24"] {
            push_iba(&mut ibas, parse_iba(spec).unwrap());
        }
        // one entry per ifindex, in order of first appearance
        assert_eq!(ibas.len(), 2);
        assert_eq!(ibas[0].ifindex, 2);
        assert_eq!(
            ibas[0].prefixes,
            vec![prefix("10.0.0.0/24"), prefix("10.0.1.0/24")]
        );
        assert_eq!(ibas[1].ifindex, 3);
        assert_eq!(ibas[1].prefixes, vec![prefix("198.51.100.0/24")]);
    }

    #[test]
    fn mixed_forms_and_legacy_single_prefix() {
        // legacy forms still parse: bare ifindex = empty allowlist,
        // single prefix without comma
        assert_eq!(parse_iba("5").unwrap().prefixes, Vec::new());
        assert_eq!(
            parse_iba("5:192.0.2.0/24").unwrap().prefixes,
            vec![prefix("192.0.2.0/24")]
        );
        // mixed: one comma-split flag plus a repeated flag, same ifindex
        let mut ibas = Vec::new();
        for spec in ["7:10.0.0.0/24,10.0.1.0/24", "7:10.0.2.0/24"] {
            push_iba(&mut ibas, parse_iba(spec).unwrap());
        }
        assert_eq!(ibas.len(), 1);
        assert_eq!(
            ibas[0].prefixes,
            vec![
                prefix("10.0.0.0/24"),
                prefix("10.0.1.0/24"),
                prefix("10.0.2.0/24")
            ]
        );
    }

    #[test]
    fn bad_iba_specs_error() {
        assert!(parse_iba("not-an-ifindex:10.0.0.0/24").is_err());
        assert!(parse_iba("2:10.0.0.0/24,,10.0.1.0/24").is_err()); // empty element
        assert!(parse_iba("2:not-a-prefix").is_err());
        assert!(parse_iba("2:10.0.0.0/24,banana").is_err());
    }
}
