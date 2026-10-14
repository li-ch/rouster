//! vtyd — the Rouster VTY daemon binary.
//!
//! The thin shell over the `vty` library (the savd/bfdd shape):
//! this binary owns arguments, the `vtyd.conf` file, signals, and
//! the one-shot `--command` mode.
//!
//! Usage:
//!
//! ```text
//! vtyd [--config <PATH>] [--bind <IP>] [--port <N>] [--run-dir <PATH>] [--hostname <NAME>]
//!      [--canonical <PATH>] [--etc-dir <PATH>]
//! vtyd --command 'show ...' [--config <PATH> | --bind <IP> --port <N>]
//! ```
//!
//! `vtyd.conf` (the savd line conventions — blank/`!`/`#` ignored,
//! line-numbered errors):
//!
//! ```text
//! port 2626
//! bind 127.0.0.1
//! run-dir /run/rouster
//! hostname rouster
//! canonical /etc/rouster.conf
//! etc-dir /etc
//! ```
//!
//! Defaults: port 2626 (vtyd's own, in the 26xx VTY family —
//! FRR's per-daemon ports end at 2621), bind loopback, run dir
//! `/run/rouster`, hostname `rouster`, canonical `/etc/rouster.conf`
//! (the configd convention), etc-dir `/etc`. Flags beat the file;
//! the file beats defaults. SIGTERM and SIGINT stop the listener and
//! exit 0. The one-shot mode exits 0 (ran), 1 (transport), 2 (not
//! a command) — see `vty::client`. The write path (S8-c M4):
//! `write file`/`write memory` merge the session's edits onto the
//! canonical file, stage it atomically, and spawn `configd apply`
//! over it (the CLI surface — no IPC invention); configd's report
//! lines are the command's output.

use std::path::PathBuf;
use std::sync::Arc;

use tokio::net::TcpListener;
use tokio::signal::unix::{signal, SignalKind};
use tokio::sync::watch;
use tracing::{error, info, warn};

use vty::client;
use vty::server;
use vty::session::ServerInfo;
use vty::writer::ConfigdBackend;

/// Default port (vtyd's own, disclosed in the doc header).
const DEFAULT_PORT: u16 = 2626;
/// Default bind: loopback only (an operator who wants it reachable
/// says so in the config).
const DEFAULT_BIND: &str = "127.0.0.1";
/// Default run dir (the run-dir contract).
const DEFAULT_RUN_DIR: &str = "/run/rouster";
/// Default hostname (the prompt's name).
const DEFAULT_HOSTNAME: &str = "rouster";
/// Default canonical config file (the configd convention: the flat
/// `/etc` shape every smoke uses).
const DEFAULT_CANONICAL: &str = "/etc/rouster.conf";
/// Default etc-dir (forwarded to `configd apply`).
const DEFAULT_ETC_DIR: &str = "/etc";

/// The resolved settings (flags over file over defaults).
#[derive(Debug, Clone)]
struct Settings {
    bind: String,
    port: Option<u16>,
    run_dir: PathBuf,
    hostname: String,
    canonical: PathBuf,
    etc_dir: PathBuf,
}

impl Default for Settings {
    fn default() -> Settings {
        Settings {
            bind: DEFAULT_BIND.into(),
            port: None,
            run_dir: DEFAULT_RUN_DIR.into(),
            hostname: DEFAULT_HOSTNAME.into(),
            canonical: DEFAULT_CANONICAL.into(),
            etc_dir: DEFAULT_ETC_DIR.into(),
        }
    }
}

/// What the operator asked vtyd to do.
enum Command {
    /// Serve VTY connections.
    Run(Settings),
    /// Run one command against a running vtyd and exit.
    OneShot { settings: Settings, command: String },
}

fn parse_args() -> Result<Command, String> {
    let mut config_path: Option<PathBuf> = None;
    let mut settings = Settings::default();
    let mut command: Option<String> = None;
    let mut it = std::env::args().skip(1);
    while let Some(arg) = it.next() {
        match arg.as_str() {
            "--config" | "-f" => {
                config_path = Some(PathBuf::from(it.next().ok_or("--config requires a path")?));
            }
            "--bind" => {
                settings.bind = it.next().ok_or("--bind requires an IP address")?;
            }
            "--port" | "-p" => {
                let value = it.next().ok_or("--port requires a number")?;
                settings.port = Some(value.parse().map_err(|_| format!("bad port `{value}`"))?);
            }
            "--run-dir" => {
                settings.run_dir = PathBuf::from(it.next().ok_or("--run-dir requires a path")?);
            }
            "--hostname" => {
                settings.hostname = it.next().ok_or("--hostname requires a name")?;
            }
            "--canonical" => {
                settings.canonical = PathBuf::from(it.next().ok_or("--canonical requires a path")?);
            }
            "--etc-dir" => {
                settings.etc_dir = PathBuf::from(it.next().ok_or("--etc-dir requires a path")?);
            }
            "--command" | "-c" => {
                command = Some(it.next().ok_or("--command requires a command string")?);
            }
            "--help" | "-h" => {
                print_help();
                std::process::exit(0);
            }
            "--version" | "-V" => {
                println!("{}", vty::VERSION);
                std::process::exit(0);
            }
            other => return Err(format!("unknown argument `{other}`")),
        }
    }
    if let Some(path) = &config_path {
        apply_config_file(&mut settings, path)?;
    }
    match command {
        Some(command) => Ok(Command::OneShot { settings, command }),
        None => Ok(Command::Run(settings)),
    }
}

/// Applies `vtyd.conf` lines (line-numbered errors, the savd
/// conventions).
fn apply_config_file(settings: &mut Settings, path: &std::path::Path) -> Result<(), String> {
    let text = std::fs::read_to_string(path)
        .map_err(|err| format!("cannot read {}: {err}", path.display()))?;
    for (index, line) in text.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('!') || line.starts_with('#') {
            continue;
        }
        let mut words = line.split_whitespace();
        let directive = words.next().expect("nonempty line");
        let number = index + 1;
        match directive {
            "port" => {
                let value = words
                    .next()
                    .ok_or(format!("line {number}: port requires a number"))?;
                settings.port = Some(
                    value
                        .parse()
                        .map_err(|_| format!("line {number}: bad port `{value}`"))?,
                );
            }
            "bind" => {
                let value = words
                    .next()
                    .ok_or(format!("line {number}: bind requires an IP address"))?;
                settings.bind = value.to_string();
            }
            "run-dir" => {
                let value = words
                    .next()
                    .ok_or(format!("line {number}: run-dir requires a path"))?;
                settings.run_dir = PathBuf::from(value);
            }
            "hostname" => {
                let value = words
                    .next()
                    .ok_or(format!("line {number}: hostname requires a name"))?;
                settings.hostname = value.to_string();
            }
            "canonical" => {
                let value = words
                    .next()
                    .ok_or(format!("line {number}: canonical requires a path"))?;
                settings.canonical = PathBuf::from(value);
            }
            "etc-dir" => {
                let value = words
                    .next()
                    .ok_or(format!("line {number}: etc-dir requires a path"))?;
                settings.etc_dir = PathBuf::from(value);
            }
            other => return Err(format!("line {number}: unknown directive `{other}`")),
        }
        if let Some(extra) = words.next() {
            return Err(format!(
                "line {number}: unexpected `{extra}` after `{directive}`"
            ));
        }
    }
    Ok(())
}

fn print_help() {
    print!(
        "\
vtyd {version} — Rouster VTY daemon (vtysh-compatible surface, v1)

USAGE:
    vtyd [--config <PATH>] [--bind <IP>] [--port <N>] [--run-dir <PATH>] [--hostname <NAME>]
    vtyd --command '<show ...>' [--config <PATH> | --bind <IP> --port <N>]

SERVER:
    Serves a plain TCP line protocol (v1 disclosure) with a Cisco-style
    command parser: `?` help anywhere, abbreviated commands, user/enable/
    configure modes. Reads the run-dir contract (savd.status, savd.pid,
    bfdd.status, bfdd.pid); `write file`/`write memory` stage the merged
    canonical config and spawn `configd apply` (S8-c).

FLAGS:
    --config, -f <PATH>   vtyd.conf to read (flags beat the file)
    --bind <IP>           listen address (default {default_bind})
    --port, -p <N>        listen port (default {default_port})
    --run-dir <PATH>      run dir to read (default {default_run_dir})
    --hostname <NAME>     prompt hostname (default {default_hostname})
    --canonical <PATH>    canonical config the write path reads/writes
                          (default {default_canonical})
    --etc-dir <PATH>      etc-dir forwarded to configd apply
                          (default {default_etc_dir})
    --command, -c <CMD>   one-shot: run one command against a running vtyd
                          (the `vtysh -c` analog), print its output, exit
    --help, -h            this help
    --version, -V         print the version

ONE-SHOT EXIT CODES:
    0 command ran (source-state complaints are output, not failures —
      verify state, never trust rc)
    1 transport failure (connect, IO, timeout)
    2 not a command (unknown/ambiguous/incomplete/invalid input)

SIGNALS:
    SIGTERM/SIGINT stop the listener and exit 0.
",
        version = vty::VERSION,
        default_bind = DEFAULT_BIND,
        default_port = DEFAULT_PORT,
        default_run_dir = DEFAULT_RUN_DIR,
        default_hostname = DEFAULT_HOSTNAME,
        default_canonical = DEFAULT_CANONICAL,
        default_etc_dir = DEFAULT_ETC_DIR,
    );
}

fn main() {
    let command = match parse_args() {
        Ok(command) => command,
        Err(complaint) => {
            eprintln!("vtyd: {complaint}");
            eprintln!("vtyd: try `--help`");
            std::process::exit(2);
        }
    };
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("tokio runtime");
    let code = runtime.block_on(async {
        match command {
            Command::OneShot { settings, command } => {
                let addr = format!(
                    "{}:{}",
                    settings.bind,
                    settings.port.unwrap_or(DEFAULT_PORT)
                );
                match client::oneshot(&addr, &command).await {
                    Ok((body, errored)) => {
                        if !body.is_empty() {
                            println!("{body}");
                        }
                        if errored {
                            2
                        } else {
                            0
                        }
                    }
                    Err(err) => {
                        eprintln!("vtyd: {err}");
                        1
                    }
                }
            }
            Command::Run(settings) => run_server(settings).await,
        }
    });
    std::process::exit(code as i32);
}

/// The serving mode: bind, wire signals, serve until SIGTERM/INT.
async fn run_server(settings: Settings) -> u8 {
    // The bfdd shape: plain stderr logs, no ANSI (the env-filter
    // feature would add crates; verbosity rides RUST_LOG-less INFO).
    let _ = tracing_subscriber::fmt()
        .with_ansi(false)
        .with_writer(std::io::stderr)
        .try_init();
    let port = settings.port.unwrap_or(DEFAULT_PORT);
    let addr = format!("{}:{port}", settings.bind);
    let listener = match TcpListener::bind(&addr).await {
        Ok(listener) => listener,
        Err(err) => {
            error!("vtyd: cannot bind {addr}: {err}");
            return 1;
        }
    };
    let info = ServerInfo {
        bind: settings.bind.clone(),
        port,
        run_dir: settings.run_dir.clone(),
        canonical: settings.canonical.clone(),
        etc_dir: settings.etc_dir.clone(),
        started: std::time::Instant::now(),
        pid: std::process::id(),
    };
    // The write path (S8-c M4): `write file`/`write memory` stage the
    // merged canonical and spawn `configd apply` over it (process
    // spawn of the CLI surface — no IPC invention).
    let writer = Arc::new(ConfigdBackend::new(
        settings.canonical.clone(),
        settings.run_dir.clone(),
        settings.etc_dir.clone(),
    ));
    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    tokio::spawn(async move {
        let mut term = signal(SignalKind::terminate()).expect("SIGTERM handler");
        let mut int = signal(SignalKind::interrupt()).expect("SIGINT handler");
        tokio::select! {
            _ = term.recv() => info!("vtyd: SIGTERM"),
            _ = int.recv() => info!("vtyd: SIGINT"),
        }
        let _ = shutdown_tx.send(true);
    });
    let hostname = Arc::new(settings.hostname);
    match server::serve(listener, hostname, info, writer, shutdown_rx).await {
        Ok(()) => 0,
        Err(err) => {
            warn!("vtyd: server ended with an IO error: {err}");
            1
        }
    }
}
