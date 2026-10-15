//! restconfd — the RESTCONF northbound edge daemon (S12-a, the
//! owner's gNMI decision C): the RESTCONF-shaped HTTP/1.1 server
//! over configd's YANG tree ops and the RFC 7951 dump.
//!
//! The vtyd shell shape: this binary owns arguments, the listener,
//! signals, and the status file; the library (`configd::restconf`)
//! owns everything else.
//!
//! Usage:
//!
//! ```text
//! restconfd [--canonical <PATH>] [--run-dir <PATH>] [--etc-dir <PATH>]
//!           [--bind <IP>] [--port <N>] [--dry-run]
//! ```
//!
//! Server config precedence: flags over the canonical file's
//! `restconf { port <n>; bind <addr>; }` stanza (S12-a M4 —
//! YANG-validated at bind time against `rouster-vty`'s `restconf`
//! container) over the defaults (port 8080, bind 127.0.0.1). The
//! stanza is a STARTUP-ONLY knob — restconfd does not reload on its
//! own config changes (the vtyd bind discipline; a config-change
//! restart is the honest v1).
//!
//! **Security posture v1, PROMINENT**: plain HTTP on loopback by
//! default, **NO AUTHENTICATION**. RFC 8040 §2 expects HTTPS with
//! client authentication; the options (a local unix-socket
//! alternative, TLS via rustls) are an owner dependency decision —
//! §Deferred in docs/yang.md's implementation section. Until then:
//! bind loopback, treat the port as a management surface.
//!
//! `--dry-run` answers GETs/HEADs and refuses every mutation with
//! 503 — the smoke-probe surface without side effects (a Rouster
//! extension; RFC 8040 defines no dry-run).
//!
//! `<run-dir>/restconf.status` (house format, written at start,
//! removed on clean shutdown):
//!
//! ```text
//! restconfd 0.1.0 pid 4242
//! mode serve                      (or: mode dry-run)
//! bind 127.0.0.1
//! port 8080
//! canonical /etc/rouster.conf
//! run-dir /run/rouster
//! etc-dir /etc
//! security none v1 (loopback default, no auth, no TLS; RFC 8040 §2 expects HTTPS — docs/yang.md §restconf)
//! ```
//!
//! SIGTERM/SIGINT stop the listener, remove the status file, exit 0.

use std::path::PathBuf;
use std::sync::Arc;

use configd::restconf::resources::Datastore;
use configd::restconf::server::{self, Server};
use configd::restconf::{RESTCONF_DEFAULT_BIND, RESTCONF_DEFAULT_PORT};
use configd::tree;
use configd::yangmode;
use tokio::net::TcpListener;
use tokio::signal::unix::{signal, SignalKind};
use tokio::sync::watch;

/// Default canonical file (the configd convention).
const DEFAULT_CANONICAL: &str = "/etc/rouster.conf";
/// Default run dir (the run-dir contract).
const DEFAULT_RUN_DIR: &str = "/run/rouster";
/// Default etc dir.
const DEFAULT_ETC_DIR: &str = "/etc";

/// The resolved settings (flags over the `restconf` stanza over the
/// model defaults).
#[derive(Debug, Clone)]
struct Settings {
    bind: Option<String>,
    port: Option<u16>,
    canonical: PathBuf,
    run_dir: PathBuf,
    etc_dir: PathBuf,
    dry_run: bool,
}

impl Default for Settings {
    fn default() -> Settings {
        Settings {
            bind: None,
            port: None,
            canonical: PathBuf::from(DEFAULT_CANONICAL),
            run_dir: PathBuf::from(DEFAULT_RUN_DIR),
            etc_dir: PathBuf::from(DEFAULT_ETC_DIR),
            dry_run: false,
        }
    }
}

fn print_help() {
    print!(
        "\
restconfd {version} — Rouster RESTCONF northbound edge (RFC 8040 subset, v1)

USAGE:
    restconfd [--canonical <PATH>] [--run-dir <PATH>] [--etc-dir <PATH>]
              [--bind <IP>] [--port <N>] [--dry-run]

WHAT:
    Serves the canonical config's YANG trees over hand-rolled HTTP/1.1
    (no HTTP crate, no HTTP/2, no TLS):
      GET    /restconf/data[/path]    the candidate (the canonical file)
      GET    /restconf/running[/path] the last confirmed generation
      PUT    /restconf/data/path      replace a subtree (validate-first)
      POST   /restconf/data/path      merge (PATCH's plain-patch shape)
      PATCH  /restconf/data/path      the same merge
      DELETE /restconf/data/path      remove (404 on absent)
    Accepted mutations rewrite the canonical file and run the configd
    apply pipeline (render, SIGHUP, verify, auto-rollback); the
    response carries the per-daemon ack summary.

SECURITY (v1, read this):
    Plain HTTP, loopback-only by default, NO authentication. RFC 8040
    §2 expects HTTPS+auth; TLS (rustls) and a unix-socket alternative
    are an owner dependency decision (§Deferred, docs/yang.md). Do
    not bind beyond loopback until that decision lands.

SERVER CONFIG:
    The canonical file's `restconf {{ port <n>; bind <addr>; }}` stanza
    (default port {default_port}, bind {default_bind}); flags beat the
    stanza. Startup-only: restart to change.

FLAGS:
    --canonical <PATH>   the canonical config (default {default_canonical})
    --run-dir <PATH>     run dir (default {default_run_dir})
    --etc-dir <PATH>     etc dir forwarded to apply (default {default_etc_dir})
    --bind <IP>          listen address (default {default_bind}; loopback!)
    --port, -p <N>       listen port (default {default_port})
    --dry-run            GETs only; mutations refused with 503
    --help, -h           this help
    --version, -V        the version

SIGNALS:
    SIGTERM/SIGINT stop the listener and exit 0.
",
        version = env!("CARGO_PKG_VERSION"),
        default_port = RESTCONF_DEFAULT_PORT,
        default_bind = RESTCONF_DEFAULT_BIND,
        default_canonical = DEFAULT_CANONICAL,
        default_run_dir = DEFAULT_RUN_DIR,
        default_etc_dir = DEFAULT_ETC_DIR,
    );
}

fn parse_args() -> Result<Settings, String> {
    let mut settings = Settings::default();
    let mut it = std::env::args().skip(1);
    while let Some(arg) = it.next() {
        match arg.as_str() {
            "--canonical" => {
                settings.canonical = PathBuf::from(it.next().ok_or("--canonical requires a path")?);
            }
            "--run-dir" => {
                settings.run_dir = PathBuf::from(it.next().ok_or("--run-dir requires a path")?);
            }
            "--etc-dir" => {
                settings.etc_dir = PathBuf::from(it.next().ok_or("--etc-dir requires a path")?);
            }
            "--bind" => {
                settings.bind = Some(it.next().ok_or("--bind requires an IP address")?);
            }
            "--port" | "-p" => {
                let value = it.next().ok_or("--port requires a number")?;
                settings.port = Some(value.parse().map_err(|_| format!("bad port `{value}`"))?);
            }
            "--dry-run" => settings.dry_run = true,
            "--help" | "-h" => {
                print_help();
                std::process::exit(0);
            }
            "--version" | "-V" => {
                println!("restconfd {}", env!("CARGO_PKG_VERSION"));
                std::process::exit(0);
            }
            other => return Err(format!("unknown argument `{other}`")),
        }
    }
    Ok(settings)
}

/// The stanza's settings from the canonical file, when present and
/// bindable. An unreadable file falls back to defaults with a
/// warning (the file may appear later); a file that DOES NOT BIND
/// is a hard refusal — serving with an invalid server config would
/// lie about the plane.
fn stanza_settings(canonical: &std::path::Path) -> Result<(Option<u16>, Option<String>), String> {
    let bytes = match std::fs::read(canonical) {
        Ok(bytes) => bytes,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok((None, None)),
        Err(err) => {
            return Err(format!(
                "cannot read {}: {err} (fix it, or pass --bind/--port)",
                canonical.display()
            ))
        }
    };
    let text = String::from_utf8_lossy(&bytes);
    let parsed =
        tree::parse(&text).map_err(|e| format!("the canonical file does not parse: {e}"))?;
    let bound =
        yangmode::bind(&parsed).map_err(|e| format!("the canonical file does not bind: {e}"))?;
    match bound.restconf {
        Some(settings) => Ok((Some(settings.port), Some(settings.bind))),
        None => Ok((None, None)),
    }
}

/// Renders and writes `<run-dir>/restconf.status` (house format).
fn write_status(settings: &Settings, bind: &str, port: u16) -> std::io::Result<()> {
    let text = format!(
        "restconfd {} pid {}\nmode {}\nbind {}\nport {}\ncanonical {}\nrun-dir {}\netc-dir {}\n\
         security none v1 (loopback default, no auth, no TLS; RFC 8040 §2 expects HTTPS — docs/yang.md §restconf)\n",
        env!("CARGO_PKG_VERSION"),
        std::process::id(),
        if settings.dry_run { "dry-run" } else { "serve" },
        bind,
        port,
        settings.canonical.display(),
        settings.run_dir.display(),
        settings.etc_dir.display(),
    );
    configd::atomic::write_atomic(&settings.run_dir.join("restconf.status"), &text)
}

fn main() {
    let settings = match parse_args() {
        Ok(settings) => settings,
        Err(complaint) => {
            eprintln!("restconfd: {complaint}");
            eprintln!("restconfd: try `--help`");
            std::process::exit(2);
        }
    };
    let (stanza_port, stanza_bind) = match stanza_settings(&settings.canonical) {
        Ok(pair) => pair,
        Err(complaint) => {
            eprintln!("restconfd: {complaint}");
            std::process::exit(1);
        }
    };
    let port = settings
        .port
        .or(stanza_port)
        .unwrap_or(RESTCONF_DEFAULT_PORT);
    let bind = settings
        .bind
        .clone()
        .or(stanza_bind)
        .unwrap_or_else(|| RESTCONF_DEFAULT_BIND.to_string());
    if bind != "127.0.0.1" && bind != "::1" && bind != "localhost" {
        eprintln!(
            "restconfd: WARNING: binding {bind} with NO authentication and NO TLS — \
             RFC 8040 §2 expects HTTPS; this is a management surface, not a public one \
             (docs/yang.md §restconf has the posture)"
        );
    }
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("tokio runtime");
    let code = runtime.block_on(run(settings, bind, port));
    std::process::exit(code as i32);
}

/// Bind, publish the status file, serve until SIGTERM/SIGINT.
async fn run(settings: Settings, bind: String, port: u16) -> u8 {
    let addr = format!("{bind}:{port}");
    let listener = match TcpListener::bind(&addr).await {
        Ok(listener) => listener,
        Err(err) => {
            eprintln!("restconfd: cannot bind {addr}: {err}");
            return 1;
        }
    };
    if let Err(err) = write_status(&settings, &bind, port) {
        eprintln!(
            "restconfd: cannot write {}: {err} (serving anyway)",
            settings.run_dir.join("restconf.status").display()
        );
    }
    eprintln!(
        "restconfd: serving {addr} ({}), candidate=/restconf/data running=/restconf/running — \
         plain HTTP, NO AUTH (v1 posture; docs/yang.md §restconf)",
        if settings.dry_run {
            "dry-run: GETs only"
        } else {
            "mutations armed"
        },
    );
    let store = Datastore {
        canonical: settings.canonical.clone(),
        run_dir: settings.run_dir.clone(),
        etc_dir: settings.etc_dir.clone(),
    };
    let dry_run = settings.dry_run;
    let server = Arc::new(Server::new(store, dry_run));
    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let run_dir = settings.run_dir.clone();
    tokio::spawn(async move {
        let mut term = signal(SignalKind::terminate()).expect("SIGTERM handler");
        let mut int = signal(SignalKind::interrupt()).expect("SIGINT handler");
        tokio::select! {
            _ = term.recv() => eprintln!("restconfd: SIGTERM"),
            _ = int.recv() => eprintln!("restconfd: SIGINT"),
        }
        let _ = shutdown_tx.send(true);
        // The clean-exit clear (the savd discipline): a stale status
        // file only survives SIGKILL.
        let _ = std::fs::remove_file(run_dir.join("restconf.status"));
    });
    match server::serve(listener, server, shutdown_rx).await {
        Ok(()) => 0,
        Err(err) => {
            eprintln!("restconfd: server ended with an IO error: {err}");
            1
        }
    }
}
