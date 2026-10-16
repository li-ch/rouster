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
//!           [--socket <PATH>] [--tcp [--bind <IP>] [--port <N>]] [--dry-run]
//! ```
//!
//! Server config precedence: flags over the canonical file's
//! `restconf { socket <path>; port <n>; bind <addr>; }` stanza
//! (YANG-validated at bind time against `rouster-vty`'s `restconf`
//! container) over the defaults. The stanza is a STARTUP-ONLY knob —
//! restconfd does not reload on its own config changes (the vtyd
//! bind discipline; a config-change restart is the honest v1).
//!
//! **Security posture v1.0 (S13-c), PROMINENT**: the DEFAULT
//! listener is the local unix socket `/run/rouster/restconf.sock`
//! (mode 0660) — filesystem permissions ARE the access control (the
//! unix convention: whoever may connect is whoever the operator let
//! into the socket's group). The TCP plane (loopback bind, plain
//! HTTP) is opt-in via `--tcp` (or an explicit `--bind`/`--port`
//! flag); RFC 8040 §2 expects HTTPS+auth — TLS is the documented
//! OWNER DECISION, not implemented (docs/yang.md §restconf has the
//! evaluation and the decision block). The optional static bearer
//! token (`restconf { token <hex>; }`, S13-c M2) is checked on
//! every request when configured — not a substitute for TLS over a
//! network.
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
//! listener socket                 (or: listener tcp)
//! socket /run/rouster/restconf.sock
//! canonical /etc/rouster.conf
//! run-dir /run/rouster
//! etc-dir /etc
//! security v1.0 socket 0660 (filesystem permissions = access control, the unix convention; docs/yang.md §restconf)
//! ```
//!
//! (TCP mode carries `bind`/`port` lines instead of the socket
//! line, and its security line says so — plain HTTP, RFC 8040 §2
//! expects HTTPS.)
//!
//! SIGTERM/SIGINT stop the listener, remove the status file AND the
//! socket file, exit 0.

use std::path::PathBuf;
use std::sync::Arc;

use configd::restconf::resources::Datastore;
use configd::restconf::server::{self, Server};
use configd::restconf::{RESTCONF_DEFAULT_BIND, RESTCONF_DEFAULT_PORT, RESTCONF_DEFAULT_SOCKET};
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
    socket: Option<PathBuf>,
    /// Force the TCP plane (the v1.0 default flip's opt-in).
    tcp: bool,
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
            socket: None,
            tcp: false,
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
restconfd {version} — Rouster RESTCONF northbound edge (RFC 8040 subset)

USAGE:
    restconfd [--canonical <PATH>] [--run-dir <PATH>] [--etc-dir <PATH>]
              [--socket <PATH>] [--tcp [--bind <IP>] [--port <N>]] [--dry-run]

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

SECURITY (v1.0, read this):
    The DEFAULT listener is the local unix socket {default_socket}
    (mode 0660): filesystem permissions ARE the access control —
    put the API's drivers in the socket's group, everyone else is
    refused by the kernel. The TCP plane (plain HTTP, no TLS) is
    opt-in: --tcp, or an explicit --bind/--port flag. RFC 8040 §2
    expects HTTPS; TLS (rustls) is a documented owner decision,
    not implemented (docs/yang.md §restconf). The optional bearer
    token (`restconf {{ token <hex>; }}`) is checked on every
    request when configured — it is not a substitute for TLS.

SERVER CONFIG:
    The canonical file's `restconf {{ socket <path>; port <n>; bind <addr>; }}`
    stanza (defaults socket {default_socket}, port {default_port}, bind
    {default_bind}); flags beat the stanza. Startup-only: restart to
    change.

FLAGS:
    --canonical <PATH>   the canonical config (default {default_canonical})
    --run-dir <PATH>     run dir (default {default_run_dir})
    --etc-dir <PATH>     etc dir forwarded to apply (default {default_etc})
    --socket <PATH>      the local unix socket to serve (default {default_socket})
    --tcp                serve TCP instead of the unix socket (the v1
                         flip's opt-in; --bind/--port imply it too)
    --bind <IP>          TCP listen address (default {default_bind}; loopback!)
    --port, -p <N>       TCP listen port (default {default_port})
    --dry-run            GETs only; mutations refused with 503
    --help, -h           this help
    --version, -V        the version

SIGNALS:
    SIGTERM/SIGINT stop the listener, remove the status file and the
    socket file, exit 0.
",
        version = env!("CARGO_PKG_VERSION"),
        default_port = RESTCONF_DEFAULT_PORT,
        default_bind = RESTCONF_DEFAULT_BIND,
        default_socket = RESTCONF_DEFAULT_SOCKET,
        default_canonical = DEFAULT_CANONICAL,
        default_run_dir = DEFAULT_RUN_DIR,
        default_etc = DEFAULT_ETC_DIR,
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
                // A bind flag names the TCP plane (the v1.0 flip's
                // opt-in; --tcp spells the same thing).
                settings.tcp = true;
            }
            "--port" | "-p" => {
                let value = it.next().ok_or("--port requires a number")?;
                settings.port = Some(value.parse().map_err(|_| format!("bad port `{value}`"))?);
                settings.tcp = true;
            }
            "--socket" => {
                settings.socket = Some(PathBuf::from(it.next().ok_or("--socket requires a path")?));
            }
            "--tcp" => settings.tcp = true,
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

/// The stanza's overrides, each present only when the file carries
/// (and the model fills) it.
#[derive(Default)]
struct StanzaKnobs {
    port: Option<u16>,
    bind: Option<String>,
    socket: Option<String>,
}

/// The stanza's settings from the canonical file, when present and
/// bindable. An unreadable file falls back to defaults with a
/// warning (the file may appear later); a file that DOES NOT BIND
/// is a hard refusal — serving with an invalid server config would
/// lie about the plane.
fn stanza_settings(canonical: &std::path::Path) -> Result<StanzaKnobs, String> {
    let bytes = match std::fs::read(canonical) {
        Ok(bytes) => bytes,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(StanzaKnobs::default()),
        Err(err) => {
            return Err(format!(
                "cannot read {}: {err} (fix it, or pass --socket/--bind/--port)",
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
        Some(settings) => Ok(StanzaKnobs {
            port: Some(settings.port),
            bind: Some(settings.bind),
            socket: Some(settings.socket),
        }),
        None => Ok(StanzaKnobs::default()),
    }
}

/// Which plane this run serves.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Plane {
    Socket(PathBuf),
    Tcp { bind: String, port: u16 },
}

/// Renders and writes `<run-dir>/restconf.status` (house format).
fn write_status(settings: &Settings, plane: &Plane) -> std::io::Result<()> {
    let listener = match plane {
        Plane::Socket(path) => format!(
            "listener socket\nsocket {}\nsecurity v1.0 socket 0{:o} (filesystem permissions = \
             access control, the unix convention; docs/yang.md §restconf)",
            path.display(),
            server::SOCKET_MODE
        ),
        Plane::Tcp { bind, port } => format!(
            "listener tcp\nbind {bind}\nport {port}\nsecurity v1.0 tcp plain-HTTP no-TLS \
             (RFC 8040 §2 expects HTTPS — the documented owner decision; docs/yang.md §restconf)"
        ),
    };
    let text = format!(
        "restconfd {} pid {}\nmode {}\n{}\ncanonical {}\nrun-dir {}\netc-dir {}\n",
        env!("CARGO_PKG_VERSION"),
        std::process::id(),
        if settings.dry_run { "dry-run" } else { "serve" },
        listener,
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
    let knobs = match stanza_settings(&settings.canonical) {
        Ok(knobs) => knobs,
        Err(complaint) => {
            eprintln!("restconfd: {complaint}");
            std::process::exit(1);
        }
    };
    let plane = if settings.tcp {
        let port = settings
            .port
            .or(knobs.port)
            .unwrap_or(RESTCONF_DEFAULT_PORT);
        let bind = settings
            .bind
            .clone()
            .or(knobs.bind)
            .unwrap_or_else(|| RESTCONF_DEFAULT_BIND.to_string());
        if bind != "127.0.0.1" && bind != "::1" && bind != "localhost" {
            eprintln!(
                "restconfd: WARNING: binding {bind} over plain HTTP with NO TLS — \
                 RFC 8040 §2 expects HTTPS; this is a management surface, not a public one \
                 (docs/yang.md §restconf has the posture and the TLS decision)"
            );
        }
        Plane::Tcp { bind, port }
    } else {
        // The v1.0 default: the local unix socket.
        if knobs.bind.is_some() || knobs.port.is_some() {
            eprintln!(
                "restconfd: NOTE: the stanza carries bind/port but the default listener is \
                 the local unix socket (the v1.0 flip, S13-c); pass --tcp to arm the TCP plane"
            );
        }
        let socket = settings
            .socket
            .clone()
            .or(knobs.socket.map(PathBuf::from))
            .unwrap_or_else(|| PathBuf::from(RESTCONF_DEFAULT_SOCKET));
        Plane::Socket(socket)
    };
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("tokio runtime");
    let code = runtime.block_on(run(settings, plane));
    std::process::exit(code as i32);
}

/// Bind the plane, publish the status file, serve until
/// SIGTERM/SIGINT.
async fn run(settings: Settings, plane: Plane) -> u8 {
    let server = Arc::new(Server::new(
        Datastore {
            canonical: settings.canonical.clone(),
            run_dir: settings.run_dir.clone(),
            etc_dir: settings.etc_dir.clone(),
        },
        settings.dry_run,
    ));
    // The clean-exit clear list (the savd discipline): a stale status
    // or socket file only survives SIGKILL.
    let mut cleanup: Vec<std::path::PathBuf> = vec![settings.run_dir.join("restconf.status")];
    match &plane {
        Plane::Socket(path) => {
            // The library owns the bind discipline (stale-file
            // removal + the 0660 access-control bits — the mode IS
            // the security model; a chmod failure refuses the bind).
            let listener = match server::bind_unix_socket(path) {
                Ok(listener) => listener,
                Err(err) => {
                    eprintln!(
                        "restconfd: cannot bind {} (stale removal + mode 0{:o}): {err}",
                        path.display(),
                        server::SOCKET_MODE
                    );
                    return 1;
                }
            };
            cleanup.push(path.clone());
            eprintln!(
                "restconfd: serving {} (mode 0{:o}; {}), candidate=/restconf/data \
                 running=/restconf/running — filesystem permissions are the access control \
                 (v1.0 posture; docs/yang.md §restconf)",
                path.display(),
                server::SOCKET_MODE,
                if settings.dry_run {
                    "dry-run: GETs only"
                } else {
                    "mutations armed"
                },
            );
            let path = path.clone();
            finish(settings, plane, cleanup, move |shutdown| {
                server::serve_unix(listener, path, server, shutdown)
            })
            .await
        }
        Plane::Tcp { bind, port } => {
            let addr = format!("{bind}:{port}");
            let listener = match TcpListener::bind(&addr).await {
                Ok(listener) => listener,
                Err(err) => {
                    eprintln!("restconfd: cannot bind {addr}: {err}");
                    return 1;
                }
            };
            eprintln!(
                "restconfd: serving {addr} ({}), candidate=/restconf/data \
                 running=/restconf/running — plain HTTP, no TLS (the opt-in TCP plane; \
                 docs/yang.md §restconf)",
                if settings.dry_run {
                    "dry-run: GETs only"
                } else {
                    "mutations armed"
                },
            );
            finish(settings, plane, cleanup, move |shutdown| {
                server::serve(listener, server, shutdown)
            })
            .await
        }
    }
}

/// The shared tail: status file, signal wiring, the serve call
/// (`serve` closes over the plane's already-bound listener).
async fn finish<S>(
    settings: Settings,
    plane: Plane,
    cleanup: Vec<std::path::PathBuf>,
    serve: impl FnOnce(watch::Receiver<bool>) -> S,
) -> u8
where
    S: std::future::Future<Output = std::io::Result<()>>,
{
    if let Err(err) = write_status(&settings, &plane) {
        eprintln!(
            "restconfd: cannot write {}: {err} (serving anyway)",
            settings.run_dir.join("restconf.status").display()
        );
    }
    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    tokio::spawn(async move {
        let mut term = signal(SignalKind::terminate()).expect("SIGTERM handler");
        let mut int = signal(SignalKind::interrupt()).expect("SIGINT handler");
        tokio::select! {
            _ = term.recv() => eprintln!("restconfd: SIGTERM"),
            _ = int.recv() => eprintln!("restconfd: SIGINT"),
        }
        let _ = shutdown_tx.send(true);
        // The clean-exit clear (the savd discipline): a stale status
        // file — or socket file — only survives SIGKILL.
        for path in cleanup {
            let _ = std::fs::remove_file(path);
        }
    });
    match serve(shutdown_rx).await {
        Ok(()) => 0,
        Err(err) => {
            eprintln!("restconfd: server ended with an IO error: {err}");
            1
        }
    }
}
