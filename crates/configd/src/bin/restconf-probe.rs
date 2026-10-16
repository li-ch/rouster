//! restconf-probe — the RESTCONF edge's smoke client (S13-c M4):
//! one HTTP/1.1 exchange over the local unix socket (the default
//! plane) or TCP, with an optional bearer token, printing the raw
//! wire response. The zapi-neigh-probe/zapi-notify-probe precedent:
//! busybox `nc` has no `-U`, so the container smokes need a real
//! socket client — and operators get a dependency-free one-liner
//! for the socket plane (`curl --unix-socket` needs curl).
//!
//! A CLIENT: taking `--token` on its command line is fine (the
//! no-flag rule is about restconfd's SERVER config — a daemon whose
//! credential would sit in every `ps` output for its lifetime; a
//! probe runs for milliseconds. Still: shells history it, so prefer
//! reading the token from the environment when scripting:
//! `--token-env NAME`).
//!
//! Usage:
//!
//! ```text
//! restconf-probe [--socket <PATH>] [--host <IP>] [--port <N>]
//!                [--token <HEX> | --token-env <NAME>]
//!                <METHOD> <TARGET> [BODY]
//! ```
//!
//! Exits 0 when an exchange completed (the response — status line
//! and all — goes to stdout; grep it), 1 on a usage or connect
//! failure, 2 on an IO failure mid-exchange.

use std::io::Write;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UnixStream};

#[derive(Clone)]
enum Plane {
    Socket(String),
    Tcp { host: String, port: u16 },
}

struct Args {
    plane: Option<Plane>,
    token: Option<String>,
    method: String,
    target: String,
    body: Option<String>,
}

fn print_help() {
    print!(
        "\
restconf-probe {version} — the RESTCONF edge's socket/TCP client (S13-c)

USAGE:
    restconf-probe [--socket <PATH>] [--host <IP>] [--port <N>]
                   [--token <HEX> | --token-env <NAME>]
                   <METHOD> <TARGET> [BODY]

WHAT:
    One HTTP/1.1 request over the plane restconfd actually serves
    (the local unix socket by default — pass --socket explicitly or
    set --host/--port for the TCP plane), the raw response on
    stdout (status line, headers, body — the connection-per-request
    subset means read-to-EOF is the frame).

    --socket <PATH>   the unix socket (default /run/rouster/restconf.sock)
    --host <IP>       the TCP plane's host (with --port; overrides the socket)
    --port <N>        the TCP plane's port
    --token <HEX>     send 'Authorization: Bearer <HEX>' (the client-side
                      one-off; scripts should prefer --token-env)
    --token-env NAME  read the token from the environment variable NAME
    --help, -h        this help
    --version, -V     the version

EXIT:
    0 exchange completed · 1 usage/connect failure · 2 mid-exchange IO failure
",
        version = env!("CARGO_PKG_VERSION")
    );
}

fn parse_args() -> Result<Args, String> {
    let mut socket: Option<String> = None;
    let mut host: Option<String> = None;
    let mut port: Option<u16> = None;
    let mut token: Option<String> = None;
    let mut rest: Vec<String> = Vec::new();
    let mut it = std::env::args().skip(1);
    while let Some(arg) = it.next() {
        match arg.as_str() {
            "--socket" => {
                socket = Some(it.next().ok_or("--socket requires a path")?);
            }
            "--host" => {
                host = Some(it.next().ok_or("--host requires an address")?);
            }
            "--port" | "-p" => {
                let value = it.next().ok_or("--port requires a number")?;
                port = Some(value.parse().map_err(|_| format!("bad port `{value}`"))?);
            }
            "--token" => {
                token = Some(it.next().ok_or("--token requires a value")?);
            }
            "--token-env" => {
                let name = it.next().ok_or("--token-env requires a variable name")?;
                token = Some(
                    std::env::var(&name)
                        .map_err(|_| format!("the environment variable {name} is not set"))?,
                );
            }
            "--help" | "-h" => {
                print_help();
                std::process::exit(0);
            }
            "--version" | "-V" => {
                println!("restconf-probe {}", env!("CARGO_PKG_VERSION"));
                std::process::exit(0);
            }
            other if other.starts_with('-') => return Err(format!("unknown argument `{other}`")),
            other => rest.push(other.to_string()),
        }
    }
    let plane = match (host, port) {
        (Some(host), Some(port)) => Plane::Tcp { host, port },
        (Some(_), None) => return Err("--host needs --port".to_string()),
        (None, Some(_)) => return Err("--port needs --host".to_string()),
        (None, None) => {
            Plane::Socket(socket.unwrap_or_else(|| "/run/rouster/restconf.sock".into()))
        }
    };
    let mut rest = rest.into_iter();
    let method = rest
        .next()
        .ok_or("usage: <METHOD> <TARGET> [BODY] (e.g. GET /restconf/data)")?;
    let target = rest.next().ok_or("usage: <METHOD> <TARGET> [BODY]")?;
    let body = rest.next();
    Ok(Args {
        plane: Some(plane),
        token,
        method,
        target,
        body,
    })
}

/// Renders the request wire bytes (the server's frozen subset:
/// HTTP/1.1, Host, optional bearer, Content-Length, close).
fn render_request(args: &Args, host_header: &str) -> Vec<u8> {
    let body = args.body.as_deref().unwrap_or("");
    let mut wire = format!(
        "{} {} HTTP/1.1\r\nHost: {}\r\n",
        args.method, args.target, host_header
    );
    if let Some(token) = &args.token {
        wire.push_str(&format!("Authorization: Bearer {token}\r\n"));
    }
    wire.push_str(&format!("Content-Length: {}\r\n", body.len()));
    wire.push_str("Connection: close\r\n\r\n");
    let mut bytes = wire.into_bytes();
    bytes.extend_from_slice(body.as_bytes());
    bytes
}

#[tokio::main]
async fn main() {
    let args = match parse_args() {
        Ok(args) => args,
        Err(complaint) => {
            eprintln!("restconf-probe: {complaint}");
            eprintln!("restconf-probe: try `--help`");
            std::process::exit(1);
        }
    };
    let code = run(args).await;
    std::process::exit(code as i32);
}

async fn run(args: Args) -> u8 {
    let plane = args
        .plane
        .clone()
        .expect("parse_args always sets the plane");
    match plane {
        Plane::Socket(path) => {
            let mut stream = match UnixStream::connect(&path).await {
                Ok(stream) => stream,
                Err(err) => {
                    eprintln!("restconf-probe: cannot connect to {path}: {err}");
                    return 1;
                }
            };
            exchange(&mut stream, &args, "localhost").await
        }
        Plane::Tcp { host, port } => {
            let mut stream = match TcpStream::connect((host.as_str(), port)).await {
                Ok(stream) => stream,
                Err(err) => {
                    eprintln!("restconf-probe: cannot connect to {host}:{port}: {err}");
                    return 1;
                }
            };
            exchange(&mut stream, &args, &host).await
        }
    }
}

/// Writes the request, reads to EOF (connection-per-request), prints
/// the raw response.
async fn exchange<S>(stream: &mut S, args: &Args, host_header: &str) -> u8
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    let request = render_request(args, host_header);
    if let Err(err) = stream.write_all(&request).await {
        eprintln!("restconf-probe: cannot write the request: {err}");
        return 2;
    }
    let _ = stream.shutdown().await;
    let mut response = Vec::new();
    if let Err(err) = stream.read_to_end(&mut response).await {
        eprintln!("restconf-probe: cannot read the response: {err}");
        return 2;
    }
    let mut stdout = std::io::stdout().lock();
    let _ = stdout.write_all(&response);
    0
}
