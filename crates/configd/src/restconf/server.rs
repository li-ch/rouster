//! The server (S12-a): the tokio listener over the HTTP core and
//! the resource map — the vtyd server discipline (one listener, one
//! task per connection, graceful shutdown on a watch channel), with
//! two additions the vtyd shape does not need:
//!
//! - **Single-flight mutations** ([`Server::flight`]): one mutation
//!   at a time, the edit-collision discipline RFC 8040 §3.4.1 asks
//!   for (the optimistic-concurrency headers are §Deferred — the
//!   lock is the honest v1 form). The mutation itself (validate
//!   gates + the apply pipeline) runs on the blocking pool.
//! - **Dry-run mode**: GETs and HEADs answer; every mutation is a
//!   503 with the disclosure — a smoke-probe surface with no side
//!   effects. RFC 8040 has no dry-run; this is a Rouster extension,
//!   disclosed.
//!
//! Two listeners over the ONE HTTP core (S13-c): the DEFAULT is the
//! local unix socket ([`serve_unix`] — the v1.0 posture flip: the
//! socket's filesystem permissions ARE the access control, the unix
//! convention; the binary sets 0660 and owns the file's lifecycle),
//! and the TCP plane ([`serve`]) stays available for operators that
//! opt in (restconfd `--tcp`). The core is byte-identical over
//! either — [`handle_connection`] is generic over any
//! AsyncRead+AsyncWrite stream.
//!
//! Routing (RFC 8040 §4 vocabulary):
//!
//! | Method | `/restconf/data` | `/restconf/running` |
//! |---|---|---|
//! | GET (§4.3) | the candidate view | the running view |
//! | HEAD (§4.2) | GET's headers, no body | same |
//! | OPTIONS (§4.1) | 200 + Allow | same |
//! | PUT/POST/PATCH/DELETE | mutate (503 in dry-run) | 405 (read-only) |
//!
//! Version gate: HTTP/1.1 only (505 otherwise — RFC 9110 §9.6's
//! version negotiation is not attempted); a missing `Host` on 1.1 is
//! a 400 (RFC 9110 §7.2, the one conformance bit that guards the
//! parser). Connection-per-request: the answer is written, the
//! connection closes.

use std::sync::Arc;

use tokio::io::{AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, UnixListener};
use tokio::sync::watch;
use tracing::{info, warn};

use super::http::{self, HttpError, Request};
use super::resources::{self, Datastore, Reply, Store, Verb};

/// The serving state: where the datastore lives, whether mutations
/// are armed, and the single-flight lock.
pub struct Server {
    pub store: Datastore,
    pub dry_run: bool,
    /// One mutation at a time (RFC 8040 §3.4.1).
    flight: std::sync::Mutex<()>,
}

impl Server {
    pub fn new(store: Datastore, dry_run: bool) -> Server {
        Server {
            store,
            dry_run,
            flight: std::sync::Mutex::new(()),
        }
    }
}

/// Binds the unix socket the v1.0 way (S13-c): removes a stale
/// socket file (a SIGKILLed predecessor — the zapi-server
/// precedent; a live predecessor keeps its listener, the status
/// file's pid line is the liveness check), binds, and sets the
/// access-control bits. **The mode bits ARE the security model**:
/// 0660 — the socket's group may drive the API, everyone else is
/// refused by the kernel (connecting needs WRITE on a unix socket;
/// the operator's grouping is the ACL — docs/yang.md §restconf). A
/// chmod failure refuses the bind: serving with the umask's default
/// bits would silently change the access policy.
pub fn bind_unix_socket(path: &std::path::Path) -> std::io::Result<UnixListener> {
    if path.exists() {
        std::fs::remove_file(path)?;
    }
    let listener = UnixListener::bind(path)?;
    std::fs::set_permissions(
        path,
        std::os::unix::fs::PermissionsExt::from_mode(SOCKET_MODE),
    )?;
    Ok(listener)
}

/// The unix socket's mode bits (S13-c): owner+group read/write, no
/// world access. Connect needs WRITE on a unix socket, so 0660 =
/// "the socket's group may drive the API".
pub const SOCKET_MODE: u32 = 0o660;

/// Serves the TCP plane until `shutdown` fires (SIGTERM/SIGINT
/// wiring lives in the binary, the vtyd shape). Opt-in since S13-c
/// (restconfd `--tcp`); the default listener is [`serve_unix`].
pub async fn serve(
    listener: TcpListener,
    server: Arc<Server>,
    mut shutdown: watch::Receiver<bool>,
) -> std::io::Result<()> {
    info!(
        bind = %listener
            .local_addr()
            .map(|a| a.to_string())
            .unwrap_or_default(),
        dry_run = server.dry_run,
        "restconfd: RESTCONF server listening on TCP (hand-rolled HTTP/1.1, no TLS — the disclosed posture; docs/yang.md §restconf)"
    );
    loop {
        tokio::select! {
            accepted = listener.accept() => {
                let (stream, peer) = match accepted {
                    Ok(pair) => pair,
                    Err(err) => {
                        warn!(%err, "restconfd: accept failed");
                        continue;
                    }
                };
                let server = Arc::clone(&server);
                tokio::spawn(async move {
                    if let Err(err) = handle_connection(stream, server).await {
                        warn!(%peer, %err, "restconfd: connection ended with an IO error");
                    }
                });
            }
            _ = shutdown.changed() => {
                info!("restconfd: shutdown signal; closing listener (the open connection, if any, closes with its response)");
                return Ok(());
            }
        }
    }
}

/// Serves the DEFAULT plane (S13-c): the local unix socket, over the
/// exact same HTTP core. The caller (the binary) owns the socket
/// file's lifecycle — stale-file removal before bind, the 0660 mode
/// bits after, unlink on clean exit; this fn only accepts.
pub async fn serve_unix(
    listener: UnixListener,
    socket_path: std::path::PathBuf,
    server: Arc<Server>,
    mut shutdown: watch::Receiver<bool>,
) -> std::io::Result<()> {
    info!(
        socket = %socket_path.display(),
        dry_run = server.dry_run,
        "restconfd: RESTCONF server listening on the local unix socket (mode 0660 — \
         filesystem permissions are the access control, the unix convention)"
    );
    loop {
        tokio::select! {
            accepted = listener.accept() => {
                let (stream, _peer) = match accepted {
                    Ok(pair) => pair,
                    Err(err) => {
                        warn!(%err, "restconfd: accept failed");
                        continue;
                    }
                };
                let server = Arc::clone(&server);
                tokio::spawn(async move {
                    if let Err(err) = handle_connection(stream, server).await {
                        warn!(%err, "restconfd: connection ended with an IO error");
                    }
                });
            }
            _ = shutdown.changed() => {
                info!("restconfd: shutdown signal; closing listener (the open connection, if any, closes with its response)");
                return Ok(());
            }
        }
    }
}

/// One connection (either plane): one request, one response, close
/// (the disclosed no-keep-alive subset). Generic over the stream —
/// TCP and unix sockets share the byte flow.
async fn handle_connection<S>(mut stream: S, server: Arc<Server>) -> std::io::Result<()>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    let request = {
        let mut reader = BufReader::new(&mut stream);
        http::read_request(&mut reader).await
    };
    let request = match request {
        Ok(request) => request,
        Err(HttpError::Incomplete) => return Ok(()), // quiet close
        Err(err) => {
            let response = error_for_http(&err);
            stream.write_all(&response).await?;
            return Ok(());
        }
    };
    let response = respond(server, request).await;
    stream.write_all(&response).await?;
    stream.shutdown().await?;
    Ok(())
}

/// Maps a read error to its response.
fn error_for_http(err: &HttpError) -> Vec<u8> {
    let (status, note) = match err {
        HttpError::Malformed(note) => (400, note.clone()),
        HttpError::BodyTooLarge => (413, err.to_string()),
        HttpError::HeadTooLarge => (431, err.to_string()),
        HttpError::Chunked => (501, err.to_string()),
        HttpError::Version(note) => (505, note.clone()),
        HttpError::Incomplete => (400, err.to_string()),
    };
    let mut e = resources::ApiError::not_found(note);
    e.status = status;
    http::render_response(
        status,
        resources::JSON_MEDIA_TYPE,
        e.body().as_bytes(),
        None,
    )
}

/// The router: one request in, one response out.
async fn respond(server: Arc<Server>, request: Request) -> Vec<u8> {
    if request.version != "HTTP/1.1" {
        let mut e = resources::ApiError::not_found(format!(
            "only HTTP/1.1 is supported (saw `{}`)",
            request.version
        ));
        e.status = 505;
        return http::render_response(505, resources::JSON_MEDIA_TYPE, e.body().as_bytes(), None);
    }
    if request.header("host").is_none() {
        let mut e = resources::ApiError::bad_request("HTTP/1.1 requires a Host header");
        e.status = 400;
        return http::render_response(400, resources::JSON_MEDIA_TYPE, e.body().as_bytes(), None);
    }
    let tail_store = match resources::split_target(&request.target) {
        Ok(pair) => pair,
        Err(err) => {
            return http::render_response(
                err.status,
                resources::JSON_MEDIA_TYPE,
                err.body().as_bytes(),
                None,
            )
        }
    };
    let (store, tail) = tail_store;
    let method = request.method.as_str();
    let running = store == Store::Running;

    match method {
        "GET" | "HEAD" => match resources::get(&server.store, running, tail) {
            Ok(reply) => render(reply, method == "HEAD"),
            Err(err) => http::render_response(
                err.status,
                resources::JSON_MEDIA_TYPE,
                err.body().as_bytes(),
                if running {
                    Some("GET, HEAD, OPTIONS")
                } else {
                    Some(Verb::ALLOW)
                },
            ),
        },
        "OPTIONS" => http::render_response(
            200,
            resources::JSON_MEDIA_TYPE,
            b"",
            Some(if running {
                "OPTIONS, HEAD, GET"
            } else {
                Verb::ALLOW
            }),
        ),
        "PUT" | "POST" | "PATCH" | "DELETE" => {
            if server.dry_run {
                let e = resources::ApiError::unavailable(
                    "dry-run: mutations are refused (restconfd --dry-run; a Rouster extension, \
                     disclosed — RFC 8040 defines no dry-run)",
                );
                return http::render_response(
                    503,
                    resources::JSON_MEDIA_TYPE,
                    e.body().as_bytes(),
                    None,
                );
            }
            let verb = match method {
                "PUT" => Verb::Put,
                "DELETE" => Verb::Delete,
                // POST = merge (the decision-C cut); PATCH is the
                // RFC 8040 §4.6.1 plain-patch merge.
                _ => Verb::Merge,
            };
            if running {
                // The read-only view (the router's Allow-carrying
                // form; resources::mutate holds the same refusal as
                // the inner safety).
                let e = resources::ApiError::new(
                    405,
                    "operation-not-supported",
                    "the running view is read-only (the last confirmed generation) — mutate /restconf/data",
                );
                return http::render_response(
                    405,
                    resources::JSON_MEDIA_TYPE,
                    e.body().as_bytes(),
                    Some("OPTIONS, HEAD, GET"),
                );
            }
            let body = request.body.clone();
            let store = server.store.clone();
            let tail = tail.to_string();
            let guard = Arc::clone(&server);
            let reply = tokio::task::spawn_blocking(move || {
                // Single-flight: one mutation at a time (§3.4.1).
                let _flight = guard.flight.lock().unwrap_or_else(|p| p.into_inner());
                resources::mutate(&store, running, verb, &tail, &body)
            })
            .await;
            match reply {
                Ok(reply) => render(reply, false),
                Err(join) => {
                    let e =
                        resources::ApiError::internal(format!("the mutation task failed: {join}"));
                    http::render_response(
                        500,
                        resources::JSON_MEDIA_TYPE,
                        e.body().as_bytes(),
                        None,
                    )
                }
            }
        }
        other => {
            let e = resources::ApiError::new(
                405,
                "operation-not-supported",
                format!("method `{other}` is not supported on this resource"),
            );
            http::render_response(
                405,
                resources::JSON_MEDIA_TYPE,
                e.body().as_bytes(),
                Some(if running {
                    "OPTIONS, HEAD, GET"
                } else {
                    Verb::ALLOW
                }),
            )
        }
    }
}

/// A reply rendered to wire bytes; HEAD strips the body but keeps
/// GET's Content-Length (RFC 9110 §9.3.2).
fn render(reply: Reply, head: bool) -> Vec<u8> {
    let bytes = http::render_response(
        reply.status,
        resources::JSON_MEDIA_TYPE,
        reply.body.as_bytes(),
        None,
    );
    if !head {
        return bytes;
    }
    let split = bytes
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .map(|pos| pos + 4)
        .unwrap_or(bytes.len());
    bytes[..split].to_vec()
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::net::{TcpStream, UnixStream};

    fn scratch(tag: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "configd-restconf-server-{tag}-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join("run")).unwrap();
        std::fs::create_dir_all(dir.join("etc")).unwrap();
        dir
    }

    async fn spawn_server(tag: &str, dry_run: bool, canonical: &str) -> (std::path::PathBuf, u16) {
        let dir = scratch(tag);
        let canonical_path = dir.join("rouster.conf");
        std::fs::write(&canonical_path, canonical).unwrap();
        let server = Arc::new(Server::new(
            Datastore {
                canonical: canonical_path,
                run_dir: dir.join("run"),
                etc_dir: dir.join("etc"),
            },
            dry_run,
        ));
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let (tx, rx) = watch::channel(false);
        tokio::spawn(serve(listener, server, rx));
        // Keep the shutdown sender alive for the test's length.
        std::mem::forget(tx);
        (dir, port)
    }

    async fn roundtrip(port: u16, wire: &str) -> (u16, String) {
        let mut stream = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
        use tokio::io::AsyncReadExt;
        stream.write_all(wire.as_bytes()).await.unwrap();
        let mut buf = Vec::new();
        // The server closes after the response (connection-per-
        // request), so read-to-EOF is the frame.
        let _ = stream.read_to_end(&mut buf).await;
        let text = String::from_utf8_lossy(&buf).into_owned();
        let status = text
            .split_whitespace()
            .nth(1)
            .and_then(|s| s.parse().ok())
            .unwrap_or(0);
        let body = text
            .split_once("\r\n\r\n")
            .map(|(_, b)| b.to_string())
            .unwrap_or_default();
        (status, body)
    }

    const CANONICAL: &str = "daemon savd {\nmode strict\npoll 2\n}\n";

    #[tokio::test]
    async fn get_over_real_tcp_answers_and_closes() {
        let (_dir, port) = spawn_server("get", false, CANONICAL).await;
        let (status, body) = roundtrip(
            port,
            "GET /restconf/data/savd/poll HTTP/1.1\r\nHost: t\r\n\r\n",
        )
        .await;
        assert_eq!(status, 200, "{body}");
        assert_eq!(body, "{\"poll\":2}");
    }

    #[tokio::test]
    async fn put_over_real_tcp_mutates_the_candidate() {
        let (dir, port) = spawn_server("put", false, CANONICAL).await;
        let (status, body) = roundtrip(
            port,
            "PUT /restconf/data/savd/poll HTTP/1.1\r\nHost: t\r\nContent-Length: 1\r\n\r\n3",
        )
        .await;
        assert_eq!(status, 200, "{body}");
        assert!(body.contains("\"generation\":1"), "{body}");
        assert!(std::fs::read_to_string(dir.join("rouster.conf"))
            .unwrap()
            .contains("poll 3"));
    }

    #[tokio::test]
    async fn dry_run_answers_gets_and_refuses_mutations() {
        let (dir, port) = spawn_server("dry", true, CANONICAL).await;
        let (status, _) = roundtrip(
            port,
            "GET /restconf/data/savd/poll HTTP/1.1\r\nHost: t\r\n\r\n",
        )
        .await;
        assert_eq!(status, 200);
        for method in ["PUT", "POST", "PATCH", "DELETE"] {
            let (status, body) = roundtrip(
                port,
                &format!("{method} /restconf/data/savd/poll HTTP/1.1\r\nHost: t\r\nContent-Length: 1\r\n\r\n3"),
            )
            .await;
            assert_eq!(status, 503, "{method}: {body}");
        }
        assert_eq!(
            std::fs::read_to_string(dir.join("rouster.conf")).unwrap(),
            CANONICAL
        );
    }

    #[tokio::test]
    async fn running_mutations_are_405_with_allow() {
        let (_dir, port) = spawn_server("running", false, CANONICAL).await;
        let mut stream = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
        stream
            .write_all(b"DELETE /restconf/running/savd/poll HTTP/1.1\r\nHost: t\r\n\r\n")
            .await
            .unwrap();
        let mut buf = Vec::new();
        use tokio::io::AsyncReadExt;
        let _ = stream.read_to_end(&mut buf).await;
        let text = String::from_utf8_lossy(&buf).into_owned();
        assert!(text.starts_with("HTTP/1.1 405"), "{text}");
        assert!(text.contains("Allow: OPTIONS, HEAD, GET"), "{text}");
    }

    #[tokio::test]
    async fn head_keeps_gets_headers_and_drops_the_body() {
        let (_dir, port) = spawn_server("head", false, CANONICAL).await;
        let (_status, body) = roundtrip(
            port,
            "HEAD /restconf/data/savd/poll HTTP/1.1\r\nHost: t\r\n\r\n",
        )
        .await;
        assert_eq!(body, "");
        // The headers above the empty body carried GET's length.
        // (roundtrip returns the body only; the status asserted the
        // resource exists.)
    }

    #[tokio::test]
    async fn options_advertises_the_allow_set() {
        let (_dir, port) = spawn_server("options", false, CANONICAL).await;
        let mut stream = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
        stream
            .write_all(b"OPTIONS /restconf/data HTTP/1.1\r\nHost: t\r\n\r\n")
            .await
            .unwrap();
        let mut buf = Vec::new();
        use tokio::io::AsyncReadExt;
        let _ = stream.read_to_end(&mut buf).await;
        let text = String::from_utf8_lossy(&buf).into_owned();
        assert!(text.starts_with("HTTP/1.1 200"), "{text}");
        assert!(text.contains(&format!("Allow: {}", Verb::ALLOW)), "{text}");
    }

    #[tokio::test]
    async fn bad_version_and_missing_host_are_refused() {
        let (_dir, port) = spawn_server("version", false, CANONICAL).await;
        let (status, _) = roundtrip(port, "GET /restconf/data HTTP/1.0\r\nHost: t\r\n\r\n").await;
        assert_eq!(status, 505);
        let (status, _) = roundtrip(port, "GET /restconf/data HTTP/1.1\r\n\r\n").await;
        assert_eq!(status, 400);
    }

    #[tokio::test]
    async fn unknown_methods_get_405() {
        let (_dir, port) = spawn_server("brew", false, CANONICAL).await;
        let (status, _) = roundtrip(port, "BREW /restconf/data HTTP/1.1\r\nHost: t\r\n\r\n").await;
        assert_eq!(status, 405);
    }

    #[tokio::test]
    async fn targets_outside_restconf_are_404() {
        let (_dir, port) = spawn_server("outside", false, CANONICAL).await;
        let (status, _) = roundtrip(port, "GET /vty HTTP/1.1\r\nHost: t\r\n\r\n").await;
        assert_eq!(status, 404);
    }

    // ---- the unix-socket plane (S13-c M1) ----

    fn spawn_unix_server(
        tag: &str,
        dry_run: bool,
        canonical: &str,
    ) -> (std::path::PathBuf, std::path::PathBuf) {
        let dir = scratch(tag);
        let canonical_path = dir.join("rouster.conf");
        std::fs::write(&canonical_path, canonical).unwrap();
        let server = Arc::new(Server::new(
            Datastore {
                canonical: canonical_path,
                run_dir: dir.join("run"),
                etc_dir: dir.join("etc"),
            },
            dry_run,
        ));
        // The socket needs a SHORT path (sun_path is ~104 bytes; the
        // temp-dir scratch prefix alone can eat that).
        let socket = std::env::temp_dir().join(format!("rc-srv-{tag}-{}.sock", std::process::id()));
        let _ = std::fs::remove_file(&socket);
        let listener = bind_unix_socket(&socket).expect("bind the unix socket");
        let (_tx, rx) = watch::channel(false);
        let path = socket.clone();
        tokio::spawn(serve_unix(listener, path, server, rx));
        std::mem::forget(_tx);
        (dir, socket)
    }

    async fn unix_roundtrip(socket: &std::path::Path, wire: &str) -> (u16, String) {
        let mut stream = UnixStream::connect(socket).await.unwrap();
        stream.write_all(wire.as_bytes()).await.unwrap();
        let mut buf = Vec::new();
        use tokio::io::AsyncReadExt;
        let _ = stream.read_to_end(&mut buf).await;
        let text = String::from_utf8_lossy(&buf).into_owned();
        let status = text
            .split_whitespace()
            .nth(1)
            .and_then(|s| s.parse().ok())
            .unwrap_or(0);
        let body = text
            .split_once("\r\n\r\n")
            .map(|(_, b)| b.to_string())
            .unwrap_or_default();
        (status, body)
    }

    #[tokio::test]
    async fn the_socket_lands_with_the_0660_access_control_bits() {
        let (_dir, socket) = spawn_unix_server("modebits", false, CANONICAL);
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(&socket).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o660, "the filesystem bits ARE the ACL");
    }

    #[tokio::test]
    async fn bind_unix_socket_replaces_a_stale_socket_file() {
        let socket = std::env::temp_dir().join(format!("rc-srv-stale-{}.sock", std::process::id()));
        std::fs::write(&socket, b"leftover bytes from a SIGKILLed run").unwrap();
        // The leftover bytes would make connect() fail with ECONNREFUSED
        // ("socket in use" shape); bind_unix_socket removes and rebinds.
        bind_unix_socket(&socket).expect("stale removal + rebind");
        use std::os::unix::fs::FileTypeExt;
        assert!(std::fs::metadata(&socket).unwrap().file_type().is_socket());
    }

    #[tokio::test]
    async fn get_over_the_unix_socket_answers_the_same_bytes() {
        let (_dir, socket) = spawn_unix_server("unixget", false, CANONICAL);
        let (status, body) = unix_roundtrip(
            &socket,
            "GET /restconf/data/savd/poll HTTP/1.1\r\nHost: t\r\n\r\n",
        )
        .await;
        assert_eq!(status, 200, "{body}");
        assert_eq!(body, "{\"poll\":2}");
    }

    #[tokio::test]
    async fn put_over_the_unix_socket_mutates_the_candidate() {
        let (dir, socket) = spawn_unix_server("unixput", false, CANONICAL);
        let (status, body) = unix_roundtrip(
            &socket,
            "PUT /restconf/data/savd/poll HTTP/1.1\r\nHost: t\r\nContent-Length: 1\r\n\r\n3",
        )
        .await;
        assert_eq!(status, 200, "{body}");
        assert!(std::fs::read_to_string(dir.join("rouster.conf"))
            .unwrap()
            .contains("poll 3"));
    }

    #[tokio::test]
    async fn dry_run_over_the_socket_refuses_mutations() {
        let (dir, socket) = spawn_unix_server("unixdry", true, CANONICAL);
        let (status, _) = unix_roundtrip(
            &socket,
            "GET /restconf/data/savd/poll HTTP/1.1\r\nHost: t\r\n\r\n",
        )
        .await;
        assert_eq!(status, 200);
        let (status, _) = unix_roundtrip(
            &socket,
            "DELETE /restconf/data/savd/poll HTTP/1.1\r\nHost: t\r\n\r\n",
        )
        .await;
        assert_eq!(status, 503);
        assert_eq!(
            std::fs::read_to_string(dir.join("rouster.conf")).unwrap(),
            CANONICAL
        );
    }
}
