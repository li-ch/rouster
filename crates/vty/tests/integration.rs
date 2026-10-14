//! Real-socket integration: an in-process server with a live
//! listener, the one-shot client over the actual TCP path, and the
//! real binaries end-to-end (server spawn, `--command` child, and
//! the SIGTERM contract).

use std::io::{Read, Write};
use std::net::TcpStream;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Output, Stdio};
use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::net::TcpListener;
use tokio::sync::watch;

use vty::client;
use vty::server;
use vty::session::ServerInfo;
use vty::writer::WriteBackend;

/// A write backend that records what it was handed and answers with
/// fixed lines — the configd contract in test form.
struct RecordingBackend {
    written: std::sync::Mutex<Vec<String>>,
    reply: Vec<String>,
}

impl WriteBackend for RecordingBackend {
    fn write(&self, canonical: &str) -> Vec<String> {
        self.written.lock().unwrap().push(canonical.to_string());
        self.reply.clone()
    }
}

fn scratch(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("vty-int-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn fixture(name: &str) -> String {
    let path = format!("{}/tests/fixtures/{name}", env!("CARGO_MANIFEST_DIR"));
    std::fs::read_to_string(&path).unwrap_or_else(|err| panic!("fixture {name}: {err}"))
}

/// A free loopback port (bound then released — a fresh race window,
/// retried by the callers that must bind it).
fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

/// Spawns an in-process server on its own thread; `(port, shutdown)`.
/// Bind retries on `AddrInUse` — the free-port probe's teardown race
/// (the same flake bfdd's daemon tests guard against). The canonical
/// path defaults to `<run-dir>/rouster.conf` and the write backend to
/// a recorder, both overridable via [`spawn_server_with`].
fn spawn_server(run_dir: &Path) -> (u16, watch::Sender<bool>) {
    let canonical = run_dir.join("rouster.conf");
    let writer: Arc<dyn WriteBackend> = Arc::new(RecordingBackend {
        written: std::sync::Mutex::new(Vec::new()),
        reply: vec!["configd: (recorder) applied".into()],
    });
    spawn_server_with(run_dir, &canonical, writer)
}

/// The full-control variant: canonical path and write backend.
fn spawn_server_with(
    run_dir: &Path,
    canonical: &Path,
    writer: Arc<dyn WriteBackend>,
) -> (u16, watch::Sender<bool>) {
    let (tx, rx) = watch::channel(false);
    let run_dir = run_dir.to_path_buf();
    let canonical = canonical.to_path_buf();
    let (bind_tx, bind_rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("runtime");
        runtime.block_on(async move {
            let mut listener = None;
            for _ in 0..5 {
                match TcpListener::bind(("127.0.0.1", 0)).await {
                    Ok(bound) => {
                        listener = Some(bound);
                        break;
                    }
                    Err(err) if err.kind() == std::io::ErrorKind::AddrInUse => continue,
                    Err(err) => panic!("bind: {err}"),
                }
            }
            let listener = listener.expect("bind after retries");
            let port = listener.local_addr().expect("local addr").port();
            bind_tx.send(port).ok();
            let info = ServerInfo {
                bind: "127.0.0.1".into(),
                port,
                run_dir,
                canonical,
                etc_dir: PathBuf::from("/nonexistent-etc"),
                started: Instant::now(),
                pid: std::process::id(),
            };
            server::serve(listener, Arc::new("rouster".into()), info, writer, rx)
                .await
                .expect("serve");
        });
    });
    let port = bind_rx.recv().expect("bound port");
    (port, tx)
}

/// Waits until a TCP connect to `port` succeeds (server spin-up).
fn wait_listening(port: u16) {
    let deadline = Instant::now() + Duration::from_secs(5);
    while Instant::now() < deadline {
        if TcpStream::connect(("127.0.0.1", port)).is_ok() {
            return;
        }
        std::thread::sleep(Duration::from_millis(25));
    }
    panic!("server on {port} never listened");
}

#[tokio::test]
async fn oneshot_over_a_real_socket_returns_the_body() {
    let dir = scratch("oneshot");
    std::fs::write(dir.join("savd.status"), fixture("savd-status-today.status")).unwrap();
    let (port, shutdown) = spawn_server(&dir);
    wait_listening(port);
    let (body, errored) = client::oneshot(&format!("127.0.0.1:{port}"), "sh ver")
        .await
        .expect("one-shot");
    assert!(!errored);
    assert!(body.contains("vtysh-compatible VTY server"));
    assert!(!body.contains("rouster> "), "prompt leaked into the body");
    // The banner's first line only — `show version` itself mentions
    // the line protocol, so the phrase alone proves nothing.
    assert!(
        !body.contains("Rouster VTY server (vtyd"),
        "banner leaked into the body"
    );
    // And a run-dir answer through the same path.
    let (body, errored) = client::oneshot(&format!("127.0.0.1:{port}"), "show sav")
        .await
        .expect("one-shot");
    assert!(!errored);
    assert!(body.contains("savd 0.0.0"));
    assert!(body.contains("198.51.100.0/24"));
    shutdown.send(true).ok();
    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test]
async fn oneshot_reports_command_errors_without_transport_errors() {
    let dir = scratch("oneshot-err");
    let (port, shutdown) = spawn_server(&dir);
    wait_listening(port);
    let (body, errored) = client::oneshot(&format!("127.0.0.1:{port}"), "router static")
        .await
        .expect("one-shot");
    assert!(errored);
    assert_eq!(body, "% Unknown command: router static");
    shutdown.send(true).ok();
    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test]
async fn oneshot_missing_status_is_output_not_failure() {
    let dir = scratch("oneshot-missing");
    let (port, shutdown) = spawn_server(&dir);
    wait_listening(port);
    let (body, errored) = client::oneshot(&format!("127.0.0.1:{port}"), "show sav")
        .await
        .expect("one-shot");
    assert!(!errored, "source-state honesty must not fail the run");
    assert!(body.starts_with("% No savd status published"));
    shutdown.send(true).ok();
    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test]
async fn oneshot_to_a_dead_port_is_a_transport_error() {
    let port = free_port();
    let err = client::oneshot(&format!("127.0.0.1:{port}"), "show version")
        .await
        .unwrap_err();
    assert!(
        matches!(
            err,
            client::ClientError::Connect { .. } | client::ClientError::Timeout { .. }
        ),
        "{err:?}"
    );
}

/// A byte-level prompt-framed reader — prompts carry no newline, so
/// line reading cannot see them; the stream between prompts is the
/// command's output. (Note the caveat exercised below: a token that
/// itself ends `> `/`# ` ends a read early — the one-shot client
/// has the same shape constraint, which is exactly why hostname
/// grammar forbids those characters.)
struct PromptReader {
    stream: TcpStream,
    buf: Vec<u8>,
}

impl PromptReader {
    fn new(stream: TcpStream) -> PromptReader {
        PromptReader {
            stream,
            buf: Vec::new(),
        }
    }

    /// Reads until the buffered stream ends with a prompt suffix.
    fn until_prompt(&mut self) -> String {
        let mut chunk = [0u8; 1];
        loop {
            if self.buf.ends_with(b"> ") || self.buf.ends_with(b"# ") {
                let text = String::from_utf8_lossy(&self.buf).into_owned();
                self.buf.clear();
                return text;
            }
            let read = self.stream.read(&mut chunk).expect("read");
            assert!(read > 0, "server closed early");
            self.buf.extend_from_slice(&chunk[..read]);
        }
    }

    fn send(&mut self, line: &str) {
        self.stream
            .write_all(format!("{line}\r\n").as_bytes())
            .expect("write");
    }
}

/// An interactive session over a raw `TcpStream`: banner, prompts,
/// mode transitions, help — the line discipline as a human sees it.
#[test]
fn interactive_session_walks_modes_over_the_socket() {
    let dir = scratch("interactive");
    let (port, shutdown) = spawn_server(&dir);
    wait_listening(port);
    let stream = TcpStream::connect(("127.0.0.1", port)).expect("connect");
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    let mut vty = PromptReader::new(stream);

    let banner_and_prompt = vty.until_prompt();
    assert!(banner_and_prompt.contains("plain TCP line protocol"));
    assert!(
        banner_and_prompt.ends_with("rouster> "),
        "{banner_and_prompt:?}"
    );

    // Empty-output commands: newline + prompt only.
    vty.send("enable");
    assert_eq!(vty.until_prompt(), "\r\nrouster# ", "enable");
    vty.send("conf t");
    assert_eq!(vty.until_prompt(), "\r\nrouster(config)# ", "conf t");
    vty.send("hostname edge");
    assert!(vty.until_prompt().ends_with("edge(config)# "));
    vty.send("ip route 203.0.113.0/24 blackhole");
    vty.until_prompt();
    vty.send("end");
    assert!(vty.until_prompt().ends_with("edge# "));

    // Output + prompt framing.
    vty.send("show running-config");
    let out = vty.until_prompt();
    assert!(out.contains("hostname edge"));
    assert!(out.contains("ip route 203.0.113.0/24 blackhole"));
    assert!(
        out.ends_with("\r\nedge# "),
        "prompt starts a fresh line: {out:?}"
    );

    vty.send("?");
    let help = vty.until_prompt();
    assert!(help.contains("exit"));

    // exit pops enable -> user (a prompt, no close)...
    vty.send("exit");
    assert!(vty.until_prompt().ends_with("edge> "));
    // ...and exit at the bottom of the stack closes quietly.
    vty.send("exit");
    let mut tail = Vec::new();
    vty.stream.read_to_end(&mut tail).ok();
    assert!(
        tail.is_empty(),
        "exit at user mode must close quietly, got {tail:?}"
    );
    shutdown.send(true).ok();
    let _ = std::fs::remove_dir_all(&dir);
}

// ---------------------------------------------------------------------------
// The real binaries end-to-end (the smoke-script shape).
// ---------------------------------------------------------------------------

fn vtyd(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_vtyd"))
        .args(args)
        .output()
        .expect("spawn vtyd")
}

fn out(output: &Output) -> String {
    String::from_utf8_lossy(&output.stdout).into_owned()
}

fn err(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
}

/// Spawns the real server binary with a temp config (inside the
/// scratch run dir) on a free port; returns the child and the port.
/// Bind-retries on AddrInUse — the free-port probe races other tests
/// for the port between probe and bind (the bfdd flake class;
/// likelier under `cargo test --workspace` parallelism on CI).
fn spawn_server_binary(tag: &str, run_dir: &Path) -> (Child, u16) {
    let mut last_status = None;
    for _ in 0..8 {
        let port = free_port();
        let config = run_dir.join(format!("vtyd-{tag}.conf"));
        std::fs::write(
            &config,
            format!(
                "! smoke config\nport {port}\nbind 127.0.0.1\nrun-dir {}\nhostname bin-r1\n",
                run_dir.display()
            ),
        )
        .unwrap();
        let mut child = Command::new(env!("CARGO_BIN_EXE_vtyd"))
            .arg("--config")
            .arg(&config)
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn vtyd server");
        let deadline = Instant::now() + Duration::from_secs(5);
        while Instant::now() < deadline {
            if TcpStream::connect(("127.0.0.1", port)).is_ok() {
                return (child, port);
            }
            match child.try_wait().expect("child state") {
                Some(status) => {
                    last_status = Some(status);
                    break;
                }
                None => std::thread::sleep(Duration::from_millis(25)),
            }
        }
        // Early exit (port taken) or listen deadline — fresh port.
        let _ = child.kill();
        let _ = child.wait();
    }
    panic!(
        "vtyd server never listened after 8 attempts{}",
        last_status
            .map(|s| format!("; last early exit: {s}"))
            .unwrap_or_default()
    );
}

#[test]
fn binary_oneshot_show_version_end_to_end() {
    let dir = scratch("bin-ver");
    std::fs::write(dir.join("bfdd.status"), fixture("bfdd-status-today.status")).unwrap();
    let (mut child, port) = spawn_server_binary("ver", &dir);
    let output = vtyd(&["--command", "show version", "--port", &port.to_string()]);
    assert_eq!(output.status.code(), Some(0), "stderr: {}", err(&output));
    let text = out(&output);
    assert!(text.contains("vtysh-compatible VTY server"));
    assert!(text.contains("Hostname: bin-r1"));
    assert!(text.contains(&format!("Run dir: {}", dir.display())));
    assert!(!text.contains("bin-r1#"), "no prompt leakage");
    // And a run-dir answer through the real binary pair.
    let output = vtyd(&["--command", "show bfd summary", "--port", &port.to_string()]);
    assert_eq!(output.status.code(), Some(0), "stderr: {}", err(&output));
    assert!(out(&output).contains("Up 2"));
    let _ = child.kill();
    let _ = child.wait();
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn binary_oneshot_unknown_command_exits_2() {
    let dir = scratch("bin-unknown");
    let (mut child, port) = spawn_server_binary("unknown", &dir);
    let output = vtyd(&["--command", "router static", "--port", &port.to_string()]);
    assert_eq!(output.status.code(), Some(2));
    assert_eq!(out(&output).trim_end(), "% Unknown command: router static");
    let _ = child.kill();
    let _ = child.wait();
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn binary_oneshot_connect_failure_exits_1() {
    let port = free_port();
    let output = vtyd(&["--command", "show version", "--port", &port.to_string()]);
    assert_eq!(output.status.code(), Some(1));
    assert!(err(&output).contains("vtyd:"));
}

#[cfg(unix)]
#[test]
fn binary_sigterm_exits_zero() {
    let dir = scratch("bin-term");
    let (mut child, _port) = spawn_server_binary("term", &dir);
    let pid = child.id();
    // SIGTERM via /bin/kill — the same trusted binary the liveness
    // module uses (no libc dependency to add).
    let status = std::process::Command::new("/bin/kill")
        .arg("-15")
        .arg(pid.to_string())
        .status()
        .expect("run /bin/kill");
    assert!(status.success(), "kill -TERM {pid} failed");
    let status = child.wait().expect("wait for SIGTERM exit");
    assert_eq!(status.code(), Some(0), "graceful SIGTERM must exit 0");
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn binary_help_and_version_work() {
    let output = vtyd(&["--help"]);
    assert_eq!(output.status.code(), Some(0));
    let text = out(&output);
    assert!(text.contains("--command"));
    assert!(text.contains("2626"));
    assert!(text.contains("/run/rouster"));
    let output = vtyd(&["--version"]);
    assert_eq!(output.status.code(), Some(0));
    assert_eq!(out(&output).trim(), env!("CARGO_PKG_VERSION"));
}

#[test]
fn binary_usage_errors_exit_2_with_a_complaint() {
    let output = vtyd(&["--frobnicate"]);
    assert_eq!(output.status.code(), Some(2));
    assert!(err(&output).contains("unknown argument"));
    let output = vtyd(&["--port"]);
    assert_eq!(output.status.code(), Some(2));
    assert!(err(&output).contains("--port requires"));
}

#[test]
fn config_file_errors_are_line_numbered() {
    let dir = scratch("badconf");
    let config = dir.join("vtyd-bad.conf");
    std::fs::write(&config, "port 2626\nfrobnicate now\n").unwrap();
    let output = vtyd(&["--config", config.to_str().unwrap()]);
    assert_eq!(output.status.code(), Some(2));
    assert!(
        err(&output).contains("line 2: unknown directive `frobnicate`"),
        "stderr: {}",
        err(&output)
    );
    let _ = std::fs::remove_dir_all(&dir);
}

// ---------------------------------------------------------------------------
// The write path (S8-c M4): config edits over the real socket, the
// merged canonical handed to the backend, configd's report relayed.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn write_file_over_the_socket_merges_and_applies() {
    let dir = scratch("write");
    // A pre-existing canonical: an unmodeled savd section, one
    // modeled static, and the configd-owned router-id.
    let canonical = dir.join("rouster.conf");
    std::fs::write(
        &canonical,
        concat!(
            "router-id 198.51.100.1\n",
            "daemon savd {\n",
            "    mode strict\n",
            "    poll 2\n",
            "}\n",
            "daemon rousterd {\n",
            "    ip route 203.0.113.0/24 blackhole\n",
            "}\n",
        ),
    )
    .unwrap();
    let recorder = Arc::new(RecordingBackend {
        written: std::sync::Mutex::new(Vec::new()),
        reply: vec![
            // (No "-> " here: the PromptReader harness stops on any
            // token ending `> ` — the real one-shot client strips
            // only the exact trailing prompt and has no such issue.)
            "configd: savd wrote /etc/savd.conf (18 bytes), not running".into(),
            "configd: generation 4 recorded (hash 0000abc)".into(),
        ],
    });
    let (port, shutdown) = spawn_server_with(&dir, &canonical, recorder.clone());
    wait_listening(port);
    let stream = TcpStream::connect(("127.0.0.1", port)).expect("connect");
    stream
        .set_read_timeout(Some(Duration::from_secs(10)))
        .unwrap();
    let mut vty = PromptReader::new(stream);
    let _ = vty.until_prompt(); // banner + first prompt

    vty.send("enable");
    let _ = vty.until_prompt();
    vty.send("conf t");
    let _ = vty.until_prompt();
    vty.send("ip route 198.51.100.0/24 192.0.2.1");
    let _ = vty.until_prompt();
    vty.send("end");
    let _ = vty.until_prompt();

    // write file: the naming disclosure plus the backend's report,
    // relayed verbatim.
    vty.send("write file");
    let wrote = vty.until_prompt();
    assert!(wrote.contains("write memory = write file here"), "{wrote}");
    assert!(wrote.contains("configd: generation 4 recorded"), "{wrote}");

    // show running-config: the merged canonical view — the new
    // static AND the untouched savd section AND the router-id.
    vty.send("show running-config");
    let running = vty.until_prompt();
    assert!(running.contains("router-id 198.51.100.1"), "{running}");
    assert!(
        running.contains("daemon savd {\r\n    mode strict\r\n    poll 2\r\n}"),
        "{running}"
    );
    assert!(
        running.contains("ip route 198.51.100.0/24 192.0.2.1"),
        "{running}"
    );
    assert!(
        running.contains("ip route 203.0.113.0/24 blackhole"),
        "{running}"
    );

    // And what the backend was handed is the same merged document.
    let written = recorder.written.lock().unwrap();
    assert_eq!(written.len(), 1, "exactly one apply per write");
    assert!(written[0].contains("daemon savd {"), "{}", written[0]);
    assert!(
        written[0].contains("ip route 198.51.100.0/24 192.0.2.1"),
        "{}",
        written[0]
    );

    shutdown.send(true).ok();
    let _ = std::fs::remove_dir_all(&dir);
}

/// A stub configd: records its argv and the staged file's content to
/// a log, answers with one report line, exits 0.
fn stub_configd(dir: &Path) -> PathBuf {
    let log = dir.join("configd.log");
    let stub = dir.join("configd");
    std::fs::write(
        &stub,
        format!(
            "#!/bin/sh\n\
             case \"$1\" in\n\
             apply) {{ echo \"APPLY $2\"; cat \"$2\"; }} >> '{log}'; \
             echo 'configd: stub applied the canonical'; exit 0;;\n\
             esac\n\
             exit 2\n",
            log = log.display(),
        ),
    )
    .unwrap();
    use std::os::unix::fs::PermissionsExt;
    let mut perms = std::fs::metadata(&stub).unwrap().permissions();
    perms.set_mode(0o755);
    std::fs::set_permissions(&stub, perms).unwrap();
    stub
}

#[test]
fn binary_write_file_end_to_end_through_a_stub_configd() {
    let dir = scratch("bin-write");
    let canonical = dir.join("rouster.conf");
    let seeded = "router-id 198.51.100.1\ndaemon savd {\nmode strict\n}\n";
    std::fs::write(&canonical, seeded).unwrap();
    let stub = stub_configd(&dir);

    let port = free_port();
    let config = dir.join("vtyd-write.conf");
    std::fs::write(
        &config,
        format!(
            "port {port}\nbind 127.0.0.1\nrun-dir {}\ncanonical {}\nhostname bin-w1\n",
            dir.display(),
            canonical.display()
        ),
    )
    .unwrap();
    let mut child = Command::new(env!("CARGO_BIN_EXE_vtyd"))
        .arg("--config")
        .arg(&config)
        .env("ROUSTER_CONFIGD_BIN", &stub)
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn vtyd server");
    let deadline = Instant::now() + Duration::from_secs(5);
    while Instant::now() < deadline {
        if TcpStream::connect(("127.0.0.1", port)).is_ok() {
            break;
        }
        assert!(child.try_wait().expect("child state").is_none());
        std::thread::sleep(Duration::from_millis(25));
    }

    // A one-shot write over the real binary pair: a fresh session
    // seeds from the canonical, so this write is the idempotence leg
    // (same document in, same document applied).
    let output = Command::new(env!("CARGO_BIN_EXE_vtyd"))
        .args(["--command", "write file", "--port", &port.to_string()])
        .output()
        .expect("one-shot write");
    assert_eq!(output.status.code(), Some(0), "stderr: {}", err(&output));
    let text = out(&output);
    assert!(
        text.contains("configd: stub applied the canonical"),
        "stdout: {text}"
    );
    assert!(
        text.contains("write memory = write file here"),
        "stdout: {text}"
    );

    // The stub saw the canonical path and its content, verbatim.
    let log = std::fs::read_to_string(dir.join("configd.log")).unwrap();
    assert!(
        log.contains(&format!("APPLY {}", canonical.display())),
        "{log}"
    );
    assert!(log.contains("daemon savd {\nmode strict\n}"), "{log}");
    // And the staged canonical on disk is byte-stable.
    assert_eq!(std::fs::read_to_string(&canonical).unwrap(), seeded);

    let _ = child.kill();
    let _ = child.wait();
    let _ = std::fs::remove_dir_all(&dir);
}
