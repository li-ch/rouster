//! The TCP half — one listener, one task per connection, the
//! session state machine doing all the thinking.
//!
//! Each connection: write the banner, then loop { write prompt;
//! read a CRLF line; feed [`Session::handle_line`]; write the
//! output lines; stop on [`Outcome::Close`] or EOF }. Line length
//! is capped; an overlong line is refused and the connection kept
//! (a stray binary blob should not wedge the listener).

use std::sync::Arc;

use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::watch;
use tracing::{info, warn};

use crate::protocol;
use crate::session::{Outcome, ServerInfo, Session};
use crate::writer::WriteBackend;

/// Lines longer than this are refused (binary garbage guard).
const MAX_LINE: usize = 8192;

/// Serves until `shutdown` fires (SIGTERM/SIGINT wiring lives in the
/// binary). The listener is bound by the caller-supplied info; the
/// `writer` is the write path's actuator (the configd backend), wired
/// into every session alongside the canonical-file state seeded from
/// `info.canonical` — the merge base for `show running-config` and
/// `write`.
pub async fn serve(
    listener: TcpListener,
    hostname: Arc<String>,
    info: ServerInfo,
    writer: Arc<dyn WriteBackend>,
    mut shutdown: watch::Receiver<bool>,
) -> std::io::Result<()> {
    info!(
        bind = %listener.local_addr().map(|a| a.to_string()).unwrap_or_default(),
        "vtyd: VTY server listening (plain TCP line protocol)"
    );
    loop {
        tokio::select! {
            accepted = listener.accept() => {
                let (stream, peer) = match accepted {
                    Ok(pair) => pair,
                    Err(err) => {
                        warn!(%err, "vtyd: accept failed");
                        continue;
                    }
                };
                let hostname = Arc::clone(&hostname);
                let info = info.clone();
                let writer = Arc::clone(&writer);
                tokio::spawn(async move {
                    if let Err(err) = handle_connection(stream, hostname, info, writer).await {
                        warn!(%peer, %err, "vtyd: connection ended with an IO error");
                    }
                });
            }
            _ = shutdown.changed() => {
                info!("vtyd: shutdown signal; closing listener (open connections close with their sessions)");
                return Ok(());
            }
        }
    }
}

/// One connection's line discipline.
async fn handle_connection(
    stream: TcpStream,
    hostname: Arc<String>,
    info: ServerInfo,
    writer: Arc<dyn WriteBackend>,
) -> std::io::Result<()> {
    let mut session = Session::new(hostname.as_ref().clone(), info);
    // Seed the canonical merge state (S8-c M4): everything in the
    // canonical file this grammar cannot speak rides verbatim; the
    // modeled lines project into the session config. Read once per
    // connection — a single-operator surface; concurrent edits from
    // another session land on its next connect (disclosed).
    session.doc = crate::writer::CanonState::load(&session.info.canonical, &mut session.config);
    session.writer = Some(writer);
    let (read_half, mut write_half) = stream.into_split();
    let mut reader = BufReader::new(read_half);
    let mut line = String::new();

    write_half
        .write_all(protocol::banner(crate::VERSION).as_bytes())
        .await?;
    loop {
        write_half.write_all(session.prompt().as_bytes()).await?;
        line.clear();
        let read = reader.read_line(&mut line).await?;
        if read == 0 {
            // EOF (the one-shot client half-closes): drop quietly.
            return Ok(());
        }
        let input = line.trim_end_matches(['\r', '\n']);
        if input.len() > MAX_LINE {
            write_half
                .write_all(b"% Input line too long - refused (binary on a line protocol?).\r\n")
                .await?;
            continue;
        }
        match session.handle_line(input) {
            Outcome::Lines(lines) => {
                if lines.is_empty() {
                    write_half.write_all(b"\r\n").await?;
                } else {
                    for out in &lines {
                        write_all_line(&mut write_half, out).await?;
                    }
                }
            }
            Outcome::Close => return Ok(()),
        }
    }
}

/// Writes one output line, CRLF-terminated (the prompt that
/// follows it in the loop starts a fresh line).
async fn write_all_line(
    write_half: &mut tokio::net::tcp::OwnedWriteHalf,
    text: &str,
) -> std::io::Result<()> {
    write_half.write_all(text.as_bytes()).await?;
    write_half.write_all(b"\r\n").await?;
    Ok(())
}
