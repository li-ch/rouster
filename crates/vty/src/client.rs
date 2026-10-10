//! The one-shot client — the `vtysh -c` analog, and what smoke
//! scripts drive.
//!
//! `vtyd --command 'show version'`: connect to the running server,
//! run `enable` (no password in v1 — disclosed), the command, and
//! `exit`; half-close; read to EOF; strip the framing
//! ([`crate::protocol::strip_to_body`]). The body prints to stdout.
//!
//! Exit codes — deliberately narrow, per the quarantine-B7 lesson
//! (`vtysh -b` exits 0 even when apply fails; scripts must verify
//! state, never trust rc): **0** the command ran (source-state
//! honesty like `% No savd status published` or a stale-pid footer
//! is output, not a failure); **1** transport failure (connect,
//! IO, timeout); **2** the command itself was not a command
//! (unknown/ambiguous/incomplete/invalid input).

use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;

use crate::protocol;

/// How long the connect attempt may take.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(3);

/// How long the whole exchange may take after connecting.
const EXCHANGE_TIMEOUT: Duration = Duration::from_secs(5);

/// Why a one-shot run failed.
#[derive(Debug, thiserror::Error)]
pub enum ClientError {
    /// Could not reach the server (connect, IO, or timeout).
    #[error("vtyd at {addr}: {source}")]
    Connect {
        /// The address that was tried.
        addr: String,
        /// The underlying IO error.
        source: std::io::Error,
    },
    /// The exchange did not finish in time.
    #[error("vtyd at {addr}: exchange timed out")]
    Timeout {
        /// The address that was tried.
        addr: String,
    },
    /// The protocol stream was not the shape the server produces.
    #[error("protocol violation from vtyd at {addr}: framing not found")]
    Framing {
        /// The address that was tried.
        addr: String,
    },
}

/// Runs one command against the vtyd at `addr`, returning its body
/// (stdout for the binary to print) and whether the command itself
/// errored (exit 2).
pub async fn oneshot(addr: &str, command: &str) -> Result<(String, bool), ClientError> {
    let stream = timeout(CONNECT_TIMEOUT, TcpStream::connect(addr))
        .await
        .map_err(|_| ClientError::Timeout {
            addr: addr.to_string(),
        })?
        .map_err(|source| ClientError::Connect {
            addr: addr.to_string(),
            source,
        })?;
    run_on_stream(stream, command).await
}

/// The client half of [`oneshot`] over an established stream (the
/// test bench drives this against an in-process listener).
pub async fn run_on_stream(
    mut stream: TcpStream,
    command: &str,
) -> Result<(String, bool), ClientError> {
    let addr = stream
        .peer_addr()
        .map(|a| a.to_string())
        .unwrap_or_else(|_| "unknown".into());
    let exchange = async {
        let script = format!("enable\r\n{command}\r\nexit\r\n");
        stream.write_all(script.as_bytes()).await?;
        stream.shutdown().await?;
        let mut raw = Vec::new();
        stream.read_to_end(&mut raw).await?;
        Ok::<_, std::io::Error>(raw)
    };
    let raw = timeout(EXCHANGE_TIMEOUT, exchange)
        .await
        .map_err(|_| ClientError::Timeout { addr: addr.clone() })?
        .map_err(|source| ClientError::Connect {
            addr: addr.clone(),
            source,
        })?;
    let text = String::from_utf8_lossy(&raw).into_owned();
    let body = protocol::strip_to_body(&text).ok_or(ClientError::Framing { addr })?;
    let errored = protocol::body_has_command_error(&body);
    Ok((body, errored))
}
