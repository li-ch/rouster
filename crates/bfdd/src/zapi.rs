//! The bfdd zapi edge (W1-b): the daemon-side client of rousterd's
//! ZAPI server, the savd shape. Speaks the wire-pinned BFD daemon
//! protocol:
//!
//! - connect burst: HELLO (redist byte 0x1a = ZEBRA_ROUTE_BFD, the
//!   captured FRR bfdd form), the empty INTERFACE_ADD request, and the
//!   4-byte REPLAY (30) that claims the BFD-daemon role — the server
//!   then relays client registrations here.
//! - forwarded REGISTER (27) / UPDATE (29) / DEREGISTER (28) arrive as
//!   [`ZapiEdgeEvent`]s on the feed the daemon's owner drains.
//! - every local session TRANSITION is reported back as the 25-byte
//!   REPLAY form (pid + the 26 tuple, the Phase C pin): dst /32-|/128,
//!   status bitmask (Up=UP, AdminDown=ADMIN_DOWN, else DOWN), src
//!   wildcard, ifindex 0 (the bfdd-side reports never resolved one —
//!   Phase C), cbit 0.
//!
//! Reconnects with a pause (the savd convention); the whole burst is
//! re-sent, so a restarted rousterd re-learns the daemon and replays
//! the registrations it remembers (the M3 server-side replay).

use std::io;
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt, WriteHalf};
use tokio::net::UnixStream;
use tokio::sync::mpsc;
use tracing::{debug, info, warn};
use zapi::IpPrefix;

use zapi::{bfd_status, ZapiBfdDestStatus, ZapiHeader, ZapiMessage, ZAPI_HEADER_LEN};

pub use zapi::ZapiBfdSessionCmd;

/// ZEBRA_ROUTE_BFD (the pinned doc's route-type table): the redist
/// byte FRR's bfdd announces in its HELLO (captured body
/// `1a 0000 00000000 00`).
pub const ZAPI_ROUTE_BFD: u8 = 26;

/// Reconnect pause (the savd convention).
const RECONNECT_PAUSE: Duration = Duration::from_secs(1);

/// The transition feed's element (an alias for readability).
pub type SessionSnapshot = crate::transport::SessionSnapshot;

/// What the forwarded commands mean to the daemon's owner.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ZapiEdgeEvent {
    /// A BFD_DEST_REGISTER (27) or UPDATE (29): create (or restart
    /// with new parameters) the dynamic session for the destination.
    Register(ZapiBfdSessionCmd),
    /// A BFD_DEST_DEREGISTER (28): graceful removal.
    Deregister(ZapiBfdSessionCmd),
}

/// The daemon-side handle of the spawned edge task: the feed of
/// forwarded commands (drained next to the daemon's signal loop).
pub struct ZapiEdgeHandle {
    pub events: mpsc::Receiver<ZapiEdgeEvent>,
}

/// Spawns the edge task: it owns the connection lifecycle and drains
/// the session-transition feed (`status_rx` — what
/// [`crate::daemon::BfddDaemon::spawn_with_status_feed`] publishes).
pub fn spawn_zapi_edge(
    socket: PathBuf,
    status_rx: mpsc::Receiver<SessionSnapshot>,
) -> ZapiEdgeHandle {
    let (events_tx, events) = mpsc::channel(64);
    tokio::spawn(async move {
        let mut status_rx = status_rx;
        loop {
            match connect_and_serve(&socket, &events_tx, &mut status_rx).await {
                Ok(()) => debug!("bfdd zapi: edge session ended; reconnecting"),
                Err(err) => warn!(%err, "bfdd zapi: edge error; reconnecting"),
            }
            tokio::time::sleep(RECONNECT_PAUSE).await;
        }
    });
    ZapiEdgeHandle { events }
}

/// One connection's lifetime: the connect burst, then both directions
/// (inbound frames via a reader task — `read_exact` is not
/// cancel-safe; outbound status reports from the edge loop, the
/// single writer) until the socket dies.
async fn connect_and_serve(
    socket: &Path,
    events: &mpsc::Sender<ZapiEdgeEvent>,
    status_rx: &mut mpsc::Receiver<SessionSnapshot>,
) -> io::Result<()> {
    let stream = UnixStream::connect(socket).await?;
    info!(path = %socket.display(), "bfdd zapi: connected to rousterd");
    let (reader, mut writer) = tokio::io::split(stream);

    // The bfdd connect burst (Phase A pin): HELLO + the empty
    // INTERFACE_ADD + the 4-byte REPLAY. Fire-and-forget — real zebra
    // answers none of these synchronously; rousterd echoes HELLO
    // (accepted, pinned doc finding 2) and the echo arrives as just
    // another inbound frame to skip.
    write_message(
        &mut writer,
        &ZapiMessage::Hello(zapi::ZapiHello {
            redist_default: ZAPI_ROUTE_BFD,
            instance: 0,
            session_id: 0,
            synchronous: 0,
        }),
    )
    .await?;
    write_message(&mut writer, &ZapiMessage::InterfaceAddRequest).await?;
    write_message(
        &mut writer,
        &ZapiMessage::BfdDestReplay {
            pid: std::process::id(),
        },
    )
    .await?;

    let (frames_tx, mut frames_rx) = mpsc::channel::<io::Result<ZapiMessage>>(16);
    let read_task = tokio::spawn(async move {
        let mut reader = reader;
        loop {
            match read_message(&mut reader).await {
                Ok(msg) => {
                    if frames_tx.send(Ok(msg)).await.is_err() {
                        return;
                    }
                }
                Err(err) => {
                    let _ = frames_tx.send(Err(err)).await;
                    return;
                }
            }
        }
    });

    let pid = std::process::id();
    let result = loop {
        tokio::select! {
            frame = frames_rx.recv() => match frame {
                None => break Ok(()),
                Some(Err(err)) => break Err(err),
                Some(Ok(msg)) => match msg {
                    ZapiMessage::BfdDestRegister(cmd) | ZapiMessage::BfdDestUpdate(cmd) => {
                        // Daemon owner gone == nothing left to serve.
                        if events.send(ZapiEdgeEvent::Register(cmd)).await.is_err() {
                            break Ok(());
                        }
                    }
                    ZapiMessage::BfdDestDeregister(cmd) => {
                        if events.send(ZapiEdgeEvent::Deregister(cmd)).await.is_err() {
                            break Ok(());
                        }
                    }
                    other => {
                        debug!(command = other.command(), "bfdd zapi: skipped frame");
                    }
                },
            },
            status = status_rx.recv() => match status {
                None => break Ok(()), // daemon gone; nothing to report
                Some(snapshot) => {
                    if let Err(err) = report_status(&mut writer, pid, &snapshot).await {
                        break Err(err);
                    }
                }
            },
        }
    };
    read_task.abort();
    result
}

/// Encodes and writes one frame (the zapi-notify-probe convention).
async fn write_message<W>(io: &mut W, msg: &ZapiMessage) -> io::Result<()>
where
    W: AsyncWriteExt + Unpin,
{
    let frame = msg
        .encode_frame(0)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?;
    io.write_all(&frame).await
}

/// Reads one framed message off the stream.
async fn read_message<R>(io: &mut R) -> io::Result<ZapiMessage>
where
    R: AsyncReadExt + Unpin,
{
    let mut header_buf = [0u8; ZAPI_HEADER_LEN];
    io.read_exact(&mut header_buf).await?;
    let header = ZapiHeader::decode(&header_buf)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?;
    let mut body = vec![0u8; header.length as usize - ZAPI_HEADER_LEN];
    io.read_exact(&mut body).await?;
    ZapiMessage::decode(header.command, &body)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))
}

/// Reports one transition as the 25-byte REPLAY form (the Phase C
/// pin): pid + the exact 26 tuple.
async fn report_status(
    writer: &mut WriteHalf<UnixStream>,
    pid: u32,
    snapshot: &SessionSnapshot,
) -> io::Result<()> {
    let status = ZapiBfdDestStatus {
        ifindex: 0, // the Phase C pin: bfdd-side reports carry 0
        dst: dest_prefix(snapshot.peer),
        status: status_of(snapshot.state),
        src: src_prefix(snapshot.peer),
        remote_cbit: false,
    };
    write_message(writer, &ZapiMessage::BfdDaemonStatus { pid, status }).await
}

fn dest_prefix(peer: IpAddr) -> IpPrefix {
    match peer {
        IpAddr::V4(v4) => format!("{v4}/32").parse().expect("valid prefix"),
        IpAddr::V6(v6) => format!("{v6}/128").parse().expect("valid prefix"),
    }
}

fn src_prefix(peer: IpAddr) -> IpPrefix {
    match peer {
        IpAddr::V4(_) => "0.0.0.0/32".parse().expect("valid prefix"),
        IpAddr::V6(_) => "::/128".parse().expect("valid prefix"),
    }
}

/// BFD state → the lib/bfd.h BITMASK (UP=4 and DOWN=2 observed live,
/// Phase C; ADMIN_DOWN per source). Init reports DOWN — FRR's clients
/// act on Up/Down only (disclosed approximation).
fn status_of(state: crate::packet::BfdState) -> u32 {
    use crate::packet::BfdState::*;
    match state {
        Up => bfd_status::UP,
        AdminDown => bfd_status::ADMIN_DOWN,
        Down | Init => bfd_status::DOWN,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The state → bitmask mapping (UP=4 / DOWN=2 observed on the wire
    /// in Phase C; ADMIN_DOWN from the source bitmask table).
    #[test]
    fn status_of_maps_the_pinned_bitmask() {
        assert_eq!(status_of(crate::packet::BfdState::Up), bfd_status::UP);
        assert_eq!(status_of(crate::packet::BfdState::Down), bfd_status::DOWN);
        assert_eq!(status_of(crate::packet::BfdState::Init), bfd_status::DOWN);
        assert_eq!(
            status_of(crate::packet::BfdState::AdminDown),
            bfd_status::ADMIN_DOWN
        );
    }

    /// The destination prefix is the peer at full host length; the
    /// source is the family's wildcard (the Phase C bodies).
    #[test]
    fn prefixes_are_host_length_and_wildcard() {
        assert_eq!(
            dest_prefix("192.0.2.9".parse().unwrap()).to_string(),
            "192.0.2.9/32"
        );
        assert_eq!(
            dest_prefix("2001:db8::9".parse().unwrap()).to_string(),
            "2001:db8::9/128"
        );
        assert_eq!(
            src_prefix("192.0.2.9".parse().unwrap()).to_string(),
            "0.0.0.0/32"
        );
        assert_eq!(
            src_prefix("2001:db8::9".parse().unwrap()).to_string(),
            "::/128"
        );
    }
}
