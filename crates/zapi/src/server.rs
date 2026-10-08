//! ZAPI server: accepts FRR daemon connections over a Unix-domain socket.
//!
//! Default socket path matches FRR's (`/var/run/frr/zserv.api`) so unmodified
//! FRR daemons can attach; Rouster's own default lives under `/run/rouster/`
//! and is selected by config. Phase 1 wires decoded messages into the RIB.

use std::path::Path;

use tokio::net::UnixListener;
use tracing::{info, warn};

/// Accept loop for ZAPI clients. Skeleton: accepts and logs; Phase 1 adds
/// header framing, version negotiation, and message dispatch into the RIB.
pub async fn serve(socket_path: &Path) -> std::io::Result<()> {
    if socket_path.exists() {
        std::fs::remove_file(socket_path)?;
    }
    let listener = UnixListener::bind(socket_path)?;
    info!(path = %socket_path.display(), "zapi: listening");

    loop {
        match listener.accept().await {
            Ok((_stream, _addr)) => {
                // TODO(phase-1): per-connection task — header decode,
                // {protocol, instance, session_id} handshake, message loop.
                info!("zapi: client connected (handling not implemented yet)");
            }
            Err(err) => {
                warn!(%err, "zapi: accept failed");
            }
        }
    }
}
