//! ospfd's ZAPI edge (the bgpd `zedge` idioms): ospfd as a zebra
//! client.
//!
//! - **HELLO as OSPF** (route type 7) — the z5c-proven attach.
//! - **The interface dump** (ADD-C2): [`crate::ifdump::sync`] runs on
//!   the same session this edge keeps — the dump's merged live
//!   addresses/link-state are the core's construction input, then the
//!   session becomes the resident edge (one socket, one HELLO).
//! - **`redistribute static`** registration (REDISTRIBUTE_ADD,
//!   afi v4 STATIC): zebra's REDISTRIBUTE_ROUTE_ADD/DELETE pushes
//!   become the §12.4.4 external-LSA origination/withdrawal feed.
//! - **Export**: SPF route changes become ZEBRA_ROUTE_ADD/_DELETE
//!   (protocol OSPF) so OSPF-learned routes reach the kernel through
//!   rousterd.
//!
//! v1 disclosures: the ROUTER_ID_ADD request is not sent (`ZapiClient`
//! exposes no raw send — the bgpd P2-b deviation-2 precedent): the
//! router ID comes from config. Interface addresses now come from the
//! zapi interface dump when a socket is configured (`ifdump`), static
//! config as the fallback.

use std::io;
use std::sync::{Arc, Mutex};

use common::{IpPrefix, RouteEntry};
use tokio::sync::mpsc;
use tracing::{info, warn};
use zapi::message::{route_type, ZapiMessage};
use zapi::ZapiClient;

/// Commands toward zebra.
#[derive(Debug, Clone)]
pub enum ZedgeCommand {
    RouteAdd(RouteEntry),
    RouteDel(RouteEntry),
}

/// A redistributed route zebra pushed (v4 only, v1).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RedistributedRoute {
    pub prefix: IpPrefix,
    pub metric: u32,
}

/// A type alias so the daemon-facing surface does not name zapi's
/// route type directly.
pub type ZapiRoute = zapi::message::ZapiRoute;

/// The zapi-attached edge task.
pub struct Zedge<IO> {
    client: ZapiClient<IO>,
    redistribute_static: bool,
    /// Daemon-bound redistribute pushes.
    pushed: mpsc::UnboundedSender<RedistributedRoute>,
    /// Daemon-bound withdraw pushes.
    withdrawn: mpsc::UnboundedSender<RedistributedRoute>,
}

impl<IO> Zedge<IO>
where
    IO: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    pub fn new(
        client: ZapiClient<IO>,
        redistribute_static: bool,
        pushed: mpsc::UnboundedSender<RedistributedRoute>,
        withdrawn: mpsc::UnboundedSender<RedistributedRoute>,
    ) -> Self {
        Self {
            client,
            redistribute_static,
            pushed,
            withdrawn,
        }
    }

    /// HELLO as OSPF (§ the z5c attach) + the redistribute
    /// registration when configured.
    pub async fn start(&mut self) -> io::Result<()> {
        self.client.handshake(route_type::OSPF).await?;
        info!("ospfd: zapi session established (protocol=7)");
        self.register().await
    }

    /// The post-handshake registrations (an already-established
    /// session — e.g. one that just ran the [`crate::ifdump`] sync —
    /// calls this directly; `start` is handshake + this).
    pub async fn register(&mut self) -> io::Result<()> {
        if self.redistribute_static {
            // afi 1 (v4), STATIC, instance 0 — the z5d byte shape.
            self.client
                .send_redistribute_add(1, route_type::STATIC, 0)
                .await?;
            info!("ospfd: redistribute static registered");
        }
        Ok(())
    }

    /// Consume one zebra message; redistribute pushes are forwarded
    /// to the daemon, everything else is observability-only v1.
    pub fn apply_message(&mut self, message: ZapiMessage) {
        let (route, add) = match &message {
            ZapiMessage::RedistributeRouteAdd(route) => (route, true),
            ZapiMessage::RedistributeRouteDel(route) => (route, false),
            other => {
                info!(?other, "ospfd: zapi message (not consumed)");
                return;
            }
        };
        let Ok(entry) = RedistributedRoute::try_from(route) else {
            return;
        };
        if add {
            let _ = self.pushed.send(entry);
        } else {
            let _ = self.withdrawn.send(entry);
        }
    }

    /// One command drain → ROUTE_ADD/DELETE.
    pub async fn flush(&mut self, command: &ZedgeCommand) -> io::Result<()> {
        match command {
            ZedgeCommand::RouteAdd(entry) => {
                self.client.send_route_add(entry).await?;
                info!(prefix = %entry.prefix, "ospfd: route add -> zebra");
            }
            ZedgeCommand::RouteDel(entry) => {
                self.client.send_route_delete(entry).await?;
                info!(prefix = %entry.prefix, "ospfd: route delete -> zebra");
            }
        }
        Ok(())
    }

    /// The resident loop.
    pub async fn run(
        mut self,
        mut commands: mpsc::UnboundedReceiver<ZedgeCommand>,
    ) -> io::Result<()> {
        loop {
            tokio::select! {
                message = self.client.read_message() => {
                    match message {
                        Ok(message) => self.apply_message(message),
                        Err(e) => {
                            warn!(error = %e, "ospfd: zapi session lost");
                            return Err(e);
                        }
                    }
                }
                command = commands.recv() => {
                    match command {
                        Some(command) => {
                            if let Err(e) = self.flush(&command).await {
                                warn!(error = %e, "ospfd: zapi flush failed");
                                return Err(e);
                            }
                        }
                        None => {
                            info!("ospfd: export channel closed, zedge exiting");
                            return Ok(());
                        }
                    }
                }
            }
        }
    }
}

impl TryFrom<&ZapiRoute> for RedistributedRoute {
    type Error = ();

    fn try_from(route: &ZapiRoute) -> Result<Self, ()> {
        // v4-only v1 (the whole daemon is v2).
        if !matches!(route.prefix, IpPrefix::V4(_)) {
            return Err(());
        }
        Ok(Self {
            prefix: route.prefix,
            metric: route.metric.unwrap_or(0),
        })
    }
}

/// Connect to the zebra socket with bounded retry (30 attempts, 1 s
/// apart — the bgpd/staticd pattern): the session a [`spawn`] or an
/// [`crate::ifdump::sync`] runs on.
pub async fn connect(
    socket: &std::path::Path,
) -> io::Result<zapi::ZapiClient<tokio::net::UnixStream>> {
    for _ in 0..30 {
        match ZapiClient::connect(socket).await {
            Ok(client) => return Ok(client),
            Err(_) => tokio::time::sleep(std::time::Duration::from_secs(1)).await,
        }
    }
    Err(io::Error::new(
        io::ErrorKind::TimedOut,
        "zebra socket never appeared",
    ))
}

/// Run the resident edge on an ALREADY-ESTABLISHED session (the
/// ADD-C2 flow: [`crate::ifdump::sync`] handshook and dumped on it):
/// the redistribute registration, then the select loop. Returns the
/// command sender.
pub async fn spawn_with_client(
    client: zapi::ZapiClient<tokio::net::UnixStream>,
    redistribute_static: bool,
    pushed: mpsc::UnboundedSender<RedistributedRoute>,
    withdrawn: mpsc::UnboundedSender<RedistributedRoute>,
) -> io::Result<mpsc::UnboundedSender<ZedgeCommand>> {
    let mut zedge = Zedge::new(client, redistribute_static, pushed, withdrawn);
    zedge.register().await?;
    let (tx, rx) = mpsc::unbounded_channel();
    tokio::spawn(async move {
        if let Err(e) = zedge.run(rx).await {
            warn!(error = %e, "ospfd: zedge task exited");
        }
    });
    Ok(tx)
}

/// Spawn the zedge task against the real socket (connect-with-retry,
/// HELLO, then the resident loop). Returns the command sender.
pub async fn spawn(
    socket: std::path::PathBuf,
    redistribute_static: bool,
    pushed: mpsc::UnboundedSender<RedistributedRoute>,
    withdrawn: mpsc::UnboundedSender<RedistributedRoute>,
) -> io::Result<mpsc::UnboundedSender<ZedgeCommand>> {
    let client = connect(&socket).await?;
    let mut zedge = Zedge::new(client, redistribute_static, pushed, withdrawn);
    zedge.start().await?;
    let (tx, rx) = mpsc::unbounded_channel();
    tokio::spawn(async move {
        if let Err(e) = zedge.run(rx).await {
            warn!(error = %e, "ospfd: zedge task exited");
        }
    });
    Ok(tx)
}

/// A no-op sender stand-in for standalone mode (daemon tests).
pub type SharedCommandSender = Arc<Mutex<Option<mpsc::UnboundedSender<ZedgeCommand>>>>;
