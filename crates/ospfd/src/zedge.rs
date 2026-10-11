//! ospfd's ZAPI edge (the bgpd `zedge` idioms): ospfd as a zebra
//! client.
//!
//! - **HELLO as OSPF** (route type 7) — the z5c-proven attach.
//! - **`redistribute static`** registration (REDISTRIBUTE_ADD,
//!   afi v4 STATIC): zebra's REDISTRIBUTE_ROUTE_ADD/DELETE pushes
//!   become the §12.4.4 external-LSA origination/withdrawal feed.
//! - **Export**: SPF route changes become ZEBRA_ROUTE_ADD/_DELETE
//!   (protocol OSPF) so OSPF-learned routes reach the kernel through
//!   rousterd.
//!
//! v1 disclosures: the ROUTER_ID_ADD request and the
//! INTERFACE_ADD_REQUEST dump are not sent (`ZapiClient` exposes no
//! raw send — the bgpd P2-b deviation-2 precedent): the router ID
//! comes from config, interface addresses from the config stanzas.

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

/// Spawn the zedge task against the real socket (connect-with-retry,
/// the bgpd/staticd pattern). Returns the command sender.
pub async fn spawn(
    socket: std::path::PathBuf,
    redistribute_static: bool,
    pushed: mpsc::UnboundedSender<RedistributedRoute>,
    withdrawn: mpsc::UnboundedSender<RedistributedRoute>,
) -> io::Result<mpsc::UnboundedSender<ZedgeCommand>> {
    let mut client = None;
    for _ in 0..30 {
        match ZapiClient::connect(&socket).await {
            Ok(c) => {
                client = Some(c);
                break;
            }
            Err(_) => tokio::time::sleep(std::time::Duration::from_secs(1)).await,
        }
    }
    let client = client
        .ok_or_else(|| io::Error::new(io::ErrorKind::TimedOut, "zebra socket never appeared"))?;
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
