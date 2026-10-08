//! rouster-staticd: the static-route daemon logic.
//!
//! Rouster's canonical static-route path (Z4): a separate small binary
//! parses the route config and speaks ZAPI to rousterd — the FRR shape
//! (staticd → zebra), exercising the codec's client direction against our
//! own server before real FRR interop (Z5). rousterd's own direct
//! config-load (`--once` CI mode; resident mode without a `zapi socket`
//! line) is legacy now that this path exists.
//!
//! The daemon state machine lives here (not in the binary) so the
//! end-to-end test drives the exact production logic:
//! [`StaticDaemon::initial_load`] handshakes, installs every route, and
//! lock-step-registers each distinct gateway (reading each NEXTHOP_UPDATE
//! answer before proceeding — real daemons pipeline this, but lock-step
//! makes the exchange causally observable without timers);
//! [`StaticDaemon::reload`] is the SIGHUP semantics (ROUTE_DELETE for
//! vanished prefixes, ROUTE_ADD for new ones, NHT follow the gateways).

use std::collections::{BTreeMap, BTreeSet};
use std::io;
use std::path::Path;

use common::{IpPrefix, Ipv4Prefix, Ipv6Prefix, Nexthop, RouteEntry};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::UnixStream;
use tracing::{debug, info, warn};
use zapi::{route_type, ZapiClient, ZapiNexthopUpdate};

/// The static-route daemon: one ZAPI client plus what it has told the
/// server (installed routes, tracked gateways) so reloads can diff.
pub struct StaticDaemon<IO> {
    client: ZapiClient<IO>,
    /// Routes currently installed at the server, by prefix.
    installed: BTreeMap<IpPrefix, RouteEntry>,
    /// Gateways currently NHT-registered (as /32 or /128).
    gateways: BTreeSet<IpPrefix>,
    /// Every NEXTHOP_UPDATE received, in arrival order (observable state
    /// for tests and for the eventual resident-loop NHT reprogramming).
    updates: Vec<ZapiNexthopUpdate>,
}

impl StaticDaemon<UnixStream> {
    /// Connects to rousterd's ZAPI socket (single attempt; callers that
    /// must wait for the server wrap their own retry).
    pub async fn connect(socket_path: &Path) -> io::Result<Self> {
        Ok(Self {
            client: ZapiClient::connect(socket_path).await?,
            installed: BTreeMap::new(),
            gateways: BTreeSet::new(),
            updates: Vec::new(),
        })
    }
}

impl<IO> StaticDaemon<IO>
where
    IO: AsyncRead + AsyncWrite + Unpin,
{
    /// Wraps an established client (tests drive this over duplex pairs).
    pub fn new(client: ZapiClient<IO>) -> Self {
        Self {
            client,
            installed: BTreeMap::new(),
            gateways: BTreeSet::new(),
            updates: Vec::new(),
        }
    }

    /// The NEXTHOP_UPDATEs received so far.
    pub fn updates(&self) -> &[ZapiNexthopUpdate] {
        &self.updates
    }

    /// Initial configuration load: HELLO (protocol = static), ROUTE_ADD
    /// for every route, NEXTHOP_REGISTER for every distinct gateway —
    /// reading each update answer in lock-step, so on return the server
    /// has handled everything sent.
    pub async fn initial_load(&mut self, routes: &[RouteEntry]) -> io::Result<()> {
        let hello = self.client.handshake(route_type::STATIC).await?;
        info!(
            protocol = hello.redist_default,
            "staticd: session established"
        );

        for route in routes {
            self.client.send_route_add(route).await?;
            self.installed.insert(route.prefix, route.clone());
        }
        info!(routes = routes.len(), "staticd: routes installed");

        for gateway in gateways_of(routes) {
            self.register(gateway).await?;
        }
        Ok(())
    }

    /// SIGHUP semantics: re-converge the server onto `routes` —
    /// ROUTE_DELETE for vanished (or changed) prefixes, ROUTE_ADD for new
    /// (or changed) ones, NHT registrations follow the gateway set.
    /// Ingest errors are per-item warns, never fatal.
    pub async fn reload(&mut self, routes: &[RouteEntry]) -> io::Result<()> {
        let fresh: BTreeMap<IpPrefix, &RouteEntry> = routes.iter().map(|r| (r.prefix, r)).collect();

        // Vanished or changed: withdraw first.
        let to_remove: Vec<RouteEntry> = self
            .installed
            .values()
            .filter(|old| fresh.get(&old.prefix) != Some(old))
            .cloned()
            .collect();
        for old in &to_remove {
            if let Err(err) = self.client.send_route_delete(old).await {
                warn!(prefix = %old.prefix, %err, "staticd: route delete failed");
            } else {
                self.installed.remove(&old.prefix);
            }
        }

        // New or changed: (re-)install.
        for route in routes {
            let changed = self.installed.get(&route.prefix) != Some(route);
            if changed {
                if let Err(err) = self.client.send_route_add(route).await {
                    warn!(prefix = %route.prefix, %err, "staticd: route add failed");
                    continue;
                }
                self.installed.insert(route.prefix, route.clone());
            }
        }

        // NHT follows the gateways actually referenced now.
        let fresh_gws = gateways_of(routes);
        let to_register: Vec<IpPrefix> = fresh_gws.difference(&self.gateways).copied().collect();
        let to_unregister: Vec<IpPrefix> = self.gateways.difference(&fresh_gws).copied().collect();
        for gateway in to_register {
            if let Err(err) = self.register(gateway).await {
                warn!(%gateway, %err, "staticd: nexthop register failed");
            }
        }
        for gateway in to_unregister {
            if let Err(err) = self.client.send_nexthop_unregister(gateway).await {
                warn!(%gateway, %err, "staticd: nexthop unregister failed");
            }
        }
        self.gateways = fresh_gws;

        info!(
            installed = self.installed.len(),
            tracked = self.gateways.len(),
            "staticd: config reloaded"
        );
        Ok(())
    }

    /// Sends a marker HELLO and reads the echo. Not something FRR staticd
    /// does on demand — it is the causality hook tests (and anyone
    /// proving the server drained a burst) can call: the echo is only
    /// written after every earlier message on the connection was fully
    /// handled.
    pub async fn ping(&mut self) -> io::Result<()> {
        self.client.handshake(route_type::STATIC).await.map(|_| ())
    }

    /// Reads one incoming zebra message: NEXTHOP_UPDATEs are recorded,
    /// everything else (interface pushes, …) is logged at debug — no
    /// action tonight (reprogramming on NHT flips is Z3B-fed work).
    pub async fn read_message(&mut self) -> io::Result<()> {
        use zapi::ZapiMessage;
        match self.client.read_message().await? {
            ZapiMessage::NexthopUpdate(update) => {
                info!(
                    prefix = %update.registered_prefix,
                    resolved = update.is_resolved(),
                    "staticd: nexthop update"
                );
                self.updates.push(update);
            }
            other => {
                debug!(command = other.command(), "staticd: zebra push ignored");
            }
        }
        Ok(())
    }

    /// Registers one gateway and consumes its (first) update answer.
    async fn register(&mut self, gateway: IpPrefix) -> io::Result<()> {
        self.client.send_nexthop_register(gateway).await?;
        let update = self.client.next_nexthop_update(&gateway).await?;
        info!(
            gateway = %gateway,
            resolved = update.is_resolved(),
            "staticd: gateway tracked"
        );
        self.gateways.insert(gateway);
        self.updates.push(update);
        Ok(())
    }
}

/// Distinct gateway addresses referenced by a route set, as the /32//128
/// prefixes NHT registers them (`Ipv4`/`Ipv6` hops only — blackhole and
/// interface hops need no tracking).
pub fn gateways_of(routes: &[RouteEntry]) -> BTreeSet<IpPrefix> {
    routes
        .iter()
        .flat_map(|route| {
            route
                .nexthops
                .hops()
                .iter()
                .filter_map(|(hop, _)| gateway_prefix(hop))
        })
        .collect()
}

fn gateway_prefix(hop: &Nexthop) -> Option<IpPrefix> {
    match hop {
        Nexthop::Ipv4(g) => Some(IpPrefix::V4(Ipv4Prefix::new(*g, 32).ok()?)),
        Nexthop::Ipv6(g) => Some(IpPrefix::V6(Ipv6Prefix::new(*g, 128).ok()?)),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use common::{NexthopGroup, RouteProtocol};
    use zapi::ZapiMessage;

    fn route(prefix: &str, gw: &str) -> RouteEntry {
        RouteEntry::new(
            prefix.parse().unwrap(),
            RouteProtocol::Static,
            NexthopGroup::single(Nexthop::Ipv4(gw.parse().unwrap())),
            0,
        )
    }

    fn gw_prefix(gw: &str) -> IpPrefix {
        format!("{gw}/32").parse().unwrap()
    }

    /// Fake rousterd on a duplex pair: echoes HELLOs, answers each
    /// NEXTHOP_REGISTER with a resolved-looking update for the same
    /// prefix. Route adds/deletes get no reply.
    async fn fake_server(server: &mut tokio::io::DuplexStream) -> io::Result<()> {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use zapi::{ZapiHeader, ZAPI_HEADER_LEN};
        loop {
            let mut header_buf = [0u8; ZAPI_HEADER_LEN];
            server.read_exact(&mut header_buf).await?;
            let header = ZapiHeader::decode(&header_buf).unwrap();
            let mut body = vec![0u8; header.length as usize - ZAPI_HEADER_LEN];
            server.read_exact(&mut body).await?;
            let message = ZapiMessage::decode(header.command, &body).unwrap();
            match message {
                ZapiMessage::Hello(hello) => {
                    server
                        .write_all(&ZapiMessage::Hello(hello).encode_frame(0).unwrap())
                        .await?;
                }
                ZapiMessage::NexthopRegister(register) => {
                    let update = ZapiNexthopUpdate::resolved(register.prefix, 1, 3, 0, 0, vec![]);
                    server
                        .write_all(&ZapiMessage::NexthopUpdate(update).encode_frame(0).unwrap())
                        .await?;
                }
                _ => {} // route adds/deletes: no reply
            }
        }
    }

    fn spawn_fake_server() -> (
        tokio::io::DuplexStream,
        tokio::task::JoinHandle<io::Result<()>>,
    ) {
        let (client_io, mut server_io) = tokio::io::duplex(64 * 1024);
        (
            client_io,
            tokio::spawn(async move { fake_server(&mut server_io).await }),
        )
    }

    #[tokio::test]
    async fn initial_load_handshakes_installs_and_tracks() {
        let (client_io, server) = spawn_fake_server();
        let mut daemon = StaticDaemon::new(ZapiClient::new(client_io));

        let routes = vec![
            route("198.51.100.0/24", "192.0.2.9"),
            route("203.0.113.0/24", "192.0.2.9"),
            RouteEntry::new(
                "192.0.2.0/24".parse().unwrap(),
                RouteProtocol::Static,
                NexthopGroup::single(Nexthop::Blackhole),
                0,
            ),
        ];
        daemon.initial_load(&routes).await.unwrap();

        // Distinct gateways collapse to one registration.
        assert_eq!(daemon.gateways.len(), 1);
        assert_eq!(
            daemon.gateways.iter().next().unwrap(),
            &gw_prefix("192.0.2.9")
        );
        assert_eq!(daemon.updates().len(), 1, "one NEXTHOP_UPDATE consumed");
        assert_eq!(
            daemon.updates()[0].registered_prefix,
            gw_prefix("192.0.2.9")
        );

        // Reload to an empty config (SIGHUP semantics): everything goes.
        daemon.reload(&[]).await.unwrap();
        assert!(daemon.installed.is_empty());
        assert!(daemon.gateways.is_empty(), "gateway unregistered");

        // Ping still handshakes cleanly after the diff.
        daemon.ping().await.unwrap();
        drop(daemon);
        let _ = server.await;
    }

    /// A changed route (same prefix, new gateway) is withdrawn and
    /// re-added, and NHT follows the new gateway.
    #[tokio::test]
    async fn reload_replaces_changed_route() {
        let (client_io, server) = spawn_fake_server();
        let mut daemon = StaticDaemon::new(ZapiClient::new(client_io));

        daemon
            .initial_load(&[route("198.51.100.0/24", "192.0.2.9")])
            .await
            .unwrap();
        daemon
            .reload(&[route("198.51.100.0/24", "192.0.2.10")])
            .await
            .unwrap();
        assert_eq!(daemon.installed.len(), 1);
        assert_eq!(
            daemon.gateways.iter().next().unwrap(),
            &gw_prefix("192.0.2.10"),
            "tracking followed the new gateway"
        );
        drop(daemon);
        let _ = server.await;
    }

    #[tokio::test]
    async fn read_message_records_updates_and_skips_pushes() {
        use tokio::io::AsyncWriteExt;
        let (client_io, mut server_io) = tokio::io::duplex(64 * 1024);
        let mut daemon = StaticDaemon::new(ZapiClient::new(client_io));
        server_io
            .write_all(&ZapiMessage::InterfaceAddRequest.encode_frame(0).unwrap())
            .await
            .unwrap();
        let update = ZapiNexthopUpdate::unresolved("10.9.9.9/32".parse().unwrap(), 1);
        server_io
            .write_all(&ZapiMessage::NexthopUpdate(update).encode_frame(0).unwrap())
            .await
            .unwrap();
        daemon.read_message().await.unwrap(); // the push: ignored
        daemon.read_message().await.unwrap(); // the update: recorded
        assert_eq!(daemon.updates().len(), 1);
        assert!(!daemon.updates()[0].is_resolved());
    }
}
