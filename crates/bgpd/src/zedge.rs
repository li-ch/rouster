//! The ZAPI edge (the savd/W8 + A23 client idioms): bgpd as a zebra
//! client.
//!
//! - **NHT for peer addresses**: NEXTHOP_REGISTER per configured
//!   neighbor (the /32 or /128 form both fixtures pin); the answers
//!   (NEXTHOP_UPDATE) and the interface dump feed a mirror whose
//!   on-link check gates the connectors (§8: Connect waits for a
//!   usable route — the natural zebra-client behavior).
//! - **RIB view**: REDISTRIBUTE_ADD (STATIC, v4) — v1 keeps the view
//!   for observability; exporting kernel/statics into BGP needs the
//!   policy engine (§Deferred).
//! - **Export**: best-path changes become ZEBRA_ROUTE_ADD / _DELETE
//!   (protocol BGP) so bgpd-learned routes reach the kernel through
//!   rousterd, the z5b-proven direction.
//!
//! No session-loss recovery subtleties v1: on socket error the task
//! exits and the daemon logs; the interop smoke's topology has
//! rousterd up first (the connect-with-retry binary loop covers
//! ordering).

use std::collections::BTreeMap;
use std::io;
use std::net::IpAddr;
use std::sync::{Arc, Mutex};

use common::{IpPrefix, RouteEntry};
use tokio::sync::mpsc;
use tracing::{debug, info, warn};
use zapi::message::{route_type, ZapiMessage};
use zapi::{ZapiClient, ZapiInterfaceAddress};

/// Commands the daemon sends toward zebra.
#[derive(Debug, Clone)]
pub enum ZedgeCommand {
    RouteAdd(RouteEntry),
    RouteDel(RouteEntry),
}

/// The interface mirror built from zebra's dumps and pushes: per
/// ifindex, its addresses. Address presence is the v1 liveness proxy
/// (INTERFACE_UP/DOWN tracking is §Deferred — a connected peer needs
/// the address, which is what NHT cares about).
#[derive(Default)]
pub struct InterfaceMirror {
    addresses: BTreeMap<u32, Vec<IpPrefix>>,
}

impl InterfaceMirror {
    /// True when `addr` falls inside any mirrored interface address
    /// (the on-link answer single-hop BGP peers need).
    pub fn on_link(&self, addr: IpAddr) -> bool {
        self.addresses
            .values()
            .flatten()
            .any(|p| prefix_contains(*p, addr))
    }

    /// Fold one zebra message into the mirror; true when consumed.
    pub fn apply(&mut self, message: &ZapiMessage) -> bool {
        match message {
            ZapiMessage::InterfaceAdd(iface) => {
                self.addresses.entry(iface.ifindex).or_default();
                debug!(ifindex = iface.ifindex, name = %iface.ifname, "bgpd: interface seen");
                true
            }
            ZapiMessage::InterfaceAddressAdd(addr) => {
                self.add_address(addr);
                true
            }
            ZapiMessage::InterfaceAddressDelete(addr) => {
                if let Some(list) = self.addresses.get_mut(&addr.ifindex) {
                    list.retain(|p| *p != addr.address);
                }
                true
            }
            ZapiMessage::InterfaceDelete(iface) => {
                self.addresses.remove(&iface.ifindex);
                true
            }
            _ => false,
        }
    }

    fn add_address(&mut self, addr: &ZapiInterfaceAddress) {
        self.addresses
            .entry(addr.ifindex)
            .or_default()
            .push(addr.address);
    }

    pub fn route_count(&self) -> usize {
        // Interfaces tracked (the "view size" log line).
        self.addresses.len()
    }
}

fn prefix_contains(p: IpPrefix, addr: IpAddr) -> bool {
    match (p, addr) {
        (IpPrefix::V4(p), IpAddr::V4(a)) => p.contains(a),
        (IpPrefix::V6(p), IpAddr::V6(a)) => p.contains(a),
        _ => false,
    }
}

/// Connector gating surface: is this peer address usable yet?
pub trait PeerReachability: Send + Sync {
    fn reachable(&self, addr: IpAddr) -> bool;
}

/// Standalone mode (no zapi socket configured): everything is.
pub struct AlwaysReachable;
impl PeerReachability for AlwaysReachable {
    fn reachable(&self, _: IpAddr) -> bool {
        true
    }
}

/// Mirror-backed gating (the zapi-attached shape).
pub struct MirrorReachability(pub Arc<Mutex<InterfaceMirror>>);

impl PeerReachability for MirrorReachability {
    fn reachable(&self, addr: IpAddr) -> bool {
        self.0.lock().unwrap().on_link(addr)
    }
}

/// The registered peer address as an NHT prefix (/32 or /128).
fn peer_prefix(addr: IpAddr) -> IpPrefix {
    match addr {
        IpAddr::V4(a) => IpPrefix::V4(common::Ipv4Prefix::new(a, 32).unwrap()),
        IpAddr::V6(a) => IpPrefix::V6(common::Ipv6Prefix::new(a, 128).unwrap()),
    }
}

/// The zapi-attached edge task's state machine, IO-generic for the
/// duplex tests.
pub struct Zedge<IO> {
    client: ZapiClient<IO>,
    pub mirror: Arc<Mutex<InterfaceMirror>>,
    peers: Vec<IpAddr>,
}

impl<IO> Zedge<IO>
where
    IO: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    pub fn new(client: ZapiClient<IO>, peers: Vec<IpAddr>) -> Self {
        Self {
            client,
            mirror: Arc::new(Mutex::new(InterfaceMirror::default())),
            peers,
        }
    }

    /// HELLO as BGP, NHT for every peer, the redistribute view.
    pub async fn start(&mut self) -> io::Result<()> {
        self.client.handshake(route_type::BGP).await?;
        for peer in &self.peers {
            self.client
                .send_nexthop_register(peer_prefix(*peer))
                .await?;
            info!(peer = %peer, "bgpd: NHT registered");
        }
        self.client
            .send_redistribute_add(1, route_type::STATIC, 0)
            .await?;
        Ok(())
    }

    /// Consume one zebra message (mirror maintenance + NHT answers).
    pub fn apply_message(&mut self, message: ZapiMessage) {
        match &message {
            ZapiMessage::NexthopUpdate(update) => {
                info!(
                    prefix = %update.registered_prefix,
                    resolved = update.is_resolved(),
                    "bgpd: NHT answer"
                );
            }
            ZapiMessage::RouterIdUpdate(id) => {
                debug!(?id.address, "bgpd: router-id update from zebra");
            }
            other => {
                self.mirror.lock().unwrap().apply(other);
            }
        }
    }

    /// One drain of the command channel → ROUTE_ADD/DELETE.
    pub async fn flush(&mut self, commands: impl Iterator<Item = ZedgeCommand>) -> io::Result<()> {
        for command in commands {
            match command {
                ZedgeCommand::RouteAdd(entry) => {
                    self.client.send_route_add(&entry).await?;
                    info!(prefix = %entry.prefix, "bgpd: route add -> zebra");
                }
                ZedgeCommand::RouteDel(entry) => {
                    self.client.send_route_delete(&entry).await?;
                    info!(prefix = %entry.prefix, "bgpd: route delete -> zebra");
                }
            }
        }
        Ok(())
    }

    /// The resident loop: reads zebra, drains commands.
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
                            warn!(error = %e, "bgpd: zapi session lost");
                            return Err(e);
                        }
                    }
                }
                command = commands.recv() => {
                    match command {
                        Some(command) => {
                            self.flush(std::iter::once(command)).await?;
                        }
                        None => {
                            info!("bgpd: export channel closed, zedge exiting");
                            return Ok(());
                        }
                    }
                }
            }
        }
    }
}

/// Spawns the zedge task against the real socket (the binary's wiring):
/// connect-with-retry (staticd's pattern), start, run. Returns the
/// reachability surface + the command sender.
pub async fn spawn(
    socket: std::path::PathBuf,
    peers: Vec<IpAddr>,
) -> io::Result<(
    Arc<Mutex<InterfaceMirror>>,
    mpsc::UnboundedSender<ZedgeCommand>,
)> {
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
    let mut zedge = Zedge::new(client, peers);
    zedge.start().await?;
    let mirror = Arc::clone(&zedge.mirror);
    let (tx, rx) = mpsc::unbounded_channel();
    tokio::spawn(async move {
        if let Err(e) = zedge.run(rx).await {
            warn!(error = %e, "bgpd: zedge task exited");
        }
    });
    Ok((mirror, tx))
}

#[cfg(test)]
mod tests {
    use super::*;
    use common::{Ipv4Prefix, Nexthop, NexthopGroup, RouteProtocol};
    use tokio::io::{duplex, AsyncReadExt, AsyncWriteExt};
    use zapi::message::ZapiInterface;

    async fn fake_zebra_hello(server: &mut tokio::io::DuplexStream) {
        let mut header_buf = [0u8; zapi::ZAPI_HEADER_LEN];
        server.read_exact(&mut header_buf).await.unwrap();
        let header = zapi::ZapiHeader::decode(&header_buf).unwrap();
        let mut body = vec![0u8; header.length as usize - zapi::ZAPI_HEADER_LEN];
        server.read_exact(&mut body).await.unwrap();
        let mut frame = header_buf.to_vec();
        frame.extend_from_slice(&body);
        server.write_all(&frame).await.unwrap();
    }

    async fn server_read_frame(server: &mut tokio::io::DuplexStream) -> (u16, Vec<u8>) {
        let mut header_buf = [0u8; zapi::ZAPI_HEADER_LEN];
        server.read_exact(&mut header_buf).await.unwrap();
        let header = zapi::ZapiHeader::decode(&header_buf).unwrap();
        let mut body = vec![0u8; header.length as usize - zapi::ZAPI_HEADER_LEN];
        server.read_exact(&mut body).await.unwrap();
        (header.command, body)
    }

    #[tokio::test]
    async fn start_registers_nht_and_redistribute() {
        let (client_io, mut server) = duplex(8192);
        let mut zedge = Zedge::new(
            ZapiClient::new(client_io),
            vec!["192.0.2.9".parse().unwrap()],
        );
        let start = tokio::spawn(async move { zedge.start().await });
        fake_zebra_hello(&mut server).await;
        // NEXTHOP_REGISTER with the /32 fixture shape.
        let (cmd, body) = server_read_frame(&mut server).await;
        assert_eq!(cmd, 21);
        assert_eq!(
            body,
            vec![0x00, 0x00, 0x00, 0x01, 0x00, 0x02, 0x20, 192, 0, 2, 9]
        );
        // REDISTRIBUTE_ADD (v4, STATIC).
        let (cmd, body) = server_read_frame(&mut server).await;
        assert_eq!(cmd, 12);
        assert_eq!(body, vec![0x01, 0x04, 0x00, 0x00]);
        start.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn interface_pushes_build_the_mirror() {
        let mut mirror = InterfaceMirror::default();
        let iface = ZapiMessage::InterfaceAdd(ZapiInterface::new("eth0", 2));
        assert!(mirror.apply(&iface));
        let addr = ZapiMessage::InterfaceAddressAdd(ZapiInterfaceAddress {
            ifindex: 2,
            flags: 0,
            address: IpPrefix::V4(Ipv4Prefix::new("192.0.2.1".parse().unwrap(), 24).unwrap()),
            destination: None,
        });
        assert!(mirror.apply(&addr));
        assert!(mirror.on_link("192.0.2.9".parse().unwrap()));
        assert!(!mirror.on_link("198.51.100.9".parse().unwrap()));
        // Removal flips reachability.
        if let ZapiMessage::InterfaceAddressAdd(a) = addr {
            let del = ZapiMessage::InterfaceAddressDelete(a);
            assert!(mirror.apply(&del));
        }
        assert!(!mirror.on_link("192.0.2.9".parse().unwrap()));
    }

    #[tokio::test]
    async fn export_commands_reach_the_wire() {
        let (client_io, mut server) = duplex(8192);
        let mut zedge = Zedge::new(ZapiClient::new(client_io), vec![]);
        let entry = RouteEntry::new(
            "203.0.113.0/24".parse().unwrap(),
            RouteProtocol::Bgp,
            NexthopGroup::single(Nexthop::Ipv4("192.0.2.9".parse().unwrap())),
            0,
        );
        let flush = tokio::spawn(async move {
            zedge
                .flush(
                    [
                        ZedgeCommand::RouteAdd(entry.clone()),
                        ZedgeCommand::RouteDel(entry),
                    ]
                    .into_iter(),
                )
                .await
        });
        let (cmd, _body) = server_read_frame(&mut server).await;
        assert_eq!(cmd, 9, "ROUTE_ADD");
        let (cmd, _body) = server_read_frame(&mut server).await;
        assert_eq!(cmd, 10, "ROUTE_DELETE");
        flush.await.unwrap().unwrap();
    }
}
