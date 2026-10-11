//! ZAPI client core: the daemon side of the wire.
//!
//! [`ZapiClient`] is what a Rouster (or FRR-shaped) protocol daemon holds
//! to talk to a zebra: connect to the ZAPI Unix socket, HELLO with its
//! protocol number, push ROUTE_ADD/ROUTE_DELETE, and track gateways via
//! NEXTHOP_REGISTER/UNREGISTER. Incoming zebra pushes (NEXTHOP_UPDATE,
//! interface dumps) are readable via [`ZapiClient::read_message`] — callers
//! that only need tracking answers can use
//! [`ZapiClient::next_nexthop_update`], which skips and logs everything
//! else at debug.
//!
//! `IO` is generic over `AsyncRead + AsyncWrite + Unpin` (same testability
//! pattern as [`crate::server::run_session`]); [`ZapiClient::connect`]
//! produces the Unix-socket form.
//!
//! This completes the crate's CLIENT direction: the server (Z3) and this
//! client exercise both directions of the Z2 codec natively, so the first
//! real-FRR contact (Z5) happens against a wire already proven in both
//! directions against ourselves.

use std::io;
use std::path::Path;

use common::{IpPrefix, RouteEntry, RouteProtocol};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::UnixStream;
use tracing::{debug, warn};

use crate::header::{ZapiHeader, ZAPI_HEADER_LEN};
use crate::message::{
    message_flag, route_type, ZapiCodecError, ZapiHello, ZapiMessage, ZapiNexthop,
    ZapiNexthopRegister, ZapiNexthopUpdate, ZapiRedistribute, ZapiRoute,
};

/// Route flags FRR 10.2.2 staticd sends on its ROUTE_ADD/DELETE:
/// `ZEBRA_FLAG_ALLOW_RECURSION | ZEBRA_FLAG_RR_USE_DISTANCE` (0x41, Z2
/// finding — E in the staticd fixtures). Mirrored so our staticd is
/// byte-compatible with the captured daemon.
const STATIC_ROUTE_FLAGS: u32 = 0x41;

/// A ZAPI protocol client connected (or connectable) to a zebra.
pub struct ZapiClient<IO> {
    io: IO,
}

impl ZapiClient<UnixStream> {
    /// Connects to a ZAPI server socket. Single attempt — callers that
    /// must tolerate a not-yet-started server wrap this in their own
    /// retry (the staticd binary sleeps between attempts).
    pub async fn connect(socket_path: &Path) -> io::Result<Self> {
        let io = UnixStream::connect(socket_path).await?;
        debug!(path = %socket_path.display(), "zapi client: connected");
        Ok(Self { io })
    }
}

impl<IO> ZapiClient<IO>
where
    IO: AsyncRead + AsyncWrite + Unpin,
{
    /// Wraps an established stream (tests drive this over duplex pairs).
    pub fn new(io: IO) -> Self {
        Self { io }
    }

    /// Sends HELLO announcing `protocol` (a [`crate::route_type`] value)
    /// and waits for the reply. Zebra answers HELLO by echoing it (pinned
    /// doc, operational finding 2); anything else is treated as a broken
    /// handshake. Returns the echoed HELLO.
    pub async fn handshake(&mut self, protocol: u8) -> io::Result<ZapiHello> {
        let hello = ZapiHello {
            redist_default: protocol,
            instance: 0,
            session_id: 0,
            synchronous: 0,
        };
        self.send(&ZapiMessage::Hello(hello)).await?;
        match self.read_message().await? {
            ZapiMessage::Hello(echo) if echo == hello => Ok(echo),
            ZapiMessage::Hello(echo) => {
                warn!(
                    ?echo,
                    "zapi client: HELLO reply differs from ours (accepted)"
                );
                Ok(echo)
            }
            other => Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("expected HELLO reply, got command {}", other.command()),
            )),
        }
    }

    /// ROUTE_ADD for one route entry.
    pub async fn send_route_add(&mut self, entry: &RouteEntry) -> io::Result<()> {
        self.send(&route_add_message(entry)).await
    }

    /// ROUTE_DELETE for one route entry (identified by prefix + protocol;
    /// FRR sends no nexthops in the delete).
    pub async fn send_route_delete(&mut self, entry: &RouteEntry) -> io::Result<()> {
        self.send(&route_delete_message(entry)).await
    }

    /// NEXTHOP_REGISTER for a gateway (registered as a /32 or /128 — the
    /// form both fixtures use). The zebra answer arrives later as a
    /// NEXTHOP_UPDATE; read it with [`Self::next_nexthop_update`].
    pub async fn send_nexthop_register(&mut self, gateway: IpPrefix) -> io::Result<()> {
        self.send(&ZapiMessage::NexthopRegister(nexthop_register_message(
            gateway,
        )))
        .await
    }

    /// NEXTHOP_UNREGISTER: stop tracking a gateway.
    pub async fn send_nexthop_unregister(&mut self, gateway: IpPrefix) -> io::Result<()> {
        self.send(&ZapiMessage::NexthopUnregister(nexthop_register_message(
            gateway,
        )))
        .await
    }

    /// INTERFACE_ADD (0) with an empty body — the client→zebra
    /// interface-state registration request. Zebra answers with one
    /// INTERFACE_ADD dump per interface (each followed by its
    /// INTERFACE_ADDRESS_ADDes), then event-driven pushes. Read them
    /// with [`Self::read_message`] (the savd/ospfd collectors do).
    /// E: the empty-body form every connecting daemon sends (pinned
    /// doc, command table row 0).
    pub async fn send_interface_dump_request(&mut self) -> io::Result<()> {
        self.send(&ZapiMessage::InterfaceAddRequest).await
    }

    /// REDISTRIBUTE_ADD (12): register interest in best-route pushes
    /// (`zclient_redistribute_set`; the zebra side answers with the
    /// current best-route dump of that type, then event-driven
    /// REDISTRIBUTE_ROUTE_ADD/DEL). Consumed by Rouster's savd to hold a
    /// RIB view without any new message type.
    pub async fn send_redistribute_add(
        &mut self,
        afi: u8,
        route_type: u8,
        instance: u16,
    ) -> io::Result<()> {
        self.send(&ZapiMessage::RedistributeAdd(ZapiRedistribute {
            afi,
            route_type,
            instance,
        }))
        .await
    }

    /// Reads one framed message. Errors on a malformed body — this client
    /// speaks to our own server first and wants drift loud.
    pub async fn read_message(&mut self) -> io::Result<ZapiMessage> {
        let mut header_buf = [0u8; ZAPI_HEADER_LEN];
        self.io.read_exact(&mut header_buf).await?;
        let header = ZapiHeader::decode(&header_buf)
            .map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err.to_string()))?;
        let mut body = vec![0u8; header.length as usize - ZAPI_HEADER_LEN];
        self.io.read_exact(&mut body).await?;
        ZapiMessage::decode(header.command, &body)
            .map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err.to_string()))
    }

    /// Reads until the NEXTHOP_UPDATE answering the registration of
    /// `gateway` arrives. Everything else read on the way (interface
    /// dumps, other updates) is logged at debug and skipped — zebra's
    /// pushes and the tracking replies share one stream.
    pub async fn next_nexthop_update(
        &mut self,
        gateway: &IpPrefix,
    ) -> io::Result<ZapiNexthopUpdate> {
        loop {
            match self.read_message().await? {
                ZapiMessage::NexthopUpdate(update) if &update.registered_prefix == gateway => {
                    return Ok(update)
                }
                other => {
                    debug!(
                        command = other.command(),
                        "zapi client: skipped zebra push while awaiting NEXTHOP_UPDATE"
                    );
                }
            }
        }
    }

    /// Encodes and writes one message (vrf 0).
    async fn send(&mut self, message: &ZapiMessage) -> io::Result<()> {
        let frame = message.encode_frame(0).map_err(|err: ZapiCodecError| {
            io::Error::new(io::ErrorKind::InvalidData, err.to_string())
        })?;
        self.io.write_all(&frame).await?;
        self.io.flush().await
    }
}

/// Builds the NEXTHOP_REGISTER/UNREGISTER body both fixtures pin:
/// connected=0, resolve_via_default=0, safi=1 (SAFI_UNICAST).
fn nexthop_register_message(gateway: IpPrefix) -> ZapiNexthopRegister {
    ZapiNexthopRegister {
        connected: false,
        resolve_via_default: false,
        safi: 1,
        prefix: gateway,
    }
}

/// Internal route entry → ZEBRA_ROUTE_ADD message, in the exact shape FRR
/// 10.2.2 staticd sends (pinned by the fixture: flags 0x41, message
/// NEXTHOP|DISTANCE, safi 1, staticd's protocol distance).
pub fn route_add_message(entry: &RouteEntry) -> ZapiMessage {
    ZapiMessage::RouteAdd(route_message(entry, false))
}

/// Internal route entry → ZEBRA_ROUTE_DELETE message (empty nexthop list,
/// same fixture-pinned shape).
pub fn route_delete_message(entry: &RouteEntry) -> ZapiMessage {
    ZapiMessage::RouteDelete(route_message(entry, true))
}

fn route_message(entry: &RouteEntry, empty_nexthops: bool) -> ZapiRoute {
    let nexthops = if empty_nexthops {
        Vec::new()
    } else {
        entry
            .nexthops
            .hops()
            .iter()
            .map(|&(hop, _)| ZapiNexthop::from_common(hop))
            .collect()
    };
    ZapiRoute {
        route_type: route_type_from(entry.protocol),
        instance: 0,
        flags: STATIC_ROUTE_FLAGS,
        message: message_flag::NEXTHOP | message_flag::DISTANCE,
        safi: 1,
        prefix: entry.prefix,
        src_prefix: None,
        nhg_id: 0,
        nexthops,
        backup_nexthops: Vec::new(),
        distance: Some(entry.protocol.admin_distance()),
        // The METRIC message bit is never set, so the metric rides nowhere;
        // kept None to match the fixture bodies exactly.
        metric: None,
        tag: None,
        mtu: None,
        tableid: None,
        opaque: None,
    }
}

/// Reverse of [`ZapiRoute::route_protocol`]: the ZEBRA_ROUTE_* number an
/// internal protocol is announced as. Kernel/OSPF/RIP families collapse
/// to their v4 representative (the wire carries no more precision).
pub fn route_type_from(protocol: RouteProtocol) -> u8 {
    match protocol {
        RouteProtocol::Kernel => route_type::KERNEL,
        RouteProtocol::Connected => route_type::CONNECT,
        RouteProtocol::Static => route_type::STATIC,
        RouteProtocol::Rip => route_type::RIP,
        RouteProtocol::Ospf => route_type::OSPF,
        RouteProtocol::IsIs => route_type::ISIS,
        RouteProtocol::Bgp => route_type::BGP,
        RouteProtocol::Local => route_type::LOCAL,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use common::{Nexthop, NexthopGroup};
    use tokio::io::duplex;

    /// A fake zebra on the other end of a duplex pair: answers HELLO by
    /// echoing it, records nothing (each test reads what it needs from the
    /// returned stream half).
    async fn echo_hello(server: &mut tokio::io::DuplexStream) {
        let mut header_buf = [0u8; ZAPI_HEADER_LEN];
        server.read_exact(&mut header_buf).await.unwrap();
        let header = ZapiHeader::decode(&header_buf).unwrap();
        let mut body = vec![0u8; header.length as usize - ZAPI_HEADER_LEN];
        server.read_exact(&mut body).await.unwrap();
        assert_eq!(header.command, 19, "fake zebra sees HELLO first");
        let mut frame = header_buf.to_vec();
        frame.extend_from_slice(&body);
        server.write_all(&frame).await.unwrap();
    }

    #[tokio::test]
    async fn handshake_sends_static_hello_and_accepts_echo() {
        let (client_io, mut server_io) = duplex(4096);
        let mut client = ZapiClient::new(client_io);
        let client_task = tokio::spawn(async move { client.handshake(route_type::STATIC).await });
        echo_hello(&mut server_io).await;
        client_task.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn handshake_rejects_non_hello_reply() {
        let (client_io, mut server_io) = duplex(4096);
        let mut client = ZapiClient::new(client_io);
        let client_task = tokio::spawn(async move { client.handshake(route_type::STATIC).await });
        // Swallow the HELLO, answer with something else (a push).
        let (_header, _body) = server_read_frame(&mut server_io).await;
        server_io
            .write_all(&ZapiMessage::InterfaceAddRequest.encode_frame(0).unwrap())
            .await
            .unwrap();
        let err = client_task.await.unwrap().unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
    }

    fn static_entry(prefix: &str, hop: Nexthop) -> RouteEntry {
        RouteEntry::new(
            prefix.parse().unwrap(),
            RouteProtocol::Static,
            NexthopGroup::single(hop),
            0,
        )
    }

    /// The client's ROUTE_ADD for a blackhole static must be byte-identical
    /// to the captured FRR staticd fixture body (Z1/Z2 pin).
    #[tokio::test]
    async fn route_add_encodes_fixture_bytes() {
        let (client_io, mut server_io) = duplex(4096);
        let mut client = ZapiClient::new(client_io);
        let entry = static_entry("203.0.113.0/24", Nexthop::Blackhole);
        let send = tokio::spawn(async move { client.send_route_add(&entry).await });
        let (header, body) = server_read_frame(&mut server_io).await;
        send.await.unwrap().unwrap();
        assert_eq!(header.command, 9);
        assert_eq!(
            body,
            unhex("0400000000004100000003010218cb007100010000000006000101")
        );
    }

    /// ROUTE_DELETE: fixture shape (no nexthops, distance kept).
    #[tokio::test]
    async fn route_delete_encodes_fixture_bytes() {
        let (client_io, mut server_io) = duplex(4096);
        let mut client = ZapiClient::new(client_io);
        let entry = static_entry("198.51.100.0/24", Nexthop::Blackhole);
        let send = tokio::spawn(async move { client.send_route_delete(&entry).await });
        let (header, body) = server_read_frame(&mut server_io).await;
        send.await.unwrap().unwrap();
        assert_eq!(header.command, 10);
        assert_eq!(body, unhex("0400000000004100000003010218c63364000001"));
    }

    /// NEXTHOP_REGISTER must reproduce the staticd fixture body exactly.
    #[tokio::test]
    async fn nexthop_register_encodes_fixture_bytes() {
        let (client_io, mut server_io) = duplex(4096);
        let mut client = ZapiClient::new(client_io);
        let gw: IpPrefix = "192.0.2.1/32".parse().unwrap();
        let send = tokio::spawn(async move { client.send_nexthop_register(gw).await });
        let (header, body) = server_read_frame(&mut server_io).await;
        send.await.unwrap().unwrap();
        assert_eq!(header.command, 21);
        assert_eq!(body, unhex("00000001000220c0000201"));
    }

    /// REDISTRIBUTE_ADD must reproduce the bgpd `redistribute static`
    /// fixture body exactly (E: `01 04 0000`).
    #[tokio::test]
    async fn redistribute_add_encodes_fixture_bytes() {
        let (client_io, mut server_io) = duplex(4096);
        let mut client = ZapiClient::new(client_io);
        let send =
            tokio::spawn(
                async move { client.send_redistribute_add(1, route_type::STATIC, 0).await },
            );
        let (header, body) = server_read_frame(&mut server_io).await;
        send.await.unwrap().unwrap();
        assert_eq!(header.command, 12);
        assert_eq!(body, unhex("01040000"));
    }

    /// The dump request is the empty-body INTERFACE_ADD (command 0,
    /// zero body bytes) — the registration form every connecting
    /// daemon sends.
    #[tokio::test]
    async fn interface_dump_request_encodes_empty_interface_add() {
        let (client_io, mut server_io) = duplex(4096);
        let mut client = ZapiClient::new(client_io);
        let send = tokio::spawn(async move { client.send_interface_dump_request().await });
        let (header, body) = server_read_frame(&mut server_io).await;
        send.await.unwrap().unwrap();
        assert_eq!(header.command, 0);
        assert!(body.is_empty());
    }

    /// next_nexthop_update skips an interface push standing in front of
    /// the update (one stream, interleaved zebra pushes).
    #[tokio::test]
    async fn next_update_skips_interleaved_pushes() {
        let (client_io, mut server_io) = duplex(4096);
        let mut client = ZapiClient::new(client_io);
        let gw: IpPrefix = "192.0.2.1/32".parse().unwrap();
        let push = ZapiMessage::InterfaceAdd(crate::ZapiInterface::new("eth0", 2));
        let update = ZapiNexthopUpdate::resolved(
            gw,
            1,
            route_type::CONNECT,
            0,
            0,
            vec![ZapiNexthop::new_ipv4_ifindex(
                0,
                "192.0.2.1".parse().unwrap(),
                2,
            )],
        );
        server_io
            .write_all(&push.encode_frame(0).unwrap())
            .await
            .unwrap();
        server_io
            .write_all(&ZapiMessage::NexthopUpdate(update).encode_frame(0).unwrap())
            .await
            .unwrap();
        let got = client.next_nexthop_update(&gw).await.unwrap();
        assert!(got.is_resolved());
        assert_eq!(got.nexthops.len(), 1);
        assert_eq!(got.nexthops[0].ifindex, 2);
    }

    /// A gateway route (the common staticd case) encodes an IPV4 nexthop.
    #[tokio::test]
    async fn gateway_route_encodes_ipv4_nexthop() {
        let (client_io, mut server_io) = duplex(4096);
        let mut client = ZapiClient::new(client_io);
        let entry = static_entry(
            "198.51.100.0/24",
            Nexthop::Ipv4("192.0.2.9".parse().unwrap()),
        );
        let send = tokio::spawn(async move { client.send_route_add(&entry).await });
        let (_header, body) = server_read_frame(&mut server_io).await;
        send.await.unwrap().unwrap();
        let decoded = ZapiRoute::decode(&body).unwrap();
        assert_eq!(decoded.nexthops.len(), 1);
        assert_eq!(decoded.nexthops[0].nh_type, crate::nexthop_type::IPV4);
        assert_eq!(
            decoded.nexthops[0].gate,
            Some("192.0.2.9".parse::<std::net::IpAddr>().unwrap())
        );
    }

    async fn server_read_frame(io: &mut tokio::io::DuplexStream) -> (ZapiHeader, Vec<u8>) {
        let mut header_buf = [0u8; ZAPI_HEADER_LEN];
        io.read_exact(&mut header_buf).await.unwrap();
        let header = ZapiHeader::decode(&header_buf).unwrap();
        let mut body = vec![0u8; header.length as usize - ZAPI_HEADER_LEN];
        io.read_exact(&mut body).await.unwrap();
        (header, body)
    }

    fn unhex(s: &str) -> Vec<u8> {
        s.as_bytes()
            .chunks(2)
            .map(|p| u8::from_str_radix(std::str::from_utf8(p).unwrap(), 16).unwrap())
            .collect()
    }
}
