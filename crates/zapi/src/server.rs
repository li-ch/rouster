//! ZAPI server: accepts FRR daemon connections over a Unix-domain socket.
//!
//! Per connection a session task runs a length-framed message loop
//! ([`run_session`]): read exactly one 10-byte header, then exactly
//! `length - header` body bytes, decode with the Z2 codec, dispatch.
//! A malformed *body* skips that message (framing is length-delimited and
//! survives); a malformed *header* loses framing and closes the connection.
//!
//! The server owns no RIB lock: every state-touching request becomes a
//! [`RibCommand`] on an mpsc queue that the rousterd main loop drains into
//! the RIB (followed by a reconcile pass). All ZAPI↔internal mapping
//! happens at this edge — `rib`/`common` never see ZAPI types (repo
//! AGENTS.md invariant #1).
//!
//! The reverse direction is [`SessionPush`]: on attach every session hands
//! the driver a push channel (Z3B), and the driver fans event-driven
//! updates down it — NEXTHOP_UPDATE when a registered nexthop's resolution
//! flips on a dataplane event, REDISTRIBUTE_ROUTE_ADD when a best route
//! changes and the session registered interest in its type, and (W2)
//! REDISTRIBUTE_ROUTE_DEL when that best route is withdrawn. Pushes are
//! never dropped silently by this side: the session interleaves them with
//! request replies through one writer, so frame order on the wire is the
//! order the session produced it in.
//!
//! The first HELLO also reports the session's identity to the driver (M6):
//! bgpd's reconnect burst omits REDISTRIBUTE_ADD (pinned doc, operational
//! finding 5), so the driver remembers redistribute registrations per
//! client identity and replays the current state as a delta when the same
//! identity re-establishes — a reconnecting bgpd resyncs without
//! re-registering.
//!
//! Wire-behavior pins: reply to HELLO by echoing the client's body
//! (pinned doc, operational finding 2); answer LABEL_MANAGER_CONNECT with
//! proto+instance+result or bgpd's label-manager client stalls
//! (finding 3); the socket must be writable by the (unprivileged) FRR
//! daemons (finding 1). FRR 10.2.2 speaks ZAPI version 6 only.

use std::collections::{BTreeMap, BTreeSet};
use std::io;
use std::net::Ipv4Addr;
use std::path::Path;

use common::{IpPrefix, Nexthop, RouteEntry, RouteProtocol, TableId};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadHalf};
use tokio::net::UnixListener;
use tokio::sync::{mpsc, oneshot};
use tracing::{debug, info, warn};

use crate::client::route_type_from;
use crate::header::{ZapiHeader, ZAPI_HEADER_LEN, ZAPI_VERSION};
use crate::message::{
    blackhole_type, iff, route_type, ZapiInterface, ZapiInterfaceAddress, ZapiMessage, ZapiNexthop,
    ZapiNexthopUpdate, ZapiRoute, ZapiRouterIdUpdate,
};

/// The table all default-VRF client routes land in tonight (RT_TABLE_MAIN).
/// The message's vrf_id selects it: 0 (default VRF) → 254; non-zero VRFs are
/// out of scope for tonight and dropped with a warning.
pub const DEFAULT_TABLE: TableId = 254;

/// ZEBRA_FLAG_SELECTED (frr-10.2.2 `lib/zclient.h`): every route this
/// server pushes via REDISTRIBUTE_ROUTE_ADD is by construction the
/// selected (best) path, and `zsend_redistribute_route` passes `re->flags`
/// through with exactly this bit set in that case (pinned doc, Z2B).
const ZEBRA_FLAG_SELECTED: u32 = 0x08;

/// Per-session push queue depth. Bounded so a daemon that stops reading
/// its socket cannot grow rousterd's memory without bound; the driver
/// drops (with a warning) when full — a genuinely stuck client re-syncs
/// on its next registration or reconnect.
const SESSION_PUSH_QUEUE: usize = 64;

/// A request from a ZAPI session to the RIB owner (rousterd's main loop).
///
/// Typed end to end — no `Box<dyn Any>`, no ZAPI structs leaking past this
/// edge: wire values are mapped to `common` types before a command is
/// built. Variants with a `reply` channel need an answer before the
/// session can continue (interface dump, NHT lookup).
#[derive(Debug)]
pub enum RibCommand {
    /// Session attach (sent by [`serve`] at accept time, before the session
    /// task starts): hands the RIB owner the push channel for `owner`.
    /// FIFO ordering through the command channel guarantees the driver has
    /// this sender before it can see any other command from the session —
    /// so a push triggered by a later command never races a missing
    /// registration.
    AttachSession {
        owner: u64,
        push: mpsc::Sender<SessionPush>,
    },
    /// First HELLO on a connection (session establish, M6): announces the
    /// client's identity — `(redist_default, instance, session_id)` from
    /// the HELLO body, stable across a daemon's reconnects and distinct
    /// between bgpd's three connections. The driver adopts any
    /// redistribute registrations it remembers for the identity and dumps
    /// the current state as a delta (REDISTRIBUTE_ROUTE_ADD per present
    /// route of the registered types, DEL per route the identity was last
    /// told about that no longer exists): bgpd's reconnect burst omits
    /// REDISTRIBUTE_ADD (pinned doc, operational finding 5), so without
    /// this a reconnecting bgpd stays stale (B1 deadlock-risk D2).
    /// Fire-and-forget — the dump rides the push channel; FIFO through
    /// this channel guarantees the driver saw [`AttachSession`] first.
    SessionEstablished {
        owner: u64,
        protocol: u8,
        instance: u16,
        session_id: u32,
    },
    AddRoute(RouteEntry),
    DeleteRoute {
        table: TableId,
        prefix: IpPrefix,
        protocol: RouteProtocol,
    },
    /// NEXTHOP_REGISTER: record the tracking interest (Z3B re-evaluates it
    /// on dataplane events) and answer with the current resolution —
    /// `Some(hop)` resolved, `None` unresolved.
    RegisterNexthop {
        owner: u64,
        prefix: IpPrefix,
        reply: oneshot::Sender<Option<Nexthop>>,
    },
    /// NEXTHOP_UNREGISTER.
    UnregisterNexthop {
        owner: u64,
        prefix: IpPrefix,
    },
    /// REDISTRIBUTE_ADD. Recorded per session; pushing
    /// REDISTRIBUTE_ROUTE_ADD on best-route change is Z3B territory.
    RegisterRedistribute {
        owner: u64,
        afi: u8,
        route_type: u8,
        instance: u16,
    },
    /// REDISTRIBUTE_DELETE.
    UnregisterRedistribute {
        owner: u64,
        afi: u8,
        route_type: u8,
        instance: u16,
    },
    /// INTERFACE_ADD request: the driver answers with the interface mirror
    /// snapshot, which the session encodes back to the client.
    RequestInterfaces {
        reply: oneshot::Sender<Vec<InterfaceMirror>>,
    },
    /// ROUTER_ID_ADD (16): the driver answers with the router-id it derives
    /// from the interface mirror (`None` = no IPv4 address to derive from);
    /// the session encodes a ROUTER_ID_UPDATE (18) reply when `Some`.
    RequestRouterId {
        reply: oneshot::Sender<Option<Ipv4Addr>>,
    },
}

/// Interface state snapshot the driver sends back to answer an
/// INTERFACE_ADD request. Internal-typed twin of the RIB's interface
/// mirror; the session encodes it into wire INTERFACE_ADD (+ address)
/// messages. Keeping this internal-typed means the zapi crate needs no
/// dependency on `rib`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InterfaceMirror {
    pub ifindex: u32,
    pub name: String,
    pub is_up: bool,
    /// Configured addresses (host prefixes) — sent as
    /// INTERFACE_ADDRESS_ADD per address.
    pub addresses: Vec<IpPrefix>,
}

/// One NEXTHOP_REGISTER recorded by a session (bookkeeping for Z3B's
/// event-driven re-evaluation; not otherwise consumed tonight).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NhtRegistration {
    pub safi: u16,
    pub connected: bool,
}

/// An event-driven push from the RIB owner (rousterd's main loop) to one
/// ZAPI session — the driver-side counterpart of [`RibCommand`]. Internal
/// types only: the session maps them onto wire bodies at this edge
/// ([`ZapiSession::handle_push`]).
#[derive(Debug)]
pub enum SessionPush {
    /// A registered nexthop's resolution flipped (dataplane event); the
    /// session answers with NEXTHOP_UPDATE. `None` = now unresolved.
    NexthopResolution {
        prefix: IpPrefix,
        resolution: Option<Nexthop>,
    },
    /// The best route for a prefix changed and this session registered
    /// REDISTRIBUTE interest in its type; answered as
    /// REDISTRIBUTE_ROUTE_ADD. Nexthops are in push form — gateway hops
    /// resolved to ifindex-carrying form where the RIB can resolve them
    /// (gateway-form otherwise, exactly what an NHT-tracking client
    /// expects).
    RedistributeRouteAdd(RouteEntry),
    /// The best route for a prefix was withdrawn and this session
    /// registered REDISTRIBUTE interest in its type; answered as
    /// ZEBRA_REDISTRIBUTE_ROUTE_DEL (32) carrying the withdrawn route —
    /// the same `zsend_redistribute_route` body as the ADD twin (W2,
    /// closing Z3B's disclosed cut). The entry is the route as it last
    /// was, in push form.
    RedistributeRouteDel(RouteEntry),
}

/// Per-connection session state, established by the HELLO handshake.
///
/// `id` is the server-assigned connection counter and the owner key for
/// registrations: HELLO's `session_id` is NOT unique across one daemon's
/// connections (bgpd runs three: main, auxiliary, label-manager).
#[derive(Debug, Default)]
pub struct ZapiSession {
    pub id: u64,
    /// HELLO `redist_default` — the ZEBRA_ROUTE_* the client announces.
    pub protocol: u8,
    pub instance: u16,
    pub session_id: u32,
    /// Set once any HELLO has been seen.
    pub established: bool,
    /// REDISTRIBUTE_ADD set: (afi, route_type, instance).
    pub redistributes: BTreeSet<(u8, u8, u16)>,
    /// NEXTHOP_REGISTER set, keyed by registered prefix.
    pub nht: BTreeMap<IpPrefix, NhtRegistration>,
    /// BFD_CLIENT_REGISTER count — mirrors zebra's per-client
    /// `bfd_client_reg_cnt` (frr-10.2.2 `zebra/zebra_ptm.c`); clients
    /// re-send the registration on reconnect replay (`lib/bfd.c`
    /// `zclient_bfd_session_replay`), so the count can exceed one per
    /// connection lifetime.
    pub bfd_client_reg_cnt: u32,
    /// The pid from the most recent BFD_CLIENT_REGISTER (`getpid()` of
    /// the registering daemon — the value real zebra forwards to the BFD
    /// daemon; recorded here, no consumer tonight).
    pub bfd_pid: Option<u32>,
}

/// Accept loop for ZAPI clients. Runs until the task is stopped; every
/// accepted connection gets its own session task sharing `commands`.
///
/// The socket file is world-writable (0666): FRR daemons drop privileges
/// to user `frr` and need WRITE permission on the socket file (pinned
/// doc, operational finding 1). Production ownership management can come
/// with the frr.conf/vtysh edge work.
pub async fn serve(socket_path: &Path, commands: mpsc::Sender<RibCommand>) -> io::Result<()> {
    if socket_path.exists() {
        std::fs::remove_file(socket_path)?;
    }
    let listener = UnixListener::bind(socket_path)?;
    let _ = std::fs::set_permissions(
        socket_path,
        std::os::unix::fs::PermissionsExt::from_mode(0o666),
    );
    info!(path = %socket_path.display(), "zapi: listening");

    let mut next_id = 0u64;
    loop {
        match listener.accept().await {
            Ok((stream, _addr)) => {
                next_id += 1;
                let id = next_id;
                let commands = commands.clone();
                let (push_tx, push_rx) = mpsc::channel(SESSION_PUSH_QUEUE);
                // Attach before the session runs: the driver must hold the
                // push sender by the time it processes anything else from
                // this connection. A closed command channel means no RIB
                // owner — drop the connection rather than run a session
                // that can never touch the RIB.
                if commands
                    .send(RibCommand::AttachSession {
                        owner: id,
                        push: push_tx,
                    })
                    .await
                    .is_err()
                {
                    warn!(id, "zapi: no RIB owner; dropping connection");
                    continue;
                }
                tokio::spawn(async move {
                    match run_session(stream, id, commands, push_rx).await {
                        Ok(session) => {
                            info!(id, protocol = session.protocol, "zapi: session closed");
                        }
                        Err(err) => warn!(id, %err, "zapi: session ended"),
                    }
                });
            }
            Err(err) => {
                warn!(%err, "zapi: accept failed");
            }
        }
    }
}

/// One connection's message loop. Returns the final session state when the
/// peer disconnects (EOF at a message boundary or mid-body), an error when
/// the header-level contract is broken (malformed header, unsupported
/// version) — the connection is closed in both cases.
///
/// Structured as a framing reader task plus a handler loop so the session
/// can serve two directions at once: client requests (via the reader) and
/// event-driven pushes from the RIB owner (via `pushes`). `read_exact` is
/// not cancel-safe — partial reads must never be discarded — so the reader
/// runs as its own task and the handler receives whole frames on a
/// channel; both directions serialize through the single writer the
/// handler owns, keeping wire order well-defined.
///
/// `IO` is generic so tests can drive the loop over `tokio::io::duplex`;
/// `Send + 'static` because the reader half moves into its task.
pub async fn run_session<IO>(
    io: IO,
    id: u64,
    commands: mpsc::Sender<RibCommand>,
    mut pushes: mpsc::Receiver<SessionPush>,
) -> io::Result<ZapiSession>
where
    IO: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let mut session = ZapiSession {
        id,
        ..ZapiSession::default()
    };
    let (reader, mut writer) = tokio::io::split(io);
    let (frames_tx, mut frames_rx) = mpsc::channel::<Result<(ZapiHeader, Vec<u8>), io::Error>>(8);
    let reading = tokio::spawn(read_frames(id, reader, frames_tx));
    // A closed push channel downgrades the session to request/reply (the
    // RIB owner dropped this session's push sender — e.g. at driver
    // shutdown); it does not end the connection.
    let mut pushes_open = true;
    let result = loop {
        tokio::select! {
            frame = frames_rx.recv() => match frame {
                // Reader ended at a clean boundary (or mid-body): the peer
                // went away; this is a normal close.
                None => break Ok(session),
                Some(Err(err)) => break Err(err),
                Some(Ok((header, body))) => {
                    let message = match ZapiMessage::decode(header.command, &body) {
                        Ok(message) => message,
                        Err(err) => {
                            // One bad body does not lose framing
                            // (length-delimited): skip the message, keep
                            // the connection.
                            warn!(
                                id,
                                command = header.command,
                                %err,
                                "zapi: malformed body, skipping message"
                            );
                            continue;
                        }
                    };
                    if !session.established {
                        debug!(id, command = header.command, "zapi: message before HELLO");
                    }
                    if let Err(err) =
                        session.handle(message, header.vrf_id, &commands, &mut writer).await
                    {
                        break Err(err);
                    }
                }
            },
            push = pushes.recv(), if pushes_open => match push {
                None => pushes_open = false,
                Some(push) => {
                    if let Err(err) = session.handle_push(push, &mut writer).await {
                        break Err(err);
                    }
                }
            },
        }
    };
    reading.abort();
    result
}

/// The framing half of a session: reads exactly one 10-byte header, then
/// exactly `length - header` body bytes, and forwards whole frames to the
/// session handler. FRR clients always send whole frames, so `read_exact`
/// framing is exact (no resync needed on clean peers). Header-level
/// garbage loses framing — resync is not worth it for a versioned
/// protocol — so it is reported as an error and the connection closes.
async fn read_frames<IO>(
    id: u64,
    mut io: ReadHalf<IO>,
    frames: mpsc::Sender<Result<(ZapiHeader, Vec<u8>), io::Error>>,
) where
    IO: AsyncRead + Unpin,
{
    loop {
        let mut header_buf = [0u8; ZAPI_HEADER_LEN];
        match io.read_exact(&mut header_buf).await {
            Ok(_) => {}
            Err(err) if err.kind() == io::ErrorKind::UnexpectedEof => return,
            Err(err) => {
                let _ = frames.send(Err(err)).await;
                return;
            }
        }
        let header = match ZapiHeader::decode(&header_buf) {
            Ok(header) => header,
            Err(err) => {
                warn!(id, %err, "zapi: malformed header, closing connection");
                let _ = frames
                    .send(Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        err.to_string(),
                    )))
                    .await;
                return;
            }
        };
        if header.version != ZAPI_VERSION {
            warn!(
                id,
                version = header.version,
                expected = ZAPI_VERSION,
                "zapi: unsupported ZAPI version, closing connection"
            );
            let _ = frames
                .send(Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("unsupported ZAPI version {}", header.version),
                )))
                .await;
            return;
        }
        let mut body = vec![0u8; header.length as usize - ZAPI_HEADER_LEN];
        match io.read_exact(&mut body).await {
            Ok(_) => {}
            Err(err) if err.kind() == io::ErrorKind::UnexpectedEof => return,
            Err(err) => {
                let _ = frames.send(Err(err)).await;
                return;
            }
        }
        if frames.send(Ok((header, body))).await.is_err() {
            return; // session handler gone
        }
    }
}

/// Maps a resolved internal hop back onto the wire nexthop shape.
fn zapi_nexthop_from(hop: Nexthop) -> ZapiNexthop {
    match hop {
        Nexthop::Ipv4(gate) => ZapiNexthop::new_ipv4(0, gate),
        Nexthop::Ipv6(gate) => ZapiNexthop::new_ipv6(0, gate),
        Nexthop::IfIndex(ifindex) => ZapiNexthop::new_ifindex(0, ifindex),
        Nexthop::Ipv4If(gate, ifindex) => ZapiNexthop::new_ipv4_ifindex(0, gate, ifindex),
        Nexthop::Ipv6If(gate, ifindex) => ZapiNexthop::new_ipv6_ifindex(0, gate, ifindex),
        Nexthop::Blackhole => ZapiNexthop::new_blackhole(0, blackhole_type::NULL),
    }
}

fn encode_io_err(err: crate::ZapiCodecError) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, err.to_string())
}

fn channel_closed() -> io::Error {
    io::Error::new(io::ErrorKind::BrokenPipe, "rib command channel closed")
}

/// Synthesizes the link-flags word for the interface mirror. The RIB
/// mirror tracks only up/down, but protocol daemons gate hard on the
/// classic IFF bits: with flags 0 ospfd reports every interface down
/// (`if_is_operative` needs UP|RUNNING) and without BROADCAST|MULTICAST
/// it falls back to the non-broadcast network type, which never sends
/// hellos. Loopback names follow the driver's `lo`-prefix convention
/// (the mirror has no IFF_LOOPBACK bit of its own). DOWN links carry no
/// bits, matching a kernel dump of a down link.
fn mirror_link_flags(name: &str, is_up: bool) -> u64 {
    if !is_up {
        return 0;
    }
    let base = iff::UP | iff::RUNNING;
    if name.starts_with("lo") {
        base | iff::LOOPBACK
    } else {
        base | iff::BROADCAST | iff::MULTICAST
    }
}

impl ZapiSession {
    /// Dispatches one decoded message: mutate session state, queue
    /// [`RibCommand`]s, write replies. ZAPI↔internal mapping happens here.
    async fn handle<W>(
        &mut self,
        message: ZapiMessage,
        vrf_id: u32,
        commands: &mpsc::Sender<RibCommand>,
        io: &mut W,
    ) -> io::Result<()>
    where
        W: AsyncWrite + Unpin,
    {
        match message {
            ZapiMessage::Hello(hello) => {
                if !self.established {
                    self.established = true;
                    info!(
                        id = self.id,
                        protocol = hello.redist_default,
                        instance = hello.instance,
                        session = hello.session_id,
                        "zapi: session established"
                    );
                    // M6: report the client's identity so the driver can
                    // replay redistribute registrations remembered from a
                    // previous connection of the same daemon.
                    commands
                        .send(RibCommand::SessionEstablished {
                            owner: self.id,
                            protocol: hello.redist_default,
                            instance: hello.instance,
                            session_id: hello.session_id,
                        })
                        .await
                        .map_err(|_| channel_closed())?;
                }
                self.protocol = hello.redist_default;
                self.instance = hello.instance;
                self.session_id = hello.session_id;
                // Echo the client's HELLO back — empirically accepted by
                // staticd and bgpd (pinned doc, operational finding 2).
                let reply = ZapiMessage::Hello(hello)
                    .encode_frame(0)
                    .map_err(encode_io_err)?;
                io.write_all(&reply).await
            }

            ZapiMessage::InterfaceAddRequest => {
                let (reply_tx, reply_rx) = oneshot::channel();
                commands
                    .send(RibCommand::RequestInterfaces { reply: reply_tx })
                    .await
                    .map_err(|_| channel_closed())?;
                let mirror = reply_rx.await.map_err(|_| channel_closed())?;
                for intf in &mirror {
                    let mut wire = ZapiInterface::new(&intf.name, intf.ifindex);
                    wire.status = u8::from(intf.is_up);
                    wire.flags = mirror_link_flags(&intf.name, intf.is_up);
                    let frame = ZapiMessage::InterfaceAdd(wire)
                        .encode_frame(0)
                        .map_err(encode_io_err)?;
                    io.write_all(&frame).await?;
                    for &address in &intf.addresses {
                        let frame = ZapiMessage::InterfaceAddressAdd(ZapiInterfaceAddress {
                            ifindex: intf.ifindex,
                            flags: 0,
                            address,
                            destination: None,
                        })
                        .encode_frame(0)
                        .map_err(encode_io_err)?;
                        io.write_all(&frame).await?;
                    }
                }
                io.flush().await
            }

            ZapiMessage::RouteAdd(route) => {
                if vrf_id != 0 {
                    warn!(id = self.id, vrf_id, prefix = %route.prefix,
                          "zapi: route in non-default VRF dropped (per-VRF tables out of scope)");
                    return Ok(());
                }
                match route.to_route_entry() {
                    Some(mut entry) => {
                        entry.table = DEFAULT_TABLE;
                        info!(id = self.id, prefix = %entry.prefix, ?entry.protocol,
                              "zapi: route add");
                        commands
                            .send(RibCommand::AddRoute(entry))
                            .await
                            .map_err(|_| channel_closed())
                    }
                    None => {
                        warn!(
                            id = self.id,
                            route_type = route.route_type,
                            "zapi: route with unmapped type/nexthops ignored"
                        );
                        Ok(())
                    }
                }
            }

            ZapiMessage::RouteDelete(route) => {
                if vrf_id != 0 {
                    warn!(id = self.id, vrf_id, prefix = %route.prefix,
                          "zapi: route delete in non-default VRF dropped (per-VRF tables out of scope)");
                    return Ok(());
                }
                match route.protocol() {
                    Some(protocol) => {
                        info!(id = self.id, prefix = %route.prefix, ?protocol,
                              "zapi: route delete");
                        commands
                            .send(RibCommand::DeleteRoute {
                                table: DEFAULT_TABLE,
                                prefix: route.prefix,
                                protocol,
                            })
                            .await
                            .map_err(|_| channel_closed())
                    }
                    None => {
                        warn!(
                            id = self.id,
                            route_type = route.route_type,
                            "zapi: route delete with unmapped type ignored"
                        );
                        Ok(())
                    }
                }
            }

            ZapiMessage::NexthopRegister(register) => {
                self.nht.insert(
                    register.prefix,
                    NhtRegistration {
                        safi: register.safi,
                        connected: register.connected,
                    },
                );
                let (reply_tx, reply_rx) = oneshot::channel();
                commands
                    .send(RibCommand::RegisterNexthop {
                        owner: self.id,
                        prefix: register.prefix,
                        reply: reply_tx,
                    })
                    .await
                    .map_err(|_| channel_closed())?;
                // Answer immediately from the RIB's current resolution
                // (event-driven re-evaluation is Z3B).
                let resolution = reply_rx.await.unwrap_or(None);
                let update = match resolution.map(zapi_nexthop_from) {
                    Some(hop) => ZapiNexthopUpdate::resolved(
                        register.prefix,
                        register.safi,
                        route_type::CONNECT,
                        0,
                        0,
                        vec![hop],
                    ),
                    None => ZapiNexthopUpdate::unresolved(register.prefix, register.safi),
                };
                let reply = ZapiMessage::NexthopUpdate(update)
                    .encode_frame(0)
                    .map_err(encode_io_err)?;
                io.write_all(&reply).await
            }

            ZapiMessage::NexthopUnregister(register) => {
                self.nht.remove(&register.prefix);
                commands
                    .send(RibCommand::UnregisterNexthop {
                        owner: self.id,
                        prefix: register.prefix,
                    })
                    .await
                    .map_err(|_| channel_closed())
            }

            ZapiMessage::RedistributeAdd(redist) => {
                let key = (redist.afi, redist.route_type, redist.instance);
                self.redistributes.insert(key);
                commands
                    .send(RibCommand::RegisterRedistribute {
                        owner: self.id,
                        afi: redist.afi,
                        route_type: redist.route_type,
                        instance: redist.instance,
                    })
                    .await
                    .map_err(|_| channel_closed())
            }

            ZapiMessage::RedistributeDelete(redist) => {
                let key = (redist.afi, redist.route_type, redist.instance);
                self.redistributes.remove(&key);
                commands
                    .send(RibCommand::UnregisterRedistribute {
                        owner: self.id,
                        afi: redist.afi,
                        route_type: redist.route_type,
                        instance: redist.instance,
                    })
                    .await
                    .map_err(|_| channel_closed())
            }

            ZapiMessage::LabelManagerConnect { proto, instance } => {
                // Reply proto + instance + result(0) or bgpd's
                // label-manager client stalls (pinned doc, finding 3).
                let reply = ZapiMessage::LabelManagerConnectResult {
                    proto,
                    instance,
                    result: 0,
                }
                .encode_frame(0)
                .map_err(encode_io_err)?;
                io.write_all(&reply).await
            }

            ZapiMessage::BfdClientRegister { pid } => {
                // ZEBRA_BFD_CLIENT_REGISTER (36): the client announces
                // itself as a BFD client (body = its pid, pinned doc E).
                // Real zebra sends NO reply on the zapi socket —
                // `zebra_ptm_bfd_client_register` (frr-10.2.2
                // `zebra/zebra_ptm.c`, both HAVE_BFDD variants) bumps
                // `client->bfd_client_reg_cnt` and forwards the pid to
                // the BFD daemon; the sender (`bfd_client_sendmsg`,
                // `lib/bfd.c`) fire-and-forgets without waiting. A
                // guessed ack frame would deviate from zebra, so the
                // recorded registration is the whole answer; BFD
                // session signaling (26–30) is future work.
                self.bfd_client_reg_cnt = self.bfd_client_reg_cnt.saturating_add(1);
                self.bfd_pid = Some(pid);
                info!(
                    id = self.id,
                    pid,
                    registrations = self.bfd_client_reg_cnt,
                    "zapi: BFD client registered (no reply, per zebra)"
                );
                Ok(())
            }
            ZapiMessage::RouteNotifyRequest { flag } => {
                // ROUTE_NOTIFY_REQUEST wants route-owner status updates,
                // answered with ROUTE_NOTIFY_OWNER (11) — whose body layout
                // is NOT-PINNED (no source read, no wire capture; the
                // pinned doc records the gap). The request is therefore
                // left unanswered rather than guessed: staticd (the
                // sender, E in the fixtures) tolerates the silence through
                // full route installation (Z4/Z5 smokes). Loud on purpose
                // so the gap surfaces in every log.
                warn!(
                    id = self.id,
                    flag,
                    "zapi: ROUTE_NOTIFY_REQUEST left unanswered: ROUTE_NOTIFY_OWNER (11) body NOT-PINNED (pinned doc gap)"
                );
                Ok(())
            }
            ZapiMessage::RouterIdAdd { afi } => {
                // Answer with a ROUTER_ID_UPDATE carrying the derived
                // router-id (W2): FRR zebra registers the client and sends
                // its current id; bgpd/staticd use it when config pins
                // none. No IPv4 address yet → no answer (W1 observed both
                // daemons tolerate the silence; the next ROUTER_ID_ADD or
                // reconnect re-asks).
                let (reply_tx, reply_rx) = oneshot::channel();
                commands
                    .send(RibCommand::RequestRouterId { reply: reply_tx })
                    .await
                    .map_err(|_| channel_closed())?;
                match reply_rx.await {
                    Ok(Some(router_id)) => {
                        let reply = ZapiMessage::RouterIdUpdate(ZapiRouterIdUpdate {
                            address: std::net::IpAddr::V4(router_id),
                            prefix_len: 32,
                        })
                        .encode_frame(0)
                        .map_err(encode_io_err)?;
                        io.write_all(&reply).await
                    }
                    Ok(None) => {
                        warn!(
                            id = self.id,
                            afi,
                            "zapi: no IPv4 address to derive a router-id; ROUTER_ID_UPDATE withheld"
                        );
                        Ok(())
                    }
                    Err(_) => Err(channel_closed()),
                }
            }

            ZapiMessage::Unknown { command, body } => {
                debug!(
                    id = self.id,
                    command,
                    len = body.len(),
                    "zapi: unhandled command ignored"
                );
                Ok(())
            }

            // Zebra→client bodies sent *by* a client make no sense; ignore.
            other => {
                debug!(
                    id = self.id,
                    command = other.command(),
                    "zapi: unexpected zebra→client message ignored"
                );
                Ok(())
            }
        }
    }

    /// Encodes one event-driven [`SessionPush`] onto the wire. The session's
    /// own registration metadata completes the picture (the NHT safi); a
    /// push for a prefix the session no longer tracks is dropped — the
    /// driver pruned its registration, so the client withdrew interest.
    async fn handle_push<W>(&mut self, push: SessionPush, io: &mut W) -> io::Result<()>
    where
        W: AsyncWrite + Unpin,
    {
        match push {
            SessionPush::NexthopResolution { prefix, resolution } => {
                let Some(registration) = self.nht.get(&prefix) else {
                    debug!(
                        id = self.id,
                        %prefix,
                        "zapi: NHT push for unregistered prefix dropped"
                    );
                    return Ok(());
                };
                let safi = registration.safi;
                let update = match resolution.map(zapi_nexthop_from) {
                    Some(hop) => ZapiNexthopUpdate::resolved(
                        prefix,
                        safi,
                        route_type::CONNECT,
                        0,
                        0,
                        vec![hop],
                    ),
                    None => ZapiNexthopUpdate::unresolved(prefix, safi),
                };
                info!(
                    id = self.id,
                    %prefix,
                    resolved = update.is_resolved(),
                    "zapi: pushing NEXTHOP_UPDATE"
                );
                let frame = ZapiMessage::NexthopUpdate(update)
                    .encode_frame(0)
                    .map_err(encode_io_err)?;
                io.write_all(&frame).await
            }

            SessionPush::RedistributeRouteAdd(entry) => {
                let route = ZapiRoute::redistribute_push(
                    route_type_from(entry.protocol),
                    0,
                    ZEBRA_FLAG_SELECTED,
                    entry.prefix,
                    entry
                        .nexthops
                        .hops()
                        .iter()
                        .map(|&(hop, _)| ZapiNexthop::from_common(hop))
                        .collect(),
                    entry.protocol.admin_distance(),
                    entry.metric,
                    0,
                    0,
                );
                info!(
                    id = self.id,
                    prefix = %entry.prefix,
                    "zapi: pushing REDISTRIBUTE_ROUTE_ADD"
                );
                let frame = ZapiMessage::RedistributeRouteAdd(route)
                    .encode_frame(0)
                    .map_err(encode_io_err)?;
                io.write_all(&frame).await
            }

            SessionPush::RedistributeRouteDel(entry) => {
                let route = ZapiRoute::redistribute_push(
                    route_type_from(entry.protocol),
                    0,
                    ZEBRA_FLAG_SELECTED,
                    entry.prefix,
                    entry
                        .nexthops
                        .hops()
                        .iter()
                        .map(|&(hop, _)| ZapiNexthop::from_common(hop))
                        .collect(),
                    entry.protocol.admin_distance(),
                    entry.metric,
                    0,
                    0,
                );
                info!(
                    id = self.id,
                    prefix = %entry.prefix,
                    "zapi: pushing REDISTRIBUTE_ROUTE_DEL"
                );
                let frame = ZapiMessage::RedistributeRouteDel(route)
                    .encode_frame(0)
                    .map_err(encode_io_err)?;
                io.write_all(&frame).await
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::message::{
        message_flag, ZapiHello, ZapiNexthopRegister, ZapiRedistribute, ZapiRoute,
    };
    use std::collections::HashMap;
    use std::net::{IpAddr, Ipv4Addr};

    /// Test driver for the command channel: answers RequestInterfaces and
    /// RegisterNexthop from canned state, records everything received.
    /// All methods are async-safe (the tests await them, so the session
    /// task gets scheduled while the driver waits).
    #[derive(Default)]
    struct Driver {
        commands: std::sync::Mutex<Vec<String>>,
        interfaces: Vec<InterfaceMirror>,
        resolutions: std::sync::Mutex<HashMap<IpAddr, Nexthop>>,
        router_id: Option<Ipv4Addr>,
    }

    /// What the driver observed, returned after any reply was sent (the
    /// oneshot senders are consumed by answering, so the observable form
    /// is this summary, not the original command).
    #[derive(Debug)]
    enum Seen {
        Attach,
        Established {
            owner: u64,
            protocol: u8,
            instance: u16,
            session_id: u32,
        },
        Add(RouteEntry),
        Del {
            table: TableId,
            prefix: IpPrefix,
            protocol: RouteProtocol,
        },
        Nht {
            owner: u64,
            prefix: IpPrefix,
        },
        NhtUn {
            owner: u64,
            prefix: IpPrefix,
        },
        Red {
            owner: u64,
            afi: u8,
            route_type: u8,
            instance: u16,
        },
        RedUn,
        Ifaces,
        RouterId,
    }

    fn describe(cmd: &RibCommand) -> String {
        match cmd {
            RibCommand::AttachSession { .. } => "attach".to_string(),
            RibCommand::SessionEstablished { .. } => "establish".to_string(),
            RibCommand::AddRoute(entry) => format!("add {} {:?}", entry.prefix, entry.protocol),
            RibCommand::DeleteRoute { prefix, .. } => format!("del {prefix}"),
            RibCommand::RegisterNexthop { owner, prefix, .. } => format!("nht+ {owner} {prefix}"),
            RibCommand::UnregisterNexthop { owner, prefix } => format!("nht- {owner} {prefix}"),
            RibCommand::RegisterRedistribute { .. } => "red+".to_string(),
            RibCommand::UnregisterRedistribute { .. } => "red-".to_string(),
            RibCommand::RequestInterfaces { .. } => "ifaces".to_string(),
            RibCommand::RequestRouterId { .. } => "router-id".to_string(),
        }
    }

    impl Driver {
        async fn recv(&self, rx: &mut mpsc::Receiver<RibCommand>) -> Seen {
            let cmd = rx.recv().await.expect("command arrives");
            self.commands.lock().unwrap().push(describe(&cmd));
            self.answer(cmd)
        }

        /// Answers the reply-carrying variants (consuming the oneshot
        /// senders) and reports what was observed.
        fn answer(&self, cmd: RibCommand) -> Seen {
            match cmd {
                RibCommand::AttachSession { .. } => Seen::Attach,
                RibCommand::SessionEstablished {
                    owner,
                    protocol,
                    instance,
                    session_id,
                } => Seen::Established {
                    owner,
                    protocol,
                    instance,
                    session_id,
                },
                RibCommand::AddRoute(entry) => Seen::Add(entry),
                RibCommand::DeleteRoute {
                    table,
                    prefix,
                    protocol,
                } => Seen::Del {
                    table,
                    prefix,
                    protocol,
                },
                RibCommand::RegisterNexthop {
                    owner,
                    prefix,
                    reply,
                    ..
                } => {
                    let resolution = self
                        .resolutions
                        .lock()
                        .unwrap()
                        .get(&prefix_addr(&prefix))
                        .copied();
                    let _ = reply.send(resolution);
                    Seen::Nht { owner, prefix }
                }
                RibCommand::UnregisterNexthop { owner, prefix } => Seen::NhtUn { owner, prefix },
                RibCommand::RegisterRedistribute {
                    owner,
                    afi,
                    route_type,
                    instance,
                } => Seen::Red {
                    owner,
                    afi,
                    route_type,
                    instance,
                },
                RibCommand::UnregisterRedistribute { .. } => Seen::RedUn,
                RibCommand::RequestInterfaces { reply } => {
                    let _ = reply.send(self.interfaces.clone());
                    Seen::Ifaces
                }
                RibCommand::RequestRouterId { reply } => {
                    let _ = reply.send(self.router_id);
                    Seen::RouterId
                }
            }
        }
    }

    fn prefix_addr(prefix: &IpPrefix) -> IpAddr {
        match prefix {
            IpPrefix::V4(p) => IpAddr::V4(p.addr()),
            IpPrefix::V6(p) => IpAddr::V6(p.addr()),
        }
    }

    /// Client side of a duplex test: writes frames, reads framed replies.
    struct Client {
        io: tokio::io::DuplexStream,
    }

    impl Client {
        async fn send(&mut self, msg: &ZapiMessage, vrf_id: u32) {
            let frame = msg.encode_frame(vrf_id).expect("encode");
            self.io.write_all(&frame).await.expect("send");
        }

        async fn read_frame(&mut self) -> (ZapiHeader, Vec<u8>) {
            let mut header_buf = [0u8; ZAPI_HEADER_LEN];
            self.io
                .read_exact(&mut header_buf)
                .await
                .expect("reply header");
            let header = ZapiHeader::decode(&header_buf).expect("reply header decodes");
            let mut body = vec![0u8; header.length as usize - ZAPI_HEADER_LEN];
            self.io.read_exact(&mut body).await.expect("reply body");
            (header, body)
        }
    }

    /// Spawns a session (owner id 1) over one end of a duplex pair, plus
    /// the push sender the driver side would hold.
    #[allow(clippy::type_complexity)]
    fn spawn_session(
        capacity: usize,
    ) -> (
        Client,
        mpsc::Receiver<RibCommand>,
        mpsc::Sender<SessionPush>,
        tokio::task::JoinHandle<io::Result<ZapiSession>>,
    ) {
        let (client_io, server_io) = tokio::io::duplex(64 * 1024);
        let (tx, rx) = mpsc::channel(capacity);
        let (push_tx, push_rx) = mpsc::channel(16);
        let task = tokio::spawn(run_session(server_io, 1, tx, push_rx));
        (Client { io: client_io }, rx, push_tx, task)
    }

    fn staticd_hello() -> ZapiMessage {
        ZapiMessage::Hello(ZapiHello {
            redist_default: 4,
            instance: 0,
            session_id: 0,
            synchronous: 0,
        })
    }

    fn bgpd_label_hello() -> ZapiMessage {
        ZapiMessage::Hello(ZapiHello {
            redist_default: 10,
            instance: 0,
            session_id: 1,
            synchronous: 1,
        })
    }

    /// The staticd ROUTE_ADD fixture (203.0.113.0/24 reject-blackhole) as
    /// a codec-built message; `encode_frame` reproduces the captured bytes.
    fn staticd_route_add() -> ZapiMessage {
        ZapiMessage::RouteAdd(ZapiRoute {
            route_type: route_type::STATIC,
            instance: 0,
            flags: 0x41,
            message: message_flag::NEXTHOP | message_flag::DISTANCE,
            safi: 1,
            prefix: "203.0.113.0/24".parse().unwrap(),
            src_prefix: None,
            nhg_id: 0,
            nexthops: vec![ZapiNexthop::new_blackhole(0, blackhole_type::REJECT)],
            backup_nexthops: Vec::new(),
            distance: Some(1),
            metric: None,
            tag: None,
            mtu: None,
            tableid: None,
            opaque: None,
        })
    }

    /// The staticd ROUTE_DELETE fixture shape (198.51.100.0/24, no hops).
    fn staticd_route_delete() -> ZapiMessage {
        ZapiMessage::RouteDelete(ZapiRoute {
            route_type: route_type::STATIC,
            instance: 0,
            flags: 0x41,
            message: message_flag::NEXTHOP | message_flag::DISTANCE,
            safi: 1,
            prefix: "198.51.100.0/24".parse().unwrap(),
            src_prefix: None,
            nhg_id: 0,
            nexthops: Vec::new(),
            backup_nexthops: Vec::new(),
            distance: Some(1),
            metric: None,
            tag: None,
            mtu: None,
            tableid: None,
            opaque: None,
        })
    }

    fn nht_register(prefix: &str) -> ZapiMessage {
        ZapiMessage::NexthopRegister(ZapiNexthopRegister {
            connected: false,
            resolve_via_default: false,
            safi: 1,
            prefix: prefix.parse().unwrap(),
        })
    }

    #[tokio::test]
    async fn hello_echo_reply_records_session() {
        let (mut client, mut rx, _push, task) = spawn_session(16);
        let driver = Driver::default();
        client.send(&staticd_hello(), 0).await;
        let (header, body) = client.read_frame().await;
        assert_eq!(header.command, 19, "HELLO reply");
        assert_eq!(
            body,
            vec![4, 0, 0, 0, 0, 0, 0, 0],
            "echo of the client's 8-byte HELLO body"
        );
        // M6: the FIRST HELLO reports the session's identity to the
        // driver — and nothing else queues a command.
        match driver.recv(&mut rx).await {
            Seen::Established {
                owner,
                protocol,
                instance,
                session_id,
            } => assert_eq!((owner, protocol, instance, session_id), (1, 4, 0, 0)),
            other => panic!("expected SessionEstablished, got {other:?}"),
        }
        assert!(rx.try_recv().is_err(), "no further command");
        drop(client);
        let session = task.await.unwrap().expect("clean close");
        assert!(session.established);
        assert_eq!(
            (session.protocol, session.instance, session.session_id),
            (4, 0, 0)
        );
        assert!(
            driver.commands.lock().unwrap().len() == 1,
            "only the establish command"
        );
        rx.close();
    }

    #[tokio::test]
    async fn bgpd_label_client_hello_recorded() {
        let (mut client, mut rx, _push, task) = spawn_session(16);
        client.send(&bgpd_label_hello(), 0).await;
        let (header, _) = client.read_frame().await;
        assert_eq!(header.command, 19);
        drop(client);
        let session = task.await.unwrap().expect("clean close");
        assert_eq!(session.session_id, 1);
        assert_eq!(session.protocol, 10);
        rx.close();
    }

    #[tokio::test]
    async fn route_add_emits_add_route_command() {
        let (mut client, mut rx, _push, task) = spawn_session(16);
        let driver = Driver::default();
        client.send(&staticd_route_add(), 0).await;
        match driver.recv(&mut rx).await {
            Seen::Add(entry) => {
                assert_eq!(entry.prefix, "203.0.113.0/24".parse::<IpPrefix>().unwrap());
                assert_eq!(entry.protocol, RouteProtocol::Static);
                assert_eq!(entry.table, DEFAULT_TABLE);
                assert_eq!(entry.nexthops.hops(), &[(Nexthop::Blackhole, 1)]);
            }
            other => panic!("expected AddRoute, got {other:?}"),
        }
        drop(client);
        let session = task.await.unwrap().unwrap();
        assert!(
            !session.established,
            "no HELLO seen; message still processed"
        );
    }

    #[tokio::test]
    async fn route_delete_emits_delete_route_command() {
        let (mut client, mut rx, _push, _task) = spawn_session(16);
        let driver = Driver::default();
        client.send(&staticd_route_delete(), 0).await;
        match driver.recv(&mut rx).await {
            Seen::Del {
                table,
                prefix,
                protocol,
            } => {
                assert_eq!(table, DEFAULT_TABLE);
                assert_eq!(prefix, "198.51.100.0/24".parse::<IpPrefix>().unwrap());
                assert_eq!(protocol, RouteProtocol::Static);
            }
            other => panic!("expected DeleteRoute, got {other:?}"),
        }
    }

    /// Proves no command was queued for a message, without blocking: the
    /// session is single-threaded per connection, so once it has replied to
    /// a later HELLO, every earlier message was fully handled — anything it
    /// queued is already in the channel, and `try_recv` sees it. Since M6
    /// a HELLO may legitimately queue exactly one command (the marker's
    /// own `SessionEstablished`); anything else fails.
    async fn assert_no_command_after(client: &mut Client, rx: &mut mpsc::Receiver<RibCommand>) {
        client.send(&staticd_hello(), 0).await;
        let (header, _) = client.read_frame().await;
        assert_eq!(header.command, 19);
        while let Ok(cmd) = rx.try_recv() {
            assert!(
                matches!(cmd, RibCommand::SessionEstablished { .. }),
                "only a HELLO's establish command may be queued, got {cmd:?}"
            );
        }
    }

    #[tokio::test]
    async fn route_add_in_nonzero_vrf_dropped() {
        let (mut client, mut rx, _push, _task) = spawn_session(16);
        client.send(&staticd_route_add(), 7).await;
        assert_no_command_after(&mut client, &mut rx).await;
    }

    #[tokio::test]
    async fn route_add_with_unmapped_type_ignored() {
        let (mut client, mut rx, _push, _task) = spawn_session(16);
        let mut route = match staticd_route_add() {
            ZapiMessage::RouteAdd(route) => route,
            _ => unreachable!(),
        };
        route.route_type = 0; // no ZEBRA_ROUTE_* mapping
        client.send(&ZapiMessage::RouteAdd(route), 0).await;
        assert_no_command_after(&mut client, &mut rx).await;
    }

    fn driver_with_resolution(gateway: IpAddr, hop: Nexthop) -> Driver {
        let driver = Driver::default();
        driver.resolutions.lock().unwrap().insert(gateway, hop);
        driver
    }

    #[tokio::test]
    async fn nht_register_resolved_answer_carries_hop() {
        let (mut client, mut rx, _push, task) = spawn_session(16);
        let driver = driver_with_resolution(
            IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)),
            Nexthop::Ipv4If(Ipv4Addr::new(192, 0, 2, 1), 2),
        );
        client.send(&nht_register("192.0.2.1/32"), 0).await;
        match driver.recv(&mut rx).await {
            Seen::Nht { owner, prefix } => {
                assert_eq!(owner, 1);
                assert_eq!(prefix, "192.0.2.1/32".parse::<IpPrefix>().unwrap());
            }
            other => panic!("expected RegisterNexthop, got {other:?}"),
        }
        let (header, body) = client.read_frame().await;
        assert_eq!(header.command, 23, "NEXTHOP_UPDATE");
        let update = ZapiNexthopUpdate::decode(&body).expect("update decodes");
        assert!(update.is_resolved());
        assert_eq!(update.nexthops.len(), 1);
        assert_eq!(update.nexthops[0].ifindex, 2);
        assert_eq!(
            update.nexthops[0].nh_type,
            crate::nexthop_type::IPV4_IFINDEX
        );
        drop(client);
        let session = task.await.unwrap().unwrap();
        assert_eq!(session.nht.len(), 1, "registration recorded for Z3B");
    }

    #[tokio::test]
    async fn nht_register_unresolved_answer_zeroed_tail() {
        let (mut client, mut rx, _push, _task) = spawn_session(16);
        let driver = Driver::default();
        client.send(&nht_register("10.9.9.9/32"), 0).await;
        driver.recv(&mut rx).await;
        let (_header, body) = client.read_frame().await;
        // Hand-derived zeroed tail for an unresolved /32 (matches the Z2
        // codec unit test byte-for-byte).
        let expected: Vec<u8> = vec![
            0, 0, 0, 0, // message
            0, 1, // safi
            0, 2, 32, 10, 9, 9, 9, // registered 10.9.9.9/32
            0, 2, 32, 10, 9, 9, 9, // resolved (echoed)
            0, // route type
            0, 0, // instance
            0, // distance
            0, 0, 0, 0, // metric
            0, // nexthop count
        ];
        assert_eq!(body, expected);
    }

    #[tokio::test]
    async fn nht_unregister_removes_registration() {
        let (mut client, mut rx, _push, task) = spawn_session(16);
        let driver = Driver::default();
        client.send(&nht_register("192.0.2.1/32"), 0).await;
        driver.recv(&mut rx).await;
        let _ = client.read_frame().await; // the update
        client
            .send(
                &ZapiMessage::NexthopUnregister(ZapiNexthopRegister {
                    connected: false,
                    resolve_via_default: false,
                    safi: 1,
                    prefix: "192.0.2.1/32".parse().unwrap(),
                }),
                0,
            )
            .await;
        match driver.recv(&mut rx).await {
            Seen::NhtUn { owner, prefix } => {
                assert_eq!(owner, 1);
                assert_eq!(prefix, "192.0.2.1/32".parse::<IpPrefix>().unwrap());
            }
            other => panic!("expected UnregisterNexthop, got {other:?}"),
        }
        drop(client);
        let session = task.await.unwrap().unwrap();
        assert!(session.nht.is_empty());
    }

    #[tokio::test]
    async fn redistribute_add_delete_recorded_and_forwarded() {
        let (mut client, mut rx, _push, task) = spawn_session(16);
        let driver = Driver::default();
        let redist = ZapiRedistribute {
            afi: 1,
            route_type: route_type::STATIC,
            instance: 0,
        };
        client.send(&ZapiMessage::RedistributeAdd(redist), 0).await;
        match driver.recv(&mut rx).await {
            Seen::Red {
                owner,
                afi,
                route_type,
                instance,
            } => assert_eq!((owner, afi, route_type, instance), (1, 1, 4, 0)),
            other => panic!("expected RegisterRedistribute, got {other:?}"),
        }
        client
            .send(&ZapiMessage::RedistributeDelete(redist), 0)
            .await;
        assert!(matches!(driver.recv(&mut rx).await, Seen::RedUn));
        drop(client);
        let session = task.await.unwrap().unwrap();
        assert!(session.redistributes.is_empty(), "tonight: store only");
    }

    // --- Event-driven pushes (Z3B) ---

    /// Registers a nexthop and consumes the session's immediate answer, so
    /// the next frame the client reads is unambiguous.
    async fn register_and_drain_answer(
        client: &mut Client,
        rx: &mut mpsc::Receiver<RibCommand>,
        driver: &Driver,
        prefix: &str,
    ) {
        client.send(&nht_register(prefix), 0).await;
        driver.recv(rx).await;
        let (header, _) = client.read_frame().await;
        assert_eq!(header.command, 23, "the immediate NEXTHOP_UPDATE");
    }

    #[tokio::test]
    async fn nht_flip_push_writes_resolved_update() {
        let (mut client, mut rx, push, _task) = spawn_session(16);
        let driver = Driver::default();
        register_and_drain_answer(&mut client, &mut rx, &driver, "10.9.9.9/32").await;

        // The dataplane grew a covering subnet: the driver re-evaluated and
        // the resolution flipped to ifindex-carrying form.
        push.send(SessionPush::NexthopResolution {
            prefix: "10.9.9.9/32".parse().unwrap(),
            resolution: Some(Nexthop::Ipv4If(Ipv4Addr::new(10, 9, 9, 9), 2)),
        })
        .await
        .expect("session alive");

        let (header, body) = client.read_frame().await;
        assert_eq!(header.command, 23, "flip pushes NEXTHOP_UPDATE");
        let update = ZapiNexthopUpdate::decode(&body).expect("update decodes");
        assert!(update.is_resolved());
        assert_eq!(update.registered_prefix, "10.9.9.9/32".parse().unwrap());
        assert_eq!(update.nexthops.len(), 1);
        assert_eq!(update.nexthops[0].ifindex, 2);
        assert_eq!(
            update.nexthops[0].nh_type,
            crate::nexthop_type::IPV4_IFINDEX
        );
    }

    #[tokio::test]
    async fn nht_flip_push_unresolved_writes_zeroed_tail() {
        let (mut client, mut rx, push, _task) = spawn_session(16);
        let driver = driver_with_resolution(
            IpAddr::V4(Ipv4Addr::new(192, 0, 2, 9)),
            Nexthop::Ipv4If(Ipv4Addr::new(192, 0, 2, 9), 2),
        );
        register_and_drain_answer(&mut client, &mut rx, &driver, "192.0.2.9/32").await;

        // The carrying address went away: flip to unresolved.
        push.send(SessionPush::NexthopResolution {
            prefix: "192.0.2.9/32".parse().unwrap(),
            resolution: None,
        })
        .await
        .expect("session alive");

        let (_header, body) = client.read_frame().await;
        // The same zeroed-tail shape as the immediate unresolved answer
        // (byte-pinned in nht_register_unresolved_answer_zeroed_tail).
        let expected: Vec<u8> = vec![
            0, 0, 0, 0, // message
            0, 1, // safi
            0, 2, 32, 192, 0, 2, 9, // registered 192.0.2.9/32
            0, 2, 32, 192, 0, 2, 9, // resolved (echoed)
            0, // route type
            0, 0, // instance
            0, // distance
            0, 0, 0, 0, // metric
            0, // nexthop count
        ];
        assert_eq!(body, expected, "unresolve pushes the zeroed-tail form");
    }

    /// A push for a prefix the session no longer tracks must write nothing
    /// (and not error): proven by handing the writer one push and then
    /// reading the client side to EOF — read_to_end collects any bytes the
    /// push did write, so empty means none.
    #[tokio::test]
    async fn nht_push_for_unregistered_prefix_writes_nothing() {
        let mut session = ZapiSession {
            id: 7,
            ..ZapiSession::default()
        };
        let (mut client_io, mut server_io) = tokio::io::duplex(1024);
        session
            .handle_push(
                SessionPush::NexthopResolution {
                    prefix: "10.9.9.9/32".parse().unwrap(),
                    resolution: None,
                },
                &mut server_io,
            )
            .await
            .expect("push for unregistered prefix is a no-op, not an error");
        drop(server_io);
        let mut written = Vec::new();
        use tokio::io::AsyncReadExt;
        client_io.read_to_end(&mut written).await.expect("eof");
        assert!(written.is_empty(), "no frame for an unregistered prefix");
    }

    /// The redistribute push encodes as command 31 with the
    /// zsend_redistribute_route bit policy (Z2B): SELECTED flag, DISTANCE +
    /// METRIC + MTU always present, nexthops in push form.
    #[tokio::test]
    async fn redistribute_push_encodes_command_31() {
        let mut session = ZapiSession {
            id: 3,
            ..ZapiSession::default()
        };
        let (mut client_io, mut server_io) = tokio::io::duplex(1024);
        let mut entry = RouteEntry::new(
            "203.0.113.0/24".parse().unwrap(),
            RouteProtocol::Static,
            common::NexthopGroup::single(Nexthop::Blackhole),
            20,
        );
        entry.table = DEFAULT_TABLE;
        session
            .handle_push(SessionPush::RedistributeRouteAdd(entry), &mut server_io)
            .await
            .expect("push encodes");
        drop(server_io);
        let mut bytes = Vec::new();
        use tokio::io::AsyncReadExt;
        client_io.read_to_end(&mut bytes).await.expect("eof");

        let header = ZapiHeader::decode(&bytes[..ZAPI_HEADER_LEN]).unwrap();
        assert_eq!(header.command, 31);
        assert_eq!(
            header.length as usize,
            bytes.len(),
            "exactly one framed message"
        );
        let body = bytes[ZAPI_HEADER_LEN..].to_vec();
        match ZapiMessage::decode(31, &body).unwrap() {
            ZapiMessage::RedistributeRouteAdd(route) => {
                assert_eq!(route.route_type, route_type::STATIC);
                assert_eq!(route.flags, 0x08, "ZEBRA_FLAG_SELECTED");
                assert_eq!(
                    route.message,
                    message_flag::NEXTHOP
                        | message_flag::DISTANCE
                        | message_flag::METRIC
                        | message_flag::MTU
                );
                assert_eq!(route.prefix, "203.0.113.0/24".parse().unwrap());
                assert_eq!(route.distance, Some(1), "static admin distance");
                assert_eq!(route.metric, Some(20));
                assert_eq!(route.nexthops.len(), 1);
                assert_eq!(route.nexthops[0].nh_type, crate::nexthop_type::BLACKHOLE);
                assert_eq!(route.nexthops[0].gate, None);
            }
            other => panic!("expected RedistributeRouteAdd, got {other:?}"),
        }
    }

    /// The withdrawal twin of `redistribute_push_encodes_command_31`:
    /// command 32, the withdrawn route's prefix/type, SELECTED flag, the
    /// always-set DISTANCE/METRIC/MTU bits, and no nexthop list (the
    /// withdrawn route had none to offer the client).
    #[tokio::test]
    async fn redistribute_del_push_encodes_command_32() {
        let mut session = ZapiSession {
            id: 5,
            ..ZapiSession::default()
        };
        let (mut client_io, mut server_io) = tokio::io::duplex(1024);
        let mut entry = RouteEntry::new(
            "198.51.100.0/24".parse().unwrap(),
            RouteProtocol::Static,
            common::NexthopGroup::single(Nexthop::Blackhole),
            20,
        );
        entry.table = DEFAULT_TABLE;
        session
            .handle_push(SessionPush::RedistributeRouteDel(entry), &mut server_io)
            .await
            .expect("push encodes");
        drop(server_io);
        let mut bytes = Vec::new();
        use tokio::io::AsyncReadExt;
        client_io.read_to_end(&mut bytes).await.expect("eof");

        let header = ZapiHeader::decode(&bytes[..ZAPI_HEADER_LEN]).unwrap();
        assert_eq!(header.command, 32, "ZEBRA_REDISTRIBUTE_ROUTE_DEL");
        assert_eq!(
            header.length as usize,
            bytes.len(),
            "exactly one framed message"
        );
        let body = bytes[ZAPI_HEADER_LEN..].to_vec();
        match ZapiMessage::decode(32, &body).unwrap() {
            ZapiMessage::RedistributeRouteDel(route) => {
                assert_eq!(route.route_type, route_type::STATIC);
                assert_eq!(route.flags, 0x08, "ZEBRA_FLAG_SELECTED");
                assert_eq!(
                    route.message,
                    message_flag::NEXTHOP
                        | message_flag::DISTANCE
                        | message_flag::METRIC
                        | message_flag::MTU,
                    "NEXTHOP bit because the withdrawn route had a hop (the bit \
                     is gated on the hop count, per zsend_redistribute_route)"
                );
                assert_eq!(route.prefix, "198.51.100.0/24".parse().unwrap());
                assert_eq!(route.distance, Some(1), "static admin distance");
                assert_eq!(route.metric, Some(20));
                assert_eq!(route.nexthops.len(), 1);
                assert_eq!(route.nexthops[0].nh_type, crate::nexthop_type::BLACKHOLE);
            }
            other => panic!("expected RedistributeRouteDel, got {other:?}"),
        }
    }

    /// ROUTER_ID_ADD is answered with a ROUTER_ID_UPDATE carrying the
    /// driver-derived id: body `family u8 | address | prefixlen u8` per the
    /// pinned doc (SRC: zebra_router_id_update_read) — byte-pinned here.
    #[tokio::test]
    async fn router_id_add_answered_with_derived_update() {
        let (mut client, mut rx, _push, _task) = spawn_session(16);
        let driver = Driver {
            router_id: Some(Ipv4Addr::new(192, 168, 1, 1)),
            ..Driver::default()
        };
        client.send(&ZapiMessage::RouterIdAdd { afi: 1 }, 0).await;
        match driver.recv(&mut rx).await {
            Seen::RouterId => {}
            other => panic!("expected RequestRouterId, got {other:?}"),
        }
        let (header, body) = client.read_frame().await;
        assert_eq!(header.command, 18, "ZEBRA_ROUTER_ID_UPDATE");
        assert_eq!(
            body,
            vec![crate::message::AF_INET as u8, 192, 168, 1, 1, 32],
            "family AF_INET, the address, prefixlen 32 (address BEFORE length)"
        );
        let update = crate::ZapiRouterIdUpdate::decode(&body).expect("update decodes");
        assert_eq!(
            update,
            crate::ZapiRouterIdUpdate {
                address: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)),
                prefix_len: 32,
            }
        );
    }

    /// No derivable id → no ROUTER_ID_UPDATE, connection stays usable (the
    /// next message still gets its reply; W1 observed daemons tolerate the
    /// silence).
    #[tokio::test]
    async fn router_id_add_without_derivable_id_answers_nothing() {
        let (mut client, mut rx, _push, _task) = spawn_session(16);
        let driver = Driver::default();
        client.send(&ZapiMessage::RouterIdAdd { afi: 1 }, 0).await;
        match driver.recv(&mut rx).await {
            Seen::RouterId => {}
            other => panic!("expected RequestRouterId, got {other:?}"),
        }
        // The HELLO echo arriving FIRST proves no update frame preceded it.
        client.send(&staticd_hello(), 0).await;
        let (header, _) = client.read_frame().await;
        assert_eq!(header.command, 19, "no ROUTER_ID_UPDATE before the echo");
        // The marker HELLO is this session's first: its establish command
        // is the only thing queued.
        assert!(matches!(
            driver.recv(&mut rx).await,
            Seen::Established { .. }
        ));
        assert!(rx.try_recv().is_err(), "no further command");
    }

    /// ROUTE_NOTIFY_REQUEST is recorded but NOT answered: ROUTE_NOTIFY_OWNER
    /// (11) has no pinned body (pinned doc gap, W2 disclosure), and no
    /// answer beats a guessed wire format. Proven by handling one request
    /// and reading the client side to EOF — empty means nothing was
    /// written, and the Ok return means the connection survived.
    #[tokio::test]
    async fn route_notify_request_left_unanswered_alive() {
        let mut session = ZapiSession {
            id: 9,
            ..ZapiSession::default()
        };
        let (mut client_io, mut server_io) = tokio::io::duplex(1024);
        let (tx, mut rx) = mpsc::channel(16);
        session
            .handle(
                ZapiMessage::RouteNotifyRequest { flag: 1 },
                0,
                &tx,
                &mut server_io,
            )
            .await
            .expect("handled without error (NOT-PINNED, not fatal)");
        drop(server_io);
        drop(tx);
        let mut written = Vec::new();
        use tokio::io::AsyncReadExt;
        client_io.read_to_end(&mut written).await.expect("eof");
        assert!(written.is_empty(), "no ROUTE_NOTIFY_OWNER may be written");
        assert!(
            rx.try_recv().is_err(),
            "no RibCommand: nothing to ask the RIB for"
        );
    }

    #[tokio::test]
    async fn label_manager_connect_replied_with_result_zero() {
        let (mut client, mut rx, _push, _task) = spawn_session(16);
        client
            .send(
                &ZapiMessage::LabelManagerConnect {
                    proto: 10,
                    instance: 0,
                },
                0,
            )
            .await;
        let (header, body) = client.read_frame().await;
        assert_eq!(header.command, 49);
        assert_eq!(body, vec![10, 0, 0, 0], "proto, instance, result=0");
        assert!(rx.try_recv().is_err(), "no RibCommand for the RPC");
    }

    /// BFD_CLIENT_REGISTER is answered by RECORDING, not by a frame: real
    /// zebra writes nothing back (`zebra_ptm_bfd_client_register`, frr
    /// 10.2.2 zebra/zebra_ptm.c), so the first frame after the
    /// registration must be the next message's HELLO echo. The pid
    /// (fixture value 373, bgpd-10.2.2.log:6) lands in the session state.
    #[tokio::test]
    async fn bfd_client_register_recorded_without_reply() {
        let (mut client, mut rx, _push, task) = spawn_session(16);
        client
            .send(&ZapiMessage::BfdClientRegister { pid: 373 }, 0)
            .await;
        client.send(&staticd_hello(), 0).await;
        let (header, _) = client.read_frame().await;
        assert_eq!(
            header.command, 19,
            "no BFD reply frame may precede the HELLO echo"
        );
        // The first HELLO's establish command is the whole command traffic.
        assert!(matches!(
            rx.recv().await.expect("establish command"),
            RibCommand::SessionEstablished { .. }
        ));
        assert!(
            rx.try_recv().is_err(),
            "registration is session state only, no further RibCommand"
        );
        drop(client);
        let session = task.await.unwrap().expect("connection survives");
        assert_eq!(session.bfd_pid, Some(373), "pid recorded");
        assert_eq!(session.bfd_client_reg_cnt, 1, "counted once");
        assert!(session.established);
        rx.close();
    }

    /// Re-registration (clients re-send cmd 36 on reconnect replay,
    /// `zclient_bfd_session_replay`): the count accumulates like zebra's
    /// `bfd_client_reg_cnt` and the latest pid wins — still no frames out
    /// (both fixture pids used: 373 then the post-restart 535,
    /// bgpd-10.2.2.log:6/:37).
    #[tokio::test]
    async fn bfd_client_reregister_counts_and_updates_pid() {
        let (mut client, mut rx, _push, task) = spawn_session(16);
        client
            .send(&ZapiMessage::BfdClientRegister { pid: 373 }, 0)
            .await;
        client
            .send(&ZapiMessage::BfdClientRegister { pid: 535 }, 0)
            .await;
        client.send(&staticd_hello(), 0).await;
        let (header, _) = client.read_frame().await;
        assert_eq!(header.command, 19, "still nothing but the echo");
        assert!(matches!(
            rx.recv().await.expect("establish command"),
            RibCommand::SessionEstablished { .. }
        ));
        assert!(rx.try_recv().is_err(), "no further RibCommand either time");
        drop(client);
        let session = task.await.unwrap().expect("connection survives");
        assert_eq!(session.bfd_client_reg_cnt, 2);
        assert_eq!(session.bfd_pid, Some(535), "latest pid wins");
        rx.close();
    }

    #[tokio::test]
    async fn malformed_body_skips_message_and_keeps_connection() {
        let (mut client, mut rx, _push, _task) = spawn_session(16);
        client.send(&staticd_hello(), 0).await;
        let _ = client.read_frame().await;

        // A complete frame whose ROUTE_ADD body cannot parse (family byte
        // 47 is neither AF_INET nor AF_INET6): body-level error → skip the
        // message, framing intact, connection stays up.
        let mut frame = staticd_route_add().encode_frame(0).unwrap().to_vec();
        let family_offset = ZAPI_HEADER_LEN + 1 + 2 + 4 + 4 + 1; // route body prefix
        frame[family_offset] = 47;
        client.io.write_all(&frame).await.expect("send bad body");

        assert_no_command_after(&mut client, &mut rx).await;
    }

    #[tokio::test]
    async fn bad_header_closes_connection() {
        let (mut client, rx, _push, task) = spawn_session(16);
        // length field 4 (< header length): BadLength at header level.
        let mut frame = staticd_hello().encode_frame(0).unwrap().to_vec();
        frame[0] = 0;
        frame[1] = 4;
        client.io.write_all(&frame).await.expect("send bad header");
        let result = task.await.unwrap();
        assert!(result.is_err(), "header-level failure closes the session");
        drop(rx);
    }

    #[tokio::test]
    async fn unsupported_version_closes_connection() {
        let (mut client, rx, _push, task) = spawn_session(16);
        let mut frame = staticd_hello().encode_frame(0).unwrap().to_vec();
        frame[3] = 5; // version 5
        client.io.write_all(&frame).await.expect("send v5 header");
        assert!(task.await.unwrap().is_err());
        drop(rx);
    }

    #[tokio::test]
    async fn unknown_command_ignored_connection_alive() {
        let (mut client, mut rx, _push, _task) = spawn_session(16);
        client
            .send(
                &ZapiMessage::Unknown {
                    command: 200,
                    body: vec![0xde, 0xad, 0xbe, 0xef],
                },
                0,
            )
            .await;
        assert_no_command_after(&mut client, &mut rx).await;
    }

    #[tokio::test]
    async fn interface_add_request_streams_mirror() {
        let (mut client, mut rx, _push, _task) = spawn_session(16);
        let driver = Driver {
            interfaces: vec![
                InterfaceMirror {
                    ifindex: 2,
                    name: "eth0".into(),
                    is_up: true,
                    addresses: vec!["192.0.2.1/24".parse().unwrap()],
                },
                InterfaceMirror {
                    ifindex: 1,
                    name: "lo".into(),
                    is_up: true,
                    addresses: vec!["127.0.0.1/8".parse().unwrap()],
                },
                InterfaceMirror {
                    ifindex: 3,
                    name: "eth1".into(),
                    is_up: false,
                    addresses: vec![],
                },
            ],
            ..Driver::default()
        };
        client.send(&ZapiMessage::InterfaceAddRequest, 0).await;
        match driver.recv(&mut rx).await {
            Seen::Ifaces => {}
            other => panic!("expected RequestInterfaces, got {other:?}"),
        }
        let (h1, b1) = client.read_frame().await;
        assert_eq!(h1.command, 0, "INTERFACE_ADD");
        let intf = crate::ZapiInterface::decode(&b1).unwrap();
        assert_eq!(intf.ifname, "eth0");
        assert_eq!(intf.ifindex, 2);
        assert_eq!(intf.status, 1, "is_up → ACTIVE");
        assert_eq!(
            intf.flags,
            iff::UP | iff::RUNNING | iff::BROADCAST | iff::MULTICAST,
            "UP broadcast link carries the bits ospfd gates on"
        );
        let (h2, b2) = client.read_frame().await;
        assert_eq!(h2.command, 2, "INTERFACE_ADDRESS_ADD");
        let addr = crate::ZapiInterfaceAddress::decode(&b2).unwrap();
        assert_eq!(addr.address, "192.0.2.1/24".parse::<IpPrefix>().unwrap());
        assert_eq!(addr.ifindex, 2);
        let (h3, b3) = client.read_frame().await;
        assert_eq!(h3.command, 0, "INTERFACE_ADD (lo)");
        let lo = crate::ZapiInterface::decode(&b3).unwrap();
        assert_eq!(lo.ifname, "lo");
        assert_eq!(lo.flags, iff::UP | iff::RUNNING | iff::LOOPBACK);
        let (h4, _b4) = client.read_frame().await;
        assert_eq!(h4.command, 2, "INTERFACE_ADDRESS_ADD (lo)");
        let (h5, b5) = client.read_frame().await;
        assert_eq!(h5.command, 0, "INTERFACE_ADD (down eth1)");
        let down = crate::ZapiInterface::decode(&b5).unwrap();
        assert_eq!(down.ifname, "eth1");
        assert_eq!(down.status, 0);
        assert_eq!(down.flags, 0, "DOWN link carries no bits");
    }

    /// Replays the entire staticd Z1 fixture through a session: every
    /// captured frame must decode, drive commands where expected, and the
    /// connection must still be standing afterwards.
    #[tokio::test]
    async fn staticd_fixture_burst_replay() {
        let fixture = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures/staticd-10.2.2.log");
        let text = std::fs::read_to_string(fixture).expect("fixture present");

        let (mut client, rx, _push, task) = spawn_session(256);
        let driver = std::sync::Arc::new(Driver::default());
        let mut frames = 0usize;
        // Only HELLO (echo) and NEXTHOP_REGISTER (update) produce replies;
        // the count lets the test know exactly when the burst is drained
        // (INTERFACE_ADD over an empty mirror produces none).
        let mut expected_replies = 0usize;
        let mut cmd_sequence = Vec::new();
        for line in text.lines() {
            if !line.contains(" msg=") {
                continue;
            }
            let mut hdr = None;
            let mut body = None;
            let mut cmd = None;
            for tok in line.split_whitespace() {
                if let Some(v) = tok.strip_prefix("hdr=") {
                    hdr = Some(unhex(v));
                } else if let Some(v) = tok.strip_prefix("body=") {
                    body = Some(unhex(v));
                } else if let Some(v) = tok.strip_prefix("cmd=") {
                    cmd = Some(v.parse::<u16>().unwrap());
                }
            }
            let (Some(mut hdr), Some(body), Some(cmd)) = (hdr, body, cmd) else {
                panic!("malformed fixture line: {line}");
            };
            hdr.extend(body);
            client.io.write_all(&hdr).await.expect("replay frame");
            frames += 1;
            cmd_sequence.push(cmd);
            if cmd == 19 || cmd == 21 {
                expected_replies += 1;
            }
        }
        assert!(
            frames >= 10,
            "fixture replay covered the full burst ({frames})"
        );

        // Service the command channel while the burst is processed: a
        // NEXTHOP_REGISTER mid-burst blocks its session until answered, so
        // the driver must run concurrently with the client.
        let (burst_done_tx, mut burst_done_rx) = oneshot::channel::<()>();
        let drv = std::sync::Arc::clone(&driver);
        let mut rx = rx;
        let servicing = tokio::spawn(async move {
            let mut adds = 0usize;
            let mut nhts = 0usize;
            let mut done = false;
            while !done {
                tokio::select! {
                    cmd = rx.recv() => match cmd {
                        Some(cmd) => {
                            drv.commands.lock().unwrap().push(describe(&cmd));
                            match drv.answer(cmd) {
                                Seen::Add(_) => adds += 1,
                                Seen::Nht { .. } => nhts += 1,
                                _ => {}
                            }
                        }
                        None => break,
                    },
                    _ = &mut burst_done_rx => {
                        // All frames are handled once the marker HELLO (sent
                        // below) got its reply; drain what is queued, stop.
                        while let Ok(cmd) = rx.try_recv() {
                            drv.commands.lock().unwrap().push(describe(&cmd));
                            match drv.answer(cmd) {
                                Seen::Add(_) => adds += 1,
                                Seen::Nht { .. } => nhts += 1,
                                _ => {}
                            }
                        }
                        done = true;
                    }
                }
            }
            (adds, nhts)
        });

        // Marker HELLO: with the fixture's own replies counted, the last of
        // expected_replies+1 replies is the marker echo — proof the whole
        // burst (including the driver-blocking NEXTHOP_REGISTER) drained.
        client.send(&staticd_hello(), 0).await;
        let mut saw_update = false;
        for i in 0..=expected_replies {
            let (header, _) = client.read_frame().await;
            match header.command {
                19 => {}
                23 => saw_update = true,
                other => panic!("unexpected reply command {other}"),
            }
            if i == expected_replies {
                assert_eq!(header.command, 19, "marker echo arrives last");
            }
        }
        assert!(saw_update, "fixture NEXTHOP_REGISTER answered");
        burst_done_tx.send(()).expect("servicing task alive");
        let (adds, nhts) = servicing.await.expect("servicing task");
        assert!(adds >= 1, "fixture ROUTE_ADD(s) reached the RIB queue");
        assert!(nhts >= 1, "fixture NEXTHOP_REGISTER reached the RIB queue");
        assert_eq!(
            cmd_sequence.iter().filter(|&&c| c == 9).count(),
            adds,
            "every fixture ROUTE_ADD became an AddRoute command"
        );
        assert_eq!(
            cmd_sequence.iter().filter(|&&c| c == 10).count(),
            driver
                .commands
                .lock()
                .unwrap()
                .iter()
                .filter(|d| d.starts_with("del "))
                .count(),
            "every fixture ROUTE_DELETE became a DeleteRoute command"
        );

        drop(client);
        let session = task.await.unwrap().expect("clean close after burst");
        assert!(session.established);
        assert_eq!(session.protocol, 4);
    }

    /// Replays the ospfd Z5C fixture through a session: every captured
    /// frame must decode, both INTERFACE_ADD requests and the
    /// ROUTER_ID_ADD must reach the driver, the HELLO echo and a
    /// ROUTER_ID_UPDATE come back, and the connection survives the burst.
    #[tokio::test]
    async fn ospfd_fixture_burst_replay() {
        let fixture = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures/ospfd-10.2.2.log");
        let text = std::fs::read_to_string(fixture).expect("fixture present");

        let (mut client, rx, _push, task) = spawn_session(256);
        let driver = std::sync::Arc::new(Driver {
            router_id: Some("10.255.1.1".parse::<Ipv4Addr>().unwrap()),
            ..Driver::default()
        });
        let mut frames = 0usize;
        let mut cmd_sequence = Vec::new();
        for line in text.lines() {
            if !line.contains(" msg=") {
                continue;
            }
            let mut hdr = None;
            let mut body = None;
            let mut cmd = None;
            for tok in line.split_whitespace() {
                if let Some(v) = tok.strip_prefix("hdr=") {
                    hdr = Some(unhex(v));
                } else if let Some(v) = tok.strip_prefix("body=") {
                    body = Some(unhex(v));
                } else if let Some(v) = tok.strip_prefix("cmd=") {
                    cmd = Some(v.parse::<u16>().unwrap());
                }
            }
            let (Some(mut hdr), Some(body), Some(cmd)) = (hdr, body, cmd) else {
                panic!("malformed fixture line: {line}");
            };
            hdr.extend(body);
            client.io.write_all(&hdr).await.expect("replay frame");
            frames += 1;
            cmd_sequence.push(cmd);
        }
        // The captured burst: HELLO(redist_default=7 OSPF), INTERFACE_ADD
        // request, BFD_CLIENT_REGISTER (pid), ROUTER_ID_ADD (AFI_IP), and
        // a second INTERFACE_ADD request.
        assert_eq!(cmd_sequence, vec![19, 0, 36, 16, 0]);
        assert_eq!(frames, 5, "full burst replayed");

        // Service the command channel while the burst is processed: the
        // ROUTER_ID_ADD blocks its session until answered, so the driver
        // must run concurrently with the client (the marker HELLO below
        // ends the loop once its echo is the last reply out).
        let (burst_done_tx, mut burst_done_rx) = oneshot::channel::<()>();
        let drv = std::sync::Arc::clone(&driver);
        let servicing = tokio::spawn(async move {
            let mut rx = rx;
            let mut ifaces = 0usize;
            let mut router_ids = 0usize;
            let mut done = false;
            while !done {
                tokio::select! {
                    cmd = rx.recv() => {
                        if let Some(cmd) = cmd {
                            match drv.answer(cmd) {
                                Seen::Ifaces => ifaces += 1,
                                Seen::RouterId => router_ids += 1,
                                _ => {}
                            }
                        } else {
                            break;
                        }
                    }
                    _ = &mut burst_done_rx => {
                        while let Ok(cmd) = rx.try_recv() {
                            match drv.answer(cmd) {
                                Seen::Ifaces => ifaces += 1,
                                Seen::RouterId => router_ids += 1,
                                _ => {}
                            }
                        }
                        done = true;
                    }
                }
            }
            (ifaces, router_ids)
        });

        // Marker HELLO: the fixture's own replies are the HELLO echo and
        // the ROUTER_ID_UPDATE; the marker's echo is the last of three.
        client
            .send(
                &ZapiMessage::Hello(ZapiHello {
                    redist_default: route_type::OSPF,
                    instance: 0,
                    session_id: 0,
                    synchronous: 0,
                }),
                0,
            )
            .await;
        let mut saw_router_id_update = false;
        let mut last_reply_command = 0u16;
        for _ in 0..3 {
            let (header, _body) = client.read_frame().await;
            match header.command {
                19 => {}
                18 => saw_router_id_update = true,
                other => panic!("unexpected reply command {other}"),
            }
            last_reply_command = header.command;
        }
        assert!(
            saw_router_id_update,
            "ROUTER_ID_ADD answered with an update"
        );
        assert_eq!(last_reply_command, 19, "marker echo arrives last");
        burst_done_tx.send(()).expect("servicing task alive");
        let (ifaces, router_ids) = servicing.await.expect("servicing task");
        assert_eq!(ifaces, 2, "both INTERFACE_ADD requests reached the driver");
        assert_eq!(router_ids, 1, "ROUTER_ID_ADD reached the driver");

        drop(client);
        let session = task.await.unwrap().expect("clean close after burst");
        assert!(session.established);
        assert_eq!(session.protocol, 7, "ospfd redist_default = OSPF bit");
    }

    fn unhex(s: &str) -> Vec<u8> {
        assert_eq!(s.len() % 2, 0);
        s.as_bytes()
            .chunks(2)
            .map(|p| u8::from_str_radix(std::str::from_utf8(p).unwrap(), 16).unwrap())
            .collect()
    }
}
