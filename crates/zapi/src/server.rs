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

use common::{IpPrefix, LinkFlags, Nexthop, RouteEntry, RouteProtocol, TableId};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadHalf};
use tokio::net::UnixListener;
use tokio::sync::{mpsc, oneshot};
use tracing::{debug, info, warn};

use crate::client::route_type_from;
use crate::header::{ZapiHeader, ZAPI_HEADER_LEN, ZAPI_VERSION};
use crate::message::{
    blackhole_type, nexthop_flag, route_type, ZapiBfdDestStatus, ZapiBfdSessionCmd, ZapiInterface,
    ZapiInterfaceAddress, ZapiMessage, ZapiNeighNotify, ZapiNexthop, ZapiNexthopUpdate, ZapiRoute,
    ZapiRouterIdUpdate,
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
    /// `Some(hop)` resolved, `None` unresolved. `resolve_via_default`
    /// (wire flag; A23 ospfd fixture) gates the routing-table fallback in
    /// the answer.
    RegisterNexthop {
        owner: u64,
        prefix: IpPrefix,
        resolve_via_default: bool,
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
    /// ROUTER_ID_ADD (16): the driver records `owner` as interested in
    /// router-id changes and answers with the router-id it derives from
    /// the interface mirror (`None` = no IPv4 address to derive from);
    /// the session encodes a ROUTER_ID_UPDATE (18) reply when `Some`.
    /// Later derived-id changes push
    /// [`SessionPush::RouterIdUpdate`] to the same owner (A2, the
    /// `reevaluate_nht` pattern applied to router-id).
    RequestRouterId {
        owner: u64,
        reply: oneshot::Sender<Option<Ipv4Addr>>,
    },
    /// NEIGH_REGISTER (131) / NEIGH_UNREGISTER (132): the client's
    /// per-afi neighbour-change interest (vrf 0 only — the edge's
    /// default-VRF scope). No reply exists on this path (the pinned
    /// capture shows a silent registration that then earns pushes).
    RegisterNeighbourInterest {
        owner: u64,
        afi: u16,
        interested: bool,
    },
    /// ZEBRA_BFD_DEST_REGISTER (27) / UPDATE (29): a client armed a BFD
    /// session for a destination (W1-b). The driver records the
    /// interest and forwards the command to the attached BFD-daemon
    /// session — real zebra's relay (source-inferred shape: the same
    /// command reaches bfdd's zclient). No synchronous reply exists
    /// (the pins: the answer is the later 26 push). `update` carries
    /// which of the two commands the client sent (the relay keeps the
    /// number).
    RegisterBfdDest {
        owner: u64,
        vrf_id: u32,
        cmd: ZapiBfdSessionCmd,
        update: bool,
    },
    /// ZEBRA_BFD_DEST_DEREGISTER (28): drop the interest and forward
    /// the withdrawal to the BFD daemon (also answerless).
    UnregisterBfdDest {
        owner: u64,
        vrf_id: u32,
        cmd: ZapiBfdSessionCmd,
    },
    /// ZEBRA_BFD_CLIENT_REGISTER (36): the client wants BFD state
    /// pushes. The pin: updates fan out to EVERY such client, not just
    /// a destination's registrant — the driver keeps the set.
    BfdClientRegistered {
        owner: u64,
    },
    /// ZEBRA_BFD_DEST_REPLAY (30, 4-byte pid form): the sender IS the
    /// BFD daemon (zebra's identification rule, M1). The driver
    /// replays every recorded registration to it.
    BfdDaemonAttached {
        owner: u64,
        pid: u32,
    },
    /// ZEBRA_BFD_DEST_REPLAY (30, 25-byte form): the daemon reports a
    /// session transition; the driver fans an
    /// INTERFACE_BFD_DEST_UPDATE (26) push out to every registered
    /// client (the fan-out pin).
    BfdDaemonStatusUpdate {
        status: ZapiBfdDestStatus,
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
    /// The VRF context of the INTERFACE_ADD/ADDRESS_ADD frames: 0 for
    /// plain interfaces, the enslaving VRF device's ifindex for slaves,
    /// and the vrf device's OWN ifindex for the vrf device itself — the
    /// header vrf_id of the M4 wire capture (the body carries no master
    /// field; link_ifindex is the veth peer there, not a master).
    pub vrf_id: u32,
    /// The mirrored enslavement (IFLA_MASTER), carried for consumers; NOT
    /// encoded on the wire (W4's mirror field, A12's pass-through
    /// pattern).
    pub master_ifindex: Option<u32>,
    /// The kernel's `ifi_flags` word as mirrored from the dataplane —
    /// relayed VERBATIM into the INTERFACE_ADD flags field (what real
    /// zebra does; the pinned `iff` bits document why: ospfd gates on
    /// UP|RUNNING/BROADCAST|MULTICAST and treats LOOPBACK as a stub).
    pub flags: LinkFlags,
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
    /// `resolve_via_default` from the wire: the registration may be
    /// answered by the routing table (ospfd's NSSA default import check
    /// sets it — A23; staticd/bgpd fixtures send 0).
    pub resolve_via_default: bool,
}

/// An event-driven push from the RIB owner (rousterd's main loop) to one
/// ZAPI session — the driver-side counterpart of [`RibCommand`]. Internal
/// types only: the session maps them onto wire bodies at this edge
/// ([`ZapiSession::handle_push`]).
#[derive(Debug, Clone)]
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
    /// The derived router-id changed and this session registered interest
    /// with ROUTER_ID_ADD (A2); answered as ZEBRA_ROUTER_ID_UPDATE (18)
    /// with the same pinned body as the request answer. Only pushed for
    /// a derivable id — FRR zebra skips registered clients when the id
    /// becomes 0/none (`router_id_update`, zebra/router-id.c, which even
    /// carries a TODO for that case).
    RouterIdUpdate(Ipv4Addr),
    /// A neighbour change for an AF this session registered with
    /// NEIGH_REGISTER (131); answered as ZEBRA_NEIGH_ADDED (128) with
    /// the wire-pinned body (M4 capture: with-MAC and FAILED flavours).
    NeighbourAdded(ZapiNeighNotify),
    /// The withdrawal twin: ZEBRA_NEIGH_REMOVED (129), AF_UNSPEC body
    /// with ndm FAILED (the pinned encoder branch).
    NeighbourRemoved(ZapiNeighNotify),
    /// A BFD registration forwarded to the BFD-daemon session (W1-b):
    /// zebra's relay of a client's 27/29 to the daemon that will run
    /// the session. Shape source-inferred (bfdd's zclient handles 27);
    /// disclosed.
    ForwardBfdRegister {
        cmd: ZapiBfdSessionCmd,
        /// True when the client sent UPDATE (29) — the relay keeps
        /// the command number (wire fidelity to what zebra forwards).
        update: bool,
    },
    /// The DEREGISTER (28) twin of the forward.
    ForwardBfdDeregister(ZapiBfdSessionCmd),
    /// A BFD state change (the daemon's 25-byte report under command
    /// 30, W1-b Phase C) fanned out as ZEBRA_INTERFACE_BFD_DEST_UPDATE
    /// (26) with the wire-pinned 21-byte body.
    BfdDestStatus(ZapiBfdDestStatus),
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
    /// NEIGH_REGISTER interests: the afis this client watches (vrf 0).
    pub neigh_afis: BTreeSet<u16>,
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
    /// ROUTE_NOTIFY_REQUEST (126) flag, recorded like zebra's per-client
    /// `route_notify` bit: the client wants ROUTE_NOTIFY_OWNER (11)
    /// pushes when routes it owns get their status decided. Zebra sends
    /// NO synchronous reply to the request itself (A5 wire capture), so
    /// recording the flag IS the answer; pushing the 11 frames needs
    /// reconcile feedback the driver does not yet surface (deferred,
    /// pinned doc A5 section).
    pub route_notify: bool,
    /// BFD_DEST_REGISTER (27/29) destinations this session armed,
    /// keyed by destination address (W1-b) — the session-side interest
    /// record; the driver keeps the global view.
    pub bfd_destinations: BTreeMap<std::net::IpAddr, ZapiBfdSessionCmd>,
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
    // PERF-P3 M2c: 64 frames of read-ahead (was 8) — with the chunked
    // reader producing ~10³ frames per read, a deeper queue keeps the
    // reader from parking per handful under a mass import; the bound
    // stays trivial (~6 KiB of typical route frames).
    let (frames_tx, mut frames_rx) = mpsc::channel::<Result<(ZapiHeader, Vec<u8>), io::Error>>(64);
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

/// The framing half of a session: reads length-delimited frames
/// (10-byte header, then `length - header` body bytes) and forwards
/// them whole to the session handler. FRR clients always send whole
/// frames, so framing is exact (no resync needed on clean peers).
/// Header-level garbage loses framing — resync is not worth it for a
/// versioned protocol — so it is reported as an error and the
/// connection closes.
///
/// PERF-P3 M2c: the reader is chunked, not per-field `read_exact` —
/// a mass import paid two read syscalls (header, body) per route
/// message on this task; one 64 KiB `read` now frames ~10³ typical
/// IPV4_ROUTE_ADD messages (the census's "2 read_exact syscalls per
/// message" residual). Semantics preserved exactly: any peer close
/// (even mid-frame) is the clean `None`-equivalent return the old
/// `UnexpectedEof` path produced, a bad header or unsupported version
/// errors and closes before the body is consumed, and partial frames
/// accumulate across reads until whole.
async fn read_frames<IO>(
    id: u64,
    mut io: ReadHalf<IO>,
    frames: mpsc::Sender<Result<(ZapiHeader, Vec<u8>), io::Error>>,
) where
    IO: AsyncRead + Unpin,
{
    // One read's size. Frames larger than this simply accumulate
    // across reads; frames smaller fill many per read.
    const READ_CHUNK: usize = 64 * 1024;
    // Unconsumed bytes (a possibly-partial frame at the front).
    let mut buf: Vec<u8> = Vec::with_capacity(READ_CHUNK);
    // Offset of the first unconsumed byte (frames before it are sent).
    let mut consumed = 0usize;
    let mut chunk = vec![0u8; READ_CHUNK];
    loop {
        // Frame everything the buffer already holds.
        while buf.len() - consumed >= ZAPI_HEADER_LEN {
            let header = match ZapiHeader::decode(&buf[consumed..]) {
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
            let total = header.length as usize;
            if buf.len() - consumed < total {
                break; // partial body: read more below
            }
            let body = buf[consumed + ZAPI_HEADER_LEN..consumed + total].to_vec();
            consumed += total;
            if frames.send(Ok((header, body))).await.is_err() {
                return; // session handler gone
            }
        }
        // Drop the consumed front, then fill the buffer with one read.
        buf.drain(..consumed);
        consumed = 0;
        match io.read(&mut chunk).await {
            // Peer went away — the old shape's UnexpectedEof twin:
            // a normal close whether or not a partial frame waits.
            Ok(0) => return,
            Ok(n) => buf.extend_from_slice(&chunk[..n]),
            Err(err) => {
                let _ = frames.send(Err(err)).await;
                return;
            }
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

/// A redistribute-push nexthop: the internal hop with the flags byte and
/// flag-gated tail zebra's live 31 frames carry — the M4 capture shows
/// flags 0x04 (the codec's WEIGHT bit) with an 8-byte weight block whose
/// last byte is 1 (default single-path weight) on the pushed blackhole
/// hop. The flags-0 form also interoperated (z5b/z5d live, bgpd/ospfd
/// consumed it); 0x04 is the byte zebra itself sends.
fn redistribute_nexthop(hop: Nexthop) -> ZapiNexthop {
    let mut wire = match hop {
        Nexthop::Ipv4(gate) => ZapiNexthop::new_ipv4(0, gate),
        Nexthop::Ipv6(gate) => ZapiNexthop::new_ipv6(0, gate),
        Nexthop::IfIndex(ifindex) => ZapiNexthop::new_ifindex(0, ifindex),
        Nexthop::Ipv4If(gate, ifindex) => ZapiNexthop::new_ipv4_ifindex(0, gate, ifindex),
        Nexthop::Ipv6If(gate, ifindex) => ZapiNexthop::new_ipv6_ifindex(0, gate, ifindex),
        Nexthop::Blackhole => ZapiNexthop::new_blackhole(0, blackhole_type::REJECT),
    };
    wire.flags |= nexthop_flag::WEIGHT;
    wire.tail = vec![0, 0, 0, 0, 0, 0, 0, 1];
    wire
}

fn encode_io_err(err: crate::ZapiCodecError) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, err.to_string())
}

fn channel_closed() -> io::Error {
    io::Error::new(io::ErrorKind::BrokenPipe, "rib command channel closed")
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
                    // The kernel's own ifi_flags, relayed verbatim like
                    // zebra does (A12; no name-based synthesis — the
                    // mirror's word is the truth, W1B deviation 1 retired).
                    wire.flags = u64::from(intf.flags.bits());
                    // M4 pin: an enslaved interface's frames carry the
                    // enslaving VRF's id in the HEADER (vrf_id = the vrf
                    // device's ifindex, observed live); the body's
                    // link_ifindex field is NOT the master (it is the
                    // veth peer on real zebra — see the M4 addendum).
                    let frame = ZapiMessage::InterfaceAdd(wire)
                        .encode_frame(intf.vrf_id)
                        .map_err(encode_io_err)?;
                    io.write_all(&frame).await?;
                    for &address in &intf.addresses {
                        let frame = ZapiMessage::InterfaceAddressAdd(ZapiInterfaceAddress {
                            ifindex: intf.ifindex,
                            flags: 0,
                            address,
                            destination: None,
                        })
                        .encode_frame(intf.vrf_id)
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
                        // PERF-P3 M2b (the granted half of PERF-P2's
                        // census item #2): the session layer's per-route
                        // add line joins the driver's at debug — a mass
                        // import logging one info line per route costs
                        // ~0.5-0.7 s of daemon CPU per million and
                        // buries the operator in noise FRR zebra also
                        // avoids (its route adds log at debug). With
                        // both layers demoted, the smokes that grep
                        // 'zapi: route add' start their rousterd with
                        // ROUSTERD_LOG=debug (the knob exists for
                        // exactly this shape of need).
                        debug!(id = self.id, prefix = %entry.prefix, ?entry.protocol,
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
                        // PERF-P3 M2b: the delete twin of the add
                        // demotion above (same census item, same
                        // rationale).
                        debug!(id = self.id, prefix = %route.prefix, ?protocol,
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
                        resolve_via_default: register.resolve_via_default,
                    },
                );
                info!(
                    id = self.id,
                    prefix = %register.prefix,
                    safi = register.safi,
                    connected = register.connected,
                    resolve_via_default = register.resolve_via_default,
                    "zapi: nexthop register"
                );
                let (reply_tx, reply_rx) = oneshot::channel();
                commands
                    .send(RibCommand::RegisterNexthop {
                        owner: self.id,
                        prefix: register.prefix,
                        resolve_via_default: register.resolve_via_default,
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
                // recorded registration is the whole answer (W1-b:
                // the driver additionally keeps the owner in the
                // fan-out set — the pin says updates reach EVERY
                // such client, not just a registrant).
                self.bfd_client_reg_cnt = self.bfd_client_reg_cnt.saturating_add(1);
                self.bfd_pid = Some(pid);
                info!(
                    id = self.id,
                    pid,
                    registrations = self.bfd_client_reg_cnt,
                    "zapi: BFD client registered (no reply, per zebra)"
                );
                if commands
                    .send(RibCommand::BfdClientRegistered { owner: self.id })
                    .await
                    .is_err()
                {
                    return Err(channel_closed());
                }
                Ok(())
            }
            ZapiMessage::BfdDestRegister(cmd) => {
                self.handle_bfd_dest(cmd, false, vrf_id, commands).await
            }
            ZapiMessage::BfdDestUpdate(cmd) => {
                self.handle_bfd_dest(cmd, true, vrf_id, commands).await
            }
            ZapiMessage::BfdDestDeregister(cmd) => {
                // DEREGISTER (28): answerless twin (the probe's
                // mid-window deregister drew zero frames).
                self.bfd_destinations.remove(&cmd.dst);
                info!(id = self.id, dst = %cmd.dst, "zapi: BFD destination deregistered");
                if commands
                    .send(RibCommand::UnregisterBfdDest {
                        owner: self.id,
                        vrf_id,
                        cmd,
                    })
                    .await
                    .is_err()
                {
                    return Err(channel_closed());
                }
                Ok(())
            }
            ZapiMessage::BfdDestReplay { pid } => {
                // The 4-byte form of REPLAY (30): the sender IS the BFD
                // daemon (zebra's identification rule; bfdd's connect
                // burst, Phase A). The driver replays every recorded
                // registration to it. No reply (real zebra answers a
                // daemon's replay with the registration relay itself).
                info!(id = self.id, pid, "zapi: BFD daemon attached (replay form)");
                if commands
                    .send(RibCommand::BfdDaemonAttached {
                        owner: self.id,
                        pid,
                    })
                    .await
                    .is_err()
                {
                    return Err(channel_closed());
                }
                Ok(())
            }
            ZapiMessage::BfdDaemonStatus { pid, status } => {
                // The 25-byte form of REPLAY (30): a session state
                // report from the daemon (Phase C). The driver fans the
                // 26 push out to every BFD-registered client.
                info!(
                    id = self.id,
                    pid,
                    dst = %status.dst,
                    status = status.status,
                    "zapi: BFD daemon status report"
                );
                if commands
                    .send(RibCommand::BfdDaemonStatusUpdate { status })
                    .await
                    .is_err()
                {
                    return Err(channel_closed());
                }
                Ok(())
            }
            ZapiMessage::RouteNotifyRequest { flag } => {
                // ROUTE_NOTIFY_REQUEST: the client (staticd in practice)
                // asks for ROUTE_NOTIFY_OWNER (11) pushes about routes it
                // owns. Zebra answers NOTHING synchronously — A5 wire
                // capture against a real zebra 10.2.2: the only frames a
                // fresh client receives after the request are the connect
                // pushes (CAPABILITIES 20, VRF_ADD 33), and the 11 frame
                // arrives asynchronously once an owned route's install
                // status is decided (body now PINNED in the doc and
                // modeled in the codec). So the zebra-faithful answer is
                // to record the interest, not to write a reply; pushing
                // the 11 frames needs per-route reconcile feedback the
                // driver does not surface yet (disclosed in the pinned
                // doc's A5 section) — staticd tolerates the missing
                // pushes through full route installation (Z4/Z5 smokes).
                self.route_notify = flag != 0;
                info!(
                    id = self.id,
                    flag,
                    "zapi: route-notify request recorded (no synchronous reply, per zebra — A5)"
                );
                Ok(())
            }
            ZapiMessage::RouterIdAdd { afi } => {
                // Answer with a ROUTER_ID_UPDATE carrying the derived
                // router-id (W2) AND register the session for pushes on
                // later id changes (A2) — FRR zebra puts the client on
                // `rid_clients` and re-sends the id whenever the derived
                // value flips on an address/link event. bgpd/staticd use
                // the id when config pins none. No IPv4 address yet → no
                // answer (W1 observed both daemons tolerate the silence;
                // the next ROUTER_ID_ADD or reconnect re-asks — the
                // registration burst always includes cmd 16, pinned doc
                // operational finding 5).
                let (reply_tx, reply_rx) = oneshot::channel();
                commands
                    .send(RibCommand::RequestRouterId {
                        owner: self.id,
                        reply: reply_tx,
                    })
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

            ZapiMessage::NeighRegister(register) => {
                // NEIGH_REGISTER (131): record the per-afi interest and
                // tell the driver. Zebra writes NO reply on this path
                // (the M4 capture: a silent registration that then earns
                // the 128/129 pushes), so recording is the whole answer.
                self.neigh_afis.insert(register.afi);
                info!(id = self.id, afi = register.afi, "zapi: neighbour register");
                commands
                    .send(RibCommand::RegisterNeighbourInterest {
                        owner: self.id,
                        afi: register.afi,
                        interested: true,
                    })
                    .await
                    .map_err(|_| channel_closed())
            }

            ZapiMessage::NeighUnregister(register) => {
                self.neigh_afis.remove(&register.afi);
                commands
                    .send(RibCommand::RegisterNeighbourInterest {
                        owner: self.id,
                        afi: register.afi,
                        interested: false,
                    })
                    .await
                    .map_err(|_| channel_closed())
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
    /// REGISTER (27) / UPDATE (29): arm or re-announce a BFD
    /// destination. The pins: NO synchronous reply (the probe's
    /// register drew zero frames back; the answer is the asynchronous
    /// 26 push when the daemon reports state). The driver records the
    /// interest and relays the command to the BFD daemon, keeping the
    /// command number.
    async fn handle_bfd_dest(
        &mut self,
        cmd: ZapiBfdSessionCmd,
        update: bool,
        vrf_id: u32,
        commands: &mpsc::Sender<RibCommand>,
    ) -> io::Result<()> {
        self.bfd_destinations.insert(cmd.dst, cmd.clone());
        info!(
            id = self.id,
            dst = %cmd.dst,
            update,
            mhop = cmd.mhop,
            min_rx_ms = cmd.min_rx_ms,
            "zapi: BFD destination command (no reply; relay to daemon)"
        );
        commands
            .send(RibCommand::RegisterBfdDest {
                owner: self.id,
                vrf_id,
                cmd,
                update,
            })
            .await
            .map_err(|_| channel_closed())?;
        Ok(())
    }

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
                        .map(|&(hop, _)| redistribute_nexthop(hop))
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

            SessionPush::RouterIdUpdate(router_id) => {
                // Same pinned body as the ROUTER_ID_ADD answer: family u8,
                // address, prefixlen 32 (A2). The driver only pushes a
                // derivable id, so there is no None arm here.
                info!(
                    id = self.id,
                    %router_id,
                    "zapi: pushing ROUTER_ID_UPDATE"
                );
                let frame = ZapiMessage::RouterIdUpdate(ZapiRouterIdUpdate {
                    address: std::net::IpAddr::V4(router_id),
                    prefix_len: 32,
                })
                .encode_frame(0)
                .map_err(encode_io_err)?;
                io.write_all(&frame).await
            }

            SessionPush::NeighbourAdded(notify) => {
                // The session-level interest check mirrors the driver's
                // fan-out (a stale push for a withdrawn interest is
                // dropped, the NHT pattern).
                let afi = match notify.ip {
                    std::net::IpAddr::V4(_) => 1u16,
                    std::net::IpAddr::V6(_) => 2u16,
                };
                if !self.neigh_afis.contains(&afi) {
                    debug!(
                        id = self.id,
                        ?notify.ip,
                        "zapi: neighbour push for unregistered afi dropped"
                    );
                    return Ok(());
                }
                info!(id = self.id, ip = %notify.ip, "zapi: pushing NEIGH_ADDED");
                let frame = ZapiMessage::NeighAdded(notify)
                    .encode_frame(0)
                    .map_err(encode_io_err)?;
                io.write_all(&frame).await
            }

            SessionPush::NeighbourRemoved(notify) => {
                let afi = match notify.ip {
                    std::net::IpAddr::V4(_) => 1u16,
                    std::net::IpAddr::V6(_) => 2u16,
                };
                if !self.neigh_afis.contains(&afi) {
                    return Ok(());
                }
                info!(id = self.id, ip = %notify.ip, "zapi: pushing NEIGH_REMOVED");
                let frame = ZapiMessage::NeighRemoved(notify)
                    .encode_frame(0)
                    .map_err(encode_io_err)?;
                io.write_all(&frame).await
            }

            SessionPush::ForwardBfdRegister { cmd, update } => {
                info!(id = self.id, dst = %cmd.dst, update, "zapi: relaying BFD command to daemon");
                let frame = if update {
                    ZapiMessage::BfdDestUpdate(cmd)
                } else {
                    ZapiMessage::BfdDestRegister(cmd)
                }
                .encode_frame(0)
                .map_err(encode_io_err)?;
                io.write_all(&frame).await
            }

            SessionPush::ForwardBfdDeregister(cmd) => {
                info!(id = self.id, dst = %cmd.dst, "zapi: relaying BFD deregister to daemon");
                let frame = ZapiMessage::BfdDestDeregister(cmd)
                    .encode_frame(0)
                    .map_err(encode_io_err)?;
                io.write_all(&frame).await
            }

            SessionPush::BfdDestStatus(status) => {
                // The fan-out push (26). Recipient selection is the
                // driver's (it addresses exactly the sessions that
                // sent BFD_CLIENT_REGISTER — the fan-out pin); the
                // session just encodes the pinned body.
                info!(
                    id = self.id,
                    dst = %status.dst,
                    status = status.status,
                    "zapi: pushing INTERFACE_BFD_DEST_UPDATE"
                );
                let frame = ZapiMessage::InterfaceBfdDestUpdate(status)
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
        iff, message_flag, ZapiHello, ZapiNexthopRegister, ZapiRedistribute, ZapiRoute,
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
            resolve_via_default: bool,
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
        NeighbourInterest,
        BfdClient,
        BfdRegister,
        BfdUnregister,
        BfdDaemonAttach,
        BfdStatus,
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
            RibCommand::RegisterNeighbourInterest { .. } => "neighbour-interest".to_string(),
            RibCommand::RegisterBfdDest { cmd, .. } => format!("bfd+ {}", cmd.dst),
            RibCommand::UnregisterBfdDest { cmd, .. } => format!("bfd- {}", cmd.dst),
            RibCommand::BfdClientRegistered { .. } => "bfd-client".to_string(),
            RibCommand::BfdDaemonAttached { pid, .. } => format!("bfd-daemon {pid}"),
            RibCommand::BfdDaemonStatusUpdate { .. } => "bfd-status".to_string(),
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
                    resolve_via_default,
                    reply,
                } => {
                    let resolution = self
                        .resolutions
                        .lock()
                        .unwrap()
                        .get(&prefix_addr(&prefix))
                        .copied();
                    let _ = reply.send(resolution);
                    Seen::Nht {
                        owner,
                        prefix,
                        resolve_via_default,
                    }
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
                RibCommand::RequestRouterId { reply, .. } => {
                    let _ = reply.send(self.router_id);
                    Seen::RouterId
                }
                RibCommand::RegisterNeighbourInterest { .. } => Seen::NeighbourInterest,
                RibCommand::BfdClientRegistered { .. } => Seen::BfdClient,
                RibCommand::RegisterBfdDest { .. } => Seen::BfdRegister,
                RibCommand::UnregisterBfdDest { .. } => Seen::BfdUnregister,
                RibCommand::BfdDaemonAttached { .. } => Seen::BfdDaemonAttach,
                RibCommand::BfdDaemonStatusUpdate { .. } => Seen::BfdStatus,
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

    fn hex(bytes: &[u8]) -> String {
        let mut s = String::with_capacity(bytes.len() * 2);
        for b in bytes {
            s.push_str(&format!("{b:02x}"));
        }
        s
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
        // PIM (11): a real frr-10.2.2 table value we do not model. 0 no
        // longer works as the probe — it is SYSTEM, which maps to Kernel
        // since the A19 numbering correction.
        route.route_type = 11;
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
            Seen::Nht {
                owner,
                prefix,
                resolve_via_default,
            } => {
                assert_eq!(owner, 1);
                assert_eq!(prefix, "192.0.2.1/32".parse::<IpPrefix>().unwrap());
                assert!(!resolve_via_default, "staticd shape");
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

    /// A23: the live-captured ospfd registration (NSSA default import
    /// check) — the raw fixture bytes of a real ospfd 10.2.2 cmd-21 frame
    /// decode, flow to the driver with the flag, and are answered with a
    /// resolved NEXTHOP_UPDATE.
    #[tokio::test]
    async fn nht_register_ospfd_default_import_check_shape() {
        use crate::header::ZapiHeader;
        const ZAPI_HEADER_LEN: usize = crate::ZAPI_HEADER_LEN;
        let (mut client, mut rx, _push, task) = spawn_session(16);
        let driver = driver_with_resolution(
            IpAddr::V4(Ipv4Addr::UNSPECIFIED),
            Nexthop::Ipv4If(Ipv4Addr::new(192, 168, 215, 1), 2),
        );
        // The exact body captured on the wire (zapi-sniff, a23 probe):
        // connected=0, resolve_via_default=1, safi=1, 0.0.0.0/0.
        let body: Vec<u8> = vec![
            0x00, 0x01, 0x00, 0x01, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00,
        ];
        let mut frame = vec![0u8; ZAPI_HEADER_LEN];
        ZapiHeader::new(21, 0, body.len()).encode(&mut frame);
        frame.extend_from_slice(&body);
        client.io.write_all(&frame).await.expect("send");
        match driver.recv(&mut rx).await {
            Seen::Nht {
                owner,
                prefix,
                resolve_via_default,
            } => {
                assert_eq!(owner, 1);
                assert_eq!(prefix, "0.0.0.0/0".parse::<IpPrefix>().unwrap());
                assert!(resolve_via_default, "ospfd sets the flag");
            }
            other => panic!("expected RegisterNexthop, got {other:?}"),
        }
        let (header, body) = client.read_frame().await;
        assert_eq!(header.command, 23, "NEXTHOP_UPDATE");
        let update = ZapiNexthopUpdate::decode(&body).expect("update decodes");
        assert!(update.is_resolved());
        assert_eq!(
            update.nexthops[0].nh_type,
            crate::nexthop_type::IPV4_IFINDEX
        );
        drop(client);
        let session = task.await.unwrap().unwrap();
        assert_eq!(session.nht.len(), 1);
        assert!(session.nht[&"0.0.0.0/0".parse::<IpPrefix>().unwrap()].resolve_via_default);
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

    /// M4: NEIGH_REGISTER (131) records the per-afi interest, forwards it
    /// to the driver, and writes NO reply (the pinned capture's silent
    /// registration that then earns pushes).
    #[tokio::test]
    async fn neigh_register_records_interest_without_reply() {
        let (mut client, mut rx, _push, task) = spawn_session(16);
        client
            .send(
                &ZapiMessage::NeighRegister(crate::ZapiNeighRegister { afi: 1 }),
                0,
            )
            .await;
        client
            .send(
                &ZapiMessage::NeighUnregister(crate::ZapiNeighRegister { afi: 2 }),
                0,
            )
            .await;
        client.send(&staticd_hello(), 0).await;
        let (header, _) = client.read_frame().await;
        assert_eq!(
            header.command, 19,
            "no NEIGH_REGISTER reply frame may precede the HELLO echo"
        );
        let first = rx.recv().await.expect("register forwarded");
        let second = rx.recv().await.expect("unregister forwarded");
        assert!(
            matches!(
                (&first, &second),
                (
                    RibCommand::RegisterNeighbourInterest {
                        afi: 1,
                        interested: true,
                        ..
                    },
                    RibCommand::RegisterNeighbourInterest {
                        afi: 2,
                        interested: false,
                        ..
                    },
                )
            ),
            "interest commands: {first:?} {second:?}"
        );
        assert!(matches!(
            rx.recv().await.expect("establish"),
            RibCommand::SessionEstablished { .. }
        ));
        drop(client);
        let session = task.await.unwrap().expect("connection survives");
        assert_eq!(
            session.neigh_afis,
            BTreeSet::from([1]),
            "afi 1 in, afi 2 never registered"
        );
        rx.close();
    }

    /// M4: the NEIGH_ADDED/REMOVED push bodies are byte-pinned to the
    /// live zebra capture (crates/zapi/tests/fixtures/m4-capture,
    /// 2026-10-10): the 22-byte with-MAC ADDED and the 18-byte AF_UNSPEC
    /// forms, header vrf 0.
    #[tokio::test]
    async fn neighbour_pushes_encode_the_captured_bodies() {
        let mut session = ZapiSession {
            id: 7,
            ..Default::default()
        };
        session.neigh_afis.insert(1);

        let added = ZapiMessage::NeighAdded(ZapiNeighNotify::added(
            "192.168.215.99".parse().unwrap(),
            &[0x02, 0x00, 0x00, 0x00, 0x00, 0x99],
            2,
            0x80,
        ))
        .encode_frame(0)
        .unwrap();
        let body = &added[crate::ZAPI_HEADER_LEN..];
        assert_eq!(
            hex(body),
            // 02|c0a8d763|02|02000000|00000006|00000002|00000080 — the
            // captured 22-byte body verbatim (the MAC truncated to its
            // first four bytes, true length 6 in ip_len).
            "02c0a8d7630202000000000000060000000200000080"
        );

        let removed = ZapiMessage::NeighRemoved(ZapiNeighNotify::without_link_layer(
            "192.168.215.99".parse().unwrap(),
            2,
            0x20,
        ))
        .encode_frame(0)
        .unwrap();
        let body = &removed[crate::ZAPI_HEADER_LEN..];
        assert_eq!(hex(body), "02c0a8d76300000000000000000200000020");

        // The AF gate: an unregistered family's push is dropped.
        session.neigh_afis.clear();
        let (mut server_io, mut client_io) = tokio::io::duplex(64);
        session
            .handle_push(
                SessionPush::NeighbourAdded(ZapiNeighNotify::added(
                    "192.168.215.99".parse().unwrap(),
                    &[0x02, 0x00, 0x00, 0x00, 0x00, 0x99],
                    2,
                    0x80,
                )),
                &mut server_io,
            )
            .await
            .unwrap();
        drop(server_io);
        use tokio::io::AsyncReadExt;
        let mut buf = Vec::new();
        client_io.read_to_end(&mut buf).await.unwrap();
        assert!(buf.is_empty(), "unregistered afi: nothing written");
    }

    /// M4: the interface dump's frames carry the VRF in the HEADER —
    /// header vrf_id = the enslaving vrf device's ifindex for a slave,
    /// own ifindex for the vrf device itself, 0 for plain links (the
    /// live capture: dummy0 under vrf-test answered vrf_id 3).
    #[tokio::test]
    async fn interface_dump_carries_vrf_in_the_header() {
        let (mut client, mut rx, _push, task) = spawn_session(16);
        client.send(&ZapiMessage::InterfaceAddRequest, 0).await;
        // Answer the request like the driver would: the mirror in
        // ifindex order (eth0 plain, the vrf device, its slave).
        let cmd = rx.recv().await.expect("request");
        let RibCommand::RequestInterfaces { reply } = cmd else {
            panic!("not an interface request: {cmd:?}")
        };
        let _ = reply.send(vec![
            InterfaceMirror {
                ifindex: 2,
                name: "eth0".into(),
                is_up: true,
                vrf_id: 0,
                master_ifindex: None,
                flags: common::LinkFlags::up_broadcast(),
                addresses: vec!["10.0.0.1/24".parse().unwrap()],
            },
            InterfaceMirror {
                ifindex: 3,
                name: "vrf-test".into(),
                is_up: true,
                vrf_id: 3,
                master_ifindex: None,
                flags: common::LinkFlags::UP,
                addresses: vec![],
            },
            InterfaceMirror {
                ifindex: 4,
                name: "dummy0".into(),
                is_up: true,
                vrf_id: 3,
                master_ifindex: Some(3),
                flags: common::LinkFlags::up_broadcast(),
                addresses: vec!["192.0.2.1/24".parse().unwrap()],
            },
        ]);

        // eth0: header vrf 0; its ADDRESS_ADD too.
        let (header, _) = client.read_frame().await;
        assert_eq!(header.vrf_id, 0);
        let (header, _) = client.read_frame().await;
        assert_eq!(header.command, 2, "eth0 address");
        assert_eq!(header.vrf_id, 0);
        // vrf-test itself: header vrf 3.
        let (header, _) = client.read_frame().await;
        assert_eq!(header.vrf_id, 3, "the vrf device dumps under its own id");
        // dummy0 (slave): INTERFACE_ADD and its address both vrf 3.
        let (header, _) = client.read_frame().await;
        assert_eq!(header.vrf_id, 3, "the slave dumps under the vrf's id");
        let (header, _) = client.read_frame().await;
        assert_eq!(header.command, 2, "dummy0 address");
        assert_eq!(header.vrf_id, 3);

        drop(client);
        task.await.unwrap().expect("connection survives");
    }

    /// M4: redistribute-push nexthops carry the flags byte and weight
    /// block zebra's live 31 frames show (0x04 + the 8-byte block ending
    /// 1) — the captured blackhole hop's bytes, reproduced.
    #[test]
    fn redistribute_nexthop_carries_the_captured_flags() {
        let wire = redistribute_nexthop(Nexthop::Blackhole);
        assert_eq!(wire.flags, nexthop_flag::WEIGHT);
        assert_eq!(wire.tail, vec![0, 0, 0, 0, 0, 0, 0, 1]);
        let mut buf = bytes::BytesMut::new();
        wire.encode(&mut buf);
        // vrf 0 | BLACKHOLE | flags 04 | bh_type 1 | weight block
        assert_eq!(
            buf,
            bytes::BytesMut::from(&[0, 0, 0, 0, 6, 4, 1, 0, 0, 0, 0, 0, 0, 0, 1][..])
        );
    }

    #[tokio::test]
    async fn router_id_push_encodes_command_18() {
        let mut session = ZapiSession {
            id: 11,
            ..ZapiSession::default()
        };
        let (mut client_io, mut server_io) = tokio::io::duplex(1024);
        session
            .handle_push(
                SessionPush::RouterIdUpdate(Ipv4Addr::new(192, 0, 2, 9)),
                &mut server_io,
            )
            .await
            .expect("push encodes");
        drop(server_io);
        let mut bytes = Vec::new();
        use tokio::io::AsyncReadExt;
        client_io.read_to_end(&mut bytes).await.expect("eof");

        let header = ZapiHeader::decode(&bytes[..ZAPI_HEADER_LEN]).unwrap();
        assert_eq!(header.command, 18, "ZEBRA_ROUTER_ID_UPDATE");
        assert_eq!(
            header.length as usize,
            bytes.len(),
            "exactly one framed message"
        );
        let body = bytes[ZAPI_HEADER_LEN..].to_vec();
        assert_eq!(
            body,
            vec![crate::message::AF_INET as u8, 192, 0, 2, 9, 32],
            "family AF_INET, the address, prefixlen 32 — byte-identical \
             to the ROUTER_ID_ADD answer body"
        );
    }

    /// ROUTE_NOTIFY_REQUEST is recorded and NOT answered synchronously —
    /// exactly what a real zebra 10.2.2 does (A5 wire capture: no reply
    /// frame; the ROUTE_NOTIFY_OWNER (11) push comes later, asynchronously,
    /// once an owned route's status is decided). Proven by handling one
    /// request and reading the client side to EOF — empty means nothing
    /// was written, and the Ok return means the connection survived.
    #[tokio::test]
    async fn route_notify_request_recorded_without_reply() {
        let mut session = ZapiSession {
            id: 9,
            ..ZapiSession::default()
        };
        let (mut client_io, mut server_io) = tokio::io::duplex(1024);
        let (tx, mut rx) = mpsc::channel(16);
        assert!(!session.route_notify, "flag starts clear");
        session
            .handle(
                ZapiMessage::RouteNotifyRequest { flag: 1 },
                0,
                &tx,
                &mut server_io,
            )
            .await
            .expect("handled without error (no-reply is the pinned answer)");
        drop(server_io);
        drop(tx);
        let mut written = Vec::new();
        use tokio::io::AsyncReadExt;
        client_io.read_to_end(&mut written).await.expect("eof");
        assert!(
            written.is_empty(),
            "no synchronous reply — no ROUTE_NOTIFY_OWNER may be written here (per zebra, A5)"
        );
        assert!(session.route_notify, "interest recorded for later pushes");
        assert!(
            rx.try_recv().is_err(),
            "no RibCommand: nothing to ask the RIB for"
        );
    }

    /// A ROUTE_NOTIFY_REQUEST with flag 0 clears the interest (zebra's
    /// `route_notify` bit follows the flag byte verbatim).
    #[tokio::test]
    async fn route_notify_request_flag_zero_clears_interest() {
        let mut session = ZapiSession {
            id: 10,
            route_notify: true,
            ..ZapiSession::default()
        };
        let (_client_io, mut server_io) = tokio::io::duplex(1024);
        let (tx, _rx) = mpsc::channel(16);
        session
            .handle(
                ZapiMessage::RouteNotifyRequest { flag: 0 },
                0,
                &tx,
                &mut server_io,
            )
            .await
            .expect("handled without error");
        assert!(!session.route_notify, "flag 0 clears the interest");
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
        // The W1-b fan-out entry arrives with (in arrival order, before
        // or after) the first HELLO's establish — the only command
        // traffic. Drain until both are seen.
        let mut establish = false;
        let mut fanout = 0;
        while !establish || fanout < 1 {
            match rx.recv().await.expect("command") {
                RibCommand::SessionEstablished { .. } => establish = true,
                RibCommand::BfdClientRegistered { owner: 1 } => fanout += 1,
                other => panic!("unexpected command: {other:?}"),
            }
        }
        assert!(
            rx.try_recv().is_err(),
            "registration is session state plus the fan-out entry, nothing more"
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
        // Two fan-out entries (one per registration) plus the establish,
        // in arrival order.
        let mut establish = false;
        let mut fanout = 0;
        while !establish || fanout < 2 {
            match rx.recv().await.expect("command") {
                RibCommand::SessionEstablished { .. } => establish = true,
                RibCommand::BfdClientRegistered { .. } => fanout += 1,
                other => panic!("unexpected command: {other:?}"),
            }
        }
        assert!(rx.try_recv().is_err(), "no further RibCommand either time");
        drop(client);
        let session = task.await.unwrap().expect("connection survives");
        assert_eq!(session.bfd_client_reg_cnt, 2);
        assert_eq!(session.bfd_pid, Some(535), "latest pid wins");
        rx.close();
    }

    /// A bgpd-shaped register (27): recorded in the session, relayed as a
    /// RegisterBfdDest command, NO reply frame (the Phase B pin — the
    /// answer is the later asynchronous 26 push).
    #[tokio::test]
    async fn bfd_dest_register_relayed_without_reply() {
        let (mut client, mut rx, _push, task) = spawn_session(16);
        let cmd = ZapiBfdSessionCmd {
            pid: 0x51,
            dst: "198.51.100.9".parse().unwrap(),
            min_rx_ms: 300,
            min_tx_ms: 300,
            detection_multiplier: 3,
            mhop: true,
            src: "192.168.215.4".parse().unwrap(),
            hops: 255,
            ifname: None,
            cbit: false,
            profile: None,
        };
        client
            .send(&ZapiMessage::BfdDestRegister(cmd.clone()), 0)
            .await;
        client.send(&staticd_hello(), 0).await;
        let (header, _) = client.read_frame().await;
        assert_eq!(header.command, 19, "only the HELLO echo answers");
        match rx.recv().await.expect("register relay") {
            RibCommand::RegisterBfdDest {
                owner,
                vrf_id,
                cmd: got,
                update,
            } => {
                assert_eq!((owner, vrf_id, update), (1, 0, false));
                assert_eq!(got, cmd);
            }
            other => panic!("not a register relay: {other:?}"),
        }
        drop(client);
        let session = task.await.unwrap().expect("connection survives");
        assert_eq!(
            session
                .bfd_destinations
                .get(&"198.51.100.9".parse::<IpAddr>().unwrap()),
            Some(&cmd),
            "session-side interest recorded"
        );
        rx.close();
    }

    /// DEREGISTER (28): interest removed, UnregisterBfdDest relayed,
    /// nothing on the wire back.
    #[tokio::test]
    async fn bfd_dest_deregister_relays_and_clears() {
        let (mut client, mut rx, _push, task) = spawn_session(16);
        let cmd = ZapiBfdSessionCmd {
            pid: 7,
            dst: "192.0.2.9".parse().unwrap(),
            min_rx_ms: 100,
            min_tx_ms: 100,
            detection_multiplier: 3,
            mhop: false,
            src: "0.0.0.0".parse().unwrap(),
            hops: 1,
            ifname: None,
            cbit: false,
            profile: None,
        };
        client
            .send(&ZapiMessage::BfdDestRegister(cmd.clone()), 0)
            .await;
        client.send(&ZapiMessage::BfdDestDeregister(cmd), 0).await;
        client.send(&staticd_hello(), 0).await;
        let (header, _) = client.read_frame().await;
        assert_eq!(header.command, 19, "no reply to either");
        assert!(matches!(
            rx.recv().await.expect("register"),
            RibCommand::RegisterBfdDest { .. }
        ));
        assert!(matches!(
            rx.recv().await.expect("deregister"),
            RibCommand::UnregisterBfdDest { .. }
        ));
        drop(client);
        let session = task.await.unwrap().expect("connection survives");
        assert!(!session
            .bfd_destinations
            .contains_key(&"192.0.2.9".parse::<IpAddr>().unwrap()));
        rx.close();
    }

    /// The two REPLAY (30) forms route differently: 4 bytes = "I am the
    /// daemon" (BfdDaemonAttached), 25 bytes = a state report
    /// (BfdDaemonStatusUpdate) — the Phase A/C pins.
    #[tokio::test]
    async fn bfd_replay_forms_split_attach_from_status() {
        let (mut client, mut rx, _push, _task) = spawn_session(16);
        client
            .send(&ZapiMessage::BfdDestReplay { pid: 30 }, 0)
            .await;
        assert!(matches!(
            rx.recv().await.expect("attach"),
            RibCommand::BfdDaemonAttached { owner: 1, pid: 30 }
        ));
        let status = ZapiBfdDestStatus {
            ifindex: 2,
            dst: "192.168.215.5/32".parse().unwrap(),
            status: crate::message::bfd_status::UP,
            src: "0.0.0.0/32".parse().unwrap(),
            remote_cbit: false,
        };
        client
            .send(&ZapiMessage::BfdDaemonStatus { pid: 30, status }, 0)
            .await;
        assert!(matches!(
            rx.recv().await.expect("status report"),
            RibCommand::BfdDaemonStatusUpdate { .. }
        ));
        drop(client);
        rx.close();
    }

    /// The driver->session pushes: a forwarded register reaches the daemon
    /// as command 27 with the pinned body; a state change reaches the
    /// client as command 26 with the pinned 21-byte body.
    #[tokio::test]
    async fn bfd_pushes_encode_the_pinned_frames() {
        let (mut client, _rx, push_tx, _task) = spawn_session(16);
        let cmd = ZapiBfdSessionCmd {
            pid: 0x3b,
            dst: "192.168.215.5".parse().unwrap(),
            min_rx_ms: 100,
            min_tx_ms: 100,
            detection_multiplier: 3,
            mhop: false,
            src: "0.0.0.0".parse().unwrap(),
            hops: 1,
            ifname: None,
            cbit: false,
            profile: None,
        };
        push_tx
            .send(SessionPush::ForwardBfdRegister { cmd, update: false })
            .await
            .unwrap();
        let (header, body) = client.read_frame().await;
        assert_eq!(header.command, 27);
        assert_eq!(
            hex(&body),
            "0000003b0002c0a8d7050000006400000064030000020000000001000000",
            "the probe's accepted single-hop register bytes"
        );

        // The 26 push encodes the captured UP body (recipient selection
        // is the driver's — the session encodes whatever it is handed).
        let status = ZapiBfdDestStatus {
            ifindex: 2,
            dst: "192.168.215.5/32".parse().unwrap(),
            status: crate::message::bfd_status::UP,
            src: "0.0.0.0/32".parse().unwrap(),
            remote_cbit: false,
        };
        push_tx
            .send(SessionPush::BfdDestStatus(status))
            .await
            .unwrap();
        let (header, body) = client.read_frame().await;
        assert_eq!(header.command, 26);
        assert_eq!(
            hex(&body),
            "0000000202c0a8d705200000000402000000002000",
            "the captured UP push bytes"
        );
        drop(client);
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
                    vrf_id: 0,
                    master_ifindex: None,
                    flags: LinkFlags::up_broadcast(),
                    addresses: vec!["192.0.2.1/24".parse().unwrap()],
                },
                InterfaceMirror {
                    ifindex: 1,
                    name: "lo".into(),
                    is_up: true,
                    vrf_id: 0,
                    master_ifindex: None,
                    flags: LinkFlags::up_loopback(),
                    addresses: vec!["127.0.0.1/8".parse().unwrap()],
                },
                InterfaceMirror {
                    ifindex: 3,
                    name: "eth1".into(),
                    is_up: false,
                    vrf_id: 0,
                    master_ifindex: None,
                    // Kernel realism: an admin-down eth keeps its static
                    // capability bits, drops UP|RUNNING.
                    flags: LinkFlags::BROADCAST | LinkFlags::MULTICAST,
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
            "the kernel's word for an UP broadcast link, relayed verbatim"
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
        assert_eq!(
            down.flags,
            iff::BROADCAST | iff::MULTICAST,
            "the word is the mirror's, not re-derived from is_up"
        );
    }

    /// A12: the wire flags word is the mirror's `ifi_flags` VERBATIM —
    /// names no longer participate. An `lo`-named link without the
    /// LOOPBACK bit gets none; a non-`lo` name carrying the bit gets it;
    /// and bits outside the pinned `iff` set (here NOARP, 0x80) survive
    /// the trip, exactly like a zebra relay of the kernel word.
    #[tokio::test]
    async fn interface_flags_relay_decoupled_from_names() {
        let (mut client, mut rx, _push, _task) = spawn_session(16);
        let driver = Driver {
            interfaces: vec![
                InterfaceMirror {
                    ifindex: 6,
                    name: "lo9999".into(),
                    is_up: true,
                    vrf_id: 0,
                    master_ifindex: None,
                    flags: LinkFlags::UP | LinkFlags::RUNNING | LinkFlags::BROADCAST,
                    addresses: vec![],
                },
                InterfaceMirror {
                    ifindex: 7,
                    name: "gre0".into(),
                    is_up: true,
                    vrf_id: 0,
                    master_ifindex: None,
                    flags: LinkFlags::from_bits(
                        LinkFlags::up_loopback().bits() | LinkFlags::MULTICAST.bits() | 0x80,
                    ),
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
        let (_h1, b1) = client.read_frame().await;
        let lo_named = crate::ZapiInterface::decode(&b1).unwrap();
        assert_eq!(lo_named.ifname, "lo9999");
        assert_eq!(
            lo_named.flags,
            iff::UP | iff::RUNNING | iff::BROADCAST,
            "no LOOPBACK bit reported → none on the wire, whatever the name"
        );
        let (_h2, b2) = client.read_frame().await;
        let gre = crate::ZapiInterface::decode(&b2).unwrap();
        assert_eq!(gre.ifname, "gre0");
        assert_eq!(
            gre.flags,
            iff::UP
                | iff::RUNNING
                | iff::LOOPBACK
                | iff::MULTICAST
                // NOARP has no pinned iff constant; the raw bit rides.
                | 0x80,
            "LOOPBACK from the flag word, and unnamed kernel bits survive"
        );
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

    /// PERF-P3 M2c: the chunked framing reader keeps the exact
    /// per-field `read_exact` contract under adversarial chunking —
    /// byte-dribbled writes that split inside a header and inside a
    /// body still yield exactly the frames written, and a peer close
    /// mid-frame is the clean end-of-stream the old `UnexpectedEof`
    /// path produced (partial data is dropped, never mis-framed).
    #[tokio::test]
    async fn chunked_read_frames_handle_splits_and_midframe_close() {
        let (mut client, server) = tokio::io::duplex(64);
        let (server_read, _server_write) = tokio::io::split(server);
        let (tx, mut rx) = mpsc::channel(8);
        let reader = tokio::spawn(read_frames(1, server_read, tx));

        let frame = ZapiMessage::Hello(ZapiHello {
            redist_default: 10,
            instance: 0,
            session_id: 0,
            synchronous: 0,
        })
        .encode_frame(0)
        .expect("hello encodes");
        // Three frames as one blob, dribbled in chunks that split a
        // header (after 3 and after 9 bytes) and a body (after 25).
        let blob: Vec<u8> = [frame.clone(), frame.clone(), frame.clone()].concat();
        for range in [
            0usize..3,
            3..9,
            9..10,
            10..25,
            25..blob.len(),
        ] {
            client.write_all(&blob[range]).await.expect("write");
            tokio::task::yield_now().await;
        }
        for _ in 0..3 {
            let (header, body) = rx.recv().await.expect("frame delivered").expect("no io error");
            assert_eq!(header.command, 19, "HELLO");
            assert_eq!(body.as_slice(), &frame[ZAPI_HEADER_LEN..]);
        }
        // Half a header, then close: the reader must finish cleanly and
        // deliver nothing for the partial frame.
        client.write_all(&blob[..5]).await.expect("partial write");
        drop(client);
        reader.await.expect("reader ended cleanly on close");
        assert!(
            rx.try_recv().is_err(),
            "partial frame dropped at close, never mis-framed"
        );
    }
}
