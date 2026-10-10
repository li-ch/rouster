//! Rouster `bfdd` — the BFD daemon (Phase 2 stream P2-a).
//!
//! Layers, one milestone each:
//!
//! - [`packet`] — the RFC 5880 §4.1/§5/§6.7 wire codec, including the
//!   §6.8.6 steps 1–6 packet-level validation and the §6.7
//!   authentication-section grammar.
//! - [`session`] — the RFC 5880 §6.1/§6.8 state machine: the §6.8.6
//!   steps 7–25 receive procedure, the §6.8.7 transmit rules with
//!   §6.8.2/§6.8.3 interval math, and §6.8.4 detection-time math.
//! - [`transport`] — RFC 5881 single-hop (UDP 3784) and RFC 5883
//!   multihop (UDP 4784) encapsulation, per-session async loops,
//!   discriminator allocation, and the optional echo function
//!   (RFC 5880 §5.7/§6.8.9, RFC 5881 §4 port 3785).
//! - [`daemon`] — the config-driven daemon: `bfd.conf`-shaped peer
//!   stanzas, the `/run/rouster/bfdd.status` surface (the A21
//!   pattern), SIGHUP reload, monitor-first logging.
//!
//! RFC 5882 governs the application interface; its §8 rule (hold
//! AdminDown for at least one Detection Time before stopping
//! transmission) is the daemon's shutdown behavior, and its §2
//! "single session per data protocol path" is the config model's
//! one-peer-one-session invariant.

pub mod packet;
pub mod session;
