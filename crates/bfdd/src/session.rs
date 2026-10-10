//! The BFD session state machine — RFC 5880 §6.1 (overview),
//! §6.8.6 steps 7–25 (receive), §6.8.7 (transmit), §6.8.4 (detection
//! time), §6.8.2/§6.8.3 (interval computation), §6.8.8 (expiry),
//! §6.8.5 (AdminDown), and Appendix A's optional version
//! negotiation.
//!
//! [`SessionSm`] is pure and clock-free: the caller owns every timer
//! (the session loop in [`crate::transport`]); the state machine
//! consumes events (a decoded packet, a detection-time expiry, an
//! operator down) and answers what the protocol says the answer is.
//! Tests are table-driven with the RFC section pinned to every row.
//!
//! One deliberate reading, disclosed: §6.1's diagram draws an
//! INIT→DOWN edge on received Down, but the normative §6.8.6
//! pseudocode (the "MUST be followed, in the order specified"
//! procedure) has no Init+Down transition — Init waits for its own
//! Detection Time. This implements the pseudocode exactly (FRR's
//! bfd_state_set takes the same reading).

use std::time::Duration;

use crate::packet::{AuthSection, BfdPacket, BfdState, Diagnostic};

/// §6.8.3's floor: "When bfd.SessionState is not Up, the system MUST
/// set bfd.DesiredMinTxInterval to a value of not less than one
/// second."
pub const NOT_UP_TX_FLOOR: Duration = Duration::from_secs(1);

/// §6.8.1's initial RemoteMinRxInterval: "a value of 1" (µs on the
/// wire — effectively zero, letting a peer transmit as fast as it
/// likes until the first real packet arrives).
const INITIAL_REMOTE_MIN_RX: Duration = Duration::from_micros(1);

/// Authentication the session verifies. Simple Password (RFC 5880
/// §6.7.2) verifies byte-exact; the keyed digest types need MD5/SHA1
/// primitives the workspace does not carry (no-new-deps fence), so a
/// session configured for them is refused at construction — an
/// un-verifiable packet class would silently weaken step 12 to a
/// no-op, and refusing is the honest option. The codec still parses
/// those sections (structural accounting), for logging.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthConfig {
    pub key_id: u8,
    pub password: Vec<u8>,
}

/// Operator-set session parameters (RFC 5880 §6.8.1: timing
/// parameters are a local matter; the wire carries them per §4.1).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionConfig {
    /// Desired Min Tx Interval while Up (§6.8.1; the effective value
    /// is floored at 1 s while not Up, §6.8.3).
    pub desired_min_tx: Duration,
    /// Required Min Rx Interval (§6.8.1).
    pub required_min_rx: Duration,
    /// Detection multiplier (§6.8.1, nonzero).
    pub detect_mult: u8,
    /// Min Echo Rx Interval we advertise — zero disables the echo
    /// function on our receive side (§4.1/§6.8.9).
    pub min_echo_rx: Duration,
    /// Demand mode operation (§6.6).
    pub demand_mode: bool,
    /// Passive role: never initiate periodic transmission before the
    /// remote discriminator is learned (§6.1).
    pub passive: bool,
    /// Control Plane Independent bit on transmission (§4.1).
    pub control_plane_independent: bool,
    /// Simple Password authentication, when configured (§6.7.2).
    pub auth: Option<AuthConfig>,
}

impl Default for SessionConfig {
    fn default() -> Self {
        Self {
            // FRR bfdd's defaults: 300 ms × 3.
            desired_min_tx: Duration::from_millis(300),
            required_min_rx: Duration::from_millis(300),
            detect_mult: 3,
            min_echo_rx: Duration::ZERO,
            demand_mode: false,
            passive: false,
            control_plane_independent: false,
            auth: None,
        }
    }
}

/// One §6.8.6 receive: what the session did, for the caller's logs
/// and side effects (send-a-Final, cease/resume periodic).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReceiveOutcome {
    /// The state transition the packet caused, if any (§6.8.6 steps
    /// 22–23), with the RFC's own name for it.
    pub transition: Option<Transition>,
    /// A received Poll demands a prompt Final (§6.8.6 step 25).
    pub send_final: bool,
    /// A Final terminated a Poll we initiated (§6.8.6 step 18).
    pub poll_terminated: bool,
}

/// A state transition with its RFC 5880 cause — the transition names
/// the monitor-first log lines use (§6.8.6 steps 22–23, §6.8.8).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Transition {
    pub from: BfdState,
    pub to: BfdState,
    pub diag: Diagnostic,
    pub cause: &'static str,
}

impl std::fmt::Display for Transition {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{} -> {} ({}, {})",
            self.from, self.to, self.diag, self.cause
        )
    }
}

/// Why a packet was discarded — one variant per discard rule the
/// session-level half of §6.8.6 can hit (steps 8, 10, 11, 12, 21;
/// step 7's mismatch arrives as [`DiscardReason::NotForUs`] from the
/// daemon's demultiplexing of its session set).
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum DiscardReason {
    #[error("your-discriminator belongs to no session here (RFC 5880 §6.8.6 step 7)")]
    NotForUs,
    #[error("zero your-discriminator with state {0:?} (RFC 5880 §6.8.6 step 8)")]
    ZeroYourDiscrBadState(BfdState),
    #[error("auth present but session authenticates none (RFC 5880 §6.8.6 step 10)")]
    AuthUnexpected,
    #[error("auth absent but session expects it (RFC 5880 §6.8.6 step 11)")]
    AuthMissing,
    #[error("authentication mismatch (RFC 5880 §6.8.6 step 12)")]
    AuthFailed,
    #[error("local session admin-down (RFC 5880 §6.8.6 step 21)")]
    AdminDownLocal,
}

/// The BFD session state machine (module docs).
pub struct SessionSm {
    config: SessionConfig,
    /// Label for logs (the peer address the daemon owns).
    label: String,
    /// Transmit version — 1 (§4.1); Appendix A negotiation may flip
    /// it to 0.
    version: u8,
    local_discr: u32,
    state: BfdState,
    remote_state: BfdState,
    local_diag: Diagnostic,
    remote_discr: u32,
    remote_detect_mult: u8,
    remote_desired_min_tx: Duration,
    remote_min_rx: Duration,
    remote_min_echo_rx: Duration,
    remote_demand: bool,
    /// A Poll we transmitted awaits its Final (§6.5).
    poll_seq: bool,
    /// A received Poll demands a Final on the next transmission
    /// (§6.8.6 step 25).
    final_pending: bool,
}

impl SessionSm {
    /// A session in its §6.8.1 initial state: Down, remote Down,
    /// zero remote discriminator, no diagnostic.
    pub fn new(config: SessionConfig, local_discr: u32, label: impl Into<String>) -> Self {
        assert_ne!(local_discr, 0, "§6.8.1: local discriminator nonzero");
        assert_ne!(config.detect_mult, 0, "§6.8.1: detect multiplier nonzero");
        let initial_mult = config.detect_mult;
        Self {
            config,
            label: label.into(),
            version: 1,
            local_discr,
            state: BfdState::Down,
            remote_state: BfdState::Down,
            local_diag: Diagnostic::None,
            remote_discr: 0,
            remote_detect_mult: initial_mult,
            remote_desired_min_tx: Duration::from_secs(1),
            remote_min_rx: INITIAL_REMOTE_MIN_RX,
            remote_min_echo_rx: Duration::ZERO,
            remote_demand: false,
            poll_seq: false,
            final_pending: false,
        }
    }

    pub fn label(&self) -> &str {
        &self.label
    }

    pub fn state(&self) -> BfdState {
        self.state
    }

    pub fn local_discr(&self) -> u32 {
        self.local_discr
    }

    pub fn remote_discr(&self) -> u32 {
        self.remote_discr
    }

    /// The last-received Detect Mult (§6.8.4's async multiplier).
    pub fn remote_detect_mult(&self) -> u8 {
        self.remote_detect_mult
    }

    pub fn is_up(&self) -> bool {
        self.state == BfdState::Up
    }

    /// Whether a Poll is awaiting its Final (§6.5).
    pub fn poll_in_flight(&self) -> bool {
        self.poll_seq
    }

    /// The transmit version in use (Appendix A).
    pub fn version(&self) -> u8 {
        self.version
    }

    /// Desired Min Tx as transmitted: the configured value once Up,
    /// floored at 1 s otherwise (§6.8.3).
    pub fn effective_desired_min_tx(&self) -> Duration {
        if self.state == BfdState::Up {
            self.config.desired_min_tx
        } else {
            self.config.desired_min_tx.max(NOT_UP_TX_FLOOR)
        }
    }

    /// §6.8.2's negotiated control transmission interval: the greater
    /// of what we want to send and what the remote can receive.
    pub fn negotiated_tx_interval(&self) -> Duration {
        self.effective_desired_min_tx().max(self.remote_min_rx)
    }

    /// §6.8.7's jittered interval for one transmission: `r` in [0, 1)
    /// (the caller's RNG). With a detection multiplier above 1 the
    /// interval lands in [75%, 100%) of the negotiated interval; with
    /// a multiplier of exactly 1, in [75%, 90%] — the tighter band
    /// §6.8.7 mandates so a single lost packet still fits the window.
    pub fn transmit_interval(&self, r: f64) -> Duration {
        jittered_interval(self.negotiated_tx_interval(), self.config.detect_mult, r)
    }

    /// §6.8.4 Local Detection Time: the remote-written Detect Mult
    /// times the negotiated receive interval while both sides run
    /// async; when the remote runs Demand, our local multiplier times
    /// the greater of our transmit desire and the remote's receive
    /// floor.
    pub fn detection_time(&self) -> Duration {
        if self.remote_demand {
            let interval = self.effective_desired_min_tx().max(self.remote_min_rx);
            interval * u32::from(self.config.detect_mult)
        } else {
            let interval = self.config.required_min_rx.max(self.remote_desired_min_tx);
            interval * u32::from(self.remote_detect_mult)
        }
    }

    /// Whether periodic transmission is allowed — the §6.8.7 MUST
    /// NOTs: not before learning the remote discriminator when
    /// passive, not when the remote asks for no packets, not while
    /// the remote's Demand ceases ours (a Poll in flight overrides
    /// the Demand cessation, §6.6).
    pub fn should_transmit_periodic(&self) -> bool {
        if self.config.passive && self.remote_discr == 0 {
            return false; // §6.8.7 first bullet
        }
        if self.remote_min_rx.is_zero() {
            return false; // §6.8.7 second bullet
        }
        if self.remote_demand
            && self.state == BfdState::Up
            && self.remote_state == BfdState::Up
            && !self.poll_seq
        {
            return false; // §6.8.7 third bullet / step 24
        }
        true
    }

    /// §6.8.9: echo transmission only while Up and only if the remote
    /// advertised a nonzero Min Echo Rx Interval.
    pub fn echo_transmission_allowed(&self) -> bool {
        self.state == BfdState::Up && !self.remote_min_echo_rx.is_zero()
    }

    /// §6.8.9: the echo interval we transmit at — the remote's floor.
    pub fn echo_tx_interval(&self) -> Duration {
        self.remote_min_echo_rx
    }

    /// §6.8.9: echo detection time = multiplier × echo interval.
    pub fn echo_detection_time(&self) -> Duration {
        self.echo_tx_interval() * u32::from(self.config.detect_mult)
    }

    /// Starts a Poll Sequence (§6.5): every transmission carries P
    /// until a Final arrives (§6.8.7).
    pub fn start_poll(&mut self) {
        self.poll_seq = true;
    }

    /// Operator down (§6.8.5): AdminDown with the given diagnostic —
    /// the daemon's shutdown sequence holds this for one Detection
    /// Time before stopping (RFC 5882 §8).
    pub fn enter_admin_down(&mut self, diag: Diagnostic) {
        self.state = BfdState::AdminDown;
        self.local_diag = diag;
    }

    /// §6.8.8: the control Detection Time expired — Down, Control
    /// Detection Time Expired. Per §6.8.1's recommendation the remote
    /// discriminator clears (the remote may restart with a new one),
    /// and §6.6 ends any Demand interplay by the same reset.
    pub fn on_detection_timeout(&mut self) -> Transition {
        let from = self.state;
        self.local_diag = Diagnostic::TimeExpired;
        self.state = BfdState::Down;
        self.remote_discr = 0;
        self.remote_demand = false;
        self.poll_seq = false;
        Transition {
            from,
            to: self.state,
            diag: self.local_diag,
            cause: "control detection time expired (RFC 5880 §6.8.8)",
        }
    }

    /// §6.8.9: the echo Detection Time expired — Down, Echo Function
    /// Failed.
    pub fn on_echo_timeout(&mut self) -> Transition {
        let from = self.state;
        self.local_diag = Diagnostic::EchoFailed;
        self.state = BfdState::Down;
        self.remote_discr = 0;
        self.remote_demand = false;
        self.poll_seq = false;
        Transition {
            from,
            to: self.state,
            diag: self.local_diag,
            cause: "echo detection time expired (RFC 5880 §6.8.9)",
        }
    }

    /// Builds the packet the next transmission carries (§6.8.7's
    /// transmit contents): local version/diag/state, P while a Poll
    /// is in flight, F once for a received Poll, D only when Demand
    /// is meaningful (both sides Up), and the effective intervals.
    /// The one-shot F is consumed here.
    pub fn build_packet(&mut self) -> BfdPacket {
        let final_bit = self.final_pending;
        self.final_pending = false;
        BfdPacket {
            version: self.version,
            diag: self.local_diag,
            state: self.state,
            poll: self.poll_seq,
            final_bit,
            control_plane_independent: self.config.control_plane_independent,
            auth_present: self.config.auth.is_some(),
            // §6.8.7: D "MUST be set to 1 if Demand Mode is active on
            // the local system ... and 0 otherwise".
            demand: self.demand_active(),
            detect_mult: self.config.detect_mult,
            my_discr: self.local_discr,
            your_discr: self.remote_discr,
            desired_min_tx: self.effective_desired_min_tx(),
            required_min_rx: self.config.required_min_rx,
            min_echo_rx: self.config.min_echo_rx,
            auth: self
                .config
                .auth
                .as_ref()
                .map(|a| AuthSection::SimplePassword {
                    key_id: a.key_id,
                    password: a.password.clone(),
                }),
        }
    }

    /// Demand Mode is active on transmit only when configured AND
    /// both systems reached Up (§6.6/§6.8.7).
    fn demand_active(&self) -> bool {
        self.config.demand_mode && self.state == BfdState::Up && self.remote_state == BfdState::Up
    }

    /// The session-level half of the §6.8.6 receive procedure —
    /// steps 7–25 (the packet-level steps 1–6 are
    /// [`BfdPacket::decode`]; the daemon's transport selected this
    /// session, which is steps 7–9's demultiplexing for a
    /// config-owned single session per peer, RFC 5882 §2).
    ///
    /// Steps 13–20 (learn remote fields, terminate Poll on Final,
    /// recompute intervals) run for every packet that passes the
    /// auth gates, including one discarded at step 21 — the
    /// procedure's own ordering.
    pub fn receive(&mut self, pkt: &BfdPacket) -> Result<ReceiveOutcome, DiscardReason> {
        // Appendix A (non-normative): receiving v0 switches us to v0
        // immediately; once on v0, a v1 AdminDown switches us back.
        if self.version == 1 && pkt.version == 0 {
            tracing::debug!(peer = %self.label, "bfdd: appendix A: switching to version 0");
            self.version = 0;
        } else if self.version == 0 && pkt.version == 1 && pkt.state == BfdState::AdminDown {
            tracing::debug!(peer = %self.label, "bfdd: appendix A: switching back to version 1");
            self.version = 1;
        }

        // Step 7: a nonzero Your Discriminator selects its session.
        if pkt.your_discr != 0 && pkt.your_discr != self.local_discr {
            return Err(DiscardReason::NotForUs);
        }
        // Step 8: a null Your Discriminator is only a session-start
        // attempt (Down or AdminDown states).
        if pkt.your_discr == 0 && !matches!(pkt.state, BfdState::Down | BfdState::AdminDown) {
            return Err(DiscardReason::ZeroYourDiscrBadState(pkt.state));
        }
        // Step 9 selected this object (the daemon owns one session
        // per configured peer; no dynamic creation).
        // Step 10: A set, no auth configured.
        if pkt.auth_present && self.config.auth.is_none() {
            return Err(DiscardReason::AuthUnexpected);
        }
        // Step 11: A clear, auth configured.
        if !pkt.auth_present && self.config.auth.is_some() {
            return Err(DiscardReason::AuthMissing);
        }
        // Step 12: authenticate. Only Simple Password is verifiable
        // (§6.7.2; module docs disclose the fence on keyed digests).
        if let Some(expected) = &self.config.auth {
            match pkt.auth.as_ref() {
                Some(AuthSection::SimplePassword { key_id, password }) => {
                    if *key_id != expected.key_id || *password != expected.password {
                        return Err(DiscardReason::AuthFailed);
                    }
                }
                Some(other) => {
                    tracing::warn!(
                        peer = %self.label,
                        auth = %other.auth_type(),
                        "bfdd: auth type not verifiable (no crypto crates); discarding per §6.8.6 step 12"
                    );
                    return Err(DiscardReason::AuthFailed);
                }
                None => return Err(DiscardReason::AuthMissing),
            }
        }

        // Step 13: learn the remote's discriminator.
        self.remote_discr = pkt.my_discr;
        // Step 14: learn the remote's state.
        self.remote_state = pkt.state;
        // Step 15: learn the remote's Demand mode.
        self.remote_demand = pkt.demand;
        // Step 16: learn the remote's receive floor.
        self.remote_min_rx = pkt.required_min_rx;
        self.remote_detect_mult = pkt.detect_mult;
        self.remote_desired_min_tx = pkt.desired_min_tx;
        let echo_was_allowed = self.echo_transmission_allowed();
        self.remote_min_echo_rx = pkt.min_echo_rx;
        // Step 17: a zero Min Echo Rx ceases echo transmission.
        let echo_ceased = echo_was_allowed && pkt.min_echo_rx.is_zero();

        // Step 18: a Final terminates our Poll.
        let poll_terminated = self.poll_seq && pkt.final_bit;
        if poll_terminated {
            self.poll_seq = false;
        }

        // Steps 19–20 recompute the transmit interval and Detection
        // Time — pure functions of the fields just learned, nothing
        // to mutate for.

        // Step 21: packets received while AdminDown are discarded
        // after the accounting above.
        if self.state == BfdState::AdminDown {
            return Err(DiscardReason::AdminDownLocal);
        }

        // Steps 22–23: the state transitions.
        let from = self.state;
        let mut transition = None;
        if pkt.state == BfdState::AdminDown {
            if self.state != BfdState::Down {
                self.local_diag = Diagnostic::NeighborSignaledSessionDown;
                self.state = BfdState::Down;
                transition = Some(Transition {
                    from,
                    to: self.state,
                    diag: self.local_diag,
                    cause: "received AdminDown (RFC 5880 §6.8.6 step 22)",
                });
            }
        } else {
            match self.state {
                BfdState::Down => match pkt.state {
                    BfdState::Down => {
                        self.state = BfdState::Init;
                        transition = Some(Transition {
                            from,
                            to: self.state,
                            diag: self.local_diag,
                            cause: "received Down while Down (RFC 5880 §6.8.6 step 23)",
                        });
                    }
                    BfdState::Init => {
                        self.local_diag = Diagnostic::None;
                        self.state = BfdState::Up;
                        transition = Some(Transition {
                            from,
                            to: self.state,
                            diag: self.local_diag,
                            cause: "received Init while Down (RFC 5880 §6.8.6 step 23)",
                        });
                    }
                    _ => {} // received Up while Down: no transition.
                },
                BfdState::Init => {
                    if matches!(pkt.state, BfdState::Init | BfdState::Up) {
                        self.local_diag = Diagnostic::None;
                        self.state = BfdState::Up;
                        transition = Some(Transition {
                            from,
                            to: self.state,
                            diag: self.local_diag,
                            cause: "received Init/Up while Init (RFC 5880 §6.8.6 step 23)",
                        });
                    }
                    // received Down while Init: §6.8.6's pseudocode has
                    // no edge — wait for our own Detection Time (the
                    // §6.1 diagram draws one; the MUST-procedure wins,
                    // module docs).
                }
                BfdState::Up => {
                    if pkt.state == BfdState::Down {
                        self.local_diag = Diagnostic::NeighborSignaledSessionDown;
                        self.state = BfdState::Down;
                        transition = Some(Transition {
                            from,
                            to: self.state,
                            diag: self.local_diag,
                            cause: "received Down while Up (RFC 5880 §6.8.6 step 23)",
                        });
                    }
                }
                BfdState::AdminDown => unreachable!("step 21 returned"),
            }
        }

        if echo_ceased {
            tracing::info!(peer = %self.label, "bfdd: echo transmission ceased (zero Min Echo Rx, RFC 5880 §6.8.6 step 17)");
        }
        if let Some(t) = &transition {
            tracing::info!(peer = %self.label, %t, "bfdd: session transition");
        }

        // Step 25: answer a Poll with a Final on the next packet.
        let send_final = pkt.poll;
        if pkt.poll {
            self.final_pending = true;
        }

        // Step 24 is should_transmit_periodic()'s Demand clause,
        // which the loop consults before every transmission.

        Ok(ReceiveOutcome {
            transition,
            send_final,
            poll_terminated,
        })
    }
}

/// §6.8.7's jitter, as a pure function (property-tested): multiplier
/// above 1 → [75%, 100%) of the negotiated interval; exactly 1 →
/// [75%, 90%].
pub fn jittered_interval(negotiated: Duration, detect_mult: u8, r: f64) -> Duration {
    let r = r.clamp(0.0, 0.999_999);
    let (lo, hi) = if detect_mult == 1 {
        (0.75, 0.90)
    } else {
        (0.75, 1.0)
    };
    let factor = lo + (hi - lo) * r;
    Duration::from_nanos((negotiated.as_nanos() as f64 * factor) as u64)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sm() -> SessionSm {
        SessionSm::new(SessionConfig::default(), 0x1000, "198.51.100.2")
    }

    fn rcv(state: BfdState) -> BfdPacket {
        BfdPacket::new(state, 0x2000, 0x1000)
    }

    /// §6.8.6 step 23, the Down column: rcv Down → Init, rcv Init →
    /// Up, rcv Up → nothing.
    #[test]
    fn down_receives_the_three_way_handshake() {
        let mut s = sm();
        assert_eq!(s.state(), BfdState::Down);

        let out = s.receive(&rcv(BfdState::Down)).unwrap();
        assert_eq!(
            out.transition,
            Some(Transition {
                from: BfdState::Down,
                to: BfdState::Init,
                diag: Diagnostic::None,
                cause: "received Down while Down (RFC 5880 §6.8.6 step 23)",
            })
        );

        // Fresh session for the second row (Down + rcv Init → Up).
        let mut s = sm();
        let out = s.receive(&rcv(BfdState::Init)).unwrap();
        assert_eq!(out.transition.as_ref().map(|t| t.to), Some(BfdState::Up));

        // Third row: rcv Up while Down — no transition.
        let mut s = sm();
        let out = s.receive(&rcv(BfdState::Up)).unwrap();
        assert_eq!(out.transition, None);
        assert_eq!(s.state(), BfdState::Down);
    }

    /// §6.8.6 step 23, the Init column: rcv Init → Up, rcv Up → Up;
    /// rcv Down leaves Init (the pseudocode has no edge — the
    /// disclosed §6.1 diagram divergence).
    #[test]
    fn init_receives() {
        let mut s = sm();
        s.receive(&rcv(BfdState::Down)).unwrap();
        assert_eq!(s.state(), BfdState::Init);

        let out = s.receive(&rcv(BfdState::Up)).unwrap();
        assert_eq!(out.transition.as_ref().map(|t| t.to), Some(BfdState::Up));

        let mut s = sm();
        s.receive(&rcv(BfdState::Down)).unwrap();
        let out = s.receive(&rcv(BfdState::Down)).unwrap();
        assert_eq!(out.transition, None);
        assert_eq!(
            s.state(),
            BfdState::Init,
            "Init+Down stays Init (§6.8.6 pseudocode)"
        );
    }

    /// §6.8.6 step 23, the Up column: rcv Down → Down with
    /// NeighborSignaledSessionDown; rcv Init leaves Up.
    #[test]
    fn up_receives() {
        let mut s = sm();
        bring_up(&mut s);
        let out = s.receive(&rcv(BfdState::Down)).unwrap();
        let t = out.transition.expect("transition");
        assert_eq!((t.from, t.to), (BfdState::Up, BfdState::Down));
        assert_eq!(t.diag, Diagnostic::NeighborSignaledSessionDown);

        let mut s = sm();
        bring_up(&mut s);
        let out = s.receive(&rcv(BfdState::Init)).unwrap();
        assert_eq!(out.transition, None);
        assert_eq!(s.state(), BfdState::Up);
    }

    /// §6.8.6 step 22: received AdminDown forces Down with diag 3
    /// from any state except Down, which stays put.
    #[test]
    fn received_admin_down_forces_down() {
        let mut s = sm();
        bring_up(&mut s);
        let out = s.receive(&rcv(BfdState::AdminDown)).unwrap();
        let t = out.transition.expect("transition");
        assert_eq!(t.to, BfdState::Down);
        assert_eq!(t.diag, Diagnostic::NeighborSignaledSessionDown);

        // From Down: no transition (§6.8.6: "is not Down" guard).
        let mut s = sm();
        let out = s.receive(&rcv(BfdState::AdminDown)).unwrap();
        assert_eq!(out.transition, None);
        assert_eq!(s.state(), BfdState::Down);
    }

    /// §6.8.6 step 21: while locally AdminDown, packets are discarded
    /// — but the remote fields still updated (steps 13–20 precede
    /// step 21).
    #[test]
    fn admin_down_local_discards_but_learns() {
        let mut s = sm();
        s.enter_admin_down(Diagnostic::AdminDown);
        let pkt = rcv(BfdState::Up);
        let err = s.receive(&pkt).unwrap_err();
        assert_eq!(err, DiscardReason::AdminDownLocal);
        assert_eq!(s.remote_discr(), 0x2000, "step 13 ran before step 21");
        assert_eq!(s.state(), BfdState::AdminDown);
    }

    fn bring_up(s: &mut SessionSm) {
        s.receive(&rcv(BfdState::Down)).unwrap();
        s.receive(&rcv(BfdState::Init)).unwrap();
        assert!(s.is_up());
    }

    /// §6.8.6 steps 7–8: a nonzero Your Discriminator that is not
    /// ours is not for us; a zero one with a live state is not a
    /// session start.
    #[test]
    fn demultiplex_discards() {
        let mut s = sm();
        let mut pkt = rcv(BfdState::Down);
        pkt.your_discr = 0x9999;
        assert_eq!(s.receive(&pkt).unwrap_err(), DiscardReason::NotForUs);

        let mut pkt = rcv(BfdState::Up);
        pkt.your_discr = 0;
        assert_eq!(
            s.receive(&pkt).unwrap_err(),
            DiscardReason::ZeroYourDiscrBadState(BfdState::Up)
        );
    }

    /// §6.8.6 steps 10–12 with Simple Password: symmetric discards on
    /// presence mismatch, byte-exact accept, mismatch discard.
    #[test]
    fn simple_password_authentication() {
        let auth = AuthConfig {
            key_id: 7,
            password: b"rouster!".to_vec(),
        };
        let mut good = rcv(BfdState::Down);
        good.auth_present = true;
        good.auth = Some(AuthSection::SimplePassword {
            key_id: 7,
            password: b"rouster!".to_vec(),
        });

        // Step 10: A set, session authenticates none.
        let mut s = sm();
        assert_eq!(s.receive(&good).unwrap_err(), DiscardReason::AuthUnexpected);

        // Step 11: A clear, session expects auth.
        let mut s = SessionSm::new(
            SessionConfig {
                auth: Some(auth.clone()),
                ..SessionConfig::default()
            },
            0x1000,
            "p",
        );
        assert_eq!(
            s.receive(&rcv(BfdState::Down)).unwrap_err(),
            DiscardReason::AuthMissing
        );

        // Step 12: accept + learn, then reject on both a wrong
        // password and a wrong key id.
        let mut s = SessionSm::new(
            SessionConfig {
                auth: Some(auth),
                ..SessionConfig::default()
            },
            0x1000,
            "p",
        );
        s.receive(&good).unwrap();
        assert_eq!(s.state(), BfdState::Init);

        let mut wrong = good.clone();
        wrong.auth = Some(AuthSection::SimplePassword {
            key_id: 7,
            password: b"rouster?".to_vec(),
        });
        assert_eq!(s.receive(&wrong).unwrap_err(), DiscardReason::AuthFailed);

        let mut wrong_key = good;
        wrong_key.auth = Some(AuthSection::SimplePassword {
            key_id: 8,
            password: b"rouster!".to_vec(),
        });
        assert_eq!(
            s.receive(&wrong_key).unwrap_err(),
            DiscardReason::AuthFailed
        );
    }

    /// §6.8.8: Detection Time expiry → Down, Control Detection Time
    /// Expired; the remote discriminator clears per §6.8.1 and any
    /// Poll in flight dies with the session.
    #[test]
    fn detection_timeout() {
        let mut s = sm();
        bring_up(&mut s);
        s.start_poll();
        let t = s.on_detection_timeout();
        assert_eq!((t.from, t.to), (BfdState::Up, BfdState::Down));
        assert_eq!(t.diag, Diagnostic::TimeExpired);
        assert_eq!(s.remote_discr(), 0);
        assert!(!s.poll_in_flight());
        assert_eq!(s.state(), BfdState::Down);
    }

    /// §6.8.9: echo expiry → Down, Echo Function Failed.
    #[test]
    fn echo_timeout() {
        let mut s = sm();
        bring_up(&mut s);
        let t = s.on_echo_timeout();
        assert_eq!((t.from, t.to), (BfdState::Up, BfdState::Down));
        assert_eq!(t.diag, Diagnostic::EchoFailed);
    }

    /// §6.5/§6.8.6 steps 18/25: a started Poll rides every packet
    /// until a Final; a received Poll demands a one-shot Final.
    #[test]
    fn poll_and_final_sequence() {
        let mut s = sm();
        bring_up(&mut s);
        assert!(!s.build_packet().poll);

        s.start_poll();
        assert!(s.poll_in_flight());
        let p = s.build_packet();
        assert!(p.poll, "§6.8.7: P set while the Poll is in flight");
        assert!(!p.final_bit);

        // A Final for our Poll terminates it (step 18).
        let mut fin = rcv(BfdState::Up);
        fin.final_bit = true;
        let out = s.receive(&fin).unwrap();
        assert!(out.poll_terminated);
        assert!(!s.poll_in_flight());

        // A received Poll sets the Final on exactly the next packet
        // (step 25).
        let mut poll = rcv(BfdState::Up);
        poll.poll = true;
        let out = s.receive(&poll).unwrap();
        assert!(out.send_final);
        let p = s.build_packet();
        assert!(p.final_bit);
        assert!(!p.poll);
        // One-shot: the following packet carries no stale Final.
        assert!(!s.build_packet().final_bit);
    }

    /// §6.8.4 async Detection Time: the remote-written multiplier
    /// times the greater of our receive floor and their transmit
    /// desire.
    #[test]
    fn detection_time_async_formula() {
        let mut s = SessionSm::new(
            SessionConfig {
                required_min_rx: Duration::from_millis(300),
                detect_mult: 5,
                ..SessionConfig::default()
            },
            0x1000,
            "p",
        );
        let mut pkt = rcv(BfdState::Down);
        pkt.detect_mult = 3;
        pkt.desired_min_tx = Duration::from_millis(500);
        pkt.required_min_rx = Duration::from_millis(700);
        s.receive(&pkt).unwrap();
        // max(our 300ms, their 500ms) = 500ms, × their mult 3.
        assert_eq!(s.detection_time(), Duration::from_millis(1500));

        // Their transmit desire drops below our receive floor: ours
        // wins.
        let mut pkt = rcv(BfdState::Down);
        pkt.detect_mult = 3;
        pkt.desired_min_tx = Duration::from_millis(100);
        pkt.required_min_rx = Duration::from_millis(700);
        s.receive(&pkt).unwrap();
        assert_eq!(s.detection_time(), Duration::from_millis(900));
    }

    /// §6.8.4 remote-demand Detection Time: our multiplier times the
    /// greater of our transmit desire and their receive floor.
    #[test]
    fn detection_time_remote_demand_formula() {
        let mut s = SessionSm::new(
            SessionConfig {
                desired_min_tx: Duration::from_millis(200),
                required_min_rx: Duration::from_millis(300),
                detect_mult: 4,
                ..SessionConfig::default()
            },
            0x1000,
            "p",
        );
        let mut pkt = rcv(BfdState::Down);
        pkt.detect_mult = 9; // ignored under remote demand
        pkt.desired_min_tx = Duration::from_millis(50);
        pkt.required_min_rx = Duration::from_millis(600);
        pkt.demand = true;
        s.receive(&pkt).unwrap();
        // Not Up: §6.8.3 floors our transmit desire at 1 s, and that
        // floored variable is what §6.8.4's formula reads —
        // max(1s, 600ms) × 4.
        assert_eq!(s.detection_time(), Duration::from_secs(4));
        // Once Up the configured 200 ms applies: max(200, 600) × 4.
        s.receive(&rcv(BfdState::Down)).unwrap();
        s.receive(&rcv(BfdState::Init)).unwrap();
        let mut up = rcv(BfdState::Up);
        up.demand = true;
        up.required_min_rx = Duration::from_millis(600);
        s.receive(&up).unwrap();
        assert_eq!(s.detection_time(), Duration::from_millis(2400));
    }

    /// §6.8.3: the effective Desired Min Tx is floored at 1 s while
    /// not Up and returns to the configured value once Up.
    #[test]
    fn not_up_transmit_floor() {
        let mut s = SessionSm::new(
            SessionConfig {
                desired_min_tx: Duration::from_millis(300),
                ..SessionConfig::default()
            },
            0x1000,
            "p",
        );
        assert_eq!(s.effective_desired_min_tx(), NOT_UP_TX_FLOOR);
        bring_up(&mut s);
        assert_eq!(s.effective_desired_min_tx(), Duration::from_millis(300));
    }

    /// §6.8.2/§6.8.7: the negotiated interval is the max of our
    /// transmit desire and their receive floor, and the jittered
    /// interval never leaves the mandated band — a property loop over
    /// pseudo-random draws (the no-proptest substitute).
    #[test]
    fn transmit_interval_property() {
        let mut s = sm();
        let mut pkt = rcv(BfdState::Down);
        pkt.required_min_rx = Duration::from_millis(700); // their floor dominates
        pkt.desired_min_tx = Duration::from_millis(100);
        s.receive(&pkt).unwrap();
        // While not Up our desire is floored at 1s; max(1s, 700ms).
        assert_eq!(s.negotiated_tx_interval(), Duration::from_secs(1));

        bring_up(&mut s);
        // The handshake packets carried the codec default floor (1 s);
        // re-establish the 700 ms floor before the Up-phase check.
        let mut pkt = rcv(BfdState::Up);
        pkt.required_min_rx = Duration::from_millis(700);
        s.receive(&pkt).unwrap();
        // Up: max(300ms, 700ms) = 700ms.
        assert_eq!(s.negotiated_tx_interval(), Duration::from_millis(700));

        // xorshift64* — deterministic, seeded.
        let mut seed = 0x9e37_79b9_7f4a_7c15u64;
        let mut next = || {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            (seed >> 11) as f64 / (1u64 << 53) as f64
        };
        for r in (0..10_000).map(|_| next()) {
            let iv = s.transmit_interval(r);
            let negotiated = s.negotiated_tx_interval().as_nanos() as f64;
            let got = iv.as_nanos() as f64;
            assert!(
                got >= 0.75 * negotiated && got < negotiated,
                "mult 3 jitter {got} out of [75%, 100%) of {negotiated} (r={r})"
            );
        }
        // Multiplier 1's tighter band.
        let tight = jittered_interval(Duration::from_millis(100), 1, 0.0);
        assert_eq!(tight, Duration::from_millis(75));
        let tight = jittered_interval(Duration::from_millis(100), 1, 0.999_999);
        assert_eq!(tight, Duration::from_nanos(89_999_985));
        // Out-of-range r clamps rather than panics.
        let clamped = jittered_interval(Duration::from_millis(100), 1, 7.0);
        assert_eq!(clamped, Duration::from_nanos(89_999_985));
    }

    /// §6.8.7's transmit MUST NOTs: passive before learning the
    /// remote, a zero remote receive floor, and remote Demand with
    /// both sides Up (a Poll overrides the cessation).
    #[test]
    fn periodic_transmission_gates() {
        let mut s = SessionSm::new(
            SessionConfig {
                passive: true,
                ..SessionConfig::default()
            },
            0x1000,
            "p",
        );
        assert!(!s.should_transmit_periodic());
        s.receive(&rcv(BfdState::Down)).unwrap();
        assert!(
            s.should_transmit_periodic(),
            "passive gate lifts once remote learned"
        );

        let mut s = sm();
        let mut pkt = rcv(BfdState::Down);
        pkt.required_min_rx = Duration::ZERO;
        s.receive(&pkt).unwrap();
        assert!(!s.should_transmit_periodic(), "zero remote rx floor");

        let mut s = sm();
        bring_up(&mut s);
        let mut pkt = rcv(BfdState::Up);
        pkt.demand = true;
        pkt.your_discr = 0x1000;
        s.receive(&pkt).unwrap();
        assert!(!s.should_transmit_periodic(), "remote demand ceases ours");
        s.start_poll();
        assert!(
            s.should_transmit_periodic(),
            "a Poll overrides the cessation"
        );
    }

    /// §6.8.7: the Demand bit transmits only when configured and both
    /// sides reached Up.
    #[test]
    fn demand_bit_only_when_both_up() {
        let mut s = SessionSm::new(
            SessionConfig {
                demand_mode: true,
                ..SessionConfig::default()
            },
            0x1000,
            "p",
        );
        assert!(!s.build_packet().demand);
        bring_up(&mut s);
        let pkt = rcv(BfdState::Up);
        s.receive(&pkt).unwrap();
        assert!(s.build_packet().demand);
    }

    /// §6.8.6 step 17 + §6.8.9: echo transmission requires Up and a
    /// nonzero remote Min Echo Rx; a zero field ceases it.
    #[test]
    fn echo_gates() {
        let mut s = sm();
        assert!(!s.echo_transmission_allowed());
        bring_up(&mut s);
        assert!(
            !s.echo_transmission_allowed(),
            "remote advertised zero echo rx"
        );

        let mut pkt = rcv(BfdState::Up);
        pkt.min_echo_rx = Duration::from_millis(50);
        pkt.your_discr = 0x1000;
        s.receive(&pkt).unwrap();
        assert!(s.echo_transmission_allowed());
        assert_eq!(s.echo_tx_interval(), Duration::from_millis(50));
        assert_eq!(s.echo_detection_time(), Duration::from_millis(150)); // ×3

        // Step 17: zero Min Echo Rx ceases.
        let mut pkt = rcv(BfdState::Up);
        pkt.min_echo_rx = Duration::ZERO;
        pkt.your_discr = 0x1000;
        s.receive(&pkt).unwrap();
        assert!(!s.echo_transmission_allowed());
    }

    /// Appendix A (non-normative): a v0 packet switches the transmit
    /// version to 0 immediately; from v0, a v1 AdminDown switches
    /// back to 1.
    #[test]
    fn appendix_a_version_negotiation() {
        let mut s = sm();
        let mut v0 = rcv(BfdState::Down);
        v0.version = 0;
        s.receive(&v0).unwrap();
        assert_eq!(s.version(), 0);
        assert_eq!(s.build_packet().version, 0);

        let mut v1_down = rcv(BfdState::Down);
        v1_down.version = 1;
        s.receive(&v1_down).unwrap();
        assert_eq!(s.version(), 0, "only AdminDown switches v0 back to v1");

        let mut v1_admin = rcv(BfdState::AdminDown);
        v1_admin.version = 1;
        let _ = s.receive(&v1_admin); // discarded at step 22/21-adjacent, still switches
        assert_eq!(s.version(), 1);
    }

    /// §6.8.5 + RFC 5882 §8: the operator's AdminDown carries the
    /// diagnostic and state into every transmission.
    #[test]
    fn admin_down_transmission() {
        let mut s = sm();
        bring_up(&mut s);
        s.enter_admin_down(Diagnostic::AdminDown);
        let p = s.build_packet();
        assert_eq!(p.state, BfdState::AdminDown);
        assert_eq!(p.diag, Diagnostic::AdminDown);
    }
}
