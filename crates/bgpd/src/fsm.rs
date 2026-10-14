//! The BGP session FSM (RFC 4271 §8): six states (§8.2.2.1–.6), the
//! event set (§8.1), and the state-transition table rendered as code.
//!
//! Design, pinned to the RFC text:
//! - **Pure and clock-injected.** [`Fsm::fire`] takes an event and
//!   returns the actions the tables prescribe; timers never run inside
//!   the core. The async session layer owns real timers and delivers
//!   Events 9/10/11 as expirations — tests deliver them by hand, which
//!   is what "table-driven" means here.
//! - **DelayOpen is always FALSE** (§8.1.1 optional attribute): the
//!   DelayOpenTimer paths (Events 12/20) never fire, so they are
//!   absent from the match arms. Disclosed v1 simplification.
//! - Events 14/15 (`TcpConnection_Valid`/`Tcp_CR_Invalid`) are
//!   TCP-layer accept decisions the listener makes before a
//!   connection reaches the FSM; Event 16 (`Tcp_CR_Acked`) and 17
//!   (`TcpConnectionConfirmed`) get identical table handling and are
//!   unified into one variant.
//! - Event 24 (`NotifMsgVerErr`) and 25 (`NotifMsg`) differ only in
//!   ConnectRetryCounter bookkeeping; v1 unifies them (disclosed).
//! - Collision detection (§6.8) is first-connection-wins at the
//!   daemon layer, §Deferred for the BGP-ID tiebreak (see the stream
//!   report).
//!
//! Timer defaults (§10): ConnectRetry 120 s, Hold 90 s (configurable
//! per peer — MUST per §10), Keepalive = Hold/3, and the "large"
//! OpenSent Hold = 4 minutes (§8.2.2.3's suggested value).

use std::net::Ipv4Addr;

use crate::error::cease_subcode;
use crate::message::BgpOpen;

/// The six states (RFC 4271 §8.2.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum State {
    Idle,
    Connect,
    Active,
    OpenSent,
    OpenConfirm,
    Established,
}

impl State {
    pub fn name(self) -> &'static str {
        match self {
            Self::Idle => "Idle",
            Self::Connect => "Connect",
            Self::Active => "Active",
            Self::OpenSent => "OpenSent",
            Self::OpenConfirm => "OpenConfirm",
            Self::Established => "Established",
        }
    }
}

/// FSM events (RFC 4271 §8.1; numbers in the docs).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Event {
    /// Event 1: ManualStart (also the AutomaticStart, Event 3, shape —
    /// same table handling when not passive).
    Start { passive: bool },
    /// Event 2: ManualStop. SIGTERM maps here (see `daemon`); the
    /// Established-table row sends NOTIFICATION Cease.
    ManualStop,
    /// Event 9: ConnectRetryTimer_Expires.
    ConnectRetryTimerExpires,
    /// Event 10: HoldTimer_Expires.
    HoldTimerExpires,
    /// Event 11: KeepaliveTimer_Expires.
    KeepaliveTimerExpires,
    /// Events 16/17: Tcp_CR_Acked / TcpConnectionConfirmed.
    TcpConnectionConfirmed,
    /// Event 18: TcpConnectionFails.
    TcpConnectionFails,
    /// Event 19: BGPOpen — a fully validated OPEN.
    BgpOpen(BgpOpen),
    /// Event 21: BGPHeaderErr — carries the NOTIFICATION (code,
    /// subcode) the checker derived (§6.1).
    BgpHeaderErr(u8, u8),
    /// Event 22: BGPOpenMsgErr — (code, subcode) per §6.2.
    BgpOpenMsgErr(u8, u8),
    /// Events 24/25: NotifMsgVerErr / NotifMsg.
    NotifMsg,
    /// Event 26: KeepAliveMsg.
    KeepAliveMsg,
    /// Event 27: UpdateMsg.
    UpdateMsg,
    /// Event 28: UpdateMsgErr — (code, subcode) per §6.3.
    UpdateMsgErr(u8, u8),
}

/// What the session layer must do after an event (compressed from the
/// per-state bullet lists; each variant names its table origin).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Action {
    /// "Initiates a TCP connection to the other BGP peer".
    ConnectTcp,
    /// "Drops the TCP connection".
    CloseTcp,
    SendOpen,
    SendKeepalive,
    /// NOTIFICATION with the given (code, subcode); always paired
    /// with [`Action::CloseTcp`] by the rows that prescribe it.
    Notify(u8, u8),
    StartConnectRetry,
    RestartConnectRetry,
    StopConnectRetry,
    /// Arm the HoldTimer at the 4-minute "large value" (§8.2.2.3).
    SetHoldLarge,
    /// Arm Hold + Keepalive at the negotiated values (OpenSent→
    /// OpenConfirm); disarms both when the negotiated hold is zero
    /// (§4.2).
    ArmNegotiatedTimers,
    /// "Restarts its HoldTimer" (Established 26/27 rows).
    RestartHoldTimer,
    /// "Restarts the KeepaliveTimer".
    RestartKeepalive,
    /// "Releases all BGP resources" (and stops the timers).
    ReleaseResources,
    /// "Deletes all routes associated with this connection"
    /// (Established teardown rows).
    WithdrawRoutes,
}

/// Session-configuration inputs the FSM needs to act.
#[derive(Debug, Clone)]
pub struct SessionConfig {
    pub local_as: u32,
    pub local_id: Ipv4Addr,
    /// Configured HoldTime (§10 default 90 s; per-peer configurable).
    pub hold_time: u16,
    /// Whether we advertise the 4-octet capability (always true in
    /// this daemon — the field exists so negotiation logic is visible).
    pub local_four_octet: bool,
    /// Locally configured ADD-PATH receive per unicast family
    /// (RFC 7911, `neighbor X addpath rx`): we then advertise
    /// Send/Receive 1 for that family. Off by default — the classic
    /// NLRI encoding.
    pub add_path_rx_v4: bool,
    pub add_path_rx_v6: bool,
    /// Locally configured ADD-PATH transmit per unicast family
    /// (RFC 7911, `neighbor X addpath tx` — or `both`): we then
    /// advertise Send/Receive 2 (3 together with rx) for that family,
    /// and outbound NLRI toward a receiving peer uses the extended
    /// encoding under our own per-peer path ids. Off by default.
    pub add_path_tx_v4: bool,
    pub add_path_tx_v6: bool,
}

impl SessionConfig {
    pub fn new(local_as: u32, local_id: Ipv4Addr, hold_time: u16) -> Self {
        Self {
            local_as,
            local_id,
            hold_time,
            local_four_octet: true,
            add_path_rx_v4: false,
            add_path_rx_v6: false,
            add_path_tx_v4: false,
            add_path_tx_v6: false,
        }
    }
}

/// Negotiated session facts, recorded when a valid OPEN arrives
/// (OpenSent Event 19 row).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Negotiated {
    pub hold_time: u16,
    pub peer_as: u32,
    pub peer_id: Ipv4Addr,
    /// Both sides advertised the 4-octet AS capability (RFC 6793 §5.2).
    pub asn4: bool,
    /// "Internal" = peer AS equals local AS (§8.2.2.3 note).
    pub internal: bool,
    pub route_refresh: bool,
    /// The peer's Graceful Restart capability (RFC 4724 §3) when
    /// advertised: the Restart State (R) bit and the 12-bit Restart
    /// Time. Presence alone switches the receiving-side retention
    /// rules on (§4.1).
    pub graceful_restart: Option<GracefulRestartInfo>,
    /// The peer's ADD-PATH Send/Receive value per unicast family
    /// (RFC 7911 §4; 0 = off, and 0 when any tuple carries an invalid
    /// value — the §4 whole-capability ignore).
    pub add_path_v4: u8,
    pub add_path_v6: u8,
    /// Effective ADD-PATH *receive* direction per family — the §5
    /// MUST: true only when we advertised Send/Receive 1 (locally
    /// configured rx) AND the peer advertised 2 or 3 (willing to
    /// send). Only then may inbound NLRI for the family use the
    /// extended encoding (the 4-octet Path Identifier, §3).
    pub add_path_rx_v4: bool,
    pub add_path_rx_v6: bool,
    /// Effective ADD-PATH *transmit* direction per family — the §5
    /// MUST mirrored: true only when we advertised Send/Receive 2 or 3
    /// (locally configured tx) AND the peer advertised 1 or 3 (willing
    /// to receive). Only then may outbound NLRI for the family use the
    /// extended encoding, under our own path ids (§2).
    pub add_path_tx_v4: bool,
    pub add_path_tx_v6: bool,
}

/// The RFC 4724 §3 facts a receiving speaker needs from the peer's
/// capability: whether the peer restarted (R) and how long its routes
/// may be retained (Restart Time, seconds). RFC 8538 §2 adds the
/// Graceful Notification (N) bit — the peer supports NOTIFICATION
/// messages inside the graceful-restart procedures.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GracefulRestartInfo {
    pub restart_state: bool,
    pub graceful_notification: bool,
    pub restart_time: u16,
}

/// A pure BGP FSM instance for one peer.
pub struct Fsm {
    config: SessionConfig,
    state: State,
    negotiated: Option<Negotiated>,
    connect_retry_running: bool,
    /// ConnectRetryCounter — incremented on the error teardown rows
    /// (observability only in v1; no damping, §8.1.1).
    pub connect_retry_counter: u32,
}

impl Fsm {
    pub fn new(config: SessionConfig) -> Self {
        Self {
            config,
            state: State::Idle,
            negotiated: None,
            connect_retry_running: false,
            connect_retry_counter: 0,
        }
    }

    pub fn state(&self) -> State {
        self.state
    }

    pub fn negotiated(&self) -> Option<Negotiated> {
        self.negotiated
    }

    /// The KeepaliveTime this session will use: 1/3 of the negotiated
    /// hold (§10), zero when hold is zero.
    pub fn keepalive_time(&self) -> u16 {
        self.negotiated.map(|n| n.hold_time / 3).unwrap_or(0)
    }

    /// Apply one event; returns the prescribed actions in table order.
    pub fn fire(&mut self, event: Event) -> Vec<Action> {
        match self.state {
            State::Idle => self.fire_idle(event),
            State::Connect => self.fire_connect(event),
            State::Active => self.fire_active(event),
            State::OpenSent => self.fire_open_sent(event),
            State::OpenConfirm => self.fire_open_confirm(event),
            State::Established => self.fire_established(event),
        }
    }

    fn fire_idle(&mut self, event: Event) -> Vec<Action> {
        match event {
            // §8.2.2.1: start events move to Connect (active) or
            // Active (passive — Events 4/5 shape).
            Event::Start { passive: false } => {
                self.state = State::Connect;
                self.connect_retry_running = true;
                vec![Action::StartConnectRetry, Action::ConnectTcp]
            }
            Event::Start { passive: true } => {
                self.state = State::Active;
                Vec::new()
            }
            // "Any other event (Events 9-12, 15-28) received in the
            // Idle state does not cause change in the state" — and
            // ManualStop in Idle has nothing to stop.
            _ => Vec::new(),
        }
    }

    fn fire_connect(&mut self, event: Event) -> Vec<Action> {
        match event {
            // "The start events (Events 1, 3-7) are ignored."
            Event::Start { .. } => Vec::new(),
            // §8.2.2.3 ManualStop: stop ConnectRetry, drop, → Idle.
            Event::ManualStop => {
                self.connect_retry_running = false;
                self.state = State::Idle;
                vec![
                    Action::StopConnectRetry,
                    Action::ReleaseResources,
                    Action::CloseTcp,
                ]
            }
            Event::ConnectRetryTimerExpires => {
                // Restart ConnectRetry, re-initiate TCP, stay Connect.
                vec![Action::RestartConnectRetry, Action::ConnectTcp]
            }
            Event::TcpConnectionConfirmed => {
                // DelayOpen=FALSE: stop ConnectRetry, send OPEN, Hold
                // ← large, → OpenSent.
                self.connect_retry_running = false;
                self.state = State::OpenSent;
                vec![
                    Action::StopConnectRetry,
                    Action::SendOpen,
                    Action::SetHoldLarge,
                ]
            }
            Event::TcpConnectionFails => {
                // Restart ConnectRetry, → Active.
                self.state = State::Active;
                vec![Action::RestartConnectRetry]
            }
            Event::BgpHeaderErr(code, subcode) | Event::BgpOpenMsgErr(code, subcode) => {
                self.error_teardown();
                vec![Action::Notify(code, subcode), Action::CloseTcp]
            }
            Event::NotifMsg => {
                // DelayOpenTimer not running: release, drop, → Idle.
                self.connect_retry_running = false;
                self.state = State::Idle;
                vec![
                    Action::StopConnectRetry,
                    Action::ReleaseResources,
                    Action::CloseTcp,
                ]
            }
            // Events 8, 10-11, 13, 19, 23, 25-28 catch-all: FSM-style
            // teardown without a NOTIFICATION (the tables' generic
            // "release, drop, → Idle").
            _ => {
                self.error_teardown();
                vec![Action::CloseTcp]
            }
        }
    }

    fn fire_active(&mut self, event: Event) -> Vec<Action> {
        match event {
            Event::Start { .. } => Vec::new(),
            Event::ManualStop => {
                self.connect_retry_running = false;
                self.state = State::Idle;
                vec![
                    Action::StopConnectRetry,
                    Action::ReleaseResources,
                    Action::CloseTcp,
                ]
            }
            // §8.2.2.4: Event 9 restarts ConnectRetry and initiates
            // the connection, → Connect.
            Event::ConnectRetryTimerExpires => {
                self.state = State::Connect;
                self.connect_retry_running = true;
                vec![Action::RestartConnectRetry, Action::ConnectTcp]
            }
            Event::TcpConnectionConfirmed => {
                self.connect_retry_running = false;
                self.state = State::OpenSent;
                vec![
                    Action::StopConnectRetry,
                    Action::SendOpen,
                    Action::SetHoldLarge,
                ]
            }
            // "Releases all BGP resources... restarts ConnectRetry...
            // remains in Active"? — §8.2.2.4 Event 18: restart
            // ConnectRetry, release resources, stay in Active.
            Event::TcpConnectionFails => {
                vec![Action::RestartConnectRetry, Action::ReleaseResources]
            }
            Event::BgpHeaderErr(code, subcode) | Event::BgpOpenMsgErr(code, subcode) => {
                self.error_teardown();
                vec![Action::Notify(code, subcode), Action::CloseTcp]
            }
            Event::NotifMsg => {
                self.error_teardown();
                vec![Action::CloseTcp]
            }
            _ => {
                self.error_teardown();
                vec![Action::CloseTcp]
            }
        }
    }

    fn fire_open_sent(&mut self, event: Event) -> Vec<Action> {
        match event {
            Event::Start { .. } | Event::ManualStop => {
                // §8.2.2.5: start events ignored? — no: Event 2 in
                // OpenSent is the "any other event" row → FSM error.
                // ManualStop specifically: release, drop, → Idle.
                if matches!(event, Event::ManualStop) {
                    self.error_teardown();
                    vec![Action::CloseTcp]
                } else {
                    Vec::new()
                }
            }
            Event::ConnectRetryTimerExpires => {
                // OpenSent catch-all (Events 9, 11-13, 20, 25-28):
                // FSM-error NOTIFICATION.
                self.error_teardown();
                vec![Action::Notify(5, 0), Action::CloseTcp]
            }
            Event::HoldTimerExpires => {
                // NOTIFICATION Hold Timer Expired, release, → Idle.
                self.error_teardown();
                vec![Action::Notify(4, 0), Action::CloseTcp]
            }
            Event::TcpConnectionFails => {
                // Close, restart ConnectRetry, → Active.
                self.state = State::Active;
                self.connect_retry_running = true;
                vec![Action::CloseTcp, Action::RestartConnectRetry]
            }
            Event::BgpOpen(open) => {
                // The Event 19 row: record negotiation, KEEPALIVE, arm
                // timers, → OpenConfirm.
                let negotiated = Negotiated {
                    hold_time: self.config.hold_time.min(open.hold_time),
                    peer_as: open.peer_as4(),
                    peer_id: open.bgp_id,
                    asn4: self.config.local_four_octet && open.four_octet_capable(),
                    internal: open.peer_as4() == self.config.local_as,
                    route_refresh: open.supports_route_refresh(),
                    graceful_restart: open.graceful_restart(),
                    add_path_v4: open.add_path(1, 1),
                    add_path_v6: open.add_path(2, 1),
                    // RFC 7911 §5's receive MUST: we receive multiple
                    // paths only when we offered S/R 1 and the peer
                    // offered S/R 2/3 for the family.
                    add_path_rx_v4: self.config.add_path_rx_v4
                        && matches!(open.add_path(1, 1), 2 | 3),
                    add_path_rx_v6: self.config.add_path_rx_v6
                        && matches!(open.add_path(2, 1), 2 | 3),
                    // The mirrored transmit MUST: we send multiple
                    // paths only when we offered S/R 2/3 and the peer
                    // offered S/R 1/3 (willing to receive).
                    add_path_tx_v4: self.config.add_path_tx_v4
                        && matches!(open.add_path(1, 1), 1 | 3),
                    add_path_tx_v6: self.config.add_path_tx_v6
                        && matches!(open.add_path(2, 1), 1 | 3),
                };
                let zero_hold = negotiated.hold_time == 0;
                self.negotiated = Some(negotiated);
                self.state = State::OpenConfirm;
                let mut actions = vec![Action::StopConnectRetry, Action::SendKeepalive];
                if zero_hold {
                    // §4.2: negotiated zero — neither timer runs.
                } else {
                    actions.push(Action::ArmNegotiatedTimers);
                }
                actions
            }
            Event::BgpHeaderErr(code, subcode) | Event::BgpOpenMsgErr(code, subcode) => {
                self.error_teardown();
                vec![Action::Notify(code, subcode), Action::CloseTcp]
            }
            Event::NotifMsg => {
                self.error_teardown();
                vec![Action::CloseTcp]
            }
            // Events 26-28 in OpenSent are the catch-all FSM error.
            _ => {
                self.error_teardown();
                vec![Action::Notify(5, 0), Action::CloseTcp]
            }
        }
    }

    fn fire_open_confirm(&mut self, event: Event) -> Vec<Action> {
        match event {
            Event::KeepAliveMsg => {
                // §8.2.2.6: → Established.
                self.state = State::Established;
                Vec::new()
            }
            Event::HoldTimerExpires => {
                self.error_teardown();
                vec![Action::Notify(4, 0), Action::CloseTcp]
            }
            Event::KeepaliveTimerExpires => {
                vec![Action::SendKeepalive, Action::RestartKeepalive]
            }
            Event::TcpConnectionFails | Event::NotifMsg => {
                self.error_teardown();
                vec![Action::CloseTcp]
            }
            Event::BgpHeaderErr(code, subcode) | Event::BgpOpenMsgErr(code, subcode) => {
                self.error_teardown();
                vec![Action::Notify(code, subcode), Action::CloseTcp]
            }
            Event::ManualStop => {
                self.error_teardown();
                vec![Action::CloseTcp]
            }
            // Events 9, 11-13, 20, 25-28 shape → FSM error.
            _ => {
                self.error_teardown();
                vec![Action::Notify(5, 0), Action::CloseTcp]
            }
        }
    }

    fn fire_established(&mut self, event: Event) -> Vec<Action> {
        match event {
            // ManualStop: NOTIFICATION Cease, withdraw, release, → Idle
            // (§8.2.2.7). SIGTERM maps here: §6.7 sanctions Cease for
            // a locally-chosen close.
            Event::ManualStop => {
                self.established_teardown();
                vec![
                    Action::Notify(
                        crate::error::error_code::CEASE,
                        cease_subcode::ADMIN_SHUTDOWN,
                    ),
                    Action::ReleaseResources,
                    Action::CloseTcp,
                ]
            }
            Event::HoldTimerExpires => {
                self.established_teardown();
                vec![
                    Action::Notify(4, 0),
                    Action::ReleaseResources,
                    Action::CloseTcp,
                ]
            }
            Event::KeepaliveTimerExpires => {
                vec![Action::SendKeepalive, Action::RestartKeepalive]
            }
            // Event 26: restart the HoldTimer, stay Established.
            Event::KeepAliveMsg => vec![Action::RestartHoldTimer],
            Event::TcpConnectionFails | Event::NotifMsg => {
                // Withdraw, release, drop, → Idle.
                self.established_teardown();
                vec![Action::ReleaseResources, Action::CloseTcp]
            }
            // Process the UPDATE and restart the HoldTimer (§8.2.2.7
            // Event 27 row); route handling itself is the session
            // layer's, not the FSM's.
            Event::UpdateMsg => vec![Action::RestartHoldTimer],
            Event::UpdateMsgErr(code, subcode) => {
                self.established_teardown();
                vec![
                    Action::Notify(code, subcode),
                    Action::ReleaseResources,
                    Action::CloseTcp,
                ]
            }
            // A second connection (16/17) is §6.8 territory: tracked
            // by the daemon, not a state change here.
            Event::TcpConnectionConfirmed => Vec::new(),
            _ => {
                self.established_teardown();
                vec![
                    Action::Notify(5, 0),
                    Action::ReleaseResources,
                    Action::CloseTcp,
                ]
            }
        }
    }

    /// The common error-path teardown: stop timers, release, → Idle,
    /// bump the ConnectRetryCounter (the tables' repeated tail).
    fn error_teardown(&mut self) {
        self.connect_retry_running = false;
        self.negotiated = None;
        self.connect_retry_counter += 1;
        self.state = State::Idle;
    }

    fn established_teardown(&mut self) {
        self.error_teardown();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::capability::Capability;
    use crate::error::{error_code, open_subcode};

    fn fsm(hold: u16) -> Fsm {
        Fsm::new(SessionConfig::new(65000, "10.0.0.1".parse().unwrap(), hold))
    }

    fn open(hold: u16, as4: bool) -> BgpOpen {
        let caps = if as4 {
            vec![Capability::FourOctetAsNumber { asn: 65001 }]
        } else {
            vec![]
        };
        BgpOpen::new(65001, hold, "10.0.0.2".parse().unwrap(), caps)
    }

    /// Drive a fresh FSM to a given state by the canonical event path.
    fn to(mut f: Fsm, state: State) -> Fsm {
        if state == State::Idle {
            return f;
        }
        if state == State::Active {
            f.fire(Event::Start { passive: true });
            return f;
        }
        f.fire(Event::Start { passive: false });
        if state == State::Connect {
            return f;
        }
        f.fire(Event::TcpConnectionConfirmed);
        if state == State::OpenSent {
            return f;
        }
        f.fire(Event::BgpOpen(open(90, true)));
        if state == State::OpenConfirm {
            return f;
        }
        f.fire(Event::KeepAliveMsg);
        assert_eq!(f.state(), State::Established);
        f
    }

    /// Table-driven rows: (state, event) → (expected state, expected
    /// actions). Each cites the RFC event/section it pins.
    #[test]
    fn idle_start_active_moves_to_connect() {
        // §8.2.2.1 Events 1/3: → Connect, ConnectRetry started, TCP
        // initiated.
        let mut f = fsm(90);
        let actions = f.fire(Event::Start { passive: false });
        assert_eq!(f.state(), State::Connect);
        assert_eq!(actions, vec![Action::StartConnectRetry, Action::ConnectTcp]);
    }

    #[test]
    fn idle_passive_start_moves_to_active() {
        // §8.2.2.1 Events 4/5 (PassiveTcpEstablishment): → Active.
        let mut f = fsm(90);
        f.fire(Event::Start { passive: true });
        assert_eq!(f.state(), State::Active);
    }

    #[test]
    fn idle_ignores_hold_expiry() {
        // "Events 9-12, 15-28 ... do not cause change".
        let mut f = fsm(90);
        let actions = f.fire(Event::HoldTimerExpires);
        assert_eq!(f.state(), State::Idle);
        assert!(actions.is_empty());
    }

    #[test]
    fn connect_start_events_ignored() {
        let mut f = to(fsm(90), State::Connect);
        assert!(f.fire(Event::Start { passive: false }).is_empty());
        assert_eq!(f.state(), State::Connect);
    }

    #[test]
    fn connect_manual_stop_drops_to_idle() {
        // §8.2.2.3 Event 2.
        let mut f = to(fsm(90), State::Connect);
        let actions = f.fire(Event::ManualStop);
        assert_eq!(f.state(), State::Idle);
        assert_eq!(
            actions,
            vec![
                Action::StopConnectRetry,
                Action::ReleaseResources,
                Action::CloseTcp
            ]
        );
    }

    #[test]
    fn connect_retry_expires_reinitiates() {
        // §8.2.2.3 Event 9: restart timer, re-initiate, stay Connect.
        let mut f = to(fsm(90), State::Connect);
        let actions = f.fire(Event::ConnectRetryTimerExpires);
        assert_eq!(f.state(), State::Connect);
        assert_eq!(
            actions,
            vec![Action::RestartConnectRetry, Action::ConnectTcp]
        );
    }

    #[test]
    fn connect_confirmed_sends_open_sets_large_hold() {
        // §8.2.2.3 Events 16/17 (DelayOpen FALSE): OPEN out, Hold ←
        // large, → OpenSent.
        let mut f = to(fsm(90), State::Connect);
        let actions = f.fire(Event::TcpConnectionConfirmed);
        assert_eq!(f.state(), State::OpenSent);
        assert_eq!(
            actions,
            vec![
                Action::StopConnectRetry,
                Action::SendOpen,
                Action::SetHoldLarge
            ]
        );
    }

    #[test]
    fn connect_tcp_fail_moves_to_active() {
        let mut f = to(fsm(90), State::Connect);
        f.fire(Event::TcpConnectionFails);
        assert_eq!(f.state(), State::Active);
    }

    #[test]
    fn connect_open_err_notifies_and_idles() {
        // §8.2.2.3 Event 21/22.
        let mut f = to(fsm(90), State::Connect);
        let actions = f.fire(Event::BgpOpenMsgErr(
            error_code::OPEN_MESSAGE,
            open_subcode::BAD_PEER_AS,
        ));
        assert_eq!(f.state(), State::Idle);
        assert_eq!(f.connect_retry_counter, 1);
        assert_eq!(
            actions,
            vec![
                Action::Notify(error_code::OPEN_MESSAGE, open_subcode::BAD_PEER_AS),
                Action::CloseTcp
            ]
        );
    }

    #[test]
    fn active_retry_moves_to_connect() {
        // §8.2.2.4 Event 9: → Connect.
        let mut f = to(fsm(90), State::Active);
        f.fire(Event::ConnectRetryTimerExpires);
        assert_eq!(f.state(), State::Connect);
    }

    #[test]
    fn opensent_valid_open_negotiates_and_confirms() {
        // §8.2.2.5 Event 19: KEEPALIVE out, timers at negotiated
        // values, → OpenConfirm. Negotiation = min(local, received)
        // (§4.2), 4-octet iff both advertised (RFC 6793).
        let mut f = to(fsm(90), State::OpenSent);
        let actions = f.fire(Event::BgpOpen(open(30, true)));
        assert_eq!(f.state(), State::OpenConfirm);
        assert_eq!(
            actions,
            vec![
                Action::StopConnectRetry,
                Action::SendKeepalive,
                Action::ArmNegotiatedTimers
            ]
        );
        let n = f.negotiated().unwrap();
        assert_eq!(n.hold_time, 30, "min(90, 30) per §4.2");
        assert!(n.asn4);
        assert!(!n.internal, "65001 != 65000");
        assert_eq!(f.keepalive_time(), 10, "1/3 of negotiated hold (§10)");
    }

    #[test]
    fn opensent_zero_hold_disarms_timers() {
        let mut f = to(fsm(90), State::OpenSent);
        let bare = BgpOpen {
            version: 4,
            my_as: 65001,
            hold_time: 0,
            bgp_id: "10.0.0.2".parse().unwrap(),
            capabilities: Vec::new(),
        };
        let actions = f.fire(Event::BgpOpen(bare));
        assert_eq!(f.state(), State::OpenConfirm);
        assert_eq!(
            actions,
            vec![Action::StopConnectRetry, Action::SendKeepalive],
            "negotiated zero hold: no ArmNegotiatedTimers (§4.2)"
        );
        assert!(!f.negotiated().unwrap().asn4, "peer sent no AS4 capability");
    }

    #[test]
    fn opensent_tcp_fail_moves_to_active() {
        let mut f = to(fsm(90), State::OpenSent);
        f.fire(Event::TcpConnectionFails);
        assert_eq!(f.state(), State::Active);
    }

    #[test]
    fn opensent_bad_open_notifies() {
        let mut f = to(fsm(90), State::OpenSent);
        let actions = f.fire(Event::BgpHeaderErr(1, 3));
        assert_eq!(f.state(), State::Idle);
        assert_eq!(actions, vec![Action::Notify(1, 3), Action::CloseTcp]);
    }

    #[test]
    fn openconfirm_keepalive_establishes() {
        // §8.2.2.6 Event 26.
        let mut f = to(fsm(90), State::OpenConfirm);
        f.fire(Event::KeepAliveMsg);
        assert_eq!(f.state(), State::Established);
    }

    #[test]
    fn openconfirm_hold_expiry_notifies_hold_expired() {
        // §8.2.2.6 Event 10.
        let mut f = to(fsm(90), State::OpenConfirm);
        let actions = f.fire(Event::HoldTimerExpires);
        assert_eq!(f.state(), State::Idle);
        assert_eq!(actions, vec![Action::Notify(4, 0), Action::CloseTcp]);
    }

    #[test]
    fn openconfirm_keepalive_timer_sends_keepalive() {
        // §8.2.2.6 Event 11: send KEEPALIVE, restart timer, stay.
        let mut f = to(fsm(90), State::OpenConfirm);
        let actions = f.fire(Event::KeepaliveTimerExpires);
        assert_eq!(f.state(), State::OpenConfirm);
        assert_eq!(
            actions,
            vec![Action::SendKeepalive, Action::RestartKeepalive]
        );
    }

    #[test]
    fn established_keepalive_restarts_hold() {
        // §8.2.2.7 Event 26: restart HoldTimer, stay.
        let mut f = to(fsm(90), State::Established);
        let actions = f.fire(Event::KeepAliveMsg);
        assert_eq!(f.state(), State::Established);
        assert_eq!(actions, vec![Action::RestartHoldTimer]);
    }

    #[test]
    fn established_update_restarts_hold_and_stays() {
        // §8.2.2.7 Event 27.
        let mut f = to(fsm(90), State::Established);
        let actions = f.fire(Event::UpdateMsg);
        assert_eq!(f.state(), State::Established);
        assert_eq!(actions, vec![Action::RestartHoldTimer]);
    }

    #[test]
    fn established_manual_stop_sends_cease_and_withdraws() {
        // §8.2.2.7 Event 2 + §6.7: Cease for a locally-chosen close.
        let mut f = to(fsm(90), State::Established);
        let actions = f.fire(Event::ManualStop);
        assert_eq!(f.state(), State::Idle);
        assert_eq!(
            actions,
            vec![
                Action::Notify(error_code::CEASE, cease_subcode::ADMIN_SHUTDOWN),
                Action::ReleaseResources,
                Action::CloseTcp
            ]
        );
    }

    #[test]
    fn established_hold_expiry_notifies_and_withdraws() {
        let mut f = to(fsm(90), State::Established);
        let actions = f.fire(Event::HoldTimerExpires);
        assert_eq!(f.state(), State::Idle);
        assert_eq!(
            actions,
            vec![
                Action::Notify(4, 0),
                Action::ReleaseResources,
                Action::CloseTcp
            ]
        );
    }

    #[test]
    fn established_notification_withdraws() {
        // §8.2.2.7 Events 24/25: routes deleted, → Idle.
        let mut f = to(fsm(90), State::Established);
        f.fire(Event::NotifMsg);
        assert_eq!(f.state(), State::Idle);
        assert_eq!(f.connect_retry_counter, 1);
    }

    #[test]
    fn established_tcp_fail_withdraws() {
        let mut f = to(fsm(90), State::Established);
        f.fire(Event::TcpConnectionFails);
        assert_eq!(f.state(), State::Idle);
    }

    #[test]
    fn established_update_error_notifies_update() {
        // §8.2.2.7 Event 28: NOTIFICATION with the update error.
        let mut f = to(fsm(90), State::Established);
        let actions = f.fire(Event::UpdateMsgErr(3, 3));
        assert_eq!(f.state(), State::Idle);
        assert_eq!(
            actions,
            vec![
                Action::Notify(3, 3),
                Action::ReleaseResources,
                Action::CloseTcp
            ]
        );
    }

    /// RFC 4724 §3: the GR capability lands in Negotiated — the
    /// receiving-side retention switch.
    #[test]
    fn negotiation_records_graceful_restart() {
        let mut f = Fsm::new(SessionConfig::new(65000, "10.0.0.1".parse().unwrap(), 90));
        let open = BgpOpen::new(
            65001,
            90,
            "10.9.9.9".parse().unwrap(),
            vec![crate::capability::Capability::GracefulRestart {
                restart_state: true,
                graceful_notification: true,
                restart_time: 150,
                families: vec![(1, 1, true)],
            }],
        );
        f.fire(Event::Start { passive: false });
        f.fire(Event::TcpConnectionConfirmed);
        f.fire(Event::BgpOpen(open));
        assert_eq!(
            f.negotiated().unwrap().graceful_restart,
            Some(crate::fsm::GracefulRestartInfo {
                restart_state: true,
                graceful_notification: true,
                restart_time: 150
            })
        );
        // Without the capability: None (RFC 4271 teardown rules).
        let mut f = Fsm::new(SessionConfig::new(65000, "10.0.0.1".parse().unwrap(), 90));
        let open = BgpOpen::new(65001, 90, "10.9.9.9".parse().unwrap(), vec![]);
        f.fire(Event::Start { passive: false });
        f.fire(Event::TcpConnectionConfirmed);
        f.fire(Event::BgpOpen(open));
        assert_eq!(f.negotiated().unwrap().graceful_restart, None);
    }

    /// RFC 7911 §4: the ADD-PATH Send/Receive values land per family
    /// (N5B foundation).
    #[test]
    fn negotiation_records_add_path_per_family() {
        let mut f = Fsm::new(SessionConfig::new(65000, "10.0.0.1".parse().unwrap(), 90));
        let open = BgpOpen::new(
            65001,
            90,
            "10.9.9.9".parse().unwrap(),
            vec![
                crate::capability::Capability::Multiprotocol { afi: 1, safi: 1 },
                crate::capability::Capability::AddPath(vec![crate::capability::AddPathFamily {
                    afi: 1,
                    safi: 1,
                    send_receive: 3, // both
                }]),
            ],
        );
        f.fire(Event::Start { passive: false });
        f.fire(Event::TcpConnectionConfirmed);
        f.fire(Event::BgpOpen(open));
        let n = f.negotiated().unwrap();
        assert_eq!(n.add_path_v4, 3);
        assert_eq!(n.add_path_v6, 0, "no v6 tuple advertised");
    }

    /// RFC 7911 §5's two direction MUSTs, as the effective-receive
    /// matrix: we receive multiple paths only when locally configured
    /// rx AND the peer offered Send/Receive 2 or 3 for the family.
    /// Everything else stays the classic encoding.
    #[test]
    fn add_path_effective_rx_matrix() {
        let open_with = |v4: u8, v6: u8| {
            let mut tuples = Vec::new();
            if v4 != 0 {
                tuples.push(crate::capability::AddPathFamily {
                    afi: 1,
                    safi: 1,
                    send_receive: v4,
                });
            }
            if v6 != 0 {
                tuples.push(crate::capability::AddPathFamily {
                    afi: 2,
                    safi: 1,
                    send_receive: v6,
                });
            }
            let caps = if tuples.is_empty() {
                vec![]
            } else {
                vec![crate::capability::Capability::AddPath(tuples)]
            };
            BgpOpen::new(65001, 90, "10.9.9.9".parse().unwrap(), caps)
        };
        let negotiate = |local_rx: bool, peer_v4: u8| {
            let mut config = SessionConfig::new(65000, "10.0.0.1".parse().unwrap(), 90);
            config.add_path_rx_v4 = local_rx;
            let mut f = Fsm::new(config);
            f.fire(Event::Start { passive: false });
            f.fire(Event::TcpConnectionConfirmed);
            f.fire(Event::BgpOpen(open_with(peer_v4, 0)));
            f.negotiated().unwrap().add_path_rx_v4
        };
        // local off: nothing the peer says turns extended rx on.
        for peer in [0u8, 1, 2, 3] {
            assert!(!negotiate(false, peer), "local-rx off, peer {peer}");
        }
        // local on: only a peer willing to send (2 or 3) does.
        assert!(!negotiate(true, 0), "peer silent");
        assert!(!negotiate(true, 1), "peer receive-only");
        assert!(negotiate(true, 2), "peer send");
        assert!(negotiate(true, 3), "peer both");
        // v6 independently: peer offers only v4 → v6 stays classic.
        let mut config = SessionConfig::new(65000, "10.0.0.1".parse().unwrap(), 90);
        config.add_path_rx_v6 = true;
        let mut f = Fsm::new(config);
        f.fire(Event::Start { passive: false });
        f.fire(Event::TcpConnectionConfirmed);
        f.fire(Event::BgpOpen(open_with(2, 0)));
        assert!(!f.negotiated().unwrap().add_path_rx_v6);
    }

    /// RFC 7911 §5's transmit MUST as the mirrored matrix: we send
    /// extended NLRI only when locally configured tx AND the peer
    /// offered Send/Receive 1 or 3 (willing to receive) for the family.
    /// `both` against a `both` peer turns every direction on.
    #[test]
    fn add_path_effective_tx_matrix() {
        let open_with = |v4: u8| {
            let caps = if v4 == 0 {
                vec![]
            } else {
                vec![Capability::AddPath(vec![
                    crate::capability::AddPathFamily {
                        afi: 1,
                        safi: 1,
                        send_receive: v4,
                    },
                ])]
            };
            BgpOpen::new(65001, 90, "10.9.9.9".parse().unwrap(), caps)
        };
        let negotiate = |local_tx: bool, peer_v4: u8| {
            let mut config = SessionConfig::new(65000, "10.0.0.1".parse().unwrap(), 90);
            config.add_path_tx_v4 = local_tx;
            let mut f = Fsm::new(config);
            f.fire(Event::Start { passive: false });
            f.fire(Event::TcpConnectionConfirmed);
            f.fire(Event::BgpOpen(open_with(peer_v4)));
            f.negotiated().unwrap().add_path_tx_v4
        };
        // local off: nothing the peer says turns extended tx on.
        for peer in [0u8, 1, 2, 3] {
            assert!(!negotiate(false, peer), "local-tx off, peer {peer}");
        }
        // local on: only a peer willing to receive (1 or 3) does.
        assert!(!negotiate(true, 0), "peer silent");
        assert!(negotiate(true, 1), "peer receive-only");
        assert!(!negotiate(true, 2), "peer send-only");
        assert!(negotiate(true, 3), "peer both");
    }

    /// `addpath both` against a both-capable peer: rx and tx both
    /// negotiate for the family (S/R 3 on each side).
    #[test]
    fn add_path_both_config_negotiates_both_directions() {
        let mut config = SessionConfig::new(65000, "10.0.0.1".parse().unwrap(), 90);
        config.add_path_rx_v4 = true;
        config.add_path_tx_v4 = true;
        let mut f = Fsm::new(config);
        f.fire(Event::Start { passive: false });
        f.fire(Event::TcpConnectionConfirmed);
        f.fire(Event::BgpOpen(BgpOpen::new(
            65001,
            90,
            "10.9.9.9".parse().unwrap(),
            vec![Capability::AddPath(vec![
                crate::capability::AddPathFamily {
                    afi: 1,
                    safi: 1,
                    send_receive: 3,
                },
            ])],
        )));
        let n = f.negotiated().unwrap();
        assert!(n.add_path_rx_v4 && n.add_path_tx_v4);
        assert!(!n.add_path_rx_v6 && !n.add_path_tx_v6, "v6 untouched");
    }

    /// Session-identity facts: iBGP detection and AS_TRANS peers.
    #[test]
    fn negotiation_marks_internal_sessions() {
        let mut f = to(fsm(90), State::OpenSent);
        let mut o = open(90, true);
        o.my_as = 65000;
        o.capabilities = vec![Capability::FourOctetAsNumber { asn: 65000 }];
        f.fire(Event::BgpOpen(o));
        assert!(
            f.negotiated().unwrap().internal,
            "same AS = internal (§8.2.2.3)"
        );
    }

    #[test]
    fn teardown_clears_negotiation() {
        let mut f = to(fsm(90), State::Established);
        assert!(f.negotiated().is_some());
        f.fire(Event::NotifMsg);
        assert!(f.negotiated().is_none());
    }
}
