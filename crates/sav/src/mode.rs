//! Validation modes and per-interface enablement (architecture.md §2's
//! "validation-mode rules" box of the SAV subsystem).
//!
//! The four modes are the taxonomy of
//! draft-ietf-savnet-general-sav-capabilities (GSC; -03, 2026-06-22 is
//! the version these citations track) §2.1–§2.4, as called for by
//! docs/implementation-plan.md §Phase 1.5 "Validation-mode rule model":
//!
//! | Mode   | Scale   | Rule shape                        | Unmatched source |
//! |--------|---------|-----------------------------------|------------------|
//! | IBA    | iface   | interface-based prefix allowlist  | invalid          |
//! | IBB    | iface   | interface-based prefix blocklist  | valid            |
//! | PBA    | router  | prefix-based interface allowlist  | invalid          |
//! | PBB    | router  | prefix-based interface blocklist  | valid            |
//!
//! (GSC §3 Figure 1.) The uRPF-family rule generators ([`crate::gen`])
//! all compile into IBA-shaped rules — GSC §2.1: "FIB-based strict uRPF
//! belongs to this mode", loose uRPF being "an extreme example" of an
//! over-broad allowlist. IBB/PBA/PBB rule *sources* (SAVNET agents,
//! operator config) arrive in later slices; the typed rule data and the
//! compile/evaluate semantics for all four modes exist tonight.
//!
//! Verdict handling is decoupled from the verdict (GSC §4): an "invalid"
//! verdict becomes a [`SavAction`] — Monitor (log) or Drop — carried as
//! data on every enforcement surface, never a hidden global. The default
//! is Monitor per the workspace SAVNET rules ("enforcement defaults to
//! log/monitor before drop; unknown ≠ invalid").

use std::collections::BTreeMap;
use std::fmt;

/// What enforcement does with an "invalid" verdict (GSC §4's traffic
/// handling, scoped to the two policies Rouster's first milestone
/// needs; rate-limit/redirect are noted there as FlowSpec-like
/// extensions). Default: [`SavAction::Monitor`] — log, do not drop.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum SavAction {
    /// Log/monitor only (the default until an operator opts into
    /// dropping): the workspace rule "enforcement defaults to
    /// log/monitor before drop".
    #[default]
    Monitor,
    /// Drop non-conforming traffic.
    Drop,
}

impl SavAction {
    /// True for the drop policy.
    pub fn is_drop(&self) -> bool {
        matches!(self, SavAction::Drop)
    }
}

impl fmt::Display for SavAction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SavAction::Monitor => write!(f, "monitor"),
            SavAction::Drop => write!(f, "drop"),
        }
    }
}

/// Which of the four validation modes a rule (or an interface
/// enablement) belongs to. GSC §2.1–§2.4:
///
/// - [`IBA`](ValidationMode::Iba) — interface-scale prefix **allow**list:
///   "Only the source prefixes recorded in the list will be considered
///   valid, otherwise invalid" (GSC §2.1). Fail closed.
/// - [`IBB`](ValidationMode::Ibb) — interface-scale prefix **block**list:
///   "The source prefixes recorded in the list will be considered
///   invalid, otherwise valid" (GSC §2.2). Fail open.
/// - [`PBA`](ValidationMode::Pba) — router-scale: "The router maintains
///   an interface allowlist for each protected source prefix. A packet
///   is considered valid only if its incoming interface is in the
///   interface allowlist for that source prefix" (GSC §2.3).
/// - [`PBB`](ValidationMode::Pbb) — router-scale: a packet is invalid
///   only "when its incoming interface is in the interface blocklist"
///   for that source prefix (GSC §2.4).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum ValidationMode {
    /// Interface-based prefix allowlist (GSC §2.1).
    Iba,
    /// Interface-based prefix blocklist (GSC §2.2).
    Ibb,
    /// Prefix-based interface allowlist (GSC §2.3).
    Pba,
    /// Prefix-based interface blocklist (GSC §2.4).
    Pbb,
}

/// The scale a mode applies at (GSC §3 Figure 1's first column).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ModeScale {
    /// One rule list per interface (IBA/IBB).
    Interface,
    /// One rule list per source prefix, router-wide (PBA/PBB).
    Router,
}

/// The polarity of a mode's list (GSC §3 Figure 1: "allowlist" ⇒
/// invalid if *not* matched; "blocklist" ⇒ invalid if matched).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ModePolarity {
    /// Allowlist: unmatched ⇒ invalid (fail closed).
    Allow,
    /// Blocklist: unmatched ⇒ valid (fail open).
    Block,
}

impl ValidationMode {
    /// The scale this mode applies at.
    pub fn scale(&self) -> ModeScale {
        match self {
            ValidationMode::Iba | ValidationMode::Ibb => ModeScale::Interface,
            ValidationMode::Pba | ValidationMode::Pbb => ModeScale::Router,
        }
    }

    /// The list polarity: allowlists fail closed, blocklists fail open
    /// (the Figure 1 "Validation result" cells, GSC §3).
    pub fn polarity(&self) -> ModePolarity {
        match self {
            ValidationMode::Iba | ValidationMode::Pba => ModePolarity::Allow,
            ValidationMode::Ibb | ValidationMode::Pbb => ModePolarity::Block,
        }
    }

    /// True for the two interface-scale modes.
    pub fn is_interface_scale(&self) -> bool {
        self.scale() == ModeScale::Interface
    }
}

impl fmt::Display for ValidationMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let name = match self {
            ValidationMode::Iba => "IBA-SAV",
            ValidationMode::Ibb => "IBB-SAV",
            ValidationMode::Pba => "PBA-SAV",
            ValidationMode::Pbb => "PBB-SAV",
        };
        f.write_str(name)
    }
}

/// One interface's enforcement configuration: the interface-scale mode
/// enabled on it plus the action applied to invalid verdicts there.
///
/// An interface holds at most one interface-scale mode at a time
/// ([`SavConfig`]'s map makes "IBA and IBB on the same interface"
/// structurally unrepresentable — GSC §3 requires exactly that
/// exclusivity; the sanctioned merge-by-subtraction variant is noted on
/// [`crate::table::compile`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InterfaceEnforcement {
    /// The interface-scale mode enabled on this interface.
    pub mode: ValidationMode,
    /// What to do with invalid verdicts here. Defaults to
    /// [`SavAction::Monitor`] — an interface opts into [`SavAction::Drop`]
    /// explicitly, never by default.
    pub action: SavAction,
}

impl InterfaceEnforcement {
    /// Enable `mode` with the default (monitor) action.
    pub fn new(mode: ValidationMode) -> Self {
        Self {
            mode,
            action: SavAction::default(),
        }
    }
}

/// The SAV enforcement configuration: which validation mode (if any) is
/// enabled on each interface, and the actions invalid verdicts map to.
///
/// Actions are carried as data at the granularity GSC §4 sanctions
/// ("per system level, per interface level, or ... rule level"): per
/// interface for the interface-scale modes, and a router-wide default
/// for the router-scale modes tonight (per-rule action granularity
/// arrives with operator config in a later slice). There is no hidden
/// global: everything an enforcement surface needs is in this struct or
/// in the compiled ops derived from it.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SavConfig {
    /// Per-interface enablement, keyed by kernel ifindex. An interface
    /// absent from this map has no interface-scale mode enabled —
    /// traffic arriving there is *unknown*, never invalid.
    interfaces: BTreeMap<u32, InterfaceEnforcement>,
    /// The action for router-scale (PBA/PBB) invalid verdicts; defaults
    /// to [`SavAction::Monitor`].
    router_action: SavAction,
}

impl SavConfig {
    /// An empty configuration: nothing enabled anywhere, monitor-only.
    pub fn new() -> Self {
        Self::default()
    }

    /// Enable `mode` on `ifindex` with the given action
    /// (insert-or-replace — the latest call for an interface wins, so an
    /// interface can flip modes but never hold two).
    pub fn enable_interface(&mut self, ifindex: u32, mode: ValidationMode, action: SavAction) {
        self.interfaces
            .insert(ifindex, InterfaceEnforcement { mode, action });
    }

    /// The enforcement enabled on `ifindex`, if any.
    pub fn enforcement(&self, ifindex: u32) -> Option<&InterfaceEnforcement> {
        self.interfaces.get(&ifindex)
    }

    /// The mode enabled on `ifindex`, if any.
    pub fn mode_on(&self, ifindex: u32) -> Option<ValidationMode> {
        self.enforcement(ifindex).map(|e| e.mode)
    }

    /// The action for invalid verdicts on `ifindex` ([`SavAction::Monitor`]
    /// when no mode is enabled there — nothing to act on).
    pub fn action_on(&self, ifindex: u32) -> SavAction {
        self.enforcement(ifindex)
            .map(|e| e.action)
            .unwrap_or_default()
    }

    /// The router-wide action for router-scale (PBA/PBB) invalid
    /// verdicts.
    pub fn router_action(&self) -> SavAction {
        self.router_action
    }

    /// Override the router-scale action (data, not a global default
    /// outside the config).
    pub fn set_router_action(&mut self, action: SavAction) {
        self.router_action = action;
    }

    /// The ifindexes with `mode` enabled, ascending (BTreeMap order —
    /// deterministic).
    pub fn enabled_interfaces(&self, mode: ValidationMode) -> Vec<u32> {
        self.interfaces
            .iter()
            .filter(|(_, e)| e.mode == mode)
            .map(|(&ifindex, _)| ifindex)
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// GSC §3 Figure 1, as a table test: each mode's scale and
    /// polarity, exactly the four rows of the taxonomy.
    #[test]
    fn mode_scale_and_polarity_table() {
        let table = [
            (
                ValidationMode::Iba,
                ModeScale::Interface,
                ModePolarity::Allow,
            ),
            (
                ValidationMode::Ibb,
                ModeScale::Interface,
                ModePolarity::Block,
            ),
            (ValidationMode::Pba, ModeScale::Router, ModePolarity::Allow),
            (ValidationMode::Pbb, ModeScale::Router, ModePolarity::Block),
        ];
        for (mode, scale, polarity) in table {
            assert_eq!(mode.scale(), scale, "{mode}");
            assert_eq!(mode.polarity(), polarity, "{mode}");
            assert_eq!(mode.is_interface_scale(), scale == ModeScale::Interface);
        }
    }

    /// GSC §3: "IBA-SAV and IBB-SAV ... must not be enabled on same
    /// interface at same time." The config's one-slot-per-interface map
    /// makes the violation unrepresentable: enabling IBB replaces IBA.
    #[test]
    fn an_interface_holds_at_most_one_interface_scale_mode() {
        let mut cfg = SavConfig::new();
        cfg.enable_interface(2, ValidationMode::Iba, SavAction::Monitor);
        assert_eq!(cfg.mode_on(2), Some(ValidationMode::Iba));
        cfg.enable_interface(2, ValidationMode::Ibb, SavAction::Monitor);
        assert_eq!(
            cfg.mode_on(2),
            Some(ValidationMode::Ibb),
            "the latest enablement replaces the previous mode"
        );
        assert_eq!(cfg.interfaces.len(), 1);
        assert_eq!(cfg.mode_on(3), None, "an unconfigured interface");
    }

    /// The workspace SAVNET rule: enforcement defaults to log/monitor
    /// before drop — action is data, and the data defaults to Monitor.
    #[test]
    fn actions_default_to_monitor() {
        assert_eq!(SavAction::default(), SavAction::Monitor);
        assert!(!SavAction::default().is_drop());
        assert!(SavAction::Drop.is_drop());
        let cfg = SavConfig::new();
        assert_eq!(cfg.action_on(9), SavAction::Monitor);
        assert_eq!(cfg.router_action(), SavAction::Monitor);
        let mut cfg = cfg;
        cfg.enable_interface(2, ValidationMode::Iba, SavAction::Drop);
        assert_eq!(cfg.action_on(2), SavAction::Drop);
        assert_eq!(cfg.action_on(3), SavAction::Monitor);
    }

    /// `enabled_interfaces` is sorted and mode-filtered (generator input
    /// determinism).
    #[test]
    fn enabled_interfaces_are_sorted_per_mode() {
        let mut cfg = SavConfig::new();
        cfg.enable_interface(7, ValidationMode::Iba, SavAction::Monitor);
        cfg.enable_interface(2, ValidationMode::Iba, SavAction::Monitor);
        cfg.enable_interface(5, ValidationMode::Ibb, SavAction::Monitor);
        assert_eq!(cfg.enabled_interfaces(ValidationMode::Iba), vec![2, 7]);
        assert_eq!(cfg.enabled_interfaces(ValidationMode::Ibb), vec![5]);
        assert!(cfg.enabled_interfaces(ValidationMode::Pba).is_empty());
    }
}
