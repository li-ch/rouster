//! SavOp → dataplane program conversion (architecture.md §2's "table
//! manager" → "enforcing via the dataplane trait" edge).
//!
//! [`crate::table::SavOp`] is the sav crate's compiled enforcement
//! operation; [`common::SavProgram`] is the backend-neutral form the
//! [`common::Dataplane`] trait installs. This module is the only bridge:
//! pure conversion, no policy of its own — every verdict/counter
//! semantic stays in [`crate::table`], every kernel mapping in the
//! backend. The dependency direction forces that split: `common`
//! cannot see the `sav` crate, so the action enum converts here
//! ([`enforce_of`]) and the uRPF generator semantics travel as the
//! [`common::SavUrpf`] hint on interface allowlists (backends that
//! approximate allowlists with the kernel's FIB uRPF need to know
//! strict from loose; real rule engines ignore it and enforce the
//! prefix content).

use common::{SavEnforce, SavProgram, SavProgramOp, SavUrpf};

use crate::gen::UrpfMode;
use crate::mode::SavAction;
use crate::table::SavOp;

/// Convert a compiled op list into the program the dataplane installs.
///
/// `mode` is the uRPF generator semantics that produced any interface
/// allowlists (W6's `generate_urpf` runs one mode at a time, so one
/// install carries one mode). Router-scale and blocklist ops pass
/// through unchanged — the mode hint is allowlist-only.
pub fn program(ops: &[SavOp], mode: UrpfMode) -> SavProgram {
    SavProgram::from_ops(ops.iter().map(|op| match *op {
        SavOp::IbaPermit {
            ifindex,
            ref prefixes,
            action,
        } => SavProgramOp::IfaceAllow {
            ifindex,
            prefixes: prefixes.clone(),
            urpf: match mode {
                UrpfMode::Strict => SavUrpf::Strict,
                // Loose, FP, and EFP are all route-existence semantics
                // (RFC 3704 §2.3/§2.5, RFC 8704 §2.4): for an
                // FIB-uRPF backend they collapse to loose rp_filter.
                UrpfMode::Loose | UrpfMode::Fp | UrpfMode::Efp => SavUrpf::Loose,
            },
            action: enforce_of(action),
        },
        SavOp::IbbBlock {
            ifindex,
            ref prefixes,
            action,
        } => SavProgramOp::IfaceBlock {
            ifindex,
            prefixes: prefixes.clone(),
            action: enforce_of(action),
        },
        SavOp::PbaPermit {
            prefix,
            ref ifindexes,
            action,
        } => SavProgramOp::PrefixAllow {
            prefix,
            ifindexes: ifindexes.clone(),
            action: enforce_of(action),
        },
        SavOp::PbbBlock {
            prefix,
            ref ifindexes,
            action,
        } => SavProgramOp::PrefixBlock {
            prefix,
            ifindexes: ifindexes.clone(),
            action: enforce_of(action),
        },
    }))
}

/// `SavAction` → the backend-neutral enforcement policy (the orphan
/// rule keeps this as a function, not a `From` impl: neither type's
/// crate may implement on the other's type).
fn enforce_of(action: SavAction) -> SavEnforce {
    match action {
        SavAction::Monitor => SavEnforce::Monitor,
        SavAction::Drop => SavEnforce::Drop,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mode::SavAction;

    fn p(s: &str) -> common::IpPrefix {
        s.parse().unwrap()
    }

    /// All four op kinds map one-to-one onto the program ops, carrying
    /// prefixes/ifindexes and the action (monitor stays monitor — the
    /// default never silently becomes drop).
    #[test]
    fn all_four_ops_map_with_actions_carried() {
        let ops = vec![
            SavOp::IbaPermit {
                ifindex: 2,
                prefixes: vec![p("198.51.100.0/24")],
                action: SavAction::Monitor,
            },
            SavOp::IbbBlock {
                ifindex: 3,
                prefixes: vec![p("192.0.2.0/24")],
                action: SavAction::Drop,
            },
            SavOp::PbaPermit {
                prefix: p("203.0.113.0/24"),
                ifindexes: vec![2, 3],
                action: SavAction::Drop,
            },
            SavOp::PbbBlock {
                prefix: p("2001:db8::/48"),
                ifindexes: vec![4],
                action: SavAction::Monitor,
            },
        ];
        let prog = program(&ops, UrpfMode::Strict);
        let got = prog.ops();
        assert_eq!(got.len(), 4);
        assert!(got.contains(&SavProgramOp::IfaceAllow {
            ifindex: 2,
            prefixes: vec![p("198.51.100.0/24")],
            urpf: SavUrpf::Strict,
            action: SavEnforce::Monitor,
        }));
        assert!(got.contains(&SavProgramOp::IfaceBlock {
            ifindex: 3,
            prefixes: vec![p("192.0.2.0/24")],
            action: SavEnforce::Drop,
        }));
        assert!(got.contains(&SavProgramOp::PrefixAllow {
            prefix: p("203.0.113.0/24"),
            ifindexes: vec![2, 3],
            action: SavEnforce::Drop,
        }));
        assert!(got.contains(&SavProgramOp::PrefixBlock {
            prefix: p("2001:db8::/48"),
            ifindexes: vec![4],
            action: SavEnforce::Monitor,
        }));
    }

    /// The uRPF hint follows the generator mode: strict annotates
    /// Strict; loose/FP/EFP annotate Loose (route-existence semantics).
    #[test]
    fn urpf_hint_follows_generator_mode() {
        let iba = |action| SavOp::IbaPermit {
            ifindex: 7,
            prefixes: vec![p("10.0.0.0/8")],
            action,
        };
        for mode in [UrpfMode::Loose, UrpfMode::Fp, UrpfMode::Efp] {
            let prog = program(&[iba(SavAction::Monitor)], mode);
            let SavProgramOp::IfaceAllow { urpf, .. } = &prog.ops()[0] else {
                panic!("expected allow op");
            };
            assert_eq!(*urpf, SavUrpf::Loose, "{mode} collapses to loose");
        }
        let prog = program(&[iba(SavAction::Monitor)], UrpfMode::Strict);
        let SavProgramOp::IfaceAllow { urpf, action, .. } = &prog.ops()[0] else {
            panic!("expected allow op");
        };
        assert_eq!(*urpf, SavUrpf::Strict);
        assert_eq!(*action, SavEnforce::Monitor, "monitor default carried");
    }

    /// The program is normalized (W6's determinism bar, one layer
    /// down): op order and duplicates do not survive the bridge.
    #[test]
    fn conversion_yields_the_normalized_program() {
        let a = [SavOp::IbaPermit {
            ifindex: 2,
            prefixes: vec![],
            action: SavAction::Drop,
        }];
        let b = [
            SavOp::IbaPermit {
                ifindex: 2,
                prefixes: vec![],
                action: SavAction::Drop,
            },
            SavOp::IbaPermit {
                ifindex: 2,
                prefixes: vec![],
                action: SavAction::Drop,
            },
        ];
        assert_eq!(program(&a, UrpfMode::Strict), program(&b, UrpfMode::Strict));
        assert_eq!(program(&a, UrpfMode::Strict).ops().len(), 1);
    }
}
