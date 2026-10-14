//! BAR-SAV through the existing SAV table manager (S9-a M2): the
//! derivation's typed IBA rules (`sav::barsav`, draft-ietf-sidrops-
//! bar-sav-10 §4/§8) compile with `sav::table::compile`, evaluate
//! under the GSC -03 §3 reference pipeline, and convert into the
//! backend-neutral program (`sav::program`) — the same path every
//! other rule source rides, monitor-default included (repo AGENTS.md:
//! log/monitor before drop).

use common::IpPrefix;
use rpki::{AspaTable, PayloadFlags, Vrp, VrpTable};
use sav::barsav::{generate_barsav, BarNeighbor, BarPath, BarRole, BarsavInput};
use sav::gen::RuleOrigin;
use sav::gen::UrpfMode;
use sav::mode::{SavAction, ValidationMode};
use sav::program::program;
use sav::table::{compile, evaluate, SavOp, Verdict};

fn p(s: &str) -> IpPrefix {
    s.parse().unwrap()
}

fn ip(s: &str) -> std::net::IpAddr {
    s.parse().unwrap()
}

/// The worked topology from the unit tests, one level up: customer
/// 201 (198.51.100.0/24) with sub-customer 202 (203.0.113.0/24) on
/// ifindex 2; lateral peer 401 (192.0.2.0/24) on ifindex 3; provider
/// 501 on ifindex 4; a fourth interface (ifindex 5) with no BAR-SAV
/// stanza at all.
fn topology() -> (Vec<BarNeighbor>, Vec<BarPath>, VrpTable, AspaTable) {
    let neighbors = vec![
        BarNeighbor::new(2, 201, BarRole::Customer),
        BarNeighbor::new(3, 401, BarRole::LateralPeer),
        BarNeighbor::new(4, 501, BarRole::Provider),
    ];
    let paths = vec![
        BarPath::sequence("198.51.100.0/24", 2, &[201]),
        BarPath::sequence("203.0.113.0/24", 2, &[201, 202]),
        BarPath::sequence("192.0.2.0/24", 3, &[401]),
        BarPath::sequence("198.18.0.0/15", 4, &[501, 502]),
    ];
    let mut vrps = VrpTable::new();
    vrps.apply(
        Vrp {
            prefix: p("198.51.100.0/24"),
            max_len: 24,
            asn: 201,
        },
        PayloadFlags::ANNOUNCE,
    )
    .unwrap();
    vrps.apply(
        Vrp {
            prefix: p("203.0.113.0/24"),
            max_len: 24,
            asn: 202,
        },
        PayloadFlags::ANNOUNCE,
    )
    .unwrap();
    let mut aspas = AspaTable::new();
    aspas
        .apply(202, PayloadFlags::ANNOUNCE, [201].into_iter().collect())
        .unwrap();
    (neighbors, paths, vrps, aspas)
}

fn derive() -> sav::barsav::BarsavDerivation {
    let (neighbors, paths, vrps, aspas) = topology();
    let input = BarsavInput::new(100, &neighbors, &paths, &vrps, &aspas);
    generate_barsav(&input)
}

/// The derivation's rules compile, unchanged, through the table
/// manager: one IbaPermit op per BAR-SAV interface, its prefixes
/// exactly the derived allowlist, provenance bar-sav carried onto the
/// op (B5 observation 5 — the op-level origin is the shared origin of
/// every contributing rule).
#[test]
fn barsav_rules_compile_through_the_table_manager() {
    let derivation = derive();
    let rules = derivation.rules();
    let mut cfg = sav::mode::SavConfig::new();
    for ifindex in [2u32, 3, 4] {
        cfg.enable_interface(ifindex, ValidationMode::Iba, SavAction::Monitor);
    }
    let ops = compile(&rules, &cfg);
    let op_for = |ifindex: u32| -> &SavOp {
        ops.iter()
            .find(|op| matches!(op, SavOp::IbaPermit { ifindex: i, .. } if *i == ifindex))
            .expect("op for ifindex")
    };
    // Customer interface: the cone's two prefixes (§4 Steps 11-13).
    match op_for(2) {
        SavOp::IbaPermit {
            prefixes,
            action,
            origin,
            ..
        } => {
            assert_eq!(prefixes, &vec![p("198.51.100.0/24"), p("203.0.113.0/24")]);
            assert_eq!(*action, SavAction::Monitor, "monitor default");
            assert_eq!(*origin, Some(RuleOrigin::BarSav));
        }
        _ => panic!("iba op"),
    }
    // Lateral peer: its own prefix only (§2).
    match op_for(3) {
        SavOp::IbaPermit { prefixes, .. } => {
            assert_eq!(prefixes, &vec![p("192.0.2.0/24")]);
        }
        _ => panic!("iba op"),
    }
    // Provider: §8's G — the loose set minus the cone-exclusive
    // prefixes (both cone prefixes qualify as S here).
    match op_for(4) {
        SavOp::IbaPermit { prefixes, .. } => {
            assert_eq!(prefixes, &vec![p("192.0.2.0/24"), p("198.18.0.0/15")]);
        }
        _ => panic!("iba op"),
    }
    assert_eq!(ops.len(), 3, "no op for the unconfigured ifindex 5");
}

/// Monitor-default is the house rule made concrete: the same rules
/// compiled with drop enabled on one interface carry Drop there and
/// Monitor stays everywhere else — the action is data on the op, and
/// drop requires the operator's explicit config (the savd friction
/// gate upstream of this compile).
#[test]
fn barsav_ops_carry_the_configured_action_with_monitor_default() {
    let derivation = derive();
    let rules = derivation.rules();
    let mut cfg = sav::mode::SavConfig::new();
    cfg.enable_interface(2, ValidationMode::Iba, SavAction::Monitor);
    cfg.enable_interface(3, ValidationMode::Iba, SavAction::Drop);
    let ops = compile(&rules, &cfg);
    let action_of = |ifindex: u32| {
        ops.iter()
            .find(|op| matches!(op, SavOp::IbaPermit { ifindex: i, .. } if *i == ifindex))
            .unwrap()
            .action()
    };
    assert_eq!(action_of(2), SavAction::Monitor);
    assert_eq!(action_of(3), SavAction::Drop);
}

/// The spoof-differential, table-driven (GSC -03 §3 pipeline over the
/// compiled ops): a source inside the customer interface's derived
/// allowlist is Valid there and Invalid on the peer's interface (and
/// vice versa); a source no allowlist lists is Invalid on every
/// BAR-SAV interface (fail-closed IBA, GSC §2.1) but Unknown on an
/// unconfigured one (unknown ≠ invalid); the provider interface
/// permits the non-cone sources (§8 Step 6: G = loose − S).
#[test]
fn barsav_verdicts_the_spoof_differential() {
    let derivation = derive();
    let rules = derivation.rules();
    let mut cfg = sav::mode::SavConfig::new();
    for ifindex in [2u32, 3, 4] {
        cfg.enable_interface(ifindex, ValidationMode::Iba, SavAction::Monitor);
    }
    let ops = compile(&rules, &cfg);
    let cases = [
        // (source, ingress, expected, citation)
        (
            ip("198.51.100.9"),
            2,
            Verdict::Valid,
            "§4 Q covers the customer cone",
        ),
        (
            ip("203.0.113.9"),
            2,
            Verdict::Valid,
            "§4 Step 7: the deeper cone prefix",
        ),
        (
            ip("192.0.2.9"),
            2,
            Verdict::Invalid,
            "the peer's prefix is not in this cone",
        ),
        (
            ip("198.51.100.9"),
            3,
            Verdict::Invalid,
            "the customer's prefix is not the peer's",
        ),
        (
            ip("192.0.2.9"),
            3,
            Verdict::Valid,
            "§2: the peer's own cone",
        ),
        (
            ip("198.51.100.9"),
            4,
            Verdict::Invalid,
            "§8: cone-exclusive, subtracted at providers",
        ),
        (
            ip("203.0.113.9"),
            4,
            Verdict::Invalid,
            "§8 Step 6: S subtracted from loose",
        ),
        (
            ip("192.0.2.9"),
            4,
            Verdict::Valid,
            "§8 Step 6: not cone-exclusive, stays",
        ),
        (
            ip("198.18.9.9"),
            4,
            Verdict::Valid,
            "the provider's own far prefix",
        ),
        (
            ip("198.51.100.9"),
            5,
            Verdict::Unknown,
            "unconfigured interface: unjudged",
        ),
        (ip("203.0.113.9"), 5, Verdict::Unknown, "unknown != invalid"),
    ];
    for (source, ingress, expected, why) in cases {
        assert_eq!(
            evaluate(&ops, source, ingress).verdict,
            expected,
            "src {source} ingress {ingress}: {why}"
        );
    }
}

/// The backend-neutral program: BAR-SAV IbaPermit ops convert into
/// IfaceAllow entries carrying the monitor action as data — the nft
/// backend enforces this CONTENT (interval sets + counters), and the
/// uRPF hint a content-blind sysctl backend would approximate with
/// reads Loose (route-existence semantics — the disclosed
/// approximation; BAR-SAV's real enforcement is the content, which
/// only the nft ruleset expresses).
#[test]
fn barsav_ops_convert_into_the_program_shapes() {
    let derivation = derive();
    let rules = derivation.rules();
    let mut cfg = sav::mode::SavConfig::new();
    for ifindex in [2u32, 3, 4] {
        cfg.enable_interface(ifindex, ValidationMode::Iba, SavAction::Monitor);
    }
    let ops = compile(&rules, &cfg);
    let program = program(&ops, UrpfMode::Loose);
    let allow = |ifindex: u32| {
        program
            .ops()
            .iter()
            .find(|op| matches!(op, common::SavProgramOp::IfaceAllow { ifindex: i, .. } if *i == ifindex))
            .expect("allow op")
    };
    match allow(2) {
        common::SavProgramOp::IfaceAllow {
            prefixes,
            urpf,
            action,
            ..
        } => {
            assert_eq!(prefixes, &vec![p("198.51.100.0/24"), p("203.0.113.0/24")]);
            assert_eq!(*action, common::SavEnforce::Monitor);
            assert_eq!(
                *urpf,
                common::SavUrpf::Loose,
                "the sysctl approximation hint"
            );
        }
        _ => panic!("allow op"),
    }
    assert_eq!(program.ops().len(), 3);
}

/// GSC -03 §2.1 at the BAR-SAV edge: an interface IBA-enabled with an
/// EMPTY derived allowlist denies everything (fail closed) — a real
/// derivation of "nothing is permissible", monitor action included.
/// The unknown-≠-invalid half is the caller's posture: a feed that
/// never arrived enables nothing (savd's disclosed behavior), and
/// with no mode enabled anywhere every packet is Unknown.
#[test]
fn an_empty_derivation_is_deny_all_monitor_or_unjudged() {
    let (neighbors, _paths, _vrps, aspas) = topology();
    let empty: [BarPath; 0] = [];
    let no_vrps = VrpTable::new();
    let input = BarsavInput::new(100, &neighbors, &empty, &no_vrps, &aspas);
    let derivation = generate_barsav(&input);
    assert!(
        derivation.rules().is_empty(),
        "no paths AND no ROAs: nothing derivable"
    );

    // Enabled + empty derivation: the seeded allowlist denies all
    // (GSC §2.1 "otherwise invalid"), the action stays monitor.
    let mut cfg = sav::mode::SavConfig::new();
    for ifindex in [2u32, 3, 4] {
        cfg.enable_interface(ifindex, ValidationMode::Iba, SavAction::Monitor);
    }
    let ops = compile(&derivation.rules(), &cfg);
    assert_eq!(ops.len(), 3, "the seeded empty allowlists");
    assert_eq!(
        evaluate(&ops, ip("198.51.100.9"), 2).verdict,
        Verdict::Invalid,
        "deny-all is the real derivation of an empty permissible set"
    );

    // Nothing enabled (the feed-unavailable posture): unjudged.
    let none = compile(&derivation.rules(), &sav::mode::SavConfig::new());
    assert!(none.is_empty());
    assert_eq!(
        evaluate(&none, ip("198.51.100.9"), 2).verdict,
        Verdict::Unknown,
        "unknown != invalid"
    );
}
