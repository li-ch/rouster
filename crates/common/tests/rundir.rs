//! The fixture-corpus leg of the run-dir reader: every status shape
//! the three daemons publish today, pinned file-by-file through the
//! ONE reader (`common::rundir`). The corpus is the union of the
//! per-consumer corpora (rousterctl's and vty's mirrors, which their
//! own suites keep pinning); these assertions are the reader's own
//! copy of the contract, so a regression is caught in common before
//! any consumer maps it.

use common::rundir::{parse_bfdd, parse_rousterd, parse_savd, SavRule};

fn fixture(name: &str) -> String {
    let path = format!("{}/tests/fixtures/{name}", env!("CARGO_MANIFEST_DIR"));
    std::fs::read_to_string(&path).unwrap_or_else(|err| panic!("fixture {name}: {err}"))
}

// -------------------------------------------------------------- savd

#[test]
fn savd_today_corpus_parses_completely() {
    let parsed = parse_savd(&fixture("savd-status-today.status"));
    assert_eq!(parsed.version.as_deref(), Some("0.0.0"));
    assert_eq!(parsed.pid, Some(4242));
    assert_eq!(parsed.config.mode.as_deref(), Some("strict-uRPF"));
    assert_eq!(parsed.config.poll_secs, Some(5));
    assert_eq!(parsed.installed_claim, Some(2));
    assert_eq!(parsed.evaluated, Some(true));
    assert_eq!(parsed.rules.len(), 2);
    assert_eq!(parsed.monitor.source.as_deref(), Some("simulation"));
    assert_eq!(parsed.unknown_lines, 0);
}

#[test]
fn savd_all_op_kinds_corpus_covers_the_four_shapes() {
    let parsed = parse_savd(&fixture("savd-status-all-op-kinds.status"));
    assert_eq!(parsed.config.action.as_deref(), Some("drop"));
    assert_eq!(parsed.installed_claim, Some(6));
    assert_eq!(parsed.rules.len(), 6);
    // Multi-member prefix set, empty prefix set, both router scales.
    assert!(matches!(
        &parsed.rules[0],
        SavRule::Iface { prefixes, urpf: Some(hint), action, .. }
            if prefixes.len() == 2 && hint == "strict" && action == "drop"
    ));
    assert!(
        matches!(&parsed.rules[4], SavRule::Iface { prefixes, urpf: Some(hint), .. }
            if prefixes.is_empty() && hint == "loose")
    );
    assert!(
        matches!(&parsed.rules[3], SavRule::Prefix { ifindexes, action, .. }
            if ifindexes == &vec![4] && action == "drop")
    );
    assert_eq!(parsed.monitor.source.as_deref(), Some("dataplane"));
    assert_eq!(parsed.monitor.invalid, Some(7));
}

#[test]
fn savd_future_fields_corpus_tolerates_growth() {
    let parsed = parse_savd(&fixture("savd-status-future-fields.status"));
    assert_eq!(parsed.version.as_deref(), Some("2.0.0"));
    assert_eq!(parsed.pid, Some(51_234));
    assert_eq!(parsed.config.bindings, Some(1));
    assert_eq!(parsed.rules.len(), 1);
    assert!(matches!(&parsed.rules[0], SavRule::Raw(_)));
    assert_eq!(parsed.unknown_lines, 1);
}

#[test]
fn savd_malformed_corpus_stays_defensive() {
    let parsed = parse_savd(&fixture("savd-status-malformed.status"));
    assert_eq!(parsed.version.as_deref(), Some("x.y"));
    assert_eq!(parsed.pid, None);
    assert_eq!(parsed.config.poll_secs, None);
    assert_eq!(parsed.installed_claim, None);
    assert_eq!(parsed.rules.len(), 2);
    assert!(parsed.rules.iter().all(|r| matches!(r, SavRule::Raw(_))));
    assert_eq!(parsed.monitor.invalid, None);
    assert_eq!(parsed.monitor.valid, Some(0));
    assert_eq!(parsed.unknown_lines, 1);
}

#[test]
fn savd_never_evaluated_corpus_parses() {
    let parsed = parse_savd(&fixture("savd-status-never-evaluated.status"));
    assert_eq!(parsed.installed_claim, Some(0));
    assert_eq!(parsed.evaluated, Some(false));
    assert!(parsed.rules.is_empty());
}

// -------------------------------------------------------------- bfdd

#[test]
fn bfdd_today_corpus_parses_completely() {
    let parsed = parse_bfdd(&fixture("bfdd-status-today.status"));
    assert_eq!(parsed.pid, Some(4711));
    assert_eq!(parsed.peers_claim, Some(3));
    assert_eq!(parsed.sessions.len(), 3);
    assert_eq!(parsed.sessions[0].remote_discr, Some(7));
    assert!(parsed.sessions[2].last_transition.is_some());
    assert_eq!(parsed.unknown_lines, 0);
}

#[test]
fn bfdd_future_and_malformed_corpora_stay_defensive() {
    let future = parse_bfdd(&fixture("bfdd-status-future-fields.status"));
    assert_eq!(future.version.as_deref(), Some("2.0.0"));
    assert_eq!(future.peers_claim, Some(1));
    assert_eq!(future.sessions.len(), 1);
    assert_eq!(future.unknown_lines, 1, "`agent ...` counts unknown");

    let malformed = parse_bfdd(&fixture("bfdd-status-malformed.status"));
    assert_eq!(malformed.pid, None);
    assert_eq!(malformed.peers_claim, None);
    assert_eq!(
        malformed.sessions.len(),
        1,
        "the peerless session counts unknown"
    );
    assert_eq!(malformed.sessions[0].diag, None);
    // peerless session + empty last-transition child = 2 unknown.
    assert_eq!(malformed.unknown_lines, 2);
}

#[test]
fn bfdd_never_started_corpus_parses_quietly() {
    let parsed = parse_bfdd(&fixture("bfdd-status-never-started.status"));
    assert_eq!(parsed.peers_claim, Some(0));
    assert!(parsed.sessions.is_empty());
    assert_eq!(parsed.unknown_lines, 0);
}

// ------------------------------------------------------------ rousterd

#[test]
fn rousterd_full_corpus_parses_completely() {
    let parsed = parse_rousterd(&fixture("rousterd-status-full.status"));
    assert_eq!(parsed.pid, Some(4242));
    assert_eq!(parsed.router_id.as_deref(), Some("198.51.100.1"));
    assert_eq!(parsed.interfaces_claim, Some(4));
    assert_eq!(parsed.neighbours_claim, Some(2));
    assert_eq!(parsed.tables_claim, Some(2));
    assert_eq!(parsed.interfaces.len(), 4);
    assert_eq!(parsed.interfaces[1].addresses.len(), 2);
    assert_eq!(parsed.interfaces[2].vrf_table, Some(1001));
    assert_eq!(parsed.tables[1].vrf.as_deref(), Some("vrf-blue"));
    assert_eq!(parsed.unknown_lines, 0);
}

#[test]
fn rousterd_empty_corpus_parses_with_claims() {
    let parsed = parse_rousterd(&fixture("rousterd-status-empty.status"));
    assert_eq!(parsed.router_id, None, "`router-id none` parses to None");
    assert_eq!(parsed.interfaces_claim, Some(0));
    assert_eq!(parsed.tables_claim, Some(1));
    assert_eq!(parsed.tables.len(), 1);
    assert_eq!(parsed.unknown_lines, 0);
}

#[test]
fn rousterd_future_corpus_tolerates_growth() {
    let parsed = parse_rousterd(&fixture("rousterd-status-future-fields.status"));
    assert_eq!(parsed.pid, Some(51_234));
    assert_eq!(parsed.router_id.as_deref(), Some("192.0.2.1"));
    assert_eq!(
        parsed.interfaces[0].addresses,
        vec!["192.0.2.1/24 preferred lifetime 2592000s".to_string()]
    );
    assert_eq!(parsed.tables[0].kernel, Some(3));
    assert_eq!(parsed.unknown_lines, 1);
}

#[test]
fn rousterd_malformed_corpus_stays_defensive() {
    let parsed = parse_rousterd(&fixture("rousterd-status-malformed.status"));
    assert_eq!(parsed.pid, None);
    assert_eq!(parsed.router_id, None);
    assert_eq!(
        parsed.interfaces.len(),
        1,
        "the bare `interface` line counts unknown"
    );
    assert!(parsed.neighbours.is_empty());
    assert_eq!(parsed.tables[0].routes, None);
    // bare `interface` + anchorless `neighbour` + `neighbours one`?
    // — `neighbours one` is a known-but-unreadable claim, not unknown.
    assert_eq!(parsed.unknown_lines, 2);
}
