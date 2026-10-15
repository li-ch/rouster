//! Conformance: the model set vs the fixture corpus (S11-a M3).
//!
//! The corpus is the configd suite's canonical bodies (the smoke's
//! v1/v2/bad/poison canonicals, apply_e2e's sections, the
//! validate_gate bodies) plus each daemon parser's own sample
//! configs, cited per entry. Every entry must:
//!
//! 1. bind to its module with the DISCLOSED unmodeled lines only
//!    (the policy pass-through in bgpd; the intentionally broken
//!    pass-through in apply_e2e),
//! 2. validate clean (or, for the corpus's known-BAD configs,
//!    refuse — the model catches what the smoke needed the daemon
//!    for),
//! 3. round-trip byte-identically through the tree
//!    (`render(source_lines()) == input`).

use yang::line::{self, LineDialect, SourceLine};
use yang::models;
use yang::schema::SchemaError;

#[derive(Debug, PartialEq, Eq)]
enum Expect {
    /// Binds, validates clean, renders byte-identically.
    Clean,
    /// The bind itself refuses (a type violation), naming the line.
    BindErr,
    /// Binds, but validate() refuses (a must violation).
    ValidateFail,
}

fn bind(module: &str, text: &str) -> (yang::DataTree, line::BindReport) {
    let lines: Vec<SourceLine> = text
        .lines()
        .enumerate()
        .map(|(i, l)| SourceLine {
            line: i + 1,
            text: l.trim_end().to_string(),
        })
        .collect();
    line::parse(
        &models::schema(module),
        &lines,
        &LineDialect {
            boolean: line::BooleanLineForm::Shorthand,
        },
    )
    .unwrap_or_else(|e| panic!("{module}: bind failed: {e}"))
}

fn rendered(tree: &yang::DataTree) -> String {
    let lines = tree.source_lines();
    if lines.is_empty() {
        return String::new();
    }
    let mut out = lines
        .iter()
        .map(|o| o.raw.clone())
        .collect::<Vec<_>>()
        .join("\n");
    out.push('\n');
    out
}

/// (name, module, text, expected-unmodeled-line-count, expectation)
fn corpus() -> Vec<(&'static str, &'static str, String, usize, Expect)> {
    vec![
        // ---- scripts/test-configd-smoke.sh write_canonical_v1/v2 ----
        (
            "smoke rousterd v2 (zapi socket)",
            "rouster-common",
            "zapi socket /run/rouster/zserv.api\n".to_string(),
            0,
            Expect::Clean,
        ),
        (
            "smoke savd v2 (two stanzas + poll)",
            "rouster-savd",
            "interface veths1\n  mode strict\ninterface veths2\n  mode strict\npoll 3\n"
                .to_string(),
            0,
            Expect::Clean,
        ),
        (
            "smoke bfdd v2 (two peers)",
            "rouster-bfdd",
            "peer 192.0.2.9\n  transmit-interval 300\npeer 198.51.100.9\n".to_string(),
            0,
            Expect::Clean,
        ),
        (
            "smoke savd POISON (comment marker rides opaque)",
            "rouster-savd",
            "interface veths1\n  mode strict\npoll 9\n! refused-load\n".to_string(),
            0,
            Expect::Clean,
        ),
        // ---- scripts/test-configd-smoke.sh write_canonical_bad ----
        (
            "smoke savd BAD (mode nosuch refuses at the MODEL now)",
            "rouster-savd",
            "interface veths1\n  mode nosuch\n".to_string(),
            0,
            Expect::BindErr,
        ),
        // ---- crates/configd/tests/apply_e2e.rs ----
        (
            "apply_e2e savd section",
            "rouster-savd",
            "mode strict\npoll 2\n".to_string(),
            0,
            Expect::Clean,
        ),
        (
            "apply_e2e bfdd section",
            "rouster-bfdd",
            "peer 192.0.2.9\n".to_string(),
            0,
            Expect::Clean,
        ),
        // (apply_e2e's `mode broken-but-pass-through` line rides a
        // STRUCTURALLY broken file — the canonical parse refuses it
        // before any body handling; it is not a pass-through case.)
        // ---- crates/bgpd/src/config.rs SAMPLE ----
        (
            "bgpd SAMPLE",
            "rouster-bgpd",
            "# rouster bgpd\nzapi socket /run/rouster/zapi.api\nrouter bgp 65000\n bgp router-id 10.0.0.1\n neighbor 192.0.2.9 remote-as 65001\n neighbor 192.0.2.9 timers 10 30\n network 203.0.113.0/24\n network 2001:db8:1::/48\n".to_string(),
            0,
            Expect::Clean,
        ),
        // ---- crates/bgpd/src/config.rs module docs (the W2-e/W1-a shape) ----
        (
            "bgpd policy stanzas ride opaque (disclosed)",
            "rouster-bgpd",
            "router bgp 65000\n import IN\n export OUT\nrpki\n cache 192.0.2.10 3323\n vrp-file /etc/rouster/vrps.conf\n reject-invalid true\naspa advisory\nroute-map IN permit 10\n match ip address prefix-list CUST\n set local-preference 200\nip prefix-list CUST seq 5 permit 203.0.113.0/24\n".to_string(),
            // route-map + match + set + ip prefix-list: the W1-a
            // policy grammar, unmodeled by design (4 lines).
            4,
            Expect::ValidateFail, // cache AND vrp-file: the model's must refuses it (bgpd agrees)
        ),
        (
            "bgpd neighbor surface",
            "rouster-bgpd",
            "router bgp 65000\n neighbor 192.0.2.9 remote-as 65001\n neighbor 192.0.2.9 passive\n neighbor 192.0.2.9 mrai 0\n neighbor 192.0.2.9 role peer\n neighbor 192.0.2.9 update-error-handling rfc7606\n neighbor 192.0.2.9 route-server\n neighbor 10.0.0.9 route-reflector-client\n graceful-restart deferral 120\n neighbor 192.0.2.9 graceful-restart 120\n neighbor 192.0.2.9 addpath both\n".to_string(),
            0,
            Expect::Clean,
        ),
        // ---- crates/ospfd/src/config.rs module docs ----
        (
            "ospfd key chains + router stanza",
            "rouster-ospfd",
            "zapi socket /run/rouster/zapi.api\nkey chain kc1\n key 1\n  key-string old-secret\n  cryptographic-algorithm hmac-sha-256\n  send-lifetime 0 infinite\n  accept-lifetime 0 3600\n key 2\n  key-string new-secret\n  cryptographic-algorithm md5\n  send-lifetime 3600 infinite\n  accept-lifetime 3600 infinite\nrouter ospf\n router-id 10.0.0.1\n area 0.0.0.0\n  interface eth0\n   authentication key-chain kc1\n   cost 10\n   hello-interval 10\n   dead-interval 40\n   priority 1\n  network 10.0.0.0/24 area 0.0.0.0\n redistribute static\n".to_string(),
            0,
            Expect::Clean,
        ),
        (
            "ospfd area parameters (stub/nssa ladder + ranges + vlink)",
            "rouster-ospfd",
            "router ospf\n area 0.0.0.1 stub no-summary\n area 0.0.0.2 nssa default-information-originate\n area 0.0.0.2 default-cost 5\n area 0.0.0.0 range 10.0.0.0/8 advertise cost 20\n area 0.0.0.0 range 192.0.2.0/24 not-advertise\n area 0.0.0.1 virtual-link 10.0.0.9\n".to_string(),
            0,
            Expect::Clean,
        ),
        // ---- crates/isisd/src/config.rs module docs ----
        (
            "isisd sample",
            "rouster-isisd",
            "zapi socket /var/run/frr/zserv.api\nrouter isis ROUSTER\n net 49.0001.1921.6800.1002.00\n is-type level-1-2\n metric-style wide\n hostname rouster-r2\n redistribute static\n interface eth0\n  address 172.16.0.2/24\n  circuit-type level-1-2\n  hello-interval 10\n  hello-multiplier 3\n  mtu 1500\n".to_string(),
            0,
            Expect::Clean,
        ),
        // ---- crates/vty/src/writer.rs (the session surface) ----
        (
            "vtyd session surface (B7's observed set)",
            "rouster-vty",
            "frr version 3\nfrr defaults traditional\nhostname rouster-r1\nline vty\nip route 203.0.113.0/24 blackhole\nrouter bgp 65000\n bgp router-id 10.0.0.1\n bgp network-import-check\n neighbor 192.0.2.9 remote-as 65001\n address-family ipv4 unicast\n  network 203.0.113.0/24\n  redistribute static\n".to_string(),
            0,
            Expect::Clean,
        ),
    ]
}

#[test]
fn the_model_set_parses_and_resolves() {
    // Every embedded module loads; a failure here names its own line.
    for (_, text) in models::MODEL_TEXTS {
        yang::schema::parse_module_text("model", text)
            .unwrap_or_else(|e| panic!("model failed to parse: {e}"));
    }
    // The full set resolves imports and types.
    yang::ModuleSet::build(
        models::MODEL_TEXTS
            .iter()
            .map(|(f, t)| (f.to_string(), t.to_string()))
            .collect(),
    )
    .unwrap();
}

#[test]
fn corpus_conforms() {
    for (name, module, text, unmodeled, expect) in corpus() {
        match expect {
            Expect::BindErr => {
                let lines: Vec<SourceLine> = text
                    .lines()
                    .enumerate()
                    .map(|(i, l)| SourceLine {
                        line: i + 1,
                        text: l.trim_end().to_string(),
                    })
                    .collect();
                let err = line::parse(&models::schema(module), &lines, &LineDialect::default())
                    .expect_err(&format!("{name}: expected the bind to refuse"));
                assert!(
                    err.to_string().contains("line 2"),
                    "{name}: refusal names the line: {err}"
                );
                continue;
            }
            Expect::Clean | Expect::ValidateFail => {}
        }
        let (tree, report) = bind(module, &text);
        assert_eq!(
            report.unmodeled.len(),
            unmodeled,
            "{name}: unmodeled lines {:?}",
            report.unmodeled
        );
        assert_eq!(rendered(&tree), text, "{name}: render round-trip");
        let violations = tree.validate();
        match expect {
            Expect::Clean => assert!(
                violations.is_empty(),
                "{name}: violations: {:?}",
                violations
            ),
            Expect::ValidateFail => assert!(
                !violations.is_empty(),
                "{name}: expected the model to refuse this corpus entry"
            ),
            Expect::BindErr => unreachable!("handled above"),
        }
    }
}

#[test]
fn the_smoke_bad_config_refuses_with_a_line_number() {
    // The smoke's BAD canonical (savd `mode nosuch`): today the
    // daemon's --validate-config catches it; the model now catches
    // it one layer earlier, with the same line.
    let lines = vec![
        SourceLine {
            line: 1,
            text: "interface veths1".into(),
        },
        SourceLine {
            line: 2,
            text: "  mode nosuch".into(),
        },
    ];
    let err = line::parse(
        &models::schema("rouster-savd"),
        &lines,
        &LineDialect::default(),
    )
    .unwrap_err();
    assert!(err.to_string().contains("line 2"), "{err}");
}

#[test]
fn schemas_reject_a_bad_model_edit() {
    // A model referencing a typedef that does not exist refuses to
    // load (the machine-readable §Deferred discipline).
    let bad = "module broken {\n  yang-version 1.1;\n  namespace \"urn:x\";\n  prefix b;\n  leaf x { type rc:nonexistent; }\n}\n";
    let e = yang::ModuleSet::build(vec![("bad.yang".into(), bad.to_string())]).unwrap_err();
    assert!(matches!(e, SchemaError::Line { .. }), "{e}");
}
