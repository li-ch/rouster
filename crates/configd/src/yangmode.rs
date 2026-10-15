//! The YANG mode — invariant 5's flip (S11-a M4): the canonical
//! file's section bodies bind to the daemon's YANG model
//! (`crates/yang` + `yang/*.yang`), the trees VALIDATE before
//! anything is rendered or written, and the per-daemon files RENDER
//! FROM THE TREES — the tree is the internal source of truth, the
//! text grammar stays the edge input, and the render output is
//! byte-identical to the section-split render (asserted by test
//! against the legacy renderer, which stays as the oracle).
//!
//! The layers, in order (docs/protocols/config.md §2's pipeline
//! gains step 1.4):
//!
//! 1. canonical parse (structural — unchanged, `tree`);
//! 2. **YANG bind + validate (this module)**: each section body →
//!    linebind → `DataTree`; `validate()` violations refuse the
//!    apply with data-path + line errors; unmodeled lines are a
//!    DISCLOSED pass-through (the daemon's own `--validate-config`
//!    remains the semantic gate — step 1.5 unchanged);
//! 3. render from the trees (byte-stable: every source line rides
//!    the tree with its origin; trailing blank body lines drop,
//!    exactly the legacy contract);
//! 4. the deep-validation gate, the atomic writes, the signals —
//!    unchanged, now consuming the tree-rendered bytes.
//!
//! `configd dump --json` (§4 of the operator surface) emits the
//! bound trees in the RFC 7951 JSON encoding (leafs §5.1,
//! containers §5.2, leaf-lists §5.3, lists §5.4; type mapping §6) —
//! RESTCONF's RFC 8040 §5.2 points at exactly this encoding (its
//! §5.3 is metadata; the encoding itself is RFC 7951 — cited where
//! it lives). Defaults are filled before encoding (report-all; no
//! with-defaults negotiation is pretended). Unmodeled lines ride a
//! non-standard `#unmodeled` member per daemon — the disclosure
//! made machine-readable, documented in docs/yang.md.

use std::collections::BTreeMap;
use std::net::Ipv4Addr;

use tracing::warn;

use crate::tree::{BodyLine, Canonical, Daemon, RestconfStanza};
use yang::line::{BindReport, LineDialect, SourceLine};
use yang::{DataTree, Path, Violation};

/// restconfd's default port (S12-a): no IANA allocation exists for
/// RESTCONF; 8080 is the plain-HTTP convention, disclosed (the
/// model's `default` mirrors it).
pub const RESTCONF_DEFAULT_PORT: u16 = 8080;
/// restconfd's default bind: loopback only — the v1 security
/// posture (docs/yang.md's implementation section).
pub const RESTCONF_DEFAULT_BIND: &str = "127.0.0.1";

/// The env escape hatch for the YANG mode (the CLI's `--no-yang`
/// sets it before any library call — the same pattern as
/// [`crate::validate::BIN_DIR_ENV`]). Absent = the YANG mode IS the
/// mode (invariant 5; the e2e suite runs flipped by default).
pub const NO_YANG_ENV: &str = "ROUSTER_CONFIGD_NO_YANG";

/// Is the YANG mode enabled? (Default yes.)
pub fn yang_enabled() -> bool {
    std::env::var(NO_YANG_ENV).is_err()
}

/// The boolean line dialect per daemon: savd/bfdd spell booleans
/// `yes|no`; bgpd uses the bare-keyword shorthand; the rest default
/// to yes/no (their corpus carries no boolean leafs today).
pub fn dialect_for(daemon: Daemon) -> LineDialect {
    LineDialect {
        boolean: match daemon {
            Daemon::Bgpd => yang::line::BooleanLineForm::Shorthand,
            _ => yang::line::BooleanLineForm::YesNo,
        },
    }
}

/// One daemon's bound section.
#[derive(Debug)]
pub struct SectionBind {
    pub daemon: Daemon,
    pub tree: DataTree,
    pub report: BindReport,
}

/// The canonical file's YANG binding: the per-daemon trees plus the
/// configd-owned router-id (validated against `rouster-common`) and
/// the restconfd stanza (S12-a — validated against `rouster-vty`'s
/// `restconf` container).
#[derive(Debug)]
pub struct Bound {
    pub sections: Vec<SectionBind>,
    pub router_id: Option<(usize, Ipv4Addr)>,
    /// The `restconf { … }` stanza's resolved settings, when the
    /// file carries the stanza.
    pub restconf: Option<RestconfSettings>,
}

/// The restconfd stanza's resolved settings (model defaults filled —
/// `rouster-vty`'s `restconf` container).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RestconfSettings {
    pub port: u16,
    pub bind: String,
    /// The stanza opener's line (errors point at the operator's file).
    pub header_line: usize,
}

impl Bound {
    pub fn section(&self, daemon: Daemon) -> Option<&SectionBind> {
        self.sections.iter().find(|s| s.daemon == daemon)
    }
}

/// A YANG-mode refusal — line-numbered, the house shape (the
/// per-line stderr contract maps onto the bind/violation errors).
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum YangError {
    #[error("line {line}: {reason}")]
    Bind { line: usize, reason: String },
    #[error("{count} YANG constraint violation(s): {details}")]
    Violations { count: usize, details: String },
}

/// Binds every section of a parsed canonical file (step 1.4).
///
/// - Every present section binds to its daemon's model; a bind
///   error (a line the model types but cannot accept) refuses the
///   file — one layer earlier than the daemon's own gate, with the
///   same line number.
/// - Tree validation (mandatory/leaf-list/must) runs per section;
///   violations refuse the file.
/// - Unmodeled lines are WARNINGS (pass-through — configd's v1
///   discipline; the daemon stays the semantic gate).
/// - The `router-id` directive validates against `rouster-common`'s
///   leaf (the envelope's model).
pub fn bind(canonical: &Canonical) -> Result<Bound, YangError> {
    let mut sections = Vec::new();
    for section in &canonical.sections {
        let module = yang::models::module_for_daemon(section.daemon.name())
            .unwrap_or_else(|| panic!("every daemon has a model: {}", section.daemon.name()));
        let sources: Vec<SourceLine> = section
            .body
            .iter()
            .map(|BodyLine { line, text }| SourceLine {
                line: *line,
                text: text.clone(),
            })
            .collect();
        let (tree, report) = yang::line::parse(
            &yang::models::schema(module),
            &sources,
            &dialect_for(section.daemon),
        )
        .map_err(|e| YangError::Bind {
            line: bind_line(&e),
            reason: bind_reason(&e),
        })?;
        if !report.unmodeled.is_empty() {
            warn!(
                daemon = section.daemon.name(),
                lines = ?report.unmodeled,
                "configd: {} line(s) not covered by the YANG model ride pass-through",
                report.unmodeled.len()
            );
        }
        let violations = tree.validate();
        if !violations.is_empty() {
            return Err(violations_error(&violations));
        }
        sections.push(SectionBind {
            daemon: section.daemon,
            tree,
            report,
        });
    }
    // The envelope: router-id against rouster-common's leaf.
    if let Some((line, addr)) = canonical.router_id {
        let schema = yang::models::schema("rouster-common");
        let mut probe = DataTree::empty(schema);
        probe
            .set(
                &Path::parse("/router-id").expect("literal path"),
                &addr.to_string(),
                None,
            )
            .map_err(|e| YangError::Bind {
                line,
                reason: e.to_string(),
            })?;
    }
    // The restconfd stanza (S12-a): bind against rouster-vty's
    // `restconf` container by walking the opener — the body's
    // `port`/`bind` lines land inside it by the linebind's
    // container-walk rule.
    let restconf = canonical.restconf.as_ref().map(bind_restconf).transpose()?;
    Ok(Bound {
        sections,
        router_id: canonical.router_id,
        restconf,
    })
}

/// Binds the `restconf` stanza body: a synthetic `restconf` opener
/// line walks the linebind into rouster-vty's container, the body
/// lines follow inside it, the filled tree yields (port, bind).
fn bind_restconf(stanza: &RestconfStanza) -> Result<RestconfSettings, YangError> {
    let schema = yang::models::schema("rouster-vty");
    let mut sources = vec![SourceLine {
        line: stanza.header_line,
        text: "restconf".to_string(),
    }];
    sources.extend(
        stanza
            .body
            .iter()
            .map(|BodyLine { line, text }| SourceLine {
                line: *line,
                text: text.clone(),
            }),
    );
    let dialect = LineDialect::default();
    let (mut tree, _) =
        yang::line::parse(&schema, &sources, &dialect).map_err(|e| YangError::Bind {
            line: match &e {
                yang::line::LineError::Line { line, .. } => *line,
                yang::line::LineError::Data(_) => stanza.header_line,
            },
            reason: match &e {
                yang::line::LineError::Line { reason, .. } => reason.clone(),
                yang::line::LineError::Data(d) => d.to_string(),
            },
        })?;
    let violations = tree.validate();
    if !violations.is_empty() {
        return Err(violations_error(&violations));
    }
    tree.default_fill();
    let port = tree
        .get_value(&Path::parse("/restconf/port").expect("literal path"))
        .and_then(|v| v.parse().ok())
        .unwrap_or(RESTCONF_DEFAULT_PORT);
    let bind = tree
        .get_value(&Path::parse("/restconf/bind").expect("literal path"))
        .unwrap_or_else(|| RESTCONF_DEFAULT_BIND.to_string());
    Ok(RestconfSettings {
        port,
        bind,
        header_line: stanza.header_line,
    })
}

fn violations_error(violations: &[Violation]) -> YangError {
    let details = violations
        .iter()
        .map(|v| v.to_string())
        .collect::<Vec<_>>()
        .join("; ");
    YangError::Violations {
        count: violations.len(),
        details,
    }
}

/// Renders one daemon's file from its bound tree — the byte-stable
/// contract (§2's render): body lines verbatim, trailing blanks
/// dropped, exactly one final newline. Byte-identical to the legacy
/// section-split render (pinned by test against `render::render_daemon`).
pub fn render_daemon(bound: &SectionBind) -> String {
    let origins = bound.tree.source_lines();
    let mut text = String::new();
    // Drop trailing blank body lines (leading whitespace = blank).
    let lines: Vec<&yang::Origin> = {
        let mut slice = origins.as_slice();
        while let Some(last) = slice.last() {
            if last.raw.trim().is_empty() {
                slice = &slice[..slice.len() - 1];
            } else {
                break;
            }
        }
        slice.iter().collect()
    };
    for origin in lines {
        text.push_str(&origin.raw);
        text.push('\n');
    }
    text
}

/// Renders every bound section, keyed by daemon.
pub fn render_all(bound: &Bound) -> BTreeMap<Daemon, String> {
    bound
        .sections
        .iter()
        .map(|s| (s.daemon, render_daemon(s)))
        .collect()
}

/// The JSON dump (RFC 7951 for the subset): one member per daemon
/// section (the daemon's name — the canonical envelope's own
/// vocabulary), defaults filled, plus the top-level `router-id`,
/// the `restconf` stanza's settings (S12-a), and the non-standard
/// `#unmodeled` disclosure members.
pub fn dump_json(bound: &Bound) -> String {
    let mut parts: Vec<String> = Vec::new();
    match bound.router_id {
        Some((_, addr)) => parts.push(format!("\"router-id\":\"{addr}\"")),
        None => parts.push("\"router-id\":null".to_string()),
    }
    if let Some(settings) = &bound.restconf {
        parts.push(format!(
            "\"restconf\":{{\"port\":{},\"bind\":\"{}\"}}",
            settings.port, settings.bind
        ));
    }
    for section in &bound.sections {
        let mut tree = section.tree.clone();
        tree.default_fill();
        parts.push(format!(
            "\"{}\":{}",
            section.daemon.name(),
            yang::json::encode(&tree)
        ));
        if !section.report.unmodeled.is_empty() {
            let lines: Vec<String> = section
                .report
                .unmodeled
                .iter()
                .map(|l| l.to_string())
                .collect();
            parts.push(format!(
                "\"#unmodeled-{}\":[{}]",
                section.daemon.name(),
                lines.join(",")
            ));
        }
    }
    format!("{{{}}}", parts.join(","))
}

/// A bind error's source line (0 when the error carries none —
/// data-shape errors name their path instead).
fn bind_line(err: &yang::line::LineError) -> usize {
    match err {
        yang::line::LineError::Line { line, .. } => *line,
        yang::line::LineError::Data(_) => 0,
    }
}

fn bind_reason(err: &yang::line::LineError) -> String {
    match err {
        yang::line::LineError::Line { reason, .. } => reason.clone(),
        yang::line::LineError::Data(e) => e.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tree;

    fn bind_text(text: &str) -> Result<Bound, YangError> {
        bind(&tree::parse(text).expect("parses"))
    }

    #[test]
    fn restconf_stanza_binds_with_model_defaults_filled() {
        let bound = bind_text("restconf {\n}\n").unwrap();
        assert_eq!(
            bound.restconf,
            Some(RestconfSettings {
                port: RESTCONF_DEFAULT_PORT,
                bind: RESTCONF_DEFAULT_BIND.to_string(),
                header_line: 1,
            })
        );
        // Explicit values win.
        let bound = bind_text("restconf {\nport 8443\nbind 10.0.0.9\n}\n").unwrap();
        assert_eq!(
            bound.restconf,
            Some(RestconfSettings {
                port: 8443,
                bind: "10.0.0.9".to_string(),
                header_line: 1,
            })
        );
        // No stanza, no settings.
        assert!(bind_text("daemon savd {\n}\n").unwrap().restconf.is_none());
    }

    #[test]
    fn restconf_stanza_type_failures_ride_the_linebind_discipline() {
        // A leaf's type failure is SOFT in the linebind (it retries
        // at a shallower depth, then rides pass-through) — so a bad
        // `port` or `bind` VALUE falls back to the model default with
        // the bad line disclosed as unmodeled, exactly like every
        // daemon section's seam. The JSON mutation path (restconfd's
        // PUT/POST) sets through DataTree directly — type failures
        // are hard 400s there.
        let bound = bind_text("restconf {\nport 99999\n}\n").unwrap();
        assert_eq!(bound.restconf.as_ref().unwrap().port, RESTCONF_DEFAULT_PORT);
        let bound = bind_text("restconf {\nbind not-an-addr\n}\n").unwrap();
        assert_eq!(bound.restconf.as_ref().unwrap().bind, "127.0.0.1");
        // Unknown lines ride pass-through (the discipline).
        let bound = bind_text("restconf {\nport 8081\nfrobnicate yes\n}\n").unwrap();
        assert_eq!(bound.restconf.as_ref().unwrap().port, 8081);
    }

    #[test]
    fn dump_json_carries_the_restconf_member() {
        let bound = bind_text("restconf {\nport 8081\n}\ndaemon savd {\nmode strict\n}\n").unwrap();
        let json = dump_json(&bound);
        assert!(
            json.contains("\"restconf\":{\"port\":8081,\"bind\":\"127.0.0.1\"}"),
            "{json}"
        );
    }
}
