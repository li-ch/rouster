//! The canonical `rouster.conf` tree (Phase 4, M1).
//!
//! One superset file composes every daemon's config. v1 grammar —
//! line-based like every daemon grammar in the suite (blank / `!` / `#`
//! ignored structurally), with brace-delimited per-daemon sections
//! whose bodies are **pass-through**: configd renders them, the owning
//! daemon parses them (semantic validation stays at the daemon, at
//! reload time — the `--validate-config` flags that would move it
//! earlier are §Deferred and live in the daemon crates).
//!
//! ```text
//! ! the canonical superset (docs/protocols/config.md is the owner)
//! router-id 198.51.100.1
//!
//! daemon rousterd {
//!     zapi socket /run/rouster/zserv.api
//!     ip route 203.0.113.0/24 blackhole
//! }
//!
//! daemon savd {
//!     mode strict
//!     interface vethlegit
//!       mode strict
//! }
//! ```
//!
//! Structural rules (v1 validation, this module's whole job):
//!
//! - `daemon <name> {` opens a section; a line that is exactly `}` (after
//!   trimming) closes it. Sections must nest nowhere else: a lone `}`
//!   outside a section is an error, an unclosed section is an error, and
//!   body lines must not be a lone `}` (none of today's daemon grammars
//!   uses braces — they are all token-per-line, so the terminator is
//!   unambiguous).
//! - The daemon name must be one configd knows how to actuate
//!   ([`Daemon`]); unknown names are refused here, not at apply time.
//! - Each daemon appears at most once; a second section for the same
//!   daemon would make the render order ambiguous.
//! - The body may be empty (a legitimate "wipe this daemon's config"
//!   intent — renders an empty file, valid input for every parser in
//!   the suite today).
//! - `router-id <ipv4>` is the one configd-owned top-level directive:
//!   it must parse as an IPv4 address and may appear at most once. v1
//!   records it in the tree and renders it nowhere — no daemon's
//!   grammar accepts the line yet, so emitting it would poison the
//!   rendered file (the exact ask per daemon is §Deferred in
//!   docs/protocols/config.md).
//! - Any other top-level line outside a section is an error: the
//!   canonical file is configd's own grammar and is strict, unlike the
//!   tolerant run-dir status readers.
//!
//! Line numbers are kept for every element (sections, bodies, the
//! router-id) so errors and audit output point at the operator's file,
//! not a re-rendered intermediate.

use std::net::Ipv4Addr;

/// A daemon configd knows how to actuate, in apply order (rousterd —
/// the RIB/zebra — first, protocols after; `daemon ospfd`/`daemon bgpd`
/// render and write but carry no signal arm yet, see [`crate::apply`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Daemon {
    Rousterd,
    Savd,
    Bfdd,
    Ospfd,
    Bgpd,
}

impl Daemon {
    /// The canonical section name (`daemon <name>`).
    pub fn name(self) -> &'static str {
        match self {
            Daemon::Rousterd => "rousterd",
            Daemon::Savd => "savd",
            Daemon::Bfdd => "bfdd",
            Daemon::Ospfd => "ospfd",
            Daemon::Bgpd => "bgpd",
        }
    }

    /// Parses a section name; unknown names are a structural error.
    pub fn from_name(name: &str) -> Option<Self> {
        match name {
            "rousterd" => Some(Daemon::Rousterd),
            "savd" => Some(Daemon::Savd),
            "bfdd" => Some(Daemon::Bfdd),
            "ospfd" => Some(Daemon::Ospfd),
            "bgpd" => Some(Daemon::Bgpd),
            _ => None,
        }
    }

    /// The daemon's rendered file name (inside configd's etc-dir;
    /// `rouster.conf`, `savd.conf`, `bfdd.conf`, `ospfd.conf`,
    /// `bgpd.conf` — the flat-`/etc` convention every existing smoke
    /// script uses; no daemon binary ships a default `--config` path,
    /// so the deployment convention is the contract).
    pub fn file_name(self) -> &'static str {
        match self {
            Daemon::Rousterd => "rouster.conf",
            Daemon::Savd => "savd.conf",
            Daemon::Bfdd => "bfdd.conf",
            Daemon::Ospfd => "ospfd.conf",
            Daemon::Bgpd => "bgpd.conf",
        }
    }

    /// All daemons in apply order.
    pub fn all() -> [Daemon; 5] {
        [
            Daemon::Rousterd,
            Daemon::Savd,
            Daemon::Bfdd,
            Daemon::Ospfd,
            Daemon::Bgpd,
        ]
    }
}

/// One pass-through body line, with its line number in the canonical
/// file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BodyLine {
    /// 1-based line number in the canonical `rouster.conf`.
    pub line: usize,
    /// The line's text with trailing whitespace trimmed (leading
    /// whitespace is preserved verbatim — it is operator intent, and
    /// every daemon grammar is token-based so it is cosmetic there).
    pub text: String,
}

/// A `daemon <name> { ... }` section of the canonical file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Section {
    /// Which daemon this section feeds.
    pub daemon: Daemon,
    /// Line number of the `daemon <name> {` opener.
    pub header_line: usize,
    /// Line number of the closing `}` (`None` only on the parse error
    /// that names it).
    pub close_line: Option<usize>,
    /// The pass-through body lines, in file order.
    pub body: Vec<BodyLine>,
}

/// The parsed canonical `rouster.conf` (the section tree).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Canonical {
    /// The configd-owned `router-id <ipv4>` directive, if present
    /// (line number + value).
    pub router_id: Option<(usize, Ipv4Addr)>,
    /// Top-level comment / blank lines (wherever they sit outside
    /// sections), kept with line numbers so audit output can name
    /// them. Render consumes section bodies only.
    pub preamble: Vec<BodyLine>,
    /// Daemon sections in file order.
    pub sections: Vec<Section>,
}

impl Canonical {
    /// The section feeding a given daemon, if the file has one.
    pub fn section(&self, daemon: Daemon) -> Option<&Section> {
        self.sections.iter().find(|s| s.daemon == daemon)
    }
}

/// Canonical-file parse errors — line-numbered, the house shape.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum ParseError {
    #[error("line {line}: {reason}")]
    Line { line: usize, reason: String },
}

fn fail(line: usize, reason: impl Into<String>) -> ParseError {
    ParseError::Line {
        line,
        reason: reason.into(),
    }
}

/// A line trimmed for structural matching: leading/trailing whitespace
/// gone, inner whitespace collapsed to single spaces.
fn squash(raw: &str) -> String {
    raw.split_whitespace().collect::<Vec<_>>().join(" ")
}

/// Parses the canonical `rouster.conf` into the section tree.
///
/// Structural validation only — semantic validation is each daemon's,
/// at reload time (disclosed in docs/protocols/config.md).
pub fn parse(input: &str) -> Result<Canonical, ParseError> {
    let mut tree = Canonical::default();
    // The currently open section (its daemon), if any.
    let mut open: Option<usize> = None; // index into tree.sections

    for (idx, raw) in input.lines().enumerate() {
        let line_no = idx + 1;
        let trimmed = raw.trim();
        if trimmed.is_empty() || trimmed.starts_with('!') || trimmed.starts_with('#') {
            match open {
                // Inside a section, comments and blanks are BODY:
                // pass-through, exactly what the owning daemon's
                // parser sees (every daemon grammar ignores them —
                // and the operator wrote them for that file).
                Some(section) => tree.sections[section].body.push(BodyLine {
                    line: line_no,
                    text: raw.trim_end().to_string(),
                }),
                // Outside sections they are preamble, wherever they
                // sit: recorded for audit output. Render consumes
                // bodies only.
                None => tree.preamble.push(BodyLine {
                    line: line_no,
                    text: raw.trim_end().to_string(),
                }),
            }
            continue;
        }

        // Section close: a lone `}` line.
        if trimmed == "}" {
            match open.take() {
                Some(section) => {
                    tree.sections[section].close_line = Some(line_no);
                }
                None => {
                    return Err(fail(line_no, "`}` outside any `daemon` section"));
                }
            }
            continue;
        }

        // Section opener: `daemon <name> {` (brace on the same line —
        // the one shape the render/audit tooling needs to pin).
        if let Some(rest) = squash(trimmed).strip_prefix("daemon ") {
            if open.is_some() {
                return Err(fail(
                    line_no,
                    "`daemon` section inside another section (close it with `}` first)",
                ));
            }
            let Some(name) = rest.strip_suffix(" {") else {
                return Err(fail(
                    line_no,
                    format!("expected `daemon <name> {{`, got `{trimmed}`"),
                ));
            };
            let daemon = Daemon::from_name(name).ok_or_else(|| {
                fail(
                    line_no,
                    format!(
                        "unknown daemon `{name}` (known: {})",
                        Daemon::all()
                            .iter()
                            .map(|d| d.name())
                            .collect::<Vec<_>>()
                            .join(", ")
                    ),
                )
            })?;
            if tree.section(daemon).is_some() {
                return Err(fail(
                    line_no,
                    format!("duplicate `daemon {}` section", daemon.name()),
                ));
            }
            tree.sections.push(Section {
                daemon,
                header_line: line_no,
                close_line: None,
                body: Vec::new(),
            });
            open = Some(tree.sections.len() - 1);
            continue;
        }

        // Body line: pass-through inside an open section.
        if let Some(section) = open {
            tree.sections[section].body.push(BodyLine {
                line: line_no,
                text: raw.trim_end().to_string(),
            });
            continue;
        }

        // Top-level directive: router-id.
        let tokens: Vec<&str> = trimmed.split_whitespace().collect();
        match tokens.as_slice() {
            ["router-id", addr] => {
                if tree.router_id.is_some() {
                    return Err(fail(line_no, "duplicate `router-id` line"));
                }
                let addr: Ipv4Addr = addr.parse().map_err(|_| {
                    fail(
                        line_no,
                        format!("bad router-id address `{addr}` (expected IPv4)"),
                    )
                })?;
                tree.router_id = Some((line_no, addr));
            }
            _ => {
                return Err(fail(
                    line_no,
                    format!("expected `router-id <ipv4>` or `daemon <name> {{`, got `{trimmed}`"),
                ));
            }
        }
    }

    if let Some(section) = open {
        return Err(fail(
            tree.sections[section].header_line,
            format!(
                "`daemon {}` section opened here is never closed (missing `}}`)",
                tree.sections[section].daemon.name()
            ),
        ));
    }

    Ok(tree)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_a_minimal_single_section_with_line_numbers() {
        let text = "daemon savd {\nmode strict\npoll 2\n}\n";
        let tree = parse(text).unwrap();
        assert_eq!(tree.sections.len(), 1);
        let section = &tree.sections[0];
        assert_eq!(section.daemon, Daemon::Savd);
        assert_eq!(section.header_line, 1);
        assert_eq!(section.close_line, Some(4));
        assert_eq!(
            section
                .body
                .iter()
                .map(|l| (l.line, l.text.as_str()))
                .collect::<Vec<_>>(),
            vec![(2, "mode strict"), (3, "poll 2")]
        );
    }

    #[test]
    fn parses_router_id_and_keeps_its_line() {
        let tree = parse("router-id 198.51.100.1\n").unwrap();
        assert_eq!(tree.router_id, Some((1, "198.51.100.1".parse().unwrap())));
    }

    #[test]
    fn preamble_comments_and_blanks_are_kept() {
        let text = "! site config\n\n# managed by configd\nrouter-id 10.0.0.1\ndaemon bfdd {\n}\n";
        let tree = parse(text).unwrap();
        assert_eq!(tree.preamble.len(), 3);
        assert_eq!(tree.preamble[0].line, 1);
        assert_eq!(tree.preamble[0].text, "! site config");
        assert_eq!(tree.preamble[2].text, "# managed by configd");
    }

    #[test]
    fn body_keeps_leading_whitespace_and_comments() {
        let text = "daemon ospfd {\nrouter ospf\n  area 0.0.0.0\n    interface eth0\n! comment inside\n}\n";
        let tree = parse(text).unwrap();
        let body = &tree.sections[0].body;
        assert_eq!(body[1].text, "  area 0.0.0.0");
        assert_eq!(body[2].text, "    interface eth0");
        assert_eq!(body[3].text, "! comment inside");
    }

    #[test]
    fn empty_body_is_allowed() {
        let tree = parse("daemon rousterd {\n}\n").unwrap();
        assert!(tree.sections[0].body.is_empty());
        assert_eq!(tree.sections[0].close_line, Some(2));
    }

    #[test]
    fn multiple_sections_in_order() {
        let text = "daemon rousterd {\n}\ndaemon savd {\n}\ndaemon bgpd {\n}\n";
        let tree = parse(text).unwrap();
        let names: Vec<_> = tree.sections.iter().map(|s| s.daemon.name()).collect();
        assert_eq!(names, ["rousterd", "savd", "bgpd"]);
        assert_eq!(tree.section(Daemon::Bgpd).unwrap().header_line, 5);
    }

    #[test]
    fn rejects_unknown_daemon_name() {
        let err = parse("daemon zebra {\n}\n").unwrap_err();
        assert_eq!(
            err,
            fail(
                1,
                "unknown daemon `zebra` (known: rousterd, savd, bfdd, ospfd, bgpd)"
            )
        );
    }

    #[test]
    fn rejects_duplicate_section() {
        let err = parse("daemon savd {\n}\ndaemon savd {\n}\n").unwrap_err();
        assert_eq!(err, fail(3, "duplicate `daemon savd` section"));
    }

    #[test]
    fn rejects_unclosed_section_naming_the_opener() {
        let err = parse("daemon bfdd {\npeer 192.0.2.9\n").unwrap_err();
        assert_eq!(
            err,
            fail(
                1,
                "`daemon bfdd` section opened here is never closed (missing `}`)"
            )
        );
    }

    #[test]
    fn rejects_orphan_close() {
        assert_eq!(
            parse("}\n").unwrap_err(),
            fail(1, "`}` outside any `daemon` section")
        );
        assert_eq!(
            parse("daemon savd {\n}\n}\n").unwrap_err(),
            fail(3, "`}` outside any `daemon` section")
        );
    }

    #[test]
    fn rejects_nested_section_open() {
        let err = parse("daemon savd {\ndaemon bfdd {\n}\n}\n").unwrap_err();
        assert_eq!(
            err,
            fail(
                2,
                "`daemon` section inside another section (close it with `}` first)"
            )
        );
    }

    #[test]
    fn rejects_opener_without_name() {
        assert!(parse("daemon {\n}\n").is_err());
        assert!(parse("daemon savd\n").is_err());
        assert!(parse("daemon savd { extra\n").is_err());
    }

    #[test]
    fn rejects_bad_and_duplicate_router_id() {
        assert_eq!(
            parse("router-id 2001:db8::1\n").unwrap_err(),
            fail(1, "bad router-id address `2001:db8::1` (expected IPv4)")
        );
        assert_eq!(
            parse("router-id not-an-addr\n").unwrap_err(),
            fail(1, "bad router-id address `not-an-addr` (expected IPv4)")
        );
        assert_eq!(
            parse("router-id 10.0.0.1\nrouter-id 10.0.0.2\n").unwrap_err(),
            fail(2, "duplicate `router-id` line")
        );
    }

    #[test]
    fn rejects_unknown_top_level_directive() {
        let err = parse("ip route 203.0.113.0/24 blackhole\n").unwrap_err();
        assert_eq!(
            err.to_string(),
            "line 1: expected `router-id <ipv4>` or `daemon <name> {`, \
             got `ip route 203.0.113.0/24 blackhole`"
        );
    }

    #[test]
    fn empty_file_is_a_valid_empty_tree() {
        assert_eq!(parse("").unwrap(), Canonical::default());
        assert_eq!(
            parse("\n! only comments\n# yes\n").unwrap().preamble.len(),
            3
        );
    }

    #[test]
    fn braces_inside_body_words_pass_through() {
        // Not a lone `}` line: pass-through (no daemon grammar uses
        // braces today, but a password-ish token must not close a
        // section).
        let tree = parse("daemon bfdd {\npeer 192.0.2.9\n  password 1 s3cr{t\n}\n").unwrap();
        assert_eq!(tree.sections[0].body.len(), 2);
        assert_eq!(tree.sections[0].body[1].text, "  password 1 s3cr{t");
    }
}
