//! Per-daemon render (Phase 4, M2 step 1): project a section's
//! pass-through body onto the owning daemon's config file,
//! byte-stable.
//!
//! The canonical fmt contract (what "byte-stable" means here, pinned
//! by tests):
//!
//! - every body line keeps its text as parsed (leading whitespace
//!   preserved — operator intent, cosmetic to every daemon grammar in
//!   the suite, which are all `split_whitespace` token-per-line);
//! - trailing blank body lines are dropped, and the file ends with
//!   exactly one newline (an empty body renders the empty string —
//!   valid input for every parser in the suite today);
//! - render is idempotent: `render(parse(render(x))) == render(x)`
//!   (parse never reorders or rewrites body text, so re-rendering a
//!   rendered file is a fixed point — the property apply/rollback
//!   rely on when a generation is re-applied).
//!
//! What render deliberately does NOT do: re-indent, re-wrap, strip
//! comments, or normalize token spacing inside a line. The daemon
//! grammars are the owners of their bytes; configd's fmt touches only
//! file-level whitespace (trailing blanks + final newline).

use std::collections::BTreeMap;

use crate::tree::{Canonical, Daemon, Section};

/// Renders one section's body into the daemon's config-file bytes
/// (the canonical fmt above). Returns the exact file content.
pub fn render_daemon(section: &Section) -> String {
    let mut out = String::new();
    let mut body = section.body.as_slice();
    // Drop trailing blank body lines (leading whitespace means a line
    // of spaces is blank too).
    while let Some(last) = body.last() {
        if last.text.trim().is_empty() {
            body = &body[..body.len() - 1];
        } else {
            break;
        }
    }
    for line in body {
        out.push_str(&line.text);
        out.push('\n');
    }
    out
}

/// Renders every section present in the tree, keyed by daemon, in
/// apply order (rousterd first, protocols after — [`Daemon::all`]'s
/// order; the map's BTree-ness is only for deterministic iteration,
/// the order the apply path walks comes from [`Daemon::all`]).
pub fn render_all(tree: &Canonical) -> BTreeMap<Daemon, String> {
    tree.sections
        .iter()
        .map(|section| (section.daemon, render_daemon(section)))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tree::parse;

    fn rendered(input: &str, daemon: Daemon) -> String {
        let tree = parse(input).unwrap();
        render_daemon(tree.section(daemon).expect("section present"))
    }

    #[test]
    fn renders_body_verbatim_in_order() {
        let out = rendered(
            "daemon savd {\nmode strict\ninterface vethlegit\n  mode loose\nbinding 192.0.2.0/24 interface vethlegit\n}\n",
            Daemon::Savd,
        );
        assert_eq!(
            out,
            "mode strict\ninterface vethlegit\n  mode loose\nbinding 192.0.2.0/24 interface vethlegit\n"
        );
    }

    #[test]
    fn drops_trailing_blank_body_lines_and_ends_with_one_newline() {
        let out = rendered("daemon bfdd {\npeer 192.0.2.9\n\n\n   \n}\n", Daemon::Bfdd);
        assert_eq!(out, "peer 192.0.2.9\n");
    }

    #[test]
    fn empty_body_renders_empty_string() {
        assert_eq!(rendered("daemon rousterd {\n}\n", Daemon::Rousterd), "");
    }

    #[test]
    fn keeps_interior_blank_lines_and_comments() {
        let out = rendered(
            "daemon bgpd {\nrouter bgp 65000\n\n! peers\n neighbor 192.0.2.9 remote-as 65001\n}\n",
            Daemon::Bgpd,
        );
        assert_eq!(
            out,
            "router bgp 65000\n\n! peers\n neighbor 192.0.2.9 remote-as 65001\n"
        );
    }

    #[test]
    fn render_is_idempotent_round_trip() {
        // render -> re-parse (wrapped in a section again) -> render
        // is a fixed point, for a body exercising indentation,
        // comments, blanks, and odd spacing.
        let body =
            "router ospf\n  area 0.0.0.0\n    interface eth0\n      cost   10\n\n! tail comment\n";
        let input = format!("daemon ospfd {{\n{body}}}\n");
        let once = rendered(&input, Daemon::Ospfd);
        // Feed the rendered file back in as a fresh section body.
        let again_input = format!("daemon ospfd {{\n{once}}}\n");
        let twice = rendered(&again_input, Daemon::Ospfd);
        assert_eq!(once, twice);
        assert_eq!(once, body);
    }

    #[test]
    fn render_all_keys_by_daemon_and_skips_absent() {
        let tree = parse("daemon rousterd {\n}\ndaemon bfdd {\npeer 10.0.0.1\n}\n").unwrap();
        let all = render_all(&tree);
        assert_eq!(all.len(), 2);
        assert_eq!(all[&Daemon::Rousterd], "");
        assert_eq!(all[&Daemon::Bfdd], "peer 10.0.0.1\n");
    }
}
