//! The v1 wire framing — a plain TCP line protocol, disclosed.
//!
//! The real vtysh expects its own pty/unix-socket plumbing; v1 is a
//! line protocol and says so in the banner. Rules:
//!
//! - The server writes a banner, then a prompt (`host> ` and
//!   family); the client submits one CRLF-terminated line; the
//!   server writes the output lines (CRLF-terminated) then the
//!   prompt again; an empty-output command gets a bare `\r\n`
//!   before its prompt so the prompt always starts a fresh line. No
//!   remote echo, no telnet IAC negotiation (a raw `telnet` client
//!   works best in char mode with local echo).
//! - `exit` at the bottom of the mode stack closes the connection
//!   without further bytes.
//!
//! The one-shot client (`vtyd --command`, the `vtysh -c` analog)
//! exploits both ends deterministically. It always runs `enable`
//! first (v1 has no enable password, and the interesting show
//! commands are enable-mode), then the command, then `exit`, then
//! half-closes and reads to EOF. Stripping is sound because a
//! hostname is `[A-Za-z0-9._-]+`
//! ([`crate::tree::ParamKind::Word`]) — no output line can contain
//! the prompt shapes, and the stream can only end with the exact
//! trailing prompt sequence.

/// The banner every connection sees on connect. It always ends with
/// `\r\n\r\n`, so the prompt that follows starts a fresh line; it
/// contains no `>` character, so the first `> ` in any stream is
/// the end of the first prompt.
pub fn banner(version: &str) -> String {
    format!(
        "\r\nRouster VTY server (vtyd {version}) - plain TCP line protocol (v1 disclosure);\r\n`?` for help anywhere, `list` for commands, `exit` to close.\r\n\r\n"
    )
}

/// Extracts the command body from a full one-shot session stream
/// (banner, user prompt, enable framing, output, trailing prompts,
/// EOF-terminated).
///
/// `None` when the stream is not the shape the server produces
/// (truncated, or a hostname smuggling `>`/whitespace — the grammar
/// forbids both, so this signals a protocol violation).
pub fn strip_to_body(stream: &str) -> Option<String> {
    let first = stream.find("> ")?;
    let head = &stream[..first + 2];
    let user_prompt = head.rsplit_once("\r\n")?.1;
    let name = user_prompt.strip_suffix("> ")?;
    let enable_prompt = format!("{name}# ");
    let mut body = &stream[first + 2..];
    // The enable step's no-output framing leads the body.
    let lead = format!("\r\n{enable_prompt}");
    body = body.strip_prefix(&lead).unwrap_or(body);
    // The post-command prompt plus exit's return-to-user framing
    // trail it.
    let tail = format!("{enable_prompt}\r\n{user_prompt}");
    body = body.strip_suffix(&tail).unwrap_or(body);
    // The empty-output command leaves a bare newline before the
    // trailing prompts.
    let body = body.strip_suffix("\r\n").unwrap_or(body);
    Some(body.to_string())
}

/// The parser-error line prefixes — the only outputs a `--command`
/// run turns into a nonzero exit (see [`crate::client`]). Source
/// state honesty (`% No savd status published`, the stale footer)
/// deliberately does NOT fail the run: verify state, never trust
/// exit codes (the quarantine-B7 `vtysh -b` lesson).
pub const COMMAND_ERROR_PREFIXES: [&str; 4] = [
    "% Unknown command:",
    "% Ambiguous command:",
    "% Incomplete command.",
    "% Invalid input:",
];

/// Does this body contain a command-level error line?
pub fn body_has_command_error(body: &str) -> bool {
    body.lines().any(|line| {
        COMMAND_ERROR_PREFIXES
            .iter()
            .any(|prefix| line.starts_with(prefix))
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn banner_discloses_the_line_protocol() {
        let text = banner("9.9.9");
        assert!(text.contains("plain TCP line protocol"));
        assert!(text.ends_with("\r\n\r\n"));
        assert!(
            !text.contains('>'),
            "banner must not contain a prompt shape"
        );
    }

    #[test]
    fn stripping_keeps_the_body_and_drops_all_framing() {
        let stream = format!(
            "{}rouster> \r\nrouster# Rouster vtyd 0.0.0 - vtysh-compatible VTY server\r\nline two\r\nrouster# \r\nrouster> ",
            banner("0.0.0")
        );
        assert_eq!(
            strip_to_body(&stream).as_deref(),
            Some("Rouster vtyd 0.0.0 - vtysh-compatible VTY server\r\nline two")
        );
    }

    #[test]
    fn stripping_the_empty_output_case_yields_empty() {
        let stream = format!(
            "{}rouster> \r\nrouster# \r\nrouster# \r\nrouster> ",
            banner("0.0.0")
        );
        assert_eq!(strip_to_body(&stream).as_deref(), Some(""));
    }

    #[test]
    fn a_renamed_host_framing_the_same_way() {
        let stream = format!(
            "{}edge-1.gw> \r\nedge-1.gw# output\r\nedge-1.gw# \r\nedge-1.gw> ",
            banner("0.0.0")
        );
        assert_eq!(strip_to_body(&stream).as_deref(), Some("output"));
    }

    #[test]
    fn a_truncated_stream_is_rejected_not_guessed() {
        assert_eq!(strip_to_body("garbage with no prompt"), None);
    }

    #[test]
    fn command_errors_are_detected_by_prefix() {
        assert!(body_has_command_error("% Unknown command: router static\n"));
        assert!(body_has_command_error("% Incomplete command.\n"));
        assert!(!body_has_command_error(
            "% No savd status published at /run/rouster/savd.status\n"
        ));
        assert!(!body_has_command_error("savd 0.0.0 pid 4242 running\n"));
    }
}
