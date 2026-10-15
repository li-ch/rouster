//! The HTTP/1.1 core for the RESTCONF edge (S12-a M1) — hand-rolled
//! over tokio, the vtyd server discipline: one listener, one task
//! per connection, a frozen-spec parser small enough to inspect.
//! No HTTP crate, no HTTP/2, no TLS (owner decision §Deferred in
//! docs/yang.md; RFC 8040 §2 expects HTTPS — the v1 posture is
//! disclosed at every surface).
//!
//! The subset, honestly:
//!
//! - **Requests**: one request line (`METHOD SP request-target SP
//!   HTTP/1.1`, RFC 9112 §3), header fields (`Name: value`,
//!   case-insensitive names, RFC 9110 §5.1), and a Content-Length
//!   body (RFC 9112 §6.3). Bare-LF line endings are tolerated (the
//!   suite's line protocols accept both); anything else is a 400.
//! - **No chunked** (RFC 9112 §7.1): a `Transfer-Encoding` header is
//!   refused with 501 — disclosed, not silent.
//! - **No keep-alive**: connection-per-request (RFC 9110 §9.3's
//!   close semantics); every response carries `Connection: close`
//!   and the connection follows it.
//! - **Bounded**: request line ≤ 8 KiB, header block ≤ 16 KiB,
//!   body ≤ 1 MiB — an oversized anything is refused (413/431) and
//!   the connection dropped, never wedged (the vtyd binary-garbage
//!   guard, HTTP-shaped).
//! - **Responses**: status line + `Content-Type`, `Content-Length`,
//!   `Connection: close` — no Date (needs a dependency-grade
//!   formatter; curl-class clients do not miss it), no chunked
//!   responses (bodies always fit the bound above).
//!
//! Everything here is pure parsing/rendering over bytes so the
//! parser edges are unit-testable without a socket; [`read_request`]
//! is the thin async wrapper the server calls.

/// Request-line bound (bytes).
pub const MAX_REQUEST_LINE: usize = 8 * 1024;
/// Header-block bound (bytes, request line included).
pub const MAX_HEAD: usize = 16 * 1024;
/// Request-body bound (bytes).
pub const MAX_BODY: usize = 1024 * 1024;

/// One parsed request (head + body).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Request {
    pub method: String,
    pub target: String,
    /// The version token, verbatim (`HTTP/1.1` — anything else is a
    /// 505 at the server; the parser only records).
    pub version: String,
    /// Header fields in arrival order, names as-received (lookup is
    /// case-insensitive, [`Request::header`]).
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

impl Request {
    /// Case-insensitive header lookup (RFC 9110 §5.1), first match.
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }
}

/// Why a request could not be read — each maps to exactly one
/// response the server sends before closing (except `Incomplete`,
/// which is a quiet close: the peer went away).
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum HttpError {
    /// 400 Bad Request.
    #[error("malformed request: {0}")]
    Malformed(String),
    /// 413 Content Too Large (a body over [`MAX_BODY`]).
    #[error("request body exceeds {MAX_BODY} bytes")]
    BodyTooLarge,
    /// 431 Request Header Fields Too Large (head over [`MAX_HEAD`]
    /// or a request line over [`MAX_REQUEST_LINE`]).
    #[error("request head exceeds the bound")]
    HeadTooLarge,
    /// 501 Not Implemented (chunked transfer encoding).
    #[error("chunked transfer encoding is not implemented")]
    Chunked,
    /// 505 HTTP Version Not Supported (anything but HTTP/1.1).
    #[error("only HTTP/1.1 is supported (saw `{0}`)")]
    Version(String),
    /// The peer closed before a full request — close quietly.
    #[error("connection closed mid-request")]
    Incomplete,
}

/// Parses a request head (request line + headers, everything before
/// the blank line). Pure; the server owns the byte framing.
pub fn parse_head(head: &str) -> Result<Request, HttpError> {
    let mut lines = head.split('\n').map(|l| l.strip_suffix('\r').unwrap_or(l));
    let request_line = lines.next().unwrap_or_default();
    if request_line.len() > MAX_REQUEST_LINE {
        return Err(HttpError::HeadTooLarge);
    }
    let mut parts = request_line.split_whitespace();
    let (method, target, version) = match (parts.next(), parts.next(), parts.next()) {
        (Some(m), Some(t), Some(v)) if parts.next().is_none() => {
            (m.to_string(), t.to_string(), v.to_string())
        }
        _ => {
            return Err(HttpError::Malformed(format!(
                "request line is not `METHOD SP target SP HTTP/1.1`: `{request_line}`"
            )))
        }
    };
    if !method
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
    {
        return Err(HttpError::Malformed(format!("bad method token `{method}`")));
    }
    let mut headers = Vec::new();
    for line in lines {
        if line.is_empty() {
            continue;
        }
        let Some((name, value)) = line.split_once(':') else {
            return Err(HttpError::Malformed(format!(
                "header line has no `:` separator: `{line}`"
            )));
        };
        if name.is_empty() || name.contains(char::is_whitespace) {
            return Err(HttpError::Malformed(format!("bad header name `{name}`")));
        }
        headers.push((name.trim().to_string(), value.trim().to_string()));
    }
    Ok(Request {
        method,
        target,
        version,
        headers,
        body: Vec::new(),
    })
}

/// Reads one request off a buffered stream: head until CRLFCRLF (a
/// bare-LFLF tail is tolerated), then exactly Content-Length body
/// bytes. Enforces every bound above; callers send the mapped
/// error response and close.
pub async fn read_request<R>(reader: &mut R) -> Result<Request, HttpError>
where
    R: tokio::io::AsyncRead + Unpin,
{
    use tokio::io::AsyncReadExt;

    let mut buf: Vec<u8> = Vec::with_capacity(1024);
    let mut chunk = [0u8; 2048];
    // Find the head terminator: \r\n\r\n or \n\n.
    let head_end = loop {
        if let Some(pos) = find_head_end(&buf) {
            if pos > MAX_HEAD {
                return Err(HttpError::HeadTooLarge);
            }
            break pos;
        }
        if buf.len() > MAX_HEAD {
            return Err(HttpError::HeadTooLarge);
        }
        let read = reader
            .read(&mut chunk)
            .await
            .map_err(|_| HttpError::Incomplete)?;
        if read == 0 {
            return Err(HttpError::Incomplete);
        }
        buf.extend_from_slice(&chunk[..read]);
    };
    let head = String::from_utf8_lossy(&buf[..head_end]).into_owned();
    let mut request = parse_head(&head)?;

    if let Some(te) = request.header("transfer-encoding") {
        if !te.is_empty() {
            return Err(HttpError::Chunked);
        }
    }
    let length = match request
        .headers
        .iter()
        .filter(|(k, _)| k.eq_ignore_ascii_case("content-length"))
        .map(|(_, v)| v.as_str())
        .collect::<Vec<_>>()
        .as_slice()
    {
        [] => 0,
        [only] => only
            .trim()
            .parse::<usize>()
            .map_err(|_| HttpError::Malformed(format!("bad Content-Length `{only}`")))?,
        [a, b, ..] if a.trim() == b.trim() => a
            .trim()
            .parse::<usize>()
            .map_err(|_| HttpError::Malformed(format!("bad Content-Length `{a}`")))?,
        conflicting => {
            return Err(HttpError::Malformed(format!(
                "conflicting Content-Length values {conflicting:?}"
            )))
        }
    };
    if length > MAX_BODY {
        return Err(HttpError::BodyTooLarge);
    }
    // The body may already be partially buffered (the read that
    // completed the head may have carried body bytes — possibly more
    // than the body; connection-per-request ignores the tail).
    let mut body: Vec<u8> = buf[head_end..].to_vec();
    while body.len() < length {
        let read = reader
            .read(&mut chunk)
            .await
            .map_err(|_| HttpError::Incomplete)?;
        if read == 0 {
            return Err(HttpError::Incomplete);
        }
        body.extend_from_slice(&chunk[..read]);
    }
    body.truncate(length);
    request.body = body;
    Ok(request)
}

/// The byte offset just past the head terminator — the earliest of
/// `\r\n\r\n` and `\n\n` — when present.
fn find_head_end(buf: &[u8]) -> Option<usize> {
    const CRLFCRLF: &[u8] = b"\r\n\r\n";
    const LFLF: &[u8] = b"\n\n";
    let crlf = buf
        .windows(CRLFCRLF.len())
        .position(|w| w == CRLFCRLF)
        .map(|pos| pos + CRLFCRLF.len());
    let lf = buf
        .windows(LFLF.len())
        .position(|w| w == LFLF)
        .map(|pos| pos + LFLF.len());
    match (crlf, lf) {
        (Some(a), Some(b)) => Some(a.min(b)),
        (a, b) => a.or(b),
    }
}

/// The reason phrase for a status code (the handful this edge
/// emits; RFC 9110 §15 vocabulary).
pub fn reason(status: u16) -> &'static str {
    match status {
        200 => "OK",
        201 => "Created",
        204 => "No Content",
        400 => "Bad Request",
        404 => "Not Found",
        405 => "Method Not Allowed",
        409 => "Conflict",
        413 => "Content Too Large",
        431 => "Request Header Fields Too Large",
        500 => "Internal Server Error",
        501 => "Not Implemented",
        503 => "Service Unavailable",
        505 => "HTTP Version Not Supported",
        _ => "Status",
    }
}

/// Renders a full response: status line, the fixed headers, an
/// optional `Allow` value (405 responses; RFC 9110 §15.5.6), the
/// body. Every response says `Connection: close` and means it.
pub fn render_response(
    status: u16,
    content_type: &str,
    body: &[u8],
    allow: Option<&str>,
) -> Vec<u8> {
    let mut out = Vec::with_capacity(body.len() + 128);
    out.extend_from_slice(format!("HTTP/1.1 {status} {}\r\n", reason(status)).as_bytes());
    out.extend_from_slice(format!("Content-Type: {content_type}\r\n").as_bytes());
    out.extend_from_slice(format!("Content-Length: {}\r\n", body.len()).as_bytes());
    if let Some(allow) = allow {
        out.extend_from_slice(format!("Allow: {allow}\r\n").as_bytes());
    }
    out.extend_from_slice(b"Connection: close\r\n\r\n");
    out.extend_from_slice(body);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn head_of(text: &str) -> &str {
        let end = find_head_end(text.as_bytes()).expect("head end present");
        std::str::from_utf8(&text.as_bytes()[..end]).unwrap()
    }

    #[test]
    fn parses_a_well_formed_get() {
        let req = parse_head(head_of("GET /restconf/data HTTP/1.1\r\nHost: x\r\n\r\n")).unwrap();
        assert_eq!(req.method, "GET");
        assert_eq!(req.target, "/restconf/data");
        assert_eq!(req.version, "HTTP/1.1");
        assert_eq!(req.header("host"), Some("x"));
        assert_eq!(req.header("HOST"), Some("x"));
        assert!(req.body.is_empty());
    }

    #[test]
    fn tolerates_bare_lf_line_endings() {
        let req = parse_head(head_of("GET / HTTP/1.1\nHost: y\n\n")).unwrap();
        assert_eq!(req.header("host"), Some("y"));
    }

    #[test]
    fn a_two_token_request_line_is_malformed() {
        assert!(parse_head(head_of("GET /restconf\r\n\r\n")).is_err());
        let err = parse_head(head_of("GET A B C\r\n\r\n")).unwrap_err();
        assert!(err.to_string().contains("request line"), "{err}");
    }

    #[test]
    fn a_header_without_colon_is_malformed() {
        let err = parse_head(head_of("GET / HTTP/1.1\r\nBrokenHeader\r\n\r\n")).unwrap_err();
        assert!(err.to_string().contains("separator"), "{err}");
    }

    #[test]
    fn an_empty_header_name_is_malformed() {
        assert!(parse_head(head_of("GET / HTTP/1.1\r\n: v\r\n\r\n")).is_err());
    }

    #[test]
    fn header_names_may_carry_no_whitespace() {
        assert!(parse_head(head_of("GET / HTTP/1.1\r\nBad Name: v\r\n\r\n")).is_err());
    }

    #[test]
    fn conflicting_content_length_is_malformed() {
        let req = parse_head(head_of(
            "PUT /x HTTP/1.1\r\nContent-Length: 3\r\ncontent-length: 4\r\n\r\n",
        ))
        .unwrap();
        // The duplication is a read_request-level check.
        assert_eq!(req.header("Content-Length"), Some("3"));
    }

    #[test]
    fn head_too_large_is_bounded() {
        let long = "X".repeat(MAX_REQUEST_LINE + 1);
        assert_eq!(
            parse_head(&format!("GET /{long} HTTP/1.1\r\n\r\n")),
            Err(HttpError::HeadTooLarge)
        );
    }

    #[test]
    fn reason_phrases_cover_the_emitted_statuses() {
        for status in [
            200, 201, 204, 400, 404, 405, 409, 413, 431, 500, 501, 503, 505,
        ] {
            assert_ne!(reason(status), "Status", "{status} needs a phrase");
        }
    }

    #[test]
    fn responses_render_the_exact_wire_form() {
        let bytes = render_response(404, "application/json", b"{\"x\":1}", Some("GET"));
        assert_eq!(
            String::from_utf8(bytes).unwrap(),
            "HTTP/1.1 404 Not Found\r\n\
             Content-Type: application/json\r\n\
             Content-Length: 7\r\n\
             Allow: GET\r\n\
             Connection: close\r\n\
             \r\n\
             {\"x\":1}"
        );
    }

    #[test]
    fn a_no_content_response_has_no_body() {
        let bytes = render_response(204, "application/json", b"", None);
        let text = String::from_utf8(bytes).unwrap();
        assert!(text.starts_with("HTTP/1.1 204 No Content\r\n"));
        assert!(text.ends_with("Content-Length: 0\r\nConnection: close\r\n\r\n"));
    }

    #[tokio::test]
    async fn read_request_assembles_head_and_body() {
        let wire =
            b"PUT /restconf/data/savd/poll HTTP/1.1\r\nHost: r\r\nContent-Length: 1\r\n\r\n3";
        let mut reader = &wire[..];
        let req = read_request(&mut reader).await.unwrap();
        assert_eq!(req.method, "PUT");
        assert_eq!(req.body, b"3");
    }

    #[tokio::test]
    async fn read_request_rejects_bad_content_length() {
        let wire = b"PUT /x HTTP/1.1\r\nContent-Length: nan\r\n\r\n";
        let mut reader = &wire[..];
        assert!(matches!(
            read_request(&mut reader).await,
            Err(HttpError::Malformed(_))
        ));
    }

    #[tokio::test]
    async fn read_request_rejects_chunked() {
        let wire = b"PUT /x HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n";
        let mut reader = &wire[..];
        assert_eq!(read_request(&mut reader).await, Err(HttpError::Chunked));
    }

    #[tokio::test]
    async fn read_request_bounds_the_body() {
        let wire = format!(
            "PUT /x HTTP/1.1\r\nContent-Length: {}\r\n\r\n",
            MAX_BODY + 1
        );
        let mut reader = wire.as_bytes();
        assert_eq!(
            read_request(&mut reader).await,
            Err(HttpError::BodyTooLarge)
        );
    }

    #[tokio::test]
    async fn read_request_bounds_the_head() {
        let mut wire = String::from("GET /x HTTP/1.1\r\nX-F: ");
        wire.push_str(&"a".repeat(MAX_HEAD));
        wire.push_str("\r\n\r\n");
        let mut reader = wire.as_bytes();
        assert_eq!(
            read_request(&mut reader).await,
            Err(HttpError::HeadTooLarge)
        );
    }

    #[tokio::test]
    async fn a_truncated_request_is_incomplete_not_malformed() {
        let wire = b"PUT /x HTTP/1.1\r\nContent-Length: 5\r\n\r\n12";
        let mut reader = &wire[..];
        assert_eq!(read_request(&mut reader).await, Err(HttpError::Incomplete));
    }

    #[tokio::test]
    async fn an_immediate_eof_is_incomplete() {
        let wire = b"";
        let mut reader = &wire[..];
        assert_eq!(read_request(&mut reader).await, Err(HttpError::Incomplete));
    }

    #[tokio::test]
    async fn identical_duplicate_content_length_is_accepted() {
        let wire = b"PUT /x HTTP/1.1\r\nContent-Length: 1\r\nContent-Length: 1\r\n\r\nz";
        let mut reader = &wire[..];
        let req = read_request(&mut reader).await.unwrap();
        assert_eq!(req.body, b"z");
    }

    #[tokio::test]
    async fn conflicting_duplicate_content_length_is_malformed() {
        let wire = b"PUT /x HTTP/1.1\r\nContent-Length: 1\r\nContent-Length: 2\r\n\r\nzz";
        let mut reader = &wire[..];
        assert!(matches!(
            read_request(&mut reader).await,
            Err(HttpError::Malformed(_))
        ));
    }

    #[test]
    fn find_head_end_accepts_both_terminators() {
        assert_eq!(find_head_end(b"A\r\nB\r\n\r\nbody"), Some(8));
        assert_eq!(find_head_end(b"A\nB\n\nbody"), Some(5));
        assert_eq!(find_head_end(b"no terminator"), None);
        // CRLFCRLF wins over an earlier LFLF inside the block only
        // when it appears first — here \n\n appears at 1.
        assert_eq!(find_head_end(b"A\n\nrest"), Some(3));
    }
}
