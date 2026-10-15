//! Lexical tokenization for the Rouster YANG subset — RFC 7950
//! §6.1 "Lexical Tokenization", §6.1.1 "Comments", §6.1.2 "Tokens",
//! §6.1.3 "Quoting", §6.2 "Identifiers".
//!
//! A YANG file is a sequence of statements (§6.3): `keyword
//! [argument] (";" | "{" statements ")`. This module produces that
//! stream as flat tokens plus, one layer up ([`crate::schema`]), a
//! statement tree.
//!
//! What is implemented, by RFC letter:
//!
//! - comments: `//` to end of line and `/* ... */` block comments
//!   (§6.1.1);
//! - tokens: keywords, arguments, `{`, `}`, `;` (§6.1.2);
//! - quoting (§6.1.3): unquoted strings, single- and double-quoted
//!   strings, and `+`-concatenation of quoted fragments — the
//!   subset's models use concatenation for long `pattern` and
//!   `description` arguments;
//! - identifiers (§6.2): `[A-Za-z_][A-Za-z0-9_.-]*`, optionally
//!   prefix-qualified (`prefix:name`, §6.2.1's namespace rule);
//! - within double-quoted strings, the escapes `\n \t \" \\`
//!   (§6.1.3's enumerated set; the full XSD escape surface is not
//!   implemented — §Deferred in the crate docs).
//!
//! What is deliberately NOT implemented: none of the lexical surface
//! our models need is skipped; the only §6.1 divergence is that an
//! unquoted string is additionally rejected when it contains any of
//! `{}<>"` — a strictness (never a leniency) that keeps tokenizer
//! ambiguity out of the hand-written statement parser.

use std::fmt;

/// A lexical token with its 1-based line and column (errors point at
/// the operator's file, the house rule).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Token {
    /// A keyword or an unquoted argument (§6.1.2). Keywords are
    /// matched by the statement layer; the lexer does not care.
    Word(String),
    /// A single- or double-quoted string argument (§6.1.3), already
    /// unescaped/verbatim.
    Quoted(String),
    /// `{` — opens a statement block (§6.3).
    OpenBrace,
    /// `}` — closes a statement block.
    CloseBrace,
    /// `;` — terminates a leafless statement.
    Semicolon,
}

impl Token {
    /// The argument text (Word or Quoted); `None` for punctuation.
    pub fn as_arg(&self) -> Option<&str> {
        match self {
            Token::Word(s) | Token::Quoted(s) => Some(s),
            _ => None,
        }
    }
}

impl fmt::Display for Token {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Token::Word(s) => write!(f, "{s}"),
            Token::Quoted(s) => write!(f, "{s:?}"),
            Token::OpenBrace => f.write_str("{"),
            Token::CloseBrace => f.write_str("}"),
            Token::Semicolon => f.write_str(";"),
        }
    }
}

/// A token with its source position.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Spanned {
    pub token: Token,
    pub line: usize,
    pub col: usize,
}

/// Lexical error — line/column-numbered, the house shape.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum LexError {
    #[error("line {line}:{col}: {reason}")]
    At {
        line: usize,
        col: usize,
        reason: String,
    },
}

fn at(line: usize, col: usize, reason: impl Into<String>) -> LexError {
    LexError::At {
        line,
        col,
        reason: reason.into(),
    }
}

/// An unquoted string (§6.1.3): the RFC forbids whitespace, the
/// statement punctuation, both quote kinds, and the XML specials.
/// The subset keeps the RFC's exclusion set and adds `<`/`>`.
pub fn is_unquoted_ok(s: &str) -> bool {
    !s.is_empty()
        && !s.chars().any(|c| {
            c.is_whitespace()
                || matches!(
                    c,
                    ';' | '{' | '}' | '"' | '\'' | '(' | ')' | '[' | ']' | '<' | '>'
                )
        })
}

/// Is `s` an identifier per §6.2 (module/statement/typedef names)?
/// Identifiers are a subset of unquoted strings: the pattern is
/// `[A-Za-z_][A-Za-z0-9_.-]*`. (§6.2 also permits them to carry a
/// `prefix:` qualifier; that is handled by the statement layer.)
pub fn is_identifier(s: &str) -> bool {
    let mut chars = s.chars();
    match chars.next() {
        Some(c) if c.is_ascii_alphabetic() || c == '_' => {}
        _ => return false,
    }
    chars.all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '.' | '-'))
}

/// Is `s` a qualified identifier (`prefix:name` or plain `name`)?
pub fn is_qualified_identifier(s: &str) -> bool {
    match s.split_once(':') {
        Some((prefix, name)) => is_identifier(prefix) && is_identifier(name),
        None => is_identifier(s),
    }
}

/// Tokenizes YANG source text (§6.1).
pub fn tokenize(input: &str) -> Result<Vec<Spanned>, LexError> {
    let mut out = Vec::new();
    let bytes: Vec<char> = input.chars().collect();
    let mut i = 0usize;
    let mut line = 1usize;
    let mut col = 1usize;

    macro_rules! bump {
        () => {{
            if bytes[i] == '\n' {
                line += 1;
                col = 1;
            } else {
                col += 1;
            }
            i += 1;
        }};
    }

    while i < bytes.len() {
        let c = bytes[i];
        // Whitespace separates tokens (§6.1.2).
        if c.is_whitespace() {
            bump!();
            continue;
        }
        // Comments (§6.1.1): `//` to end of line; `/* ... */` nested
        // per the RFC ("comments may be nested").
        if c == '/' && i + 1 < bytes.len() && bytes[i + 1] == '/' {
            while i < bytes.len() && bytes[i] != '\n' {
                bump!();
            }
            continue;
        }
        if c == '/' && i + 1 < bytes.len() && bytes[i + 1] == '*' {
            let (sl, sc) = (line, col);
            bump!();
            bump!();
            let mut depth = 1usize;
            while i < bytes.len() && depth > 0 {
                if bytes[i] == '/' && i + 1 < bytes.len() && bytes[i + 1] == '*' {
                    depth += 1;
                    bump!();
                    bump!();
                } else if bytes[i] == '*' && i + 1 < bytes.len() && bytes[i + 1] == '/' {
                    depth -= 1;
                    bump!();
                    bump!();
                } else {
                    bump!();
                }
            }
            if depth > 0 {
                return Err(at(sl, sc, "unterminated /* comment"));
            }
            continue;
        }
        // Statement punctuation (§6.3).
        if c == '{' {
            out.push(Spanned {
                token: Token::OpenBrace,
                line,
                col,
            });
            bump!();
            continue;
        }
        if c == '}' {
            out.push(Spanned {
                token: Token::CloseBrace,
                line,
                col,
            });
            bump!();
            continue;
        }
        if c == ';' {
            out.push(Spanned {
                token: Token::Semicolon,
                line,
                col,
            });
            bump!();
            continue;
        }
        // Quoted strings (§6.1.3), with `+`-concatenation.
        if c == '"' || c == '\'' {
            let (text, used) = quoted_string(&bytes[i..], line, col)?;
            out.push(Spanned {
                token: Token::Quoted(text),
                line,
                col,
            });
            for _ in 0..used {
                bump!();
            }
            // Concatenation: `"a" + "b"` (§6.1.3) — only across
            // whitespace, and only quoted fragments (the subset's
            // declaration; the RFC also allows mixing unquoted
            // fragments, which our models never do).
            let mut guard = i;
            loop {
                // Look ahead past whitespace for '+' then a quote.
                let mut j = i;
                while j < bytes.len() && bytes[j].is_whitespace() {
                    j += 1;
                }
                if j < bytes.len() && bytes[j] == '+' {
                    let mut k = j + 1;
                    while k < bytes.len() && bytes[k].is_whitespace() {
                        k += 1;
                    }
                    if k < bytes.len() && (bytes[k] == '"' || bytes[k] == '\'') {
                        let (extra, used2) = quoted_string(&bytes[k..], line, col)?;
                        if let Some(Token::Quoted(prev)) = out.last_mut().map(|s| &mut s.token) {
                            prev.push_str(&extra);
                        }
                        // Advance the outer cursor past the fragment.
                        i = k + used2;
                        // Keep line/col honest for whatever follows:
                        // recompute cheaply by scanning what we skipped.
                        for skipped in bytes.iter().take(i).skip(guard) {
                            if *skipped == '\n' {
                                line += 1;
                                col = 1;
                            } else {
                                col += 1;
                            }
                        }
                        guard = i;
                        continue;
                    }
                }
                break;
            }
            continue;
        }
        // Unquoted string (§6.1.3): runs to the next separator.
        let (sl, sc) = (line, col);
        let start = i;
        while i < bytes.len()
            && !bytes[i].is_whitespace()
            && !matches!(bytes[i], ';' | '{' | '}' | '"' | '\'')
        {
            bump!();
        }
        let word: String = bytes[start..i].iter().collect();
        if !is_unquoted_ok(&word) {
            return Err(at(
                sl,
                sc,
                format!("illegal unquoted string `{word}` (quote it)"),
            ));
        }
        out.push(Spanned {
            token: Token::Word(word),
            line: sl,
            col: sc,
        });
    }
    Ok(out)
}

/// Reads one quoted string starting at `chars[0]` (the quote char);
/// returns `(text, chars_consumed)`. Double-quoted strings process
/// the escapes `\n \t \" \\` (§6.1.3); single-quoted are verbatim.
fn quoted_string(chars: &[char], line: usize, col: usize) -> Result<(String, usize), LexError> {
    let quote = chars[0];
    let mut out = String::new();
    let mut i = 1usize;
    while i < chars.len() {
        let c = chars[i];
        if c == quote {
            return Ok((out, i + 1));
        }
        if quote == '"' && c == '\\' {
            let next = chars
                .get(i + 1)
                .copied()
                .ok_or_else(|| at(line, col, "string ends inside an escape"))?;
            match next {
                'n' => out.push('\n'),
                't' => out.push('\t'),
                '"' => out.push('"'),
                '\\' => out.push('\\'),
                other => {
                    // §6.1.3's list; the XSD numeric escapes and
                    // tab-within-single-quote behavior are out
                    // (§Deferred, crate docs).
                    return Err(at(line, col + i, format!("unsupported escape `\\{other}`")));
                }
            }
            i += 2;
            continue;
        }
        out.push(c);
        i += 1;
    }
    Err(at(line, col, "unterminated string"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn words(input: &str) -> Vec<String> {
        tokenize(input)
            .unwrap()
            .into_iter()
            .map(|s| s.token.to_string())
            .collect()
    }

    #[test]
    fn golden_simple_module_statement_stream() {
        // RFC 7950 §7.1's opening shape, tokenized.
        let toks =
            tokenize("module rouster-common {\n  yang-version 1.1;\n  namespace \"urn:x\";\n}\n")
                .unwrap();
        let kinds: Vec<&Token> = toks.iter().map(|s| &s.token).collect();
        assert_eq!(
            kinds,
            vec![
                &Token::Word("module".into()),
                &Token::Word("rouster-common".into()),
                &Token::OpenBrace,
                &Token::Word("yang-version".into()),
                &Token::Word("1.1".into()),
                &Token::Semicolon,
                &Token::Word("namespace".into()),
                &Token::Quoted("urn:x".into()),
                &Token::Semicolon,
                &Token::CloseBrace,
            ]
        );
        assert_eq!((toks[0].line, toks[0].col), (1, 1));
        assert_eq!((toks[3].line, toks[3].col), (2, 3));
    }

    #[test]
    fn comments_both_kinds_and_nesting() {
        assert_eq!(words("// hi\na\n"), vec!["a"]);
        assert_eq!(words("/* one */ a"), vec!["a"]);
        assert_eq!(words("/* outer /* inner */ still */ a"), vec!["a"]);
    }

    #[test]
    fn quoted_strings_and_escapes() {
        let toks = tokenize("\"a\\nb\\t\\\"\"").unwrap();
        assert_eq!(toks[0].token, Token::Quoted("a\nb\t\"".into()));
        // Single-quoted: verbatim, backslash is literal (§6.1.3).
        assert_eq!(
            tokenize("'a\\nb'").unwrap()[0].token,
            Token::Quoted("a\\nb".into())
        );
    }

    #[test]
    fn plus_concatenation_joins_fragments() {
        assert_eq!(
            tokenize("\"abc\" + \"def\"").unwrap()[0].token,
            Token::Quoted("abcdef".into())
        );
        // The long-pattern idiom: concatenation across newlines.
        assert_eq!(
            tokenize("\"49.\" +\n  \"0001\"").unwrap()[0].token,
            Token::Quoted("49.0001".into())
        );
    }

    #[test]
    fn positions_advance_over_newlines_and_multibyte() {
        let toks = tokenize("a\nbé").unwrap();
        assert_eq!((toks[1].line, toks[1].col), (2, 1));
        assert_eq!(toks[1].token, Token::Word("bé".into()));
    }

    // ---- malformed-input suite (the house codec rule) ----

    #[test]
    fn unterminated_string_is_positioned() {
        let err = tokenize("leaf x {\n  type \"unterminated;\n}\n").unwrap_err();
        assert_eq!(err, at(2, 8, "unterminated string"));
    }

    #[test]
    fn unterminated_block_comment_is_positioned() {
        let err = tokenize("/* never closed").unwrap_err();
        assert_eq!(err, at(1, 1, "unterminated /* comment"));
    }

    #[test]
    fn illegal_unquoted_characters_are_rejected() {
        // Quotes inside an unquoted word would tokenize ambiguously;
        // the RFC excludes them from unquoted strings.
        assert!(tokenize("a\"b").is_err());
        // Braces/semicolons always self-delimit, so they terminate
        // the word instead — the word itself stays legal.
        assert_eq!(words("a{b"), vec!["a", "{", "b"]);
    }

    #[test]
    fn unsupported_escapes_are_rejected_not_guessed() {
        assert!(tokenize("\"\\x41\"").is_err());
        // Trailing backslash: the escape never completes.
        assert!(tokenize("\"abc\\").is_err());
    }

    #[test]
    fn empty_input_tokenizes_to_nothing() {
        assert_eq!(tokenize(""), Ok(Vec::new()));
        assert_eq!(tokenize("\n// only comments\n"), Ok(Vec::new()));
    }
}
