//! The `must` expression subset — RFC 7950 §7.5.3.
//!
//! The RFC's `must` takes "an XPath 1.0 expression" evaluated in
//! the context node (§6.4.1's XPath context). Full XPath is far
//! outside this crate; this module defines and implements the
//! DOCUMENTED subset every Rouster model's `must` uses, and its
//! grammar is printed in full here so the models' expressions can
//! be audited against it:
//!
//! ```text
//! expr   := or
//! or     := and ( 'or' and )*
//! and    := not ( 'and' not )*
//! not    := 'not' '(' expr ')' | primary
//! primary:= '(' expr ')' | comparison | path
//! comparison := path ('=' | '!=') literal
//! path   := [prefix ':'] step ('/' step)*
//! step   := identifier ('[' key '=' literal ']')*
//! literal:= quoted string | number | true | false
//! ```
//!
//! A bare `path` is an EXISTENCE test (true iff the addressed node
//! exists — the subset's one predicate form). Equality compares the
//! addressed leaf's value against a literal. Paths resolve
//! absolutely (`/interfaces/interface[name=eth0]/mtu`) or relatively
//! from the must's context node (`.`, `..`, `mode`); `..` in XPath
//! is the parent axis.
//!
//! What §7.5.3's full XPath offers that this subset deliberately
//! does NOT (each named so a model needing it fails loudly at
//! schema-parse time — see [`crate::schema::parse_must`], which
//! parses eagerly):
//!
//! - arithmetic and comparison operators beyond `=`/`!=` (`<`,
//!   `<=`, `>`, `>=`, `+`, `-`, `*`, `div`, `mod`);
//! - every XPath axis except child and parent (`ancestor::`,
//!   `descendant::`, `following-sibling::`, …);
//! - node-set functions (`count`, `sum`, `min`, `max`, `avg`,
//!   `string-length`, `substring`, `contains`, `starts-with`,
//!   `starts-with2`, …);
//! - the RFC 7950 §10 function library: `current()` (§10.1.1),
//!   `re-match()` (§10.2.1), `deref()` (§10.3.1),
//!   `derived-from()`-family (§10.4), `enum-value()` (§10.5.1),
//!   `bit-is-set()` (§10.6.1);
//! - variables and key predicates beyond single equality tests.
//!
//! Violations carry the must's `error-message` (§7.5.4.1) when one
//! was declared, else a synthesized message naming the path and the
//! failed expression.

/// A parsed `must` (§7.5.3): expression + optional error-message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MustDef {
    pub expr: Expr,
    pub source: String,
    pub error_message: Option<String>,
}

/// The expression AST (the grammar in the module docs).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Expr {
    Or(Box<Expr>, Box<Expr>),
    And(Box<Expr>, Box<Expr>),
    Not(Box<Expr>),
    /// Existence: the path must address an existing node.
    Exists(Path),
    /// Equality: the addressed leaf's value equals (or differs
    /// from) the literal.
    Cmp {
        path: Path,
        negated: bool,
        literal: String,
    },
}

/// A schema-relative path: segments with optional key predicates.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Path {
    /// Absolute (`/…`) or relative.
    pub absolute: bool,
    pub steps: Vec<Step>,
}

impl Path {
    /// A one-segment relative path (`name`).
    pub fn leaf(name: &str) -> Path {
        Path {
            absolute: false,
            steps: vec![Step {
                name: name.to_string(),
                key: None,
            }],
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Step {
    pub name: String,
    /// Single key predicate `[name = literal]`.
    pub key: Option<(String, String)>,
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum MustError {
    #[error("bad must expression `{src}`: {reason}")]
    Bad { src: String, reason: String },
    #[error("must `{src}` violated at {path}: {message}")]
    Violated {
        src: String,
        path: String,
        message: String,
    },
}

impl MustDef {
    /// Parses and validates a must expression (grammar above).
    pub fn parse(source: &str, error_message: Option<String>) -> Result<MustDef, String> {
        let tokens =
            lex_expr(source).map_err(|reason| format!("must expression `{source}`: {reason}"))?;
        let mut pos = 0usize;
        let expr = parse_or(source, &tokens, &mut pos)?;
        if pos != tokens.len() {
            return Err(format!(
                "must expression `{source}`: trailing tokens at {}",
                tokens[pos]
            ));
        }
        Ok(MustDef {
            expr,
            source: source.to_string(),
            error_message,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum Tok {
    Word(String),
    Str(String),
    Num(String),
    Slash,
    LBracket,
    RBracket,
    LParen,
    RParen,
    Eq,
    Ne,
    Colon,
}

impl std::fmt::Display for Tok {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Tok::Word(w) => f.write_str(w),
            Tok::Str(s) => write!(f, "{s:?}"),
            Tok::Num(n) => f.write_str(n),
            Tok::Slash => f.write_str("/"),
            Tok::LBracket => f.write_str("["),
            Tok::RBracket => f.write_str("]"),
            Tok::LParen => f.write_str("("),
            Tok::RParen => f.write_str(")"),
            Tok::Eq => f.write_str("="),
            Tok::Ne => f.write_str("!="),
            Tok::Colon => f.write_str(":"),
        }
    }
}

fn lex_expr(src: &str) -> Result<Vec<Tok>, String> {
    let chars: Vec<char> = src.chars().collect();
    let mut out = Vec::new();
    let mut i = 0usize;
    while i < chars.len() {
        let c = chars[i];
        match c {
            ' ' | '\t' => i += 1,
            '/' => {
                out.push(Tok::Slash);
                i += 1;
            }
            '[' => {
                out.push(Tok::LBracket);
                i += 1;
            }
            ']' => {
                out.push(Tok::RBracket);
                i += 1;
            }
            '(' => {
                out.push(Tok::LParen);
                i += 1;
            }
            ')' => {
                out.push(Tok::RParen);
                i += 1;
            }
            ':' => {
                out.push(Tok::Colon);
                i += 1;
            }
            '=' => {
                out.push(Tok::Eq);
                i += 1;
            }
            '!' if chars.get(i + 1) == Some(&'=') => {
                out.push(Tok::Ne);
                i += 2;
            }
            '\'' | '"' => {
                let quote = c;
                let mut s = String::new();
                i += 1;
                while i < chars.len() && chars[i] != quote {
                    s.push(chars[i]);
                    i += 1;
                }
                if i >= chars.len() {
                    return Err("unterminated string literal".to_string());
                }
                i += 1;
                out.push(Tok::Str(s));
            }
            _ if c.is_ascii_digit() || c == '-' => {
                let start = i;
                while i < chars.len()
                    && (chars[i].is_ascii_digit() || matches!(chars[i], '-' | '.'))
                {
                    i += 1;
                }
                out.push(Tok::Num(chars[start..i].iter().collect()));
            }
            _ if c.is_ascii_alphabetic() || c == '_' || c == '.' => {
                let start = i;
                while i < chars.len()
                    && (chars[i].is_ascii_alphanumeric() || matches!(chars[i], '_' | '-' | '.'))
                {
                    i += 1;
                }
                out.push(Tok::Word(chars[start..i].iter().collect()));
            }
            other => {
                return Err(format!("`{other}` is not in the must-subset grammar"));
            }
        }
    }
    Ok(out)
}

fn parse_or(src: &str, toks: &[Tok], pos: &mut usize) -> Result<Expr, String> {
    let mut left = parse_and(src, toks, pos)?;
    while toks.get(*pos) == Some(&Tok::Word("or".into())) {
        *pos += 1;
        let right = parse_and(src, toks, pos)?;
        left = Expr::Or(Box::new(left), Box::new(right));
    }
    Ok(left)
}

fn parse_and(src: &str, toks: &[Tok], pos: &mut usize) -> Result<Expr, String> {
    let mut left = parse_not(src, toks, pos)?;
    while toks.get(*pos) == Some(&Tok::Word("and".into())) {
        *pos += 1;
        let right = parse_not(src, toks, pos)?;
        left = Expr::And(Box::new(left), Box::new(right));
    }
    Ok(left)
}

fn parse_not(src: &str, toks: &[Tok], pos: &mut usize) -> Result<Expr, String> {
    if toks.get(*pos) == Some(&Tok::Word("not".into())) && toks.get(*pos + 1) == Some(&Tok::LParen)
    {
        *pos += 2;
        let inner = parse_or(src, toks, pos)?;
        expect(src, toks, pos, &Tok::RParen)?;
        return Ok(Expr::Not(Box::new(inner)));
    }
    parse_primary(src, toks, pos)
}

fn expect(src: &str, toks: &[Tok], pos: &mut usize, want: &Tok) -> Result<(), String> {
    if toks.get(*pos) == Some(want) {
        *pos += 1;
        Ok(())
    } else {
        Err(format!(
            "expected `{want}`, got `{}`",
            toks.get(*pos).map(|t| t.to_string()).unwrap_or_default()
        ))
        .map_err(|e| format!("{src}: {e}"))
    }
}

fn parse_primary(src: &str, toks: &[Tok], pos: &mut usize) -> Result<Expr, String> {
    match toks.get(*pos) {
        Some(Tok::LParen) => {
            *pos += 1;
            let inner = parse_or(src, toks, pos)?;
            expect(src, toks, pos, &Tok::RParen)?;
            Ok(inner)
        }
        Some(Tok::Word(w)) if w == "not" => Err(format!(
            "{src}: `not` needs parentheses in the subset: not(expr)"
        )),
        _ => {
            let path = parse_path(src, toks, pos)?;
            match toks.get(*pos) {
                Some(Tok::Eq) | Some(Tok::Ne) => {
                    let negated = toks[*pos] == Tok::Ne;
                    *pos += 1;
                    let literal = match toks.get(*pos) {
                        Some(Tok::Str(s)) => s.clone(),
                        Some(Tok::Num(n)) => n.clone(),
                        Some(Tok::Word(w)) if w == "true" || w == "false" => w.clone(),
                        other => {
                            return Err(format!(
                                "{src}: comparison needs a string/number/boolean literal, got `{}`",
                                other
                                    .as_ref()
                                    .map(|t| t.to_string())
                                    .unwrap_or_else(|| "end".into())
                            ));
                        }
                    };
                    *pos += 1;
                    Ok(Expr::Cmp {
                        path,
                        negated,
                        literal,
                    })
                }
                _ => Ok(Expr::Exists(path)),
            }
        }
    }
}

fn parse_path(src: &str, toks: &[Tok], pos: &mut usize) -> Result<Path, String> {
    let mut absolute = false;
    if toks.get(*pos) == Some(&Tok::Slash) {
        absolute = true;
        *pos += 1;
    }
    let mut steps = Vec::new();
    loop {
        match toks.get(*pos) {
            Some(Tok::Word(w)) if w == "." || w == ".." => {
                steps.push(Step {
                    name: w.clone(),
                    key: None,
                });
                *pos += 1;
            }
            Some(Tok::Word(name)) => {
                *pos += 1;
                // Optional prefix qualifier: `prefix:name` (a
                // module-qualified step; the subset's trees are
                // single-module, so the prefix must match the owning
                // module — checked at evaluation, ignored here).
                let mut name = name.clone();
                if toks.get(*pos) == Some(&Tok::Colon) {
                    if let Some(Tok::Word(tail)) = toks.get(*pos + 1) {
                        name = format!("{name}:{tail}");
                        *pos += 2;
                    } else {
                        return Err(format!("{src}: dangling `:` in path"));
                    }
                }
                let mut key = None;
                while toks.get(*pos) == Some(&Tok::LBracket) {
                    *pos += 1;
                    let Some(Tok::Word(kname)) = toks.get(*pos).cloned() else {
                        return Err(format!("{src}: key predicate needs a leaf name"));
                    };
                    *pos += 1;
                    expect(src, toks, pos, &Tok::Eq)?;
                    let Some(Tok::Str(kval)) = toks.get(*pos).cloned() else {
                        return Err(format!(
                            "{src}: key predicate value must be a quoted string"
                        ));
                    };
                    *pos += 1;
                    expect(src, toks, pos, &Tok::RBracket)?;
                    key = Some((kname, kval));
                }
                steps.push(Step { name, key });
            }
            _ => break,
        }
        if toks.get(*pos) == Some(&Tok::Slash) {
            *pos += 1;
            continue;
        }
        break;
    }
    if steps.is_empty() {
        return Err(format!("{src}: path needs at least one step"));
    }
    Ok(Path { absolute, steps })
}

/// The evaluation callback: resolves a path against the evaluator's
/// context. Returns `None` when the path addresses no existing node.
/// Implemented by [`crate::data::DataTree`].
pub trait PathResolver {
    /// Resolve `path` (relative to the context node `context_path`)
    /// to the addressed leaf's value, or `None` when absent.
    fn leaf_value(&self, context_path: &[String], path: &Path) -> Option<String>;

    /// Does `path` address an existing node (container, list entry,
    /// or leaf)?
    fn node_exists(&self, context_path: &[String], path: &Path) -> bool;
}

impl MustDef {
    /// Evaluates the expression; on violation returns the
    /// [`MustError::Violated`] with the declared error-message
    /// (§7.5.4.1) or a synthesized one.
    pub fn check(
        &self,
        resolver: &dyn PathResolver,
        context_path: &[String],
    ) -> Result<(), MustError> {
        if eval(&self.expr, resolver, context_path) {
            Ok(())
        } else {
            Err(MustError::Violated {
                src: self.source.clone(),
                path: context_path.join("/"),
                message: self
                    .error_message
                    .clone()
                    .unwrap_or_else(|| self.source.clone()),
            })
        }
    }
}

fn eval(expr: &Expr, r: &dyn PathResolver, ctx: &[String]) -> bool {
    match expr {
        Expr::Or(a, b) => eval(a, r, ctx) || eval(b, r, ctx),
        Expr::And(a, b) => eval(a, r, ctx) && eval(b, r, ctx),
        Expr::Not(a) => !eval(a, r, ctx),
        Expr::Exists(path) => r.node_exists(ctx, path),
        Expr::Cmp {
            path,
            negated,
            literal,
        } => {
            let value = r.leaf_value(ctx, path);
            match value {
                Some(v) => {
                    if *negated {
                        v != *literal
                    } else {
                        v == *literal
                    }
                }
                // XPath 1.0: comparing a non-existent node yields
                // false; `!=` against nothing is still false (an
                // empty node-set compares false both ways).
                None => false,
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse_ok(s: &str) -> MustDef {
        MustDef::parse(s, None).unwrap()
    }

    #[test]
    fn parses_existence_paths_absolute_and_relative() {
        let d = parse_ok("/interfaces/interface[name='eth0']/mtu");
        assert_eq!(
            d.expr,
            Expr::Exists(Path {
                absolute: true,
                steps: vec![
                    Step {
                        name: "interfaces".into(),
                        key: None
                    },
                    Step {
                        name: "interface".into(),
                        key: Some(("name".into(), "eth0".into()))
                    },
                    Step {
                        name: "mtu".into(),
                        key: None
                    },
                ]
            })
        );
        assert!(matches!(parse_ok("mode").expr, Expr::Exists(_)));
        assert!(matches!(parse_ok(".").expr, Expr::Exists(_)));
        assert!(matches!(parse_ok("../action").expr, Expr::Exists(_)));
    }

    #[test]
    fn parses_comparisons_and_booleans() {
        assert!(matches!(
            parse_ok("action = 'drop'").expr,
            Expr::Cmp { negated: false, .. }
        ));
        assert!(matches!(
            parse_ok("count != 3").expr,
            Expr::Cmp { negated: true, literal, .. } if literal == "3"
        ));
        assert!(matches!(
            parse_ok("enabled = true").expr,
            Expr::Cmp { literal, .. } if literal == "true"
        ));
    }

    #[test]
    fn parses_and_or_not_parens() {
        let d = parse_ok("not(action = 'drop') or i-understand-drop-mode = 'yes'");
        assert!(matches!(d.expr, Expr::Or(_, _)));
        let d2 = parse_ok("(a = '1' or b = '2') and not(c = '3')");
        assert!(matches!(d2.expr, Expr::And(_, _)));
    }

    // ---- malformed expressions ----

    #[test]
    fn malformed_expressions_are_rejected() {
        assert!(MustDef::parse("count(.)", None).is_err()); // no functions
        assert!(MustDef::parse("a <", None).is_err()); // no operators beyond = !=
        assert!(MustDef::parse("a < 3", None).is_err());
        assert!(MustDef::parse("current()", None).is_err());
        assert!(MustDef::parse("'unterminated", None).is_err());
        assert!(MustDef::parse("a = ", None).is_err());
        assert!(MustDef::parse("(a = '1'", None).is_err());
        assert!(MustDef::parse("not a = '1'", None).is_err()); // parens required
        assert!(MustDef::parse("", None).is_err());
        assert!(MustDef::parse("/interface[name=eth0]", None).is_err()); // unquoted key
    }

    // ---- evaluation ----

    /// A tiny map-backed resolver for the evaluator tests.
    struct MapResolver {
        values: Vec<(String, String)>, // absolute path -> value
    }

    impl PathResolver for MapResolver {
        fn leaf_value(&self, ctx: &[String], path: &Path) -> Option<String> {
            let abs = resolve_abs(ctx, path);
            self.values
                .iter()
                .find(|(k, _)| *k == abs)
                .map(|(_, v)| v.clone())
        }

        fn node_exists(&self, ctx: &[String], path: &Path) -> bool {
            let abs = resolve_abs(ctx, path);
            self.values
                .iter()
                .any(|(k, _)| k.starts_with(&abs) || *k == abs)
        }
    }

    fn resolve_abs(ctx: &[String], path: &Path) -> String {
        let mut parts: Vec<String> = if path.absolute {
            Vec::new()
        } else {
            ctx.to_vec()
        };
        for step in &path.steps {
            match step.name.as_str() {
                "." => {}
                ".." => {
                    parts.pop();
                }
                name => {
                    let seg = match &step.key {
                        Some((k, v)) => format!("{name}[{k}={v}]"),
                        None => name.to_string(),
                    };
                    parts.push(seg);
                }
            }
        }
        format!("/{}", parts.join("/"))
    }

    #[test]
    fn evaluates_existence_equality_and_connectives() {
        let r = MapResolver {
            values: vec![
                ("/action".into(), "drop".into()),
                ("/ack".into(), "yes".into()),
                ("/if[name=eth0]/mode".into(), "strict".into()),
            ],
        };
        assert!(parse_ok("action").check(&r, &[]).is_ok());
        assert!(parse_ok("action = 'drop'").check(&r, &[]).is_ok());
        assert!(parse_ok("action != 'monitor'").check(&r, &[]).is_ok());
        assert!(parse_ok("nope").check(&r, &[]).is_err());
        // Relative resolution from a context node.
        assert!(parse_ok("mode = 'strict'")
            .check(&r, &["if[name=eth0]".to_string()])
            .is_ok());
        // .. walks up from the entry.
        assert!(parse_ok("../action = 'drop'")
            .check(&r, &["if[name=eth0]".to_string()])
            .is_ok());
        // Connectives: the savd drop-friction shape.
        let m = parse_ok("not(action = 'drop') or ack = 'yes'");
        assert!(m.check(&r, &[]).is_ok());
        let r2 = MapResolver {
            values: vec![("/action".into(), "drop".into())],
        };
        let err = m.check(&r2, &[]).unwrap_err();
        assert!(
            err.to_string().contains("action = 'drop' or ack = 'yes'")
                || err.to_string().contains("violated"),
            "{err}"
        );
        // XPath empty node-set: both = and != are false.
        let r3 = MapResolver { values: vec![] };
        assert!(parse_ok("missing != 'x'").check(&r3, &[]).is_err());
    }
}
