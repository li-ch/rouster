//! A hand-written regular-expression engine for `pattern` facets —
//! RFC 7950 §9.4.5, which normatively points at XSD's pattern
//! language. No regex crate (the no-new-deps fence).
//!
//! What this implements (the subset the Rouster models need, and a
//! little headroom):
//!
//! - whole-string matching — XSD patterns are implicitly anchored
//!   at both ends (§9.4.5 "MUST match the whole string" semantics);
//!   explicit `^`/`$` are accepted and are no-ops;
//! - alternation `a|b`, concatenation, grouping `(...)`;
//! - quantifiers `*`, `+`, `?` (postfix, single atom);
//! - wildcard `.` (any character);
//! - character classes `[abc]`, ranges `[a-z]`, negation `[^…]`;
//! - the escapes `\d \w \s` (and their in-class use) plus escaped
//!   literals for the punctuation set.
//!
//! What it does NOT implement (each an XSD feature §9.4.5 allows):
//! back-references, `{m,n}` counted repetition, `\p{…}` Unicode
//! property classes, and XSD's multi-`pattern` inheritance
//! composition. Values are bounded (config tokens), and a step
//! budget [`STEP_BUDGET`] turns pathological backtracking into a
//! non-match rather than a hang — disclosed, and pinned by test.

/// The backtracking step budget: a pattern/value pair that exceeds
/// it simply does not match. Generous against real config values
/// (the longest modeled token is an IPv6 prefix) and instant to
/// exhaust against adversarial input.
const STEP_BUDGET: u64 = 100_000;
#[derive(Debug, Clone, PartialEq, Eq)]
enum Ast {
    /// `a|b|c`
    Alt(Vec<Vec<Piece>>),
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct Piece {
    atom: Atom,
    min: u32,
    max: Option<u32>, // None = unbounded
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum Atom {
    Literal(char),
    Dot,
    Class {
        neg: bool,
        ranges: Vec<(char, char)>,
    },
    Group(Box<Ast>),
}

/// A compiled pattern (§9.4.5).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Regex {
    ast: Ast,
    source: String,
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum RegexError {
    #[error("bad pattern `{src}`: {reason}")]
    Bad { src: String, reason: String },
}

fn bad(src: &str, reason: impl Into<String>) -> RegexError {
    RegexError::Bad {
        src: src.to_string(),
        reason: reason.into(),
    }
}

impl Regex {
    /// Compiles a pattern (the argument of a `pattern` facet).
    pub fn new(source: &str) -> Result<Self, RegexError> {
        let chars: Vec<char> = source.chars().collect();
        let mut pos = 0usize;
        let ast = parse_alt(source, &chars, &mut pos)?;
        if pos != chars.len() {
            return Err(bad(source, format!("stray `{}`", chars[pos])));
        }
        Ok(Regex {
            ast,
            source: source.to_string(),
        })
    }

    /// The pattern text (error messages).
    pub fn source(&self) -> &str {
        &self.source
    }

    /// Whole-string match (XSD anchoring).
    pub fn is_match(&self, value: &str) -> bool {
        let chars: Vec<char> = value.chars().collect();
        let mut steps = STEP_BUDGET;
        let mut matched = false;
        let matched_ref = &mut matched;
        match_alt(&self.ast, &chars, 0, &mut steps, &mut |end| {
            if end == chars.len() {
                *matched_ref = true;
                return true; // stop: whole-string match found
            }
            false
        });
        matched
    }
}

// ---- parser ----

fn parse_alt(src: &str, chars: &[char], pos: &mut usize) -> Result<Ast, RegexError> {
    let mut branches = Vec::new();
    loop {
        let branch = parse_concat(src, chars, pos)?;
        branches.push(branch);
        if *pos < chars.len() && chars[*pos] == '|' {
            *pos += 1;
            continue;
        }
        break;
    }
    Ok(Ast::Alt(branches))
}

fn parse_concat(src: &str, chars: &[char], pos: &mut usize) -> Result<Vec<Piece>, RegexError> {
    let mut pieces = Vec::new();
    while *pos < chars.len() {
        match chars[*pos] {
            '|' | ')' => break,
            '^' | '$' => {
                // Implicit anchoring makes these no-ops (documented).
                *pos += 1;
            }
            '*' | '+' | '?' => {
                return Err(bad(src, "quantifier with nothing to repeat"));
            }
            _ => {
                let atom = parse_atom(src, chars, pos)?;
                let (min, max) = if *pos < chars.len() {
                    match chars[*pos] {
                        '*' => {
                            *pos += 1;
                            (0, None)
                        }
                        '+' => {
                            *pos += 1;
                            (1, None)
                        }
                        '?' => {
                            *pos += 1;
                            (0, Some(1))
                        }
                        _ => (1, Some(1)),
                    }
                } else {
                    (1, Some(1))
                };
                pieces.push(Piece { atom, min, max });
            }
        }
    }
    Ok(pieces)
}

fn parse_atom(src: &str, chars: &[char], pos: &mut usize) -> Result<Atom, RegexError> {
    let c = chars[*pos];
    *pos += 1;
    Ok(match c {
        '.' => Atom::Dot,
        '(' => {
            let inner = parse_alt(src, chars, pos)?;
            if *pos >= chars.len() || chars[*pos] != ')' {
                return Err(bad(src, "missing )"));
            }
            *pos += 1;
            Atom::Group(Box::new(inner))
        }
        '[' => {
            let mut neg = false;
            if *pos < chars.len() && chars[*pos] == '^' {
                neg = true;
                *pos += 1;
            }
            let mut ranges = Vec::new();
            let mut first = true;
            loop {
                let Some(&c) = chars.get(*pos) else {
                    return Err(bad(src, "missing ]"));
                };
                if c == ']' && !first {
                    *pos += 1;
                    break;
                }
                first = false;
                let lo_ranges = parse_class_item(src, chars, pos)?;
                // A trailing `-` starts a range to the next item
                // (unless it closes the class or is the last char).
                if *pos < chars.len()
                    && chars[*pos] == '-'
                    && chars.get(*pos + 1).map(|c| *c != ']').unwrap_or(false)
                {
                    *pos += 1;
                    let hi_ranges = parse_class_item(src, chars, pos)?;
                    let (lo, hi) = match (&lo_ranges[..], &hi_ranges[..]) {
                        (&[(lo, _)], &[(hi, _)]) => (lo, hi),
                        _ => {
                            return Err(bad(src, "range endpoints must be single characters"));
                        }
                    };
                    ranges.push((lo, hi));
                } else {
                    ranges.extend(lo_ranges);
                }
            }
            for (lo, hi) in &ranges {
                if lo > hi {
                    return Err(bad(src, format!("class range {lo:?}..{hi:?} out of order")));
                }
            }
            Atom::Class { neg, ranges }
        }
        '\\' => {
            let Some(&e) = chars.get(*pos) else {
                return Err(bad(src, "trailing backslash"));
            };
            *pos += 1;
            match e {
                'd' => Atom::Class {
                    neg: false,
                    ranges: vec![('0', '9')],
                },
                'w' => Atom::Class {
                    neg: false,
                    ranges: word_ranges(),
                },
                's' => Atom::Class {
                    neg: false,
                    ranges: vec![(' ', ' '), ('\t', '\t'), ('\n', '\n')],
                },
                other => Atom::Literal(other),
            }
        }
        other => Atom::Literal(other),
    })
}

/// One class item: a literal char or an escape that expands to
/// ranges (`\\d`, `\\w`, `\\s`).
fn parse_class_item(
    src: &str,
    chars: &[char],
    pos: &mut usize,
) -> Result<Vec<(char, char)>, RegexError> {
    let Some(&c) = chars.get(*pos) else {
        return Err(bad(src, "missing ]"));
    };
    *pos += 1;
    if c == '\\' {
        let Some(&e) = chars.get(*pos) else {
            return Err(bad(src, "trailing backslash in class"));
        };
        *pos += 1;
        return Ok(match e {
            'd' => vec![('0', '9')],
            'w' => word_ranges(),
            's' => vec![(' ', ' '), ('\t', '\t'), ('\n', '\n')],
            other => vec![(other, other)],
        });
    }
    Ok(vec![(c, c)])
}

fn word_ranges() -> Vec<(char, char)> {
    vec![('a', 'z'), ('A', 'Z'), ('0', '9'), ('_', '_')]
}

// ---- matcher (CPS backtracking) ----

type Cont<'a> = dyn FnMut(usize) -> bool + 'a;

fn match_alt(ast: &Ast, s: &[char], pos: usize, steps: &mut u64, k: &mut Cont<'_>) -> bool {
    if *steps == 0 {
        return false;
    }
    *steps -= 1;
    let Ast::Alt(branches) = ast;
    for branch in branches {
        if match_seq(branch, s, pos, steps, k) {
            return true;
        }
    }
    false
}

/// One atom matched once at `pos`; `k(end)` is the continuation
/// (returns true = stop, a match was found down this road).
fn match_atom(atom: &Atom, s: &[char], pos: usize, steps: &mut u64, k: &mut Cont<'_>) -> bool {
    if *steps == 0 {
        return false;
    }
    *steps -= 1;
    match atom {
        Atom::Literal(c) => {
            if s.get(pos) == Some(c) {
                k(pos + 1)
            } else {
                false
            }
        }
        Atom::Dot => {
            if pos < s.len() {
                k(pos + 1)
            } else {
                false
            }
        }
        Atom::Class { neg, ranges } => match s.get(pos) {
            Some(&c) => {
                let inside = ranges.iter().any(|&(lo, hi)| c >= lo && c <= hi);
                if inside != *neg {
                    k(pos + 1)
                } else {
                    false
                }
            }
            None => false,
        },
        Atom::Group(inner) => match_alt(inner, s, pos, steps, k),
    }
}

/// All positions reachable by ONE match of `atom` from any of
/// `from` (collects every alternative; never early-stops).
fn extend(atom: &Atom, from: &[usize], s: &[char], steps: &mut u64) -> Vec<usize> {
    let mut out: Vec<usize> = Vec::new();
    for &p in from {
        match_atom(atom, s, p, steps, &mut |end| {
            if !out.contains(&end) {
                out.push(end);
            }
            false // keep collecting
        });
    }
    out
}

fn match_seq(pieces: &[Piece], s: &[char], pos: usize, steps: &mut u64, k: &mut Cont<'_>) -> bool {
    if *steps == 0 {
        return false;
    }
    *steps -= 1;
    let Some((head, rest)) = pieces.split_first() else {
        return k(pos);
    };
    // Repetition: sets of reachable positions per count, greedy
    // (longest first). Unbounded counts are capped at `s.len() + 1`
    // — every productive repetition consumes at least one character.
    let cap = head
        .max
        .map(|m| m.min(s.len() as u32 + 1))
        .unwrap_or(s.len() as u32 + 1);
    let mut layers: Vec<Vec<usize>> = vec![vec![pos]];
    let mut n: u32 = 0;
    // Did repetition stop because the atom only matched empty at the
    // fixpoint? Then any higher (or min-satisfying) count is padding
    // and the fixpoint positions still count.
    let mut empty_pad = false;
    while n < cap {
        let next = extend(&head.atom, &layers[n as usize], s, steps);
        if next.is_empty() {
            break;
        }
        if next == layers[n as usize] {
            empty_pad = true;
            break;
        }
        layers.push(next);
        n += 1;
    }
    let reachable = layers.len() as u32 - 1;
    // Greedy: highest feasible count first, then fewer. Padding can
    // satisfy a min beyond the productive layers.
    let top = if empty_pad {
        reachable.max(head.min)
    } else {
        reachable
    };
    let mut count = top;
    loop {
        if count < head.min {
            break;
        }
        let layer = &layers[count.min(reachable) as usize];
        for &p in layer {
            if match_seq(rest, s, p, steps, k) {
                return true;
            }
        }
        if count == 0 {
            break;
        }
        count -= 1;
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    fn m(pattern: &str, value: &str) -> bool {
        Regex::new(pattern).unwrap().is_match(value)
    }

    #[test]
    fn whole_string_match_no_partial() {
        assert!(m("abc", "abc"));
        // XSD anchoring: substrings do not match.
        assert!(!m("bc", "abc"));
        assert!(!m("ab", "abc"));
        assert!(!m("abc", "abcd"));
    }

    #[test]
    fn classes_ranges_negation_and_dots() {
        assert!(m("[a-z]+", "hello"));
        assert!(!m("[a-z]+", "hello1"));
        assert!(m("[^0-9]+", "abc"));
        assert!(!m("[^0-9]+", "a1"));
        assert!(m("a.c", "abc"));
        assert!(m("a.c", "a c"));
        assert!(!m("a.c", "ac"));
    }

    #[test]
    fn quantifiers_alternation_groups() {
        assert!(m("ab*", "a"));
        assert!(m("ab*", "abbb"));
        assert!(m("ab+", "ab"));
        assert!(!m("ab+", "a"));
        assert!(m("colou?r", "color"));
        assert!(m("cat|dog", "dog"));
        assert!(!m("cat|dog", "cow"));
        assert!(m("(ab)+", "abab"));
        assert!(!m("(ab)+", "aba"));
    }

    #[test]
    fn escapes_work_in_and_out_of_classes() {
        assert!(m(r"\d+", "123"));
        assert!(!m(r"\d+", "12a"));
        assert!(m(r"a\.b", "a.b"));
        assert!(!m(r"a\.b", "axb"));
        assert!(m(r"[\d\-]+", "9-1"));
    }

    #[test]
    fn the_modeled_patterns_match_their_values() {
        // isisd NET: dotted hex groups ending in the zero NSEL
        // (`{m,n}` counted repetition is not in the subset — the
        // models use `+`/`*` spellings).
        let net = "([0-9a-fA-F]+\\.)*[0-9a-fA-F]+\\.00";
        assert!(m(net, "49.0001.1921.6800.1002.00"));
        assert!(!m(net, "49.0001.1921.6800.1002"));
        assert!(!m(net, "49.0001.1921.6800.1002.01"));
        // ospfd area-id: dotted quad without leading zeros.
        let area = "(0|[1-9][0-9]*)(\\.(0|[1-9][0-9]*))(\\.(0|[1-9][0-9]*))(\\.(0|[1-9][0-9]*))";
        assert!(m(area, "0.0.0.0"));
        assert!(m(area, "10.1.255.0"));
        assert!(!m(area, "01.0.0.0"));
        assert!(!m(area, "10.1.2"));
    }

    #[test]
    fn empty_repetition_padding_satisfies_min() {
        // (b?)+ must still match zero b's — the min is satisfiable
        // by empty padding.
        assert!(m("a(b?)+c", "ac"));
        assert!(m("a(b?)+c", "abc"));
        assert!(m("a(x|)+b", "ab"));
    }

    #[test]
    fn malformed_patterns_are_refused() {
        assert!(Regex::new("[a-").is_err());
        assert!(Regex::new("(ab").is_err());
        assert!(Regex::new("*ab").is_err());
        assert!(Regex::new("a\\").is_err());
        // A trailing ) that never opened.
        assert!(Regex::new("ab)").is_err());
    }

    #[test]
    fn step_budget_prevents_the_blowup_not_the_machine() {
        // A classic pathological pair against this engine; the
        // budget turns it into a non-match within milliseconds.
        let pattern = "(a*)*b";
        let value = "a".repeat(40);
        let started = std::time::Instant::now();
        assert!(!m(pattern, &value));
        assert!(started.elapsed().as_secs() < 5, "budget held");
        // And the same pattern still works on the honest inputs.
        assert!(m("(a*)*b", "aaab"));
    }
}
