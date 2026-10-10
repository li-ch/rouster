//! FRR AS-path regular expressions: the POSIX-ERE subset BGP filters
//! actually use, without a regex dependency (fence: no new deps). [W1-a
//! M2/M4]
//!
//! FRR grounds the syntax: "BGP regular expressions are based on POSIX
//! 1003.2 regular expressions" with the documented quick subset `.  *  +
//! ?  ^  $` and `_`, where `_` "matches to space and comma , and AS set
//! delimiter { and } and AS confederation delimiter ( and ). And it also
//! matches to the beginning of the line and the end of the line ...
//! technically evaluates to `(^|[,{}()]|$)`" (FRR docs, BGP chapter,
//! "BGP Regular Expressions"). Observed FRR examples:
//! `_23456_`, `_1310[0-6][0-9]_|_13107[0-1]_`, `^65` (bgpd access-list
//! examples in the same chapter).
//!
//! Matching model: NFA *simulation* over position sets (no
//! backtracking), so pathological patterns cannot blow up: each round
//! produces a deduplicated set of reachable offsets, bounded by input
//! length + 1. Patterns are matched **anywhere** in the rendered path
//! (POSIX `regexec` find semantics) by wrapping with implicit `.*` on
//! both ends; explicit `^` / `$` atoms still anchor.

use crate::route::AsPath;

/// One node of the compiled pattern.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Node {
    /// Literal character.
    Char(char),
    /// `.` — any single character.
    Any,
    /// `[...]` character class; `neg` for `[^...]`.
    Class {
        neg: bool,
        ranges: Vec<(char, char)>,
    },
    /// `_` — the AS-boundary atom: zero-width at start/end, else one
    /// character from `[,{}()]`.
    AsBoundary,
    /// `^` — zero-width at start of string.
    Start,
    /// `$` — zero-width at end of string.
    End,
    Concat(Vec<Node>),
    Alt(Vec<Node>),
    /// `min..max` repetitions of the inner node (`*` = 0.., `+` = 1..,
    /// `?` = 0..1, `{n}` = n..n, `{n,}` = n.., `{n,m}` = n..m).
    Repeat {
        node: Box<Node>,
        min: u32,
        max: Option<u32>,
    },
}

/// Error from pattern compilation, with the offending fragment.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum AsRegexError {
    #[error("unterminated character class at position {pos}")]
    UnterminatedClass { pos: usize },
    #[error("unexpected `)` at position {pos}")]
    UnbalancedClose { pos: usize },
    #[error("missing closing `)` (opened at position {pos})")]
    UnclosedGroup { pos: usize },
    #[error("dangling repeat operator `{op}` at position {pos} with nothing to repeat")]
    DanglingRepeat { op: char, pos: usize },
    #[error("unsupported escape at position {pos}")]
    BadEscape { pos: usize },
}

/// A compiled AS-path regex.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AsRegex {
    prog: Node,
    source: String,
}

impl AsRegex {
    /// Compile a pattern (FRR `_`-style operators included).
    pub fn new(pattern: &str) -> Result<Self, AsRegexError> {
        let chars: Vec<char> = pattern.chars().collect();
        let mut pos = 0usize;
        let prog = parse_alt(&chars, &mut pos)?;
        if pos != chars.len() {
            // parse_alt stops early only on an unmatched `)`.
            return Err(AsRegexError::UnbalancedClose { pos });
        }
        Ok(Self {
            prog,
            source: pattern.to_string(),
        })
    }

    /// The original pattern text.
    pub fn source(&self) -> &str {
        &self.source
    }

    /// Does the path match this pattern (find-anywhere semantics)?
    pub fn matches_path(&self, path: &AsPath) -> bool {
        self.matches_str(&path.render())
    }

    /// Does an already-rendered AS-path string match?
    pub fn matches_str(&self, rendered: &str) -> bool {
        let text: Vec<char> = rendered.chars().collect();
        // Implicit .* on both ends: start from every offset is equivalent
        // and cheaper than synthesizing nodes — simulate the full program
        // seeded from every start offset, accept if any run ends anywhere.
        for start in 0..=text.len() {
            let mut cur = vec![start];
            dedup(&mut cur, text.len());
            if run_seq(&self.prog, &text, &mut cur) {
                return true;
            }
        }
        false
    }
}

impl std::fmt::Display for AsRegex {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.source)
    }
}

impl std::str::FromStr for AsRegex {
    type Err = AsRegexError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::new(s)
    }
}

// ---------------------------------------------------------------------------
// Parser (recursive descent): alt := concat ('|' concat)* ;
// concat := repeat* ; repeat := atom ('*'|'+'|'?')* ; atom := literal,
// '.', '_', '^', '$', class, or '(' alt ')'.
// ---------------------------------------------------------------------------

fn parse_alt(cs: &[char], pos: &mut usize) -> Result<Node, AsRegexError> {
    let mut branches = vec![parse_concat(cs, pos)?];
    while *pos < cs.len() && cs[*pos] == '|' {
        *pos += 1;
        branches.push(parse_concat(cs, pos)?);
    }
    Ok(if branches.len() == 1 {
        branches.pop().expect("one branch")
    } else {
        Node::Alt(branches)
    })
}

fn parse_concat(cs: &[char], pos: &mut usize) -> Result<Node, AsRegexError> {
    let mut items: Vec<Node> = Vec::new();
    while *pos < cs.len() {
        match cs[*pos] {
            '|' | ')' => break,
            '*' | '+' | '?' => {
                // Nothing to repeat (start of sequence).
                return Err(AsRegexError::DanglingRepeat {
                    op: cs[*pos],
                    pos: *pos,
                });
            }
            _ => {
                let atom = parse_atom(cs, pos)?;
                items.push(parse_repeat(cs, pos, atom)?);
            }
        }
    }
    Ok(match items.len() {
        0 => Node::Concat(Vec::new()),
        1 => items.pop().expect("one item"),
        _ => Node::Concat(items),
    })
}

fn parse_repeat(cs: &[char], pos: &mut usize, atom: Node) -> Result<Node, AsRegexError> {
    let mut node = atom;
    loop {
        if *pos >= cs.len() {
            break;
        }
        let op_pos = *pos;
        let op = cs[op_pos];
        let (min, max) = match op {
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
            '{' => match parse_braces(cs, pos) {
                Some((lo, hi)) => (lo, hi),
                None => break, // malformed braces → literal `{` (POSIX UB)
            },
            _ => break,
        };
        if matches!(node, Node::Start | Node::End) {
            return Err(AsRegexError::DanglingRepeat { op, pos: op_pos });
        }
        node = Node::Repeat {
            node: Box::new(node),
            min,
            max,
        };
    }
    Ok(node)
}

/// Parse `{n}`, `{n,}`, `{n,m}` at `pos` (which points at `{`).
/// Returns `None` (and leaves `pos` untouched) when the text is not a
/// valid bound — the `{` then matches literally, POSIX-undefined
/// territory.
fn parse_braces(cs: &[char], pos: &mut usize) -> Option<(u32, Option<u32>)> {
    let mut i = *pos + 1;
    let mut lo_s = String::new();
    while i < cs.len() && cs[i].is_ascii_digit() {
        lo_s.push(cs[i]);
        i += 1;
    }
    if lo_s.is_empty() {
        return None;
    }
    let lo: u32 = lo_s.parse().ok()?;
    if i < cs.len() && cs[i] == '}' {
        *pos = i + 1;
        return Some((lo, Some(lo)));
    }
    if i >= cs.len() || cs[i] != ',' {
        return None;
    }
    i += 1;
    let mut hi_s = String::new();
    while i < cs.len() && cs[i].is_ascii_digit() {
        hi_s.push(cs[i]);
        i += 1;
    }
    if i >= cs.len() || cs[i] != '}' {
        return None;
    }
    *pos = i + 1;
    let hi = if hi_s.is_empty() {
        None
    } else {
        Some(hi_s.parse().ok()?)
    };
    Some((lo, hi))
}

fn parse_atom(cs: &[char], pos: &mut usize) -> Result<Node, AsRegexError> {
    let open = *pos;
    let c = cs[open];
    *pos += 1;
    Ok(match c {
        '.' => Node::Any,
        '_' => Node::AsBoundary,
        '^' => Node::Start,
        '$' => Node::End,
        '(' => {
            let inner = parse_alt(cs, pos)?;
            if *pos >= cs.len() || cs[*pos] != ')' {
                return Err(AsRegexError::UnclosedGroup { pos: open });
            }
            *pos += 1;
            inner
        }
        '[' => parse_class(cs, pos, open)?,
        '\\' => {
            if *pos >= cs.len() {
                return Err(AsRegexError::BadEscape { pos: open });
            }
            let e = cs[*pos];
            *pos += 1;
            Node::Char(e)
        }
        other => Node::Char(other),
    })
}

fn parse_class(cs: &[char], pos: &mut usize, open: usize) -> Result<Node, AsRegexError> {
    let mut neg = false;
    if *pos < cs.len() && cs[*pos] == '^' {
        neg = true;
        *pos += 1;
    }
    let mut ranges: Vec<(char, char)> = Vec::new();
    let mut first = true;
    while *pos < cs.len() {
        let c = cs[*pos];
        if c == ']' && !first {
            *pos += 1;
            return Ok(Node::Class { neg, ranges });
        }
        first = false;
        let lo = if c == '\\' && *pos + 1 < cs.len() {
            *pos += 1;
            cs[*pos]
        } else {
            c
        };
        *pos += 1;
        if *pos + 1 < cs.len() && cs[*pos] == '-' && cs[*pos + 1] != ']' {
            let hi = cs[*pos + 1];
            *pos += 2;
            ranges.push((lo, hi));
        } else {
            ranges.push((lo, lo));
        }
    }
    Err(AsRegexError::UnterminatedClass { pos: open })
}

// ---------------------------------------------------------------------------
// NFA simulation. `run_seq` steps a set of input offsets through a node,
// leaving the reachable output offsets in `cur`.
// ---------------------------------------------------------------------------

/// Push `p` if in range and not already present (input offsets are
/// unique; sets stay tiny — linear scan beats a bitmap allocation).
fn push_dedup(cur: &mut Vec<usize>, p: usize, len: usize) {
    if p <= len && !cur.contains(&p) {
        cur.push(p);
    }
}

fn dedup(cur: &mut Vec<usize>, _len: usize) {
    cur.sort_unstable();
    cur.dedup();
}

/// Step every offset in `cur` through `node`; `cur` is replaced by the
/// reachable offsets. Returns false when no offset survives.
fn run_seq(node: &Node, text: &[char], cur: &mut Vec<usize>) -> bool {
    let mut out: Vec<usize> = Vec::with_capacity(cur.len() + 1);
    std::mem::swap(cur, &mut out);
    run_node(node, text, &out, cur);
    !cur.is_empty()
}

/// Append to `out` all offsets reachable from some offset in `ins` after
/// the node consumes once.
fn run_node(node: &Node, text: &[char], ins: &[usize], out: &mut Vec<usize>) {
    match node {
        Node::Char(c) => {
            for &p in ins {
                if p < text.len() && text[p] == *c {
                    push_dedup(out, p + 1, text.len());
                }
            }
        }
        Node::Any => {
            for &p in ins {
                if p < text.len() {
                    push_dedup(out, p + 1, text.len());
                }
            }
        }
        Node::Class { neg, ranges } => {
            for &p in ins {
                if p < text.len() {
                    let c = text[p];
                    let hit = ranges.iter().any(|&(lo, hi)| lo <= c && c <= hi);
                    if hit != *neg {
                        push_dedup(out, p + 1, text.len());
                    }
                }
            }
        }
        Node::AsBoundary => {
            // `(^|[,{}()]|$)`: zero-width at the ends, one separator
            // character in the middle.
            for &p in ins {
                if p == 0 || p == text.len() {
                    push_dedup(out, p, text.len());
                } else if matches!(text[p], ' ' | ',' | '{' | '}' | '(' | ')') {
                    push_dedup(out, p + 1, text.len());
                }
            }
        }
        Node::Start => {
            for &p in ins {
                if p == 0 {
                    push_dedup(out, 0, text.len());
                }
            }
        }
        Node::End => {
            for &p in ins {
                if p == text.len() {
                    push_dedup(out, p, text.len());
                }
            }
        }
        Node::Concat(items) => {
            let mut cur = ins.to_vec();
            for item in items {
                let mut next = Vec::with_capacity(cur.len() + 1);
                run_node(item, text, &cur, &mut next);
                cur = next;
                if cur.is_empty() {
                    return;
                }
            }
            out.extend(cur.iter().copied());
            dedup(out, text.len());
        }
        Node::Alt(branches) => {
            for b in branches {
                run_node(b, text, ins, out);
            }
        }
        Node::Repeat { node, min, max } => {
            // Union over k ∈ [min, max] of offsets reachable after k
            // applications. Rounds before `min` run unconditionally (at
            // most `min` of them); afterwards every round collects the
            // frontier into `acc` and the next frontier is pruned
            // against `acc` — each round must surface a never-collected
            // offset (≤ len+1 exist) or the frontier empties, so the
            // loop terminates even for zero-width inner nodes.
            let mut frontier = ins.to_vec();
            let mut acc: Vec<usize> = Vec::new();
            let mut count = 0u32;
            loop {
                if count >= *min {
                    acc.extend(frontier.iter().copied());
                }
                if let Some(m) = max {
                    if count >= *m {
                        break;
                    }
                }
                if frontier.is_empty() {
                    break;
                }
                let mut next = Vec::with_capacity(frontier.len() + 1);
                run_node(node, text, &frontier, &mut next);
                dedup(&mut next, text.len());
                next.retain(|p| !acc.contains(p));
                frontier = next;
                count += 1;
                if count > *min + text.len() as u32 + 2 {
                    break;
                }
            }
            out.extend(acc);
            dedup(out, text.len());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn path(s: &str) -> AsPath {
        AsPath::from_sequence(
            &s.split_whitespace()
                .map(|t| t.parse::<u32>().unwrap())
                .collect::<Vec<_>>(),
        )
    }

    #[test]
    fn doc_examples() {
        // FRR bgpd chapter examples, verbatim operators.
        let m99a = AsRegex::new("_23456_").unwrap();
        assert!(m99a.matches_path(&path("65001 23456 65002")));
        assert!(!m99a.matches_path(&path("65001 65002")));
        let m99b = AsRegex::new("^65").unwrap();
        assert!(m99b.matches_path(&path("65001 65002")));
        assert!(!m99b.matches_path(&path("23456 65001")));
        let m99c = AsRegex::new("_1310[0-6][0-9]_|_13107[0-1]_").unwrap();
        assert!(m99c.matches_path(&path("65000 131070 65001")));
        assert!(m99c.matches_path(&path("65000 131071")));
        assert!(!m99c.matches_path(&path("65000 131072")));
        assert!(!m99c.matches_path(&path("65000 131080")));
    }

    #[test]
    fn anchors() {
        let exact = AsRegex::new("^65001$").unwrap();
        assert!(exact.matches_path(&path("65001")));
        assert!(!exact.matches_path(&path("65001 65002")));
        assert!(!exact.matches_path(&path("65002 65001")));
        let tail = AsRegex::new("_65002$").unwrap();
        assert!(tail.matches_path(&path("65001 65002")));
        assert!(!tail.matches_path(&path("65002 65001")));
    }

    #[test]
    fn star_plus_question() {
        let any = AsRegex::new(".*").unwrap();
        assert!(any.matches_path(&path("1 2 3")));
        assert!(any.matches_path(&AsPath::default()));
        let opt = AsRegex::new("^6500[0-9]? 7$").unwrap();
        assert!(opt.matches_path(&path("6500 7")));
        assert!(opt.matches_path(&path("65001 7")));
        assert!(!opt.matches_path(&path("650011 7")));
        // `8+` alone cannot cross the separator between elements — a
        // repeated group containing the `_` boundary does.
        let plus = AsRegex::new("^7(_8)+$").unwrap();
        assert!(plus.matches_path(&path("7 8")));
        assert!(plus.matches_path(&path("7 8 8 8")));
        assert!(!plus.matches_path(&path("7")));
    }

    #[test]
    fn alternation_and_groups() {
        let alt = AsRegex::new("^(11|22) 33$").unwrap();
        assert!(alt.matches_path(&path("11 33")));
        assert!(alt.matches_path(&path("22 33")));
        assert!(!alt.matches_path(&path("12 33")));
        let rep_group = AsRegex::new("^(ab)+$").unwrap();
        assert!(rep_group.matches_str("ab"));
        assert!(rep_group.matches_str("ababab"));
        assert!(!rep_group.matches_str("aba"));
        assert!(!rep_group.matches_str(""));
    }

    #[test]
    fn bounded_repetition_braces() {
        let two = AsRegex::new("^7(_8){2}$").unwrap();
        assert!(!two.matches_path(&path("7 8")));
        assert!(two.matches_path(&path("7 8 8")));
        assert!(!two.matches_path(&path("7 8 8 8")));
        let range = AsRegex::new("^7(_8){1,2}$").unwrap();
        assert!(range.matches_path(&path("7 8")));
        assert!(range.matches_path(&path("7 8 8")));
        assert!(!range.matches_path(&path("7 8 8 8")));
        let open = AsRegex::new("^7(_8){2,}$").unwrap();
        assert!(!open.matches_path(&path("7 8")));
        assert!(open.matches_path(&path("7 8 8 8")));
        // Malformed braces fall back to a literal `{`.
        let lit = AsRegex::new("^7 8{x$").unwrap();
        assert!(lit.matches_str("7 8{x"));
    }

    #[test]
    fn boundary_atoms_with_sets() {
        // Path with an AS_SET renders as `{a,b}`; `_` must find it.
        let p = AsPath::from_segments(vec![
            crate::route::AsSegment::Sequence(vec![65001]),
            crate::route::AsSegment::Set(vec![65100, 65101]),
        ]);
        let m = AsRegex::new("_65100_").unwrap();
        assert!(m.matches_path(&p), "rendered: {}", p.render());
        let m2 = AsRegex::new("_65101}_").unwrap();
        assert!(m2.matches_path(&p), "boundary between `}}` and end");
        let m3 = AsRegex::new("_{65100").unwrap();
        assert!(m3.matches_path(&p), "boundary before `{{`");
    }

    #[test]
    fn partial_asn_is_not_a_member() {
        // `_0_` must not match inside `65000` — the FRR doc's own
        // example lists `_0_` (AS 0), and `_` requires a boundary.
        let m = AsRegex::new("_0_").unwrap();
        assert!(m.matches_path(&path("65001 0 65002")));
        assert!(!m.matches_path(&path("65001 65002")));
    }

    #[test]
    fn negated_class_and_escape() {
        let m = AsRegex::new("^65[^0-9]").unwrap();
        assert!(
            !m.matches_path(&path("65001 7")),
            "next char after 65 is 0, a digit"
        );
        // Backslash makes the next character a literal.
        let m2 = AsRegex::new(r"^6500\1$").unwrap();
        assert!(m2.matches_path(&path("65001")));
        let m3 = AsRegex::new(r"^6500\1 2$").unwrap();
        assert!(m3.matches_path(&path("65001 2")));
    }

    #[test]
    fn repeat_min_two_with_zero_width_inner() {
        // `a?` gives the repetition a zero-width branch; offsets must be
        // collected for every count >= min even when first reached at a
        // lower count (the visited-pruning hazard this loop avoids).
        let m = AsRegex::new("^(a?|b){2}$").unwrap();
        assert!(m.matches_str("ab"));
        assert!(m.matches_str("a"));
        assert!(m.matches_str("b"));
        assert!(m.matches_str(""));
        assert!(!m.matches_str("abb"), "two reps cover at most two chars");
    }

    #[test]
    fn parse_errors_carry_positions() {
        assert!(matches!(
            AsRegex::new("[0-9"),
            Err(AsRegexError::UnterminatedClass { pos: 0 })
        ));
        assert!(matches!(
            AsRegex::new("(65"),
            Err(AsRegexError::UnclosedGroup { pos: 0 })
        ));
        assert!(matches!(
            AsRegex::new("65)"),
            Err(AsRegexError::UnbalancedClose { pos: 2 })
        ));
        assert!(matches!(
            AsRegex::new("*65"),
            Err(AsRegexError::DanglingRepeat { op: '*', pos: 0 })
        ));
        assert!(matches!(
            AsRegex::new("6\\"),
            Err(AsRegexError::BadEscape { pos: 1 })
        ));
    }

    #[test]
    fn long_path_linear() {
        // Repetition over a long path terminates (fixpoint guard).
        let asns: Vec<u32> = (1..=80).collect();
        let long = AsPath::from_sequence(&asns);
        let m = AsRegex::new("^1(_[0-9]+)+$").unwrap();
        assert!(m.matches_path(&long));
        assert!(!m.matches_path(&AsPath::from_sequence(&[2, 3])));
    }
}
