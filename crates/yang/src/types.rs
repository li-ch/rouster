//! The type subset — RFC 7950 §7.4 ("type"), §9.2 integer types,
//! §9.4 string, §9.5 boolean, §9.6 enumeration, §9.12 union; the
//! derived inet types of RFC 6991 §3.2 (ietf-inet-types); the
//! `pattern` restriction (§9.4.5) and `range` (§9.2.4) and `length`
//! (§9.4.4) facets; typedef derivation (§7.3, default §7.3.4).
//!
//! Every type is validated by hand — no regex crate, no parse crate
//! (the no-new-deps fence; §Deferred in the crate docs records what
//! that costs). [`Type::check`] validates a lexical value and
//! returns its canonical form (§9.2.2 canonical integer form: no
//! `+`, no leading zeros — applied to every integer type).
//!
//! The built-in types (§9's table):
//!
//! - `int8..int64`/`uint8..uint64` — §9.2. Lexical form (§9.2.1):
//!   an optional sign then decimal digits. `range` (§9.2.4) with
//!   `min`/`max` keywords and `|`-joined intervals is parsed and
//!   enforced.
//! - `string` — §9.4. `length` (§9.4.4) and `pattern` (§9.4.5)
//!   enforced; multiple patterns AND together (§9.4.5: "all
//!   patterns").
//! - `boolean` — §9.5, lexical `true`/`false` only.
//! - `enumeration` — §9.6, `enum` sub-statements with unique names
//!   (§9.6.4); `value` statements (§9.6.4.2) are parsed and
//!   recorded but not enforced (nothing in the subset reads integer
//!   enum values back — §Deferred).
//! - `union` — §9.12: a member type matches if any alternative
//!   validates; the FIRST matching alternative's canonical form
//!   wins (§9.12's "the value must match at least one member type").
//! - `empty` — §9.11: implemented because the daemon grammars have
//!   valueless presence knobs (`redistribute static` rides an enum
//!   instead, but `multihop`-style shorthand keys evaluate through
//!   boolean; `empty` exists for completeness of the line-binding
//!   layer). Its one lexical value is the empty string.
//!
//! The inet types (RFC 6991 §3.2's typedefs, re-derived here as
//! built-ins so the models can say `type inet:ipv4-address`):
//! `ipv4-address`, `ipv6-address`, `ip-address`, `ipv4-prefix`,
//! `ipv6-prefix`, `ip-prefix`. Validation is by std
//! `Ipv4Addr`/`Ipv6Addr`/`IpPrefix`-shaped parsing, which matches
//! RFC 6991's patterns (no leading zeros in either the dotted-quad
//! or the length field) and is stricter about nothing else.

use std::collections::BTreeSet;
use std::net::{Ipv4Addr, Ipv6Addr};

use crate::regex::Regex;

/// A resolved (post-typedef) type.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Type {
    Int(IntKind, Vec<(i128, i128)>),
    /// string with length bounds (§9.4.4) and patterns (§9.4.5).
    Str {
        lengths: Vec<(usize, usize)>,
        patterns: Vec<Regex>,
    },
    Boolean,
    Enum(BTreeSet<String>),
    Union(Vec<Type>),
    /// §9.11 `empty` — presence without a value.
    Empty,
    /// RFC 6991 §3.2 derived types, re-derived as built-ins.
    Inet(InetType),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IntKind {
    Int8,
    Int16,
    Int32,
    Int64,
    Uint8,
    Uint16,
    Uint32,
    Uint64,
}

impl IntKind {
    pub fn bounds(self) -> (i128, i128) {
        match self {
            IntKind::Int8 => (i8::MIN as i128, i8::MAX as i128),
            IntKind::Int16 => (i16::MIN as i128, i16::MAX as i128),
            IntKind::Int32 => (i32::MIN as i128, i32::MAX as i128),
            IntKind::Int64 => (i64::MIN as i128, i64::MAX as i128),
            IntKind::Uint8 => (0, u8::MAX as i128),
            IntKind::Uint16 => (0, u16::MAX as i128),
            IntKind::Uint32 => (0, u32::MAX as i128),
            IntKind::Uint64 => (0, u64::MAX as i128),
        }
    }

    pub fn name(self) -> &'static str {
        match self {
            IntKind::Int8 => "int8",
            IntKind::Int16 => "int16",
            IntKind::Int32 => "int32",
            IntKind::Int64 => "int64",
            IntKind::Uint8 => "uint8",
            IntKind::Uint16 => "uint16",
            IntKind::Uint32 => "uint32",
            IntKind::Uint64 => "uint64",
        }
    }

    pub(crate) fn from_name(name: &str) -> Option<Self> {
        Some(match name {
            "int8" => IntKind::Int8,
            "int16" => IntKind::Int16,
            "int32" => IntKind::Int32,
            "int64" => IntKind::Int64,
            "uint8" => IntKind::Uint8,
            "uint16" => IntKind::Uint16,
            "uint32" => IntKind::Uint32,
            "uint64" => IntKind::Uint64,
            _ => return None,
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InetType {
    Ipv4Address,
    Ipv6Address,
    IpAddress,
    Ipv4Prefix,
    Ipv6Prefix,
    IpPrefix,
}

impl InetType {
    pub fn name(self) -> &'static str {
        match self {
            InetType::Ipv4Address => "ipv4-address",
            InetType::Ipv6Address => "ipv6-address",
            InetType::IpAddress => "ip-address",
            InetType::Ipv4Prefix => "ipv4-prefix",
            InetType::Ipv6Prefix => "ipv6-prefix",
            InetType::IpPrefix => "ip-prefix",
        }
    }

    pub(crate) fn from_name(name: &str) -> Option<Self> {
        Some(match name {
            "ipv4-address" => InetType::Ipv4Address,
            "ipv6-address" => InetType::Ipv6Address,
            "ip-address" => InetType::IpAddress,
            "ipv4-prefix" => InetType::Ipv4Prefix,
            "ipv6-prefix" => InetType::Ipv6Prefix,
            "ip-prefix" => InetType::IpPrefix,
            _ => return None,
        })
    }
}

/// Parses a base-type name into a [`Type`]; `None` = not a built-in
/// (a typedef reference — the schema layer resolves those).
pub fn builtin(name: &str) -> Option<Type> {
    if let Some(kind) = IntKind::from_name(name) {
        return Some(Type::Int(kind, Vec::new()));
    }
    // NOTE: the inet types are NOT bare builtins — they are only
    // reachable through the `inet:` qualified prefix (RFC 6991
    // §3.2's ietf-inet-types module, re-derived in `types.rs`).
    match name {
        "string" => Some(Type::Str {
            lengths: Vec::new(),
            patterns: Vec::new(),
        }),
        "boolean" => Some(Type::Boolean),
        "enumeration" => Some(Type::Enum(BTreeSet::new())),
        "union" => Some(Type::Union(Vec::new())),
        "empty" => Some(Type::Empty),
        _ => None,
    }
}

impl Type {
    /// Validates a lexical value against this type; returns the
    /// canonical form on success (§9.2.2 for integers, the lexical
    /// value itself for everything else).
    pub fn check(&self, value: &str) -> Result<String, String> {
        match self {
            Type::Int(kind, ranges) => {
                let n = parse_int_lexical(value, *kind)?;
                in_ranges(*kind, ranges, n, value)?;
                Ok(n.to_string())
            }
            Type::Str { lengths, patterns } => {
                for (lo, hi) in lengths {
                    let len = value.chars().count();
                    if len < *lo || len > *hi {
                        return Err(format!(
                            "length {} outside {}..{} (RFC 7950 §9.4.4)",
                            len, lo, hi
                        ));
                    }
                }
                for pattern in patterns {
                    if !pattern.is_match(value) {
                        return Err(format!(
                            "value `{value}` fails pattern `{}` (RFC 7950 §9.4.5)",
                            pattern.source()
                        ));
                    }
                }
                Ok(value.to_string())
            }
            Type::Boolean => match value {
                "true" | "false" => Ok(value.to_string()),
                _ => Err(format!("`{value}` is not true|false (RFC 7950 §9.5)")),
            },
            Type::Enum(variants) => {
                if variants.contains(value) {
                    Ok(value.to_string())
                } else {
                    Err(format!(
                        "`{value}` is not one of the enumeration's names (RFC 7950 §9.6): {}",
                        variants.iter().cloned().collect::<Vec<_>>().join("|")
                    ))
                }
            }
            Type::Union(alts) => {
                // §9.12: valid if any member type validates; the
                // first match's canonical form wins.
                let mut last = String::new();
                for alt in alts {
                    match alt.check(value) {
                        Ok(canon) => return Ok(canon),
                        Err(err) => last = err,
                    }
                }
                Err(format!(
                    "`{value}` matches no union member (RFC 7950 §9.12): {last}"
                ))
            }
            Type::Empty => {
                if value.is_empty() {
                    Ok(String::new())
                } else {
                    Err("type empty takes no value (RFC 7950 §9.11)".to_string())
                }
            }
            Type::Inet(inet) => check_inet(*inet, value),
        }
    }

    /// A human-readable type name for error messages.
    pub fn describe(&self) -> String {
        match self {
            Type::Int(kind, ranges) if ranges.is_empty() => kind.name().to_string(),
            Type::Int(kind, _) => {
                format!("{} (ranged)", kind.name())
            }
            Type::Str { .. } => "string".to_string(),
            Type::Boolean => "boolean".to_string(),
            Type::Enum(variants) => format!(
                "enumeration({})",
                variants.iter().cloned().collect::<Vec<_>>().join("|")
            ),
            Type::Union(_) => "union".to_string(),
            Type::Empty => "empty".to_string(),
            Type::Inet(inet) => format!("inet:{}", inet.name()),
        }
    }
}

/// Integer lexical form (§9.2.1): optional sign, then decimal
/// digits. Leading zeros and `+` are accepted lexically and
/// canonicalized away by [`Type::check`].
fn parse_int_lexical(value: &str, kind: IntKind) -> Result<i128, String> {
    let body = value
        .strip_prefix('-')
        .or_else(|| value.strip_prefix('+'))
        .unwrap_or(value);
    if body.is_empty() || !body.bytes().all(|b| b.is_ascii_digit()) {
        return Err(format!(
            "`{value}` is not an integer (RFC 7950 §9.2.1 lexical form)"
        ));
    }
    let n: i128 = value
        .parse()
        .map_err(|_| format!("`{value}` overflows the lexical integer range"))?;
    let (lo, hi) = kind.bounds();
    if n < lo || n > hi {
        return Err(format!(
            "`{value}` outside {} range {}..{} (RFC 7950 §9.2)",
            kind.name(),
            lo,
            hi
        ));
    }
    Ok(n)
}

/// `range` enforcement (§9.2.4): the value must fall in one of the
/// `|`-separated intervals parsed by the schema layer.
fn in_ranges(kind: IntKind, ranges: &[(i128, i128)], n: i128, value: &str) -> Result<(), String> {
    if ranges.is_empty() || ranges.iter().any(|&(lo, hi)| n >= lo && n <= hi) {
        return Ok(());
    }
    let shape = ranges
        .iter()
        .map(|&(lo, hi)| format!("{lo}..{hi}"))
        .collect::<Vec<_>>()
        .join("|");
    let _ = kind;
    Err(format!("`{value}` outside range {shape} (RFC 7950 §9.2.4)"))
}

/// The inet types (RFC 6991 §3.2): strict dotted-quad / IPv6
/// parsing via std, prefixes as `addr/len` with the length bounded
/// by the family. Leading zeros are rejected in octets (std's rule
/// since 2021, matching RFC 6991's patterns, which never allowed
/// them); the IPv6 zone-id suffix RFC 6991 permits
/// (`%zone`) is NOT implemented (§Deferred).
fn check_inet(inet: InetType, value: &str) -> Result<String, String> {
    let cite = "RFC 6991 §3.2";
    let canon = match inet {
        InetType::Ipv4Address => {
            let addr: Ipv4Addr = value
                .parse()
                .map_err(|_| format!("`{value}` is not an IPv4 address ({cite})"))?;
            addr.to_string()
        }
        InetType::Ipv6Address => {
            let addr: Ipv6Addr = value
                .parse()
                .map_err(|_| format!("`{value}` is not an IPv6 address ({cite})"))?;
            addr.to_string()
        }
        InetType::IpAddress => {
            let addr: std::net::IpAddr = value
                .parse()
                .map_err(|_| format!("`{value}` is not an IP address ({cite})"))?;
            addr.to_string()
        }
        InetType::Ipv4Prefix | InetType::Ipv6Prefix | InetType::IpPrefix => {
            let (addr, len) = value
                .split_once('/')
                .ok_or_else(|| format!("`{value}` has no /length ({cite})"))?;
            let len: u8 = len
                .parse()
                .map_err(|_| format!("`{value}` has a non-numeric length ({cite})"))?;
            let max = match inet {
                InetType::Ipv4Prefix => {
                    let a: Ipv4Addr = addr
                        .parse()
                        .map_err(|_| format!("`{value}` is not an IPv4 prefix ({cite})"))?;
                    let _ = a;
                    32u8
                }
                InetType::Ipv6Prefix => {
                    let a: Ipv6Addr = addr
                        .parse()
                        .map_err(|_| format!("`{value}` is not an IPv6 prefix ({cite})"))?;
                    let _ = a;
                    128
                }
                _ => {
                    let a: std::net::IpAddr = addr
                        .parse()
                        .map_err(|_| format!("`{value}` is not an IP prefix ({cite})"))?;
                    if a.is_ipv4() {
                        32
                    } else {
                        128
                    }
                }
            };
            if len > max {
                return Err(format!(
                    "prefix length /{len} exceeds the family maximum /{max} ({cite})"
                ));
            }
            format!("{addr}/{len}")
        }
    };
    Ok(canon)
}

/// Parses a `range` argument (§9.2.4): `lo..hi | lo..hi`, with
/// `min`/`max` keywords standing for the type's bounds.
pub fn parse_range(arg: &str, kind: IntKind) -> Result<Vec<(i128, i128)>, String> {
    let (base_lo, base_hi) = kind.bounds();
    let mut out = Vec::new();
    for part in arg.split('|') {
        let part = part.trim();
        let (lo, hi) = match part.split_once("..") {
            Some((lo, hi)) => (bound(lo, base_lo)?, bound(hi, base_hi)?),
            None => {
                let v = bound(part, base_lo)?;
                (v, v)
            }
        };
        if lo > hi {
            return Err(format!("range part `{part}` has lo > hi (§9.2.4)"));
        }
        if let Some((_, prev_hi)) = out.last() {
            if lo <= *prev_hi {
                return Err(format!(
                    "range `{arg}` is not ascending and disjoint (§9.2.4)"
                ));
            }
        }
        out.push((lo, hi));
    }
    Ok(out)
}

fn bound(token: &str, default: i128) -> Result<i128, String> {
    match token.trim() {
        "min" => Ok(default),
        "max" => Ok(i128::MAX),
        other => other
            .parse()
            .map_err(|_| format!("bad range bound `{other}` (§9.2.4)")),
    }
}

/// Parses a `length` argument (§9.4.4): `lo..hi | lo..hi`.
pub fn parse_length(arg: &str) -> Result<Vec<(usize, usize)>, String> {
    let mut out = Vec::new();
    for part in arg.split('|') {
        let part = part.trim();
        let (lo, hi) = match part.split_once("..") {
            Some((lo, hi)) => (
                lo.trim()
                    .parse()
                    .map_err(|_| format!("bad length bound `{lo}` (§9.4.4)"))?,
                hi.trim()
                    .parse()
                    .map_err(|_| format!("bad length bound `{hi}` (§9.4.4)"))?,
            ),
            None => {
                let v: usize = part
                    .parse()
                    .map_err(|_| format!("bad length `{part}` (§9.4.4)"))?;
                (v, v)
            }
        };
        if lo > hi {
            return Err(format!("length part `{part}` has lo > hi (§9.4.4)"));
        }
        out.push((lo, hi));
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn enum_type(names: &[&str]) -> Type {
        Type::Enum(names.iter().map(|s| s.to_string()).collect())
    }

    #[test]
    fn integers_validate_and_canonicalize() {
        let t = Type::Int(IntKind::Uint8, Vec::new());
        assert_eq!(t.check("42").unwrap(), "42");
        // §9.2.1 lexical: sign allowed; §9.2.2 canonical: gone.
        assert_eq!(t.check("+7").unwrap(), "7");
        assert_eq!(t.check("007").unwrap(), "7");
        assert!(t.check("-1").is_err()); // outside uint8
        assert!(t.check("256").is_err());
        assert!(t.check("1x").is_err());
        assert!(t.check("").is_err());
        let i8t = Type::Int(IntKind::Int8, Vec::new());
        assert_eq!(i8t.check("-128").unwrap(), "-128");
        assert!(i8t.check("-129").is_err());
    }

    #[test]
    fn range_facet_enforces_disjoint_ascending_intervals() {
        let t = Type::Int(
            IntKind::Uint16,
            parse_range("100..200 | 300..max", IntKind::Uint16).unwrap(),
        );
        assert_eq!(t.check("150").unwrap(), "150");
        assert_eq!(t.check("300").unwrap(), "300");
        assert!(t.check("250").is_err());
        assert!(t.check("99").is_err());
        // Malformed ranges refuse to parse (§9.2.4's constraints).
        assert!(parse_range("200..100", IntKind::Uint8).is_err());
        assert!(parse_range("1..2 | 2..3", IntKind::Uint8).is_err());
        assert!(parse_range("min..max", IntKind::Uint8).is_ok());
    }

    #[test]
    fn string_length_and_pattern_facets() {
        let t = Type::Str {
            lengths: parse_length("1..5").unwrap(),
            patterns: vec![Regex::new("[a-z]+").unwrap()],
        };
        assert_eq!(t.check("abc").unwrap(), "abc");
        assert!(t.check("abcdef").is_err()); // length
        assert!(t.check("ABC").is_err()); // pattern
        assert!(t.check("").is_err());
    }

    #[test]
    fn boolean_is_true_or_false_only() {
        let t = Type::Boolean;
        assert_eq!(t.check("true").unwrap(), "true");
        assert_eq!(t.check("false").unwrap(), "false");
        assert!(t.check("True").is_err());
        assert!(t.check("yes").is_err());
        assert!(t.check("1").is_err());
    }

    #[test]
    fn enumeration_matches_declared_names() {
        let t = enum_type(&["strict", "loose", "fp", "efp", "barsav"]);
        assert_eq!(t.check("strict").unwrap(), "strict");
        let err = t.check("nosuch").unwrap_err();
        assert!(err.contains("strict") && err.contains("loose"), "{err}");
    }

    #[test]
    fn union_takes_first_matching_member() {
        let t = Type::Union(vec![
            Type::Inet(InetType::Ipv4Address),
            enum_type(&["blackhole"]),
        ]);
        assert_eq!(t.check("192.0.2.1").unwrap(), "192.0.2.1");
        assert_eq!(t.check("blackhole").unwrap(), "blackhole");
        assert!(t.check("2001:db8::1").is_err());
        assert!(t.check("grayhole").is_err());
    }

    #[test]
    fn inet_types_reject_leading_zeros_and_bad_lengths() {
        assert_eq!(
            Type::Inet(InetType::Ipv4Address)
                .check("192.0.2.1")
                .unwrap(),
            "192.0.2.1"
        );
        assert!(Type::Inet(InetType::Ipv4Address)
            .check("192.000.2.1")
            .is_err());
        assert_eq!(
            Type::Inet(InetType::Ipv6Address)
                .check("2001:db8::1")
                .unwrap(),
            "2001:db8::1"
        );
        assert!(Type::Inet(InetType::IpPrefix).check("192.0.2.0/24").is_ok());
        assert!(Type::Inet(InetType::IpPrefix)
            .check("192.0.2.0/33")
            .is_err());
        assert!(Type::Inet(InetType::IpPrefix)
            .check("2001:db8::/129")
            .is_err());
        assert!(Type::Inet(InetType::IpPrefix).check("192.0.2.0").is_err());
        // ip-prefix accepts either family; v4 rejects v6 lengths.
        assert!(Type::Inet(InetType::Ipv4Prefix).check("10.0.0.0/8").is_ok());
        assert!(Type::Inet(InetType::Ipv4Prefix)
            .check("10.0.0.0/64")
            .is_err());
    }

    #[test]
    fn empty_takes_no_value() {
        assert_eq!(Type::Empty.check("").unwrap(), "");
        assert!(Type::Empty.check("x").is_err());
    }

    #[test]
    fn builtin_names_resolve() {
        assert!(builtin("string").is_some());
        assert!(builtin("decimal64").is_none()); // not in the subset
        assert!(builtin("ipv4-address").is_none()); // inet:-qualified only
        assert!(matches!(builtin("boolean"), Some(Type::Boolean)));
    }
}
