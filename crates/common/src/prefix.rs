//! IP prefix types (IPv4/IPv6), validated at construction.

use std::fmt;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::str::FromStr;

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum PrefixError {
    #[error("prefix length {len} exceeds {max} for this address family")]
    LengthTooLong { len: u8, max: u8 },
    #[error("invalid prefix syntax: {0}")]
    Syntax(String),
}

macro_rules! impl_prefix {
    ($t:ident, $addr:ty, $max:expr) => {
        impl $t {
            /// Creates a prefix, validating the prefix length.
            pub fn new(addr: $addr, len: u8) -> Result<Self, PrefixError> {
                if len > $max {
                    return Err(PrefixError::LengthTooLong { len, max: $max });
                }
                Ok(Self { addr, len })
            }

            pub fn addr(&self) -> $addr {
                self.addr
            }

            pub fn prefix_len(&self) -> u8 {
                self.len
            }

            /// True if `addr` falls inside this prefix.
            pub fn contains(&self, addr: $addr) -> bool {
                let plen = self.len as usize;
                let a = addr.octets();
                let p = self.addr.octets();
                for i in 0..plen / 8 {
                    if a[i] != p[i] {
                        return false;
                    }
                }
                let rem = plen % 8;
                if rem == 0 {
                    return true;
                }
                let mask = 0xffu8 << (8 - rem);
                (a[plen / 8] & mask) == (p[plen / 8] & mask)
            }
        }

        impl fmt::Display for $t {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, "{}/{}", self.addr, self.len)
            }
        }

        impl FromStr for $t {
            type Err = PrefixError;

            fn from_str(s: &str) -> Result<Self, Self::Err> {
                let (addr, len) = s
                    .split_once('/')
                    .ok_or_else(|| PrefixError::Syntax(s.to_string()))?;
                let addr = addr
                    .parse::<$addr>()
                    .map_err(|_| PrefixError::Syntax(s.to_string()))?;
                let len = len
                    .parse::<u8>()
                    .map_err(|_| PrefixError::Syntax(s.to_string()))?;
                Self::new(addr, len)
            }
        }
    };
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Ipv4Prefix {
    addr: Ipv4Addr,
    len: u8,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Ipv6Prefix {
    addr: Ipv6Addr,
    len: u8,
}

impl_prefix!(Ipv4Prefix, Ipv4Addr, 32);
impl_prefix!(Ipv6Prefix, Ipv6Addr, 128);

/// Address-family-generic prefix.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum IpPrefix {
    V4(Ipv4Prefix),
    V6(Ipv6Prefix),
}

impl fmt::Display for IpPrefix {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            IpPrefix::V4(p) => p.fmt(f),
            IpPrefix::V6(p) => p.fmt(f),
        }
    }
}

impl FromStr for IpPrefix {
    type Err = PrefixError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if let Ok(p) = s.parse::<Ipv4Prefix>() {
            return Ok(IpPrefix::V4(p));
        }
        if let Ok(p) = s.parse::<Ipv6Prefix>() {
            return Ok(IpPrefix::V6(p));
        }
        Err(PrefixError::Syntax(s.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_and_contains_v4() {
        let p: Ipv4Prefix = "192.0.2.0/24".parse().unwrap();
        assert!(p.contains("192.0.2.7".parse().unwrap()));
        assert!(!p.contains("192.0.3.1".parse().unwrap()));
    }

    #[test]
    fn rejects_overlong_prefix() {
        assert!("10.0.0.0/33".parse::<Ipv4Prefix>().is_err());
        assert!("2001:db8::/129".parse::<Ipv6Prefix>().is_err());
    }

    #[test]
    fn parse_generic() {
        assert!(matches!(
            "2001:db8::/32".parse::<IpPrefix>().unwrap(),
            IpPrefix::V6(_)
        ));
        assert!(matches!(
            "10.0.0.0/8".parse::<IpPrefix>().unwrap(),
            IpPrefix::V4(_)
        ));
    }
}
