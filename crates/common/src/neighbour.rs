//! Kernel neighbour (ARP/NDP) entries, as observed from the dataplane.
//!
//! Mirror vocabulary only: neighbours are read from the kernel, never
//! programmed by Rouster (tonight's stages model awareness, not control).
//! The state/flag bit values are the kernel UAPI `NUD_*`/`NTF_*` constants
//! (include/uapi/linux/neighbour.h — stable ABI), so the netlink backend
//! maps raw message fields straight into these types.

use std::fmt;
use std::net::IpAddr;

/// Neighbour cache entry state (`ndm_state`, `NUD_*`).
///
/// A bit field on the wire: combinations are legal (and kernel-internal
/// bits outside the exported set can appear), so bits are retained, never
/// truncated — the mirror keeps exactly what the kernel reported.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
pub struct NeighbourState(u16);

impl NeighbourState {
    /// Resolution started, no reply yet (no lladdr by definition).
    pub const INCOMPLETE: Self = Self(0x01);
    /// Recently confirmed reachable.
    pub const REACHABLE: Self = Self(0x02);
    /// Valid but unconfirmed; the kernel revalidates before use.
    pub const STALE: Self = Self(0x04);
    /// Revalidation deferred to a timer.
    pub const DELAY: Self = Self(0x08);
    /// Revalidation in progress.
    pub const PROBE: Self = Self(0x10);
    /// Resolution failed; entry is quarantined.
    pub const FAILED: Self = Self(0x20);
    /// No address resolution needed (e.g. point-to-point).
    pub const NOARP: Self = Self(0x40);
    /// Administratively installed (`ip neigh add ... nud permanent`).
    pub const PERMANENT: Self = Self(0x80);

    /// Retains every bit, unnamed ones included (mirror = observed state).
    pub const fn from_bits(bits: u16) -> Self {
        Self(bits)
    }

    pub const fn bits(self) -> u16 {
        self.0
    }

    /// True when every bit of `other` is set.
    pub const fn contains(self, other: Self) -> bool {
        self.0 & other.0 == other.0
    }

    /// True when any bit of `other` is set.
    pub const fn intersects(self, other: Self) -> bool {
        self.0 & other.0 != 0
    }

    /// Confirmed-good states: verified reachable, administratively pinned,
    /// or exempt from resolution. `STALE`/`DELAY`/`PROBE` deliberately do
    /// not qualify — they keep forwarding (see [`NeighbourEntry::is_up`])
    /// but are not confirmed.
    pub const fn is_reachable(self) -> bool {
        // Raw bits: the BitOr impl is not callable from a const fn.
        self.0 & (Self::REACHABLE.0 | Self::PERMANENT.0 | Self::NOARP.0) != 0
    }
}

impl std::ops::BitOr for NeighbourState {
    type Output = Self;
    fn bitor(self, rhs: Self) -> Self {
        Self(self.0 | rhs.0)
    }
}

impl std::ops::BitOrAssign for NeighbourState {
    fn bitor_assign(&mut self, rhs: Self) {
        self.0 |= rhs.0;
    }
}

impl fmt::Display for NeighbourState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        const NAMED: [(&str, NeighbourState); 8] = [
            ("INCOMPLETE", NeighbourState::INCOMPLETE),
            ("REACHABLE", NeighbourState::REACHABLE),
            ("STALE", NeighbourState::STALE),
            ("DELAY", NeighbourState::DELAY),
            ("PROBE", NeighbourState::PROBE),
            ("FAILED", NeighbourState::FAILED),
            ("NOARP", NeighbourState::NOARP),
            ("PERMANENT", NeighbourState::PERMANENT),
        ];
        let named_mask: u16 = NAMED.iter().map(|&(_, s)| s.0).fold(0, |a, b| a | b);
        let mut any = false;
        for (name, bit) in NAMED {
            if self.contains(bit) {
                if any {
                    f.write_str("|")?;
                }
                f.write_str(name)?;
                any = true;
            }
        }
        let rest = self.0 & !named_mask;
        if rest != 0 {
            if any {
                f.write_str("|")?;
            }
            write!(f, "0x{rest:x}")?;
            any = true;
        }
        if !any {
            f.write_str("NONE")?;
        }
        Ok(())
    }
}

/// Neighbour cache entry flags (`ndm_flags`, `NTF_*`).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
pub struct NeighbourFlags(u8);

impl NeighbourFlags {
    pub const USE: Self = Self(0x01);
    pub const SELF: Self = Self(0x02);
    /// Kernel name `NTF_MASTER`.
    pub const MASTER: Self = Self(0x04);
    pub const PROXY: Self = Self(0x08);
    /// Learned from an external controller (FDB).
    pub const EXT_LEARNED: Self = Self(0x10);
    pub const OFFLOADED: Self = Self(0x20);
    pub const STICKY: Self = Self(0x40);
    /// NDP: the neighbour is a router (sends RAs).
    pub const ROUTER: Self = Self(0x80);

    /// Retains every bit, unnamed ones included (mirror = observed state).
    pub const fn from_bits(bits: u8) -> Self {
        Self(bits)
    }

    pub const fn bits(self) -> u8 {
        self.0
    }

    /// True when every bit of `other` is set.
    pub const fn contains(self, other: Self) -> bool {
        self.0 & other.0 == other.0
    }

    /// True when any bit of `other` is set.
    pub const fn intersects(self, other: Self) -> bool {
        self.0 & other.0 != 0
    }
}

impl std::ops::BitOr for NeighbourFlags {
    type Output = Self;
    fn bitor(self, rhs: Self) -> Self {
        Self(self.0 | rhs.0)
    }
}

impl std::ops::BitOrAssign for NeighbourFlags {
    fn bitor_assign(&mut self, rhs: Self) {
        self.0 |= rhs.0;
    }
}

impl fmt::Display for NeighbourFlags {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        const NAMED: [(&str, NeighbourFlags); 8] = [
            ("USE", NeighbourFlags::USE),
            ("SELF", NeighbourFlags::SELF),
            ("MASTER", NeighbourFlags::MASTER),
            ("PROXY", NeighbourFlags::PROXY),
            ("EXT_LEARNED", NeighbourFlags::EXT_LEARNED),
            ("OFFLOADED", NeighbourFlags::OFFLOADED),
            ("STICKY", NeighbourFlags::STICKY),
            ("ROUTER", NeighbourFlags::ROUTER),
        ];
        let named_mask: u8 = NAMED.iter().map(|&(_, s)| s.0).fold(0, |a, b| a | b);
        let mut any = false;
        for (name, bit) in NAMED {
            if self.contains(bit) {
                if any {
                    f.write_str("|")?;
                }
                f.write_str(name)?;
                any = true;
            }
        }
        let rest = self.0 & !named_mask;
        if rest != 0 {
            if any {
                f.write_str("|")?;
            }
            write!(f, "0x{rest:x}")?;
            any = true;
        }
        if !any {
            f.write_str("NONE")?;
        }
        Ok(())
    }
}

/// One neighbour (ARP/NDP) entry observed on a link.
///
/// Keyed by (`ip`, `link_ifindex`) — the kernel's neighbour identity;
/// the same IP on two links is two entries.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NeighbourEntry {
    /// Destination IP of the entry (`NDA_DST`).
    pub ip: IpAddr,
    /// Interface the entry lives on (`ndm_ifindex`).
    pub link_ifindex: u32,
    /// Link-layer address (`NDA_LLADDR`; e.g. a 6-octet MAC for Ethernet).
    /// `None` while resolution is pending or failed. Raw bytes: the kernel
    /// does not promise a MAC length.
    pub lladdr: Option<Vec<u8>>,
    pub state: NeighbourState,
    pub flags: NeighbourFlags,
}

impl NeighbourEntry {
    /// Builds an entry from the raw rtnetlink fields of an RTM_NEWNEIGH
    /// message (header `ndm_state`/`ndm_flags`, `NDA_DST`/`NDA_LLADDR`
    /// attributes), as extracted by the netlink backend. Bits pass through
    /// unfiltered.
    pub fn from_rtnetlink(
        ip: IpAddr,
        link_ifindex: u32,
        lladdr: Option<Vec<u8>>,
        ndm_state: u16,
        ndm_flags: u8,
    ) -> Self {
        Self {
            ip,
            link_ifindex,
            lladdr,
            state: NeighbourState::from_bits(ndm_state),
            flags: NeighbourFlags::from_bits(ndm_flags),
        }
    }

    /// Good for forwarding now: the entry has a link-layer address and its
    /// state is not a failed or pending resolution. `STALE`/`DELAY`/`PROBE`
    /// qualify — the kernel keeps forwarding on them while revalidating.
    pub fn is_up(&self) -> bool {
        self.lladdr.is_some()
            && !self
                .state
                .intersects(NeighbourState::INCOMPLETE | NeighbourState::FAILED)
    }

    /// Link-layer address as colon-separated hex (`02:00:00:00:00:11`);
    /// `-` when absent.
    fn lladdr_hex(&self) -> String {
        match &self.lladdr {
            Some(bytes) => bytes
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect::<Vec<_>>()
                .join(":"),
            None => "-".to_string(),
        }
    }
}

impl fmt::Display for NeighbourEntry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} dev {} lladdr {} state {}",
            self.ip,
            self.link_ifindex,
            self.lladdr_hex(),
            self.state
        )?;
        if self.flags.bits() != 0 {
            write!(f, " flags {}", self.flags)?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    fn mac(last: u8) -> Option<Vec<u8>> {
        Some(vec![0x02, 0x00, 0x00, 0x00, 0x00, last])
    }

    /// `ip neigh add 192.0.2.11 dev eth0 lladdr 02:..:11 nud permanent`
    /// reports ndm_state = NUD_PERMANENT (0x80), no flags.
    #[test]
    fn maps_permanent_kernel_entry() {
        let e = NeighbourEntry::from_rtnetlink(ip("192.0.2.11"), 2, mac(0x11), 0x80, 0);
        assert_eq!(e.ip, ip("192.0.2.11"));
        assert_eq!(e.link_ifindex, 2);
        assert_eq!(e.state.bits(), 0x80);
        assert!(e.state.contains(NeighbourState::PERMANENT));
        assert!(e.state.is_reachable());
        assert!(e.is_up());
        assert_eq!(e.flags.bits(), 0);
    }

    /// An NDP router discovered by RA: NUD_REACHABLE (0x02) with
    /// NTF_ROUTER (0x80) set.
    #[test]
    fn maps_reachable_ndp_router_entry() {
        let e = NeighbourEntry::from_rtnetlink(
            ip("fe80::1"),
            3,
            Some(vec![0x33, 0x33, 0x00, 0x00, 0x00, 0x01]),
            0x02,
            0x80,
        );
        assert!(e.flags.contains(NeighbourFlags::ROUTER));
        assert!(e.state.is_reachable());
        assert!(e.is_up());
    }

    /// Pending and failed resolutions are not up; stale entries keep
    /// forwarding but are not confirmed.
    #[test]
    fn pending_and_failed_resolutions_are_not_up() {
        let incomplete = NeighbourEntry::from_rtnetlink(ip("192.0.2.99"), 2, None, 0x01, 0);
        assert!(!incomplete.is_up());
        assert!(!incomplete.state.is_reachable());

        // FAILED may still carry the last lladdr; it must not count as up.
        let failed = NeighbourEntry::from_rtnetlink(ip("192.0.2.98"), 2, mac(0x98), 0x20, 0);
        assert!(!failed.is_up());

        let stale = NeighbourEntry::from_rtnetlink(ip("192.0.2.97"), 2, mac(0x97), 0x04, 0);
        assert!(stale.is_up());
        assert!(!stale.state.is_reachable());
    }

    /// Bits round-trip unfiltered, including wire combinations and bits
    /// outside the exported set; Display names what it knows.
    #[test]
    fn state_and_flag_bits_roundtrip_unfiltered() {
        let s = NeighbourState::from_bits(0x02 | 0x80);
        assert_eq!(s.bits(), 0x82);
        assert!(s.contains(NeighbourState::REACHABLE));
        assert!(s.contains(NeighbourState::PERMANENT));
        assert_eq!(s.to_string(), "REACHABLE|PERMANENT");
        assert_eq!(NeighbourState::default().to_string(), "NONE");
        // A kernel-internal bit survives the mirror and shows as hex.
        let odd = NeighbourState::from_bits(0x0100 | 0x02);
        assert_eq!(odd.bits(), 0x0102);
        assert_eq!(odd.to_string(), "REACHABLE|0x100");

        let fl = NeighbourFlags::from_bits(0x80 | 0x01);
        assert_eq!(fl.bits(), 0x81);
        assert!(fl.contains(NeighbourFlags::ROUTER));
        assert!(fl.contains(NeighbourFlags::USE));
        assert_eq!(fl.to_string(), "USE|ROUTER");
        assert_eq!(NeighbourFlags::default().to_string(), "NONE");
    }

    /// The entry Display carries the identifying fields (ip, dev, lladdr,
    /// state, flags) — this is what the mirror log lines show.
    #[test]
    fn entry_display_carries_identifying_fields() {
        let full = NeighbourEntry::from_rtnetlink(ip("192.0.2.11"), 2, mac(0x11), 0x80, 0x80);
        assert_eq!(
            full.to_string(),
            "192.0.2.11 dev 2 lladdr 02:00:00:00:00:11 state PERMANENT flags ROUTER"
        );
        let bare = NeighbourEntry::from_rtnetlink(ip("192.0.2.12"), 2, None, 0x01, 0);
        assert_eq!(
            bare.to_string(),
            "192.0.2.12 dev 2 lladdr - state INCOMPLETE"
        );
        let v6 = NeighbourEntry::from_rtnetlink(
            ip("fe80::1"),
            3,
            Some(vec![0x33, 0x33, 0x00, 0x00, 0x00, 0x01]),
            0x02,
            0,
        );
        assert_eq!(
            v6.to_string(),
            "fe80::1 dev 3 lladdr 33:33:00:00:00:01 state REACHABLE"
        );
    }
}
