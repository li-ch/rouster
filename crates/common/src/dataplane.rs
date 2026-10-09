//! The dataplane abstraction.
//!
//! Everything that programs or observes the forwarding plane goes through this
//! trait: netlink (today), FPM/eBPF (later). No component outside the
//! dataplane crate(s) may talk to the kernel directly.

use std::fmt;
use std::future::Future;
use std::net::IpAddr;

use crate::neighbour::NeighbourEntry;
use crate::prefix::IpPrefix;
use crate::route::{RouteEntry, RouteProtocol, TableId};

/// Error type for dataplane operations.
#[derive(Debug, thiserror::Error)]
pub enum DataplaneError {
    #[error("dataplane I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("dataplane operation not supported: {0}")]
    Unsupported(&'static str),
    #[error("dataplane error: {0}")]
    Other(String),
}

/// Events observed from the forwarding plane (link, address, and route
/// changes).
///
/// The RIB consumes these for nexthop resolution, interface tracking, and
/// (for the route events) the kernel FIB mirror.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DataplaneEvent {
    LinkNew {
        ifindex: u32,
        name: String,
        is_up: bool,
        /// Routing table bound to the link when it is a VRF device (link
        /// kind "vrf", `IFLA_VRF_TABLE`); `None` for every other link kind.
        vrf_table: Option<TableId>,
        /// Ifindex of the master device the link is enslaved to via
        /// `IFLA_MASTER` (a VRF device in the VRF case; bridges and bonds
        /// use the same attribute); `None` when unenslaved.
        master_ifindex: Option<u32>,
    },
    LinkDel {
        ifindex: u32,
    },
    /// An address was configured on an interface (host prefix, e.g.
    /// 10.0.0.1/24 on eth0).
    AddressNew {
        ifindex: u32,
        prefix: IpPrefix,
    },
    AddressDel {
        ifindex: u32,
        prefix: IpPrefix,
    },
    /// A kernel-origin route was observed in the forwarding plane (mirror
    /// direction: routes we did NOT program ourselves; see
    /// [`RouteProtocol::is_kernel_origin`]).
    RouteNew {
        table: TableId,
        prefix: IpPrefix,
        protocol: RouteProtocol,
        metric: u32,
    },
    /// A route left the forwarding plane. Unlike [`DataplaneEvent::RouteNew`]
    /// this is not filtered by origin: whoever deleted it, the kernel no
    /// longer has it, and the RIB must drop its programmed-set belief so a
    /// still-desired route is reinstalled.
    RouteDel {
        table: TableId,
        prefix: IpPrefix,
    },
    /// A neighbour (ARP/NDP) entry was observed in the forwarding plane.
    /// Mirror direction only: neighbours are never programmed by Rouster
    /// (read-only awareness). Replacements arrive as `NeighbourNew` for an
    /// existing (ip, link) key.
    NeighbourNew {
        entry: NeighbourEntry,
    },
    /// A neighbour entry left the forwarding plane (RTM_DELNEIGH).
    NeighbourDel {
        ip: IpAddr,
        link_ifindex: u32,
    },
}

impl fmt::Display for DataplaneEvent {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DataplaneEvent::LinkNew {
                ifindex,
                name,
                is_up,
                vrf_table,
                master_ifindex,
            } => {
                write!(
                    f,
                    "link new: {name} (ifindex {ifindex}, {}",
                    if *is_up { "up" } else { "down" }
                )?;
                if let Some(table) = vrf_table {
                    write!(f, ", vrf table {table}")?;
                }
                if let Some(master) = master_ifindex {
                    write!(f, ", master ifindex {master}")?;
                }
                write!(f, ")")
            }
            DataplaneEvent::LinkDel { ifindex } => write!(f, "link del: ifindex {ifindex}"),
            DataplaneEvent::AddressNew { ifindex, prefix } => {
                write!(f, "addr new: {prefix} on ifindex {ifindex}")
            }
            DataplaneEvent::AddressDel { ifindex, prefix } => {
                write!(f, "addr del: {prefix} on ifindex {ifindex}")
            }
            DataplaneEvent::RouteNew {
                table,
                prefix,
                protocol,
                metric,
            } => write!(
                f,
                "route new: {prefix} table {table} proto {protocol:?} metric {metric}"
            ),
            DataplaneEvent::RouteDel { table, prefix } => {
                write!(f, "route del: {prefix} table {table}")
            }
            DataplaneEvent::NeighbourNew { entry } => {
                write!(f, "neighbour new: {entry}")
            }
            DataplaneEvent::NeighbourDel { ip, link_ifindex } => {
                write!(f, "neighbour del: {ip} dev {link_ifindex}")
            }
        }
    }
}

/// What the dataplane does with traffic an installed SAV rule judges
/// invalid (GSC §4's traffic-handling policies, the two Rouster's first
/// milestone needs). The `sav` crate's action enum converts into this
/// one — the trait cannot see the `sav` crate's types (the dependency
/// points the other way), so the program carries this backend-neutral
/// form. Monitor is the default: count/log, never drop.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum SavEnforce {
    /// Log/count only (the workspace SAVNET rule: enforcement defaults
    /// to log/monitor before drop).
    #[default]
    Monitor,
    /// Drop non-conforming traffic.
    Drop,
}

impl fmt::Display for SavEnforce {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            SavEnforce::Monitor => "monitor",
            SavEnforce::Drop => "drop",
        })
    }
}

/// Which uRPF semantics an interface allowlist was generated with
/// (RFC 3704 §2.2 strict vs §2.5 loose — the `sav` crate's `UrpfMode`).
///
/// A backend that approximates interface allowlists with the kernel's
/// own FIB uRPF (`rp_filter`) needs this hint: strict maps to mode 1,
/// loose/FP/EFP to mode 2 (FP unions and default-encompassing EFP are
/// route-existence semantics, not egress-membership). Backends with real
/// per-prefix rules (an nftables `fib` ruleset) ignore it — they enforce
/// the allowlist content itself.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum SavUrpf {
    /// Strict: the arrival interface must be the source's egress.
    Strict,
    /// Loose/FP/EFP: any route to the source suffices.
    Loose,
}

impl fmt::Display for SavUrpf {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            SavUrpf::Strict => "strict",
            SavUrpf::Loose => "loose",
        })
    }
}

/// One backend-neutral SAV enforcement instruction — the dataplane
/// mirror of the `sav` crate's compiled op. All four cells of GSC §3
/// Figure 1's rule taxonomy: interface-scale prefix sets and
/// router-scale interface sets, allow and block polarity.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum SavProgramOp {
    /// IBA (GSC §2.1): a packet arriving on `ifindex` is valid iff its
    /// source is inside some prefix of `prefixes` (empty set denies all).
    IfaceAllow {
        ifindex: u32,
        prefixes: Vec<IpPrefix>,
        /// Generator semantics hint for FIB-uRPF-capable backends.
        urpf: SavUrpf,
        action: SavEnforce,
    },
    /// IBB (GSC §2.2): a packet arriving on `ifindex` with a source
    /// inside some prefix of `prefixes` is invalid.
    IfaceBlock {
        ifindex: u32,
        prefixes: Vec<IpPrefix>,
        action: SavEnforce,
    },
    /// PBA (GSC §2.3): sources inside `prefix` are valid iff they arrive
    /// on one of `ifindexes`.
    PrefixAllow {
        prefix: IpPrefix,
        ifindexes: Vec<u32>,
        action: SavEnforce,
    },
    /// PBB (GSC §2.4): sources inside `prefix` are invalid iff they
    /// arrive on one of `ifindexes`.
    PrefixBlock {
        prefix: IpPrefix,
        ifindexes: Vec<u32>,
        action: SavEnforce,
    },
}

impl fmt::Display for SavProgramOp {
    /// Operator-facing one-liner (the daemon's rule logs): mode, scale,
    /// interface/prefix set, action — e.g.
    /// `allow if#2 [198.51.100.0/24] strict monitor`.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let join = |items: &[String]| items.join(", ");
        match self {
            SavProgramOp::IfaceAllow {
                ifindex,
                prefixes,
                urpf,
                action,
            } => {
                let p: Vec<String> = prefixes.iter().map(|p| p.to_string()).collect();
                write!(f, "allow if#{ifindex} [{}] {urpf} {action}", join(&p))
            }
            SavProgramOp::IfaceBlock {
                ifindex,
                prefixes,
                action,
            } => {
                let p: Vec<String> = prefixes.iter().map(|p| p.to_string()).collect();
                write!(f, "block if#{ifindex} [{}] {action}", join(&p))
            }
            SavProgramOp::PrefixAllow {
                prefix,
                ifindexes,
                action,
            } => write!(f, "allow {prefix} if {ifindexes:?} {action}"),
            SavProgramOp::PrefixBlock {
                prefix,
                ifindexes,
                action,
            } => write!(f, "block {prefix} if {ifindexes:?} {action}"),
        }
    }
}

/// A compiled SAV program to install in the dataplane, normalized to a
/// deterministic order (sorted, deduplicated) so the same op set always
/// yields a byte-identical program.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SavProgram {
    ops: Vec<SavProgramOp>,
}

impl SavProgram {
    /// An empty program (installs nothing).
    pub fn new() -> Self {
        Self::default()
    }

    /// Build from ops, normalizing to the canonical sorted/deduplicated
    /// order. Order- and duplicate-invariant: any permutation of the
    /// same ops yields the same program.
    pub fn from_ops(ops: impl IntoIterator<Item = SavProgramOp>) -> Self {
        let mut ops: Vec<SavProgramOp> = ops.into_iter().collect();
        ops.sort();
        ops.dedup();
        Self { ops }
    }

    /// The normalized operations, in canonical order.
    pub fn ops(&self) -> &[SavProgramOp] {
        &self.ops
    }

    /// True when the program installs nothing.
    pub fn is_empty(&self) -> bool {
        self.ops.is_empty()
    }
}

/// Monitor counters for installed SAV rules: how many observed
/// (source, ingress) pairs each verdict bucket received. `invalid` is
/// the spoof counter — invalid is what a monitor action logs and a drop
/// action drops; `unknown` is never a drop candidate (unknown ≠ invalid).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct SavMonitorCounts {
    /// Observed pairs judged invalid (the spoof counter).
    pub invalid: u64,
    /// Observed pairs judged valid.
    pub valid: u64,
    /// Observed pairs no rule judged.
    pub unknown: u64,
}

impl fmt::Display for SavMonitorCounts {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "invalid={} valid={} unknown={}",
            self.invalid, self.valid, self.unknown
        )
    }
}

/// The forwarding-plane interface.
///
/// Implemented by `netlink-dp` today; FPM/eBPF backends plug in later without
/// touching the RIB or protocol crates.
///
/// The SAV operations carry architecture.md §2's third SAV box ("table
/// manager" output) to the kernel — enforcement always goes through
/// them, never around (invariant: the dataplane crate owns all kernel
/// I/O). They default to [`DataplaneError::Unsupported`] so route-only
/// backends and test mocks keep compiling unchanged.
pub trait Dataplane {
    /// Atomically install or replace a route (RTM_NEWROUTE NLM_F_REPLACE).
    fn route_replace(
        &self,
        entry: &RouteEntry,
    ) -> impl Future<Output = Result<(), DataplaneError>> + Send;

    /// Remove a route (RTM_DELROUTE).
    fn route_delete(
        &self,
        entry: &RouteEntry,
    ) -> impl Future<Output = Result<(), DataplaneError>> + Send;

    /// Install or replace a SAV program (replace semantics: interfaces
    /// covered by the previous program but not this one are reverted to
    /// their pre-SAV state).
    fn sav_install(
        &self,
        _program: &SavProgram,
    ) -> impl Future<Output = Result<(), DataplaneError>> + Send {
        std::future::ready(Err(DataplaneError::Unsupported(
            "SAV enforcement not implemented by this backend",
        )))
    }

    /// Read the monitor counters of the installed SAV rules.
    fn sav_monitor_counts(
        &self,
    ) -> impl Future<Output = Result<SavMonitorCounts, DataplaneError>> + Send {
        std::future::ready(Err(DataplaneError::Unsupported(
            "SAV enforcement not implemented by this backend",
        )))
    }

    /// Remove every installed SAV rule, restoring pre-SAV state.
    fn sav_clear(&self) -> impl Future<Output = Result<(), DataplaneError>> + Send {
        std::future::ready(Err(DataplaneError::Unsupported(
            "SAV enforcement not implemented by this backend",
        )))
    }

    // TODO(phase-0): netns awareness; TODO(phase-1): nexthop-group
    // objects. (Initial dump + event stream for links — including VRF
    // device/table association —, addresses, routes, and neighbours is
    // done — see the netlink-dp backend.)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    fn link_new(vrf_table: Option<u32>, master_ifindex: Option<u32>) -> DataplaneEvent {
        DataplaneEvent::LinkNew {
            ifindex: 5,
            name: "vrf-test".into(),
            is_up: true,
            vrf_table,
            master_ifindex,
        }
    }

    /// A plain link renders exactly as before the VRF extension; a VRF
    /// device and an enslaved link each carry their new payload (smoke
    /// greps pin the same rendering live).
    #[test]
    fn link_new_display_carries_vrf_and_master_fields() {
        let plain = DataplaneEvent::LinkNew {
            ifindex: 2,
            name: "eth0".into(),
            is_up: false,
            vrf_table: None,
            master_ifindex: None,
        };
        assert_eq!(plain.to_string(), "link new: eth0 (ifindex 2, down)");

        let vrf = link_new(Some(5001), None);
        assert_eq!(
            vrf.to_string(),
            "link new: vrf-test (ifindex 5, up, vrf table 5001)"
        );

        let enslaved = link_new(None, Some(5));
        assert_eq!(
            enslaved.to_string(),
            "link new: vrf-test (ifindex 5, up, master ifindex 5)"
        );

        // A VRF device is never itself enslaved; a link may still carry
        // both payloads in a malformed stream — rendering covers it.
        let both = link_new(Some(5001), Some(9));
        assert_eq!(
            both.to_string(),
            "link new: vrf-test (ifindex 5, up, vrf table 5001, master ifindex 9)"
        );
    }

    /// A recording SAV-capable mock, following the workspace's test-mock
    /// pattern (rib's `MockDp` shape): interior-mutable state behind a
    /// `Mutex`, `Ready` futures, no runtime needed. Backends that count
    /// without dropping answer `sav_monitor_counts` from state; `clear`
    /// empties both.
    #[derive(Default)]
    struct MockSavDp {
        installed: Mutex<Vec<SavProgram>>,
        counts: Mutex<SavMonitorCounts>,
        cleared: Mutex<u32>,
    }

    impl Dataplane for MockSavDp {
        fn route_replace(
            &self,
            _entry: &RouteEntry,
        ) -> impl Future<Output = Result<(), DataplaneError>> + Send {
            std::future::ready(Ok(()))
        }

        fn route_delete(
            &self,
            _entry: &RouteEntry,
        ) -> impl Future<Output = Result<(), DataplaneError>> + Send {
            std::future::ready(Ok(()))
        }

        fn sav_install(
            &self,
            program: &SavProgram,
        ) -> impl Future<Output = Result<(), DataplaneError>> + Send {
            self.installed.lock().unwrap().push(program.clone());
            std::future::ready(Ok(()))
        }

        fn sav_monitor_counts(
            &self,
        ) -> impl Future<Output = Result<SavMonitorCounts, DataplaneError>> + Send {
            std::future::ready(Ok(*self.counts.lock().unwrap()))
        }

        fn sav_clear(&self) -> impl Future<Output = Result<(), DataplaneError>> + Send {
            *self.cleared.lock().unwrap() += 1;
            *self.counts.lock().unwrap() = SavMonitorCounts::default();
            std::future::ready(Ok(()))
        }
    }

    fn allow(prefixes: &[&str], urpf: SavUrpf, action: SavEnforce) -> SavProgramOp {
        SavProgramOp::IfaceAllow {
            ifindex: 3,
            prefixes: prefixes.iter().map(|p| p.parse().unwrap()).collect(),
            urpf,
            action,
        }
    }

    /// The program normalizes to canonical order: permutations and
    /// duplicates of one op set yield identical programs.
    #[test]
    fn sav_program_normalization_is_order_and_duplicate_invariant() {
        let a = SavProgram::from_ops([
            allow(&["198.51.100.0/24"], SavUrpf::Strict, SavEnforce::Drop),
            allow(&["192.0.2.0/24"], SavUrpf::Loose, SavEnforce::Monitor),
        ]);
        let b = SavProgram::from_ops([
            allow(&["192.0.2.0/24"], SavUrpf::Loose, SavEnforce::Monitor),
            allow(&["198.51.100.0/24"], SavUrpf::Strict, SavEnforce::Drop),
            allow(&["198.51.100.0/24"], SavUrpf::Strict, SavEnforce::Drop),
        ]);
        assert_eq!(a, b);
        assert_eq!(a.ops().len(), 2);
        assert!(!a.is_empty());
        assert!(SavProgram::new().is_empty());
    }

    /// The operator-facing one-liners (the savd rule logs): each cell of
    /// the GSC §3 taxonomy renders mode, scale, set, and action.
    #[test]
    fn sav_program_op_display_lines() {
        assert_eq!(
            allow(&["198.51.100.0/24"], SavUrpf::Strict, SavEnforce::Monitor).to_string(),
            "allow if#3 [198.51.100.0/24] strict monitor"
        );
        assert_eq!(
            SavProgramOp::IfaceAllow {
                ifindex: 6,
                prefixes: vec![],
                urpf: SavUrpf::Loose,
                action: SavEnforce::Drop,
            }
            .to_string(),
            "allow if#6 [] loose drop",
        );
        assert_eq!(
            SavProgramOp::IfaceBlock {
                ifindex: 2,
                prefixes: vec!["192.0.2.0/24".parse().unwrap()],
                action: SavEnforce::Drop,
            }
            .to_string(),
            "block if#2 [192.0.2.0/24] drop"
        );
        assert_eq!(
            SavProgramOp::PrefixAllow {
                prefix: "203.0.113.0/24".parse().unwrap(),
                ifindexes: vec![2, 3],
                action: SavEnforce::Monitor,
            }
            .to_string(),
            "allow 203.0.113.0/24 if [2, 3] monitor"
        );
        assert_eq!(
            SavProgramOp::PrefixBlock {
                prefix: "2001:db8::/48".parse().unwrap(),
                ifindexes: vec![4],
                action: SavEnforce::Monitor,
            }
            .to_string(),
            "block 2001:db8::/48 if [4] monitor"
        );
    }

    /// A route-only backend (no SAV impl) gets Unsupported from the
    /// defaulted trait ops — every existing `MockDp` keeps compiling and
    /// reports an honest "cannot" instead of pretending.
    #[test]
    fn default_sav_ops_report_unsupported() {
        struct RouteOnlyDp;
        impl Dataplane for RouteOnlyDp {
            fn route_replace(
                &self,
                _entry: &RouteEntry,
            ) -> impl Future<Output = Result<(), DataplaneError>> + Send {
                std::future::ready(Ok(()))
            }
            fn route_delete(
                &self,
                _entry: &RouteEntry,
            ) -> impl Future<Output = Result<(), DataplaneError>> + Send {
                std::future::ready(Ok(()))
            }
        }
        let dp = RouteOnlyDp;
        let err = futures_ready(dp.sav_install(&SavProgram::new()));
        assert!(matches!(err, Err(DataplaneError::Unsupported(_))));
        assert!(matches!(
            futures_ready(dp.sav_monitor_counts()),
            Err(DataplaneError::Unsupported(_))
        ));
        assert!(matches!(
            futures_ready(dp.sav_clear()),
            Err(DataplaneError::Unsupported(_))
        ));
    }

    /// Mock behaviors: install records the program, counts read back
    /// from state, clear resets the counters — the surface a monitor
    /// loop (W8) will drive.
    #[test]
    fn mock_records_install_reads_counts_and_clears() {
        let dp = MockSavDp::default();
        let program = SavProgram::from_ops([allow(
            &["198.51.100.0/24"],
            SavUrpf::Strict,
            SavEnforce::Monitor,
        )]);
        futures_ready(dp.sav_install(&program)).unwrap();
        futures_ready(dp.sav_install(&program)).unwrap();
        assert_eq!(dp.installed.lock().unwrap().len(), 2);
        assert_eq!(dp.installed.lock().unwrap()[0], program);

        *dp.counts.lock().unwrap() = SavMonitorCounts {
            invalid: 7,
            valid: 3,
            unknown: 1,
        };
        let counts = futures_ready(dp.sav_monitor_counts()).unwrap();
        assert_eq!(counts.invalid, 7);
        assert_eq!(counts.to_string(), "invalid=7 valid=3 unknown=1");

        futures_ready(dp.sav_clear()).unwrap();
        assert_eq!(*dp.cleared.lock().unwrap(), 1);
        assert_eq!(
            futures_ready(dp.sav_monitor_counts()).unwrap(),
            SavMonitorCounts::default(),
            "clear resets the counters"
        );
    }

    /// The mock's futures complete without a runtime (Ready futures,
    /// same recipe the rib tests use).
    fn futures_ready<T>(fut: impl Future<Output = T>) -> T {
        let mut fut = Box::pin(fut);
        let waker = std::task::Waker::noop();
        let mut cx = std::task::Context::from_waker(waker);
        match fut.as_mut().poll(&mut cx) {
            std::task::Poll::Ready(out) => out,
            std::task::Poll::Pending => unreachable!("mock futures are always Ready"),
        }
    }
}
