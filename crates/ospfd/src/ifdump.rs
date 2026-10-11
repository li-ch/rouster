//! The ZAPI interface dump as ospfd's address source (ADD-C2).
//!
//! Today's alternative was the static `ospfd.conf` stanza: every
//! `interface <name>` needed an `address <a.b.c.d/m>` line because
//! The dynamic source this module lands: ospfd as a ZAPI **client**
//! (the same [`zapi::ZapiClient`] the savd/bfdd edges hold) asks zebra
//! for the interface dump and merges it with the configured
//! interfaces — a configured interface picks up its live addresses
//! (and link state) when available, while the static config stays the
//! fallback for interfaces the dump does not know.
//!
//! # Wire protocol (all pre-modeled message types — no new pins)
//!
//! - HELLO as OSPF (route type 7, the z5c-proven attach).
//! - `INTERFACE_ADD` with an EMPTY body (`InterfaceAddRequest`): the
//!   registration request; zebra answers with one real `INTERFACE_ADD`
//!   per interface, each followed by its `INTERFACE_ADDRESS_ADD`s
//!   (pinned doc, command table row 0; the rousterd server's
//!   `RequestInterfaces` answer is exactly this shape).
//! - ZAPI has no end-of-dump marker, so the savd causality-marker
//!   pattern rides along: a transient dummy `NEXTHOP_REGISTER` sent
//!   AFTER the dump request can only be answered once the server has
//!   processed the request, and the server writes one session's
//!   messages sequentially — the marker's `NEXTHOP_UPDATE` is
//!   therefore the last frame of the dump. The dummy interest is then
//!   unregistered (rousterd keeps no dead NHT state).
//!
//! # Merge semantics (dump wins, config falls back)
//!
//! - **Address**: the interface's first NON-secondary IPv4 address
//!   becomes the OSPF address (mask from the prefix length); IPv6 is
//!   skipped (this daemon is OSPFv2) and secondary-only interfaces
//!   keep the static config (FRR ospfd runs on the primary). If the
//!   dump knows the interface but has no usable IPv4 address, the
//!   static config address stays.
//! - **Link state**: `IFF_UP|IFF_RUNNING` (FRR `if_is_operative`)
//!   plus not-`IFF_LOOPBACK` — the flags word the dump's INTERFACE_ADD
//!   relays verbatim from the kernel. An interface the dump reports
//!   down (or a loopback: hello-less stub, no `passive` knob exists
//!   yet) does NOT fire §9.3's InterfaceUp at construction: it sits in
//!   Down, sends no Hellos, and contributes no router-LSA links until
//!   ongoing link-state tracking lands (§Deferred).
//! - **MTU**: NOT overlaid (disclosed): the wire body carries it, but
//!   rousterd's interface mirror does not — the server's dump frames
//!   stamp every interface with the codec default 1500, which would
//!   stomp an operator's `mtu 9000` with a fabricated value. The
//!   overlay lands when the mirror carries the kernel's MTU
//!   (§Deferred); [`LiveInterface::mtu`] keeps the wire value for
//!   observability.

use std::collections::BTreeMap;
use std::net::Ipv4Addr;
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncWrite};
use tracing::{info, warn};
use zapi::message::{ifa_flag, iff, route_type, ZapiMessage};
use zapi::ZapiClient;

use crate::config::OspfdConfig;

/// Quiet bound for the whole sync (marker included) — the dump is
/// produced synchronously inside the server's request handling, so a
/// healthy session answers well within it; a stuck one must not hang
/// startup indefinitely.
const SYNC_TIMEOUT: Duration = Duration::from_secs(5);

/// The dummy prefix used as the dump-end causality marker (a /32 no
/// interface ever carries — the savd convention).
fn sync_marker() -> common::IpPrefix {
    "0.0.0.0/32".parse().expect("static prefix parses")
}

/// One address of a dumped interface.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DumpAddress {
    /// The host prefix as dumped (address + prefix length).
    pub prefix: common::IpPrefix,
    /// `ZEBRA_IFA_SECONDARY` (SPEC; our server sends 0 today).
    pub secondary: bool,
}

/// One interface as seen in the ZAPI dump.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LiveInterface {
    pub ifname: String,
    pub ifindex: u32,
    /// `if_is_operative`: IFF_UP|IFF_RUNNING in the dumped flags word.
    pub operative: bool,
    /// IFF_LOOPBACK in the flags word (hello-less stub for protocols).
    pub loopback: bool,
    /// The dump's MTU (0 = unknown/not reported).
    pub mtu: u32,
    /// Addresses in dump order (the primary comes first on real
    /// zebra; selection at merge time, not here).
    pub addresses: Vec<DumpAddress>,
}

impl LiveInterface {
    /// The address OSPF should run on: the first non-secondary IPv4
    /// address as `(address, mask)` — FRR's ospfd runs on the primary.
    /// IPv6 is skipped (OSPFv2 daemon); `None` when no usable IPv4
    /// address exists (the merge then keeps the static config).
    pub fn primary_v4(&self) -> Option<(Ipv4Addr, Ipv4Addr)> {
        let v4 = self
            .addresses
            .iter()
            .filter(|a| !a.secondary)
            .filter_map(|a| match a.prefix {
                common::IpPrefix::V4(p) => Some((p.addr(), p.prefix_len())),
                common::IpPrefix::V6(_) => None,
            })
            .next()?;
        Some((v4.0, mask_from_len(v4.1)))
    }

    /// Whether OSPF may bring this interface up: operative and not a
    /// loopback.
    pub fn ospf_usable(&self) -> bool {
        self.operative && !self.loopback
    }
}

/// The IPv4 netmask for a prefix length (len 0 = 0.0.0.0, 32 =
/// 255.255.255.255).
fn mask_from_len(len: u8) -> Ipv4Addr {
    Ipv4Addr::from(u32::MAX.checked_shl(32 - u32::from(len)).unwrap_or(0))
}

/// The collected interface dump: zebra's view of every interface,
/// keyed by name (the config's interface identity) with the ifindex
/// kept for the ADDRESS_ADD/DELETE bodies, which name no name.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct InterfaceDump {
    interfaces: BTreeMap<String, LiveInterface>,
    /// Addresses that arrived before their interface's INTERFACE_ADD
    /// (real zebra dumps INTERFACE_ADD first; a defensive bag so an
    /// odd ordering never loses an address).
    pending: BTreeMap<u32, Vec<DumpAddress>>,
}

impl InterfaceDump {
    pub fn new() -> Self {
        Self::default()
    }

    /// The dumped interface by name.
    pub fn get(&self, ifname: &str) -> Option<&LiveInterface> {
        self.interfaces.get(ifname)
    }

    /// How many interfaces the dump holds.
    pub fn len(&self) -> usize {
        self.interfaces.len()
    }

    /// Whether the dump holds nothing at all (standalone mode, or a
    /// zebra with no interfaces).
    pub fn is_empty(&self) -> bool {
        self.interfaces.is_empty()
    }

    /// Applies one zebra message to the dump. Returns whether the
    /// message was a dump-family frame (the caller's observability
    /// count). INTERFACE_ADD resets the entry's addresses — a dump's
    /// INTERFACE_ADD precedes its ADDRESS_ADDs, and a re-dump starts
    /// from a clean entry.
    pub fn apply(&mut self, message: &ZapiMessage) -> bool {
        match message {
            ZapiMessage::InterfaceAdd(z) => {
                let entry = LiveInterface {
                    ifname: z.ifname.clone(),
                    ifindex: z.ifindex,
                    operative: z.flags & (iff::UP | iff::RUNNING) == (iff::UP | iff::RUNNING),
                    loopback: z.flags & iff::LOOPBACK != 0,
                    mtu: z.mtu,
                    addresses: self.pending.remove(&z.ifindex).unwrap_or_default(),
                };
                self.interfaces.insert(entry.ifname.clone(), entry);
                true
            }
            ZapiMessage::InterfaceDelete(z) => {
                self.interfaces.remove(&z.ifname);
                self.pending.remove(&z.ifindex);
                true
            }
            ZapiMessage::InterfaceAddressAdd(a) => {
                let address = DumpAddress {
                    prefix: a.address,
                    secondary: a.flags & ifa_flag::SECONDARY != 0,
                };
                match self
                    .interfaces
                    .values_mut()
                    .find(|i| i.ifindex == a.ifindex)
                {
                    Some(live) => live.addresses.push(address),
                    None => self.pending.entry(a.ifindex).or_default().push(address),
                }
                true
            }
            ZapiMessage::InterfaceAddressDelete(a) => {
                let address = DumpAddress {
                    prefix: a.address,
                    secondary: a.flags & ifa_flag::SECONDARY != 0,
                };
                if let Some(live) = self
                    .interfaces
                    .values_mut()
                    .find(|i| i.ifindex == a.ifindex)
                {
                    live.addresses.retain(|x| *x != address);
                }
                if let Some(list) = self.pending.get_mut(&a.ifindex) {
                    list.retain(|x| *x != address);
                }
                true
            }
            _ => false,
        }
    }

    /// Merges the dump into a parsed configuration: for every
    /// configured interface stanza (all areas), the dump's live
    /// address/link-state/MTU override the static values when
    /// available; interfaces the dump does not know keep their static
    /// config untouched. Returns the per-outcome counts for callers
    /// and tests.
    pub fn merge_into(&self, config: &mut OspfdConfig) -> MergeReport {
        let mut report = MergeReport::default();
        for area in &mut config.areas {
            for (name, icfg) in &mut area.interfaces {
                let Some(live) = self.get(name) else {
                    report.static_fallback += 1;
                    info!(
                        interface = %name,
                        "ospfd: not in the zapi interface dump; static config is the source"
                    );
                    continue;
                };
                match live.primary_v4() {
                    Some((addr, mask)) => {
                        icfg.address = Some((addr, mask));
                        report.dynamic_address += 1;
                        info!(
                            interface = %name,
                            address = %addr,
                            operative = live.operative,
                            "ospfd: address from the zapi interface dump"
                        );
                    }
                    None => {
                        report.static_fallback += 1;
                        warn!(
                            interface = %name,
                            "ospfd: dumped interface has no non-secondary IPv4 address; \
                             static config is the source"
                        );
                    }
                }
                icfg.link_state = Some(live.ospf_usable());
                if !live.ospf_usable() {
                    report.down += 1;
                    warn!(
                        interface = %name,
                        loopback = live.loopback,
                        "ospfd: dump reports the interface not OSPF-usable; \
                         it stays Down (no Hellos, no router-LSA links)"
                    );
                }
                // No MTU overlay: the mirror carries no MTU, so the
                // dump frames would stamp the codec default 1500 on
                // every interface (module docs' disclosure).
            }
        }
        report
    }
}

/// What [`InterfaceDump::merge_into`] did, per outcome.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct MergeReport {
    /// Interfaces whose address came from the dump.
    pub dynamic_address: usize,
    /// Interfaces that kept their static config address (absent from
    /// the dump, or no usable IPv4 address on it).
    pub static_fallback: usize,
    /// Interfaces the dump reports not OSPF-usable (down/loopback) —
    /// they stay Down at construction.
    pub down: usize,
}

/// HELLO + the interface dump: handshake as OSPF, request the dump,
/// then the causality marker; collect every dump-family frame until
/// the marker's NEXTHOP_UPDATE, and unregister the marker. The client
/// is left established for the caller's resident loop (one session,
/// one socket).
pub async fn sync<IO>(client: &mut ZapiClient<IO>) -> std::io::Result<InterfaceDump>
where
    IO: AsyncRead + AsyncWrite + Unpin,
{
    client.handshake(route_type::OSPF).await?;
    info!("ospfd: zapi session established for the interface dump (protocol=7)");
    client.send_interface_dump_request().await?;

    let marker = sync_marker();
    client.send_nexthop_register(marker).await?;
    let mut dump = InterfaceDump::new();
    // The marker reply bounds the loop: the server answers NEXTHOP_
    // REGISTER (resolved or unresolved) after processing the earlier
    // dump request on the same session, so every dump frame precedes
    // it (sequential session handling).
    tokio::time::timeout(SYNC_TIMEOUT, async {
        loop {
            match client.read_message().await? {
                ZapiMessage::NexthopUpdate(update) if update.registered_prefix == marker => {
                    break;
                }
                other => {
                    dump.apply(&other);
                }
            }
        }
        std::io::Result::<()>::Ok(())
    })
    .await
    .map_err(|_| {
        std::io::Error::new(
            std::io::ErrorKind::TimedOut,
            "zapi interface dump: no marker answer within the sync window",
        )
    })??;
    client.send_nexthop_unregister(marker).await?;

    info!(
        interfaces = dump.len(),
        "ospfd: zapi interface dump collected"
    );
    Ok(dump)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::parse as parse_config;
    use common::IpPrefix;
    use zapi::{ZapiInterface, ZapiInterfaceAddress};

    fn iface_add(name: &str, ifindex: u32, flags: u64) -> ZapiMessage {
        let mut z = ZapiInterface::new(name, ifindex);
        z.flags = flags;
        z.mtu = 9000;
        ZapiMessage::InterfaceAdd(z)
    }

    fn addr_add(ifindex: u32, prefix: &str, secondary: bool) -> ZapiMessage {
        ZapiMessage::InterfaceAddressAdd(ZapiInterfaceAddress {
            ifindex,
            flags: if secondary { ifa_flag::SECONDARY } else { 0 },
            address: prefix.parse::<IpPrefix>().unwrap(),
            destination: None,
        })
    }

    fn addr_del(ifindex: u32, prefix: &str) -> ZapiMessage {
        ZapiMessage::InterfaceAddressDelete(ZapiInterfaceAddress {
            ifindex,
            flags: 0,
            address: prefix.parse::<IpPrefix>().unwrap(),
            destination: None,
        })
    }

    const UP_RUNNING: u64 = iff::UP | iff::RUNNING | iff::BROADCAST | iff::MULTICAST;

    fn dump_of(messages: &[ZapiMessage]) -> InterfaceDump {
        let mut dump = InterfaceDump::new();
        for m in messages {
            dump.apply(m);
        }
        dump
    }

    fn config_with(iface: &str, address: Option<&str>) -> OspfdConfig {
        let address_line = address
            .map(|a| format!("   address {a}\n"))
            .unwrap_or_default();
        let text = format!(
            "router ospf\n router-id 1.2.3.4\n area 0.0.0.0\n  interface {iface}\n{address_line}"
        );
        parse_config(&text).unwrap()
    }

    /// The dump order (INTERFACE_ADD then its ADDRESS_ADDs) fills the
    /// entry; v6 skipped, the first non-secondary v4 picked with the
    /// mask from the prefix length.
    #[test]
    fn primary_selection_skips_v6_and_secondary() {
        let dump = dump_of(&[
            iface_add("eth0", 2, UP_RUNNING),
            addr_add(2, "fe80::1/64", false),
            addr_add(2, "192.0.2.10/24", true),
            addr_add(2, "10.0.0.1/30", false),
        ]);
        let live = dump.get("eth0").unwrap();
        assert_eq!(
            live.primary_v4(),
            Some((
                "10.0.0.1".parse::<Ipv4Addr>().unwrap(),
                "255.255.255.252".parse::<Ipv4Addr>().unwrap()
            ))
        );
        assert!(live.operative);
        assert!(!live.loopback);
        assert_eq!(live.mtu, 9000);
    }

    /// A secondary-only interface has no usable address: the merge
    /// keeps the static config.
    #[test]
    fn secondary_only_has_no_primary() {
        let dump = dump_of(&[
            iface_add("eth0", 2, UP_RUNNING),
            addr_add(2, "192.0.2.10/24", true),
        ]);
        assert_eq!(dump.get("eth0").unwrap().primary_v4(), None);
    }

    /// ADDRESS_ADD before INTERFACE_ADD (defensive order) still lands
    /// via the pending bag.
    #[test]
    fn address_before_interface_lands_via_pending() {
        let dump = dump_of(&[
            addr_add(7, "10.1.1.1/24", false),
            iface_add("eth1", 7, UP_RUNNING),
        ]);
        assert_eq!(dump.get("eth1").unwrap().addresses.len(), 1);
    }

    /// INTERFACE_DELETE removes the entry (and its pending addresses).
    #[test]
    fn delete_removes() {
        let dump = dump_of(&[
            iface_add("eth0", 2, UP_RUNNING),
            addr_add(2, "10.0.0.1/24", false),
            ZapiMessage::InterfaceDelete({
                let mut z = ZapiInterface::new("eth0", 2);
                z.flags = UP_RUNNING;
                z
            }),
        ]);
        assert!(dump.get("eth0").is_none());
        assert!(dump.is_empty());
    }

    /// ADDRESS_DELETE removes exactly the matching prefix.
    #[test]
    fn address_delete_removes_one() {
        let dump = dump_of(&[
            iface_add("eth0", 2, UP_RUNNING),
            addr_add(2, "10.0.0.1/24", false),
            addr_add(2, "10.0.0.2/24", false),
            addr_del(2, "10.0.0.1/24"),
        ]);
        assert_eq!(dump.get("eth0").unwrap().addresses.len(), 1);
    }

    /// Non-dump messages are not consumed (the observability flag).
    #[test]
    fn non_dump_messages_ignored() {
        let mut dump = InterfaceDump::new();
        assert!(!dump.apply(&ZapiMessage::InterfaceAddRequest));
        assert!(dump.is_empty());
    }

    /// Merge: the dump's address overrides the static one; a
    /// not-dumped interface keeps its static config and unknown link
    /// state.
    #[test]
    fn merge_dynamic_overrides_static_fallback_keeps_config() {
        let dump = dump_of(&[
            iface_add("dyn0", 2, UP_RUNNING),
            addr_add(2, "10.0.0.1/24", false),
        ]);
        let mut config = parse_config(
            "router ospf\n router-id 1.2.3.4\n area 0.0.0.0\n  interface dyn0\n   \
             address 192.0.2.1/24\n  interface stat0\n   address 198.51.100.1/30\n",
        )
        .unwrap();
        let report = dump.merge_into(&mut config);
        assert_eq!(report.dynamic_address, 1);
        assert_eq!(report.static_fallback, 1);
        assert_eq!(report.down, 0);
        let a0 = &config.areas[0].interfaces["dyn0"];
        assert_eq!(
            a0.address,
            Some((
                "10.0.0.1".parse::<Ipv4Addr>().unwrap(),
                "255.255.255.0".parse::<Ipv4Addr>().unwrap()
            ))
        );
        assert_eq!(a0.link_state, Some(true));
        // No MTU overlay (the mirror carries no MTU; module docs).
        assert_eq!(a0.mtu, 1500);
        let a1 = &config.areas[0].interfaces["stat0"];
        assert_eq!(
            a1.address,
            Some((
                "198.51.100.1".parse::<Ipv4Addr>().unwrap(),
                "255.255.255.252".parse::<Ipv4Addr>().unwrap()
            ))
        );
        assert_eq!(a1.link_state, None);
    }

    /// Merge: a dumped interface with no usable v4 falls back to the
    /// static address but still records the link state; a down
    /// interface records Some(false) and counts in `down`. (Interface
    /// names keep file order == BTreeMap order — the parser's
    /// parameter-attachment rule.)
    #[test]
    fn merge_v6_only_falls_back_and_down_records_state() {
        let dump = dump_of(&[
            iface_add("eth5", 5, UP_RUNNING),
            addr_add(5, "2001:db8::1/64", false),
            iface_add("eth6", 6, 0),
            addr_add(6, "10.9.9.9/24", false),
        ]);
        let mut config = parse_config(
            "router ospf\n router-id 1.2.3.4\n area 0.0.0.0\n  interface eth5\n   \
             address 192.0.2.7/24\n  interface eth6\n   address 10.9.9.9/24\n",
        )
        .unwrap();
        let report = dump.merge_into(&mut config);
        assert_eq!(report.static_fallback, 1);
        assert_eq!(report.down, 1);
        let v6 = &config.areas[0].interfaces["eth5"];
        // Static address kept, live link state recorded.
        assert_eq!(
            v6.address,
            Some((
                "192.0.2.7".parse::<Ipv4Addr>().unwrap(),
                "255.255.255.0".parse::<Ipv4Addr>().unwrap()
            ))
        );
        assert_eq!(v6.link_state, Some(true));
        let down = &config.areas[0].interfaces["eth6"];
        // Dump address still applied (dump wins when it has one) even
        // though the interface is down — the state, not the address,
        // keeps it quiet.
        assert_eq!(
            down.address.map(|(a, _)| a),
            Some("10.9.9.9".parse().unwrap())
        );
        assert_eq!(down.link_state, Some(false));
    }

    /// A loopback is not OSPF-usable (hello-less stub; no passive knob
    /// exists yet) — the merge marks it down.
    #[test]
    fn loopback_is_not_usable() {
        let dump = dump_of(&[
            iface_add("lo", 1, iff::UP | iff::RUNNING | iff::LOOPBACK),
            addr_add(1, "127.0.0.1/8", false),
        ]);
        let live = dump.get("lo").unwrap();
        assert!(live.operative);
        assert!(live.loopback);
        assert!(!live.ospf_usable());
        let mut config = config_with("lo", Some("127.0.0.1/8"));
        let report = dump.merge_into(&mut config);
        assert_eq!(report.down, 1);
        assert_eq!(config.areas[0].interfaces["lo"].link_state, Some(false));
    }

    /// Mask edge cases: /0 masks to 0.0.0.0, /32 to all-ones.
    #[test]
    fn mask_edges() {
        assert_eq!(mask_from_len(0), Ipv4Addr::UNSPECIFIED);
        assert_eq!(mask_from_len(32), Ipv4Addr::from(u32::MAX));
        assert_eq!(
            mask_from_len(24),
            "255.255.255.0".parse::<Ipv4Addr>().unwrap()
        );
    }

    /// The /32 marker prefix parses (the sync protocol's constant).
    #[test]
    fn marker_prefix_parses() {
        assert!(matches!(sync_marker(), IpPrefix::V4(_)));
    }

    /// Daemon-level: a merged down `link_state` keeps the interface
    /// in Down — no §9.3 InterfaceUp at construction, no Hellos on
    /// the tick, no router-LSA link — while an up interface behaves
    /// exactly as the static-config path always did.
    #[test]
    fn down_link_state_stays_down_silent_and_linkless() {
        use crate::daemon::Ospfd;
        let mut config = parse_config(
            "router ospf\n router-id 1.2.3.4\n area 0.0.0.0\n  interface eth0\n   \
             address 10.0.0.1/24\n  interface eth1\n   address 10.0.1.1/24\n",
        )
        .unwrap();
        // The dump's verdict: eth0 up, eth1 down.
        config.areas[0]
            .interfaces
            .get_mut("eth0")
            .unwrap()
            .link_state = Some(true);
        config.areas[0]
            .interfaces
            .get_mut("eth1")
            .unwrap()
            .link_state = Some(false);
        let mut core = Ospfd::new(&config).unwrap();
        assert_eq!(
            core.interfaces[0].fsm.state,
            crate::iface::InterfaceState::Waiting
        );
        assert_eq!(
            core.interfaces[1].fsm.state,
            crate::iface::InterfaceState::Down
        );

        // t=0: Hellos only from eth0 (§9.3: Down sends none).
        let mut out = Vec::new();
        let mut zap = Vec::new();
        core.tick(0, &mut out, &mut zap);
        assert!(!out.is_empty(), "the up interface still hellos");
        assert!(
            out.iter().all(|w| w.iface == 0),
            "no wire output for the Down interface: {:?}",
            out.iter().map(|w| w.iface).collect::<Vec<_>>()
        );
        // Later ticks (WaitTimer long fired): still nothing from eth1.
        let mut out = Vec::new();
        core.tick(50, &mut out, &mut zap);
        assert!(
            out.iter().all(|w| w.iface == 0),
            "the Down interface stays silent"
        );

        // The originated router-LSA numbers eth0's stub network but
        // not the Down interface's (§12.4.1's state filter).
        let key = crate::lsa::LsaKey {
            ls_type: crate::lsa::LsaType::ROUTER,
            link_state_id: crate::lsa::LinkStateId(core.router_id.0),
            adv_router: core.router_id,
        };
        let area = core.areas.values().next().unwrap();
        let entry = area.lsdb.get(&key).expect("router-LSA originated");
        let crate::lsa::LsaBody::Router(body) = &entry.lsa.body else {
            panic!("router-LSA body")
        };
        let stub_nets: Vec<u32> = body
            .links
            .iter()
            .filter(|l| l.link_type == crate::lsa::LinkType::Stub)
            .map(|l| l.link_id.0)
            .collect();
        assert!(stub_nets.contains(&u32::from("10.0.0.0".parse::<Ipv4Addr>().unwrap())));
        assert!(!stub_nets.contains(&u32::from("10.0.1.0".parse::<Ipv4Addr>().unwrap())));
    }

    /// Daemon-level: link_state Some(true) (or None) is exactly the
    /// v1 construction path — InterfaceUp fires.
    #[test]
    fn up_and_unknown_link_state_fire_interface_up() {
        use crate::daemon::Ospfd;
        for state in [None, Some(true)] {
            let mut config = parse_config(
                "router ospf\n router-id 1.2.3.4\n area 0.0.0.0\n  interface eth0\n   \
                 address 10.0.0.1/24\n",
            )
            .unwrap();
            config.areas[0]
                .interfaces
                .get_mut("eth0")
                .unwrap()
                .link_state = state;
            let core = Ospfd::new(&config).unwrap();
            assert_eq!(
                core.interfaces[0].fsm.state,
                crate::iface::InterfaceState::Waiting,
                "link_state {state:?}: v1 construction"
            );
        }
    }
}
