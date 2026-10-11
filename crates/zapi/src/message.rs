//! ZAPI message model and body codecs (FRR 10.2.2, ZAPI version 6).
//!
//! Command numbers follow `zebra_message_types_t` from FRR 10.2.2's
//! `lib/zclient.h`, cross-checked against every wire fixture in
//! `tests/fixtures/` and against the 10.2.2 sources for the body layouts
//! (`lib/zclient.c`, `lib/zapi_route.c` included by it, `zebra/zebra_rnh.c`).
//! The pinned reference doc is `docs/interop/zapi-10.2-pinned.md`.
//!
//! Evidence tags used in field docs:
//! - `E:` — validated against a captured fixture (EMPIRICAL).
//! - `SPEC:` — layout from the FRR 10.2.2 source, not yet seen on our wire.
//!
//! Message bodies outside the modeled set decode as
//! [`ZapiMessage::Unknown`] with the raw body preserved; modeled bodies that
//! fail to parse produce a hard [`ZapiCodecError`] so layout drift is loud,
//! never silent.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use bytes::{BufMut, Bytes, BytesMut};
use common::{
    IpPrefix, Ipv4Prefix, Ipv6Prefix, Nexthop as CommonNexthop, NexthopGroup, RouteEntry,
    RouteProtocol,
};

use crate::header::{ZapiHeader, ZAPI_HEADER_LEN};

/// `AF_INET` as it appears in ZAPI prefix fields.
pub const AF_INET: u16 = 2;
/// `AF_INET6` as it appears in ZAPI prefix fields.
pub const AF_INET6: u16 = 10;

/// FRR `IFNAMSIZ` on Linux (16): interface names occupy exactly this many
/// wire bytes in INTERFACE_ADD/DELETE. Z5-fix: was 20 (a misreading of the
/// pinned doc — FRR does NOT widen the name on the wire; `zclient.c` reads
/// the system `IFNAMSIZ`, and a 20-byte write makes the client consume 4
/// padding bytes as the ifindex, registering every interface with ifindex 0
/// and rejecting all INTERFACE_ADDRESS_ADDs: "Cannot find IF 1 in VRF 0").
pub const ZAPI_IFNAMSIZ: usize = 16;
/// FRR `INTERFACE_HWADDR_MAX`.
pub const ZAPI_HWADDR_MAX: usize = 20;

/// Linux `IFF_*` bits as relayed in the u64 flags word of ZAPI
/// INTERFACE_ADD/DELETE bodies (the kernel's `ifi_flags`; zebra forwards
/// them verbatim). Protocol daemons gate on the classic set:
/// `if_is_operative` = UP|RUNNING, `if_is_broadcast` = RUNNING|BROADCAST
/// (ospfd's default broadcast network type and multicast hellos need
/// both), and `IFF_LOOPBACK` marks hello-less stub interfaces. Values are
/// the kernel ABI (uapi/linux/if.h) — identical on every architecture we
/// target.
pub mod iff {
    pub const UP: u64 = 0x1;
    pub const BROADCAST: u64 = 0x2;
    pub const LOOPBACK: u64 = 0x8;
    pub const RUNNING: u64 = 0x40;
    pub const MULTICAST: u64 = 0x1000;
}

/// `ZEBRA_IFA_*` bits for the flags u8 of INTERFACE_ADDRESS_ADD/DELETE
/// (frr-10.2.2 `lib/zclient.h`). SPEC: our zebra answers every dump
/// address with flags 0, so these bits only distinguish primaries from
/// a real FRR zebra dump (the consumer is ospfd's interface merge).
pub mod ifa_flag {
    /// A secondary address of the interface — protocol daemons run on
    /// the primary.
    pub const SECONDARY: u8 = 0x01;
    /// The address carries a peer address (point-to-point form).
    pub const PEER: u8 = 0x02;
}

/// ZEBRA_ROUTE_* type numbers — sequential from 0 over frr-10.2.2's
/// `lib/route_types.txt` as expanded by `lib/route_types.pl` (its loop
/// assigns `#define <name> <index>` starting at 0). `ZEBRA_ROUTE_LOCAL`
/// (3) sits between CONNECT and STATIC — the insertion that lifts
/// STATIC..BGP one above the pre-LOCAL table; SYSTEM/KERNEL/CONNECT keep
/// the classic values. E: STATIC=4 (staticd ROUTE_ADD/HELLO/
/// REDISTRIBUTE_ADD fixtures), OSPF=7 (live ospfd HELLO, z5c), BGP=10
/// (bgpd HELLO / LABEL_MANAGER_CONNECT fixtures), CONNECT=2 (live ospfd
/// `redistribute connected` REDISTRIBUTE_ADD capture, body `01 02 0000`).
pub mod route_type {
    /// Reserved, zebra-internal (route_types.txt: "Reserved").
    pub const SYSTEM: u8 = 0;
    /// Kernel routes not installed via the zebra RIB.
    pub const KERNEL: u8 = 1;
    /// Connected routes (directly attached subnet or host).
    pub const CONNECT: u8 = 2;
    /// Local routes (directly attached host route) — the 10.2 table's
    /// insertion between CONNECT and STATIC.
    pub const LOCAL: u8 = 3;
    /// E: staticd ROUTE_ADD/HELLO/REDISTRIBUTE_ADD in the fixtures.
    pub const STATIC: u8 = 4;
    pub const RIP: u8 = 5;
    pub const RIPNG: u8 = 6;
    pub const OSPF: u8 = 7;
    pub const OSPF6: u8 = 8;
    pub const ISIS: u8 = 9;
    /// E: bgpd HELLO and LABEL_MANAGER_CONNECT in the fixtures.
    pub const BGP: u8 = 10;
}

/// ZAPI_MESSAGE_* route-attribute bitmask (frr-10.2.2 `lib/zclient.h`).
/// E: 0x03 (`NEXTHOP | DISTANCE`) in both fixture route messages.
pub mod message_flag {
    pub const NEXTHOP: u32 = 0x01;
    pub const DISTANCE: u32 = 0x02;
    pub const METRIC: u32 = 0x04;
    pub const TAG: u32 = 0x08;
    pub const MTU: u32 = 0x10;
    pub const SRCPFX: u32 = 0x20;
    pub const BACKUP_NEXTHOPS: u32 = 0x40;
    pub const NHG: u32 = 0x80;
    pub const TABLEID: u32 = 0x0100;
    pub const SRTE: u32 = 0x0200;
    pub const OPAQUE: u32 = 0x0400;
}

/// ZAPI_NEXTHOP_FLAG_* per-nexthop bitmask (frr-10.2.2 `lib/zclient.h`).
pub mod nexthop_flag {
    pub const ONLINK: u8 = 0x01;
    pub const LABEL: u8 = 0x02;
    pub const WEIGHT: u8 = 0x04;
    pub const HAS_BACKUP: u8 = 0x08;
    pub const SEG6: u8 = 0x10;
    pub const SEG6LOCAL: u8 = 0x20;
    pub const EVPN: u8 = 0x40;
}

/// `enum nexthop_types_t` values (frr-10.2.2). 6 is fixture-verified; the
/// rest are SPEC from the `zapi_nexthop_encode` switch.
pub mod nexthop_type {
    pub const IFINDEX: u8 = 1;
    pub const IPV4: u8 = 2;
    pub const IPV4_IFINDEX: u8 = 3;
    pub const IPV6: u8 = 4;
    pub const IPV6_IFINDEX: u8 = 5;
    /// E: the blackhole nexthop in staticd's ROUTE_ADD fixture.
    pub const BLACKHOLE: u8 = 6;
}

/// `enum blackhole_type` values (frr-10.2.2 `lib/zclient.h`).
pub mod blackhole_type {
    /// Forward to the null device.
    pub const NULL: u8 = 0;
    /// Silently discard. E: value seen in the staticd fixture nexthop.
    pub const REJECT: u8 = 1;
    pub const UNSPEC: u8 = 2;
}

/// `enum zapi_route_notify_owner` values (frr-10.2.2 `lib/zclient.h`):
/// the flavor of a ZEBRA_ROUTE_NOTIFY_OWNER (11) push. E (A5): 2
/// (INSTALLED) wire-captured from a real zebra.
pub mod route_notify_note {
    pub const FAIL_INSTALL: u32 = 0;
    pub const BETTER_ADMIN_WON: u32 = 1;
    /// E: the A5 capture (blackhole static route, kernel-confirmed).
    pub const INSTALLED: u32 = 2;
    pub const REMOVED: u32 = 3;
    pub const REMOVE_FAIL: u32 = 4;
}

/// ZAPI command codes: `zebra_message_types_t` (frr-10.2.2 `lib/zclient.h`),
/// values 0..=146. Wire-observed entries are fixture-cited in the pinned doc.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ZapiCommand {
    InterfaceAdd,
    InterfaceDelete,
    InterfaceAddressAdd,
    InterfaceAddressDelete,
    InterfaceUp,
    InterfaceDown,
    InterfaceSetMaster,
    InterfaceSetArp,
    InterfaceSetProtodown,
    RouteAdd,
    RouteDelete,
    RouteNotifyOwner,
    RedistributeAdd,
    RedistributeDelete,
    RedistributeDefaultAdd,
    RedistributeDefaultDelete,
    RouterIdAdd,
    RouterIdDelete,
    RouterIdUpdate,
    Hello,
    Capabilities,
    NexthopRegister,
    NexthopUnregister,
    NexthopUpdate,
    InterfaceNbrAddressAdd,
    InterfaceNbrAddressDelete,
    InterfaceBfdDestUpdate,
    BfdDestRegister,
    BfdDestDeregister,
    BfdDestUpdate,
    BfdDestReplay,
    RedistributeRouteAdd,
    RedistributeRouteDel,
    VrfAdd,
    VrfDelete,
    VrfLabel,
    BfdClientRegister,
    BfdClientDeregister,
    InterfaceEnableRadv,
    InterfaceDisableRadv,
    NexthopLookupMrib,
    InterfaceLinkParams,
    MplsLabelsAdd,
    MplsLabelsDelete,
    MplsLabelsReplace,
    SrPolicySet,
    SrPolicyDelete,
    SrPolicyNotifyStatus,
    IpmrRouteStats,
    LabelManagerConnect,
    LabelManagerConnectAsync,
    GetLabelChunk,
    ReleaseLabelChunk,
    FecRegister,
    FecUnregister,
    FecUpdate,
    AdvertiseDefaultGw,
    AdvertiseSviMacip,
    AdvertiseSubnet,
    AdvertiseAllVni,
    LocalEsAdd,
    LocalEsDel,
    RemoteEsVtepAdd,
    RemoteEsVtepDel,
    LocalEsEviAdd,
    LocalEsEviDel,
    VniAdd,
    VniDel,
    L3VniAdd,
    L3VniDel,
    RemoteVtepAdd,
    RemoteVtepDel,
    MacipAdd,
    MacipDel,
    IpPrefixRouteAdd,
    IpPrefixRouteDel,
    RemoteMacipAdd,
    RemoteMacipDel,
    DuplicateAddrDetection,
    PwAdd,
    PwDelete,
    PwSet,
    PwUnset,
    PwStatusUpdate,
    RuleAdd,
    RuleDelete,
    RuleNotifyOwner,
    TableManagerConnect,
    GetTableChunk,
    ReleaseTableChunk,
    IpsetCreate,
    IpsetDestroy,
    IpsetEntryAdd,
    IpsetEntryDelete,
    IpsetNotifyOwner,
    IpsetEntryNotifyOwner,
    IptableAdd,
    IptableDelete,
    IptableNotifyOwner,
    VxlanFloodControl,
    VxlanSgAdd,
    VxlanSgDel,
    VxlanSgReplay,
    MlagProcessUp,
    MlagProcessDown,
    MlagClientRegister,
    MlagClientUnregister,
    MlagForwardMsg,
    NhgAdd,
    NhgDel,
    NhgNotifyOwner,
    EvpnRemoteNhAdd,
    EvpnRemoteNhDel,
    Srv6LocatorAdd,
    Srv6LocatorDelete,
    Srv6ManagerGetLocatorChunk,
    Srv6ManagerReleaseLocatorChunk,
    Srv6ManagerGetLocator,
    Srv6ManagerGetSrv6Sid,
    Srv6ManagerReleaseSrv6Sid,
    Error,
    ClientCapabilities,
    OpaqueMessage,
    OpaqueRegister,
    OpaqueUnregister,
    NeighDiscover,
    RouteNotifyRequest,
    ClientCloseNotify,
    NeighAdded,
    NeighRemoved,
    NeighGet,
    NeighRegister,
    NeighUnregister,
    NeighIpAdd,
    NeighIpDel,
    ConfigureArp,
    GreGet,
    GreUpdate,
    GreSourceSet,
    TcQdiscInstall,
    TcQdiscUninstall,
    TcClassAdd,
    TcClassDelete,
    TcFilterAdd,
    TcFilterDelete,
    OpaqueNotify,
    Srv6SidNotify,
    /// Any command number outside `zebra_message_types_t` (0..=146).
    /// Values 147+ are NOT zebra message types: the entries the pinned doc
    /// first listed at 150-154 belong to `enum zserv_client_capabilities`.
    Unknown(u16),
}

impl ZapiCommand {
    /// Maps a wire command number to a variant. Every member of
    /// `zebra_message_types_t` (0..=146) is named; anything else decodes as
    /// [`ZapiCommand::Unknown`] with the number preserved.
    pub fn from_u16(value: u16) -> Self {
        match value {
            0 => Self::InterfaceAdd,
            1 => Self::InterfaceDelete,
            2 => Self::InterfaceAddressAdd,
            3 => Self::InterfaceAddressDelete,
            4 => Self::InterfaceUp,
            5 => Self::InterfaceDown,
            6 => Self::InterfaceSetMaster,
            7 => Self::InterfaceSetArp,
            8 => Self::InterfaceSetProtodown,
            9 => Self::RouteAdd,
            10 => Self::RouteDelete,
            11 => Self::RouteNotifyOwner,
            12 => Self::RedistributeAdd,
            13 => Self::RedistributeDelete,
            14 => Self::RedistributeDefaultAdd,
            15 => Self::RedistributeDefaultDelete,
            16 => Self::RouterIdAdd,
            17 => Self::RouterIdDelete,
            18 => Self::RouterIdUpdate,
            19 => Self::Hello,
            20 => Self::Capabilities,
            21 => Self::NexthopRegister,
            22 => Self::NexthopUnregister,
            23 => Self::NexthopUpdate,
            24 => Self::InterfaceNbrAddressAdd,
            25 => Self::InterfaceNbrAddressDelete,
            26 => Self::InterfaceBfdDestUpdate,
            27 => Self::BfdDestRegister,
            28 => Self::BfdDestDeregister,
            29 => Self::BfdDestUpdate,
            30 => Self::BfdDestReplay,
            31 => Self::RedistributeRouteAdd,
            32 => Self::RedistributeRouteDel,
            33 => Self::VrfAdd,
            34 => Self::VrfDelete,
            35 => Self::VrfLabel,
            36 => Self::BfdClientRegister,
            37 => Self::BfdClientDeregister,
            38 => Self::InterfaceEnableRadv,
            39 => Self::InterfaceDisableRadv,
            40 => Self::NexthopLookupMrib,
            41 => Self::InterfaceLinkParams,
            42 => Self::MplsLabelsAdd,
            43 => Self::MplsLabelsDelete,
            44 => Self::MplsLabelsReplace,
            45 => Self::SrPolicySet,
            46 => Self::SrPolicyDelete,
            47 => Self::SrPolicyNotifyStatus,
            48 => Self::IpmrRouteStats,
            49 => Self::LabelManagerConnect,
            50 => Self::LabelManagerConnectAsync,
            51 => Self::GetLabelChunk,
            52 => Self::ReleaseLabelChunk,
            53 => Self::FecRegister,
            54 => Self::FecUnregister,
            55 => Self::FecUpdate,
            56 => Self::AdvertiseDefaultGw,
            57 => Self::AdvertiseSviMacip,
            58 => Self::AdvertiseSubnet,
            59 => Self::AdvertiseAllVni,
            60 => Self::LocalEsAdd,
            61 => Self::LocalEsDel,
            62 => Self::RemoteEsVtepAdd,
            63 => Self::RemoteEsVtepDel,
            64 => Self::LocalEsEviAdd,
            65 => Self::LocalEsEviDel,
            66 => Self::VniAdd,
            67 => Self::VniDel,
            68 => Self::L3VniAdd,
            69 => Self::L3VniDel,
            70 => Self::RemoteVtepAdd,
            71 => Self::RemoteVtepDel,
            72 => Self::MacipAdd,
            73 => Self::MacipDel,
            74 => Self::IpPrefixRouteAdd,
            75 => Self::IpPrefixRouteDel,
            76 => Self::RemoteMacipAdd,
            77 => Self::RemoteMacipDel,
            78 => Self::DuplicateAddrDetection,
            79 => Self::PwAdd,
            80 => Self::PwDelete,
            81 => Self::PwSet,
            82 => Self::PwUnset,
            83 => Self::PwStatusUpdate,
            84 => Self::RuleAdd,
            85 => Self::RuleDelete,
            86 => Self::RuleNotifyOwner,
            87 => Self::TableManagerConnect,
            88 => Self::GetTableChunk,
            89 => Self::ReleaseTableChunk,
            90 => Self::IpsetCreate,
            91 => Self::IpsetDestroy,
            92 => Self::IpsetEntryAdd,
            93 => Self::IpsetEntryDelete,
            94 => Self::IpsetNotifyOwner,
            95 => Self::IpsetEntryNotifyOwner,
            96 => Self::IptableAdd,
            97 => Self::IptableDelete,
            98 => Self::IptableNotifyOwner,
            99 => Self::VxlanFloodControl,
            100 => Self::VxlanSgAdd,
            101 => Self::VxlanSgDel,
            102 => Self::VxlanSgReplay,
            103 => Self::MlagProcessUp,
            104 => Self::MlagProcessDown,
            105 => Self::MlagClientRegister,
            106 => Self::MlagClientUnregister,
            107 => Self::MlagForwardMsg,
            108 => Self::NhgAdd,
            109 => Self::NhgDel,
            110 => Self::NhgNotifyOwner,
            111 => Self::EvpnRemoteNhAdd,
            112 => Self::EvpnRemoteNhDel,
            113 => Self::Srv6LocatorAdd,
            114 => Self::Srv6LocatorDelete,
            115 => Self::Srv6ManagerGetLocatorChunk,
            116 => Self::Srv6ManagerReleaseLocatorChunk,
            117 => Self::Srv6ManagerGetLocator,
            118 => Self::Srv6ManagerGetSrv6Sid,
            119 => Self::Srv6ManagerReleaseSrv6Sid,
            120 => Self::Error,
            121 => Self::ClientCapabilities,
            122 => Self::OpaqueMessage,
            123 => Self::OpaqueRegister,
            124 => Self::OpaqueUnregister,
            125 => Self::NeighDiscover,
            126 => Self::RouteNotifyRequest,
            127 => Self::ClientCloseNotify,
            128 => Self::NeighAdded,
            129 => Self::NeighRemoved,
            130 => Self::NeighGet,
            131 => Self::NeighRegister,
            132 => Self::NeighUnregister,
            133 => Self::NeighIpAdd,
            134 => Self::NeighIpDel,
            135 => Self::ConfigureArp,
            136 => Self::GreGet,
            137 => Self::GreUpdate,
            138 => Self::GreSourceSet,
            139 => Self::TcQdiscInstall,
            140 => Self::TcQdiscUninstall,
            141 => Self::TcClassAdd,
            142 => Self::TcClassDelete,
            143 => Self::TcFilterAdd,
            144 => Self::TcFilterDelete,
            145 => Self::OpaqueNotify,
            146 => Self::Srv6SidNotify,
            _ => Self::Unknown(value),
        }
    }

    /// The wire command number (identity for [`ZapiCommand::Unknown`]).
    pub const fn to_u16(&self) -> u16 {
        match self {
            Self::InterfaceAdd => 0,
            Self::InterfaceDelete => 1,
            Self::InterfaceAddressAdd => 2,
            Self::InterfaceAddressDelete => 3,
            Self::InterfaceUp => 4,
            Self::InterfaceDown => 5,
            Self::InterfaceSetMaster => 6,
            Self::InterfaceSetArp => 7,
            Self::InterfaceSetProtodown => 8,
            Self::RouteAdd => 9,
            Self::RouteDelete => 10,
            Self::RouteNotifyOwner => 11,
            Self::RedistributeAdd => 12,
            Self::RedistributeDelete => 13,
            Self::RedistributeDefaultAdd => 14,
            Self::RedistributeDefaultDelete => 15,
            Self::RouterIdAdd => 16,
            Self::RouterIdDelete => 17,
            Self::RouterIdUpdate => 18,
            Self::Hello => 19,
            Self::Capabilities => 20,
            Self::NexthopRegister => 21,
            Self::NexthopUnregister => 22,
            Self::NexthopUpdate => 23,
            Self::InterfaceNbrAddressAdd => 24,
            Self::InterfaceNbrAddressDelete => 25,
            Self::InterfaceBfdDestUpdate => 26,
            Self::BfdDestRegister => 27,
            Self::BfdDestDeregister => 28,
            Self::BfdDestUpdate => 29,
            Self::BfdDestReplay => 30,
            Self::RedistributeRouteAdd => 31,
            Self::RedistributeRouteDel => 32,
            Self::VrfAdd => 33,
            Self::VrfDelete => 34,
            Self::VrfLabel => 35,
            Self::BfdClientRegister => 36,
            Self::BfdClientDeregister => 37,
            Self::InterfaceEnableRadv => 38,
            Self::InterfaceDisableRadv => 39,
            Self::NexthopLookupMrib => 40,
            Self::InterfaceLinkParams => 41,
            Self::MplsLabelsAdd => 42,
            Self::MplsLabelsDelete => 43,
            Self::MplsLabelsReplace => 44,
            Self::SrPolicySet => 45,
            Self::SrPolicyDelete => 46,
            Self::SrPolicyNotifyStatus => 47,
            Self::IpmrRouteStats => 48,
            Self::LabelManagerConnect => 49,
            Self::LabelManagerConnectAsync => 50,
            Self::GetLabelChunk => 51,
            Self::ReleaseLabelChunk => 52,
            Self::FecRegister => 53,
            Self::FecUnregister => 54,
            Self::FecUpdate => 55,
            Self::AdvertiseDefaultGw => 56,
            Self::AdvertiseSviMacip => 57,
            Self::AdvertiseSubnet => 58,
            Self::AdvertiseAllVni => 59,
            Self::LocalEsAdd => 60,
            Self::LocalEsDel => 61,
            Self::RemoteEsVtepAdd => 62,
            Self::RemoteEsVtepDel => 63,
            Self::LocalEsEviAdd => 64,
            Self::LocalEsEviDel => 65,
            Self::VniAdd => 66,
            Self::VniDel => 67,
            Self::L3VniAdd => 68,
            Self::L3VniDel => 69,
            Self::RemoteVtepAdd => 70,
            Self::RemoteVtepDel => 71,
            Self::MacipAdd => 72,
            Self::MacipDel => 73,
            Self::IpPrefixRouteAdd => 74,
            Self::IpPrefixRouteDel => 75,
            Self::RemoteMacipAdd => 76,
            Self::RemoteMacipDel => 77,
            Self::DuplicateAddrDetection => 78,
            Self::PwAdd => 79,
            Self::PwDelete => 80,
            Self::PwSet => 81,
            Self::PwUnset => 82,
            Self::PwStatusUpdate => 83,
            Self::RuleAdd => 84,
            Self::RuleDelete => 85,
            Self::RuleNotifyOwner => 86,
            Self::TableManagerConnect => 87,
            Self::GetTableChunk => 88,
            Self::ReleaseTableChunk => 89,
            Self::IpsetCreate => 90,
            Self::IpsetDestroy => 91,
            Self::IpsetEntryAdd => 92,
            Self::IpsetEntryDelete => 93,
            Self::IpsetNotifyOwner => 94,
            Self::IpsetEntryNotifyOwner => 95,
            Self::IptableAdd => 96,
            Self::IptableDelete => 97,
            Self::IptableNotifyOwner => 98,
            Self::VxlanFloodControl => 99,
            Self::VxlanSgAdd => 100,
            Self::VxlanSgDel => 101,
            Self::VxlanSgReplay => 102,
            Self::MlagProcessUp => 103,
            Self::MlagProcessDown => 104,
            Self::MlagClientRegister => 105,
            Self::MlagClientUnregister => 106,
            Self::MlagForwardMsg => 107,
            Self::NhgAdd => 108,
            Self::NhgDel => 109,
            Self::NhgNotifyOwner => 110,
            Self::EvpnRemoteNhAdd => 111,
            Self::EvpnRemoteNhDel => 112,
            Self::Srv6LocatorAdd => 113,
            Self::Srv6LocatorDelete => 114,
            Self::Srv6ManagerGetLocatorChunk => 115,
            Self::Srv6ManagerReleaseLocatorChunk => 116,
            Self::Srv6ManagerGetLocator => 117,
            Self::Srv6ManagerGetSrv6Sid => 118,
            Self::Srv6ManagerReleaseSrv6Sid => 119,
            Self::Error => 120,
            Self::ClientCapabilities => 121,
            Self::OpaqueMessage => 122,
            Self::OpaqueRegister => 123,
            Self::OpaqueUnregister => 124,
            Self::NeighDiscover => 125,
            Self::RouteNotifyRequest => 126,
            Self::ClientCloseNotify => 127,
            Self::NeighAdded => 128,
            Self::NeighRemoved => 129,
            Self::NeighGet => 130,
            Self::NeighRegister => 131,
            Self::NeighUnregister => 132,
            Self::NeighIpAdd => 133,
            Self::NeighIpDel => 134,
            Self::ConfigureArp => 135,
            Self::GreGet => 136,
            Self::GreUpdate => 137,
            Self::GreSourceSet => 138,
            Self::TcQdiscInstall => 139,
            Self::TcQdiscUninstall => 140,
            Self::TcClassAdd => 141,
            Self::TcClassDelete => 142,
            Self::TcFilterAdd => 143,
            Self::TcFilterDelete => 144,
            Self::OpaqueNotify => 145,
            Self::Srv6SidNotify => 146,
            Self::Unknown(value) => *value,
        }
    }
}

/// Codec failures for modeled message bodies. Unknown commands never error
/// (they pass through as [`ZapiMessage::Unknown`]); an `Err` here means a
/// modeled body disagreed with the pinned layout.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ZapiCodecError {
    #[error("body truncated: {need} more byte(s) needed")]
    Truncated { need: usize },
    #[error("unknown address family byte/word on the wire: {0}")]
    BadFamily(u16),
    #[error("prefix length {len} exceeds the family maximum")]
    BadPrefixLen { family: u16, len: u8 },
    #[error("unsupported nexthop type {0}")]
    BadNexthopType(u8),
    #[error("unsupported per-nexthop flag bits {0:#04x} (SEG6/SEG6LOCAL not modeled)")]
    UnsupportedNexthopFlags(u8),
    #[error("{0} unexpected trailing byte(s) after a fully parsed body")]
    TrailingBytes(usize),
    #[error("interface name is {len} bytes, max {max}")]
    NameTooLong { len: usize, max: usize },
    #[error("BFD command carries family {first} for dst but {second} for src")]
    FamilyMismatch { first: u16, second: u16 },
    #[error("interface/profile name is not valid UTF-8")]
    BadIfname,
}

// ---------------------------------------------------------------------------
// Checked decode helpers (never panic on short buffers)
// ---------------------------------------------------------------------------

fn take_u8(b: &mut &[u8]) -> Result<u8, ZapiCodecError> {
    let (first, rest) = b
        .split_first()
        .ok_or(ZapiCodecError::Truncated { need: 1 })?;
    *b = rest;
    Ok(*first)
}

fn take_be_u16(b: &mut &[u8]) -> Result<u16, ZapiCodecError> {
    let raw = take_n(b, 2)?;
    Ok(u16::from_be_bytes([raw[0], raw[1]]))
}

fn take_be_u32(b: &mut &[u8]) -> Result<u32, ZapiCodecError> {
    let raw = take_n(b, 4)?;
    Ok(u32::from_be_bytes([raw[0], raw[1], raw[2], raw[3]]))
}

fn take_be_u64(b: &mut &[u8]) -> Result<u64, ZapiCodecError> {
    let raw = take_n(b, 8)?;
    Ok(u64::from_be_bytes([
        raw[0], raw[1], raw[2], raw[3], raw[4], raw[5], raw[6], raw[7],
    ]))
}

fn take_n<'a>(b: &mut &'a [u8], n: usize) -> Result<&'a [u8], ZapiCodecError> {
    if b.len() < n {
        return Err(ZapiCodecError::Truncated { need: n - b.len() });
    }
    let (head, rest) = b.split_at(n);
    *b = rest;
    Ok(head)
}

/// Address bytes for a wire family (4 for IPv4, 16 for IPv6).
fn family_blen(family: u16) -> Result<usize, ZapiCodecError> {
    match family {
        AF_INET => Ok(4),
        AF_INET6 => Ok(16),
        other => Err(ZapiCodecError::BadFamily(other)),
    }
}

fn v4_prefix(addr: [u8; 4], len: u8) -> Result<IpPrefix, ZapiCodecError> {
    Ipv4Prefix::new(Ipv4Addr::from(addr), len)
        .map(Into::into)
        .map_err(|_| ZapiCodecError::BadPrefixLen {
            family: AF_INET,
            len,
        })
}

fn v6_prefix(addr: [u8; 16], len: u8) -> Result<IpPrefix, ZapiCodecError> {
    Ipv6Prefix::new(Ipv6Addr::from(addr), len)
        .map(Into::into)
        .map_err(|_| ZapiCodecError::BadPrefixLen {
            family: AF_INET6,
            len,
        })
}

fn prefix_parts(p: &IpPrefix) -> (u16, u8, [u8; 16]) {
    match p {
        IpPrefix::V4(p) => (AF_INET, p.prefix_len(), pad16(&p.addr().octets())),
        IpPrefix::V6(p) => (AF_INET6, p.prefix_len(), p.addr().octets()),
    }
}

fn pad16(b: &[u8]) -> [u8; 16] {
    let mut out = [0u8; 16];
    out[..b.len()].copy_from_slice(b);
    out
}

/// Route-message prefix framing (frr-10.2.2 `zapi_route_encode`):
/// family u8, prefixlen u8, then only `PSIZE(prefixlen)` = (len+7)/8 address
/// bytes — a /24 carries 3 address bytes on the wire. E: both fixtures.
fn put_route_prefix(buf: &mut BytesMut, p: &IpPrefix) {
    let (family, len, addr) = prefix_parts(p);
    buf.put_u8(family as u8);
    buf.put_u8(len);
    buf.put_slice(&addr[..(usize::from(len).div_ceil(8))]);
}

fn take_route_prefix(b: &mut &[u8]) -> Result<IpPrefix, ZapiCodecError> {
    let family = u16::from(take_u8(b)?);
    let len = take_u8(b)?;
    let blen = family_blen(family)?;
    if usize::from(len) > blen * 8 {
        return Err(ZapiCodecError::BadPrefixLen { family, len });
    }
    let psize = usize::from(len).div_ceil(8);
    let addr = take_n(b, psize)?;
    match family {
        AF_INET => {
            let mut a = [0u8; 4];
            a[..psize].copy_from_slice(addr);
            v4_prefix(a, len)
        }
        _ => {
            let mut a = [0u8; 16];
            a[..psize].copy_from_slice(addr);
            v6_prefix(a, len)
        }
    }
}

/// NHT prefix framing (`zclient_send_rnh`, `zebra_send_rnh_update`):
/// family u16, prefixlen u8, full 4/16 address bytes. E: NEXTHOP_REGISTER.
fn put_af_prefix(buf: &mut BytesMut, p: &IpPrefix) {
    let (family, len, addr) = prefix_parts(p);
    buf.put_u16(family);
    buf.put_u8(len);
    let blen = family_blen(family).expect("IpPrefix is always v4/v6");
    buf.put_slice(&addr[..blen]);
}

fn take_af_prefix(b: &mut &[u8]) -> Result<IpPrefix, ZapiCodecError> {
    let family = take_be_u16(b)?;
    let len = take_u8(b)?;
    let blen = family_blen(family)?;
    if usize::from(len) > blen * 8 {
        return Err(ZapiCodecError::BadPrefixLen { family, len });
    }
    let addr = take_n(b, blen)?;
    match family {
        AF_INET => {
            let mut a = [0u8; 4];
            a.copy_from_slice(addr);
            v4_prefix(a, len)
        }
        _ => {
            let mut a = [0u8; 16];
            a.copy_from_slice(addr);
            v6_prefix(a, len)
        }
    }
}

/// Router-id / interface-address prefix framing
/// (`zclient_stream_get_prefix`): family u8, full address bytes, then
/// prefixlen u8. SPEC: not fixture-validated.
fn put_addr_prefix(buf: &mut BytesMut, p: &IpPrefix) {
    let (family, len, addr) = prefix_parts(p);
    buf.put_u8(family as u8);
    let blen = family_blen(family).expect("IpPrefix is always v4/v6");
    buf.put_slice(&addr[..blen]);
    buf.put_u8(len);
}

// ---------------------------------------------------------------------------
// Message bodies
// ---------------------------------------------------------------------------

/// ZEBRA_HELLO (19) body — 8 bytes (`zclient_send_hello`). E: four variants
/// in the fixtures.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ZapiHello {
    /// `redist_default`: route type the client announces. E: staticd=4,
    /// bgpd main=10, bgpd auxiliary client=0x12, bgpd label-manager=10.
    pub redist_default: u8,
    pub instance: u16,
    /// E: 1 only on bgpd's label-manager client.
    pub session_id: u32,
    /// SPEC name (`synchronous` option); E: 1 exactly where session_id=1.
    pub synchronous: u8,
}

impl ZapiHello {
    pub fn decode(body: &[u8]) -> Result<Self, ZapiCodecError> {
        let mut b = body;
        let redist_default = take_u8(&mut b)?;
        let instance = take_be_u16(&mut b)?;
        let session_id = take_be_u32(&mut b)?;
        let synchronous = take_u8(&mut b)?;
        if !b.is_empty() {
            return Err(ZapiCodecError::TrailingBytes(b.len()));
        }
        Ok(Self {
            redist_default,
            instance,
            session_id,
            synchronous,
        })
    }

    pub fn encode(&self, buf: &mut BytesMut) {
        buf.put_u8(self.redist_default);
        buf.put_u16(self.instance);
        buf.put_u32(self.session_id);
        buf.put_u8(self.synchronous);
    }
}

/// ZEBRA_REDISTRIBUTE_ADD/DELETE (12/13) body — `zclient_redistribute_set`:
/// afi u8, route type u8, instance u16. E: bgpd `redistribute static`
/// fixture `01 04 0000`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ZapiRedistribute {
    /// AFI_IP=1 / AFI_IP6=2.
    pub afi: u8,
    /// route_type::* value.
    pub route_type: u8,
    pub instance: u16,
}

impl ZapiRedistribute {
    pub fn decode(body: &[u8]) -> Result<Self, ZapiCodecError> {
        let mut b = body;
        let afi = take_u8(&mut b)?;
        let route_type = take_u8(&mut b)?;
        let instance = take_be_u16(&mut b)?;
        if !b.is_empty() {
            return Err(ZapiCodecError::TrailingBytes(b.len()));
        }
        Ok(Self {
            afi,
            route_type,
            instance,
        })
    }

    pub fn encode(&self, buf: &mut BytesMut) {
        buf.put_u8(self.afi);
        buf.put_u8(self.route_type);
        buf.put_u16(self.instance);
    }
}

/// ZEBRA_NEXTHOP_REGISTER/UNREGISTER (21/22) body — `zclient_send_rnh`:
/// connected u8, resolve_via_default u8, safi u16, then an NHT-framed
/// prefix. E: both register fixtures (11 bytes each).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ZapiNexthopRegister {
    /// E: staticd=0 (gateway NHT), bgpd=1 (neighbor NHT).
    pub connected: bool,
    /// SPEC name from `zclient_send_rnh`; 0 in both fixtures.
    pub resolve_via_default: bool,
    /// E: 1 (SAFI_UNICAST) in both fixtures.
    pub safi: u16,
    /// E: 192.0.2.1/32 (staticd), 10.9.9.9/32 (bgpd).
    pub prefix: IpPrefix,
}

impl ZapiNexthopRegister {
    pub fn decode(body: &[u8]) -> Result<Self, ZapiCodecError> {
        let mut b = body;
        let connected = take_u8(&mut b)? != 0;
        let resolve_via_default = take_u8(&mut b)? != 0;
        let safi = take_be_u16(&mut b)?;
        let prefix = take_af_prefix(&mut b)?;
        if !b.is_empty() {
            return Err(ZapiCodecError::TrailingBytes(b.len()));
        }
        Ok(Self {
            connected,
            resolve_via_default,
            safi,
            prefix,
        })
    }

    pub fn encode(&self, buf: &mut BytesMut) {
        buf.put_u8(u8::from(self.connected));
        buf.put_u8(u8::from(self.resolve_via_default));
        buf.put_u16(self.safi);
        put_af_prefix(buf, &self.prefix);
    }
}

/// One wire nexthop (`zapi_nexthop_encode`, frr-10.2.2): vrf_id u32, type
/// u8, flags u8, type-specific fields, then flag-gated extras.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ZapiNexthop {
    /// The nexthop's own VRF. E: 0 in the fixture; leads the encoding.
    pub vrf_id: u32,
    /// nexthop_type::*. E: 6 (BLACKHOLE) in the fixture.
    pub nh_type: u8,
    /// nexthop_flag::*. E: 0 in the fixture.
    pub flags: u8,
    /// Present for IPV4/IPV6 forms (with or without ifindex).
    pub gate: Option<IpAddr>,
    /// Encoded for IFINDEX and both IPV4/IPV6 forms; 0 for BLACKHOLE.
    pub ifindex: u32,
    /// blackhole_type::*; BLACKHOLE only. E: 1 (REJECT) in the fixture.
    pub bh_type: u8,
    /// The flag-gated extras (labels, weight u64, EVPN RMAC, SRTE color,
    /// backup indices, SRv6 segments) in wire order, preserved verbatim —
    /// decoded with exact widths so lists stay in sync. No fixture carries
    /// any. SPEC: contents undecoded.
    pub tail: Vec<u8>,
}

impl ZapiNexthop {
    pub fn new_blackhole(vrf_id: u32, bh_type: u8) -> Self {
        Self {
            vrf_id,
            nh_type: nexthop_type::BLACKHOLE,
            flags: 0,
            gate: None,
            ifindex: 0,
            bh_type,
            tail: Vec::new(),
        }
    }

    pub fn new_ifindex(vrf_id: u32, ifindex: u32) -> Self {
        Self {
            vrf_id,
            nh_type: nexthop_type::IFINDEX,
            flags: 0,
            gate: None,
            ifindex,
            bh_type: 0,
            tail: Vec::new(),
        }
    }

    pub fn new_ipv4(vrf_id: u32, gate: Ipv4Addr) -> Self {
        Self {
            vrf_id,
            nh_type: nexthop_type::IPV4,
            flags: 0,
            gate: Some(gate.into()),
            ifindex: 0,
            bh_type: 0,
            tail: Vec::new(),
        }
    }

    pub fn new_ipv4_ifindex(vrf_id: u32, gate: Ipv4Addr, ifindex: u32) -> Self {
        Self {
            vrf_id,
            nh_type: nexthop_type::IPV4_IFINDEX,
            flags: 0,
            gate: Some(gate.into()),
            ifindex,
            bh_type: 0,
            tail: Vec::new(),
        }
    }

    pub fn new_ipv6(vrf_id: u32, gate: Ipv6Addr) -> Self {
        Self {
            vrf_id,
            nh_type: nexthop_type::IPV6,
            flags: 0,
            gate: Some(gate.into()),
            ifindex: 0,
            bh_type: 0,
            tail: Vec::new(),
        }
    }

    pub fn new_ipv6_ifindex(vrf_id: u32, gate: Ipv6Addr, ifindex: u32) -> Self {
        Self {
            vrf_id,
            nh_type: nexthop_type::IPV6_IFINDEX,
            flags: 0,
            gate: Some(gate.into()),
            ifindex,
            bh_type: 0,
            tail: Vec::new(),
        }
    }

    /// Sets the WEIGHT flag, prepending the u64 weight to `tail` — the
    /// correct wire position when no labels precede it. SPEC.
    pub fn set_weight(&mut self, weight: u64) {
        let mut tail = BytesMut::with_capacity(8 + self.tail.len());
        tail.put_u64(weight);
        tail.extend_from_slice(&self.tail);
        self.tail = tail.to_vec();
        self.flags |= nexthop_flag::WEIGHT;
    }

    /// `message` is the enclosing message's `ZAPI_MESSAGE_*` bitmask: the
    /// SRTE color field inside a nexthop is gated by the message bits, not
    /// the nexthop's own flags (`zapi_nexthop_encode(s, api_nh, message)`).
    pub fn decode(b: &mut &[u8], message: u32) -> Result<Self, ZapiCodecError> {
        let vrf_id = take_be_u32(b)?;
        let nh_type = take_u8(b)?;
        let flags = take_u8(b)?;
        let (gate, ifindex, bh_type) = match nh_type {
            nexthop_type::BLACKHOLE => {
                let bh_type = take_u8(b)?;
                (None, 0, bh_type)
            }
            nexthop_type::IFINDEX => {
                let ifindex = take_be_u32(b)?;
                (None, ifindex, 0)
            }
            nexthop_type::IPV4 | nexthop_type::IPV4_IFINDEX => {
                let raw = take_n(b, 4)?;
                let mut a = [0u8; 4];
                a.copy_from_slice(raw);
                let ifindex = take_be_u32(b)?;
                (Some(IpAddr::V4(Ipv4Addr::from(a))), ifindex, 0)
            }
            nexthop_type::IPV6 | nexthop_type::IPV6_IFINDEX => {
                let raw = take_n(b, 16)?;
                let mut a = [0u8; 16];
                a.copy_from_slice(raw);
                let ifindex = take_be_u32(b)?;
                (Some(IpAddr::V6(Ipv6Addr::from(a))), ifindex, 0)
            }
            other => return Err(ZapiCodecError::BadNexthopType(other)),
        };
        // Flag-gated extras are consumed structurally (exact widths from
        // the 10.2.2 encoder, in wire order: labels, weight, EVPN RMAC,
        // SRTE color, backup indices, SRv6 segments) and preserved raw in
        // `tail`, so nexthop lists stop at the right boundary and encode
        // stays byte-identical. SEG6LOCAL has a variable-length context and
        // is rejected loudly instead of mis-sized.
        let mut tail = Vec::new();
        if flags & nexthop_flag::LABEL != 0 {
            let label_num = take_u8(b)?;
            let label_type = take_u8(b)?;
            tail.push(label_num);
            tail.push(label_type);
            tail.extend_from_slice(take_n(b, 3 * usize::from(label_num))?);
        }
        if flags & nexthop_flag::WEIGHT != 0 {
            tail.extend_from_slice(take_n(b, 8)?);
        }
        if flags & nexthop_flag::EVPN != 0 {
            tail.extend_from_slice(take_n(b, 6)?);
        }
        if message & message_flag::SRTE != 0 {
            tail.extend_from_slice(take_n(b, 4)?);
        }
        if flags & nexthop_flag::HAS_BACKUP != 0 {
            let backup_num = take_u8(b)?;
            tail.push(backup_num);
            tail.extend_from_slice(take_n(b, usize::from(backup_num))?);
        }
        if flags & nexthop_flag::SEG6LOCAL != 0 {
            return Err(ZapiCodecError::UnsupportedNexthopFlags(flags));
        }
        if flags & nexthop_flag::SEG6 != 0 {
            let seg_num = take_u8(b)?;
            tail.push(seg_num);
            tail.extend_from_slice(take_n(b, 16 * usize::from(seg_num))?);
        }
        Ok(Self {
            vrf_id,
            nh_type,
            flags,
            gate,
            ifindex,
            bh_type,
            tail,
        })
    }

    pub fn encode(&self, buf: &mut BytesMut) {
        buf.put_u32(self.vrf_id);
        buf.put_u8(self.nh_type);
        buf.put_u8(self.flags);
        match self.nh_type {
            nexthop_type::BLACKHOLE => buf.put_u8(self.bh_type),
            nexthop_type::IFINDEX => buf.put_u32(self.ifindex),
            nexthop_type::IPV4 | nexthop_type::IPV4_IFINDEX => {
                match self.gate {
                    Some(IpAddr::V4(gate)) => buf.put_slice(&gate.octets()),
                    _ => buf.put_slice(&[0u8; 4]),
                }
                buf.put_u32(self.ifindex);
            }
            nexthop_type::IPV6 | nexthop_type::IPV6_IFINDEX => {
                match self.gate {
                    Some(IpAddr::V6(gate)) => buf.put_slice(&gate.octets()),
                    _ => buf.put_slice(&[0u8; 16]),
                }
                buf.put_u32(self.ifindex);
            }
            _ => unreachable!("decode/constructors constrain nh_type to 1..=6"),
        }
        buf.put_slice(&self.tail);
    }

    /// Maps onto the internal model. Returns None for gate-less v4/v6
    /// forms (which cannot occur via [`ZapiNexthop::decode`]).
    pub fn to_common(&self) -> Option<CommonNexthop> {
        let hop = match (self.nh_type, self.gate) {
            (nexthop_type::BLACKHOLE, _) => CommonNexthop::Blackhole,
            (nexthop_type::IFINDEX, _) => CommonNexthop::IfIndex(self.ifindex),
            (nexthop_type::IPV4, Some(IpAddr::V4(g))) => CommonNexthop::Ipv4(g),
            (nexthop_type::IPV4_IFINDEX, Some(IpAddr::V4(g))) => {
                CommonNexthop::Ipv4If(g, self.ifindex)
            }
            (nexthop_type::IPV6, Some(IpAddr::V6(g))) => CommonNexthop::Ipv6(g),
            (nexthop_type::IPV6_IFINDEX, Some(IpAddr::V6(g))) => {
                CommonNexthop::Ipv6If(g, self.ifindex)
            }
            _ => return None,
        };
        Some(hop)
    }

    /// Maps an internal hop onto the wire shape (the inverse of
    /// [`ZapiNexthop::to_common`]); vrf 0, no extras. A `Blackhole` hop
    /// becomes the REJECT form — what FRR staticd sends for
    /// `ip route <pfx> blackhole`.
    pub fn from_common(hop: CommonNexthop) -> Self {
        match hop {
            CommonNexthop::Ipv4(gate) => Self::new_ipv4(0, gate),
            CommonNexthop::Ipv6(gate) => Self::new_ipv6(0, gate),
            CommonNexthop::IfIndex(ifindex) => Self::new_ifindex(0, ifindex),
            CommonNexthop::Ipv4If(gate, ifindex) => Self::new_ipv4_ifindex(0, gate, ifindex),
            CommonNexthop::Ipv6If(gate, ifindex) => Self::new_ipv6_ifindex(0, gate, ifindex),
            CommonNexthop::Blackhole => Self::new_blackhole(0, blackhole_type::REJECT),
        }
    }
}

/// ZEBRA_ROUTE_ADD/DELETE (9/10) body — `zapi_route_encode`
/// (frr-10.2.2). E: the staticd blackhole add and reconnect delete
/// fixtures decode exactly; gated fields beyond those are SPEC.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ZapiRoute {
    /// route_type::*. E: 4 (STATIC).
    pub route_type: u8,
    pub instance: u16,
    /// ZEBRA_FLAG_* (zclient.h). E: 0x41 = ALLOW_RECURSION | RR_USE_DISTANCE
    /// — NOT the classic INTERNAL|STATIC reading; 10.2.2 renumbered flags.
    pub flags: u32,
    /// message_flag::* bitmask selecting the optional tail fields.
    /// E: 0x03 = NEXTHOP | DISTANCE in both fixtures.
    pub message: u32,
    /// E: 1 (SAFI_UNICAST).
    pub safi: u8,
    /// E: 203.0.113.0/24 (add), 198.51.100.0/24 (delete). Address bytes on
    /// the wire are PSIZE(plen)-sized (3 bytes for a /24).
    pub prefix: IpPrefix,
    /// SPEC (ZAPI_MESSAGE_SRCPFX, IPv6 only).
    pub src_prefix: Option<IpPrefix>,
    /// SPEC (ZAPI_MESSAGE_NHG): nexthop-group id.
    pub nhg_id: u32,
    /// E: one BLACKHOLE nexthop in the add fixture; empty for the delete
    /// (count 0 — the NEXTHOP bit stays set).
    pub nexthops: Vec<ZapiNexthop>,
    /// SPEC (ZAPI_MESSAGE_BACKUP_NEXTHOPS).
    pub backup_nexthops: Vec<ZapiNexthop>,
    /// E: 1 in both fixtures (staticd's default static distance).
    pub distance: Option<u8>,
    pub metric: Option<u32>,
    pub tag: Option<u32>,
    pub mtu: Option<u32>,
    pub tableid: Option<u32>,
    /// SPEC (ZAPI_MESSAGE_OPAQUE): length u16 + bytes.
    pub opaque: Option<Vec<u8>>,
}

impl ZapiRoute {
    pub fn decode(body: &[u8]) -> Result<Self, ZapiCodecError> {
        let mut b = body;
        let route_type = take_u8(&mut b)?;
        let instance = take_be_u16(&mut b)?;
        let flags = take_be_u32(&mut b)?;
        let message = take_be_u32(&mut b)?;
        let safi = take_u8(&mut b)?;
        let prefix = take_route_prefix(&mut b)?;

        let src_prefix = if message & message_flag::SRCPFX != 0 {
            let len = take_u8(&mut b)?;
            let psize = usize::from(len).div_ceil(8);
            let addr = take_n(&mut b, psize)?;
            match prefix {
                IpPrefix::V4(_) => {
                    let mut a = [0u8; 4];
                    a[..psize.min(4)].copy_from_slice(&addr[..psize.min(4)]);
                    v4_prefix(a, len).ok()
                }
                IpPrefix::V6(_) => {
                    let mut a = [0u8; 16];
                    a[..psize.min(16)].copy_from_slice(&addr[..psize.min(16)]);
                    v6_prefix(a, len).ok()
                }
            }
        } else {
            None
        };

        let nhg_id = if message & message_flag::NHG != 0 {
            take_be_u32(&mut b)?
        } else {
            0
        };

        let nexthops = if message & message_flag::NEXTHOP != 0 {
            take_nexthop_list(&mut b, message)?
        } else {
            Vec::new()
        };
        let backup_nexthops = if message & message_flag::BACKUP_NEXTHOPS != 0 {
            take_nexthop_list(&mut b, message)?
        } else {
            Vec::new()
        };

        let distance = (message & message_flag::DISTANCE != 0)
            .then(|| take_u8(&mut b))
            .transpose()?;
        let metric = (message & message_flag::METRIC != 0)
            .then(|| take_be_u32(&mut b))
            .transpose()?;
        let tag = (message & message_flag::TAG != 0)
            .then(|| take_be_u32(&mut b))
            .transpose()?;
        let mtu = (message & message_flag::MTU != 0)
            .then(|| take_be_u32(&mut b))
            .transpose()?;
        let tableid = (message & message_flag::TABLEID != 0)
            .then(|| take_be_u32(&mut b))
            .transpose()?;
        let opaque = if message & message_flag::OPAQUE != 0 {
            let len = take_be_u16(&mut b)? as usize;
            Some(take_n(&mut b, len)?.to_vec())
        } else {
            None
        };

        if !b.is_empty() {
            return Err(ZapiCodecError::TrailingBytes(b.len()));
        }

        Ok(Self {
            route_type,
            instance,
            flags,
            message,
            safi,
            prefix,
            src_prefix,
            nhg_id,
            nexthops,
            backup_nexthops,
            distance,
            metric,
            tag,
            mtu,
            tableid,
            opaque,
        })
    }

    pub fn encode(&self, buf: &mut BytesMut) {
        buf.put_u8(self.route_type);
        buf.put_u16(self.instance);
        buf.put_u32(self.flags);
        buf.put_u32(self.message);
        buf.put_u8(self.safi);
        put_route_prefix(buf, &self.prefix);

        let message = self.message;
        if message & message_flag::SRCPFX != 0 {
            if let Some(src) = &self.src_prefix {
                let (_, len, addr) = prefix_parts(src);
                buf.put_u8(len);
                buf.put_slice(&addr[..(usize::from(len).div_ceil(8))]);
            }
        }
        if message & message_flag::NHG != 0 {
            buf.put_u32(self.nhg_id);
        }
        if message & message_flag::NEXTHOP != 0 {
            buf.put_u16(self.nexthops.len() as u16);
            for nh in &self.nexthops {
                nh.encode(buf);
            }
        }
        if message & message_flag::BACKUP_NEXTHOPS != 0 {
            buf.put_u16(self.backup_nexthops.len() as u16);
            for nh in &self.backup_nexthops {
                nh.encode(buf);
            }
        }
        if message & message_flag::DISTANCE != 0 {
            buf.put_u8(self.distance.unwrap_or(0));
        }
        if message & message_flag::METRIC != 0 {
            buf.put_u32(self.metric.unwrap_or(0));
        }
        if message & message_flag::TAG != 0 {
            buf.put_u32(self.tag.unwrap_or(0));
        }
        if message & message_flag::MTU != 0 {
            buf.put_u32(self.mtu.unwrap_or(0));
        }
        if message & message_flag::TABLEID != 0 {
            buf.put_u32(self.tableid.unwrap_or(0));
        }
        if message & message_flag::OPAQUE != 0 {
            let opaque = self.opaque.clone().unwrap_or_default();
            buf.put_u16(opaque.len() as u16);
            buf.put_slice(&opaque);
        }
    }

    /// ZEBRA_ROUTE_* number to the internal protocol enum. 4 (STATIC) and
    /// 10 (BGP) are E; the rest are SPEC per the 10.2.2 numbering.
    pub fn route_protocol(route_type: u8) -> Option<RouteProtocol> {
        match route_type {
            route_type::SYSTEM | route_type::KERNEL => Some(RouteProtocol::Kernel),
            route_type::CONNECT => Some(RouteProtocol::Connected),
            route_type::LOCAL => Some(RouteProtocol::Local),
            route_type::STATIC => Some(RouteProtocol::Static),
            route_type::RIP | route_type::RIPNG => Some(RouteProtocol::Rip),
            route_type::OSPF | route_type::OSPF6 => Some(RouteProtocol::Ospf),
            route_type::ISIS => Some(RouteProtocol::IsIs),
            route_type::BGP => Some(RouteProtocol::Bgp),
            _ => None,
        }
    }

    /// The internal protocol for this route, None for unmapped types.
    pub fn protocol(&self) -> Option<RouteProtocol> {
        Self::route_protocol(self.route_type)
    }

    /// Maps the route into the internal model. Returns None when the route
    /// type or any nexthop has no internal equivalent. Distance/tag have no
    /// RouteEntry slot yet; metric defaults to 0.
    pub fn to_route_entry(&self) -> Option<RouteEntry> {
        let protocol = self.protocol()?;
        let mut group = NexthopGroup::new();
        for nh in &self.nexthops {
            group.add(nh.to_common()?, 1);
        }
        Some(RouteEntry::new(
            self.prefix,
            protocol,
            group,
            self.metric.unwrap_or(0),
        ))
    }

    /// Builds the route body zebra pushes for
    /// ZEBRA_REDISTRIBUTE_ROUTE_ADD (31), mirroring
    /// `zsend_redistribute_route` (frr-10.2.2 `zebra/zapi_msg.c`):
    /// SAFI is always unicast; the DISTANCE, METRIC and MTU message bits
    /// are always set (fields included even when zero); the TAG bit is set
    /// only for a non-zero tag; the NEXTHOP bit and list are present only
    /// when the route has at least one (active) nexthop. `flags` carries
    /// the route's ZEBRA_FLAG_* bits (zebra passes `re->flags` through,
    /// e.g. SELECTED for the best path). SPEC: source-verified, not yet
    /// wire-captured.
    #[allow(clippy::too_many_arguments)]
    pub fn redistribute_push(
        route_type: u8,
        instance: u16,
        flags: u32,
        prefix: IpPrefix,
        nexthops: Vec<ZapiNexthop>,
        distance: u8,
        metric: u32,
        tag: u32,
        mtu: u32,
    ) -> Self {
        let mut message = message_flag::DISTANCE | message_flag::METRIC | message_flag::MTU;
        if !nexthops.is_empty() {
            message |= message_flag::NEXTHOP;
        }
        if tag != 0 {
            message |= message_flag::TAG;
        }
        Self {
            route_type,
            instance,
            flags,
            message,
            safi: 1, // SAFI_UNICAST — zsend_redistribute_route hardcodes it
            prefix,
            src_prefix: None,
            nhg_id: 0,
            nexthops,
            backup_nexthops: Vec::new(),
            distance: Some(distance),
            metric: Some(metric),
            tag: (tag != 0).then_some(tag),
            mtu: Some(mtu),
            tableid: None,
            opaque: None,
        }
    }
}

/// Reads a u16-counted nexthop list; `message` is the enclosing
/// ZAPI_MESSAGE_* bitmask (it gates the per-nexthop SRTE field).
fn take_nexthop_list(b: &mut &[u8], message: u32) -> Result<Vec<ZapiNexthop>, ZapiCodecError> {
    let count = take_be_u16(b)?;
    let mut hops = Vec::with_capacity(count.min(256) as usize);
    for _ in 0..count {
        hops.push(ZapiNexthop::decode(b, message)?);
    }
    Ok(hops)
}

/// ZEBRA_INTERFACE_ADD/DELETE (0/1) zebra→client body — mirrored from
/// `zebra_interface_state_read` (frr-10.2.2 `lib/zclient.c`); the layout
/// diagram in that file is stale, this is what 10.2.2 actually parses.
/// SPEC: no fixture yet (our masquerade never answered INTERFACE_ADD).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ZapiInterface {
    /// Exactly `ZAPI_IFNAMSIZ` bytes on the wire, NUL padded.
    pub ifname: String,
    pub ifindex: u32,
    pub status: u8,
    /// ZEBRA_INTERFACE_* status bits (u64 on the wire).
    pub flags: u64,
    pub ptm_enable: u8,
    pub ptm_status: u8,
    pub metric: u32,
    pub speed: u32,
    pub txqlen: u32,
    pub mtu: u32,
    pub mtu6: u32,
    pub bandwidth: u32,
    pub link_ifindex: u32,
    pub ll_type: u32,
    /// Wire carries `hw_addr_len u32` then min(len, 20) bytes; the original
    /// length is kept so encode is byte-identical.
    pub hw_addr_len: u32,
    pub hw_addr: Vec<u8>,
    /// link_params_status u8 followed by the (undecoded) link-params blob,
    /// preserved raw. 0/empty for ordinary interfaces.
    pub link_params_status: u8,
    pub link_params: Vec<u8>,
}

impl Default for ZapiInterface {
    fn default() -> Self {
        Self {
            ifname: String::new(),
            ifindex: 0,
            status: 0,
            flags: 0,
            ptm_enable: 0,
            ptm_status: 0,
            metric: 0,
            speed: 0,
            txqlen: 0,
            mtu: 1500,
            mtu6: 1500,
            bandwidth: 0,
            link_ifindex: 0,
            ll_type: 0,
            hw_addr_len: 0,
            hw_addr: Vec::new(),
            link_params_status: 0,
            link_params: Vec::new(),
        }
    }
}

impl ZapiInterface {
    pub fn new(ifname: &str, ifindex: u32) -> Self {
        Self {
            ifname: ifname.to_string(),
            ifindex,
            ..Self::default()
        }
    }

    pub fn decode(body: &[u8]) -> Result<Self, ZapiCodecError> {
        let mut b = body;
        let raw_name = take_n(&mut b, ZAPI_IFNAMSIZ)?;
        let name_end = raw_name
            .iter()
            .position(|&c| c == 0)
            .unwrap_or(raw_name.len());
        let ifname = String::from_utf8_lossy(&raw_name[..name_end]).into_owned();
        let ifindex = take_be_u32(&mut b)?;
        let status = take_u8(&mut b)?;
        let flags = take_be_u64(&mut b)?;
        let ptm_enable = take_u8(&mut b)?;
        let ptm_status = take_u8(&mut b)?;
        let metric = take_be_u32(&mut b)?;
        let speed = take_be_u32(&mut b)?;
        let txqlen = take_be_u32(&mut b)?;
        let mtu = take_be_u32(&mut b)?;
        let mtu6 = take_be_u32(&mut b)?;
        let bandwidth = take_be_u32(&mut b)?;
        let link_ifindex = take_be_u32(&mut b)?;
        let ll_type = take_be_u32(&mut b)?;
        let hw_addr_len = take_be_u32(&mut b)?;
        let hw_addr = take_n(&mut b, (hw_addr_len as usize).min(ZAPI_HWADDR_MAX))?.to_vec();
        let link_params_status = take_u8(&mut b)?;
        let link_params = b.to_vec();
        Ok(Self {
            ifname,
            ifindex,
            status,
            flags,
            ptm_enable,
            ptm_status,
            metric,
            speed,
            txqlen,
            mtu,
            mtu6,
            bandwidth,
            link_ifindex,
            ll_type,
            hw_addr_len,
            hw_addr,
            link_params_status,
            link_params,
        })
    }

    pub fn encode(&self, buf: &mut BytesMut) -> Result<(), ZapiCodecError> {
        let name = self.ifname.as_bytes();
        if name.len() > ZAPI_IFNAMSIZ {
            return Err(ZapiCodecError::NameTooLong {
                len: name.len(),
                max: ZAPI_IFNAMSIZ,
            });
        }
        let mut wire_name = [0u8; ZAPI_IFNAMSIZ];
        wire_name[..name.len()].copy_from_slice(name);
        buf.put_slice(&wire_name);
        buf.put_u32(self.ifindex);
        buf.put_u8(self.status);
        buf.put_u64(self.flags);
        buf.put_u8(self.ptm_enable);
        buf.put_u8(self.ptm_status);
        buf.put_u32(self.metric);
        buf.put_u32(self.speed);
        buf.put_u32(self.txqlen);
        buf.put_u32(self.mtu);
        buf.put_u32(self.mtu6);
        buf.put_u32(self.bandwidth);
        buf.put_u32(self.link_ifindex);
        buf.put_u32(self.ll_type);
        buf.put_u32(self.hw_addr_len);
        buf.put_slice(&self.hw_addr);
        buf.put_u8(self.link_params_status);
        buf.put_slice(&self.link_params);
        Ok(())
    }
}

/// ZEBRA_INTERFACE_ADDRESS_ADD/DELETE (2/3) zebra→client body — mirrored
/// from `zebra_interface_address_read`: ifindex u32, flags u8, family u8,
/// address bytes, prefixlen u8 (address BEFORE length), destination
/// address (all-zero = None). SPEC: no fixture yet.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ZapiInterfaceAddress {
    pub ifindex: u32,
    /// ZEBRA_INTERFACE_SECONDARY etc.
    pub flags: u8,
    pub address: IpPrefix,
    /// Peer/broadcast address; the wire always carries 4/16 bytes.
    pub destination: Option<IpAddr>,
}

impl ZapiInterfaceAddress {
    pub fn decode(body: &[u8]) -> Result<Self, ZapiCodecError> {
        let mut b = body;
        let ifindex = take_be_u32(&mut b)?;
        let flags = take_u8(&mut b)?;
        let family = u16::from(take_u8(&mut b)?);
        let blen = family_blen(family)?;
        let addr = take_n(&mut b, blen)?;
        let len = take_u8(&mut b)?;
        if usize::from(len) > blen * 8 {
            return Err(ZapiCodecError::BadPrefixLen { family, len });
        }
        let prefix = match family {
            AF_INET => {
                let mut a = [0u8; 4];
                a.copy_from_slice(addr);
                v4_prefix(a, len)?
            }
            _ => {
                let mut a = [0u8; 16];
                a.copy_from_slice(addr);
                v6_prefix(a, len)?
            }
        };
        let dst_raw = take_n(&mut b, blen)?;
        let all_zero = dst_raw.iter().all(|&x| x == 0);
        let destination = match family {
            AF_INET => {
                let mut a = [0u8; 4];
                a.copy_from_slice(dst_raw);
                (!all_zero).then(|| IpAddr::V4(Ipv4Addr::from(a)))
            }
            _ => {
                let mut a = [0u8; 16];
                a.copy_from_slice(dst_raw);
                (!all_zero).then(|| IpAddr::V6(Ipv6Addr::from(a)))
            }
        };
        if !b.is_empty() {
            return Err(ZapiCodecError::TrailingBytes(b.len()));
        }
        Ok(Self {
            ifindex,
            flags,
            address: prefix,
            destination,
        })
    }

    pub fn encode(&self, buf: &mut BytesMut) {
        buf.put_u32(self.ifindex);
        buf.put_u8(self.flags);
        put_addr_prefix(buf, &self.address);
        let blen = match self.address {
            IpPrefix::V4(_) => 4,
            IpPrefix::V6(_) => 16,
        };
        match self.destination {
            Some(IpAddr::V4(d)) => buf.put_slice(&d.octets()),
            Some(IpAddr::V6(d)) => buf.put_slice(&d.octets()),
            None => buf.put_slice(&[0u8; 16][..blen]),
        }
    }
}

/// ZEBRA_NEXTHOP_UPDATE (23) zebra→client body — mirrored from
/// `zebra_send_rnh_update` (frr-10.2.2 `zebra/zebra_rnh.c`): message u32,
/// safi u16, registered prefix (NHT framing), resolved prefix, [srte_color],
/// then route_type/instance/distance/metric and a u8 count of nexthops.
/// When the nexthop is unresolved zebra sends zeros for the tail fields.
/// SPEC: no fixture yet — the reply Z3 must emit to NHT registers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ZapiNexthopUpdate {
    /// message_flag::*; only SRTE adds a field here.
    pub message: u32,
    pub safi: u16,
    /// The prefix the client registered (E: seen inside NEXTHOP_REGISTER).
    pub registered_prefix: IpPrefix,
    /// The covering resolved prefix; zebra echoes the registered prefix
    /// when unresolved.
    pub resolved_prefix: IpPrefix,
    /// Present iff ZAPI_MESSAGE_SRTE.
    pub srte_color: Option<u32>,
    /// Resolved route type (0 when unresolved).
    pub route_type: u8,
    pub instance: u16,
    pub distance: u8,
    pub metric: u32,
    pub nexthops: Vec<ZapiNexthop>,
}

impl ZapiNexthopUpdate {
    /// A resolved reply over `hops` (metric/distance from the RIB).
    #[allow(clippy::too_many_arguments)]
    pub fn resolved(
        registered: IpPrefix,
        safi: u16,
        route_type: u8,
        metric: u32,
        distance: u8,
        hops: Vec<ZapiNexthop>,
    ) -> Self {
        Self {
            message: 0,
            safi,
            registered_prefix: registered,
            resolved_prefix: registered,
            srte_color: None,
            route_type,
            instance: 0,
            distance,
            metric,
            nexthops: hops,
        }
    }

    /// The unresolved form zebra sends for still-tracking prefixes
    /// (zeroed tail fields).
    pub fn unresolved(registered: IpPrefix, safi: u16) -> Self {
        Self {
            message: 0,
            safi,
            registered_prefix: registered,
            resolved_prefix: registered,
            srte_color: None,
            route_type: 0,
            instance: 0,
            distance: 0,
            metric: 0,
            nexthops: Vec::new(),
        }
    }

    /// True when this update carries a usable resolution.
    pub fn is_resolved(&self) -> bool {
        self.route_type != 0 || !self.nexthops.is_empty()
    }

    pub fn decode(body: &[u8]) -> Result<Self, ZapiCodecError> {
        let mut b = body;
        let message = take_be_u32(&mut b)?;
        let safi = take_be_u16(&mut b)?;
        let registered_prefix = take_af_prefix(&mut b)?;
        let resolved_prefix = take_af_prefix(&mut b)?;
        let srte_color = if message & message_flag::SRTE != 0 {
            Some(take_be_u32(&mut b)?)
        } else {
            None
        };
        let route_type = take_u8(&mut b)?;
        let instance = take_be_u16(&mut b)?;
        let distance = take_u8(&mut b)?;
        let metric = take_be_u32(&mut b)?;
        let count = take_u8(&mut b)?;
        let mut nexthops = Vec::with_capacity(usize::from(count));
        for _ in 0..count {
            nexthops.push(ZapiNexthop::decode(&mut b, message)?);
        }
        if !b.is_empty() {
            return Err(ZapiCodecError::TrailingBytes(b.len()));
        }
        Ok(Self {
            message,
            safi,
            registered_prefix,
            resolved_prefix,
            srte_color,
            route_type,
            instance,
            distance,
            metric,
            nexthops,
        })
    }

    pub fn encode(&self, buf: &mut BytesMut) {
        buf.put_u32(self.message);
        buf.put_u16(self.safi);
        put_af_prefix(buf, &self.registered_prefix);
        put_af_prefix(buf, &self.resolved_prefix);
        if self.message & message_flag::SRTE != 0 {
            buf.put_u32(self.srte_color.unwrap_or(0));
        }
        buf.put_u8(self.route_type);
        buf.put_u16(self.instance);
        buf.put_u8(self.distance);
        buf.put_u32(self.metric);
        buf.put_u8(self.nexthops.len() as u8);
        for nh in &self.nexthops {
            nh.encode(buf);
        }
    }
}

/// ZEBRA_NEIGH_REGISTER (131) / NEIGH_UNREGISTER (132) body — `afi` u16,
/// exactly (frr-10.2.2 `lib/zclient.c` `zclient_register_neigh`,
/// source-pinned from the cached copy; acceptance wire-proven by the M4
/// capture: a `0001` registration earned NEIGH_ADDED pushes).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ZapiNeighRegister {
    pub afi: u16,
}

impl ZapiNeighRegister {
    pub fn decode(body: &[u8]) -> Result<Self, ZapiCodecError> {
        let mut b = body;
        let afi = take_be_u16(&mut b)?;
        if !b.is_empty() {
            return Err(ZapiCodecError::TrailingBytes(b.len()));
        }
        Ok(Self { afi })
    }

    pub fn encode(&self, buf: &mut BytesMut) {
        buf.put_u16(self.afi);
    }
}

/// ZEBRA_NEIGH_ADDED (128) / NEIGH_REMOVED (129) body — the
/// `zclient_neigh_ip_encode` shape, wire-pinned by the M4 capture
/// (docs/interop/zapi-10.2-pinned.md, M4 addendum):
/// family(in) u8 | ip.addr 4/16 | family(out) u8 (2 when a link-layer
/// exists, 0 = AF_UNSPEC otherwise) | out.addr FOUR bytes — the v4-sized
/// sockunion body carries only the first 4 bytes of the 6-byte MAC, a
/// real FRR quirk (replace frames for ...:99 and ...:aa are
/// byte-identical) | ip_len u32 BE (6 with a MAC, 0 without) | ifindex
/// u32 BE | ndm_state u32 BE (NUD value; REMOVED hardcodes FAILED 0x20,
/// the encoder's `out == NULL` branch).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ZapiNeighNotify {
    pub ip: IpAddr,
    /// The first 4 bytes of the link-layer address when one exists.
    pub link_layer: Option<[u8; 4]>,
    /// The link-layer's TRUE length (6 for a MAC) when one exists.
    pub ip_len: u32,
    pub ifindex: u32,
    /// NUD state bits; `ZEBRA_NEIGH_STATE_FAILED` (0x20) for REMOVED.
    pub ndm_state: u32,
}

/// `ZEBRA_NEIGH_STATE_FAILED` (lib/zclient.h NUD-mapped constants).
pub const ZEBRA_NEIGH_STATE_FAILED: u32 = 0x20;

impl ZapiNeighNotify {
    /// The ADDED flavour for a neighbour holding a link-layer address.
    pub fn added(ip: IpAddr, lladdr: &[u8], ifindex: u32, ndm_state: u32) -> Self {
        let mut prefix = [0u8; 4];
        for (i, b) in lladdr.iter().take(4).enumerate() {
            prefix[i] = *b;
        }
        Self {
            ip,
            link_layer: Some(prefix),
            ip_len: lladdr.len() as u32,
            ifindex,
            ndm_state,
        }
    }

    /// The no-link-layer flavour: an INCOMPLETE/FAILED ADDED, or the
    /// REMOVED twin (which hardcodes ndm FAILED per the encoder).
    pub fn without_link_layer(ip: IpAddr, ifindex: u32, ndm_state: u32) -> Self {
        Self {
            ip,
            link_layer: None,
            ip_len: 0,
            ifindex,
            ndm_state,
        }
    }

    pub fn decode(body: &[u8]) -> Result<Self, ZapiCodecError> {
        let mut b = body;
        let family = take_u8(&mut b)?;
        let ip = match family {
            2 => {
                let raw = take_n(&mut b, 4)?;
                let mut a = [0u8; 4];
                a.copy_from_slice(raw);
                IpAddr::V4(Ipv4Addr::from(a))
            }
            10 => {
                let raw = take_n(&mut b, 16)?;
                let mut a = [0u8; 16];
                a.copy_from_slice(raw);
                IpAddr::V6(Ipv6Addr::from(a))
            }
            other => return Err(ZapiCodecError::BadFamily(u16::from(other))),
        };
        let out_family = take_u8(&mut b)?;
        let link_layer = if out_family != 0 {
            let raw = take_n(&mut b, 4)?;
            let mut a = [0u8; 4];
            a.copy_from_slice(raw);
            Some(a)
        } else {
            None
        };
        let ip_len = take_be_u32(&mut b)?;
        let ifindex = take_be_u32(&mut b)?;
        let ndm_state = take_be_u32(&mut b)?;
        if !b.is_empty() {
            return Err(ZapiCodecError::TrailingBytes(b.len()));
        }
        Ok(Self {
            ip,
            link_layer,
            ip_len,
            ifindex,
            ndm_state,
        })
    }

    pub fn encode(&self, buf: &mut BytesMut) {
        let (family, addr): (u8, &[u8]) = match self.ip {
            IpAddr::V4(a) => (2, &a.octets()),
            IpAddr::V6(a) => (10, &a.octets()),
        };
        buf.put_u8(family);
        buf.put_slice(addr);
        match self.link_layer {
            Some(four) => {
                buf.put_u8(2); // the sockunion carries AF_INET
                buf.put_slice(&four);
            }
            None => buf.put_u8(0), // AF_UNSPEC
        }
        buf.put_u32(self.ip_len);
        buf.put_u32(self.ifindex);
        buf.put_u32(self.ndm_state);
    }
}

/// ZEBRA_ROUTER_ID_UPDATE (18) zebra→client body — mirrored from
/// `zebra_router_id_update_read`: family u8, address bytes, prefixlen u8.
/// SPEC: no fixture yet.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ZapiRouterIdUpdate {
    pub address: IpAddr,
    pub prefix_len: u8,
}

impl ZapiRouterIdUpdate {
    pub fn decode(body: &[u8]) -> Result<Self, ZapiCodecError> {
        let mut b = body;
        let family = u16::from(take_u8(&mut b)?);
        let blen = family_blen(family)?;
        let addr = take_n(&mut b, blen)?;
        let prefix_len = take_u8(&mut b)?;
        let address = match family {
            AF_INET => {
                let mut a = [0u8; 4];
                a.copy_from_slice(addr);
                IpAddr::V4(Ipv4Addr::from(a))
            }
            _ => {
                let mut a = [0u8; 16];
                a.copy_from_slice(addr);
                IpAddr::V6(Ipv6Addr::from(a))
            }
        };
        if !b.is_empty() {
            return Err(ZapiCodecError::TrailingBytes(b.len()));
        }
        Ok(Self {
            address,
            prefix_len,
        })
    }

    pub fn encode(&self, buf: &mut BytesMut) {
        match self.address {
            IpAddr::V4(a) => {
                buf.put_u8(AF_INET as u8);
                buf.put_slice(&a.octets());
            }
            IpAddr::V6(a) => {
                buf.put_u8(AF_INET6 as u8);
                buf.put_slice(&a.octets());
            }
        }
        buf.put_u8(self.prefix_len);
    }
}

/// ZEBRA_ROUTE_NOTIFY_OWNER (11) zebra→client body — the asynchronous
/// answer to ROUTE_NOTIFY_REQUEST (126) interest: zebra pushes one when a
/// route owned by the requesting client has its status decided (installed
/// into the kernel, install failed, better route won, removed). There is
/// NO synchronous reply to 126 itself (A5 capture: the only frames after
/// the request are the connect pushes 20/33 and this notification).
///
/// Layout per the A5 wire capture, cross-checked against
/// `zapi_route_notify_decode` (`lib/zclient.c`, frr-10.2.2):
/// note u32 in the CPU's NATIVE byte order (zebra `stream_put`s the C
/// enum raw — `sizeof(enum)` = 4, little-endian on x86_64/aarch64) |
/// family u8 (AF_INET=2/AF_INET6=10) | prefixlen u8 | address at FULL
/// family byte-length (4/16 — NOT the PSIZE(plen) of ROUTE_ADD) |
/// tableid u32 big-endian | afi u8 | safi u8.
///
/// E (A5): `02000000 02 18 cb007100 000000fe 01 01` = INSTALLED,
/// 203.0.113.0/24, table 254 (RT_TABLE_MAIN), AFI_IP, SAFI_UNICAST.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ZapiRouteNotifyOwner {
    /// [`route_notify_note`] value; see the struct docs for the
    /// little-endian raw-enum quirk.
    pub note: u32,
    pub prefix: IpPrefix,
    /// E: 254 = RT_TABLE_MAIN (the crate's [`crate::DEFAULT_TABLE`]).
    pub tableid: u32,
    /// E: 1 (AFI_IP).
    pub afi: u8,
    /// E: 1 (SAFI_UNICAST).
    pub safi: u8,
}

impl ZapiRouteNotifyOwner {
    pub fn decode(body: &[u8]) -> Result<Self, ZapiCodecError> {
        let mut b = body;
        let raw_note = take_n(&mut b, 4)?;
        let note = u32::from_le_bytes([raw_note[0], raw_note[1], raw_note[2], raw_note[3]]);
        let family = u16::from(take_u8(&mut b)?);
        let blen = family_blen(family)?;
        let prefix_len = take_u8(&mut b)?;
        let addr = take_n(&mut b, blen)?;
        let prefix = match family {
            AF_INET => {
                let mut a = [0u8; 4];
                a.copy_from_slice(addr);
                v4_prefix(a, prefix_len)?
            }
            _ => {
                let mut a = [0u8; 16];
                a.copy_from_slice(addr);
                v6_prefix(a, prefix_len)?
            }
        };
        let tableid = take_be_u32(&mut b)?;
        let afi = take_u8(&mut b)?;
        let safi = take_u8(&mut b)?;
        if !b.is_empty() {
            return Err(ZapiCodecError::TrailingBytes(b.len()));
        }
        Ok(Self {
            note,
            prefix,
            tableid,
            afi,
            safi,
        })
    }

    pub fn encode(&self, buf: &mut BytesMut) {
        buf.put_slice(&self.note.to_le_bytes());
        let (family, len, addr) = prefix_parts(&self.prefix);
        buf.put_u8(family as u8);
        buf.put_u8(len);
        let blen = family_blen(family).expect("IpPrefix is always v4/v6");
        buf.put_slice(&addr[..blen]);
        buf.put_u32(self.tableid);
        buf.put_u8(self.afi);
        buf.put_u8(self.safi);
    }
}

// ---------------------------------------------------------------------------
// The BFD message family (W1-b pins)
// ---------------------------------------------------------------------------

/// Status bits of ZEBRA_INTERFACE_BFD_DEST_UPDATE (26) — frr-10.2.2
/// `lib/bfd.h` defines them as BITMASKS (`1 << n`), not enum values;
/// E (W1-b Phase B): DOWN=2 observed at register and at failure, UP=4
/// while the session was established.
pub mod bfd_status {
    /// BFD session status never received (`1 << 0`).
    pub const UNKNOWN: u32 = 1;
    /// BFD session status is down (`1 << 1`).
    pub const DOWN: u32 = 2;
    /// BFD session status is up (`1 << 2`).
    pub const UP: u32 = 4;
    /// BFD session is admin down (`1 << 3`).
    pub const ADMIN_DOWN: u32 = 8;
}

/// The client→zebra BFD session command body, shared by
/// ZEBRA_BFD_DEST_REGISTER (27), ZEBRA_BFD_DEST_DEREGISTER (28) and
/// ZEBRA_BFD_DEST_UPDATE (29) — one encoder in frr-10.2.2
/// (`zclient_bfd_command`, `lib/bfd.c`) writes all three, so the body
/// is one shape (the command differs only in the header).
///
/// E (W1-b Phase A): the exact 30 bytes a real bgpd 10.2.2 sent for a
/// multihop neighbor with `update-source`; single-hop differs only in
/// mhop=0/src=0.0.0.0/hops=1 and a carried ifname (source-read branch;
/// pinned by Phase B acceptance — see the pinned doc deviations).
///
/// `pid` u32 BE | family u16 BE | dst (family-sized) | min_rx u32 BE
/// (MILLISECONDS) | min_tx u32 BE (ms) | detection_multiplier u8 |
/// mhop u8 | family u16 BE (again) | src (family-sized) | hops u8 |
/// ifnamelen u8 [+ name] | cbit u8 | profilelen u8 [+ name].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ZapiBfdSessionCmd {
    /// The sender's `getpid()`; zebra keys its per-client fan-out on it.
    pub pid: u32,
    pub dst: IpAddr,
    /// Required minimum receive interval, milliseconds.
    pub min_rx_ms: u32,
    /// Desired minimum transmit interval, milliseconds.
    pub min_tx_ms: u32,
    pub detection_multiplier: u8,
    pub mhop: bool,
    /// 0.0.0.0/:: when the client has no local address (single-hop).
    pub src: IpAddr,
    /// 255 in bgpd's multihop frame (p->ttl); 1 single-hop.
    pub hops: u8,
    /// Carried for single-hop when the egress interface is known;
    /// multihop always sends ifnamelen 0 (frr suppresses it).
    pub ifname: Option<String>,
    /// Control-plane-independent bit.
    pub cbit: bool,
    /// bfd profile name, when configured.
    pub profile: Option<String>,
}

impl ZapiBfdSessionCmd {
    pub fn decode(body: &[u8]) -> Result<Self, ZapiCodecError> {
        let mut b = body;
        let pid = take_be_u32(&mut b)?;
        let family = take_be_u16(&mut b)?;
        let blen = family_blen(family)?;
        let dst_raw = take_n(&mut b, blen)?;
        let min_rx_ms = take_be_u32(&mut b)?;
        let min_tx_ms = take_be_u32(&mut b)?;
        let detection_multiplier = take_u8(&mut b)?;
        let mhop = take_u8(&mut b)? != 0;
        let family2 = take_be_u16(&mut b)?;
        if family2 != family {
            return Err(ZapiCodecError::FamilyMismatch {
                first: family,
                second: family2,
            });
        }
        let src_raw = take_n(&mut b, blen)?;
        let hops = take_u8(&mut b)?;
        let ifnamelen = take_u8(&mut b)? as usize;
        if ifnamelen > b.len() {
            return Err(ZapiCodecError::Truncated {
                need: ifnamelen - b.len(),
            });
        }
        let ifname = if ifnamelen > 0 {
            Some(
                std::str::from_utf8(&b[..ifnamelen])
                    .map_err(|_| ZapiCodecError::BadIfname)?
                    .to_string(),
            )
        } else {
            None
        };
        b = &b[ifnamelen..];
        let cbit = take_u8(&mut b)? != 0;
        let profilelen = take_u8(&mut b)? as usize;
        if profilelen > b.len() {
            return Err(ZapiCodecError::Truncated {
                need: profilelen - b.len(),
            });
        }
        let profile = if profilelen > 0 {
            Some(
                std::str::from_utf8(&b[..profilelen])
                    .map_err(|_| ZapiCodecError::BadIfname)?
                    .to_string(),
            )
        } else {
            None
        };
        b = &b[profilelen..];
        if !b.is_empty() {
            return Err(ZapiCodecError::TrailingBytes(b.len()));
        }
        Ok(Self {
            pid,
            dst: ip_from_parts(family, dst_raw)?,
            min_rx_ms,
            min_tx_ms,
            detection_multiplier,
            mhop,
            src: ip_from_parts(family, src_raw)?,
            hops,
            ifname,
            cbit,
            profile,
        })
    }

    pub fn encode(&self, buf: &mut BytesMut) {
        buf.put_u32(self.pid);
        let (family, dst, src) = match (self.dst, self.src) {
            (IpAddr::V4(d), IpAddr::V4(s)) => (AF_INET, d.octets().to_vec(), s.octets().to_vec()),
            (IpAddr::V6(d), IpAddr::V6(s)) => (AF_INET6, d.octets().to_vec(), s.octets().to_vec()),
            _ => panic!("src/dst family mismatch"),
        };
        buf.put_u16(family);
        buf.put_slice(&dst);
        buf.put_u32(self.min_rx_ms);
        buf.put_u32(self.min_tx_ms);
        buf.put_u8(self.detection_multiplier);
        buf.put_u8(u8::from(self.mhop));
        buf.put_u16(family);
        buf.put_slice(&src);
        buf.put_u8(self.hops);
        // Multihop suppresses the interface (frr-10.2.2 lib/bfd.c).
        let ifname = if self.mhop {
            None
        } else {
            self.ifname.as_deref()
        };
        match ifname {
            Some(name) => {
                buf.put_u8(name.len() as u8);
                buf.put_slice(name.as_bytes());
            }
            None => buf.put_u8(0),
        }
        buf.put_u8(u8::from(self.cbit));
        match &self.profile {
            Some(p) => {
                buf.put_u8(p.len() as u8);
                buf.put_slice(p.as_bytes());
            }
            None => buf.put_u8(0),
        }
    }
}

fn ip_from_parts(family: u16, raw: &[u8]) -> Result<IpAddr, ZapiCodecError> {
    match family {
        AF_INET => {
            let mut a = [0u8; 4];
            a.copy_from_slice(raw);
            Ok(IpAddr::V4(std::net::Ipv4Addr::from(a)))
        }
        AF_INET6 => {
            let mut a = [0u8; 16];
            a.copy_from_slice(raw);
            Ok(IpAddr::V6(std::net::Ipv6Addr::from(a)))
        }
        other => Err(ZapiCodecError::BadFamily(other)),
    }
}

/// ZEBRA_INTERFACE_BFD_DEST_UPDATE (26) zebra→client body — the BFD
/// state push for a registered destination. E (W1-b Phase B): captured
/// in three states (DOWN at register with ifindex 0, UP with the
/// resolved egress ifindex, DOWN after failure); layout cross-verified
/// against `bfd_get_peer_info` (frr-10.2.2 `lib/bfd.c`):
///
/// `ifindex` u32 BE | dst.family **u8** | dst address (family-sized) |
/// dst.prefixlen u8 | status u32 BE ([`bfd_status`]) | src.family u8 |
/// src address | src.prefixlen u8 | remote_cbit u8. Note the u8
/// families (NOT the register's u16) — FRR's `struct prefix` carries a
/// one-byte family.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ZapiBfdDestStatus {
    /// 0 until zebra resolved the egress interface (E: 0 at register, 2
    /// for eth0 once resolved).
    pub ifindex: u32,
    /// The registered destination as a /32 or /128 (E: plen 32).
    pub dst: IpPrefix,
    /// [`bfd_status`] value.
    pub status: u32,
    /// The session's local address as a prefix; single-hop wildcard
    /// shows 0.0.0.0/32 (E).
    pub src: IpPrefix,
    /// The peer's control-plane-independent bit.
    pub remote_cbit: bool,
}

impl ZapiBfdDestStatus {
    pub fn decode(body: &[u8]) -> Result<Self, ZapiCodecError> {
        let mut b = body;
        let ifindex = take_be_u32(&mut b)?;
        let dst_family = u16::from(take_u8(&mut b)?);
        let dst_blen = family_blen(dst_family)?;
        let dst_raw = take_n(&mut b, dst_blen)?;
        let dst_len = take_u8(&mut b)?;
        let status = take_be_u32(&mut b)?;
        let src_family = u16::from(take_u8(&mut b)?);
        let src_blen = family_blen(src_family)?;
        let src_raw = take_n(&mut b, src_blen)?;
        let src_len = take_u8(&mut b)?;
        let remote_cbit = take_u8(&mut b)? != 0;
        if !b.is_empty() {
            return Err(ZapiCodecError::TrailingBytes(b.len()));
        }
        let dst = prefix_from_parts(dst_family, dst_raw, dst_len)?;
        let src = prefix_from_parts(src_family, src_raw, src_len)?;
        Ok(Self {
            ifindex,
            dst,
            status,
            src,
            remote_cbit,
        })
    }

    pub fn encode(&self, buf: &mut BytesMut) {
        buf.put_u32(self.ifindex);
        put_u8_family_prefix(buf, &self.dst);
        buf.put_u32(self.status);
        put_u8_family_prefix(buf, &self.src);
        buf.put_u8(u8::from(self.remote_cbit));
    }
}

fn prefix_from_parts(family: u16, raw: &[u8], len: u8) -> Result<IpPrefix, ZapiCodecError> {
    match family {
        AF_INET => {
            let mut a = [0u8; 4];
            a.copy_from_slice(raw);
            v4_prefix(a, len)
        }
        AF_INET6 => {
            let mut a = [0u8; 16];
            a.copy_from_slice(raw);
            v6_prefix(a, len)
        }
        other => Err(ZapiCodecError::BadFamily(other)),
    }
}

/// family u8 | address bytes | prefixlen u8 — the `struct prefix`
/// shape the BFD update carries (contrast [`put_addr_prefix`], the u16
/// family form of NHT prefixes).
fn put_u8_family_prefix(buf: &mut BytesMut, p: &IpPrefix) {
    match p {
        IpPrefix::V4(net) => {
            buf.put_u8(AF_INET as u8);
            buf.put_slice(&net.addr().octets());
            buf.put_u8(net.prefix_len());
        }
        IpPrefix::V6(net) => {
            buf.put_u8(AF_INET6 as u8);
            buf.put_slice(&net.addr().octets());
            buf.put_u8(net.prefix_len());
        }
    }
}

// ---------------------------------------------------------------------------
// The message envelope
// ---------------------------------------------------------------------------

/// A decoded ZAPI message: header command + typed body.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ZapiMessage {
    /// ZEBRA_INTERFACE_ADD (0) with an empty body — the client→zebra
    /// "send me interface state" registration request. E: sent by every
    /// connecting daemon in the fixtures.
    InterfaceAddRequest,
    /// ZEBRA_INTERFACE_ADD (0) zebra→client full interface dump. SPEC.
    InterfaceAdd(ZapiInterface),
    InterfaceDelete(ZapiInterface),
    InterfaceAddressAdd(ZapiInterfaceAddress),
    InterfaceAddressDelete(ZapiInterfaceAddress),
    /// ZEBRA_ROUTER_ID_ADD (16), client→zebra: `afi` u16. E: body `0001`
    /// (AFI_IP) from staticd and bgpd (`zclient_send_router_id_update`).
    RouterIdAdd {
        afi: u16,
    },
    /// ZEBRA_ROUTER_ID_UPDATE (18), zebra→client. SPEC.
    RouterIdUpdate(ZapiRouterIdUpdate),
    /// ZEBRA_HELLO (19). E: four fixture variants.
    Hello(ZapiHello),
    /// ZEBRA_NEXTHOP_REGISTER (21). E: two fixture samples.
    NexthopRegister(ZapiNexthopRegister),
    /// ZEBRA_NEXTHOP_UNREGISTER (22). SPEC (same shape as register).
    NexthopUnregister(ZapiNexthopRegister),
    /// ZEBRA_NEXTHOP_UPDATE (23), zebra→client. SPEC.
    NexthopUpdate(ZapiNexthopUpdate),
    /// ZEBRA_ROUTE_ADD (9). E: staticd blackhole fixture.
    RouteAdd(ZapiRoute),
    /// ZEBRA_ROUTE_DELETE (10). E: staticd reconnect fixture.
    RouteDelete(ZapiRoute),
    /// ZEBRA_ROUTE_NOTIFY_OWNER (11), zebra→client: asynchronous status
    /// push to a client that asked with ROUTE_NOTIFY_REQUEST (126).
    /// E (A5): captured from a real zebra 10.2.2.
    RouteNotifyOwner(ZapiRouteNotifyOwner),
    /// ZEBRA_NEIGH_REGISTER (131), client→zebra: `afi` u16. SRC
    /// (cached zclient.c) + acceptance wire-proven (M4 capture).
    NeighRegister(ZapiNeighRegister),
    /// ZEBRA_NEIGH_UNREGISTER (132): same body.
    NeighUnregister(ZapiNeighRegister),
    /// ZEBRA_NEIGH_ADDED (128), zebra→client. E (M4): captured from a
    /// real zebra 10.2.2 (both the with-MAC and the FAILED flavours).
    NeighAdded(ZapiNeighNotify),
    /// ZEBRA_NEIGH_REMOVED (129), zebra→client. E (M4): captured
    /// (AF_UNSPEC + ndm FAILED body).
    NeighRemoved(ZapiNeighNotify),
    /// ZEBRA_REDISTRIBUTE_ADD (12). E: bgpd fixture.
    RedistributeAdd(ZapiRedistribute),
    /// ZEBRA_REDISTRIBUTE_DELETE (13). SPEC (same shape as add).
    RedistributeDelete(ZapiRedistribute),
    /// ZEBRA_REDISTRIBUTE_ROUTE_ADD (31), zebra→client: zebra pushes a
    /// route to a client that registered redistribution for its type
    /// (bgpd's `redistribute static` etc.). The body is the SAME
    /// `zapi_route_encode` shape as ROUTE_ADD (9): `zsend_redistribute_route`
    /// (frr-10.2.2 `zebra/zapi_msg.c`) fills a `struct zapi_route` and calls
    /// the shared encoder. Build with [`ZapiRoute::redistribute_push`] to
    /// mirror zebra's message-bit policy. SPEC: source-verified, not yet
    /// wire-captured (the masquerade sees only client→zebra traffic).
    RedistributeRouteAdd(ZapiRoute),
    /// ZEBRA_REDISTRIBUTE_ROUTE_DEL (32), zebra→client: the withdrawal twin
    /// of [`ZapiMessage::RedistributeRouteAdd`] — `zsend_redistribute_route`
    /// builds both from the same `zapi_route` shape (pinned doc, Z2B), so
    /// the body carries the route being withdrawn. Modeled like 31 (W2,
    /// closing Z2B disclosure 3); SPEC: source-verified, not yet
    /// wire-captured.
    RedistributeRouteDel(ZapiRoute),
    /// ZEBRA_BFD_CLIENT_REGISTER (36): u32 pid. E: matches bgpd's pid.
    BfdClientRegister {
        pid: u32,
    },
    /// ZEBRA_BFD_DEST_REGISTER (27), client→zebra: arm a BFD session for
    /// a destination. E (W1-b Phase A): the bgpd multihop frame; the
    /// body layout is shared with DEREGISTER (28) and UPDATE (29) —
    /// one encoder in frr-10.2.2 `zclient_bfd_command`.
    BfdDestRegister(ZapiBfdSessionCmd),
    /// ZEBRA_BFD_DEST_DEREGISTER (28): SRC body (same shape), E-absent —
    /// no daemon observed sending one (W1-b); zebra answers nothing.
    BfdDestDeregister(ZapiBfdSessionCmd),
    /// ZEBRA_BFD_DEST_UPDATE (29), client→zebra: re-announce parameters
    /// of an installed session. E (W1-b Phase A): bgpd's re-install
    /// frame, byte-identical body to its REGISTER.
    BfdDestUpdate(ZapiBfdSessionCmd),
    /// ZEBRA_BFD_DEST_REPLAY (30), the BFD daemon→zebra: replay the
    /// registered destinations to me; body = the daemon's pid u32.
    /// E (W1-b Phase A): bfdd's connect burst.
    BfdDestReplay {
        pid: u32,
    },
    /// ZEBRA_BFD_DEST_REPLAY (30) carrying SESSION STATE — the same
    /// command with a 25-byte body = pid u32 + the exact 26 tuple. E
    /// (W1-b Phase C): a live Up→Down cycle, both bodies verbatim.
    /// Body length distinguishes the forms (the INTERFACE_ADD
    /// request/dump pattern).
    BfdDaemonStatus {
        pid: u32,
        status: ZapiBfdDestStatus,
    },
    /// ZEBRA_INTERFACE_BFD_DEST_UPDATE (26), zebra→client: BFD state
    /// push for a registered destination. E (W1-b Phase B): captured in
    /// three states (DOWN@register / UP / DOWN@failure).
    InterfaceBfdDestUpdate(ZapiBfdDestStatus),
    /// ZEBRA_LABEL_MANAGER_CONNECT (49): proto u8 + instance u16. E: bgpd
    /// label-manager client.
    LabelManagerConnect {
        proto: u8,
        instance: u16,
    },
    /// ZEBRA_LABEL_MANAGER_CONNECT (49) zebra→client reply: the client body
    /// plus a trailing `result` u8 (0 = success). SPEC per the pinned doc
    /// ("proto u8 + instance u16 + result u8"); the server must answer or
    /// bgpd's label-manager client stalls (pinned doc, operational
    /// finding 3). Distinguished from the client form by body length, the
    /// same pattern as INTERFACE_ADD request/dump.
    LabelManagerConnectResult {
        proto: u8,
        instance: u16,
        result: u8,
    },
    /// ZEBRA_ROUTE_NOTIFY_REQUEST (126): u8 flag. E: staticd `01`.
    RouteNotifyRequest {
        flag: u8,
    },
    /// Any command outside the modeled set, raw body preserved verbatim.
    Unknown {
        command: u16,
        body: Vec<u8>,
    },
}

impl ZapiMessage {
    /// Decodes one message body for a wire command number. Unknown
    /// commands never fail — they pass through as [`ZapiMessage::Unknown`].
    pub fn decode(command: u16, body: &[u8]) -> Result<Self, ZapiCodecError> {
        match ZapiCommand::from_u16(command) {
            ZapiCommand::Hello => Ok(Self::Hello(ZapiHello::decode(body)?)),
            ZapiCommand::InterfaceAdd if body.is_empty() => Ok(Self::InterfaceAddRequest),
            ZapiCommand::InterfaceAdd => Ok(Self::InterfaceAdd(ZapiInterface::decode(body)?)),
            ZapiCommand::InterfaceDelete => Ok(Self::InterfaceDelete(ZapiInterface::decode(body)?)),
            ZapiCommand::InterfaceAddressAdd => Ok(Self::InterfaceAddressAdd(
                ZapiInterfaceAddress::decode(body)?,
            )),
            ZapiCommand::InterfaceAddressDelete => Ok(Self::InterfaceAddressDelete(
                ZapiInterfaceAddress::decode(body)?,
            )),
            ZapiCommand::RouterIdAdd => {
                let mut b = body;
                let afi = take_be_u16(&mut b)?;
                if !b.is_empty() {
                    return Err(ZapiCodecError::TrailingBytes(b.len()));
                }
                Ok(Self::RouterIdAdd { afi })
            }
            ZapiCommand::RouterIdUpdate => {
                Ok(Self::RouterIdUpdate(ZapiRouterIdUpdate::decode(body)?))
            }
            ZapiCommand::NexthopRegister => {
                Ok(Self::NexthopRegister(ZapiNexthopRegister::decode(body)?))
            }
            ZapiCommand::NexthopUnregister => {
                Ok(Self::NexthopUnregister(ZapiNexthopRegister::decode(body)?))
            }
            ZapiCommand::NexthopUpdate => Ok(Self::NexthopUpdate(ZapiNexthopUpdate::decode(body)?)),
            ZapiCommand::RouteAdd => Ok(Self::RouteAdd(ZapiRoute::decode(body)?)),
            ZapiCommand::RouteDelete => Ok(Self::RouteDelete(ZapiRoute::decode(body)?)),
            ZapiCommand::RouteNotifyOwner => {
                Ok(Self::RouteNotifyOwner(ZapiRouteNotifyOwner::decode(body)?))
            }
            ZapiCommand::NeighRegister => Ok(Self::NeighRegister(ZapiNeighRegister::decode(body)?)),
            ZapiCommand::NeighUnregister => {
                Ok(Self::NeighUnregister(ZapiNeighRegister::decode(body)?))
            }
            ZapiCommand::NeighAdded => Ok(Self::NeighAdded(ZapiNeighNotify::decode(body)?)),
            ZapiCommand::NeighRemoved => Ok(Self::NeighRemoved(ZapiNeighNotify::decode(body)?)),
            ZapiCommand::RedistributeAdd => {
                Ok(Self::RedistributeAdd(ZapiRedistribute::decode(body)?))
            }
            ZapiCommand::RedistributeDelete => {
                Ok(Self::RedistributeDelete(ZapiRedistribute::decode(body)?))
            }
            ZapiCommand::RedistributeRouteAdd => {
                Ok(Self::RedistributeRouteAdd(ZapiRoute::decode(body)?))
            }
            ZapiCommand::RedistributeRouteDel => {
                Ok(Self::RedistributeRouteDel(ZapiRoute::decode(body)?))
            }
            ZapiCommand::BfdClientRegister => {
                let mut b = body;
                let pid = take_be_u32(&mut b)?;
                if !b.is_empty() {
                    return Err(ZapiCodecError::TrailingBytes(b.len()));
                }
                Ok(Self::BfdClientRegister { pid })
            }
            ZapiCommand::BfdDestRegister => {
                Ok(Self::BfdDestRegister(ZapiBfdSessionCmd::decode(body)?))
            }
            ZapiCommand::BfdDestDeregister => {
                Ok(Self::BfdDestDeregister(ZapiBfdSessionCmd::decode(body)?))
            }
            ZapiCommand::BfdDestUpdate => Ok(Self::BfdDestUpdate(ZapiBfdSessionCmd::decode(body)?)),
            ZapiCommand::BfdDestReplay => {
                let mut b = body;
                let pid = take_be_u32(&mut b)?;
                if b.is_empty() {
                    return Ok(Self::BfdDestReplay { pid });
                }
                // The 25-byte session-state form (Phase C): pid + the
                // exact 26 tuple.
                let status = ZapiBfdDestStatus::decode(b)?;
                Ok(Self::BfdDaemonStatus { pid, status })
            }
            ZapiCommand::InterfaceBfdDestUpdate => Ok(Self::InterfaceBfdDestUpdate(
                ZapiBfdDestStatus::decode(body)?,
            )),
            ZapiCommand::LabelManagerConnect => {
                let mut b = body;
                let proto = take_u8(&mut b)?;
                let instance = take_be_u16(&mut b)?;
                if b.is_empty() {
                    return Ok(Self::LabelManagerConnect { proto, instance });
                }
                let result = take_u8(&mut b)?;
                if !b.is_empty() {
                    return Err(ZapiCodecError::TrailingBytes(b.len()));
                }
                Ok(Self::LabelManagerConnectResult {
                    proto,
                    instance,
                    result,
                })
            }
            ZapiCommand::RouteNotifyRequest => {
                let mut b = body;
                let flag = take_u8(&mut b)?;
                if !b.is_empty() {
                    return Err(ZapiCodecError::TrailingBytes(b.len()));
                }
                Ok(Self::RouteNotifyRequest { flag })
            }
            _ => Ok(Self::Unknown {
                command,
                body: body.to_vec(),
            }),
        }
    }

    /// The wire command number for this message.
    pub const fn command(&self) -> u16 {
        match self {
            Self::InterfaceAddRequest | Self::InterfaceAdd(_) => 0,
            Self::InterfaceDelete(_) => 1,
            Self::InterfaceAddressAdd(_) => 2,
            Self::InterfaceAddressDelete(_) => 3,
            Self::RouterIdAdd { .. } => 16,
            Self::RouterIdUpdate(_) => 18,
            Self::Hello(_) => 19,
            Self::NexthopRegister(_) => 21,
            Self::NexthopUnregister(_) => 22,
            Self::NexthopUpdate(_) => 23,
            Self::RouteAdd(_) => 9,
            Self::RouteDelete(_) => 10,
            Self::RouteNotifyOwner(_) => 11,
            Self::NeighRegister(_) => 131,
            Self::NeighUnregister(_) => 132,
            Self::NeighAdded(_) => 128,
            Self::NeighRemoved(_) => 129,
            Self::RedistributeAdd(_) => 12,
            Self::RedistributeDelete(_) => 13,
            Self::RedistributeRouteAdd(_) => 31,
            Self::RedistributeRouteDel(_) => 32,
            Self::BfdClientRegister { .. } => 36,
            Self::BfdDestRegister(_) => 27,
            Self::BfdDestDeregister(_) => 28,
            Self::BfdDestUpdate(_) => 29,
            Self::BfdDestReplay { .. } => 30,
            Self::BfdDaemonStatus { .. } => 30,
            Self::InterfaceBfdDestUpdate(_) => 26,
            Self::LabelManagerConnect { .. } => 49,
            Self::LabelManagerConnectResult { .. } => 49,
            Self::RouteNotifyRequest { .. } => 126,
            Self::Unknown { command, .. } => *command,
        }
    }

    /// Encodes the message body (no header).
    pub fn encode_body(&self, buf: &mut BytesMut) -> Result<(), ZapiCodecError> {
        match self {
            Self::InterfaceAddRequest => Ok(()),
            Self::InterfaceAdd(i) | Self::InterfaceDelete(i) => i.encode(buf),
            Self::InterfaceAddressAdd(a) | Self::InterfaceAddressDelete(a) => {
                a.encode(buf);
                Ok(())
            }
            Self::RouterIdAdd { afi } => {
                buf.put_u16(*afi);
                Ok(())
            }
            Self::RouterIdUpdate(r) => {
                r.encode(buf);
                Ok(())
            }
            Self::Hello(h) => {
                h.encode(buf);
                Ok(())
            }
            Self::NexthopRegister(r) | Self::NexthopUnregister(r) => {
                r.encode(buf);
                Ok(())
            }
            Self::NexthopUpdate(u) => {
                u.encode(buf);
                Ok(())
            }
            Self::RouteAdd(r) | Self::RouteDelete(r) => {
                r.encode(buf);
                Ok(())
            }
            Self::RouteNotifyOwner(n) => {
                n.encode(buf);
                Ok(())
            }
            Self::NeighRegister(r) | Self::NeighUnregister(r) => {
                r.encode(buf);
                Ok(())
            }
            Self::NeighAdded(n) | Self::NeighRemoved(n) => {
                n.encode(buf);
                Ok(())
            }
            Self::RedistributeAdd(r) | Self::RedistributeDelete(r) => {
                r.encode(buf);
                Ok(())
            }
            Self::RedistributeRouteAdd(r) | Self::RedistributeRouteDel(r) => {
                r.encode(buf);
                Ok(())
            }
            Self::BfdClientRegister { pid } => {
                buf.put_u32(*pid);
                Ok(())
            }
            Self::BfdDestRegister(cmd)
            | Self::BfdDestDeregister(cmd)
            | Self::BfdDestUpdate(cmd) => {
                cmd.encode(buf);
                Ok(())
            }
            Self::BfdDestReplay { pid } => {
                buf.put_u32(*pid);
                Ok(())
            }
            Self::BfdDaemonStatus { pid, status } => {
                buf.put_u32(*pid);
                status.encode(buf);
                Ok(())
            }
            Self::InterfaceBfdDestUpdate(update) => {
                update.encode(buf);
                Ok(())
            }
            Self::LabelManagerConnect { proto, instance } => {
                buf.put_u8(*proto);
                buf.put_u16(*instance);
                Ok(())
            }
            Self::LabelManagerConnectResult {
                proto,
                instance,
                result,
            } => {
                buf.put_u8(*proto);
                buf.put_u16(*instance);
                buf.put_u8(*result);
                Ok(())
            }
            Self::RouteNotifyRequest { flag } => {
                buf.put_u8(*flag);
                Ok(())
            }
            Self::Unknown { body, .. } => {
                buf.put_slice(body);
                Ok(())
            }
        }
    }

    /// Encodes header + body into a complete wire frame.
    pub fn encode_frame(&self, vrf_id: u32) -> Result<Bytes, ZapiCodecError> {
        let mut body = BytesMut::new();
        self.encode_body(&mut body)?;
        let mut frame = BytesMut::with_capacity(ZAPI_HEADER_LEN + body.len());
        frame.resize(ZAPI_HEADER_LEN, 0);
        ZapiHeader::new(self.command(), vrf_id, body.len()).encode(&mut frame[..ZAPI_HEADER_LEN]);
        frame.extend_from_slice(&body);
        Ok(frame.freeze())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// M4 wire pins: the captured NEIGH_ADDED (128) bodies round-trip
    /// byte-exactly — the 22-byte with-MAC form and the 18-byte
    /// AF_UNSPEC form (fixtures/m4-capture, 2026-10-10).
    #[test]
    fn neigh_added_round_trips_the_captured_bodies() {
        let with_mac = ZapiMessage::NeighAdded(ZapiNeighNotify::added(
            "192.168.215.99".parse().unwrap(),
            &[0x02, 0x00, 0x00, 0x00, 0x00, 0x99],
            2,
            0x80,
        ));
        let mut buf = BytesMut::new();
        with_mac.encode_body(&mut buf).unwrap();
        assert_eq!(
            buf,
            BytesMut::from(
                &[
                    0x02, 0xc0, 0xa8, 0xd7, 0x63, 0x02, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                    0x06, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x80
                ][..]
            )
        );
        assert_eq!(ZapiMessage::decode(128, &buf).unwrap(), with_mac);

        let failed = ZapiMessage::NeighAdded(ZapiNeighNotify::without_link_layer(
            "192.168.215.99".parse().unwrap(),
            2,
            0x20,
        ));
        let mut buf = BytesMut::new();
        failed.encode_body(&mut buf).unwrap();
        assert_eq!(
            buf,
            BytesMut::from(
                &[
                    0x02, 0xc0, 0xa8, 0xd7, 0x63, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                    0x02, 0x00, 0x00, 0x00, 0x20
                ][..]
            )
        );
        assert_eq!(ZapiMessage::decode(128, &buf).unwrap(), failed);

        let removed = ZapiMessage::NeighRemoved(ZapiNeighNotify::without_link_layer(
            "192.168.215.99".parse().unwrap(),
            2,
            0x20,
        ));
        let mut buf = BytesMut::new();
        removed.encode_body(&mut buf).unwrap();
        assert_eq!(
            buf,
            BytesMut::from(
                &[
                    0x02, 0xc0, 0xa8, 0xd7, 0x63, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                    0x02, 0x00, 0x00, 0x00, 0x20
                ][..]
            )
        );
        assert_eq!(ZapiMessage::decode(129, &buf).unwrap(), removed);
    }

    /// NEIGH_REGISTER (131) is exactly `afi` u16 — the source-pinned body
    /// the probe sent and zebra accepted.
    #[test]
    fn neigh_register_body_is_afi_u16() {
        let msg = ZapiMessage::NeighRegister(ZapiNeighRegister { afi: 1 });
        let mut buf = BytesMut::new();
        msg.encode_body(&mut buf).unwrap();
        assert_eq!(buf, BytesMut::from(&[0x00, 0x01][..]));
        assert_eq!(ZapiMessage::decode(131, &buf).unwrap(), msg);
        assert_eq!(msg.command(), 131);
    }

    /// Encodes, re-decodes, asserts structural equality, returns the wire.
    fn roundtrip(msg: &ZapiMessage) -> Vec<u8> {
        let mut buf = BytesMut::new();
        msg.encode_body(&mut buf).expect("encode");
        let decoded = ZapiMessage::decode(msg.command(), &buf).expect("re-decode");
        assert_eq!(decoded, *msg, "struct round-trip");
        buf.to_vec()
    }

    #[test]
    fn command_evidence_entries() {
        // E entries (wire-captured in fixtures).
        assert_eq!(ZapiCommand::from_u16(0), ZapiCommand::InterfaceAdd);
        assert_eq!(ZapiCommand::from_u16(9), ZapiCommand::RouteAdd);
        assert_eq!(ZapiCommand::from_u16(10), ZapiCommand::RouteDelete);
        assert_eq!(ZapiCommand::from_u16(12), ZapiCommand::RedistributeAdd);
        assert_eq!(ZapiCommand::from_u16(16), ZapiCommand::RouterIdAdd);
        assert_eq!(ZapiCommand::from_u16(19), ZapiCommand::Hello);
        assert_eq!(ZapiCommand::from_u16(21), ZapiCommand::NexthopRegister);
        assert_eq!(ZapiCommand::from_u16(36), ZapiCommand::BfdClientRegister);
        assert_eq!(ZapiCommand::from_u16(49), ZapiCommand::LabelManagerConnect);
        assert_eq!(ZapiCommand::from_u16(126), ZapiCommand::RouteNotifyRequest);
        // Source-corrected entry: 7 is SET_ARP (zclient.h), not a hole.
        assert_eq!(ZapiCommand::from_u16(7), ZapiCommand::InterfaceSetArp);
        assert_eq!(ZapiCommand::from_u16(146), ZapiCommand::Srv6SidNotify);
    }

    #[test]
    fn command_out_of_range_is_unknown() {
        // zebra_message_types_t ends at 146; 147+ are NOT message types
        // (the pinned doc's first table misattributed 150-154).
        for n in [147u16, 148, 149, 150, 154, 155, 256, 999, 65535] {
            assert_eq!(ZapiCommand::from_u16(n), ZapiCommand::Unknown(n));
            assert_eq!(ZapiCommand::from_u16(n).to_u16(), n);
        }
    }

    #[test]
    fn command_roundtrip_full_range() {
        for n in 0..=65535u16 {
            assert_eq!(ZapiCommand::from_u16(n).to_u16(), n);
        }
    }

    #[test]
    fn hello_decodes_four_observed_variants() {
        let cases = [
            (
                hex("04 0000 00000000 00"),
                ZapiHello {
                    redist_default: 4,
                    instance: 0,
                    session_id: 0,
                    synchronous: 0,
                },
            ),
            (
                hex("0a 0000 00000000 00"),
                ZapiHello {
                    redist_default: 10,
                    instance: 0,
                    session_id: 0,
                    synchronous: 0,
                },
            ),
            (
                hex("12 0000 00000000 00"),
                ZapiHello {
                    redist_default: 0x12,
                    instance: 0,
                    session_id: 0,
                    synchronous: 0,
                },
            ),
            (
                hex("0a 0000 00000001 01"),
                ZapiHello {
                    redist_default: 10,
                    instance: 0,
                    session_id: 1,
                    synchronous: 1,
                },
            ),
        ];
        for (wire, expected) in cases {
            assert_eq!(ZapiHello::decode(&wire).unwrap(), expected);
            assert_eq!(roundtrip(&ZapiMessage::Hello(expected)), wire);
        }
    }

    #[test]
    fn hello_rejects_wrong_length() {
        assert!(ZapiHello::decode(&hex("04000000")).is_err());
        assert!(ZapiHello::decode(&hex("040000000000000001")).is_err());
    }

    #[test]
    fn router_id_add_decodes_afi() {
        let msg = ZapiMessage::decode(16, &hex("0001")).unwrap();
        assert_eq!(msg, ZapiMessage::RouterIdAdd { afi: 1 });
        assert_eq!(roundtrip(&msg), hex("0001"));
    }

    #[test]
    fn route_notify_request_decodes_flag() {
        let msg = ZapiMessage::decode(126, &hex("01")).unwrap();
        assert_eq!(msg, ZapiMessage::RouteNotifyRequest { flag: 1 });
        assert_eq!(roundtrip(&msg), hex("01"));
    }

    #[test]
    fn bfd_client_register_decodes_pid() {
        let msg = ZapiMessage::decode(36, &hex("00000175")).unwrap();
        assert_eq!(msg, ZapiMessage::BfdClientRegister { pid: 373 });
        let msg2 = ZapiMessage::decode(36, &hex("00000217")).unwrap();
        assert_eq!(msg2, ZapiMessage::BfdClientRegister { pid: 535 });
        assert_eq!(roundtrip(&msg), hex("00000175"));
        assert_eq!(roundtrip(&msg2), hex("00000217"));
    }

    /// W1-b Phase A goldens: the exact bytes real FRR 10.2.2 speakers
    /// sent — bgpd's multihop REGISTER (27) and its byte-identical
    /// re-install UPDATE (29), and bfdd's REPLAY (30) pid body.
    #[test]
    fn bfd_dest_register_decodes_the_captured_bgpd_frame() {
        let wire = hex("000000520002c63364090000012c0000012c03010002c0a8d704ff000000");
        let msg = ZapiMessage::decode(27, &wire).unwrap();
        let cmd = ZapiBfdSessionCmd {
            pid: 0x52,
            dst: "198.51.100.9".parse().unwrap(),
            min_rx_ms: 300,
            min_tx_ms: 300,
            detection_multiplier: 3,
            mhop: true,
            src: "192.168.215.4".parse().unwrap(),
            hops: 255,
            ifname: None,
            cbit: false,
            profile: None,
        };
        assert_eq!(msg, ZapiMessage::BfdDestRegister(cmd.clone()));
        assert_eq!(msg.command(), 27);
        assert_eq!(
            roundtrip(&msg),
            wire,
            "REGISTER re-encodes byte-identically"
        );

        // The re-install frame: same body, command 29.
        let upd = ZapiMessage::decode(29, &wire).unwrap();
        assert_eq!(upd, ZapiMessage::BfdDestUpdate(cmd));
        assert_eq!(roundtrip(&upd), wire);
    }

    /// The DEREGISTER (28) twin shares the body (SRC — no wire frame
    /// exists; the same-encoder source read).
    #[test]
    fn bfd_dest_deregister_shares_the_body() {
        let wire = hex("000000520002c63364090000012c0000012c03010002c0a8d704ff000000");
        let msg = ZapiMessage::decode(28, &wire).unwrap();
        assert!(matches!(msg, ZapiMessage::BfdDestDeregister(_)));
        assert_eq!(msg.command(), 28);
        assert_eq!(roundtrip(&msg), wire);
    }

    /// The single-hop REGISTER the Phase B probe sent and a real zebra
    /// accepted (30 bytes, ifnamelen 0, wildcard source).
    #[test]
    fn bfd_dest_register_single_hop_roundtrips() {
        let wire = hex("0000003b0002c0a8d7050000006400000064030000020000000001000000");
        let msg = ZapiMessage::decode(27, &wire).unwrap();
        match &msg {
            ZapiMessage::BfdDestRegister(cmd) => {
                assert_eq!(cmd.dst, "192.168.215.5".parse::<IpAddr>().unwrap());
                assert!(!cmd.mhop);
                assert_eq!(cmd.hops, 1);
                assert_eq!(cmd.src, "0.0.0.0".parse::<IpAddr>().unwrap());
                assert_eq!(
                    (cmd.min_rx_ms, cmd.min_tx_ms, cmd.detection_multiplier),
                    (100, 100, 3)
                );
            }
            other => panic!("not a register: {other:?}"),
        }
        assert_eq!(roundtrip(&msg), wire);
    }

    /// M1 wire pins: the bgpd-EMITTED single-hop REGISTER bodies (real
    /// FRR 10.2.2, apply-time). Leg 1 fired against a BARE masquerade
    /// (no interface dumps, no NHT answers; the frame precedes bgpd's
    /// own NEXTHOP_REGISTER by a second) — single-hop arming at config
    /// apply needs neither. Identical shape to the multihop W1-b frame,
    /// field values only: mhop 0, src wildcard, hops 1, ifnamelen 0.
    #[test]
    fn bfd_dest_register_single_hop_wire_pins_the_bgpd_frames() {
        // Leg 1 (bare masquerade): dst = the bridge gateway.
        let leg1 = hex("0000003c0002c0a8d7010000012c0000012c030000020000000001000000");
        let msg = ZapiMessage::decode(27, &leg1).unwrap();
        match &msg {
            ZapiMessage::BfdDestRegister(cmd) => {
                assert_eq!(cmd.pid, 0x3c);
                assert_eq!(cmd.dst, "192.168.215.1".parse::<IpAddr>().unwrap());
                assert!(!cmd.mhop, "single hop");
                assert_eq!(cmd.src, "0.0.0.0".parse::<IpAddr>().unwrap());
                assert_eq!(cmd.hops, 1);
                assert_eq!(cmd.ifname, None);
                assert_eq!(
                    (cmd.min_rx_ms, cmd.min_tx_ms, cmd.detection_multiplier),
                    (300, 300, 3)
                );
            }
            other => panic!("not a register: {other:?}"),
        }
        assert_eq!(roundtrip(&msg), leg1);

        // Leg 2 (full masquerade, real EBGP peer): the apply-time frame
        // for the peer — same 30-byte single-hop form.
        let leg2 = hex("000000790002c0a8d7030000012c0000012c030000020000000001000000");
        let msg = ZapiMessage::decode(27, &leg2).unwrap();
        let ZapiMessage::BfdDestRegister(cmd) = &msg else {
            panic!("not a register");
        };
        assert_eq!(cmd.dst, "192.168.215.3".parse::<IpAddr>().unwrap());
        assert!(!cmd.mhop && cmd.hops == 1 && cmd.ifname.is_none());
        assert_eq!(roundtrip(&msg), leg2);
    }

    /// M1 wire pins: the ifname-carrying single-hop bodies bgpd emits
    /// once the EBGP session established (learned local address +
    /// egress interface) — the re-arm REGISTER, the `no neighbor ... bfd`
    /// DEREGISTER (28 — first wire evidence for the command, previously
    /// source-pinned only), and the same-address re-fire UPDATE (29).
    /// All three carry the byte-identical 34-byte body: src real,
    /// hops 1, ifnamelen 4 "eth0".
    #[test]
    fn bfd_dest_rearm_cycle_pins_deregister_and_ifname_forms() {
        let body = hex("000000790002c0a8d7030000012c0000012c03000002c0a8d7020104657468300000");
        let rearm = ZapiMessage::decode(27, &body).unwrap();
        match &rearm {
            ZapiMessage::BfdDestRegister(cmd) => {
                assert!(!cmd.mhop, "single hop");
                assert_eq!(cmd.src, "192.168.215.2".parse::<IpAddr>().unwrap());
                assert_eq!(cmd.hops, 1);
                assert_eq!(cmd.ifname.as_deref(), Some("eth0"));
            }
            other => panic!("not a register: {other:?}"),
        }
        assert_eq!(roundtrip(&rearm), body);

        // `no neighbor ... bfd` DEREGISTER — byte-identical body (28).
        let dereg = ZapiMessage::decode(28, &body).unwrap();
        assert!(matches!(dereg, ZapiMessage::BfdDestDeregister(_)));
        assert_eq!(roundtrip(&dereg), body);

        // Same-address re-fire — the UPDATE (29), byte-identical body.
        let upd = ZapiMessage::decode(29, &body).unwrap();
        assert!(matches!(upd, ZapiMessage::BfdDestUpdate(_)));
        assert_eq!(roundtrip(&upd), body);
    }

    /// Single-hop with a known egress interface carries ifname (the
    /// encoder branch frr's `zclient_bfd_command` source-read shows);
    /// multihop suppresses it even when set (so an mhop cmd with ifname
    /// set does NOT round-trip — encode drops it, mirroring frr).
    #[test]
    fn bfd_dest_register_ifname_rules() {
        let cmd = ZapiBfdSessionCmd {
            pid: 9,
            dst: "192.0.2.9".parse().unwrap(),
            min_rx_ms: 300,
            min_tx_ms: 300,
            detection_multiplier: 3,
            mhop: false,
            src: "0.0.0.0".parse().unwrap(),
            hops: 1,
            ifname: Some("eth0".to_string()),
            cbit: false,
            profile: None,
        };
        let msg = ZapiMessage::BfdDestRegister(cmd);
        let wire = roundtrip(&msg);
        assert_eq!(wire.len(), 30 + 4);
        assert_eq!(&wire[27..29], &[4, b'e']);
        // Multihop: the ifname byte is 0 even though one is set (encode
        // drops it — mirroring frr — so the struct is NOT round-trip
        // equal; assert on the wire, not via the roundtrip helper).
        let ZapiMessage::BfdDestRegister(base) = &msg else {
            unreachable!()
        };
        let mhop = ZapiMessage::BfdDestRegister(ZapiBfdSessionCmd {
            mhop: true,
            hops: 255,
            src: "192.0.2.1".parse().unwrap(),
            ..base.clone()
        });
        let mut buf = BytesMut::new();
        mhop.encode_body(&mut buf).unwrap();
        assert_eq!(buf.len(), 30, "multihop suppresses the ifname");
        assert_eq!(buf[27], 0, "the ifnamelen byte");
    }

    /// A profile name rides profilelen + bytes (bgpd `neighbor X bfd
    /// profile NAME`).
    #[test]
    fn bfd_dest_register_with_profile_roundtrips() {
        let cmd = ZapiBfdSessionCmd {
            pid: 5,
            dst: "2001:db8::9".parse().unwrap(),
            min_rx_ms: 300,
            min_tx_ms: 300,
            detection_multiplier: 5,
            mhop: true,
            src: "2001:db8::1".parse().unwrap(),
            hops: 255,
            ifname: None,
            cbit: true,
            profile: Some("slow".to_string()),
        };
        let msg = ZapiMessage::BfdDestUpdate(cmd);
        let wire = roundtrip(&msg);
        assert_eq!(
            wire.len(),
            4 + 2 + 16 + 4 + 4 + 1 + 1 + 2 + 16 + 1 + 1 + 1 + 1 + 4
        );
    }

    /// bfdd's REPLAY (30) — 4-byte pid body, E.
    #[test]
    fn bfd_dest_replay_decodes_captured_body() {
        let msg = ZapiMessage::decode(30, &hex("0000001e")).unwrap();
        assert_eq!(msg, ZapiMessage::BfdDestReplay { pid: 30 });
        assert_eq!(roundtrip(&msg), hex("0000001e"));
        assert!(matches!(
            ZapiMessage::decode(30, &hex("0000001e00")),
            Err(ZapiCodecError::Truncated { .. })
        ));
    }

    /// Phase C goldens: the SAME command 30 carrying session state —
    /// 25-byte body = pid + the exact 26 tuple, captured live for a
    /// session going Up and (peer killed) Down.
    #[test]
    fn bfd_daemon_status_decodes_the_captured_up_down_cycle() {
        let up = hex("0000001a0000000002c0a8d705200000000402000000002000");
        let msg = ZapiMessage::decode(30, &up).unwrap();
        let status = ZapiBfdDestStatus {
            ifindex: 0,
            dst: "192.168.215.5/32".parse().unwrap(),
            status: bfd_status::UP,
            src: "0.0.0.0/32".parse().unwrap(),
            remote_cbit: false,
        };
        assert_eq!(msg, ZapiMessage::BfdDaemonStatus { pid: 0x1a, status });
        assert_eq!(msg.command(), 30);
        assert_eq!(roundtrip(&msg), up);

        let down = hex("0000001a0000000002c0a8d705200000000202000000002000");
        let msg = ZapiMessage::decode(30, &down).unwrap();
        assert_eq!(
            msg,
            ZapiMessage::BfdDaemonStatus {
                pid: 0x1a,
                status: ZapiBfdDestStatus {
                    status: bfd_status::DOWN,
                    ..status
                }
            }
        );
        assert_eq!(roundtrip(&msg), down);
    }

    /// W1-b Phase B goldens: the three INTERFACE_BFD_DEST_UPDATE (26)
    /// states a real zebra 10.2.2 pushed — DOWN at register (ifindex
    /// 0), UP (ifindex 2), DOWN after the peer vanished.
    #[test]
    fn interface_bfd_dest_update_decodes_the_three_captured_states() {
        let cases = [
            (
                "0000000002c0a8d705200000000202000000002000",
                0,
                bfd_status::DOWN,
            ),
            (
                "0000000202c0a8d705200000000402000000002000",
                2,
                bfd_status::UP,
            ),
            (
                "0000000202c0a8d705200000000202000000002000",
                2,
                bfd_status::DOWN,
            ),
        ];
        for (wire, ifindex, status) in cases {
            let wire = hex(wire);
            let msg = ZapiMessage::decode(26, &wire).unwrap();
            assert_eq!(
                msg,
                ZapiMessage::InterfaceBfdDestUpdate(ZapiBfdDestStatus {
                    ifindex,
                    dst: "192.168.215.5/32".parse().unwrap(),
                    status,
                    src: "0.0.0.0/32".parse().unwrap(),
                    remote_cbit: false,
                }),
                "state ifindex={ifindex} status={status}"
            );
            assert_eq!(msg.command(), 26);
            assert_eq!(roundtrip(&msg), wire, "re-encode must be byte-identical");
        }
    }

    /// Structural errors: truncated bodies, family mismatch between the
    /// two address slots, ifname overrun, trailing bytes, bad plen.
    #[test]
    fn bfd_session_cmd_rejects_malformed_bodies() {
        // family word says AF_INET6 but only 4 address bytes follow.
        assert!(matches!(
            ZapiMessage::decode(27, &hex("00000001000a0001")),
            Err(ZapiCodecError::Truncated { .. })
        ));
        // Second family word differs from the first (AF_INET6 vs AF_INET).
        let wire = hex("000000010002c000020900000064000000640300000a0000000000");
        assert!(matches!(
            ZapiMessage::decode(27, &wire),
            Err(ZapiCodecError::FamilyMismatch { .. })
        ));
        // ifnamelen overruns the body.
        let wire = hex("000000010002c0000209000000640000006403000002000000000105");
        assert!(matches!(
            ZapiMessage::decode(27, &wire),
            Err(ZapiCodecError::Truncated { .. })
        ));
        // trailing byte after a complete body.
        let mut long = hex("0000003b0002c0a8d7050000006400000064030000020000000001000000");
        long.push(0);
        assert_eq!(
            ZapiMessage::decode(27, &long),
            Err(ZapiCodecError::TrailingBytes(1))
        );
        // Update with a prefix length beyond the family maximum.
        let mut bad = hex("0000000002c0a8d705200000000202000000002000").to_vec();
        bad[9] = 33; // dst.plen
        assert_eq!(
            ZapiMessage::decode(26, &bad),
            Err(ZapiCodecError::BadPrefixLen { family: 2, len: 33 })
        );
    }

    #[test]
    fn route_notify_owner_decodes_captured_bytes() {
        // A5: the exact 16 bytes a real zebra 10.2.2 pushed after the
        // probe (announcing STATIC, notify-requested) added blackhole
        // 203.0.113.0/24: note 2 = INSTALLED as a LITTLE-ENDIAN raw C
        // enum copy, family 2 (AF_INET), plen 24, full 4-byte address,
        // tableid 254 big-endian, afi 1, safi 1.
        let wire = hex("020000000218cb007100000000fe0101");
        let msg = ZapiMessage::decode(11, &wire).unwrap();
        assert_eq!(
            msg,
            ZapiMessage::RouteNotifyOwner(ZapiRouteNotifyOwner {
                note: route_notify_note::INSTALLED,
                prefix: "203.0.113.0/24".parse().unwrap(),
                tableid: 254,
                afi: 1,
                safi: 1,
            })
        );
        assert_eq!(msg.command(), 11);
        assert_eq!(roundtrip(&msg), wire, "re-encode must be byte-identical");
    }

    #[test]
    fn route_notify_owner_note_is_little_endian_raw_enum() {
        // FAIL_INSTALL (0) still occupies 4 bytes on the wire; the note
        // field is a raw C-enum copy, not a u8 and not big-endian.
        let msg = ZapiMessage::RouteNotifyOwner(ZapiRouteNotifyOwner {
            note: route_notify_note::FAIL_INSTALL,
            prefix: "198.51.100.0/24".parse().unwrap(),
            tableid: 254,
            afi: 1,
            safi: 1,
        });
        // 16 bytes: note 00000000 | family 02 | plen 18 | addr c6336400 |
        // tableid 000000fe | afi 01 | safi 01.
        assert_eq!(roundtrip(&msg), hex("000000000218c6336400000000fe0101"));
    }

    #[test]
    fn route_notify_owner_rejects_truncated_and_trailing() {
        let wire = hex("020000000218cb007100000000fe0101");
        assert_eq!(
            ZapiMessage::decode(11, &wire[..wire.len() - 1]),
            Err(ZapiCodecError::Truncated { need: 1 })
        );
        let mut long = wire.clone();
        long.push(0);
        assert_eq!(
            ZapiMessage::decode(11, &long),
            Err(ZapiCodecError::TrailingBytes(1))
        );
    }

    #[test]
    fn label_manager_connect_decodes() {
        let msg = ZapiMessage::decode(49, &hex("0a0000")).unwrap();
        assert_eq!(
            msg,
            ZapiMessage::LabelManagerConnect {
                proto: 10,
                instance: 0
            }
        );
        assert_eq!(roundtrip(&msg), hex("0a0000"));
    }

    #[test]
    fn label_manager_connect_result_roundtrips() {
        // Zebra's reply form: client body + trailing result u8 (0 = ok).
        // Length-sensitive decode, like INTERFACE_ADD request/dump.
        let msg = ZapiMessage::decode(49, &hex("0a000000")).unwrap();
        assert_eq!(
            msg,
            ZapiMessage::LabelManagerConnectResult {
                proto: 10,
                instance: 0,
                result: 0
            }
        );
        assert_eq!(msg.command(), 49);
        assert_eq!(roundtrip(&msg), hex("0a000000"));
        let err = ZapiMessage::decode(49, &hex("0a00000001"));
        assert_eq!(err, Err(ZapiCodecError::TrailingBytes(1)));
    }

    #[test]
    fn redistribute_decodes_and_roundtrips() {
        let wire = hex("01040000");
        let msg = ZapiMessage::decode(12, &wire).unwrap();
        assert_eq!(
            msg,
            ZapiMessage::RedistributeAdd(ZapiRedistribute {
                afi: 1,
                route_type: 4,
                instance: 0
            })
        );
        assert_eq!(roundtrip(&msg), wire);
        // Live capture (z5d): a REAL ospfd `redistribute connected`
        // registration — CONNECT is 2 on the frr-10.2.2 wire, not 3 (the
        // pre-LOCAL numbering error the capture closed).
        let ospfd = hex("01020000");
        assert_eq!(
            ZapiMessage::decode(12, &ospfd).unwrap(),
            ZapiMessage::RedistributeAdd(ZapiRedistribute {
                afi: 1,
                route_type: route_type::CONNECT,
                instance: 0
            })
        );
        // SPEC side: the delete twin uses the same shape.
        let del = ZapiMessage::RedistributeDelete(ZapiRedistribute {
            afi: 1,
            route_type: 10,
            instance: 7,
        });
        let mut buf = BytesMut::new();
        del.encode_body(&mut buf).unwrap();
        assert_eq!(buf.to_vec(), hex("010a0007"));
        assert_eq!(
            ZapiMessage::decode(13, &buf).unwrap(),
            del,
            "redistribute delete round-trip"
        );
    }

    #[test]
    fn redistribute_route_add_encodes_zebra_shape() {
        // A connected route pushed to a client that redistributed connected:
        // hand-derived from zsend_redistribute_route + zapi_route_encode.
        // message 0x17 = NEXTHOP | DISTANCE | METRIC | MTU (the three
        // attribute bits are ALWAYS set; NEXTHOP because the route has an
        // active nexthop).
        let route = ZapiRoute::redistribute_push(
            route_type::CONNECT,
            0,
            0,
            "192.0.2.0/24".parse().unwrap(),
            vec![ZapiNexthop::new_ifindex(0, 2)],
            0,
            0,
            0,
            0,
        );
        let msg = ZapiMessage::RedistributeRouteAdd(route);
        assert_eq!(msg.command(), 31);
        let wire = roundtrip(&msg);
        assert_eq!(
            wire,
            hex(concat!(
                "02 0000 00000000 00000017 01 02 18 c00002",
                " 0001 00000000 01 00 00000002",
                " 00 00000000 00000000"
            ))
        );
        // Complete frame: 10-byte header, command 31, length incl. header.
        let frame = msg.encode_frame(0).unwrap();
        assert_eq!(frame.len(), ZAPI_HEADER_LEN + wire.len());
        let header = ZapiHeader::decode(&frame).unwrap();
        assert_eq!(header.command, 31);
        assert_eq!(header.marker, 254);
        assert_eq!(header.version, 6);
        assert_eq!(header.length as usize, frame.len());
        assert_eq!(&frame[ZAPI_HEADER_LEN..], &wire[..]);
    }

    #[test]
    fn redistribute_route_add_tag_bit_only_when_nonzero() {
        // Static push with a tag: message 0x1e = DISTANCE | METRIC | TAG |
        // MTU. No active nexthops => no NEXTHOP bit at all (zebra gates the
        // bit on the active-nexthop count, unlike staticd's ROUTE_ADD
        // delete which kept the bit with count 0).
        let route = ZapiRoute::redistribute_push(
            route_type::STATIC,
            5,
            0x41,
            "203.0.113.0/24".parse().unwrap(),
            Vec::new(),
            1,
            20,
            100,
            1500,
        );
        assert_eq!(route.tag, Some(100));
        let msg = ZapiMessage::RedistributeRouteAdd(route);
        assert_eq!(
            roundtrip(&msg),
            hex(concat!(
                "04 0005 00000041 0000001e 01 02 18 cb0071",
                " 01 00000014 00000064 000005dc"
            ))
        );
        // Zero tag stays structurally absent, not Some(0).
        let untagged = ZapiRoute::redistribute_push(
            route_type::STATIC,
            0,
            0,
            "203.0.113.0/24".parse().unwrap(),
            Vec::new(),
            1,
            20,
            0,
            1500,
        );
        assert_eq!(untagged.tag, None);
        assert_eq!(untagged.message & message_flag::TAG, 0);
    }

    #[test]
    fn redistribute_route_add_shares_the_route_add_body() {
        // zsend_redistribute_route calls the SAME zapi_route_encode as
        // ROUTE_ADD: the identical bytes must decode as a ROUTE_ADD body.
        let mut nh = ZapiNexthop::new_ipv6(0, "2001:db8::1".parse().unwrap());
        nh.set_weight(0x0102_0304_0506_0708);
        let route = ZapiRoute::redistribute_push(
            route_type::BGP,
            7,
            0x08, // ZEBRA_FLAG_SELECTED — the pushed path IS the best path
            "2001:db8:1::/48".parse().unwrap(),
            vec![nh],
            200,
            500,
            0,
            0,
        );
        let msg = ZapiMessage::RedistributeRouteAdd(route.clone());
        let wire = roundtrip(&msg);
        assert_eq!(ZapiMessage::decode(31, &wire).unwrap(), msg);
        assert_eq!(
            ZapiMessage::decode(9, &wire).unwrap(),
            ZapiMessage::RouteAdd(route),
            "31 and 9 share the zapi_route_encode body byte-for-byte"
        );
        // The pushed route still maps onto the internal model.
        let ZapiMessage::RedistributeRouteAdd(back) = ZapiMessage::decode(31, &wire).unwrap()
        else {
            panic!("re-decode");
        };
        assert_eq!(back.to_route_entry().unwrap().protocol, RouteProtocol::Bgp);
    }

    #[test]
    fn redistribute_route_add_decode_never_panics_on_truncation() {
        let wire = hex(concat!(
            "02 0000 00000000 00000017 01 02 18 c00002",
            " 0001 00000000 01 00 00000002",
            " 00 00000000 00000000"
        ));
        for cut in 0..wire.len() {
            let result = ZapiMessage::decode(31, &wire[..cut]);
            assert!(result.is_err(), "cut at {cut} must error, not panic");
        }
        let mut extended = wire;
        extended.push(0);
        assert_eq!(
            ZapiMessage::decode(31, &extended),
            Err(ZapiCodecError::TrailingBytes(1))
        );
    }

    #[test]
    fn redistribute_route_add_and_del_modeled() {
        // Both redistribute-route bodies are now modeled: garbage errors
        // loudly instead of silently passing through as Unknown.
        assert_eq!(
            ZapiMessage::decode(31, &[]),
            Err(ZapiCodecError::Truncated { need: 1 })
        );
        // W2: 32 (REDISTRIBUTE_ROUTE_DEL) shares the body shape per the
        // source (zsend_redistribute_route builds both) and is modeled the
        // same way — the Z2B passthrough cut is closed.
        assert_eq!(
            ZapiMessage::decode(32, &[]),
            Err(ZapiCodecError::Truncated { need: 1 })
        );
    }

    /// The DEL twin: same zapi_route body as 31 and 9, command 32, and the
    /// withdrawn route's fields survive the round-trip.
    #[test]
    fn redistribute_route_del_decodes_and_roundtrips() {
        let route = ZapiRoute::redistribute_push(
            route_type::STATIC,
            0,
            0x08, // SELECTED — the withdrawn route was the best path
            "198.51.100.0/24".parse().unwrap(),
            Vec::new(), // withdrawn routes push no nexthop list
            1,
            20,
            0,
            0,
        );
        let msg = ZapiMessage::RedistributeRouteDel(route);
        assert_eq!(msg.command(), 32);
        let wire = roundtrip(&msg);
        assert_eq!(
            wire,
            hex("04 0000 00000008 00000016 01 02 18 c63364 01 00000014 00000000")
        );
        // The shared encoder: those bytes are also a ROUTE_ADD body.
        assert_eq!(
            ZapiMessage::decode(9, &wire).unwrap(),
            ZapiMessage::RouteAdd(ZapiRoute::redistribute_push(
                route_type::STATIC,
                0,
                0x08,
                "198.51.100.0/24".parse().unwrap(),
                Vec::new(),
                1,
                20,
                0,
                0,
            )),
            "31/32/9 all share the zapi_route_encode body byte-for-byte"
        );
        // The framed form carries command 32 with a sane header.
        let frame = msg.encode_frame(0).unwrap();
        let header = ZapiHeader::decode(&frame).unwrap();
        assert_eq!(header.command, 32);
        assert_eq!(header.version, 6);
        assert_eq!(header.length as usize, frame.len());
    }

    #[test]
    fn redistribute_route_del_decode_never_panics_on_truncation() {
        let wire = hex(concat!(
            "04 0000 00000008 00000016 01 02 18 c63364",
            " 01 00000014 00000000"
        ));
        for cut in 0..wire.len() {
            let result = ZapiMessage::decode(32, &wire[..cut]);
            assert!(result.is_err(), "cut at {cut} must error, not panic");
        }
        let mut extended = wire;
        extended.push(0);
        assert_eq!(
            ZapiMessage::decode(32, &extended),
            Err(ZapiCodecError::TrailingBytes(1))
        );
    }

    #[test]
    fn nexthop_register_decodes_all_samples() {
        let staticd = hex("00 00 0001 0002 20 c0000201");
        let bgpd = hex("01 00 0001 0002 20 0a090909");
        // E (A23): real ospfd 10.2.2 under `area 0.0.0.1 nssa
        // default-information-originate` — the only live sample with
        // resolve_via_default=1, and the only /0 registration seen
        // (ospf_area_nssa_default_originate_set → ospf_zebra_import_
        // default_route, ospfd.c).
        let ospfd = hex("00 01 0001 0002 00 00000000");
        let m1 = ZapiMessage::decode(21, &staticd).unwrap();
        assert_eq!(
            m1,
            ZapiMessage::NexthopRegister(ZapiNexthopRegister {
                connected: false,
                resolve_via_default: false,
                safi: 1,
                prefix: "192.0.2.1/32".parse().unwrap(),
            })
        );
        let m2 = ZapiMessage::decode(21, &bgpd).unwrap();
        assert_eq!(
            m2,
            ZapiMessage::NexthopRegister(ZapiNexthopRegister {
                connected: true,
                resolve_via_default: false,
                safi: 1,
                prefix: "10.9.9.9/32".parse().unwrap(),
            })
        );
        let m3 = ZapiMessage::decode(21, &ospfd).unwrap();
        assert_eq!(
            m3,
            ZapiMessage::NexthopRegister(ZapiNexthopRegister {
                connected: false,
                resolve_via_default: true,
                safi: 1,
                prefix: "0.0.0.0/0".parse().unwrap(),
            })
        );
        assert_eq!(roundtrip(&m1), staticd);
        assert_eq!(roundtrip(&m2), bgpd);
        assert_eq!(roundtrip(&m3), ospfd);
        // SPEC side: unregister uses the same shape.
        let unreg = ZapiMessage::NexthopUnregister(ZapiNexthopRegister {
            connected: false,
            resolve_via_default: true,
            safi: 1,
            prefix: "192.0.2.1/32".parse().unwrap(),
        });
        assert_eq!(roundtrip(&unreg), hex("00 01 0001 0002 20 c0000201"));
    }

    #[test]
    fn route_add_blackhole_decodes_exactly() {
        let wire = hex("04 0000 00000041 00000003 01 02 18 cb0071 0001 00000000 06 00 01 01");
        let msg = ZapiMessage::decode(9, &wire).unwrap();
        let ZapiMessage::RouteAdd(route) = &msg else {
            panic!("expected RouteAdd");
        };
        assert_eq!(route.route_type, route_type::STATIC);
        assert_eq!(route.instance, 0);
        // 0x41 = ALLOW_RECURSION | RR_USE_DISTANCE in 10.2.2 (NOT classic
        // INTERNAL|STATIC — doc corrected by Z2).
        assert_eq!(route.flags, 0x41);
        assert_eq!(
            route.message,
            message_flag::NEXTHOP | message_flag::DISTANCE
        );
        assert_eq!(route.safi, 1);
        assert_eq!(route.prefix, "203.0.113.0/24".parse().unwrap());
        assert_eq!(route.nexthops.len(), 1);
        assert_eq!(route.nexthops[0].nh_type, nexthop_type::BLACKHOLE);
        assert_eq!(route.nexthops[0].vrf_id, 0);
        assert_eq!(route.nexthops[0].flags, 0);
        assert_eq!(route.nexthops[0].bh_type, blackhole_type::REJECT);
        assert_eq!(route.distance, Some(1));
        assert!(route.metric.is_none());
        assert_eq!(roundtrip(&msg), wire, "byte-identical fixture round-trip");
    }

    #[test]
    fn route_delete_decodes_exactly() {
        let wire = hex("04 0000 00000041 00000003 01 02 18 c63364 0000 01");
        let msg = ZapiMessage::decode(10, &wire).unwrap();
        let ZapiMessage::RouteDelete(route) = &msg else {
            panic!("expected RouteDelete");
        };
        assert_eq!(route.prefix, "198.51.100.0/24".parse().unwrap());
        assert_eq!(
            route.message,
            message_flag::NEXTHOP | message_flag::DISTANCE
        );
        assert!(route.nexthops.is_empty(), "delete carries 0 nexthops");
        assert_eq!(route.distance, Some(1));
        assert_eq!(roundtrip(&msg), wire, "byte-identical fixture round-trip");
    }

    #[test]
    fn route_maps_to_internal_route_entry() {
        let wire = hex("04 0000 00000041 00000003 01 02 18 cb0071 0001 00000000 06 00 01 01");
        let ZapiMessage::RouteAdd(route) = ZapiMessage::decode(9, &wire).unwrap() else {
            panic!("expected RouteAdd");
        };
        let entry = route.to_route_entry().expect("static route maps");
        assert_eq!(entry.protocol, RouteProtocol::Static);
        assert_eq!(entry.prefix, "203.0.113.0/24".parse().unwrap());
        assert_eq!(entry.nexthops.hops(), &[(CommonNexthop::Blackhole, 1)]);
        assert_eq!(entry.metric, 0);
        assert_eq!(entry.table, 254);
    }

    #[test]
    fn route_type_mapping_table() {
        assert_eq!(
            ZapiRoute::route_protocol(route_type::SYSTEM),
            Some(RouteProtocol::Kernel)
        );
        assert_eq!(
            ZapiRoute::route_protocol(route_type::KERNEL),
            Some(RouteProtocol::Kernel)
        );
        assert_eq!(
            ZapiRoute::route_protocol(route_type::CONNECT),
            Some(RouteProtocol::Connected)
        );
        assert_eq!(
            ZapiRoute::route_protocol(route_type::LOCAL),
            Some(RouteProtocol::Local)
        );
        assert_eq!(
            ZapiRoute::route_protocol(route_type::STATIC),
            Some(RouteProtocol::Static)
        );
        assert_eq!(
            ZapiRoute::route_protocol(route_type::RIPNG),
            Some(RouteProtocol::Rip)
        );
        assert_eq!(
            ZapiRoute::route_protocol(route_type::OSPF6),
            Some(RouteProtocol::Ospf)
        );
        assert_eq!(
            ZapiRoute::route_protocol(route_type::ISIS),
            Some(RouteProtocol::IsIs)
        );
        assert_eq!(
            ZapiRoute::route_protocol(route_type::BGP),
            Some(RouteProtocol::Bgp)
        );
        // 0 is SYSTEM (the frr-10.2.2 table starts there); the unmapped
        // probe needs a number the table reaches but we do not model.
        assert_eq!(ZapiRoute::route_protocol(11), None);
        assert_eq!(ZapiRoute::route_protocol(99), None);
    }

    #[test]
    fn route_type_constants_pin_the_frr_10_2_2_numbering() {
        // Source of truth: frr-10.2.2 lib/route_types.txt expanded by
        // lib/route_types.pl (sequential from 0). ZEBRA_ROUTE_LOCAL=3 is
        // the insertion between CONNECT and STATIC that lifts STATIC..BGP
        // above the pre-LOCAL table; SYSTEM/KERNEL/CONNECT keep the
        // classic values. Empirical anchors: STATIC=4, OSPF=7, BGP=10 in
        // the fixtures + the live ospfd CONNECT=2 capture (z5d).
        assert_eq!(route_type::SYSTEM, 0);
        assert_eq!(route_type::KERNEL, 1);
        assert_eq!(route_type::CONNECT, 2);
        assert_eq!(route_type::LOCAL, 3);
        assert_eq!(route_type::STATIC, 4);
        assert_eq!(route_type::RIP, 5);
        assert_eq!(route_type::RIPNG, 6);
        assert_eq!(route_type::OSPF, 7);
        assert_eq!(route_type::OSPF6, 8);
        assert_eq!(route_type::ISIS, 9);
        assert_eq!(route_type::BGP, 10);
    }

    #[test]
    fn nexthop_type_specific_encodings() {
        // Every nexthop form round-trips (widths per frr-10.2.2 SPEC).
        let forms = vec![
            ZapiNexthop::new_blackhole(0, blackhole_type::NULL),
            ZapiNexthop::new_ifindex(3, 42),
            ZapiNexthop::new_ipv4(0, "192.0.2.1".parse().unwrap()),
            ZapiNexthop::new_ipv4_ifindex(2, "192.0.2.1".parse().unwrap(), 7),
            ZapiNexthop::new_ipv6(0, "2001:db8::1".parse().unwrap()),
            ZapiNexthop::new_ipv6_ifindex(5, "2001:db8::1".parse().unwrap(), 9),
        ];
        for nh in forms {
            let mut buf = BytesMut::new();
            nh.encode(&mut buf);
            let mut slice = buf.as_ref();
            let back = ZapiNexthop::decode(&mut slice, 0).expect("nexthop re-decode");
            assert!(slice.is_empty());
            assert_eq!(back, nh);
            assert!(nh.to_common().is_some());
        }
        // Blackhole width is E-derived: vrf(4)+type(1)+flags(1)+bh(1)=7.
        let mut buf = BytesMut::new();
        ZapiNexthop::new_blackhole(0, 1).encode(&mut buf);
        assert_eq!(buf.to_vec(), hex("00000000060001"));
    }

    #[test]
    fn route_synthetic_ipv6_and_attributes_roundtrip() {
        let mut route = ZapiRoute {
            route_type: route_type::BGP,
            instance: 5,
            flags: 0,
            message: message_flag::NEXTHOP
                | message_flag::METRIC
                | message_flag::TAG
                | message_flag::DISTANCE
                | message_flag::MTU
                | message_flag::TABLEID
                | message_flag::SRCPFX,
            safi: 1,
            prefix: "2001:db8:1::/48".parse().unwrap(),
            src_prefix: Some("2001:db8:2::/64".parse().unwrap()),
            nhg_id: 0,
            nexthops: vec![
                ZapiNexthop::new_ipv6_ifindex(0, "2001:db8:ffff::1".parse().unwrap(), 3),
                ZapiNexthop::new_blackhole(0, blackhole_type::NULL),
            ],
            backup_nexthops: Vec::new(),
            distance: Some(20),
            metric: Some(100),
            tag: Some(0xdead_beef),
            mtu: Some(9000),
            tableid: Some(254),
            opaque: None,
        };
        route.nexthops[1].set_weight(0x0102_0304_0506_0708);
        let msg = ZapiMessage::RouteAdd(route);
        let wire = roundtrip(&msg);
        assert!(wire.len() > 40);
        let ZapiMessage::RouteAdd(back) = ZapiMessage::decode(9, &wire).unwrap() else {
            panic!("re-decode");
        };
        assert_eq!(back.tag, Some(0xdead_beef));
        assert_eq!(
            back.nexthops[1].flags & nexthop_flag::WEIGHT,
            nexthop_flag::WEIGHT
        );
        assert_eq!(back.to_route_entry().unwrap().protocol, RouteProtocol::Bgp);
    }

    #[test]
    fn route_decode_never_panics_on_truncation() {
        let wire = hex("04 0000 00000041 00000003 01 02 18 cb0071 0001 00000000 06 00 01 01");
        for cut in 0..wire.len() {
            let result = ZapiRoute::decode(&wire[..cut]);
            assert!(result.is_err(), "cut at {cut} must error, not panic");
        }
        // One extra byte must be a loud trailing error.
        let mut extended = wire.clone();
        extended.push(0);
        assert_eq!(
            ZapiRoute::decode(&extended),
            Err(ZapiCodecError::TrailingBytes(1))
        );
    }

    #[test]
    fn route_decode_rejects_bad_family_and_nexthop_type() {
        // family byte 47 is neither AF_INET nor AF_INET6.
        let bad_family = hex("04 0000 00000041 00000001 01 2f 18 cb0071 0000");
        assert_eq!(
            ZapiRoute::decode(&bad_family),
            Err(ZapiCodecError::BadFamily(47))
        );
        // nexthop type 0 does not exist (enum starts at 1).
        let bad_nh = hex("04 0000 00000001 00000003 01 02 18 cb0071 0001 00000000 00 01");
        assert_eq!(
            ZapiRoute::decode(&bad_nh),
            Err(ZapiCodecError::BadNexthopType(0))
        );
    }

    #[test]
    fn interface_state_roundtrips() {
        let intf = ZapiInterface {
            ifname: "eth0".into(),
            ifindex: 2,
            status: 1,
            flags: 0xffff_ffff_ffff_ffff,
            ptm_enable: 0,
            ptm_status: 0,
            metric: 100,
            speed: 1000,
            txqlen: 1000,
            mtu: 1500,
            mtu6: 1500,
            bandwidth: 10_000,
            link_ifindex: 0,
            ll_type: 0,
            hw_addr_len: 6,
            hw_addr: vec![0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff],
            link_params_status: 0,
            link_params: Vec::new(),
        };
        for cmd_msg in [
            ZapiMessage::InterfaceAdd(intf.clone()),
            ZapiMessage::InterfaceDelete(intf.clone()),
        ] {
            roundtrip(&cmd_msg);
        }
        // Wire shape sanity: 20B name + fixed fields + 6B MAC + status.
        let mut buf = BytesMut::new();
        intf.encode(&mut buf).unwrap();
        assert_eq!(
            buf.len(),
            ZAPI_IFNAMSIZ + 4 + 1 + 8 + 1 + 1 + 8 * 4 + 4 + 6 + 1
        );
        // Long names are a loud error, never a silent truncate.
        let long = ZapiInterface::new("a-very-long-interface-name!", 1);
        let mut sink = BytesMut::new();
        assert!(long.encode(&mut sink).is_err());
    }

    #[test]
    fn interface_address_roundtrips() {
        for (addr, dst) in [
            (
                "192.0.2.1/24",
                Some("192.0.2.255".parse::<IpAddr>().unwrap()),
            ),
            ("2001:db8::1/64", None),
        ] {
            let msg = ZapiMessage::InterfaceAddressAdd(ZapiInterfaceAddress {
                ifindex: 3,
                flags: 0,
                address: addr.parse().unwrap(),
                destination: dst,
            });
            roundtrip(&msg);
        }
        let del = ZapiMessage::InterfaceAddressDelete(ZapiInterfaceAddress {
            ifindex: 3,
            flags: 1,
            address: "192.0.2.1/24".parse().unwrap(),
            destination: None,
        });
        roundtrip(&del);
    }

    #[test]
    fn nexthop_update_roundtrips() {
        let reg: IpPrefix = "192.0.2.1/32".parse().unwrap();
        let resolved = ZapiNexthopUpdate::resolved(
            reg,
            1,
            route_type::CONNECT,
            0,
            0,
            vec![ZapiNexthop::new_ifindex(0, 2)],
        );
        assert!(resolved.is_resolved());
        let unresolved = ZapiNexthopUpdate::unresolved(reg, 1);
        assert!(!unresolved.is_resolved());
        for u in [resolved, unresolved.clone()] {
            roundtrip(&ZapiMessage::NexthopUpdate(u));
        }
        // The unresolved byte shape, hand-derived from the layout:
        // message 0, safi 1, registered+resolved 192.0.2.1/32 (NHT
        // framing), zeroed tail.
        let mut buf = BytesMut::new();
        unresolved.encode(&mut buf);
        assert_eq!(
            buf.to_vec(),
            hex("00000000 0001 0002 20 c0000201 0002 20 c0000201 00 0000 00 00000000 00")
        );
    }

    #[test]
    fn router_id_update_roundtrips() {
        for (addr, len) in [
            (IpAddr::V4("10.0.0.1".parse().unwrap()), 32u8),
            (IpAddr::V6("2001:db8::1".parse().unwrap()), 128),
        ] {
            let msg = ZapiMessage::RouterIdUpdate(ZapiRouterIdUpdate {
                address: addr,
                prefix_len: len,
            });
            roundtrip(&msg);
        }
    }

    #[test]
    fn unknown_passthrough_never_errors() {
        for cmd in [7u16 + 1000, 200, 9999] {
            for body in [hex(""), hex("deadbeef"), hex("00ff00ff00ff")] {
                let msg = ZapiMessage::decode(cmd, &body).expect("unknown never errors");
                assert_eq!(
                    msg,
                    ZapiMessage::Unknown {
                        command: cmd,
                        body: body.clone()
                    }
                );
                assert_eq!(msg.command(), cmd);
                assert_eq!(roundtrip(&msg), body);
            }
        }
        // Unmodeled known commands (e.g. ZEBRA_CAPABILITIES=20) also pass
        // through as Unknown with their number intact.
        let msg = ZapiMessage::decode(20, &hex("cafe")).unwrap();
        assert_eq!(
            msg,
            ZapiMessage::Unknown {
                command: 20,
                body: hex("cafe")
            }
        );
    }

    #[test]
    fn encode_frame_produces_valid_header() {
        let msg = ZapiMessage::Hello(ZapiHello {
            redist_default: 4,
            instance: 0,
            session_id: 0,
            synchronous: 0,
        });
        let frame = msg.encode_frame(0).unwrap();
        assert_eq!(frame.len(), ZAPI_HEADER_LEN + 8);
        let header = ZapiHeader::decode(&frame).unwrap();
        assert_eq!(header.command, 19);
        assert_eq!(header.length as usize, frame.len());
        assert_eq!(&frame[ZAPI_HEADER_LEN..], &hex("0400000000000000")[..]);
    }

    /// Test-only hex helper: accepts free spacing, filters non-hex chars.
    fn hex(s: &str) -> Vec<u8> {
        let clean: String = s.chars().filter(|c| c.is_ascii_hexdigit()).collect();
        assert_eq!(clean.len() % 2, 0, "hex string must have even length");
        clean
            .as_bytes()
            .chunks(2)
            .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
            .collect()
    }
}
