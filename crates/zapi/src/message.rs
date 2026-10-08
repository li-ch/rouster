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

/// FRR `IFNAMSIZ`: interface names occupy exactly this many wire bytes.
pub const ZAPI_IFNAMSIZ: usize = 20;
/// FRR `INTERFACE_HWADDR_MAX`.
pub const ZAPI_HWADDR_MAX: usize = 20;

/// ZEBRA_ROUTE_* type numbers (frr-10.2.2 numbering; +1 vs the classic
/// table because `ZEBRA_ROUTE_SYSTEM` starts at 1).
pub mod route_type {
    /// Locally installed system routes (kernel-origin).
    pub const SYSTEM: u8 = 1;
    pub const KERNEL: u8 = 2;
    pub const CONNECT: u8 = 3;
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
    /// ZEBRA_REDISTRIBUTE_ADD (12). E: bgpd fixture.
    RedistributeAdd(ZapiRedistribute),
    /// ZEBRA_REDISTRIBUTE_DELETE (13). SPEC (same shape as add).
    RedistributeDelete(ZapiRedistribute),
    /// ZEBRA_BFD_CLIENT_REGISTER (36): u32 pid. E: matches bgpd's pid.
    BfdClientRegister {
        pid: u32,
    },
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
            ZapiCommand::RedistributeAdd => {
                Ok(Self::RedistributeAdd(ZapiRedistribute::decode(body)?))
            }
            ZapiCommand::RedistributeDelete => {
                Ok(Self::RedistributeDelete(ZapiRedistribute::decode(body)?))
            }
            ZapiCommand::BfdClientRegister => {
                let mut b = body;
                let pid = take_be_u32(&mut b)?;
                if !b.is_empty() {
                    return Err(ZapiCodecError::TrailingBytes(b.len()));
                }
                Ok(Self::BfdClientRegister { pid })
            }
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
            Self::RedistributeAdd(_) => 12,
            Self::RedistributeDelete(_) => 13,
            Self::BfdClientRegister { .. } => 36,
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
            Self::RedistributeAdd(r) | Self::RedistributeDelete(r) => {
                r.encode(buf);
                Ok(())
            }
            Self::BfdClientRegister { pid } => {
                buf.put_u32(*pid);
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
    fn nexthop_register_decodes_both_samples() {
        let staticd = hex("00 00 0001 0002 20 c0000201");
        let bgpd = hex("01 00 0001 0002 20 0a090909");
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
        assert_eq!(roundtrip(&m1), staticd);
        assert_eq!(roundtrip(&m2), bgpd);
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
        assert_eq!(ZapiRoute::route_protocol(0), None);
        assert_eq!(ZapiRoute::route_protocol(99), None);
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
