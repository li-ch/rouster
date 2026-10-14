//! The v1 command table — what each mode's [`WordTree`] contains.
//!
//! Naming stays consistent with `rousterctl` (the sibling file-based
//! reader): `show sav` is `show sav` on both surfaces. rousterctl
//! stays file-based; the vty is the interactive Cisco-style surface
//! on top of the same run-dir contract.

use crate::tree::{Action, Cmd, ParamKind, Tok, WordTree};

fn lit(word: &'static str, help: &'static str) -> Tok {
    Tok::Lit { word, help }
}

fn param(kind: ParamKind, help: &'static str) -> Tok {
    Tok::Param { kind, help }
}

/// The user-mode tree: what an unauthenticated line may do.
pub fn user_tree() -> WordTree {
    let mut t = WordTree::new();
    t.insert(Cmd {
        toks: vec![
            lit("show", "Show running system information"),
            lit("version", "Software version"),
        ],
        action: Action::ShowVersion,
        help: "Software version",
    });
    t.insert(Cmd {
        toks: vec![lit("enable", "Turn on privileged mode commands")],
        action: Action::Enable,
        help: "Turn on privileged mode commands",
    });
    t.insert(Cmd {
        toks: vec![lit("exit", "Exit the VTY (close the connection)")],
        action: Action::Exit,
        help: "Exit the VTY",
    });
    t.insert(Cmd {
        toks: vec![lit("quit", "Exit the VTY (close the connection)")],
        action: Action::Exit,
        help: "Exit the VTY",
    });
    t.insert(Cmd {
        toks: vec![lit("list", "Print command list")],
        action: Action::List,
        help: "Print command list",
    });
    t
}

/// The enable-mode tree: every exec command plus the door into
/// configuration.
pub fn enable_tree() -> WordTree {
    let mut t = user_tree();
    t.insert(Cmd {
        toks: vec![
            lit("show", "Show running system information"),
            lit(
                "sav",
                "Source-address-validation status (savd run-dir surface)",
            ),
        ],
        action: Action::ShowSav,
        help: "savd's published status (rule set, config, counters)",
    });
    t.insert(Cmd {
        toks: vec![
            lit("show", "Show running system information"),
            lit(
                "sav",
                "Source-address-validation status (savd run-dir surface)",
            ),
            lit("rules", "Only the installed rule table"),
        ],
        action: Action::ShowSavRules,
        help: "Only the installed rule table",
    });
    t.insert(Cmd {
        toks: vec![
            lit("show", "Show running system information"),
            lit(
                "bfd",
                "Bidirectional forwarding detection status (bfdd run-dir surface)",
            ),
        ],
        action: Action::ShowBfd,
        help: "bfdd's published status (per-peer sessions)",
    });
    t.insert(Cmd {
        toks: vec![
            lit("show", "Show running system information"),
            lit(
                "bfd",
                "Bidirectional forwarding detection status (bfdd run-dir surface)",
            ),
            lit("summary", "Only the state counts"),
        ],
        action: Action::ShowBfdSummary,
        help: "Only the state counts",
    });
    t.insert(Cmd {
        toks: vec![
            lit("show", "Show running system information"),
            lit("interface", "Interface status (rousterd run-dir surface)"),
        ],
        action: Action::ShowInterface,
        help: "The interface table rousterd mirrors (v4+v6)",
    });
    t.insert(Cmd {
        toks: vec![
            lit("show", "Show running system information"),
            lit("interface", "Interface status (rousterd run-dir surface)"),
            param(ParamKind::Word, "One interface's name"),
        ],
        action: Action::ShowInterface,
        help: "One interface's table row",
    });
    t.insert(Cmd {
        toks: vec![
            lit("show", "Show running system information"),
            lit("ip", "IP information"),
            lit("interface", "Interface status (rousterd run-dir surface)"),
        ],
        action: Action::ShowIpInterface,
        help: "The FRR-named view of the same interface table",
    });
    t.insert(Cmd {
        toks: vec![
            lit("show", "Show running system information"),
            lit("ip", "IP information"),
            lit("interface", "Interface status (rousterd run-dir surface)"),
            param(ParamKind::Word, "One interface's name"),
        ],
        action: Action::ShowIpInterface,
        help: "One interface's row (FRR-named view)",
    });
    t.insert(Cmd {
        toks: vec![
            lit("show", "Show running system information"),
            lit(
                "neighbor",
                "ARP/NDP neighbor mirror (rousterd run-dir surface)",
            ),
        ],
        action: Action::ShowNeighbor,
        help: "The neighbor table rousterd mirrors",
    });
    t.insert(Cmd {
        toks: vec![
            lit("show", "Show running system information"),
            lit(
                "neighbor",
                "ARP/NDP neighbor mirror (rousterd run-dir surface)",
            ),
            param(
                ParamKind::AddrOrPrefix,
                "Only neighbors inside this address or prefix",
            ),
        ],
        action: Action::ShowNeighbor,
        help: "Neighbors inside an address or prefix, either family",
    });
    t.insert(Cmd {
        toks: vec![
            lit("show", "Show running system information"),
            lit("vrf", "VRF devices (rousterd run-dir surface)"),
        ],
        action: Action::ShowVrf,
        help: "VRF devices: bound table, members, route counts",
    });
    t.insert(Cmd {
        toks: vec![
            lit("show", "Show running system information"),
            lit("rib", "The Rouster RIB (rousterd run-dir surface)"),
            lit("summary", "Counts only"),
        ],
        action: Action::ShowRibSummary,
        help: "Per-table route counts with VRF associations",
    });
    t.insert(Cmd {
        toks: vec![
            lit("show", "Show running system information"),
            lit("ip", "IP information"),
            lit("route", "IP routing table"),
            lit("summary", "Counts only"),
        ],
        action: Action::ShowIpRouteSummary,
        help: "Per-table route counts (the FRR name; summarizes every table)",
    });
    t.insert(Cmd {
        toks: vec![
            lit("show", "Show running system information"),
            lit(
                "running-config",
                "The session's current configuration (parse-only in v1)",
            ),
        ],
        action: Action::ShowRunningConfig,
        help: "The session's current configuration (parse-only in v1)",
    });
    t.insert(Cmd {
        toks: vec![
            lit("configure", "Configure the terminal"),
            lit("terminal", "Configure from the terminal"),
        ],
        action: Action::ConfTerm,
        help: "Enter configuration mode",
    });
    t.insert(Cmd {
        toks: vec![lit("disable", "Turn off privileged mode commands")],
        action: Action::Disable,
        help: "Turn off privileged mode commands",
    });
    t.insert(Cmd {
        toks: vec![
            lit("write", "Write the canonical config (via configd apply)"),
            lit("file", "Write to the canonical config file and apply"),
        ],
        action: Action::Write,
        help: "Write the canonical config and apply it through configd",
    });
    t.insert(Cmd {
        toks: vec![
            lit("write", "Write the canonical config (via configd apply)"),
            lit(
                "memory",
                "Same as `write file` here (the canonical IS the startup config)",
            ),
        ],
        action: Action::Write,
        help: "Write the canonical config and apply it through configd",
    });
    t.insert(Cmd {
        toks: vec![lit(
            "wr",
            "Write the canonical config (`write file` shorthand)",
        )],
        action: Action::Write,
        help: "Write the canonical config and apply it through configd",
    });
    t
}

/// The config-mode tree: the quarantine-B7 observed frr.conf grammar
/// subset, parse-only. `do <exec command>` is handled before the
/// tree (see [`crate::session`]).
pub fn config_tree() -> WordTree {
    let mut t = WordTree::new();
    t.insert(Cmd {
        toks: vec![
            lit("hostname", "Set the system's network name"),
            param(ParamKind::Word, "This system's name"),
        ],
        action: Action::Hostname,
        help: "Set the system's network name",
    });
    t.insert(Cmd {
        toks: vec![
            lit("frr", "FRR global directives"),
            lit("version", "FRR version string"),
            param(ParamKind::Word, "Version (e.g. 10.2)"),
        ],
        action: Action::FrrVersion,
        help: "FRR version header line",
    });
    t.insert(Cmd {
        toks: vec![
            lit("frr", "FRR global directives"),
            lit("defaults", "FRR defaults profile"),
            param(ParamKind::Word, "Profile (traditional | dataplane)"),
        ],
        action: Action::FrrDefaults,
        help: "FRR defaults header line",
    });
    t.insert(Cmd {
        toks: vec![
            lit("line", "Configure a terminal line"),
            lit("vty", "Virtual terminal"),
        ],
        action: Action::LineVty,
        help: "The `line vty` stanza marker",
    });
    t.insert(Cmd {
        toks: vec![
            lit("ip", "IP information"),
            lit("route", "Establish static routes"),
            param(ParamKind::Ipv4Prefix, "Destination prefix"),
            lit("blackhole", "Silently discard packets to the destination"),
        ],
        action: Action::IpRoute,
        help: "Static route, blackhole form",
    });
    t.insert(Cmd {
        toks: vec![
            lit("ip", "IP information"),
            lit("route", "Establish static routes"),
            param(ParamKind::Ipv4Prefix, "Destination prefix"),
            param(ParamKind::Ipv4, "Gateway address"),
        ],
        action: Action::IpRoute,
        help: "Static route, gateway form",
    });
    t.insert(Cmd {
        toks: vec![
            lit("ipv6", "IPv6 information"),
            lit("route", "Establish static routes"),
            param(ParamKind::Ipv6Prefix, "Destination prefix"),
            lit("blackhole", "Silently discard packets to the destination"),
        ],
        action: Action::IpRoute,
        help: "Static IPv6 route, blackhole form",
    });
    t.insert(Cmd {
        toks: vec![
            lit("no", "Negate a command"),
            lit("ip", "IP information"),
            lit("route", "Establish static routes"),
            param(ParamKind::Ipv4Prefix, "Destination prefix"),
            lit("blackhole", "Silently discard packets to the destination"),
        ],
        action: Action::NoIpRoute,
        help: "Remove a blackhole static route",
    });
    t.insert(Cmd {
        toks: vec![
            lit("no", "Negate a command"),
            lit("ip", "IP information"),
            lit("route", "Establish static routes"),
            param(ParamKind::Ipv4Prefix, "Destination prefix"),
            param(ParamKind::Ipv4, "Gateway address"),
        ],
        action: Action::NoIpRoute,
        help: "Remove a gateway static route",
    });
    t.insert(Cmd {
        toks: vec![
            lit(
                "route-map",
                "Route-map construction (kept verbatim for display in v1)",
            ),
            param(ParamKind::Rest, "The rest of the route-map line"),
        ],
        action: Action::RouteMap,
        help: "Route-map line, kept verbatim for display",
    });
    t.insert(Cmd {
        toks: vec![
            lit("router", "Enable a routing process"),
            lit("bgp", "BGP information"),
            param(ParamKind::U32, "Autonomous system number"),
        ],
        action: Action::RouterBgp,
        help: "Enter the router-bgp node",
    });
    t.insert(Cmd {
        toks: vec![lit("exit", "Exit from the current mode")],
        action: Action::Exit,
        help: "Exit configuration mode",
    });
    t.insert(Cmd {
        toks: vec![lit("end", "Exit from configuration mode to enable mode")],
        action: Action::End,
        help: "Exit to enable mode",
    });
    t.insert(Cmd {
        toks: vec![lit(
            "write",
            "Write the canonical config (via configd apply)",
        )],
        action: Action::Write,
        help: "Write the canonical config and apply it through configd",
    });
    t.insert(Cmd {
        toks: vec![
            lit("write", "Write the canonical config (via configd apply)"),
            lit("file", "Write to the canonical config file and apply"),
        ],
        action: Action::Write,
        help: "Write the canonical config and apply it through configd",
    });
    t.insert(Cmd {
        toks: vec![
            lit("write", "Write the canonical config (via configd apply)"),
            lit(
                "memory",
                "Same as `write file` here (the canonical IS the startup config)",
            ),
        ],
        action: Action::Write,
        help: "Write the canonical config and apply it through configd",
    });
    t
}

/// The `(config-router)` tree: bgpd's observed child lines (B7 §3).
pub fn config_router_tree() -> WordTree {
    let mut t = WordTree::new();
    t.insert(Cmd {
        toks: vec![
            lit("bgp", "BGP-specific things"),
            lit("network", "BGP network"),
            lit(
                "import-check",
                "Check nexthop exists in the RIB before announcing",
            ),
        ],
        action: Action::BgpImportCheck,
        help: "Enable import checking (the default in modern FRR)",
    });
    t.insert(Cmd {
        toks: vec![
            lit("no", "Negate a command"),
            lit("bgp", "BGP-specific things"),
            lit("network", "BGP network"),
            lit(
                "import-check",
                "Check nexthop exists in the RIB before announcing",
            ),
        ],
        action: Action::NoBgpImportCheck,
        help: "Announce networks without them existing in the RIB",
    });
    t.insert(Cmd {
        toks: vec![
            lit("bgp", "BGP-specific things"),
            lit("router-id", "Override the BGP router-id"),
            param(ParamKind::Ipv4, "Manually configured router-id"),
        ],
        action: Action::BgpRouterId,
        help: "Set the BGP router-id",
    });
    t.insert(Cmd {
        toks: vec![
            lit("neighbor", "Specify a neighbor router"),
            param(ParamKind::Ipv4, "Neighbor address"),
            lit("remote-as", "Specify a BGP neighbor's AS"),
            param(ParamKind::U32, "Autonomous system number"),
        ],
        action: Action::BgpNeighbor,
        help: "Add a neighbor",
    });
    t.insert(Cmd {
        toks: vec![
            lit("address-family", "Enter address family command mode"),
            lit("ipv4", "Address family"),
            lit("unicast", "Address family modifier"),
        ],
        action: Action::AddressFamily,
        help: "Enter the ipv4-unicast address-family node",
    });
    t.insert(Cmd {
        toks: vec![lit("exit", "Exit from the current mode")],
        action: Action::Exit,
        help: "Exit router mode",
    });
    t.insert(Cmd {
        toks: vec![lit("end", "Exit from configuration mode to enable mode")],
        action: Action::End,
        help: "Exit to enable mode",
    });
    t.insert(Cmd {
        toks: vec![lit(
            "write",
            "Write the canonical config (via configd apply)",
        )],
        action: Action::Write,
        help: "Write the canonical config and apply it through configd",
    });
    t.insert(Cmd {
        toks: vec![
            lit("write", "Write the canonical config (via configd apply)"),
            lit("file", "Write to the canonical config file and apply"),
        ],
        action: Action::Write,
        help: "Write the canonical config and apply it through configd",
    });
    t.insert(Cmd {
        toks: vec![
            lit("write", "Write the canonical config (via configd apply)"),
            lit(
                "memory",
                "Same as `write file` here (the canonical IS the startup config)",
            ),
        ],
        action: Action::Write,
        help: "Write the canonical config and apply it through configd",
    });
    t
}

/// The `(config-router-af)` tree: the address-family child lines
/// (B7 §3), two-space indentation when rendered.
pub fn config_af_tree() -> WordTree {
    let mut t = WordTree::new();
    t.insert(Cmd {
        toks: vec![
            lit("network", "Specify a network to announce via BGP"),
            param(ParamKind::Ipv4Prefix, "IPv4 prefix"),
        ],
        action: Action::AfNetwork,
        help: "Announce a network",
    });
    t.insert(Cmd {
        toks: vec![
            lit(
                "redistribute",
                "Redistribute information from another routing protocol",
            ),
            lit("static", "Static routes"),
        ],
        action: Action::AfRedistributeStatic,
        help: "Redistribute static routes",
    });
    t.insert(Cmd {
        toks: vec![lit(
            "exit-address-family",
            "Exit from address family configuration mode",
        )],
        action: Action::ExitAddressFamily,
        help: "Exit the address-family node",
    });
    t.insert(Cmd {
        toks: vec![lit("exit", "Exit from the current mode")],
        action: Action::Exit,
        help: "Exit the address-family node",
    });
    t.insert(Cmd {
        toks: vec![lit("end", "Exit from configuration mode to enable mode")],
        action: Action::End,
        help: "Exit to enable mode",
    });
    t.insert(Cmd {
        toks: vec![lit(
            "write",
            "Write the canonical config (via configd apply)",
        )],
        action: Action::Write,
        help: "Write the canonical config and apply it through configd",
    });
    t.insert(Cmd {
        toks: vec![
            lit("write", "Write the canonical config (via configd apply)"),
            lit("file", "Write to the canonical config file and apply"),
        ],
        action: Action::Write,
        help: "Write the canonical config and apply it through configd",
    });
    t.insert(Cmd {
        toks: vec![
            lit("write", "Write the canonical config (via configd apply)"),
            lit(
                "memory",
                "Same as `write file` here (the canonical IS the startup config)",
            ),
        ],
        action: Action::Write,
        help: "Write the canonical config and apply it through configd",
    });
    t
}
