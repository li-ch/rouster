//! LSP fragmentation (ISO 10589 §7.3.4, clause numbers via RFC
//! 1142): splitting one system's TLV set across the fragments of its
//! LSP, and the per-fragment rules the SPF consumer relies on
//! (§7.2.5).
//!
//! §7.3.4's constraints, as implemented:
//!
//! - **"a maximum of 256" fragments** — LSP numbers 0 through 255;
//!   a TLV set that needs more is truncated at the cap (disclosed:
//!   v1 logs nothing here — the daemon's prefix sets stay far below).
//! - **"the area-addresses option is only permitted in the LSP with
//!   LSP number 0"** — TLV 1 never leaves fragment 0.
//! - **"The IS neighbours options shall be included in the lowest
//!   numbered link state PDU(s) which can accommodate them, and
//!   shall be included in the LSP with LSP number 0 if it can
//!   accommodate them. They shall be placed before the ES neighbours
//!   options and the prefix neighbours options"** — TLV 22/2 entries
//!   pack into the lowest fragments, ahead of every prefix family.
//! - Entry-structured TLVs split at entry granularity (a fragment
//!   boundary may fall inside one TLV's entry list); each emitted
//!   TLV instance honours the 255-octet value cap, so a long entry
//!   list becomes multiple TLV instances across fragments.
//!
//! The budget: ISO's OriginatingLSPBufferSize ("shall be less than
//! or equal to the smallest MTU of any circuit", at least 512) — the
//! caller passes it; fragment 0's fixed part is 27 octets.

use crate::tlv::Tlv;

/// The wire size of one TLV instance (code + length + value).
fn tlv_wire_len(tlv: &Tlv) -> usize {
    let mut buf = Vec::new();
    crate::tlv::encode_tlv(&mut buf, tlv);
    buf.len()
}

/// The per-entry wire size inside its TLV value.
fn entry_len_ext_is(n: &crate::tlv::ExtIsNeighbor) -> usize {
    7 + 3 + 1 + n.sub_tlvs.iter().map(|s| 2 + s.value.len()).sum::<usize>()
}

fn entry_len_ext_ip(p: &crate::tlv::WideIpReach) -> usize {
    let prefix_octets = crate::tlv::WideIpReach::prefix_octets(p.prefix.1);
    let sub = if p.sub_tlvs.is_empty() {
        0
    } else {
        1 + p.sub_tlvs.iter().map(|s| 2 + s.value.len()).sum::<usize>()
    };
    4 + 1 + prefix_octets + sub
}

/// Split `tlvs` into fragment bodies fitting `budget` octets of TLV
/// block each. Fragment 0 carries the identity TLVs and the first
/// adjacency/prefix entries; adjacency entries precede prefix
/// entries across the fragment space (§7.3.4).
pub fn fragment_tlvs(tlvs: &[Tlv], budget: usize) -> Vec<Vec<Tlv>> {
    let budget = budget.max(64);
    let mut identity: Vec<Tlv> = Vec::new();
    let mut adjacency: Vec<crate::tlv::ExtIsNeighbor> = Vec::new();
    let mut prefixes: Vec<crate::tlv::WideIpReach> = Vec::new();
    for tlv in tlvs {
        match tlv {
            Tlv::ExtIsReachability(entries) => adjacency.extend(entries.iter().cloned()),
            Tlv::ExtIpReachability(entries) => prefixes.extend(entries.iter().cloned()),
            other => identity.push(other.clone()),
        }
    }

    // Fragment 0: the identity set first; whatever room remains goes
    // to adjacencies (they "shall be placed before" prefixes).
    let mut fragments: Vec<Vec<Tlv>> = vec![Vec::new()];
    let mut used = 0;
    for tlv in identity {
        let len = tlv_wire_len(&tlv);
        if used + len > budget {
            // Identity cannot move to a higher fragment: drop the
            // rest (v1's identity set is a handful of short TLVs; a
            // real overflow needs a >512-byte hostname).
            break;
        }
        used += len;
        fragments[0].push(tlv);
    }

    // Pack the adjacency entries first, then the prefix entries,
    // opening fragments as the budget demands.
    pack_ext_is(&mut fragments, &mut adjacency, budget);
    pack_ext_ip(&mut fragments, &mut prefixes, budget);
    fragments
}

/// Open a new fragment (capped at 256 — §7.3.4's LSP number space).
fn open_fragment(fragments: &mut Vec<Vec<Tlv>>) -> Option<()> {
    if fragments.len() >= 256 {
        return None;
    }
    fragments.push(Vec::new());
    Some(())
}

/// Pack TLV 22 entries: each emitted TLV instance's value must fit
/// the 255-octet length byte; instances open fragments as the budget
/// demands.
fn pack_ext_is(
    fragments: &mut Vec<Vec<Tlv>>,
    entries: &mut Vec<crate::tlv::ExtIsNeighbor>,
    budget: usize,
) {
    let mut iter = std::mem::take(entries).into_iter().peekable();
    while let Some(entry) = iter.next() {
        // Start a TLV instance in the last fragment if both the
        // instance header and the entry fit; else open a fragment.
        let entry_len = entry_len_ext_is(&entry);
        if 2 + entry_len > budget {
            continue; // cannot fit even a fresh fragment: dropped
        }
        let current = fragments.last_mut().expect("fragment 0 exists");
        let current_used: usize = current.iter().map(tlv_wire_len).sum();
        if current_used + 2 + entry_len > budget && open_fragment(fragments).is_none() {
            break; // 256-fragment cap reached
        }
        let mut value: Vec<crate::tlv::ExtIsNeighbor> = vec![entry];
        let mut value_len = entry_len;
        // Greedily add same-family entries while the instance value
        // stays <= 255 (the length byte) and the fragment stays in
        // budget.
        while let Some(next) = iter.peek() {
            let next_len = entry_len_ext_is(next);
            if value_len + next_len > 255 {
                break; // length-byte cap for this TLV instance
            }
            let fragment_used: usize = fragments
                .last()
                .map(|f| f.iter().map(tlv_wire_len).sum())
                .unwrap_or(0);
            if fragment_used + 2 + value_len + next_len > budget {
                break;
            }
            value_len += next_len;
            value.push(iter.next().expect("peeked"));
        }
        let last = fragments.last_mut().expect("fragment exists");
        last.push(Tlv::ExtIsReachability(value));
    }
}

fn pack_ext_ip(
    fragments: &mut Vec<Vec<Tlv>>,
    entries: &mut Vec<crate::tlv::WideIpReach>,
    budget: usize,
) {
    let mut iter = std::mem::take(entries).into_iter().peekable();
    while let Some(entry) = iter.next() {
        let entry_len = entry_len_ext_ip(&entry);
        if 2 + entry_len > budget {
            continue; // cannot fit even a fresh fragment: dropped
        }
        let current_used: usize = fragments
            .last()
            .map(|f| f.iter().map(tlv_wire_len).sum::<usize>())
            .unwrap_or(0);
        if current_used + 2 + entry_len > budget && open_fragment(fragments).is_none() {
            break;
        }
        let mut value: Vec<crate::tlv::WideIpReach> = vec![entry];
        let mut value_len = entry_len;
        while let Some(next) = iter.peek() {
            let next_len = entry_len_ext_ip(next);
            if value_len + next_len > 255 {
                break;
            }
            let fragment_used: usize = fragments
                .last()
                .map(|f| f.iter().map(tlv_wire_len).sum())
                .unwrap_or(0);
            if fragment_used + 2 + value_len + next_len > budget {
                break;
            }
            value_len += next_len;
            value.push(iter.next().expect("peeked"));
        }
        let last = fragments.last_mut().expect("fragment exists");
        last.push(Tlv::ExtIpReachability(value));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::system::{NeighborId, SystemId};
    use crate::tlv::{ExtIsNeighbor, WideIpReach};
    use std::net::Ipv4Addr;

    const SYS: SystemId = SystemId::from_bytes([0, 0, 0, 0, 0, 9]);

    fn wide(metric: u32, third: u8) -> WideIpReach {
        WideIpReach {
            metric,
            up_down: false,
            prefix: (Ipv4Addr::new(10, third, 0, 0), 24),
            sub_tlvs: vec![],
        }
    }

    /// §7.3.4's placement rules: area addresses only in fragment 0;
    /// IS neighbours before prefixes; every fragment within budget;
    /// nothing lost.
    #[test]
    fn placement_and_budget() {
        let tlvs = vec![
            Tlv::AreaAddresses(vec![vec![0x49, 0x00, 0x01]]),
            Tlv::ProtocolsSupported(vec![0xCC]),
            Tlv::Hostname("frag-test".into()),
            Tlv::ExtIsReachability(vec![
                ExtIsNeighbor {
                    id: NeighborId::new(SYS, 0),
                    metric: 10,
                    sub_tlvs: vec![],
                },
                ExtIsNeighbor {
                    id: NeighborId::new(SystemId::from_bytes([0, 0, 0, 0, 0, 8]), 0),
                    metric: 20,
                    sub_tlvs: vec![],
                },
            ]),
            Tlv::ExtIpReachability((0..40).map(|i| wide(10, i as u8)).collect()),
        ];
        // A budget that fits the identity set plus a couple of
        // entries per fragment.
        let fragments = fragment_tlvs(&tlvs, 96);
        assert!(fragments.len() >= 5, "spread across fragments");
        // Every fragment within budget (accounting its fixed part).
        for body in &fragments {
            let used: usize = body.iter().map(tlv_wire_len).sum();
            assert!(used <= 96, "fragment body {used} > 96");
        }
        // Identity in fragment 0 only.
        assert!(fragments[0]
            .iter()
            .any(|t| matches!(t, Tlv::AreaAddresses(_))));
        for body in &fragments[1..] {
            assert!(
                !body.iter().any(|t| matches!(t, Tlv::AreaAddresses(_))),
                "area addresses only in fragment 0 (7.3.4)"
            );
        }
        // Adjacencies before prefixes: no prefix rides a fragment
        // lower than the highest adjacency fragment.
        let highest_adj = fragments
            .iter()
            .position(|b| b.iter().any(|t| matches!(t, Tlv::ExtIsReachability(_))))
            .map(|first| {
                fragments
                    .iter()
                    .rposition(|b| b.iter().any(|t| matches!(t, Tlv::ExtIsReachability(_))))
                    .unwrap_or(first)
            });
        let lowest_pfx = fragments
            .iter()
            .position(|b| b.iter().any(|t| matches!(t, Tlv::ExtIpReachability(_))));
        if let (Some(adj), Some(pfx)) = (highest_adj, lowest_pfx) {
            assert!(adj <= pfx, "IS neighbours placed before prefixes");
        }
        // Nothing lost: 40 prefixes + 2 adjacencies all present.
        let pfx_count: usize = fragments
            .iter()
            .flat_map(|b| {
                b.iter().filter_map(|t| match t {
                    Tlv::ExtIpReachability(ps) => Some(ps.len()),
                    _ => None,
                })
            })
            .sum();
        assert_eq!(pfx_count, 40);
        let adj_count: usize = fragments
            .iter()
            .flat_map(|b| {
                b.iter().filter_map(|t| match t {
                    Tlv::ExtIsReachability(ns) => Some(ns.len()),
                    _ => None,
                })
            })
            .sum();
        assert_eq!(adj_count, 2);
    }

    /// The 255-octet TLV value cap: a long entry list becomes
    /// multiple TLV instances (11-octet TLV 22 entries: 23 per
    /// instance maximum).
    #[test]
    fn value_length_cap_chunks_instances() {
        let entries: Vec<ExtIsNeighbor> = (0..30)
            .map(|i| ExtIsNeighbor {
                id: NeighborId::new(SystemId::from_bytes([0, 0, 0, 0, 0, i as u8]), 0),
                metric: 10,
                sub_tlvs: vec![],
            })
            .collect();
        let tlvs = vec![Tlv::ExtIsReachability(entries)];
        let fragments = fragment_tlvs(&tlvs, 4096);
        assert_eq!(fragments.len(), 1);
        let instances: Vec<usize> = fragments[0]
            .iter()
            .filter_map(|t| match t {
                Tlv::ExtIsReachability(ns) => Some(ns.len()),
                _ => None,
            })
            .collect();
        assert_eq!(instances, vec![23, 7], "23 entries max per 255-octet value");
    }

    /// An entry too large for ANY fresh fragment is dropped, not
    /// looped on (a 250-octet sub-TLV under a tiny budget).
    #[test]
    fn oversized_entry_dropped() {
        let mut entries = vec![WideIpReach {
            metric: 1,
            up_down: false,
            prefix: (Ipv4Addr::new(10, 1, 0, 0), 24),
            sub_tlvs: vec![crate::tlv::SubTlv::new(1, vec![0u8; 250])],
        }];
        let tlvs = vec![Tlv::ExtIpReachability(std::mem::take(&mut entries))];
        let fragments = fragment_tlvs(&tlvs, 128);
        let total: usize = fragments
            .iter()
            .flat_map(|b| {
                b.iter().filter_map(|t| match t {
                    Tlv::ExtIpReachability(ps) => Some(ps.len()),
                    _ => None,
                })
            })
            .sum();
        assert_eq!(total, 0, "the oversized entry is dropped, no hang");
    }
}
