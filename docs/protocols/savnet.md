# SAVNET — the agent interface, the feature flag, and what stays out

Status: experimental surface behind `experimental-savnet` (default OFF).
Scope owner decision: SAVNET is prioritized above BAR-SAV (repo
AGENTS.md). Companion docs: [../architecture.md](../architecture.md) §2
(SAV: SIB · validation-mode rules · table manager),
[../implementation-plan.md](../implementation-plan.md) §4 (SAVNET
workstream rules). This note records what the flag gates, what the
interface promises, and — load-bearing — what deliberately stays out
until the drafts stabilize.

## What landed (2026-10-11, the N4 slice)

Two things, one behind the flag and one not:

1. **The SIB fold-in (NOT behind the flag — ratified direction).** The
   SIB consumes the RIB's explicit surfaces: bindings derive from the
   merged view of the main table's protocol candidates and its CONNECT
   set (`Rib::best_with_connected` — a connected candidate masks a
   protocol best at distance 0), and gateway egress resolves through
   the recursive resolver (`Rib::resolve_nexthop_recursive`; the S1
   deviations carry over: no fall-through on an unusable candidate,
   the /0 default never answers, the kernel mirror participates in the
   walk as a resolution source but never as a binding source). When
   both new surfaces are empty the derivation is byte-identical to the
   pre-fold-in one (property-pinned, `crates/sav/tests/sib_props.rs`).

2. **The agent interface (behind `experimental-savnet`).**
   `crates/sav/src/agent.rs`: the [`SavAgent`] trait protocol anchors
   call to report SAV-relevant events (route installed/withdrawn at
   bgpd's `on_message` UPDATE arm, LSA installed with changed contents
   from ospfd's `InstallAndFlood` products, adjacency up/down) and from
   which binding suggestions are received. savd hosts the default
   [`MonitorAgent`] — monitor-only: every event logs, suggestions
   derive from the adjacency heuristic (below), and **nothing a
   suggestion proposes is ever enforced** — the log-before-drop rule.

## The interface contract

- **In-process only.** No serialization, no sockets, no wire codecs.
  An anchor holds one optional shared handle
  (`Arc<dyn SavAgent>`, default `None`) and calls it at its hook
  points; both ends compile only under the flag.
- **Types over `common`/`sav` shapes only.** Events carry
  `IpPrefix`/`IpAddr`/ifindex `u32`/LSA identity; each anchor
  translates its protocol-native data at the call site. The SAV layer
  never learns BGP or OSPF types.
- **Monitor-only default.** The default agent's suggestions are
  observations for the operator. savd's evaluate logs each suggestion
  and moves on. No landed path turns a suggestion into a
  `Binding`, a rule, or a dataplane op.
- **The suggestion heuristic** (EFP-uRPF-adjacent, RFC 8704 §3's
  grouping intuition at adjacency granularity): a prefix announced by
  a peer whose adjacency names an interface is suggested for that
  interface; per-prefix egress unions across announcing peers. No
  peer granularity (savd's own ZAPI view) or no adjacency interface
  (bgpd's session shape tonight) ⇒ no suggestion — the agent never
  invents an interface.
- **Bounded state.** The monitor agent retains a bounded event window
  (1024; oldest half drops) — observations, never authoritative
  state.

## Process-topology scoping (honest disclosure)

bgpd, ospfd, and savd are separate processes in today's interim
multi-process shape, and this interface is in-process by design — so
an anchor's hook calls reach an agent instance inside the **anchor's**
process. Tests compose anchor + agent in-process today; the
architecture's single-binary default deployment (architecture.md §2)
makes that composition production-real without changing a line. savd's
hosted agent additionally observes savd's own ZAPI RIB view (the
`RibView` events, no peer granularity) so the default host has a real
production feed — but the adjacency-derived suggestion path needs
anchor-side events and therefore produces suggestions only where the
composition is in-process. No transport is added to bridge the
processes: that would be a wire protocol by another name, and the
wire is exactly what the flag exists to gate.

## What the flag is for, and what stays out

Repo AGENTS.md SAVNET rules: *"Draft-dependent wire protocols
(intra-domain IGP/BGP signaling, inter-domain) go behind the
`experimental-savnet` feature flag; pin implemented draft versions in
docs; isolate wire codecs."* The drafts this workstream tracks
(`draft-ietf-savnet-intra-domain-sav-igp` / `-bgp`, the
`-architecture` documents, GSC
`draft-ietf-savnet-general-sav-capabilities`) were all expired or
dormant at the time of this note's writing; there is no stable wire
protocol to mirror. Consequently:

- **Nothing behind the flag today is wire work.** The flag currently
  gates only the in-process agent interface — the seam the future
  wire protocols will plug into. When a draft stabilizes, its codec
  lands in an isolated module behind this same flag with the
  implemented revision pinned here.
- **Staying out until drafts stabilize (owner's future decisions):**
  1. Any inter-daemon signaling of SAV state (the drafts'
     intra-domain communication design).
  2. Turning suggestions into bindings — the confirmation protocol,
     TTL policy, and precedence slot (`BindingOrigin` has exactly
     `Rib | Config` today; an agent origin is a new-origin decision,
     not a config line).
  3. Agent-originated IBB/PBA/PBB rules feeding the SAV table manager
     (the rule layer's `RuleOrigin::SavnetAgent` slot and the
     `collision-policy` knob are the landed, unwired landing zone).
  4. The LSDB-aware IGP derivation (the `LsaChanged` events are
     recorded; consuming them needs the draft's BFS design).

## Where the code is

- `crates/sav/src/agent.rs` — trait, events, suggestion type,
  `MonitorAgent` (flag-gated).
- `crates/sav/src/savd.rs` — savd's hosting: `set_agent`, the RibView
  feed in `apply_push`, the per-evaluate suggestion log (flag-gated).
- `crates/bgpd/src/peer.rs` — the `on_message` UPDATE arm and the
  Established/session-end transitions (flag-gated calls).
- `crates/ospfd/src/daemon.rs` — `after_report` (the
  `InstallAndFlood` changed-key products and the adjacency_up/down
  branches; flag-gated calls).
- `crates/sav/tests/agent_contract.rs` — the contract tests
  (mock anchor; compile to nothing in the default build).
