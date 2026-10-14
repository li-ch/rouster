# SAVNET — the agent interface, the feature flag, and what stays out

Status: experimental surface behind `experimental-savnet` (default OFF).
Scope owner decision: SAVNET is prioritized above BAR-SAV (repo
AGENTS.md). Companion docs: [../architecture.md](../architecture.md) §2
(SAV: SIB · validation-mode rules · table manager),
[../implementation-plan.md](../implementation-plan.md) §4 (SAVNET
workstream rules). This note records what the flag gates, what the
interface promises, and — load-bearing — what deliberately stays out
until the drafts stabilize.

**BAR-SAV is NOT behind the flag** — see the [BAR-SAV](#bar-sav-the-per-interface-allowlist-module)
section below: it derives from chartered-RFC data (ROA/ASPA) plus the
local BGP speaker's Adj-RIBs-In, no draft-dependent wire protocol, so
it ships in the default build as the complement SAVNET will absorb
later (priority unchanged: SAVNET first, BAR-SAV second).

## Enforcement backends (savd `backend` knob)

SAV programs install through the `Dataplane` trait ops on either of
two landed surfaces, selected by savd.conf's `backend <rp_filter|nft>`
(default `rp_filter`, unchanged since W7):

- **rp_filter** — per-interface sysctls approximating the compiled
  ops with the kernel FIB's own uRPF (strict=1/loose=2); no monitor
  counters (monitor counting runs in savd's route-lookup simulation);
  IPv4-only; IBB/PBA/PBB rejected with logged reasons.
- **nft** (N6) — a wholly-owned `table inet rouster_sav` enforcing
  the compiled rule CONTENT: per-interface allowlists as interval
  sets, blocklists, router-scale prefix ops, IPv4 and IPv6, monitor
  actions as named kernel counters (`sav_monitor_counts` answers from
  them — the dataplane-first path), drop actions as enforced denies.
  Interval sets declare `auto-merge`: a daemon-fed allowlist can hold
  a covering and a covered prefix at once (the SIB merges the
  interface mirror's connected prefixes with RIB-derived ones), and a
  plain interval set rejects overlapping elements — auto-merge
  resolves them to the union, the list's own semantics either way.
  Enforcement lives only in the table: the sysctl surface is never
  touched and clear is a single `destroy table`. Since N6B the
  counters also answer PER OP (`sav_monitor_per_op` joins the
  install-time counter-units map with `nft list counters`): savd's
  status `count` lines (GSC §4 "count") render the kernel-sourced
  rows, and the simulation tallies are the fallback view only.
  Attribution is install-scoped (counter names are minted at install
  time; savd installs before reading, so its flow always answers).
  Evidence: `scripts/test-sav-nft.sh` (spoof-differential vs the
  rp_filter baseline, same topology; both scripts' readouts recorded
  under the stage's quarantine) and `scripts/test-savd-nft.sh` (the
  savd daemon end-to-end on this backend: SIB from the ZAPI
  redistribute push, kernel ruleset install, spoof/legit differential
  in monitor counters and drop loss, status-file count lines, clean
  SIGTERM teardown — sysctls stay 0 in every leg).

The verdict semantics are backend-independent: the nft ruleset's
interpreted decisions are pinned equal to the reference pipeline
(`sav::table::evaluate`, GSC §3) by `crates/sav/tests/nft_semantics.rs`.

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
   walk as a resolution source but never as a binding source). The
   kernel-mirror participation is pinned as **intended semantics**
   (SAV-7, owner-adjudicated 2026-10-14: allow + pin — "the walk reads
   observed state"; the W5 "kernel-mirror routes never ingested" rule
   governs *bindings*, not the resolution lineage of the egress walk).
   When both new surfaces are empty the derivation is byte-identical
   to the pre-fold-in one (property-pinned, `crates/sav/tests/sib_props.rs`).

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

## Process-topology scoping (honest disclosure, pinned SAV-4)

bgpd, ospfd, and savd are separate processes in today's interim
multi-process shape, and this interface is in-process by design — so
an anchor's hook calls reach an agent instance inside the **anchor's**
process. The hosting model is pinned (SAV-4, owner-adjudicated
2026-10-14): **anchor-local no-op agents + savd-as-reference** — each
anchor registers its own no-op/logger agent in-process, and savd's
hosted `MonitorAgent` is the reference implementation visible in
tests, which the architecture's single-binary default deployment
(architecture.md §2) promotes to the production default host without
changing a line. Anchors without a registered agent simply no-op
their hooks. savd's hosted agent additionally observes savd's own
ZAPI RIB view (the `RibView` events, no peer granularity) so the
default host has a real production feed — but the adjacency-derived
suggestion path needs anchor-side events and therefore produces
suggestions only where the composition is in-process. No transport is
added to bridge the processes: that would be a wire protocol by
another name, and the wire is exactly what the flag exists to gate.

## What the flag is for, and what stays out

Repo AGENTS.md SAVNET rules: *"Draft-dependent wire protocols
(intra-domain IGP/BGP signaling, inter-domain) go behind the
`experimental-savnet` feature flag; pin implemented draft versions in
docs; isolate wire codecs."* Implemented-draft version pin (SAV-3,
owner-adjudicated 2026-10-14: pin at next sav doc touch): the four-mode
validation taxonomy — the only draft-derived *semantics* implemented —
follows `draft-ietf-savnet-general-sav-capabilities` **-03** (published
2026-06-21, an active WG document at pin time; savd's `collision-policy`
resolves that draft's §3/§5 collision cases), and the SIB / SAV-Agent
vocabulary aligns with the WG-adopted
`draft-ietf-savnet-intra-domain-architecture-05`. No wire codec exists
yet, so no codec revision is pinned. The drafts this workstream tracks
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

## BAR-SAV: the per-interface allowlist module

BAR-SAV derives per-interface permissible source-prefix allowlists
from BGP UPDATE AS_PATHs + ASPA + ROA. Implemented against
**draft-ietf-sidrops-bar-sav-10** (Sriram/Lubashev/Montgomery,
published 2026-07-19, expires 2027-01-20 — the pinned revision; local
copy: `away/2026-10-14/quarantine/barsav/bar-sav-10.txt`). The
implementation plan's §Phase 5+ pre-registered scope, landed as the
SAVNET complement: priority order unchanged (SAVNET above BAR-SAV,
owner decision), and nothing here is behind `experimental-savnet` —
the module consumes only chartered-RFC data (ROA/ASPA) plus the local
BGP speaker's own Adj-RIBs-In; there is no draft wire protocol in it.

### The algorithm (S9-a M1)

`crates/sav/src/barsav.rs` — pure, deterministic (BTree-backed),
every rule step-cited to -10. Inputs: per-adjacency BGP paths
(prefix, wire-order AS_PATH, receiving interface), the VRP set, the
ASPA set, the local AS, per-interface neighbor roles, and the two
per-interface ACLs.

**§4, customer and lateral-peer interfaces** (§2: the same procedure —
"the CC includes the AS belonging to the customer or lateral peer"):

| Draft step | Rule implemented |
|---|---|
| §4 Step 2-3 | Z(1) = {AS-k} ∪ the interface's ASN ACL |
| §4 Step 5 | A(i) = ASNs whose ASPA names a frontier member as provider |
| §4 Step 6 | AS 0 and the IANA special-purpose ASNs leave A(i) |
| §4 Step 7 | B(i) = customers of frontier members per the unique AS_PATHs in Adj-RIBs-In of ALL interfaces (wire-order pairs: the AS toward the origin is the customer) |
| §4 Step 8-9 | Z(i) = (A(i) ∪ B(i)) − seen, until a round adds nothing (the draft's preamble: ASPA and AS_PATH interleave ROUND BY ROUND, never merge) |
| §4 Step 10 | D = ∪ Z(i) — the customer cone |
| §4 Step 11 | Q1 = prefixes of ROAs whose origin ASN ∈ D |
| §4 Step 12 | Q2 = prefixes the Adj-RIBs-In show cone ASes originating |
| §4 Step 13 | Q = Q1 ∪ Q2 ∪ the Prefix ACL — the permissible list |

**§8, provider interfaces (BAR-SAV-PI)**: per customer interface
compute D and Q (§8 Step 1-2, unions Du/Qu); keep only prefixes whose
customer-interface routes are all ROV-Valid and ASPA-Valid (Step 3),
whose covering ROAs' origins all lie in Du (Step 4), and whose every
path AS has all its ASPA providers inside Du (Step 5) — that set S is
subtracted from the loose-uRPF allowed set (Step 6), the local
exemptions leave (Step 7), and G applies at every provider interface
(Step 8).

**§4's security preamble**: paths that are RPKI-ROV Invalid
(RFC 6811 §2), AS_PATH-verification Invalid
(draft-ietf-sidrops-aspa-verification §5.5/§5.6, the procedure
selected by the receiving role), or AS_SET-carrying never feed the
derivation.

The derivation's output is typed IBA rules (GSC -03 §2.1 — BAR-SAV is
one of the mechanisms GSC names as needing exactly that shape) with
provenance `RuleOrigin::BarSav` (a NEW origin, deliberately not
`SavnetAgent`), compiled through the SAME SAV table manager as every
other rule source. 19 unit tests + 5 table tests
(`crates/sav/tests/barsav_table.rs`).

### The feed (M3) and the knobs (M2)

bgpd exposes its Adj-RIB-In as a **read-only snapshot file** (the
disclosed choice — a direct query surface, not the agent interface,
which is flag-gated): `barsav feed <path>` in bgpd.conf makes a
writer task publish `LocRib::barsav_feed_text` atomically on change
(one line per prefix/peer/path, wire-order AS_PATHs, `as-set`
marked). savd joins it: `barsav feed <path>` reads the snapshot each
evaluate, resolving each peer address to an interface through the
mirror's CONNECT table (single-hop eBGP; multi-hop/iBGP feeds
§Deferred). RPKI data comes from a `barsav vrp-file <path>` snapshot
in bgpd's vrp-file format — one file can serve both daemons.

savd.conf grammar (monitor-default per the house rules; drop needs
the same `action drop` + `i-understand-drop-mode yes` friction gate
as every other generator):

```text
barsav feed <path>                  ! bgpd's Adj-RIB-In snapshot
barsav vrp-file <path>              ! ROA+ASPA snapshot (vrp-file format)
barsav local-as <asn>               ! cone guard (0 = unset, guard inert)
barsav provider-exempt <prefix>     ! -10 §8 Step 7 exemption (repeatable)
interface <name>
 mode barsav                        ! the derivation gates this interface
 role <customer|peer|provider>      ! required (the neighbor's role)
 remote-as <asn>                    ! required (AS-k, §4 Step 1)
```

A missing or unparseable input file derives NOTHING and enables
NOTHING — every BAR-SAV interface stays unjudged (unknown ≠ invalid;
the -10 §7.5.1 fail-open posture), never a seeded deny-all. The
program-level uRPF hint for BAR-SAV allowlists is Loose — the
approximation a content-blind rp_filter backend would install
(disclosed); the nft backend enforces the allowlist content, which is
the only faithful rendering.

Evidence: `scripts/test-sav-barsav.sh` (exit 0 ×2) — real FRR peers
in four bridge networks, bgpd learns the four paths (feed lines
asserted byte-exact), savd derives, and the spoof-differential proves
it: monitor-default passes everything while the kernel counters
record the loose-equivalent improper permit on the provider interface
(`urpf-baseline.txt` in the stage quarantine); in drop mode the cone
prefix still passes on the customer interface (improper block 0) and
is 100% blocked on the provider and peer interfaces — the
directionality loose uRPF cannot express. The savd/sav-nft smokes
stay green untouched.

### §Deferred (BAR-SAV)

- **The draft's open ASPA edges** (named by -10 itself): §8 Step 5's
  "all its Provider ASes (per ASPAs) contained within AS-set Du" is
  implemented as the literal vacuous truth for an unattested AS —
  which makes the top-of-cone customer (whose provider is the local
  AS, never in Du) pass on no-attestation but fail when attested to
  us. Whether the local AS belongs in Du for Step 5 is the draft's
  open edge; the smoke's snapshot simply leaves the top AS
  unattested. Same class: §8 Step 3's "all RPKI-ROV Valid" over
  zero customer routes (we require ≥1).
- **§8 Step 1's wording** computes Du over CUSTOMER interfaces only —
  whether lateral peers join the provider subtraction is unaddressed
  by the draft; we follow the letter.
- §4 Step 3/13's per-interface ASN/Prefix ACLs exist in the pure
  model (`BarNeighbor`) but have no savd.conf lines yet.
- The §8 Step 8 per-provider-interface extension of G, iBGP and
  multi-hop feeds, RTR-sourced (live, non-file) VRP/ASPA input, and
  §5's special-purpose denylist.
