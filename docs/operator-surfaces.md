# Rouster — Operator Surfaces (rousterctl v1)

Date: 2026-10-10 · v2 extension: 2026-10-11 (W2-f)
Status: Decided (v1 shipped; v2 adds the rousterd dump consumers)
Companion docs: [architecture.md](architecture.md), [implementation-plan.md](implementation-plan.md), [protocols/vty.md](protocols/vty.md)

`rousterctl` is a single static binary with **no daemon, no IPC
protocol, and no dependencies**: every answer comes from files a
Rouster daemon already publishes in the run dir. This document is the
contract — the command tables, the run-dir files and who writes them,
the exit codes, and how these surfaces map onto the vtysh shim (the
`vty` crate, whose `vtyd` speaks the Cisco grammar over the same
files).

---

## 1. Command table

### 1.1 rousterctl

| Command | What it does | Source | Exit codes |
|---|---|---|---|
| `rousterctl show sav [--json]` | savd's published status: installed rule set (aligned table), running-config summary, monitor counters, pid liveness assessment | `<run-dir>/savd.status` + `<run-dir>/savd.pid` | 0 ok · 3 no status published · 4 dead pid |
| `rousterctl show interface [NAME] [--json]` | the interface table rousterd mirrors: name, ifindex, up/down, flags, addresses, VRF membership, `vrf-table` for VRF devices | `<run-dir>/rousterd.status` | 0 · 3 no dump, or NAME names nothing · 4 dead header pid |
| `rousterctl show neighbour [PREFIX] [--json]` | the ARP/NDP mirror; PREFIX filters (bare address = host route, either family) | `<run-dir>/rousterd.status` | 0 · 3 no dump, or PREFIX matches nothing · 4 |
| `rousterctl show vrf [--json]` | VRF devices: bound table, member count, the owning table's route/kernel counts | `<run-dir>/rousterd.status` | 0 · 3 · 4 |
| `rousterctl show rib summary [--json]` | per-table route/prefix/connected/kernel counts with VRF associations | `<run-dir>/rousterd.status` | 0 · 3 · 4 |
| `rousterctl status` | Run-dir inventory: savd running / stale / early, rousterd running / stale from its dump's header pid (socket-candidate fallback when no dump exists) | run dir listing + savd files + `rousterd.status` | 0 · 4 stale files |
| `rousterctl --help` / `-h` | Every subcommand, flag, and exit code | — | 0 |
| `rousterctl --version` / `-V` | The CLI's version | `CARGO_PKG_VERSION` | 0 |

Global flag: `--run-dir <PATH>` (default `/run/rouster`). `--json` is
a show-command flag only — before the subcommand or on `status` it is
a usage error, so a flag's meaning never depends on where it sits.
An *unfiltered* empty table is a fine answer (exit 0); only a filter
that names nothing is a 3.

Exit codes: **0** ok, **2** usage error (complaint + help on stderr),
**3** not found (the needed run-dir file does not exist, or a filter
that names nothing in it), **4** not running (stale files naming a
dead pid).

### 1.2 vtyd (the vtysh-compatible surface)

The same run-dir files under Cisco grammar (`vtyd --command '...'`
is the `vtysh -c` analog; exit 0 ran / 1 transport / 2 not-a-command,
with source-state complaints as output — B7 §4.2: verify state, never
trust rc):

| vty command | Native source | Notes |
|---|---|---|
| `show sav [rules]` | `savd.status` | W1-c |
| `show bfd [summary]` | `bfdd.status` | W1-c |
| `show interface [NAME]`, `show ip interface [NAME]` | `rousterd.status` | one AF-agnostic table under both names (disclosed) |
| `show neighbor [ADDR\|PREFIX]` | `rousterd.status` | Rouster extension (FRR has no ARP-table vty command); filter is either family, bare or CIDR |
| `show vrf` | `rousterd.status` | FRR name |
| `show ip route summary`, `show rib summary` | `rousterd.status` | the FRR name and the rousterctl-parity name render the same summary (every table, both AFs — the dump is AF-agnostic) |
| `show running-config`, config mode | session-local | parse-only (W1-c; the apply design is recorded in [protocols/vty.md](protocols/vty.md) — file+SIGHUP interim, config-manager target — the build is Phase 4) |

## 2. The run-dir contract (who writes what)

`/run/rouster/` is the workspace's sanctioned run dir. v1 reads only —
`rousterctl` never writes it. (The recorded vtyd apply design
([protocols/vty.md](protocols/vty.md), K3) will amend this when it
lands: vtyd becomes the one sanctioned writer of *candidate* config
files there; `rousterctl` stays read-only.)

**Reader note (N8)**: all three status files are parsed by ONE
implementation — `common::rundir` (std-only), one parser table per
format (§2.1 savd, §2.3 rousterd, plus bfdd's session file per
`docs/protocols/bfd.md`), one tolerance engine underneath them all.
The edge consumers (rousterctl, vty) map from the reader's typed
structs into their own render shapes; they no longer carry parser
copies. The canonical fixture corpus lives in
`crates/common/tests/fixtures/` (the union of the per-consumer
corpora); the per-consumer mirrors stay in place pinning their own
suites (test-side mirroring is the adopted G2 deviation — unifying
the mirrors is a separate owner call).

| File | Writer | Lifecycle | v1 consumer |
|---|---|---|---|
| `savd.pid` | savd (`--pidfile`, default `/run/rouster/savd.pid`) | written at start; removed on every clean exit; only SIGKILL leaves it behind, naming a dead pid | `show sav` (liveness, preferred), `status` |
| `savd.status` | savd (`--status-file`, default `/run/rouster/savd.status`) | refreshed after every evaluate; removed on the clean-exit clear; survives SIGKILL as the last-known-installed record | `show sav` (content), `status` |
| `rousterd.status` | rousterd (A21 dump, `crates/rousterd/src/status.rs`) | refreshed on the main loop's reconcile tick (10 s; first tick at startup); **not** written on the `--once` path; **not** removed on clean exit (the header pid makes the stale file detectable — see §2.3) | `show interface/neighbour/vrf/rib summary` (content + header-pid liveness), `status`, the vty views |
| `*.sock` | rousterd (only when its config has a `zapi socket <PATH>` line — no canonical name yet) | while the ZAPI server runs | `status` (fallback candidates when no dump exists) |

Consequences the consumers rely on:

- `savd.status` present + `savd.pid` absent → the status file's own
  header pid is used for the liveness assessment.
- `savd.status` present + dead pid → the file is the **last-known
  record** (a SIGKILL aftermath): it still renders, but the exit is 4.
- `savd.pid` present + live pid + no `savd.status` → running, not yet
  evaluated (the status file appears after the first evaluate).
- `rousterd.status` present + dead header pid → same last-known-record
  rule: renders, exit 4 (rousterd has no pidfile; the dump's header
  pid is its live word).
- `rousterd.status` absent → `status` falls back to listing zapi
  socket candidates and discloses the older-rousterd possibility.

### 2.1 savd.status format (as consumed)

Line-based; today's shape:

```text
savd 0.0.0 pid 4242
config mode strict-uRPF action monitor poll 5s interfaces 2 bindings 0 collision ignore hysteresis 3s backend rp_filter
installed 2 rules                       (or: installed 0 rules (never evaluated))
rule allow if#2 [198.51.100.0/24] strict monitor     (IBA)
rule block if#7 [192.0.2.0/26] drop                  (IBB)
rule allow 2001:db8:1::/48 if [2, 3] monitor         (PBA)
rule block 192.0.2.128/25 if [7, 9] monitor          (PBB)
monitor source simulation invalid=0 valid=0 unknown=0
count iba permit #2 [198.51.100.0/24] monitor (from fib) invalid=1 valid=6 unknown=0
```

The `count` lines are the GSC §4 "count" per-op cut of the `monitor`
aggregate: one line per op that has judged anything, the op rendered
in the daemon's effective-op vocabulary (provenance suffix included
when the contributing rules agreed on an origin). Their numbers are
kernel-sourced when the enforcement backend answers per-op counter
reads (`backend nft` — the `monitor` line's `source` says `dataplane`
and the rows sum to it); otherwise they are the sav layer's
route-lookup simulation tallies. Only ops that judged something
render (zero rows are noise).

**Tolerance contract** (the format is savd's to grow; rousterctl
adapts, not the reverse): unknown *lines* are counted and dropped;
known *keywords* are picked out wherever they sit on their line, so
added fields ride along harmlessly; a `rule` line matching no known
shape is kept verbatim (rendered in the table, carried as
`{"kind":"raw"}` in JSON) so no operator data is lost; a malformed
number leaves its field unset rather than failing the parse. Parsing
never fails. The canonical fixture corpus pinning this lives in
`crates/common/tests/fixtures/` (the reader's own suite); the
rousterctl mirror that pins this CLI's rendering stays in
`crates/rousterctl/tests/fixtures/`.

### 2.2 Liveness method (disclosed)

- **Linux**: `/proc/<pid>` existence (no signal rights needed).
- **macOS / other Unixes**: `/bin/kill -0 <pid>` — success is alive;
  "operation not permitted" is also alive (EPERM: the process exists,
  it just is not ours to signal); anything else is dead. A failed
  probe is `unknown`, never guessed.
- Pid 0 is fenced off before any probe (`kill -0 0` would signal the
  whole process group).
- Residual caveat, accepted for v1: none of these prove the pid still
  *is* the daemon — pid reuse can fool them.

### 2.3 rousterd.status format (as consumed)

Line-based, written by `crates/rousterd/src/status.rs` on the
reconcile cadence; today's shape:

```text
rousterd 0.0.0 pid 4242
router-id 198.51.100.1                      (or: router-id none)
interfaces 4
interface lo ifindex 1 up flags UP|LOOPBACK|RUNNING vrf -
  address 127.0.0.1/8
interface vrf-blue ifindex 5 up flags UP|BROADCAST|RUNNING|MULTICAST vrf - vrf-table 1001
interface eth1 ifindex 6 up flags UP|BROADCAST|RUNNING|MULTICAST vrf vrf-blue
  address 198.51.100.1/24
neighbours 2
neighbour 192.0.2.10 ifindex 2 state INCOMPLETE lladdr -
neighbour 198.51.100.9 ifindex 6 state REACHABLE lladdr 02:00:00:00:00:11
tables 2
table 254 routes 1 prefixes 1 connected 3 kernel 1 vrf -
table 1001 routes 0 prefixes 0 connected 1 kernel 1 vrf vrf-blue
```

**Tolerance contract** (same rules as §2.1, the format is rousterd's
to grow): unknown *lines* are counted and dropped; known *keywords*
are picked wherever they sit on their line; a value position never
swallows another keyword (a `flags` whose value is missing does not
eat the next word); indented `address` lines attach to the interface
above them; a malformed number leaves its field unset. Parsing never
fails. `router-id` is only rendered when it parses as an address.

**Semantics pinned** (the writer's module docs hold the rationale):

- `interface ... vrf <name>` is *membership*: the VRF device this
  link is enslaved to (`-` otherwise). A VRF device itself instead
  carries `vrf-table <id>` — the routing table it binds.
- `flags`/`state` are the kernel bit words, named bits pipe-joined
  with a hex remainder (`UP|RUNNING|0x30`); consumers treat them as
  opaque tokens.
- `table` lines enumerate `{254} ∪ static keys ∪ connected keys ∪
  VRF-bound tables` — the rib exposes no "all table ids" iterator;
  protocol tables existing only in other ids are not listed (nothing
  creates them today; disclosed so the gap is known when it first
  matters).
- Counts are *candidates*, not bests (FRR's summary distinguishes
  per-protocol rows; this is the additive v1 form).
- Lifecycle deviation from savd/bfdd, disclosed: no pidfile, no
  clean-exit removal (the one-line wiring budget in rousterd's main);
  the header pid is the liveness word, and a stale file is the
  last-known record.

The canonical fixture corpus pinning this lives in
`crates/common/tests/fixtures/` (`rousterd-status-*.status`;
`full`/`empty` are generated from the writer's real renders, which
the writer's own tests byte-pin). The per-consumer mirrors stay in
`crates/rousterctl/tests/fixtures/` and `crates/vty/tests/fixtures/`
for their own suites (the former W1-c in-crate-parser deviation is
resolved — N8 consolidated the parsing itself into
`common::rundir`; only the mirrored fixtures remain, per the adopted
G2 keep-mirrors decision).

## 3. vtysh-shim mapping (edge adapter)

The vtysh shim is a translator at the compatibility edge
(architecture invariant 1); `rousterctl`'s run-dir reads are the
native surface underneath it, and the `vty` crate (W1-c) is that
translator today — `vtyd` reads the same run-dir files through the
same shared reader (`common::rundir`, the N8 consolidation) and
renders them under Cisco grammar (§1.2).
Mapping, informed by the observed FRR grammar subset (quarantine B7):

| vtysh command | Native source | Status |
|---|---|---|
| `show sav` (FRR has no native equivalent — Rouster extension) | `savd.status` via `rousterctl show sav` / `vtyd show sav` | **v1: shipped** |
| `show ip route` / `show ipv6 route` | rousterd RIB dump | **summary shipped** (W2-f: `show ip route summary`, both AFs in one table); per-route rows still PENDING (the dump carries counts, not routes) |
| `show interface` / `show ip interface [NAME]` | `rousterd.status` interface table | **v2: shipped** (W2-f) |
| `show vrf` | `rousterd.status` VRF devices | **v2: shipped** (W2-f) |
| `show neighbor` (Rouster extension — FRR has no ARP-table vty command) | `rousterd.status` neighbour mirror | **v2: shipped** (W2-f) |
| `show running-config` | YANG-native config store | out of v1 scope (Phase 4) |
| bgpd/ospfd session state (`show bgp summary`, `show ip ospf neighbor`) | bgpd/ospfd status writers | **PENDING sources** — neither daemon publishes a run-dir status yet; when W2-d/W2-e grow writers, the pattern to repeat is this one (publish → tolerant parse + fixture corpus → shim maps the grammar) |

When a PENDING source lands, the pattern to repeat is today's:
daemon publishes a run-dir file (or a dump command with a pinned
format) → a format table joins the ONE reader (`common::rundir`)
with fixture-corpus coverage there → the edge surfaces map their
views onto it → the shim maps vtysh grammar over the same parse. The shim must verify state, never
trust exit codes (B7 §4.2: `vtysh -b` exits 0 even when apply fails
— the same discipline applies in reverse). The end-to-end proof of
the whole chain (writer → files → both consumers, content-asserted)
is `scripts/test-vty-smoke.sh`, auto-discovered by
`scripts/run-smokes.sh`.

## 4. Non-goals (v1/v2)

No writes to the run dir, no daemon management (start/stop stay with
the operator's process supervisor), no config editing (YANG-native
northbound is Phase 4), no external crates — the crate stays free of
outside dependencies by design; its single dependency is the
workspace member `common` (the N8-consolidated run-dir reader;
pulling in a parser or JSON crate remains an owner decision to
record, not a patch detail). Per-route `show ip route` rows (not just
the summary) need a dump format decision (route lines in
`rousterd.status`, or a separate dump file) — an owner decision to
record when the demand lands.
