# Rouster — Operator Surfaces (rousterctl v1)

Date: 2026-10-10
Status: Decided (v1 shipped)
Companion docs: [architecture.md](architecture.md), [implementation-plan.md](implementation-plan.md)

`rousterctl` v1 is a single static binary with **no daemon, no IPC
protocol, and no dependencies**: every answer comes from files a
Rouster daemon already publishes in the run dir. This document is the
contract — the command table, the run-dir files and who writes them,
the exit codes, and how these surfaces map onto the future vtysh shim.

---

## 1. Command table (v1)

| Command | What it does | Source | Exit codes |
|---|---|---|---|
| `rousterctl show sav [--json]` | savd's published status: installed rule set (aligned table), running-config summary, monitor counters, pid liveness assessment | `<run-dir>/savd.status` + `<run-dir>/savd.pid` | 0 ok · 3 no status published · 4 dead pid |
| `rousterctl status` | Run-dir inventory: savd running / stale / early, rousterd zapi sockets if present | run dir listing + savd files | 0 · 4 stale files |
| `rousterctl --help` / `-h` | Every subcommand, flag, and exit code | — | 0 |
| `rousterctl --version` / `-V` | The CLI's version | `CARGO_PKG_VERSION` | 0 |

Global flag: `--run-dir <PATH>` (default `/run/rouster`). `--json` is a
`show sav` flag only — on `status` or before the subcommand it is a
usage error, so a flag's meaning never depends on where it sits.

Exit codes: **0** ok, **2** usage error (complaint + help on stderr),
**3** not found (the needed run-dir file does not exist), **4** not
running (stale files naming a dead pid).

## 2. The run-dir contract (who writes what)

`/run/rouster/` is the workspace's sanctioned run dir. v1 reads only —
`rousterctl` never writes it.

| File | Writer | Lifecycle | v1 consumer |
|---|---|---|---|
| `savd.pid` | savd (`--pidfile`, default `/run/rouster/savd.pid`) | written at start; removed on every clean exit; only SIGKILL leaves it behind, naming a dead pid | `show sav` (liveness, preferred), `status` |
| `savd.status` | savd (`--status-file`, default `/run/rouster/savd.status`) | refreshed after every evaluate; removed on the clean-exit clear; survives SIGKILL as the last-known-installed record | `show sav` (content), `status` |
| `*.sock` | rousterd (only when its config has a `zapi socket <PATH>` line — no canonical name yet) | while the ZAPI server runs | `status` (listed as candidates) |

Consequences v1 relies on:

- `savd.status` present + `savd.pid` absent → the status file's own
  header pid is used for the liveness assessment.
- `savd.status` present + dead pid → the file is the **last-known
  record** (a SIGKILL aftermath): it still renders, but the exit is 4.
- `savd.pid` present + live pid + no `savd.status` → running, not yet
  evaluated (the status file appears after the first evaluate).
- rousterd liveness is **not knowable** today (no pidfile contract,
  no fixed socket name) — `status` lists sockets and says so. This is
  a PENDING source (§4).

### 2.1 savd.status format (as consumed)

Line-based; today's shape:

```text
savd 0.0.0 pid 4242
config mode strict-uRPF action monitor poll 5s interfaces 2 bindings 0
installed 2 rules                       (or: installed 0 rules (never evaluated))
rule allow if#2 [198.51.100.0/24] strict monitor     (IBA)
rule block if#7 [192.0.2.0/26] drop                  (IBB)
rule allow 2001:db8:1::/48 if [2, 3] monitor         (PBA)
rule block 192.0.2.128/25 if [7, 9] monitor          (PBB)
monitor source simulation invalid=0 valid=0 unknown=0
```

**Tolerance contract** (the format is savd's to grow; rousterctl
adapts, not the reverse): unknown *lines* are counted and dropped;
known *keywords* are picked out wherever they sit on their line, so
added fields ride along harmlessly; a `rule` line matching no known
shape is kept verbatim (rendered in the table, carried as
`{"kind":"raw"}` in JSON) so no operator data is lost; a malformed
number leaves its field unset rather than failing the parse. Parsing
never fails. The fixture corpus pinning this lives in
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
  *is* savd — pid reuse can fool them.

## 3. vtysh-shim mapping (edge adapter, planned)

The vtysh shim is a translator at the compatibility edge
(architecture invariant 1); `rousterctl`'s run-dir reads are the
native surface underneath it. Mapping, informed by the observed FRR
grammar subset (quarantine B7):

| vtysh command (future) | Native source | Status |
|---|---|---|
| `show sav` (FRR has no native equivalent — Rouster extension) | `savd.status` via `rousterctl show sav` | **v1: shipped** |
| `show ip route` / `show ipv6 route` | rousterd RIB dump | **PENDING source** — S1's rousterd status surface, not yet built; do not implement against a guessed format |
| `show vrf` | rousterd VRF/interface dump | **PENDING source** — same |
| `show neighbour(s)` | protocol crates' session state | **PENDING source** — no publisher today |
| `show running-config` | YANG-native config store | out of v1 scope (Phase 4) |

When a PENDING source lands, the pattern to repeat is today's:
daemon publishes a run-dir file (or a dump command with a pinned
format) → rousterctl parses tolerantly with a fixture corpus → the
shim maps vtysh grammar onto it. The shim must verify state, never
trust exit codes (B7 §4.2: `vtysh -b` exits 0 even when apply fails
— the same discipline applies in reverse).

## 4. Non-goals (v1)

No writes to the run dir, no daemon management (start/stop stay with
the operator's process supervisor), no config editing (YANG-native
northbound is Phase 4), no new dependencies — the crate is std-only
by design; pulling in a parser or JSON crate is an owner decision to
record, not a patch detail.
