# configd — the canonical `rouster.conf`, the apply pipeline, and the run-dir contract extension

Status: v1 shipped (Phase 4 opener, 2026-10-14); the S8-c round
(2026-10-14 evening) landed the deep-validation gate (each daemon's
own `--validate-config` before anything is touched) and
rollback-on-failure (post-signal acknowledgment verification +
auto-revert). configd is the K3 interim the owner recorded in
[vty.md](vty.md) "Config apply — the recorded design": the
config-manager is the target, file+SIGHUP is the interim it
orchestrates, and the vtyd write path now rides it. This doc is the
canonical grammar's owner (v1), the pipeline's contract, and the
§Deferred ledger for everything that deliberately did not land.
Companion: [../operator-surfaces.md](../operator-surfaces.md) (the
run-dir contract this extends), [../implementation-plan.md](../implementation-plan.md)
Phase 4.

The familiar analogy is FRR's `integrated-vtysh-config`; the closer
model is BIRD's single `bird.conf` — one file, sections owned by the
component that consumes them.

## 1. The canonical grammar (v1)

One superset file composes every daemon's config. Line-based like
every daemon grammar in the suite (blank / `!` / `#` lines are
ignorable), with brace-delimited per-daemon sections whose bodies
are **pass-through**: configd renders them, the owning daemon parses
them.

```text
! the canonical rouster.conf
router-id 198.51.100.1

daemon rousterd {
    zapi socket /run/rouster/zserv.api
    ip route 203.0.113.0/24 blackhole
}

daemon savd {
    mode strict
    interface vethlegit
      mode strict
    binding 192.0.2.0/24 interface vethlegit
}

daemon bfdd {
    peer 192.0.2.9
      transmit-interval 300
}

daemon ospfd {
    router ospf
      router-id 10.0.0.1
}

daemon bgpd {
    router bgp 65000
      neighbor 192.0.2.9 remote-as 65001
}
```

Structural rules (what configd validates — the whole of v1
validation):

| Rule | On violation |
|---|---|
| `daemon <name> {` opens; a lone `}` line closes | unclosed section: error naming the opener's line; `}` outside a section: error |
| `<name>` ∈ {`rousterd`, `savd`, `bfdd`, `ospfd`, `bgpd`} | `unknown daemon` error listing the known names |
| each daemon at most once | `duplicate` error at the second opener |
| `router-id <ipv4>`, at most once, configd-owned | bad address / duplicate errors |
| anything else at top level | error (the canonical file is configd's own grammar and is strict — unlike the tolerant run-dir readers) |
| body lines | pass-through verbatim (a body line is never a lone `}`; no daemon grammar uses braces — they are all token-per-line, so the terminator is unambiguous) |

Semantic validation **runs pre-apply since S8-c**: each section's
rendered bytes go through the owning daemon's own `--validate-config`
arm (§2 step 1.5) — a semantically dead line like `mode nosuch`
inside `daemon savd` refuses the apply before any file is touched,
with the daemon's line-numbered complaint verbatim. The `router-id`
directive is validated by configd but **rendered nowhere in v1**: no
daemon's grammar accepts the line yet, and emitting it would poison
the rendered file. It is recorded in the tree and the status file,
ready for the first daemon that grows a consumer (the exact
per-daemon asks are §Deferred).

Section order in the file does not matter; apply order is
configd's registry (§2), not file order.

## 1.5 The YANG layer (S11-a M4 — invariant 5's flip)

Since S11-a the canonical file's section bodies BIND to YANG models
(`yang/*.yang`, parsed by `crates/yang` — the RFC 7950-subset core):
each section body → a data tree against its daemon's module. The
tree is the **internal source of truth**: validation runs on it
(§8.1: types at bind time, mandatory/leaf-list/`must` after), and
the per-daemon files RENDER FROM THE TREES — byte-identical to the
section-split render (pinned by `crates/configd/tests/yang_flip.rs`
against the legacy renderer, which stays as the oracle and the
`--no-yang` escape's fallback). The text grammar remains the edge
input; the daemon `--validate-config` gates stay (§2 step 1.5) — a
line the model does not cover is pass-through, disclosed, and the
daemon remains its semantic gate. `configd dump --json <FILE>`
emits the bound trees in the RFC 7951 JSON encoding (defaults
filled; a non-standard `#unmodeled-<daemon>` member carries the
pass-through disclosure) — the form is documented in
[../yang.md](../yang.md).

## 2. The apply pipeline

```text
              rouster.conf (canonical, operator-owned)
                            │ read
                            v
                 parse → section tree (structural validate)
                            │
                            v
        1.4 YANG bind+validate (S11-a M4): each section body binds
            to its model; tree violations refuse the apply with
            data-path + line errors; unmodeled lines are disclosed
            pass-through (crates/yang, docs/yang.md)
                            │
                            v
        1.5 deep validation: each section's rendered bytes through
            the owning daemon's --validate-config (absent/flagless
            binary = disclosed skip; a refusal stops everything)
                            │ render (byte-stable)
                            v
        per-daemon bytes ──┬─ rousterd → <etc>/rouster.conf ─┐
                           ├─ savd    → <etc>/savd.conf       │ atomic write
                           ├─ bfdd    → <etc>/bfdd.conf       │ (temp+fsync+rename,
                           ├─ ospfd   → <etc>/ospfd.conf      │  in the dest dir)
                           └─ bgpd    → <etc>/bgpd.conf ──────┘
                            │                            │ registry order:
                            │                            │ rousterd, savd, bfdd,
                            │                            │ ospfd, bgpd
                            v                            v
        4.5 post-signal verification          SIGHUP per ARMED daemon:
        (10 s deadline, per signaled          rousterd (pid = rousterd.status
        daemon with an ack surface)            header — no pidfile exists),
            │                                  savd, bfdd (pidfiles).
            │ refused → AUTO-ROLLBACK:         ospfd/bgpd: NO arm — never
            │   re-apply the CURRENT (last     signaled (default disposition
            │   confirmed) generation as a     would terminate them)
            │   NEW generation; apply fails
            v
        generation record <run>/configd/        (only a fully confirmed
        generations/<seq>-<hash>/rouster.conf     apply reaches this step)
        current / previous pointers
        + history prune (keep 8)
                            │
                            v
              <run>/configd.status
```

- **Render** is byte-stable: body lines verbatim (leading whitespace
  preserved — cosmetic to every token-per-line grammar), trailing
  blank body lines dropped, exactly one final newline, and
  idempotent (`render(parse(render(x))) == render(x)`) — the
  property rollback relies on when a generation is re-applied.
- **Deep validation (step 1.5, S8-c)**: each section's rendered
  bytes go through the owning daemon binary's own
  `--validate-config` arm before anything is touched (exit 0 =
  validated; exit 1 = refused, the daemon's line-numbered stderr
  verbatim — `configd validate <FILE>` exposes the same gate as a
  verb). An absent binary, or one whose `--help` predates the flag
  (bgpd/ospfd until their streams land it), is a **disclosed skip,
  never a failure** — an operator without the daemon binaries
  installed must still be able to stage files. Binary discovery:
  `--daemon-bin-dir` / `$ROUSTER_DAEMON_BIN_DIR`, configd's own exe
  dir, then `PATH`; every validator child is bounded (5 s). The flag
  is landed in rousterd, savd, and bfdd (S8-c); gate and reload
  share each daemon's one parser, which is the point.
- **Atomic write**: temp file in the destination directory + fsync +
  rename — a daemon never re-parses a half-written file. Per-file
  atomicity only: on a mid-apply write failure the earlier files are
  already replaced and no generation is recorded (disclosed;
  cross-file atomicity is §Deferred).
- **Signal** happens only for daemons with a section, in dependency
  order (rousterd — the RIB/zebra — first, protocols after). A dead
  or missing pid is **not** a failure: the file is in place for the
  next start (`not-running` in the outcome). Liveness and pid
  sources follow the run-dir contract (operator-surfaces §2):
  `savd.pid`/`bfdd.pid` pidfiles, the `rousterd.status` header pid
  via `common::rundir`, `/proc` then `kill -0` with EPERM = alive,
  pid 0 fenced. Each ack-able daemon's status-file mtime is
  captured BEFORE the signal — the "has the daemon spoken since"
  comparison point for step 4.5.
- **Post-signal verification (step 4.5, S8-c)**: for every SIGNALED
  daemon with an ack surface, configd polls the daemon's status file
  (100 ms cadence, 10 s deadline) for the rendered config's
  projection. What each daemon can honestly report today:

  | Daemon | Ack surface | The projection checked |
  |---|---|---|
  | `savd` | `savd.status`'s `config` line | `poll <N>s`, `interfaces <n>`, `bindings <n>` (the default 5 s poll is mirrored — configd takes no cross-crate dependency, `sav::savd::DEFAULT_POLL_SECS` pinned by test) |
  | `bfdd` | `bfdd.status`'s session lines | every configured `peer <ip>` appears in a `session peer <ip>` line (subset: dynamic zapi sessions cannot false-fail; a refused *removal* is therefore not detected — disclosed) |
  | `rousterd` | none | `rousterd.status` carries interface/route tables, not config content — `no-ack-surface` (§Deferred) |
  | `ospfd`/`bgpd` | — | never signaled; nothing to verify |

  The verdicts: **confirmed** (the projection matches — the SIGHUP
  arms republish immediately after their reload, so this is fast on
  success); **failed** (the status was rewritten after the signal
  AND disagrees — the daemon's own current word names a refused
  reload); **unverified** (deadline, no evidence either way — NEVER
  a rollback trigger: absence of evidence is not evidence);
  **no-status**. A `failed` verdict triggers the auto-rollback
  BEFORE the generation is recorded — a refused apply never advances
  `current`, and `current` still names the last confirmed config,
  which is exactly what the revert re-applies.
- **Auto-rollback** re-applies the current (last confirmed)
  generation through the full pipeline as a NEW generation (history
  is never rewritten; the audit trail shows the refusal and the
  revert), then fails the apply with the honest story: `daemon savd
  refused the reload: expected poll 3s …, saw poll 2s … —
  auto-rolled back to generation 3 (now generation 4)`. One bounce
  only — the revert pass never auto-reverts again (if the REVERT is
  itself refused, both facts surface in one error). With no
  confirmed generation (the first apply ever) there is nothing to
  revert to: the daemon kept its running config, the on-disk file
  holds the refused bytes, and the error says both (the next start
  of that daemon would load them — operator action required).
- **Generations**: every fully confirmed apply copies the canonical
  bytes to `<run>/configd/generations/<seq>-<hash>/rouster.conf` and
  swaps the `current`/`previous` pointers (old current becomes
  previous). `<seq>` is 6-digit monotonic; `<hash>` is a 64-bit
  FNV-1a of the canonical bytes — a change fingerprint for the
  status file, not a cryptographic checksum. History keeps the
  newest 8 dirs.
- **Rollback** (`configd rollback`) re-applies the previous
  generation's bytes **as a new generation** (the audit trail never
  rewrites history): render → write → signal → verify, exactly one
  apply. Two rollbacks in a row therefore toggle, the FRR-style
  behavior. A rollback whose reload is refused bounces back to the
  config it was leaving (the same auto-revert, one bounce). With no
  `previous` pointer (first apply ever) rollback refuses (exit 3).

## 3. The daemon registry (v1)

| Daemon | Rendered file | Pid source | SIGHUP arm | Why |
|---|---|---|---|---|
| `rousterd` | `rouster.conf` | `rousterd.status` header (no pidfile exists — operator-surfaces §2.3's disclosed gap) | **yes** | re-parses + diffs static routes; a changed `zapi socket` path is refused with a warning (startup-only knob) |
| `savd` | `savd.conf` | `savd.pid` | **yes** | re-parses (drop-friction line re-checked), swaps the SIB's Config origin, regenerates |
| `bfdd` | `bfdd.conf` | `bfdd.pid` | **yes** (diff-based) | unchanged peers keep their sessions — the invariant-2 seam |
| `ospfd` | `ospfd.conf` | — | **no** | signals are SIGTERM/SIGINT only; a SIGHUP under the default disposition would terminate the daemon. Files render + write; reload waits for the next start |
| `bgpd` | `bgpd.conf` | — | **no** | same: SIGTERM/SIGINT → Cease, SIGUSR1 → refresh; no HUP arm |

`staticd` has no section in v1: it renders the same grammar as
`rousterd`'s (it IS the static-route grammar, fed over ZAPI), and
rousterd's direct config load is the legacy path the smokes still
use. Choosing per-deployment between "rousterd loads routes
directly" and "staticd owns them" needs a configd knob that does
not exist yet (§Deferred).

**Daemon config paths**: no daemon binary ships a default
`--config` path (all require `--config`/`-f`), so the deployment
convention is the contract: `<etc-dir>/<daemon>.conf` with
`--etc-dir` defaulting to `/etc` — the flat-`/etc` shape every
existing smoke script uses (`/etc/rouster.conf`,
`/etc/savd.conf`, …). Daemons must be started pointing at these
paths (the operator's process supervisor owns start lines).

## 4. The operator surface

`configd validate <FILE> | apply <FILE> | rollback | status | render
<FILE> [--dry-run]`, with `--run-dir` (default `/run/rouster`),
`--etc-dir` (default `/etc`), and `--daemon-bin-dir` (validate/apply
binary discovery, default: configd's own dir then `PATH`):

| Verb | What it does | Exit codes |
|---|---|---|
| `validate <FILE>` | parse + render in memory + run each section through the owning daemon's `--validate-config` (§2 step 1.5); nothing written, nothing signaled; skips are honest warnings | 0 · 1 unreadable/structurally-rejected/refused · 2 usage |
| `apply <FILE>` | full pipeline (§2) + per-daemon stdout report with ack verdicts | 0 · 1 unreadable/rejected/refused/write-failed/**auto-rolled-back** · 2 usage |
| `rollback` | re-apply the previous generation | 0 · 1 · 2 · 3 no previous generation |
| `status` | prints `<run-dir>/configd.status` verbatim (the `savd --show` shape) | 0 · 2 · 3 no status published |
| `render <FILE>` | parse + render + **write** the daemon files, no signals, no generation (staging) | 0 · 1 · 2 |
| `render <FILE> --dry-run` | prints each daemon's output with its destination, touches nothing | 0 · 1 · 2 |
| `dump --json <FILE>` | the bound trees in the RFC 7951 JSON encoding (needs the YANG mode) | 0 · 1 · 2 |

Dead-pid daemons never fail an apply (exit 0, `not-running`
recorded); a structurally- or semantically-rejected canonical file
fails it before any file is touched. An auto-rolled-back apply exits
1 — the operator must know what was refused — and prints the revert
report (what the system runs now) after the failure story.

### 4.1 The status file (`<run-dir>/configd.status`)

The house line-based format (keyword-led lines; the tolerant reader
picks known keywords wherever they sit, counts unknown lines, never
fails):

```text
configd 0.0.0
generation 2 1a2b3c4d5e6f7088
applied 1790000123
source /root/rouster.conf
router-id 198.51.100.1             (or: router-id none)
run-dir /run/rouster
etc-dir /etc
daemons 3
daemon rousterd file /etc/rouster.conf bytes 38 pid 4242 result signaled ack no-ack-surface
daemon savd file /etc/savd.conf bytes 18 pid 4243 result signaled ack confirmed
daemon bfdd file /etc/bfdd.conf bytes 15 result not-running
```

`source` also renders `rollback of generation N` (the explicit verb)
and `auto-rollback to generation N (post-signal load refusal)` (the
M3 pass — such a status file describes the REVERT, the config the
system actually runs). `result` is the **actuation record** — what
configd did (`signaled` / `not-running` / `no-signal-arm` /
`signal-failed`); `ack` (S8-c) is the acceptance half: the
post-signal verification verdict per SIGNALed daemon (`confirmed` /
`unverified` / `no-status` / `no-ack-surface`). A `failed` ack never
appears here — it triggers the auto-rollback, and the published file
describes the revert. `applied` is Unix seconds (no date math
without a dependency; the no-new-deps fence holds).

### 4.2 Run-dir contract extension

The read-only run-dir rule (operator-surfaces §2) gains one writer,
the configd apply path itself (the vty.md K3 interim predicted
exactly this shape for a writer; configd, not vtyd, is who landed):

| File | Writer | Lifecycle |
|---|---|---|
| `configd/generations/<seq>-<hash>/rouster.conf` | configd apply | written per apply; pruned to newest 8 |
| `configd/current`, `configd/previous` | configd apply | one line each (the generation dir name); `previous` appears from the second apply on |
| `configd.status` | configd apply | refreshed every apply (also on rollback applies) |

`rousterctl` stays read-only; `savd.pid`/`savd.status`/`bfdd.*`/
`rousterd.status` ownership is unchanged. configd only READS those
(pid sources). Single-writer assumption v1: one configd invocation
at a time (no lockfile; disclosed).

## 5. Testing

- **Unit** (`crates/configd`): tree/validate, render byte-stability
  and idempotence, atomic-write machinery, pid sources and
  liveness, apply order, generation/rollback/prune, status
  round-trip + tolerance, the deep-validation gate (stand-in
  daemon binaries: accepted / refused-verbatim / no-binary and
  flagless skips / wedged-validator bound), and the verification
  verdicts (projections against the real status-file shapes, the
  stale-file-is-not-failure rule, the rewrite-before-refusal rule).
- **Integration** (`crates/configd/tests/`): the full pipeline over
  a temp run-dir against REAL stand-in processes — pidfile and
  status-header pid sources, live SIGHUP round-trips (a stand-in
  that republishes a `savd.status`-shaped word from its config
  file is the observable reload), dead-pid tolerance,
  rejected-canonical leaves files untouched, the pre-apply gate's
  refusal, and the auto-rollback (a stand-in that refuses a
  poison-marked config → the apply fails, the last confirmed
  generation is re-applied as a new one, the status file describes
  the revert) plus the first-apply-refusal honest error. No
  Rouster daemon binary is host-runnable off Linux (netlink-dp
  refuses construction on non-Linux by design), so the real-daemon
  proof rides the smoke.
- **Smoke** (`scripts/test-configd-smoke.sh`, docker, in
  containers): configd applies a changed savd/bfdd config to REAL
  running daemons and their published status files change —
  savd's `config … poll Ns` line and rule set, bfdd's session
  lines — then `rollback` restores the previous behavior; a
  semantically-bad canonical is refused by savd's own
  `--validate-config` with nothing touched; and the auto-rollback
  leg proves the catch-and-revert in the container (a stand-in
  daemon provides the load-refusal window the real daemons cannot
  — their validate and load parsers are the same fn, disclosed).
  Always asserted via status files, never log greps alone.

## §Deferred (the honest ledger)

1. **DONE (S8-c)** ~~`--validate-config` arms in the daemon crates~~
   — landed in rousterd, savd, and bfdd (the pre-apply gate rides
   them, §2 step 1.5). The residual: bgpd/ospfd get the same flag
   from their own streams; until then their sections validate
   structurally only (the disclosed skip).
2. **SIGHUP arms for ospfd and bgpd** (in their crates) — the
   vty.md named prerequisite: diff-based, session-preserving
   (bfdd's reload is the pattern; invariant 2). Until they land,
   `daemon ospfd`/`daemon bgpd` sections render and write but
   reload only at next start.
3. **Pid/status publication for ospfd/bgpd** (and the rousterd
   pidfile, or standing on the status-header pid permanently) —
   the publish → tolerant parse → fixture corpus pattern
   (operator-surfaces §3).
4. **DONE (S8-c)** ~~Automatic rollback on daemon error~~ — landed
   as post-signal verification + auto-revert (§2 step 4.5). The
   honest residuals: **rousterd publishes no ack surface** (a
   refused reload there is `no-ack-surface`, unverifiable — needs
   config content in `rousterd.status` or a generation/ack
   handshake); **`unverified`/`no-status` never roll back** (a
   daemon wedged past the 10 s deadline keeps its old config with
   configd's report saying so — evidence, not assumption); and the
   **first-apply refusal leaves the refused bytes on disk** (the
   daemon kept its running config; the next start would load them
   — the error names it).
5. **A `router-id` consumer** — the directive is validated and
   recorded; the first taker is rousterd's grammar (a `router-id`
   line in `rouster.conf`), then configd renders it into that
   section's output.
6. **DONE (S11-a M4)** ~~The YANG mapping~~ — the bodies bind to
   `yang/*.yang` models, validate as trees, and the daemon files
   render FROM the trees (§1.5; `crates/yang` is the RFC 7950-subset
   core, `docs/yang.md` the model reference). The section grammar
   and the legacy renderer survive as the northbound parse layer
   and the byte-identity oracle (vty.md's K3 criterion holds:
   nothing is a second source of truth). The residuals live in
   `docs/yang.md` §Deferred (the full RFC 7950 surface — grouping/
   uses/augment, when, choice, anydata, deviations — and the
   cross-module data composition they enable).
7. **DONE (S8-c)** ~~The vtyd write path~~ — landed: `write file`/
   `write memory` stage the merged canonical and spawn
   `configd apply` (vty.md's "Config apply" section, rewritten as
   landed).
8. **A staticd/rousterd deployment knob** — which binary owns
   static routes (§3's note); a `static-routes owner` directive
   shape is an owner decision when the zapi-first deployment
   becomes the default.
9. **Apply concurrency lock** — a `<run>/configd/lock` (O_EXCL
   with staleness breaking) if concurrent invocations ever become
   real; v1 assumes one operator (the vtyd write path inherits
   the same single-flight assumption — one `write` at a time per
   connection, and the canonical merge is seeded per connection).
