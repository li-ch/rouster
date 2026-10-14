# configd — the canonical `rouster.conf`, the apply pipeline, and the run-dir contract extension

Status: v1 shipped (Phase 4 opener, 2026-10-14). configd is the
K3 interim the owner recorded in [vty.md](vty.md) "Config apply —
the recorded design": the config-manager is the target, file+SIGHUP
is the interim it orchestrates. This doc is the canonical grammar's
owner (v1), the pipeline's contract, and the §Deferred ledger for
everything that deliberately did not land. Companion:
[../operator-surfaces.md](../operator-surfaces.md) (the run-dir
contract this extends), [../implementation-plan.md](../implementation-plan.md)
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

Semantic validation **stays with each daemon at reload time**: a
`mode nosuch` inside `daemon savd` passes configd and is refused by
savd's own parser at SIGHUP (the daemon keeps its running config —
every landed SIGHUP arm behaves this way). Moving semantic
validation earlier needs `--validate-config` arms in the daemon
crates (§Deferred). The `router-id` directive is validated by
configd but **rendered nowhere in v1**: no daemon's grammar accepts
the line yet, and emitting it would poison the rendered file. It is
recorded in the tree and the status file, ready for the first daemon
that grows a consumer (the exact per-daemon asks are §Deferred).

Section order in the file does not matter; apply order is
configd's registry (§2), not file order.

## 2. The apply pipeline

```text
              rouster.conf (canonical, operator-owned)
                            │ read
                            v
                 parse → section tree (structural validate)
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
        generation record <run>/configd/        SIGHUP per ARMED daemon:
        generations/<seq>-<hash>/rouster.conf     rousterd (pid = rousterd.status
        current / previous pointers                header — no pidfile exists),
        + history prune (keep 8)                   savd, bfdd (pidfiles).
                            │                      ospfd/bgpd: NO arm — never
                            v                      signaled (default disposition
              <run>/configd.status                 would terminate them)
```

- **Render** is byte-stable: body lines verbatim (leading whitespace
  preserved — cosmetic to every token-per-line grammar), trailing
  blank body lines dropped, exactly one final newline, and
  idempotent (`render(parse(render(x))) == render(x)`) — the
  property rollback relies on when a generation is re-applied.
- **Atomic write**: temp file in the destination directory + fsync +
  rename — a daemon never re-parses a half-written file. Per-file
  atomicity only: on a mid-apply write failure the earlier files are
  already replaced and no generation is recorded (disclosed;
  cross-file atomicity is the auto-rollback §Deferred).
- **Signal** happens only for daemons with a section, in dependency
  order (rousterd — the RIB/zebra — first, protocols after). A dead
  or missing pid is **not** a failure: the file is in place for the
  next start (`not-running` in the outcome). Liveness and pid
  sources follow the run-dir contract (operator-surfaces §2):
  `savd.pid`/`bfdd.pid` pidfiles, the `rousterd.status` header pid
  via `common::rundir`, `/proc` then `kill -0` with EPERM = alive,
  pid 0 fenced.
- **Generations**: every apply copies the canonical bytes to
  `<run>/configd/generations/<seq>-<hash>/rouster.conf` and swaps
  the `current`/`previous` pointers (old current becomes previous).
  `<seq>` is 6-digit monotonic; `<hash>` is a 64-bit FNV-1a of the
  canonical bytes — a change fingerprint for the status file, not a
  cryptographic checksum. History keeps the newest 8 dirs.
- **Rollback** (`configd rollback`) re-applies the previous
  generation's bytes **as a new generation** (the audit trail never
  rewrites history): render → write → signal, exactly one apply.
  Two rollbacks in a row therefore toggle, the FRR-style behavior.
  With no `previous` pointer (first apply ever) rollback refuses
  (exit 3).

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

`configd apply <FILE> | rollback | status | render <FILE>
[--dry-run]`, with `--run-dir` (default `/run/rouster`) and
`--etc-dir` (default `/etc`):

| Verb | What it does | Exit codes |
|---|---|---|
| `apply <FILE>` | full pipeline (§2) + per-daemon stdout report | 0 · 1 unreadable/rejected/write-failed · 2 usage |
| `rollback` | re-apply the previous generation | 0 · 1 · 2 · 3 no previous generation |
| `status` | prints `<run-dir>/configd.status` verbatim (the `savd --show` shape) | 0 · 2 · 3 no status published |
| `render <FILE>` | parse + render + **write** the daemon files, no signals, no generation (staging) | 0 · 1 · 2 |
| `render <FILE> --dry-run` | prints each daemon's output with its destination, touches nothing — the vtyd-integration entry point | 0 · 1 · 2 |

Dead-pid daemons never fail an apply (exit 0, `not-running`
recorded); a structurally-rejected canonical file fails it before
any file is touched.

### 4.1 The status file (`<run-dir>/configd.status`)

The house line-based format (keyword-led lines; the tolerant reader
picks known keywords wherever they sit, counts unknown lines, never
fails):

```text
configd 0.0.0
generation 2 1a2b3c4d5e6f7088
applied 1790000123
source /root/rouster.conf          (or: rollback of generation 1)
router-id 198.51.100.1             (or: router-id none)
run-dir /run/rouster
etc-dir /etc
daemons 3
daemon rousterd file /etc/rouster.conf bytes 38 pid 4242 result signaled
daemon savd file /etc/savd.conf bytes 18 pid 4243 result signaled
daemon bfdd file /etc/bfdd.conf bytes 15 result not-running
```

`result` is the **actuation record** — what configd did
(`signaled` / `not-running` / `no-signal-arm` / `signal-failed`) —
NOT the daemon's acceptance. Verifying a reload took means
re-reading each daemon's own status file, which is exactly the
auto-rollback machinery (§Deferred). `applied` is Unix seconds (no
date math without a dependency; the no-new-deps fence holds).

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
  round-trip + tolerance.
- **Integration** (`crates/configd/tests/apply_e2e.rs`): the full
  pipeline over a temp run-dir against REAL stand-in processes —
  pidfile and status-header pid sources, live SIGHUP round-trips
  (a trap-touch marker is the observable reload), dead-pid
  tolerance, rejected-canonical leaves files untouched. No
  Rouster daemon binary is host-runnable off Linux (netlink-dp
  refuses construction on non-Linux by design), so the real-daemon
  proof rides the smoke.
- **Smoke** (`scripts/test-configd-smoke.sh`, docker, in
  containers): configd applies a changed savd/bfdd config to REAL
  running daemons and their published status files change —
  savd's `config … poll Ns` line and rule set, bfdd's session
  lines — then `rollback` restores the previous behavior. This is
  the "behavior actually changed" leg (assert via status files,
  never log greps alone).

## §Deferred (the honest ledger)

1. **`--validate-config` arms in the daemon crates** — the exact
   ask: a flag each daemon binary accepts that parses a candidate
   file and exits 0/1 with line-numbered errors, so configd can
   run semantic validation BEFORE the write+signal (closing the
   "structurally fine, semantically refused" gap; the daemon keeps
   its running config on a refused reload, which is correct but
   invisible to configd today).
2. **SIGHUP arms for ospfd and bgpd** (in their crates) — the
   vty.md named prerequisite: diff-based, session-preserving
   (bfdd's reload is the pattern; invariant 2). Until they land,
   `daemon ospfd`/`daemon bgpd` sections render and write but
   reload only at next start.
3. **Pid/status publication for ospfd/bgpd** (and the rousterd
   pidfile, or standing on the status-header pid permanently) —
   the publish → tolerant parse → fixture corpus pattern
   (operator-surfaces §3).
4. **Automatic rollback on daemon error** — needs daemon
   status-file semantics for "the reload I signaled took" (a
   generation/ack handshake or status-file re-read with a
   deadline); v1's explicit `rollback` is the operator's tool.
5. **A `router-id` consumer** — the directive is validated and
   recorded; the first taker is rousterd's grammar (a `router-id`
   line in `rouster.conf`), then configd renders it into that
   section's output.
6. **The YANG mapping** — the architecture invariant-5 target: the
   canonical tree maps onto a YANG datastore; the section grammar
   and the renderer survive as the northbound parse layer and the
   southbound appliers respectively (vty.md's K3 criterion:
   nothing in this interim survives as a second source of truth).
7. **The vtyd write path** — `configd render --dry-run` is the
   pinned entry point; vtyd's `write` compiles the session tree
   into a canonical file and shells to configd apply (the K3
   interim's second half).
8. **A staticd/rousterd deployment knob** — which binary owns
   static routes (§3's note); a `static-routes owner` directive
   shape is an owner decision when the zapi-first deployment
   becomes the default.
9. **Apply concurrency lock** — a `<run>/configd/lock` (O_EXCL
   with staleness breaking) if concurrent invocations ever become
   real; v1 assumes one operator.
