# vty (vtyd) — the vtysh-compatible VTY server, v1

Status: weekend-program stream W1-c, delivered 2026-10-11 (commits
`62413df` parser/session core → `420e5fb` vtyd binary → `19ff65e`
test suites); **the write path landed S8-c (2026-10-14 evening)** —
`write file`/`write memory` ride `configd apply` (below).
Positioning: the interactive Cisco-style operator
surface at the compatibility edge (architecture invariant 1) —
FRR-compatible grammar and habits, Rouster-native underneath. It is
the sibling of `rousterctl` (the file-based reader): command naming
stays consistent (`show sav` on both), rousterctl stays daemonless,
vty is the interactive surface. v1 reads only the run-dir contract
and invents no IPC — the run-dir files ARE the interface — and the
write path is a process spawn of the configd CLI, not a new
channel.

## Process model

`vtyd` (tokio): one TCP listener, one task per connection, and a
pure session state machine (`vty::session`) doing all the thinking
(so every line behavior is unit-testable without a socket). `vtyd
--command 'show ...'` is a one-shot client to a running vtyd — the
`vtysh -c` analog, and what smoke scripts drive.

## Wire protocol (v1 disclosure)

A **plain TCP line protocol** — the real vtysh expects pty/unix
socket plumbing, which stays §Deferred until an interop capture
pins it. Rules:

- On connect the server sends a banner (which discloses the line
  protocol itself) and a prompt `hostname> `.
- The client submits one CRLF-terminated line per command. No
  remote echo, no telnet IAC negotiation — `nc` and scripts work
  as-is; a raw `telnet` client works best in char mode with local
  echo.
- After each command the server writes the output lines
  (CRLF-terminated) and the prompt at a fresh line start; empty
  output gets a bare `\r\n` before the prompt.
- `exit` at the bottom of the mode stack closes the connection
  without further bytes.
- Prompts are `host> ` / `host# ` / `host(config)# ` /
  `host(config-router)# ` / `host(config-router-af)# `. Hostname
  grammar is `[A-Za-z0-9._-]+` — this is load-bearing: it is why
  the one-shot client can strip framing deterministically (no
  output line can masquerade as a prompt).

## Command table (v1)

**user mode** (`host>`): `show version`, `enable`, `exit`/`quit`,
`list`, `?`.

**enable mode** (`host#`): everything above plus:

| Command | Source | Notes |
|---|---|---|
| `show sav [rules]` | `<run-dir>/savd.status` + `savd.pid` | re-rendered (aligned rule table); `rules` prints only the table |
| `show bfd [summary]` | `<run-dir>/bfdd.status` + `bfdd.pid` | per-peer sessions with `last-transition` children; `summary` prints state counts |
| `show running-config` | the canonical file + session edits | the merged canonical view (below) |
| `configure terminal` | — | enters config mode |
| `disable` | — | drops to user mode |
| `write file`, `write memory`, `wr` | → `configd apply` | **landed (S8-c)**: stages the merged canonical, spawns the configd CLI, relays its report (below) |

**config family** (`host(config)#` and the router/af submodes):
the B7 observed grammar subset (below), `exit` (pop one mode),
`end` (to enable), `do <exec command>`, `write` (deferred).

## The parser (Cisco conventions kept)

- Table-driven word tree (`vty::tree`); commands are static
  grammar slices registered per mode.
- **Abbreviated unambiguous commands**: `sh ver` = `show version`;
  `en` = `enable`. An ambiguous prefix (`e` → enable/exit) is an
  error naming the candidates.
- An exact literal beats parameter siblings (`blackhole` is never
  ambiguous with a gateway address); a token at a parameter
  position that fails validation names the expectation
  (`% Invalid input: 203.0.113.0/33 — expected <A.B.C.D/M>`).
- Error wording follows quarantine B7 §4 (observed on real FRR
  10.2.2): `% Unknown command: <input>`; plus Cisco's
  `% Incomplete command.` and `% Ambiguous command: ...`.
- `?` help anywhere: candidates with one-line help, alphabetical,
  plus `<cr>` when the line already matches; `sh?` (no space) lists
  word completions. TAB completion is §Deferred.
- Parameter kinds are validated std-only (`<WORD>`, `<A.B.C.D>`,
  `<A.B.C.D/M>`, `<X:X::X:X/M>`, `<U32>`, rest-of-line `<LINE>`).
- No enable password in v1 (disclosed: nobody has designed
  aaa/enable-secret integration; the one-shot client relies on it).

## Config mode — the B7 grammar, the canonical merge (S8-c), the YANG translator seam (S11-a M5)

`configure terminal` accepts the **quarantine-B7 observed frr.conf
grammar subset**; the vtysh-shaped grammar is the EDGE, and since
S11-a M5 every config-mode edit builds a **YANG-tree operation** —
the session config IS a `yang::DataTree` bound to the
`rouster-vty` model (`yang/rouster-vty.yang`, the same paths
configd's bind uses), so `show running-config` and `write file`
render FROM the tree (invariant 5: a translator, never a second
source of truth; the grammar stays the vtysh-compatible surface).
The merge's other half is everything in the canonical `rouster.conf`
the grammar cannot speak, loaded verbatim at connection start
(`vty::writer`):

- `frr version <s>` · `frr defaults <s>` · `line vty` (B7 §1)
- `hostname <word>` — also changes the prompt
- `ip route <v4/m> blackhole` · `ip route <v4/m> <gw>` (B7 §2) ·
  `no ip route ...` negation
- `ipv6 route <v6/m> blackhole` — B7 §7's Rouster-side grammar, not
  FRR-observed (B7 §6); included for frr.conf-import parity with
  rousterd's native config
- `route-map <rest-of-line>` — kept verbatim (bgpd's policy grammar
  eats them through its section)
- `router bgp <asn>` → `(config-router)`: `bgp network
  import-check` / `no bgp network import-check`, `bgp router-id
  <v4>`, `neighbor <v4> remote-as <asn>`; `address-family ipv4
  unicast` → `(config-router-af)`: `network <v4/m>`,
  `redistribute static`, `exit-address-family` (B7 §3)
- `!` accepted as a no-op

Anything else in config mode is rejected with the B7 error shape
(`% Unknown command: router static` — the §4.1-observed rejection).

**`show running-config` renders the merged canonical view** —
exactly what `write` writes, in the canonical `rouster.conf` shape
([protocols/config.md](config.md) §1): the session's modeled lines
project into `daemon rousterd` (statics) and `daemon bgpd` (the
flattened router-bgp stanza + route-maps), everything the canonical
file carries that the grammar cannot model rides verbatim (whole
savd/bfdd/ospfd sections, `zapi socket`, `table <N>` static forms,
policy stanzas, the `router-id` line), and the display-only
directives round-trip as `! vtyd:` comments (legal canonical
comments; no daemon consumes them). `write` never destroys config
the vty grammar cannot speak.

**`write file` / `write memory` (S8-c, landed)**: stages the merged
canonical atomically at the configured canonical path (default
`/etc/rouster.conf`), spawns `configd apply <canonical> --run-dir
… --etc-dir …` (process spawn of the CLI surface — no IPC
invention), and relays configd's report lines verbatim — per-daemon
outcomes, ack verdicts, the generation, and on refusal the
configd-side story (a failed apply prefixes `% Configuration apply
FAILED`, which is deliberately NOT a one-shot exit-2 error: verify
state, never trust rc). `write memory` = `write file` here — the
canonical file IS the startup config — disclosed at point of use in
the command's own output. Binary discovery for configd:
`$ROUSTER_CONFIGD_BIN`, vtyd's own dir, then `PATH`.

## Config apply — the recorded design (K3), LANDED as the interim

Owner decision (2026-10-11, all-options-adopted round; recorded in
the plan's Appendix C status log): **the config-manager is the
target, file+SIGHUP is the interim** (`docs/implementation-plan.md`,
2026-10-11 "later" entry). S8-c (2026-10-14 evening) landed the
interim's second half: the write path through configd, exactly the
shape this section recorded. What shipped:

1. **Merge, never clobber**: the session's edits project into the
   canonical `rouster.conf` shape over everything the file already
   carries that the vty grammar cannot speak (verbatim
   ride-through; the modeled/unmodeled table in the config-mode
   section above). The projection follows the recorded design:
   `ip`/`ipv6 route` → the rousterd section (the same FRR cut as
   rousterd's grammar), the `router bgp` subtree → the bgpd section
   with the address-family nesting flattened to router-level
   `network` lines (bgpd.conf has no address-family stanza), and
   the two modeled lines bgpd's grammar does not accept
   (`bgp network import-check`, `redistribute static`) ride as
   canonical comments — preserved for display, poisonous to
   nothing. `hostname`/`frr version`/`frr defaults`/`line vty` stay
   display-only (`! vtyd:` comments), the recorded rule: no daemon
   consumes them from a file.
2. **Stage atomically** — temp + fsync + rename at the canonical
   path (default `/etc/rouster.conf`, relocatable `--canonical`);
   configd (and any daemon) never re-reads a half-written file.
3. **Apply through configd** — `configd apply <canonical>
   --run-dir <vtyd's> --etc-dir <vtyd's>`; configd owns the render,
   the per-daemon atomic writes, the SIGHUPs, the generations, the
   deep validation, and (S8-c) the post-signal verification and
   auto-rollback. vtyd is a translator, never a second source of
   truth.
4. **Verify, never trust rc** — configd's report (per-daemon
   outcomes, ack verdicts, generation, or the refusal story) is
   relayed verbatim as the command's output; the one-shot exit
   codes stay 0/1/2 (a failed apply is OUTPUT, not exit 2).

The interim's recorded fences, as landed: the run-dir contract
gained configd (not vtyd) as its writer — vtyd itself still writes
nothing in the run dir, staging only the canonical file in the etc
dir — and the file race stays accepted and disclosed (K1): the
canonical is vtyd's write surface, operator edits to it race a
`write` exactly as they race any configd apply.

### The seams (still the source of truth for what reloads)

| Daemon | Config file | Grammar owner | SIGHUP today |
|---|---|---|---|
| `rousterd` | `rouster.conf` (its `--config`; the README quickstart shape) | `crates/rousterd/src/config.rs` — FRR-flavored strict subset: `ip`/`ipv6 route <prefix> {gw…\|blackhole} [table <N>]`, `zapi socket <PATH>` | **yes** — re-parses and the driver diffs the static routes through the RIB; a changed `zapi socket` path is refused with a warning |
| `staticd` | the same static-route shape (`--config`) | `crates/rousterd/src/staticd.rs` | **yes** — `StaticDaemon::reload` diffs onto the server |
| `savd` | `savd.conf` (`--config`) | `crates/sav/src/savd.rs` (`parse_savd_config`) | **yes** — re-parses and swaps the config, i.e. the SIB's Config origin |
| `bfdd` | `bfd.conf`-shaped (`--config`) — bfdd owns its own file; there is **no `bfd` stanza in `rouster.conf`** | `crates/bfdd/src/daemon.rs` (the savd line grammar) | **yes, diff-based: unchanged peers keep their sessions** — the soft-reconfig seam invariant 2 demands |
| `ospfd` | `ospfd.conf` | `crates/ospfd/src/config.rs` (A11/B7 strict) | **no** — the run loop wires SIGTERM/SIGINT only |
| `bgpd` | `bgpd.conf` | `crates/bgpd/src/config.rs` (A11/B7 strict; `router bgp` stanza, `route-map`/`rpki` stanzas) | **no** — signals are SIGTERM/SIGINT → ManualStop → Cease |

Pid sources for the signal step: `savd.pid` and `bfdd.pid` exist;
rousterd has no pidfile but the `rousterd.status` header pid is its
live word (operator-surfaces §2.3); staticd/ospfd/bgpd publish
neither pid nor status yet (the operator-surfaces §3 PENDING row).

### The target: a config-manager owning transactional apply

The Phase-4 endgame (implementation-plan §2 Phase 4; architecture:
"YANG-native, transactional, rollback"): a single-writer
config-manager owns candidate → validate → commit → running with
rollback; the unified `rouster.conf`-style file and gNMI/gRPC
northbound sit on the same store. vtyd becomes a pure translator —
the session tree maps to datastore edits, `write` becomes commit,
and the shim is never the source of truth (architecture invariant
5). The interim's per-daemon renderers survive as the manager's
southbound appliers; nothing in the interim survives as a second
source of truth, which is the K3 criterion for the interim at all.

## Run-dir reads (the v1 data sources)

| File | Read by | v1 use |
|---|---|---|
| `savd.status` | `show sav` | tolerant parse (S3 conventions), re-rendered with an aligned rule table |
| `savd.pid` | `show sav` | liveness, preferred over the status header's pid |
| `bfdd.status` | `show bfd` | tolerant parse (same conventions; W1-b's writer is the format owner) |
| `bfdd.pid` | `show bfd` | liveness |

Tolerance contract (both parsers): unknown lines counted and
dropped; known keywords picked wherever they sit so added fields
ride along; shapes that match nothing are kept verbatim
(savd rules) or counted (bfd sessions); malformed numbers leave
their field unset (`?` at render); **parsing never fails**. The
fixture corpus pinning this lives in `crates/vty/tests/fixtures/`
(the rousterctl savd corpus copied in, bfdd fixtures new).

Liveness method: the rousterctl discipline — `/proc/<pid>` on
Linux, `/bin/kill -0` elsewhere, EPERM = alive, pid 0 fenced,
unknown never guessed. A dead pid still renders the file (the
last-known record) with a `% ... stale run-dir files` footer;
rousterctl's exit-4 signal is vty's footer line instead.

## `vtyd.conf` and flags

```
port 2626          # default: vtyd's own, in the 26xx VTY family
bind 127.0.0.1     # loopback unless the operator says otherwise
run-dir /run/rouster
hostname rouster
canonical /etc/rouster.conf   # the write path's file (S8-c)
etc-dir /etc                  # forwarded to configd apply
```

Line conventions per savd (blank/`!`/`#` ignored, line-numbered
errors). Flags: `--config/-f`, `--bind`, `--port/-p`, `--run-dir`,
`--hostname`, `--canonical`, `--etc-dir`, `--command/-c`,
`--help/-h`, `--version/-V`; flags beat the file, the file beats
defaults.

## One-shot mode (`--command`)

`vtyd --command 'show sav'` connects to the running vtyd, runs
`enable` (no password in v1) + the command + `exit`, half-closes,
reads to EOF, strips the framing, prints the body. Exit codes are
deliberately narrow, per the B7 §4 lesson (`vtysh -b` exits 0 even
when apply fails — verify state, never trust rc):

- **0** — the command ran. Source-state honesty (`% No savd status
  published`, the stale-pid footer) is *output*, not a failure.
- **1** — transport failure (connect, IO, timeout).
- **2** — not a command (`% Unknown/Ambiguous/Incomplete/Invalid`).

## Signals

SIGTERM/SIGINT stop the listener and exit 0; open connections
close with their sessions. vtyd writes no run-dir file, ever —
the run dir stays the daemons' (and configd's) publication medium;
the write path stages only the canonical config file in the etc
dir and spawns configd, which owns every run-dir write.

## Deviations (fences, disclosed)

1. **Plain TCP, not vtysh's transport.** Real `vtysh` attaches via
   per-daemon unix sockets and ptys; v1 is a line protocol that
   says so in its banner. Wiring a genuine vtysh is §Deferred
   behind an interop capture.
2. **`show running-config` shows the merged canonical view** (since
   S8-c), not an frr.conf-shaped echo of the session's edits alone:
   there is no YANG store to read (Phase 4), so the canonical file
   plus the session's modeled edits IS the truth — one view, the
   one `write` writes. The W1-c frr-shaped display (bgp children
   indented, `!` separators, `end`) was replaced by it.
3. **No TAB completion** (v1 is `?`-only), no telnet IAC handling,
   no per-user AAA, no enable password.
4. **Rest-of-line params are canonicalized** to single-space joins
   (`route-map` display lines).
5. **Parse consolidation, done (N8)**: the run-dir status parsing
   previously lived in-crate (the W1-c deviation, so the two edge
   adapters stayed decoupled); since the N8 consolidation both edges
   read through the ONE shared reader, `common::rundir` —
   `savparse`/`bfdparse` are re-exports of its types, `ribparse` is
   the claim-less vty projection. The liveness method is still
   in-crate (rousterctl's `liveness` and vty's `liveness` remain
   separate thin modules; pooling them was never asked for).
6. **tokio `io-util` feature** added crate-locally on the
   workspace dependency (line discipline needs AsyncRead/WriteExt);
   no workspace-file change, no new lock entries. `tracing`
   output uses the bfdd shape (no env-filter feature — that would
   add crates).

## §Deferred

- **Config apply / `write`** — **DONE (S8-c)**: the recorded K3
  interim landed (`write file`/`write memory` stage the merged
  canonical and spawn `configd apply`; the design section above is
  the as-built record). The remaining climb is the target itself:
  the YANG-native transactional store (Phase 4), where vtyd's
  session tree maps to datastore edits and `write` becomes commit —
  until then the canonical file through configd is the one truth
  path, and nothing here survives as a second one.
- **Real vtysh attach** — capture FRR 10.2 vtysh's socket/pty
  behavior against a live daemon (the z5b raw-marker pattern),
  then decide unix-socket endpoints per daemon vs one endpoint.
- **TAB completion** — the tree already computes candidates;
  wiring is line-editor work (~an hour).
- **More show sources** — the W2-f round landed four of them over
  `rousterd.status` (`show interface`/`show ip interface`, `show
  neighbor`, `show vrf`, `show ip route summary`/`show rib summary`,
  parsed by `ribparse.rs` with its own fixture corpus); still PENDING
  per docs/operator-surfaces.md §3: per-route `show ip route` rows
  and the bgpd/ospfd status writers.
- **rousterctl/vty shared reader crate** — owner decision (see
  deviation 5).
- **Smoke-script wiring** — DONE by W2-f
  (`scripts/test-vty-smoke.sh`: live rousterd+savd+bfdd+vtyd in one
  container, content-asserted `--command` legs, liveness flip on
  rousterd SIGTERM; auto-discovered by `scripts/run-smokes.sh`).
  Remaining from the original note: the pieces it
  needs (fixed-port config, `--command` exit codes, SIGTERM) are
  pinned by tests here.
