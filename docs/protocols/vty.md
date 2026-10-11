# vty (vtyd) — the vtysh-compatible VTY server, v1

Status: weekend-program stream W1-c, delivered 2026-10-11 (commits
`62413df` parser/session core → `420e5fb` vtyd binary → `19ff65e`
test suites). Positioning: the interactive Cisco-style operator
surface at the compatibility edge (architecture invariant 1) —
FRR-compatible grammar and habits, Rouster-native underneath. It is
the sibling of `rousterctl` (the file-based reader): command naming
stays consistent (`show sav` on both), rousterctl stays daemonless,
vty is the interactive surface. v1 reads only the run-dir contract
and invents no IPC — the run-dir files ARE the interface.

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
| `show running-config` | the session's config tree | parse-only v1 (below) |
| `configure terminal` | — | enters config mode |
| `disable` | — | drops to user mode |
| `write memory` / `wr` | — | **deferred** (below) — honest disclosure, not a silent no-op |

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

## Config mode, parse-only v1

`configure terminal` accepts the **quarantine-B7 observed frr.conf
grammar subset** into a session config tree; `show running-config`
echoes it back in the FRR file shape (headers, `hostname`, `!`
separated stanzas, bgp children one-space indented, address-family
children two-space, `end` closing):

- `frr version <s>` · `frr defaults <s>` · `line vty` (B7 §1)
- `hostname <word>` — also changes the prompt
- `ip route <v4/m> blackhole` · `ip route <v4/m> <gw>` (B7 §2) ·
  `no ip route ...` negation
- `ipv6 route <v6/m> blackhole` — B7 §7's Rouster-side grammar, not
  FRR-observed (B7 §6); included for frr.conf-import parity with
  rousterd's native config
- `route-map <rest-of-line>` — kept verbatim for display (the
  typed policy engine is W1-a's `policy` crate; a route-map
  compatibility layer over it is its §Deferred, not vty's)
- `router bgp <asn>` → `(config-router)`: `bgp network
  import-check` / `no bgp network import-check`, `bgp router-id
  <v4>`, `neighbor <v4> remote-as <asn>`; `address-family ipv4
  unicast` → `(config-router-af)`: `network <v4/m>`,
  `redistribute static`, `exit-address-family` (B7 §3)
- `!` accepted as a no-op (separators are regenerated at render)

Anything else in config mode is rejected with the B7 error shape
(`% Unknown command: router static` — the §4.1-observed rejection).

**`write` is §Deferred, disclosed at point of use**: applying a
session config needs the owner's transactional-config design
(YANG-native northbound is the primary model, architecture
invariant 5; vtysh-as-translator never the source of truth). The
command prints the deferral instead of pretending. Anchor: the
session tree (`vty::config`) is the parse layer a future apply
path would hand to that transactional store.

## Config apply — the recorded design (K3)

Owner decision (2026-10-11, all-options-adopted round; recorded in
the plan's Appendix C status log): **the config-manager is the
target, file+SIGHUP is the interim** (`docs/implementation-plan.md`,
2026-10-11 "later" entry). This section pins the design so the
Phase-4 build follows it; v1 behavior is unchanged — `write` keeps
printing its deferral until the interim lands.

### The seams that exist today

Every daemon parses its own file at startup (`--config`/`-f`); four
of the six reload it on SIGHUP:

| Daemon | Config file | Grammar owner | SIGHUP today |
|---|---|---|---|
| `rousterd` | `rouster.conf` (its `--config`; the README quickstart shape) | `crates/rousterd/src/config.rs` — FRR-flavored strict subset: `ip`/`ipv6 route <prefix> {gw…\|blackhole} [table <N>]`, `zapi socket <PATH>` | **yes** — `crates/rousterd/src/main.rs` re-parses and the driver swaps the static routes through the RIB as a diff (`crates/rousterd/src/driver.rs`); a changed `zapi socket` path is refused with a warning |
| `staticd` | the same static-route shape (`--config`) | `crates/rousterd/src/staticd.rs` | **yes** — `StaticDaemon::reload` diffs onto the server (`crates/rousterd/src/bin/staticd.rs`) |
| `savd` | `savd.conf` (`--config`) | `crates/sav/src/savd.rs` (`parse_savd_config`) | **yes** — re-parses and swaps the config, i.e. the SIB's Config origin (`crates/sav/src/bin/savd.rs`) |
| `bfdd` | `bfd.conf`-shaped (`--config`) — bfdd owns its own file; there is **no** `bfd` stanza in `rouster.conf` | `crates/bfdd/src/daemon.rs` (the savd line grammar) | **yes, diff-based: unchanged peers keep their sessions** (`crates/bfdd/src/daemon.rs`) — the soft-reconfig seam invariant 2 demands |
| `ospfd` | `ospfd.conf` | `crates/ospfd/src/config.rs` (A11/B7 strict) | **no** — the run loop wires SIGTERM/SIGINT only (`crates/ospfd/src/bin/ospfd.rs`) |
| `bgpd` | `bgpd.conf` | `crates/bgpd/src/config.rs` (A11/B7 strict; `router bgp` stanza, `route-map`/`rpki` stanzas) | **no** — signals are SIGTERM/SIGINT → ManualStop → Cease (`crates/bgpd/src/bin/bgpd.rs`) |

Pid sources for the signal step: `savd.pid` and `bfdd.pid` exist;
rousterd has no pidfile but the `rousterd.status` header pid is its
live word (operator-surfaces §2.3); staticd/ospfd/bgpd publish
neither pid nor status yet (the operator-surfaces §3 PENDING row).

### The interim: file + SIGHUP

`write memory` renders the session tree (`vty::config`, the B7
subset above) into per-daemon file shapes and hands each to its
owning daemon:

1. **Project** the frr.conf-shaped tree onto the per-daemon
   grammars: `ip`/`ipv6 route` → the `rouster.conf` static lines
   (shapes identical by construction — the vty subset and
   rousterd's grammar are the same FRR cut; `table <N>` is not in
   the vty subset, disclosed); the `router bgp` subtree → the
   `bgpd.conf` `router bgp` stanza — a strict subset of bgpd's
   neighbor surface, with the `address-family` nesting flattened to
   bgpd.conf's router-level `network` lines (bgpd.conf has no
   address-family stanza today); verbatim `route-map` lines →
   bgpd.conf's route-map stanzas (the compiled engine is
   `policy`'s, consumed via bgpd.conf — `crates/policy/src/routemap.rs`).
   `hostname` (vtyd has its own line in `vtyd.conf`), `frr
   version/defaults`, `line vty` stay display-only in the interim —
   no daemon consumes them from a file.
2. **Write atomically** — temp file + rename in the destination
   directory; a daemon must never re-parse a half-written file.
3. **Signal** each owning daemon with SIGHUP (pid per the sources
   above).
4. **Verify, never trust rc** — the B7 §4.2 `vtysh -b` lesson
   already discipline for the one-shot client: apply output
   re-reads the run-dir status files (`savd.status`, `bfdd.status`,
   `rousterd.status`) and reports what took; a signaled daemon with
   no status writer answers "signaled, unverifiable".

Two fences, amended or accepted deliberately:

- **The read-only run-dir contract gains one writer.** v1 says vty
  never writes the run dir (Signals, below; operator-surfaces §2
  "v1 reads only"). The interim makes vtyd the sanctioned writer of
  *candidate* config files there
  (`<run-dir>/candidate/<daemon>.conf`) — symmetric with the
  daemons publishing status files outward; `rousterctl` stays
  read-only. Today's SIGHUP arms re-read the startup `--config`
  path, so each reload-capable daemon grows one small arm: on
  SIGHUP prefer the run-dir candidate when present, else the
  startup path. That per-daemon extension is Phase-4 code, not a
  new IPC contract — the point of keeping the interim small.
- **The file race is accepted, disclosed** (the recorded K1
  downside): operator edits to a daemon's `--config` file race the
  apply path. The candidate-file form contains it — vtyd owns only
  the run-dir candidates, never the operator's files — but a
  daemon started pointing elsewhere ignores them; deployment pins
  one convention per daemon.

Named prerequisites: SIGHUP arms for ospfd and bgpd (diff-based and
session-preserving — bfdd's reload is the pattern; invariant 2:
config changes must not bounce sessions), and pid/status
publication for staticd/ospfd/bgpd (the publish → tolerant parse →
fixture corpus pattern, operator-surfaces §3).

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
```

Line conventions per savd (blank/`!`/`#` ignored, line-numbered
errors). Flags: `--config/-f`, `--bind`, `--port/-p`, `--run-dir`,
`--hostname`, `--command/-c`, `--help/-h`, `--version/-V`; flags
beat the file, the file beats defaults.

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
close with their sessions. No run-dir files are written by vtyd —
the run dir stays the daemons' publication medium (vty never
writes it).

## Deviations (fences, disclosed)

1. **Plain TCP, not vtysh's transport.** Real `vtysh` attaches via
   per-daemon unix sockets and ptys; v1 is a line protocol that
   says so in its banner. Wiring a genuine vtysh is §Deferred
   behind an interop capture.
2. **`show running-config` shows the *session's* tree**, not a
   daemon's running config — there is no YANG store to read yet
   (Phase 4). The session tree seeds the future translator.
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

- **Config apply / `write`** — the *design is recorded* ("Config
  apply — the recorded design (K3)", above): file+SIGHUP interim,
  config-manager target; the build is Phase-4 work. vty's parse
  tree + B7 grammar remains the import layer that feeds it, and
  soft-reconfiguration semantics (invariant 2) are pinned in the
  design's prerequisites (bfdd's diff-based reload is the pattern).
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
