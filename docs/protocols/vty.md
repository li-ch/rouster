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
5. **Liveness/parse duplication with rousterctl**: the S3
   conventions and liveness method are re-implemented in-crate so
   the two edge adapters stay decoupled (both are W2-f's to
   consolidate if the owner wants a shared reader crate — a
   dependency-edge decision, recorded here).
6. **tokio `io-util` feature** added crate-locally on the
   workspace dependency (line discipline needs AsyncRead/WriteExt);
   no workspace-file change, no new lock entries. `tracing`
   output uses the bfdd shape (no env-filter feature — that would
   add crates).

## §Deferred

- **Config apply / `write`** — needs the owner's transactional
  YANG-native config design (the architecture's Phase 4 core);
  vty's parse tree + B7 grammar is the import layer ready to feed
  it. Record: any apply design must decide soft-reconfiguration
  semantics (invariant 2) at the same time.
- **Real vtysh attach** — capture FRR 10.2 vtysh's socket/pty
  behavior against a live daemon (the z5b raw-marker pattern),
  then decide unix-socket endpoints per daemon vs one endpoint.
- **TAB completion** — the tree already computes candidates;
  wiring is line-editor work (~an hour).
- **More show sources** — `show ip route` / `show vrf` /
  `show neighbour` stay PENDING sources per
  docs/operator-surfaces.md §3 (do not implement against guessed
  formats); each lands as: daemon publishes a run-dir file →
  tolerant parser + fixture corpus → vty command.
- **rousterctl/vty shared reader crate** — owner decision (see
  deviation 5).
- **Smoke-script wiring** — W2-f's operator round; the pieces it
  needs (fixed-port config, `--command` exit codes, SIGTERM) are
  pinned by tests here.
