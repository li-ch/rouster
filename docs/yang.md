# The YANG core — the model reference and the gNMI-transport decision

Status: S11-a (2026-10-15). The YANG core is LANDED as the internal
source of truth (architecture invariant 5): a pure-Rust RFC 7950
subset (`crates/yang` — parser, data tree, validator, the line
binding), the Rouster model set (`yang/*.yang`), configd's flip
(`docs/protocols/config.md` §1.5 — text grammar in, trees validated,
files rendered FROM the trees), and vtyd's translator seam
(`docs/protocols/vty.md` — config-mode edits build tree operations).
This document is the model set's reference, the machine shapes'
contract, and the §Deferred ledger; §gNMI-transport is the transport
evaluation ending in an owner decision.

## The subset (what "RFC 7950 subset" means here)

`crates/yang/src/lib.rs` carries the full RFC-lettered declaration —
implemented sections and the §Deferred list. The shape in one
paragraph: module/submodule statements with single-file imports
(§7.1/§7.1.5/§7.1.6/§7.2), typedef derivation with facet narrowing
(§7.3, §7.3.4), the type subset (integers §9.2 + range §9.2.4,
string §9.4 + length §9.4.4 + pattern §9.4.5 via a hand-written mini
regex, boolean §9.5, enumeration §9.6, empty §9.11, union §9.12;
RFC 6991 §3.2's inet types re-derived natively behind the `inet:`
pseudo-prefix), the data statements (container §7.5, leaf §7.6 with
default/mandatory, leaf-list §7.7, list §7.8 with §7.8.2 keys),
`must` as a documented expression subset (§7.5.3 — existence,
equality, not/and/or; the full XPath and the §10 function library
are out), and `config` inheritance (§7.21.1). Everything else —
grouping/uses/refine, choice, anydata/anyxml, augment, when,
identity/extension, feature/if-feature, deviation, rpc/action/
notification, presence, unique, min/max-elements, ordered-by,
decimal64, bits, binary, leafref, identityref,
instance-identifier, multi-revision imports — REFUSES TO LOAD with
a message naming the RFC section: the machine-readable §Deferred.

## The model set (`yang/`)

| Module | Models (the daemon's own parser is the semantic reference) |
|---|---|
| `rouster-common` | Shared typedefs (interface-name ≤ 15, area-id, isis-net, seconds, as-number, the bfdd millisecond window); the common/rousterd data: `router-id` (configd-owned), `interfaces`, static routes v4/v6 (`ip`/`ipv6 route` with the positional nexthop leaf-list and `table`), `zapi socket`. Doubles as the `daemon rousterd` section model. |
| `rouster-savd` | mode/action (the drop-friction gate is a leaf `must`)/poll/hysteresis/collision-policy/backend, interface stanzas (uRPF modes + barsav/role/remote-as), `binding` (prefix → interface leaf-list), the `barsav` inputs. |
| `rouster-bfdd` | The `peer` list keyed `(address, multihop)` — RFC 5882 §2's session identity; the boolean-key shorthand; intervals/multiplier/echo/passive/demand/version-negotiation/local-address; `password <id> <secret>`. |
| `rouster-ospfd` | `router ospf` (router-id, address-family, redistribute, rfc1583-compatibility), areas with the FRR parameter ladder (stub/nssa/default-cost/ranges/virtual-links), interface knobs (§C.3), classic `network <prefix> area <id>`, RFC 8177 `key chain` stanzas. |
| `rouster-isisd` | `router isis <tag>` (net/is-type/metric-style/hostname/redistribute), the p2p interface stanza. |
| `rouster-bgpd` | listen-port/hold-time, `router bgp <as>` (bgp router-id, import/export policy names, graceful-restart deferral, networks, the full neighbor surface: remote-as/passive/timers/mrai/role/update-error-handling/route-server/rr-client/graceful-restart/addpath), the `rpki` stanza (cache XOR vrp-file — a `must`), `barsav feed`, top-level `aspa`. The W1-a policy stanzas ride configd's pass-through BY DESIGN (the policy crate's grammar stays the gate). |
| `rouster-vty` | vtyd's session surface (frr version/defaults, hostname, line vty, statics, route-map lines, router bgp with the AF container) — what config-mode edits address. |

Boolean line dialects: savd/bfdd/ospfd/isisd spell booleans `yes|no`;
bgpd uses the bare-keyword shorthand. The models are EMBEDDED at
compile time (`crates/yang/src/models.rs`) — a build IS the model
set; the files at `yang/` are the source.

## The line binding ("linebind")

`crates/yang/src/line.rs` maps the suite's token-per-line daemon
grammars onto tree paths — table-driven off the schema, so a model
edit re-targets configd's bind and vtyd's translator at once. The
rules (the whole grammar of the seam):

1. Lines are token-per-line; blank/`!`/`#` ride verbatim (Opaque).
2. A line interprets against the stanza context left by the
   previous line — deepest-first with walk-up (savd's `mode` is the
   interface's inside a stanza, the global's before one).
3. Containers descend by name (`router` `bgp`); lists consume key
   tokens — boolean keys take the FRR shorthand (`peer <ip>
   multihop`).
4. Trailing `(name value)` statements; boolean leaves may take the
   shorthand; a leaf-list consumes the multi-value tail until a
   token names a sibling (`ip route <p> <gw> <gw> table <n>`);
   **4b**: bare values after a list's keys append to its first
   leaf-list (the positional shape); **4c**: bare values in a
   container assign to its leafs in declaration order
   (`send-lifetime 0 infinite`). A soft type-failure retries a
   shallower depth (bgpd's router-level `graceful-restart
   deferral` vs the neighbor's `graceful-restart <secs>`).
5. Unknown lines ride the Opaque bucket — disclosed pass-through;
   the daemon's own `--validate-config` stays the semantic gate.
6. Re-entering a keyed entry MERGES (§7.8.2) — deliberately more
   lenient than the daemon parsers, which refuse duplicates; merged
   stanza openers and re-assigned leafs keep every source line for
   the render.

Render: origin-carrying nodes emit their verbatim source lines
(byte-identical — configd's contract, `DataTree::source_lines`,
sorted by line); synthesized nodes (vtyd's edits) render at one
space of indent per depth, booleans per the dialect, defaults
never.

## The JSON form (`configd dump --json`)

The RFC 7951 encoding for the subset — leafs §5.1, containers §5.2,
leaf-lists §5.3, lists §5.4 (arrays of objects, keys as plain
members), type mapping §6 (integers as numbers, booleans as JSON
booleans, `empty` as null, strings/enums/inet as strings). Member
names are unqualified (single-module trees; §4 permits it). Defaults
are FILLED before encoding (report-all; no with-defaults
negotiation is pretended). Unmodeled pass-through lines surface as a
non-standard `"#unmodeled-<daemon>": [lines]` member — the
disclosure made machine-readable. (RESTCONF's RFC 8040 §5.2 is what
points at this encoding; RFC 8040 §5.3 itself is "RESTCONF
Metadata" — the pointer in the S11-a prompt lands there, corrected
here per the cite-what-the-RFC-says rule.)

## §Deferred (the honest ledger)

1. **The full RFC 7950 surface** — everything in the subset
   declaration's NOT-list, led by grouping/uses (§7.12/§7.13; the
   reason `zapi socket` and the static-route shapes are re-declared
   per module), choice/case (§7.9), presence (§7.5.5), when
   (§7.21.5), anydata (§7.10), deviation (§7.20.3), rpc/notification
   (§7.14/§7.16). Each refuses schema load naming its section —
   adding one is a deliberate, greppable act.
2. **The `must` subset** — no arithmetic/inequalities, no axes
   beyond child/parent, no node-set functions, no §10 library
   (`current()`, `re-match()`, `deref()`, …). The savd drop-friction
   and bgpd rpki-exclusivity constraints are the current ceiling.
3. **leafref (§9.9)** — ospfd's `authentication key-chain <name>`
   cannot yet reference the key-chain list; uniqueness is not
   checked across that seam.
4. **Pattern engine** — no `{m,n}` counted repetition, back-
   references, or `\p{…}` classes (XSD §9.4.5 features); a step
   budget bounds pathological backtracking into a non-match.
5. **The savd positional quirk** — a `mode` line following a
   `binding` line attaches to the global here, to the last
   interface in savd's parser (the corpus never interleaves them;
   disclosed divergence).
6. **Multi-revision imports (§5.1.1)** — one revision per module;
   `revision-date` is parsed, not selecting.
7. **ospfd area IDs** — the dotted-quad lexical form only (the
   parser also accepts plain integers); `instance-id`/`ifindex`/
   `message-digest-key` value sub-shapes are modeled shallowly.
8. **Multiple `must` on one node / error-app-tag surfacing** —
   parsed, but only `error-message` reaches operators.
9. **gNMI/RESTCONF transports** — §gNMI-transport below; the owner
   decision gates any crate adoption.

## §gNMI-transport — the evaluation (NO implementation; an owner decision)

The question the YANG core eventually answers: which wire does the
tree speak northbound? gNMI (the OpenConfig gRPC Network Management
interface: `Capabilities`/`Get`/`Set`/`Subscribe` over HTTP/2 gRPC,
`gnmi.proto` from `openconfig/gnmi`) is the incumbent operator
surface for YANG-modeled boxes; RESTCONF (RFC 8040) is the
IETF-standard HTTP form; `configd dump --json` (RFC 7951) is what
exists TODAY. Holo's prior art: MIT-licensed, `holo-yang` embeds
models and rides `yang5` 0.4 (the libyang binding line), with
gRPC/gNMI northbound on `tonic` 0.14 + `tonic-prost` 0.14 + `prost`
0.14 (per its workspace manifest, fetched 2026-10-15) — we EVALUATE
that approach, we do not adopt its crates (and notably: our core is
pure Rust where holo binds C libyang).

### Option A — the tonic/prost gRPC stack

- **What**: `tonic` (server) + `prost` (protobuf codegen for
  `gnmi.proto`) + `tonic-prost` build glue; the `Set`/`Get` RPCs
  mapped onto `DataTree` ops (paths exist already — the linebind
  and vtyd seam are the proof), `Subscribe` streaming over tokio.
- **Dep weight**: the heavy option. tonic pulls hyper, h2, http,
  tower + tower-layer stack, prost pulls its codegen at build time;
  on today's 99-crate lock (no HTTP stack at all — verified) this
  is plausibly +25..45 crates. Every one is mainstream and
  maintained; all transitively MIT/Apache-2.0.
- **Maintenance posture**: best-in-class Rust gRPC; protobuf
  upgrades and the gnmi.proto vendoring are ours (the spec moves
  slowly). TLS (rustls via tonic's feature) when operators ask.
- **Effort**: the largest — a gNMI server task in rousterd or a
  northbound daemon, auth model (gNMI has none built-in beyond
  TLS+certs), plus Subscribe's streaming semantics (on-change
  notifications need a change feed the tree layer does not expose
  yet — a real design item, not glue).

### Option B — a minimal hand-rolled HTTP/2 gNMI stub

- **What**: hand-write just enough HTTP/2 + gRPC framing (the
  HTTP/2 spec's server-push-free subset, gRPC's length-prefixed
  messages) to serve `Get`/`Set` (+ `Capabilities`); protobuf
  hand-encoded (gNMI's messages are large but a Get/Set subset is
  enumerable).
- **Dep weight**: zero new crates (the no-new-deps fence holds) —
  the entire appeal.
- **Maintenance posture**: WORST. We would own a private HTTP/2
  implementation — flow control, SETTINGS negotiation, HPACK —
  against real clients (gnmic, OpenConfig collectors) that exercise
  corners. This is the class of code the workspace's own bars
  (fuzz every wire codec) exists to avoid shipping lightly.
- **Effort**: deceptively large; correct-but-slow HPACK alone is a
  project. Not recommended even as a stopgap.

### Option C — a RESTCONF-shaped HTTP edge first (RFC 8040 subset)

- **What**: a small HTTP/1.1 server (std TcpListener + tokio; the
  suite already speaks line protocols everywhere) exposing the
  datastore REST-ish: `GET /restconf/data/...` (the RFC 7951 JSON
  `dump --json` already produces), `PATCH`/`PUT` mapping onto tree
  set/merge ops (the vtyd seam's exact operations), `?content`
  knobs later. Not full RESTCONF (no YANG Patch, no streams, no
  NETCONF-style transactions) — an honest subset, disclosed.
- **Dep weight**: zero-to-tiny (hand-rolled HTTP/1.1 parse is ~a
  few hundred lines and fuzzable like any wire codec; no HTTP/2,
  no protobuf).
- **Maintenance posture**: small and inspectable; HTTP/1.1 is a
  frozen spec. The subset is disclosed rather than standards-
  claimed until the full RFC 8040 surface lands.
- **Effort**: the smallest useful northbound; the tree ops, paths,
  and JSON encoding all exist today.

### Option D — defer any northbound transport (vty + dump only)

- **What**: nothing new; `vtyd` (the vtysh grammar) and
  `configd dump --json` remain the surfaces. The tree stays the
  internal truth; the transport question waits for an operator who
  needs it.
- **Dep weight / maintenance / effort**: zero / zero / zero. The
  risk is only external: automation tooling that speaks nothing but
  gNMI cannot adopt Rouster.

### OWNER DECISION BLOCK

- **A** — adopt tonic+prost, build the full gNMI northbound now.
- **B** — hand-roll the gRPC/HTTP/2 stub (recommended AGAINST; see
  posture above).
- **C** — build the RESTCONF-shaped HTTP/1.1 edge on the existing
  tree ops and RFC 7951 dump, keep gNMI as the documented next
  step. **(RECOMMENDED)** — it is the only option that adds a
  northbound surface without a dependency decision, it exercises
  the exact seams M4/M5 landed (paths, set/merge, the JSON form),
  and it leaves A open: the datastore semantics A would map to are
  identical, so nothing is thrown away when gNMI is wanted.
- **D** — defer; revisit when an operator asks.

Decide: ____
